// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/sync_sessions/session_sync_bridge.h"

#include <stdint.h>

#include <algorithm>
#include <set>
#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "components/sync/base/hash_util.h"
#include "components/sync/base/time.h"
#include "components/sync/model/entity_change.h"
#include "components/sync/model/metadata_batch.h"
#include "components/sync/model/mutable_data_batch.h"
#include "components/sync/model_impl/in_memory_metadata_change_list.h"
#include "components/sync/protocol/model_type_state.pb.h"
#include "components/sync/protocol/sync.pb.h"
#include "components/sync_sessions/sync_sessions_client.h"
#include "components/sync_sessions/synced_window_delegate.h"
#include "components/sync_sessions/synced_window_delegates_getter.h"

namespace sync_sessions {
namespace {

using sync_pb::SessionSpecifics;
using syncer::MetadataChangeList;
using syncer::ModelTypeStore;
using syncer::ModelTypeSyncBridge;

// Maximum number of favicons to sync.
const int kMaxSyncFavicons = 200;

std::unique_ptr<syncer::EntityData> MoveToEntityData(
    const std::string& client_name,
    SessionSpecifics* specifics) {
  auto entity_data = std::make_unique<syncer::EntityData>();
  entity_data->non_unique_name = client_name;
  entity_data->specifics.mutable_session()->Swap(specifics);
  return entity_data;
}

class LocalSessionWriteBatch : public LocalSessionEventHandlerImpl::WriteBatch {
 public:
  LocalSessionWriteBatch(const SessionStore::SessionInfo& session_info,
                         std::unique_ptr<SessionStore::WriteBatch> batch,
                         syncer::ModelTypeChangeProcessor* processor)
      : session_info_(session_info),
        batch_(std::move(batch)),
        processor_(processor) {
    DCHECK(batch_);
    DCHECK(processor_);
    DCHECK(processor_->IsTrackingMetadata());
  }

  ~LocalSessionWriteBatch() override {}

  // WriteBatch implementation.
  void Delete(int tab_node_id) override {
    const std::string storage_key =
        batch_->DeleteLocalTabWithoutUpdatingTracker(tab_node_id);
    processor_->Delete(storage_key, batch_->GetMetadataChangeList());
  }

  void Add(std::unique_ptr<sync_pb::SessionSpecifics> specifics) override {
    Update(std::move(specifics));
  }

  void Update(std::unique_ptr<sync_pb::SessionSpecifics> specifics) override {
    DCHECK(SessionStore::AreValidSpecifics(*specifics));
    const std::string storage_key =
        batch_->PutWithoutUpdatingTracker(*specifics);

    processor_->Put(
        storage_key,
        MoveToEntityData(session_info_.client_name, specifics.get()),
        batch_->GetMetadataChangeList());
  }

  void Commit() override {
    DCHECK(batch_) << "Cannot commit twice";
    SessionStore::WriteBatch::Commit(std::move(batch_));
  }

 private:
  const SessionStore::SessionInfo session_info_;
  std::unique_ptr<SessionStore::WriteBatch> batch_;
  syncer::ModelTypeChangeProcessor* const processor_;
};

bool IsSessionRestoreInProgress(SyncSessionsClient* sessions_client) {
  DCHECK(sessions_client);
  SyncedWindowDelegatesGetter* synced_window_getter =
      sessions_client->GetSyncedWindowDelegatesGetter();
  SyncedWindowDelegatesGetter::SyncedWindowDelegateMap windows =
      synced_window_getter->GetSyncedWindowDelegates();
  for (const auto& window_iter_pair : windows) {
    if (window_iter_pair.second->IsSessionRestoreInProgress()) {
      return true;
    }
  }
  return false;
}

}  // namespace

SessionSyncBridge::SessionSyncBridge(
    SyncSessionsClient* sessions_client,
    syncer::SessionSyncPrefs* sync_prefs,
    syncer::LocalDeviceInfoProvider* local_device_info_provider,
    const syncer::RepeatingModelTypeStoreFactory& store_factory,
    const base::RepeatingClosure& foreign_sessions_updated_callback,
    std::unique_ptr<syncer::ModelTypeChangeProcessor> change_processor)
    : ModelTypeSyncBridge(std::move(change_processor)),
      sessions_client_(sessions_client),
      local_session_event_router_(
          sessions_client->GetLocalSessionEventRouter()),
      foreign_sessions_updated_callback_(foreign_sessions_updated_callback),
      favicon_cache_(sessions_client->GetFaviconService(),
                     sessions_client->GetHistoryService(),
                     kMaxSyncFavicons),
      session_store_factory_(SessionStore::CreateFactory(
          sessions_client,
          sync_prefs,
          local_device_info_provider,
          store_factory,
          base::BindRepeating(&FaviconCache::UpdateMappingsFromForeignTab,
                              base::Unretained(&favicon_cache_)))),
      is_session_restore_in_progress_(
          IsSessionRestoreInProgress(sessions_client)) {
  DCHECK(sessions_client_);
  DCHECK(local_session_event_router_);
  DCHECK(foreign_sessions_updated_callback_);
}

SessionSyncBridge::~SessionSyncBridge() {
  if (syncing_) {
    local_session_event_router_->Stop();
  }
}

void SessionSyncBridge::ScheduleGarbageCollection() {
  if (!syncing_) {
    return;
  }
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&SessionSyncBridge::DoGarbageCollection,
                                base::AsWeakPtr(this)));
}

FaviconCache* SessionSyncBridge::GetFaviconCache() {
  return &favicon_cache_;
}

SessionsGlobalIdMapper* SessionSyncBridge::GetGlobalIdMapper() {
  return &global_id_mapper_;
}

OpenTabsUIDelegate* SessionSyncBridge::GetOpenTabsUIDelegate() {
  if (!syncing_) {
    return nullptr;
  }
  return syncing_->open_tabs_ui_delegate.get();
}

void SessionSyncBridge::OnSessionRestoreComplete() {
  is_session_restore_in_progress_ = false;

  if (syncing_) {
    StartLocalSessionEventHandler();
  }
}

syncer::SyncableService* SessionSyncBridge::GetSyncableService() {
  return nullptr;
}

syncer::ModelTypeSyncBridge* SessionSyncBridge::GetModelTypeSyncBridge() {
  return this;
}

std::unique_ptr<MetadataChangeList>
SessionSyncBridge::CreateMetadataChangeList() {
  return std::make_unique<syncer::InMemoryMetadataChangeList>();
}

base::Optional<syncer::ModelError> SessionSyncBridge::MergeSyncData(
    std::unique_ptr<MetadataChangeList> metadata_change_list,
    syncer::EntityChangeList entity_data) {
  DCHECK(syncing_);
  DCHECK(change_processor()->IsTrackingMetadata());

  if (!is_session_restore_in_progress_) {
    StartLocalSessionEventHandler();
  }

  return ApplySyncChanges(std::move(metadata_change_list),
                          std::move(entity_data));
}

void SessionSyncBridge::StartLocalSessionEventHandler() {
  // We should be ready to propagate local state to sync.
  DCHECK(syncing_);
  DCHECK(!syncing_->local_session_event_handler);
  DCHECK(change_processor()->IsTrackingMetadata());
  DCHECK(!is_session_restore_in_progress_);

  // TODO(crbug.com/681921): Remove injecting |local_session_write_batch| and
  // let the impl create one via the delegate once the directory-based
  // implementation is removed.
  std::unique_ptr<LocalSessionEventHandlerImpl::WriteBatch>
      local_session_write_batch = CreateLocalSessionWriteBatch();
  syncing_->local_session_event_handler =
      std::make_unique<LocalSessionEventHandlerImpl>(
          /*delegate=*/this, sessions_client_,
          syncing_->store->mutable_tracker(), local_session_write_batch.get());

  local_session_write_batch->Commit();

  // Start processing local changes, which will be propagated to the store as
  // well as the processor.
  local_session_event_router_->StartRoutingTo(
      syncing_->local_session_event_handler.get());
}

base::Optional<syncer::ModelError> SessionSyncBridge::ApplySyncChanges(
    std::unique_ptr<MetadataChangeList> metadata_change_list,
    syncer::EntityChangeList entity_changes) {
  DCHECK(change_processor()->IsTrackingMetadata());
  DCHECK(syncing_);

  // Merging sessions is simple: remote entities are expected to be foreign
  // sessions (identified by the session tag)  and hence must simply be
  // stored (server wins, including undeletion). For local sessions, remote
  // information is ignored (local wins).
  std::unique_ptr<SessionStore::WriteBatch> batch =
      CreateSessionStoreWriteBatch();
  for (const syncer::EntityChange& change : entity_changes) {
    switch (change.type()) {
      case syncer::EntityChange::ACTION_DELETE:
        // Deletions are all or nothing (since we only ever delete entire
        // sessions). Therefore we don't care if it's a tab node or meta node,
        // and just ensure we've disassociated.
        if (syncing_->store->StorageKeyMatchesLocalSession(
                change.storage_key())) {
          // Another client has attempted to delete our local data (possibly by
          // error or a clock is inaccurate). Just ignore the deletion for now.
          DLOG(WARNING) << "Local session data deleted. Ignoring until next "
                        << "local navigation event.";
        } else {
          batch->DeleteForeignEntityAndUpdateTracker(change.storage_key());
        }
        break;
      case syncer::EntityChange::ACTION_ADD:
      case syncer::EntityChange::ACTION_UPDATE: {
        const SessionSpecifics& specifics = change.data().specifics.session();

        if (!SessionStore::AreValidSpecifics(specifics) ||
            change.data().client_tag_hash !=
                GenerateSyncableHash(syncer::SESSIONS,
                                     SessionStore::GetClientTag(specifics))) {
          continue;
        }

        if (syncing_->store->StorageKeyMatchesLocalSession(
                change.storage_key())) {
          // We should only ever receive a change to our own machine's session
          // info if encryption was turned on. In that case, the data is still
          // the same, so we can ignore.
          DLOG(WARNING) << "Dropping modification to local session.";
          continue;
        }

        batch->PutAndUpdateTracker(specifics, change.data().modification_time);
        // If a favicon or favicon urls are present, load the URLs and visit
        // times into the in-memory favicon cache.
        if (specifics.has_tab()) {
          favicon_cache_.UpdateMappingsFromForeignTab(
              specifics.tab(), change.data().modification_time);
        }
        break;
      }
    }
  }

  static_cast<syncer::InMemoryMetadataChangeList*>(metadata_change_list.get())
      ->TransferChangesTo(batch->GetMetadataChangeList());
  SessionStore::WriteBatch::Commit(std::move(batch));

  // This might overtrigger because we don't check if the batch is empty, but
  // observers should handle these events well so we don't bother detecting.
  foreign_sessions_updated_callback_.Run();
  return base::nullopt;
}

void SessionSyncBridge::GetData(StorageKeyList storage_keys,
                                DataCallback callback) {
  DCHECK(syncing_);
  std::move(callback).Run(syncing_->store->GetSessionDataForKeys(storage_keys));
}

void SessionSyncBridge::GetAllData(DataCallback callback) {
  DCHECK(syncing_);
  std::move(callback).Run(syncing_->store->GetAllSessionData());
}

std::string SessionSyncBridge::GetClientTag(
    const syncer::EntityData& entity_data) {
  return SessionStore::GetClientTag(entity_data.specifics.session());
}

std::string SessionSyncBridge::GetStorageKey(
    const syncer::EntityData& entity_data) {
  if (!SessionStore::AreValidSpecifics(entity_data.specifics.session())) {
    return std::string();
  }
  return SessionStore::GetStorageKey(entity_data.specifics.session());
}

ModelTypeSyncBridge::DisableSyncResponse
SessionSyncBridge::ApplyDisableSyncChanges(
    std::unique_ptr<MetadataChangeList> delete_metadata_change_list) {
  local_session_event_router_->Stop();
  if (syncing_) {
    syncing_->store->DeleteAllDataAndMetadata();
  }
  syncing_.reset();
  return DisableSyncResponse::kModelNoLongerReadyToSync;
}

std::unique_ptr<LocalSessionEventHandlerImpl::WriteBatch>
SessionSyncBridge::CreateLocalSessionWriteBatch() {
  DCHECK(syncing_);
  return std::make_unique<LocalSessionWriteBatch>(
      syncing_->store->local_session_info(), CreateSessionStoreWriteBatch(),
      change_processor());
}

void SessionSyncBridge::TrackLocalNavigationId(base::Time timestamp,
                                               int unique_id) {
  global_id_mapper_.TrackNavigationId(timestamp, unique_id);
}

void SessionSyncBridge::OnPageFaviconUpdated(const GURL& page_url) {
  favicon_cache_.OnPageFaviconUpdated(page_url, base::Time::Now());
}

void SessionSyncBridge::OnFaviconVisited(const GURL& page_url,
                                         const GURL& favicon_url) {
  favicon_cache_.OnFaviconVisited(page_url, favicon_url);
}

void SessionSyncBridge::OnSyncStarting(
    const syncer::ModelErrorHandler& error_handler,
    syncer::ModelTypeChangeProcessor::StartCallback callback) {
  DCHECK(!syncing_);

  session_store_factory_.Run(base::BindOnce(
      &SessionSyncBridge::OnStoreInitialized, base::AsWeakPtr(this)));

  ModelTypeSyncBridge::OnSyncStarting(error_handler, std::move(callback));
}

void SessionSyncBridge::OnStoreInitialized(
    const base::Optional<syncer::ModelError>& error,
    std::unique_ptr<SessionStore> store,
    std::unique_ptr<syncer::MetadataBatch> metadata_batch) {
  DCHECK(!syncing_);

  if (error) {
    change_processor()->ReportError(*error);
    return;
  }

  DCHECK(store);
  DCHECK(metadata_batch);

  syncing_.emplace();
  syncing_->store = std::move(store);
  syncing_->open_tabs_ui_delegate = std::make_unique<OpenTabsUIDelegateImpl>(
      sessions_client_, syncing_->store->tracker(), &favicon_cache_,
      base::BindRepeating(&SessionSyncBridge::DeleteForeignSessionFromUI,
                          base::Unretained(this)));

  change_processor()->ModelReadyToSync(this, std::move(metadata_batch));

  // If initial sync was already done, MergeSyncData() will never be called so
  // we need to start syncing local changes.
  if (change_processor()->IsTrackingMetadata() &&
      !is_session_restore_in_progress_) {
    StartLocalSessionEventHandler();
  }
}

void SessionSyncBridge::DeleteForeignSessionFromUI(const std::string& tag) {
  if (!syncing_) {
    return;
  }

  std::unique_ptr<SessionStore::WriteBatch> batch =
      CreateSessionStoreWriteBatch();
  DeleteForeignSessionWithBatch(tag, batch.get());
  SessionStore::WriteBatch::Commit(std::move(batch));
}

void SessionSyncBridge::DoGarbageCollection() {
  // TODO(crbug.com/681921): Implement logic and also run
  // foreign_sessions_updated_callback_ if needed.
  NOTIMPLEMENTED();
}

void SessionSyncBridge::DeleteForeignSessionWithBatch(
    const std::string& session_tag,
    SessionStore::WriteBatch* batch) {
  DCHECK(syncing_);
  DCHECK(change_processor()->IsTrackingMetadata());

  if (session_tag == syncing_->store->local_session_info().session_tag) {
    DLOG(ERROR) << "Attempting to delete local session. This is not currently "
                << "supported.";
    return;
  }

  // Delete tabs.
  for (int tab_node_id :
       syncing_->store->tracker()->LookupTabNodeIds(session_tag)) {
    const std::string tab_storage_key =
        SessionStore::GetTabStorageKey(session_tag, tab_node_id);
    batch->DeleteForeignEntityAndUpdateTracker(tab_storage_key);
    change_processor()->Delete(tab_storage_key, batch->GetMetadataChangeList());
  }

  // Delete header.
  const std::string header_storage_key =
      SessionStore::GetHeaderStorageKey(session_tag);
  batch->DeleteForeignEntityAndUpdateTracker(header_storage_key);
  change_processor()->Delete(header_storage_key,
                             batch->GetMetadataChangeList());

  foreign_sessions_updated_callback_.Run();
}

std::unique_ptr<SessionStore::WriteBatch>
SessionSyncBridge::CreateSessionStoreWriteBatch() {
  DCHECK(syncing_);
  return syncing_->store->CreateWriteBatch(
      base::BindOnce(&SessionSyncBridge::ReportError, base::AsWeakPtr(this)));
}

void SessionSyncBridge::ReportError(const syncer::ModelError& error) {
  change_processor()->ReportError(error);
}

SessionSyncBridge::SyncingState::SyncingState() {}

SessionSyncBridge::SyncingState::~SyncingState() {}

}  // namespace sync_sessions

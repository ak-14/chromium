// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_SYNC_SESSIONS_SESSION_SYNC_BRIDGE_H_
#define COMPONENTS_SYNC_SESSIONS_SESSION_SYNC_BRIDGE_H_

#include <memory>
#include <string>

#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "components/sync/device_info/local_device_info_provider.h"
#include "components/sync/model/model_error.h"
#include "components/sync/model/model_type_store.h"
#include "components/sync/model/model_type_sync_bridge.h"
#include "components/sync_sessions/abstract_sessions_sync_manager.h"
#include "components/sync_sessions/favicon_cache.h"
#include "components/sync_sessions/local_session_event_handler_impl.h"
#include "components/sync_sessions/open_tabs_ui_delegate_impl.h"
#include "components/sync_sessions/session_store.h"
#include "components/sync_sessions/sessions_global_id_mapper.h"

namespace sync_sessions {

class LocalSessionEventRouter;
class SyncSessionsClient;

// Sync bridge implementation for SESSIONS model type. Takes care of propagating
// local sessions to other clients as well as providing a representation of
// foreign sessions.
//
// This is achieved by implementing the interface ModelTypeSyncBridge, which
// ClientTagBasedModelTypeProcessor will use to interact, ultimately, with the
// sync server. See
// https://chromium.googlesource.com/chromium/src/+/lkcr/docs/sync/model_api.md#Implementing-ModelTypeSyncBridge
// for details.
class SessionSyncBridge : public AbstractSessionsSyncManager,
                          public syncer::ModelTypeSyncBridge,
                          public LocalSessionEventHandlerImpl::Delegate {
 public:
  // Raw pointers must not be null and their pointees must outlive this object.
  SessionSyncBridge(
      SyncSessionsClient* sessions_client,
      syncer::SessionSyncPrefs* sync_prefs,
      syncer::LocalDeviceInfoProvider* local_device_info_provider,
      const syncer::RepeatingModelTypeStoreFactory& store_factory,
      const base::RepeatingClosure& foreign_sessions_updated_callback,
      std::unique_ptr<syncer::ModelTypeChangeProcessor> change_processor);
  ~SessionSyncBridge() override;

  // AbstractSessionsSyncManager implementation.
  void ScheduleGarbageCollection() override;
  FaviconCache* GetFaviconCache() override;
  SessionsGlobalIdMapper* GetGlobalIdMapper() override;
  OpenTabsUIDelegate* GetOpenTabsUIDelegate() override;
  void OnSessionRestoreComplete() override;
  syncer::SyncableService* GetSyncableService() override;
  syncer::ModelTypeSyncBridge* GetModelTypeSyncBridge() override;

  // ModelTypeSyncBridge implementation.
  std::unique_ptr<syncer::MetadataChangeList> CreateMetadataChangeList()
      override;
  base::Optional<syncer::ModelError> MergeSyncData(
      std::unique_ptr<syncer::MetadataChangeList> metadata_change_list,
      syncer::EntityChangeList entity_data) override;
  base::Optional<syncer::ModelError> ApplySyncChanges(
      std::unique_ptr<syncer::MetadataChangeList> metadata_change_list,
      syncer::EntityChangeList entity_changes) override;
  void GetData(StorageKeyList storage_keys, DataCallback callback) override;
  void GetAllData(DataCallback callback) override;
  std::string GetClientTag(const syncer::EntityData& entity_data) override;
  std::string GetStorageKey(const syncer::EntityData& entity_data) override;
  void OnSyncStarting(
      const syncer::ModelErrorHandler& error_handler,
      syncer::ModelTypeChangeProcessor::StartCallback callback) override;
  DisableSyncResponse ApplyDisableSyncChanges(
      std::unique_ptr<syncer::MetadataChangeList> delete_metadata_change_list)
      override;

  // LocalSessionEventHandlerImpl::Delegate implementation.
  std::unique_ptr<LocalSessionEventHandlerImpl::WriteBatch>
  CreateLocalSessionWriteBatch() override;
  void TrackLocalNavigationId(base::Time timestamp, int unique_id) override;
  void OnPageFaviconUpdated(const GURL& page_url) override;
  void OnFaviconVisited(const GURL& page_url, const GURL& favicon_url) override;

 private:
  void OnStoreInitialized(
      const base::Optional<syncer::ModelError>& error,
      std::unique_ptr<SessionStore> store,
      std::unique_ptr<syncer::MetadataBatch> metadata_batch);
  void StartLocalSessionEventHandler();
  void DeleteForeignSessionFromUI(const std::string& tag);
  void DoGarbageCollection();
  std::unique_ptr<SessionStore::WriteBatch> CreateSessionStoreWriteBatch();
  void DeleteForeignSessionWithBatch(const std::string& session_tag,
                                     SessionStore::WriteBatch* batch);
  void ReportError(const syncer::ModelError& error);

  SyncSessionsClient* const sessions_client_;
  LocalSessionEventRouter* const local_session_event_router_;
  const base::RepeatingClosure foreign_sessions_updated_callback_;

  FaviconCache favicon_cache_;
  SessionsGlobalIdMapper global_id_mapper_;
  SessionStore::Factory session_store_factory_;
  bool is_session_restore_in_progress_;

  // All data dependent on sync being starting or started.
  struct SyncingState {
    SyncingState();
    ~SyncingState();

    std::unique_ptr<SessionStore> store;
    std::unique_ptr<OpenTabsUIDelegateImpl> open_tabs_ui_delegate;
    std::unique_ptr<LocalSessionEventHandlerImpl> local_session_event_handler;
  };

  base::Optional<SyncingState> syncing_;

  DISALLOW_COPY_AND_ASSIGN(SessionSyncBridge);
};

}  // namespace sync_sessions

#endif  // COMPONENTS_SYNC_SESSIONS_SESSION_SYNC_BRIDGE_H_

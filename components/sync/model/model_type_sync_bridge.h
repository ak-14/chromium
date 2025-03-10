// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_SYNC_MODEL_MODEL_TYPE_SYNC_BRIDGE_H_
#define COMPONENTS_SYNC_MODEL_MODEL_TYPE_SYNC_BRIDGE_H_

#include <memory>
#include <string>
#include <vector>

#include "base/callback.h"
#include "base/memory/weak_ptr.h"
#include "base/optional.h"
#include "components/sync/engine/activation_context.h"
#include "components/sync/model/conflict_resolution.h"
#include "components/sync/model/entity_change.h"
#include "components/sync/model/entity_data.h"
#include "components/sync/model/model_error.h"
#include "components/sync/model/model_type_change_processor.h"

namespace syncer {

class DataBatch;
class MetadataChangeList;

// Interface implemented by model types to receive updates from sync via a
// ModelTypeChangeProcessor. Provides a way for sync to update the data and
// metadata for entities, as well as the model type state. Sync bridge
// implementations must provide their change_processor() with metadata through
// ModelReadyToSync() as soon as possible. Once this is called, sync will
// immediately begin locally tracking changes and can start syncing with the
// server soon afterward. If an error occurs during startup, the processor's
// ReportError() method should be called instead of ModelReadyToSync().
class ModelTypeSyncBridge : public base::SupportsWeakPtr<ModelTypeSyncBridge> {
 public:
  using DataCallback = base::OnceCallback<void(std::unique_ptr<DataBatch>)>;
  using StorageKeyList = std::vector<std::string>;

  enum class DisableSyncResponse {
    kModelStillReadyToSync,
    kModelNoLongerReadyToSync
  };

  ModelTypeSyncBridge(
      std::unique_ptr<ModelTypeChangeProcessor> change_processor);

  virtual ~ModelTypeSyncBridge();

  // Creates an object used to communicate changes in the sync metadata to the
  // model type store.
  virtual std::unique_ptr<MetadataChangeList> CreateMetadataChangeList() = 0;

  // Perform the initial merge between local and sync data. This should only be
  // called when a data type is first enabled to start syncing, and there is no
  // sync metadata. Best effort should be made to match local and sync data.
  // Storage key in entity_data elements will be set to result of
  // GetStorageKey() call if the bridge supports it. Otherwise it will be left
  // empty, bridge is responsible for updating storage keys of new entities with
  // change_processor()->UpdateStorageKey() in this case. If a local and sync
  // data should match/merge but disagree on storage key, the bridge should
  // delete one of the records (preferably local). Any local pieces of data that
  // are not present in sync should immediately be Put(...) to the processor
  // before returning. The same MetadataChangeList that was passed into this
  // function can be passed to Put(...) calls. Delete(...) can also be called
  // but should not be needed for most model types. Durable storage writes, if
  // not able to combine all change atomically, should save the metadata after
  // the data changes, so that this merge will be re-driven by sync if is not
  // completely saved during the current run.
  virtual base::Optional<ModelError> MergeSyncData(
      std::unique_ptr<MetadataChangeList> metadata_change_list,
      EntityChangeList entity_data) = 0;

  // Apply changes from the sync server locally.
  // Please note that |entity_changes| might have fewer entries than
  // |metadata_change_list| in case when some of the data changes are filtered
  // out, or even be empty in case when a commit confirmation is processed and
  // only the metadata needs to persisted.
  virtual base::Optional<ModelError> ApplySyncChanges(
      std::unique_ptr<MetadataChangeList> metadata_change_list,
      EntityChangeList entity_changes) = 0;

  // Asynchronously retrieve the corresponding sync data for |storage_keys|.
  // |callback| should be invoked if the operation is successful, otherwise
  // the processor's ReportError method should be called.
  virtual void GetData(StorageKeyList storage_keys, DataCallback callback) = 0;

  // Asynchronously retrieve all of the local sync data. |callback| should be
  // invoked if the operation is successful, otherwise the processor's
  // ReportError method should be called.
  virtual void GetAllData(DataCallback callback) = 0;

  // Get or generate a client tag for |entity_data|. This must be the same tag
  // that was/would have been generated in the SyncableService/Directory world
  // for backward compatibility with pre-USS clients. The only time this
  // theoretically needs to be called is on the creation of local data, however
  // it is also used to verify the hash of remote data. If a model type was
  // never launched pre-USS, then method does not need to be different from
  // GetStorageKey(). Only the hash of this value is kept.
  virtual std::string GetClientTag(const EntityData& entity_data) = 0;

  // Get or generate a storage key for |entity_data|. This will only ever be
  // called once when first encountering a remote entity. Local changes will
  // provide their storage keys directly to Put instead of using this method.
  // Theoretically this function doesn't need to be stable across multiple calls
  // on the same or different clients, but to keep things simple, it probably
  // should be. Storage keys are kept in memory at steady state, so each model
  // type should strive to keep these keys as small as possible.
  virtual std::string GetStorageKey(const EntityData& entity_data) = 0;

  // By returning true in this function datatype indicates that it can generate
  // storage key from EntityData. In this case for all new entities received
  // from server, change processor will call GetStorageKey and update
  // EntityChange structures before passing them to MergeSyncData and
  // ApplySyncChanges.
  //
  // This function should return false when datatype's native storage is not
  // indexed by some combination of values from EntityData, when key into the
  // storage is obtained at the time the record is inserted into it (e.g. ROWID
  // in SQLite). In this case entity changes for new entities passed to
  // MergeSyncData and ApplySyncChanges will have empty storage_key. It is
  // datatype's responsibility to call UpdateStorageKey for such entities.
  virtual bool SupportsGetStorageKey() const;

  // Resolve a conflict between the client and server versions of data. They are
  // guaranteed not to match (both be deleted or have identical specifics). A
  // default implementation chooses the server data unless it is a deletion.
  virtual ConflictResolution ResolveConflict(
      const EntityData& local_data,
      const EntityData& remote_data) const;

  // Called by the DataTypeController to gather additional information needed
  // before the processor can be connected to a sync worker. Once the
  // metadata has been loaded, the info is collected and given to |callback|.
  // When overriding, the bridge must notify the processor.
  virtual void OnSyncStarting(const ModelErrorHandler& error_handler,
                              ModelTypeChangeProcessor::StartCallback callback);

  // Indicates that we no longer want to do any sync-related things for this
  // data type. Severs all ties to the sync thread, deletes all local sync
  // metadata, and then destroys the change processor.
  void DisableSync();

  // Similar to ApplySyncChanges() but called by the processor when sync
  // is in the process of being disabled. |delete_metadata_change_list| contains
  // a change list to remove all metadata that the processor knows about, but
  // the bridge may decide to implement deletion by other means.
  virtual DisableSyncResponse ApplyDisableSyncChanges(
      std::unique_ptr<MetadataChangeList> delete_metadata_change_list);

  // Needs to be informed about any model change occurring via Delete() and
  // Put(). The changing metadata should be stored to persistent storage before
  // or atomically with the model changes.
  ModelTypeChangeProcessor* change_processor() const;

 private:
  std::unique_ptr<ModelTypeChangeProcessor> change_processor_;
};

}  // namespace syncer

#endif  // COMPONENTS_SYNC_MODEL_MODEL_TYPE_SYNC_BRIDGE_H_

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/sync_file_system/sync_file_system_service.h"

#include <stddef.h>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "chrome/browser/sync_file_system/local/canned_syncable_file_system.h"
#include "chrome/browser/sync_file_system/local/local_file_sync_context.h"
#include "chrome/browser/sync_file_system/local/local_file_sync_service.h"
#include "chrome/browser/sync_file_system/local/mock_sync_status_observer.h"
#include "chrome/browser/sync_file_system/local/sync_file_system_backend.h"
#include "chrome/browser/sync_file_system/mock_remote_file_sync_service.h"
#include "chrome/browser/sync_file_system/sync_callbacks.h"
#include "chrome/browser/sync_file_system/sync_event_observer.h"
#include "chrome/browser/sync_file_system/sync_file_metadata.h"
#include "chrome/browser/sync_file_system/sync_file_system_test_util.h"
#include "chrome/browser/sync_file_system/sync_status_code.h"
#include "chrome/browser/sync_file_system/syncable_file_system_util.h"
#include "chrome/test/base/testing_profile.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/test/test_browser_thread_bundle.h"
#include "content/public/test/test_utils.h"
#include "storage/browser/fileapi/file_system_context.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/leveldatabase/leveldb_chrome.h"

using content::BrowserThread;
using storage::FileSystemURL;
using storage::FileSystemURLSet;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::InSequence;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::_;

namespace sync_file_system {

namespace {

const char kOrigin[] = "http://example.com";

template <typename R> struct AssignTrait {
  typedef const R& ArgumentType;
};

template <> struct AssignTrait<SyncFileStatus> {
  typedef SyncFileStatus ArgumentType;
};

template <typename R>
void AssignValueAndQuit(base::RunLoop* run_loop,
                        SyncStatusCode* status_out, R* value_out,
                        SyncStatusCode status,
                        typename AssignTrait<R>::ArgumentType value) {
  DCHECK(status_out);
  DCHECK(value_out);
  DCHECK(run_loop);
  *status_out = status;
  *value_out = value;
  run_loop->Quit();
}

// This is called on IO thread. Posts |callback| to be called on UI thread.
void VerifyFileError(base::Closure callback,
                     base::File::Error error) {
  EXPECT_EQ(base::File::FILE_OK, error);
  BrowserThread::PostTask(BrowserThread::UI, FROM_HERE, callback);
}

}  // namespace

class MockSyncEventObserver : public SyncEventObserver {
 public:
  MockSyncEventObserver() {}
  virtual ~MockSyncEventObserver() {}

  MOCK_METHOD3(OnSyncStateUpdated,
               void(const GURL& app_origin,
                    SyncServiceState state,
                    const std::string& description));
  MOCK_METHOD5(OnFileSynced,
               void(const storage::FileSystemURL& url,
                    SyncFileType file_type,
                    SyncFileStatus status,
                    SyncAction action,
                    SyncDirection direction));
};

ACTION_P3(NotifyStateAndCallback,
          mock_remote_service, service_state, operation_status) {
  mock_remote_service->NotifyRemoteServiceStateUpdated(
      service_state, "Test event.");
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(arg1, operation_status));
}

ACTION_P(RecordState, states) {
  states->push_back(arg1);
}

ACTION_P(MockStatusCallback, status) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                                base::BindOnce(arg4, status));
}

ACTION_P2(MockSyncFileCallback, status, url) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(arg0, status, url));
}

ACTION(InvokeCompletionClosure) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, arg0);
}

class SyncFileSystemServiceTest : public testing::Test {
 protected:
  SyncFileSystemServiceTest()
      : thread_bundle_(content::TestBrowserThreadBundle::REAL_IO_THREAD) {}

  void SetUp() override {
    in_memory_env_ = leveldb_chrome::NewMemEnv("SyncFileSystemServiceTest");
    file_system_.reset(new CannedSyncableFileSystem(
        GURL(kOrigin), in_memory_env_.get(),
        BrowserThread::GetTaskRunnerForThread(BrowserThread::IO),
        base::CreateSingleThreadTaskRunnerWithTraits({base::MayBlock()})));

    std::unique_ptr<LocalFileSyncService> local_service =
        LocalFileSyncService::CreateForTesting(&profile_, in_memory_env_.get());
    remote_service_ = new StrictMock<MockRemoteFileSyncService>;
    sync_service_.reset(new SyncFileSystemService(&profile_));

    EXPECT_CALL(*mock_remote_service(),
                AddServiceObserver(_)).Times(1);
    EXPECT_CALL(*mock_remote_service(),
                AddFileStatusObserver(sync_service_.get())).Times(1);
    EXPECT_CALL(*mock_remote_service(),
                GetLocalChangeProcessor())
        .WillRepeatedly(Return(&local_change_processor_));
    EXPECT_CALL(*mock_remote_service(),
                SetRemoteChangeProcessor(local_service.get())).Times(1);

    sync_service_->Initialize(
        std::move(local_service),
        std::unique_ptr<RemoteFileSyncService>(remote_service_));

    // Disable auto sync by default.
    EXPECT_CALL(*mock_remote_service(), SetSyncEnabled(false)).Times(1);
    sync_service_->SetSyncEnabledForTesting(false);

    file_system_->SetUp(CannedSyncableFileSystem::QUOTA_ENABLED);
  }

  void TearDown() override {
    sync_service_->Shutdown();
    file_system_->TearDown();
    RevokeSyncableFileSystem();
    base::TaskScheduler::GetInstance()->FlushForTesting();
  }

  void InitializeApp() {
    base::RunLoop run_loop;
    SyncStatusCode status = SYNC_STATUS_UNKNOWN;

    EXPECT_CALL(*mock_remote_service(),
                RegisterOrigin(GURL(kOrigin), _)).Times(1);

    // GetCurrentState may be called when a remote or local sync is scheduled
    // by change notifications or by a timer.
    EXPECT_CALL(*mock_remote_service(), GetCurrentState())
        .Times(AnyNumber())
        .WillRepeatedly(Return(REMOTE_SERVICE_OK));

    sync_service_->InitializeForApp(
        file_system_->file_system_context(),
        GURL(kOrigin),
        AssignAndQuitCallback(&run_loop, &status));
    run_loop.Run();

    EXPECT_EQ(SYNC_STATUS_OK, status);
    EXPECT_EQ(base::File::FILE_OK, file_system_->OpenFileSystem());
  }

  // Calls InitializeForApp after setting up the mock remote service to
  // perform following when RegisterOrigin is called:
  //  1. Notify RemoteFileSyncService's observers of |state_to_notify|
  //  2. Run the given callback with |status_to_return|.
  //
  // ..and verifies if following conditions are met:
  //  1. The SyncEventObserver of the service is called with
  //     |expected_states| service state values.
  //  2. InitializeForApp's callback is called with |expected_status|
  void InitializeAppForObserverTest(
      RemoteServiceState state_to_notify,
      SyncStatusCode status_to_return,
      const std::vector<SyncServiceState>& expected_states,
      SyncStatusCode expected_status) {
    StrictMock<MockSyncEventObserver> event_observer;
    sync_service_->AddSyncEventObserver(&event_observer);

    EnableSync();

    EXPECT_CALL(*mock_remote_service(), GetCurrentState())
        .Times(AnyNumber())
        .WillRepeatedly(Return(state_to_notify));

    EXPECT_CALL(*mock_remote_service(),
                RegisterOrigin(GURL(kOrigin), _))
        .WillOnce(NotifyStateAndCallback(mock_remote_service(),
                                         state_to_notify,
                                         status_to_return));

    std::vector<SyncServiceState> actual_states;
    EXPECT_CALL(event_observer, OnSyncStateUpdated(GURL(), _, _))
        .WillRepeatedly(RecordState(&actual_states));

    SyncStatusCode actual_status = SYNC_STATUS_UNKNOWN;
    base::RunLoop run_loop;
    sync_service_->InitializeForApp(
        file_system_->file_system_context(),
        GURL(kOrigin),
        AssignAndQuitCallback(&run_loop, &actual_status));
    run_loop.Run();

    EXPECT_EQ(expected_status, actual_status);
    ASSERT_EQ(expected_states.size(), actual_states.size());
    for (size_t i = 0; i < actual_states.size(); ++i)
      EXPECT_EQ(expected_states[i], actual_states[i]);

    sync_service_->RemoveSyncEventObserver(&event_observer);
  }

  FileSystemURL URL(const std::string& path) const {
    return file_system_->URL(path);
  }

  StrictMock<MockRemoteFileSyncService>* mock_remote_service() {
    return remote_service_;
  }

  StrictMock<MockLocalChangeProcessor>* mock_local_change_processor() {
    return &local_change_processor_;
  }

  void EnableSync() {
    EXPECT_CALL(*mock_remote_service(), SetSyncEnabled(true)).Times(1);
    sync_service_->SetSyncEnabledForTesting(true);
  }

  content::TestBrowserThreadBundle thread_bundle_;
  std::unique_ptr<leveldb::Env> in_memory_env_;
  TestingProfile profile_;
  std::unique_ptr<CannedSyncableFileSystem> file_system_;

  // Their ownerships are transferred to SyncFileSystemService.
  StrictMock<MockRemoteFileSyncService>* remote_service_;
  StrictMock<MockLocalChangeProcessor> local_change_processor_;

  std::unique_ptr<SyncFileSystemService> sync_service_;
};

TEST_F(SyncFileSystemServiceTest, InitializeForApp) {
  InitializeApp();
}

TEST_F(SyncFileSystemServiceTest, InitializeForAppSuccess) {
  std::vector<SyncServiceState> expected_states;
  expected_states.push_back(SYNC_SERVICE_RUNNING);

  InitializeAppForObserverTest(
      REMOTE_SERVICE_OK,
      SYNC_STATUS_OK,
      expected_states,
      SYNC_STATUS_OK);
}

TEST_F(SyncFileSystemServiceTest, InitializeForAppWithNetworkFailure) {
  std::vector<SyncServiceState> expected_states;
  expected_states.push_back(SYNC_SERVICE_TEMPORARY_UNAVAILABLE);

  // Notify REMOTE_SERVICE_TEMPORARY_UNAVAILABLE and callback with
  // SYNC_STATUS_NETWORK_ERROR.  This should let the
  // InitializeApp fail.
  InitializeAppForObserverTest(
      REMOTE_SERVICE_TEMPORARY_UNAVAILABLE,
      SYNC_STATUS_NETWORK_ERROR,
      expected_states,
      SYNC_STATUS_NETWORK_ERROR);
}

TEST_F(SyncFileSystemServiceTest, InitializeForAppWithError) {
  std::vector<SyncServiceState> expected_states;
  expected_states.push_back(SYNC_SERVICE_DISABLED);

  // Notify REMOTE_SERVICE_DISABLED and callback with
  // SYNC_STATUS_FAILED.  This should let the InitializeApp fail.
  InitializeAppForObserverTest(
      REMOTE_SERVICE_DISABLED,
      SYNC_STATUS_FAILED,
      expected_states,
      SYNC_STATUS_FAILED);
}

TEST_F(SyncFileSystemServiceTest, SimpleLocalSyncFlow) {
  InitializeApp();

  StrictMock<MockSyncStatusObserver> status_observer;

  EnableSync();
  file_system_->backend()->sync_context()->
      set_mock_notify_changes_duration_in_sec(0);
  file_system_->AddSyncStatusObserver(&status_observer);

  // We'll test one local sync for this file.
  const FileSystemURL kFile(file_system_->URL("foo"));

  base::RunLoop run_loop;

  // We should get called OnSyncEnabled and OnWriteEnabled on kFile as in:
  // 1. OnWriteEnabled when PrepareForSync(SYNC_SHARED) is finished and
  //    the target file is unlocked for writing
  // 2. OnSyncEnabled x 3 times; 1) when CreateFile is finished, 2) when
  //    file is unlocked after PrepareForSync, and 3) when the sync is
  //    finished.
  EXPECT_CALL(status_observer, OnWriteEnabled(kFile))
      .Times(AtLeast(1));

  {
    ::testing::InSequence sequence;
    EXPECT_CALL(status_observer, OnSyncEnabled(kFile))
        .Times(AtLeast(2));
    EXPECT_CALL(status_observer, OnSyncEnabled(kFile))
        .WillOnce(InvokeWithoutArgs(&run_loop, &base::RunLoop::Quit));
  }

  // The local_change_processor's ApplyLocalChange should be called once
  // with ADD_OR_UPDATE change for TYPE_FILE.
  const FileChange change(FileChange::FILE_CHANGE_ADD_OR_UPDATE,
                          SYNC_FILE_TYPE_FILE);
  EXPECT_CALL(*mock_local_change_processor(),
              ApplyLocalChange(change, _, _, kFile, _))
      .WillOnce(MockStatusCallback(SYNC_STATUS_OK));
  EXPECT_CALL(*mock_remote_service(), ProcessRemoteChange(_))
      .WillRepeatedly(MockSyncFileCallback(SYNC_STATUS_NO_CHANGE_TO_SYNC,
                                           FileSystemURL()));

  EXPECT_CALL(*mock_remote_service(), PromoteDemotedChanges(_))
      .WillRepeatedly(InvokeCompletionClosure());

  EXPECT_EQ(base::File::FILE_OK, file_system_->CreateFile(kFile));

  run_loop.Run();

  file_system_->RemoveSyncStatusObserver(&status_observer);
}

TEST_F(SyncFileSystemServiceTest, SimpleRemoteSyncFlow) {
  InitializeApp();

  EnableSync();

  base::RunLoop run_loop;

  // We expect a set of method calls for starting a remote sync.
  EXPECT_CALL(*mock_remote_service(), ProcessRemoteChange(_))
      .WillOnce(InvokeWithoutArgs(&run_loop, &base::RunLoop::Quit));

  // This should trigger a remote sync.
  mock_remote_service()->NotifyRemoteChangeQueueUpdated(1);

  run_loop.Run();
}

TEST_F(SyncFileSystemServiceTest, SimpleSyncFlowWithFileBusy) {
  InitializeApp();

  EnableSync();
  file_system_->backend()->sync_context()->
      set_mock_notify_changes_duration_in_sec(0);

  const FileSystemURL kFile(file_system_->URL("foo"));

  base::RunLoop run_loop;

  {
    InSequence sequence;

    // Return with SYNC_STATUS_FILE_BUSY once.
    EXPECT_CALL(*mock_remote_service(), ProcessRemoteChange(_))
        .WillOnce(MockSyncFileCallback(SYNC_STATUS_FILE_BUSY,
                                       kFile));

    // ProcessRemoteChange should be called again when the becomes
    // not busy.
    EXPECT_CALL(*mock_remote_service(), ProcessRemoteChange(_))
        .WillOnce(InvokeWithoutArgs(&run_loop, &base::RunLoop::Quit));
  }

  EXPECT_CALL(*mock_remote_service(), PromoteDemotedChanges(_))
      .WillRepeatedly(InvokeCompletionClosure());

  // We might also see an activity for local sync as we're going to make
  // a local write operation on kFile.
  EXPECT_CALL(*mock_local_change_processor(),
              ApplyLocalChange(_, _, _, kFile, _))
      .Times(AnyNumber());

  // This should trigger a remote sync.
  mock_remote_service()->NotifyRemoteChangeQueueUpdated(1);

  // Start a local operation on the same file (to make it BUSY).
  base::RunLoop verify_file_error_run_loop;
  BrowserThread::PostTask(
      BrowserThread::IO, FROM_HERE,
      base::BindOnce(&CannedSyncableFileSystem::DoCreateFile,
                     base::Unretained(file_system_.get()), kFile,
                     base::Bind(&VerifyFileError,
                                verify_file_error_run_loop.QuitClosure())));

  run_loop.Run();

  mock_remote_service()->NotifyRemoteChangeQueueUpdated(0);

  verify_file_error_run_loop.Run();
}

#if defined(THREAD_SANITIZER)
// SyncFileSystemServiceTest.GetFileSyncStatus fails under ThreadSanitizer,
// see http://crbug.com/294904.
#define MAYBE_GetFileSyncStatus DISABLED_GetFileSyncStatus
#else
#define MAYBE_GetFileSyncStatus GetFileSyncStatus
#endif
TEST_F(SyncFileSystemServiceTest, MAYBE_GetFileSyncStatus) {
  InitializeApp();

  const FileSystemURL kFile(file_system_->URL("foo"));

  SyncStatusCode status;
  SyncFileStatus sync_file_status;

  // 1. The file is synced state.
  {
    base::RunLoop run_loop;
    status = SYNC_STATUS_UNKNOWN;
    sync_file_status = SYNC_FILE_STATUS_UNKNOWN;
    sync_service_->GetFileSyncStatus(
        kFile,
        base::Bind(&AssignValueAndQuit<SyncFileStatus>,
                   &run_loop, &status, &sync_file_status));
    run_loop.Run();

    EXPECT_EQ(SYNC_STATUS_OK, status);
    EXPECT_EQ(SYNC_FILE_STATUS_SYNCED, sync_file_status);
  }

  // 2. The file has pending local changes.
  {
    base::RunLoop run_loop;
    EXPECT_EQ(base::File::FILE_OK, file_system_->CreateFile(kFile));

    status = SYNC_STATUS_UNKNOWN;
    sync_file_status = SYNC_FILE_STATUS_UNKNOWN;
    sync_service_->GetFileSyncStatus(
        kFile,
        base::Bind(&AssignValueAndQuit<SyncFileStatus>,
                   &run_loop, &status, &sync_file_status));
    run_loop.Run();

    EXPECT_EQ(SYNC_STATUS_OK, status);
    EXPECT_EQ(SYNC_FILE_STATUS_HAS_PENDING_CHANGES, sync_file_status);
  }
}

}  // namespace sync_file_system

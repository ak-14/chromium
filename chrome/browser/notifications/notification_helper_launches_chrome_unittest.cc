// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This test file is an evolution of
// notification_helper/notification_helper_process_unittest.cc. In addition to
// testing launching notification_helper.exe by the OS via registry which is
// what notification_helper_process_unittest is all about, this test also tests
// if chrome.exe can be successfully launched by notification_helper.exe via the
// NotificationActivator::Activate function.
//
// This test is compiled into unit_tests.exe under chrome rather than
// notification_helper_unittests.exe. This is because unit_tests.exe has data
// dependency on chrome.exe which is required by this test, and it's undesired
// to make notification_helper_unittests.exe have data dependency on chrome.exe.

#include <memory>

#include <NotificationActivationCallback.h>
#include <wrl/client.h>

#include "base/base_paths.h"
#include "base/containers/flat_map.h"
#include "base/files/file_path.h"
#include "base/path_service.h"
#include "base/process/kill.h"
#include "base/process/process.h"
#include "base/process/process_iterator.h"
#include "base/stl_util.h"
#include "base/strings/string16.h"
#include "base/test/test_timeouts.h"
#include "base/win/scoped_winrt_initializer.h"
#include "base/win/windows_version.h"
#include "chrome/install_static/install_util.h"
#include "chrome/installer/util/install_util.h"
#include "chrome/installer/util/registry_key_backup.h"
#include "chrome/installer/util/util_constants.h"
#include "chrome/installer/util/work_item.h"
#include "chrome/installer/util/work_item_list.h"
#include "chrome/test/base/process_inspector_win.h"
#include "content/public/common/result_codes.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

constexpr wchar_t kLaunchId[] =
    L"0|0|Default|0|https://example.com/|notification_id";

// Returns a handle to the process of id |pid| if it is an immediate child of
// |parent|.
base::Process OpenProcessIfChildOf(base::ProcessId pid,
                                   const base::Process& parent) {
  DCHECK(parent.IsValid());
  // PROCESS_VM_READ access right is required for ProcessInspector::Create()
  // below.
  auto process = base::Process::OpenWithExtraPrivileges(pid);
  if (!process.IsValid())
    return process;
  auto inspector = ProcessInspector::Create(process);
  if (!inspector || inspector->GetParentPid() != parent.Pid())
    process.Close();
  return process;
}

// Used to filter all the descendant processes of the given process.
class ProcessTreeFilter : public base::ProcessFilter {
 public:
  explicit ProcessTreeFilter(base::Process process)
      : parent_pid_(process.Pid()) {
    ancestor_processes_[process.Pid()] = std::move(process);
  }

  bool Includes(const base::ProcessEntry& entry) const override {
    auto iter = ancestor_processes_.find(entry.parent_pid());
    if (iter != ancestor_processes_.end()) {
      base::Process process = OpenProcessIfChildOf(entry.pid(), iter->second);

      // If the process is invalid, it could be an immediate child of
      // iter->second but has been killed resulting from its parent proc's being
      // killed. Despite this, its child processes may not be killed yet. So in
      // theory, we need to add its pid to ancestor_processes_ map and continue
      // hunting for its descendant processes.
      //
      // However, it is possible that the pid was reused, and we don't want to
      // kill the new proc's child processes. With this possibility, we choose
      // not to kill the new process if it is invalid. This works fine for this
      // test as chrome puts its sub-procs in a job object so that they all
      // should die with the parent.
      if (!process.IsValid())
        return false;

      has_child_process_alive_ = true;
      ancestor_processes_[entry.pid()] = std::move(process);
      return true;
    }
    return false;
  }

  bool has_child_process_alive() { return has_child_process_alive_; }

  void set_has_child_process_alive(bool has_child_process_alive) {
    has_child_process_alive_ = has_child_process_alive;
  }

 private:
  // The handles of the ancestor processes, indexed by process id.
  // Must be mutable because override function Includes() is const.
  mutable base::flat_map<base::ProcessId, base::Process> ancestor_processes_;

  // Id of the parent process.
  const base::ProcessId parent_pid_;

  // A flag indicating if there is any child process alive.
  // Must be mutable because override function Includes() is const.
  mutable bool has_child_process_alive_ = false;

  DISALLOW_COPY_AND_ASSIGN(ProcessTreeFilter);
};

// Kills |process| and all of its descendants. Child processes are explicitly
// killed to ensure that they do not outlive the test.
void KillProcessTree(base::Process process) {
  ProcessTreeFilter process_tree_filter(process.Duplicate());

  // Start by explicitly killing the main process.
  ASSERT_TRUE(process.Terminate(content::RESULT_CODE_KILLED, true /* wait */));

  // base::KillProcesses used in conjuction with KillProcessTree kills
  // processes from parent to child. Loop until all descendant processes are
  // killed with no more than kMaxTries tries.
  static constexpr int kMaxTries = 10;
  int num_tries = 0;
  base::FilePath::StringType exe_name = installer::kChromeExe;
  do {
    process_tree_filter.set_has_child_process_alive(false);
    base::KillProcesses(exe_name, content::RESULT_CODE_KILLED,
                        &process_tree_filter);
  } while (process_tree_filter.has_child_process_alive() &&
           ++num_tries < kMaxTries);

  DLOG_IF(ERROR, num_tries >= kMaxTries) << "Failed to kill all processes!";
}

// Returns the process with name |name| if it is found.
base::Process FindProcess(const base::string16& name) {
  unsigned int pid;
  {
    base::NamedProcessIterator iter(name, nullptr);
    const auto* entry = iter.NextProcessEntry();
    if (!entry)
      return base::Process();
    pid = entry->pid();
  }

  auto process = base::Process::Open(pid);
  if (!process.IsValid())
    return process;

  // Since the process could go away suddenly before we open a handle to it,
  // it's possible that a different process was just opened and assigned the
  // same PID due to aggressive PID reuse. Now that a handle is held to *some*
  // process, take another run through the snapshot to see if the process with
  // this PID has the right exe name.
  base::NamedProcessIterator iter(name, nullptr);
  while (const auto* entry = iter.NextProcessEntry()) {
    if (entry->pid() == pid)
      return process;  // PID was not reused since the PID's match.
  }
  return base::Process();  // The PID was reused.
}

// Used to filter all the immediate child processes by process id.
class ChildProcessFilter : public base::ProcessFilter {
 public:
  explicit ChildProcessFilter(base::ProcessId parent_pid)
      : parent_pid_(parent_pid) {}

  bool Includes(const base::ProcessEntry& entry) const override {
    return parent_pid_ == entry.parent_pid();
  }

 private:
  const base::ProcessId parent_pid_;

  DISALLOW_COPY_AND_ASSIGN(ChildProcessFilter);
};

}  // namespace

class NotificationHelperLaunchesChrome : public testing::Test {
 protected:
  NotificationHelperLaunchesChrome()
      : toast_activator_reg_path_(InstallUtil::GetToastActivatorRegistryPath()),
        root_(HKEY_CURRENT_USER) {}

  ~NotificationHelperLaunchesChrome() override = default;

  void SetUp() override {
    // Back up the existing registration.
    ASSERT_TRUE(backup_.Initialize(root_, toast_activator_reg_path_.c_str(),
                                   WorkItem::kWow64Default));

    ASSERT_NO_FATAL_FAILURE(RegisterServer());
  }

  void TearDown() override {
    ASSERT_NO_FATAL_FAILURE(UnregisterServer());

    // Restore the registration.
    ASSERT_TRUE(backup_.WriteTo(root_, toast_activator_reg_path_.c_str(),
                                WorkItem::kWow64Default));
  }

 private:
  // Registers notification_helper.exe as the server.
  // TODO(chengx): Remove duplicated code by reusing the code in
  // chrome/installer/setup/install_worker.cc
  void RegisterServer() {
    std::unique_ptr<WorkItemList> list(WorkItem::CreateWorkItemList());

    // Delete the old registration to ensure a clean environment for server
    // registration. This is okay because we have already backed up the existing
    // registration in SetUp(), and will restore it in TearDown().
    list->AddDeleteRegKeyWorkItem(root_, toast_activator_reg_path_,
                                  WorkItem::kWow64Default);

    // Notification_helper.exe is in the build output directory next to this
    // test executable, as the test build target has a data_deps dependency on
    // it.
    base::FilePath dir_exe;
    ASSERT_TRUE(PathService::Get(base::DIR_EXE, &dir_exe));
    base::FilePath notification_helper =
        dir_exe.Append(installer::kNotificationHelperExe);

    base::string16 toast_activator_server_path = toast_activator_reg_path_;
    toast_activator_server_path.append(L"\\LocalServer32");

    // Command-line featuring the quoted path to the exe.
    base::string16 command(1, L'"');
    command.append(notification_helper.value()).append(1, L'"');

    list->AddCreateRegKeyWorkItem(root_, toast_activator_server_path,
                                  WorkItem::kWow64Default);

    list->AddSetRegValueWorkItem(root_, toast_activator_server_path,
                                 WorkItem::kWow64Default, L"", command, true);

    list->AddSetRegValueWorkItem(root_, toast_activator_server_path,
                                 WorkItem::kWow64Default, L"ServerExecutable",
                                 notification_helper.value(), true);

    ASSERT_TRUE(list->Do());
  }

  // Unregisters the server by deleting the registry key installed during the
  // test.
  void UnregisterServer() {
    ASSERT_TRUE(InstallUtil::DeleteRegistryKey(root_, toast_activator_reg_path_,
                                               WorkItem::kWow64Default));
  }

  // Path to the toast activator registry.
  const base::string16 toast_activator_reg_path_;

  // Predefined handle to the registry.
  const HKEY root_;

  // Backup of the deleted registry.
  RegistryKeyBackup backup_;

  DISALLOW_COPY_AND_ASSIGN(NotificationHelperLaunchesChrome);
};

TEST_F(NotificationHelperLaunchesChrome, ChromeLaunchTest) {
  // This test requires WinRT core functions, which are not available in
  // older versions of Windows.
  if (base::win::GetVersion() < base::win::VERSION_WIN8)
    return;

  base::win::ScopedWinrtInitializer winrt_initializer;
  ASSERT_TRUE(winrt_initializer.Succeeded());

  // There isn't a way to directly correlate the notification_helper.exe server
  // to this test. So we need to hunt for the server.
  base::Process notification_helper_process =
      FindProcess(installer::kNotificationHelperExe);
  ASSERT_FALSE(notification_helper_process.IsValid());

  Microsoft::WRL::ComPtr<INotificationActivationCallback>
      notification_activator;
  ASSERT_HRESULT_SUCCEEDED(::CoCreateInstance(
      install_static::GetToastActivatorClsid(), nullptr, CLSCTX_LOCAL_SERVER,
      IID_PPV_ARGS(&notification_activator)));
  ASSERT_TRUE(notification_activator);

  // The notification_helper server is now invoked upon the request of creating
  // the object instance. The server module now holds a reference of the
  // instance object, the notification_helper.exe process is alive waiting for
  // that reference to be released.
  notification_helper_process = FindProcess(installer::kNotificationHelperExe);
  ASSERT_TRUE(notification_helper_process.IsValid());

  // This relies on |notification_helper_process| outliving |filter| to ensure
  // that its pid isn't reused.
  ChildProcessFilter filter(notification_helper_process.Pid());
  int child_chrome_process_count = 0;
  base::Process notification_helper_crashpad;
  {
    base::NamedProcessIterator iter(installer::kChromeExe, &filter);
    while (const auto* entry = iter.NextProcessEntry()) {
      ++child_chrome_process_count;
      notification_helper_crashpad =
          OpenProcessIfChildOf(entry->pid(), notification_helper_process);
    }
  }
  // The notification_helper process has launched a child chrome process as its
  // crashpad handler.
  ASSERT_EQ(child_chrome_process_count, 1);
  ASSERT_TRUE(notification_helper_crashpad.IsValid());

  // Launch chrome.exe with the launch id from notification_helper.
  ASSERT_HRESULT_SUCCEEDED(
      notification_activator->Activate(L"", kLaunchId, nullptr, 0));

  // Now the notification_helper process has another immediate child process, in
  // addition to the crashpad child process as mentioned above. Note that
  // notification_helper has more than two descendant chrome processes. Kill all
  // notification_helper's child processes except for the crashpad child process
  // while counting.
  child_chrome_process_count = 0;
  {
    base::NamedProcessIterator iter(installer::kChromeExe, &filter);
    while (const auto* entry = iter.NextProcessEntry()) {
      if (entry->pid() == notification_helper_crashpad.Pid())
        continue;
      base::Process process =
          OpenProcessIfChildOf(entry->pid(), notification_helper_process);
      ASSERT_TRUE(process.IsValid());
      KillProcessTree(std::move(process));
      ++child_chrome_process_count;
    }
  }
  ASSERT_EQ(child_chrome_process_count, 1);

  // The crashpad process should be the only living child process of
  // notification_helper.
  child_chrome_process_count = 0;
  {
    base::NamedProcessIterator iter(installer::kChromeExe, &filter);
    while (iter.NextProcessEntry())
      ++child_chrome_process_count;
  }
  ASSERT_EQ(child_chrome_process_count, 1);

  // Release the instance object. Now that the last (and the only) instance
  // object of the module is released, the event living in the server
  // process is signaled, which allows the notification_helper process and its
  // crashpad child process to exit.
  notification_activator.Reset();
  ASSERT_TRUE(notification_helper_process.WaitForExitWithTimeout(
      TestTimeouts::action_timeout(), nullptr));
  ASSERT_TRUE(notification_helper_crashpad.WaitForExitWithTimeout(
      TestTimeouts::action_timeout(), nullptr));
}

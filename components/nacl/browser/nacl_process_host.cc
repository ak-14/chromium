// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/nacl/browser/nacl_process_host.h"

#include <string.h>
#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/base_switches.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "base/path_service.h"
#include "base/process/launch.h"
#include "base/process/process_iterator.h"
#include "base/rand_util.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/sys_byteorder.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "components/nacl/browser/nacl_browser.h"
#include "components/nacl/browser/nacl_browser_delegate.h"
#include "components/nacl/browser/nacl_host_message_filter.h"
#include "components/nacl/common/nacl_cmd_line.h"
#include "components/nacl/common/nacl_constants.h"
#include "components/nacl/common/nacl_host_messages.h"
#include "components/nacl/common/nacl_messages.h"
#include "components/nacl/common/nacl_process_type.h"
#include "components/nacl/common/nacl_switches.h"
#include "components/url_formatter/url_formatter.h"
#include "content/public/browser/browser_child_process_host.h"
#include "content/public/browser/browser_ppapi_host.h"
#include "content/public/browser/child_process_data.h"
#include "content/public/browser/plugin_service.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/common/child_process_host.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/mojo_channel_switches.h"
#include "content/public/common/process_type.h"
#include "content/public/common/sandboxed_process_launcher_delegate.h"
#include "content/public/common/zygote_buildflags.h"
#include "ipc/ipc_channel.h"
#include "mojo/edk/embedder/embedder.h"
#include "net/socket/socket_descriptor.h"
#include "ppapi/host/host_factory.h"
#include "ppapi/host/ppapi_host.h"
#include "ppapi/proxy/ppapi_messages.h"
#include "ppapi/shared_impl/ppapi_constants.h"
#include "ppapi/shared_impl/ppapi_nacl_plugin_args.h"
#include "services/service_manager/sandbox/switches.h"

#if BUILDFLAG(USE_ZYGOTE_HANDLE)
#include "content/public/common/zygote_handle.h"
#endif  // BUILDFLAG(USE_ZYGOTE_HANDLE)

#if defined(OS_POSIX)

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#elif defined(OS_WIN)
#include <windows.h>
#include <winsock2.h>

#include "base/threading/thread.h"
#include "base/win/scoped_handle.h"
#include "base/win/windows_version.h"
#include "components/nacl/browser/nacl_broker_service_win.h"
#include "components/nacl/common/nacl_debug_exception_handler_win.h"
#include "content/public/common/sandbox_init.h"
#endif

using content::BrowserThread;
using content::ChildProcessData;
using content::ChildProcessHost;
using ppapi::proxy::SerializedHandle;

namespace nacl {

#if defined(OS_WIN)
namespace {

// Looks for the largest contiguous unallocated region of address
// space and returns it via |*out_addr| and |*out_size|.
void FindAddressSpace(base::ProcessHandle process,
                      char** out_addr, size_t* out_size) {
  *out_addr = NULL;
  *out_size = 0;
  char* addr = 0;
  while (true) {
    MEMORY_BASIC_INFORMATION info;
    size_t result = VirtualQueryEx(process, static_cast<void*>(addr),
                                   &info, sizeof(info));
    if (result < sizeof(info))
      break;
    if (info.State == MEM_FREE && info.RegionSize > *out_size) {
      *out_addr = addr;
      *out_size = info.RegionSize;
    }
    addr += info.RegionSize;
  }
}

#ifdef _DLL

bool IsInPath(const std::string& path_env_var, const std::string& dir) {
  for (const base::StringPiece& cur : base::SplitStringPiece(
           path_env_var, ";", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL)) {
    if (cur == dir)
      return true;
  }
  return false;
}

#endif  // _DLL

}  // namespace

// Allocates |size| bytes of address space in the given process at a
// randomised address.
void* AllocateAddressSpaceASLR(base::ProcessHandle process, size_t size) {
  char* addr;
  size_t avail_size;
  FindAddressSpace(process, &addr, &avail_size);
  if (avail_size < size)
    return NULL;
  size_t offset = base::RandGenerator(avail_size - size);
  const int kPageSize = 0x10000;
  void* request_addr = reinterpret_cast<void*>(
      reinterpret_cast<uint64_t>(addr + offset) & ~(kPageSize - 1));
  return VirtualAllocEx(process, request_addr, size,
                        MEM_RESERVE, PAGE_NOACCESS);
}

namespace {

bool RunningOnWOW64() {
  return (base::win::OSInfo::GetInstance()->wow64_status() ==
          base::win::OSInfo::WOW64_ENABLED);
}

}  // namespace

#endif  // defined(OS_WIN)

namespace {

// NOTE: changes to this class need to be reviewed by the security team.
class NaClSandboxedProcessLauncherDelegate
    : public content::SandboxedProcessLauncherDelegate {
 public:
  NaClSandboxedProcessLauncherDelegate() {}

#if defined(OS_WIN)
  void PostSpawnTarget(base::ProcessHandle process) override {
    // For Native Client sel_ldr processes on 32-bit Windows, reserve 1 GB of
    // address space to prevent later failure due to address space fragmentation
    // from .dll loading. The NaCl process will attempt to locate this space by
    // scanning the address space using VirtualQuery.
    // TODO(bbudge) Handle the --no-sandbox case.
    // http://code.google.com/p/nativeclient/issues/detail?id=2131
    const SIZE_T kNaClSandboxSize = 1 << 30;
    if (!nacl::AllocateAddressSpaceASLR(process, kNaClSandboxSize)) {
      DLOG(WARNING) << "Failed to reserve address space for Native Client";
    }
  }
#endif  // OS_WIN

#if BUILDFLAG(USE_ZYGOTE_HANDLE)
  content::ZygoteHandle GetZygote() override {
    return content::GetGenericZygote();
  }
#endif  // BUILDFLAG(USE_ZYGOTE_HANDLE)

  service_manager::SandboxType GetSandboxType() override {
    return service_manager::SANDBOX_TYPE_PPAPI;
  }
};

void CloseFile(base::File file) {
  // The base::File destructor will close the file for us.
}

}  // namespace

NaClProcessHost::NaClProcessHost(
    const GURL& manifest_url,
    base::File nexe_file,
    const NaClFileToken& nexe_token,
    const std::vector<NaClResourcePrefetchResult>& prefetched_resource_files,
    ppapi::PpapiPermissions permissions,
    int render_view_id,
    uint32_t permission_bits,
    bool uses_nonsfi_mode,
    bool off_the_record,
    NaClAppProcessType process_type,
    const base::FilePath& profile_directory)
    : manifest_url_(manifest_url),
      nexe_file_(std::move(nexe_file)),
      nexe_token_(nexe_token),
      prefetched_resource_files_(prefetched_resource_files),
      permissions_(permissions),
#if defined(OS_WIN)
      process_launched_by_broker_(false),
#endif
      reply_msg_(NULL),
#if defined(OS_WIN)
      debug_exception_handler_requested_(false),
#endif
      uses_nonsfi_mode_(uses_nonsfi_mode),
      enable_debug_stub_(false),
      enable_crash_throttling_(false),
      off_the_record_(off_the_record),
      process_type_(process_type),
      profile_directory_(profile_directory),
      render_view_id_(render_view_id),
      weak_factory_(this) {
  process_.reset(content::BrowserChildProcessHost::Create(
      static_cast<content::ProcessType>(PROCESS_TYPE_NACL_LOADER), this,
      kNaClLoaderServiceName));

  // Set the display name so the user knows what plugin the process is running.
  // We aren't on the UI thread so getting the pref locale for language
  // formatting isn't possible, so IDN will be lost, but this is probably OK
  // for this use case.
  process_->SetName(url_formatter::FormatUrl(manifest_url_));

  enable_debug_stub_ = base::CommandLine::ForCurrentProcess()->HasSwitch(
      switches::kEnableNaClDebug);
  DCHECK(process_type_ != kUnknownNaClProcessType);
  enable_crash_throttling_ = process_type_ != kNativeNaClProcessType;
}

NaClProcessHost::~NaClProcessHost() {
  // Report exit status only if the process was successfully started.
  if (process_->GetData().handle != base::kNullProcessHandle) {
    content::ChildProcessTerminationInfo info =
        process_->GetTerminationInfo(false /* known_dead */);
    std::string message =
        base::StringPrintf("NaCl process exited with status %i (0x%x)",
                           info.exit_code, info.exit_code);
    if (info.exit_code == 0) {
      VLOG(1) << message;
    } else {
      LOG(ERROR) << message;
    }
    NaClBrowser::GetInstance()->OnProcessEnd(process_->GetData().id);
  }

  // Note: this does not work on Windows, though we currently support this
  // prefetching feature only on POSIX platforms, so it should be ok.
#if defined(OS_WIN)
  DCHECK(prefetched_resource_files_.empty());
#else
  for (size_t i = 0; i < prefetched_resource_files_.size(); ++i) {
    // The process failed to launch for some reason. Close resource file
    // handles.
    base::File file(IPC::PlatformFileForTransitToFile(
        prefetched_resource_files_[i].file));
    base::PostTaskWithTraits(FROM_HERE,
                             {base::TaskPriority::BACKGROUND, base::MayBlock()},
                             base::BindOnce(&CloseFile, std::move(file)));
  }
#endif
  // Open files need to be closed on the blocking pool.
  if (nexe_file_.IsValid()) {
    base::PostTaskWithTraits(FROM_HERE,
                             {base::TaskPriority::BACKGROUND, base::MayBlock()},
                             base::BindOnce(&CloseFile, std::move(nexe_file_)));
  }

  if (reply_msg_) {
    // The process failed to launch for some reason.
    // Don't keep the renderer hanging.
    reply_msg_->set_reply_error();
    nacl_host_message_filter_->Send(reply_msg_);
  }
#if defined(OS_WIN)
  if (process_launched_by_broker_) {
    NaClBrokerService::GetInstance()->OnLoaderDied();
  }
#endif
}

void NaClProcessHost::OnProcessCrashed(int exit_status) {
  if (enable_crash_throttling_ &&
      !base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kDisablePnaclCrashThrottling)) {
    NaClBrowser::GetInstance()->OnProcessCrashed();
  }
}

// This is called at browser startup.
// static
void NaClProcessHost::EarlyStartup() {
  NaClBrowser::GetInstance()->EarlyStartup();
  // Inform NaClBrowser that we exist and will have a debug port at some point.
#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
  // Open the IRT file early to make sure that it isn't replaced out from
  // under us by autoupdate.
  NaClBrowser::GetInstance()->EnsureIrtAvailable();
#endif
  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
  UMA_HISTOGRAM_BOOLEAN(
      "NaCl.nacl-gdb",
      !cmd->GetSwitchValuePath(switches::kNaClGdb).empty());
  UMA_HISTOGRAM_BOOLEAN(
      "NaCl.nacl-gdb-script",
      !cmd->GetSwitchValuePath(switches::kNaClGdbScript).empty());
  UMA_HISTOGRAM_BOOLEAN(
      "NaCl.enable-nacl-debug",
      cmd->HasSwitch(switches::kEnableNaClDebug));
  std::string nacl_debug_mask =
      cmd->GetSwitchValueASCII(switches::kNaClDebugMask);
  // By default, exclude debugging SSH and the PNaCl translator.
  // about::flags only allows empty flags as the default, so replace
  // the empty setting with the default. To debug all apps, use a wild-card.
  if (nacl_debug_mask.empty()) {
    nacl_debug_mask = "!*://*/*ssh_client.nmf,chrome://pnacl-translator/*";
  }
  NaClBrowser::GetDelegate()->SetDebugPatterns(nacl_debug_mask);
}

void NaClProcessHost::Launch(
    NaClHostMessageFilter* nacl_host_message_filter,
    IPC::Message* reply_msg,
    const base::FilePath& manifest_path) {
  nacl_host_message_filter_ = nacl_host_message_filter;
  reply_msg_ = reply_msg;
  manifest_path_ = manifest_path;

  // Do not launch the requested NaCl module if NaCl is marked "unstable" due
  // to too many crashes within a given time period.
  if (enable_crash_throttling_ &&
      !base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kDisablePnaclCrashThrottling) &&
      NaClBrowser::GetInstance()->IsThrottled()) {
    SendErrorToRenderer("Process creation was throttled due to excessive"
                        " crashes");
    delete this;
    return;
  }

  const base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
#if defined(OS_WIN)
  if (cmd->HasSwitch(switches::kEnableNaClDebug) &&
      !cmd->HasSwitch(service_manager::switches::kNoSandbox)) {
    // We don't switch off sandbox automatically for security reasons.
    SendErrorToRenderer("NaCl's GDB debug stub requires --no-sandbox flag"
                        " on Windows. See crbug.com/265624.");
    delete this;
    return;
  }
#endif
  if (cmd->HasSwitch(switches::kNaClGdb) &&
      !cmd->HasSwitch(switches::kEnableNaClDebug)) {
    LOG(WARNING) << "--nacl-gdb flag requires --enable-nacl-debug flag";
  }

  // Start getting the IRT open asynchronously while we launch the NaCl process.
  // We'll make sure this actually finished in StartWithLaunchedProcess, below.
  NaClBrowser* nacl_browser = NaClBrowser::GetInstance();
  nacl_browser->EnsureAllResourcesAvailable();
  if (!nacl_browser->IsOk()) {
    SendErrorToRenderer("could not find all the resources needed"
                        " to launch the process");
    delete this;
    return;
  }

  if (uses_nonsfi_mode_) {
    bool nonsfi_mode_forced_by_command_line = false;
    bool nonsfi_mode_allowed = false;
#if defined(OS_LINUX)
    nonsfi_mode_forced_by_command_line =
        cmd->HasSwitch(switches::kEnableNaClNonSfiMode);
#if defined(OS_CHROMEOS) && \
    (defined(ARCH_CPU_X86_FAMILY) || defined(ARCH_CPU_ARMEL))
    nonsfi_mode_allowed = NaClBrowser::GetDelegate()->IsNonSfiModeAllowed(
        nacl_host_message_filter->profile_directory(), manifest_url_);
#endif
#endif
    bool nonsfi_mode_enabled =
        nonsfi_mode_forced_by_command_line || nonsfi_mode_allowed;

    if (!nonsfi_mode_enabled) {
      SendErrorToRenderer(
          "NaCl non-SFI mode is not available for this platform"
          " and NaCl module.");
      delete this;
      return;
    }
  }

  // Create a shared memory region that the renderer and plugin share for
  // reporting crash information.
  crash_info_shmem_.CreateAnonymous(kNaClCrashInfoShmemSize);

  // Launch the process
  if (!LaunchSelLdr()) {
    delete this;
  }
}

void NaClProcessHost::OnChannelConnected(int32_t peer_pid) {
  if (!base::CommandLine::ForCurrentProcess()->GetSwitchValuePath(
          switches::kNaClGdb).empty()) {
    LaunchNaClGdb();
  }
}

#if defined(OS_WIN)
void NaClProcessHost::OnProcessLaunchedByBroker(base::ProcessHandle handle) {
  process_launched_by_broker_ = true;
  process_->SetHandle(handle);
  SetDebugStubPort(nacl::kGdbDebugStubPortUnknown);
  if (!StartWithLaunchedProcess())
    delete this;
}

void NaClProcessHost::OnDebugExceptionHandlerLaunchedByBroker(bool success) {
  IPC::Message* reply = attach_debug_exception_handler_reply_msg_.release();
  NaClProcessMsg_AttachDebugExceptionHandler::WriteReplyParams(reply, success);
  Send(reply);
}
#endif

// Needed to handle sync messages in OnMessageReceived.
bool NaClProcessHost::Send(IPC::Message* msg) {
  return process_->Send(msg);
}

void NaClProcessHost::LaunchNaClGdb() {
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();
#if defined(OS_WIN)
  base::FilePath nacl_gdb =
      command_line.GetSwitchValuePath(switches::kNaClGdb);
  base::CommandLine cmd_line(nacl_gdb);
#else
  base::CommandLine::StringType nacl_gdb =
      command_line.GetSwitchValueNative(switches::kNaClGdb);
  // We don't support spaces inside arguments in --nacl-gdb switch.
  base::CommandLine cmd_line(base::SplitString(
      nacl_gdb, base::CommandLine::StringType(1, ' '),
      base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL));
#endif
  cmd_line.AppendArg("--eval-command");
  base::FilePath::StringType irt_path(
      NaClBrowser::GetInstance()->GetIrtFilePath().value());
  // Avoid back slashes because nacl-gdb uses posix escaping rules on Windows.
  // See issue https://code.google.com/p/nativeclient/issues/detail?id=3482.
  std::replace(irt_path.begin(), irt_path.end(), '\\', '/');
  cmd_line.AppendArgNative(FILE_PATH_LITERAL("nacl-irt \"") + irt_path +
                           FILE_PATH_LITERAL("\""));
  if (!manifest_path_.empty()) {
    cmd_line.AppendArg("--eval-command");
    base::FilePath::StringType manifest_path_value(manifest_path_.value());
    std::replace(manifest_path_value.begin(), manifest_path_value.end(),
                 '\\', '/');
    cmd_line.AppendArgNative(FILE_PATH_LITERAL("nacl-manifest \"") +
                             manifest_path_value + FILE_PATH_LITERAL("\""));
  }
  cmd_line.AppendArg("--eval-command");
  cmd_line.AppendArg("target remote :4014");
  base::FilePath script =
      command_line.GetSwitchValuePath(switches::kNaClGdbScript);
  if (!script.empty()) {
    cmd_line.AppendArg("--command");
    cmd_line.AppendArgNative(script.value());
  }
  base::LaunchProcess(cmd_line, base::LaunchOptions());
}

bool NaClProcessHost::LaunchSelLdr() {
  process_->GetHost()->CreateChannelMojo();

  // Build command line for nacl.

#if defined(OS_LINUX)
  int flags = ChildProcessHost::CHILD_ALLOW_SELF;
#else
  int flags = ChildProcessHost::CHILD_NORMAL;
#endif

  base::FilePath exe_path = ChildProcessHost::GetChildPath(flags);
  if (exe_path.empty())
    return false;

#if defined(OS_WIN)
  // On Windows 64-bit NaCl loader is called nacl64.exe instead of chrome.exe
  if (RunningOnWOW64()) {
    if (!NaClBrowser::GetInstance()->GetNaCl64ExePath(&exe_path)) {
      SendErrorToRenderer("could not get path to nacl64.exe");
      return false;
    }

#ifdef _DLL
    // When using the DLL CRT on Windows, we need to amend the PATH to include
    // the location of the x64 CRT DLLs. This is only the case when using a
    // component=shared_library build (i.e. generally dev debug builds). The
    // x86 CRT DLLs are in e.g. out\Debug for chrome.exe etc., so the x64 ones
    // are put in out\Debug\x64 which we add to the PATH here so that loader
    // can find them. See http://crbug.com/346034.
    std::unique_ptr<base::Environment> env(base::Environment::Create());
    static const char kPath[] = "PATH";
    std::string old_path;
    base::FilePath module_path;
    if (!PathService::Get(base::FILE_MODULE, &module_path)) {
      SendErrorToRenderer("could not get path to current module");
      return false;
    }
    std::string x64_crt_path =
        base::WideToUTF8(module_path.DirName().Append(L"x64").value());
    if (!env->GetVar(kPath, &old_path)) {
      env->SetVar(kPath, x64_crt_path);
    } else if (!IsInPath(old_path, x64_crt_path)) {
      std::string new_path(old_path);
      new_path.append(";");
      new_path.append(x64_crt_path);
      env->SetVar(kPath, new_path);
    }
#endif  // _DLL
  }
#endif

  std::unique_ptr<base::CommandLine> cmd_line(new base::CommandLine(exe_path));
  CopyNaClCommandLineArguments(cmd_line.get());

  cmd_line->AppendSwitchASCII(switches::kProcessType,
                              (uses_nonsfi_mode_ ?
                               switches::kNaClLoaderNonSfiProcess :
                               switches::kNaClLoaderProcess));
  if (NaClBrowser::GetDelegate()->DialogsAreSuppressed())
    cmd_line->AppendSwitch(switches::kNoErrorDialogs);

#if defined(OS_WIN)
  cmd_line->AppendArg(switches::kPrefetchArgumentOther);
#endif  // defined(OS_WIN)

// On Windows we might need to start the broker process to launch a new loader
#if defined(OS_WIN)
  if (RunningOnWOW64()) {
    if (!NaClBrokerService::GetInstance()->LaunchLoader(
            weak_factory_.GetWeakPtr(),
            process_->TakeInProcessServiceRequest())) {
      SendErrorToRenderer("broker service did not launch process");
      return false;
    }
    return true;
  }
#endif
  process_->Launch(std::make_unique<NaClSandboxedProcessLauncherDelegate>(),
                   std::move(cmd_line), true);
  return true;
}

bool NaClProcessHost::OnMessageReceived(const IPC::Message& msg) {
  if (uses_nonsfi_mode_) {
    // IPC messages relating to NaCl's validation cache must not be exposed
    // in Non-SFI Mode, otherwise a Non-SFI nexe could use SetKnownToValidate
    // to create a hole in the SFI sandbox.
    // In Non-SFI mode, no message is expected.
    return false;
  }

  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(NaClProcessHost, msg)
    IPC_MESSAGE_HANDLER(NaClProcessMsg_QueryKnownToValidate,
                        OnQueryKnownToValidate)
    IPC_MESSAGE_HANDLER(NaClProcessMsg_SetKnownToValidate,
                        OnSetKnownToValidate)
    IPC_MESSAGE_HANDLER(NaClProcessMsg_ResolveFileToken,
                        OnResolveFileToken)

#if defined(OS_WIN)
    IPC_MESSAGE_HANDLER_DELAY_REPLY(
        NaClProcessMsg_AttachDebugExceptionHandler,
        OnAttachDebugExceptionHandler)
    IPC_MESSAGE_HANDLER(NaClProcessHostMsg_DebugStubPortSelected,
                        OnDebugStubPortSelected)
#endif
    IPC_MESSAGE_HANDLER(NaClProcessHostMsg_PpapiChannelsCreated,
                        OnPpapiChannelsCreated)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()
  return handled;
}

void NaClProcessHost::OnProcessLaunched() {
  if (!StartWithLaunchedProcess())
    delete this;
}

// Called when the NaClBrowser singleton has been fully initialized.
void NaClProcessHost::OnResourcesReady() {
  NaClBrowser* nacl_browser = NaClBrowser::GetInstance();
  if (!nacl_browser->IsReady()) {
    SendErrorToRenderer("could not acquire shared resources needed by NaCl");
    delete this;
  } else if (!StartNaClExecution()) {
    delete this;
  }
}

void NaClProcessHost::ReplyToRenderer(
    mojo::ScopedMessagePipeHandle ppapi_channel_handle,
    mojo::ScopedMessagePipeHandle trusted_channel_handle,
    mojo::ScopedMessagePipeHandle manifest_service_channel_handle) {
  // Hereafter, we always send an IPC message with handles created above
  // which, on Windows, are not closable in this process.
  std::string error_message;
  base::SharedMemoryHandle crash_info_shmem_renderer_handle =
      crash_info_shmem_.handle().Duplicate();
  if (!crash_info_shmem_renderer_handle.IsValid()) {
    // On error, we do not send "IPC::ChannelHandle"s to the renderer process.
    // Note that some other FDs/handles still get sent to the renderer, but
    // will be closed there.
    ppapi_channel_handle.reset();
    trusted_channel_handle.reset();
    manifest_service_channel_handle.reset();
    error_message = "handle duplication failed";
  }

  const ChildProcessData& data = process_->GetData();
  SendMessageToRenderer(
      NaClLaunchResult(ppapi_channel_handle.release(),
                       trusted_channel_handle.release(),
                       manifest_service_channel_handle.release(),
                       base::GetProcId(data.handle),
                       data.id,
                       crash_info_shmem_renderer_handle),
      error_message);

  // Now that the crash information shmem handles have been shared with the
  // plugin and the renderer, the browser can close its handle.
  crash_info_shmem_.Close();
}

void NaClProcessHost::SendErrorToRenderer(const std::string& error_message) {
  LOG(ERROR) << "NaCl process launch failed: " << error_message;
  SendMessageToRenderer(NaClLaunchResult(), error_message);
}

void NaClProcessHost::SendMessageToRenderer(
    const NaClLaunchResult& result,
    const std::string& error_message) {
  DCHECK(nacl_host_message_filter_.get());
  DCHECK(reply_msg_);
  if (nacl_host_message_filter_.get() == NULL || reply_msg_ == NULL) {
    // As DCHECKed above, this case should not happen in general.
    // Though, in this case, unfortunately there is no proper way to release
    // resources which are already created in |result|. We just give up on
    // releasing them, and leak them.
    return;
  }

  NaClHostMsg_LaunchNaCl::WriteReplyParams(reply_msg_, result, error_message);
  nacl_host_message_filter_->Send(reply_msg_);
  nacl_host_message_filter_ = NULL;
  reply_msg_ = NULL;
}

void NaClProcessHost::SetDebugStubPort(int port) {
  NaClBrowser* nacl_browser = NaClBrowser::GetInstance();
  nacl_browser->SetProcessGdbDebugStubPort(process_->GetData().id, port);
}

#if defined(OS_POSIX)
// TCP port we chose for NaCl debug stub. It can be any other number.
static const uint16_t kInitialDebugStubPort = 4014;

net::SocketDescriptor NaClProcessHost::GetDebugStubSocketHandle() {
  // We always try to allocate the default port first. If this fails, we then
  // allocate any available port.
  // On success, if the test system has register a handler
  // (GdbDebugStubPortListener), we fire a notification.
  uint16_t port = kInitialDebugStubPort;
  net::SocketDescriptor s =
      net::CreatePlatformSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s != net::kInvalidSocket) {
    // Allow rapid reuse.
    static const int kOn = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &kOn, sizeof(kOn));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = base::HostToNet16(port);
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) {
      // Try allocate any available port.
      addr.sin_port = base::HostToNet16(0);
      if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) {
        close(s);
        LOG(ERROR) << "Could not bind socket to port" << port;
        s = net::kInvalidSocket;
      } else {
        sockaddr_in sock_addr;
        socklen_t sock_addr_size = sizeof(sock_addr);
        if (getsockname(s, reinterpret_cast<struct sockaddr*>(&sock_addr),
                        &sock_addr_size) != 0 ||
            sock_addr_size != sizeof(sock_addr)) {
          LOG(ERROR) << "Could not determine bound port, getsockname() failed";
          close(s);
          s = net::kInvalidSocket;
        } else {
          port = base::NetToHost16(sock_addr.sin_port);
        }
      }
    }
  }

  if (s != net::kInvalidSocket) {
    SetDebugStubPort(port);
  }
  if (s == net::kInvalidSocket) {
    LOG(ERROR) << "failed to open socket for debug stub";
    return net::kInvalidSocket;
  }
  LOG(WARNING) << "debug stub on port " << port;
  if (listen(s, 1)) {
    LOG(ERROR) << "listen() failed on debug stub socket";
    if (IGNORE_EINTR(close(s)) < 0)
      PLOG(ERROR) << "failed to close debug stub socket";
    return net::kInvalidSocket;
  }
  return s;
}
#endif

#if defined(OS_WIN)
void NaClProcessHost::OnDebugStubPortSelected(uint16_t debug_stub_port) {
  CHECK(!uses_nonsfi_mode_);
  SetDebugStubPort(debug_stub_port);
}
#endif

bool NaClProcessHost::StartNaClExecution() {
  NaClBrowser* nacl_browser = NaClBrowser::GetInstance();

  NaClStartParams params;

  params.process_type = process_type_;
  bool enable_nacl_debug = enable_debug_stub_ &&
      NaClBrowser::GetDelegate()->URLMatchesDebugPatterns(manifest_url_);
  if (uses_nonsfi_mode_) {
    // Currently, non-SFI mode is supported only on Linux.
    if (enable_nacl_debug) {
      base::ProcessId pid = base::GetProcId(process_->GetData().handle);
      LOG(WARNING) << "nonsfi nacl plugin running in " << pid;
    }
  } else {
    params.validation_cache_enabled = nacl_browser->ValidationCacheIsEnabled();
    params.validation_cache_key = nacl_browser->GetValidationCacheKey();
    params.version = NaClBrowser::GetDelegate()->GetVersionString();
    params.enable_debug_stub = enable_nacl_debug;

    const base::File& irt_file = nacl_browser->IrtFile();
    CHECK(irt_file.IsValid());
    // Send over the IRT file handle.  We don't close our own copy!
    params.irt_handle = IPC::GetPlatformFileForTransit(
        irt_file.GetPlatformFile(), false);
    if (params.irt_handle == IPC::InvalidPlatformFileForTransit()) {
      return false;
    }

#if defined(OS_POSIX)
    if (params.enable_debug_stub) {
      net::SocketDescriptor server_bound_socket = GetDebugStubSocketHandle();
      if (server_bound_socket != net::kInvalidSocket) {
        params.debug_stub_server_bound_socket = IPC::GetPlatformFileForTransit(
            server_bound_socket, true);
      }
    }
#endif
  }

  params.crash_info_shmem_handle = crash_info_shmem_.handle().Duplicate();
  if (!params.crash_info_shmem_handle.IsValid()) {
    DLOG(ERROR) << "Failed to duplicate a shared memory buffer";
    return false;
  }

  // Pass the pre-opened resource files to the loader. We do not have to reopen
  // resource files here even for SFI mode because the descriptors are not from
  // a renderer.
  for (size_t i = 0; i < prefetched_resource_files_.size(); ++i) {
    process_->Send(new NaClProcessMsg_AddPrefetchedResource(
        NaClResourcePrefetchResult(
            prefetched_resource_files_[i].file,
            // For the same reason as the comment below, always use an empty
            // base::FilePath for non-SFI mode.
            (uses_nonsfi_mode_ ? base::FilePath() :
             prefetched_resource_files_[i].file_path_metadata),
            prefetched_resource_files_[i].file_key)));
  }
  prefetched_resource_files_.clear();

  base::FilePath file_path;
  if (uses_nonsfi_mode_) {
    // Don't retrieve the file path when using nonsfi mode; there's no
    // validation caching in that case, so it's unnecessary work, and would
    // expose the file path to the plugin.
  } else {
    if (NaClBrowser::GetInstance()->GetFilePath(nexe_token_.lo,
                                                nexe_token_.hi,
                                                &file_path)) {
      // We have to reopen the file in the browser process; we don't want a
      // compromised renderer to pass an arbitrary fd that could get loaded
      // into the plugin process.
      base::PostTaskWithTraitsAndReplyWithResult(
          FROM_HERE, {base::MayBlock(), base::TaskPriority::BACKGROUND},
          base::Bind(OpenNaClReadExecImpl, file_path, true /* is_executable */),
          base::Bind(&NaClProcessHost::StartNaClFileResolved,
                     weak_factory_.GetWeakPtr(), params, file_path));
      return true;
    }
  }

  StartNaClFileResolved(params, base::FilePath(), base::File());
  return true;
}

void NaClProcessHost::StartNaClFileResolved(
    NaClStartParams params,
    const base::FilePath& file_path,
    base::File checked_nexe_file) {
  if (checked_nexe_file.IsValid()) {
    // Release the file received from the renderer. This has to be done on a
    // thread where IO is permitted, though.
    base::PostTaskWithTraits(FROM_HERE,
                             {base::TaskPriority::BACKGROUND, base::MayBlock()},
                             base::BindOnce(&CloseFile, std::move(nexe_file_)));
    params.nexe_file_path_metadata = file_path;
    params.nexe_file =
        IPC::TakePlatformFileForTransit(std::move(checked_nexe_file));
  } else {
    params.nexe_file = IPC::TakePlatformFileForTransit(std::move(nexe_file_));
  }

#if defined(OS_LINUX)
  // In Non-SFI mode, create socket pairs for IPC channels here, unlike in
  // SFI-mode, in which those channels are created in nacl_listener.cc.
  // This is for security hardening. We can then prohibit the socketpair()
  // system call in nacl_helper and nacl_helper_nonsfi.
  if (uses_nonsfi_mode_) {
    mojo::MessagePipe ppapi_browser_channel;
    mojo::MessagePipe ppapi_renderer_channel;
    mojo::MessagePipe trusted_service_channel;
    mojo::MessagePipe manifest_service_channel;

    if (!StartPPAPIProxy(std::move(ppapi_browser_channel.handle1))) {
      SendErrorToRenderer("Failed to start browser PPAPI proxy.");
      return;
    }

    // On success, send back a success message to the renderer process,
    // and transfer the channel handles for the NaCl loader process to
    // |params|.
    ReplyToRenderer(std::move(ppapi_renderer_channel.handle1),
                    std::move(trusted_service_channel.handle1),
                    std::move(manifest_service_channel.handle1));
    params.ppapi_browser_channel_handle =
        ppapi_browser_channel.handle0.release();
    params.ppapi_renderer_channel_handle =
        ppapi_renderer_channel.handle0.release();
    params.trusted_service_channel_handle =
        trusted_service_channel.handle0.release();
    params.manifest_service_channel_handle =
        manifest_service_channel.handle0.release();
  }
#endif

  process_->Send(new NaClProcessMsg_Start(params));
}

bool NaClProcessHost::StartPPAPIProxy(
    mojo::ScopedMessagePipeHandle channel_handle) {
  if (ipc_proxy_channel_.get()) {
    // Attempt to open more than 1 browser channel is not supported.
    // Shut down the NaCl process.
    process_->GetHost()->ForceShutdown();
    return false;
  }

  DCHECK_EQ(PROCESS_TYPE_NACL_LOADER, process_->GetData().process_type);

  ipc_proxy_channel_ = IPC::ChannelProxy::Create(
      channel_handle.release(), IPC::Channel::MODE_CLIENT, NULL,
      base::ThreadTaskRunnerHandle::Get().get(),
      base::ThreadTaskRunnerHandle::Get().get());
  // Create the browser ppapi host and enable PPAPI message dispatching to the
  // browser process.
  ppapi_host_.reset(content::BrowserPpapiHost::CreateExternalPluginProcess(
      ipc_proxy_channel_.get(),  // sender
      permissions_,
      process_->GetData().handle,
      ipc_proxy_channel_.get(),
      nacl_host_message_filter_->render_process_id(),
      render_view_id_,
      profile_directory_));

  ppapi::PpapiNaClPluginArgs args;
  args.off_the_record = nacl_host_message_filter_->off_the_record();
  args.permissions = permissions_;
  base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();
  DCHECK(cmdline);
  std::string flag_whitelist[] = {
    switches::kV,
    switches::kVModule,
  };
  for (size_t i = 0; i < arraysize(flag_whitelist); ++i) {
    std::string value = cmdline->GetSwitchValueASCII(flag_whitelist[i]);
    if (!value.empty()) {
      args.switch_names.push_back(flag_whitelist[i]);
      args.switch_values.push_back(value);
    }
  }

  ppapi_host_->GetPpapiHost()->AddHostFactoryFilter(
      std::unique_ptr<ppapi::host::HostFactory>(
          NaClBrowser::GetDelegate()->CreatePpapiHostFactory(
              ppapi_host_.get())));

  // Send a message to initialize the IPC dispatchers in the NaCl plugin.
  ipc_proxy_channel_->Send(new PpapiMsg_InitializeNaClDispatcher(args));
  return true;
}

// This method is called when NaClProcessHostMsg_PpapiChannelCreated is
// received.
void NaClProcessHost::OnPpapiChannelsCreated(
    const IPC::ChannelHandle& raw_ppapi_browser_channel_handle,
    const IPC::ChannelHandle& raw_ppapi_renderer_channel_handle,
    const IPC::ChannelHandle& raw_trusted_renderer_channel_handle,
    const IPC::ChannelHandle& raw_manifest_service_channel_handle) {
  DCHECK(raw_ppapi_browser_channel_handle.is_mojo_channel_handle());
  DCHECK(raw_ppapi_renderer_channel_handle.is_mojo_channel_handle());
  DCHECK(raw_trusted_renderer_channel_handle.is_mojo_channel_handle());
  DCHECK(raw_manifest_service_channel_handle.is_mojo_channel_handle());

  mojo::ScopedMessagePipeHandle ppapi_browser_channel_handle(
      raw_ppapi_browser_channel_handle.mojo_handle);
  mojo::ScopedMessagePipeHandle ppapi_renderer_channel_handle(
      raw_ppapi_renderer_channel_handle.mojo_handle);
  mojo::ScopedMessagePipeHandle trusted_renderer_channel_handle(
      raw_trusted_renderer_channel_handle.mojo_handle);
  mojo::ScopedMessagePipeHandle manifest_service_channel_handle(
      raw_manifest_service_channel_handle.mojo_handle);

  if (!StartPPAPIProxy(std::move(ppapi_browser_channel_handle))) {
    SendErrorToRenderer("Browser PPAPI proxy could not start.");
    return;
  }

  // Let the renderer know that the IPC channels are established.
  ReplyToRenderer(std::move(ppapi_renderer_channel_handle),
                  std::move(trusted_renderer_channel_handle),
                  std::move(manifest_service_channel_handle));
}

bool NaClProcessHost::StartWithLaunchedProcess() {
  NaClBrowser* nacl_browser = NaClBrowser::GetInstance();

  if (nacl_browser->IsReady())
    return StartNaClExecution();
  if (nacl_browser->IsOk()) {
    nacl_browser->WaitForResources(
        base::Bind(&NaClProcessHost::OnResourcesReady,
                   weak_factory_.GetWeakPtr()));
    return true;
  }
  SendErrorToRenderer("previously failed to acquire shared resources");
  return false;
}

void NaClProcessHost::OnQueryKnownToValidate(const std::string& signature,
                                             bool* result) {
  CHECK(!uses_nonsfi_mode_);
  NaClBrowser* nacl_browser = NaClBrowser::GetInstance();
  *result = nacl_browser->QueryKnownToValidate(signature, off_the_record_);
}

void NaClProcessHost::OnSetKnownToValidate(const std::string& signature) {
  CHECK(!uses_nonsfi_mode_);
  NaClBrowser::GetInstance()->SetKnownToValidate(
      signature, off_the_record_);
}

void NaClProcessHost::OnResolveFileToken(uint64_t file_token_lo,
                                         uint64_t file_token_hi) {
  // Was the file registered?
  //
  // Note that the file path cache is of bounded size, and old entries can get
  // evicted.  If a large number of NaCl modules are being launched at once,
  // resolving the file_token may fail because the path cache was thrashed
  // while the file_token was in flight.  In this case the query fails, and we
  // need to fall back to the slower path.
  //
  // However: each NaCl process will consume 2-3 entries as it starts up, this
  // means that eviction will not happen unless you start up 33+ NaCl processes
  // at the same time, and this still requires worst-case timing.  As a
  // practical matter, no entries should be evicted prematurely.
  // The cache itself should take ~ (150 characters * 2 bytes/char + ~60 bytes
  // data structure overhead) * 100 = 35k when full, so making it bigger should
  // not be a problem, if needed.
  //
  // Each NaCl process will consume 2-3 entries because the manifest and main
  // nexe are currently not resolved.  Shared libraries will be resolved.  They
  // will be loaded sequentially, so they will only consume a single entry
  // while the load is in flight.
  //
  // TODO(ncbray): track behavior with UMA. If entries are getting evicted or
  // bogus keys are getting queried, this would be good to know.
  CHECK(!uses_nonsfi_mode_);
  base::FilePath file_path;
  if (!NaClBrowser::GetInstance()->GetFilePath(
        file_token_lo, file_token_hi, &file_path)) {
    Send(new NaClProcessMsg_ResolveFileTokenReply(
             file_token_lo,
             file_token_hi,
             IPC::PlatformFileForTransit(),
             base::FilePath()));
    return;
  }

  // Open the file.
  base::PostTaskWithTraitsAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::BACKGROUND},
      base::Bind(OpenNaClReadExecImpl, file_path, true /* is_executable */),
      base::Bind(&NaClProcessHost::FileResolved, weak_factory_.GetWeakPtr(),
                 file_token_lo, file_token_hi, file_path));
}

void NaClProcessHost::FileResolved(
    uint64_t file_token_lo,
    uint64_t file_token_hi,
    const base::FilePath& file_path,
    base::File file) {
  base::FilePath out_file_path;
  IPC::PlatformFileForTransit out_handle;
  if (file.IsValid()) {
    out_file_path = file_path;
    out_handle = IPC::TakePlatformFileForTransit(std::move(file));
  } else {
    out_handle = IPC::InvalidPlatformFileForTransit();
  }
  Send(new NaClProcessMsg_ResolveFileTokenReply(
           file_token_lo,
           file_token_hi,
           out_handle,
           out_file_path));
}

#if defined(OS_WIN)
void NaClProcessHost::OnAttachDebugExceptionHandler(const std::string& info,
                                                    IPC::Message* reply_msg) {
  CHECK(!uses_nonsfi_mode_);
  if (!AttachDebugExceptionHandler(info, reply_msg)) {
    // Send failure message.
    NaClProcessMsg_AttachDebugExceptionHandler::WriteReplyParams(reply_msg,
                                                                 false);
    Send(reply_msg);
  }
}

bool NaClProcessHost::AttachDebugExceptionHandler(const std::string& info,
                                                  IPC::Message* reply_msg) {
  bool enable_exception_handling = process_type_ == kNativeNaClProcessType;
  if (!enable_exception_handling && !enable_debug_stub_) {
    DLOG(ERROR) <<
        "Debug exception handler requested by NaCl process when not enabled";
    return false;
  }
  if (debug_exception_handler_requested_) {
    // The NaCl process should not request this multiple times.
    DLOG(ERROR) << "Multiple AttachDebugExceptionHandler requests received";
    return false;
  }
  debug_exception_handler_requested_ = true;

  base::ProcessId nacl_pid = base::GetProcId(process_->GetData().handle);
  // We cannot use process_->GetData().handle because it does not have
  // the necessary access rights.  We open the new handle here rather
  // than in the NaCl broker process in case the NaCl loader process
  // dies before the NaCl broker process receives the message we send.
  // The debug exception handler uses DebugActiveProcess() to attach,
  // but this takes a PID.  We need to prevent the NaCl loader's PID
  // from being reused before DebugActiveProcess() is called, and
  // holding a process handle open achieves this.
  base::Process process =
      base::Process::OpenWithAccess(nacl_pid,
                                    PROCESS_QUERY_INFORMATION |
                                    PROCESS_SUSPEND_RESUME |
                                    PROCESS_TERMINATE |
                                    PROCESS_VM_OPERATION |
                                    PROCESS_VM_READ |
                                    PROCESS_VM_WRITE |
                                    PROCESS_DUP_HANDLE |
                                    SYNCHRONIZE);
  if (!process.IsValid()) {
    LOG(ERROR) << "Failed to get process handle";
    return false;
  }

  attach_debug_exception_handler_reply_msg_.reset(reply_msg);
  // If the NaCl loader is 64-bit, the process running its debug
  // exception handler must be 64-bit too, so we use the 64-bit NaCl
  // broker process for this.  Otherwise, on a 32-bit system, we use
  // the 32-bit browser process to run the debug exception handler.
  if (RunningOnWOW64()) {
    return NaClBrokerService::GetInstance()->LaunchDebugExceptionHandler(
               weak_factory_.GetWeakPtr(), nacl_pid, process.Handle(),
               info);
  }
  NaClStartDebugExceptionHandlerThread(
      std::move(process), info, base::ThreadTaskRunnerHandle::Get(),
      base::Bind(&NaClProcessHost::OnDebugExceptionHandlerLaunchedByBroker,
                 weak_factory_.GetWeakPtr()));
  return true;
}
#endif

}  // namespace nacl

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/browser_process_impl.h"

#include <stddef.h>

#include <algorithm>
#include <map>
#include <utility>
#include <vector>

#include "base/atomic_ref_count.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/command_line.h"
#include "base/debug/leak_annotations.h"
#include "base/files/file_path.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/metrics/histogram_macros.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/post_task.h"
#include "base/task_scheduler/task_traits.h"
#include "base/threading/thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/default_clock.h"
#include "base/time/default_tick_clock.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "chrome/browser/chrome_browser_main.h"
#include "chrome/browser/chrome_child_process_watcher.h"
#include "chrome/browser/chrome_content_browser_client.h"
#include "chrome/browser/chrome_device_client.h"
#include "chrome/browser/chrome_notification_types.h"
#include "chrome/browser/component_updater/chrome_component_updater_configurator.h"
#include "chrome/browser/component_updater/supervised_user_whitelist_installer.h"
#include "chrome/browser/defaults.h"
#include "chrome/browser/devtools/devtools_auto_opener.h"
#include "chrome/browser/devtools/remote_debugging_server.h"
#include "chrome/browser/download/download_request_limiter.h"
#include "chrome/browser/download/download_status_updater.h"
#include "chrome/browser/gpu/gpu_mode_manager.h"
#include "chrome/browser/icon_manager.h"
#include "chrome/browser/intranet_redirect_detector.h"
#include "chrome/browser/io_thread.h"
#include "chrome/browser/lifetime/application_lifetime.h"
#include "chrome/browser/lifetime/switch_utils.h"
#include "chrome/browser/loader/chrome_resource_dispatcher_host_delegate.h"
#include "chrome/browser/metrics/chrome_metrics_service_accessor.h"
#include "chrome/browser/metrics/chrome_metrics_services_manager_client.h"
#include "chrome/browser/metrics/thread_watcher.h"
#include "chrome/browser/net/chrome_net_log_helper.h"
#include "chrome/browser/net/system_network_context_manager.h"
#include "chrome/browser/notifications/notification_platform_bridge.h"
#include "chrome/browser/notifications/notification_ui_manager.h"
#include "chrome/browser/plugins/chrome_plugin_service_filter.h"
#include "chrome/browser/plugins/plugin_finder.h"
#include "chrome/browser/policy/chrome_browser_policy_connector.h"
#include "chrome/browser/prefs/browser_prefs.h"
#include "chrome/browser/prefs/chrome_pref_service_factory.h"
#include "chrome/browser/printing/background_printing_manager.h"
#include "chrome/browser/printing/print_job_manager.h"
#include "chrome/browser/printing/print_preview_dialog_controller.h"
#include "chrome/browser/profiles/profile_manager.h"
#include "chrome/browser/resource_coordinator/tab_lifecycle_unit_source.h"
#include "chrome/browser/safe_browsing/safe_browsing_service.h"
#include "chrome/browser/shell_integration.h"
#include "chrome/browser/status_icons/status_tray.h"
#include "chrome/browser/ui/browser_dialogs.h"
#include "chrome/browser/ui/browser_finder.h"
#include "chrome/browser/update_client/chrome_update_query_params_delegate.h"
#include "chrome/common/buildflags.h"
#include "chrome/common/channel_info.h"
#include "chrome/common/chrome_constants.h"
#include "chrome/common/chrome_features.h"
#include "chrome/common/chrome_paths.h"
#include "chrome/common/chrome_switches.h"
#include "chrome/common/extensions/chrome_extensions_client.h"
#include "chrome/common/pref_names.h"
#include "chrome/common/url_constants.h"
#include "chrome/installer/util/google_update_settings.h"
#include "components/component_updater/component_updater_service.h"
#include "components/crash/core/common/crash_key.h"
#include "components/gcm_driver/gcm_driver.h"
#include "components/metrics/metrics_pref_names.h"
#include "components/metrics/metrics_service.h"
#include "components/metrics_services_manager/metrics_services_manager.h"
#include "components/net_log/chrome_net_log.h"
#include "components/network_time/network_time_tracker.h"
#include "components/optimization_guide/optimization_guide_service.h"
#include "components/physical_web/data_source/physical_web_data_source.h"
#include "components/policy/core/common/policy_service.h"
#include "components/prefs/json_pref_store.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/pref_service.h"
#include "components/previews/core/previews_features.h"
#include "components/rappor/public/rappor_utils.h"
#include "components/rappor/rappor_service_impl.h"
#include "components/signin/core/browser/profile_management_switches.h"
#include "components/subresource_filter/content/browser/content_ruleset_service.h"
#include "components/subresource_filter/core/browser/ruleset_service.h"
#include "components/subresource_filter/core/browser/subresource_filter_constants.h"
#include "components/subresource_filter/core/browser/subresource_filter_features.h"
#include "components/translate/core/browser/translate_download_manager.h"
#include "components/ukm/ukm_service.h"
#include "components/update_client/update_query_params.h"
#include "components/web_resource/web_resource_pref_names.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/child_process_security_policy.h"
#include "content/public/browser/network_service_instance.h"
#include "content/public/browser/notification_details.h"
#include "content/public/browser/plugin_service.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/resource_dispatcher_host.h"
#include "content/public/browser/service_worker_context.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/common/content_features.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/network_connection_tracker.h"
#include "content/public/common/service_manager_connection.h"
#include "extensions/buildflags/buildflags.h"
#include "extensions/common/constants.h"
#include "media/media_buildflags.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/url_request/url_request_context_getter.h"
#include "ppapi/buildflags/buildflags.h"
#include "printing/buildflags/buildflags.h"
#include "services/network/public/cpp/network_switches.h"
#include "services/preferences/public/cpp/in_process_service_factory.h"
#include "ui/base/idle/idle.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/message_center/message_center.h"

#if defined(OS_WIN)
#include "base/win/windows_version.h"
#elif defined(OS_MACOSX)
#include "chrome/browser/chrome_browser_main_mac.h"
#endif

#if defined(OS_CHROMEOS)
#include "chrome/browser/ui/ash/ash_util.h"
#endif

#if defined(OS_ANDROID)
#include "chrome/browser/android/physical_web/physical_web_data_source_android.h"
#else  // !defined(OS_ANDROID)
#include "chrome/browser/gcm/gcm_product_util.h"
#include "components/gcm_driver/gcm_client_factory.h"
#include "components/gcm_driver/gcm_desktop_utils.h"
#include "components/keep_alive_registry/keep_alive_registry.h"
#endif

#if BUILDFLAG(ENABLE_BACKGROUND_MODE)
#include "chrome/browser/background/background_mode_manager.h"
#endif

#if BUILDFLAG(ENABLE_EXTENSIONS)
#include "chrome/browser/extensions/chrome_extensions_browser_client.h"
#include "chrome/browser/extensions/event_router_forwarder.h"
#include "chrome/browser/media_galleries/media_file_system_registry.h"
#include "chrome/browser/ui/apps/chrome_app_window_client.h"
#include "components/storage_monitor/storage_monitor.h"
#include "extensions/common/extension_l10n_util.h"
#endif

#if BUILDFLAG(ENABLE_PLUGINS)
#include "chrome/browser/plugins/plugins_resource_service.h"
#endif

#if BUILDFLAG(ENABLE_WEBRTC)
#include "chrome/browser/media/webrtc/webrtc_event_log_manager.h"
#include "chrome/browser/media/webrtc/webrtc_log_uploader.h"
#endif

#if defined(OS_WIN) || defined(OS_MACOSX) || defined(OS_LINUX)
#include "chrome/browser/resource_coordinator/tab_manager.h"
#endif

#if !defined(OS_ANDROID) && !defined(OS_CHROMEOS)
#include "chrome/browser/first_run/upgrade_util.h"
#include "chrome/browser/ui/user_manager.h"
#endif

#if (defined(OS_WIN) || defined(OS_LINUX)) && !defined(OS_CHROMEOS)
// How often to check if the persistent instance of Chrome needs to restart
// to install an update.
static const int kUpdateCheckIntervalHours = 6;
#endif

#if defined(USE_X11) || defined(OS_WIN) || defined(USE_OZONE)
// How long to wait for the File thread to complete during EndSession, on Linux
// and Windows. We have a timeout here because we're unable to run the UI
// messageloop and there's some deadlock risk. Our only option is to exit
// anyway.
static constexpr base::TimeDelta kEndSessionTimeout =
    base::TimeDelta::FromSeconds(10);
#endif

using content::BrowserThread;
using content::ChildProcessSecurityPolicy;
using content::PluginService;
using content::ResourceDispatcherHost;

rappor::RapporService* GetBrowserRapporService() {
  if (g_browser_process != nullptr)
    return g_browser_process->rappor_service();
  return nullptr;
}

BrowserProcessImpl::BrowserProcessImpl(
    base::SequencedTaskRunner* local_state_task_runner)
    : local_state_task_runner_(local_state_task_runner),
      pref_service_factory_(
          std::make_unique<prefs::InProcessPrefServiceFactory>()) {
  g_browser_process = this;
  platform_part_ = std::make_unique<BrowserProcessPlatformPart>();
  // Most work should be done in Init().
}

void BrowserProcessImpl::Init() {
#if defined(OS_CHROMEOS)
  // Forces creation of |metrics_services_manager_client_| if neccessary
  // (typically this call is a no-op as MetricsServicesManager has already been
  // created).
  GetMetricsServicesManager();
  DCHECK(metrics_services_manager_client_);
  metrics_services_manager_client_->OnCrosSettingsCreated();
#endif

  download_status_updater_ = std::make_unique<DownloadStatusUpdater>();

  rappor::SetDefaultServiceAccessor(&GetBrowserRapporService);

#if BUILDFLAG(ENABLE_PRINTING)
  // Must be created after the NotificationService.
  print_job_manager_ = std::make_unique<printing::PrintJobManager>();
#endif

  net_log_ = std::make_unique<net_log::ChromeNetLog>();

  ChildProcessSecurityPolicy::GetInstance()->RegisterWebSafeScheme(
      chrome::kChromeSearchScheme);

#if defined(OS_MACOSX)
  ui::InitIdleMonitor();
#endif

  device_client_ = std::make_unique<ChromeDeviceClient>();

#if BUILDFLAG(ENABLE_EXTENSIONS)
  extensions::AppWindowClient::Set(ChromeAppWindowClient::GetInstance());

  extension_event_router_forwarder_ =
      base::MakeRefCounted<extensions::EventRouterForwarder>();

  extensions::ExtensionsClient::Set(
      extensions::ChromeExtensionsClient::GetInstance());

  extensions_browser_client_ =
      std::make_unique<extensions::ChromeExtensionsBrowserClient>();
  extensions::ExtensionsBrowserClient::Set(extensions_browser_client_.get());
#endif

  bool initialize_message_center = true;
#if defined(OS_CHROMEOS)
  // On Chrome OS, the message center is initialized and shut down by Ash and
  // should not be directly accessible to Chrome. However, ARC++ still relies
  // on the existence of a MessageCenter object, so in Mash, initialize one
  // here.
  initialize_message_center = ash_util::IsRunningInMash();
#endif
  if (initialize_message_center)
    message_center::MessageCenter::Initialize();

  update_client::UpdateQueryParams::SetDelegate(
      ChromeUpdateQueryParamsDelegate::GetInstance());

#if !defined(OS_ANDROID)
  KeepAliveRegistry::GetInstance()->SetIsShuttingDown(false);
  KeepAliveRegistry::GetInstance()->AddObserver(this);
#endif  // !defined(OS_ANDROID)

  pref_change_registrar_.Init(local_state());

  // Initialize the notification for the default browser setting policy.
  pref_change_registrar_.Add(
      prefs::kDefaultBrowserSettingEnabled,
      base::Bind(&BrowserProcessImpl::ApplyDefaultBrowserPolicy,
                 base::Unretained(this)));

#if !defined(OS_ANDROID)
  // This preference must be kept in sync with external values; update them
  // whenever the preference or its controlling policy changes.
  pref_change_registrar_.Add(
      metrics::prefs::kMetricsReportingEnabled,
      base::Bind(&BrowserProcessImpl::ApplyMetricsReportingPolicy,
                 base::Unretained(this)));
#endif

  int max_per_proxy = local_state_->GetInteger(prefs::kMaxConnectionsPerProxy);
  net::ClientSocketPoolManager::set_max_sockets_per_proxy_server(
      net::HttpNetworkSession::NORMAL_SOCKET_POOL,
      std::max(std::min(max_per_proxy, 99),
               net::ClientSocketPoolManager::max_sockets_per_group(
                   net::HttpNetworkSession::NORMAL_SOCKET_POOL)));

#if BUILDFLAG(ENABLE_WEBRTC)
  DCHECK(!webrtc_event_log_manager_);
  webrtc_event_log_manager_ = WebRtcEventLogManager::CreateSingletonInstance();
#endif
}

BrowserProcessImpl::~BrowserProcessImpl() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
#if BUILDFLAG(ENABLE_EXTENSIONS)
  extensions::ExtensionsBrowserClient::Set(nullptr);
  extensions::AppWindowClient::Set(nullptr);
#endif

#if !defined(OS_ANDROID)
  KeepAliveRegistry::GetInstance()->RemoveObserver(this);
#endif  // !defined(OS_ANDROID)

  g_browser_process = NULL;
}

#if !defined(OS_ANDROID)
void BrowserProcessImpl::StartTearDown() {
  TRACE_EVENT0("shutdown", "BrowserProcessImpl::StartTearDown");
  // TODO(crbug.com/560486): Fix the tests that make the check of
  // |tearing_down_| necessary in IsShuttingDown().
  tearing_down_ = true;
  DCHECK(IsShuttingDown());

  KeepAliveRegistry::GetInstance()->SetIsShuttingDown();

  // We need to destroy the MetricsServicesManager, IntranetRedirectDetector,
  // NetworkTimeTracker, and SafeBrowsing ClientSideDetectionService
  // (owned by the SafeBrowsingService) before the io_thread_ gets destroyed,
  // since their destructors can call the URLFetcher destructor, which does a
  // PostDelayedTask operation on the IO thread. (The IO thread will handle
  // that URLFetcher operation before going away.)
  metrics_services_manager_.reset();
  intranet_redirect_detector_.reset();
  if (safe_browsing_service_.get())
    safe_browsing_service()->ShutDown();
  network_time_tracker_.reset();
#if BUILDFLAG(ENABLE_PLUGINS)
  plugins_resource_service_.reset();
#endif

  // Need to clear the desktop notification balloons before the io_thread_ and
  // before the profiles, since if there are any still showing we will access
  // those things during teardown.
  notification_ui_manager_.reset();

  // The SupervisedUserWhitelistInstaller observes the ProfileAttributesStorage,
  // so it needs to be shut down before the ProfileManager.
  supervised_user_whitelist_installer_.reset();

  // Debugger must be cleaned up before ProfileManager.
  remote_debugging_server_.reset();
  devtools_auto_opener_.reset();

  // Need to clear profiles (download managers) before the io_thread_.
  {
    TRACE_EVENT0("shutdown",
                 "BrowserProcessImpl::StartTearDown:ProfileManager");
#if !defined(OS_CHROMEOS)
    // The desktop User Manager needs to be closed before the guest profile
    // can be destroyed.
    UserManager::Hide();
#endif  // !defined(OS_CHROMEOS)
    profile_manager_.reset();
  }

  child_process_watcher_.reset();

#if BUILDFLAG(ENABLE_EXTENSIONS)
  media_file_system_registry_.reset();
  // Remove the global instance of the Storage Monitor now. Otherwise the
  // FILE thread would be gone when we try to release it in the dtor and
  // Valgrind would report a leak on almost every single browser_test.
  // TODO(gbillock): Make this unnecessary.
  storage_monitor::StorageMonitor::Destroy();
#endif

  if (message_center::MessageCenter::Get())
    message_center::MessageCenter::Shutdown();

  // The policy providers managed by |browser_policy_connector_| need to shut
  // down while the IO and FILE threads are still alive. The monitoring
  // framework owned by |browser_policy_connector_| relies on |gcm_driver_|, so
  // this must be shutdown before |gcm_driver_| below.
  if (browser_policy_connector_)
    browser_policy_connector_->Shutdown();

  // The |gcm_driver_| must shut down while the IO thread is still alive.
  if (gcm_driver_)
    gcm_driver_->Shutdown();

  // Stop the watchdog thread before stopping other threads.
  watchdog_thread_.reset();

  platform_part()->StartTearDown();

#if BUILDFLAG(ENABLE_WEBRTC)
  // Cancel any uploads to release the system url request context references.
  if (webrtc_log_uploader_)
    webrtc_log_uploader_->StartShutdown();
#endif

  if (local_state_)
    local_state_->CommitPendingWrite();

  // This expects to be destroyed before the task scheduler is torn down.
  system_network_context_manager_.reset();
}

void BrowserProcessImpl::PostDestroyThreads() {
  // With the file_thread_ flushed, we can release any icon resources.
  icon_manager_.reset();

#if BUILDFLAG(ENABLE_WEBRTC)
  // Must outlive the worker threads.
  webrtc_log_uploader_.reset();
#endif

  // Reset associated state right after actual thread is stopped,
  // as io_thread_.global_ cleanup happens in CleanUp on the IO
  // thread, i.e. as the thread exits its message loop.
  //
  // This is important also because in various places, the
  // IOThread object being NULL is considered synonymous with the
  // IO thread having stopped.
  io_thread_.reset();
}
#endif  // !defined(OS_ANDROID)

namespace {

// Used at the end of session to block the UI thread for completion of sentinel
// tasks on the set of threads used to persist profile data and local state.
// This is done to ensure that the data has been persisted to disk before
// continuing.
class RundownTaskCounter :
    public base::RefCountedThreadSafe<RundownTaskCounter> {
 public:
  RundownTaskCounter();

  // Posts a rundown task to |task_runner|, can be invoked an arbitrary number
  // of times before calling TimedWait.
  void Post(base::SequencedTaskRunner* task_runner);

  // Waits until the count is zero or |end_time| is reached.
  // This can only be called once per instance. Returns true if a count of zero
  // is reached or false if the |end_time| is reached. It is valid to pass an
  // |end_time| in the past.
  bool TimedWaitUntil(const base::TimeTicks& end_time);

 private:
  friend class base::RefCountedThreadSafe<RundownTaskCounter>;
  ~RundownTaskCounter() {}

  // Decrements the counter and releases the waitable event on transition to
  // zero.
  void Decrement();

  // The count starts at one to defer the possibility of one->zero transitions
  // until TimedWait is called.
  base::AtomicRefCount count_;
  base::WaitableEvent waitable_event_;

  DISALLOW_COPY_AND_ASSIGN(RundownTaskCounter);
};

RundownTaskCounter::RundownTaskCounter()
    : count_(1),
      waitable_event_(base::WaitableEvent::ResetPolicy::MANUAL,
                      base::WaitableEvent::InitialState::NOT_SIGNALED) {}

void RundownTaskCounter::Post(base::SequencedTaskRunner* task_runner) {
  // As the count starts off at one, it should never get to zero unless
  // TimedWait has been called.
  DCHECK(!count_.IsZero());

  count_.Increment();

  // The task must be non-nestable to guarantee that it runs after all tasks
  // currently scheduled on |task_runner| have completed.
  task_runner->PostNonNestableTask(
      FROM_HERE, base::BindOnce(&RundownTaskCounter::Decrement, this));
}

void RundownTaskCounter::Decrement() {
  if (!count_.Decrement())
    waitable_event_.Signal();
}

bool RundownTaskCounter::TimedWaitUntil(const base::TimeTicks& end_time) {
  // Decrement the excess count from the constructor.
  Decrement();

  return waitable_event_.TimedWaitUntil(end_time);
}

}  // namespace

void BrowserProcessImpl::FlushLocalStateAndReply(base::OnceClosure reply) {
  if (local_state_)
    local_state_->CommitPendingWrite();
  local_state_task_runner_->PostTaskAndReply(FROM_HERE, base::DoNothing(),
                                             std::move(reply));
}

void BrowserProcessImpl::EndSession() {
  // Mark all the profiles as clean.
  ProfileManager* pm = profile_manager();
  std::vector<Profile*> profiles(pm->GetLoadedProfiles());
  scoped_refptr<RundownTaskCounter> rundown_counter =
      base::MakeRefCounted<RundownTaskCounter>();
  for (size_t i = 0; i < profiles.size(); ++i) {
    Profile* profile = profiles[i];
    profile->SetExitType(Profile::EXIT_SESSION_ENDED);
    if (profile->GetPrefs()) {
      profile->GetPrefs()->CommitPendingWrite();
      rundown_counter->Post(profile->GetIOTaskRunner().get());
    }
  }

  // Tell the metrics service it was cleanly shutdown.
  metrics::MetricsService* metrics = g_browser_process->metrics_service();
  if (metrics && local_state_) {
    metrics->RecordStartOfSessionEnd();
#if !defined(OS_CHROMEOS)
    // MetricsService lazily writes to prefs, force it to write now.
    // On ChromeOS, chrome gets killed when hangs, so no need to
    // commit metrics::prefs::kStabilitySessionEndCompleted change immediately.
    local_state_->CommitPendingWrite();

    rundown_counter->Post(local_state_task_runner_.get());
#endif
  }

  // http://crbug.com/125207
  base::ThreadRestrictions::ScopedAllowWait allow_wait;

  // We must write that the profile and metrics service shutdown cleanly,
  // otherwise on startup we'll think we crashed. So we block until done and
  // then proceed with normal shutdown.
  //
  // If you change the condition here, be sure to also change
  // ProfileBrowserTests to match.
#if defined(USE_X11) || defined(OS_WIN) || defined(USE_OZONE)
  // Do a best-effort wait on the successful countdown of rundown tasks. Note
  // that if we don't complete "quickly enough", Windows will terminate our
  // process.
  //
  // On Windows, we previously posted a message to FILE and then ran a nested
  // message loop, waiting for that message to be processed until quitting.
  // However, doing so means that other messages will also be processed. In
  // particular, if the GPU process host notices that the GPU has been killed
  // during shutdown, it races exiting the nested loop with the process host
  // blocking the message loop attempting to re-establish a connection to the
  // GPU process synchronously. Because the system may not be allowing
  // processes to launch, this can result in a hang. See
  // http://crbug.com/318527.
  const base::TimeTicks end_time = base::TimeTicks::Now() + kEndSessionTimeout;
  rundown_counter->TimedWaitUntil(end_time);
#else
  NOTIMPLEMENTED();
#endif
}

metrics_services_manager::MetricsServicesManager*
BrowserProcessImpl::GetMetricsServicesManager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!metrics_services_manager_) {
    auto client =
        std::make_unique<ChromeMetricsServicesManagerClient>(local_state());
    metrics_services_manager_client_ = client.get();
    metrics_services_manager_ =
        std::make_unique<metrics_services_manager::MetricsServicesManager>(
            std::move(client));
  }
  return metrics_services_manager_.get();
}

metrics::MetricsService* BrowserProcessImpl::metrics_service() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return GetMetricsServicesManager()->GetMetricsService();
}

rappor::RapporServiceImpl* BrowserProcessImpl::rappor_service() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return GetMetricsServicesManager()->GetRapporServiceImpl();
}

IOThread* BrowserProcessImpl::io_thread() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(io_thread_.get());
  return io_thread_.get();
}

SystemNetworkContextManager*
BrowserProcessImpl::system_network_context_manager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(system_network_context_manager_.get());
  return system_network_context_manager_.get();
}

content::NetworkConnectionTracker*
BrowserProcessImpl::network_connection_tracker() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(io_thread_);
  if (!network_connection_tracker_) {
    network_connection_tracker_ =
        std::make_unique<content::NetworkConnectionTracker>();
    network_connection_tracker_->Initialize(content::GetNetworkService());
  }
  return network_connection_tracker_.get();
}

WatchDogThread* BrowserProcessImpl::watchdog_thread() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!created_watchdog_thread_)
    CreateWatchdogThread();
  DCHECK(watchdog_thread_.get() != NULL);
  return watchdog_thread_.get();
}

ProfileManager* BrowserProcessImpl::profile_manager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!created_profile_manager_)
    CreateProfileManager();
  return profile_manager_.get();
}

PrefService* BrowserProcessImpl::local_state() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!local_state_)
    CreateLocalState();
  return local_state_.get();
}

net::URLRequestContextGetter* BrowserProcessImpl::system_request_context() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return io_thread()->system_url_request_context_getter();
}

variations::VariationsService* BrowserProcessImpl::variations_service() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return GetMetricsServicesManager()->GetVariationsService();
}

BrowserProcessPlatformPart* BrowserProcessImpl::platform_part() {
  return platform_part_.get();
}

extensions::EventRouterForwarder*
BrowserProcessImpl::extension_event_router_forwarder() {
#if BUILDFLAG(ENABLE_EXTENSIONS)
  return extension_event_router_forwarder_.get();
#else
  return NULL;
#endif
}

NotificationUIManager* BrowserProcessImpl::notification_ui_manager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
// TODO(miguelg) return NULL for MAC as well once native notifications
// are enabled by default.
#if defined(OS_ANDROID)
  return nullptr;
#else
  if (!created_notification_ui_manager_)
    CreateNotificationUIManager();
  return notification_ui_manager_.get();
#endif
}

NotificationPlatformBridge* BrowserProcessImpl::notification_platform_bridge() {
#if BUILDFLAG(ENABLE_NATIVE_NOTIFICATIONS)
  if (!created_notification_bridge_)
    CreateNotificationPlatformBridge();
  return notification_bridge_.get();
#else
  return nullptr;
#endif
}

policy::ChromeBrowserPolicyConnector*
BrowserProcessImpl::browser_policy_connector() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!created_browser_policy_connector_) {
    DCHECK(!browser_policy_connector_);
    browser_policy_connector_ = platform_part_->CreateBrowserPolicyConnector();
    created_browser_policy_connector_ = true;
  }
  return browser_policy_connector_.get();
}

policy::PolicyService* BrowserProcessImpl::policy_service() {
  return browser_policy_connector()->GetPolicyService();
}

IconManager* BrowserProcessImpl::icon_manager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!created_icon_manager_)
    CreateIconManager();
  return icon_manager_.get();
}

GpuModeManager* BrowserProcessImpl::gpu_mode_manager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!gpu_mode_manager_)
    gpu_mode_manager_ = std::make_unique<GpuModeManager>();
  return gpu_mode_manager_.get();
}

void BrowserProcessImpl::CreateDevToolsProtocolHandler() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
#if !defined(OS_ANDROID)
  // StartupBrowserCreator::LaunchBrowser can be run multiple times when browser
  // is started with several profiles or existing browser process is reused.
  if (!remote_debugging_server_) {
    remote_debugging_server_ = std::make_unique<RemoteDebuggingServer>();
  }
#endif
}

void BrowserProcessImpl::CreateDevToolsAutoOpener() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
#if !defined(OS_ANDROID)
  // StartupBrowserCreator::LaunchBrowser can be run multiple times when browser
  // is started with several profiles or existing browser process is reused.
  if (!devtools_auto_opener_)
    devtools_auto_opener_ = std::make_unique<DevToolsAutoOpener>();
#endif
}

bool BrowserProcessImpl::IsShuttingDown() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // TODO(crbug.com/560486): Fix the tests that make the check of
  // |tearing_down_| necessary here.
  return shutting_down_ || tearing_down_;
}

printing::PrintJobManager* BrowserProcessImpl::print_job_manager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return print_job_manager_.get();
}

printing::PrintPreviewDialogController*
    BrowserProcessImpl::print_preview_dialog_controller() {
#if BUILDFLAG(ENABLE_PRINT_PREVIEW)
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!print_preview_dialog_controller_.get())
    CreatePrintPreviewDialogController();
  return print_preview_dialog_controller_.get();
#else
  NOTIMPLEMENTED();
  return NULL;
#endif
}

printing::BackgroundPrintingManager*
    BrowserProcessImpl::background_printing_manager() {
#if BUILDFLAG(ENABLE_PRINT_PREVIEW)
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!background_printing_manager_)
    CreateBackgroundPrintingManager();
  return background_printing_manager_.get();
#else
  NOTIMPLEMENTED();
  return NULL;
#endif
}

IntranetRedirectDetector* BrowserProcessImpl::intranet_redirect_detector() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!intranet_redirect_detector_)
    CreateIntranetRedirectDetector();
  return intranet_redirect_detector_.get();
}

const std::string& BrowserProcessImpl::GetApplicationLocale() {
  DCHECK(!locale_.empty());
  return locale_;
}

void BrowserProcessImpl::SetApplicationLocale(const std::string& locale) {
  // NOTE: this is called before any threads have been created in non-test
  // environments.
  locale_ = locale;
#if BUILDFLAG(ENABLE_EXTENSIONS)
  extension_l10n_util::SetProcessLocale(locale);
#endif
  ChromeContentBrowserClient::SetApplicationLocale(locale);
  translate::TranslateDownloadManager::GetInstance()->set_application_locale(
      locale);
}

DownloadStatusUpdater* BrowserProcessImpl::download_status_updater() {
  return download_status_updater_.get();
}

MediaFileSystemRegistry* BrowserProcessImpl::media_file_system_registry() {
#if BUILDFLAG(ENABLE_EXTENSIONS)
  if (!media_file_system_registry_)
    media_file_system_registry_ = std::make_unique<MediaFileSystemRegistry>();
  return media_file_system_registry_.get();
#else
  return NULL;
#endif
}

#if BUILDFLAG(ENABLE_WEBRTC)
WebRtcLogUploader* BrowserProcessImpl::webrtc_log_uploader() {
  if (!webrtc_log_uploader_)
    webrtc_log_uploader_ = std::make_unique<WebRtcLogUploader>();
  return webrtc_log_uploader_.get();
}
#endif

network_time::NetworkTimeTracker* BrowserProcessImpl::network_time_tracker() {
  if (!network_time_tracker_) {
    network_time_tracker_ = std::make_unique<network_time::NetworkTimeTracker>(
        base::WrapUnique(new base::DefaultClock()),
        base::WrapUnique(new base::DefaultTickClock()), local_state(),
        system_request_context());
  }
  return network_time_tracker_.get();
}

gcm::GCMDriver* BrowserProcessImpl::gcm_driver() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!gcm_driver_)
    CreateGCMDriver();
  return gcm_driver_.get();
}

resource_coordinator::TabManager* BrowserProcessImpl::GetTabManager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
#if defined(OS_WIN) || defined(OS_MACOSX) || defined(OS_LINUX)
  if (!tab_manager_) {
    tab_manager_ = std::make_unique<resource_coordinator::TabManager>();
    tab_lifecycle_unit_source_ =
        std::make_unique<resource_coordinator::TabLifecycleUnitSource>();
    tab_lifecycle_unit_source_->AddObserver(tab_manager_.get());
  }
  return tab_manager_.get();
#else
  return nullptr;
#endif
}

shell_integration::DefaultWebClientState
BrowserProcessImpl::CachedDefaultWebClientState() {
  return cached_default_web_client_state_;
}

physical_web::PhysicalWebDataSource*
BrowserProcessImpl::GetPhysicalWebDataSource() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
#if defined(OS_ANDROID)
  if (!physical_web_data_source_) {
    CreatePhysicalWebDataSource();
    DCHECK(physical_web_data_source_);
  }
  return physical_web_data_source_.get();
#else
  return nullptr;
#endif
}

prefs::InProcessPrefServiceFactory* BrowserProcessImpl::pref_service_factory()
    const {
  return pref_service_factory_.get();
}

// static
void BrowserProcessImpl::RegisterPrefs(PrefRegistrySimple* registry) {
  registry->RegisterBooleanPref(prefs::kDefaultBrowserSettingEnabled,
                                false);
  // This policy needs to be defined before the net subsystem is initialized,
  // so we do it here.
  registry->RegisterIntegerPref(prefs::kMaxConnectionsPerProxy,
                                net::kDefaultMaxSocketsPerProxyServer);

  registry->RegisterBooleanPref(prefs::kAllowCrossOriginAuthPrompt, false);

#if defined(OS_CHROMEOS) || defined(OS_ANDROID)
  registry->RegisterBooleanPref(prefs::kEulaAccepted, false);
#endif  // defined(OS_CHROMEOS) || defined(OS_ANDROID)

  // TODO(brettw,*): this comment about ResourceBundle was here since
  // initial commit.  This comment seems unrelated, bit-rotten and
  // a candidate for removal.
  // Initialize ResourceBundle which handles files loaded from external
  // sources. This has to be done before uninstall code path and before prefs
  // are registered.
  registry->RegisterStringPref(prefs::kApplicationLocale, std::string());
#if defined(OS_CHROMEOS)
  registry->RegisterStringPref(prefs::kOwnerLocale, std::string());
  registry->RegisterStringPref(prefs::kHardwareKeyboardLayout,
                               std::string());
#endif  // defined(OS_CHROMEOS)

  registry->RegisterBooleanPref(metrics::prefs::kMetricsReportingEnabled,
                                GoogleUpdateSettings::GetCollectStatsConsent());

#if defined(OS_ANDROID)
  registry->RegisterBooleanPref(
      prefs::kCrashReportingEnabled, false);
#endif  // defined(OS_ANDROID)
}

DownloadRequestLimiter* BrowserProcessImpl::download_request_limiter() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!download_request_limiter_.get()) {
    download_request_limiter_ = base::MakeRefCounted<DownloadRequestLimiter>();
  }
  return download_request_limiter_.get();
}

BackgroundModeManager* BrowserProcessImpl::background_mode_manager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
#if BUILDFLAG(ENABLE_BACKGROUND_MODE)
  if (!background_mode_manager_)
    CreateBackgroundModeManager();
  return background_mode_manager_.get();
#else
  NOTIMPLEMENTED();
  return NULL;
#endif
}

void BrowserProcessImpl::set_background_mode_manager_for_test(
    std::unique_ptr<BackgroundModeManager> manager) {
#if BUILDFLAG(ENABLE_BACKGROUND_MODE)
  background_mode_manager_ = std::move(manager);
#endif
}

StatusTray* BrowserProcessImpl::status_tray() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!status_tray_)
    CreateStatusTray();
  return status_tray_.get();
}

safe_browsing::SafeBrowsingService*
BrowserProcessImpl::safe_browsing_service() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!created_safe_browsing_service_)
    CreateSafeBrowsingService();
  return safe_browsing_service_.get();
}

safe_browsing::ClientSideDetectionService*
    BrowserProcessImpl::safe_browsing_detection_service() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (safe_browsing_service())
    return safe_browsing_service()->safe_browsing_detection_service();
  return NULL;
}

subresource_filter::ContentRulesetService*
BrowserProcessImpl::subresource_filter_ruleset_service() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!created_subresource_filter_ruleset_service_)
    CreateSubresourceFilterRulesetService();
  return subresource_filter_ruleset_service_.get();
}

optimization_guide::OptimizationGuideService*
BrowserProcessImpl::optimization_guide_service() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!created_optimization_guide_service_)
    CreateOptimizationGuideService();
  return optimization_guide_service_.get();
}

#if (defined(OS_WIN) || defined(OS_LINUX)) && !defined(OS_CHROMEOS)
void BrowserProcessImpl::StartAutoupdateTimer() {
  autoupdate_timer_.Start(FROM_HERE,
      base::TimeDelta::FromHours(kUpdateCheckIntervalHours),
      this,
      &BrowserProcessImpl::OnAutoupdateTimer);
}
#endif

net_log::ChromeNetLog* BrowserProcessImpl::net_log() {
  return net_log_.get();
}

component_updater::ComponentUpdateService*
BrowserProcessImpl::component_updater() {
  if (component_updater_)
    return component_updater_.get();

  if (!BrowserThread::CurrentlyOn(BrowserThread::UI))
    return nullptr;

  component_updater_ = component_updater::ComponentUpdateServiceFactory(
      component_updater::MakeChromeComponentUpdaterConfigurator(
          base::CommandLine::ForCurrentProcess(),
          g_browser_process->local_state()));

  return component_updater_.get();
}

component_updater::SupervisedUserWhitelistInstaller*
BrowserProcessImpl::supervised_user_whitelist_installer() {
  if (!supervised_user_whitelist_installer_) {
    supervised_user_whitelist_installer_ =
        component_updater::SupervisedUserWhitelistInstaller::Create(
            component_updater(),
            &profile_manager()->GetProfileAttributesStorage(),
            local_state());
  }
  return supervised_user_whitelist_installer_.get();
}

void BrowserProcessImpl::ResourceDispatcherHostCreated() {
  resource_dispatcher_host_delegate_ =
      std::make_unique<ChromeResourceDispatcherHostDelegate>();
  ResourceDispatcherHost::Get()->SetDelegate(
      resource_dispatcher_host_delegate_.get());

  pref_change_registrar_.Add(
      prefs::kAllowCrossOriginAuthPrompt,
      base::Bind(&BrowserProcessImpl::ApplyAllowCrossOriginAuthPromptPolicy,
                 base::Unretained(this)));
  ApplyAllowCrossOriginAuthPromptPolicy();
}

void BrowserProcessImpl::OnKeepAliveStateChanged(bool is_keeping_alive) {
  if (is_keeping_alive)
    Pin();
  else
    Unpin();
}

void BrowserProcessImpl::OnKeepAliveRestartStateChanged(bool can_restart) {}

void BrowserProcessImpl::CreateWatchdogThread() {
  DCHECK(!created_watchdog_thread_ && !watchdog_thread_);
  created_watchdog_thread_ = true;

  auto thread = std::make_unique<WatchDogThread>();
  base::Thread::Options options;
  options.timer_slack = base::TIMER_SLACK_MAXIMUM;
  if (!thread->StartWithOptions(options))
    return;
  watchdog_thread_.swap(thread);
}

void BrowserProcessImpl::CreateProfileManager() {
  DCHECK(!created_profile_manager_ && !profile_manager_);
  created_profile_manager_ = true;

  base::FilePath user_data_dir;
  PathService::Get(chrome::DIR_USER_DATA, &user_data_dir);
  profile_manager_ = std::make_unique<ProfileManager>(user_data_dir);
}

void BrowserProcessImpl::CreateLocalState() {
  DCHECK(!local_state_);

  base::FilePath local_state_path;
  CHECK(PathService::Get(chrome::FILE_LOCAL_STATE, &local_state_path));
  auto pref_registry = base::MakeRefCounted<PrefRegistrySimple>();

  // Register local state preferences.
  RegisterLocalState(pref_registry.get());

  auto delegate = pref_service_factory_->CreateDelegate();
  delegate->InitPrefRegistry(pref_registry.get());
  local_state_ = chrome_prefs::CreateLocalState(
      local_state_path, local_state_task_runner_.get(), policy_service(),
      std::move(pref_registry), false, std::move(delegate));
  DCHECK(local_state_);
}

void BrowserProcessImpl::PreCreateThreads(
    const base::CommandLine& command_line) {
#if BUILDFLAG(ENABLE_EXTENSIONS)
  // chrome-extension:// URLs are safe to request anywhere, but may only
  // commit (including in iframes) in extension processes.
  ChildProcessSecurityPolicy::GetInstance()->RegisterWebSafeIsolatedScheme(
      extensions::kExtensionScheme, true);
#endif

  if (command_line.HasSwitch(network::switches::kLogNetLog)) {
    base::FilePath log_file =
        command_line.GetSwitchValuePath(network::switches::kLogNetLog);
    if (log_file.empty()) {
      base::FilePath user_data_dir;
      bool success =
          base::PathService::Get(chrome::DIR_USER_DATA, &user_data_dir);
      DCHECK(success);
      log_file = user_data_dir.AppendASCII("netlog.json");
    }
    net_log_->StartWritingToFile(
        log_file, GetNetCaptureModeFromCommandLine(command_line),
        command_line.GetCommandLineString(), chrome::GetChannelName());
  }

  // Must be created before the IOThread.
  // TODO(mmenke): Once IOThread class is no longer needed (not the thread
  // itself), this can be created on first use.
  system_network_context_manager_ =
      std::make_unique<SystemNetworkContextManager>();
  io_thread_ = std::make_unique<IOThread>(
      local_state(), policy_service(), net_log_.get(),
      extension_event_router_forwarder(),
      system_network_context_manager_.get());
}

void BrowserProcessImpl::PreMainMessageLoopRun() {
  TRACE_EVENT0("startup", "BrowserProcessImpl::PreMainMessageLoopRun");
  SCOPED_UMA_HISTOGRAM_TIMER(
      "Startup.BrowserProcessImpl_PreMainMessageLoopRunTime");

  // browser_policy_connector() is created very early because local_state()
  // needs policy to be initialized with the managed preference values.
  // However, policy fetches from the network and loading of disk caches
  // requires that threads are running; this Init() call lets the connector
  // resume its initialization now that the loops are spinning and the
  // system request context is available for the fetchers.
  browser_policy_connector()->Init(local_state(), system_request_context());

  if (local_state_->IsManagedPreference(prefs::kDefaultBrowserSettingEnabled))
    ApplyDefaultBrowserPolicy();

#if !defined(OS_ANDROID)
  ApplyMetricsReportingPolicy();
#endif

#if BUILDFLAG(ENABLE_PLUGINS)
  PluginService* plugin_service = PluginService::GetInstance();
  plugin_service->SetFilter(ChromePluginServiceFilter::GetInstance());

  // Triggers initialization of the singleton instance on UI thread.
  PluginFinder::GetInstance()->Init();

  DCHECK(!plugins_resource_service_);
  plugins_resource_service_ =
      std::make_unique<PluginsResourceService>(local_state());
  plugins_resource_service_->Init();
#endif  // BUILDFLAG(ENABLE_PLUGINS)

#if !defined(OS_ANDROID)
  storage_monitor::StorageMonitor::Create(
      content::ServiceManagerConnection::GetForProcess()
          ->GetConnector()
          ->Clone());
#endif

  child_process_watcher_ = std::make_unique<ChromeChildProcessWatcher>();

  CacheDefaultWebClientState();

  platform_part_->PreMainMessageLoopRun();

  if (base::FeatureList::IsEnabled(network_time::kNetworkTimeServiceQuerying)) {
    network_time_tracker_ = std::make_unique<network_time::NetworkTimeTracker>(
        base::WrapUnique(new base::DefaultClock()),
        base::WrapUnique(new base::DefaultTickClock()), local_state(),
        system_request_context());
  }
}

void BrowserProcessImpl::CreateIconManager() {
  DCHECK(!created_icon_manager_ && !icon_manager_);
  created_icon_manager_ = true;
  icon_manager_ = std::make_unique<IconManager>();
}

void BrowserProcessImpl::CreateIntranetRedirectDetector() {
  DCHECK(!intranet_redirect_detector_);
  intranet_redirect_detector_ = std::make_unique<IntranetRedirectDetector>();
}

void BrowserProcessImpl::CreateNotificationPlatformBridge() {
#if BUILDFLAG(ENABLE_NATIVE_NOTIFICATIONS)
  DCHECK(!notification_bridge_);
  notification_bridge_.reset(NotificationPlatformBridge::Create());
  created_notification_bridge_ = true;
#endif
}

void BrowserProcessImpl::CreateNotificationUIManager() {
// Android does not use the NotificationUIManager anymore
// All notification traffic is routed through NotificationPlatformBridge.
#if !defined(OS_ANDROID)
  DCHECK(!notification_ui_manager_);
  notification_ui_manager_.reset(NotificationUIManager::Create());
  created_notification_ui_manager_ = !!notification_ui_manager_;
#endif
}

void BrowserProcessImpl::CreateBackgroundModeManager() {
#if BUILDFLAG(ENABLE_BACKGROUND_MODE)
  DCHECK(!background_mode_manager_);
  background_mode_manager_ = std::make_unique<BackgroundModeManager>(
      *base::CommandLine::ForCurrentProcess(),
      &profile_manager()->GetProfileAttributesStorage());
#endif
}

void BrowserProcessImpl::CreateStatusTray() {
  DCHECK(!status_tray_);
  status_tray_.reset(StatusTray::Create());
}

void BrowserProcessImpl::CreatePrintPreviewDialogController() {
#if BUILDFLAG(ENABLE_PRINT_PREVIEW)
  DCHECK(!print_preview_dialog_controller_);
  print_preview_dialog_controller_ =
      base::MakeRefCounted<printing::PrintPreviewDialogController>();
#else
  NOTIMPLEMENTED();
#endif
}

void BrowserProcessImpl::CreateBackgroundPrintingManager() {
#if BUILDFLAG(ENABLE_PRINT_PREVIEW)
  DCHECK(!background_printing_manager_);
  background_printing_manager_ =
      std::make_unique<printing::BackgroundPrintingManager>();
#else
  NOTIMPLEMENTED();
#endif
}

void BrowserProcessImpl::CreateSafeBrowsingService() {
  DCHECK(!safe_browsing_service_);
  // Set this flag to true so that we don't retry indefinitely to
  // create the service class if there was an error.
  created_safe_browsing_service_ = true;
  safe_browsing_service_ =
      safe_browsing::SafeBrowsingService::CreateSafeBrowsingService();
  safe_browsing_service_->Initialize();
}

void BrowserProcessImpl::CreateSubresourceFilterRulesetService() {
  DCHECK(!subresource_filter_ruleset_service_);
  created_subresource_filter_ruleset_service_ = true;

  if (!base::FeatureList::IsEnabled(
          subresource_filter::kSafeBrowsingSubresourceFilter)) {
    return;
  }

  // Runner for tasks critical for user experience.
  scoped_refptr<base::SequencedTaskRunner> blocking_task_runner(
      base::CreateSequencedTaskRunnerWithTraits(
          {base::MayBlock(), base::TaskPriority::USER_BLOCKING,
           base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN}));

  // Runner for tasks that do not influence user experience.
  scoped_refptr<base::SequencedTaskRunner> background_task_runner(
      base::CreateSequencedTaskRunnerWithTraits(
          {base::MayBlock(), base::TaskPriority::BACKGROUND,
           base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN}));

  base::FilePath user_data_dir;
  PathService::Get(chrome::DIR_USER_DATA, &user_data_dir);
  base::FilePath indexed_ruleset_base_dir =
      user_data_dir.Append(subresource_filter::kTopLevelDirectoryName)
          .Append(subresource_filter::kIndexedRulesetBaseDirectoryName);
  subresource_filter_ruleset_service_ =
      std::make_unique<subresource_filter::ContentRulesetService>(
          blocking_task_runner);
  subresource_filter_ruleset_service_->set_ruleset_service(
      std::make_unique<subresource_filter::RulesetService>(
          local_state(), background_task_runner,
          subresource_filter_ruleset_service_.get(), indexed_ruleset_base_dir));
}

void BrowserProcessImpl::CreateOptimizationGuideService() {
  DCHECK(!created_optimization_guide_service_);
  DCHECK(!optimization_guide_service_);
  created_optimization_guide_service_ = true;

  if (!base::FeatureList::IsEnabled(previews::features::kOptimizationHints))
    return;

  optimization_guide_service_ =
      std::make_unique<optimization_guide::OptimizationGuideService>(
          content::BrowserThread::GetTaskRunnerForThread(
              content::BrowserThread::IO));
}

void BrowserProcessImpl::CreateGCMDriver() {
  DCHECK(!gcm_driver_);

#if defined(OS_ANDROID)
  // Android's GCMDriver currently makes the assumption that it's a singleton.
  // Until this gets fixed, instantiating multiple Java GCMDrivers will throw
  // an exception, but because they're only initialized on demand these crashes
  // would be very difficult to triage. See http://crbug.com/437827.
  NOTREACHED();
#else
  base::FilePath store_path;
  CHECK(PathService::Get(chrome::DIR_GLOBAL_GCM_STORE, &store_path));
  scoped_refptr<base::SequencedTaskRunner> blocking_task_runner(
      base::CreateSequencedTaskRunnerWithTraits(
          {base::MayBlock(), base::TaskPriority::BACKGROUND,
           base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN}));

  gcm_driver_ = gcm::CreateGCMDriverDesktop(
      base::WrapUnique(new gcm::GCMClientFactory), local_state(), store_path,
      system_request_context(), chrome::GetChannel(),
      gcm::GetProductCategoryForSubtypes(local_state()),
      content::BrowserThread::GetTaskRunnerForThread(
          content::BrowserThread::UI),
      content::BrowserThread::GetTaskRunnerForThread(
          content::BrowserThread::IO),
      blocking_task_runner);
#endif  // defined(OS_ANDROID)
}

void BrowserProcessImpl::CreatePhysicalWebDataSource() {
  DCHECK(!physical_web_data_source_);

#if defined(OS_ANDROID)
  physical_web_data_source_ = std::make_unique<PhysicalWebDataSourceAndroid>();
#else
  NOTIMPLEMENTED();
#endif
}

void BrowserProcessImpl::ApplyDefaultBrowserPolicy() {
  if (local_state()->GetBoolean(prefs::kDefaultBrowserSettingEnabled)) {
    // The worker pointer is reference counted. While it is running, the
    // message loops of the FILE and UI thread will hold references to it
    // and it will be automatically freed once all its tasks have finished.
    auto set_browser_worker =
        base::MakeRefCounted<shell_integration::DefaultBrowserWorker>(
            shell_integration::DefaultWebClientWorkerCallback());
    // The user interaction must always be disabled when applying the default
    // browser policy since it is done at each browser startup and the result
    // of the interaction cannot be forced.
    set_browser_worker->set_interactive_permitted(false);
    set_browser_worker->StartSetAsDefault();
  }
}

void BrowserProcessImpl::ApplyAllowCrossOriginAuthPromptPolicy() {
  bool value = local_state()->GetBoolean(prefs::kAllowCrossOriginAuthPrompt);
  ResourceDispatcherHost::Get()->SetAllowCrossOriginAuthPrompt(value);
}

#if !defined(OS_ANDROID)
void BrowserProcessImpl::ApplyMetricsReportingPolicy() {
  GoogleUpdateSettings::CollectStatsConsentTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          base::IgnoreResult(&GoogleUpdateSettings::SetCollectStatsConsent),
          ChromeMetricsServiceAccessor::IsMetricsAndCrashReportingEnabled()));
}
#endif

void BrowserProcessImpl::CacheDefaultWebClientState() {
#if defined(OS_CHROMEOS)
  cached_default_web_client_state_ = shell_integration::IS_DEFAULT;
#elif !defined(OS_ANDROID)
  cached_default_web_client_state_ = shell_integration::GetDefaultBrowser();
#endif
}

void BrowserProcessImpl::Pin() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // CHECK(!IsShuttingDown());
  if (IsShuttingDown()) {
    // TODO(rsesek): Consider removing this trace, but it has been helpful
    // in debugging several shutdown crashes (https://crbug.com/113031,
    // https://crbug.com/625646, and https://crbug.com/779829).
    static crash_reporter::CrashKeyString<1024> browser_unpin_trace(
        "browser-unpin-trace");
    crash_reporter::SetCrashKeyStringToStackTrace(
        &browser_unpin_trace, release_last_reference_callstack_);
    CHECK(false);
  }
}

void BrowserProcessImpl::Unpin() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  release_last_reference_callstack_ = base::debug::StackTrace();

  shutting_down_ = true;
#if BUILDFLAG(ENABLE_PRINTING)
  // Wait for the pending print jobs to finish. Don't do this later, since
  // this might cause a nested run loop to run, and we don't want pending
  // tasks to run once teardown has started.
  print_job_manager_->Shutdown();
#endif

#if defined(LEAK_SANITIZER)
  // Check for memory leaks now, before we start shutting down threads. Doing
  // this early means we won't report any shutdown-only leaks (as they have
  // not yet happened at this point).
  // If leaks are found, this will make the process exit immediately.
  __lsan_do_leak_check();
#endif

  CHECK(base::RunLoop::IsRunningOnCurrentThread());

#if defined(OS_MACOSX)
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(ChromeBrowserMainPartsMac::DidEndMainMessageLoop));
#endif
  base::RunLoop::QuitCurrentWhenIdleDeprecated();

#if !defined(OS_ANDROID)
  chrome::ShutdownIfNeeded();
#endif  // !defined(OS_ANDROID)
}

// Mac is currently not supported.
#if (defined(OS_WIN) || defined(OS_LINUX)) && !defined(OS_CHROMEOS)

bool BrowserProcessImpl::IsRunningInBackground() const {
  // Check if browser is in the background.
  return chrome::GetTotalBrowserCount() == 0 &&
         KeepAliveRegistry::GetInstance()->IsKeepingAlive();
}

void BrowserProcessImpl::RestartBackgroundInstance() {
  base::CommandLine* old_cl = base::CommandLine::ForCurrentProcess();
  auto new_cl = std::make_unique<base::CommandLine>(old_cl->GetProgram());

  base::CommandLine::SwitchMap switches = old_cl->GetSwitches();
  switches::RemoveSwitchesForAutostart(&switches);

  // Append the rest of the switches (along with their values, if any)
  // to the new command line
  for (const auto& it : switches) {
    const auto& switch_name = it.first;
    const auto& switch_value = it.second;
    if (switch_value.empty())
      new_cl->AppendSwitch(switch_name);
    else
      new_cl->AppendSwitchNative(switch_name, switch_value);
  }

  // Switches to add when auto-restarting Chrome.
  static constexpr const char* kSwitchesToAddOnAutorestart[] = {
      switches::kNoStartupWindow};

  // Ensure that our desired switches are set on the new process.
  for (const char* switch_to_add : kSwitchesToAddOnAutorestart) {
    if (!new_cl->HasSwitch(switch_to_add))
      new_cl->AppendSwitch(switch_to_add);
  }

#if defined(OS_WIN)
  new_cl->AppendArg(switches::kPrefetchArgumentBrowserBackground);
#endif  // defined(OS_WIN)

  DLOG(WARNING) << "Shutting down current instance of the browser.";
  chrome::AttemptExit();

  upgrade_util::SetNewCommandLine(new_cl.release());
}

void BrowserProcessImpl::OnAutoupdateTimer() {
  if (IsRunningInBackground()) {
    // upgrade_util::IsUpdatePendingRestart touches the disk, so do it on a
    // suitable thread.
    base::PostTaskWithTraitsAndReplyWithResult(
        FROM_HERE,
        {base::TaskPriority::BACKGROUND,
         base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN, base::MayBlock()},
        base::BindOnce(&upgrade_util::IsUpdatePendingRestart),
        base::BindOnce(&BrowserProcessImpl::OnPendingRestartResult,
                       base::Unretained(this)));
  }
}

void BrowserProcessImpl::OnPendingRestartResult(
    bool is_update_pending_restart) {
  // Make sure that the browser is still in the background after returning from
  // the check.
  if (is_update_pending_restart && IsRunningInBackground()) {
    DLOG(WARNING) << "Detected update.  Restarting browser.";
    RestartBackgroundInstance();
  }
}

#endif  // (defined(OS_WIN) || defined(OS_LINUX)) && !defined(OS_CHROMEOS)

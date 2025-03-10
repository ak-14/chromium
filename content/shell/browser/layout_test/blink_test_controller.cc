// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/shell/browser/layout_test/blink_test_controller.h"

#include <stddef.h>
#include <string.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "base/barrier_closure.h"
#include "base/base64.h"
#include "base/callback.h"
#include "base/command_line.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/strings/nullable_string16.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "content/common/page_state_serialization.h"
#include "content/common/unique_name_helper.h"
#include "content/public/browser/devtools_agent_host.h"
#include "content/public/browser/gpu_data_manager.h"
#include "content/public/browser/navigation_controller.h"
#include "content/public/browser/navigation_entry.h"
#include "content/public/browser/notification_service.h"
#include "content/public/browser/notification_types.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/render_view_host.h"
#include "content/public/browser/render_widget_host.h"
#include "content/public/browser/render_widget_host_view.h"
#include "content/public/browser/service_worker_context.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_package_context.h"
#include "content/public/common/bindings_policy.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/url_constants.h"
#include "content/public/test/layouttest_support.h"
#include "content/shell/browser/layout_test/devtools_protocol_test_bindings.h"
#include "content/shell/browser/layout_test/fake_bluetooth_chooser.h"
#include "content/shell/browser/layout_test/layout_test_bluetooth_chooser_factory.h"
#include "content/shell/browser/layout_test/layout_test_content_browser_client.h"
#include "content/shell/browser/layout_test/layout_test_devtools_bindings.h"
#include "content/shell/browser/layout_test/layout_test_first_device_bluetooth_chooser.h"
#include "content/shell/browser/shell.h"
#include "content/shell/browser/shell_browser_context.h"
#include "content/shell/browser/shell_content_browser_client.h"
#include "content/shell/browser/shell_devtools_frontend.h"
#include "content/shell/common/layout_test/layout_test_messages.h"
#include "content/shell/common/layout_test/layout_test_switches.h"
#include "content/shell/common/shell_messages.h"
#include "content/shell/renderer/layout_test/blink_test_helpers.h"
#include "content/shell/test_runner/test_common.h"
#include "mojo/public/cpp/bindings/sync_call_restrictions.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "ui/gfx/codec/png_codec.h"

#if defined(OS_MACOSX)
#include "base/mac/foundation_util.h"
#endif

namespace content {

namespace {

base::FilePath GetBuildDirectory() {
  base::FilePath result;
  base::PathService::Get(base::DIR_EXE, &result);

#if defined(OS_MACOSX)
  if (base::mac::AmIBundled()) {
    // The bundled app executables (Chromium, TestShell, etc) live three
    // levels down from the build directory, eg:
    // Chromium.app/Contents/MacOS/Chromium
    result = result.DirName().DirName().DirName();
  }
#endif
  return result;
}

std::string DumpFrameState(const ExplodedFrameState& frame_state,
                           size_t indent,
                           bool is_current_index) {
  std::string result;
  if (is_current_index) {
    constexpr const char kCurrentMarker[] = "curr->";
    result.append(kCurrentMarker);
    result.append(indent - strlen(kCurrentMarker), ' ');
  } else {
    result.append(indent, ' ');
  }

  std::string url = test_runner::NormalizeLayoutTestURL(
      base::UTF16ToUTF8(frame_state.url_string.value_or(base::string16())));
  result.append(url);
  DCHECK(frame_state.target);
  if (!frame_state.target->empty()) {
    std::string unique_name = base::UTF16ToUTF8(*frame_state.target);
    result.append(" (in frame \"");
    result.append(UniqueNameHelper::ExtractStableNameForTesting(unique_name));
    result.append("\")");
  }
  result.append("\n");

  std::vector<ExplodedFrameState> sorted_children = frame_state.children;
  std::sort(sorted_children.begin(), sorted_children.end(),
            [](const ExplodedFrameState& lhs, const ExplodedFrameState& rhs) {
              // Child nodes should always have a target (aka unique name).
              DCHECK(lhs.target);
              DCHECK(rhs.target);
              std::string lhs_name =
                  UniqueNameHelper::ExtractStableNameForTesting(
                      base::UTF16ToUTF8(*lhs.target));
              std::string rhs_name =
                  UniqueNameHelper::ExtractStableNameForTesting(
                      base::UTF16ToUTF8(*rhs.target));
              if (!base::EqualsCaseInsensitiveASCII(lhs_name, rhs_name))
                return base::CompareCaseInsensitiveASCII(lhs_name, rhs_name) <
                       0;

              return lhs.item_sequence_number < rhs.item_sequence_number;
            });
  for (const auto& child : sorted_children)
    result += DumpFrameState(child, indent + 4, false);

  return result;
}

std::string DumpNavigationEntry(NavigationEntry* navigation_entry,
                                bool is_current_index) {
  // This is silly, but it's currently the best way to extract the information.
  PageState page_state = navigation_entry->GetPageState();
  ExplodedPageState exploded_page_state;
  CHECK(DecodePageState(page_state.ToEncodedData(), &exploded_page_state));
  return DumpFrameState(exploded_page_state.top, 8, is_current_index);
}

std::string DumpHistoryForWebContents(WebContents* web_contents) {
  std::string result;
  const int current_index =
      web_contents->GetController().GetCurrentEntryIndex();
  for (int i = 0; i < web_contents->GetController().GetEntryCount(); ++i) {
    result += DumpNavigationEntry(
        web_contents->GetController().GetEntryAtIndex(i), i == current_index);
  }
  return result;
}

}  // namespace

// BlinkTestResultPrinter ----------------------------------------------------

BlinkTestResultPrinter::BlinkTestResultPrinter(std::ostream* output,
                                               std::ostream* error)
    : state_(DURING_TEST),
      capture_text_only_(false),
      encode_binary_data_(false),
      output_(output),
      error_(error) {
}

BlinkTestResultPrinter::~BlinkTestResultPrinter() {
}

void BlinkTestResultPrinter::StartStateDump() {
  state_ = DURING_STATE_DUMP;
}

void BlinkTestResultPrinter::PrintTextHeader() {
  if (state_ != DURING_STATE_DUMP)
    return;
  if (!capture_text_only_)
    *output_ << "Content-Type: text/plain\n";
  state_ = IN_TEXT_BLOCK;
}

void BlinkTestResultPrinter::PrintTextBlock(const std::string& block) {
  if (state_ != IN_TEXT_BLOCK)
    return;
  *output_ << block;
}

void BlinkTestResultPrinter::PrintTextFooter() {
  if (state_ != IN_TEXT_BLOCK)
    return;
  if (!capture_text_only_) {
    *output_ << "#EOF\n";
    output_->flush();
  }
  state_ = IN_IMAGE_BLOCK;
}

void BlinkTestResultPrinter::PrintImageHeader(
    const std::string& actual_hash,
    const std::string& expected_hash) {
  if (state_ != IN_IMAGE_BLOCK || capture_text_only_)
    return;
  *output_ << "\nActualHash: " << actual_hash << "\n";
  if (!expected_hash.empty())
    *output_ << "\nExpectedHash: " << expected_hash << "\n";
}

void BlinkTestResultPrinter::PrintImageBlock(
    const std::vector<unsigned char>& png_image) {
  if (state_ != IN_IMAGE_BLOCK || capture_text_only_)
    return;
  *output_ << "Content-Type: image/png\n";
  if (encode_binary_data_) {
    PrintEncodedBinaryData(png_image);
    return;
  }

  *output_ << "Content-Length: " << png_image.size() << "\n";
  output_->write(
      reinterpret_cast<const char*>(&png_image[0]), png_image.size());
}

void BlinkTestResultPrinter::PrintImageFooter() {
  if (state_ != IN_IMAGE_BLOCK)
    return;
  if (!capture_text_only_) {
    *output_ << "#EOF\n";
    output_->flush();
  }
  state_ = AFTER_TEST;
}

void BlinkTestResultPrinter::PrintAudioHeader() {
  DCHECK_EQ(state_, DURING_STATE_DUMP);
  if (!capture_text_only_)
    *output_ << "Content-Type: audio/wav\n";
  state_ = IN_AUDIO_BLOCK;
}

void BlinkTestResultPrinter::PrintAudioBlock(
    const std::vector<unsigned char>& audio_data) {
  if (state_ != IN_AUDIO_BLOCK || capture_text_only_)
    return;
  if (encode_binary_data_) {
    PrintEncodedBinaryData(audio_data);
    return;
  }

  *output_ << "Content-Length: " << audio_data.size() << "\n";
  output_->write(
      reinterpret_cast<const char*>(&audio_data[0]), audio_data.size());
}

void BlinkTestResultPrinter::PrintAudioFooter() {
  if (state_ != IN_AUDIO_BLOCK)
    return;
  if (!capture_text_only_) {
    *output_ << "#EOF\n";
    output_->flush();
  }
  state_ = IN_IMAGE_BLOCK;
}

void BlinkTestResultPrinter::AddMessageToStderr(const std::string& message) {
  *error_ << message;
}

void BlinkTestResultPrinter::AddMessage(const std::string& message) {
  AddMessageRaw(message + "\n");
}

void BlinkTestResultPrinter::AddMessageRaw(const std::string& message) {
  if (state_ != DURING_TEST)
    return;
  *output_ << message;
}

void BlinkTestResultPrinter::AddErrorMessage(const std::string& message) {
  if (!capture_text_only_)
    *error_ << message << "\n";
  if (state_ != DURING_TEST && state_ != DURING_STATE_DUMP)
    return;
  PrintTextHeader();
  *output_ << message << "\n";
  PrintTextFooter();
  PrintImageFooter();
}

void BlinkTestResultPrinter::PrintEncodedBinaryData(
    const std::vector<unsigned char>& data) {
  *output_ << "Content-Transfer-Encoding: base64\n";

  std::string data_base64;
  base::Base64Encode(
      base::StringPiece(reinterpret_cast<const char*>(&data[0]), data.size()),
      &data_base64);

  *output_ << "Content-Length: " << data_base64.length() << "\n";
  output_->write(data_base64.c_str(), data_base64.length());
}

void BlinkTestResultPrinter::CloseStderr() {
  if (state_ != AFTER_TEST)
    return;
  if (!capture_text_only_) {
    *error_ << "#EOF\n";
    error_->flush();
  }
}

// BlinkTestController -------------------------------------------------------

BlinkTestController* BlinkTestController::instance_ = nullptr;

// static
BlinkTestController* BlinkTestController::Get() {
  return instance_;
}

BlinkTestController::BlinkTestController()
    : main_window_(nullptr),
      secondary_window_(nullptr),
      devtools_window_(nullptr),
      test_phase_(BETWEEN_TESTS),
      crash_when_leak_found_(false),
      pending_layout_dumps_(0),
      render_process_host_observer_(this),
      weak_factory_(this) {
  CHECK(!instance_);
  instance_ = this;

  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kEnableLeakDetection)) {
    leak_detector_ = std::make_unique<LeakDetector>();
    std::string switchValue =
        base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
            switches::kEnableLeakDetection);
    crash_when_leak_found_ = switchValue == switches::kCrashOnFailure;
  }

  printer_.reset(new BlinkTestResultPrinter(&std::cout, &std::cerr));
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kEncodeBinary))
    printer_->set_encode_binary_data(true);
  registrar_.Add(this,
                 NOTIFICATION_RENDERER_PROCESS_CREATED,
                 NotificationService::AllSources());
  GpuDataManager::GetInstance()->AddObserver(this);
  ResetAfterLayoutTest();
}

BlinkTestController::~BlinkTestController() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(instance_ == this);
  CHECK(test_phase_ == BETWEEN_TESTS);
  GpuDataManager::GetInstance()->RemoveObserver(this);
  DiscardMainWindow();
  instance_ = nullptr;
}

bool BlinkTestController::PrepareForLayoutTest(
    const GURL& test_url,
    const base::FilePath& current_working_directory,
    bool enable_pixel_dumping,
    const std::string& expected_pixel_hash) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  test_phase_ = DURING_TEST;
  current_working_directory_ = current_working_directory;
  enable_pixel_dumping_ = enable_pixel_dumping;
  expected_pixel_hash_ = expected_pixel_hash;
  bool is_devtools_js_test = false;
  test_url_ = LayoutTestDevToolsBindings::MapTestURLIfNeeded(
      test_url, &is_devtools_js_test);
  bool is_devtools_protocol_test = false;
  test_url_ = DevToolsProtocolTestBindings::MapTestURLIfNeeded(
      test_url_, &is_devtools_protocol_test);
  did_send_initial_test_configuration_ = false;
  printer_->reset();
  frame_to_layout_dump_map_.clear();
  render_process_host_observer_.RemoveAll();
  all_observed_render_process_hosts_.clear();
  main_window_render_process_hosts_.clear();
  accumulated_layout_test_runtime_flags_changes_.Clear();
  layout_test_control_map_.clear();
  ShellBrowserContext* browser_context =
      ShellContentBrowserClient::Get()->browser_context();
  is_compositing_test_ =
      test_url_.spec().find("compositing/") != std::string::npos;
  initial_size_ = Shell::GetShellDefaultSize();
  if (!main_window_) {
    main_window_ = content::Shell::CreateNewWindow(browser_context, GURL(),
                                                   nullptr, initial_size_);
    WebContentsObserver::Observe(main_window_->web_contents());
    if (is_devtools_protocol_test) {
      devtools_protocol_test_bindings_.reset(
          new DevToolsProtocolTestBindings(main_window_->web_contents()));
    }
    current_pid_ = base::kNullProcessId;
    default_prefs_ =
      main_window_->web_contents()->GetRenderViewHost()->GetWebkitPreferences();
    if (is_devtools_js_test)
      LoadDevToolsJSTest();
    else
      main_window_->LoadURL(test_url_);

#if defined(OS_ANDROID)
    // On Android, the browser main loop runs on the UI thread so the view
    // hierarchy never gets to layout since the UI thread is blocked. This call
    // simulates a layout and ensures our RenderWidget hierarchy gets correctly
    // sized.
    main_window_->SizeTo(initial_size_);
#endif
  } else {
#if defined(OS_MACOSX)
    // Shell::SizeTo is not implemented on all platforms.
    main_window_->SizeTo(initial_size_);
#endif
    main_window_->web_contents()
        ->GetRenderViewHost()
        ->GetWidget()
        ->GetView()
        ->SetSize(initial_size_);
    // Try to reset the window size. This can fail, see crbug.com/772811
    main_window_->web_contents()
        ->GetRenderViewHost()
        ->GetWidget()
        ->WasResized();
    RenderViewHost* render_view_host =
        main_window_->web_contents()->GetRenderViewHost();

    if (is_devtools_protocol_test) {
      devtools_protocol_test_bindings_.reset(
          new DevToolsProtocolTestBindings(main_window_->web_contents()));
    }

    // Compositing tests override the default preferences (see
    // BlinkTestController::OverrideWebkitPrefs) so we force them to be
    // calculated again to ensure is_compositing_test_ changes are picked up.
    OverrideWebkitPrefs(&default_prefs_);

    render_view_host->UpdateWebkitPreferences(default_prefs_);
    HandleNewRenderFrameHost(render_view_host->GetMainFrame());

    if (is_devtools_js_test) {
      LoadDevToolsJSTest();
    } else {
      NavigationController::LoadURLParams params(test_url_);
      // Using PAGE_TRANSITION_LINK avoids a BrowsingInstance/process swap
      // between layout tests.
      params.transition_type =
          ui::PageTransitionFromInt(ui::PAGE_TRANSITION_LINK);
      params.should_clear_history_list = true;
      main_window_->web_contents()->GetController().LoadURLWithParams(params);
      main_window_->web_contents()->Focus();
    }
  }
  main_window_->web_contents()->GetRenderViewHost()->GetWidget()->SetActive(
      true);
  main_window_->web_contents()->GetRenderViewHost()->GetWidget()->Focus();
  return true;
}

Shell* BlinkTestController::SecondaryWindow() {
  if (!secondary_window_) {
    ShellBrowserContext* browser_context =
        ShellContentBrowserClient::Get()->browser_context();
    secondary_window_ = content::Shell::CreateNewWindow(browser_context, GURL(),
                                                        nullptr, initial_size_);
  }
  return secondary_window_;
}

void BlinkTestController::LoadDevToolsJSTest() {
  devtools_window_ = main_window_;
  Shell* secondary = SecondaryWindow();
  devtools_bindings_ = std::make_unique<LayoutTestDevToolsBindings>(
      devtools_window_->web_contents(), secondary->web_contents(), test_url_);
}

bool BlinkTestController::ResetAfterLayoutTest() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  printer_->PrintTextFooter();
  printer_->PrintImageFooter();
  printer_->CloseStderr();
  did_send_initial_test_configuration_ = false;
  test_phase_ = BETWEEN_TESTS;
  is_compositing_test_ = false;
  enable_pixel_dumping_ = false;
  expected_pixel_hash_.clear();
  test_url_ = GURL();
  prefs_ = WebPreferences();
  should_override_prefs_ = false;
  LayoutTestContentBrowserClient::Get()->SetPopupBlockingEnabled(false);
  navigation_history_dump_ = "";
  pixel_dump_.reset();
  actual_pixel_hash_ = "";
  main_frame_dump_ = nullptr;
  waiting_for_pixel_results_ = false;
  waiting_for_main_frame_dump_ = false;
  weak_factory_.InvalidateWeakPtrs();

#if defined(OS_ANDROID)
  // Re-using the shell's main window on Android causes issues with networking
  // requests never succeeding. See http://crbug.com/277652.
  DiscardMainWindow();
#endif
  return true;
}

void BlinkTestController::SetTempPath(const base::FilePath& temp_path) {
  temp_path_ = temp_path;
}

void BlinkTestController::RendererUnresponsive() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(WARNING) << "renderer unresponsive";
}

void BlinkTestController::OverrideWebkitPrefs(WebPreferences* prefs) {
  if (should_override_prefs_) {
    *prefs = prefs_;
  } else {
    ApplyLayoutTestDefaultPreferences(prefs);
    if (is_compositing_test_) {
      base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
      if (!command_line.HasSwitch(switches::kDisableGpu))
        prefs->accelerated_2d_canvas_enabled = true;
      prefs->mock_scrollbars_enabled = true;
    }
  }
}

void BlinkTestController::OpenURL(const GURL& url) {
  if (test_phase_ != DURING_TEST)
    return;

  Shell::CreateNewWindow(main_window_->web_contents()->GetBrowserContext(),
                         url,
                         main_window_->web_contents()->GetSiteInstance(),
                         gfx::Size());
}

void BlinkTestController::OnTestFinishedInSecondaryRenderer() {
  RenderViewHost* main_render_view_host =
      main_window_->web_contents()->GetRenderViewHost();
  main_render_view_host->Send(new ShellViewMsg_TestFinishedInSecondaryRenderer(
      main_render_view_host->GetRoutingID()));
}

void BlinkTestController::OnInitiateCaptureDump(bool capture_navigation_history,
                                                bool capture_pixels) {
  if (test_phase_ != DURING_TEST)
    return;

  if (capture_navigation_history) {
    RenderFrameHost* main_rfh = main_window_->web_contents()->GetMainFrame();
    for (auto* window : Shell::windows()) {
      WebContents* web_contents = window->web_contents();
      // Only capture the history from windows in the same process_host as the
      // main window. During layout tests, we only use two processes when a
      // devtools window is open.
      // TODO(https://crbug.com/771003): Dump history for all WebContentses, not
      // just ones that happen to be in the same process_host as the main test
      // window's main frame.
      if (main_rfh->GetProcess() != web_contents->GetMainFrame()->GetProcess())
        continue;

      navigation_history_dump_ +=
          "\n============== Back Forward List ==============\n";
      navigation_history_dump_ += DumpHistoryForWebContents(web_contents);
      navigation_history_dump_ +=
          "===============================================\n";
    }
  }

  // Ensure to say that we need to wait for main frame dump here, since
  // CopyFromSurface call below may synchronously issue the callback, meaning
  // that we would report results too early.
  waiting_for_main_frame_dump_ = true;

  if (capture_pixels) {
    DCHECK(base::CommandLine::ForCurrentProcess()->HasSwitch(
        switches::kEnableDisplayCompositorPixelDump));
    waiting_for_pixel_results_ = true;

    // Trigger compositing on all frames.
    CompositeAllFrames();

    // Enqueue a copy output request.
    auto* rwhv = main_window_->web_contents()->GetRenderWidgetHostView();
    rwhv->CopyFromSurface(
        gfx::Rect(), gfx::Size(),
        base::BindOnce(&BlinkTestController::OnPixelDumpCaptured,
                       weak_factory_.GetWeakPtr()));
  }

  RenderFrameHost* rfh = main_window_->web_contents()->GetMainFrame();
  printer_->StartStateDump();
  GetLayoutTestControlPtr(rfh)->CaptureDump(
      base::BindOnce(&BlinkTestController::OnCaptureDumpCompleted,
                     weak_factory_.GetWeakPtr()));
}

void BlinkTestController::CompositeAllFrames() {
  std::vector<Node> node_storage;
  Node* root = BuildFrameTree(main_window_->web_contents()->GetAllFrames(),
                              &node_storage);

  mojo::SyncCallRestrictions::ScopedAllowSyncCall allow_sync_calls;
  CompositeDepthFirst(root);
}

BlinkTestController::Node* BlinkTestController::BuildFrameTree(
    const std::vector<RenderFrameHost*>& frames,
    std::vector<Node>* storage) const {
  // Ensure we don't reallocate during tree construction.
  storage->reserve(frames.size());

  // Returns a Node for a given RenderFrameHost, or nullptr if doesn't exist.
  auto node_for_frame = [storage](RenderFrameHost* rfh) {
    auto it = std::find_if(
        storage->begin(), storage->end(),
        [rfh](const Node& node) { return node.render_frame_host == rfh; });
    return it == storage->end() ? nullptr : &*it;
  };

  // Add all of the frames to storage.
  for (auto* frame : frames) {
    DCHECK(!node_for_frame(frame)) << "Frame seen multiple times.";
    storage->emplace_back(frame);
  }

  // Construct a tree rooted at |root|.
  Node* root = nullptr;
  for (auto* frame : frames) {
    Node* node = node_for_frame(frame);
    DCHECK(node);
    if (!frame->GetParent()) {
      DCHECK(!root) << "Multiple roots found.";
      root = node;
    } else {
      Node* parent = node_for_frame(frame->GetParent());
      DCHECK(parent);
      parent->children.push_back(node);
    }
  }
  DCHECK(root) << "No root found.";
  return root;
}

void BlinkTestController::CompositeDepthFirst(Node* node) {
  if (!node->render_frame_host->IsRenderFrameLive())
    return;
  for (auto* child : node->children)
    CompositeDepthFirst(child);
  GetLayoutTestControlPtr(node->render_frame_host)->CompositeWithRaster();
}

bool BlinkTestController::IsMainWindow(WebContents* web_contents) const {
  return main_window_ && web_contents == main_window_->web_contents();
}

std::unique_ptr<BluetoothChooser> BlinkTestController::RunBluetoothChooser(
    RenderFrameHost* frame,
    const BluetoothChooser::EventHandler& event_handler) {
  // TODO(https://crbug.com/509038): Remove |bluetooth_chooser_factory_| once
  // all of the Web Bluetooth tests are migrated to external/wpt/.
  if (bluetooth_chooser_factory_) {
    return bluetooth_chooser_factory_->RunBluetoothChooser(frame,
                                                           event_handler);
  }
  auto next_fake_bluetooth_chooser =
      LayoutTestContentBrowserClient::Get()->GetNextFakeBluetoothChooser();
  if (next_fake_bluetooth_chooser) {
    next_fake_bluetooth_chooser->SetEventHandler(event_handler);
    return next_fake_bluetooth_chooser;
  }
  return std::make_unique<LayoutTestFirstDeviceBluetoothChooser>(event_handler);
}

bool BlinkTestController::OnMessageReceived(const IPC::Message& message) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(BlinkTestController, message)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_PrintMessage, OnPrintMessage)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_PrintMessageToStderr,
                        OnPrintMessageToStderr)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_InitiateLayoutDump,
                        OnInitiateLayoutDump)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_OverridePreferences,
                        OnOverridePreferences)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_SetPopupBlockingEnabled,
                        OnSetPopupBlockingEnabled)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_NavigateSecondaryWindow,
                        OnNavigateSecondaryWindow)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_GoToOffset, OnGoToOffset)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_Reload, OnReload)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_LoadURLForFrame, OnLoadURLForFrame)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_CloseRemainingWindows,
                        OnCloseRemainingWindows)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_ResetDone, OnResetDone)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_SetBluetoothManualChooser,
                        OnSetBluetoothManualChooser)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_GetBluetoothManualChooserEvents,
                        OnGetBluetoothManualChooserEvents)
    IPC_MESSAGE_HANDLER(ShellViewHostMsg_SendBluetoothManualChooserEvent,
                        OnSendBluetoothManualChooserEvent)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()

  return handled;
}

void BlinkTestController::PluginCrashed(const base::FilePath& plugin_path,
                                        base::ProcessId plugin_pid) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  printer_->AddErrorMessage(
      base::StringPrintf("#CRASHED - plugin (pid %" CrPRIdPid ")", plugin_pid));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(base::IgnoreResult(
                                    &BlinkTestController::DiscardMainWindow),
                                weak_factory_.GetWeakPtr()));
}

void BlinkTestController::RenderFrameCreated(
    RenderFrameHost* render_frame_host) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  HandleNewRenderFrameHost(render_frame_host);
}

void BlinkTestController::DevToolsProcessCrashed() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  printer_->AddErrorMessage("#CRASHED - devtools");
  devtools_bindings_.reset();
  if (devtools_window_)
    devtools_window_->Close();
  devtools_window_ = nullptr;
}

void BlinkTestController::WebContentsDestroyed() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  printer_->AddErrorMessage("FAIL: main window was destroyed");
  DiscardMainWindow();
}

void BlinkTestController::RenderProcessHostDestroyed(
    RenderProcessHost* render_process_host) {
  render_process_host_observer_.Remove(render_process_host);
  all_observed_render_process_hosts_.erase(render_process_host);
  main_window_render_process_hosts_.erase(render_process_host);
}

void BlinkTestController::RenderProcessExited(
    RenderProcessHost* render_process_host,
    base::TerminationStatus status,
    int exit_code) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  switch (status) {
    case base::TerminationStatus::TERMINATION_STATUS_NORMAL_TERMINATION:
    case base::TerminationStatus::TERMINATION_STATUS_STILL_RUNNING:
      break;

    case base::TerminationStatus::TERMINATION_STATUS_ABNORMAL_TERMINATION:
    case base::TerminationStatus::TERMINATION_STATUS_LAUNCH_FAILED:
    case base::TerminationStatus::TERMINATION_STATUS_PROCESS_CRASHED:
    case base::TerminationStatus::TERMINATION_STATUS_PROCESS_WAS_KILLED:
    default: {
      const base::Process& process = render_process_host->GetProcess();
      if (process.IsValid()) {
        printer_->AddErrorMessage(std::string("#CRASHED - renderer (pid ") +
                                  base::IntToString(process.Pid()) + ")");
      } else {
        printer_->AddErrorMessage("#CRASHED - renderer");
      }

      DiscardMainWindow();
      break;
    }
  }
}

void BlinkTestController::Observe(int type,
                                  const NotificationSource& source,
                                  const NotificationDetails& details) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  switch (type) {
    case NOTIFICATION_RENDERER_PROCESS_CREATED: {
      if (!main_window_)
        return;
      RenderViewHost* render_view_host =
          main_window_->web_contents()->GetRenderViewHost();
      if (!render_view_host)
        return;
      RenderProcessHost* render_process_host =
          Source<RenderProcessHost>(source).ptr();
      if (render_process_host != render_view_host->GetProcess())
        return;
      current_pid_ = render_process_host->GetProcess().Pid();
      break;
    }
    default:
      NOTREACHED();
  }
}

void BlinkTestController::OnGpuProcessCrashed(
    base::TerminationStatus exit_code) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  printer_->AddErrorMessage("#CRASHED - gpu");
  DiscardMainWindow();
}

void BlinkTestController::DiscardMainWindow() {
  // If we're running a test, we need to close all windows and exit the message
  // loop. Otherwise, we're already outside of the message loop, and we just
  // discard the main window.
  devtools_bindings_.reset();
  devtools_protocol_test_bindings_.reset();
  WebContentsObserver::Observe(nullptr);
  if (test_phase_ != BETWEEN_TESTS) {
    Shell::CloseAllWindows();
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::MessageLoop::QuitWhenIdleClosure());
    test_phase_ = CLEAN_UP;
  } else if (main_window_) {
    main_window_->Close();
  }
  main_window_ = nullptr;
  current_pid_ = base::kNullProcessId;
}

void BlinkTestController::HandleNewRenderFrameHost(RenderFrameHost* frame) {
  RenderProcessHost* process_host = frame->GetProcess();
  bool main_window =
      WebContents::FromRenderFrameHost(frame) == main_window_->web_contents();

  // Track pid of the renderer handling the main frame.
  if (main_window && frame->GetParent() == nullptr) {
    const base::Process& process = process_host->GetProcess();
    if (process.IsValid())
      current_pid_ = process.Pid();
  }

  // Is this the 1st time this renderer contains parts of the main test window?
  if (main_window &&
      !base::ContainsKey(main_window_render_process_hosts_, process_host)) {
    main_window_render_process_hosts_.insert(process_host);

    // Make sure the new renderer process_host has a test configuration shared
    // with other renderers.
    mojom::ShellTestConfigurationPtr params =
        mojom::ShellTestConfiguration::New();
    params->allow_external_pages = false;
    params->current_working_directory = current_working_directory_;
    params->temp_path = temp_path_;
    params->build_directory = GetBuildDirectory();
    params->test_url = test_url_;
    params->enable_pixel_dumping = enable_pixel_dumping_;
    params->allow_external_pages =
        base::CommandLine::ForCurrentProcess()->HasSwitch(
            switches::kAllowExternalPages);
    params->expected_pixel_hash = expected_pixel_hash_;
    params->initial_size = initial_size_;

    if (did_send_initial_test_configuration_) {
      GetLayoutTestControlPtr(frame)->ReplicateTestConfiguration(
          std::move(params));
    } else {
      did_send_initial_test_configuration_ = true;
      GetLayoutTestControlPtr(frame)->SetTestConfiguration(std::move(params));
    }
  }

  // Is this a previously unknown renderer process_host?
  if (!render_process_host_observer_.IsObserving(process_host)) {
    render_process_host_observer_.Add(process_host);
    all_observed_render_process_hosts_.insert(process_host);

    if (!main_window) {
      GetLayoutTestControlPtr(frame)->SetupSecondaryRenderer();
    }

    process_host->Send(new LayoutTestMsg_ReplicateLayoutTestRuntimeFlagsChanges(
        accumulated_layout_test_runtime_flags_changes_));
  }
}

void BlinkTestController::OnTestFinished() {
  test_phase_ = CLEAN_UP;
  if (!printer_->output_finished())
    printer_->PrintImageFooter();
  if (main_window_)
    main_window_->web_contents()->ExitFullscreen(/*will_cause_resize=*/false);
  devtools_bindings_.reset();
  devtools_protocol_test_bindings_.reset();

  ShellBrowserContext* browser_context =
      ShellContentBrowserClient::Get()->browser_context();

  base::RepeatingClosure barrier_closure = base::BarrierClosure(
      3, base::BindOnce(&BlinkTestController::OnCleanupFinished,
                        weak_factory_.GetWeakPtr()));

  StoragePartition* storage_partition =
      BrowserContext::GetStoragePartition(browser_context, nullptr);
  storage_partition->GetServiceWorkerContext()->ClearAllServiceWorkersForTest(
      barrier_closure);
  storage_partition->ClearBluetoothAllowedDevicesMapForTesting();

  // TODO(nhiroki): Add a comment about the reason why we terminate all shared
  // workers here.
  TerminateAllSharedWorkersForTesting(
      BrowserContext::GetStoragePartition(
          ShellContentBrowserClient::Get()->browser_context(), nullptr),
      barrier_closure);

  // Resets the SignedHTTPExchange verification time overriding. The time for
  // the verification may be changed in the LayoutTest using Mojo JS API.
  BrowserThread::PostTaskAndReply(
      BrowserThread::IO, FROM_HERE,
      base::BindOnce(
          &WebPackageContext::SetSignedExchangeVerificationTimeForTesting,
          base::Unretained(storage_partition->GetWebPackageContext()),
          base::nullopt),
      barrier_closure);
}

void BlinkTestController::OnCleanupFinished() {
  if (main_window_) {
    main_window_->web_contents()->Stop();
    RenderViewHost* rvh = main_window_->web_contents()->GetRenderViewHost();
    rvh->Send(new ShellViewMsg_Reset(rvh->GetRoutingID()));
  }
  if (secondary_window_) {
    secondary_window_->web_contents()->Stop();
    RenderViewHost* rvh =
        secondary_window_->web_contents()->GetRenderViewHost();
    rvh->Send(new ShellViewMsg_Reset(rvh->GetRoutingID()));
  }
}

void BlinkTestController::OnCaptureDumpCompleted(
    mojom::LayoutTestDumpPtr dump) {
  main_frame_dump_ = std::move(dump);

  waiting_for_main_frame_dump_ = false;
  ReportResults();
}

void BlinkTestController::OnPixelDumpCaptured(const SkBitmap& snapshot) {
  DCHECK(!snapshot.drawsNothing());

  // The snapshot arrives from the GPU process via shared memory. Because MSan
  // can't track initializedness across processes, we must assure it that the
  // pixels are in fact initialized.
  MSAN_UNPOISON(snapshot.getPixels(), snapshot.computeByteSize());
  base::MD5Digest digest;
  base::MD5Sum(snapshot.getPixels(), snapshot.computeByteSize(), &digest);
  actual_pixel_hash_ = base::MD5DigestToBase16(digest);
  pixel_dump_ = snapshot;

  waiting_for_pixel_results_ = false;
  ReportResults();
}

void BlinkTestController::ReportResults() {
  if (waiting_for_pixel_results_ || waiting_for_main_frame_dump_)
    return;

  if (main_frame_dump_->audio)
    OnAudioDump(*main_frame_dump_->audio);
  if (main_frame_dump_->layout)
    OnTextDump(*main_frame_dump_->layout);
  // If we have local pixels, report that. Otherwise report whatever the pixel
  // dump received from the renderer contains.
  if (pixel_dump_) {
    OnImageDump(actual_pixel_hash_, *pixel_dump_);
  } else if (!main_frame_dump_->actual_pixel_hash.empty()) {
    OnImageDump(main_frame_dump_->actual_pixel_hash, main_frame_dump_->pixels);
  }
  OnTestFinished();
}

void BlinkTestController::OnImageDump(const std::string& actual_pixel_hash,
                                      const SkBitmap& image) {
  printer_->PrintImageHeader(actual_pixel_hash, expected_pixel_hash_);

  // Only encode and dump the png if the hashes don't match. Encoding the
  // image is really expensive.
  if (actual_pixel_hash != expected_pixel_hash_) {
    std::vector<unsigned char> png;

    bool discard_transparency = true;
    if (base::CommandLine::ForCurrentProcess()->HasSwitch(
            switches::kForceOverlayFullscreenVideo)) {
      discard_transparency = false;
    }

    gfx::PNGCodec::ColorFormat pixel_format;
    switch (image.info().colorType()) {
      case kBGRA_8888_SkColorType:
        pixel_format = gfx::PNGCodec::FORMAT_BGRA;
        break;
      case kRGBA_8888_SkColorType:
        pixel_format = gfx::PNGCodec::FORMAT_RGBA;
        break;
      default:
        NOTREACHED();
        return;
    }

    std::vector<gfx::PNGCodec::Comment> comments;
    comments.push_back(gfx::PNGCodec::Comment("checksum", actual_pixel_hash));
    bool success = gfx::PNGCodec::Encode(
        static_cast<const unsigned char*>(image.getPixels()), pixel_format,
        gfx::Size(image.width(), image.height()),
        static_cast<int>(image.rowBytes()), discard_transparency, comments,
        &png);
    if (success)
      printer_->PrintImageBlock(png);
  }
  printer_->PrintImageFooter();
}

void BlinkTestController::OnAudioDump(const std::vector<unsigned char>& dump) {
  printer_->PrintAudioHeader();
  printer_->PrintAudioBlock(dump);
  printer_->PrintAudioFooter();
}

void BlinkTestController::OnTextDump(const std::string& dump) {
  printer_->PrintTextHeader();
  printer_->PrintTextBlock(dump);
  if (!navigation_history_dump_.empty())
    printer_->PrintTextBlock(navigation_history_dump_);
  printer_->PrintTextFooter();
}

void BlinkTestController::OnInitiateLayoutDump() {
  // There should be at most 1 layout dump in progress at any given time.
  DCHECK_EQ(0, pending_layout_dumps_);

  int number_of_messages = 0;
  for (RenderFrameHost* rfh : main_window_->web_contents()->GetAllFrames()) {
    if (!rfh->IsRenderFrameLive())
      continue;

    ++number_of_messages;
    GetLayoutTestControlPtr(rfh)->DumpFrameLayout(
        base::BindOnce(&BlinkTestController::OnDumpFrameLayoutResponse,
                       weak_factory_.GetWeakPtr(), rfh->GetFrameTreeNodeId()));
  }

  pending_layout_dumps_ = number_of_messages;
}

void BlinkTestController::OnLayoutTestRuntimeFlagsChanged(
    int sender_process_host_id,
    const base::DictionaryValue& changed_layout_test_runtime_flags) {
  // Stash the accumulated changes for future, not-yet-created renderers.
  accumulated_layout_test_runtime_flags_changes_.MergeDictionary(
      &changed_layout_test_runtime_flags);

  // Propagate the changes to all the tracked renderer processes.
  for (RenderProcessHost* process : all_observed_render_process_hosts_) {
    // Do not propagate the changes back to the process that originated
    // them. (propagating them back could also clobber subsequent changes in the
    // originator).
    if (process->GetID() == sender_process_host_id)
      continue;

    process->Send(new LayoutTestMsg_ReplicateLayoutTestRuntimeFlagsChanges(
        changed_layout_test_runtime_flags));
  }
}

void BlinkTestController::OnDumpFrameLayoutResponse(int frame_tree_node_id,
                                                    const std::string& dump) {
  // Store the result.
  auto pair = frame_to_layout_dump_map_.insert(
      std::make_pair(frame_tree_node_id, dump));
  bool insertion_took_place = pair.second;
  DCHECK(insertion_took_place);

  // See if we need to wait for more responses.
  pending_layout_dumps_--;
  DCHECK_LE(0, pending_layout_dumps_);
  if (pending_layout_dumps_ > 0)
    return;

  // If the main test window was destroyed while waiting for the responses, then
  // there is nobody to receive the |stitched_layout_dump| and finish the test.
  if (!web_contents()) {
    OnTestFinished();
    return;
  }

  // Stitch the frame-specific results in the right order.
  std::string stitched_layout_dump;
  for (auto* render_frame_host : web_contents()->GetAllFrames()) {
    auto it =
        frame_to_layout_dump_map_.find(render_frame_host->GetFrameTreeNodeId());
    if (it != frame_to_layout_dump_map_.end()) {
      const std::string& dump = it->second;
      stitched_layout_dump.append(dump);
    }
  }

  // Continue finishing the test.
  RenderViewHost* render_view_host =
      main_window_->web_contents()->GetRenderViewHost();
  render_view_host->Send(new ShellViewMsg_LayoutDumpCompleted(
      render_view_host->GetRoutingID(), stitched_layout_dump));
}

void BlinkTestController::OnPrintMessage(const std::string& message) {
  printer_->AddMessageRaw(message);
}

void BlinkTestController::OnPrintMessageToStderr(const std::string& message) {
  printer_->AddMessageToStderr(message);
}

void BlinkTestController::OnOverridePreferences(const WebPreferences& prefs) {
  should_override_prefs_ = true;
  prefs_ = prefs;

  // Notifies the main RenderViewHost that Blink preferences changed so
  // immediately apply the new settings and to avoid re-usage of cached
  // preferences that are now stale. RenderViewHost::UpdateWebkitPreferences is
  // not used here because it would send an unneeded preferences update to the
  // renderer.
  RenderViewHost* main_render_view_host =
      main_window_->web_contents()->GetRenderViewHost();
  main_render_view_host->OnWebkitPreferencesChanged();
}

void BlinkTestController::OnSetPopupBlockingEnabled(bool block_popups) {
  LayoutTestContentBrowserClient::Get()->SetPopupBlockingEnabled(block_popups);
}

void BlinkTestController::OnNavigateSecondaryWindow(const GURL& url) {
  if (secondary_window_)
    secondary_window_->LoadURL(url);
}

void BlinkTestController::OnInspectSecondaryWindow() {
  if (devtools_bindings_)
    devtools_bindings_->Attach();
}

void BlinkTestController::OnGoToOffset(int offset) {
  main_window_->GoBackOrForward(offset);
}

void BlinkTestController::OnReload() {
  main_window_->Reload();
}

void BlinkTestController::OnLoadURLForFrame(const GURL& url,
                                            const std::string& frame_name) {
  main_window_->LoadURLForFrame(url, frame_name, ui::PAGE_TRANSITION_LINK);
}

void BlinkTestController::OnCloseRemainingWindows() {
  DevToolsAgentHost::DetachAllClients();
  std::vector<Shell*> open_windows(Shell::windows());
  for (size_t i = 0; i < open_windows.size(); ++i) {
    if (open_windows[i] != main_window_ && open_windows[i] != secondary_window_)
      open_windows[i]->Close();
  }
  base::RunLoop().RunUntilIdle();
}

void BlinkTestController::OnResetDone() {
  if (leak_detector_) {
    if (main_window_ && main_window_->web_contents()) {
      RenderViewHost* rvh = main_window_->web_contents()->GetRenderViewHost();
      DCHECK_EQ(GURL(url::kAboutBlankURL),
                rvh->GetMainFrame()->GetLastCommittedURL());
      leak_detector_->TryLeakDetection(
          rvh->GetProcess(),
          base::BindOnce(&BlinkTestController::OnLeakDetectionDone,
                         weak_factory_.GetWeakPtr()));
    }
    return;
  }

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::MessageLoop::QuitWhenIdleClosure());
}

void BlinkTestController::OnLeakDetectionDone(
    const LeakDetector::LeakDetectionReport& report) {
  if (!report.leaked) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::MessageLoop::QuitWhenIdleClosure());
    return;
  }

  printer_->AddErrorMessage(base::StringPrintf(
      "#LEAK - renderer pid %d (%s)", current_pid_, report.detail.c_str()));
  CHECK(!crash_when_leak_found_);

  DiscardMainWindow();
}

void BlinkTestController::OnSetBluetoothManualChooser(bool enable) {
  bluetooth_chooser_factory_.reset();
  if (enable) {
    bluetooth_chooser_factory_.reset(new LayoutTestBluetoothChooserFactory());
  }
}

void BlinkTestController::OnGetBluetoothManualChooserEvents() {
  if (!bluetooth_chooser_factory_) {
    printer_->AddErrorMessage(
        "FAIL: Must call setBluetoothManualChooser before "
        "getBluetoothManualChooserEvents.");
    return;
  }
  RenderViewHost* rvh = main_window_->web_contents()->GetRenderViewHost();
  rvh->Send(new ShellViewMsg_ReplyBluetoothManualChooserEvents(
      rvh->GetRoutingID(), bluetooth_chooser_factory_->GetAndResetEvents()));
}

void BlinkTestController::OnSendBluetoothManualChooserEvent(
    const std::string& event_name,
    const std::string& argument) {
  if (!bluetooth_chooser_factory_) {
    printer_->AddErrorMessage(
        "FAIL: Must call setBluetoothManualChooser before "
        "sendBluetoothManualChooserEvent.");
    return;
  }
  BluetoothChooser::Event event;
  if (event_name == "cancelled") {
    event = BluetoothChooser::Event::CANCELLED;
  } else if (event_name == "selected") {
    event = BluetoothChooser::Event::SELECTED;
  } else if (event_name == "rescan") {
    event = BluetoothChooser::Event::RESCAN;
  } else {
    printer_->AddErrorMessage(base::StringPrintf(
        "FAIL: Unexpected sendBluetoothManualChooserEvent() event name '%s'.",
        event_name.c_str()));
    return;
  }
  bluetooth_chooser_factory_->SendEvent(event, argument);
}

mojom::LayoutTestControl* BlinkTestController::GetLayoutTestControlPtr(
    RenderFrameHost* frame) {
  if (layout_test_control_map_.find(frame) == layout_test_control_map_.end()) {
    frame->GetRemoteAssociatedInterfaces()->GetInterface(
        &layout_test_control_map_[frame]);
    layout_test_control_map_[frame].set_connection_error_handler(
        base::BindOnce(&BlinkTestController::HandleLayoutTestControlError,
                       weak_factory_.GetWeakPtr(), frame));
  }
  DCHECK(layout_test_control_map_[frame].get());
  return layout_test_control_map_[frame].get();
}

void BlinkTestController::HandleLayoutTestControlError(RenderFrameHost* frame) {
  layout_test_control_map_.erase(frame);
}

BlinkTestController::Node::Node() = default;
BlinkTestController::Node::Node(RenderFrameHost* host)
    : render_frame_host(host) {}
BlinkTestController::Node::Node(Node&& other) = default;
BlinkTestController::Node::~Node() = default;

}  // namespace content

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/site_per_process_browsertest.h"

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/callback.h"
#include "base/command_line.h"
#include "base/feature_list.h"
#include "base/json/json_reader.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/scoped_observer.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/pattern.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/bind_test_util.h"
#include "base/test/test_timeouts.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "cc/input/touch_action.h"
#include "components/network_session_configurator/common/network_switches.h"
#include "content/browser/child_process_security_policy_impl.h"
#include "content/browser/frame_host/cross_process_frame_connector.h"
#include "content/browser/frame_host/frame_navigation_entry.h"
#include "content/browser/frame_host/frame_tree.h"
#include "content/browser/frame_host/interstitial_page_impl.h"
#include "content/browser/frame_host/navigation_controller_impl.h"
#include "content/browser/frame_host/navigation_entry_impl.h"
#include "content/browser/frame_host/navigator.h"
#include "content/browser/frame_host/render_frame_host_impl.h"
#include "content/browser/frame_host/render_frame_proxy_host.h"
#include "content/browser/gpu/compositor_util.h"
#include "content/browser/loader/resource_dispatcher_host_impl.h"
#include "content/browser/renderer_host/input/input_router.h"
#include "content/browser/renderer_host/render_view_host_impl.h"
#include "content/browser/renderer_host/render_widget_host_input_event_router.h"
#include "content/browser/renderer_host/render_widget_host_view_child_frame.h"
#include "content/browser/storage_partition_impl.h"
#include "content/browser/url_loader_factory_getter.h"
#include "content/browser/web_contents/web_contents_impl.h"
#include "content/common/frame_messages.h"
#include "content/common/input_messages.h"
#include "content/common/renderer.mojom.h"
#include "content/common/view_messages.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/interstitial_page_delegate.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/notification_observer.h"
#include "content/public/browser/notification_service.h"
#include "content/public/browser/notification_types.h"
#include "content/public/browser/render_widget_host_observer.h"
#include "content/public/browser/resource_dispatcher_host.h"
#include "content/public/common/browser_side_navigation_policy.h"
#include "content/public/common/content_features.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/url_constants.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/content_browser_test_utils.h"
#include "content/public/test/navigation_handle_observer.h"
#include "content/public/test/test_frame_navigation_observer.h"
#include "content/public/test/test_navigation_observer.h"
#include "content/public/test/test_utils.h"
#include "content/public/test/url_loader_interceptor.h"
#include "content/shell/browser/shell.h"
#include "content/shell/common/shell_switches.h"
#include "content/test/content_browser_test_utils_internal.h"
#include "content/test/did_commit_provisional_load_interceptor.h"
#include "ipc/constants.mojom.h"
#include "ipc/ipc_security_test_util.h"
#include "media/base/media_switches.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "net/dns/mock_host_resolver.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "services/network/public/cpp/features.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/feature_policy/feature_policy.h"
#include "third_party/blink/public/common/frame/sandbox_flags.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "third_party/blink/public/platform/web_insecure_request_policy.h"
#include "ui/display/display_switches.h"
#include "ui/display/screen.h"
#include "ui/events/base_event_utils.h"
#include "ui/events/event.h"
#include "ui/events/event_utils.h"
#include "ui/events/gesture_detection/gesture_configuration.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/latency/latency_info.h"
#include "ui/native_theme/native_theme_features.h"

#if defined(USE_AURA)
#include "content/browser/renderer_host/render_widget_host_view_aura.h"
#endif

#if defined(OS_MACOSX)
#include "ui/base/test/scoped_preferred_scroller_style_mac.h"
#endif

#if defined(OS_ANDROID)
#include "base/android/jni_android.h"
#include "base/android/jni_string.h"
#include "base/android/scoped_java_ref.h"
#include "base/json/json_reader.h"
#include "content/browser/android/ime_adapter_android.h"
#include "content/browser/renderer_host/input/touch_selection_controller_client_manager_android.h"
#include "content/browser/renderer_host/render_widget_host_view_android.h"
#include "content/public/browser/android/child_process_importance.h"
#include "content/test/mock_overscroll_refresh_handler_android.h"
#include "ui/events/android/motion_event_android.h"
#include "ui/gfx/geometry/point_f.h"
#endif

#if defined(OS_CHROMEOS)
#include "ui/aura/env.h"
#include "ui/aura/test/test_screen.h"
#endif

using ::testing::SizeIs;

namespace content {

namespace {

// Helper function to send a postMessage and wait for a reply message.  The
// |post_message_script| is executed on the |sender_ftn| frame, and the sender
// frame is expected to post |reply_status| from the DOMAutomationController
// when it receives a reply.
void PostMessageAndWaitForReply(FrameTreeNode* sender_ftn,
                                const std::string& post_message_script,
                                const std::string& reply_status) {
  // Subtle: msg_queue needs to be declared before the ExecuteScript below, or
  // else it might miss the message of interest.  See https://crbug.com/518729.
  DOMMessageQueue msg_queue;

  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      sender_ftn,
      "window.domAutomationController.send(" + post_message_script + ");",
      &success));
  EXPECT_TRUE(success);

  std::string status;
  while (msg_queue.WaitForMessage(&status)) {
    if (status == reply_status)
      break;
  }
}

// Helper function to extract and return "window.receivedMessages" from the
// |sender_ftn| frame.  This variable is used in post_message.html to count the
// number of messages received via postMessage by the current window.
int GetReceivedMessages(FrameTreeNode* ftn) {
  int received_messages = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      ftn, "window.domAutomationController.send(window.receivedMessages);",
      &received_messages));
  return received_messages;
}

// Helper function to perform a window.open from the |caller_frame| targeting a
// frame with the specified name.
void NavigateNamedFrame(const ToRenderFrameHost& caller_frame,
                        const GURL& url,
                        const std::string& name) {
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      caller_frame,
      "window.domAutomationController.send("
      "    !!window.open('" + url.spec() + "', '" + name + "'));",
      &success));
  EXPECT_TRUE(success);
}

// Helper function to generate a click on the given RenderWidgetHost.  The
// mouse event is forwarded directly to the RenderWidgetHost without any
// hit-testing.
void SimulateMouseClick(RenderWidgetHost* rwh, int x, int y) {
  blink::WebMouseEvent mouse_event(
      blink::WebInputEvent::kMouseDown, blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  mouse_event.button = blink::WebPointerProperties::Button::kLeft;
  mouse_event.SetPositionInWidget(x, y);
  rwh->ForwardMouseEvent(mouse_event);
}

// Retrieve document.origin for the frame |ftn|.
std::string GetDocumentOrigin(FrameTreeNode* ftn) {
  std::string origin;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      ftn, "domAutomationController.send(document.origin)", &origin));
  return origin;
}

double GetFrameDeviceScaleFactor(const ToRenderFrameHost& adapter) {
  double device_scale_factor;
  const char kGetFrameDeviceScaleFactor[] =
      "window.domAutomationController.send(window.devicePixelRatio);";
  EXPECT_TRUE(ExecuteScriptAndExtractDouble(adapter, kGetFrameDeviceScaleFactor,
                                            &device_scale_factor));
  return device_scale_factor;
}

// This helper accounts for Android devices which use page scale factor
// different from 1.0. Coordinate targeting needs to be adjusted before
// hit testing.
double GetPageScaleFactor(Shell* shell) {
  return RenderWidgetHostImpl::From(
             shell->web_contents()->GetRenderViewHost()->GetWidget())
      ->last_frame_metadata()
      .page_scale_factor;
}

class RedirectNotificationObserver : public NotificationObserver {
 public:
  // Register to listen for notifications of the given type from either a
  // specific source, or from all sources if |source| is
  // NotificationService::AllSources().
  RedirectNotificationObserver(int notification_type,
                               const NotificationSource& source);
  ~RedirectNotificationObserver() override;

  // Wait until the specified notification occurs.  If the notification was
  // emitted between the construction of this object and this call then it
  // returns immediately.
  void Wait();

  // Returns NotificationService::AllSources() if we haven't observed a
  // notification yet.
  const NotificationSource& source() const {
    return source_;
  }

  const NotificationDetails& details() const {
    return details_;
  }

  // NotificationObserver:
  void Observe(int type,
               const NotificationSource& source,
               const NotificationDetails& details) override;

 private:
  bool seen_;
  bool seen_twice_;
  bool running_;
  NotificationRegistrar registrar_;

  NotificationSource source_;
  NotificationDetails details_;
  scoped_refptr<MessageLoopRunner> message_loop_runner_;

  DISALLOW_COPY_AND_ASSIGN(RedirectNotificationObserver);
};

RedirectNotificationObserver::RedirectNotificationObserver(
    int notification_type,
    const NotificationSource& source)
    : seen_(false),
      running_(false),
      source_(NotificationService::AllSources()) {
  registrar_.Add(this, notification_type, source);
}

RedirectNotificationObserver::~RedirectNotificationObserver() {}

void RedirectNotificationObserver::Wait() {
  if (seen_ && seen_twice_)
    return;

  running_ = true;
  message_loop_runner_ = new MessageLoopRunner;
  message_loop_runner_->Run();
  EXPECT_TRUE(seen_);
}

void RedirectNotificationObserver::Observe(
    int type,
    const NotificationSource& source,
    const NotificationDetails& details) {
  source_ = source;
  details_ = details;
  seen_twice_ = seen_;
  seen_ = true;
  if (!running_)
    return;

  message_loop_runner_->Quit();
  running_ = false;
}

// This observer keeps track of the number of created RenderFrameHosts.  Tests
// can use this to ensure that a certain number of child frames has been
// created after navigating.
class RenderFrameHostCreatedObserver : public WebContentsObserver {
 public:
  RenderFrameHostCreatedObserver(WebContents* web_contents,
                                 int expected_frame_count)
      : WebContentsObserver(web_contents),
        expected_frame_count_(expected_frame_count),
        frames_created_(0),
        message_loop_runner_(new MessageLoopRunner) {}

  ~RenderFrameHostCreatedObserver() override;

  // Runs a nested run loop and blocks until the expected number of
  // RenderFrameHosts is created.
  void Wait();

 private:
  // WebContentsObserver
  void RenderFrameCreated(RenderFrameHost* render_frame_host) override;

  // The number of RenderFrameHosts to wait for.
  int expected_frame_count_;

  // The number of RenderFrameHosts that have been created.
  int frames_created_;

  // The MessageLoopRunner used to spin the message loop.
  scoped_refptr<MessageLoopRunner> message_loop_runner_;

  DISALLOW_COPY_AND_ASSIGN(RenderFrameHostCreatedObserver);
};

RenderFrameHostCreatedObserver::~RenderFrameHostCreatedObserver() {
}

void RenderFrameHostCreatedObserver::Wait() {
  message_loop_runner_->Run();
}

void RenderFrameHostCreatedObserver::RenderFrameCreated(
    RenderFrameHost* render_frame_host) {
  frames_created_++;
  if (frames_created_ == expected_frame_count_) {
    message_loop_runner_->Quit();
  }
}

// This observer detects when WebContents receives notification of a user
// gesture having occurred, following a user input event targeted to
// a RenderWidgetHost under that WebContents.
class UserInteractionObserver : public WebContentsObserver {
 public:
  explicit UserInteractionObserver(WebContents* web_contents)
      : WebContentsObserver(web_contents), user_interaction_received_(false) {}

  ~UserInteractionObserver() override {}

  // Retrieve the flag. There is no need to wait on a loop since
  // DidGetUserInteraction() should be called synchronously with the input
  // event processing in the browser process.
  bool WasUserInteractionReceived() { return user_interaction_received_; }

  void Reset() { user_interaction_received_ = false; }

 private:
  // WebContentsObserver
  void DidGetUserInteraction(const blink::WebInputEvent::Type type) override {
    user_interaction_received_ = true;
  }

  bool user_interaction_received_;

  DISALLOW_COPY_AND_ASSIGN(UserInteractionObserver);
};

// Helper function to focus a frame by sending it a mouse click and then
// waiting for it to become focused.
void FocusFrame(FrameTreeNode* frame) {
  FrameFocusedObserver focus_observer(frame->current_frame_host());
  SimulateMouseClick(frame->current_frame_host()->GetRenderWidgetHost(), 1, 1);
  focus_observer.Wait();
}

// A BrowserMessageFilter that drops SwapOut ACK messages.
class SwapoutACKMessageFilter : public BrowserMessageFilter {
 public:
  SwapoutACKMessageFilter() : BrowserMessageFilter(FrameMsgStart) {}

 protected:
  ~SwapoutACKMessageFilter() override {}

 private:
  // BrowserMessageFilter:
  bool OnMessageReceived(const IPC::Message& message) override {
    return message.type() == FrameHostMsg_SwapOut_ACK::ID;
  }

  DISALLOW_COPY_AND_ASSIGN(SwapoutACKMessageFilter);
};

class RenderWidgetHostVisibilityObserver : public RenderWidgetHostObserver {
 public:
  explicit RenderWidgetHostVisibilityObserver(RenderWidgetHostImpl* rwhi,
                                              bool expected_visibility_state)
      : expected_visibility_state_(expected_visibility_state),
        observer_(this),
        was_observed_(false),
        did_fail_(false),
        render_widget_(rwhi) {
    observer_.Add(render_widget_);
    message_loop_runner_ = new MessageLoopRunner;
  }

  bool WaitUntilSatisfied() {
    if (!was_observed_)
      message_loop_runner_->Run();
    if (observer_.IsObserving(render_widget_))
      observer_.Remove(render_widget_);
    return !did_fail_;
  }

 private:
  void RenderWidgetHostVisibilityChanged(RenderWidgetHost* widget_host,
                                         bool became_visible) override {
    was_observed_ = true;
    did_fail_ = expected_visibility_state_ != became_visible;
    if (message_loop_runner_->loop_running())
      message_loop_runner_->Quit();
  }

  void RenderWidgetHostDestroyed(RenderWidgetHost* widget_host) override {
    observer_.Remove(widget_host);
  }

  bool expected_visibility_state_;
  scoped_refptr<MessageLoopRunner> message_loop_runner_;
  ScopedObserver<RenderWidgetHost, RenderWidgetHostObserver> observer_;
  bool was_observed_;
  bool did_fail_;
  RenderWidgetHost* render_widget_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetHostVisibilityObserver);
};

class TestInterstitialDelegate : public InterstitialPageDelegate {
 private:
  // InterstitialPageDelegate:
  std::string GetHTMLContents() override { return "<p>Interstitial</p>"; }
};

#if defined(OS_ANDROID)
bool ConvertJSONToPoint(const std::string& str, gfx::PointF* point) {
  std::unique_ptr<base::Value> value = base::JSONReader::Read(str);
  if (!value)
    return false;
  base::DictionaryValue* root;
  if (!value->GetAsDictionary(&root))
    return false;
  double x, y;
  if (!root->GetDouble("x", &x))
    return false;
  if (!root->GetDouble("y", &y))
    return false;
  point->set_x(x);
  point->set_y(y);
  return true;
}
#endif  // defined (OS_ANDROID)

void OpenURLBlockUntilNavigationComplete(Shell* shell, const GURL& url) {
  WaitForLoadStop(shell->web_contents());
  TestNavigationObserver same_tab_observer(shell->web_contents(), 1);

  OpenURLParams params(
      url,
      content::Referrer(shell->web_contents()->GetLastCommittedURL(),
                        blink::kWebReferrerPolicyAlways),
      WindowOpenDisposition::CURRENT_TAB, ui::PAGE_TRANSITION_LINK,
      true /* is_renderer_initiated */);
  shell->OpenURLFromTab(shell->web_contents(), params);

  same_tab_observer.Wait();
}

// Helper function to generate a feature policy for a single feature and a list
// of origins. (Equivalent to the declared policy "feature origin1 origin2...".)
blink::ParsedFeaturePolicy CreateFPHeader(
    blink::mojom::FeaturePolicyFeature feature,
    const std::vector<GURL>& origins) {
  blink::ParsedFeaturePolicy result(1);
  result[0].feature = feature;
  result[0].matches_all_origins = false;
  DCHECK(!origins.empty());
  for (const GURL& origin : origins)
    result[0].origins.push_back(url::Origin::Create(origin));
  return result;
}

// Helper function to generate a feature policy for a single feature which
// matches every origin. (Equivalent to the declared policy "feature *".)
blink::ParsedFeaturePolicy CreateFPHeaderMatchesAll(
    blink::mojom::FeaturePolicyFeature feature) {
  blink::ParsedFeaturePolicy result(1);
  result[0].feature = feature;
  result[0].matches_all_origins = true;
  return result;
}

// Check frame depth on node, widget, and process all match expected depth.
void CheckFrameDepth(unsigned int expected_depth, FrameTreeNode* node) {
  EXPECT_EQ(expected_depth, node->depth());
  RenderProcessHost::Priority priority =
      node->current_frame_host()->GetRenderWidgetHost()->GetPriority();
  EXPECT_EQ(expected_depth, priority.frame_depth);
  EXPECT_EQ(
      expected_depth,
      node->current_frame_host()->GetProcess()->GetFrameDepthForTesting());
}

}  // namespace

//
// SitePerProcessBrowserTest
//

SitePerProcessBrowserTest::SitePerProcessBrowserTest() {}

std::string SitePerProcessBrowserTest::DepictFrameTree(FrameTreeNode* node) {
  return visualizer_.DepictFrameTree(node);
}

void SitePerProcessBrowserTest::SetUpCommandLine(
    base::CommandLine* command_line) {
  IsolateAllSitesForTesting(command_line);
#if !defined(OS_ANDROID)
  // TODO(bokan): Needed for scrollability check in
  // FrameOwnerPropertiesPropagationScrolling. crbug.com/662196.
  feature_list_.InitAndDisableFeature(features::kOverlayScrollbar);
#endif
}

void SitePerProcessBrowserTest::SetUpOnMainThread() {
  host_resolver()->AddRule("*", "127.0.0.1");
  SetupCrossSiteRedirector(embedded_test_server());
  ASSERT_TRUE(embedded_test_server()->Start());
}

//
// SitePerProcessHighDPIBrowserTest
//

class SitePerProcessHighDPIBrowserTest : public SitePerProcessBrowserTest {
 public:
  const double kDeviceScaleFactor = 2.0;

  SitePerProcessHighDPIBrowserTest() {}

 protected:
  void SetUpCommandLine(base::CommandLine* command_line) override {
    SitePerProcessBrowserTest::SetUpCommandLine(command_line);
    command_line->AppendSwitchASCII(
        switches::kForceDeviceScaleFactor,
        base::StringPrintf("%f", kDeviceScaleFactor));
  }
};

// SitePerProcessIgnoreCertErrorsBrowserTest

class SitePerProcessIgnoreCertErrorsBrowserTest
    : public SitePerProcessBrowserTest {
 public:
  SitePerProcessIgnoreCertErrorsBrowserTest() {}

 protected:
  void SetUpCommandLine(base::CommandLine* command_line) override {
    SitePerProcessBrowserTest::SetUpCommandLine(command_line);
    command_line->AppendSwitch(switches::kIgnoreCertificateErrors);
  }
};

// SitePerProcessFeaturePolicyJavaScriptBrowserTest

class SitePerProcessFeaturePolicyJavaScriptBrowserTest
    : public SitePerProcessBrowserTest {
 public:
  SitePerProcessFeaturePolicyJavaScriptBrowserTest() = default;

  // Enable the feature policy JavaScript interface
  void SetUpCommandLine(base::CommandLine* command_line) override {
    SitePerProcessBrowserTest::SetUpCommandLine(command_line);
    command_line->AppendSwitchASCII("enable-blink-features",
                                    "FeaturePolicyJavaScriptInterface");
  }
};

// SitePerProcessAutoplayBrowserTest

class SitePerProcessAutoplayBrowserTest : public SitePerProcessBrowserTest {
 public:
  SitePerProcessAutoplayBrowserTest() = default;

  void SetUpCommandLine(base::CommandLine* command_line) override {
    SitePerProcessBrowserTest::SetUpCommandLine(command_line);
    command_line->AppendSwitchASCII(
        switches::kAutoplayPolicy,
        switches::autoplay::kDocumentUserActivationRequiredPolicy);
    command_line->AppendSwitchASCII("enable-blink-features",
                                    "FeaturePolicyAutoplayFeature");
  }

  bool AutoplayAllowed(const ToRenderFrameHost& adapter,
                       bool with_user_gesture) {
    RenderFrameHost* rfh = adapter.render_frame_host();
    const char* test_script = "attemptPlay();";
    bool worked = false;
    if (with_user_gesture) {
      EXPECT_TRUE(ExecuteScriptAndExtractBool(rfh, test_script, &worked));
    } else {
      EXPECT_TRUE(ExecuteScriptWithoutUserGestureAndExtractBool(
          rfh, test_script, &worked));
    }
    return worked;
  }

  void NavigateFrameAndWait(FrameTreeNode* node, const GURL& url) {
    NavigateFrameToURL(node, url);
    EXPECT_TRUE(WaitForLoadStop(shell()->web_contents()));
    EXPECT_EQ(url, node->current_url());
  }
};

class SitePerProcesScrollAnchorTest : public SitePerProcessBrowserTest {
 public:
  SitePerProcesScrollAnchorTest() = default;

  void SetUpCommandLine(base::CommandLine* command_line) override {
    SitePerProcessBrowserTest::SetUpCommandLine(command_line);
    command_line->AppendSwitchASCII("enable-blink-features",
                                    "ScrollAnchorSerialization");
  }
};

// SitePerProcessEmbedderCSPEnforcementBrowserTest

class SitePerProcessEmbedderCSPEnforcementBrowserTest
    : public SitePerProcessBrowserTest {
 public:
  SitePerProcessEmbedderCSPEnforcementBrowserTest() {}

 protected:
  void SetUpCommandLine(base::CommandLine* command_line) override {
    SitePerProcessBrowserTest::SetUpCommandLine(command_line);
    // TODO(amalika): Remove this switch when the EmbedderCSPEnforcement becomes
    // stable
    command_line->AppendSwitchASCII(switches::kEnableBlinkFeatures,
                                    "EmbedderCSPEnforcement");
  }
};

// SitePerProcessProgrammaticScrollTest.

class SitePerProcessProgrammaticScrollTest : public SitePerProcessBrowserTest {
 public:
  SitePerProcessProgrammaticScrollTest()
      : kInfinity(1000000U), kPositiveXYPlane(0, 0, kInfinity, kInfinity) {}

 protected:
  const size_t kInfinity;
  const std::string kIframeOutOfViewHTML = "/iframe_out_of_view.html";
  const std::string kIframeClippedHTML = "/iframe_clipped.html";
  const std::string kInputBoxHTML = "/input_box.html";
  const std::string kIframeSelector = "iframe";
  const std::string kInputSelector = "input";
  const gfx::Rect kPositiveXYPlane;

  // Waits until the |load| handle is called inside the frame.
  void WaitForOnLoad(FrameTreeNode* node) {
    RunCommandAndWaitForResponse(node, "notifyWhenLoaded();", "LOADED");
  }

  void WaitForElementVisible(FrameTreeNode* node, const std::string& sel) {
    RunCommandAndWaitForResponse(
        node,
        base::StringPrintf("notifyWhenVisible(document.querySelector('%s'));",
                           sel.c_str()),
        "VISIBLE");
  }

  void WaitForViewportToStabilize(FrameTreeNode* node) {
    RunCommandAndWaitForResponse(node, "notifyWhenViewportStable(0);",
                                 "VIEWPORT_STABLE");
  }

  void AddFocusedInputField(FrameTreeNode* node) {
    ASSERT_TRUE(ExecuteScript(node, "addFocusedInputField();"));
  }

  void SetWindowScroll(FrameTreeNode* node, int x, int y) {
    ASSERT_TRUE(ExecuteScript(
        node, base::StringPrintf("window.scrollTo(%d, %d);", x, y)));
  }

  // Helper function to retrieve the bounding client rect of the element
  // identified by |sel| inside |rfh|.
  gfx::Rect GetBoundingClientRect(FrameTreeNode* node, const std::string& sel) {
    std::string result;
    EXPECT_TRUE(ExecuteScriptAndExtractString(
        node,
        base::StringPrintf(
            "window.domAutomationController.send(rectAsString("
            "    document.querySelector('%s').getBoundingClientRect()));",
            sel.c_str()),
        &result));
    return GetRectFromString(result);
  }

  // Returns a rect representing the current |visualViewport| in the main frame
  // of |contents|.
  gfx::Rect GetVisualViewport(FrameTreeNode* node) {
    std::string result;
    EXPECT_TRUE(ExecuteScriptAndExtractString(
        node,
        "window.domAutomationController.send("
        "    rectAsString(visualViewportAsRect()));",
        &result));
    return GetRectFromString(result);
  }

  float GetVisualViewportScale(FrameTreeNode* node) {
    double scale;
    EXPECT_TRUE(ExecuteScriptAndExtractDouble(
        node, "window.domAutomationController.send(visualViewport.scale);",
        &scale));
    return static_cast<float>(scale);
  }

 private:
  void RunCommandAndWaitForResponse(FrameTreeNode* node,
                                    const std::string& command,
                                    const std::string& response) {
    std::string msg_from_renderer;
    ASSERT_TRUE(
        ExecuteScriptAndExtractString(node, command, &msg_from_renderer));
    ASSERT_EQ(response, msg_from_renderer);
  }

  gfx::Rect GetRectFromString(const std::string& str) {
    std::vector<std::string> tokens = base::SplitString(
        str, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    EXPECT_EQ(4U, tokens.size());
    double x = 0.0, y = 0.0, width = 0.0, height = 0.0;
    EXPECT_TRUE(base::StringToDouble(tokens[0], &x));
    EXPECT_TRUE(base::StringToDouble(tokens[1], &y));
    EXPECT_TRUE(base::StringToDouble(tokens[2], &width));
    EXPECT_TRUE(base::StringToDouble(tokens[3], &height));
    return {static_cast<int>(x), static_cast<int>(y), static_cast<int>(width),
            static_cast<int>(height)};
  }

  DISALLOW_COPY_AND_ASSIGN(SitePerProcessProgrammaticScrollTest);
};

IN_PROC_BROWSER_TEST_F(SitePerProcessHighDPIBrowserTest,
                       SubframeLoadsWithCorrectDeviceScaleFactor) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // On Android forcing device scale factor does not work for tests, therefore
  // we ensure that make frame and iframe have the same DIP scale there, but
  // not necessarily kDeviceScaleFactor.
  const double expected_dip_scale =
#if defined(OS_ANDROID)
      GetFrameDeviceScaleFactor(web_contents());
#else
      SitePerProcessHighDPIBrowserTest::kDeviceScaleFactor;
#endif

  EXPECT_EQ(expected_dip_scale, GetFrameDeviceScaleFactor(web_contents()));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1U, root->child_count());

  FrameTreeNode* child = root->child_at(0);
  EXPECT_EQ(expected_dip_scale, GetFrameDeviceScaleFactor(child));
}

#if defined(OS_CHROMEOS)
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       SubframeUpdateToCorrectDeviceScaleFactor) {
  if (aura::Env::GetInstance()->mode() == aura::Env::Mode::MUS)
    return;

  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  EXPECT_EQ(1.0, GetFrameDeviceScaleFactor(web_contents()));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1U, root->child_count());

  FrameTreeNode* child = root->child_at(0);
  EXPECT_EQ(1.0, GetFrameDeviceScaleFactor(child));

  double expected_dip_scale = 2.0;

  // TODO(oshima): allow DeviceScaleFactor change on other platforms
  // (win, linux, mac, android and mus).
  aura::TestScreen* test_screen =
      static_cast<aura::TestScreen*>(display::Screen::GetScreen());
  test_screen->CreateHostForPrimaryDisplay();
  test_screen->SetDeviceScaleFactor(expected_dip_scale);

  double device_scale_factor = 0;
  // Wait until dppx becomes 2 if the frame's dpr hasn't beeen updated
  // to 2 yet.
  const char kScript[] =
      "function sendDpr() "
      "{window.domAutomationController.send(window.devicePixelRatio);}; "
      "if (window.devicePixelRatio == 2) sendDpr();"
      "window.matchMedia('screen and "
      "(min-resolution: 2dppx)').addListener(function(e) { if (e.matches) { "
      "sendDpr();}})";
  // Make sure that both main frame and iframe are updated to 2x.
  EXPECT_TRUE(
      ExecuteScriptAndExtractDouble(child, kScript, &device_scale_factor));
  EXPECT_EQ(expected_dip_scale, device_scale_factor);

  device_scale_factor = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractDouble(web_contents(), kScript,
                                            &device_scale_factor));
  EXPECT_EQ(expected_dip_scale, device_scale_factor);
}

#endif

// Ensure that navigating subframes in --site-per-process mode works and the
// correct documents are committed.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, CrossSiteIframe) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,a(a,a(a)))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());

  // Load same-site page into iframe.
  FrameTreeNode* child = root->child_at(0);
  GURL http_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  NavigateFrameToURL(child, http_url);
  EXPECT_EQ(http_url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());
  {
    // There should be only one RenderWidgetHost when there are no
    // cross-process iframes.
    std::set<RenderWidgetHostView*> views_set =
        web_contents()->GetRenderWidgetHostViewsInTree();
    EXPECT_EQ(1U, views_set.size());
  }

  EXPECT_EQ(
      " Site A\n"
      "   |--Site A\n"
      "   +--Site A\n"
      "        |--Site A\n"
      "        +--Site A\n"
      "             +--Site A\n"
      "Where A = http://a.com/",
      DepictFrameTree(root));

  // Load cross-site page into iframe.
  GURL url = embedded_test_server()->GetURL("foo.com", "/title2.html");
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    NavigateFrameToURL(root->child_at(0), url);
    deleted_observer.WaitUntilDeleted();
  }
  // Verify that the navigation succeeded and the expected URL was loaded.
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());

  // Ensure that we have created a new process for the subframe.
  ASSERT_EQ(2U, root->child_count());
  SiteInstance* site_instance = child->current_frame_host()->GetSiteInstance();
  RenderViewHost* rvh = child->current_frame_host()->render_view_host();
  RenderProcessHost* rph = child->current_frame_host()->GetProcess();
  EXPECT_NE(shell()->web_contents()->GetRenderViewHost(), rvh);
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(), site_instance);
  EXPECT_NE(shell()->web_contents()->GetMainFrame()->GetProcess(), rph);
  {
    // There should be now two RenderWidgetHosts, one for each process
    // rendering a frame.
    std::set<RenderWidgetHostView*> views_set =
        web_contents()->GetRenderWidgetHostViewsInTree();
    EXPECT_EQ(2U, views_set.size());
  }
  RenderFrameProxyHost* proxy_to_parent =
      child->render_manager()->GetProxyToParent();
  EXPECT_TRUE(proxy_to_parent);
  EXPECT_TRUE(proxy_to_parent->cross_process_frame_connector());
  // The out-of-process iframe should have its own RenderWidgetHost,
  // independent of any RenderViewHost.
  EXPECT_NE(
      rvh->GetWidget()->GetView(),
      proxy_to_parent->cross_process_frame_connector()->get_view_for_testing());
  EXPECT_TRUE(child->current_frame_host()->GetRenderWidgetHost());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "        |--Site A -- proxies for B\n"
      "        +--Site A -- proxies for B\n"
      "             +--Site A -- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://foo.com/",
      DepictFrameTree(root));

  // Load another cross-site page into the same iframe.
  url = embedded_test_server()->GetURL("bar.com", "/title3.html");
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    NavigateFrameToURL(root->child_at(0), url);
    deleted_observer.WaitUntilDeleted();
  }
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());

  // Check again that a new process is created and is different from the
  // top level one and the previous one.
  ASSERT_EQ(2U, root->child_count());
  child = root->child_at(0);
  EXPECT_NE(shell()->web_contents()->GetRenderViewHost(),
            child->current_frame_host()->render_view_host());
  EXPECT_NE(rvh, child->current_frame_host()->render_view_host());
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());
  EXPECT_NE(site_instance,
            child->current_frame_host()->GetSiteInstance());
  EXPECT_NE(shell()->web_contents()->GetMainFrame()->GetProcess(),
            child->current_frame_host()->GetProcess());
  EXPECT_NE(rph, child->current_frame_host()->GetProcess());
  {
    std::set<RenderWidgetHostView*> views_set =
        web_contents()->GetRenderWidgetHostViewsInTree();
    EXPECT_EQ(2U, views_set.size());
  }
  EXPECT_EQ(proxy_to_parent, child->render_manager()->GetProxyToParent());
  EXPECT_TRUE(proxy_to_parent->cross_process_frame_connector());
  EXPECT_NE(
      child->current_frame_host()->render_view_host()->GetWidget()->GetView(),
      proxy_to_parent->cross_process_frame_connector()->get_view_for_testing());
  EXPECT_TRUE(child->current_frame_host()->GetRenderWidgetHost());

  EXPECT_EQ(
      " Site A ------------ proxies for C\n"
      "   |--Site C ------- proxies for A\n"
      "   +--Site A ------- proxies for C\n"
      "        |--Site A -- proxies for C\n"
      "        +--Site A -- proxies for C\n"
      "             +--Site A -- proxies for C\n"
      "Where A = http://a.com/\n"
      "      C = http://bar.com/",
      DepictFrameTree(root));
}

// Ensure that title updates affect the correct NavigationEntry after a new
// subframe navigation with an out-of-process iframe.  https://crbug.com/616609.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, TitleAfterCrossSiteIframe) {
  // Start at an initial page.
  GURL initial_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), initial_url));

  // Navigate to a same-site page with a same-site iframe.
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Make the main frame update its title after the subframe loads.
  EXPECT_TRUE(ExecuteScript(shell()->web_contents(),
                            "document.querySelector('iframe').onload = "
                            "    function() { document.title = 'loaded'; };"));
  EXPECT_TRUE(
      ExecuteScript(shell()->web_contents(), "document.title = 'not loaded';"));
  base::string16 expected_title(base::UTF8ToUTF16("loaded"));
  TitleWatcher title_watcher(shell()->web_contents(), expected_title);

  // Navigate the iframe cross-site.
  TestNavigationObserver load_observer(shell()->web_contents());
  GURL frame_url = embedded_test_server()->GetURL("b.com", "/title2.html");
  EXPECT_TRUE(
      ExecuteScript(root->child_at(0)->current_frame_host(),
                    "window.location.href = '" + frame_url.spec() + "';"));
  load_observer.Wait();

  // Wait for the title to update and ensure it affects the right NavEntry.
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());
  NavigationEntry* entry =
      shell()->web_contents()->GetController().GetLastCommittedEntry();
  EXPECT_EQ(expected_title, entry->GetTitle());
}

// Test that the physical backing size and view bounds for a scaled out-of-
// process iframe are set and updated correctly.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CompositorViewportPixelSizeTest) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_scaled_frame.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  ASSERT_EQ(1U, root->child_count());

  FrameTreeNode* parent_iframe_node = root->child_at(0);

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site A ------- proxies for B\n"
      "        +--Site B -- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://baz.com/",
      DepictFrameTree(root));

  FrameTreeNode* nested_iframe_node = parent_iframe_node->child_at(0);
  RenderFrameProxyHost* proxy_to_parent =
      nested_iframe_node->render_manager()->GetProxyToParent();
  CrossProcessFrameConnector* connector =
      proxy_to_parent->cross_process_frame_connector();
  RenderWidgetHostViewBase* rwhv_nested =
      static_cast<RenderWidgetHostViewBase*>(
          nested_iframe_node->current_frame_host()
              ->GetRenderWidgetHost()
              ->GetView());

  WaitForChildFrameSurfaceReady(nested_iframe_node->current_frame_host());

  // Verify that applying a CSS scale transform does not impact the size of the
  // content of the nested iframe.
  EXPECT_EQ(gfx::Size(50, 50), connector->screen_space_rect_in_dip().size());
  EXPECT_EQ(gfx::Size(100, 100), rwhv_nested->GetViewBounds().size());
  EXPECT_EQ(gfx::Size(100, 100), connector->local_frame_size_in_dip());
  EXPECT_EQ(connector->local_frame_size_in_pixels(),
            rwhv_nested->GetCompositorViewportPixelSize());
}

// Test that the view bounds for an out-of-process iframe are set and updated
// correctly, including accounting for local frame offsets in the parent and
// scroll positions.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, ViewBoundsInNestedFrameTest) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  RenderWidgetHostViewBase* rwhv_root = static_cast<RenderWidgetHostViewBase*>(
      root->current_frame_host()->GetRenderWidgetHost()->GetView());
  ASSERT_EQ(1U, root->child_count());

  FrameTreeNode* parent_iframe_node = root->child_at(0);
  GURL site_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_positioned_frame.html"));
  NavigateFrameToURL(parent_iframe_node, site_url);

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site A ------- proxies for B\n"
      "        +--Site B -- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://baz.com/",
      DepictFrameTree(root));

  FrameTreeNode* nested_iframe_node = parent_iframe_node->child_at(0);
  RenderWidgetHostViewBase* rwhv_nested =
      static_cast<RenderWidgetHostViewBase*>(
          nested_iframe_node->current_frame_host()
              ->GetRenderWidgetHost()
              ->GetView());
  WaitForChildFrameSurfaceReady(nested_iframe_node->current_frame_host());

  float scale_factor = GetPageScaleFactor(shell());

  // Get the view bounds of the nested iframe, which should account for the
  // relative offset of its direct parent within the root frame.
  gfx::Rect bounds = rwhv_nested->GetViewBounds();

  scoped_refptr<UpdateResizeParamsMessageFilter> filter =
      new UpdateResizeParamsMessageFilter();
  root->current_frame_host()->GetProcess()->AddFilter(filter.get());

  // Scroll the parent frame downward to verify that the child rect gets updated
  // correctly.
  blink::WebMouseWheelEvent scroll_event(
      blink::WebInputEvent::kMouseWheel, blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());

  scroll_event.SetPositionInWidget(
      gfx::ToFlooredInt((bounds.x() - rwhv_root->GetViewBounds().x() - 5) *
                        scale_factor),
      gfx::ToFlooredInt((bounds.y() - rwhv_root->GetViewBounds().y() - 5) *
                        scale_factor));
  scroll_event.delta_x = 0.0f;
  scroll_event.delta_y = -30.0f;
  scroll_event.phase = blink::WebMouseWheelEvent::kPhaseBegan;
  rwhv_root->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());

  filter->WaitForRect();

  // The precise amount of scroll for the first view position update is not
  // deterministic, so this simply verifies that the OOPIF moved from its
  // earlier position.
  gfx::Rect update_rect = filter->last_rect();
  EXPECT_LT(update_rect.y(), bounds.y() - rwhv_root->GetViewBounds().y());
}

// This test verifies that scroll bubbling from an OOPIF properly forwards
// GestureFlingStart events from the child frame to the parent frame. This
// test times out on failure.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       GestureFlingStartEventsBubble) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  ASSERT_EQ(1U, root->child_count());
  RenderWidgetHost* root_rwh =
      root->current_frame_host()->GetRenderWidgetHost();

  FrameTreeNode* child_iframe_node = root->child_at(0);

  RenderWidgetHost* child_rwh =
      child_iframe_node->current_frame_host()->GetRenderWidgetHost();

  RenderWidgetHostViewBase* child_rwhv =
      static_cast<RenderWidgetHostViewBase*>(child_rwh->GetView());

  // If wheel scroll latching is enabled, the fling start won't bubble since
  // its corresponding GSB hasn't bubbled.
  InputEventAckWaiter gesture_fling_start_ack_observer(
      (child_rwhv->wheel_scroll_latching_enabled() ? child_rwh : root_rwh),
      blink::WebInputEvent::kGestureFlingStart);

  WaitForChildFrameSurfaceReady(child_iframe_node->current_frame_host());

  gesture_fling_start_ack_observer.Reset();
  // Send a GSB, GSU, GFS sequence and verify that the GFS bubbles.
  blink::WebGestureEvent gesture_scroll_begin(
      blink::WebGestureEvent::kGestureScrollBegin,
      blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests(),
      blink::kWebGestureDeviceTouchscreen);
  gesture_scroll_begin.data.scroll_begin.delta_hint_units =
      blink::WebGestureEvent::ScrollUnits::kPrecisePixels;
  gesture_scroll_begin.data.scroll_begin.delta_x_hint = 0.f;
  gesture_scroll_begin.data.scroll_begin.delta_y_hint = 5.f;

  child_rwh->ForwardGestureEvent(gesture_scroll_begin);

  blink::WebGestureEvent gesture_scroll_update(
      blink::WebGestureEvent::kGestureScrollUpdate,
      blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests(),
      blink::kWebGestureDeviceTouchscreen);
  gesture_scroll_update.data.scroll_update.delta_units =
      blink::WebGestureEvent::ScrollUnits::kPrecisePixels;
  gesture_scroll_update.data.scroll_update.delta_x = 0.f;
  gesture_scroll_update.data.scroll_update.delta_y = 5.f;
  gesture_scroll_update.data.scroll_update.velocity_y = 5.f;

  child_rwh->ForwardGestureEvent(gesture_scroll_update);

  blink::WebGestureEvent gesture_fling_start(
      blink::WebGestureEvent::kGestureFlingStart,
      blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests(),
      blink::kWebGestureDeviceTouchscreen);
  gesture_fling_start.data.fling_start.velocity_x = 0.f;
  gesture_fling_start.data.fling_start.velocity_y = 5.f;

  child_rwh->ForwardGestureEvent(gesture_fling_start);

  // We now wait for the fling start event to be acked by the parent
  // frame. If the test fails, then the test times out.
  gesture_fling_start_ack_observer.Wait();
}

// Test that scrolling a nested out-of-process iframe bubbles unused scroll
// delta to a parent frame.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, ScrollBubblingFromOOPIFTest) {
  ui::GestureConfiguration::GetInstance()->set_scroll_debounce_interval_in_ms(
      0);
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  ASSERT_EQ(1U, root->child_count());

  FrameTreeNode* parent_iframe_node = root->child_at(0);

  // This test uses the position of the nested iframe within the parent iframe
  // to infer the scroll position of the parent. UpdateResizeParamsMessageFilter
  // catches updates to the position in order to avoid busy waiting.
  // It gets created early to catch the initial rects from the navigation.
  scoped_refptr<UpdateResizeParamsMessageFilter> filter =
      new UpdateResizeParamsMessageFilter();
  parent_iframe_node->current_frame_host()->GetProcess()->AddFilter(
      filter.get());

  InputEventAckWaiter ack_observer(
      parent_iframe_node->current_frame_host()->GetRenderWidgetHost(),
      blink::WebInputEvent::kGestureScrollEnd);

  GURL site_url(embedded_test_server()->GetURL(
      "b.com", "/frame_tree/page_with_positioned_frame.html"));
  NavigateFrameToURL(parent_iframe_node, site_url);

  // Navigate the nested frame to a page large enough to have scrollbars.
  FrameTreeNode* nested_iframe_node = parent_iframe_node->child_at(0);
  GURL nested_site_url(embedded_test_server()->GetURL(
      "baz.com", "/tall_page.html"));
  NavigateFrameToURL(nested_iframe_node, nested_site_url);

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   +--Site B ------- proxies for A C\n"
      "        +--Site C -- proxies for A B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/\n"
      "      C = http://baz.com/",
      DepictFrameTree(root));

  RenderWidgetHostViewBase* rwhv_parent =
      static_cast<RenderWidgetHostViewBase*>(
          parent_iframe_node->current_frame_host()
              ->GetRenderWidgetHost()
              ->GetView());

  RenderWidgetHostViewBase* rwhv_nested =
      static_cast<RenderWidgetHostViewBase*>(
          nested_iframe_node->current_frame_host()
              ->GetRenderWidgetHost()
              ->GetView());

  WaitForChildFrameSurfaceReady(nested_iframe_node->current_frame_host());

  // Save the original offset as a point of reference.
  filter->WaitForRect();
  gfx::Rect update_rect = filter->last_rect();
  int initial_y = update_rect.y();
  filter->ResetRectRunLoop();

  // Scroll the parent frame downward.
  blink::WebMouseWheelEvent scroll_event(
      blink::WebInputEvent::kMouseWheel, blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  scroll_event.SetPositionInWidget(1, 1);
  scroll_event.delta_x = 0.0f;
  scroll_event.delta_y = -5.0f;
  scroll_event.phase = blink::WebMouseWheelEvent::kPhaseBegan;
  // Set has_precise_scroll_deltas to keep these events off the animated scroll
  // pathways, which currently break this test.
  // https://bugs.chromium.org/p/chromium/issues/detail?id=710513
  scroll_event.has_precise_scrolling_deltas = true;
  rwhv_parent->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());

  if (rwhv_parent->wheel_scroll_latching_enabled()) {
    // When scroll latching is enabled the event router sends wheel events of a
    // single scroll sequence to the target under the first wheel event. Send a
    // wheel end event to the current target view before sending a wheel event
    // to a different one.
    scroll_event.delta_y = 0.0f;
    scroll_event.phase = blink::WebMouseWheelEvent::kPhaseEnded;
    scroll_event.dispatch_type =
        blink::WebInputEvent::DispatchType::kEventNonBlocking;
    rwhv_parent->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());
  }

  // Ensure that the view position is propagated to the child properly.
  filter->WaitForRect();
  update_rect = filter->last_rect();
  EXPECT_LT(update_rect.y(), initial_y);
  filter->ResetRectRunLoop();
  ack_observer.Reset();

  // Now scroll the nested frame upward, which should bubble to the parent.
  // The upscroll exceeds the amount that the frame was initially scrolled
  // down to account for rounding.
  scroll_event.delta_y = 6.0f;
  scroll_event.dispatch_type = blink::WebInputEvent::DispatchType::kBlocking;
  scroll_event.phase = blink::WebMouseWheelEvent::kPhaseBegan;
  rwhv_nested->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());

  filter->WaitForRect();
  // This loop isn't great, but it accounts for the possibility of multiple
  // incremental updates happening as a result of the scroll animation.
  // A failure condition of this test is that the loop might not terminate
  // due to bubbling not working properly. If the overscroll bubbles to the
  // parent iframe then the nested frame's y coord will return to its
  // initial position.
  update_rect = filter->last_rect();
  while (update_rect.y() > initial_y) {
    base::RunLoop run_loop;
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(), TestTimeouts::tiny_timeout());
    run_loop.Run();
    update_rect = filter->last_rect();
  }

  if (rwhv_parent->wheel_scroll_latching_enabled()) {
    // When scroll latching is enabled the event router sends wheel events of a
    // single scroll sequence to the target under the first wheel event. Send a
    // wheel end event to the current target view before sending a wheel event
    // to a different one.
    scroll_event.delta_y = 0.0f;
    scroll_event.phase = blink::WebMouseWheelEvent::kPhaseEnded;
    scroll_event.dispatch_type =
        blink::WebInputEvent::DispatchType::kEventNonBlocking;
    rwhv_nested->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());
  }

  filter->ResetRectRunLoop();
  // Once we've sent a wheel to the nested iframe that we expect to turn into
  // a bubbling scroll, we need to delay to make sure the GestureScrollBegin
  // from this new scroll doesn't hit the RenderWidgetHostImpl before the
  // GestureScrollEnd bubbled from the child.
  // This timing only seems to be needed for CrOS, but we'll enable it on
  // all platforms just to lessen the possibility of tests being flakey
  // on non-CrOS platforms.
  ack_observer.Wait();

  // Scroll the parent down again in order to test scroll bubbling from
  // gestures.
  scroll_event.delta_y = -5.0f;
  scroll_event.dispatch_type = blink::WebInputEvent::DispatchType::kBlocking;
  scroll_event.phase = blink::WebMouseWheelEvent::kPhaseBegan;
  rwhv_parent->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());

  if (rwhv_parent->wheel_scroll_latching_enabled()) {
    // When scroll latching is enabled the event router sends wheel events of a
    // single scroll sequence to the target under the first wheel event. Send a
    // wheel end event to the current target view before sending a wheel event
    // to a different one.
    scroll_event.delta_y = 0.0f;
    scroll_event.phase = blink::WebMouseWheelEvent::kPhaseEnded;
    scroll_event.dispatch_type =
        blink::WebInputEvent::DispatchType::kEventNonBlocking;
    rwhv_parent->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());
  }

  // Ensure ensuing offset change is received, and then reset the filter.
  filter->WaitForRect();
  filter->ResetRectRunLoop();

  // Scroll down the nested iframe via gesture. This requires 3 separate input
  // events.
  blink::WebGestureEvent gesture_event(
      blink::WebGestureEvent::kGestureScrollBegin,
      blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests(),
      blink::kWebGestureDeviceTouchpad);
  gesture_event.SetPositionInWidget(gfx::PointF(1, 1));
  gesture_event.data.scroll_begin.delta_x_hint = 0.0f;
  gesture_event.data.scroll_begin.delta_y_hint = 6.0f;
  rwhv_nested->GetRenderWidgetHost()->ForwardGestureEvent(gesture_event);

  gesture_event =
      blink::WebGestureEvent(blink::WebGestureEvent::kGestureScrollUpdate,
                             blink::WebInputEvent::kNoModifiers,
                             blink::WebInputEvent::GetStaticTimeStampForTests(),
                             blink::kWebGestureDeviceTouchpad);
  gesture_event.SetPositionInWidget(gfx::PointF(1, 1));
  gesture_event.data.scroll_update.delta_x = 0.0f;
  gesture_event.data.scroll_update.delta_y = 6.0f;
  gesture_event.data.scroll_update.velocity_x = 0;
  gesture_event.data.scroll_update.velocity_y = 0;
  rwhv_nested->GetRenderWidgetHost()->ForwardGestureEvent(gesture_event);

  gesture_event =
      blink::WebGestureEvent(blink::WebGestureEvent::kGestureScrollEnd,
                             blink::WebInputEvent::kNoModifiers,
                             blink::WebInputEvent::GetStaticTimeStampForTests(),
                             blink::kWebGestureDeviceTouchpad);
  gesture_event.SetPositionInWidget(gfx::PointF(1, 1));
  rwhv_nested->GetRenderWidgetHost()->ForwardGestureEvent(gesture_event);

  filter->WaitForRect();
  update_rect = filter->last_rect();
  // As above, if this loop does not terminate then it indicates an issue
  // with scroll bubbling.
  while (update_rect.y() > initial_y) {
    base::RunLoop run_loop;
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(), TestTimeouts::tiny_timeout());
    run_loop.Run();
    update_rect = filter->last_rect();
  }

  // Test that when the child frame absorbs all of the scroll delta, it does
  // not propagate to the parent (see https://crbug.com/621624).
  filter->ResetRectRunLoop();
  scroll_event.delta_y = -5.0f;
  scroll_event.dispatch_type = blink::WebInputEvent::DispatchType::kBlocking;
  scroll_event.phase = blink::WebMouseWheelEvent::kPhaseBegan;
  rwhv_nested->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());
  // It isn't possible to busy loop waiting on the renderer here because we
  // are explicitly testing that something does *not* happen. This creates a
  // small chance of false positives but shouldn't result in false negatives,
  // so flakiness implies this test is failing.
  {
    base::RunLoop run_loop;
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(), TestTimeouts::action_timeout());
    run_loop.Run();
  }
  DCHECK_EQ(filter->last_rect().x(), 0);
  DCHECK_EQ(filter->last_rect().y(), 0);
}

// Test that fling on an out-of-process iframe progresses properly.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, GestureFlingStart) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  ASSERT_EQ(1U, root->child_count());

  FrameTreeNode* child_iframe_node = root->child_at(0);

  RenderWidgetHost* child_rwh =
      child_iframe_node->current_frame_host()->GetRenderWidgetHost();

  WaitForChildFrameSurfaceReady(child_iframe_node->current_frame_host());

  // Send a GSB to start scrolling sequence.
  blink::WebGestureEvent gesture_scroll_begin(
      blink::WebGestureEvent::kGestureScrollBegin,
      blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  gesture_scroll_begin.SetSourceDevice(blink::kWebGestureDeviceTouchscreen);
  gesture_scroll_begin.data.scroll_begin.delta_hint_units =
      blink::WebGestureEvent::ScrollUnits::kPrecisePixels;
  gesture_scroll_begin.data.scroll_begin.delta_x_hint = 0.f;
  gesture_scroll_begin.data.scroll_begin.delta_y_hint = 5.f;
  child_rwh->ForwardGestureEvent(gesture_scroll_begin);

  // Send a GFS and wait for the ack of the first GSU generated from progressing
  // the fling on the browser.
  InputEventAckWaiter gesture_scroll_update_ack_observer(
      child_rwh, blink::WebInputEvent::kGestureScrollUpdate);
  gesture_scroll_update_ack_observer.Reset();
  blink::WebGestureEvent gesture_fling_start(
      blink::WebGestureEvent::kGestureFlingStart,
      blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  gesture_fling_start.SetSourceDevice(blink::kWebGestureDeviceTouchscreen);
  gesture_fling_start.data.fling_start.velocity_x = 0.f;
  gesture_fling_start.data.fling_start.velocity_y = 50.f;
  child_rwh->ForwardGestureEvent(gesture_fling_start);
  gesture_scroll_update_ack_observer.Wait();
}

class ScrollObserver : public RenderWidgetHost::InputEventObserver {
 public:
  ScrollObserver(double delta_x, double delta_y) { Reset(delta_x, delta_y); }
  ~ScrollObserver() override {}

  void OnInputEvent(const blink::WebInputEvent& event) override {
    if (event.GetType() == blink::WebInputEvent::kGestureScrollUpdate) {
      blink::WebGestureEvent received_update =
          *static_cast<const blink::WebGestureEvent*>(&event);
      remaining_delta_x_ -= received_update.data.scroll_update.delta_x;
      remaining_delta_y_ -= received_update.data.scroll_update.delta_y;
    } else if (event.GetType() == blink::WebInputEvent::kGestureScrollEnd) {
      if (message_loop_runner_->loop_running())
        message_loop_runner_->Quit();
      DCHECK_EQ(0, remaining_delta_x_);
      DCHECK_EQ(0, remaining_delta_y_);
      scroll_end_received_ = true;
    }
  }

  void Wait() {
    if (!scroll_end_received_) {
      message_loop_runner_->Run();
    }
  }

  void Reset(double delta_x, double delta_y) {
    message_loop_runner_ = new content::MessageLoopRunner;
    remaining_delta_x_ = delta_x;
    remaining_delta_y_ = delta_y;
    scroll_end_received_ = false;
  }

 private:
  scoped_refptr<content::MessageLoopRunner> message_loop_runner_;
  double remaining_delta_x_;
  double remaining_delta_y_;
  bool scroll_end_received_;

  DISALLOW_COPY_AND_ASSIGN(ScrollObserver);
};

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ScrollBubblingFromNestedOOPIFTest) {
  ui::GestureConfiguration::GetInstance()->set_scroll_debounce_interval_in_ms(
      0);
  GURL main_url(embedded_test_server()->GetURL(
      "/frame_tree/page_with_positioned_nested_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1U, root->child_count());

  FrameTreeNode* parent_iframe_node = root->child_at(0);
  GURL site_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_positioned_frame.html"));
  EXPECT_EQ(site_url, parent_iframe_node->current_url());

  FrameTreeNode* nested_iframe_node = parent_iframe_node->child_at(0);
  GURL nested_site_url(
      embedded_test_server()->GetURL("baz.com", "/title1.html"));
  EXPECT_EQ(nested_site_url, nested_iframe_node->current_url());

  RenderWidgetHostViewBase* root_view = static_cast<RenderWidgetHostViewBase*>(
      root->current_frame_host()->GetRenderWidgetHost()->GetView());

  RenderWidgetHostViewBase* rwhv_nested =
      static_cast<RenderWidgetHostViewBase*>(
          nested_iframe_node->current_frame_host()
              ->GetRenderWidgetHost()
              ->GetView());

  WaitForChildFrameSurfaceReady(nested_iframe_node->current_frame_host());

  InputEventAckWaiter ack_observer(
      root->current_frame_host()->GetRenderWidgetHost(),
      blink::WebInputEvent::kGestureScrollBegin);

  std::unique_ptr<ScrollObserver> scroll_observer;
  if (root_view->wheel_scroll_latching_enabled()) {
    // All GSU events will be wrapped between a single GSB-GSE pair. The
    // expected delta value is equal to summation of all scroll update deltas.
    scroll_observer = std::make_unique<ScrollObserver>(0, 15);
  } else {
    // Each GSU will be wrapped betweeen its own GSB-GSE pair. The expected
    // delta value is the delta of the first GSU event.
    scroll_observer = std::make_unique<ScrollObserver>(0, 5);
  }
  root->current_frame_host()->GetRenderWidgetHost()->AddInputEventObserver(
      scroll_observer.get());

  // Now scroll the nested frame upward, this must bubble all the way up to the
  // root.
  blink::WebMouseWheelEvent scroll_event(
      blink::WebInputEvent::kMouseWheel, blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  gfx::Rect bounds = rwhv_nested->GetViewBounds();
  float scale_factor = GetPageScaleFactor(shell());
  scroll_event.SetPositionInWidget(
      gfx::ToCeiledInt((bounds.x() - root_view->GetViewBounds().x() + 10) *
                       scale_factor),
      gfx::ToCeiledInt((bounds.y() - root_view->GetViewBounds().y() + 10) *
                       scale_factor));
  scroll_event.delta_x = 0.0f;
  scroll_event.delta_y = 5.0f;
  scroll_event.phase = blink::WebMouseWheelEvent::kPhaseBegan;
  scroll_event.has_precise_scrolling_deltas = true;
  rwhv_nested->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());
  ack_observer.Wait();

  // When wheel scroll latching is disabled, each wheel event will have its own
  // complete scroll seqeunce.
  if (!root_view->wheel_scroll_latching_enabled())
    scroll_observer->Wait();

  // Send 10 wheel events with delta_y = 1 to the nested oopif. When scroll
  // latching is disabled, each wheel event will have its own scroll sequence.
  scroll_event.delta_y = 1.0f;
  scroll_event.phase = blink::WebMouseWheelEvent::kPhaseChanged;
  for (int i = 0; i < 10; i++) {
    if (!root_view->wheel_scroll_latching_enabled())
      scroll_observer->Reset(0, 1);
    rwhv_nested->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());
    if (!root_view->wheel_scroll_latching_enabled())
      scroll_observer->Wait();
  }

  // Send a wheel end event to complete the scrolling sequence when wheel scroll
  // latching is enabled.
  if (root_view->wheel_scroll_latching_enabled()) {
    scroll_event.delta_y = 0.0f;
    scroll_event.phase = blink::WebMouseWheelEvent::kPhaseEnded;
    rwhv_nested->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());
    scroll_observer->Wait();
  }
}

// Tests that scrolling bubbles from an oopif if its source body has
// "overflow:hidden" style.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ScrollBubblingFromOOPIFWithBodyOverflowHidden) {
  GURL url_domain_a(embedded_test_server()->GetURL(
      "a.com", "/scrollable_page_with_iframe.html"));
  EXPECT_TRUE(NavigateToURL(shell(), url_domain_a));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  FrameTreeNode* iframe_node = root->child_at(0);
  GURL url_domain_b(
      embedded_test_server()->GetURL("b.com", "/body_overflow_hidden.html"));
  NavigateFrameToURL(iframe_node, url_domain_b);
  WaitForChildFrameSurfaceReady(iframe_node->current_frame_host());

  RenderWidgetHostViewBase* root_view = static_cast<RenderWidgetHostViewBase*>(
      root->current_frame_host()->GetRenderWidgetHost()->GetView());

  RenderWidgetHostViewBase* child_view = static_cast<RenderWidgetHostViewBase*>(
      iframe_node->current_frame_host()->GetRenderWidgetHost()->GetView());

  ScrollObserver scroll_observer(0, -5);
  root->current_frame_host()->GetRenderWidgetHost()->AddInputEventObserver(
      &scroll_observer);

  // Now scroll the nested frame downward, this must bubble to the root since
  // the iframe source body is not scrollable.
  blink::WebMouseWheelEvent scroll_event(
      blink::WebInputEvent::kMouseWheel, blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  gfx::Rect bounds = child_view->GetViewBounds();
  float scale_factor = GetPageScaleFactor(shell());
  scroll_event.SetPositionInWidget(
      gfx::ToCeiledInt((bounds.x() - root_view->GetViewBounds().x() + 10) *
                       scale_factor),
      gfx::ToCeiledInt((bounds.y() - root_view->GetViewBounds().y() + 10) *
                       scale_factor));
  scroll_event.delta_x = 0.0f;
  scroll_event.delta_y = -5.0f;
  scroll_event.phase = blink::WebMouseWheelEvent::kPhaseBegan;
  scroll_event.has_precise_scrolling_deltas = true;
  child_view->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());

  // Send a wheel end event to complete the scrolling sequence when wheel scroll
  // latching is enabled.
  if (root_view->wheel_scroll_latching_enabled()) {
    scroll_event.delta_y = 0.0f;
    scroll_event.phase = blink::WebMouseWheelEvent::kPhaseEnded;
    child_view->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());
  }

  scroll_observer.Wait();
}

// Ensure that the scrollability of a local subframe in an OOPIF is considered
// when acknowledging GestureScrollBegin events sent to OOPIFs.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, ScrollLocalSubframeInOOPIF) {
  ui::GestureConfiguration::GetInstance()->set_scroll_debounce_interval_in_ms(
      0);

  // This must be tall enough such that the outer iframe is not scrollable.
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_tall_positioned_frame.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1U, root->child_count());

  FrameTreeNode* parent_iframe_node = root->child_at(0);
  GURL outer_frame_url(embedded_test_server()->GetURL(
      "baz.com", "/frame_tree/page_with_positioned_frame.html"));
  NavigateFrameToURL(parent_iframe_node, outer_frame_url);

  // This must be tall enough such that the inner iframe is scrollable.
  FrameTreeNode* nested_iframe_node = parent_iframe_node->child_at(0);
  GURL inner_frame_url(
      embedded_test_server()->GetURL("baz.com", "/tall_page.html"));
  NavigateFrameToURL(nested_iframe_node, inner_frame_url);

  ASSERT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "        +--Site B -- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://baz.com/",
      DepictFrameTree(root));

  RenderWidgetHostViewBase* rwhv_child = static_cast<RenderWidgetHostViewBase*>(
      nested_iframe_node->current_frame_host()
          ->GetRenderWidgetHost()
          ->GetView());

  WaitForChildFrameSurfaceReady(parent_iframe_node->current_frame_host());

  // When we scroll the inner frame, we should have the GSB be consumed.
  // The outer iframe not being scrollable should not cause the GSB to go
  // unconsumed.
  InputEventAckWaiter ack_observer(
      parent_iframe_node->current_frame_host()->GetRenderWidgetHost(),
      base::BindRepeating([](content::InputEventAckSource,
                             content::InputEventAckState state,
                             const blink::WebInputEvent& event) {
        return event.GetType() == blink::WebGestureEvent::kGestureScrollBegin &&
               state == content::INPUT_EVENT_ACK_STATE_CONSUMED;
      }));

  // Wait until renderer's compositor thread is synced. Otherwise the non fast
  // scrollable regions won't be set when the event arrives.
  MainThreadFrameObserver observer(rwhv_child->GetRenderWidgetHost());
  observer.Wait();

  // Now scroll the inner frame downward.
  blink::WebMouseWheelEvent scroll_event(
      blink::WebInputEvent::kMouseWheel, blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  scroll_event.SetPositionInWidget(90, 110);
  scroll_event.delta_x = 0.0f;
  scroll_event.delta_y = -50.0f;
  scroll_event.phase = blink::WebMouseWheelEvent::kPhaseBegan;
  scroll_event.has_precise_scrolling_deltas = true;
  rwhv_child->ProcessMouseWheelEvent(scroll_event, ui::LatencyInfo());
  ack_observer.Wait();
}

// This test verifies that scrolling an element to view works across OOPIFs. The
// testing methodology is based on measuring bounding client rect position of
// nested <iframe>'s after the inner-most frame scrolls into view. The
// measurements are for two identical pages where one page does not have any
// OOPIFs while the other has some nested OOPIFs.
#if defined(OS_LINUX)
// crbug.com/827431
#define MAYBE_ScrollElementIntoView DISABLED_ScrollElementIntoView
#else
#define MAYBE_ScrollElementIntoView ScrollElementIntoView
#endif

IN_PROC_BROWSER_TEST_F(SitePerProcessProgrammaticScrollTest,
                       MAYBE_ScrollElementIntoView) {
  const GURL url_a(
      embedded_test_server()->GetURL("a.com", kIframeOutOfViewHTML));
  const GURL url_b(
      embedded_test_server()->GetURL("b.com", kIframeOutOfViewHTML));
  const GURL url_c(
      embedded_test_server()->GetURL("c.com", kIframeOutOfViewHTML));

  // Number of <iframe>'s which will not be empty. The actual frame tree has two
  // more nodes one for root and one for the inner-most empty <iframe>.
  const size_t kNonEmptyIframesCount = 5;
  const std::string kScrollIntoViewScript =
      "document.body.scrollIntoView({'behavior' : 'instant'});";
  const int kRectDimensionErrorTolerance = 0;

  // First, recursively set the |scrollTop| and |scrollLeft| of |document.body|
  // to its maximum and then navigate the <iframe> to |url_a|. The page will be
  // structured as a(a(a(a(a(a(a)))))) where the inner-most <iframe> is empty.
  ASSERT_TRUE(NavigateToURL(shell(), url_a));
  FrameTreeNode* node = web_contents()->GetFrameTree()->root();
  WaitForOnLoad(node);
  std::vector<gfx::Rect> reference_page_bounds_before_scroll = {
      GetBoundingClientRect(node, kIframeSelector)};
  node = node->child_at(0);
  for (size_t index = 0; index < kNonEmptyIframesCount; ++index) {
    NavigateFrameToURL(node, url_a);
    WaitForOnLoad(node);
    // Store |document.querySelector('iframe').getBoundingClientRect()|.
    reference_page_bounds_before_scroll.push_back(
        GetBoundingClientRect(node, kIframeSelector));
    node = node->child_at(0);
  }
  // Sanity-check: If the page is setup properly then all the <iframe>s should
  // be out of view and their bounding rect should not intersect with the
  // positive XY plane.
  for (const auto& rect : reference_page_bounds_before_scroll)
    ASSERT_FALSE(rect.Intersects(kPositiveXYPlane));
  // Now scroll the inner-most frame into view.
  ASSERT_TRUE(ExecuteScript(node, kScrollIntoViewScript));
  // Store current client bounds origins to later compare against those from the
  // page which contains OOPIFs.
  node = web_contents()->GetFrameTree()->root();
  std::vector<gfx::Rect> reference_page_bounds_after_scroll = {
      GetBoundingClientRect(node, kIframeSelector)};
  node = node->child_at(0);
  for (size_t index = 0; index < kNonEmptyIframesCount; ++index) {
    reference_page_bounds_after_scroll.push_back(
        GetBoundingClientRect(node, kIframeSelector));
    node = node->child_at(0);
  }

  // Repeat the same process for the page containing OOPIFs. The page is
  // structured as b(b(a(c(a(a(a)))))) where the inner-most <iframe> is empty.
  ASSERT_TRUE(NavigateToURL(shell(), url_b));
  node = web_contents()->GetFrameTree()->root();
  WaitForOnLoad(node);
  std::vector<gfx::Rect> test_page_bounds_before_scroll = {
      GetBoundingClientRect(node, kIframeSelector)};
  const GURL iframe_urls[] = {url_b, url_a, url_c, url_a, url_a};
  node = node->child_at(0);
  for (size_t index = 0; index < kNonEmptyIframesCount; ++index) {
    NavigateFrameToURL(node, iframe_urls[index]);
    WaitForOnLoad(node);
    test_page_bounds_before_scroll.push_back(
        GetBoundingClientRect(node, kIframeSelector));
    node = node->child_at(0);
  }
  // Sanity-check: The bounds should match those from non-OOPIF page.
  for (size_t index = 0; index < kNonEmptyIframesCount; ++index) {
    ASSERT_TRUE(test_page_bounds_before_scroll[index].ApproximatelyEqual(
        reference_page_bounds_before_scroll[index],
        kRectDimensionErrorTolerance));
  }
  // Scroll the inner most OOPIF.
  ASSERT_TRUE(ExecuteScript(node, kScrollIntoViewScript));
  // Now traverse the chain bottom to top and verify the bounds match for each
  // <iframe>.
  int index = kNonEmptyIframesCount;
  RenderFrameHostImpl* current_rfh = node->current_frame_host()->GetParent();
  while (current_rfh) {
    gfx::Rect current_bounds =
        GetBoundingClientRect(current_rfh->frame_tree_node(), kIframeSelector);
    gfx::Rect reference_bounds = reference_page_bounds_after_scroll[index];
    if (current_bounds.ApproximatelyEqual(reference_bounds,
                                          kRectDimensionErrorTolerance)) {
      current_rfh = current_rfh->GetParent();
      --index;
    } else {
      base::RunLoop run_loop;
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE, run_loop.QuitClosure(), TestTimeouts::tiny_timeout());
      run_loop.Run();
    }
  }
}

// This test verifies that ScrollFocusedEditableElementIntoView works correctly
// for OOPIFs. Essentially, the test verifies that in a similar setup, the
// resultant page scale factor is the same for OOPIF and non-OOPIF cases. This
// also verifies that in response to the scroll command, the root-layer scrolls
// correctly and the <input> is visible in visual viewport.
#if defined(OS_ANDROID)
// crbug.com/793616
#define MAYBE_ScrollFocusedEditableElementIntoView \
  DISABLED_ScrollFocusedEditableElementIntoView
#else
#define MAYBE_ScrollFocusedEditableElementIntoView \
  ScrollFocusedEditableElementIntoView
#endif
IN_PROC_BROWSER_TEST_F(SitePerProcessProgrammaticScrollTest,
                       MAYBE_ScrollFocusedEditableElementIntoView) {
  GURL url_a(embedded_test_server()->GetURL("a.com", kIframeOutOfViewHTML));
  GURL url_b(embedded_test_server()->GetURL("b.com", kIframeOutOfViewHTML));

#if defined(OS_ANDROID)
  // The reason for Android specific code is that
  // AutoZoomFocusedNodeToLegibleScale is in blink's WebSettings and difficult
  // to access from here. It so happens that the setting is on for Android.

  // A lower bound on the ratio of page scale factor after scroll. The actual
  // value depends on minReadableCaretHeight / caret_bounds.Height(). The page
  // is setup so caret height is quite small so the expected scale should be
  // larger than 2.0.
  float kLowerBoundOnScaleAfterScroll = 2.0;
  float kEpsilon = 0.1;
#endif

  ASSERT_TRUE(NavigateToURL(shell(), url_a));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  WaitForOnLoad(root);
  NavigateFrameToURL(root->child_at(0), url_a);
  WaitForOnLoad(root->child_at(0));
#if defined(OS_ANDROID)
  float scale_before_scroll_nonoopif = GetVisualViewportScale(root);
#endif
  AddFocusedInputField(root->child_at(0));
  // Focusing <input> causes scrollIntoView(). The following line makes sure
  // that the <iframe> is out of view again.
  SetWindowScroll(root, 0, 0);
  ASSERT_FALSE(GetVisualViewport(root).Intersects(
      GetBoundingClientRect(root, kIframeSelector)));
  root->child_at(0)
      ->current_frame_host()
      ->GetFrameInputHandler()
      ->ScrollFocusedEditableNodeIntoRect(gfx::Rect());
  WaitForElementVisible(root, kIframeSelector);
#if defined(OS_ANDROID)
  float scale_after_scroll_nonoopif = GetVisualViewportScale(root);
  // Increased scale means zoom triggered correctly.
  EXPECT_GT(scale_after_scroll_nonoopif - scale_before_scroll_nonoopif,
            kEpsilon);
  EXPECT_GT(scale_after_scroll_nonoopif, kLowerBoundOnScaleAfterScroll);
#endif

  // Retry the test on an OOPIF page.
  Shell* new_shell = CreateBrowser();
  ASSERT_TRUE(NavigateToURL(new_shell, url_b));
  root = static_cast<WebContentsImpl*>(new_shell->web_contents())
             ->GetFrameTree()
             ->root();
  WaitForOnLoad(root);
#if defined(OS_ANDROID)
  float scale_before_scroll_oopif = GetVisualViewportScale(root);
  // Sanity-check:
  ASSERT_NEAR(scale_before_scroll_oopif, scale_before_scroll_nonoopif,
              kEpsilon);
#endif
  NavigateFrameToURL(root->child_at(0), url_a);
  WaitForOnLoad(root->child_at(0));
  AddFocusedInputField(root->child_at(0));
  SetWindowScroll(root, 0, 0);
  ASSERT_FALSE(GetVisualViewport(root).Intersects(
      GetBoundingClientRect(root, kIframeSelector)));
  root->child_at(0)
      ->current_frame_host()
      ->GetFrameInputHandler()
      ->ScrollFocusedEditableNodeIntoRect(gfx::Rect());
  WaitForElementVisible(root, kIframeSelector);
#if defined(OS_ANDROID)
  float scale_after_scroll_oopif = GetVisualViewportScale(root);
  EXPECT_GT(scale_after_scroll_oopif - scale_before_scroll_oopif, kEpsilon);
  EXPECT_GT(scale_after_scroll_oopif, kLowerBoundOnScaleAfterScroll);
  // The scale is based on the caret height and it should be the same in both
  // OOPIF and non-OOPIF pages.
  EXPECT_NEAR(scale_after_scroll_oopif, scale_after_scroll_nonoopif, kEpsilon);
#endif
  // Make sure the <input> is at least partly visible in the |visualViewport|.
  gfx::Rect final_visual_viewport_oopif = GetVisualViewport(root);
  gfx::Rect iframe_bounds_after_scroll_oopif =
      GetBoundingClientRect(root, kIframeSelector);
  gfx::Rect input_bounds_after_scroll_oopif =
      GetBoundingClientRect(root->child_at(0), kInputSelector);
  input_bounds_after_scroll_oopif +=
      iframe_bounds_after_scroll_oopif.OffsetFromOrigin();
  ASSERT_TRUE(
      final_visual_viewport_oopif.Intersects(input_bounds_after_scroll_oopif));
}

IN_PROC_BROWSER_TEST_F(SitePerProcessProgrammaticScrollTest,
                       ScrollClippedFocusedEditableElementIntoView) {
  GURL url_a(embedded_test_server()->GetURL("a.com", kIframeClippedHTML));
  GURL child_url_b(embedded_test_server()->GetURL("b.com", kInputBoxHTML));

  ASSERT_TRUE(NavigateToURL(shell(), url_a));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  WaitForOnLoad(root);
  NavigateFrameToURL(root->child_at(0), child_url_b);
  WaitForOnLoad(root->child_at(0));

  SetWindowScroll(root, 0, 0);
  SetWindowScroll(root->child_at(0), 1000, 2000);

  float scale_before = GetVisualViewportScale(root);

  // The input_box page focuses the input box on load. This call should
  // simulate the scroll into view we do when an input box is tapped.
  root->child_at(0)
      ->current_frame_host()
      ->GetFrameInputHandler()
      ->ScrollFocusedEditableNodeIntoRect(gfx::Rect());

  // The scroll into view is animated on the compositor. Make sure we wait
  // until that's completed before testing the rects.
  WaitForElementVisible(root, kIframeSelector);
  WaitForViewportToStabilize(root);

  // These rects are in the coordinate space of the root frame.
  gfx::Rect visual_viewport_rect = GetVisualViewport(root);
  gfx::Rect window_rect = GetBoundingClientRect(root, ":root");
  gfx::Rect iframe_rect = GetBoundingClientRect(root, "iframe");
  gfx::Rect clip_rect = GetBoundingClientRect(root, "#clip");

  // This is in the coordinate space of the iframe, we'll add the iframe offset
  // after to put it into the root frame's coordinate space.
  gfx::Rect input_rect = GetBoundingClientRect(root->child_at(0), "input");

  // Make sure the input rect is visible in the iframe.
  EXPECT_TRUE(gfx::Rect(iframe_rect.size()).Intersects(input_rect))
      << "Input box [" << input_rect.ToString() << "] isn't visible in iframe ["
      << gfx::Rect(iframe_rect.size()).ToString() << "]";

  input_rect += iframe_rect.OffsetFromOrigin();

  // Make sure the input rect is visible through the clipping layer.
  EXPECT_TRUE(clip_rect.Intersects(input_rect))
      << "Input box [" << input_rect.ToString() << "] isn't scrolled into view "
      << "of the clipping layer [" << clip_rect.ToString() << "]";

  // And finally, it should be visible in the layout and visual viewports.
  EXPECT_TRUE(window_rect.Intersects(input_rect))
      << "Input box [" << input_rect.ToString() << "] isn't visible in the "
      << "layout viewport [" << window_rect.ToString() << "]";
  EXPECT_TRUE(visual_viewport_rect.Intersects(input_rect))
      << "Input box [" << input_rect.ToString() << "] isn't visible in the "
      << "visual viewport [" << visual_viewport_rect.ToString() << "]";

  float scale_after = GetVisualViewportScale(root);

// Make sure we still zoom in on the input box on platforms that zoom into the
// focused editable.
#if defined(OS_ANDROID)
  EXPECT_GT(scale_after, scale_before);
#else
  EXPECT_FLOAT_EQ(scale_after, scale_before);
#endif
}

// Tests OOPIF rendering by checking that the RWH of the iframe generates
// OnSwapCompositorFrame message.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, CompositorFrameSwapped) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(baz)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1U, root->child_count());

  FrameTreeNode* child_node = root->child_at(0);
  GURL site_url(embedded_test_server()->GetURL(
      "baz.com", "/cross_site_iframe_factory.html?baz()"));
  EXPECT_EQ(site_url, child_node->current_url());
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            child_node->current_frame_host()->GetSiteInstance());
  RenderWidgetHostViewBase* rwhv_base = static_cast<RenderWidgetHostViewBase*>(
      child_node->current_frame_host()->GetRenderWidgetHost()->GetView());

  // Wait for OnSwapCompositorFrame message.
  while (rwhv_base->RendererFrameNumber() <= 0) {
    // TODO(lazyboy): Find a better way to avoid sleeping like this. See
    // http://crbug.com/405282 for details.
    base::RunLoop run_loop;
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(),
        base::TimeDelta::FromMilliseconds(10));
    run_loop.Run();
  }
}

// Ensure that OOPIFs are deleted after navigating to a new main frame.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, CleanupCrossSiteIframe) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,a(a,a(a)))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());

  // Load a cross-site page into both iframes.
  GURL foo_url = embedded_test_server()->GetURL("foo.com", "/title2.html");
  NavigateFrameToURL(root->child_at(0), foo_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(foo_url, observer.last_navigation_url());
  NavigateFrameToURL(root->child_at(1), foo_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(foo_url, observer.last_navigation_url());

  // Ensure that we have created a new process for the subframes.
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://foo.com/",
      DepictFrameTree(root));

  int subframe_process_id = root->child_at(0)
                                ->current_frame_host()
                                ->GetSiteInstance()
                                ->GetProcess()
                                ->GetID();
  int subframe_rvh_id = root->child_at(0)
                            ->current_frame_host()
                            ->render_view_host()
                            ->GetRoutingID();
  EXPECT_TRUE(RenderViewHost::FromID(subframe_process_id, subframe_rvh_id));

  // Use Javascript in the parent to remove one of the frames and ensure that
  // the subframe goes away.
  EXPECT_TRUE(ExecuteScript(shell(),
                            "document.body.removeChild("
                            "document.querySelectorAll('iframe')[0])"));
  ASSERT_EQ(1U, root->child_count());

  // Load a new same-site page in the top-level frame and ensure the other
  // subframe goes away.
  GURL new_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), new_url));
  ASSERT_EQ(0U, root->child_count());

  // Ensure the RVH for the subframe gets cleaned up when the frame goes away.
  EXPECT_FALSE(RenderViewHost::FromID(subframe_process_id, subframe_rvh_id));
}

// Ensure that root frames cannot be detached.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, RestrictFrameDetach) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,a(a,a(a)))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());

  // Load cross-site pages into both iframes.
  GURL foo_url = embedded_test_server()->GetURL("foo.com", "/title2.html");
  NavigateFrameToURL(root->child_at(0), foo_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(foo_url, observer.last_navigation_url());
  GURL bar_url = embedded_test_server()->GetURL("bar.com", "/title2.html");
  NavigateFrameToURL(root->child_at(1), bar_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(bar_url, observer.last_navigation_url());

  // Ensure that we have created new processes for the subframes.
  ASSERT_EQ(2U, root->child_count());
  FrameTreeNode* foo_child = root->child_at(0);
  SiteInstance* foo_site_instance =
      foo_child->current_frame_host()->GetSiteInstance();
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(), foo_site_instance);
  FrameTreeNode* bar_child = root->child_at(1);
  SiteInstance* bar_site_instance =
      bar_child->current_frame_host()->GetSiteInstance();
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(), bar_site_instance);

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   |--Site B ------- proxies for A C\n"
      "   +--Site C ------- proxies for A B\n"
      "Where A = http://a.com/\n"
      "      B = http://foo.com/\n"
      "      C = http://bar.com/",
      DepictFrameTree(root));

  // Simulate an attempt to detach the root frame from foo_site_instance.  This
  // should kill foo_site_instance's process.
  RenderFrameProxyHost* foo_mainframe_rfph =
      root->render_manager()->GetRenderFrameProxyHost(foo_site_instance);
  content::RenderProcessHostKillWaiter kill_waiter(
      foo_mainframe_rfph->GetProcess());
  FrameHostMsg_Detach evil_msg2(foo_mainframe_rfph->GetRoutingID());
  IPC::IpcSecurityTestUtil::PwnMessageReceived(
      foo_mainframe_rfph->GetProcess()->GetChannel(), evil_msg2);
  EXPECT_EQ(bad_message::RFPH_DETACH, kill_waiter.Wait());

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   |--Site B ------- proxies for A C\n"
      "   +--Site C ------- proxies for A B\n"
      "Where A = http://a.com/\n"
      "      B = http://foo.com/ (no process)\n"
      "      C = http://bar.com/",
      DepictFrameTree(root));
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, NavigateRemoteFrame) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,a(a,a(a)))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());

  // Load same-site page into iframe.
  FrameTreeNode* child = root->child_at(0);
  GURL http_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  NavigateFrameToURL(child, http_url);
  EXPECT_EQ(http_url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());

  // Load cross-site page into iframe.
  GURL url = embedded_test_server()->GetURL("foo.com", "/title2.html");
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    NavigateFrameToURL(root->child_at(0), url);
    deleted_observer.WaitUntilDeleted();
  }
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());

  // Ensure that we have created a new process for the subframe.
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "        |--Site A -- proxies for B\n"
      "        +--Site A -- proxies for B\n"
      "             +--Site A -- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://foo.com/",
      DepictFrameTree(root));
  SiteInstance* site_instance = child->current_frame_host()->GetSiteInstance();
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(), site_instance);

  // Emulate the main frame changing the src of the iframe such that it
  // navigates cross-site.
  url = embedded_test_server()->GetURL("bar.com", "/title3.html");
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    NavigateIframeToURL(shell()->web_contents(), "child-0", url);
    deleted_observer.WaitUntilDeleted();
  }
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());

  // Check again that a new process is created and is different from the
  // top level one and the previous one.
  EXPECT_EQ(
      " Site A ------------ proxies for C\n"
      "   |--Site C ------- proxies for A\n"
      "   +--Site A ------- proxies for C\n"
      "        |--Site A -- proxies for C\n"
      "        +--Site A -- proxies for C\n"
      "             +--Site A -- proxies for C\n"
      "Where A = http://a.com/\n"
      "      C = http://bar.com/",
      DepictFrameTree(root));

  // Navigate back to the parent's origin and ensure we return to the
  // parent's process.
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    NavigateFrameToURL(child, http_url);
    deleted_observer.WaitUntilDeleted();
  }
  EXPECT_EQ(http_url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(shell()->web_contents()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateRemoteFrameToBlankAndDataURLs) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,a(a))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());

  // Load same-site page into iframe.
  FrameTreeNode* child = root->child_at(0);
  GURL http_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  NavigateFrameToURL(child, http_url);
  EXPECT_EQ(http_url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(
      " Site A\n"
      "   |--Site A\n"
      "   +--Site A\n"
      "        +--Site A\n"
      "Where A = http://a.com/",
      DepictFrameTree(root));

  // Load cross-site page into iframe.
  GURL url = embedded_test_server()->GetURL("foo.com", "/title2.html");
  NavigateFrameToURL(child, url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "        +--Site A -- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://foo.com/",
      DepictFrameTree(root));

  // Navigate iframe to a data URL. The navigation happens from a script in the
  // parent frame, so the data URL should be committed in the same SiteInstance
  // as the parent frame.
  RenderFrameDeletedObserver deleted_observer1(
      root->child_at(0)->current_frame_host());
  GURL data_url("data:text/html,dataurl");
  NavigateIframeToURL(shell()->web_contents(), "child-0", data_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(data_url, observer.last_navigation_url());

  // Wait for the old process to exit, to verify that the proxies go away.
  deleted_observer1.WaitUntilDeleted();

  // Ensure that we have navigated using the top level process.
  EXPECT_EQ(
      " Site A\n"
      "   |--Site A\n"
      "   +--Site A\n"
      "        +--Site A\n"
      "Where A = http://a.com/",
      DepictFrameTree(root));

  // Load cross-site page into iframe.
  url = embedded_test_server()->GetURL("bar.com", "/title2.html");
  NavigateFrameToURL(child, url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());
  EXPECT_EQ(
      " Site A ------------ proxies for C\n"
      "   |--Site C ------- proxies for A\n"
      "   +--Site A ------- proxies for C\n"
      "        +--Site A -- proxies for C\n"
      "Where A = http://a.com/\n"
      "      C = http://bar.com/",
      DepictFrameTree(root));

  // Navigate iframe to about:blank. The navigation happens from a script in the
  // parent frame, so it should be committed in the same SiteInstance as the
  // parent frame.
  RenderFrameDeletedObserver deleted_observer2(
      root->child_at(0)->current_frame_host());
  GURL about_blank_url("about:blank");
  NavigateIframeToURL(shell()->web_contents(), "child-0", about_blank_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(about_blank_url, observer.last_navigation_url());

  // Wait for the old process to exit, to verify that the proxies go away.
  deleted_observer2.WaitUntilDeleted();

  // Ensure that we have navigated using the top level process.
  EXPECT_EQ(
      " Site A\n"
      "   |--Site A\n"
      "   +--Site A\n"
      "        +--Site A\n"
      "Where A = http://a.com/",
      DepictFrameTree(root));

  // Load cross-site page into iframe again.
  url = embedded_test_server()->GetURL("f00.com", "/title3.html");
  NavigateFrameToURL(child, url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());
  EXPECT_EQ(
      " Site A ------------ proxies for D\n"
      "   |--Site D ------- proxies for A\n"
      "   +--Site A ------- proxies for D\n"
      "        +--Site A -- proxies for D\n"
      "Where A = http://a.com/\n"
      "      D = http://f00.com/",
      DepictFrameTree(root));

  // Navigate the iframe itself to about:blank using a script executing in its
  // own context. It should stay in the same SiteInstance as before, not the
  // parent one.
  TestFrameNavigationObserver frame_observer(child);
  ExecuteScriptAsync(child, "window.location.href = 'about:blank';");
  frame_observer.Wait();
  EXPECT_EQ(about_blank_url, child->current_url());

  // Ensure that we have navigated using the top level process.
  EXPECT_EQ(
      " Site A ------------ proxies for D\n"
      "   |--Site D ------- proxies for A\n"
      "   +--Site A ------- proxies for D\n"
      "        +--Site A -- proxies for D\n"
      "Where A = http://a.com/\n"
      "      D = http://f00.com/",
      DepictFrameTree(root));
}

// This test checks that killing a renderer process of a remote frame
// and then navigating some other frame to the same SiteInstance of the killed
// process works properly.
// This can be illustrated as follows,
// where 1/2/3 are FrameTreeNode-s and A/B are processes and B* is the killed
// B process:
//
//     1        A                  A                           A
//    / \  ->  / \  -> Kill B ->  / \  -> Navigate 3 to B ->  / \  .
//   2   3    B   A              B*  A                       B*  B
//
// Initially, node1.proxy_hosts_ = {B}
// After we kill B, we make sure B stays in node1.proxy_hosts_, then we navigate
// 3 to B and we expect that to complete normally.
// See http://crbug.com/432107.
//
// Note that due to http://crbug.com/450681, node2 cannot be re-navigated to
// site B and stays in not rendered state.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateRemoteFrameToKilledProcess) {
  GURL main_url(embedded_test_server()->GetURL(
      "foo.com", "/cross_site_iframe_factory.html?foo.com(bar.com, foo.com)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());
  ASSERT_EQ(2U, root->child_count());

  // Make sure node2 points to the correct cross-site page.
  GURL site_b_url = embedded_test_server()->GetURL(
      "bar.com", "/cross_site_iframe_factory.html?bar.com()");
  FrameTreeNode* node2 = root->child_at(0);
  EXPECT_EQ(site_b_url, node2->current_url());

  // Kill that cross-site renderer.
  RenderProcessHost* child_process = node2->current_frame_host()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      child_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  child_process->Shutdown(0);
  crash_observer.Wait();

  // Now navigate the second iframe (node3) to the same site as the node2.
  FrameTreeNode* node3 = root->child_at(1);
  NavigateFrameToURL(node3, site_b_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(site_b_url, observer.last_navigation_url());
}

// This test ensures that WebContentsImpl::FocusOwningWebContents does not crash
// the browser if the currently focused frame's renderer has disappeared.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, RemoveFocusFromKilledFrame) {
  GURL main_url(embedded_test_server()->GetURL(
      "foo.com", "/cross_site_iframe_factory.html?foo.com(bar.com)"));
  NavigateToURL(shell(), main_url);

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());
  ASSERT_EQ(1U, root->child_count());

  // Make sure node2 points to the correct cross-site page.
  GURL site_b_url = embedded_test_server()->GetURL(
      "bar.com", "/cross_site_iframe_factory.html?bar.com()");
  FrameTreeNode* node2 = root->child_at(0);
  EXPECT_EQ(site_b_url, node2->current_url());

  web_contents()->SetFocusedFrame(
      node2, node2->current_frame_host()->GetSiteInstance());

  // Kill that cross-site renderer.
  RenderProcessHost* child_process = node2->current_frame_host()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      child_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  child_process->Shutdown(0);
  crash_observer.Wait();

  // Try to focus the root's owning WebContents.
  web_contents()->FocusOwningWebContents(
      root->current_frame_host()->GetRenderWidgetHost());
}

// This test is similar to
// SitePerProcessBrowserTest.NavigateRemoteFrameToKilledProcess with
// addition that node2 also has a cross-origin frame to site C.
//
//     1          A                  A                       A
//    / \        / \                / \                     / \  .
//   2   3 ->   B   A -> Kill B -> B*   A -> Navigate 3 -> B*  B
//  /          /
// 4          C
//
// Initially, node1.proxy_hosts_ = {B, C}
// After we kill B, we make sure B stays in node1.proxy_hosts_, but
// C gets cleared from node1.proxy_hosts_.
//
// Note that due to http://crbug.com/450681, node2 cannot be re-navigated to
// site B and stays in not rendered state.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateRemoteFrameToKilledProcessWithSubtree) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(bar(baz), a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  TestNavigationObserver observer(shell()->web_contents());

  ASSERT_EQ(2U, root->child_count());

  GURL site_b_url(embedded_test_server()->GetURL(
      "bar.com", "/cross_site_iframe_factory.html?bar(baz())"));
  // We can't use a TestNavigationObserver to verify the URL here,
  // since the frame has children that may have clobbered it in the observer.
  EXPECT_EQ(site_b_url, root->child_at(0)->current_url());

  // Ensure that a new process is created for node2.
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            root->child_at(0)->current_frame_host()->GetSiteInstance());
  // Ensure that a new process is *not* created for node3.
  EXPECT_EQ(shell()->web_contents()->GetSiteInstance(),
            root->child_at(1)->current_frame_host()->GetSiteInstance());

  ASSERT_EQ(1U, root->child_at(0)->child_count());

  // Make sure node4 points to the correct cross-site page.
  FrameTreeNode* node4 = root->child_at(0)->child_at(0);
  GURL site_c_url(embedded_test_server()->GetURL(
      "baz.com", "/cross_site_iframe_factory.html?baz()"));
  EXPECT_EQ(site_c_url, node4->current_url());

  // |site_instance_c| is expected to go away once we kill |child_process_b|
  // below, so create a local scope so we can extend the lifetime of
  // |site_instance_c| with a refptr.
  {
    // Initially each frame has proxies for the other sites.
    EXPECT_EQ(
        " Site A ------------ proxies for B C\n"
        "   |--Site B ------- proxies for A C\n"
        "   |    +--Site C -- proxies for A B\n"
        "   +--Site A ------- proxies for B C\n"
        "Where A = http://a.com/\n"
        "      B = http://bar.com/\n"
        "      C = http://baz.com/",
        DepictFrameTree(root));

    // Kill the render process for Site B.
    RenderProcessHost* child_process_b =
        root->child_at(0)->current_frame_host()->GetProcess();
    RenderProcessHostWatcher crash_observer(
        child_process_b, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
    child_process_b->Shutdown(0);
    crash_observer.Wait();

    // The Site C frame (a child of the crashed Site B frame) should go away,
    // and there should be no remaining proxies for site C anywhere.
    EXPECT_EQ(
        " Site A ------------ proxies for B\n"
        "   |--Site B ------- proxies for A\n"
        "   +--Site A ------- proxies for B\n"
        "Where A = http://a.com/\n"
        "      B = http://bar.com/ (no process)",
        DepictFrameTree(root));
  }

  // Now navigate the second iframe (node3) to Site B also.
  FrameTreeNode* node3 = root->child_at(1);
  GURL url = embedded_test_server()->GetURL("bar.com", "/title1.html");
  NavigateFrameToURL(node3, url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://bar.com/",
      DepictFrameTree(root));
}

// Ensure that the renderer process doesn't crash when the main frame navigates
// a remote child to a page that results in a network error.
// See https://crbug.com/558016.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, NavigateRemoteAfterError) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Load same-site page into iframe.
  {
    TestNavigationObserver observer(shell()->web_contents());
    FrameTreeNode* child = root->child_at(0);
    GURL http_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
    NavigateFrameToURL(child, http_url);
    EXPECT_EQ(http_url, observer.last_navigation_url());
    EXPECT_TRUE(observer.last_navigation_succeeded());
    observer.Wait();
  }

  // Load cross-site page into iframe.
  {
    TestNavigationObserver observer(shell()->web_contents());
    FrameTreeNode* child = root->child_at(0);
    GURL url = embedded_test_server()->GetURL("foo.com", "/title2.html");
    NavigateFrameToURL(root->child_at(0), url);
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(url, observer.last_navigation_url());
    observer.Wait();

    // Ensure that we have created a new process for the subframe.
    EXPECT_EQ(
        " Site A ------------ proxies for B\n"
        "   +--Site B ------- proxies for A\n"
        "Where A = http://a.com/\n"
        "      B = http://foo.com/",
        DepictFrameTree(root));
    SiteInstance* site_instance =
        child->current_frame_host()->GetSiteInstance();
    EXPECT_NE(shell()->web_contents()->GetSiteInstance(), site_instance);
  }

  // Stop the test server and try to navigate the remote frame.
  {
    GURL url = embedded_test_server()->GetURL("bar.com", "/title3.html");
    EXPECT_TRUE(embedded_test_server()->ShutdownAndWaitUntilComplete());
    NavigateIframeToURL(shell()->web_contents(), "child-0", url);
  }
}

// Ensure that a cross-site page ends up in the correct process when it
// successfully loads after earlier encountering a network error for it.
// See https://crbug.com/560511.
// TODO(creis): Make the net error page show in the correct process as well,
// per https://crbug.com/588314.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, ProcessTransferAfterError) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);
  GURL url_a = child->current_url();

  // Disable host resolution in the test server and try to navigate the subframe
  // cross-site, which will lead to a committed net error.
  GURL url_b = embedded_test_server()->GetURL("b.com", "/title3.html");
  bool network_service =
      base::FeatureList::IsEnabled(network::features::kNetworkService);
  std::unique_ptr<URLLoaderInterceptor> url_loader_interceptor;
  if (network_service) {
    url_loader_interceptor = std::make_unique<URLLoaderInterceptor>(
        base::BindRepeating([](URLLoaderInterceptor::RequestParams* params) {
          network::URLLoaderCompletionStatus status;
          status.error_code = net::ERR_NOT_IMPLEMENTED;
          params->client->OnComplete(status);
          return true;
        }));
  } else {
    host_resolver()->ClearRules();
  }

  TestNavigationObserver observer(shell()->web_contents());
  NavigateIframeToURL(shell()->web_contents(), "child-0", url_b);
  EXPECT_FALSE(observer.last_navigation_succeeded());
  EXPECT_EQ(url_b, observer.last_navigation_url());
  EXPECT_EQ(2, shell()->web_contents()->GetController().GetEntryCount());

  // Ensure that we have created a new process for the subframe.
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());

  // We have switched RenderFrameHosts for the subframe, so the last successful
  // url should be empty (since the frame only loaded an error page).
  EXPECT_EQ(GURL(), child->current_frame_host()->last_successful_url());
  EXPECT_EQ(url_b, child->current_url());
  EXPECT_EQ("null", child->current_origin().Serialize());

  // Try again after re-enabling host resolution.
  if (network_service) {
    url_loader_interceptor.reset();
  } else {
    host_resolver()->AddRule("*", "127.0.0.1");
  }

  NavigateIframeToURL(shell()->web_contents(), "child-0", url_b);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url_b, observer.last_navigation_url());

  // The FrameTreeNode should have updated its URL and origin.
  EXPECT_EQ(url_b, child->current_frame_host()->last_successful_url());
  EXPECT_EQ(url_b, child->current_url());
  EXPECT_EQ(url_b.GetOrigin().spec(),
            child->current_origin().Serialize() + '/');

  // Ensure that we have created a new process for the subframe.
  // PlzNavigate: the subframe should still be in its separate process.
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());

  // Make sure that the navigation replaced the error page and that going back
  // ends up on the original site.
  EXPECT_EQ(2, shell()->web_contents()->GetController().GetEntryCount());
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    TestNavigationObserver back_load_observer(shell()->web_contents());
    shell()->web_contents()->GetController().GoBack();
    back_load_observer.Wait();

    // Wait for the old process to exit, to verify that the proxies go away.
    deleted_observer.WaitUntilDeleted();
  }
  EXPECT_EQ(
      " Site A\n"
      "   +--Site A\n"
      "Where A = http://a.com/",
      DepictFrameTree(root));
  EXPECT_EQ(shell()->web_contents()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());
  EXPECT_EQ(url_a, child->current_frame_host()->last_successful_url());
  EXPECT_EQ(url_a, child->current_url());
  EXPECT_EQ(url_a.GetOrigin().spec(),
            child->current_origin().Serialize() + '/');
}

// Verify that killing a cross-site frame's process B and then navigating a
// frame to B correctly recreates all proxies in B.
//
//      1           A                    A          A
//    / | \       / | \                / | \      / | \  .
//   2  3  4 ->  B  A  A -> Kill B -> B* A  A -> B* B  A
//
// After the last step, the test sends a postMessage from node 3 to node 4,
// verifying that a proxy for node 4 has been recreated in process B.  This
// verifies the fix for https://crbug.com/478892.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigatingToKilledProcessRestoresAllProxies) {
  // Navigate to a page with three frames: one cross-site and two same-site.
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_three_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  TestNavigationObserver observer(shell()->web_contents());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   |--Site A ------- proxies for B\n"
      "   +--Site A ------- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  // Kill the first subframe's b.com renderer.
  RenderProcessHost* child_process =
      root->child_at(0)->current_frame_host()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      child_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  child_process->Shutdown(0);
  crash_observer.Wait();

  // Navigate the second subframe to b.com to recreate the b.com process.
  GURL b_url = embedded_test_server()->GetURL("b.com", "/post_message.html");
  NavigateFrameToURL(root->child_at(1), b_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(b_url, observer.last_navigation_url());
  EXPECT_TRUE(root->child_at(1)->current_frame_host()->IsRenderFrameLive());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  // Check that third subframe's proxy is available in the b.com process by
  // sending it a postMessage from second subframe, and waiting for a reply.
  PostMessageAndWaitForReply(root->child_at(1),
                             "postToSibling('subframe-msg','frame3')",
                             "\"done-frame2\"");
}

// Verify that proxy creation doesn't recreate a crashed process if no frame
// will be created in it.
//
//      1           A                    A          A
//    / | \       / | \                / | \      / | \    .
//   2  3  4 ->  B  A  A -> Kill B -> B* A  A -> B* A  A
//                                                      \  .
//                                                       A
//
// The test kills process B (node 2), creates a child frame of node 4 in
// process A, and then checks that process B isn't resurrected to create a
// proxy for the new child frame.  See https://crbug.com/476846.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CreateChildFrameAfterKillingProcess) {
  // Navigate to a page with three frames: one cross-site and two same-site.
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_three_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   |--Site A ------- proxies for B\n"
      "   +--Site A ------- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));
  SiteInstance* b_site_instance =
      root->child_at(0)->current_frame_host()->GetSiteInstance();

  // Kill the first subframe's renderer (B).
  RenderProcessHost* child_process =
      root->child_at(0)->current_frame_host()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      child_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  child_process->Shutdown(0);
  crash_observer.Wait();

  // Add a new child frame to the third subframe.
  RenderFrameHostCreatedObserver frame_observer(shell()->web_contents(), 1);
  EXPECT_TRUE(ExecuteScript(
      root->child_at(2),
      "document.body.appendChild(document.createElement('iframe'));"));
  frame_observer.Wait();

  // The new frame should have a RenderFrameProxyHost for B, but it should not
  // be alive, and B should still not have a process (verified by last line of
  // expected DepictFrameTree output).
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   |--Site A ------- proxies for B\n"
      "   +--Site A ------- proxies for B\n"
      "        +--Site A -- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/ (no process)",
      DepictFrameTree(root));
  FrameTreeNode* grandchild = root->child_at(2)->child_at(0);
  RenderFrameProxyHost* grandchild_rfph =
      grandchild->render_manager()->GetRenderFrameProxyHost(b_site_instance);
  EXPECT_FALSE(grandchild_rfph->is_render_frame_proxy_live());

  // Navigate the second subframe to b.com to recreate process B.
  TestNavigationObserver observer(shell()->web_contents());
  GURL b_url = embedded_test_server()->GetURL("b.com", "/title1.html");
  NavigateFrameToURL(root->child_at(1), b_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(b_url, observer.last_navigation_url());

  // Ensure that the grandchild RenderFrameProxy in B was created when process
  // B was restored.
  EXPECT_TRUE(grandchild_rfph->is_render_frame_proxy_live());
}

// Verify that creating a child frame after killing and reloading an opener
// process doesn't crash. See https://crbug.com/501152.
//   1. Navigate to site A.
//   2. Open a popup with window.open and navigate it cross-process to site B.
//   3. Kill process A for the original tab.
//   4. Reload the original tab to resurrect process A.
//   5. Add a child frame to the top-level frame in the popup tab B.
// In step 5, we try to create proxies for the child frame in all SiteInstances
// for which its parent has proxies.  This includes A.  However, even though
// process A is live (step 4), the parent proxy in A is not live (which was
// incorrectly assumed previously).  This is because step 4 does not resurrect
// proxies for popups opened before the crash.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CreateChildFrameAfterKillingOpener) {
  GURL main_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  SiteInstance* site_instance_a = root->current_frame_host()->GetSiteInstance();

  // Open a popup and navigate it cross-process to b.com.
  ShellAddedObserver new_shell_observer;
  EXPECT_TRUE(ExecuteScript(root, "popup = window.open('about:blank');"));
  Shell* popup = new_shell_observer.GetShell();
  GURL popup_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  EXPECT_TRUE(NavigateToURLFromRenderer(popup, popup_url));

  // Verify that each top-level frame has proxies in the other's SiteInstance.
  FrameTreeNode* popup_root =
      static_cast<WebContentsImpl*>(popup->web_contents())
          ->GetFrameTree()
          ->root();
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));
  EXPECT_EQ(
      " Site B ------------ proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(popup_root));

  // Kill the first window's renderer (a.com).
  RenderProcessHost* child_process = root->current_frame_host()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      child_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  child_process->Shutdown(0);
  crash_observer.Wait();
  EXPECT_FALSE(root->current_frame_host()->IsRenderFrameLive());

  // The proxy for the popup in a.com should've died.
  RenderFrameProxyHost* rfph =
      popup_root->render_manager()->GetRenderFrameProxyHost(site_instance_a);
  EXPECT_FALSE(rfph->is_render_frame_proxy_live());

  // Recreate the a.com renderer.
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  EXPECT_TRUE(root->current_frame_host()->IsRenderFrameLive());

  // The popup's proxy in a.com should still not be live. Re-navigating the
  // main window to a.com doesn't reinitialize a.com proxies for popups
  // previously opened from the main window.
  EXPECT_FALSE(rfph->is_render_frame_proxy_live());

  // Add a new child frame on the popup.
  RenderFrameHostCreatedObserver frame_observer(popup->web_contents(), 1);
  EXPECT_TRUE(ExecuteScript(
      popup, "document.body.appendChild(document.createElement('iframe'));"));
  frame_observer.Wait();

  // Both the child frame's and its parent's proxies should still not be live.
  // The main page can't reach them since it lost reference to the popup after
  // it crashed, so there is no need to create them.
  EXPECT_FALSE(rfph->is_render_frame_proxy_live());
  RenderFrameProxyHost* child_rfph =
      popup_root->child_at(0)->render_manager()->GetRenderFrameProxyHost(
          site_instance_a);
  EXPECT_TRUE(child_rfph);
  EXPECT_FALSE(child_rfph->is_render_frame_proxy_live());
}

// In A-embed-B-embed-C scenario, verify that killing process B clears proxies
// of C from the tree.
//
//     1          A                  A
//    / \        / \                / \    .
//   2   3 ->   B   A -> Kill B -> B*  A
//  /          /
// 4          C
//
// node1 is the root.
// Initially, both node1.proxy_hosts_ and node3.proxy_hosts_ contain C.
// After we kill B, make sure proxies for C are cleared.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       KillingRendererClearsDescendantProxies) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_two_frames_nested.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(2U, root->child_count());

  GURL site_b_url(embedded_test_server()->GetURL(
      "bar.com", "/frame_tree/page_with_one_frame.html"));
  // We can't use a TestNavigationObserver to verify the URL here,
  // since the frame has children that may have clobbered it in the observer.
  EXPECT_EQ(site_b_url, root->child_at(0)->current_url());

  // Ensure that a new process is created for node2.
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            root->child_at(0)->current_frame_host()->GetSiteInstance());
  // Ensure that a new process is *not* created for node3.
  EXPECT_EQ(shell()->web_contents()->GetSiteInstance(),
            root->child_at(1)->current_frame_host()->GetSiteInstance());

  ASSERT_EQ(1U, root->child_at(0)->child_count());

  // Make sure node4 points to the correct cross-site-page.
  FrameTreeNode* node4 = root->child_at(0)->child_at(0);
  GURL site_c_url(embedded_test_server()->GetURL("baz.com", "/title1.html"));
  EXPECT_EQ(site_c_url, node4->current_url());

  // |site_instance_c|'s frames and proxies are expected to go away once we kill
  // |child_process_b| below.
  scoped_refptr<SiteInstanceImpl> site_instance_c =
      node4->current_frame_host()->GetSiteInstance();

  // Initially proxies for both B and C will be present in the root.
  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   |--Site B ------- proxies for A C\n"
      "   |    +--Site C -- proxies for A B\n"
      "   +--Site A ------- proxies for B C\n"
      "Where A = http://a.com/\n"
      "      B = http://bar.com/\n"
      "      C = http://baz.com/",
      DepictFrameTree(root));

  EXPECT_GT(site_instance_c->active_frame_count(), 0U);

  // Kill process B.
  RenderProcessHost* child_process_b =
      root->child_at(0)->current_frame_host()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      child_process_b, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  child_process_b->Shutdown(0);
  crash_observer.Wait();

  // Make sure proxy C has gone from root.
  // Make sure proxy C has gone from node3 as well.
  // Make sure proxy B stays around in root and node3.
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://bar.com/ (no process)",
      DepictFrameTree(root));

  EXPECT_EQ(0U, site_instance_c->active_frame_count());
}

// Crash a subframe and ensures its children are cleared from the FrameTree.
// See http://crbug.com/338508.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, CrashSubframe) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Check the subframe process.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));
  FrameTreeNode* child = root->child_at(0);
  EXPECT_TRUE(
      child->current_frame_host()->render_view_host()->IsRenderViewLive());
  EXPECT_TRUE(child->current_frame_host()->IsRenderFrameLive());

  // Crash the subframe process.
  RenderProcessHost* root_process = root->current_frame_host()->GetProcess();
  RenderProcessHost* child_process = child->current_frame_host()->GetProcess();
  {
    RenderProcessHostWatcher crash_observer(
        child_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
    child_process->Shutdown(0);
    crash_observer.Wait();
  }

  // Ensure that the child frame still exists but has been cleared.
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/ (no process)",
      DepictFrameTree(root));
  EXPECT_EQ(1U, root->child_count());
  EXPECT_EQ(main_url, root->current_url());
  EXPECT_EQ(GURL(), child->current_url());

  EXPECT_FALSE(
      child->current_frame_host()->render_view_host()->IsRenderViewLive());
  EXPECT_FALSE(child->current_frame_host()->IsRenderFrameLive());
  EXPECT_FALSE(child->current_frame_host()->render_frame_created_);

  // Now crash the top-level page to clear the child frame.
  {
    RenderProcessHostWatcher crash_observer(
        root_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
    root_process->Shutdown(0);
    crash_observer.Wait();
  }
  EXPECT_EQ(0U, root->child_count());
  EXPECT_EQ(GURL(), root->current_url());
}

// When a new subframe is added, related SiteInstances that can reach the
// subframe should create proxies for it (https://crbug.com/423587).  This test
// checks that if A embeds B and later adds a new subframe A2, A2 gets a proxy
// in B's process.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, CreateProxiesForNewFrames) {
  GURL main_url(embedded_test_server()->GetURL(
      "b.com", "/frame_tree/page_with_one_frame.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1U, root->child_count());

  // Make sure the frame starts out at the correct cross-site URL.
  EXPECT_EQ(embedded_test_server()->GetURL("baz.com", "/title1.html"),
            root->child_at(0)->current_url());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://b.com/\n"
      "      B = http://baz.com/",
      DepictFrameTree(root));

  // Add a new child frame to the top-level frame.
  RenderFrameHostCreatedObserver frame_observer(shell()->web_contents(), 1);
  EXPECT_TRUE(ExecuteScript(shell(), "addFrame('data:text/html,foo');"));
  frame_observer.Wait();

  // The new frame should have a proxy in Site B, for use by the old frame.
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "Where A = http://b.com/\n"
      "      B = http://baz.com/",
      DepictFrameTree(root));
}

// TODO(nasko): Disable this test until out-of-process iframes is ready and the
// security checks are back in place.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       DISABLED_CrossSiteIframeRedirectOnce) {
  net::EmbeddedTestServer https_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_server.ServeFilesFromSourceDirectory("content/test/data");
  ASSERT_TRUE(https_server.Start());

  GURL main_url(embedded_test_server()->GetURL("/site_per_process_main.html"));
  GURL http_url(embedded_test_server()->GetURL("/title1.html"));
  GURL https_url(https_server.GetURL("/title1.html"));

  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  TestNavigationObserver observer(shell()->web_contents());
  {
    // Load cross-site client-redirect page into Iframe.
    // Should be blocked.
    GURL client_redirect_https_url(
        https_server.GetURL("/client-redirect?/title1.html"));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    client_redirect_https_url));
    // DidFailProvisionalLoad when navigating to client_redirect_https_url.
    EXPECT_EQ(observer.last_navigation_url(), client_redirect_https_url);
    EXPECT_FALSE(observer.last_navigation_succeeded());
  }

  {
    // Load cross-site server-redirect page into Iframe,
    // which redirects to same-site page.
    GURL server_redirect_http_url(
        https_server.GetURL("/server-redirect?" + http_url.spec()));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    server_redirect_http_url));
    EXPECT_EQ(observer.last_navigation_url(), http_url);
    EXPECT_TRUE(observer.last_navigation_succeeded());
  }

  {
    // Load cross-site server-redirect page into Iframe,
    // which redirects to cross-site page.
    GURL server_redirect_http_url(
        https_server.GetURL("/server-redirect?/title1.html"));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    server_redirect_http_url));
    // DidFailProvisionalLoad when navigating to https_url.
    EXPECT_EQ(observer.last_navigation_url(), https_url);
    EXPECT_FALSE(observer.last_navigation_succeeded());
  }

  {
    // Load same-site server-redirect page into Iframe,
    // which redirects to cross-site page.
    GURL server_redirect_http_url(
        embedded_test_server()->GetURL("/server-redirect?" + https_url.spec()));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    server_redirect_http_url));

    EXPECT_EQ(observer.last_navigation_url(), https_url);
    EXPECT_FALSE(observer.last_navigation_succeeded());
  }

  {
    // Load same-site client-redirect page into Iframe,
    // which redirects to cross-site page.
    GURL client_redirect_http_url(
        embedded_test_server()->GetURL("/client-redirect?" + https_url.spec()));

    RedirectNotificationObserver load_observer2(
        NOTIFICATION_LOAD_STOP, Source<NavigationController>(
                                    &shell()->web_contents()->GetController()));

    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    client_redirect_http_url));

    // Same-site Client-Redirect Page should be loaded successfully.
    EXPECT_EQ(observer.last_navigation_url(), client_redirect_http_url);
    EXPECT_TRUE(observer.last_navigation_succeeded());

    // Redirecting to Cross-site Page should be blocked.
    load_observer2.Wait();
    EXPECT_EQ(observer.last_navigation_url(), https_url);
    EXPECT_FALSE(observer.last_navigation_succeeded());
  }

  {
    // Load same-site server-redirect page into Iframe,
    // which redirects to same-site page.
    GURL server_redirect_http_url(
        embedded_test_server()->GetURL("/server-redirect?/title1.html"));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    server_redirect_http_url));
    EXPECT_EQ(observer.last_navigation_url(), http_url);
    EXPECT_TRUE(observer.last_navigation_succeeded());
  }

  {
    // Load same-site client-redirect page into Iframe,
    // which redirects to same-site page.
    GURL client_redirect_http_url(
        embedded_test_server()->GetURL("/client-redirect?" + http_url.spec()));
    RedirectNotificationObserver load_observer2(
        NOTIFICATION_LOAD_STOP, Source<NavigationController>(
                                    &shell()->web_contents()->GetController()));

    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    client_redirect_http_url));

    // Same-site Client-Redirect Page should be loaded successfully.
    EXPECT_EQ(observer.last_navigation_url(), client_redirect_http_url);
    EXPECT_TRUE(observer.last_navigation_succeeded());

    // Redirecting to Same-site Page should be loaded successfully.
    load_observer2.Wait();
    EXPECT_EQ(observer.last_navigation_url(), http_url);
    EXPECT_TRUE(observer.last_navigation_succeeded());
  }
}

// TODO(nasko): Disable this test until out-of-process iframes is ready and the
// security checks are back in place.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       DISABLED_CrossSiteIframeRedirectTwice) {
  net::EmbeddedTestServer https_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_server.ServeFilesFromSourceDirectory("content/test/data");
  ASSERT_TRUE(https_server.Start());

  GURL main_url(embedded_test_server()->GetURL("/site_per_process_main.html"));
  GURL http_url(embedded_test_server()->GetURL("/title1.html"));
  GURL https_url(https_server.GetURL("/title1.html"));

  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  TestNavigationObserver observer(shell()->web_contents());
  {
    // Load client-redirect page pointing to a cross-site client-redirect page,
    // which eventually redirects back to same-site page.
    GURL client_redirect_https_url(
        https_server.GetURL("/client-redirect?" + http_url.spec()));
    GURL client_redirect_http_url(embedded_test_server()->GetURL(
        "/client-redirect?" + client_redirect_https_url.spec()));

    // We should wait until second client redirect get cancelled.
    RedirectNotificationObserver load_observer2(
        NOTIFICATION_LOAD_STOP, Source<NavigationController>(
                                    &shell()->web_contents()->GetController()));

    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    client_redirect_http_url));

    // DidFailProvisionalLoad when navigating to client_redirect_https_url.
    load_observer2.Wait();
    EXPECT_EQ(observer.last_navigation_url(), client_redirect_https_url);
    EXPECT_FALSE(observer.last_navigation_succeeded());
  }

  {
    // Load server-redirect page pointing to a cross-site server-redirect page,
    // which eventually redirect back to same-site page.
    GURL server_redirect_https_url(
        https_server.GetURL("/server-redirect?" + http_url.spec()));
    GURL server_redirect_http_url(embedded_test_server()->GetURL(
        "/server-redirect?" + server_redirect_https_url.spec()));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    server_redirect_http_url));
    EXPECT_EQ(observer.last_navigation_url(), http_url);
    EXPECT_TRUE(observer.last_navigation_succeeded());
  }

  {
    // Load server-redirect page pointing to a cross-site server-redirect page,
    // which eventually redirects back to cross-site page.
    GURL server_redirect_https_url(
        https_server.GetURL("/server-redirect?" + https_url.spec()));
    GURL server_redirect_http_url(embedded_test_server()->GetURL(
        "/server-redirect?" + server_redirect_https_url.spec()));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    server_redirect_http_url));

    // DidFailProvisionalLoad when navigating to https_url.
    EXPECT_EQ(observer.last_navigation_url(), https_url);
    EXPECT_FALSE(observer.last_navigation_succeeded());
  }

  {
    // Load server-redirect page pointing to a cross-site client-redirect page,
    // which eventually redirects back to same-site page.
    GURL client_redirect_http_url(
        https_server.GetURL("/client-redirect?" + http_url.spec()));
    GURL server_redirect_http_url(embedded_test_server()->GetURL(
        "/server-redirect?" + client_redirect_http_url.spec()));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "test",
                                    server_redirect_http_url));

    // DidFailProvisionalLoad when navigating to client_redirect_http_url.
    EXPECT_EQ(observer.last_navigation_url(), client_redirect_http_url);
    EXPECT_FALSE(observer.last_navigation_succeeded());
  }
}

// Ensure that when navigating a frame cross-process RenderFrameProxyHosts are
// created in the FrameTree skipping the subtree of the navigating frame (but
// not the navigating frame itself).
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, ProxyCreationSkipsSubtree) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,a(a,a(a)))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  EXPECT_TRUE(root->child_at(1) != nullptr);
  EXPECT_EQ(2U, root->child_at(1)->child_count());

  {
    // Load same-site page into iframe.
    TestNavigationObserver observer(shell()->web_contents());
    GURL http_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
    NavigateFrameToURL(root->child_at(0), http_url);
    EXPECT_EQ(http_url, observer.last_navigation_url());
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(
        " Site A\n"
        "   |--Site A\n"
        "   +--Site A\n"
        "        |--Site A\n"
        "        +--Site A\n"
        "             +--Site A\n"
        "Where A = http://a.com/",
        DepictFrameTree(root));
  }

  // Create the cross-site URL to navigate to.
  GURL cross_site_url =
      embedded_test_server()->GetURL("foo.com", "/frame_tree/title2.html");

  // Load cross-site page into the second iframe without waiting for the
  // navigation to complete. Once LoadURLWithParams returns, we would expect
  // proxies to have been created in the frame tree, but children of the
  // navigating frame to still be present. The reason is that we don't run the
  // message loop, so no IPCs that alter the frame tree can be processed.
  FrameTreeNode* child = root->child_at(1);
  SiteInstance* site = nullptr;
  std::string cross_site_rfh_type = "speculative";
  {
    TestNavigationObserver observer(shell()->web_contents());
    TestFrameNavigationObserver navigation_observer(child);
    NavigationController::LoadURLParams params(cross_site_url);
    params.transition_type = PageTransitionFromInt(ui::PAGE_TRANSITION_LINK);
    params.frame_tree_node_id = child->frame_tree_node_id();
    child->navigator()->GetController()->LoadURLWithParams(params);

    site = child->render_manager()->speculative_frame_host()->GetSiteInstance();
    EXPECT_NE(shell()->web_contents()->GetSiteInstance(), site);

    std::string tree = base::StringPrintf(
        " Site A ------------ proxies for B\n"
        "   |--Site A ------- proxies for B\n"
        "   +--Site A (B %s) -- proxies for B\n"
        "        |--Site A\n"
        "        +--Site A\n"
        "             +--Site A\n"
        "Where A = http://a.com/\n"
        "      B = http://foo.com/",
        cross_site_rfh_type.c_str());
    EXPECT_EQ(tree, DepictFrameTree(root));

    // Now that the verification is done, run the message loop and wait for the
    // navigation to complete.
    navigation_observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(cross_site_url, observer.last_navigation_url());

    EXPECT_EQ(
        " Site A ------------ proxies for B\n"
        "   |--Site A ------- proxies for B\n"
        "   +--Site B ------- proxies for A\n"
        "Where A = http://a.com/\n"
        "      B = http://foo.com/",
        DepictFrameTree(root));
  }

  // Load another cross-site page into the same iframe.
  cross_site_url = embedded_test_server()->GetURL("bar.com", "/title3.html");
  {
    // Perform the same checks as the first cross-site navigation, since
    // there have been issues in subsequent cross-site navigations. Also ensure
    // that the SiteInstance has properly changed.
    // TODO(nasko): Once we have proper cleanup of resources, add code to
    // verify that the intermediate SiteInstance/RenderFrameHost have been
    // properly cleaned up.
    TestNavigationObserver observer(shell()->web_contents());
    TestFrameNavigationObserver navigation_observer(child);
    NavigationController::LoadURLParams params(cross_site_url);
    params.transition_type = PageTransitionFromInt(ui::PAGE_TRANSITION_LINK);
    params.frame_tree_node_id = child->frame_tree_node_id();
    child->navigator()->GetController()->LoadURLWithParams(params);

    SiteInstance* site2 =
        child->render_manager()->speculative_frame_host()->GetSiteInstance();
    EXPECT_NE(shell()->web_contents()->GetSiteInstance(), site2);
    EXPECT_NE(site, site2);

    std::string tree = base::StringPrintf(
        " Site A ------------ proxies for B C\n"
        "   |--Site A ------- proxies for B C\n"
        "   +--Site B (C %s) -- proxies for A C\n"
        "Where A = http://a.com/\n"
        "      B = http://foo.com/\n"
        "      C = http://bar.com/",
        cross_site_rfh_type.c_str());
    EXPECT_EQ(tree, DepictFrameTree(root));

    navigation_observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(cross_site_url, observer.last_navigation_url());
    EXPECT_EQ(0U, child->child_count());
  }
}

// Verify that "scrolling" property on frame elements propagates to child frames
// correctly.
// Does not work on android since android has scrollbars overlayed.
// TODO(bokan): Pretty soon most/all platforms will use overlay scrollbars. This
// test should find a better way to check for scrollability. crbug.com/662196.
// Flaky on Linux. crbug.com/790929.
#if defined(OS_ANDROID) || defined(OS_LINUX)
#define MAYBE_FrameOwnerPropertiesPropagationScrolling \
  DISABLED_FrameOwnerPropertiesPropagationScrolling
#else
#define MAYBE_FrameOwnerPropertiesPropagationScrolling \
  FrameOwnerPropertiesPropagationScrolling
#endif
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       MAYBE_FrameOwnerPropertiesPropagationScrolling) {
#if defined(OS_MACOSX)
  ui::test::ScopedPreferredScrollerStyle scroller_style_override(false);
#endif
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_owner_properties_scrolling.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1u, root->child_count());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  FrameTreeNode* child = root->child_at(0);

  // If the available client width within the iframe is smaller than the
  // frame element's width, we assume there's a scrollbar.
  // Also note that just comparing clientHeight and scrollHeight of the frame's
  // document will not work.
  auto has_scrollbar = [](RenderFrameHostImpl* rfh) {
    int client_width;
    EXPECT_TRUE(ExecuteScriptAndExtractInt(
        rfh, "window.domAutomationController.send(document.body.clientWidth);",
        &client_width));
    const int kFrameElementWidth = 200;
    return client_width < kFrameElementWidth;
  };

  auto set_scrolling_property = [](RenderFrameHostImpl* parent_rfh,
                                   const std::string& value) {
    EXPECT_TRUE(ExecuteScript(
        parent_rfh,
        base::StringPrintf("document.getElementById('child-1').setAttribute("
                           "    'scrolling', '%s');",
                           value.c_str())));
  };

  // Run the test over variety of parent/child cases.
  GURL urls[] = {// Remote to remote.
                 embedded_test_server()->GetURL("c.com", "/tall_page.html"),
                 // Remote to local.
                 embedded_test_server()->GetURL("a.com", "/tall_page.html"),
                 // Local to remote.
                 embedded_test_server()->GetURL("b.com", "/tall_page.html")};
  const std::string scrolling_values[] = {"yes", "auto", "no"};

  for (size_t i = 0; i < arraysize(scrolling_values); ++i) {
    bool expect_scrollbar = scrolling_values[i] != "no";
    set_scrolling_property(root->current_frame_host(), scrolling_values[i]);
    for (size_t j = 0; j < arraysize(urls); ++j) {
      NavigateFrameToURL(child, urls[j]);
      EXPECT_EQ(expect_scrollbar, has_scrollbar(child->current_frame_host()));
    }
  }
}

// Verify that "marginwidth" and "marginheight" properties on frame elements
// propagate to child frames correctly.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       FrameOwnerPropertiesPropagationMargin) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_owner_properties_margin.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1u, root->child_count());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  FrameTreeNode* child = root->child_at(0);

  std::string margin_width;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      child,
      "window.domAutomationController.send("
      "document.body.getAttribute('marginwidth'));",
      &margin_width));
  EXPECT_EQ("10", margin_width);

  std::string margin_height;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      child,
      "window.domAutomationController.send("
      "document.body.getAttribute('marginheight'));",
      &margin_height));
  EXPECT_EQ("50", margin_height);

  // Run the test over variety of parent/child cases.
  GURL urls[] = {// Remote to remote.
                 embedded_test_server()->GetURL("c.com", "/title2.html"),
                 // Remote to local.
                 embedded_test_server()->GetURL("a.com", "/title1.html"),
                 // Local to remote.
                 embedded_test_server()->GetURL("b.com", "/title2.html")};

  int current_margin_width = 15;
  int current_margin_height = 25;

  // Before each navigation, we change the marginwidth and marginheight
  // properties of the frame. We then check whether those properties are applied
  // correctly after the navigation has completed.
  for (size_t i = 0; i < arraysize(urls); ++i) {
    // Change marginwidth and marginheight before navigating.
    EXPECT_TRUE(ExecuteScript(
        root,
        base::StringPrintf("document.getElementById('child-1').setAttribute("
                           "    'marginwidth', '%d');",
                           current_margin_width)));
    EXPECT_TRUE(ExecuteScript(
        root,
        base::StringPrintf("document.getElementById('child-1').setAttribute("
                           "    'marginheight', '%d');",
                           current_margin_height)));

    NavigateFrameToURL(child, urls[i]);

    std::string actual_margin_width;
    EXPECT_TRUE(ExecuteScriptAndExtractString(
        child,
        "window.domAutomationController.send("
        "document.body.getAttribute('marginwidth'));",
        &actual_margin_width));
    EXPECT_EQ(base::IntToString(current_margin_width), actual_margin_width);

    std::string actual_margin_height;
    EXPECT_TRUE(ExecuteScriptAndExtractString(
        child,
        "window.domAutomationController.send("
        "document.body.getAttribute('marginheight'));",
        &actual_margin_height));
    EXPECT_EQ(base::IntToString(current_margin_height), actual_margin_height);

    current_margin_width += 5;
    current_margin_height += 10;
  }
}

// Verify that "csp" property on frame elements propagates to child frames
// correctly. See  https://crbug.com/647588
IN_PROC_BROWSER_TEST_F(SitePerProcessEmbedderCSPEnforcementBrowserTest,
                       FrameOwnerPropertiesPropagationCSP) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_owner_properties_csp.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1u, root->child_count());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  FrameTreeNode* child = root->child_at(0);

  std::string csp;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      root,
      "window.domAutomationController.send("
      "document.getElementById('child-1').getAttribute('csp'));",
      &csp));
  EXPECT_EQ("object-src \'none\'", csp);

  // Run the test over variety of parent/child cases.
  GURL urls[] = {// Remote to remote.
                 embedded_test_server()->GetURL("c.com", "/title2.html"),
                 // Remote to local.
                 embedded_test_server()->GetURL("a.com", "/title1.html"),
                 // Local to remote.
                 embedded_test_server()->GetURL("b.com", "/title2.html")};

  std::vector<std::string> csp_values = {"default-src a.com",
                                         "default-src b.com", "img-src c.com"};

  // Before each navigation, we change the csp property of the frame.
  // We then check whether that property is applied
  // correctly after the navigation has completed.
  for (size_t i = 0; i < arraysize(urls); ++i) {
    // Change csp before navigating.
    EXPECT_TRUE(ExecuteScript(
        root,
        base::StringPrintf("document.getElementById('child-1').setAttribute("
                           "    'csp', '%s');",
                           csp_values[i].c_str())));

    NavigateFrameToURL(child, urls[i]);
    EXPECT_EQ(csp_values[i], child->frame_owner_properties().required_csp);
    // TODO(amalika): add checks that the CSP replication takes effect
  }
}

// Verify origin replication with an A-embed-B-embed-C-embed-A hierarchy.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, OriginReplication) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b(c(a),b), a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   |--Site B ------- proxies for A C\n"       // tiptop_child
      "   |    |--Site C -- proxies for A B\n"       // middle_child
      "   |    |    +--Site A -- proxies for B C\n"  // lowest_child
      "   |    +--Site B -- proxies for A C\n"
      "   +--Site A ------- proxies for B C\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/\n"
      "      C = http://c.com/",
      DepictFrameTree(root));

  std::string a_origin = embedded_test_server()->GetURL("a.com", "/").spec();
  std::string b_origin = embedded_test_server()->GetURL("b.com", "/").spec();
  std::string c_origin = embedded_test_server()->GetURL("c.com", "/").spec();
  FrameTreeNode* tiptop_child = root->child_at(0);
  FrameTreeNode* middle_child = root->child_at(0)->child_at(0);
  FrameTreeNode* lowest_child = root->child_at(0)->child_at(0)->child_at(0);

  // Check that b.com frame's location.ancestorOrigins contains the correct
  // origin for the parent.  The origin should have been replicated as part of
  // the mojom::Renderer::CreateView message that created the parent's
  // RenderFrameProxy in b.com's process.
  int ancestor_origins_length = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      tiptop_child,
      "window.domAutomationController.send(location.ancestorOrigins.length);",
      &ancestor_origins_length));
  EXPECT_EQ(1, ancestor_origins_length);
  std::string result;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      tiptop_child,
      "window.domAutomationController.send(location.ancestorOrigins[0]);",
      &result));
  EXPECT_EQ(a_origin, result + "/");

  // Check that c.com frame's location.ancestorOrigins contains the correct
  // origin for its two ancestors. The topmost parent origin should be
  // replicated as part of mojom::Renderer::CreateView, and the middle frame
  // (b.com's) origin should be replicated as part of
  // mojom::Renderer::CreateFrameProxy sent for b.com's frame in c.com's
  // process.
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      middle_child,
      "window.domAutomationController.send(location.ancestorOrigins.length);",
      &ancestor_origins_length));
  EXPECT_EQ(2, ancestor_origins_length);
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      middle_child,
      "window.domAutomationController.send(location.ancestorOrigins[0]);",
      &result));
  EXPECT_EQ(b_origin, result + "/");
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      middle_child,
      "window.domAutomationController.send(location.ancestorOrigins[1]);",
      &result));
  EXPECT_EQ(a_origin, result + "/");

  // Check that the nested a.com frame's location.ancestorOrigins contains the
  // correct origin for its three ancestors.
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      lowest_child,
      "window.domAutomationController.send(location.ancestorOrigins.length);",
      &ancestor_origins_length));
  EXPECT_EQ(3, ancestor_origins_length);
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      lowest_child,
      "window.domAutomationController.send(location.ancestorOrigins[0]);",
      &result));
  EXPECT_EQ(c_origin, result + "/");
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      lowest_child,
      "window.domAutomationController.send(location.ancestorOrigins[1]);",
      &result));
  EXPECT_EQ(b_origin, result + "/");
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      lowest_child,
      "window.domAutomationController.send(location.ancestorOrigins[2]);",
      &result));
  EXPECT_EQ(a_origin, result + "/");
}

// Test that HasReceivedUserGesture and HasReceivedUserGestureBeforeNavigation
// are propagated correctly across origins.
IN_PROC_BROWSER_TEST_F(SitePerProcessAutoplayBrowserTest,
                       PropagateUserGestureFlag) {
  GURL main_url(embedded_test_server()->GetURL(
      "example.com", "/media/autoplay/autoplay-enabled.html"));
  GURL foo_url(embedded_test_server()->GetURL(
      "foo.com", "/media/autoplay/autoplay-enabled.html"));
  GURL bar_url(embedded_test_server()->GetURL(
      "bar.com", "/media/autoplay/autoplay-enabled.html"));
  GURL secondary_url(embedded_test_server()->GetURL(
      "test.example.com", "/media/autoplay/autoplay-enabled.html"));
  GURL disabled_url(embedded_test_server()->GetURL(
      "test.example.com", "/media/autoplay/autoplay-disabled.html"));

  // Load a page with an iframe that has autoplay.
  OpenURLBlockUntilNavigationComplete(shell(), main_url);
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Navigate the subframes to cross-origin pages.
  NavigateFrameAndWait(root->child_at(0), foo_url);
  NavigateFrameAndWait(root->child_at(0)->child_at(0), bar_url);

  // Test that all frames can autoplay if there has been a gesture in the top
  // frame.
  EXPECT_TRUE(AutoplayAllowed(shell(), true));
  EXPECT_TRUE(AutoplayAllowed(root->child_at(0), false));
  EXPECT_TRUE(AutoplayAllowed(root->child_at(0)->child_at(0), false));

  // Navigate to a new page on the same origin.
  OpenURLBlockUntilNavigationComplete(shell(), secondary_url);
  root = web_contents()->GetFrameTree()->root();

  // Navigate the subframes to cross-origin pages.
  NavigateFrameAndWait(root->child_at(0), foo_url);
  NavigateFrameAndWait(root->child_at(0)->child_at(0), bar_url);

  // Test that all frames can autoplay because the gesture bit has been passed
  // through the navigation.
  EXPECT_TRUE(AutoplayAllowed(shell(), false));
  EXPECT_TRUE(AutoplayAllowed(root->child_at(0), false));
  EXPECT_TRUE(AutoplayAllowed(root->child_at(0)->child_at(0), false));

  // Navigate to a page with autoplay disabled.
  OpenURLBlockUntilNavigationComplete(shell(), disabled_url);
  NavigateFrameAndWait(root->child_at(0), foo_url);

  // Test that autoplay is no longer allowed.
  EXPECT_TRUE(AutoplayAllowed(shell(), false));
  EXPECT_FALSE(AutoplayAllowed(root->child_at(0), false));

  // Navigate to another origin and make sure autoplay is disabled.
  OpenURLBlockUntilNavigationComplete(shell(), foo_url);
  NavigateFrameAndWait(root->child_at(0), bar_url);
  EXPECT_FALSE(AutoplayAllowed(shell(), false));
  EXPECT_FALSE(AutoplayAllowed(shell(), false));
}

IN_PROC_BROWSER_TEST_F(SitePerProcesScrollAnchorTest,
                       RemoteToLocalScrollAnchorRestore) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/page_with_samesite_iframe.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);

  GURL frame_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  NavigateFrameToURL(child, frame_url);

  EXPECT_NE(child->current_frame_host()->GetSiteInstance(),
            root->current_frame_host()->GetSiteInstance());

  TestFrameNavigationObserver frame_observer2(child);
  EXPECT_TRUE(ExecuteScript(root, "window.history.back()"));
  frame_observer2.Wait();

  EXPECT_EQ(child->current_frame_host()->GetSiteInstance(),
            root->current_frame_host()->GetSiteInstance());
}

// Check that iframe sandbox flags are replicated correctly.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, SandboxFlagsReplication) {
  GURL main_url(embedded_test_server()->GetURL("/sandboxed_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());

  // Navigate the second (sandboxed) subframe to a cross-site page with a
  // subframe.
  GURL foo_url(
      embedded_test_server()->GetURL("foo.com", "/frame_tree/1-1.html"));
  NavigateFrameToURL(root->child_at(1), foo_url);
  EXPECT_TRUE(WaitForLoadStop(shell()->web_contents()));

  // We can't use a TestNavigationObserver to verify the URL here,
  // since the frame has children that may have clobbered it in the observer.
  EXPECT_EQ(foo_url, root->child_at(1)->current_url());

  // Load cross-site page into subframe's subframe.
  ASSERT_EQ(2U, root->child_at(1)->child_count());
  GURL bar_url(embedded_test_server()->GetURL("bar.com", "/title1.html"));
  NavigateFrameToURL(root->child_at(1)->child_at(0), bar_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(bar_url, observer.last_navigation_url());

  // Opening a popup in the sandboxed foo.com iframe should fail.
  bool success = false;
  EXPECT_TRUE(
      ExecuteScriptAndExtractBool(root->child_at(1),
                                  "window.domAutomationController.send("
                                  "!window.open('data:text/html,dataurl'));",
                                  &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());

  // Opening a popup in a frame whose parent is sandboxed should also fail.
  // Here, bar.com frame's sandboxed parent frame is a remote frame in
  // bar.com's process.
  success = false;
  EXPECT_TRUE(
      ExecuteScriptAndExtractBool(root->child_at(1)->child_at(0),
                                  "window.domAutomationController.send("
                                  "!window.open('data:text/html,dataurl'));",
                                  &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());

  // Same, but now try the case where bar.com frame's sandboxed parent is a
  // local frame in bar.com's process.
  success = false;
  EXPECT_TRUE(
      ExecuteScriptAndExtractBool(root->child_at(2)->child_at(0),
                                  "window.domAutomationController.send("
                                  "!window.open('data:text/html,dataurl'));",
                                  &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());

  // Check that foo.com frame's location.ancestorOrigins contains the correct
  // origin for the parent, which should be unaffected by sandboxing.
  int ancestor_origins_length = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root->child_at(1),
      "window.domAutomationController.send(location.ancestorOrigins.length);",
      &ancestor_origins_length));
  EXPECT_EQ(1, ancestor_origins_length);
  std::string result;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      root->child_at(1),
      "window.domAutomationController.send(location.ancestorOrigins[0]);",
      &result));
  EXPECT_EQ(result + "/", main_url.GetOrigin().spec());

  // Now check location.ancestorOrigins for the bar.com frame. The middle frame
  // (foo.com's) origin should be unique, since that frame is sandboxed, and
  // the top frame should match |main_url|.
  FrameTreeNode* bottom_child = root->child_at(1)->child_at(0);
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      bottom_child,
      "window.domAutomationController.send(location.ancestorOrigins.length);",
      &ancestor_origins_length));
  EXPECT_EQ(2, ancestor_origins_length);
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      bottom_child,
      "window.domAutomationController.send(location.ancestorOrigins[0]);",
      &result));
  EXPECT_EQ("null", result);
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      bottom_child,
      "window.domAutomationController.send(location.ancestorOrigins[1]);",
      &result));
  EXPECT_EQ(main_url.GetOrigin().spec(), result + "/");
}

// Check that dynamic updates to iframe sandbox flags are propagated correctly.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, DynamicSandboxFlags) {
  GURL main_url(
      embedded_test_server()->GetURL("/frame_tree/page_with_two_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());
  ASSERT_EQ(2U, root->child_count());

  // Make sure first frame starts out at the correct cross-site page.
  EXPECT_EQ(embedded_test_server()->GetURL("bar.com", "/title1.html"),
            root->child_at(0)->current_url());

  // Navigate second frame to another cross-site page.
  GURL baz_url(embedded_test_server()->GetURL("baz.com", "/title1.html"));
  NavigateFrameToURL(root->child_at(1), baz_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(baz_url, observer.last_navigation_url());

  // Both frames should not be sandboxed to start with.
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(0)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(0)->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(1)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(1)->effective_frame_policy().sandbox_flags);

  // Dynamically update sandbox flags for the first frame.
  EXPECT_TRUE(ExecuteScript(
      shell(), "document.querySelector('iframe').sandbox='allow-scripts';"));

  // Check that updated sandbox flags are propagated to browser process.
  // The new flags should be reflected in pending_frame_policy().sandbox_flags,
  // while effective_frame_policy().sandbox_flags should still reflect the old
  // flags, because sandbox flag updates take place only after navigations.
  // "allow-scripts" resets both SandboxFlags::Scripts and
  // SandboxFlags::AutomaticFeatures bits per blink::parseSandboxPolicy().
  blink::WebSandboxFlags expected_flags =
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
      ~blink::WebSandboxFlags::kAutomaticFeatures;
  EXPECT_EQ(expected_flags,
            root->child_at(0)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(0)->effective_frame_policy().sandbox_flags);

  // Navigate the first frame to a page on the same site.  The new sandbox
  // flags should take effect.
  GURL bar_url(
      embedded_test_server()->GetURL("bar.com", "/frame_tree/2-4.html"));
  NavigateFrameToURL(root->child_at(0), bar_url);
  // (The new page has a subframe; wait for it to load as well.)
  ASSERT_TRUE(WaitForLoadStop(shell()->web_contents()));
  EXPECT_EQ(bar_url, root->child_at(0)->current_url());
  ASSERT_EQ(1U, root->child_at(0)->child_count());

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   |--Site B ------- proxies for A C\n"
      "   |    +--Site B -- proxies for A C\n"
      "   +--Site C ------- proxies for A B\n"
      "Where A = http://127.0.0.1/\n"
      "      B = http://bar.com/\n"
      "      C = http://baz.com/",
      DepictFrameTree(root));

  // Confirm that the browser process has updated the frame's current sandbox
  // flags.
  EXPECT_EQ(expected_flags,
            root->child_at(0)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(expected_flags,
            root->child_at(0)->effective_frame_policy().sandbox_flags);

  // Opening a popup in the now-sandboxed frame should fail.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0),
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());

  // Navigate the child of the now-sandboxed frame to a page on baz.com.  The
  // child should inherit the latest sandbox flags from its parent frame, which
  // is currently a proxy in baz.com's renderer process.  This checks that the
  // proxies of |root->child_at(0)| were also updated with the latest sandbox
  // flags.
  GURL baz_child_url(embedded_test_server()->GetURL("baz.com", "/title2.html"));
  NavigateFrameToURL(root->child_at(0)->child_at(0), baz_child_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(baz_child_url, observer.last_navigation_url());

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   |--Site B ------- proxies for A C\n"
      "   |    +--Site C -- proxies for A B\n"
      "   +--Site C ------- proxies for A B\n"
      "Where A = http://127.0.0.1/\n"
      "      B = http://bar.com/\n"
      "      C = http://baz.com/",
      DepictFrameTree(root));

  // Opening a popup in the child of a sandboxed frame should fail.
  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0)->child_at(0),
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());

  // Child of a sandboxed frame should also be sandboxed on the browser side.
  EXPECT_EQ(
      expected_flags,
      root->child_at(0)->child_at(0)->effective_frame_policy().sandbox_flags);
}

// Check that dynamic updates to iframe sandbox flags are propagated correctly.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       DynamicSandboxFlagsRemoteToLocal) {
  GURL main_url(
      embedded_test_server()->GetURL("/frame_tree/page_with_two_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());
  ASSERT_EQ(2U, root->child_count());

  // Make sure the two frames starts out at correct URLs.
  EXPECT_EQ(embedded_test_server()->GetURL("bar.com", "/title1.html"),
            root->child_at(0)->current_url());
  EXPECT_EQ(embedded_test_server()->GetURL("/title1.html"),
            root->child_at(1)->current_url());

  // Update the second frame's sandbox flags.
  EXPECT_TRUE(ExecuteScript(
      shell(),
      "document.querySelectorAll('iframe')[1].sandbox='allow-scripts'"));

  // Check that the current sandbox flags are updated but the effective
  // sandbox flags are not.
  blink::WebSandboxFlags expected_flags =
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
      ~blink::WebSandboxFlags::kAutomaticFeatures;
  EXPECT_EQ(expected_flags,
            root->child_at(1)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(1)->effective_frame_policy().sandbox_flags);

  // Navigate the second subframe to a page on bar.com.  This will trigger a
  // remote-to-local frame swap in bar.com's process.
  GURL bar_url(embedded_test_server()->GetURL(
      "bar.com", "/frame_tree/page_with_one_frame.html"));
  NavigateFrameToURL(root->child_at(1), bar_url);
  EXPECT_EQ(bar_url, root->child_at(1)->current_url());
  ASSERT_EQ(1U, root->child_at(1)->child_count());

  // Confirm that the browser process has updated the current sandbox flags.
  EXPECT_EQ(expected_flags,
            root->child_at(1)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(expected_flags,
            root->child_at(1)->effective_frame_policy().sandbox_flags);

  // Opening a popup in the sandboxed second frame should fail.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(1),
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());

  // Make sure that the child frame inherits the sandbox flags of its
  // now-sandboxed parent frame.
  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(1)->child_at(0),
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());
}

// Check that dynamic updates to iframe sandbox flags are propagated correctly.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       DynamicSandboxFlagsRendererInitiatedNavigation) {
  GURL main_url(
      embedded_test_server()->GetURL("/frame_tree/page_with_one_frame.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());
  ASSERT_EQ(1U, root->child_count());

  // Make sure the frame starts out at the correct cross-site page.
  EXPECT_EQ(embedded_test_server()->GetURL("baz.com", "/title1.html"),
            root->child_at(0)->current_url());

  // The frame should not be sandboxed to start with.
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(0)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(0)->effective_frame_policy().sandbox_flags);

  // Dynamically update the frame's sandbox flags.
  EXPECT_TRUE(ExecuteScript(
      shell(), "document.querySelector('iframe').sandbox='allow-scripts';"));

  // Check that updated sandbox flags are propagated to browser process.
  // The new flags should be set in pending_frame_policy().sandbox_flags, while
  // effective_frame_policy().sandbox_flags should still reflect the old flags,
  // because sandbox flag updates take place only after navigations.
  // "allow-scripts" resets both SandboxFlags::Scripts and
  // SandboxFlags::AutomaticFeatures bits per blink::parseSandboxPolicy().
  blink::WebSandboxFlags expected_flags =
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
      ~blink::WebSandboxFlags::kAutomaticFeatures;
  EXPECT_EQ(expected_flags,
            root->child_at(0)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(0)->effective_frame_policy().sandbox_flags);

  // Perform a renderer-initiated same-site navigation in the first frame. The
  // new sandbox flags should take effect.
  TestFrameNavigationObserver frame_observer(root->child_at(0));
  ASSERT_TRUE(
      ExecuteScript(root->child_at(0), "window.location.href='/title2.html'"));
  frame_observer.Wait();
  EXPECT_EQ(embedded_test_server()->GetURL("baz.com", "/title2.html"),
            root->child_at(0)->current_url());

  // Confirm that the browser process has updated the frame's current sandbox
  // flags.
  EXPECT_EQ(expected_flags,
            root->child_at(0)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(expected_flags,
            root->child_at(0)->effective_frame_policy().sandbox_flags);

  // Opening a popup in the now-sandboxed frame should fail.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0),
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());
}

// Verify that when a new child frame is added, the proxies created for it in
// other SiteInstances have correct sandbox flags and origin.
//
//     A         A           A
//    /         / \         / \    .
//   B    ->   B   A   ->  B   A
//                              \  .
//                               B
//
// The test checks sandbox flags and origin for the proxy added in step 2, by
// checking whether the grandchild frame added in step 3 sees proper sandbox
// flags and origin for its (remote) parent.  This wasn't addressed when
// https://crbug.com/423587 was fixed.
// TODO(alexmos): Re-enable when https://crbug.com/610893 is fixed.
IN_PROC_BROWSER_TEST_F(
    SitePerProcessBrowserTest,
    DISABLED_ProxiesForNewChildFramesHaveCorrectReplicationState) {
  GURL main_url(
      embedded_test_server()->GetURL("/frame_tree/page_with_one_frame.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  TestNavigationObserver observer(shell()->web_contents());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://127.0.0.1/\n"
      "      B = http://baz.com/",
      DepictFrameTree(root));

  // In the root frame, add a new sandboxed local frame, which itself has a
  // child frame on baz.com.  Wait for three RenderFrameHosts to be created:
  // the new sandboxed local frame, its child (while it's still local), and a
  // pending RFH when starting the cross-site navigation to baz.com.
  RenderFrameHostCreatedObserver frame_observer(shell()->web_contents(), 3);
  EXPECT_TRUE(ExecuteScript(root,
                            "addFrame('/frame_tree/page_with_one_frame.html',"
                            "         'allow-scripts allow-same-origin'))"));
  frame_observer.Wait();

  // Wait for the cross-site navigation to baz.com in the grandchild to finish.
  FrameTreeNode* bottom_child = root->child_at(1)->child_at(0);
  TestFrameNavigationObserver navigation_observer(bottom_child);
  navigation_observer.Wait();

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "        +--Site B -- proxies for A\n"
      "Where A = http://127.0.0.1/\n"
      "      B = http://baz.com/",
      DepictFrameTree(root));

  // Use location.ancestorOrigins to check that the grandchild on baz.com sees
  // correct origin for its parent.
  int ancestor_origins_length = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      bottom_child,
      "window.domAutomationController.send(location.ancestorOrigins.length);",
      &ancestor_origins_length));
  EXPECT_EQ(2, ancestor_origins_length);
  std::string parent_origin;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      bottom_child,
      "window.domAutomationController.send(location.ancestorOrigins[0]);",
      &parent_origin));
  EXPECT_EQ(main_url.GetOrigin().spec(), parent_origin + "/");

  // Check that the sandbox flags in the browser process are correct.
  // "allow-scripts" resets both WebSandboxFlags::Scripts and
  // WebSandboxFlags::AutomaticFeatures bits per blink::parseSandboxPolicy().
  blink::WebSandboxFlags expected_flags =
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
      ~blink::WebSandboxFlags::kAutomaticFeatures &
      ~blink::WebSandboxFlags::kOrigin;
  EXPECT_EQ(expected_flags,
            root->child_at(1)->effective_frame_policy().sandbox_flags);

  // The child of the sandboxed frame should've inherited sandbox flags, so it
  // should not be able to create popups.
  EXPECT_EQ(expected_flags,
            bottom_child->effective_frame_policy().sandbox_flags);
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      bottom_child,
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());
}

// Verify that a child frame can retrieve the name property set by its parent.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, WindowNameReplication) {
  GURL main_url(embedded_test_server()->GetURL("/frame_tree/2-4.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());

  // Load cross-site page into iframe.
  GURL frame_url =
      embedded_test_server()->GetURL("foo.com", "/frame_tree/3-1.html");
  NavigateFrameToURL(root->child_at(0), frame_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(frame_url, observer.last_navigation_url());

  // Ensure that a new process is created for the subframe.
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            root->child_at(0)->current_frame_host()->GetSiteInstance());

  // Check that the window.name seen by the frame matches the name attribute
  // specified by its parent in the iframe tag.
  std::string result;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      root->child_at(0), "window.domAutomationController.send(window.name);",
      &result));
  EXPECT_EQ("3-1-name", result);
}

// Verify that dynamic updates to a frame's window.name propagate to the
// frame's proxies, so that the latest frame names can be used in navigations.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, DynamicWindowName) {
  GURL main_url(embedded_test_server()->GetURL("/frame_tree/2-4.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  TestNavigationObserver observer(shell()->web_contents());

  // Load cross-site page into iframe.
  GURL frame_url =
      embedded_test_server()->GetURL("foo.com", "/frame_tree/3-1.html");
  NavigateFrameToURL(root->child_at(0), frame_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(frame_url, observer.last_navigation_url());

  // Browser process should know the child frame's original window.name
  // specified in the iframe element.
  EXPECT_EQ(root->child_at(0)->frame_name(), "3-1-name");

  // Update the child frame's window.name.
  EXPECT_TRUE(
      ExecuteScript(root->child_at(0), "window.name = 'updated-name';"));

  // The change should propagate to the browser process.
  EXPECT_EQ(root->child_at(0)->frame_name(), "updated-name");

  // The proxy in the parent process should also receive the updated name.
  // Now iframe's name and the content window's name differ, so it shouldn't
  // be possible to access to the content window with the updated name.
  bool success = false;
  EXPECT_TRUE(
      ExecuteScriptAndExtractBool(shell(),
                                  "window.domAutomationController.send("
                                  "    frames['updated-name'] === undefined);",
                                  &success));
  // TODO(yukishiino): The following expectation should be TRUE, but we're
  // intentionally disabling the name and origin check of the named access on
  // window.  See also crbug.com/538562 and crbug.com/701489.
  EXPECT_FALSE(success);
  // Change iframe's name to match the content window's name so that it can
  // reference the child frame by its new name in case of cross origin.
  EXPECT_TRUE(ExecuteScript(root, "window['3-1-id'].name = 'updated-name';"));
  success = false;
  EXPECT_TRUE(
      ExecuteScriptAndExtractBool(shell(),
                                  "window.domAutomationController.send("
                                  "    frames['updated-name'] == frames[0]);",
                                  &success));
  EXPECT_TRUE(success);

  // Issue a renderer-initiated navigation from the root frame to the child
  // frame using the frame's name. Make sure correct frame is navigated.
  //
  // TODO(alexmos): When blink::createWindow is refactored to handle
  // RemoteFrames, this should also be tested via window.open(url, frame_name)
  // and a more complicated frame hierarchy (https://crbug.com/463742)
  TestFrameNavigationObserver frame_observer(root->child_at(0));
  GURL foo_url(embedded_test_server()->GetURL("foo.com", "/title1.html"));
  EXPECT_TRUE(ExecuteScript(
      shell(),
      base::StringPrintf("frames['updated-name'].location.href = '%s';",
                         foo_url.spec().c_str())));
  frame_observer.Wait();
  EXPECT_EQ(foo_url, root->child_at(0)->current_url());
}

// Verify that when a frame is navigated to a new origin, the origin update
// propagates to the frame's proxies.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, OriginUpdatesReachProxies) {
  GURL main_url(
      embedded_test_server()->GetURL("/frame_tree/page_with_two_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  TestNavigationObserver observer(shell()->web_contents());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "Where A = http://127.0.0.1/\n"
      "      B = http://bar.com/",
      DepictFrameTree(root));

  // Navigate second subframe to a baz.com.  This should send an origin update
  // to the frame's proxy in the bar.com (first frame's) process.
  GURL frame_url = embedded_test_server()->GetURL("baz.com", "/title2.html");
  NavigateFrameToURL(root->child_at(1), frame_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(frame_url, observer.last_navigation_url());

  // The first frame can't directly observe the second frame's origin with
  // JavaScript.  Instead, try to navigate the second frame from the first
  // frame.  This should fail with a console error message, which should
  // contain the second frame's updated origin (see blink::Frame::canNavigate).
  std::unique_ptr<ConsoleObserverDelegate> console_delegate(
      new ConsoleObserverDelegate(
          shell()->web_contents(),
          "Unsafe JavaScript attempt to initiate navigation*"));
  shell()->web_contents()->SetDelegate(console_delegate.get());

  // frames[1] can't be used due to a bug where RemoteFrames are created out of
  // order (https://crbug.com/478792).  Instead, target second frame by name.
  EXPECT_TRUE(ExecuteScript(root->child_at(0),
                            "try { parent.frames['frame2'].location.href = "
                            "'data:text/html,foo'; } catch (e) {}"));
  console_delegate->Wait();

  std::string frame_origin = root->child_at(1)->current_origin().Serialize();
  EXPECT_EQ(frame_origin + "/", frame_url.GetOrigin().spec());
  EXPECT_TRUE(
      base::MatchPattern(console_delegate->message(), "*" + frame_origin + "*"))
      << "Error message does not contain the frame's latest origin ("
      << frame_origin << ")";
}

// Ensure that navigating subframes in --site-per-process mode properly fires
// the DidStopLoading event on WebContentsObserver.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, CrossSiteDidStopLoading) {
  GURL main_url(embedded_test_server()->GetURL("/site_per_process_main.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());

  // Load same-site page into iframe.
  FrameTreeNode* child = root->child_at(0);
  GURL http_url(embedded_test_server()->GetURL("/title1.html"));
  NavigateFrameToURL(child, http_url);
  EXPECT_EQ(http_url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());

  // Load cross-site page into iframe.
  TestNavigationObserver nav_observer(shell()->web_contents(), 1);
  GURL url = embedded_test_server()->GetURL("foo.com", "/title2.html");
  NavigationController::LoadURLParams params(url);
  params.transition_type = ui::PAGE_TRANSITION_LINK;
  params.frame_tree_node_id = child->frame_tree_node_id();
  child->navigator()->GetController()->LoadURLWithParams(params);
  nav_observer.Wait();

  // Verify that the navigation succeeded and the expected URL was loaded.
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());
}

// Ensure that the renderer does not crash when navigating a frame that has a
// sibling RemoteFrame.  See https://crbug.com/426953.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateWithSiblingRemoteFrame) {
  GURL main_url(
      embedded_test_server()->GetURL("/frame_tree/page_with_two_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  TestNavigationObserver observer(shell()->web_contents());

  // Make sure the first frame is out of process.
  ASSERT_EQ(2U, root->child_count());
  FrameTreeNode* node2 = root->child_at(0);
  EXPECT_NE(root->current_frame_host()->GetSiteInstance(),
            node2->current_frame_host()->GetSiteInstance());

  // Make sure the second frame is in the parent's process.
  FrameTreeNode* node3 = root->child_at(1);
  EXPECT_EQ(root->current_frame_host()->GetSiteInstance(),
            node3->current_frame_host()->GetSiteInstance());

  // Navigate the second iframe (node3) to a URL in its own process.
  GURL title_url = embedded_test_server()->GetURL("/title2.html");
  NavigateFrameToURL(node3, title_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(title_url, observer.last_navigation_url());
  EXPECT_EQ(root->current_frame_host()->GetSiteInstance(),
            node3->current_frame_host()->GetSiteInstance());
  EXPECT_TRUE(node3->current_frame_host()->IsRenderFrameLive());
}

// Ensure that the renderer does not crash when a local frame with a remote
// parent frame is swapped from local to remote, then back to local again.
// See https://crbug.com/585654.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateSiblingsToSameProcess) {
  GURL main_url(
      embedded_test_server()->GetURL("/frame_tree/page_with_two_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  FrameTreeNode* node2 = root->child_at(0);
  FrameTreeNode* node3 = root->child_at(1);

  // Navigate the second iframe to the same process as the first.
  GURL frame_url = embedded_test_server()->GetURL("bar.com", "/title1.html");
  NavigateFrameToURL(node3, frame_url);

  // Verify that they are in the same process.
  EXPECT_EQ(node2->current_frame_host()->GetSiteInstance(),
            node3->current_frame_host()->GetSiteInstance());
  EXPECT_NE(root->current_frame_host()->GetSiteInstance(),
            node3->current_frame_host()->GetSiteInstance());

  // Navigate the first iframe into its parent's process.
  GURL title_url = embedded_test_server()->GetURL("/title2.html");
  NavigateFrameToURL(node2, title_url);
  EXPECT_NE(node2->current_frame_host()->GetSiteInstance(),
            node3->current_frame_host()->GetSiteInstance());

  // Return the first iframe to the same process as its sibling, and ensure
  // that it does not crash.
  NavigateFrameToURL(node2, frame_url);
  EXPECT_EQ(node2->current_frame_host()->GetSiteInstance(),
            node3->current_frame_host()->GetSiteInstance());
  EXPECT_TRUE(node2->current_frame_host()->IsRenderFrameLive());
}

// Verify that load events for iframe elements work when the child frame is
// out-of-process.  In such cases, the load event is forwarded from the child
// frame to the parent frame via the browser process.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, LoadEventForwarding) {
  // Load a page with a cross-site frame.  The parent page has an onload
  // handler in the iframe element that appends "LOADED" to the document title.
  {
    GURL main_url(
        embedded_test_server()->GetURL("/frame_with_load_event.html"));
    base::string16 expected_title(base::UTF8ToUTF16("LOADED"));
    TitleWatcher title_watcher(shell()->web_contents(), expected_title);
    EXPECT_TRUE(NavigateToURL(shell(), main_url));
    EXPECT_EQ(title_watcher.WaitAndGetTitle(), expected_title);
  }

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Load another cross-site page into the iframe and check that the load event
  // is fired.
  {
    GURL foo_url(embedded_test_server()->GetURL("foo.com", "/title1.html"));
    base::string16 expected_title(base::UTF8ToUTF16("LOADEDLOADED"));
    TitleWatcher title_watcher(shell()->web_contents(), expected_title);
    TestNavigationObserver observer(shell()->web_contents());
    NavigateFrameToURL(root->child_at(0), foo_url);
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(foo_url, observer.last_navigation_url());
    EXPECT_EQ(title_watcher.WaitAndGetTitle(), expected_title);
  }
}

// Check that postMessage can be routed between cross-site iframes.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, SubframePostMessage) {
  GURL main_url(embedded_test_server()->GetURL(
      "/frame_tree/page_with_post_message_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  ASSERT_EQ(2U, root->child_count());

  // Verify the frames start at correct URLs.  First frame should be
  // same-site; second frame should be cross-site.
  GURL same_site_url(embedded_test_server()->GetURL("/post_message.html"));
  EXPECT_EQ(same_site_url, root->child_at(0)->current_url());
  GURL foo_url(embedded_test_server()->GetURL("foo.com", "/post_message.html"));
  EXPECT_EQ(foo_url, root->child_at(1)->current_url());
  EXPECT_NE(root->child_at(0)->current_frame_host()->GetSiteInstance(),
            root->child_at(1)->current_frame_host()->GetSiteInstance());

  // Send a message from first, same-site frame to second, cross-site frame.
  // Expect the second frame to reply back to the first frame.
  PostMessageAndWaitForReply(root->child_at(0),
                             "postToSibling('subframe-msg','subframe2')",
                             "\"done-subframe1\"");

  // Send a postMessage from second, cross-site frame to its parent.  Expect
  // parent to send a reply to the frame.
  base::string16 expected_title(base::ASCIIToUTF16("subframe-msg"));
  TitleWatcher title_watcher(shell()->web_contents(), expected_title);
  PostMessageAndWaitForReply(root->child_at(1), "postToParent('subframe-msg')",
                             "\"done-subframe2\"");
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());

  // Verify the total number of received messages for each subframe.  First
  // frame should have one message (reply from second frame).  Second frame
  // should have two messages (message from first frame and reply from parent).
  // Parent should have one message (from second frame).
  EXPECT_EQ(1, GetReceivedMessages(root->child_at(0)));
  EXPECT_EQ(2, GetReceivedMessages(root->child_at(1)));
  EXPECT_EQ(1, GetReceivedMessages(root));
}

// Check that renderer initiated navigations which commit a new RenderFrameHost
// do not crash if the original RenderFrameHost was being covered by an
// interstitial. See crbug.com/607964.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateOpenerWithInterstitial) {
  EXPECT_TRUE(NavigateToURL(
      shell(), embedded_test_server()->GetURL("a.com", "/title1.html")));

  // Open a popup and navigate it to bar.com.
  ShellAddedObserver new_shell_observer;
  EXPECT_TRUE(ExecuteScript(web_contents(), "window.open('about:blank');"));
  Shell* popup = new_shell_observer.GetShell();
  EXPECT_TRUE(NavigateToURLFromRenderer(
      popup,
      embedded_test_server()->GetURL("bar.com", "/navigate_opener.html")));

  // Show an interstitial in the opener.
  TestInterstitialDelegate* delegate = new TestInterstitialDelegate;
  WebContentsImpl* opener_contents =
      static_cast<WebContentsImpl*>(web_contents());
  GURL interstitial_url("http://interstitial");
  InterstitialPageImpl* interstitial = new InterstitialPageImpl(
      opener_contents, static_cast<RenderWidgetHostDelegate*>(opener_contents),
      true, interstitial_url, delegate);
  interstitial->Show();
  WaitForInterstitialAttach(opener_contents);

  // Now, navigate the opener cross-process using the popup while it still has
  // an interstitial. This should not crash.
  TestNavigationObserver navigation_observer(opener_contents);
  EXPECT_TRUE(ExecuteScript(popup, "navigateOpener();"));
  navigation_observer.Wait();
}

// Check that postMessage can be sent from a subframe on a cross-process opener
// tab, and that its event.source points to a valid proxy.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       PostMessageWithSubframeOnOpenerChain) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_post_message_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  ASSERT_EQ(2U, root->child_count());

  // Verify the initial state of the world.  First frame should be same-site;
  // second frame should be cross-site.
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site A ------- proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://foo.com/",
      DepictFrameTree(root));

  // Open a popup from the first subframe (so that popup's window.opener points
  // to the subframe) and navigate it to bar.com.
  ShellAddedObserver new_shell_observer;
  EXPECT_TRUE(ExecuteScript(root->child_at(0), "openPopup('about:blank');"));
  Shell* popup = new_shell_observer.GetShell();
  GURL popup_url(
      embedded_test_server()->GetURL("bar.com", "/post_message.html"));
  EXPECT_TRUE(NavigateToURLFromRenderer(popup, popup_url));

  // From the popup, open another popup for baz.com.  This will be used to
  // check that the whole opener chain is processed when creating proxies and
  // not just an immediate opener.
  ShellAddedObserver new_shell_observer2;
  EXPECT_TRUE(ExecuteScript(popup, "openPopup('about:blank');"));
  Shell* popup2 = new_shell_observer2.GetShell();
  GURL popup2_url(
      embedded_test_server()->GetURL("baz.com", "/post_message.html"));
  EXPECT_TRUE(NavigateToURLFromRenderer(popup2, popup2_url));

  // Ensure that we've created proxies for SiteInstances of both popups (C, D)
  // in the main window's frame tree.
  EXPECT_EQ(
      " Site A ------------ proxies for B C D\n"
      "   |--Site A ------- proxies for B C D\n"
      "   +--Site B ------- proxies for A C D\n"
      "Where A = http://a.com/\n"
      "      B = http://foo.com/\n"
      "      C = http://bar.com/\n"
      "      D = http://baz.com/",
      DepictFrameTree(root));

  // Check the first popup's frame tree as well.  Note that it doesn't have a
  // proxy for foo.com, since foo.com can't reach the popup.  It does have a
  // proxy for its opener a.com (which can reach it via the window.open
  // reference) and second popup (which can reach it via window.opener).
  FrameTreeNode* popup_root =
      static_cast<WebContentsImpl*>(popup->web_contents())
          ->GetFrameTree()
          ->root();
  EXPECT_EQ(
      " Site C ------------ proxies for A D\n"
      "Where A = http://a.com/\n"
      "      C = http://bar.com/\n"
      "      D = http://baz.com/",
      DepictFrameTree(popup_root));

  // Send a message from first subframe on main page to the first popup and
  // wait for a reply back. The reply verifies that the proxy for the opener
  // tab's subframe is targeted properly.
  PostMessageAndWaitForReply(root->child_at(0), "postToPopup('subframe-msg')",
                             "\"done-subframe1\"");

  // Send a postMessage from the popup to window.opener and ensure that it
  // reaches subframe1.  This verifies that the subframe opener information
  // propagated to the popup's RenderFrame.  Wait for subframe1 to send a reply
  // message to the popup.
  EXPECT_TRUE(ExecuteScript(popup, "window.name = 'popup';"));
  PostMessageAndWaitForReply(popup_root, "postToOpener('subframe-msg', '*')",
                             "\"done-popup\"");

  // Second a postMessage from popup2 to window.opener.opener, which should
  // resolve to subframe1.  This tests opener chains of length greater than 1.
  // As before, subframe1 will send a reply to popup2.
  FrameTreeNode* popup2_root =
      static_cast<WebContentsImpl*>(popup2->web_contents())
          ->GetFrameTree()
          ->root();
  EXPECT_TRUE(ExecuteScript(popup2, "window.name = 'popup2';"));
  PostMessageAndWaitForReply(popup2_root,
                             "postToOpenerOfOpener('subframe-msg', '*')",
                             "\"done-popup2\"");

  // Verify the total number of received messages for each subframe:
  //  - 3 for first subframe (two from first popup, one from second popup)
  //  - 2 for popup (both from first subframe)
  //  - 1 for popup2 (reply from first subframe)
  //  - 0 for other frames
  EXPECT_EQ(0, GetReceivedMessages(root));
  EXPECT_EQ(3, GetReceivedMessages(root->child_at(0)));
  EXPECT_EQ(0, GetReceivedMessages(root->child_at(1)));
  EXPECT_EQ(2, GetReceivedMessages(popup_root));
  EXPECT_EQ(1, GetReceivedMessages(popup2_root));
}

// Check that parent.frames[num] references correct sibling frames when the
// parent is remote.  See https://crbug.com/478792.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, IndexedFrameAccess) {
  // Start on a page with three same-site subframes.
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/frame_tree/top.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(3U, root->child_count());
  FrameTreeNode* child0 = root->child_at(0);
  FrameTreeNode* child1 = root->child_at(1);
  FrameTreeNode* child2 = root->child_at(2);

  // Send each of the frames to a different site.  Each new renderer will first
  // create proxies for the parent and two sibling subframes and then create
  // and insert the new RenderFrame into the frame tree.
  GURL b_url(embedded_test_server()->GetURL("b.com", "/post_message.html"));
  GURL c_url(embedded_test_server()->GetURL("c.com", "/post_message.html"));
  GURL d_url(embedded_test_server()->GetURL("d.com", "/post_message.html"));
  NavigateFrameToURL(child0, b_url);
  NavigateFrameToURL(child1, c_url);
  NavigateFrameToURL(child2, d_url);

  EXPECT_EQ(
      " Site A ------------ proxies for B C D\n"
      "   |--Site B ------- proxies for A C D\n"
      "   |--Site C ------- proxies for A B D\n"
      "   +--Site D ------- proxies for A B C\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/\n"
      "      C = http://c.com/\n"
      "      D = http://d.com/",
      DepictFrameTree(root));

  // Check that each subframe sees itself at correct index in parent.frames.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      child0,
      "window.domAutomationController.send(window === parent.frames[0]);",
      &success));
  EXPECT_TRUE(success);

  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      child1,
      "window.domAutomationController.send(window === parent.frames[1]);",
      &success));
  EXPECT_TRUE(success);

  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      child2,
      "window.domAutomationController.send(window === parent.frames[2]);",
      &success));
  EXPECT_TRUE(success);

  // Send a postMessage from B to parent.frames[1], which should go to C, and
  // wait for reply.
  PostMessageAndWaitForReply(child0, "postToSibling('subframe-msg', 1)",
                             "\"done-1-1-name\"");

  // Send a postMessage from C to parent.frames[2], which should go to D, and
  // wait for reply.
  PostMessageAndWaitForReply(child1, "postToSibling('subframe-msg', 2)",
                             "\"done-1-2-name\"");

  // Verify the total number of received messages for each subframe.
  EXPECT_EQ(1, GetReceivedMessages(child0));
  EXPECT_EQ(2, GetReceivedMessages(child1));
  EXPECT_EQ(1, GetReceivedMessages(child2));
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, RFPHDestruction) {
  GURL main_url(embedded_test_server()->GetURL("/site_per_process_main.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  TestNavigationObserver observer(shell()->web_contents());

  // Load cross-site page into iframe.
  FrameTreeNode* child = root->child_at(0);
  GURL url = embedded_test_server()->GetURL("foo.com", "/title2.html");
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    NavigateFrameToURL(root->child_at(0), url);
    deleted_observer.WaitUntilDeleted();
  }
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "        |--Site A -- proxies for B\n"
      "        +--Site A -- proxies for B\n"
      "             +--Site A -- proxies for B\n"
      "Where A = http://127.0.0.1/\n"
      "      B = http://foo.com/",
      DepictFrameTree(root));

  // Load another cross-site page.
  url = embedded_test_server()->GetURL("bar.com", "/title3.html");
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    NavigateIframeToURL(shell()->web_contents(), "test", url);
    deleted_observer.WaitUntilDeleted();
  }
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(url, observer.last_navigation_url());
  EXPECT_EQ(
      " Site A ------------ proxies for C\n"
      "   |--Site C ------- proxies for A\n"
      "   +--Site A ------- proxies for C\n"
      "        |--Site A -- proxies for C\n"
      "        +--Site A -- proxies for C\n"
      "             +--Site A -- proxies for C\n"
      "Where A = http://127.0.0.1/\n"
      "      C = http://bar.com/",
      DepictFrameTree(root));

  // Navigate back to the parent's origin.
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    url = embedded_test_server()->GetURL("/title1.html");
    NavigateFrameToURL(child, url);
    // Wait for the old process to exit, to verify that the proxies go away.
    deleted_observer.WaitUntilDeleted();
  }
  EXPECT_EQ(url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());

  EXPECT_EQ(
      " Site A\n"
      "   |--Site A\n"
      "   +--Site A\n"
      "        |--Site A\n"
      "        +--Site A\n"
      "             +--Site A\n"
      "Where A = http://127.0.0.1/",
      DepictFrameTree(root));
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, OpenPopupWithRemoteParent) {
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/site_per_process_main.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Navigate first child cross-site.
  GURL frame_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  NavigateFrameToURL(root->child_at(0), frame_url);

  // Open a popup from the first child.
  Shell* new_shell =
      OpenPopup(root->child_at(0), GURL(url::kAboutBlankURL), "");
  EXPECT_TRUE(new_shell);

  // Check that the popup's opener is correct on both the browser and renderer
  // sides.
  FrameTreeNode* popup_root =
      static_cast<WebContentsImpl*>(new_shell->web_contents())
          ->GetFrameTree()
          ->root();
  EXPECT_EQ(root->child_at(0), popup_root->opener());

  std::string opener_url;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      popup_root,
      "window.domAutomationController.send(window.opener.location.href);",
      &opener_url));
  EXPECT_EQ(frame_url.spec(), opener_url);

  // Now try the same with a cross-site popup and make sure it ends up in a new
  // process and with a correct opener.
  GURL popup_url(embedded_test_server()->GetURL("c.com", "/title2.html"));
  Shell* cross_site_popup = OpenPopup(root->child_at(0), popup_url, "");
  EXPECT_TRUE(cross_site_popup);

  FrameTreeNode* cross_site_popup_root =
      static_cast<WebContentsImpl*>(cross_site_popup->web_contents())
          ->GetFrameTree()
          ->root();
  EXPECT_EQ(cross_site_popup_root->current_url(), popup_url);

  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            cross_site_popup->web_contents()->GetSiteInstance());
  EXPECT_NE(root->child_at(0)->current_frame_host()->GetSiteInstance(),
            cross_site_popup->web_contents()->GetSiteInstance());

  EXPECT_EQ(root->child_at(0), cross_site_popup_root->opener());

  // Ensure the popup's window.opener points to the right subframe.  Note that
  // we can't check the opener's location as above since it's cross-origin.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      cross_site_popup_root,
      "window.domAutomationController.send("
      "    window.opener === window.opener.top.frames[0]);",
      &success));
  EXPECT_TRUE(success);
}

// Test that cross-process popups can't be navigated to disallowed URLs by
// their opener.  This ensures that proper URL validation is performed when
// RenderFrameProxyHosts are navigated.  See https://crbug.com/595339.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, NavigatePopupToIllegalURL) {
  GURL main_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Open a cross-site popup.
  GURL popup_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  Shell* popup = OpenPopup(shell(), popup_url, "foo");
  EXPECT_TRUE(popup);
  EXPECT_NE(popup->web_contents()->GetSiteInstance(),
            shell()->web_contents()->GetSiteInstance());

  // From the opener, navigate the popup to a file:/// URL.  This should be
  // disallowed and result in an about:blank navigation.
  GURL file_url("file:///");
  NavigateNamedFrame(shell(), file_url, "foo");
  EXPECT_TRUE(WaitForLoadStop(popup->web_contents()));
  EXPECT_EQ(GURL(url::kAboutBlankURL),
            popup->web_contents()->GetLastCommittedURL());

  // Navigate popup back to a cross-site URL.
  EXPECT_TRUE(NavigateToURLFromRenderer(popup, popup_url));
  EXPECT_NE(popup->web_contents()->GetSiteInstance(),
            shell()->web_contents()->GetSiteInstance());

  // Now try the same test with a chrome:// URL.
  GURL chrome_url(std::string(kChromeUIScheme) + "://" +
                  std::string(kChromeUIGpuHost));
  NavigateNamedFrame(shell(), chrome_url, "foo");
  EXPECT_TRUE(WaitForLoadStop(popup->web_contents()));
  EXPECT_EQ(GURL(url::kAboutBlankURL),
            popup->web_contents()->GetLastCommittedURL());
}

// Verify that named frames are discoverable from their opener's ancestors.
// See https://crbug.com/511474.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       DiscoverNamedFrameFromAncestorOfOpener) {
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/site_per_process_main.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Navigate first child cross-site.
  GURL frame_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  NavigateFrameToURL(root->child_at(0), frame_url);

  // Open a popup named "foo" from the first child.
  Shell* foo_shell =
      OpenPopup(root->child_at(0), GURL(url::kAboutBlankURL), "foo");
  EXPECT_TRUE(foo_shell);

  // Check that a proxy was created for the "foo" popup in a.com.
  FrameTreeNode* foo_root =
      static_cast<WebContentsImpl*>(foo_shell->web_contents())
          ->GetFrameTree()
          ->root();
  SiteInstance* site_instance_a = root->current_frame_host()->GetSiteInstance();
  RenderFrameProxyHost* popup_rfph_for_a =
      foo_root->render_manager()->GetRenderFrameProxyHost(site_instance_a);
  EXPECT_TRUE(popup_rfph_for_a);

  // Verify that the main frame can find the "foo" popup by name.  If
  // window.open targets the correct frame, the "foo" popup's current URL
  // should be updated to |named_frame_url|.
  GURL named_frame_url(embedded_test_server()->GetURL("c.com", "/title2.html"));
  NavigateNamedFrame(shell(), named_frame_url, "foo");
  EXPECT_TRUE(WaitForLoadStop(foo_shell->web_contents()));
  EXPECT_EQ(named_frame_url, foo_root->current_url());

  // Navigate the popup cross-site and ensure it's still reachable via
  // window.open from the main frame.
  GURL d_url(embedded_test_server()->GetURL("d.com", "/title3.html"));
  EXPECT_TRUE(NavigateToURLFromRenderer(foo_shell, d_url));
  EXPECT_EQ(d_url, foo_root->current_url());
  NavigateNamedFrame(shell(), named_frame_url, "foo");
  EXPECT_TRUE(WaitForLoadStop(foo_shell->web_contents()));
  EXPECT_EQ(named_frame_url, foo_root->current_url());
}

// Similar to DiscoverNamedFrameFromAncestorOfOpener, but check that if a
// window is created without a name and acquires window.name later, it will
// still be discoverable from its opener's ancestors.  Also, instead of using
// an opener's ancestor, this test uses a popup with same origin as that
// ancestor. See https://crbug.com/511474.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       DiscoverFrameAfterSettingWindowName) {
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/site_per_process_main.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Open a same-site popup from the main frame.
  GURL a_com_url(embedded_test_server()->GetURL("a.com", "/title3.html"));
  Shell* a_com_shell = OpenPopup(root->child_at(0), a_com_url, "");
  EXPECT_TRUE(a_com_shell);

  // Navigate first child on main frame cross-site.
  GURL frame_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  NavigateFrameToURL(root->child_at(0), frame_url);

  // Open an unnamed popup from the first child frame.
  Shell* foo_shell =
      OpenPopup(root->child_at(0), GURL(url::kAboutBlankURL), "");
  EXPECT_TRUE(foo_shell);

  // There should be no proxy created for the "foo" popup in a.com, since
  // there's no way for the two a.com frames to access it yet.
  FrameTreeNode* foo_root =
      static_cast<WebContentsImpl*>(foo_shell->web_contents())
          ->GetFrameTree()
          ->root();
  SiteInstance* site_instance_a = root->current_frame_host()->GetSiteInstance();
  EXPECT_FALSE(
      foo_root->render_manager()->GetRenderFrameProxyHost(site_instance_a));

  // Set window.name in the popup's frame.
  EXPECT_TRUE(ExecuteScript(foo_shell, "window.name = 'foo'"));

  // A proxy for the popup should now exist in a.com.
  EXPECT_TRUE(
      foo_root->render_manager()->GetRenderFrameProxyHost(site_instance_a));

  // Verify that the a.com popup can now find the "foo" popup by name.
  GURL named_frame_url(embedded_test_server()->GetURL("c.com", "/title2.html"));
  NavigateNamedFrame(a_com_shell, named_frame_url, "foo");
  EXPECT_TRUE(WaitForLoadStop(foo_shell->web_contents()));
  EXPECT_EQ(named_frame_url, foo_root->current_url());
}

// Check that frame opener updates work with subframes.  Set up a window with a
// popup and update openers for the popup's main frame and subframe to
// subframes on first window, as follows:
//
//    foo      +---- bar
//    / \      |     / \      .
// bar   foo <-+  bar   foo
//  ^                    |
//  +--------------------+
//
// The sites are carefully set up so that both opener updates are cross-process
// but still allowed by Blink's navigation checks.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, UpdateSubframeOpener) {
  GURL main_url = embedded_test_server()->GetURL(
      "foo.com", "/frame_tree/page_with_two_frames.html");
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_EQ(2U, root->child_count());

  // From the top frame, open a popup and navigate it to a cross-site page with
  // two subframes.
  Shell* popup_shell = OpenPopup(shell(), GURL(url::kAboutBlankURL), "popup");
  EXPECT_TRUE(popup_shell);
  GURL popup_url(embedded_test_server()->GetURL(
      "bar.com", "/frame_tree/page_with_post_message_frames.html"));
  EXPECT_TRUE(NavigateToURLFromRenderer(popup_shell, popup_url));

  FrameTreeNode* popup_root =
      static_cast<WebContentsImpl*>(popup_shell->web_contents())
          ->GetFrameTree()
          ->root();
  EXPECT_EQ(2U, popup_root->child_count());

  // Popup's opener should point to main frame to start with.
  EXPECT_EQ(root, popup_root->opener());

  // Update the popup's opener to the second subframe on the main page (which
  // is same-origin with the top frame, i.e., foo.com).
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(1),
      "window.domAutomationController.send(!!window.open('','popup'));",
      &success));
  EXPECT_TRUE(success);

  // Check that updated opener propagated to the browser process and the
  // popup's bar.com process.
  EXPECT_EQ(root->child_at(1), popup_root->opener());

  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      popup_shell,
      "window.domAutomationController.send("
      "    window.opener === window.opener.parent.frames['frame2']);",
      &success));
  EXPECT_TRUE(success);

  // Now update opener on the popup's second subframe (foo.com) to the main
  // page's first subframe (bar.com).
  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0),
      "window.domAutomationController.send(!!window.open('','subframe2'));",
      &success));
  EXPECT_TRUE(success);

  // Check that updated opener propagated to the browser process and the
  // foo.com process.
  EXPECT_EQ(root->child_at(0), popup_root->child_at(1)->opener());

  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      popup_root->child_at(1),
      "window.domAutomationController.send("
      "    window.opener === window.opener.parent.frames['frame1']);",
      &success));
  EXPECT_TRUE(success);
}

// Check that when a subframe navigates to a new SiteInstance, the new
// SiteInstance will get a proxy for the opener of subframe's parent.  I.e.,
// accessing parent.opener from the subframe should still work after a
// cross-process navigation.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigatingSubframePreservesOpenerInParent) {
  GURL main_url = embedded_test_server()->GetURL("a.com", "/post_message.html");
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Open a popup with a cross-site page that has a subframe.
  GURL popup_url(embedded_test_server()->GetURL(
      "b.com", "/cross_site_iframe_factory.html?b(b)"));
  Shell* popup_shell = OpenPopup(shell(), popup_url, "popup");
  EXPECT_TRUE(popup_shell);
  FrameTreeNode* popup_root =
      static_cast<WebContentsImpl*>(popup_shell->web_contents())
          ->GetFrameTree()
          ->root();
  EXPECT_EQ(1U, popup_root->child_count());

  // Check that the popup's opener is correct in the browser process.
  EXPECT_EQ(root, popup_root->opener());

  // Navigate popup's subframe to another site.
  GURL frame_url(embedded_test_server()->GetURL("c.com", "/post_message.html"));
  NavigateFrameToURL(popup_root->child_at(0), frame_url);

  // Check that the new subframe process still sees correct opener for its
  // parent by sending a postMessage to subframe's parent.opener.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      popup_root->child_at(0),
      "window.domAutomationController.send(!!parent.opener);", &success));
  EXPECT_TRUE(success);

  base::string16 expected_title = base::ASCIIToUTF16("msg");
  TitleWatcher title_watcher(shell()->web_contents(), expected_title);
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      popup_root->child_at(0),
      "window.domAutomationController.send(postToOpenerOfParent('msg','*'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());
}

// Check that if a subframe has an opener, that opener is preserved when the
// subframe navigates cross-site.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, NavigateSubframeWithOpener) {
  GURL main_url(embedded_test_server()->GetURL(
      "foo.com", "/frame_tree/page_with_two_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "Where A = http://foo.com/\n"
      "      B = http://bar.com/",
      DepictFrameTree(root));

  // Update the first (cross-site) subframe's opener to root frame.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root, "window.domAutomationController.send(!!window.open('','frame1'));",
      &success));
  EXPECT_TRUE(success);

  // Check that updated opener propagated to the browser process and subframe's
  // process.
  EXPECT_EQ(root, root->child_at(0)->opener());

  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0),
      "window.domAutomationController.send(window.opener === window.parent);",
      &success));
  EXPECT_TRUE(success);

  // Navigate the subframe with opener to another site.
  GURL frame_url(embedded_test_server()->GetURL("baz.com", "/title1.html"));
  NavigateFrameToURL(root->child_at(0), frame_url);

  // Check that the subframe still sees correct opener in its new process.
  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0),
      "window.domAutomationController.send(window.opener === window.parent);",
      &success));
  EXPECT_TRUE(success);

  // Navigate second subframe to a new site.  Check that the proxy that's
  // created for the first subframe in the new SiteInstance has correct opener.
  GURL frame2_url(embedded_test_server()->GetURL("qux.com", "/title1.html"));
  NavigateFrameToURL(root->child_at(1), frame2_url);

  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(1),
      "window.domAutomationController.send("
      "    parent.frames['frame1'].opener === parent);",
      &success));
  EXPECT_TRUE(success);
}

// Check that if a subframe has an opener, that opener is preserved when a new
// RenderFrameProxy is created for that subframe in another renderer process.
// Similar to NavigateSubframeWithOpener, but this test verifies the subframe
// opener plumbing for mojom::Renderer::CreateFrameProxy(), whereas
// NavigateSubframeWithOpener targets mojom::Renderer::CreateFrame().
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NewRenderFrameProxyPreservesOpener) {
  GURL main_url(
      embedded_test_server()->GetURL("foo.com", "/post_message.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Open a popup with a cross-site page that has two subframes.
  GURL popup_url(embedded_test_server()->GetURL(
      "bar.com", "/frame_tree/page_with_post_message_frames.html"));
  Shell* popup_shell = OpenPopup(shell(), popup_url, "popup");
  EXPECT_TRUE(popup_shell);
  FrameTreeNode* popup_root =
      static_cast<WebContentsImpl*>(popup_shell->web_contents())
          ->GetFrameTree()
          ->root();
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site A ------- proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://bar.com/\n"
      "      B = http://foo.com/",
      DepictFrameTree(popup_root));

  // Update the popup's second subframe's opener to root frame.  This is
  // allowed because that subframe is in the same foo.com SiteInstance as the
  // root frame.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root,
      "window.domAutomationController.send(!!window.open('','subframe2'));",
      &success));
  EXPECT_TRUE(success);

  // Check that the opener update propagated to the browser process and bar.com
  // process.
  EXPECT_EQ(root, popup_root->child_at(1)->opener());
  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      popup_root->child_at(0),
      "window.domAutomationController.send("
      "    parent.frames['subframe2'].opener && "
      "        parent.frames['subframe2'].opener === parent.opener);",
      &success));
  EXPECT_TRUE(success);

  // Navigate the popup's first subframe to another site.
  GURL frame_url(
      embedded_test_server()->GetURL("baz.com", "/post_message.html"));
  NavigateFrameToURL(popup_root->child_at(0), frame_url);

  // Check that the second subframe's opener is still correct in the first
  // subframe's new process.  Verify it both in JS and with a postMessage.
  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      popup_root->child_at(0),
      "window.domAutomationController.send("
      "    parent.frames['subframe2'].opener && "
      "        parent.frames['subframe2'].opener === parent.opener);",
      &success));
  EXPECT_TRUE(success);

  base::string16 expected_title = base::ASCIIToUTF16("msg");
  TitleWatcher title_watcher(shell()->web_contents(), expected_title);
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      popup_root->child_at(0),
      "window.domAutomationController.send("
      "    postToOpenerOfSibling('subframe2', 'msg', '*'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());
}

// Test for https://crbug.com/515302.  Perform two navigations, A->B->A, and
// drop the SwapOut ACK from the A->B navigation, so that the second B->A
// navigation is initiated before the first page receives the SwapOut ACK.
// Ensure that this doesn't crash and that the RVH(A) is not reused in that
// case.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       RenderViewHostIsNotReusedAfterDelayedSwapOutACK) {
  GURL a_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), a_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  RenderFrameHostImpl* rfh = root->current_frame_host();
  RenderViewHostImpl* rvh = rfh->render_view_host();
  int rvh_routing_id = rvh->GetRoutingID();
  int rvh_process_id = rvh->GetProcess()->GetID();
  SiteInstanceImpl* site_instance = rfh->GetSiteInstance();
  RenderFrameDeletedObserver deleted_observer(rfh);

  // Install a BrowserMessageFilter to drop SwapOut ACK messages in A's
  // process.
  scoped_refptr<SwapoutACKMessageFilter> filter = new SwapoutACKMessageFilter();
  rfh->GetProcess()->AddFilter(filter.get());
  rfh->DisableSwapOutTimerForTesting();

  // Navigate to B.  This must wait for DidCommitProvisionalLoad and not
  // DidStopLoading, so that the SwapOut timer doesn't call OnSwappedOut and
  // destroy |rfh| and |rvh| before they are checked in the test.
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  TestFrameNavigationObserver commit_observer(root);
  EXPECT_TRUE(ExecuteScript(shell(), "location = '" + b_url.spec() + "'"));
  commit_observer.WaitForCommit();
  EXPECT_FALSE(deleted_observer.deleted());

  // Since the SwapOut ACK for A->B is dropped, the first page's
  // RenderFrameHost should be pending deletion after the last navigation.
  EXPECT_FALSE(rfh->is_active());

  // Wait for process A to exit so we can reinitialize it cleanly for the next
  // navigation.  Since process A doesn't have any active views, it will
  // initiate shutdown via ChildProcessHostMsg_ShutdownRequest.  After process
  // A shuts down, the |rfh| and |rvh| should get destroyed via
  // OnRenderProcessGone.
  //
  // Not waiting for process shutdown here could lead to the |rvh| being
  // reused, now that there is no notion of pending deletion RenderViewHosts.
  // This would also be fine; however, the race in https://crbug.com/535246
  // still needs to be addressed and tested in that case.
  RenderProcessHostWatcher process_exit_observer(
      rvh->GetProcess(), RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  process_exit_observer.Wait();

  // Verify that the RVH and RFH for A were cleaned up.
  EXPECT_FALSE(root->frame_tree()->GetRenderViewHost(site_instance));
  EXPECT_TRUE(deleted_observer.deleted());

  // Start a navigation back to A, being careful to stay in the same
  // BrowsingInstance, and check that the RenderViewHost wasn't reused.
  TestNavigationObserver navigation_observer(shell()->web_contents());
  shell()->LoadURLForFrame(a_url, std::string(),
                           ui::PageTransitionFromInt(ui::PAGE_TRANSITION_LINK));
  RenderViewHostImpl* pending_rvh =
      root->render_manager()->speculative_frame_host()->render_view_host();
  EXPECT_EQ(site_instance, pending_rvh->GetSiteInstance());
  EXPECT_FALSE(rvh_routing_id == pending_rvh->GetRoutingID() &&
               rvh_process_id == pending_rvh->GetProcess()->GetID());

  // Make sure the last navigation finishes without crashing.
  navigation_observer.Wait();
}

// Test for https://crbug.com/591478, where navigating to a cross-site page with
// a subframe on the old site caused a crash while trying to reuse the old
// RenderViewHost.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ReusePendingDeleteRenderViewHostForSubframe) {
  GURL main_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  std::string script =
      "window.onunload = function() { "
      "  var start = Date.now();"
      "  while (Date.now() - start < 1000);"
      "}";
  EXPECT_TRUE(ExecuteScript(shell(), script));

  // Navigating cross-site with an iframe to the original site shouldn't crash.
  GURL second_url(embedded_test_server()->GetURL(
      "b.com", "/cross_site_iframe_factory.html?b(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), second_url));

  // If the subframe is created while the main frame is pending deletion, then
  // the RVH will be reused.  The main frame should've been swapped with a
  // proxy despite being the last active frame in the progress (see
  // https://crbug.com/568836), and this proxy should also be reused by the new
  // page.
  //
  // TODO(creis, alexmos): Find a way to assert this that isn't flaky. For now,
  // the test is just likely (not certain) to catch regressions by crashing.
}

// Check that when a cross-process frame acquires focus, the old focused frame
// loses focus and fires blur events.  Starting on a page with a cross-site
// subframe, simulate mouse clicks to switch focus from root frame to subframe
// and then back to root frame.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CrossProcessFocusChangeFiresBlurEvents) {
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/page_with_input_field.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  // Focus the main frame's text field.  The return value "input-focus"
  // indicates that the focus event was fired correctly.
  std::string result;
  EXPECT_TRUE(
      ExecuteScriptAndExtractString(shell(), "focusInputField()", &result));
  EXPECT_EQ(result, "input-focus");

  // The main frame should be focused.
  EXPECT_EQ(root, root->frame_tree()->GetFocusedFrame());

  DOMMessageQueue msg_queue;

  // Click on the cross-process subframe.
  SimulateMouseClick(
      root->child_at(0)->current_frame_host()->GetRenderWidgetHost(), 1, 1);

  // Check that the main frame lost focus and fired blur event on the input
  // text field.
  std::string status;
  while (msg_queue.WaitForMessage(&status)) {
    if (status == "\"input-blur\"")
      break;
  }

  // The subframe should now be focused.
  EXPECT_EQ(root->child_at(0), root->frame_tree()->GetFocusedFrame());

  // Click on the root frame.
  SimulateMouseClick(shell()->web_contents()->GetRenderViewHost()->GetWidget(),
                     1, 1);

  // Check that the subframe lost focus and fired blur event on its
  // document's body.
  while (msg_queue.WaitForMessage(&status)) {
    if (status == "\"document-blur\"")
      break;
  }

  // The root frame should be focused again.
  EXPECT_EQ(root, root->frame_tree()->GetFocusedFrame());
}

// Check that when a cross-process subframe is focused, its parent's
// document.activeElement correctly returns the corresponding <iframe> element.
// The test sets up an A-embed-B-embed-C page and shifts focus A->B->A->C,
// checking document.activeElement after each change.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, DocumentActiveElement) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b(c))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   +--Site B ------- proxies for A C\n"
      "        +--Site C -- proxies for A B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/\n"
      "      C = http://c.com/",
      DepictFrameTree(root));

  FrameTreeNode* child = root->child_at(0);
  FrameTreeNode* grandchild = root->child_at(0)->child_at(0);

  // The main frame should be focused to start with.
  EXPECT_EQ(root, root->frame_tree()->GetFocusedFrame());

  // Focus the b.com frame.
  FocusFrame(child);
  EXPECT_EQ(child, root->frame_tree()->GetFocusedFrame());

  // Helper function to check a property of document.activeElement in the
  // specified frame.
  auto verify_active_element_property = [](RenderFrameHost* rfh,
                                           const std::string& property,
                                           const std::string& expected_value) {
    std::string script = base::StringPrintf(
        "window.domAutomationController.send(document.activeElement.%s);",
        property.c_str());
    std::string result;
    EXPECT_TRUE(ExecuteScriptAndExtractString(rfh, script, &result));
    EXPECT_EQ(expected_value, base::ToLowerASCII(result));
  };

  // Verify that document.activeElement on main frame points to the <iframe>
  // element for the b.com frame.
  RenderFrameHost* root_rfh = root->current_frame_host();
  verify_active_element_property(root_rfh, "tagName", "iframe");
  verify_active_element_property(root_rfh, "src", child->current_url().spec());

  // Focus the a.com main frame again.
  FocusFrame(root);
  EXPECT_EQ(root, root->frame_tree()->GetFocusedFrame());

  // Main frame document's <body> should now be the active element.
  verify_active_element_property(root_rfh, "tagName", "body");

  // Now shift focus from main frame to c.com frame.
  FocusFrame(grandchild);

  // Check document.activeElement in main frame.  It should still point to
  // <iframe> for the b.com frame, since Blink computes the focused iframe
  // element by walking the parent chain of the focused frame until it hits the
  // current frame.  This logic should still work with remote frames.
  verify_active_element_property(root_rfh, "tagName", "iframe");
  verify_active_element_property(root_rfh, "src", child->current_url().spec());

  // Check document.activeElement in b.com subframe.  It should point to
  // <iframe> for the c.com frame.  This is a tricky case where B needs to find
  // out that focus changed from one remote frame to another (A to C).
  RenderFrameHost* child_rfh = child->current_frame_host();
  verify_active_element_property(child_rfh, "tagName", "iframe");
  verify_active_element_property(child_rfh, "src",
                                 grandchild->current_url().spec());
}

// Check that window.focus works for cross-process subframes.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, SubframeWindowFocus) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,c)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   |--Site B ------- proxies for A C\n"
      "   +--Site C ------- proxies for A B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/\n"
      "      C = http://c.com/",
      DepictFrameTree(root));

  FrameTreeNode* child1 = root->child_at(0);
  FrameTreeNode* child2 = root->child_at(1);

  // The main frame should be focused to start with.
  EXPECT_EQ(root, root->frame_tree()->GetFocusedFrame());

  DOMMessageQueue msg_queue;

  // Register focus and blur events that will send messages when each frame's
  // window gets or loses focus.
  const char kSetupFocusEvents[] =
      "window.addEventListener('focus', function() {"
      "  domAutomationController.send('%s-got-focus');"
      "});"
      "window.addEventListener('blur', function() {"
      "  domAutomationController.send('%s-lost-focus');"
      "});";
  std::string script = base::StringPrintf(kSetupFocusEvents, "main", "main");
  ExecuteScriptAsync(shell(), script);
  script = base::StringPrintf(kSetupFocusEvents, "child1", "child1");
  ExecuteScriptAsync(child1, script);
  script = base::StringPrintf(kSetupFocusEvents, "child2", "child2");
  ExecuteScriptAsync(child2, script);

  // Execute window.focus on the B subframe from the A main frame.
  ExecuteScriptAsync(root, "frames[0].focus()");

  // Helper to wait for two specified messages to arrive on the specified
  // DOMMessageQueue, assuming that the two messages can arrive in any order.
  auto wait_for_two_messages = [](DOMMessageQueue* msg_queue,
                                  const std::string& msg1,
                                  const std::string& msg2) {
    bool msg1_received = false;
    bool msg2_received = false;
    std::string status;
    while (msg_queue->WaitForMessage(&status)) {
      if (status == msg1)
        msg1_received = true;
      if (status == msg2)
        msg2_received = true;
      if (msg1_received && msg2_received)
        break;
    }
  };

  // Process A should fire a blur event, and process B should fire a focus
  // event.  Wait for both events.
  wait_for_two_messages(&msg_queue, "\"main-lost-focus\"",
                        "\"child1-got-focus\"");

  // The B subframe should now be focused in the browser process.
  EXPECT_EQ(child1, root->frame_tree()->GetFocusedFrame());

  // Now, execute window.focus on the C subframe from A main frame.  This
  // checks that we can shift focus from one remote frame to another.
  ExecuteScriptAsync(root, "frames[1].focus()");

  // Wait for the two subframes (B and C) to fire blur and focus events.
  wait_for_two_messages(&msg_queue, "\"child1-lost-focus\"",
                        "\"child2-got-focus\"");

  // The C subframe should now be focused.
  EXPECT_EQ(child2, root->frame_tree()->GetFocusedFrame());

  // window.focus the main frame from the C subframe.
  ExecuteScriptAsync(child2, "parent.focus()");

  // Wait for the C subframe to blur and main frame to focus.
  wait_for_two_messages(&msg_queue, "\"child2-lost-focus\"",
                        "\"main-got-focus\"");

  // The main frame should now be focused.
  EXPECT_EQ(root, root->frame_tree()->GetFocusedFrame());
}

// Check that when a subframe has focus, and another subframe navigates
// cross-site to a new renderer process, this doesn't reset the focused frame
// to the main frame.  See https://crbug.com/802156.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       SubframeFocusNotLostWhenAnotherFrameNavigatesCrossSite) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child1 = root->child_at(0);
  FrameTreeNode* child2 = root->child_at(1);

  // The main frame should be focused to start with.
  EXPECT_EQ(root, root->frame_tree()->GetFocusedFrame());

  // Add an <input> element to the first subframe.
  ExecuteScriptAsync(
      child1, "document.body.appendChild(document.createElement('input'))");

  // Focus the first subframe using window.focus().
  FrameFocusedObserver focus_observer(child1->current_frame_host());
  ExecuteScriptAsync(root, "frames[0].focus()");
  focus_observer.Wait();
  EXPECT_EQ(child1, root->frame_tree()->GetFocusedFrame());

  // Give focus to the <input> element in the first subframe.
  ExecuteScriptAsync(child1, "document.querySelector('input').focus()");

  // Now, navigate second subframe cross-site.  Ensure that this won't change
  // the focused frame.
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  NavigateFrameToURL(child2, b_url);
  // This is needed because the incorrect focused frame change as in
  // https://crbug.com/802156 requires an additional post-commit IPC roundtrip.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(child1, root->frame_tree()->GetFocusedFrame());

  // The <input> in first subframe should still be the activeElement.
  std::string activeTag;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      child1, "domAutomationController.send(document.activeElement.tagName)",
      &activeTag));
  EXPECT_EQ("input", base::ToLowerASCII(activeTag));
}

// Tests that we are using the correct RenderFrameProxy when navigating an
// opener window.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, OpenerSetLocation) {
  // Navigate the main window.
  GURL main_url(embedded_test_server()->GetURL("/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  EXPECT_EQ(shell()->web_contents()->GetLastCommittedURL(), main_url);

  // Load cross-site page into a new window.
  GURL cross_url = embedded_test_server()->GetURL("foo.com", "/title1.html");
  Shell* popup = OpenPopup(shell(), cross_url, "");
  EXPECT_EQ(popup->web_contents()->GetLastCommittedURL(), cross_url);

  // Use new window to navigate main window.
  std::string script =
      "window.opener.location.href = '" + cross_url.spec() + "'";
  EXPECT_TRUE(ExecuteScript(popup, script));
  EXPECT_TRUE(WaitForLoadStop(shell()->web_contents()));
  EXPECT_EQ(shell()->web_contents()->GetLastCommittedURL(), cross_url);
}

// Test for https://crbug.com/526304, where a parent frame executes a
// remote-to-local navigation on a child frame and immediately removes the same
// child frame.  This test exercises the path where the detach happens before
// the provisional local frame is created.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateProxyAndDetachBeforeProvisionalFrameCreation) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  WebContents* contents = shell()->web_contents();
  FrameTreeNode* root =
      static_cast<WebContentsImpl*>(contents)->GetFrameTree()->root();
  EXPECT_EQ(2U, root->child_count());

  // Navigate the first child frame to 'about:blank' (which is a
  // remote-to-local transition), and then detach it.
  FrameDeletedObserver observer(root->child_at(0)->current_frame_host());
  std::string script =
      "var f = document.querySelector('iframe');"
      "f.contentWindow.location.href = 'about:blank';"
      "setTimeout(function() { document.body.removeChild(f); }, 0);";
  EXPECT_TRUE(ExecuteScript(root, script));
  observer.Wait();
  EXPECT_EQ(1U, root->child_count());

  // Make sure the main frame renderer does not crash and ignores the
  // navigation to the frame that's already been deleted.
  int child_count = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root, "domAutomationController.send(frames.length)", &child_count));
  EXPECT_EQ(1, child_count);
}

// Test for a variation of https://crbug.com/526304, where a child frame does a
// remote-to-local navigation, and the parent frame removes that child frame
// after the provisional local frame is created and starts to navigate, but
// before it commits.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateProxyAndDetachBeforeCommit) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  WebContents* contents = shell()->web_contents();
  FrameTreeNode* root =
      static_cast<WebContentsImpl*>(contents)->GetFrameTree()->root();
  EXPECT_EQ(2U, root->child_count());
  FrameTreeNode* child = root->child_at(0);

  // Start a remote-to-local navigation for the child, but don't wait for
  // commit.
  GURL same_site_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  NavigationController::LoadURLParams params(same_site_url);
  params.transition_type = ui::PAGE_TRANSITION_LINK;
  params.frame_tree_node_id = child->frame_tree_node_id();
  child->navigator()->GetController()->LoadURLWithParams(params);

  // Tell parent to remove the first child.  This should happen after the
  // previous navigation starts but before it commits.
  FrameDeletedObserver observer(child->current_frame_host());
  EXPECT_TRUE(ExecuteScript(
      root, "document.body.removeChild(document.querySelector('iframe'));"));
  observer.Wait();
  EXPECT_EQ(1U, root->child_count());

  // Make sure the a.com renderer does not crash.
  int child_count = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root, "domAutomationController.send(frames.length)", &child_count));
  EXPECT_EQ(1, child_count);
}

// Similar to NavigateProxyAndDetachBeforeCommit, but uses a synchronous
// navigation to about:blank and the parent removes the child frame in a load
// event handler for the subframe.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, NavigateAboutBlankAndDetach) {
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/remove_frame_on_load.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  WebContents* contents = shell()->web_contents();
  FrameTreeNode* root =
      static_cast<WebContentsImpl*>(contents)->GetFrameTree()->root();
  EXPECT_EQ(1U, root->child_count());
  FrameTreeNode* child = root->child_at(0);
  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());

  // Navigate the child frame to "about:blank" from the parent document and
  // wait for it to be removed.
  FrameDeletedObserver observer(child->current_frame_host());
  EXPECT_TRUE(ExecuteScript(
      root, base::StringPrintf("f.src = '%s'", url::kAboutBlankURL)));
  observer.Wait();

  // Make sure the a.com renderer does not crash and the frame is removed.
  int child_count = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root, "domAutomationController.send(frames.length)", &child_count));
  EXPECT_EQ(0, child_count);
}

// Test for https://crbug.com/568670.  In A-embed-B, simultaneously have B
// create a new (local) child frame, and have A detach B's proxy.  The child
// frame creation sends an IPC to create a new proxy in A's process, and if
// that IPC arrives after the detach, the new frame's parent (a proxy) won't be
// available, and this shouldn't cause RenderFrameProxy::CreateFrameProxy to
// crash.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       RaceBetweenCreateChildFrameAndDetachParentProxy) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  WebContents* contents = shell()->web_contents();
  FrameTreeNode* root =
      static_cast<WebContentsImpl*>(contents)->GetFrameTree()->root();

  // Simulate subframe B creating a new child frame in parallel to main frame A
  // detaching subframe B.  We can't use ExecuteScript in both A and B to do
  // this simultaneously, as that won't guarantee the timing that we want.
  // Instead, tell A to detach B and then send a fake proxy creation IPC to A
  // that would've come from create-child-frame code in B.  Prepare parameters
  // for that IPC ahead of the detach, while B's FrameTreeNode still exists.
  SiteInstance* site_instance_a = root->current_frame_host()->GetSiteInstance();
  RenderProcessHost* process_a =
      root->render_manager()->current_frame_host()->GetProcess();
  int new_routing_id = process_a->GetNextRoutingID();
  int view_routing_id =
      root->frame_tree()->GetRenderViewHost(site_instance_a)->GetRoutingID();
  int parent_routing_id =
      root->child_at(0)->render_manager()->GetProxyToParent()->GetRoutingID();

  // Tell main frame A to delete its subframe B.
  FrameDeletedObserver observer(root->child_at(0)->current_frame_host());
  EXPECT_TRUE(ExecuteScript(
      root, "document.body.removeChild(document.querySelector('iframe'));"));

  // Send the message to create a proxy for B's new child frame in A.  This
  // used to crash, as parent_routing_id refers to a proxy that doesn't exist
  // anymore.
  process_a->GetRendererInterface()->CreateFrameProxy(
      new_routing_id, view_routing_id, MSG_ROUTING_NONE, parent_routing_id,
      FrameReplicationState(), base::UnguessableToken::Create());

  // Ensure the subframe is detached in the browser process.
  observer.Wait();
  EXPECT_EQ(0U, root->child_count());

  // Make sure process A did not crash.
  int child_count = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root, "domAutomationController.send(frames.length)", &child_count));
  EXPECT_EQ(0, child_count);
}

// This test ensures that the RenderFrame isn't leaked in the renderer process
// if a pending cross-process navigation is cancelled. The test works by trying
// to create a new RenderFrame with the same routing id. If there is an
// entry with the same routing ID, a CHECK is hit and the process crashes.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       SubframePendingAndBackToSameSiteInstance) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Capture the FrameTreeNode this test will be navigating.
  FrameTreeNode* node = web_contents()->GetFrameTree()->root()->child_at(0);
  EXPECT_TRUE(node);
  EXPECT_NE(node->current_frame_host()->GetSiteInstance(),
            node->parent()->current_frame_host()->GetSiteInstance());

  // Navigate to the site of the parent, but to a page that will not commit.
  GURL same_site_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  NavigationStallDelegate stall_delegate(same_site_url);
  ResourceDispatcherHost::Get()->SetDelegate(&stall_delegate);
  {
    NavigationController::LoadURLParams params(same_site_url);
    params.transition_type = ui::PAGE_TRANSITION_LINK;
    params.frame_tree_node_id = node->frame_tree_node_id();
    node->navigator()->GetController()->LoadURLWithParams(params);
  }

  // Grab the routing id of the pending RenderFrameHost and set up a process
  // observer to ensure there is no crash when a new RenderFrame creation is
  // attempted.
  RenderProcessHost* process =
      node->render_manager()->speculative_frame_host()->GetProcess();
  RenderProcessHostWatcher watcher(
      process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  int frame_routing_id =
      node->render_manager()->speculative_frame_host()->GetRoutingID();
  int proxy_routing_id =
      node->render_manager()->GetProxyToParent()->GetRoutingID();

  // Now go to c.com so the navigation to a.com is cancelled and send an IPC
  // to create a new RenderFrame with the routing id of the previously pending
  // one.
  NavigateFrameToURL(node,
                     embedded_test_server()->GetURL("c.com", "/title2.html"));
  {
    mojom::CreateFrameParamsPtr params = mojom::CreateFrameParams::New();
    params->routing_id = frame_routing_id;
    mojo::MakeRequest(&params->interface_provider);
    params->proxy_routing_id = proxy_routing_id;
    params->opener_routing_id = IPC::mojom::kRoutingIdNone;
    params->parent_routing_id =
        shell()->web_contents()->GetMainFrame()->GetRoutingID();
    params->previous_sibling_routing_id = IPC::mojom::kRoutingIdNone;
    params->widget_params = mojom::CreateFrameWidgetParams::New();
    params->widget_params->routing_id = IPC::mojom::kRoutingIdNone;
    params->widget_params->hidden = true;
    params->replication_state.name = "name";
    params->replication_state.unique_name = "name";
    params->devtools_frame_token = base::UnguessableToken::Create();
    process->GetRendererInterface()->CreateFrame(std::move(params));
  }

  // The test must wait for the process to exit, but if there is no leak, the
  // RenderFrame will be properly created and there will be no crash.
  // Therefore, navigate the main frame to completely different site, which
  // will cause the original process to exit cleanly.
  EXPECT_TRUE(NavigateToURL(
      shell(), embedded_test_server()->GetURL("d.com", "/title3.html")));
  watcher.Wait();
  EXPECT_TRUE(watcher.did_exit_normally());

  ResourceDispatcherHost::Get()->SetDelegate(nullptr);
}

// This test ensures that the RenderFrame isn't leaked in the renderer process
// when a remote parent detaches a child frame. The test works by trying
// to create a new RenderFrame with the same routing id. If there is an
// entry with the same routing ID, a CHECK is hit and the process crashes.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, ParentDetachRemoteChild) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  WebContentsImpl* contents = web_contents();
  EXPECT_EQ(2U, contents->GetFrameTree()->root()->child_count());

  // Capture the FrameTreeNode this test will be navigating.
  FrameTreeNode* node = contents->GetFrameTree()->root()->child_at(0);
  EXPECT_TRUE(node);
  EXPECT_NE(node->current_frame_host()->GetSiteInstance(),
            node->parent()->current_frame_host()->GetSiteInstance());

  // Grab the routing id of the first child RenderFrameHost and set up a process
  // observer to ensure there is no crash when a new RenderFrame creation is
  // attempted.
  RenderProcessHost* process = node->current_frame_host()->GetProcess();
  RenderProcessHostWatcher watcher(
      process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  int frame_routing_id = node->current_frame_host()->GetRoutingID();
  int widget_routing_id =
      node->current_frame_host()->GetRenderWidgetHost()->GetRoutingID();
  int parent_routing_id =
      node->parent()->render_manager()->GetRoutingIdForSiteInstance(
          node->current_frame_host()->GetSiteInstance());

  // Have the parent frame remove the child frame from its DOM. This should
  // result in the child RenderFrame being deleted in the remote process.
  EXPECT_TRUE(ExecuteScript(contents,
                            "document.body.removeChild("
                            "document.querySelectorAll('iframe')[0])"));
  EXPECT_EQ(1U, contents->GetFrameTree()->root()->child_count());

  {
    mojom::CreateFrameParamsPtr params = mojom::CreateFrameParams::New();
    params->routing_id = frame_routing_id;
    mojo::MakeRequest(&params->interface_provider);
    params->proxy_routing_id = IPC::mojom::kRoutingIdNone;
    params->opener_routing_id = IPC::mojom::kRoutingIdNone;
    params->parent_routing_id = parent_routing_id;
    params->previous_sibling_routing_id = IPC::mojom::kRoutingIdNone;
    params->widget_params = mojom::CreateFrameWidgetParams::New();
    params->widget_params->routing_id = widget_routing_id;
    params->widget_params->hidden = true;
    params->replication_state.name = "name";
    params->replication_state.unique_name = "name";
    params->devtools_frame_token = base::UnguessableToken::Create();
    process->GetRendererInterface()->CreateFrame(std::move(params));
  }

  // The test must wait for the process to exit, but if there is no leak, the
  // RenderFrame will be properly created and there will be no crash.
  // Therefore, navigate the remaining subframe to completely different site,
  // which will cause the original process to exit cleanly.
  NavigateFrameToURL(contents->GetFrameTree()->root()->child_at(0),
                     embedded_test_server()->GetURL("d.com", "/title3.html"));
  watcher.Wait();
  EXPECT_TRUE(watcher.did_exit_normally());
}

// TODO(ekaramad): Move this test out of this file when addressing
// https://crbug.com/754726.
// This test verifies that RFHImpl::ForEachImmediateLocalRoot works as expected.
// The frame tree used in the test is:
//                                A0
//                            /    |    \
//                          A1     B1    A2
//                         /  \    |    /  \
//                        B2   A3  B3  A4   C2
//                       /    /   / \    \
//                      D1   D2  C3  C4  C5
//
// As an example, the expected set of immediate local roots for the root node A0
// should be {B1, B2, C2, D2, C5}. Note that the order is compatible with that
// of a BFS traversal from root node A0.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, FindImmediateLocalRoots) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com",
      "/cross_site_iframe_factory.html?a(a(b(d),a(d)),b(b(c,c)),a(a(c),c))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Each entry is of the frame "LABEL:ILR1ILR2..." where ILR stands for
  // immediate local root.
  std::string immediate_local_roots[] = {
      "A0:B1B2C2D2C5", "A1:B2D2", "B1:C3C4", "A2:C2C5", "B2:D1",
      "A3:D2",         "B3:C3C4", "A4:C5",   "C2:",     "D1:",
      "D2:",           "C3:",     "C4:",     "C5:"};

  std::map<RenderFrameHostImpl*, std::string>
      frame_to_immediate_local_roots_map;
  std::map<RenderFrameHostImpl*, std::string> frame_to_label_map;
  size_t index = 0;
  // Map each RenderFrameHostImpl to its label and set of immediate local roots.
  for (auto* ftn : web_contents()->GetFrameTree()->Nodes()) {
    std::string roots = immediate_local_roots[index++];
    frame_to_immediate_local_roots_map[ftn->current_frame_host()] = roots;
    frame_to_label_map[ftn->current_frame_host()] = roots.substr(0, 2);
  }

  // For each frame in the tree, verify that ForEachImmediateLocalRoot properly
  // visits each and only each immediate local root in a BFS traversal order.
  for (auto* ftn : web_contents()->GetFrameTree()->Nodes()) {
    RenderFrameHostImpl* current_frame_host = ftn->current_frame_host();
    std::list<RenderFrameHostImpl*> frame_list;
    current_frame_host->ForEachImmediateLocalRoot(
        base::Bind([](std::list<RenderFrameHostImpl*>* ilr_list,
                      RenderFrameHostImpl* rfh) { ilr_list->push_back(rfh); },
                   &frame_list));

    std::string result = frame_to_label_map[current_frame_host];
    result.append(":");
    for (auto* ilr_ptr : frame_list)
      result.append(frame_to_label_map[ilr_ptr]);
    EXPECT_EQ(frame_to_immediate_local_roots_map[current_frame_host], result);
  }
}

// This test verifies that changing the CSS visibility of a cross-origin
// <iframe> is forwarded to its corresponding RenderWidgetHost and all other
// RenderWidgetHosts corresponding to the nested cross-origin frame.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, CSSVisibilityChanged) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b(b(c(d(d(a))))))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Find all child RenderWidgetHosts.
  std::vector<RenderWidgetHostImpl*> child_widget_hosts;
  FrameTreeNode* first_cross_process_child =
      web_contents()->GetFrameTree()->root()->child_at(0);
  for (auto* ftn : web_contents()->GetFrameTree()->SubtreeNodes(
           first_cross_process_child)) {
    RenderFrameHostImpl* frame_host = ftn->current_frame_host();
    if (!frame_host->is_local_root())
      continue;

    child_widget_hosts.push_back(frame_host->GetRenderWidgetHost());
  }

  // Ignoring the root, there is exactly 4 local roots and hence 5
  // RenderWidgetHosts on the page.
  EXPECT_EQ(4U, child_widget_hosts.size());

  // Initially all the RenderWidgetHosts should be visible.
  for (size_t index = 0; index < child_widget_hosts.size(); ++index) {
    EXPECT_FALSE(child_widget_hosts[index]->is_hidden())
        << "The RWH at distance " << index + 1U
        << " from root RWH should not be hidden.";
  }

  std::string show_script =
      "document.querySelector('iframe').style.visibility = 'visible';";
  std::string hide_script =
      "document.querySelector('iframe').style.visibility = 'hidden';";

  // Define observers for notifications about hiding child RenderWidgetHosts.
  std::vector<std::unique_ptr<RenderWidgetHostVisibilityObserver>>
      hide_widget_host_observers(child_widget_hosts.size());
  for (size_t index = 0U; index < child_widget_hosts.size(); ++index) {
    hide_widget_host_observers[index].reset(
        new RenderWidgetHostVisibilityObserver(child_widget_hosts[index],
                                               false));
  }

  EXPECT_TRUE(ExecuteScript(shell(), hide_script));
  for (size_t index = 0U; index < child_widget_hosts.size(); ++index) {
    EXPECT_TRUE(hide_widget_host_observers[index]->WaitUntilSatisfied())
        << "Expected RenderWidgetHost at distance " << index + 1U
        << " from root RenderWidgetHost to become hidden.";
  }

  // Define observers for notifications about showing child RenderWidgetHosts.
  std::vector<std::unique_ptr<RenderWidgetHostVisibilityObserver>>
      show_widget_host_observers(child_widget_hosts.size());
  for (size_t index = 0U; index < child_widget_hosts.size(); ++index) {
    show_widget_host_observers[index].reset(
        new RenderWidgetHostVisibilityObserver(child_widget_hosts[index],
                                               true));
  }

  EXPECT_TRUE(ExecuteScript(shell(), show_script));
  for (size_t index = 0U; index < child_widget_hosts.size(); ++index) {
    EXPECT_TRUE(show_widget_host_observers[index]->WaitUntilSatisfied())
        << "Expected RenderWidgetHost at distance " << index + 1U
        << " from root RenderWidgetHost to become shown.";
  }
}

// A class which counts the number of times a RenderWidgetHostViewChildFrame
// swaps compositor frames.
class ChildFrameCompositorFrameSwapCounter {
 public:
  explicit ChildFrameCompositorFrameSwapCounter(
      RenderWidgetHostViewChildFrame* view)
      : view_(view), weak_factory_(this) {
    RegisterCallback();
  }

  ~ChildFrameCompositorFrameSwapCounter() {}

  // Wait until at least |count| new frames are swapped.
  void WaitForNewFrames(size_t count) {
    while (counter_ < count) {
      base::RunLoop loop;
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE, loop.QuitClosure(), TestTimeouts::tiny_timeout());
      loop.Run();
    }
  }

  void ResetCounter() { counter_ = 0; }
  size_t GetCount() const { return counter_; }

 private:
  void RegisterCallback() {
    view_->RegisterFrameSwappedCallback(
        base::BindOnce(&ChildFrameCompositorFrameSwapCounter::OnFrameSwapped,
                       weak_factory_.GetWeakPtr()));
  }

  void OnFrameSwapped() {
    counter_++;

    // Register a new callback as the old one is released now.
    RegisterCallback();
  }

  size_t counter_ = 0;

 private:
  RenderWidgetHostViewChildFrame* view_;
  base::WeakPtrFactory<ChildFrameCompositorFrameSwapCounter> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ChildFrameCompositorFrameSwapCounter);
};

// This test verifies that hiding an OOPIF in CSS will stop generating
// compositor frames for the OOPIF and any nested OOPIFs inside it. This holds
// even when the whole page is shown.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       HiddenOOPIFWillNotGenerateCompositorFrames) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_two_frames.html"));
  ASSERT_TRUE(NavigateToURL(shell(), main_url));
  ASSERT_EQ(shell()->web_contents()->GetLastCommittedURL(), main_url);

  GURL cross_site_url_b =
      embedded_test_server()->GetURL("b.com", "/counter.html");

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  NavigateFrameToURL(root->child_at(0), cross_site_url_b);

  NavigateFrameToURL(root->child_at(1), cross_site_url_b);

  // Now inject code in the first frame to create a nested OOPIF.
  RenderFrameHostCreatedObserver new_frame_created_observer(
      shell()->web_contents(), 1);
  ASSERT_TRUE(ExecuteScript(
      root->child_at(0)->current_frame_host(),
      "document.body.appendChild(document.createElement('iframe'));"));
  new_frame_created_observer.Wait();

  GURL cross_site_url_a =
      embedded_test_server()->GetURL("a.com", "/counter.html");

  // Navigate the nested frame.
  TestFrameNavigationObserver observer(root->child_at(0)->child_at(0));
  ASSERT_TRUE(ExecuteScript(
      root->child_at(0)->current_frame_host(),
      base::StringPrintf("document.querySelector('iframe').src = '%s';",
                         cross_site_url_a.spec().c_str())));
  observer.Wait();

  RenderWidgetHostViewChildFrame* first_child_view =
      static_cast<RenderWidgetHostViewChildFrame*>(
          root->child_at(0)->current_frame_host()->GetView());
  RenderWidgetHostViewChildFrame* second_child_view =
      static_cast<RenderWidgetHostViewChildFrame*>(
          root->child_at(1)->current_frame_host()->GetView());
  RenderWidgetHostViewChildFrame* nested_child_view =
      static_cast<RenderWidgetHostViewChildFrame*>(
          root->child_at(0)->child_at(0)->current_frame_host()->GetView());

  ChildFrameCompositorFrameSwapCounter first_counter(first_child_view);
  ChildFrameCompositorFrameSwapCounter second_counter(second_child_view);
  ChildFrameCompositorFrameSwapCounter third_counter(nested_child_view);

  const size_t kFrameCountLimit = 20u;

  // Wait for a minimum number of compositor frames for the second frame.
  second_counter.WaitForNewFrames(kFrameCountLimit);
  ASSERT_LE(kFrameCountLimit, second_counter.GetCount());

  // Now make sure all frames have roughly the counter value in the sense that
  // no counter value is more than twice any other.
  float ratio = static_cast<float>(first_counter.GetCount()) /
                static_cast<float>(second_counter.GetCount());
  EXPECT_GT(2.5f, ratio + 1 / ratio) << "Ratio is: " << ratio;

  ratio = static_cast<float>(first_counter.GetCount()) /
          static_cast<float>(third_counter.GetCount());
  EXPECT_GT(2.5f, ratio + 1 / ratio) << "Ratio is: " << ratio;

  // Make sure all views can become visible.
  EXPECT_TRUE(first_child_view->CanBecomeVisible());
  EXPECT_TRUE(second_child_view->CanBecomeVisible());
  EXPECT_TRUE(nested_child_view->CanBecomeVisible());

  // Hide the first frame and wait for the notification to be posted by its
  // RenderWidgetHost.
  RenderWidgetHostVisibilityObserver hide_observer(
      root->child_at(0)->current_frame_host()->GetRenderWidgetHost(), false);

  // Hide the first frame.
  ASSERT_TRUE(ExecuteScript(
      shell(),
      "document.getElementsByName('frame1')[0].style.visibility = 'hidden'"));
  ASSERT_TRUE(hide_observer.WaitUntilSatisfied());
  EXPECT_TRUE(first_child_view->FrameConnectorForTesting()->IsHidden());

  // Verify that only the second view can become visible now.
  EXPECT_FALSE(first_child_view->CanBecomeVisible());
  EXPECT_TRUE(second_child_view->CanBecomeVisible());
  EXPECT_FALSE(nested_child_view->CanBecomeVisible());

  // Now hide and show the WebContents (to simulate a tab switch).
  shell()->web_contents()->WasHidden();
  shell()->web_contents()->WasShown();

  first_counter.ResetCounter();
  second_counter.ResetCounter();
  third_counter.ResetCounter();

  // We expect the second counter to keep running.
  second_counter.WaitForNewFrames(kFrameCountLimit);
  ASSERT_LT(kFrameCountLimit, second_counter.GetCount() + 1u);

  // Verify that the counter for other two frames did not count much.
  ratio = static_cast<float>(first_counter.GetCount()) /
          static_cast<float>(second_counter.GetCount());
  EXPECT_GT(0.5f, ratio) << "Ratio is: " << ratio;

  ratio = static_cast<float>(third_counter.GetCount()) /
          static_cast<float>(second_counter.GetCount());
  EXPECT_GT(0.5f, ratio) << "Ratio is: " << ratio;
}

// This test verifies that navigating a hidden OOPIF to cross-origin will not
// lead to creating compositor frames for the new OOPIF renderer.
IN_PROC_BROWSER_TEST_F(
    SitePerProcessBrowserTest,
    HiddenOOPIFWillNotGenerateCompositorFramesAfterNavigation) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_two_frames.html"));
  ASSERT_TRUE(NavigateToURL(shell(), main_url));
  ASSERT_EQ(shell()->web_contents()->GetLastCommittedURL(), main_url);

  GURL cross_site_url_b =
      embedded_test_server()->GetURL("b.com", "/counter.html");

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  NavigateFrameToURL(root->child_at(0), cross_site_url_b);

  NavigateFrameToURL(root->child_at(1), cross_site_url_b);

  // Hide the first frame and wait for the notification to be posted by its
  // RenderWidgetHost.
  RenderWidgetHostVisibilityObserver hide_observer(
      root->child_at(0)->current_frame_host()->GetRenderWidgetHost(), false);

  // Hide the first frame.
  ASSERT_TRUE(ExecuteScript(
      shell(),
      "document.getElementsByName('frame1')[0].style.visibility = 'hidden'"));
  ASSERT_TRUE(hide_observer.WaitUntilSatisfied());

  // Now navigate the first frame to another OOPIF process.
  TestFrameNavigationObserver navigation_observer(
      root->child_at(0)->current_frame_host());
  GURL cross_site_url_c =
      embedded_test_server()->GetURL("c.com", "/counter.html");
  ASSERT_TRUE(ExecuteScript(
      web_contents(),
      base::StringPrintf("document.getElementsByName('frame1')[0].src = '%s';",
                         cross_site_url_c.spec().c_str())));
  navigation_observer.Wait();

  // Now investigate compositor frame creation.
  RenderWidgetHostViewChildFrame* first_child_view =
      static_cast<RenderWidgetHostViewChildFrame*>(
          root->child_at(0)->current_frame_host()->GetView());

  RenderWidgetHostViewChildFrame* second_child_view =
      static_cast<RenderWidgetHostViewChildFrame*>(
          root->child_at(1)->current_frame_host()->GetView());

  EXPECT_FALSE(first_child_view->CanBecomeVisible());

  ChildFrameCompositorFrameSwapCounter first_counter(first_child_view);
  ChildFrameCompositorFrameSwapCounter second_counter(second_child_view);

  const size_t kFrameCountLimit = 20u;

  // Wait for a certain number of swapped compositor frames generated for the
  // second child view. During the same interval the first frame should not have
  // swapped any compositor frames.
  second_counter.WaitForNewFrames(kFrameCountLimit);
  ASSERT_LT(kFrameCountLimit, second_counter.GetCount() + 1u);

  float ratio = static_cast<float>(first_counter.GetCount()) /
                static_cast<float>(second_counter.GetCount());
  EXPECT_GT(0.5f, ratio) << "Ratio is: " << ratio;
}

// Verify that sandbox flags inheritance works across multiple levels of
// frames.  See https://crbug.com/576845.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, SandboxFlagsInheritance) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Set sandbox flags for child frame.
  EXPECT_TRUE(ExecuteScript(
      root, "document.querySelector('iframe').sandbox = 'allow-scripts';"));

  // Calculate expected flags.  Note that "allow-scripts" resets both
  // WebSandboxFlags::Scripts and WebSandboxFlags::AutomaticFeatures bits per
  // blink::parseSandboxPolicy().
  blink::WebSandboxFlags expected_flags =
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
      ~blink::WebSandboxFlags::kAutomaticFeatures;
  EXPECT_EQ(expected_flags,
            root->child_at(0)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(0)->effective_frame_policy().sandbox_flags);

  // Navigate child frame so that the sandbox flags take effect.  Use a page
  // with three levels of frames and make sure all frames properly inherit
  // sandbox flags.
  GURL frame_url(embedded_test_server()->GetURL(
      "b.com", "/cross_site_iframe_factory.html?b(c(d))"));
  NavigateFrameToURL(root->child_at(0), frame_url);

  // Wait for subframes to load as well.
  ASSERT_TRUE(WaitForLoadStop(shell()->web_contents()));

  // Check each new frame's sandbox flags on the browser process side.
  FrameTreeNode* b_child = root->child_at(0);
  FrameTreeNode* c_child = b_child->child_at(0);
  FrameTreeNode* d_child = c_child->child_at(0);
  EXPECT_EQ(expected_flags, b_child->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(expected_flags, c_child->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(expected_flags, d_child->effective_frame_policy().sandbox_flags);

  // Check whether each frame is sandboxed on the renderer side, by seeing if
  // each frame's origin is unique ("null").
  EXPECT_EQ("null", GetDocumentOrigin(b_child));
  EXPECT_EQ("null", GetDocumentOrigin(c_child));
  EXPECT_EQ("null", GetDocumentOrigin(d_child));
}

// Check that sandbox flags are not inherited before they take effect.  Create
// a child frame, update its sandbox flags but don't navigate the frame, and
// ensure that a new cross-site grandchild frame doesn't inherit the new flags
// (which shouldn't have taken effect).
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       SandboxFlagsNotInheritedBeforeNavigation) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Set sandbox flags for child frame.
  EXPECT_TRUE(ExecuteScript(
      root, "document.querySelector('iframe').sandbox = 'allow-scripts';"));

  // These flags should be pending but not take effect, since there's been no
  // navigation.
  blink::WebSandboxFlags expected_flags =
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
      ~blink::WebSandboxFlags::kAutomaticFeatures;
  FrameTreeNode* child = root->child_at(0);
  EXPECT_EQ(expected_flags, child->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            child->effective_frame_policy().sandbox_flags);

  // Add a new grandchild frame and navigate it cross-site.
  RenderFrameHostCreatedObserver frame_observer(shell()->web_contents(), 1);
  EXPECT_TRUE(ExecuteScript(
      child, "document.body.appendChild(document.createElement('iframe'));"));
  frame_observer.Wait();

  FrameTreeNode* grandchild = child->child_at(0);
  GURL frame_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  TestFrameNavigationObserver navigation_observer(grandchild);
  NavigateFrameToURL(grandchild, frame_url);
  navigation_observer.Wait();

  // Since the update flags haven't yet taken effect in its parent, this
  // grandchild frame should not be sandboxed.
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            grandchild->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            grandchild->effective_frame_policy().sandbox_flags);

  // Check that the grandchild frame isn't sandboxed on the renderer side.  If
  // sandboxed, its origin would be unique ("null").
  EXPECT_EQ(frame_url.GetOrigin().spec(), GetDocumentOrigin(grandchild) + "/");
}

// Verify that popups opened from sandboxed frames inherit sandbox flags from
// their opener, and that they keep these inherited flags after being navigated
// cross-site.  See https://crbug.com/483584.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NewPopupInheritsSandboxFlagsFromOpener) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Set sandbox flags for child frame.
  EXPECT_TRUE(ExecuteScript(root,
                            "document.querySelector('iframe').sandbox = "
                            "    'allow-scripts allow-popups';"));

  // Calculate expected flags.  Note that "allow-scripts" resets both
  // WebSandboxFlags::Scripts and WebSandboxFlags::AutomaticFeatures bits per
  // blink::parseSandboxPolicy().
  blink::WebSandboxFlags expected_flags =
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
      ~blink::WebSandboxFlags::kAutomaticFeatures &
      ~blink::WebSandboxFlags::kPopups;
  EXPECT_EQ(expected_flags,
            root->child_at(0)->pending_frame_policy().sandbox_flags);

  // Navigate child frame cross-site.  The sandbox flags should take effect.
  GURL frame_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  TestFrameNavigationObserver frame_observer(root->child_at(0));
  NavigateFrameToURL(root->child_at(0), frame_url);
  frame_observer.Wait();
  EXPECT_EQ(expected_flags,
            root->child_at(0)->effective_frame_policy().sandbox_flags);

  // Verify that they've also taken effect on the renderer side.  The sandboxed
  // frame's origin should be unique.
  EXPECT_EQ("null", GetDocumentOrigin(root->child_at(0)));

  // Open a popup named "foo" from the sandboxed child frame.
  Shell* foo_shell =
      OpenPopup(root->child_at(0), GURL(url::kAboutBlankURL), "foo");
  EXPECT_TRUE(foo_shell);

  FrameTreeNode* foo_root =
      static_cast<WebContentsImpl*>(foo_shell->web_contents())
          ->GetFrameTree()
          ->root();

  // Check that the sandbox flags for new popup are correct in the browser
  // process.
  EXPECT_EQ(expected_flags, foo_root->effective_frame_policy().sandbox_flags);

  // The popup's origin should be unique, since it's sandboxed.
  EXPECT_EQ("null", GetDocumentOrigin(foo_root));

  // Navigate the popup cross-site.  This should keep the unique origin and the
  // inherited sandbox flags.
  GURL c_url(embedded_test_server()->GetURL("c.com", "/title1.html"));
  {
    TestFrameNavigationObserver popup_observer(foo_root);
    EXPECT_TRUE(
        ExecuteScript(foo_root, "location.href = '" + c_url.spec() + "';"));
    popup_observer.Wait();
    EXPECT_EQ(c_url, foo_shell->web_contents()->GetLastCommittedURL());
  }

  // Confirm that the popup is still sandboxed, both on browser and renderer
  // sides.
  EXPECT_EQ(expected_flags, foo_root->effective_frame_policy().sandbox_flags);
  EXPECT_EQ("null", GetDocumentOrigin(foo_root));

  // Navigate the popup back to b.com.  The popup should perform a
  // remote-to-local navigation in the b.com process, and keep the unique
  // origin and the inherited sandbox flags.
  {
    TestFrameNavigationObserver popup_observer(foo_root);
    EXPECT_TRUE(
        ExecuteScript(foo_root, "location.href = '" + frame_url.spec() + "';"));
    popup_observer.Wait();
    EXPECT_EQ(frame_url, foo_shell->web_contents()->GetLastCommittedURL());
  }

  // Confirm that the popup is still sandboxed, both on browser and renderer
  // sides.
  EXPECT_EQ(expected_flags, foo_root->effective_frame_policy().sandbox_flags);
  EXPECT_EQ("null", GetDocumentOrigin(foo_root));
}

// Verify that popups opened from frames sandboxed with the
// "allow-popups-to-escape-sandbox" directive do *not* inherit sandbox flags
// from their opener.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       OpenUnsandboxedPopupFromSandboxedFrame) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Set sandbox flags for child frame, specifying that popups opened from it
  // should not be sandboxed.
  EXPECT_TRUE(ExecuteScript(
      root,
      "document.querySelector('iframe').sandbox = "
      "    'allow-scripts allow-popups allow-popups-to-escape-sandbox';"));

  // Set expected flags for the child frame.  Note that "allow-scripts" resets
  // both WebSandboxFlags::Scripts and WebSandboxFlags::AutomaticFeatures bits
  // per blink::parseSandboxPolicy().
  blink::WebSandboxFlags expected_flags =
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
      ~blink::WebSandboxFlags::kAutomaticFeatures &
      ~blink::WebSandboxFlags::kPopups &
      ~blink::WebSandboxFlags::kPropagatesToAuxiliaryBrowsingContexts;
  EXPECT_EQ(expected_flags,
            root->child_at(0)->pending_frame_policy().sandbox_flags);

  // Navigate child frame cross-site.  The sandbox flags should take effect.
  GURL frame_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  TestFrameNavigationObserver frame_observer(root->child_at(0));
  NavigateFrameToURL(root->child_at(0), frame_url);
  frame_observer.Wait();
  EXPECT_EQ(expected_flags,
            root->child_at(0)->effective_frame_policy().sandbox_flags);

  // Open a cross-site popup named "foo" from the child frame.
  GURL b_url(embedded_test_server()->GetURL("c.com", "/title1.html"));
  Shell* foo_shell = OpenPopup(root->child_at(0), b_url, "foo");
  EXPECT_TRUE(foo_shell);

  FrameTreeNode* foo_root =
      static_cast<WebContentsImpl*>(foo_shell->web_contents())
          ->GetFrameTree()
          ->root();

  // Check that the sandbox flags for new popup are correct in the browser
  // process.  They should not have been inherited.
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            foo_root->effective_frame_policy().sandbox_flags);

  // The popup's origin should match |b_url|, since it's not sandboxed.
  std::string popup_origin;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      foo_root, "domAutomationController.send(document.origin)",
      &popup_origin));
  EXPECT_EQ(b_url.GetOrigin().spec(), popup_origin + "/");
}

// Tests that the WebContents is notified when passive mixed content is
// displayed in an OOPIF. The test ignores cert errors so that an HTTPS
// iframe can be loaded from a site other than localhost (the
// EmbeddedTestServer serves a certificate that is valid for localhost).
// This test crashes on Windows under Dr. Memory, see https://crbug.com/600942.
#if defined(OS_WIN)
#define MAYBE_PassiveMixedContentInIframe DISABLED_PassiveMixedContentInIframe
#else
#define MAYBE_PassiveMixedContentInIframe PassiveMixedContentInIframe
#endif
IN_PROC_BROWSER_TEST_F(SitePerProcessIgnoreCertErrorsBrowserTest,
                       MAYBE_PassiveMixedContentInIframe) {
  net::EmbeddedTestServer https_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_server.ServeFilesFromSourceDirectory("content/test/data");
  SetupCrossSiteRedirector(&https_server);
  ASSERT_TRUE(https_server.Start());

  WebContentsImpl* web_contents =
      static_cast<WebContentsImpl*>(shell()->web_contents());

  GURL iframe_url(
      https_server.GetURL("/mixed-content/basic-passive-in-iframe.html"));
  EXPECT_TRUE(NavigateToURL(shell(), iframe_url));
  NavigationEntry* entry = web_contents->GetController().GetVisibleEntry();
  EXPECT_TRUE(!!(entry->GetSSL().content_status &
                 SSLStatus::DISPLAYED_INSECURE_CONTENT));

  // When the subframe navigates, the WebContents should still be marked
  // as having displayed insecure content.
  GURL navigate_url(https_server.GetURL("/title1.html"));
  FrameTreeNode* root = web_contents->GetFrameTree()->root();
  NavigateFrameToURL(root->child_at(0), navigate_url);
  entry = web_contents->GetController().GetVisibleEntry();
  EXPECT_TRUE(!!(entry->GetSSL().content_status &
                 SSLStatus::DISPLAYED_INSECURE_CONTENT));

  // When the main frame navigates, it should no longer be marked as
  // displaying insecure content.
  EXPECT_TRUE(
      NavigateToURL(shell(), https_server.GetURL("b.com", "/title1.html")));
  entry = web_contents->GetController().GetVisibleEntry();
  EXPECT_FALSE(!!(entry->GetSSL().content_status &
                  SSLStatus::DISPLAYED_INSECURE_CONTENT));
}

// Tests that, when a parent frame is set to strictly block mixed
// content via Content Security Policy, child OOPIFs cannot display
// mixed content.
IN_PROC_BROWSER_TEST_F(SitePerProcessIgnoreCertErrorsBrowserTest,
                       PassiveMixedContentInIframeWithStrictBlocking) {
  net::EmbeddedTestServer https_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_server.ServeFilesFromSourceDirectory("content/test/data");
  SetupCrossSiteRedirector(&https_server);
  ASSERT_TRUE(https_server.Start());

  WebContentsImpl* web_contents =
      static_cast<WebContentsImpl*>(shell()->web_contents());

  GURL iframe_url_with_strict_blocking(https_server.GetURL(
      "/mixed-content/basic-passive-in-iframe-with-strict-blocking.html"));
  EXPECT_TRUE(NavigateToURL(shell(), iframe_url_with_strict_blocking));
  NavigationEntry* entry = web_contents->GetController().GetVisibleEntry();
  EXPECT_FALSE(!!(entry->GetSSL().content_status &
                  SSLStatus::DISPLAYED_INSECURE_CONTENT));

  FrameTreeNode* root = web_contents->GetFrameTree()->root();
  EXPECT_EQ(blink::kBlockAllMixedContent,
            root->current_replication_state().insecure_request_policy);
  EXPECT_EQ(
      blink::kBlockAllMixedContent,
      root->child_at(0)->current_replication_state().insecure_request_policy);

  // When the subframe navigates, it should still be marked as enforcing
  // strict mixed content.
  GURL navigate_url(https_server.GetURL("/title1.html"));
  NavigateFrameToURL(root->child_at(0), navigate_url);
  EXPECT_EQ(blink::kBlockAllMixedContent,
            root->current_replication_state().insecure_request_policy);
  EXPECT_EQ(
      blink::kBlockAllMixedContent,
      root->child_at(0)->current_replication_state().insecure_request_policy);

  // When the main frame navigates, it should no longer be marked as
  // enforcing strict mixed content.
  EXPECT_TRUE(
      NavigateToURL(shell(), https_server.GetURL("b.com", "/title1.html")));
  EXPECT_EQ(blink::kLeaveInsecureRequestsAlone,
            root->current_replication_state().insecure_request_policy);
}

// Tests that, when a parent frame is set to upgrade insecure requests
// via Content Security Policy, child OOPIFs will upgrade as well.
IN_PROC_BROWSER_TEST_F(SitePerProcessIgnoreCertErrorsBrowserTest,
                       PassiveMixedContentInIframeWithUpgrade) {
  net::EmbeddedTestServer https_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_server.ServeFilesFromSourceDirectory("content/test/data");
  SetupCrossSiteRedirector(&https_server);
  ASSERT_TRUE(https_server.Start());

  WebContentsImpl* web_contents =
      static_cast<WebContentsImpl*>(shell()->web_contents());

  GURL iframe_url_with_upgrade(https_server.GetURL(
      "/mixed-content/basic-passive-in-iframe-with-upgrade.html"));
  EXPECT_TRUE(NavigateToURL(shell(), iframe_url_with_upgrade));
  NavigationEntry* entry = web_contents->GetController().GetVisibleEntry();
  EXPECT_FALSE(!!(entry->GetSSL().content_status &
                  SSLStatus::DISPLAYED_INSECURE_CONTENT));

  FrameTreeNode* root = web_contents->GetFrameTree()->root();
  EXPECT_EQ(blink::kUpgradeInsecureRequests,
            root->current_replication_state().insecure_request_policy);
  EXPECT_EQ(
      blink::kUpgradeInsecureRequests,
      root->child_at(0)->current_replication_state().insecure_request_policy);

  // When the subframe navigates, it should still be marked as upgrading
  // insecure requests.
  GURL navigate_url(https_server.GetURL("/title1.html"));
  NavigateFrameToURL(root->child_at(0), navigate_url);
  EXPECT_EQ(blink::kUpgradeInsecureRequests,
            root->current_replication_state().insecure_request_policy);
  EXPECT_EQ(
      blink::kUpgradeInsecureRequests,
      root->child_at(0)->current_replication_state().insecure_request_policy);

  // When the main frame navigates, it should no longer be marked as
  // upgrading insecure requests.
  EXPECT_TRUE(
      NavigateToURL(shell(), https_server.GetURL("b.com", "/title1.html")));
  EXPECT_EQ(blink::kLeaveInsecureRequestsAlone,
            root->current_replication_state().insecure_request_policy);
}

// Tests that active mixed content is blocked in an OOPIF. The test
// ignores cert errors so that an HTTPS iframe can be loaded from a site
// other than localhost (the EmbeddedTestServer serves a certificate
// that is valid for localhost).
IN_PROC_BROWSER_TEST_F(SitePerProcessIgnoreCertErrorsBrowserTest,
                       ActiveMixedContentInIframe) {
  net::EmbeddedTestServer https_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_server.ServeFilesFromSourceDirectory("content/test/data");
  SetupCrossSiteRedirector(&https_server);
  ASSERT_TRUE(https_server.Start());

  GURL iframe_url(
      https_server.GetURL("/mixed-content/basic-active-in-iframe.html"));
  EXPECT_TRUE(NavigateToURL(shell(), iframe_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1U, root->child_count());
  FrameTreeNode* mixed_child = root->child_at(0)->child_at(0);
  ASSERT_TRUE(mixed_child);
  // The child iframe attempted to create a mixed iframe; this should
  // have been blocked, so the mixed iframe should not have committed a
  // load.
  EXPECT_FALSE(mixed_child->has_committed_real_load());
}

// Test that subresources with certificate errors get reported to the
// browser. That is, if https://example.test frames https://a.com which
// loads an image with certificate errors, the browser should be
// notified about the subresource with certificate errors and downgrade
// the UI appropriately.
IN_PROC_BROWSER_TEST_F(SitePerProcessIgnoreCertErrorsBrowserTest,
                       SubresourceWithCertificateErrors) {
  net::EmbeddedTestServer https_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_server.ServeFilesFromSourceDirectory("content/test/data");
  SetupCrossSiteRedirector(&https_server);
  ASSERT_TRUE(https_server.Start());

  GURL url(https_server.GetURL(
      "example.test",
      "/mixed-content/non-redundant-cert-error-in-iframe.html"));
  EXPECT_TRUE(NavigateToURL(shell(), url));

  NavigationEntry* entry =
      shell()->web_contents()->GetController().GetLastCommittedEntry();
  ASSERT_TRUE(entry);

  // The main page was loaded with certificate errors.
  EXPECT_TRUE(net::IsCertStatusError(entry->GetSSL().cert_status));

  // The image that the iframe loaded had certificate errors also, so
  // the page should be marked as having displayed subresources with
  // cert errors.
  EXPECT_TRUE(!!(entry->GetSSL().content_status &
                 SSLStatus::DISPLAYED_CONTENT_WITH_CERT_ERRORS));
}

// Test setting a cross-origin iframe to display: none.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, CrossSiteIframeDisplayNone) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  RenderWidgetHost* root_render_widget_host =
      root->current_frame_host()->GetRenderWidgetHost();

  // Set the iframe to display: none.
  EXPECT_TRUE(ExecuteScript(
      shell(), "document.querySelector('iframe').style.display = 'none'"));

  // Waits until pending frames are done.
  std::unique_ptr<MainThreadFrameObserver> observer(
      new MainThreadFrameObserver(root_render_widget_host));
  observer->Wait();

  // Force the renderer to generate a new frame.
  EXPECT_TRUE(
      ExecuteScript(shell(), "document.body.style.background = 'black'"));

  // Waits for the next frame.
  observer->Wait();
}

// Test that a cross-origin iframe can be blocked by X-Frame-Options and CSP
// frame-ancestors.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CrossSiteIframeBlockedByXFrameOptionsOrCSP) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Add a load event handler for the iframe element.
  EXPECT_TRUE(ExecuteScript(shell(),
                            "document.querySelector('iframe').onload = "
                            "    function() { document.title = 'loaded'; };"));

  GURL blocked_urls[] = {
    embedded_test_server()->GetURL("b.com", "/frame-ancestors-none.html"),
    embedded_test_server()->GetURL("b.com", "/x-frame-options-deny.html")
  };

  for (size_t i = 0; i < arraysize(blocked_urls); ++i) {
    EXPECT_TRUE(ExecuteScript(shell(), "document.title = 'not loaded';"));
    base::string16 expected_title(base::UTF8ToUTF16("loaded"));
    TitleWatcher title_watcher(shell()->web_contents(), expected_title);

    // Navigate the subframe to a blocked URL.
    TestNavigationObserver load_observer(shell()->web_contents());
    EXPECT_TRUE(ExecuteScript(shell(), "frames[0].location.href = '" +
                                           blocked_urls[i].spec() + "';"));
    load_observer.Wait();

    // The blocked frame's origin should become unique.
    EXPECT_EQ("null", root->child_at(0)->current_origin().Serialize());

    // Ensure that we don't use the blocked URL as the blocked frame's last
    // committed URL (see https://crbug.com/622385).
    EXPECT_NE(root->child_at(0)->current_frame_host()->GetLastCommittedURL(),
              blocked_urls[i]);

    // The blocked frame should still fire a load event in its parent's process.
    EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());

    // Check that the current RenderFrameHost has stopped loading.
    EXPECT_FALSE(root->child_at(0)->current_frame_host()->is_loading());

    // The blocked navigation should behave like an empty 200 response. Make
    // sure that the frame's document.title is empty: this double-checks both
    // that the blocked URL's contents wasn't loaded, and that the old page
    // isn't active anymore (both of these pages have non-empty titles).
    std::string frame_title;
    EXPECT_TRUE(ExecuteScriptAndExtractString(
        root->child_at(0), "domAutomationController.send(document.title)",
        &frame_title));
    EXPECT_EQ("", frame_title);

    // Navigate the subframe to another cross-origin page and ensure that this
    // navigation succeeds.  Use a renderer-initiated navigation to test the
    // transfer logic, which used to have some issues with this.
    GURL c_url(embedded_test_server()->GetURL("c.com", "/title1.html"));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "child-0", c_url));
    EXPECT_EQ(c_url, root->child_at(0)->current_url());

    // When a page gets blocked due to XFO or CSP, it is sandboxed with the
    // SandboxOrigin flag (i.e., its origin is set to be unique) to ensure that
    // the blocked page is seen as cross-origin. However, those flags shouldn't
    // affect future navigations for a frame. Verify this for the above
    // navigation.
    EXPECT_EQ(c_url.GetOrigin().spec(),
              root->child_at(0)->current_origin().Serialize() + "/");
    EXPECT_EQ(blink::WebSandboxFlags::kNone,
              root->child_at(0)->effective_frame_policy().sandbox_flags);
  }
}

// Test that a cross-origin frame's navigation can be blocked by CSP frame-src.
// In this version of a test, CSP comes from HTTP headers.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CrossSiteIframeBlockedByParentCSPFromHeaders) {
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/frame-src-self-and-b.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Sanity-check that the test page has the expected shape for testing.
  GURL old_subframe_url(
      embedded_test_server()->GetURL("b.com", "/title2.html"));
  EXPECT_FALSE(root->child_at(0)->HasSameOrigin(*root));
  EXPECT_EQ(old_subframe_url, root->child_at(0)->current_url());
  const std::vector<ContentSecurityPolicyHeader>& root_csp =
      root->current_replication_state().accumulated_csp_headers;
  EXPECT_EQ(1u, root_csp.size());
  EXPECT_EQ("frame-src 'self' http://b.com:*", root_csp[0].header_value);

  // Monitor subframe's load events via main frame's title.
  EXPECT_TRUE(ExecuteScript(shell(),
                            "document.querySelector('iframe').onload = "
                            "    function() { document.title = 'loaded'; };"));
  EXPECT_TRUE(ExecuteScript(shell(), "document.title = 'not loaded';"));
  base::string16 expected_title(base::UTF8ToUTF16("loaded"));
  TitleWatcher title_watcher(shell()->web_contents(), expected_title);

  // Try to navigate the subframe to a blocked URL.
  TestNavigationObserver load_observer(shell()->web_contents());
  GURL blocked_url = embedded_test_server()->GetURL("c.com", "/title3.html");
  EXPECT_TRUE(ExecuteScript(root->child_at(0), "window.location.href = '" +
                                                   blocked_url.spec() + "';"));

  // The blocked frame should still fire a load event in its parent's process.
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());

  // Check that the current RenderFrameHost has stopped loading.
  if (root->child_at(0)->current_frame_host()->is_loading())
    load_observer.Wait();

  // The last successful url shouldn't be the blocked url.
  EXPECT_EQ(old_subframe_url,
            root->child_at(0)->current_frame_host()->last_successful_url());

  // The blocked frame should go to an error page. Errors currently commit
  // with the URL of the blocked page.
  EXPECT_EQ(blocked_url, root->child_at(0)->current_url());

  // The page should get the title of an error page (i.e "Error") and not the
  // title of the blocked page.
  std::string frame_title;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      root->child_at(0), "domAutomationController.send(document.title)",
      &frame_title));
  EXPECT_EQ("Error", frame_title);

  // Navigate to a URL without CSP.
  EXPECT_TRUE(NavigateToURL(
      shell(), embedded_test_server()->GetURL("a.com", "/title1.html")));

  // Verify that the frame's CSP got correctly reset to an empty set.
  EXPECT_EQ(0u,
            root->current_replication_state().accumulated_csp_headers.size());
}

// Test that a cross-origin frame's navigation can be blocked by CSP frame-src.
// In this version of a test, CSP comes from a <meta> element added after the
// page has already loaded.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CrossSiteIframeBlockedByParentCSPFromMeta) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Navigate the subframe to a location we will disallow in the future.
  GURL old_subframe_url(
      embedded_test_server()->GetURL("b.com", "/title2.html"));
  NavigateFrameToURL(root->child_at(0), old_subframe_url);

  // Add frame-src CSP via a new <meta> element.
  EXPECT_TRUE(ExecuteScript(
      shell(),
      "var meta = document.createElement('meta');"
      "meta.httpEquiv = 'Content-Security-Policy';"
      "meta.content = 'frame-src https://a.com:*';"
      "document.getElementsByTagName('head')[0].appendChild(meta);"));

  // Sanity-check that the test page has the expected shape for testing.
  // (the CSP should not have an effect on the already loaded frames).
  EXPECT_FALSE(root->child_at(0)->HasSameOrigin(*root));
  EXPECT_EQ(old_subframe_url, root->child_at(0)->current_url());
  const std::vector<ContentSecurityPolicyHeader>& root_csp =
      root->current_replication_state().accumulated_csp_headers;
  EXPECT_EQ(1u, root_csp.size());
  EXPECT_EQ("frame-src https://a.com:*", root_csp[0].header_value);

  // Monitor subframe's load events via main frame's title.
  EXPECT_TRUE(ExecuteScript(shell(),
                            "document.querySelector('iframe').onload = "
                            "    function() { document.title = 'loaded'; };"));
  EXPECT_TRUE(ExecuteScript(shell(), "document.title = 'not loaded';"));
  base::string16 expected_title(base::UTF8ToUTF16("loaded"));
  TitleWatcher title_watcher(shell()->web_contents(), expected_title);

  // Try to navigate the subframe to a blocked URL.
  TestNavigationObserver load_observer2(shell()->web_contents());
  GURL blocked_url = embedded_test_server()->GetURL("c.com", "/title3.html");
  EXPECT_TRUE(ExecuteScript(root->child_at(0), "window.location.href = '" +
                                                   blocked_url.spec() + "';"));

  // The blocked frame should still fire a load event in its parent's process.
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());

  // Check that the current RenderFrameHost has stopped loading.
  if (root->child_at(0)->current_frame_host()->is_loading())
    load_observer2.Wait();

  // The last successful url shouldn't be the blocked url.
  EXPECT_EQ(old_subframe_url,
            root->child_at(0)->current_frame_host()->last_successful_url());

  // The blocked frame should go to an error page. Errors currently commit
  // with the URL of the blocked page.
  EXPECT_EQ(blocked_url, root->child_at(0)->current_url());

  // The page should get the title of an error page (i.e "Error") and not the
  // title of the blocked page.
  std::string frame_title;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      root->child_at(0), "domAutomationController.send(document.title)",
      &frame_title));
  EXPECT_EQ("Error", frame_title);
}

// Test that a cross-origin frame's navigation can be blocked by CSP frame-src.
// In this version of a test, CSP is inherited by srcdoc iframe from a parent
// that declared CSP via HTTP headers.  Cross-origin frame navigating to a
// blocked location is a child of the srcdoc iframe.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CrossSiteIframeBlockedByCSPInheritedBySrcDocParent) {
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/frame-src-self-and-b.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* srcdoc_frame = root->child_at(1);
  EXPECT_TRUE(srcdoc_frame != nullptr);
  FrameTreeNode* navigating_frame = srcdoc_frame->child_at(0);
  EXPECT_TRUE(navigating_frame != nullptr);

  // Sanity-check that the test page has the expected shape for testing.
  // (the CSP should not have an effect on the already loaded frames).
  GURL old_subframe_url(
      embedded_test_server()->GetURL("b.com", "/title2.html"));
  EXPECT_TRUE(srcdoc_frame->HasSameOrigin(*root));
  EXPECT_FALSE(srcdoc_frame->HasSameOrigin(*navigating_frame));
  EXPECT_EQ(old_subframe_url, navigating_frame->current_url());
  const std::vector<ContentSecurityPolicyHeader>& srcdoc_csp =
      srcdoc_frame->current_replication_state().accumulated_csp_headers;
  EXPECT_EQ(1u, srcdoc_csp.size());
  EXPECT_EQ("frame-src 'self' http://b.com:*", srcdoc_csp[0].header_value);

  // Monitor navigating_frame's load events via srcdoc_frame posting
  // a message to the parent frame.
  EXPECT_TRUE(
      ExecuteScript(root,
                    "window.addEventListener('message', function(event) {"
                    "  document.title = event.data;"
                    "});"));
  EXPECT_TRUE(ExecuteScript(
      srcdoc_frame,
      "document.querySelector('iframe').onload = "
      "    function() { window.top.postMessage('loaded', '*'); };"));
  EXPECT_TRUE(ExecuteScript(shell(), "document.title = 'not loaded';"));
  base::string16 expected_title(base::UTF8ToUTF16("loaded"));
  TitleWatcher title_watcher(shell()->web_contents(), expected_title);

  // Try to navigate the subframe to a blocked URL.
  TestNavigationObserver load_observer2(shell()->web_contents());
  GURL blocked_url = embedded_test_server()->GetURL("c.com", "/title3.html");
  EXPECT_TRUE(ExecuteScript(navigating_frame, "window.location.href = '" +
                                                  blocked_url.spec() + "';"));

  // The blocked frame should still fire a load event in its parent's process.
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());

  // Check that the current RenderFrameHost has stopped loading.
  if (navigating_frame->current_frame_host()->is_loading())
    load_observer2.Wait();

  // The last successful url shouldn't be the blocked url.
  EXPECT_EQ(old_subframe_url,
            navigating_frame->current_frame_host()->last_successful_url());

  // The blocked frame should go to an error page. Errors currently commit
  // with the URL of the blocked page.
  EXPECT_EQ(blocked_url, navigating_frame->current_url());

  // The page should get the title of an error page (i.e "Error") and not the
  // title of the blocked page.
  std::string frame_title;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      navigating_frame, "domAutomationController.send(document.title)",
      &frame_title));
  EXPECT_EQ("Error", frame_title);

  // Navigate the subframe to a URL without CSP.
  NavigateFrameToURL(srcdoc_frame,
                     embedded_test_server()->GetURL("a.com", "/title1.html"));

  // Verify that the frame's CSP got correctly reset to an empty set.
  EXPECT_EQ(
      0u,
      srcdoc_frame->current_replication_state().accumulated_csp_headers.size());
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, ScreenCoordinates) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);

  const char* properties[] = {"screenX", "screenY", "outerWidth",
                              "outerHeight"};

  for (const char* property : properties) {
    std::string script = "window.domAutomationController.send(window.";
    script += property;
    script += ");";
    int root_value = 1;
    int child_value = 2;
    EXPECT_TRUE(ExecuteScriptAndExtractInt(root, script.c_str(), &root_value));

    EXPECT_TRUE(
        ExecuteScriptAndExtractInt(child, script.c_str(), &child_value));

    EXPECT_EQ(root_value, child_value);
  }
}

// Tests that the swapped out state on RenderViewHost is properly reset when
// the main frame is navigated to the same SiteInstance as one of its child
// frames.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateMainFrameToChildSite) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  WebContentsImpl* contents = web_contents();
  FrameTreeNode* root = contents->GetFrameTree()->root();
  EXPECT_EQ(1U, root->child_count());

  // Ensure the RenderViewHost for the SiteInstance of the child is considered
  // in swapped out state.
  RenderViewHostImpl* rvh = contents->GetFrameTree()->GetRenderViewHost(
      root->child_at(0)->current_frame_host()->GetSiteInstance());
  EXPECT_TRUE(rvh->is_swapped_out_);

  // Have the child frame navigate its parent to its SiteInstance.
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  std::string script =
      base::StringPrintf("parent.location = '%s';", b_url.spec().c_str());

  // Ensure the child has received a user gesture, so that it has permission
  // to framebust.
  SimulateMouseClick(
      root->child_at(0)->current_frame_host()->GetRenderWidgetHost(), 1, 1);
  TestFrameNavigationObserver frame_observer(root);
  EXPECT_TRUE(ExecuteScript(root->child_at(0), script));
  frame_observer.Wait();
  EXPECT_EQ(b_url, root->current_url());

  // Verify that the same RenderViewHost is preserved and that it is no longer
  // in swapped out state.
  EXPECT_EQ(rvh, contents->GetFrameTree()->GetRenderViewHost(
                     root->current_frame_host()->GetSiteInstance()));
  EXPECT_FALSE(rvh->is_swapped_out_);
}

// Helper class to wait for a ShutdownRequest message to arrive, in response to
// which RenderProcessWillExit is called on observers by RenderProcessHost.
class ShutdownObserver : public RenderProcessHostObserver {
 public:
  ShutdownObserver() : message_loop_runner_(new MessageLoopRunner) {}

  void RenderProcessShutdownRequested(RenderProcessHost* host) override {
    message_loop_runner_->Quit();
  }

  void Wait() { message_loop_runner_->Run(); }

 private:
  scoped_refptr<MessageLoopRunner> message_loop_runner_;
  DISALLOW_COPY_AND_ASSIGN(ShutdownObserver);
};

// Test for https://crbug.com/568836.  From an A-embed-B page, navigate the
// subframe from B to A.  This cleans up the process for B, but the test delays
// the browser side from killing the B process right away.  This allows the
// B process to process two ViewMsg_Close messages sent to the subframe's
// RenderWidget and to the RenderView, in that order.  In the bug, the latter
// crashed while detaching the subframe's LocalFrame (triggered as part of
// closing the RenderView), because this tried to access the subframe's
// WebFrameWidget (from RenderFrameImpl::didChangeSelection), which had already
// been cleared by the former.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CloseSubframeWidgetAndViewOnProcessExit) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  // "Select all" in the subframe.  The bug only happens if there's a selection
  // change, which triggers the path through didChangeSelection.
  root->child_at(0)->current_frame_host()->GetFrameInputHandler()->SelectAll();

  // Prevent b.com process from terminating right away once the subframe
  // navigates away from b.com below.  This is necessary so that the renderer
  // process has time to process the closings of RenderWidget and RenderView,
  // which is where the original bug was triggered.  Incrementing the keep alive
  // ref count will cause RenderProcessHostImpl::Cleanup to forego process
  // termination.
  RenderProcessHost* subframe_process =
      root->child_at(0)->current_frame_host()->GetProcess();
  subframe_process->IncrementKeepAliveRefCount(
      RenderProcessHostImpl::KeepAliveClientType::kFetch);

  // Navigate the subframe away from b.com.  Since this is the last active
  // frame in the b.com process, this causes the RenderWidget and RenderView to
  // be closed.  If this succeeds without crashing, the renderer will release
  // the process and send a ShutdownRequest to the browser
  // process to ask whether it's ok to terminate.  Thus, wait for this message
  // to ensure that the RenderView and widget were closed without crashing.
  ShutdownObserver shutdown_observer;
  subframe_process->AddObserver(&shutdown_observer);
  NavigateFrameToURL(root->child_at(0),
                     embedded_test_server()->GetURL("a.com", "/title1.html"));
  shutdown_observer.Wait();
  subframe_process->RemoveObserver(&shutdown_observer);

  // TODO(alexmos): Navigating the subframe back to b.com at this point would
  // trigger the race in https://crbug.com/535246, where the browser process
  // tries to reuse the b.com process thinking it's still initialized, whereas
  // the process has actually been destroyed by the renderer (but the browser
  // process hasn't heard the OnChannelError yet).  This race will need to be
  // fixed.

  subframe_process->DecrementKeepAliveRefCount(
      RenderProcessHostImpl::KeepAliveClientType::kFetch);
}

// Tests that an input event targeted to a out-of-process iframe correctly
// triggers a user interaction notification for WebContentsObservers.
// This is used for browser features such as download request limiting and
// launching multiple external protocol handlers, which can block repeated
// actions from a page when a user is not interacting with the page.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       UserInteractionForChildFrameTest) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  UserInteractionObserver observer(web_contents());

  // Target an event to the child frame's RenderWidgetHostView.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  SimulateMouseClick(
      root->child_at(0)->current_frame_host()->GetRenderWidgetHost(), 5, 5);

  EXPECT_TRUE(observer.WasUserInteractionReceived());

  // Target an event to the main frame.
  observer.Reset();
  SimulateMouseClick(root->current_frame_host()->GetRenderWidgetHost(), 1, 1);

  EXPECT_TRUE(observer.WasUserInteractionReceived());
}

// Ensures that navigating to data: URLs present in session history will
// correctly commit the navigation in the same process as the parent frame.
// See https://crbug.com/606996.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateSubframeToDataUrlInSessionHistory) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_EQ(2U, root->child_count());
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  TestNavigationObserver observer(shell()->web_contents());
  FrameTreeNode* child = root->child_at(0);

  // Navigate iframe to a data URL, which will commit in a new SiteInstance.
  GURL data_url("data:text/html,dataurl");
  NavigateFrameToURL(child, data_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(data_url, observer.last_navigation_url());
  scoped_refptr<SiteInstanceImpl> orig_site_instance =
    child->current_frame_host()->GetSiteInstance();
  EXPECT_NE(root->current_frame_host()->GetSiteInstance(), orig_site_instance);

  // Navigate it to another cross-site url.
  GURL cross_site_url(embedded_test_server()->GetURL("c.com", "/title1.html"));
  NavigateFrameToURL(child, cross_site_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(cross_site_url, observer.last_navigation_url());
  EXPECT_EQ(3, web_contents()->GetController().GetEntryCount());
  EXPECT_NE(orig_site_instance, child->current_frame_host()->GetSiteInstance());

  // Go back and ensure the data: URL committed in the same SiteInstance as the
  // original navigation.
  EXPECT_TRUE(web_contents()->GetController().CanGoBack());
  TestFrameNavigationObserver frame_observer(child);
  web_contents()->GetController().GoBack();
  frame_observer.WaitForCommit();
  EXPECT_EQ(orig_site_instance, child->current_frame_host()->GetSiteInstance());
}

// Ensures that navigating to about:blank URLs present in session history will
// correctly commit the navigation in the same process as the one used for
// the original navigation.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateSubframeToAboutBlankInSessionHistory) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_EQ(2U, root->child_count());
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  TestNavigationObserver observer(shell()->web_contents());
  FrameTreeNode* child = root->child_at(0);

  // Navigate iframe to about:blank, which will commit in a new SiteInstance.
  GURL about_blank_url("about:blank");
  NavigateFrameToURL(child, about_blank_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(about_blank_url, observer.last_navigation_url());
  scoped_refptr<SiteInstanceImpl> orig_site_instance =
    child->current_frame_host()->GetSiteInstance();
  EXPECT_NE(root->current_frame_host()->GetSiteInstance(), orig_site_instance);

  // Navigate it to another cross-site url.
  GURL cross_site_url(embedded_test_server()->GetURL("c.com", "/title1.html"));
  NavigateFrameToURL(child, cross_site_url);
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(cross_site_url, observer.last_navigation_url());
  EXPECT_EQ(3, web_contents()->GetController().GetEntryCount());
  EXPECT_NE(orig_site_instance, child->current_frame_host()->GetSiteInstance());

  // Go back and ensure the about:blank URL committed in the same SiteInstance
  // as the original navigation.
  EXPECT_TRUE(web_contents()->GetController().CanGoBack());
  TestFrameNavigationObserver frame_observer(child);
  web_contents()->GetController().GoBack();
  frame_observer.WaitForCommit();
  EXPECT_EQ(orig_site_instance, child->current_frame_host()->GetSiteInstance());
}

// Tests that there are no crashes if a subframe is detached in its unload
// handler. See https://crbug.com/590054.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, DetachInUnloadHandler) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b(b))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "        +--Site B -- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  int child_count = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root->child_at(0), "window.domAutomationController.send(frames.length);",
      &child_count));
  EXPECT_EQ(1, child_count);

  RenderFrameDeletedObserver deleted_observer(
      root->child_at(0)->child_at(0)->current_frame_host());

  // Add an unload handler to the grandchild that causes it to be synchronously
  // detached, then navigate it.
  EXPECT_TRUE(ExecuteScript(
      root->child_at(0)->child_at(0),
      "window.onunload=function(e){\n"
      "    window.parent.document.getElementById('child-0').remove();\n"
      "};\n"));
  std::string script =
      std::string("window.document.getElementById('child-0').src = \"") +
      embedded_test_server()
          ->GetURL("c.com", "/cross_site_iframe_factory.html?c")
          .spec() +
      "\"";
  EXPECT_TRUE(ExecuteScript(root->child_at(0), script.c_str()));

  deleted_observer.WaitUntilDeleted();

  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root->child_at(0), "window.domAutomationController.send(frames.length);",
      &child_count));
  EXPECT_EQ(0, child_count);

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));
}

// Helper filter class to wait for a ShowCreatedWindow or ShowWidget message,
// record the routing ID from the message, and then drop the message.
const uint32_t kMessageClasses[] = {ViewMsgStart, FrameMsgStart};
class PendingWidgetMessageFilter : public BrowserMessageFilter {
 public:
  PendingWidgetMessageFilter()
      : BrowserMessageFilter(kMessageClasses, arraysize(kMessageClasses)),
        routing_id_(MSG_ROUTING_NONE),
        message_loop_runner_(new MessageLoopRunner) {}

  bool OnMessageReceived(const IPC::Message& message) override {
    bool handled = true;
    IPC_BEGIN_MESSAGE_MAP(PendingWidgetMessageFilter, message)
      IPC_MESSAGE_HANDLER(FrameHostMsg_ShowCreatedWindow, OnShowCreatedWindow)
      IPC_MESSAGE_HANDLER(ViewHostMsg_ShowWidget, OnShowWidget)
      IPC_MESSAGE_UNHANDLED(handled = false)
    IPC_END_MESSAGE_MAP()
    return handled;
  }

  void Wait() {
    message_loop_runner_->Run();
  }

  int routing_id() { return routing_id_; }

 private:
  ~PendingWidgetMessageFilter() override {}

  void OnShowCreatedWindow(int pending_widget_routing_id,
                           WindowOpenDisposition disposition,
                           const gfx::Rect& initial_rect,
                           bool user_gesture) {
    content::BrowserThread::PostTask(
        content::BrowserThread::UI, FROM_HERE,
        base::BindOnce(&PendingWidgetMessageFilter::OnReceivedRoutingIDOnUI,
                       this, pending_widget_routing_id));
  }

  void OnShowWidget(int routing_id, const gfx::Rect& initial_rect) {
    content::BrowserThread::PostTask(
        content::BrowserThread::UI, FROM_HERE,
        base::BindOnce(&PendingWidgetMessageFilter::OnReceivedRoutingIDOnUI,
                       this, routing_id));
  }

  void OnReceivedRoutingIDOnUI(int widget_routing_id) {
    routing_id_ = widget_routing_id;
    message_loop_runner_->Quit();
  }

  int routing_id_;
  scoped_refptr<MessageLoopRunner> message_loop_runner_;

  DISALLOW_COPY_AND_ASSIGN(PendingWidgetMessageFilter);
};

// Test for https://crbug.com/612276.  Simultaneously open two new windows from
// two subframes in different processes, where each subframe process's next
// routing ID is the same.  Make sure that both windows are created properly.
//
// Each new window requires two IPCs to first create it (handled by
// CreateNewWindow) and then show it (ShowCreatedWindow).  In the bug, both
// CreateNewWindow calls arrived before the ShowCreatedWindow calls, resulting
// in the two pending windows colliding in the pending WebContents map, which
// used to be keyed only by routing_id.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       TwoSubframesCreatePopupsSimultaneously) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,c)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child1 = root->child_at(0);
  FrameTreeNode* child2 = root->child_at(1);
  RenderProcessHost* process1 = child1->current_frame_host()->GetProcess();
  RenderProcessHost* process2 = child2->current_frame_host()->GetProcess();

  // Call window.open simultaneously in both subframes to create two popups.
  // Wait for and then drop both FrameHostMsg_ShowCreatedWindow messages.  This
  // will ensure that both CreateNewWindow calls happen before either
  // ShowCreatedWindow call.
  scoped_refptr<PendingWidgetMessageFilter> filter1 =
      new PendingWidgetMessageFilter();
  process1->AddFilter(filter1.get());
  EXPECT_TRUE(ExecuteScript(child1, "window.open();"));
  filter1->Wait();

  scoped_refptr<PendingWidgetMessageFilter> filter2 =
      new PendingWidgetMessageFilter();
  process2->AddFilter(filter2.get());
  EXPECT_TRUE(ExecuteScript(child2, "window.open();"));
  filter2->Wait();

  // At this point, we should have two pending WebContents.
  EXPECT_TRUE(base::ContainsKey(
      web_contents()->pending_contents_,
      std::make_pair(process1->GetID(), filter1->routing_id())));
  EXPECT_TRUE(base::ContainsKey(
      web_contents()->pending_contents_,
      std::make_pair(process2->GetID(), filter2->routing_id())));

  // Both subframes were set up in the same way, so the next routing ID for the
  // new popup windows should match up (this led to the collision in the
  // pending contents map in the original bug).
  EXPECT_EQ(filter1->routing_id(), filter2->routing_id());

  // Now, simulate that both FrameHostMsg_ShowCreatedWindow messages arrive by
  // showing both of the pending WebContents.
  web_contents()->ShowCreatedWindow(process1->GetID(), filter1->routing_id(),
                                    WindowOpenDisposition::NEW_FOREGROUND_TAB,
                                    gfx::Rect(), true);
  web_contents()->ShowCreatedWindow(process2->GetID(), filter2->routing_id(),
                                    WindowOpenDisposition::NEW_FOREGROUND_TAB,
                                    gfx::Rect(), true);

  // Verify that both shells were properly created.
  EXPECT_EQ(3u, Shell::windows().size());
}

// Test for https://crbug.com/612276.  Similar to
// TwoSubframesOpenWindowsSimultaneously, but use popup menu widgets instead of
// windows.
//
// The plumbing that this test is verifying is not utilized on Mac/Android,
// where popup menus don't create a popup RenderWidget, but rather they trigger
// a FrameHostMsg_ShowPopup to ask the browser to build and display the actual
// popup using native controls.
#if !defined(OS_MACOSX) && !defined(OS_ANDROID)
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       TwoSubframesCreatePopupMenuWidgetsSimultaneously) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,c)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child1 = root->child_at(0);
  FrameTreeNode* child2 = root->child_at(1);
  RenderProcessHost* process1 = child1->current_frame_host()->GetProcess();
  RenderProcessHost* process2 = child2->current_frame_host()->GetProcess();

  // Navigate both subframes to a page with a <select> element.
  NavigateFrameToURL(child1, embedded_test_server()->GetURL(
      "b.com", "/site_isolation/page-with-select.html"));
  NavigateFrameToURL(child2, embedded_test_server()->GetURL(
      "c.com", "/site_isolation/page-with-select.html"));

  // Open both <select> menus by focusing each item and sending a space key
  // at the focused node. This creates a popup widget in both processes.
  // Wait for and then drop the ViewHostMsg_ShowWidget messages, so that both
  // widgets are left in pending-but-not-shown state.
  NativeWebKeyboardEvent event(
      blink::WebKeyboardEvent::kChar, blink::WebInputEvent::kNoModifiers,
      blink::WebInputEvent::GetStaticTimeStampForTests());
  event.text[0] = ' ';

  scoped_refptr<PendingWidgetMessageFilter> filter1 =
      new PendingWidgetMessageFilter();
  process1->AddFilter(filter1.get());
  EXPECT_TRUE(ExecuteScript(child1, "focusSelectMenu();"));
  child1->current_frame_host()->GetRenderWidgetHost()->ForwardKeyboardEvent(
      event);
  filter1->Wait();

  scoped_refptr<PendingWidgetMessageFilter> filter2 =
      new PendingWidgetMessageFilter();
  process2->AddFilter(filter2.get());
  EXPECT_TRUE(ExecuteScript(child2, "focusSelectMenu();"));
  child2->current_frame_host()->GetRenderWidgetHost()->ForwardKeyboardEvent(
      event);
  filter2->Wait();

  // At this point, we should have two pending widgets.
  EXPECT_TRUE(base::ContainsKey(
      web_contents()->pending_widget_views_,
      std::make_pair(process1->GetID(), filter1->routing_id())));
  EXPECT_TRUE(base::ContainsKey(
      web_contents()->pending_widget_views_,
      std::make_pair(process2->GetID(), filter2->routing_id())));

  // Both subframes were set up in the same way, so the next routing ID for the
  // new popup widgets should match up (this led to the collision in the
  // pending widgets map in the original bug).
  EXPECT_EQ(filter1->routing_id(), filter2->routing_id());

  // Now simulate both widgets being shown.
  web_contents()->ShowCreatedWidget(process1->GetID(), filter1->routing_id(),
                                    false, gfx::Rect());
  web_contents()->ShowCreatedWidget(process2->GetID(), filter2->routing_id(),
                                    false, gfx::Rect());
  EXPECT_FALSE(base::ContainsKey(
      web_contents()->pending_widget_views_,
      std::make_pair(process1->GetID(), filter1->routing_id())));
  EXPECT_FALSE(base::ContainsKey(
      web_contents()->pending_widget_views_,
      std::make_pair(process2->GetID(), filter2->routing_id())));
}
#endif

// Test for https://crbug.com/615575. It ensures that file chooser triggered
// by a document in an out-of-process subframe works properly.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, FileChooserInSubframe) {
  EXPECT_TRUE(NavigateToURL(shell(), embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)")));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  GURL url(embedded_test_server()->GetURL("b.com", "/file_input.html"));
  NavigateFrameToURL(root->child_at(0), url);

  // Use FileChooserDelegate to avoid showing the actual dialog and to respond
  // back to the renderer process with predefined file.
  base::FilePath file;
  EXPECT_TRUE(PathService::Get(base::DIR_TEMP, &file));
  file = file.AppendASCII("bar");
  std::unique_ptr<FileChooserDelegate> delegate(new FileChooserDelegate(file));
  shell()->web_contents()->SetDelegate(delegate.get());
  EXPECT_TRUE(ExecuteScript(root->child_at(0),
                            "document.getElementById('fileinput').click();"));
  EXPECT_TRUE(delegate->file_chosen());

  // Also, extract the file from the renderer process to ensure that the
  // response made it over successfully and the proper filename is set.
  std::string file_name;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      root->child_at(0),
      "window.domAutomationController.send("
      "document.getElementById('fileinput').files[0].name);",
      &file_name));
  EXPECT_EQ("bar", file_name);
}

// Tests that an out-of-process iframe receives the visibilitychange event.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, VisibilityChange) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  EXPECT_TRUE(ExecuteScript(
      root->child_at(0)->current_frame_host(),
      "var event_fired = 0;\n"
      "document.addEventListener('visibilitychange',\n"
      "                          function() { event_fired++; });\n"));

  shell()->web_contents()->WasHidden();

  int event_fired = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root->child_at(0)->current_frame_host(),
      "window.domAutomationController.send(event_fired);", &event_fired));
  EXPECT_EQ(1, event_fired);

  shell()->web_contents()->WasShown();

  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root->child_at(0)->current_frame_host(),
      "window.domAutomationController.send(event_fired);", &event_fired));
  EXPECT_EQ(2, event_fired);
}

// Test that the pending RenderFrameHost is canceled and destroyed when its
// process dies. Previously, reusing a top-level pending RFH which
// is not live was hitting a CHECK in CreateRenderView due to having neither a
// main frame routing ID nor a proxy routing ID.  See https://crbug.com/627400
// for more details.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       PendingRFHIsCanceledWhenItsProcessDies) {
  GURL main_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Open a popup at b.com.
  GURL popup_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  Shell* popup_shell = OpenPopup(root, popup_url, "foo");
  EXPECT_TRUE(popup_shell);

  // The RenderViewHost for b.com in the main tab should not be active.
  SiteInstance* b_instance = popup_shell->web_contents()->GetSiteInstance();
  RenderViewHostImpl* rvh =
      web_contents()->GetFrameTree()->GetRenderViewHost(b_instance);
  EXPECT_FALSE(rvh->is_active());

  // Navigate main tab to a b.com URL that will not commit.
  GURL stall_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  TestNavigationManager delayer(shell()->web_contents(), stall_url);
  EXPECT_TRUE(ExecuteScript(shell(), "location = '" + stall_url.spec() + "'"));
  EXPECT_TRUE(delayer.WaitForRequestStart());

  // The pending RFH should be in the same process as the popup.
  RenderFrameHostImpl* pending_rfh =
      root->render_manager()->speculative_frame_host();
  RenderProcessHost* pending_process = pending_rfh->GetProcess();
  EXPECT_EQ(pending_process,
            popup_shell->web_contents()->GetMainFrame()->GetProcess());

  // Kill the b.com process, currently in use by the pending RenderFrameHost
  // and the popup.
  RenderProcessHostWatcher crash_observer(
      pending_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  EXPECT_TRUE(pending_process->Shutdown(0));
  crash_observer.Wait();

  // The pending RFH should have been canceled and destroyed, so that it won't
  // be reused while it's not live in the next navigation.
  {
    RenderFrameHostImpl* pending_rfh =
        root->render_manager()->speculative_frame_host();
    EXPECT_FALSE(pending_rfh);
  }

  // Navigate main tab to b.com again.  This should not crash.
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title3.html"));
  EXPECT_TRUE(NavigateToURLFromRenderer(shell(), b_url));

  // The b.com RVH in the main tab should become active.
  EXPECT_TRUE(rvh->is_active());
}

// Test that killing a pending RenderFrameHost's process doesn't leave its
// RenderViewHost confused whether it's active or not for future navigations
// that try to reuse it.  See https://crbug.com/627893 for more details.
// Similar to the test above for https://crbug.com/627400, except the popup is
// navigated after pending RFH's process is killed, rather than the main tab.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       RenderViewHostKeepsSwappedOutStateIfPendingRFHDies) {
  GURL main_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Open a popup at b.com.
  GURL popup_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  Shell* popup_shell = OpenPopup(root, popup_url, "foo");
  EXPECT_TRUE(popup_shell);

  // The RenderViewHost for b.com in the main tab should not be active.
  SiteInstance* b_instance = popup_shell->web_contents()->GetSiteInstance();
  RenderViewHostImpl* rvh =
      web_contents()->GetFrameTree()->GetRenderViewHost(b_instance);
  EXPECT_FALSE(rvh->is_active());

  // Navigate main tab to a b.com URL that will not commit.
  GURL stall_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  NavigationHandleObserver handle_observer(shell()->web_contents(), stall_url);
  TestNavigationManager delayer(shell()->web_contents(), stall_url);
  EXPECT_TRUE(ExecuteScript(shell(), "location = '" + stall_url.spec() + "'"));
  EXPECT_TRUE(delayer.WaitForRequestStart());

  // Kill the b.com process, currently in use by the pending RenderFrameHost
  // and the popup.
  RenderProcessHost* pending_process =
      popup_shell->web_contents()->GetMainFrame()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      pending_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  EXPECT_TRUE(pending_process->Shutdown(0));
  crash_observer.Wait();

  // Since the navigation above didn't commit, the b.com RenderViewHost in the
  // main tab should still not be active.
  EXPECT_FALSE(rvh->is_active());
  EXPECT_EQ(net::ERR_ABORTED, handle_observer.net_error_code());

  // Navigate popup to b.com to recreate the b.com process.  When creating
  // opener proxies, |rvh| should be reused as a swapped out RVH.  In
  // https://crbug.com/627893, recreating the opener RenderView was hitting a
  // CHECK(params.swapped_out) in the renderer process, since its
  // RenderViewHost was brought into an active state by the navigation to
  // |stall_url| above, even though it never committed.
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title3.html"));
  EXPECT_TRUE(NavigateToURLInSameBrowsingInstance(popup_shell, b_url));
  EXPECT_FALSE(rvh->is_active());
}

// Test that a crashed subframe can be successfully navigated to the site it
// was on before crashing.  See https://crbug.com/634368.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigateCrashedSubframeToSameSite) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);

  // Set up a postMessage handler in the main frame for later use.
  EXPECT_TRUE(ExecuteScript(
      root->current_frame_host(),
      "window.addEventListener('message',"
      "                        function(e) { document.title = e.data; });"));

  // Crash the subframe process.
  RenderProcessHost* child_process = child->current_frame_host()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      child_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  child_process->Shutdown(0);
  crash_observer.Wait();
  EXPECT_FALSE(child->current_frame_host()->IsRenderFrameLive());

  // When the subframe dies, its RenderWidgetHostView should be cleared and
  // reset in the CrossProcessFrameConnector.
  EXPECT_FALSE(child->current_frame_host()->GetView());
  RenderFrameProxyHost* proxy_to_parent =
      child->render_manager()->GetProxyToParent();
  EXPECT_FALSE(
      proxy_to_parent->cross_process_frame_connector()->get_view_for_testing());

  // Navigate the subframe to the same site it was on before crashing.  This
  // should reuse the subframe's current RenderFrameHost and reinitialize the
  // RenderFrame in a new process.
  NavigateFrameToURL(child,
                     embedded_test_server()->GetURL("b.com", "/title1.html"));
  EXPECT_TRUE(child->current_frame_host()->IsRenderFrameLive());

  // The RenderWidgetHostView for the child should be recreated and set to be
  // used in the CrossProcessFrameConnector.  Without this, the frame won't be
  // rendered properly.
  EXPECT_TRUE(child->current_frame_host()->GetView());
  EXPECT_EQ(
      child->current_frame_host()->GetView(),
      proxy_to_parent->cross_process_frame_connector()->get_view_for_testing());

  // Make sure that the child frame has submitted a compositor frame.
  WaitForChildFrameSurfaceReady(child->current_frame_host());

  // Send a postMessage from the child to its parent.  This verifies that the
  // parent's proxy in the child's SiteInstance was also restored.
  base::string16 expected_title(base::UTF8ToUTF16("I am alive!"));
  TitleWatcher title_watcher(shell()->web_contents(), expected_title);
  EXPECT_TRUE(ExecuteScript(child->current_frame_host(),
                            "parent.postMessage('I am alive!', '*');"));
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());
}

// Test that session history length and offset are replicated to all renderer
// processes in a FrameTree.  This allows each renderer to see correct values
// for history.length, and to check the offset validity properly for
// navigations initiated via history.go(). See https:/crbug.com/501116.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, SessionHistoryReplication) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child1 = root->child_at(0);
  FrameTreeNode* child2 = root->child_at(1);
  GURL child_first_url(child1->current_url());
  EXPECT_EQ(child1->current_url(), child2->current_url());

  // Helper to retrieve the history length from a given frame.
  auto history_length = [](FrameTreeNode* ftn) {
    int history_length = -1;
    EXPECT_TRUE(ExecuteScriptAndExtractInt(
        ftn->current_frame_host(),
        "window.domAutomationController.send(history.length);",
        &history_length));
    return history_length;
  };

  // All frames should see a history length of 1 to start with.
  EXPECT_EQ(1, history_length(root));
  EXPECT_EQ(1, history_length(child1));
  EXPECT_EQ(1, history_length(child2));

  // Navigate first child cross-site.  This increases history length to 2.
  NavigateFrameToURL(child1,
                     embedded_test_server()->GetURL("b.com", "/title1.html"));
  EXPECT_EQ(2, history_length(root));
  EXPECT_EQ(2, history_length(child1));
  EXPECT_EQ(2, history_length(child2));

  // Navigate second child same-site.
  GURL child2_last_url(embedded_test_server()->GetURL("a.com", "/title2.html"));
  NavigateFrameToURL(child2, child2_last_url);
  EXPECT_EQ(3, history_length(root));
  EXPECT_EQ(3, history_length(child1));
  EXPECT_EQ(3, history_length(child2));

  // Navigate first child same-site to another b.com URL.
  GURL child1_last_url(embedded_test_server()->GetURL("b.com", "/title3.html"));
  NavigateFrameToURL(child1, child1_last_url);
  EXPECT_EQ(4, history_length(root));
  EXPECT_EQ(4, history_length(child1));
  EXPECT_EQ(4, history_length(child2));

  // Go back three entries using the history API from the main frame. This
  // checks that both history length and offset are not stale in a.com, as
  // otherwise this navigation might be dropped by Blink.
  EXPECT_TRUE(ExecuteScript(root, "history.go(-3);"));
  EXPECT_TRUE(WaitForLoadStop(shell()->web_contents()));
  EXPECT_EQ(main_url, root->current_url());
  EXPECT_EQ(child_first_url, child1->current_url());
  EXPECT_EQ(child_first_url, child2->current_url());

  // Now go forward three entries from the child1 frame and check that the
  // history length and offset are not stale in b.com.
  EXPECT_TRUE(ExecuteScript(child1, "history.go(3);"));
  EXPECT_TRUE(WaitForLoadStop(shell()->web_contents()));
  EXPECT_EQ(main_url, root->current_url());
  EXPECT_EQ(child1_last_url, child1->current_url());
  EXPECT_EQ(child2_last_url, child2->current_url());
}

// A BrowserMessageFilter that drops FrameHostMsg_OnDispatchLoad messages.
class DispatchLoadMessageFilter : public BrowserMessageFilter {
 public:
  DispatchLoadMessageFilter() : BrowserMessageFilter(FrameMsgStart) {}

 protected:
  ~DispatchLoadMessageFilter() override {}

 private:
  // BrowserMessageFilter:
  bool OnMessageReceived(const IPC::Message& message) override {
    return message.type() == FrameHostMsg_DispatchLoad::ID;
  }

  DISALLOW_COPY_AND_ASSIGN(DispatchLoadMessageFilter);
};

// Test that the renderer isn't killed when a frame generates a load event just
// after becoming pending deletion.  See https://crbug.com/636513.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       LoadEventForwardingWhilePendingDeletion) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);

  // Open a popup in the b.com process for later use.
  GURL popup_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  Shell* popup_shell = OpenPopup(root, popup_url, "foo");
  EXPECT_TRUE(popup_shell);

  // Install a filter to drop DispatchLoad messages from b.com.
  scoped_refptr<DispatchLoadMessageFilter> filter =
      new DispatchLoadMessageFilter();
  RenderProcessHost* b_process =
      popup_shell->web_contents()->GetMainFrame()->GetProcess();
  b_process->AddFilter(filter.get());

  // Navigate subframe to b.com.  Wait for commit but not full load.
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  {
    TestFrameNavigationObserver commit_observer(child);
    EXPECT_TRUE(
        ExecuteScript(child, "location.href = '" + b_url.spec() + "';"));
    commit_observer.WaitForCommit();
  }
  RenderFrameHostImpl* child_rfh = child->current_frame_host();
  child_rfh->DisableSwapOutTimerForTesting();

  // At this point, the subframe should have a proxy in its parent's
  // SiteInstance, a.com.
  EXPECT_TRUE(child->render_manager()->GetProxyToParent());

  // Now, go back to a.com in the subframe and wait for commit.
  {
    TestFrameNavigationObserver commit_observer(child);
    web_contents()->GetController().GoBack();
    commit_observer.WaitForCommit();
  }

  // At this point, the subframe's old RFH for b.com should be pending
  // deletion, and the subframe's proxy in a.com should've been cleared.
  EXPECT_FALSE(child_rfh->is_active());
  EXPECT_FALSE(child->render_manager()->GetProxyToParent());

  // Simulate that the load event is dispatched from |child_rfh| just after
  // it's become pending deletion.
  child_rfh->OnDispatchLoad();

  // In the bug, OnDispatchLoad killed the b.com renderer.  Ensure that this is
  // not the case. Note that the process kill doesn't happen immediately, so
  // IsRenderFrameLive() can't be checked here (yet).  Instead, check that
  // JavaScript can still execute in b.com using the popup.
  EXPECT_TRUE(ExecuteScript(popup_shell->web_contents(), "true"));
}

// Tests that trying to navigate in the unload handler doesn't crash the
// browser.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, NavigateInUnloadHandler) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b(b))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "        +--Site B -- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  int child_count = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root->child_at(0)->current_frame_host(),
      "window.domAutomationController.send(frames.length);", &child_count));
  EXPECT_EQ(1, child_count);

  // Add an unload handler to B's subframe.
  EXPECT_TRUE(
      ExecuteScript(root->child_at(0)->child_at(0)->current_frame_host(),
                    "window.onunload=function(e){\n"
                    "    window.location = '#navigate';\n"
                    "};\n"));

  // Navigate B's subframe to a cross-site C.
  RenderFrameDeletedObserver deleted_observer(
      root->child_at(0)->child_at(0)->current_frame_host());
  std::string script =
      std::string("window.document.getElementById('child-0').src = \"") +
      embedded_test_server()
          ->GetURL("c.com", "/cross_site_iframe_factory.html")
          .spec() +
      "\"";
  EXPECT_TRUE(
      ExecuteScript(root->child_at(0)->current_frame_host(), script.c_str()));

  // Wait until B's subframe RenderFrameHost is destroyed.
  deleted_observer.WaitUntilDeleted();

  // Check that C's subframe is alive and the navigation in the unload handler
  // was ignored.
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root->child_at(0)->child_at(0)->current_frame_host(),
      "window.domAutomationController.send(frames.length);", &child_count));
  EXPECT_EQ(0, child_count);

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   +--Site B ------- proxies for A C\n"
      "        +--Site C -- proxies for A B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/\n"
      "      C = http://c.com/",
      DepictFrameTree(root));
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       RFHTransfersWhilePendingDeletion) {
  GURL main_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  // Start a cross-process navigation and wait until the response is received.
  GURL cross_site_url_1 =
      embedded_test_server()->GetURL("b.com", "/title1.html");
  TestNavigationManager cross_site_manager(shell()->web_contents(),
                                           cross_site_url_1);
  shell()->web_contents()->GetController().LoadURL(
      cross_site_url_1, Referrer(), ui::PAGE_TRANSITION_LINK, std::string());
  EXPECT_TRUE(cross_site_manager.WaitForResponse());

  // Start a renderer-initiated navigation to a cross-process url and make sure
  // the navigation will be blocked before being transferred.
  GURL cross_site_url_2 =
      embedded_test_server()->GetURL("c.com", "/title1.html");
  TestNavigationManager transfer_manager(shell()->web_contents(),
                                         cross_site_url_2);
  EXPECT_TRUE(ExecuteScript(
      root, "location.href = '" + cross_site_url_2.spec() + "';"));
  EXPECT_TRUE(transfer_manager.WaitForResponse());

  // Now have the cross-process navigation commit and mark the current RFH as
  // pending deletion.
  cross_site_manager.WaitForNavigationFinished();

  // Resume the navigation in the previous RFH that has just been marked as
  // pending deletion. We should not crash.
  transfer_manager.WaitForNavigationFinished();
}

class NavigationHandleWatcher : public WebContentsObserver {
 public:
  explicit NavigationHandleWatcher(WebContents* web_contents)
      : WebContentsObserver(web_contents) {}
  void DidStartNavigation(NavigationHandle* navigation_handle) override {
    DCHECK_EQ(GURL("http://b.com/"),
              navigation_handle->GetStartingSiteInstance()->GetSiteURL());
  }
};

// Verifies that the SiteInstance of a NavigationHandle correctly identifies the
// RenderFrameHost that started the navigation (and not the destination RFH).
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NavigationHandleSiteInstance) {
  // Navigate to a page with a cross-site iframe.
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Navigate the iframe cross-site.
  NavigationHandleWatcher watcher(shell()->web_contents());
  TestNavigationObserver load_observer(shell()->web_contents());
  GURL frame_url = embedded_test_server()->GetURL("c.com", "/title1.html");
  EXPECT_TRUE(ExecuteScript(
      shell()->web_contents(),
      "window.frames[0].location = \"" + frame_url.spec() + "\";"));
  load_observer.Wait();
}

// Test that when canceling a pending RenderFrameHost in the middle of a
// redirect, and then killing the corresponding RenderView's renderer process,
// the RenderViewHost isn't reused in an improper state later.  Previously this
// led to a crash in CreateRenderView when recreating the RenderView due to a
// stale main frame routing ID.  See https://crbug.com/627400.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ReuseNonLiveRenderViewHostAfterCancelPending) {
  GURL a_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  GURL c_url(embedded_test_server()->GetURL("c.com", "/title3.html"));

  EXPECT_TRUE(NavigateToURL(shell(), a_url));

  // Open a popup and navigate it to b.com.
  Shell* popup = OpenPopup(shell(), a_url, "popup");
  EXPECT_TRUE(NavigateToURLFromRenderer(popup, b_url));

  // Open a second popup and navigate it to b.com, which redirects to c.com.
  // The navigation to b.com will create a pending RenderFrameHost, which will
  // be canceled during the redirect to c.com.  Note that
  // NavigateToURLFromRenderer will return false because the committed URL
  // won't match the requested URL due to the redirect.
  Shell* popup2 = OpenPopup(shell(), a_url, "popup2");
  TestNavigationObserver observer(popup2->web_contents());
  GURL redirect_url(embedded_test_server()->GetURL(
      "b.com", "/server-redirect?" + c_url.spec()));
  EXPECT_FALSE(NavigateToURLFromRenderer(popup2, redirect_url));
  EXPECT_EQ(c_url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());

  // Kill the b.com process (which currently hosts a RenderFrameProxy that
  // replaced the pending RenderFrame in |popup2|, as well as the RenderFrame
  // for |popup|).
  RenderProcessHost* b_process =
      popup->web_contents()->GetMainFrame()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      b_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  b_process->Shutdown(0);
  crash_observer.Wait();

  // Navigate the second popup to b.com.  This used to crash when creating the
  // RenderView, because it reused the RenderViewHost created by the canceled
  // navigation to b.com, and that RenderViewHost had a stale main frame
  // routing ID and active state.
  EXPECT_TRUE(NavigateToURLInSameBrowsingInstance(popup2, b_url));
}

// Check that after a pending RFH is canceled and replaced with a proxy (which
// reuses the canceled RFH's RenderViewHost), navigating to a main frame in the
// same site as the canceled RFH doesn't lead to a renderer crash.  The steps
// here are similar to ReuseNonLiveRenderViewHostAfterCancelPending, but don't
// involve crashing the renderer. See https://crbug.com/651980.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       RecreateMainFrameAfterCancelPending) {
  GURL a_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  GURL c_url(embedded_test_server()->GetURL("c.com", "/title3.html"));

  EXPECT_TRUE(NavigateToURL(shell(), a_url));

  // Open a popup and navigate it to b.com.
  Shell* popup = OpenPopup(shell(), a_url, "popup");
  EXPECT_TRUE(NavigateToURLFromRenderer(popup, b_url));

  // Open a second popup and navigate it to b.com, which redirects to c.com.
  // The navigation to b.com will create a pending RenderFrameHost, which will
  // be canceled during the redirect to c.com.  Note that NavigateToURL will
  // return false because the committed URL won't match the requested URL due
  // to the redirect.
  Shell* popup2 = OpenPopup(shell(), a_url, "popup2");
  TestNavigationObserver observer(popup2->web_contents());
  GURL redirect_url(embedded_test_server()->GetURL(
      "b.com", "/server-redirect?" + c_url.spec()));
  EXPECT_FALSE(NavigateToURLFromRenderer(popup2, redirect_url));
  EXPECT_EQ(c_url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());

  // Navigate the second popup to b.com.  This used to crash the b.com renderer
  // because it failed to delete the canceled RFH's RenderFrame, so this caused
  // it to try to create a frame widget which already existed.
  EXPECT_TRUE(NavigateToURLFromRenderer(popup2, b_url));
}

// Check that when a pending RFH is canceled and a proxy needs to be created in
// its place, the proxy is properly initialized on the renderer side.  See
// https://crbug.com/653746.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CommunicateWithProxyAfterCancelPending) {
  GURL a_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  GURL c_url(embedded_test_server()->GetURL("c.com", "/title3.html"));

  EXPECT_TRUE(NavigateToURL(shell(), a_url));

  // Open a popup and navigate it to b.com.
  Shell* popup = OpenPopup(shell(), a_url, "popup");
  EXPECT_TRUE(NavigateToURLFromRenderer(popup, b_url));

  // Open a second popup and navigate it to b.com, which redirects to c.com.
  // The navigation to b.com will create a pending RenderFrameHost, which will
  // be canceled during the redirect to c.com.  Note that NavigateToURL will
  // return false because the committed URL won't match the requested URL due
  // to the redirect.
  Shell* popup2 = OpenPopup(shell(), a_url, "popup2");
  TestNavigationObserver observer(popup2->web_contents());
  GURL redirect_url(embedded_test_server()->GetURL(
      "b.com", "/server-redirect?" + c_url.spec()));
  EXPECT_FALSE(NavigateToURLFromRenderer(popup2, redirect_url));
  EXPECT_EQ(c_url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());

  // Because b.com has other active frames (namely, the frame in |popup|),
  // there should be a proxy created for the canceled RFH, and it should be
  // live.
  SiteInstance* b_instance = popup->web_contents()->GetSiteInstance();
  FrameTreeNode* popup2_root =
      static_cast<WebContentsImpl*>(popup2->web_contents())
          ->GetFrameTree()
          ->root();
  RenderFrameProxyHost* proxy =
      popup2_root->render_manager()->GetRenderFrameProxyHost(b_instance);
  EXPECT_TRUE(proxy);
  EXPECT_TRUE(proxy->is_render_frame_proxy_live());

  // Add a postMessage listener in |popup2| (currently at a c.com URL).
  EXPECT_TRUE(
      ExecuteScript(popup2,
                    "window.addEventListener('message', function(event) {\n"
                    "  document.title=event.data;\n"
                    "});"));

  // Check that a postMessage can be sent via |proxy| above.  This needs to be
  // done from the b.com process.  |popup| is currently in b.com, but it can't
  // reach the window reference for |popup2| due to a security restriction in
  // Blink. So, navigate the main tab to b.com and then send a postMessage to
  // |popup2|. This is allowed since the main tab is |popup2|'s opener.
  EXPECT_TRUE(NavigateToURLFromRenderer(shell(), b_url));

  base::string16 expected_title(base::UTF8ToUTF16("foo"));
  TitleWatcher title_watcher(popup2->web_contents(), expected_title);
  EXPECT_TRUE(ExecuteScript(
      shell(), "window.open('','popup2').postMessage('foo', '*');"));
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       TestFeaturePolicyReplicationOnSameOriginNavigation) {
  GURL start_url(
      embedded_test_server()->GetURL("a.com", "/feature-policy1.html"));
  GURL first_nav_url(
      embedded_test_server()->GetURL("a.com", "/feature-policy2.html"));
  GURL second_nav_url(embedded_test_server()->GetURL("a.com", "/title2.html"));

  EXPECT_TRUE(NavigateToURL(shell(), start_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_EQ(CreateFPHeader(blink::mojom::FeaturePolicyFeature::kGeolocation,
                           {start_url.GetOrigin()}),
            root->current_replication_state().feature_policy_header);

  // When the main frame navigates to a page with a new policy, it should
  // overwrite the old one.
  EXPECT_TRUE(NavigateToURL(shell(), first_nav_url));
  EXPECT_EQ(CreateFPHeaderMatchesAll(
                blink::mojom::FeaturePolicyFeature::kGeolocation),
            root->current_replication_state().feature_policy_header);

  // When the main frame navigates to a page without a policy, the replicated
  // policy header should be cleared.
  EXPECT_TRUE(NavigateToURL(shell(), second_nav_url));
  EXPECT_TRUE(root->current_replication_state().feature_policy_header.empty());
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       TestFeaturePolicyReplicationOnCrossOriginNavigation) {
  GURL start_url(
      embedded_test_server()->GetURL("a.com", "/feature-policy1.html"));
  GURL first_nav_url(
      embedded_test_server()->GetURL("b.com", "/feature-policy2.html"));
  GURL second_nav_url(embedded_test_server()->GetURL("c.com", "/title2.html"));

  EXPECT_TRUE(NavigateToURL(shell(), start_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_EQ(CreateFPHeader(blink::mojom::FeaturePolicyFeature::kGeolocation,
                           {start_url.GetOrigin()}),
            root->current_replication_state().feature_policy_header);

  // When the main frame navigates to a page with a new policy, it should
  // overwrite the old one.
  EXPECT_TRUE(NavigateToURL(shell(), first_nav_url));
  EXPECT_EQ(CreateFPHeaderMatchesAll(
                blink::mojom::FeaturePolicyFeature::kGeolocation),
            root->current_replication_state().feature_policy_header);

  // When the main frame navigates to a page without a policy, the replicated
  // policy header should be cleared.
  EXPECT_TRUE(NavigateToURL(shell(), second_nav_url));
  EXPECT_TRUE(root->current_replication_state().feature_policy_header.empty());
}

// Test that the replicated feature policy header is correct in subframes as
// they navigate.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       TestFeaturePolicyReplicationFromRemoteFrames) {
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/feature-policy-main.html"));
  GURL first_nav_url(
      embedded_test_server()->GetURL("b.com", "/feature-policy2.html"));
  GURL second_nav_url(embedded_test_server()->GetURL("c.com", "/title2.html"));

  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_EQ(CreateFPHeader(blink::mojom::FeaturePolicyFeature::kGeolocation,
                           {main_url.GetOrigin(), GURL("http://example.com/")}),
            root->current_replication_state().feature_policy_header);
  EXPECT_EQ(1UL, root->child_count());
  EXPECT_EQ(
      CreateFPHeader(blink::mojom::FeaturePolicyFeature::kGeolocation,
                     {main_url.GetOrigin()}),
      root->child_at(0)->current_replication_state().feature_policy_header);

  // Navigate the iframe cross-site.
  NavigateFrameToURL(root->child_at(0), first_nav_url);
  EXPECT_EQ(
      CreateFPHeaderMatchesAll(
          blink::mojom::FeaturePolicyFeature::kGeolocation),
      root->child_at(0)->current_replication_state().feature_policy_header);

  // Navigate the iframe to another location, this one with no policy header
  NavigateFrameToURL(root->child_at(0), second_nav_url);
  EXPECT_TRUE(root->child_at(0)
                  ->current_replication_state()
                  .feature_policy_header.empty());

  // Navigate the iframe back to a page with a policy
  NavigateFrameToURL(root->child_at(0), first_nav_url);
  EXPECT_EQ(
      CreateFPHeaderMatchesAll(
          blink::mojom::FeaturePolicyFeature::kGeolocation),
      root->child_at(0)->current_replication_state().feature_policy_header);
}

// Test that the replicated feature policy header is correct in remote proxies
// after the local frame has navigated.
IN_PROC_BROWSER_TEST_F(SitePerProcessFeaturePolicyJavaScriptBrowserTest,
                       TestFeaturePolicyReplicationToProxyOnNavigation) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/page_with_two_frames.html"));
  GURL first_nav_url(
      embedded_test_server()->GetURL("a.com", "/feature-policy3.html"));
  GURL second_nav_url(
      embedded_test_server()->GetURL("a.com", "/feature-policy4.html"));

  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_TRUE(root->current_replication_state().feature_policy_header.empty());
  EXPECT_EQ(2UL, root->child_count());
  EXPECT_TRUE(root->child_at(1)
                  ->current_replication_state()
                  .feature_policy_header.empty());

  // Navigate the iframe to a page with a policy, and a nested cross-site iframe
  // (to the same site as a root->child_at(1) so that the render process already
  // exists.)
  NavigateFrameToURL(root->child_at(1), first_nav_url);
  EXPECT_EQ(
      CreateFPHeaderMatchesAll(
          blink::mojom::FeaturePolicyFeature::kGeolocation),
      root->child_at(1)->current_replication_state().feature_policy_header);

  EXPECT_EQ(1UL, root->child_at(1)->child_count());

  // Ask the deepest iframe to report the enabled state of the geolocation
  // feature. If its parent frame's policy was replicated correctly to the
  // proxy, then this will be enabled. Otherwise, it will be disabled, as
  // geolocation is disabled by default in cross-origin frames.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(1)->child_at(0),
      "window.domAutomationController.send("
      "document.policy.allowsFeature('geolocation'));",
      &success));
  EXPECT_TRUE(success);

  // Now navigate the iframe to a page with no policy, and the same nested
  // cross-site iframe. The policy should be cleared in the proxy.
  NavigateFrameToURL(root->child_at(1), second_nav_url);
  EXPECT_TRUE(root->child_at(1)
                  ->current_replication_state()
                  .feature_policy_header.empty());
  EXPECT_EQ(1UL, root->child_at(1)->child_count());

  // Ask the deepest iframe to report the enabled state of the geolocation
  // feature. If its parent frame's policy was replicated correctly to the
  // proxy, then this will now be disabled.
  success = true;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(1)->child_at(0),
      "window.domAutomationController.send("
      "document.policy.allowsFeature('geolocation'));",
      &success));
  EXPECT_FALSE(success);
}

// Test that the constructed feature policy is correct in sandboxed
// frames. Sandboxed frames have an opaque origin, and if the frame policy,
// which is constructed in the parent frame, cannot send that origin through
// the browser process to the sandboxed frame, then the sandboxed frame's
// policy will be incorrect.
//
// This is a regression test for https://crbug.com/690520
IN_PROC_BROWSER_TEST_F(SitePerProcessFeaturePolicyJavaScriptBrowserTest,
                       TestAllowAttributeInSandboxedFrame) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com",
      "/cross_site_iframe_factory.html?"
      "a(b{allow-geolocation,sandbox-allow-scripts})"));
  GURL nav_url(embedded_test_server()->GetURL("c.com", "/title1.html"));

  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_TRUE(root->current_replication_state().feature_policy_header.empty());
  EXPECT_EQ(1UL, root->child_count());
  // Verify that the child frame is sandboxed with an opaque origin.
  EXPECT_TRUE(root->child_at(0)
                  ->current_frame_host()
                  ->GetLastCommittedOrigin()
                  .unique());
  // And verify that the origin in the replication state is also opaque.
  EXPECT_TRUE(root->child_at(0)->current_origin().unique());

  // Ask the sandboxed iframe to report the enabled state of the geolocation
  // feature. If the declared policy was correctly flagged as referring to the
  // opaque origin, then the policy in the sandboxed renderer will be
  // constructed correctly, and geolocation will be enabled in the sandbox.
  // Otherwise, it will be disabled, as geolocation is disabled by default in
  // cross-origin frames.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0),
      "window.domAutomationController.send("
      "document.policy.allowsFeature('geolocation'));",
      &success));
  EXPECT_TRUE(success);

  TestNavigationObserver load_observer(shell()->web_contents());
  EXPECT_TRUE(ExecuteScript(
      root->child_at(0), "document.location.href=\"" + nav_url.spec() + "\""));
  load_observer.Wait();

  // Verify that the child frame is sandboxed with an opaque origin.
  EXPECT_TRUE(root->child_at(0)
                  ->current_frame_host()
                  ->GetLastCommittedOrigin()
                  .unique());
  // And verify that the origin in the replication state is also opaque.
  EXPECT_TRUE(root->child_at(0)->current_origin().unique());

  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0),
      "window.domAutomationController.send("
      "document.policy.allowsFeature('geolocation'));",
      &success));
  EXPECT_TRUE(success);
}

// Test that the constructed feature policy is correct in sandboxed
// frames. Sandboxed frames have an opaque origin, and if the frame policy,
// which is constructed in the parent frame, cannot send that origin through
// the browser process to the sandboxed frame, then the sandboxed frame's
// policy will be incorrect.
//
// This is a regression test for https://crbug.com/690520
IN_PROC_BROWSER_TEST_F(SitePerProcessFeaturePolicyJavaScriptBrowserTest,
                       TestAllowAttributeInOpaqueOriginAfterNavigation) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/page_with_data_iframe_and_allow.html"));
  GURL nav_url(embedded_test_server()->GetURL("c.com", "/title1.html"));

  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_TRUE(root->current_replication_state().feature_policy_header.empty());
  EXPECT_EQ(1UL, root->child_count());
  // Verify that the child frame has an opaque origin.
  EXPECT_TRUE(root->child_at(0)
                  ->current_frame_host()
                  ->GetLastCommittedOrigin()
                  .unique());
  // And verify that the origin in the replication state is also opaque.
  EXPECT_TRUE(root->child_at(0)->current_origin().unique());

  // Verify that geolocation is enabled in the document.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0),
      "window.domAutomationController.send("
      "document.policy.allowsFeature('geolocation'));",
      &success));
  EXPECT_TRUE(success);

  TestNavigationObserver load_observer(shell()->web_contents());
  EXPECT_TRUE(ExecuteScript(
      root->child_at(0), "document.location.href=\"" + nav_url.spec() + "\""));
  load_observer.Wait();

  // Verify that the child frame no longer has an opaque origin.
  EXPECT_FALSE(root->child_at(0)
                   ->current_frame_host()
                   ->GetLastCommittedOrigin()
                   .unique());
  // Verify that the origin in the replication state is also no longer opaque.
  EXPECT_FALSE(root->child_at(0)->current_origin().unique());

  // Verify that the new document does not have geolocation enabled.
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0),
      "window.domAutomationController.send("
      "document.policy.allowsFeature('geolocation'));",
      &success));
  EXPECT_FALSE(success);
}

// Ensure that an iframe that navigates cross-site doesn't use the same process
// as its parent. Then when its parent navigates it via the "srcdoc" attribute,
// it must reuse its parent's process.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       IframeSrcdocAfterCrossSiteNavigation) {
  GURL parent_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  GURL child_url(embedded_test_server()->GetURL(
      "b.com", "/cross_site_iframe_factory.html?b()"));
  GURL srcdoc_url(kAboutSrcDocURL);

  // #1 Navigate to a page with a cross-site iframe.
  EXPECT_TRUE(NavigateToURL(shell(), parent_url));

  // Ensure that the iframe uses its own process.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1u, root->child_count());
  FrameTreeNode* child = root->child_at(0);
  EXPECT_EQ(parent_url, root->current_url());
  EXPECT_EQ(child_url, child->current_url());
  EXPECT_NE(root->current_frame_host()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());
  EXPECT_NE(root->current_frame_host()->GetProcess(),
            child->current_frame_host()->GetProcess());

  // #2 Navigate the iframe to its srcdoc attribute.
  TestNavigationObserver load_observer(shell()->web_contents());
  EXPECT_TRUE(ExecuteScript(
      root, "document.getElementById('child-0').srcdoc = 'srcdoc content';"));
  load_observer.Wait();

  // Ensure that the iframe reuses its parent's process.
  EXPECT_EQ(srcdoc_url, child->current_url());
  EXPECT_EQ(root->current_frame_host()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());
  EXPECT_EQ(root->current_frame_host()->GetProcess(),
            child->current_frame_host()->GetProcess());
}

// Verify that a remote-to-local navigation in a crashed subframe works.  See
// https://crbug.com/487872.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       RemoteToLocalNavigationInCrashedSubframe) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);

  // Crash the subframe process.
  RenderProcessHost* child_process = child->current_frame_host()->GetProcess();
  {
    RenderProcessHostWatcher crash_observer(
        child_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
    child_process->Shutdown(0);
    crash_observer.Wait();
  }
  EXPECT_FALSE(child->current_frame_host()->IsRenderFrameLive());

  // Do a remote-to-local navigation of the child frame from the parent frame.
  TestFrameNavigationObserver frame_observer(child);
  GURL frame_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(ExecuteScript(root, "document.querySelector('iframe').src = '" +
                                      frame_url.spec() + "';\n"));
  frame_observer.Wait();

  EXPECT_TRUE(child->current_frame_host()->IsRenderFrameLive());
  EXPECT_FALSE(child->IsLoading());
  EXPECT_EQ(child->current_frame_host()->GetSiteInstance(),
            root->current_frame_host()->GetSiteInstance());

  // Ensure the subframe is correctly attached in the frame tree, and that it
  // has correct content.
  int child_count = 0;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      root, "window.domAutomationController.send(frames.length);",
      &child_count));
  EXPECT_EQ(1, child_count);

  std::string result;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      root,
      "window.domAutomationController.send(frames[0].document.body.innerText);",
      &result));
  EXPECT_EQ("This page has no title.", result);
}

// Tests that trying to open a context menu in the old RFH after commiting a
// navigation doesn't crash the browser. https://crbug.com/677266.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ContextMenuAfterCrossProcessNavigation) {
  // Navigate to a.com.
  EXPECT_TRUE(NavigateToURL(
      shell(), embedded_test_server()->GetURL("a.com", "/title1.html")));

  // Disable the swapout ACK and the swapout timer.
  RenderFrameHostImpl* rfh = static_cast<RenderFrameHostImpl*>(
      shell()->web_contents()->GetMainFrame());
  scoped_refptr<SwapoutACKMessageFilter> filter = new SwapoutACKMessageFilter();
  rfh->GetProcess()->AddFilter(filter.get());
  rfh->DisableSwapOutTimerForTesting();

  // Open a popup on a.com to keep the process alive.
  OpenPopup(shell(), embedded_test_server()->GetURL("a.com", "/title2.html"),
            "foo");

  // Cross-process navigation to b.com.
  EXPECT_TRUE(NavigateToURL(
      shell(), embedded_test_server()->GetURL("b.com", "/title3.html")));

  // Pretend that a.com just requested a context menu. This used to cause a
  // because the RenderWidgetHostView is destroyed when the frame is swapped and
  // added to pending delete list.
  rfh->OnMessageReceived(
      FrameHostMsg_ContextMenu(rfh->GetRoutingID(), ContextMenuParams()));
}

// Test iframe container policy is replicated properly to the browser.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, ContainerPolicy) {
  GURL url(embedded_test_server()->GetURL("/allowed_frames.html"));
  EXPECT_TRUE(NavigateToURL(shell(), url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  EXPECT_EQ(0UL, root->effective_frame_policy().container_policy.size());
  EXPECT_EQ(
      0UL, root->child_at(0)->effective_frame_policy().container_policy.size());
  EXPECT_EQ(
      0UL, root->child_at(1)->effective_frame_policy().container_policy.size());
  EXPECT_EQ(
      2UL, root->child_at(2)->effective_frame_policy().container_policy.size());
  EXPECT_EQ(
      2UL, root->child_at(3)->effective_frame_policy().container_policy.size());
}

// Test dynamic updates to iframe "allow" attribute are propagated correctly.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, ContainerPolicyDynamic) {
  GURL main_url(embedded_test_server()->GetURL("/allowed_frames.html"));
  GURL nav_url(
      embedded_test_server()->GetURL("b.com", "/feature-policy2.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  EXPECT_EQ(
      2UL, root->child_at(2)->effective_frame_policy().container_policy.size());

  // Removing the "allow" attribute; pending policy should update, but effective
  // policy remains unchanged.
  EXPECT_TRUE(ExecuteScript(
      root, "document.getElementById('child-2').setAttribute('allow','')"));
  EXPECT_EQ(
      2UL, root->child_at(2)->effective_frame_policy().container_policy.size());
  EXPECT_EQ(0UL,
            root->child_at(2)->pending_frame_policy().container_policy.size());

  // Navigate the frame; pending policy should be committed.
  NavigateFrameToURL(root->child_at(2), nav_url);
  EXPECT_EQ(
      0UL, root->child_at(2)->effective_frame_policy().container_policy.size());
}

// Check that out-of-process frames correctly calculate the container policy in
// the renderer when navigating cross-origin. The policy should be unchanged
// when modified dynamically in the parent frame. When the frame is navigated,
// the new renderer should have the correct container policy.
//
// TODO(iclelland): Once there is a proper JS inspection API from the renderer,
// use that to check the policy. Until then, we test webkitFullscreenEnabled,
// which conveniently just returns the result of calling isFeatureEnabled on
// the fullscreen feature. Since there are no HTTP header policies involved,
// this verifies the presence of the container policy in the iframe.
// https://crbug.com/703703
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ContainerPolicyCrossOriginNavigation) {
  WebContentsImpl* contents = web_contents();
  FrameTreeNode* root = contents->GetFrameTree()->root();

  // Helper to check if a frame is allowed to go fullscreen on the renderer
  // side.
  auto is_fullscreen_allowed = [](FrameTreeNode* ftn) {
    bool fullscreen_allowed = false;
    EXPECT_TRUE(ExecuteScriptAndExtractBool(
        ftn,
        "window.domAutomationController.send(document.webkitFullscreenEnabled)",
        &fullscreen_allowed));
    return fullscreen_allowed;
  };

  // Load a page with an <iframe> without allowFullscreen.
  EXPECT_TRUE(NavigateToURL(
      shell(), embedded_test_server()->GetURL(
                   "a.com", "/cross_site_iframe_factory.html?a(b)")));

  // Dynamically enable fullscreen for the subframe and check that the
  // fullscreen property was updated on the FrameTreeNode.
  EXPECT_TRUE(ExecuteScript(
      root, "document.getElementById('child-0').allowFullscreen='true'"));

  // No change is expected to the container policy for dynamic modification of
  // a loaded frame.
  EXPECT_FALSE(is_fullscreen_allowed(root->child_at(0)));

  // Cross-site navigation should update the container policy in the new render
  // frame.
  NavigateFrameToURL(root->child_at(0),
                     embedded_test_server()->GetURL("c.com", "/title1.html"));
  EXPECT_TRUE(is_fullscreen_allowed(root->child_at(0)));
}

// Test that dynamic updates to iframe sandbox attribute correctly set the
// replicated container policy.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ContainerPolicySandboxDynamic) {
  GURL main_url(embedded_test_server()->GetURL("/allowed_frames.html"));
  GURL nav_url(
      embedded_test_server()->GetURL("b.com", "/feature-policy2.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Validate that the effective container policy contains a single non-unique
  // origin.
  const blink::ParsedFeaturePolicy initial_effective_policy =
      root->child_at(2)->effective_frame_policy().container_policy;
  EXPECT_EQ(1UL, initial_effective_policy[0].origins.size());
  EXPECT_FALSE(initial_effective_policy[0].origins[0].unique());

  // Set the "sandbox" attribute; pending policy should update, and should now
  // be flagged as matching the opaque origin of the frame (without containing
  // an actual opaque origin, since the parent frame doesn't actually have that
  // origin yet) but the effective policy should remain unchanged.
  EXPECT_TRUE(ExecuteScript(
      root, "document.getElementById('child-2').setAttribute('sandbox','')"));
  const blink::ParsedFeaturePolicy updated_effective_policy =
      root->child_at(2)->effective_frame_policy().container_policy;
  const blink::ParsedFeaturePolicy updated_pending_policy =
      root->child_at(2)->pending_frame_policy().container_policy;
  EXPECT_EQ(1UL, updated_effective_policy[0].origins.size());
  EXPECT_FALSE(updated_effective_policy[0].origins[0].unique());
  EXPECT_TRUE(updated_pending_policy[0].matches_opaque_src);
  EXPECT_EQ(0UL, updated_pending_policy[0].origins.size());

  // Navigate the frame; pending policy should now be committed.
  NavigateFrameToURL(root->child_at(2), nav_url);
  const blink::ParsedFeaturePolicy final_effective_policy =
      root->child_at(2)->effective_frame_policy().container_policy;
  EXPECT_TRUE(final_effective_policy[0].matches_opaque_src);
  EXPECT_EQ(0UL, final_effective_policy[0].origins.size());
}

// Test harness that allows for "barrier" style delaying of requests matching
// certain paths. Call SetDelayedRequestsForPath to delay requests, then
// SetUpEmbeddedTestServer to register handlers and start the server.
class RequestDelayingSitePerProcessBrowserTest
    : public SitePerProcessBrowserTest {
 public:
  RequestDelayingSitePerProcessBrowserTest()
      : test_server_(std::make_unique<net::EmbeddedTestServer>()) {}

  // Must be called after any calls to SetDelayedRequestsForPath.
  void SetUpEmbeddedTestServer() {
    SetupCrossSiteRedirector(test_server_.get());
    test_server_->RegisterRequestHandler(base::Bind(
        &RequestDelayingSitePerProcessBrowserTest::HandleMockResource,
        base::Unretained(this)));
    ASSERT_TRUE(test_server_->Start());
  }

  // Delays |num_delayed| requests with URLs whose path parts match |path|. When
  // the |num_delayed| + 1 request matching the path comes in, the rest are
  // unblocked.
  // Note: must be called on the UI thread before |test_server_| is started.
  void SetDelayedRequestsForPath(const std::string& path, int num_delayed) {
    DCHECK_CURRENTLY_ON(BrowserThread::UI);
    DCHECK(!test_server_->Started());
    num_remaining_requests_to_delay_for_path_[path] = num_delayed;
  }

 private:
  // Called on the test server's thread.
  void AddDelayedResponse(const net::test_server::SendBytesCallback& send,
                          const net::test_server::SendCompleteCallback& done) {
    // Just create a closure that closes the socket without sending a response.
    // This will propagate an error to the underlying request.
    send_response_closures_.push_back(base::Bind(send, "", done));
  }

  // Custom embedded test server handler. Looks for requests matching
  // num_remaining_requests_to_delay_for_path_, and delays them if necessary. As
  // soon as a single request comes in and:
  // 1) It matches a delayed path
  // 2) No path has any more requests to delay
  // Then we release the barrier and finish all delayed requests.
  std::unique_ptr<net::test_server::HttpResponse> HandleMockResource(
      const net::test_server::HttpRequest& request) {
    auto it =
        num_remaining_requests_to_delay_for_path_.find(request.GetURL().path());
    if (it == num_remaining_requests_to_delay_for_path_.end())
      return nullptr;

    // If there are requests to delay for this path, make a delayed request
    // which will be finished later. Otherwise fall through to the bottom and
    // send an empty response.
    if (it->second > 0) {
      --it->second;
      return std::make_unique<DelayedResponse>(this);
    }
    MaybeStartRequests();
    return std::unique_ptr<net::test_server::BasicHttpResponse>();
  }

  // If there are no more requests to delay, post a series of tasks finishing
  // all the delayed tasks. This will be called on the test server's thread.
  void MaybeStartRequests() {
    for (auto it : num_remaining_requests_to_delay_for_path_) {
      if (it.second > 0)
        return;
    }
    for (const auto it : send_response_closures_) {
      it.Run();
    }
  }

  // This class passes the callbacks needed to respond to a request to the
  // underlying test fixture.
  class DelayedResponse : public net::test_server::BasicHttpResponse {
   public:
    explicit DelayedResponse(
        RequestDelayingSitePerProcessBrowserTest* test_harness)
        : test_harness_(test_harness) {}
    void SendResponse(
        const net::test_server::SendBytesCallback& send,
        const net::test_server::SendCompleteCallback& done) override {
      test_harness_->AddDelayedResponse(send, done);
    }

   private:
    RequestDelayingSitePerProcessBrowserTest* test_harness_;

    DISALLOW_COPY_AND_ASSIGN(DelayedResponse);
  };

  // Set of closures to call which will complete delayed requests. May only be
  // modified on the test_server_'s thread.
  std::vector<base::Closure> send_response_closures_;

  // Map from URL paths to the number of requests to delay for that particular
  // path. Initialized on the UI thread but modified and read on the test
  // server's thread after the |test_server_| is started.
  std::map<std::string, int> num_remaining_requests_to_delay_for_path_;

  // Don't use embedded_test_server() because this one requires custom
  // initialization.
  std::unique_ptr<net::EmbeddedTestServer> test_server_;
};

// Regression tests for https://crbug.com/678206, where the request throttling
// in ResourceScheduler was not updated for OOPIFs. This resulted in a single
// hung delayable request (e.g. video) starving all other delayable requests.
// The tests work by delaying n requests in a cross-domain iframe. Once the n +
// 1st request goes through to the network stack (ensuring it was not starved),
// the delayed request completed.
//
// If the logic is not correct, these tests will time out, as the n + 1st
// request will never start.
IN_PROC_BROWSER_TEST_F(RequestDelayingSitePerProcessBrowserTest,
                       DelayableSubframeRequestsOneFrame) {
  std::string path = "/mock-video.mp4";
  SetDelayedRequestsForPath(path, 2);
  SetUpEmbeddedTestServer();
  GURL url(embedded_test_server()->GetURL(
      "a.com", base::StringPrintf("/site_isolation/"
                                  "subframes_with_resources.html?urls=%s&"
                                  "numSubresources=3",
                                  path.c_str())));
  EXPECT_TRUE(NavigateToURL(shell(), url));
  bool result;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(shell(), "createFrames()", &result));
  EXPECT_TRUE(result);
}

IN_PROC_BROWSER_TEST_F(RequestDelayingSitePerProcessBrowserTest,
                       DelayableSubframeRequestsTwoFrames) {
  std::string path0 = "/mock-video0.mp4";
  std::string path1 = "/mock-video1.mp4";
  SetDelayedRequestsForPath(path0, 2);
  SetDelayedRequestsForPath(path1, 2);
  SetUpEmbeddedTestServer();
  GURL url(embedded_test_server()->GetURL(
      "a.com", base::StringPrintf("/site_isolation/"
                                  "subframes_with_resources.html?urls=%s,%s&"
                                  "numSubresources=3",
                                  path0.c_str(), path1.c_str())));
  EXPECT_TRUE(NavigateToURL(shell(), url));
  bool result;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(shell(), "createFrames()", &result));
  EXPECT_TRUE(result);
}

#if defined(OS_ANDROID)
class TextSelectionObserver : public TextInputManager::Observer {
 public:
  explicit TextSelectionObserver(TextInputManager* text_input_manager)
      : text_input_manager_(text_input_manager) {
    text_input_manager->AddObserver(this);
  }

  ~TextSelectionObserver() { text_input_manager_->RemoveObserver(this); }

  void WaitForSelectedText(const std::string& expected_text) {
    if (last_selected_text_ == expected_text)
      return;
    expected_text_ = expected_text;
    loop_runner_ = new MessageLoopRunner();
    loop_runner_->Run();
  }

 private:
  void OnTextSelectionChanged(TextInputManager* text_input_manager,
                              RenderWidgetHostViewBase* updated_view) override {
    last_selected_text_ = base::UTF16ToUTF8(
        text_input_manager->GetTextSelection(updated_view)->selected_text());
    if (last_selected_text_ == expected_text_ && loop_runner_)
      loop_runner_->Quit();
  }

  TextInputManager* const text_input_manager_;
  std::string last_selected_text_;
  std::string expected_text_;
  scoped_refptr<MessageLoopRunner> loop_runner_;

  DISALLOW_COPY_AND_ASSIGN(TextSelectionObserver);
};

class SitePerProcessAndroidImeTest : public SitePerProcessBrowserTest {
 public:
  SitePerProcessAndroidImeTest() : SitePerProcessBrowserTest() {}
  ~SitePerProcessAndroidImeTest() override {}

 protected:
  ImeAdapterAndroid* ime_adapter() {
    return static_cast<RenderWidgetHostViewAndroid*>(
               web_contents()->GetRenderWidgetHostView())
        ->ime_adapter_for_testing();
  }

  std::string GetInputValue(RenderFrameHostImpl* frame) {
    std::string result;
    EXPECT_TRUE(ExecuteScriptAndExtractString(
        frame, "window.domAutomationController.send(input.value);", &result));
    return result;
  }

  void FocusInputInFrame(RenderFrameHostImpl* frame) {
    ASSERT_TRUE(ExecuteScript(frame, "window.focus(); input.focus();"));
  }

  // Creates a page with multiple (nested) OOPIFs and populates all of them
  // with an <input> element along with the required handlers for the test.
  void LoadPage() {
    ASSERT_TRUE(NavigateToURL(
        shell(),
        GURL(embedded_test_server()->GetURL(
            "a.com", "/cross_site_iframe_factory.html?a(b,c(a(b)))"))));
    FrameTreeNode* root = web_contents()->GetFrameTree()->root();
    frames_.push_back(root->current_frame_host());
    frames_.push_back(root->child_at(0)->current_frame_host());
    frames_.push_back(root->child_at(1)->current_frame_host());
    frames_.push_back(root->child_at(1)->child_at(0)->current_frame_host());
    frames_.push_back(
        root->child_at(1)->child_at(0)->child_at(0)->current_frame_host());

    // Adds an <input> to frame and sets up a handler for |window.oninput|. When
    // the input event is fired (by changing the value of <input> element), the
    // handler will select all the text so that the corresponding text selection
    // update on the browser side notifies the test about input insertion.
    std::string add_input_script =
        "var input = document.createElement('input');"
        "document.body.appendChild(input);"
        "window.oninput = function() {"
        "  input.select();"
        "};";

    for (auto* frame : frames_)
      ASSERT_TRUE(ExecuteScript(frame, add_input_script));
  }

  // This methods tries to commit |text| by simulating a native call from Java.
  void CommitText(const char* text) {
    JNIEnv* env = base::android::AttachCurrentThread();

    // A valid caller is needed for ImeAdapterAndroid::GetUnderlinesFromSpans.
    base::android::ScopedJavaLocalRef<jobject> caller =
        ime_adapter()->java_ime_adapter_for_testing(env);

    // Input string from Java side.
    base::android::ScopedJavaLocalRef<jstring> jtext =
        base::android::ConvertUTF8ToJavaString(env, text);

    // Simulating a native call from Java side.
    ime_adapter()->CommitText(
        env, base::android::JavaParamRef<jobject>(env, caller.obj()),
        base::android::JavaParamRef<jobject>(env, jtext.obj()),
        base::android::JavaParamRef<jstring>(env, jtext.obj()), 0);
  }

  std::vector<RenderFrameHostImpl*> frames_;

 private:
  DISALLOW_COPY_AND_ASSIGN(SitePerProcessAndroidImeTest);
};

// This test verifies that committing text will be applied on the focused
// RenderWidgetHost.
IN_PROC_BROWSER_TEST_F(SitePerProcessAndroidImeTest,
                       CommitTextForFocusedWidget) {
  LoadPage();
  TextSelectionObserver selection_observer(
      web_contents()->GetTextInputManager());
  for (size_t index = 0; index < frames_.size(); ++index) {
    std::string text = base::StringPrintf("text%zu", index);
    FocusInputInFrame(frames_[index]);
    CommitText(text.c_str());
    selection_observer.WaitForSelectedText(text);
  }
}
#endif  // OS_ANDROID

// Test that an OOPIF at b.com can navigate to a cross-site a.com URL that
// transfers back to b.com.  See https://crbug.com/681077#c10 and
// https://crbug.com/660407.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       SubframeTransfersToCurrentRFH) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  ASSERT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  scoped_refptr<SiteInstanceImpl> b_site_instance =
      root->child_at(0)->current_frame_host()->GetSiteInstance();

  // Navigate subframe to a URL that will redirect from a.com back to b.com.
  // This navigation shouldn't time out.  Also ensure that the pending RFH
  // that was created for a.com is destroyed.
  GURL frame_url(
      embedded_test_server()->GetURL("a.com", "/cross-site/b.com/title2.html"));
  NavigateIframeToURL(shell()->web_contents(), "child-0", frame_url);
  EXPECT_FALSE(root->child_at(0)->render_manager()->speculative_frame_host());
  GURL redirected_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  EXPECT_EQ(root->child_at(0)->current_url(), redirected_url);
  EXPECT_EQ(b_site_instance,
            root->child_at(0)->current_frame_host()->GetSiteInstance());

  // Try the same navigation, but use the browser-initiated path.
  NavigateFrameToURL(root->child_at(0), frame_url);
  EXPECT_FALSE(root->child_at(0)->render_manager()->speculative_frame_host());
  EXPECT_EQ(root->child_at(0)->current_url(), redirected_url);
  EXPECT_EQ(b_site_instance,
            root->child_at(0)->current_frame_host()->GetSiteInstance());
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       FrameSwapPreservesUniqueName) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  ASSERT_TRUE(NavigateToURL(shell(), main_url));

  // Navigate the subframe cross-site…
  {
    GURL url(embedded_test_server()->GetURL("b.com", "/title1.html"));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "child-0", url));
  }
  // and then same-site…
  {
    GURL url(embedded_test_server()->GetURL("a.com", "/title1.html"));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "child-0", url));
  }
  // and cross-site once more.
  {
    GURL url(embedded_test_server()->GetURL("b.com", "/title1.html"));
    EXPECT_TRUE(NavigateIframeToURL(shell()->web_contents(), "child-0", url));
  }

  // Inspect the navigation entries and make sure that the navigation target
  // remained constant across frame swaps.
  const auto& controller = static_cast<const NavigationControllerImpl&>(
      shell()->web_contents()->GetController());
  EXPECT_EQ(4, controller.GetEntryCount());

  std::set<std::string> names;
  for (int i = 0; i < controller.GetEntryCount(); ++i) {
    NavigationEntryImpl::TreeNode* root =
        controller.GetEntryAtIndex(i)->root_node();
    ASSERT_EQ(1U, root->children.size());
    names.insert(root->children[0]->frame_entry->frame_unique_name());
  }

  // More than one entry in the set means that the subframe frame navigation
  // entries didn't have a consistent unique name. This will break history
  // navigations =(
  EXPECT_THAT(names, SizeIs(1)) << "Mismatched names for subframe!";
}

// Tests that POST body is not lost when it targets a OOPIF.
// See https://crbug.com/710937.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, PostTargetSubFrame) {
  // Navigate to a page with an OOPIF.
  GURL main_url(
      embedded_test_server()->GetURL("/frame_tree/page_with_one_frame.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  // The main frame and the subframe live on different processes.
  EXPECT_EQ(1u, root->child_count());
  EXPECT_NE(root->current_frame_host()->GetSiteInstance(),
            root->child_at(0)->current_frame_host()->GetSiteInstance());

  // Make a form submission from the main frame and target the OOPIF.
  GURL form_url(embedded_test_server()->GetURL("/echoall"));
  TestNavigationObserver form_post_observer(shell()->web_contents(), 1);
  EXPECT_TRUE(ExecuteScript(shell()->web_contents(), R"(
    var form = document.createElement('form');

    // POST form submission to /echoall.
    form.setAttribute("method", "POST");
    form.setAttribute("action", ")" + form_url.spec() + R"(");

    // Target the OOPIF.
    form.setAttribute("target", "child-name-0");

    // Add some POST data: "my_token=my_value";
    var input = document.createElement("input");
    input.setAttribute("type", "hidden");
    input.setAttribute("name", "my_token");
    input.setAttribute("value", "my_value");
    form.appendChild(input);

    // Submit the form.
    document.body.appendChild(form);
    form.submit();
  )"));
  form_post_observer.Wait();

  NavigationEntryImpl* entry = static_cast<NavigationEntryImpl*>(
      shell()->web_contents()->GetController().GetLastCommittedEntry());
  // TODO(arthursonzogni): This is wrong. The last committed entry was
  // renderer-initiated. See https://crbug.com/722251.
  EXPECT_FALSE(entry->is_renderer_initiated());

  // Verify that POST body was correctly passed to the server and ended up in
  // the body of the page.
  std::string body;
  EXPECT_TRUE(ExecuteScriptAndExtractString(root->child_at(0), R"(
    var body = document.getElementsByTagName('pre')[0].innerText;
    window.domAutomationController.send(body);)",
                                            &body));
  EXPECT_EQ("my_token=my_value\n", body);
}

// Tests that POST method and body is not lost when an OOPIF submits a form
// that targets the main frame.  See https://crbug.com/806215.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       PostTargetsMainFrameFromOOPIF) {
  // Navigate to a page with an OOPIF.
  GURL main_url(
      embedded_test_server()->GetURL("/frame_tree/page_with_one_frame.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // The main frame and the subframe live on different processes.
  EXPECT_EQ(1u, root->child_count());
  EXPECT_NE(root->current_frame_host()->GetSiteInstance(),
            root->child_at(0)->current_frame_host()->GetSiteInstance());

  // Make a form submission from the subframe and target its parent frame.
  GURL form_url(embedded_test_server()->GetURL("/echoall"));
  TestNavigationObserver form_post_observer(web_contents());
  EXPECT_TRUE(ExecuteScript(root->child_at(0)->current_frame_host(), R"(
    var form = document.createElement('form');

    // POST form submission to /echoall.
    form.setAttribute("method", "POST");
    form.setAttribute("action", ")" + form_url.spec() + R"(");

    // Target the parent.
    form.setAttribute("target", "_parent");

    // Add some POST data: "my_token=my_value";
    var input = document.createElement("input");
    input.setAttribute("type", "hidden");
    input.setAttribute("name", "my_token");
    input.setAttribute("value", "my_value");
    form.appendChild(input);

    // Submit the form.
    document.body.appendChild(form);
    form.submit();
  )"));
  form_post_observer.Wait();

  // Verify that the FrameNavigationEntry's method is POST.
  NavigationEntryImpl* entry = static_cast<NavigationEntryImpl*>(
      web_contents()->GetController().GetLastCommittedEntry());
  EXPECT_EQ("POST", entry->root_node()->frame_entry->method());

  // Verify that POST body was correctly passed to the server and ended up in
  // the body of the page.
  std::string body;
  EXPECT_TRUE(ExecuteScriptAndExtractString(root, R"(
    var body = document.getElementsByTagName('pre')[0].innerText;
    window.domAutomationController.send(body);)", &body));
  EXPECT_EQ("my_token=my_value\n", body);

  // Reload the main frame and ensure the POST body is preserved.  This checks
  // that the POST body was saved in the FrameNavigationEntry.
  web_contents()->GetController().Reload(ReloadType::NORMAL,
                                         false /* check_for_repost */);
  EXPECT_TRUE(WaitForLoadStop(web_contents()));
  body = "";
  EXPECT_TRUE(ExecuteScriptAndExtractString(root, R"(
    var body = document.getElementsByTagName('pre')[0].innerText;
    window.domAutomationController.send(body);)", &body));
  EXPECT_EQ("my_token=my_value\n", body);
}

// Verify that a remote-to-local main frame navigation doesn't overwrite
// the previous history entry.  See https://crbug.com/725716.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CrossProcessMainFrameNavigationDoesNotOverwriteHistory) {
  GURL foo_url(embedded_test_server()->GetURL("foo.com", "/title1.html"));
  GURL bar_url(embedded_test_server()->GetURL("bar.com", "/title2.html"));

  EXPECT_TRUE(NavigateToURL(shell(), foo_url));

  // Open a same-site popup to keep the www.foo.com process alive.
  OpenPopup(shell(), GURL(url::kAboutBlankURL), "foo");

  // Navigate foo -> bar -> foo.
  EXPECT_TRUE(NavigateToURLFromRenderer(shell(), bar_url));
  EXPECT_TRUE(NavigateToURLFromRenderer(shell(), foo_url));

  // There should be three history entries.
  EXPECT_EQ(3, web_contents()->GetController().GetEntryCount());

  // Go back: this should go to bar.com.
  {
    TestNavigationObserver back_observer(web_contents());
    web_contents()->GetController().GoBack();
    back_observer.Wait();
  }
  EXPECT_EQ(bar_url, web_contents()->GetMainFrame()->GetLastCommittedURL());

  // Go back again.  This should go to foo.com.
  {
    TestNavigationObserver back_observer(web_contents());
    web_contents()->GetController().GoBack();
    back_observer.Wait();
  }
  EXPECT_EQ(foo_url, web_contents()->GetMainFrame()->GetLastCommittedURL());
}

// Class to sniff incoming IPCs for FrameHostMsg_SetIsInert messages.
class SetIsInertMessageFilter : public content::BrowserMessageFilter {
 public:
  SetIsInertMessageFilter()
      : content::BrowserMessageFilter(FrameMsgStart),
        message_loop_runner_(new content::MessageLoopRunner),
        msg_received_(false) {}

  bool OnMessageReceived(const IPC::Message& message) override {
    IPC_BEGIN_MESSAGE_MAP(SetIsInertMessageFilter, message)
      IPC_MESSAGE_HANDLER(FrameHostMsg_SetIsInert, OnSetIsInert)
    IPC_END_MESSAGE_MAP()
    return false;
  }

  bool is_inert() const { return is_inert_; }

  void Wait() { message_loop_runner_->Run(); }

 private:
  ~SetIsInertMessageFilter() override {}

  void OnSetIsInert(bool is_inert) {
    content::BrowserThread::PostTask(
        content::BrowserThread::UI, FROM_HERE,
        base::BindOnce(&SetIsInertMessageFilter::OnSetIsInertOnUI, this,
                       is_inert));
  }
  void OnSetIsInertOnUI(bool is_inert) {
    is_inert_ = is_inert;
    if (!msg_received_) {
      msg_received_ = true;
      message_loop_runner_->Quit();
    }
  }
  scoped_refptr<content::MessageLoopRunner> message_loop_runner_;
  bool msg_received_;
  bool is_inert_;
  DISALLOW_COPY_AND_ASSIGN(SetIsInertMessageFilter);
};

// Tests that when a frame contains a modal <dialog> element, out-of-process
// iframe children cannot take focus, because they are inert.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, CrossProcessInertSubframe) {
  // This uses a(b,b) instead of a(b) to preserve the b.com process even when
  // the first subframe is navigated away from it.
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  ASSERT_EQ(2U, root->child_count());

  FrameTreeNode* iframe_node = root->child_at(0);

  EXPECT_TRUE(ExecuteScript(
      iframe_node,
      "document.head.innerHTML = '';"
      "document.body.innerHTML = '<input id=\"text1\"> <input id=\"text2\">';"
      "text1.focus();"));

  // Add a filter to the parent frame's process to monitor for inert bit
  // updates. These are sent through the proxy for b.com child frame.
  scoped_refptr<SetIsInertMessageFilter> filter = new SetIsInertMessageFilter();
  root->current_frame_host()->GetProcess()->AddFilter(filter.get());

  // Add a <dialog> to the root frame and call showModal on it.
  EXPECT_TRUE(ExecuteScript(root,
                            "let dialog = "
                            "document.body.appendChild(document.createElement('"
                            "dialog'));"
                            "dialog.innerHTML = 'Modal dialog <input>';"
                            "dialog.showModal();"));
  filter->Wait();
  EXPECT_TRUE(filter->is_inert());

  // This yields the UI thread to ensure that the real SetIsInert message
  // handler runs, in order to guarantee that the update arrives at the
  // renderer process before the script below.
  {
    base::RunLoop loop;
    base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                                  loop.QuitClosure());
    loop.Run();
  }

  std::string focused_element;

  // Attempt to change focus in the inert subframe. This should fail.
  // The setTimeout ensures that the inert bit can propagate before the
  // test JS code runs.
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      iframe_node,
      "window.setTimeout(() => {text2.focus();"
      "domAutomationController.send(document.activeElement.id);}, 0)",
      &focused_element));
  EXPECT_EQ("", focused_element);

  // Navigate the child frame to another site, so that it moves into a new
  // process.
  GURL site_url(embedded_test_server()->GetURL("c.com", "/title1.html"));
  NavigateFrameToURL(iframe_node, site_url);

  EXPECT_TRUE(ExecuteScript(
      iframe_node,
      "document.head.innerHTML = '';"
      "document.body.innerHTML = '<input id=\"text1\"> <input id=\"text2\">';"
      "text1.focus();"));

  // Verify that inertness was preserved across the navigation.
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      iframe_node,
      "text2.focus();"
      "domAutomationController.send(document.activeElement.id);",
      &focused_element));
  EXPECT_EQ("", focused_element);

  // Navigate the subframe back into its parent process to verify that the
  // new local frame remains inert.
  GURL same_site_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  NavigateFrameToURL(iframe_node, same_site_url);

  EXPECT_TRUE(ExecuteScript(
      iframe_node,
      "document.head.innerHTML = '';"
      "document.body.innerHTML = '<input id=\"text1\"> <input id=\"text2\">';"
      "text1.focus();"));

  // Verify that inertness was preserved across the navigation.
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      iframe_node,
      "text2.focus();"
      "domAutomationController.send(document.activeElement.id);",
      &focused_element));
  EXPECT_EQ("", focused_element);
}

// Check that main frames for the same site rendering in unrelated tabs start
// sharing processes that are already dedicated to that site when over process
// limit. See https://crbug.com/513036.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       MainFrameProcessReuseWhenOverLimit) {
  // Set the process limit to 1.
  RenderProcessHost::SetMaxRendererProcessCount(1);

  GURL url_a(embedded_test_server()->GetURL("a.com", "/title1.html"));
  ASSERT_TRUE(NavigateToURL(shell(), url_a));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Create an unrelated shell window.
  GURL url_b(embedded_test_server()->GetURL("b.com", "/title2.html"));
  Shell* new_shell = CreateBrowser();
  EXPECT_TRUE(NavigateToURL(new_shell, url_b));

  FrameTreeNode* new_shell_root =
      static_cast<WebContentsImpl*>(new_shell->web_contents())
          ->GetFrameTree()
          ->root();

  // The new window's b.com root should not reuse the a.com process.
  EXPECT_NE(root->current_frame_host()->GetProcess(),
            new_shell_root->current_frame_host()->GetProcess());

  // Navigating the new window to a.com should reuse the first window's
  // process.
  EXPECT_TRUE(NavigateToURL(new_shell, url_a));
  EXPECT_EQ(root->current_frame_host()->GetProcess(),
            new_shell_root->current_frame_host()->GetProcess());
}

// Check that subframes for the same site rendering in unrelated tabs start
// sharing processes that are already dedicated to that site when over process
// limit. See https://crbug.com/513036.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       SubframeProcessReuseWhenOverLimit) {
  // Set the process limit to 1.
  RenderProcessHost::SetMaxRendererProcessCount(1);

  GURL first_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b,b(c))"));
  ASSERT_TRUE(NavigateToURL(shell(), first_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Processes for dedicated sites should never be reused.
  EXPECT_NE(root->current_frame_host()->GetProcess(),
            root->child_at(0)->current_frame_host()->GetProcess());
  EXPECT_NE(root->current_frame_host()->GetProcess(),
            root->child_at(1)->current_frame_host()->GetProcess());
  EXPECT_NE(root->current_frame_host()->GetProcess(),
            root->child_at(1)->child_at(0)->current_frame_host()->GetProcess());
  EXPECT_NE(root->child_at(1)->current_frame_host()->GetProcess(),
            root->child_at(1)->child_at(0)->current_frame_host()->GetProcess());
  EXPECT_EQ(root->child_at(0)->current_frame_host()->GetProcess(),
            root->child_at(1)->current_frame_host()->GetProcess());

  // Create an unrelated shell window.
  Shell* new_shell = CreateBrowser();

  GURL new_shell_url(embedded_test_server()->GetURL(
      "d.com", "/cross_site_iframe_factory.html?d(a(b))"));
  ASSERT_TRUE(NavigateToURL(new_shell, new_shell_url));

  FrameTreeNode* new_shell_root =
      static_cast<WebContentsImpl*>(new_shell->web_contents())
          ->GetFrameTree()
          ->root();

  // New tab's root (d.com) should go into a separate process.
  EXPECT_NE(root->current_frame_host()->GetProcess(),
            new_shell_root->current_frame_host()->GetProcess());
  EXPECT_NE(root->child_at(0)->current_frame_host()->GetProcess(),
            new_shell_root->current_frame_host()->GetProcess());
  EXPECT_NE(root->child_at(1)->child_at(0)->current_frame_host()->GetProcess(),
            new_shell_root->current_frame_host()->GetProcess());

  // The new tab's subframe should reuse the a.com process.
  EXPECT_EQ(root->current_frame_host()->GetProcess(),
            new_shell_root->child_at(0)->current_frame_host()->GetProcess());

  // The new tab's grandchild frame should reuse the b.com process.
  EXPECT_EQ(root->child_at(0)->current_frame_host()->GetProcess(),
            new_shell_root->child_at(0)
                ->child_at(0)
                ->current_frame_host()
                ->GetProcess());
}

// Check that when a main frame and a subframe start navigating to the same
// cross-site URL at the same time, the new RenderFrame for the subframe is
// created successfully without crashing, and the navigations complete
// successfully.  This test checks the scenario where the main frame ends up
// committing before the subframe, and the test below checks the case where the
// subframe commits first.
//
// This used to be problematic in that the main frame navigation created an
// active RenderViewHost with a RenderFrame already swapped into the tree, and
// then while that navigation was still pending, the subframe navigation
// created its RenderFrame, which crashed when referencing its parent by a
// proxy which didn't exist.
//
// All cross-process navigations now require creating a RenderFrameProxy before
// creating a RenderFrame, which makes such navigations follow the provisional
// frame (remote-to-local navigation) paths, where such a scenario is no longer
// possible.  See https://crbug.com/756790.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       TwoCrossSitePendingNavigationsAndMainFrameWins) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);

  // Navigate both frames cross-site to b.com simultaneously.
  GURL new_url_1(embedded_test_server()->GetURL("b.com", "/title1.html"));
  GURL new_url_2(embedded_test_server()->GetURL("b.com", "/title2.html"));
  TestNavigationManager manager1(web_contents(), new_url_1);
  TestNavigationManager manager2(web_contents(), new_url_2);
  std::string script = "location = '" + new_url_1.spec() + "';" +
                       "frames[0].location = '" + new_url_2.spec() + "';";
  EXPECT_TRUE(ExecuteScript(web_contents(), script));

  // Wait for main frame request, but don't commit it yet.  This should create
  // a speculative RenderFrameHost.
  ASSERT_TRUE(manager1.WaitForRequestStart());
  RenderFrameHostImpl* root_speculative_rfh =
      root->render_manager()->speculative_frame_host();
  EXPECT_TRUE(root_speculative_rfh);
  scoped_refptr<SiteInstanceImpl> b_site_instance(
      root_speculative_rfh->GetSiteInstance());

  // There should now be a live b.com proxy for the root, since it is doing a
  // cross-process navigation.
  RenderFrameProxyHost* root_proxy =
      root->render_manager()->GetRenderFrameProxyHost(b_site_instance.get());
  EXPECT_TRUE(root_proxy);
  EXPECT_TRUE(root_proxy->is_render_frame_proxy_live());

  // Wait for subframe request, but don't commit it yet.
  ASSERT_TRUE(manager2.WaitForRequestStart());
  EXPECT_TRUE(child->render_manager()->speculative_frame_host());

  // Similarly, the subframe should also have a b.com proxy (unused in this
  // test), since it is also doing a cross-process navigation.
  RenderFrameProxyHost* child_proxy =
      child->render_manager()->GetRenderFrameProxyHost(b_site_instance.get());
  EXPECT_TRUE(child_proxy);
  EXPECT_TRUE(child_proxy->is_render_frame_proxy_live());

  // Now let the main frame commit.
  manager1.WaitForNavigationFinished();

  // Make sure the process is live and at the new URL.
  EXPECT_TRUE(b_site_instance->GetProcess()->HasConnection());
  EXPECT_TRUE(root->current_frame_host()->IsRenderFrameLive());
  EXPECT_EQ(root_speculative_rfh, root->current_frame_host());
  EXPECT_EQ(new_url_1, root->current_frame_host()->GetLastCommittedURL());

  // The subframe should be gone, so the second navigation should have no
  // effect.
  manager2.WaitForNavigationFinished();

  // The new commit should have detached the old child frame.
  EXPECT_EQ(0U, root->child_count());
  int length = -1;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      web_contents(), "domAutomationController.send(frames.length);", &length));
  EXPECT_EQ(0, length);

  // The root proxy should be gone.
  EXPECT_FALSE(
      root->render_manager()->GetRenderFrameProxyHost(b_site_instance.get()));
}

// Similar to TwoCrossSitePendingNavigationsAndMainFrameWins, but checks the
// case where the subframe navigation commits before the main frame.  See
// https://crbug.com/756790.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       TwoCrossSitePendingNavigationsAndSubframeWins) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);
  FrameTreeNode* child2 = root->child_at(1);

  // Install postMessage handlers in main frame and second subframe for later
  // use.
  EXPECT_TRUE(
      ExecuteScript(root->current_frame_host(),
                    "window.addEventListener('message', function(event) {\n"
                    "  event.source.postMessage(event.data + '-reply', '*');\n"
                    "});"));
  EXPECT_TRUE(ExecuteScript(
      child2->current_frame_host(),
      "window.addEventListener('message', function(event) {\n"
      "  event.source.postMessage(event.data + '-subframe-reply', '*');\n"
      "});"));

  // Start a main frame navigation to b.com.
  GURL new_url_1(embedded_test_server()->GetURL("b.com", "/title1.html"));
  TestNavigationManager manager1(web_contents(), new_url_1);
  EXPECT_TRUE(
      ExecuteScript(web_contents(), "location = '" + new_url_1.spec() + "';"));

  // Wait for main frame request and check the frame tree.  There should be a
  // proxy for b.com at the root, but nowhere else at this point.
  ASSERT_TRUE(manager1.WaitForRequestStart());
  EXPECT_EQ(
      " Site A (B speculative) -- proxies for B\n"
      "   |--Site A\n"
      "   +--Site A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  // Now start navigating the first subframe to b.com.
  GURL new_url_2(embedded_test_server()->GetURL("b.com", "/title2.html"));
  TestNavigationManager manager2(web_contents(), new_url_2);
  EXPECT_TRUE(ExecuteScript(
      web_contents(), "frames[0].location = '" + new_url_2.spec() + "';"));

  // Wait for subframe request.
  ASSERT_TRUE(manager2.WaitForRequestStart());
  RenderFrameHostImpl* child_speculative_rfh =
      child->render_manager()->speculative_frame_host();
  EXPECT_TRUE(child_speculative_rfh);
  scoped_refptr<SiteInstanceImpl> b_site_instance(
      child_speculative_rfh->GetSiteInstance());

  // Check that all frames have proxies for b.com at this point.  The proxy for
  // |child2| is important to create since |child| has to use it to communicate
  // with |child2| if |child| commits first.
  EXPECT_EQ(
      " Site A (B speculative) -- proxies for B\n"
      "   |--Site A (B speculative) -- proxies for B\n"
      "   +--Site A ------- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  // Now let the subframe commit.
  manager2.WaitForNavigationFinished();

  // Make sure the process is live and at the new URL.
  EXPECT_TRUE(b_site_instance->GetProcess()->HasConnection());
  ASSERT_EQ(2U, root->child_count());
  EXPECT_TRUE(child->current_frame_host()->IsRenderFrameLive());
  EXPECT_EQ(child_speculative_rfh, child->current_frame_host());
  EXPECT_EQ(new_url_2, child->current_frame_host()->GetLastCommittedURL());

  // Recheck the proxies.  Main frame should still be pending.
  EXPECT_EQ(
      " Site A (B speculative) -- proxies for B\n"
      "   |--Site B ------- proxies for A\n"
      "   +--Site A ------- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  // Make sure the subframe can communicate to both the root remote frame
  // (where the postMessage should go to the current RenderFrameHost rather
  // than the pending one) and its sibling remote frame in the a.com process.
  EXPECT_TRUE(
      ExecuteScript(child->current_frame_host(),
                    "window.addEventListener('message', function(event) {\n"
                    "  domAutomationController.send(event.data);\n"
                    "});"));
  std::string response;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      child, "parent.postMessage('root-ping', '*')", &response));
  EXPECT_EQ("root-ping-reply", response);

  EXPECT_TRUE(ExecuteScriptAndExtractString(
      child, "parent.frames[1].postMessage('sibling-ping', '*')", &response));
  EXPECT_EQ("sibling-ping-subframe-reply", response);

  // Cancel the pending main frame navigation, and verify that the subframe can
  // still communicate with the (old) main frame.
  root->navigator()->CancelNavigation(root, true /* inform_renderer */);
  EXPECT_FALSE(root->render_manager()->speculative_frame_host());
  response = "";
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      child, "parent.postMessage('root-ping', '*')", &response));
  EXPECT_EQ("root-ping-reply", response);
}

// Similar to TwoCrossSitePendingNavigations* tests above, but checks the case
// where the current window and its opener navigate simultaneously.
// See https://crbug.com/756790.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       TwoCrossSitePendingNavigationsWithOpener) {
  GURL main_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Install a postMessage handler in main frame for later use.
  EXPECT_TRUE(
      ExecuteScript(web_contents(),
                    "window.addEventListener('message', function(event) {\n"
                    "  event.source.postMessage(event.data + '-reply', '*');\n"
                    "});"));

  Shell* popup_shell =
      OpenPopup(shell()->web_contents(), GURL(url::kAboutBlankURL), "popup");

  // Start a navigation to b.com in the first (opener) tab.
  GURL new_url_1(embedded_test_server()->GetURL("b.com", "/title1.html"));
  TestNavigationManager manager(web_contents(), new_url_1);
  EXPECT_TRUE(
      ExecuteScript(web_contents(), "location = '" + new_url_1.spec() + "';"));
  ASSERT_TRUE(manager.WaitForRequestStart());

  // Before it commits, start and commit a navigation to b.com in the second
  // tab.
  GURL new_url_2(embedded_test_server()->GetURL("b.com", "/title2.html"));
  EXPECT_TRUE(NavigateToURLFromRenderer(popup_shell, new_url_2));

  // Check that the opener still has a speculative RenderFrameHost and a
  // corresponding proxy for b.com.
  RenderFrameHostImpl* speculative_rfh =
      root->render_manager()->speculative_frame_host();
  EXPECT_TRUE(speculative_rfh);
  scoped_refptr<SiteInstanceImpl> b_site_instance(
      speculative_rfh->GetSiteInstance());
  RenderFrameProxyHost* proxy =
      root->render_manager()->GetRenderFrameProxyHost(b_site_instance.get());
  EXPECT_TRUE(proxy);
  EXPECT_TRUE(proxy->is_render_frame_proxy_live());

  // Make sure the second tab can communicate to its (old) opener remote frame.
  // The postMessage should go to the current RenderFrameHost rather than the
  // pending one in the first tab's main frame.
  EXPECT_TRUE(
      ExecuteScript(popup_shell->web_contents(),
                    "window.addEventListener('message', function(event) {\n"
                    "  domAutomationController.send(event.data);\n"
                    "});"));

  std::string response;
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      popup_shell->web_contents(), "opener.postMessage('opener-ping', '*');",
      &response));
  EXPECT_EQ("opener-ping-reply", response);

  // Cancel the pending main frame navigation, and verify that the subframe can
  // still communicate with the (old) main frame.
  root->navigator()->CancelNavigation(root, true /* inform_renderer */);
  EXPECT_FALSE(root->render_manager()->speculative_frame_host());
  response = "";
  EXPECT_TRUE(ExecuteScriptAndExtractString(
      popup_shell->web_contents(), "opener.postMessage('opener-ping', '*')",
      &response));
  EXPECT_EQ("opener-ping-reply", response);
}

#if defined(OS_ANDROID)
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, TestChildProcessImportance) {
  web_contents()->SetImportance(ChildProcessImportance::MODERATE);

  // Construct root page with one child in different domain.
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1u, root->child_count());
  FrameTreeNode* child = root->child_at(0);

  // Importance should survive initial navigation.
  EXPECT_EQ(ChildProcessImportance::MODERATE,
            root->current_frame_host()->GetProcess()->GetEffectiveImportance());
  EXPECT_EQ(
      ChildProcessImportance::MODERATE,
      child->current_frame_host()->GetProcess()->GetEffectiveImportance());

  // Check setting importance.
  web_contents()->SetImportance(ChildProcessImportance::NORMAL);
  EXPECT_EQ(ChildProcessImportance::NORMAL,
            root->current_frame_host()->GetProcess()->GetEffectiveImportance());
  EXPECT_EQ(
      ChildProcessImportance::NORMAL,
      child->current_frame_host()->GetProcess()->GetEffectiveImportance());
  web_contents()->SetImportance(ChildProcessImportance::IMPORTANT);
  EXPECT_EQ(ChildProcessImportance::IMPORTANT,
            root->current_frame_host()->GetProcess()->GetEffectiveImportance());
  EXPECT_EQ(
      ChildProcessImportance::IMPORTANT,
      child->current_frame_host()->GetProcess()->GetEffectiveImportance());

  // Check importance is maintained if child navigates to new domain.
  int old_child_process_id = child->current_frame_host()->GetProcess()->GetID();
  GURL url = embedded_test_server()->GetURL("foo.com", "/title2.html");
  {
    RenderFrameDeletedObserver deleted_observer(child->current_frame_host());
    NavigateFrameToURL(root->child_at(0), url);
    deleted_observer.WaitUntilDeleted();
  }
  int new_child_process_id = child->current_frame_host()->GetProcess()->GetID();
  EXPECT_NE(old_child_process_id, new_child_process_id);
  EXPECT_EQ(
      ChildProcessImportance::IMPORTANT,
      child->current_frame_host()->GetProcess()->GetEffectiveImportance());

  // Check importance is maintained if root navigates to new domain.
  int old_root_process_id = root->current_frame_host()->GetProcess()->GetID();
  child = nullptr;  // Going to navigate root to page without any child.
  {
    RenderFrameDeletedObserver deleted_observer(root->current_frame_host());
    NavigateFrameToURL(root, url);
    deleted_observer.WaitUntilDeleted();
  }
  EXPECT_EQ(0u, root->child_count());
  int new_root_process_id = root->current_frame_host()->GetProcess()->GetID();
  EXPECT_NE(old_root_process_id, new_root_process_id);
  EXPECT_EQ(ChildProcessImportance::IMPORTANT,
            root->current_frame_host()->GetProcess()->GetEffectiveImportance());

  // Check interstitial maintains importance.
  TestInterstitialDelegate* delegate = new TestInterstitialDelegate;
  WebContentsImpl* contents_impl =
      static_cast<WebContentsImpl*>(web_contents());
  GURL interstitial_url("http://interstitial");
  InterstitialPageImpl* interstitial = new InterstitialPageImpl(
      contents_impl, contents_impl, true, interstitial_url, delegate);
  interstitial->Show();
  WaitForInterstitialAttach(contents_impl);
  RenderProcessHost* interstitial_process =
      interstitial->GetMainFrame()->GetProcess();
  EXPECT_EQ(ChildProcessImportance::IMPORTANT,
            interstitial_process->GetEffectiveImportance());

  web_contents()->SetImportance(ChildProcessImportance::MODERATE);
  EXPECT_EQ(ChildProcessImportance::MODERATE,
            interstitial_process->GetEffectiveImportance());
}

// Tests for Android TouchSelectionEditing.
class TouchSelectionControllerClientAndroidSiteIsolationTest
    : public SitePerProcessBrowserTest {
 public:
  TouchSelectionControllerClientAndroidSiteIsolationTest() {}

  void SetUpCommandLine(base::CommandLine* command_line) override {
    IsolateAllSitesForTesting(command_line);
  }

  RenderWidgetHostViewAndroid* GetRenderWidgetHostViewAndroid() {
    return static_cast<RenderWidgetHostViewAndroid*>(
        shell()->web_contents()->GetRenderWidgetHostView());
  }

  void SelectWithLongPress(gfx::Point point) {
    // Get main frame view for event insertion.
    RenderWidgetHostViewAndroid* main_view = GetRenderWidgetHostViewAndroid();

    SendTouch(main_view, ui::MotionEvent::Action::DOWN, point);
    // action_timeout() is far longer than needed for a LongPress, so we use
    // a custom timeout here.
    DelayBy(base::TimeDelta::FromMilliseconds(2000));
    SendTouch(main_view, ui::MotionEvent::Action::UP, point);
  }

  void SimpleTap(gfx::Point point) {
    // Get main frame view for event insertion.
    RenderWidgetHostViewAndroid* main_view = GetRenderWidgetHostViewAndroid();

    SendTouch(main_view, ui::MotionEvent::Action::DOWN, point);
    // tiny_timeout() is way shorter than a reasonable user-created tap gesture,
    // so we use a custom timeout here.
    DelayBy(base::TimeDelta::FromMilliseconds(300));
    SendTouch(main_view, ui::MotionEvent::Action::UP, point);
  }

 protected:
  void DelayBy(base::TimeDelta delta) {
    base::RunLoop run_loop;
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(), delta);
    run_loop.Run();
  }

 private:
  void SendTouch(RenderWidgetHostViewAndroid* view,
                 ui::MotionEvent::Action action,
                 gfx::Point point) {
    DCHECK(action >= ui::MotionEvent::Action::DOWN &&
           action < ui::MotionEvent::Action::CANCEL);

    ui::MotionEventAndroid::Pointer p(0, point.x(), point.y(), 10, 0, 0, 0, 0);
    JNIEnv* env = base::android::AttachCurrentThread();
    auto time_ms = (ui::EventTimeForNow() - base::TimeTicks()).InMilliseconds();
    ui::MotionEventAndroid touch(
        env, nullptr, 1.f, 0, 0, 0, time_ms,
        ui::MotionEventAndroid::GetAndroidAction(action), 1, 0, 0, 0, 0, 0, 0,
        0, false, &p, nullptr);
    view->OnTouchEvent(touch);
  }
};

class FrameStableObserver {
 public:
  FrameStableObserver(RenderWidgetHostViewBase* view, base::TimeDelta delta)
      : view_(view), delta_(delta) {}
  virtual ~FrameStableObserver() {}

  void WaitUntilStable() {
    uint32_t current_frame_number = view_->RendererFrameNumber();
    uint32_t previous_frame_number;

    do {
      base::RunLoop run_loop;
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE, run_loop.QuitClosure(), delta_);
      run_loop.Run();
      previous_frame_number = current_frame_number;
      current_frame_number = view_->RendererFrameNumber();
    } while (current_frame_number != previous_frame_number);
  }

 private:
  RenderWidgetHostViewBase* view_;
  base::TimeDelta delta_;

  DISALLOW_COPY_AND_ASSIGN(FrameStableObserver);
};

class TouchSelectionControllerClientTestWrapper
    : public ui::TouchSelectionControllerClient {
 public:
  explicit TouchSelectionControllerClientTestWrapper(
      ui::TouchSelectionControllerClient* client)
      : expected_event_(ui::SELECTION_HANDLES_SHOWN), client_(client) {}

  ~TouchSelectionControllerClientTestWrapper() override {}

  void InitWaitForSelectionEvent(ui::SelectionEventType expected_event) {
    DCHECK(!run_loop_);
    expected_event_ = expected_event;
    run_loop_.reset(new base::RunLoop());
  }

  void Wait() {
    DCHECK(run_loop_);
    run_loop_->Run();
    run_loop_.reset();
  }

 private:
  // TouchSelectionControllerClient:
  void OnSelectionEvent(ui::SelectionEventType event) override {
    client_->OnSelectionEvent(event);
    if (run_loop_ && event == expected_event_)
      run_loop_->Quit();
  }

  bool SupportsAnimation() const override {
    return client_->SupportsAnimation();
  }

  void SetNeedsAnimate() override { client_->SetNeedsAnimate(); }

  void MoveCaret(const gfx::PointF& position) override {
    client_->MoveCaret(position);
  }

  void MoveRangeSelectionExtent(const gfx::PointF& extent) override {
    client_->MoveRangeSelectionExtent(extent);
  }

  void SelectBetweenCoordinates(const gfx::PointF& base,
                                const gfx::PointF& extent) override {
    client_->SelectBetweenCoordinates(base, extent);
  }

  std::unique_ptr<ui::TouchHandleDrawable> CreateDrawable() override {
    return client_->CreateDrawable();
  }

  void DidScroll() override {}

  void OnDragUpdate(const gfx::PointF& position) override {}

  ui::SelectionEventType expected_event_;
  std::unique_ptr<base::RunLoop> run_loop_;
  // Not owned.
  ui::TouchSelectionControllerClient* client_;

  DISALLOW_COPY_AND_ASSIGN(TouchSelectionControllerClientTestWrapper);
};

IN_PROC_BROWSER_TEST_F(TouchSelectionControllerClientAndroidSiteIsolationTest,
                       BasicSelectionIsolatedIframe) {
  GURL test_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), test_url));
  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  EXPECT_EQ(
      " Site A\n"
      "   +--Site A\n"
      "Where A = http://a.com/",
      FrameTreeVisualizer().DepictFrameTree(root));
  TestNavigationObserver observer(shell()->web_contents());
  EXPECT_EQ(1u, root->child_count());
  FrameTreeNode* child = root->child_at(0);

  RenderWidgetHostViewAndroid* parent_view =
      static_cast<RenderWidgetHostViewAndroid*>(
          root->current_frame_host()->GetRenderWidgetHost()->GetView());
  TouchSelectionControllerClientTestWrapper* selection_controller_client =
      new TouchSelectionControllerClientTestWrapper(
          parent_view->GetSelectionControllerClientManagerForTesting());
  parent_view->SetSelectionControllerClientForTesting(
      base::WrapUnique(selection_controller_client));

  // We need to load the desired subframe and then wait until it's stable, i.e.
  // generates no new compositor frames for some reasonable time period: a stray
  // frame between touch selection's pre-handling of GestureLongPress and the
  // expected frame containing the selected region can confuse the
  // TouchSelectionController, causing it to fail to show selection handles.
  // Note this is an issue with the TouchSelectionController in general, and
  // not a property of this test.
  GURL child_url(
      embedded_test_server()->GetURL("b.com", "/touch_selection.html"));
  NavigateFrameToURL(child, child_url);
  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      FrameTreeVisualizer().DepictFrameTree(root));
  // The child will change with the cross-site navigation. It shouldn't change
  // after this.
  child = root->child_at(0);
  WaitForChildFrameSurfaceReady(child->current_frame_host());

  RenderWidgetHostViewChildFrame* child_view =
      static_cast<RenderWidgetHostViewChildFrame*>(
          child->current_frame_host()->GetRenderWidgetHost()->GetView());

  EXPECT_EQ(child_url, observer.last_navigation_url());
  EXPECT_TRUE(observer.last_navigation_succeeded());
  FrameStableObserver child_frame_stable_observer(child_view,
                                                  TestTimeouts::tiny_timeout());
  child_frame_stable_observer.WaitUntilStable();

  EXPECT_EQ(ui::TouchSelectionController::INACTIVE,
            parent_view->touch_selection_controller()->active_status());
  // Find the location of some text to select.
  gfx::PointF point_f;
  std::string str;
  EXPECT_TRUE(ExecuteScriptAndExtractString(child->current_frame_host(),
                                            "get_point_inside_text()", &str));
  ConvertJSONToPoint(str, &point_f);
  point_f = child_view->TransformPointToRootCoordSpaceF(point_f);

  // Initiate selection with a sequence of events that go through the targeting
  // system.
  selection_controller_client->InitWaitForSelectionEvent(
      ui::SELECTION_HANDLES_SHOWN);

  SelectWithLongPress(gfx::Point(point_f.x(), point_f.y()));

  selection_controller_client->Wait();

  // Check that selection is active and the quick menu is showing.
  EXPECT_EQ(ui::TouchSelectionController::SELECTION_ACTIVE,
            parent_view->touch_selection_controller()->active_status());

  // Tap inside/outside the iframe and make sure the selection handles go away.
  selection_controller_client->InitWaitForSelectionEvent(
      ui::SELECTION_HANDLES_CLEARED);
  // Since Android tests may run with page_scale_factor < 1, use an offset a
  // bigger than +/-1 for doing the inside/outside taps to cancel the selection
  // handles.
  gfx::PointF point_inside_iframe =
      child_view->TransformPointToRootCoordSpaceF(gfx::PointF(+5.f, +5.f));
  SimpleTap(gfx::Point(point_inside_iframe.x(), point_inside_iframe.y()));
  selection_controller_client->Wait();

  EXPECT_EQ(ui::TouchSelectionController::INACTIVE,
            parent_view->touch_selection_controller()->active_status());

  // Let's wait for the previous events to clear the round-trip to the renders
  // and back.
  DelayBy(base::TimeDelta::FromMilliseconds(2000));

  // Initiate selection with a sequence of events that go through the targeting
  // system. Repeat of above but this time we'l cancel the selection by
  // tapping outside of the OOPIF.
  selection_controller_client->InitWaitForSelectionEvent(
      ui::SELECTION_HANDLES_SHOWN);

  SelectWithLongPress(gfx::Point(point_f.x(), point_f.y()));

  selection_controller_client->Wait();

  // Check that selection is active and the quick menu is showing.
  EXPECT_EQ(ui::TouchSelectionController::SELECTION_ACTIVE,
            parent_view->touch_selection_controller()->active_status());

  // Tap inside/outside the iframe and make sure the selection handles go away.
  selection_controller_client->InitWaitForSelectionEvent(
      ui::SELECTION_HANDLES_CLEARED);
  // Since Android tests may run with page_scale_factor < 1, use an offset a
  // bigger than +/-1 for doing the inside/outside taps to cancel the selection
  // handles.
  gfx::PointF point_outside_iframe =
      child_view->TransformPointToRootCoordSpaceF(gfx::PointF(-5.f, -5.f));
  SimpleTap(gfx::Point(point_outside_iframe.x(), point_outside_iframe.y()));
  selection_controller_client->Wait();

  EXPECT_EQ(ui::TouchSelectionController::INACTIVE,
            parent_view->touch_selection_controller()->active_status());
}

#endif  // defined(OS_ANDROID)

// Verify that sandbox flags specified by a CSP header are properly inherited by
// child frames, but are removed when the frame navigates.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ActiveSandboxFlagsMaintainedAcrossNavigation) {
  GURL main_url(
      embedded_test_server()->GetURL("a.com", "/sandbox_main_frame_csp.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  ASSERT_EQ(1u, root->child_count());

  EXPECT_EQ(
      " Site A\n"
      "   +--Site A\n"
      "Where A = http://a.com/",
      DepictFrameTree(root));

  FrameTreeNode* child_node = root->child_at(0);

  EXPECT_EQ(shell()->web_contents()->GetSiteInstance(),
            child_node->current_frame_host()->GetSiteInstance());

  // Main page is served with a CSP header applying sandbox flags allow-popups,
  // allow-pointer-lock and allow-scripts.
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kPopups &
                ~blink::WebSandboxFlags::kPointerLock &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->active_sandbox_flags());

  // Child frame has iframe sandbox flags allow-popups, allow-scripts, and
  // allow-orientation-lock. It should receive the intersection of those with
  // the parent sandbox flags: allow-popups and allow-scripts.
  EXPECT_EQ(blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kPopups &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(0)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kPopups &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(0)->effective_frame_policy().sandbox_flags);

  // Document in child frame is served with a CSP header giving sandbox flags
  // allow-scripts, allow-popups and allow-pointer-lock. The final effective
  // flags should only include allow-scripts and allow-popups.
  EXPECT_EQ(blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kPopups &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(0)->active_sandbox_flags());

  // Navigate the child frame to a new page. This should clear any CSP-applied
  // sandbox flags.
  GURL frame_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  NavigateFrameToURL(root->child_at(0), frame_url);

  EXPECT_NE(shell()->web_contents()->GetSiteInstance(),
            child_node->current_frame_host()->GetSiteInstance());

  // Navigating should reset the sandbox flags to the frame owner flags:
  // allow-popups and allow-scripts.
  EXPECT_EQ(blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kPopups &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(0)->active_sandbox_flags());
  EXPECT_EQ(blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kPopups &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(0)->pending_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kPopups &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(0)->effective_frame_policy().sandbox_flags);
}

// Test that after an RFH is swapped out, its old sandbox flags remain active.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ActiveSandboxFlagsRetainedAfterSwapOut) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/sandboxed_main_frame_script.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  RenderFrameHostImpl* rfh =
      static_cast<WebContentsImpl*>(shell()->web_contents())->GetMainFrame();

  // Check sandbox flags on RFH before navigating away.
  EXPECT_EQ(blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kPopups &
                ~blink::WebSandboxFlags::kPointerLock &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            rfh->active_sandbox_flags());

  // Set up a slow unload handler to force the RFH to linger in the swapped
  // out but not-yet-deleted state.
  EXPECT_TRUE(
      ExecuteScript(rfh, "window.onunload=function(e){ while(1); };\n"));

  rfh->DisableSwapOutTimerForTesting();
  RenderFrameDeletedObserver rfh_observer(rfh);

  // Navigate to a page with no sandbox, but wait for commit, not for the actual
  // load to finish.
  TestFrameNavigationObserver commit_observer(root);
  shell()->LoadURL(
      GURL(embedded_test_server()->GetURL("b.com", "/title1.html")));
  commit_observer.WaitForCommit();

  // The previous RFH should still be pending deletion, as we wait for either
  // the SwapOut ACK or a timeout.
  ASSERT_TRUE(rfh->IsRenderFrameLive());
  ASSERT_FALSE(rfh->is_active());
  ASSERT_FALSE(rfh_observer.deleted());

  // Check sandbox flags on old RFH -- they should be unchanged.
  EXPECT_EQ(blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kPopups &
                ~blink::WebSandboxFlags::kPointerLock &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            rfh->active_sandbox_flags());

  // The FrameTreeNode should have flags which represent the new state.
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->effective_frame_policy().sandbox_flags);
}

// Verify that when CSP-set sandbox flags on a page change due to navigation,
// the new flags are propagated to proxies in other SiteInstances.
//
//   A        A         A         A
//    \        \         \         \     .
//     B  ->    B*   ->   B*   ->   B*
//             /  \      /  \      /  \  .
//            B    B    A    B    C    B
//
// (B* has CSP-set sandbox flags)
// The test checks sandbox flags for the proxy added in step 2, by checking
// whether the grandchild frames navigated to in step 3 and 4 see the correct
// sandbox flags.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ActiveSandboxFlagsCorrectInProxies) {
  GURL main_url(embedded_test_server()->GetURL(
      "foo.com", "/cross_site_iframe_factory.html?foo(bar)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  TestNavigationObserver observer(shell()->web_contents());

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "Where A = http://foo.com/\n"
      "      B = http://bar.com/",
      DepictFrameTree(root));

  // Navigate the child to a CSP-sandboxed page on the same origin as it is
  // currently. This should update the flags in its proxies as well.
  NavigateFrameToURL(
      root->child_at(0),
      embedded_test_server()->GetURL("bar.com", "/csp_sandboxed_frame.html"));

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "        |--Site B -- proxies for A\n"
      "        +--Site B -- proxies for A\n"
      "Where A = http://foo.com/\n"
      "      B = http://bar.com/",
      DepictFrameTree(root));

  // Now navigate the first grandchild to a page on the same origin as the main
  // frame. It should still be sandboxed, as it should get its flags from its
  // (remote) parent.
  NavigateFrameToURL(root->child_at(0)->child_at(0),
                     embedded_test_server()->GetURL("foo.com", "/title1.html"));

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "        |--Site A -- proxies for B\n"
      "        +--Site B -- proxies for A\n"
      "Where A = http://foo.com/\n"
      "      B = http://bar.com/",
      DepictFrameTree(root));

  // The child of the sandboxed frame should've inherited sandbox flags, so it
  // should not be able to create popups.
  EXPECT_EQ(
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
          ~blink::WebSandboxFlags::kAutomaticFeatures,
      root->child_at(0)->child_at(0)->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(
      root->child_at(0)->child_at(0)->active_sandbox_flags(),
      root->child_at(0)->child_at(0)->effective_frame_policy().sandbox_flags);
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0)->child_at(0),
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());

  // Finally, navigate the grandchild frame to a new origin, creating a new site
  // instance. Again, the new document should be sandboxed, as it should get its
  // flags from its (remote) parent in B.
  NavigateFrameToURL(root->child_at(0)->child_at(0),
                     embedded_test_server()->GetURL("baz.com", "/title1.html"));

  EXPECT_EQ(
      " Site A ------------ proxies for B C\n"
      "   +--Site B ------- proxies for A C\n"
      "        |--Site C -- proxies for A B\n"
      "        +--Site B -- proxies for A C\n"
      "Where A = http://foo.com/\n"
      "      B = http://bar.com/\n"
      "      C = http://baz.com/",
      DepictFrameTree(root));

  // The child of the sandboxed frame should've inherited sandbox flags, so it
  // should not be able to create popups.
  EXPECT_EQ(
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
          ~blink::WebSandboxFlags::kAutomaticFeatures,
      root->child_at(0)->child_at(0)->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(
      root->child_at(0)->child_at(0)->active_sandbox_flags(),
      root->child_at(0)->child_at(0)->effective_frame_policy().sandbox_flags);
  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0)->child_at(0),
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());
}

// Verify that when the sandbox iframe attribute changes on a page which also
// has CSP-set sandbox flags, that the correct combination of flags is set in
// the sandboxed page after navigation.
//
//   A        A         A                                  A
//    \        \         \                                  \     .
//     B  ->    B*   ->   B*   -> (change sandbox attr) ->   B*
//             /  \      /  \                               /  \  .
//            B    B    A    B                             A'   B
//
// (B* has CSP-set sandbox flags)
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ActiveSandboxFlagsCorrectAfterUpdate) {
  GURL main_url(embedded_test_server()->GetURL(
      "foo.com", "/cross_site_iframe_factory.html?foo(bar)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  TestNavigationObserver observer(shell()->web_contents());

  // Navigate the child to a CSP-sandboxed page on the same origin as it is
  // currently. This should update the flags in its proxies as well.
  NavigateFrameToURL(
      root->child_at(0),
      embedded_test_server()->GetURL("bar.com", "/csp_sandboxed_frame.html"));

  // Now navigate the first grandchild to a page on the same origin as the main
  // frame. It should still be sandboxed, as it should get its flags from its
  // (remote) parent.
  NavigateFrameToURL(root->child_at(0)->child_at(0),
                     embedded_test_server()->GetURL("foo.com", "/title1.html"));

  // The child of the sandboxed frame should've inherited sandbox flags, so it
  // should not be able to create popups.
  EXPECT_EQ(
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
          ~blink::WebSandboxFlags::kAutomaticFeatures,
      root->child_at(0)->child_at(0)->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(
      root->child_at(0)->child_at(0)->active_sandbox_flags(),
      root->child_at(0)->child_at(0)->effective_frame_policy().sandbox_flags);
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0)->child_at(0),
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());

  // Update the sandbox attribute in the child frame. This should be overridden
  // by the CSP-set sandbox on this frame: The grandchild should *not* receive
  // an allowance for popups after it is navigated.
  EXPECT_TRUE(ExecuteScript(root->child_at(0),
                            "document.querySelector('iframe').sandbox = "
                            "    'allow-scripts allow-popups';"));
  // Finally, navigate the grandchild frame to another page on the top-level
  // origin; the active sandbox flags should still come from the it's parent's
  // CSP and the frame owner attributes.
  NavigateFrameToURL(root->child_at(0)->child_at(0),
                     embedded_test_server()->GetURL("foo.com", "/title2.html"));
  EXPECT_EQ(
      blink::WebSandboxFlags::kAll & ~blink::WebSandboxFlags::kScripts &
          ~blink::WebSandboxFlags::kAutomaticFeatures,
      root->child_at(0)->child_at(0)->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(
      root->child_at(0)->child_at(0)->active_sandbox_flags(),
      root->child_at(0)->child_at(0)->effective_frame_policy().sandbox_flags);
  success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(0)->child_at(0),
      "window.domAutomationController.send("
      "    !window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(1u, Shell::windows().size());
}

// Verify that when the sandbox iframe attribute is removed from a page which
// also has CSP-set sandbox flags, that the flags are cleared in the browser
// and renderers (including proxies) after navigation to a page without CSP-set
// flags.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ActiveSandboxFlagsCorrectWhenCleared) {
  GURL main_url(
      embedded_test_server()->GetURL("foo.com", "/sandboxed_frames_csp.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // It is safe to obtain the root frame tree node here, as it doesn't change.
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  TestNavigationObserver observer(shell()->web_contents());

  // The second child has both iframe-attribute sandbox flags and CSP-set flags.
  // Verify that it the flags are combined correctly in the frame tree.
  EXPECT_EQ(blink::WebSandboxFlags::kAll &
                ~blink::WebSandboxFlags::kPointerLock &
                ~blink::WebSandboxFlags::kOrientationLock &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(1)->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kAll &
                ~blink::WebSandboxFlags::kPointerLock &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(1)->active_sandbox_flags());

  NavigateFrameToURL(
      root->child_at(1),
      embedded_test_server()->GetURL("bar.com", "/sandboxed_child_frame.html"));
  EXPECT_EQ(blink::WebSandboxFlags::kAll &
                ~blink::WebSandboxFlags::kPointerLock &
                ~blink::WebSandboxFlags::kOrientationLock &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(1)->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kAll &
                ~blink::WebSandboxFlags::kPointerLock &
                ~blink::WebSandboxFlags::kScripts &
                ~blink::WebSandboxFlags::kAutomaticFeatures,
            root->child_at(1)->active_sandbox_flags());

  // Remove the sandbox attribute from the child frame.
  EXPECT_TRUE(ExecuteScript(root,
                            "document.querySelectorAll('iframe')[1]"
                            ".removeAttribute('sandbox');"));
  // Finally, navigate that child frame to another page on the same origin with
  // no CSP-set sandbox. Its sandbox flags should be completely cleared, and
  // should be cleared in the proxy in the main frame's renderer as well.
  // We can check that the flags were properly cleared by nesting another frame
  // under the child, and ensuring that *it* saw no sandbox flags in the
  // browser, or in the RemoteSecurityContext in the main frame's renderer.
  NavigateFrameToURL(
      root->child_at(1),
      embedded_test_server()->GetURL(
          "bar.com", "/cross_site_iframe_factory.html?bar(foo)"));

  // Check the sandbox flags on the child frame in the browser process.
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(1)->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(blink::WebSandboxFlags::kNone,
            root->child_at(1)->active_sandbox_flags());

  // Check the sandbox flags on the grandchid frame in the browser process.
  EXPECT_EQ(
      blink::WebSandboxFlags::kNone,
      root->child_at(1)->child_at(0)->effective_frame_policy().sandbox_flags);
  EXPECT_EQ(
      root->child_at(1)->child_at(0)->active_sandbox_flags(),
      root->child_at(1)->child_at(0)->effective_frame_policy().sandbox_flags);

  // Check the sandbox flags in the grandchild frame's renderer by attempting
  // to open a popup. This should succeed.
  bool success = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->child_at(1)->child_at(0),
      "window.domAutomationController.send("
      "    !!window.open('data:text/html,dataurl'));",
      &success));
  EXPECT_TRUE(success);
  EXPECT_EQ(2u, Shell::windows().size());
}

// Check that a subframe that requires a dedicated process will attempt to
// reuse an existing process for the same site, even across BrowsingInstances.
// This helps consolidate processes when running under --site-per-process.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       SubframeReusesExistingProcess) {
  GURL foo_url(
      embedded_test_server()->GetURL("foo.com", "/page_with_iframe.html"));
  EXPECT_TRUE(NavigateToURL(shell(), foo_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);

  // Open an unrelated tab in a separate BrowsingInstance, and navigate it to
  // to bar.com.  This SiteInstance should have a default process reuse
  // policy - only subframes attempt process reuse.
  GURL bar_url(
      embedded_test_server()->GetURL("bar.com", "/page_with_iframe.html"));
  Shell* second_shell = CreateBrowser();
  EXPECT_TRUE(NavigateToURL(second_shell, bar_url));
  scoped_refptr<SiteInstanceImpl> second_shell_instance =
      static_cast<SiteInstanceImpl*>(
          second_shell->web_contents()->GetMainFrame()->GetSiteInstance());
  EXPECT_FALSE(second_shell_instance->IsRelatedSiteInstance(
      root->current_frame_host()->GetSiteInstance()));
  RenderProcessHost* bar_process = second_shell_instance->GetProcess();
  EXPECT_EQ(SiteInstanceImpl::ProcessReusePolicy::DEFAULT,
            second_shell_instance->process_reuse_policy());

  // Now navigate the first tab's subframe to bar.com.  Confirm that it reuses
  // |bar_process|.
  NavigateIframeToURL(web_contents(), "test_iframe", bar_url);
  EXPECT_EQ(bar_url, child->current_url());
  EXPECT_EQ(bar_process, child->current_frame_host()->GetProcess());
  EXPECT_EQ(
      SiteInstanceImpl::ProcessReusePolicy::REUSE_PENDING_OR_COMMITTED_SITE,
      child->current_frame_host()->GetSiteInstance()->process_reuse_policy());

  EXPECT_TRUE(child->current_frame_host()->IsCrossProcessSubframe());
  EXPECT_EQ(
      bar_url.host(),
      child->current_frame_host()->GetSiteInstance()->GetSiteURL().host());

  // The subframe's SiteInstance should still be different from second_shell's
  // SiteInstance, and they should be in separate BrowsingInstances.
  EXPECT_NE(second_shell_instance,
            child->current_frame_host()->GetSiteInstance());
  EXPECT_FALSE(second_shell_instance->IsRelatedSiteInstance(
      child->current_frame_host()->GetSiteInstance()));

  // Navigate the second tab to a foo.com URL with a same-site subframe.  This
  // leaves only the first tab's subframe in the bar.com process.
  EXPECT_TRUE(NavigateToURL(second_shell, foo_url));
  EXPECT_NE(bar_process,
            second_shell->web_contents()->GetMainFrame()->GetProcess());

  // Navigate the second tab's subframe to bar.com, and check that this
  // new subframe reuses the process of the subframe in the first tab, even
  // though the two are in separate BrowsingInstances.
  NavigateIframeToURL(second_shell->web_contents(), "test_iframe", bar_url);
  FrameTreeNode* second_subframe =
      static_cast<WebContentsImpl*>(second_shell->web_contents())
          ->GetFrameTree()
          ->root()
          ->child_at(0);
  EXPECT_EQ(bar_process, second_subframe->current_frame_host()->GetProcess());
  EXPECT_NE(child->current_frame_host()->GetSiteInstance(),
            second_subframe->current_frame_host()->GetSiteInstance());

  // Open a third, unrelated tab, navigate it to bar.com, and check that
  // its main frame doesn't share a process with the existing bar.com
  // subframes.
  Shell* third_shell = CreateBrowser();
  EXPECT_TRUE(NavigateToURL(third_shell, bar_url));
  SiteInstanceImpl* third_shell_instance = static_cast<SiteInstanceImpl*>(
      third_shell->web_contents()->GetMainFrame()->GetSiteInstance());
  EXPECT_NE(third_shell_instance,
            second_subframe->current_frame_host()->GetSiteInstance());
  EXPECT_NE(third_shell_instance,
            child->current_frame_host()->GetSiteInstance());
  EXPECT_NE(third_shell_instance->GetProcess(), bar_process);
}

// Check that when a subframe reuses an existing process for the same site
// across BrowsingInstances, a browser-initiated navigation in that subframe's
// tab doesn't unnecessarily share the reused process.  See
// https://crbug.com/803367.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       NoProcessSharingAfterSubframeReusesExistingProcess) {
  GURL foo_url(embedded_test_server()->GetURL("foo.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), foo_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  SiteInstanceImpl* foo_instance =
      root->current_frame_host()->GetSiteInstance();

  // Open an unrelated tab in a separate BrowsingInstance, and navigate it to
  // to bar.com.
  GURL bar_url(
      embedded_test_server()->GetURL("bar.com", "/page_with_iframe.html"));
  Shell* second_shell = CreateBrowser();
  EXPECT_TRUE(NavigateToURL(second_shell, bar_url));
  FrameTreeNode* second_root =
      static_cast<WebContentsImpl*>(second_shell->web_contents())
          ->GetFrameTree()
          ->root();
  FrameTreeNode* second_child = second_root->child_at(0);
  scoped_refptr<SiteInstanceImpl> bar_instance =
      second_root->current_frame_host()->GetSiteInstance();
  EXPECT_FALSE(bar_instance->IsRelatedSiteInstance(foo_instance));

  // Navigate the second tab's subframe to foo.com.  Confirm that it reuses
  // first tab's process.
  NavigateIframeToURL(second_shell->web_contents(), "test_iframe", foo_url);
  EXPECT_EQ(foo_url, second_child->current_url());
  scoped_refptr<SiteInstanceImpl> second_child_foo_instance =
      second_child->current_frame_host()->GetSiteInstance();
  EXPECT_EQ(
      SiteInstanceImpl::ProcessReusePolicy::REUSE_PENDING_OR_COMMITTED_SITE,
      second_child_foo_instance->process_reuse_policy());
  EXPECT_NE(foo_instance, second_child_foo_instance);
  EXPECT_EQ(foo_instance->GetProcess(),
            second_child_foo_instance->GetProcess());

  // Perform a browser-initiated address bar navigation in the second tab to
  // foo.com.  This should swap BrowsingInstances and end up in a separate
  // process from the first tab.
  EXPECT_TRUE(NavigateToURL(second_shell, foo_url));
  SiteInstanceImpl* new_instance =
      second_root->current_frame_host()->GetSiteInstance();
  EXPECT_NE(second_child_foo_instance, new_instance);
  EXPECT_FALSE(second_child_foo_instance->IsRelatedSiteInstance(new_instance));
  EXPECT_FALSE(bar_instance->IsRelatedSiteInstance(new_instance));
  EXPECT_FALSE(foo_instance->IsRelatedSiteInstance(new_instance));
  EXPECT_NE(new_instance->GetProcess(), foo_instance->GetProcess());
  EXPECT_NE(new_instance->GetProcess(), bar_instance->GetProcess());
}

namespace {

// Intercepts the next DidCommitProvisionalLoad message for |deferred_url| in
// any frame of the |web_contents|, and holds off on dispatching it until
// *after* the DidCommitProvisionalLoad message for the next navigation in the
// |web_contents| has been dispatched.
//
// Reversing the order in which the commit messages are dispatched simulates a
// busy renderer that takes a very long time to actually commit the navigation
// to |deferred_url| after receiving FrameNavigationControl::CommitNavigation;
// whereas there is a fast cross-site navigation taking place in the same
// frame which starts second but finishes first.
class CommitMessageOrderReverser : public DidCommitProvisionalLoadInterceptor {
 public:
  using DidStartDeferringCommitCallback =
      base::OnceCallback<void(RenderFrameHost*)>;

  CommitMessageOrderReverser(
      WebContents* web_contents,
      const GURL& deferred_url,
      DidStartDeferringCommitCallback deferred_url_triggered_action)
      : DidCommitProvisionalLoadInterceptor(web_contents),
        deferred_url_(deferred_url),
        deferred_url_triggered_action_(
            std::move(deferred_url_triggered_action)) {}
  ~CommitMessageOrderReverser() override = default;

  void WaitForBothCommits() { outer_run_loop.Run(); }

 protected:
  void WillDispatchDidCommitProvisionalLoad(
      RenderFrameHost* render_frame_host,
      ::FrameHostMsg_DidCommitProvisionalLoad_Params* params,
      service_manager::mojom::InterfaceProviderRequest*
          interface_provider_request) override {
    // The DidCommitProvisionalLoad message is dispatched once this method
    // returns, so to defer committing the the navigation to |deferred_url_|,
    // run a nested message loop until the subsequent other commit message is
    // dispatched.
    if (params->url == deferred_url_) {
      std::move(deferred_url_triggered_action_).Run(render_frame_host);

      base::RunLoop nested_run_loop(base::RunLoop::Type::kNestableTasksAllowed);
      nested_loop_quit_ = nested_run_loop.QuitClosure();
      nested_run_loop.Run();
      outer_run_loop.Quit();
    } else if (nested_loop_quit_) {
      std::move(nested_loop_quit_).Run();
    }
  }

 private:
  base::RunLoop outer_run_loop;
  base::OnceClosure nested_loop_quit_;

  const GURL deferred_url_;
  DidStartDeferringCommitCallback deferred_url_triggered_action_;

  DISALLOW_COPY_AND_ASSIGN(CommitMessageOrderReverser);
};

}  // namespace

// Regression test for https://crbug.com/877239, simulating the following
// scenario:
//
//  1) http://a.com/empty.html is loaded in a main frame.
//  2) Dynamically by JS, a same-site child frame is added:
//       <iframe 'src=http://a.com/title1.html'/>.
//  3) The initial byte of the response for `title1.html` arrives, causing
//     FrameMsg_CommitNavigation to be sent to the same renderer.
//  4) Just before processing this message, however, `main.html` navigates
//     the iframe to http://baz.com/title2.html, which results in mojom::Frame::
//     BeginNavigation being called on the RenderFrameHost.
//  5) Suppose that immediately afterwards, `main.html` enters a busy-loop.
//  6) The cross site navigation in the child frame starts, the first response
//     byte arrives quickly, and thus the navigation commits quickly.
//  6.1) FrameTreeNode::has_committed_real_load is set to true for the child.
//  6.2) The same-site RenderFrame in the child FrameTreeNode is swapped out,
//       i.e. FrameMsg_SwapOut is sent.
//  7) The renderer for site instance `a.com` exits from the busy loop,
//     and starts processing messages in order:
//  7.1) The first being processed is FrameMsg_CommitNavigation, so a
//       provisional load is created and immediately committed to
//       http://a.com/title1.html.
//  7.2) Because at the time the same-site child RenderFrame was created,
//       there had been no real load committed in the child frame, and because
//       the navigation from the initial empty document to the first real
//       document was same-origin, the global object is reused and the
//       RemoteInterfaceProvider of the RenderFrame is not rebound.
//  7.3) The obsoleted load in the same-site child frame commits, calling
//       mojom::Frame::DidCommitProvisionalLoad, however, with
//       |interface_provider_request| being null.
//  8) RenderFrameHostImpl::DidCommitProvisionalLoad sees that a real load was
//     already committed in the frame, but |interface_provider_request| is
//     missing. However, it also sees that the frame was waiting for a swap-out
//     ACK, so ignores the commit, and does not kill the renderer process.
//
// In the simulation of this scenario, we simulate (5) not by delaying
// renderer-side processing of the CommmitNavigation message, but by delaying
// browser-side processing of the response to it, of DidCommitProvisionalLoad.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       InterfaceProviderRequestIsOptionalForRaceyFirstCommits) {
  const GURL kMainFrameUrl(
      embedded_test_server()->GetURL("a.com", "/empty.html"));
  const GURL kSubframeSameSiteUrl(
      embedded_test_server()->GetURL("a.com", "/title1.html"));
  const GURL kCrossSiteSubframeUrl(
      embedded_test_server()->GetURL("baz.com", "/title2.html"));

  const auto kAddSameSiteDynamicSubframe = base::StringPrintf(
      "var f = document.createElement(\"iframe\");"
      "f.src=\"%s\";"
      "document.body.append(f);",
      kSubframeSameSiteUrl.spec().c_str());
  const auto kNavigateSubframeCrossSite = base::StringPrintf(
      "f.src = \"%s\";", kCrossSiteSubframeUrl.spec().c_str());
  const std::string kExtractSubframeUrl =
      "window.domAutomationController.send(f.src);";

  ASSERT_TRUE(NavigateToURL(shell(), kMainFrameUrl));

  const auto* main_rfh_site_instance =
      shell()->web_contents()->GetMainFrame()->GetSiteInstance();

  auto did_start_deferring_commit_callback =
      base::BindLambdaForTesting([&](RenderFrameHost* subframe_rfh) {
        // Verify that the subframe starts out as same-process with its parent.
        ASSERT_EQ(main_rfh_site_instance, subframe_rfh->GetSiteInstance());

        // Trigger the second commit now that we are deferring the first one.
        ASSERT_TRUE(ExecuteScript(shell(), kNavigateSubframeCrossSite));
      });

  CommitMessageOrderReverser commit_order_reverser(
      shell()->web_contents(), kSubframeSameSiteUrl /* deferred_url */,
      std::move(did_start_deferring_commit_callback));

  ASSERT_TRUE(ExecuteScript(shell(), kAddSameSiteDynamicSubframe));
  commit_order_reverser.WaitForBothCommits();

  // Verify that:
  //  - The cross-site navigation in the sub-frame was committed and the
  //    same-site navigation was ignored.
  //  - The parent frame thinks so, too.
  //  - The renderer process corresponding to the sub-frame with the ignored
  //    commit was not killed. This is verified implicitly: this is the same
  //    renderer process where the parent RenderFrame lives, so if the call to
  //    ExecuteScriptAndExtractString succeeds here, the process is still alive.
  std::string actual_subframe_url;
  ASSERT_TRUE(ExecuteScriptAndExtractString(shell(), kExtractSubframeUrl,
                                            &actual_subframe_url));
  EXPECT_EQ(kCrossSiteSubframeUrl.spec(), actual_subframe_url);
}

// Create an out-of-process iframe that causes itself to be detached during
// its layout/animate phase. See https://crbug.com/802932.
// Disabled on Android due to flakiness, https://crbug.com/809580.
#if defined(OS_ANDROID)
#define MAYBE_OOPIFDetachDuringAnimation DISABLED_OOPIFDetachDuringAnimation
#else
#define MAYBE_OOPIFDetachDuringAnimation OOPIFDetachDuringAnimation
#endif
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       MAYBE_OOPIFDetachDuringAnimation) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/frame_tree/frame-detached-in-animationstart-event.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  EXPECT_EQ(
      " Site A ------------ proxies for B\n"
      "   +--Site B ------- proxies for A\n"
      "        +--Site A -- proxies for B\n"
      "Where A = http://a.com/\n"
      "      B = http://b.com/",
      DepictFrameTree(root));

  FrameTreeNode* nested_child = root->child_at(0)->child_at(0);
  WaitForChildFrameSurfaceReady(nested_child->current_frame_host());

  EXPECT_TRUE(
      ExecuteScript(nested_child->current_frame_host(), "startTest();"));

  // Test passes if the main renderer doesn't crash. Ping to verify.
  bool success;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root->current_frame_host(), "window.domAutomationController.send(true);",
      &success));
  EXPECT_TRUE(success);
}

// Tests that a cross-process iframe asked to navigate to the same URL will
// successfully commit the navigation.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       IFrameSameDocumentNavigation) {
  GURL main_url(embedded_test_server()->GetURL(
      "foo.com", "/cross_site_iframe_factory.html?foo(bar)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* iframe = root->child_at(0);

  EXPECT_NE(root->current_frame_host()->GetSiteInstance(),
            iframe->current_frame_host()->GetSiteInstance());

  // The iframe navigates same-document to a fragment.
  GURL iframe_fragment_url = GURL(iframe->current_url().spec() + "#foo");
  {
    TestNavigationObserver observer(shell()->web_contents());
    EXPECT_TRUE(
        ExecuteScript(iframe->current_frame_host(),
                      "location.href=\"" + iframe_fragment_url.spec() + "\";"));
    observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(iframe_fragment_url, iframe->current_url());
  }

  // The parent frame wants the iframe do a navigation to the same URL. Because
  // the URL has a fragment, this will be treated as a same-document navigation,
  // and not as a normal load of the same URL. This should succeed.
  {
    TestNavigationObserver observer(shell()->web_contents());
    EXPECT_TRUE(ExecuteScript(root->current_frame_host(),
                              "document.getElementById('child-0').src=\"" +
                                  iframe_fragment_url.spec() + "\";"));
    observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(iframe_fragment_url, iframe->current_url());
  }
}

// Verifies that when navigating an OOPIF to same site and then canceling
// navigation from beforeunload handler popup will not remove the
// RemoteFrameView from OOPIF's owner element in the parent process. This test
// uses OOPIF visibility to make sure RemoteFrameView exists after beforeunload
// is handled.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CanceledBeforeUnloadShouldNotClearRemoteFrameView) {
  GURL a_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), a_url));

  FrameTreeNode* child_node =
      web_contents()->GetFrameTree()->root()->child_at(0);
  GURL b_url(embedded_test_server()->GetURL(
      "b.com", "/render_frame_host/beforeunload.html"));
  NavigateFrameToURL(child_node, b_url);
  FrameConnectorDelegate* frame_connector_delegate =
      static_cast<RenderWidgetHostViewChildFrame*>(
          child_node->current_frame_host()->GetView())
          ->FrameConnectorForTesting();

  // Need user gesture for 'beforeunload' to fire.
  PrepContentsForBeforeUnloadTest(web_contents());

  // Simulate user choosing to stay on the page after beforeunload fired.
  SetShouldProceedOnBeforeUnload(shell(), true /* proceed */,
                                 false /* success */);

  // First, hide the <iframe>. This goes through RemoteFrameView::Hide() and
  // eventually updates the FrameConnectorDelegate. Also,
  // RemoteFrameView::self_visible_ will be set to false which can only be
  // undone by calling RemoteFrameView::Show. Therefore, potential calls to
  // RemoteFrameView::SetParentVisible(true) would not update the visibility at
  // the browser side.
  ASSERT_TRUE(ExecuteScript(
      web_contents(),
      "document.querySelector('iframe').style.visibility = 'hidden';"));
  while (!frame_connector_delegate->IsHidden()) {
    base::RunLoop run_loop;
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(), TestTimeouts::tiny_timeout());
    run_loop.Run();
  }

  // Now we navigate the child to about:blank, but since we do not proceed with
  // the navigation, the OOPIF should stay alive and RemoteFrameView intact.
  ASSERT_TRUE(ExecuteScript(
      web_contents(), "document.querySelector('iframe').src = 'about:blank';"));
  WaitForAppModalDialog(shell());

  // Sanity check: We should still have an OOPIF and hence a RWHVCF.
  ASSERT_TRUE(static_cast<RenderWidgetHostViewBase*>(
                  child_node->current_frame_host()->GetView())
                  ->IsRenderWidgetHostViewChildFrame());

  // Now make the <iframe> visible again. This calls RemoteFrameView::Show()
  // only if the RemoteFrameView is the EmbeddedContentView of the corresponding
  // HTMLFrameOwnerElement.
  ASSERT_TRUE(ExecuteScript(
      web_contents(),
      "document.querySelector('iframe').style.visibility = 'visible';"));
  while (frame_connector_delegate->IsHidden()) {
    base::RunLoop run_loop;
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(), TestTimeouts::tiny_timeout());
    run_loop.Run();
  }
}

// Verifies the the renderer has the size of the frame after commit.
// https://crbug/804046, https://crbug.com/801091
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, SizeAvailableAfterCommit) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  FrameTreeNode* child = root->child_at(0);

  GURL b_url(embedded_test_server()->GetURL("b.com", "/title2.html"));
  TestFrameNavigationObserver commit_observer(child);
  NavigationController::LoadURLParams params(b_url);
  params.transition_type = PageTransitionFromInt(ui::PAGE_TRANSITION_LINK);
  params.frame_tree_node_id = child->frame_tree_node_id();
  child->navigator()->GetController()->LoadURLWithParams(params);
  commit_observer.WaitForCommit();

  int height = -1;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(
      child, "window.domAutomationController.send(window.innerHeight);",
      &height));

  EXPECT_GT(height, 0);
}
// Test that a late swapout ACK won't incorrectly mark RenderViewHost as
// inactive if it's already been reused and switched to active by another
// navigation.  See https://crbug.com/823567.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       RenderViewHostStaysActiveWithLateSwapoutACK) {
  EXPECT_TRUE(NavigateToURL(
      shell(), embedded_test_server()->GetURL("a.com", "/title1.html")));

  // Open a popup and navigate it to a.com.
  Shell* popup = OpenPopup(
      shell(), embedded_test_server()->GetURL("a.com", "/title2.html"), "foo");
  WebContentsImpl* popup_contents =
      static_cast<WebContentsImpl*>(popup->web_contents());
  RenderFrameHostImpl* rfh = popup_contents->GetMainFrame();
  RenderViewHostImpl* rvh = rfh->render_view_host();

  // Disable the swapout ACK and the swapout timer.
  scoped_refptr<SwapoutACKMessageFilter> filter = new SwapoutACKMessageFilter();
  rfh->GetProcess()->AddFilter(filter.get());
  rfh->DisableSwapOutTimerForTesting();

  // Navigate popup to b.com.  Because there's an opener, the RVH for a.com
  // stays around in swapped-out state.
  EXPECT_TRUE(NavigateToURLInSameBrowsingInstance(
      popup, embedded_test_server()->GetURL("b.com", "/title3.html")));
  EXPECT_FALSE(rvh->is_active());

  // The old RenderFrameHost is now pending deletion.
  ASSERT_TRUE(rfh->IsRenderFrameLive());
  ASSERT_FALSE(rfh->is_active());

  // Kill the b.com process.
  RenderProcessHost* b_process = popup_contents->GetMainFrame()->GetProcess();
  RenderProcessHostWatcher crash_observer(
      b_process, RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  b_process->Shutdown(0);
  crash_observer.Wait();

  // Go back in the popup from b.com to a.com/title2.html.  Because the current
  // b.com RFH is dead, the new RFH is committed right away (without waiting
  // for renderer to commit), so that users don't need to look at the sad tab.
  TestNavigationObserver back_observer(popup_contents);
  popup_contents->GetController().GoBack();

  // Pretend that the original RFH in a.com now finishes running its unload
  // handler and sends the swapout ACK.
  rfh->OnSwappedOut();

  // Wait for the new a.com navigation to finish.
  back_observer.Wait();

  // The RVH for a.com should've been reused, and it should be active.  Its
  // main frame should've been updated to the RFH from the back navigation.
  EXPECT_EQ(popup_contents->GetMainFrame()->render_view_host(), rvh);
  EXPECT_TRUE(rvh->is_active());
  EXPECT_EQ(rvh->GetMainFrame(), popup_contents->GetMainFrame());
}

// Check that when A opens a new window with B which embeds an A subframe, the
// subframe is visible and generates paint events.  See
// https://crbug.com/638375.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       SubframeVisibleAfterRenderViewBecomesSwappedOut) {
  GURL main_url(embedded_test_server()->GetURL("a.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  GURL popup_url(embedded_test_server()->GetURL(
      "b.com", "/cross_site_iframe_factory.html?b(b)"));
  Shell* popup_shell = OpenPopup(shell()->web_contents(), popup_url, "popup");
  FrameTreeNode* popup_child =
      static_cast<WebContentsImpl*>(popup_shell->web_contents())
          ->GetFrameTree()
          ->root()
          ->child_at(0);

  // Navigate popup's subframe to a page on a.com, which will generate
  // continuous compositor frames by incrementing a counter on the page.
  NavigateFrameToURL(popup_child,
                     embedded_test_server()->GetURL("a.com", "/counter.html"));

  RenderWidgetHostViewChildFrame* child_view =
      static_cast<RenderWidgetHostViewChildFrame*>(
          popup_child->current_frame_host()->GetView());

  // Make sure the child frame keeps generating compositor frames.
  ChildFrameCompositorFrameSwapCounter counter(child_view);
  counter.WaitForNewFrames(10u);
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, FrameDepthSimple) {
  // Five nodes, from depth 0 to 4.
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b(c(d(e))))"));
  const size_t number_of_nodes = 5;
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* node = web_contents()->GetFrameTree()->root();
  for (unsigned int expected_depth = 0; expected_depth < number_of_nodes;
       ++expected_depth) {
    CheckFrameDepth(expected_depth, node);

    if (expected_depth + 1 < number_of_nodes)
      node = node->child_at(0);
  }
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, FrameDepthTest) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(a,b(a))"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  CheckFrameDepth(0u, root);

  FrameTreeNode* child0 = root->child_at(0);
  {
    EXPECT_EQ(1u, child0->depth());
    RenderProcessHost::Priority priority =
        child0->current_frame_host()->GetRenderWidgetHost()->GetPriority();
    // Same site instance as root.
    EXPECT_EQ(0u, priority.frame_depth);
    EXPECT_EQ(
        0u,
        child0->current_frame_host()->GetProcess()->GetFrameDepthForTesting());
  }

  FrameTreeNode* child1 = root->child_at(1);
  CheckFrameDepth(1u, child1);
  // In addition, site b's inactive Widget should not contribute priority.
  RenderViewHostImpl* child1_rvh =
      child1->current_frame_host()->render_view_host();
  EXPECT_FALSE(child1_rvh->is_active());
  EXPECT_EQ(RenderProcessHostImpl::kMaxFrameDepthForPriority,
            child1_rvh->GetWidget()->GetPriority().frame_depth);
  EXPECT_FALSE(static_cast<RenderWidgetHostOwnerDelegate*>(child1_rvh)
                   ->ShouldContributePriorityToProcess());

  FrameTreeNode* grand_child = root->child_at(1)->child_at(0);
  {
    EXPECT_EQ(2u, grand_child->depth());
    RenderProcessHost::Priority priority =
        grand_child->current_frame_host()->GetRenderWidgetHost()->GetPriority();
    EXPECT_EQ(2u, priority.frame_depth);
    // Same process as root
    EXPECT_EQ(0u, grand_child->current_frame_host()
                      ->GetProcess()
                      ->GetFrameDepthForTesting());
  }
}

IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest, VisibilityFrameDepthTest) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  GURL popup_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  Shell* new_shell = OpenPopup(root->child_at(0), popup_url, "");
  FrameTreeNode* popup_root =
      static_cast<WebContentsImpl*>(new_shell->web_contents())
          ->GetFrameTree()
          ->root();

  // Subframe and popup share the same process. Both are visible, so depth
  // should be 0.
  RenderProcessHost* subframe_process =
      root->child_at(0)->current_frame_host()->GetProcess();
  RenderProcessHost* popup_process =
      popup_root->current_frame_host()->GetProcess();
  EXPECT_EQ(subframe_process, popup_process);
  EXPECT_EQ(2, popup_process->VisibleClientCount());
  EXPECT_EQ(0u, popup_process->GetFrameDepthForTesting());

  // Hide popup. Process should have one visible client and depth should be 1,
  // since depth 0 popup is hidden.
  new_shell->web_contents()->WasHidden();
  EXPECT_EQ(1, popup_process->VisibleClientCount());
  EXPECT_EQ(1u, popup_process->GetFrameDepthForTesting());

  // Navigate main page to same origin as popup in same BrowsingInstance,
  // s main page should run in the same process as the popup. The depth on the
  // process should be 0, from the main frame of main page.
  EXPECT_TRUE(NavigateToURLInSameBrowsingInstance(shell(), popup_url));
  // Performing a Load causes aura window to be focused (see
  // Shell::LoadURLForFrame) which recomputes window occlusion for all windows
  // (on chromeos) which unhides the popup. Hide popup again.
  new_shell->web_contents()->WasHidden();
  RenderProcessHost* new_root_process =
      root->current_frame_host()->GetProcess();
  EXPECT_EQ(new_root_process, popup_process);
  EXPECT_EQ(1, popup_process->VisibleClientCount());
  EXPECT_EQ(0u, popup_process->GetFrameDepthForTesting());

  // Go back on main page. Should go back to same state as before navigation.
  TestNavigationObserver back_load_observer(shell()->web_contents());
  shell()->web_contents()->GetController().GoBack();
  back_load_observer.Wait();
  EXPECT_EQ(1, popup_process->VisibleClientCount());
  EXPECT_EQ(1u, popup_process->GetFrameDepthForTesting());

  // Unhide popup. Should go back to same state as before hide.
  new_shell->web_contents()->WasShown();
  EXPECT_EQ(2, popup_process->VisibleClientCount());
  EXPECT_EQ(0u, popup_process->GetFrameDepthForTesting());
}

// Ensure that after a main frame with an OOPIF is navigated cross-site, the
// unload handler in the OOPIF sees correct main frame origin, namely the old
// and not the new origin.  See https://crbug.com/825283.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       ParentOriginDoesNotChangeInUnloadHandler) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  // Open a popup on b.com.  The b.com subframe on the main frame will use this
  // in its unload handler.
  GURL b_url(embedded_test_server()->GetURL("b.com", "/title1.html"));
  EXPECT_TRUE(OpenPopup(shell()->web_contents(), b_url, "popup"));

  // Add an unload handler to b.com subframe, which will look up the top
  // frame's origin and send it via domAutomationController.  Unfortunately,
  // the subframe's browser-side state will have been torn down when it runs
  // the unload handler, so to ensure that the message can be received, send it
  // through the popup.
  EXPECT_TRUE(
      ExecuteScript(root->child_at(0),
                    "window.onunload = function(e) {"
                    "  window.open('','popup').domAutomationController.send("
                    "      'top-origin ' + location.ancestorOrigins[0]);"
                    "};"));

  // Navigate the main frame to c.com and wait for the message from the
  // subframe's unload handler.
  GURL c_url(embedded_test_server()->GetURL("c.com", "/title1.html"));
  DOMMessageQueue msg_queue;
  EXPECT_TRUE(NavigateToURL(shell(), c_url));
  std::string message, top_origin;
  while (msg_queue.WaitForMessage(&message)) {
    base::TrimString(message, "\"", &message);
    auto message_parts = base::SplitString(message, " ", base::TRIM_WHITESPACE,
                                           base::SPLIT_WANT_NONEMPTY);
    if (message_parts[0] == "top-origin") {
      top_origin = message_parts[1];
      break;
    }
  }

  // The top frame's origin should be a.com, not c.com.
  EXPECT_EQ(top_origin + "/", main_url.GetOrigin().spec());
}

// Check that when a postMessage is called on a remote frame, it waits for the
// current script block to finish executing before forwarding the postMessage,
// so that if the script causes any other IPCs to be sent in the same event
// loop iteration, those IPCs are processed, and their side effects are
// observed by the target frame before it receives the forwarded postMessage.
// See https://crbug.com/828529.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CrossProcessPostMessageWaitsForCurrentScriptToFinish) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();
  EXPECT_EQ(root, root->frame_tree()->GetFocusedFrame());

  // Add an onmessage handler to the subframe to send back a bool of whether
  // the subframe has focus.
  EXPECT_TRUE(
      ExecuteScript(root->child_at(0),
                    "window.addEventListener('message', function(event) {\n"
                    "  domAutomationController.send(document.hasFocus());\n"
                    "});"));

  // Now, send a postMessage from main frame to subframe, and then focus the
  // subframe in the same script.  postMessage should be scheduled after the
  // focus() call, so the IPC to focus the subframe should arrive before the
  // postMessage IPC, and the subframe should already know that it's focused in
  // the onmessage handler.
  bool child_has_focus = false;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(root,
                                          "frames[0].postMessage('','*');\n"
                                          "frames[0].focus();\n",
                                          &child_has_focus));
  EXPECT_TRUE(child_has_focus);
}

// Ensure that if a cross-process postMessage is scheduled, and then the target
// frame is detached before the postMessage is forwarded, the source frame's
// renderer does not crash.
IN_PROC_BROWSER_TEST_F(SitePerProcessBrowserTest,
                       CrossProcessPostMessageAndDetachTarget) {
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  FrameTreeNode* root = web_contents()->GetFrameTree()->root();

  // Send a postMessage to the subframe and then immediately detach the
  // subframe.
  EXPECT_TRUE(ExecuteScript(root,
                            "frames[0].postMessage('','*');\n"
                            "document.body.removeChild(\n"
                            "    document.querySelector('iframe'));\n"));

  // Test passes if the main renderer doesn't crash.  Use setTimeout to ensure
  // this ping is evaluated after the (scheduled) postMessage is processed.
  bool success;
  EXPECT_TRUE(ExecuteScriptAndExtractBool(
      root,
      "setTimeout(() => { window.domAutomationController.send(true); }, 0)",
      &success));
  EXPECT_TRUE(success);
}

}  // namespace content

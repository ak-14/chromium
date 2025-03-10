// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "base/auto_reset.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/macros.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "content/browser/renderer_host/input/synthetic_gesture.h"
#include "content/browser/renderer_host/input/synthetic_gesture_controller.h"
#include "content/browser/renderer_host/input/synthetic_gesture_target.h"
#include "content/browser/renderer_host/input/synthetic_smooth_scroll_gesture.h"
#include "content/browser/renderer_host/render_widget_host_impl.h"
#include "content/browser/renderer_host/render_widget_host_view_base.h"
#include "content/browser/web_contents/web_contents_impl.h"
#include "content/common/input/synthetic_gesture_params.h"
#include "content/common/input/synthetic_smooth_scroll_gesture_params.h"
#include "content/common/input_messages.h"
#include "content/public/browser/render_view_host.h"
#include "content/public/browser/render_widget_host_view.h"
#include "content/public/common/content_switches.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/content_browser_test.h"
#include "content/public/test/content_browser_test_utils.h"
#include "content/public/test/test_utils.h"
#include "content/shell/browser/shell.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "ui/latency/latency_info.h"

using blink::WebInputEvent;

namespace {

const char kTouchActionDataURL[] =
    "data:text/html;charset=utf-8,"
    "<!DOCTYPE html>"
    "<meta name='viewport' content='width=device-width'/>"
    "<style>"
    "html, body {"
    "  margin: 0;"
    "}"
    ".box {"
    "  height: 96px;"
    "  width: 96px;"
    "  border: 2px solid blue;"
    "}"
    ".spacer { height: 10000px; }"
    ".ta-none { touch-action: none; }"
    "</style>"
    "<div class=box></div>"
    "<div class='box ta-none'></div>"
    "<div class=spacer></div>"
    "<script>"
    "  window.eventCounts = "
    "    {touchstart:0, touchmove:0, touchend: 0, touchcancel:0};"
    "  function countEvent(e) { eventCounts[e.type]++; }"
    "  for (var evt in eventCounts) { "
    "    document.addEventListener(evt, countEvent); "
    "  }"
    "  document.title='ready';"
    "</script>";

const char kTouchActionURLWithOverlapArea[] =
    "data:text/html;charset=utf-8,"
    "<!DOCTYPE html>"
    "<meta name='viewport' content='width=device-width'/>"
    "<style>"
    "html, body {"
    "  margin: 0;"
    "}"
    ".box {"
    "  box-sizing: border-box;"
    "  height: 100px;"
    "  width: 100px;"
    "  border: 2px solid blue;"
    "  position: absolute;"
    "  will-change: transform;"
    "}"
    ".spacer {"
    "  height: 10000px;"
    "  width: 10000px;"
    "}"
    ".ta-auto {"
    "  top: 52px;"
    "  left: 52px;"
    "  touch-action: auto;"
    "}"
    ".ta-pany {"
    "  top: 102px;"
    "  left: 2px;"
    "  touch-action: pan-y;"
    "}"
    ".ta-panx {"
    "  top: 2px;"
    "  left: 102px;"
    "  touch-action: pan-x;"
    "}"
    "</style>"
    "<div class='box ta-panx'></div>"
    "<div class='box ta-pany'></div>"
    "<div class='box ta-auto'></div>"
    "<div class=spacer></div>"
    "<script>"
    "  document.title='ready';"
    "</script>";

void GiveItSomeTime(int t) {
  base::RunLoop run_loop;
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, run_loop.QuitClosure(), base::TimeDelta::FromMilliseconds(t));
  run_loop.Run();
}

constexpr base::TimeDelta kNoJankTime = base::TimeDelta::FromMilliseconds(0);
constexpr base::TimeDelta kShortJankTime =
    base::TimeDelta::FromMilliseconds(100);
// 1200ms is larger than both desktop / mobile_touch_ack_timeout_delay in the
// PassthroughTouchEventQueue, which ensures timeout to be triggered.
constexpr base::TimeDelta kLongJankTime =
    base::TimeDelta::FromMilliseconds(1200);
}  // namespace

namespace content {


class TouchActionBrowserTest : public ContentBrowserTest {
 public:
  TouchActionBrowserTest() {}
  ~TouchActionBrowserTest() override {}

  RenderWidgetHostImpl* GetWidgetHost() {
    return RenderWidgetHostImpl::From(
        shell()->web_contents()->GetRenderViewHost()->GetWidget());
  }

  void OnSyntheticGestureCompleted(SyntheticGesture::Result result) {
    EXPECT_EQ(SyntheticGesture::GESTURE_FINISHED, result);
    runner_->Quit();
  }

 protected:
  void LoadURL(const char* touch_action_url) {
    const GURL data_url(touch_action_url);
    NavigateToURL(shell(), data_url);

    RenderWidgetHostImpl* host = GetWidgetHost();
    frame_observer_ = std::make_unique<RenderFrameSubmissionObserver>(
        host->render_frame_metadata_provider());
    host->GetView()->SetSize(gfx::Size(400, 400));

    base::string16 ready_title(base::ASCIIToUTF16("ready"));
    TitleWatcher watcher(shell()->web_contents(), ready_title);
    ignore_result(watcher.WaitAndGetTitle());

    // We need to wait until at least one frame has been composited
    // otherwise the injection of the synthetic gestures may get
    // dropped because of MainThread/Impl thread sync of touch event
    // regions.
    frame_observer_->WaitForAnyFrameSubmission();
  }

  // ContentBrowserTest:
  void SetUpCommandLine(base::CommandLine* cmd) override {
    cmd->AppendSwitchASCII(switches::kTouchEventFeatureDetection,
                           switches::kTouchEventFeatureDetectionEnabled);
    // TODO(rbyers): Remove this switch once touch-action ships.
    // http://crbug.com/241964
    cmd->AppendSwitch(switches::kEnableExperimentalWebPlatformFeatures);
  }

  // ContentBrowserTest:
  void PostRunTestOnMainThread() override {
    // Delete this before the WebContents is destroyed.
    frame_observer_.reset();
    ContentBrowserTest::PostRunTestOnMainThread();
  }

  int ExecuteScriptAndExtractInt(const std::string& script) {
    int value = 0;
    EXPECT_TRUE(content::ExecuteScriptAndExtractInt(
        shell(), "domAutomationController.send(" + script + ")", &value));
    return value;
  }

  void JankMainThread(base::TimeDelta delta) {
    std::string script = "var end = performance.now() + ";
    script.append(std::to_string(delta.InMilliseconds()));
    script.append("; while (performance.now() < end) ; ");
    EXPECT_TRUE(content::ExecuteScript(shell(), script));
  }

  double ExecuteScriptAndExtractDouble(const std::string& script) {
    double value = 0;
    EXPECT_TRUE(content::ExecuteScriptAndExtractDouble(
        shell(), "domAutomationController.send(" + script + ")", &value));
    return value;
  }

  double GetScrollTop() {
    return ExecuteScriptAndExtractDouble("document.scrollingElement.scrollTop");
  }

  double GetScrollLeft() {
    return ExecuteScriptAndExtractDouble(
        "document.scrollingElement.scrollLeft");
  }

  bool URLLoaded() {
    base::string16 ready_title(base::ASCIIToUTF16("ready"));
    TitleWatcher watcher(shell()->web_contents(), ready_title);
    const base::string16 title = watcher.WaitAndGetTitle();
    return title == ready_title;
  }

  // In this test, we first jank the main thread for 1200ms. Then we let the
  // first finger scroll along the x-direction, on a pan-y area, for 1 second.
  // While the first finger is still scrolling, we let the second finger
  // touching the same area and scroll along the same direction. We purposely
  // trigger touch ack timeout for the first finger touch. All we need to ensure
  // is that the second finger also scrolled.
  void DoTwoFingerTouchScroll(
      bool wait_until_scrolled,
      const gfx::Vector2d& expected_scroll_position_after_scroll) {
    SyntheticSmoothScrollGestureParams params1;
    params1.gesture_source_type = SyntheticGestureParams::TOUCH_INPUT;
    params1.anchor = gfx::PointF(25, 125);
    params1.distances.push_back(gfx::Vector2dF(-5, 0));
    params1.prevent_fling = true;
    params1.speed_in_pixels_s = 5;

    SyntheticSmoothScrollGestureParams params2;
    params2.gesture_source_type = SyntheticGestureParams::TOUCH_INPUT;
    params2.anchor = gfx::PointF(25, 125);
    params2.distances.push_back(gfx::Vector2dF(-50, 0));

    runner_ = new MessageLoopRunner();

    std::unique_ptr<SyntheticSmoothScrollGesture> gesture1(
        new SyntheticSmoothScrollGesture(params1));
    GetWidgetHost()->QueueSyntheticGesture(
        std::move(gesture1),
        base::BindOnce(&TouchActionBrowserTest::OnSyntheticGestureCompleted,
                       base::Unretained(this)));

    JankMainThread(kLongJankTime);
    GiveItSomeTime(800);

    std::unique_ptr<SyntheticSmoothScrollGesture> gesture2(
        new SyntheticSmoothScrollGesture(params2));
    GetWidgetHost()->QueueSyntheticGesture(
        std::move(gesture2),
        base::BindOnce(&TouchActionBrowserTest::OnSyntheticGestureCompleted,
                       base::Unretained(this)));

    // Runs until we get the OnSyntheticGestureCompleted callback
    runner_->Run();
    runner_ = nullptr;

    CheckScrollOffset(wait_until_scrolled,
                      expected_scroll_position_after_scroll);
  }

  // Generate touch events for a synthetic scroll from |point| for |distance|.
  void DoTouchScroll(const gfx::Point& point,
                     const gfx::Vector2d& distance,
                     bool wait_until_scrolled,
                     int expected_scroll_height_after_scroll,
                     const gfx::Vector2d& expected_scroll_position_after_scroll,
                     const base::TimeDelta& jank_time) {
    DCHECK(URLLoaded());
    EXPECT_EQ(0, GetScrollTop());

    int scroll_height =
        ExecuteScriptAndExtractInt("document.documentElement.scrollHeight");
    EXPECT_EQ(expected_scroll_height_after_scroll, scroll_height);

    SyntheticSmoothScrollGestureParams params;
    params.gesture_source_type = SyntheticGestureParams::TOUCH_INPUT;
    params.anchor = gfx::PointF(point);
    params.distances.push_back(-distance);

    runner_ = new MessageLoopRunner();

    std::unique_ptr<SyntheticSmoothScrollGesture> gesture(
        new SyntheticSmoothScrollGesture(params));
    GetWidgetHost()->QueueSyntheticGesture(
        std::move(gesture),
        base::BindOnce(&TouchActionBrowserTest::OnSyntheticGestureCompleted,
                       base::Unretained(this)));

    if (jank_time > base::TimeDelta::FromMilliseconds(0))
      JankMainThread(jank_time);

    // Runs until we get the OnSyntheticGestureCompleted callback
    runner_->Run();
    runner_ = nullptr;

    CheckScrollOffset(wait_until_scrolled,
                      expected_scroll_position_after_scroll);
  }

 private:
  void CheckScrollOffset(
      bool wait_until_scrolled,
      const gfx::Vector2d& expected_scroll_position_after_scroll) {
    gfx::Vector2dF default_scroll_offset;
    gfx::Vector2dF root_scroll_offset =
        frame_observer_->LastRenderFrameMetadata().root_scroll_offset.value_or(
            default_scroll_offset);

    // GetScrollTop() and GetScrollLeft() goes through the main thread, here
    // we want to make sure that the compositor already scrolled before asking
    // the main thread.
    while (wait_until_scrolled &&
           (root_scroll_offset.y() <
                expected_scroll_position_after_scroll.y() / 2 ||
            root_scroll_offset.x() <
                expected_scroll_position_after_scroll.x() / 2)) {
      frame_observer_->WaitForMetadataChange();
      root_scroll_offset =
          frame_observer_->LastRenderFrameMetadata()
              .root_scroll_offset.value_or(default_scroll_offset);
    }

    // Check the scroll offset
    int scroll_top = GetScrollTop();
    int scroll_left = GetScrollLeft();

    // Allow for 1px rounding inaccuracies for some screen sizes.
    EXPECT_LE(expected_scroll_position_after_scroll.y() / 2, scroll_top);
    EXPECT_LE(expected_scroll_position_after_scroll.x() / 2, scroll_left);
  }

  std::unique_ptr<RenderFrameSubmissionObserver> frame_observer_;
  scoped_refptr<MessageLoopRunner> runner_;

  DISALLOW_COPY_AND_ASSIGN(TouchActionBrowserTest);
};

// Mac doesn't yet have a gesture recognizer, so can't support turning touch
// events into scroll gestures.
// Will be fixed with http://crbug.com/337142
#if defined(OS_MACOSX)
#define MAYBE_DefaultAuto DISABLED_DefaultAuto
#else
#define MAYBE_DefaultAuto DefaultAuto
#endif
//
// Verify the test infrastructure works - we can touch-scroll the page and get a
// touchcancel as expected.
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest, MAYBE_DefaultAuto) {
  LoadURL(kTouchActionDataURL);

  DoTouchScroll(gfx::Point(50, 50), gfx::Vector2d(0, 45), true, 10200,
                gfx::Vector2d(0, 45), kNoJankTime);

  EXPECT_EQ(1, ExecuteScriptAndExtractInt("eventCounts.touchstart"));
  EXPECT_GE(ExecuteScriptAndExtractInt("eventCounts.touchmove"), 1);
  EXPECT_EQ(1, ExecuteScriptAndExtractInt("eventCounts.touchend"));
  EXPECT_EQ(0, ExecuteScriptAndExtractInt("eventCounts.touchcancel"));
}

// Verify that touching a touch-action: none region disables scrolling and
// enables all touch events to be sent.
// Disabled on MacOS because it doesn't support touch input.
#if defined(OS_MACOSX)
#define MAYBE_TouchActionNone DISABLED_TouchActionNone
#else
#define MAYBE_TouchActionNone TouchActionNone
#endif
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest, MAYBE_TouchActionNone) {
  LoadURL(kTouchActionDataURL);

  DoTouchScroll(gfx::Point(50, 150), gfx::Vector2d(0, 45), false, 10200,
                gfx::Vector2d(0, 0), kNoJankTime);

  EXPECT_EQ(1, ExecuteScriptAndExtractInt("eventCounts.touchstart"));
  EXPECT_GE(ExecuteScriptAndExtractInt("eventCounts.touchmove"), 1);
  EXPECT_EQ(1, ExecuteScriptAndExtractInt("eventCounts.touchend"));
  EXPECT_EQ(0, ExecuteScriptAndExtractInt("eventCounts.touchcancel"));
}

#if defined(OS_MACOSX)
#define MAYBE_PanYMainThreadJanky DISABLED_PanYMainThreadJanky
#else
#define MAYBE_PanYMainThreadJanky PanYMainThreadJanky
#endif
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest, MAYBE_PanYMainThreadJanky) {
  LoadURL(kTouchActionURLWithOverlapArea);

  DoTouchScroll(gfx::Point(25, 125), gfx::Vector2d(0, 45), false, 10000,
                gfx::Vector2d(0, 45), kShortJankTime);
}

#if defined(OS_MACOSX)
#define MAYBE_PanXMainThreadJanky DISABLED_PanXMainThreadJanky
#else
#define MAYBE_PanXMainThreadJanky PanXMainThreadJanky
#endif
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest, MAYBE_PanXMainThreadJanky) {
  LoadURL(kTouchActionURLWithOverlapArea);

  DoTouchScroll(gfx::Point(125, 25), gfx::Vector2d(45, 0), false, 10000,
                gfx::Vector2d(45, 0), kShortJankTime);
}

#if defined(OS_ANDROID)
#define MAYBE_PanXAtYAreaWithTimeout PanXAtYAreaWithTimeout
#else
#define MAYBE_PanXAtYAreaWithTimeout DISABLED_PanXAtYAreaWithTimeout
#endif
// When touch ack timeout is triggered, the panx gesture will be allowed even
// though we touch the pany area.
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest, MAYBE_PanXAtYAreaWithTimeout) {
  LoadURL(kTouchActionURLWithOverlapArea);

  DoTouchScroll(gfx::Point(25, 125), gfx::Vector2d(45, 0), false, 10000,
                gfx::Vector2d(45, 0), kLongJankTime);
}

#if defined(OS_ANDROID)
#define MAYBE_TwoFingerPanXAtYAreaWithTimeout TwoFingerPanXAtYAreaWithTimeout
#else
#define MAYBE_TwoFingerPanXAtYAreaWithTimeout \
  DISABLED_TwoFingerPanXAtYAreaWithTimeout
#endif
// When touch ack timeout is triggered, the panx gesture will be allowed even
// though we touch the pany area.
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest,
                       MAYBE_TwoFingerPanXAtYAreaWithTimeout) {
  LoadURL(kTouchActionURLWithOverlapArea);

  DoTwoFingerTouchScroll(false, gfx::Vector2d(20, 0));
}

#if defined(OS_MACOSX)
#define MAYBE_PanXYMainThreadJanky DISABLED_PanXYMainThreadJanky
#else
#define MAYBE_PanXYMainThreadJanky PanXYMainThreadJanky
#endif
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest, MAYBE_PanXYMainThreadJanky) {
  LoadURL(kTouchActionURLWithOverlapArea);

  DoTouchScroll(gfx::Point(75, 60), gfx::Vector2d(45, 45), false, 10000,
                gfx::Vector2d(45, 45), kShortJankTime);
}

#if defined(OS_MACOSX)
#define MAYBE_PanXYAtXAreaMainThreadJanky DISABLED_PanXYAtXAreaMainThreadJanky
#else
#define MAYBE_PanXYAtXAreaMainThreadJanky PanXYAtXAreaMainThreadJanky
#endif
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest,
                       MAYBE_PanXYAtXAreaMainThreadJanky) {
  LoadURL(kTouchActionURLWithOverlapArea);

  DoTouchScroll(gfx::Point(125, 25), gfx::Vector2d(45, 45), false, 10000,
                gfx::Vector2d(45, 0), kShortJankTime);
}

#if defined(OS_MACOSX) || defined(OS_CHROMEOS) || defined(OS_WIN) || \
    defined(OS_LINUX)
#define MAYBE_PanXYAtYAreaMainThreadJanky DISABLED_PanXYAtYAreaMainThreadJanky
#else
#define MAYBE_PanXYAtYAreaMainThreadJanky PanXYAtYAreaMainThreadJanky
#endif
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest,
                       MAYBE_PanXYAtYAreaMainThreadJanky) {
  LoadURL(kTouchActionURLWithOverlapArea);

  DoTouchScroll(gfx::Point(25, 125), gfx::Vector2d(45, 45), false, 10000,
                gfx::Vector2d(0, 45), kShortJankTime);
}

#if defined(OS_MACOSX)
#define MAYBE_PanXYAtAutoYOverlapAreaMainThreadJanky \
  DISABLED_PanXYAtAutoYOverlapAreaMainThreadJanky
#else
#define MAYBE_PanXYAtAutoYOverlapAreaMainThreadJanky \
  PanXYAtAutoYOverlapAreaMainThreadJanky
#endif
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest,
                       MAYBE_PanXYAtAutoYOverlapAreaMainThreadJanky) {
  LoadURL(kTouchActionURLWithOverlapArea);

  DoTouchScroll(gfx::Point(75, 125), gfx::Vector2d(45, 45), false, 10000,
                gfx::Vector2d(0, 45), kShortJankTime);
}

#if defined(OS_MACOSX)
#define MAYBE_PanXYAtAutoXOverlapAreaMainThreadJanky \
  DISABLED_PanXYAtAutoXOverlapAreaMainThreadJanky
#else
#define MAYBE_PanXYAtAutoXOverlapAreaMainThreadJanky \
  PanXYAtAutoXOverlapAreaMainThreadJanky
#endif
IN_PROC_BROWSER_TEST_F(TouchActionBrowserTest,
                       MAYBE_PanXYAtAutoXOverlapAreaMainThreadJanky) {
  LoadURL(kTouchActionURLWithOverlapArea);

  DoTouchScroll(gfx::Point(125, 75), gfx::Vector2d(45, 45), false, 10000,
                gfx::Vector2d(45, 0), kShortJankTime);
}

}  // namespace content

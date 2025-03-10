// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/render_widget.h"

#include <tuple>
#include <vector>

#include "base/macros.h"
#include "base/optional.h"
#include "base/run_loop.h"
#include "base/test/histogram_tester.h"
#include "base/test/scoped_task_environment.h"
#include "components/viz/common/features.h"
#include "components/viz/common/surfaces/parent_local_surface_id_allocator.h"
#include "content/common/input/input_handler.mojom.h"
#include "content/common/input/synthetic_web_input_event_builders.h"
#include "content/common/input_messages.h"
#include "content/common/resize_params.h"
#include "content/common/view_messages.h"
#include "content/public/common/content_features.h"
#include "content/public/test/mock_render_thread.h"
#include "content/renderer/devtools/render_widget_screen_metrics_emulator.h"
#include "content/renderer/input/widget_input_handler_manager.h"
#include "content/test/fake_compositor_dependencies.h"
#include "content/test/mock_render_process.h"
#include "ipc/ipc_test_sink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_coalesced_input_event.h"
#include "third_party/blink/public/web/web_device_emulation_params.h"
#include "ui/events/base_event_utils.h"
#include "ui/events/blink/web_input_event_traits.h"
#include "ui/gfx/geometry/rect.h"

using testing::_;

namespace ui {

bool operator==(const ui::DidOverscrollParams& lhs,
                const ui::DidOverscrollParams& rhs) {
  return lhs.accumulated_overscroll == rhs.accumulated_overscroll &&
         lhs.latest_overscroll_delta == rhs.latest_overscroll_delta &&
         lhs.current_fling_velocity == rhs.current_fling_velocity &&
         lhs.causal_event_viewport_point == rhs.causal_event_viewport_point &&
         lhs.overscroll_behavior == rhs.overscroll_behavior;
}

}  // namespace ui

namespace content {

namespace {

const char* EVENT_LISTENER_RESULT_HISTOGRAM = "Event.PassiveListeners";

// Keep in sync with enum defined in
// RenderWidgetInputHandler::LogPassiveEventListenersUma.
enum {
  PASSIVE_LISTENER_UMA_ENUM_PASSIVE,
  PASSIVE_LISTENER_UMA_ENUM_UNCANCELABLE,
  PASSIVE_LISTENER_UMA_ENUM_SUPPRESSED,
  PASSIVE_LISTENER_UMA_ENUM_CANCELABLE,
  PASSIVE_LISTENER_UMA_ENUM_CANCELABLE_AND_CANCELED,
  PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_FLING,
  PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_MAIN_THREAD_RESPONSIVENESS,
  PASSIVE_LISTENER_UMA_ENUM_COUNT
};

class MockWidgetInputHandlerHost : public mojom::WidgetInputHandlerHost {
 public:
  MockWidgetInputHandlerHost(
      mojo::InterfaceRequest<mojom::WidgetInputHandlerHost> request)
      : binding_(this, std::move(request)) {}
  MOCK_METHOD0(CancelTouchTimeout, void());

  MOCK_METHOD3(SetWhiteListedTouchAction,
               void(cc::TouchAction, uint32_t, content::InputEventAckState));

  MOCK_METHOD1(DidOverscroll, void(const ui::DidOverscrollParams&));

  MOCK_METHOD0(DidStopFlinging, void());

  MOCK_METHOD0(DidStartScrollingViewport, void());

  MOCK_METHOD0(ImeCancelComposition, void());

  MOCK_METHOD2(ImeCompositionRangeChanged,
               void(const gfx::Range&, const std::vector<gfx::Rect>&));

 private:
  mojo::Binding<mojom::WidgetInputHandlerHost> binding_;

  DISALLOW_COPY_AND_ASSIGN(MockWidgetInputHandlerHost);
};

// Since std::unique_ptr isn't copyable we can't use the
// MockCallback template.
class MockHandledEventCallback {
 public:
  MockHandledEventCallback() = default;
  MOCK_METHOD4_T(Run,
                 void(InputEventAckState,
                      const ui::LatencyInfo&,
                      std::unique_ptr<ui::DidOverscrollParams>&,
                      base::Optional<cc::TouchAction>));

  HandledEventCallback GetCallback() {
    return BindOnce(&MockHandledEventCallback::HandleCallback,
                    base::Unretained(this));
  }

 private:
  void HandleCallback(InputEventAckState ack_state,
                      const ui::LatencyInfo& latency_info,
                      std::unique_ptr<ui::DidOverscrollParams> overscroll,
                      base::Optional<cc::TouchAction> touch_action) {
    Run(ack_state, latency_info, overscroll, touch_action);
  }

  DISALLOW_COPY_AND_ASSIGN(MockHandledEventCallback);
};

class MockWebWidget : public blink::WebWidget {
 public:
  MOCK_METHOD0(DispatchBufferedTouchEvents, blink::WebInputEventResult());
  MOCK_METHOD1(
      HandleInputEvent,
      blink::WebInputEventResult(const blink::WebCoalescedInputEvent&));
};

}  // namespace

class InteractiveRenderWidget : public RenderWidget {
 public:
  explicit InteractiveRenderWidget(CompositorDependencies* compositor_deps)
      : RenderWidget(++next_routing_id_,
                     compositor_deps,
                     blink::kWebPopupTypeNone,
                     ScreenInfo(),
                     false,
                     false,
                     false,
                     blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        always_overscroll_(false) {
    Init(RenderWidget::ShowCallback(), mock_webwidget());

    mojom::WidgetInputHandlerHostPtr widget_input_handler;
    mock_input_handler_host_ = std::make_unique<MockWidgetInputHandlerHost>(
        mojo::MakeRequest(&widget_input_handler));

    widget_input_handler_manager_->AddInterface(
        nullptr, std::move(widget_input_handler));
  }

  void SendInputEvent(const blink::WebInputEvent& event,
                      HandledEventCallback callback) {
    HandleInputEvent(blink::WebCoalescedInputEvent(
                         event, std::vector<const blink::WebInputEvent*>()),
                     ui::LatencyInfo(), std::move(callback));
  }

  void set_always_overscroll(bool overscroll) {
    always_overscroll_ = overscroll;
  }

  IPC::TestSink* sink() { return &sink_; }

  MockWebWidget* mock_webwidget() { return &mock_webwidget_; }

  MockWidgetInputHandlerHost* mock_input_handler_host() {
    return mock_input_handler_host_.get();
  }

  const viz::LocalSurfaceId& local_surface_id() const {
    return local_surface_id_;
  }

  void SetAutoResizeMode(bool enable) { auto_resize_mode_ = enable; }

  void UpdateChildLocalSurfaceIdAllocatorForAutoResize(
      const viz::LocalSurfaceId& parent_local_surface_id) {
    child_local_surface_id_allocator_.UpdateFromParent(parent_local_surface_id);
  }

 protected:
  ~InteractiveRenderWidget() override { webwidget_internal_ = nullptr; }

  // Overridden from RenderWidget:
  bool WillHandleGestureEvent(const blink::WebGestureEvent& event) override {
    if (always_overscroll_ &&
        event.GetType() == blink::WebInputEvent::kGestureScrollUpdate) {
      DidOverscroll(blink::WebFloatSize(event.data.scroll_update.delta_x,
                                        event.data.scroll_update.delta_y),
                    blink::WebFloatSize(event.data.scroll_update.delta_x,
                                        event.data.scroll_update.delta_y),
                    event.PositionInWidget(),
                    blink::WebFloatSize(event.data.scroll_update.velocity_x,
                                        event.data.scroll_update.velocity_y),
                    blink::WebOverscrollBehavior());
      return true;
    }

    return false;
  }

  bool Send(IPC::Message* msg) override {
    sink_.OnMessageReceived(*msg);
    delete msg;
    return true;
  }

 private:
  IPC::TestSink sink_;
  bool always_overscroll_;
  MockWebWidget mock_webwidget_;
  std::unique_ptr<MockWidgetInputHandlerHost> mock_input_handler_host_;
  static int next_routing_id_;

  DISALLOW_COPY_AND_ASSIGN(InteractiveRenderWidget);
};

int InteractiveRenderWidget::next_routing_id_ = 0;

class RenderWidgetUnittest : public testing::Test {
 public:
  RenderWidgetUnittest() {
    widget_ = new InteractiveRenderWidget(&compositor_deps_);
    // RenderWidget::Init does an AddRef that's balanced by a browser-initiated
    // Close IPC. That Close will never happen in this test, so do a Release
    // here to ensure |widget_| is properly freed.
    widget_->Release();
    DCHECK(widget_->HasOneRef());
  }

  ~RenderWidgetUnittest() override {}

  InteractiveRenderWidget* widget() const { return widget_.get(); }

  const base::HistogramTester& histogram_tester() const {
    return histogram_tester_;
  }

 protected:
  base::test::ScopedTaskEnvironment scoped_task_environment_;

 private:
  MockRenderProcess render_process_;
  MockRenderThread render_thread_;
  FakeCompositorDependencies compositor_deps_;
  scoped_refptr<InteractiveRenderWidget> widget_;
  base::HistogramTester histogram_tester_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetUnittest);
};

TEST_F(RenderWidgetUnittest, EventOverscroll) {
  widget()->set_always_overscroll(true);

  EXPECT_CALL(*widget()->mock_webwidget(), HandleInputEvent(_))
      .WillRepeatedly(
          ::testing::Return(blink::WebInputEventResult::kNotHandled));

  blink::WebGestureEvent scroll(
      blink::WebInputEvent::kGestureScrollUpdate,
      blink::WebInputEvent::kNoModifiers,
      ui::EventTimeStampToSeconds(ui::EventTimeForNow()));
  scroll.SetPositionInWidget(gfx::PointF(-10, 0));
  scroll.data.scroll_update.delta_y = 10;
  MockHandledEventCallback handled_event;

  ui::DidOverscrollParams expected_overscroll;
  expected_overscroll.latest_overscroll_delta = gfx::Vector2dF(0, 10);
  expected_overscroll.accumulated_overscroll = gfx::Vector2dF(0, 10);
  expected_overscroll.causal_event_viewport_point = gfx::PointF(-10, 0);
  expected_overscroll.current_fling_velocity = gfx::Vector2dF();

  // Overscroll notifications received while handling an input event should
  // be bundled with the event ack IPC.
  EXPECT_CALL(handled_event, Run(INPUT_EVENT_ACK_STATE_CONSUMED, _,
                                 testing::Pointee(expected_overscroll), _))
      .Times(1);

  widget()->SendInputEvent(scroll, handled_event.GetCallback());
}

TEST_F(RenderWidgetUnittest, FlingOverscroll) {
  ui::DidOverscrollParams expected_overscroll;
  expected_overscroll.latest_overscroll_delta = gfx::Vector2dF(10, 5);
  expected_overscroll.accumulated_overscroll = gfx::Vector2dF(5, 5);
  expected_overscroll.causal_event_viewport_point = gfx::PointF(1, 1);
  expected_overscroll.current_fling_velocity = gfx::Vector2dF(10, 5);

  EXPECT_CALL(*widget()->mock_input_handler_host(),
              DidOverscroll(expected_overscroll))
      .Times(1);

  // Overscroll notifications received outside of handling an input event should
  // be sent as a separate IPC.
  widget()->DidOverscroll(blink::WebFloatSize(10, 5), blink::WebFloatSize(5, 5),
                          blink::WebFloatPoint(1, 1),
                          blink::WebFloatSize(10, 5),
                          blink::WebOverscrollBehavior());
  base::RunLoop().RunUntilIdle();
}

TEST_F(RenderWidgetUnittest, RenderWidgetInputEventUmaMetrics) {
  SyntheticWebTouchEvent touch;
  touch.PressPoint(10, 10);
  touch.touch_start_or_first_touch_move = true;

  EXPECT_CALL(*widget()->mock_webwidget(), HandleInputEvent(_))
      .Times(7)
      .WillRepeatedly(
          ::testing::Return(blink::WebInputEventResult::kNotHandled));

  EXPECT_CALL(*widget()->mock_webwidget(), DispatchBufferedTouchEvents())
      .Times(7)
      .WillRepeatedly(
          ::testing::Return(blink::WebInputEventResult::kNotHandled));

  widget()->SendInputEvent(touch, HandledEventCallback());
  histogram_tester().ExpectBucketCount(EVENT_LISTENER_RESULT_HISTOGRAM,
                                       PASSIVE_LISTENER_UMA_ENUM_CANCELABLE, 1);

  touch.dispatch_type = blink::WebInputEvent::DispatchType::kEventNonBlocking;
  widget()->SendInputEvent(touch, HandledEventCallback());
  histogram_tester().ExpectBucketCount(EVENT_LISTENER_RESULT_HISTOGRAM,
                                       PASSIVE_LISTENER_UMA_ENUM_UNCANCELABLE,
                                       1);

  touch.dispatch_type =
      blink::WebInputEvent::DispatchType::kListenersNonBlockingPassive;
  widget()->SendInputEvent(touch, HandledEventCallback());
  histogram_tester().ExpectBucketCount(EVENT_LISTENER_RESULT_HISTOGRAM,
                                       PASSIVE_LISTENER_UMA_ENUM_PASSIVE, 1);

  touch.dispatch_type =
      blink::WebInputEvent::DispatchType::kListenersForcedNonBlockingDueToFling;
  widget()->SendInputEvent(touch, HandledEventCallback());
  histogram_tester().ExpectBucketCount(
      EVENT_LISTENER_RESULT_HISTOGRAM,
      PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_FLING, 1);

  touch.MovePoint(0, 10, 10);
  touch.touch_start_or_first_touch_move = true;
  touch.dispatch_type =
      blink::WebInputEvent::DispatchType::kListenersForcedNonBlockingDueToFling;
  widget()->SendInputEvent(touch, HandledEventCallback());
  histogram_tester().ExpectBucketCount(
      EVENT_LISTENER_RESULT_HISTOGRAM,
      PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_FLING, 2);

  touch.dispatch_type = blink::WebInputEvent::DispatchType::
      kListenersForcedNonBlockingDueToMainThreadResponsiveness;
  widget()->SendInputEvent(touch, HandledEventCallback());
  histogram_tester().ExpectBucketCount(
      EVENT_LISTENER_RESULT_HISTOGRAM,
      PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_MAIN_THREAD_RESPONSIVENESS,
      1);

  touch.MovePoint(0, 10, 10);
  touch.touch_start_or_first_touch_move = true;
  touch.dispatch_type = blink::WebInputEvent::DispatchType::
      kListenersForcedNonBlockingDueToMainThreadResponsiveness;
  widget()->SendInputEvent(touch, HandledEventCallback());
  histogram_tester().ExpectBucketCount(
      EVENT_LISTENER_RESULT_HISTOGRAM,
      PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_MAIN_THREAD_RESPONSIVENESS,
      2);

  EXPECT_CALL(*widget()->mock_webwidget(), HandleInputEvent(_))
      .WillOnce(::testing::Return(blink::WebInputEventResult::kNotHandled));
  EXPECT_CALL(*widget()->mock_webwidget(), DispatchBufferedTouchEvents())
      .WillOnce(
          ::testing::Return(blink::WebInputEventResult::kHandledSuppressed));
  touch.dispatch_type = blink::WebInputEvent::DispatchType::kBlocking;
  widget()->SendInputEvent(touch, HandledEventCallback());
  histogram_tester().ExpectBucketCount(EVENT_LISTENER_RESULT_HISTOGRAM,
                                       PASSIVE_LISTENER_UMA_ENUM_SUPPRESSED, 1);

  EXPECT_CALL(*widget()->mock_webwidget(), HandleInputEvent(_))
      .WillOnce(::testing::Return(blink::WebInputEventResult::kNotHandled));
  EXPECT_CALL(*widget()->mock_webwidget(), DispatchBufferedTouchEvents())
      .WillOnce(
          ::testing::Return(blink::WebInputEventResult::kHandledApplication));
  touch.dispatch_type = blink::WebInputEvent::DispatchType::kBlocking;
  widget()->SendInputEvent(touch, HandledEventCallback());
  histogram_tester().ExpectBucketCount(
      EVENT_LISTENER_RESULT_HISTOGRAM,
      PASSIVE_LISTENER_UMA_ENUM_CANCELABLE_AND_CANCELED, 1);
}

// Tests that if a RenderWidget goes invisible while performing a resize, the
// resize is acked immediately.
TEST_F(RenderWidgetUnittest, AckResizeOnHide) {
  // The widget should start off visible.
  ASSERT_FALSE(widget()->is_hidden());

  // Send a ResizeParams that needs to be acked.
  constexpr gfx::Size size(200, 200);
  ResizeParams resize_params;
  resize_params.screen_info = ScreenInfo();
  resize_params.new_size = size;
  resize_params.compositor_viewport_pixel_size = size;
  resize_params.local_surface_id =
      viz::LocalSurfaceId(1, 1, base::UnguessableToken::Create());
  resize_params.visible_viewport_size = size;
  resize_params.content_source_id = widget()->GetContentSourceId();
  resize_params.needs_resize_ack = true;
  widget()->OnMessageReceived(
      ViewMsg_Resize(widget()->routing_id(), resize_params));

  // Hide the widget. Make sure the resize is acked.
  widget()->sink()->ClearMessages();
  widget()->OnMessageReceived(ViewMsg_WasHidden(widget()->routing_id()));
  EXPECT_TRUE(widget()->sink()->GetUniqueMessageMatching(
      ViewHostMsg_ResizeOrRepaint_ACK::ID));
}

// Tests that if a RenderWidget auto-resizes multiple times and receives an IPC
// with a LocalSurfaceId, it will drop that LocalSurfaceId if it does not
// correspond to the latest auto-resize request.
TEST_F(RenderWidgetUnittest, SurfaceSynchronizationAutoResizeThrottling) {
  if (!features::IsSurfaceSynchronizationEnabled())
    return;

  constexpr gfx::Size auto_size(100, 100);
  widget()->InitializeLayerTreeView();
  widget()->SetAutoResizeMode(true);

  viz::ParentLocalSurfaceIdAllocator allocator;
  viz::LocalSurfaceId initial_local_surface_id = allocator.GenerateId();
  widget()->UpdateChildLocalSurfaceIdAllocatorForAutoResize(
      initial_local_surface_id);

  // Issue an auto-resize.
  widget()->DidAutoResize(auto_size);
  widget()->sink()->ClearMessages();
  base::RunLoop().RunUntilIdle();
  const IPC::Message* message = widget()->sink()->GetUniqueMessageMatching(
      ViewHostMsg_ResizeOrRepaint_ACK::ID);
  ASSERT_TRUE(message);
  ViewHostMsg_ResizeOrRepaint_ACK::Param params;
  ViewHostMsg_ResizeOrRepaint_ACK::Read(message, &params);
  EXPECT_EQ(auto_size, std::get<0>(params).view_size);
  uint64_t auto_resize_sequence_number = std::get<0>(params).sequence_number;
  EXPECT_GT(auto_resize_sequence_number, 0lu);

  // Issue another auto-resize but keep it in-flight.
  constexpr gfx::Size auto_size2(200, 200);
  widget()->DidAutoResize(auto_size2);

  // Send the LocalSurfaceId for the first Auto-Resize.
  content::ResizeParams resize_params;
  resize_params.auto_resize_enabled = true;
  resize_params.auto_resize_sequence_number = auto_resize_sequence_number;
  resize_params.min_size_for_auto_resize = auto_size;
  resize_params.max_size_for_auto_resize = auto_size2;
  resize_params.local_surface_id = allocator.GenerateId();
  widget()->OnMessageReceived(
      ViewMsg_Resize(widget()->routing_id(), resize_params));

  // The LocalSurfaceId should not take because there's another in-flight auto-
  // resize operation.
  EXPECT_NE(widget()->local_surface_id(), resize_params.local_surface_id);
}

// Tests that if a RenderWidget is auto-resized, it allocates its own
// viz::LocalSurfaceId
TEST_F(RenderWidgetUnittest, AutoResizeAllocatedLocalSurfaceId) {
#if !defined(USE_AURA)
  // Only Aura platforms support child allocation of viz::LocalSurfaceIds
  return;
#endif
  viz::LocalSurfaceId fake_parent_local_surface_id(
      1, base::UnguessableToken::Create());
  widget()->UpdateChildLocalSurfaceIdAllocatorForAutoResize(
      fake_parent_local_surface_id);
  widget()->SetAutoResizeMode(true);

  constexpr gfx::Size size(200, 200);
  widget()->DidAutoResize(size);

  widget()->sink()->ClearMessages();
  widget()->OnMessageReceived(ViewMsg_WasHidden(widget()->routing_id()));
  base::Optional<viz::LocalSurfaceId> local_surface_id1;
  ASSERT_EQ(1u, widget()->sink()->message_count());
  {
    const IPC::Message* msg = widget()->sink()->GetMessageAt(0);
    EXPECT_EQ(static_cast<uint32_t>(ViewHostMsg_ResizeOrRepaint_ACK::ID),
              msg->type());
    ViewHostMsg_ResizeOrRepaint_ACK::Param params;
    EXPECT_TRUE(ViewHostMsg_ResizeOrRepaint_ACK::Read(msg, &params));
    ViewHostMsg_ResizeOrRepaint_ACK_Params actual_params = std::get<0>(params);
    local_surface_id1 = actual_params.child_allocated_local_surface_id;
    EXPECT_TRUE(local_surface_id1.has_value());
  }

  constexpr gfx::Size size2(100, 100);
  widget()->DidAutoResize(size2);

  widget()->sink()->ClearMessages();
  widget()->OnMessageReceived(ViewMsg_WasHidden(widget()->routing_id()));
  base::Optional<viz::LocalSurfaceId> local_surface_id2;
  ASSERT_EQ(1u, widget()->sink()->message_count());
  {
    const IPC::Message* msg = widget()->sink()->GetMessageAt(0);
    EXPECT_EQ(static_cast<uint32_t>(ViewHostMsg_ResizeOrRepaint_ACK::ID),
              msg->type());
    ViewHostMsg_ResizeOrRepaint_ACK::Param params;
    EXPECT_TRUE(ViewHostMsg_ResizeOrRepaint_ACK::Read(msg, &params));
    ViewHostMsg_ResizeOrRepaint_ACK_Params actual_params = std::get<0>(params);
    local_surface_id2 = actual_params.child_allocated_local_surface_id;
    EXPECT_TRUE(local_surface_id2.has_value());
  }

  EXPECT_NE(local_surface_id1, local_surface_id2);
  EXPECT_EQ(local_surface_id1->parent_sequence_number(),
            local_surface_id2->parent_sequence_number());
  EXPECT_EQ(local_surface_id1->child_sequence_number() + 1,
            local_surface_id2->child_sequence_number());
  EXPECT_EQ(local_surface_id1->embed_token(), local_surface_id2->embed_token());
}

class PopupRenderWidget : public RenderWidget {
 public:
  explicit PopupRenderWidget(CompositorDependencies* compositor_deps)
      : RenderWidget(routing_id_++,
                     compositor_deps,
                     blink::kWebPopupTypePage,
                     ScreenInfo(),
                     false,
                     false,
                     false,
                     blink::scheduler::GetSingleThreadTaskRunnerForTesting()) {
    Init(RenderWidget::ShowCallback(), mock_webwidget());
    did_show_ = true;
  }

  IPC::TestSink* sink() { return &sink_; }

  MockWebWidget* mock_webwidget() { return &mock_webwidget_; }

  void SetScreenMetricsEmulationParameters(
      bool,
      const blink::WebDeviceEmulationParams&) override {}

 protected:
  ~PopupRenderWidget() override { webwidget_internal_ = nullptr; }

  bool Send(IPC::Message* msg) override {
    sink_.OnMessageReceived(*msg);
    delete msg;
    return true;
  }

 private:
  IPC::TestSink sink_;
  MockWebWidget mock_webwidget_;
  static int routing_id_;

  DISALLOW_COPY_AND_ASSIGN(PopupRenderWidget);
};

int PopupRenderWidget::routing_id_ = 1;

class RenderWidgetPopupUnittest : public testing::Test {
 public:
  RenderWidgetPopupUnittest() {
    widget_ = new PopupRenderWidget(&compositor_deps_);
    // RenderWidget::Init does an AddRef that's balanced by a browser-initiated
    // Close IPC. That Close will never happen in this test, so do a Release
    // here to ensure |widget_| is properly freed.
    widget_->Release();
    DCHECK(widget_->HasOneRef());
  }
  ~RenderWidgetPopupUnittest() override {}

  PopupRenderWidget* widget() const { return widget_.get(); }
  FakeCompositorDependencies compositor_deps_;

 protected:
  base::test::ScopedTaskEnvironment scoped_task_environment_;

 private:
  MockRenderProcess render_process_;
  MockRenderThread render_thread_;
  scoped_refptr<PopupRenderWidget> widget_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetPopupUnittest);
};

TEST_F(RenderWidgetPopupUnittest, EmulatingPopupRect) {
  blink::WebRect popup_screen_rect(200, 250, 100, 400);
  widget()->SetWindowRect(popup_screen_rect);

  // The view and window rect on a popup type RenderWidget should be
  // immediately set, without requiring an ACK.
  EXPECT_EQ(popup_screen_rect.x, widget()->WindowRect().x);
  EXPECT_EQ(popup_screen_rect.y, widget()->WindowRect().y);

  EXPECT_EQ(popup_screen_rect.x, widget()->ViewRect().x);
  EXPECT_EQ(popup_screen_rect.y, widget()->ViewRect().y);

  gfx::Rect emulated_window_rect(0, 0, 980, 1200);

  blink::WebDeviceEmulationParams emulation_params;
  emulation_params.screen_position = blink::WebDeviceEmulationParams::kMobile;
  emulation_params.view_size = emulated_window_rect.size();
  emulation_params.view_position = blink::WebPoint(150, 160);

  gfx::Rect parent_window_rect = gfx::Rect(0, 0, 800, 600);

  ResizeParams resize_params;
  resize_params.new_size = parent_window_rect.size();

  scoped_refptr<PopupRenderWidget> parent_widget(
      new PopupRenderWidget(&compositor_deps_));
  parent_widget->Release();  // Balance Init().
  RenderWidgetScreenMetricsEmulator emulator(
      parent_widget.get(), emulation_params, resize_params, parent_window_rect,
      parent_window_rect);
  emulator.Apply();

  widget()->SetPopupOriginAdjustmentsForEmulation(&emulator);

  // Position of the popup as seen by the emulated widget.
  gfx::Point emulated_position(
      emulation_params.view_position->x + popup_screen_rect.x,
      emulation_params.view_position->y + popup_screen_rect.y);

  // Both the window and view rects as read from the accessors should have the
  // emulation parameters applied.
  EXPECT_EQ(emulated_position.x(), widget()->WindowRect().x);
  EXPECT_EQ(emulated_position.y(), widget()->WindowRect().y);
  EXPECT_EQ(emulated_position.x(), widget()->ViewRect().x);
  EXPECT_EQ(emulated_position.y(), widget()->ViewRect().y);

  // Setting a new window rect while emulated should remove the emulation
  // transformation from the given rect so that getting the rect, which applies
  // the transformation to the raw rect, should result in the same value.
  blink::WebRect popup_emulated_rect(130, 170, 100, 400);
  widget()->SetWindowRect(popup_emulated_rect);

  EXPECT_EQ(popup_emulated_rect.x, widget()->WindowRect().x);
  EXPECT_EQ(popup_emulated_rect.y, widget()->WindowRect().y);
  EXPECT_EQ(popup_emulated_rect.x, widget()->ViewRect().x);
  EXPECT_EQ(popup_emulated_rect.y, widget()->ViewRect().y);
}

}  // namespace content

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/renderer_host/render_widget_host_impl.h"

#include <math.h>

#include <algorithm>
#include <set>
#include <tuple>
#include <utility>

#include "base/auto_reset.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/containers/hash_tables.h"
#include "base/debug/dump_without_crashing.h"
#include "base/i18n/rtl.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/shared_memory.h"
#include "base/message_loop/message_loop.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/default_tick_clock.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "cc/base/switches.h"
#include "cc/trees/render_frame_metadata.h"
#include "components/viz/common/features.h"
#include "components/viz/common/quads/compositor_frame.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/service/display_embedder/server_shared_bitmap_manager.h"
#include "content/browser/accessibility/browser_accessibility_state_impl.h"
#include "content/browser/bad_message.h"
#include "content/browser/browser_main_loop.h"
#include "content/browser/browser_plugin/browser_plugin_guest.h"
#include "content/browser/child_process_security_policy_impl.h"
#include "content/browser/compositor/surface_utils.h"
#include "content/browser/fileapi/browser_file_system_helper.h"
#include "content/browser/gpu/compositor_util.h"
#include "content/browser/renderer_host/dip_util.h"
#include "content/browser/renderer_host/display_util.h"
#include "content/browser/renderer_host/frame_metadata_util.h"
#include "content/browser/renderer_host/frame_token_message_queue.h"
#include "content/browser/renderer_host/input/input_router_config_helper.h"
#include "content/browser/renderer_host/input/input_router_impl.h"
#include "content/browser/renderer_host/input/synthetic_gesture.h"
#include "content/browser/renderer_host/input/synthetic_gesture_controller.h"
#include "content/browser/renderer_host/input/synthetic_gesture_target.h"
#include "content/browser/renderer_host/input/timeout_monitor.h"
#include "content/browser/renderer_host/input/touch_emulator.h"
#include "content/browser/renderer_host/render_view_host_delegate.h"
#include "content/browser/renderer_host/render_view_host_delegate_view.h"
#include "content/browser/renderer_host/render_view_host_impl.h"
#include "content/browser/renderer_host/render_widget_helper.h"
#include "content/browser/renderer_host/render_widget_host_input_event_router.h"
#include "content/browser/renderer_host/render_widget_host_owner_delegate.h"
#include "content/browser/renderer_host/render_widget_host_view_base.h"
#include "content/common/content_constants_internal.h"
#include "content/common/cursors/webcursor.h"
#include "content/common/drag_messages.h"
#include "content/common/frame_messages.h"
#include "content/common/input/sync_compositor_messages.h"
#include "content/common/input_messages.h"
#include "content/common/resize_params.h"
#include "content/common/text_input_state.h"
#include "content/common/view_messages.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/keyboard_event_processing_result.h"
#include "content/public/browser/native_web_keyboard_event.h"
#include "content/public/browser/notification_service.h"
#include "content/public/browser/notification_types.h"
#include "content/public/browser/render_frame_metadata_provider.h"
#include "content/public/browser/render_widget_host_iterator.h"
#include "content/public/browser/render_widget_host_observer.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/common/content_constants.h"
#include "content/public/common/content_features.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/result_codes.h"
#include "content/public/common/use_zoom_for_dsf_policy.h"
#include "content/public/common/web_preferences.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/service/gpu_switches.h"
#include "gpu/ipc/common/gpu_messages.h"
#include "mojo/public/cpp/system/platform_handle.h"
#include "net/base/filename_util.h"
#include "skia/ext/image_operations.h"
#include "skia/ext/platform_canvas.h"
#include "storage/browser/fileapi/isolated_context.h"
#include "third_party/blink/public/web/web_ime_text_span.h"
#include "ui/base/clipboard/clipboard.h"
#include "ui/base/ui_base_switches.h"
#include "ui/display/display_switches.h"
#include "ui/display/screen.h"
#include "ui/events/blink/web_input_event_traits.h"
#include "ui/events/event.h"
#include "ui/events/keycodes/dom/dom_code.h"
#include "ui/events/keycodes/dom/keycode_converter.h"
#include "ui/events/keycodes/keyboard_code_conversion.h"
#include "ui/events/keycodes/keyboard_codes.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/vector2d_conversions.h"
#include "ui/gfx/geometry/vector2d_f.h"
#include "ui/gfx/image/image.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/gfx/skbitmap_operations.h"
#include "ui/snapshot/snapshot.h"

#if defined(OS_ANDROID)
#include "ui/android/view_android.h"
#endif

#if defined(OS_MACOSX)
#include "content/public/common/service_manager_connection.h"
#include "services/device/public/mojom/constants.mojom.h"
#include "services/device/public/mojom/wake_lock_provider.mojom.h"
#include "services/service_manager/public/cpp/connector.h"
#include "ui/accelerated_widget_mac/window_resize_helper_mac.h"
#endif

using base::TimeDelta;
using base::TimeTicks;
using blink::WebDragOperation;
using blink::WebDragOperationsMask;
using blink::WebGestureEvent;
using blink::WebInputEvent;
using blink::WebKeyboardEvent;
using blink::WebMouseEvent;
using blink::WebMouseWheelEvent;
using blink::WebTextDirection;

namespace content {
namespace {

bool g_check_for_pending_resize_ack = true;

// <process id, routing id>
using RenderWidgetHostID = std::pair<int32_t, int32_t>;
using RoutingIDWidgetMap =
    base::hash_map<RenderWidgetHostID, RenderWidgetHostImpl*>;
base::LazyInstance<RoutingIDWidgetMap>::DestructorAtExit
    g_routing_id_widget_map = LAZY_INSTANCE_INITIALIZER;

// Implements the RenderWidgetHostIterator interface. It keeps a list of
// RenderWidgetHosts, and makes sure it returns a live RenderWidgetHost at each
// iteration (or NULL if there isn't any left).
class RenderWidgetHostIteratorImpl : public RenderWidgetHostIterator {
 public:
  RenderWidgetHostIteratorImpl()
      : current_index_(0) {
  }

  ~RenderWidgetHostIteratorImpl() override {}

  void Add(RenderWidgetHost* host) {
    hosts_.push_back(RenderWidgetHostID(host->GetProcess()->GetID(),
                                        host->GetRoutingID()));
  }

  // RenderWidgetHostIterator:
  RenderWidgetHost* GetNextHost() override {
    RenderWidgetHost* host = nullptr;
    while (current_index_ < hosts_.size() && !host) {
      RenderWidgetHostID id = hosts_[current_index_];
      host = RenderWidgetHost::FromID(id.first, id.second);
      ++current_index_;
    }
    return host;
  }

 private:
  std::vector<RenderWidgetHostID> hosts_;
  size_t current_index_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetHostIteratorImpl);
};

inline blink::WebGestureEvent CreateScrollBeginForWrapping(
    const blink::WebGestureEvent& gesture_event) {
  DCHECK(gesture_event.GetType() == blink::WebInputEvent::kGestureScrollUpdate);

  blink::WebGestureEvent wrap_gesture_scroll_begin(
      blink::WebInputEvent::kGestureScrollBegin, gesture_event.GetModifiers(),
      gesture_event.TimeStampSeconds(), gesture_event.SourceDevice());
  wrap_gesture_scroll_begin.data.scroll_begin.delta_x_hint = 0;
  wrap_gesture_scroll_begin.data.scroll_begin.delta_y_hint = 0;
  wrap_gesture_scroll_begin.resending_plugin_id =
      gesture_event.resending_plugin_id;
  wrap_gesture_scroll_begin.data.scroll_begin.delta_hint_units =
      gesture_event.data.scroll_update.delta_units;

  return wrap_gesture_scroll_begin;
}

inline blink::WebGestureEvent CreateScrollEndForWrapping(
    const blink::WebGestureEvent& gesture_event) {
  DCHECK(gesture_event.GetType() == blink::WebInputEvent::kGestureScrollUpdate);

  blink::WebGestureEvent wrap_gesture_scroll_end(
      blink::WebInputEvent::kGestureScrollEnd, gesture_event.GetModifiers(),
      gesture_event.TimeStampSeconds(), gesture_event.SourceDevice());
  wrap_gesture_scroll_end.resending_plugin_id =
      gesture_event.resending_plugin_id;
  wrap_gesture_scroll_end.data.scroll_end.delta_units =
      gesture_event.data.scroll_update.delta_units;

  return wrap_gesture_scroll_end;
}

std::vector<DropData::Metadata> DropDataToMetaData(const DropData& drop_data) {
  std::vector<DropData::Metadata> metadata;
  if (!drop_data.text.is_null()) {
    metadata.push_back(DropData::Metadata::CreateForMimeType(
        DropData::Kind::STRING,
        base::ASCIIToUTF16(ui::Clipboard::kMimeTypeText)));
  }

  if (drop_data.url.is_valid()) {
    metadata.push_back(DropData::Metadata::CreateForMimeType(
        DropData::Kind::STRING,
        base::ASCIIToUTF16(ui::Clipboard::kMimeTypeURIList)));
  }

  if (!drop_data.html.is_null()) {
    metadata.push_back(DropData::Metadata::CreateForMimeType(
        DropData::Kind::STRING,
        base::ASCIIToUTF16(ui::Clipboard::kMimeTypeHTML)));
  }

  // On Aura, filenames are available before drop.
  for (const auto& file_info : drop_data.filenames) {
    if (!file_info.path.empty()) {
      metadata.push_back(DropData::Metadata::CreateForFilePath(file_info.path));
    }
  }

  // On Android, only files' mime types are available before drop.
  for (const auto& mime_type : drop_data.file_mime_types) {
    if (!mime_type.empty()) {
      metadata.push_back(DropData::Metadata::CreateForMimeType(
          DropData::Kind::FILENAME, mime_type));
    }
  }

  for (const auto& file_system_file : drop_data.file_system_files) {
    if (!file_system_file.url.is_empty()) {
      metadata.push_back(
          DropData::Metadata::CreateForFileSystemUrl(file_system_file.url));
    }
  }

  for (const auto& custom_data_item : drop_data.custom_data) {
    metadata.push_back(DropData::Metadata::CreateForMimeType(
        DropData::Kind::STRING, custom_data_item.first));
  }

  return metadata;
}

class UnboundWidgetInputHandler : public mojom::WidgetInputHandler {
 public:
  void SetFocus(bool focused) override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void MouseCaptureLost() override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void SetEditCommandsForNextKeyEvent(
      const std::vector<content::EditCommand>& commands) override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void CursorVisibilityChanged(bool visible) override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void ImeSetComposition(const base::string16& text,
                         const std::vector<ui::ImeTextSpan>& ime_text_spans,
                         const gfx::Range& range,
                         int32_t start,
                         int32_t end) override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void ImeCommitText(const base::string16& text,
                     const std::vector<ui::ImeTextSpan>& ime_text_spans,
                     const gfx::Range& range,
                     int32_t relative_cursor_position) override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void ImeFinishComposingText(bool keep_selection) override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void RequestTextInputStateUpdate() override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void RequestCompositionUpdates(bool immediate_request,
                                 bool monitor_request) override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void DispatchEvent(std::unique_ptr<content::InputEvent> event,
                     DispatchEventCallback callback) override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void DispatchNonBlockingEvent(
      std::unique_ptr<content::InputEvent> event) override {
    DLOG(WARNING) << "Input request on unbound interface";
  }
  void AttachSynchronousCompositor(
      mojom::SynchronousCompositorControlHostPtr control_host,
      mojom::SynchronousCompositorHostAssociatedPtrInfo host,
      mojom::SynchronousCompositorAssociatedRequest compositor_request)
      override {
    NOTREACHED() << "Input request on unbound interface";
  }
};

base::LazyInstance<UnboundWidgetInputHandler>::Leaky g_unbound_input_handler =
    LAZY_INSTANCE_INITIALIZER;
}  // namespace

///////////////////////////////////////////////////////////////////////////////
// RenderWidgetHostImpl

RenderWidgetHostImpl::RenderWidgetHostImpl(RenderWidgetHostDelegate* delegate,
                                           RenderProcessHost* process,
                                           int32_t routing_id,
                                           mojom::WidgetPtr widget,
                                           bool hidden)
    : renderer_initialized_(false),
      destroyed_(false),
      delegate_(delegate),
      owner_delegate_(nullptr),
      process_(process),
      routing_id_(routing_id),
      clock_(base::DefaultTickClock::GetInstance()),
      is_loading_(false),
      is_hidden_(hidden),
      repaint_ack_pending_(false),
      resize_ack_pending_(false),
      auto_resize_enabled_(false),
      waiting_for_screen_rects_ack_(false),
      needs_repainting_on_restore_(false),
      is_unresponsive_(false),
      in_flight_event_count_(0),
      in_get_backing_store_(false),
      ignore_input_events_(false),
      text_direction_updated_(false),
      text_direction_(blink::kWebTextDirectionLeftToRight),
      text_direction_canceled_(false),
      suppress_events_until_keydown_(false),
      pending_mouse_lock_request_(false),
      allow_privileged_mouse_lock_(false),
      is_last_unlocked_by_target_(false),
      has_touch_handler_(false),
      is_in_touchpad_gesture_fling_(false),
      latency_tracker_(true, delegate_),
      next_browser_snapshot_id_(1),
      owned_by_render_frame_host_(false),
      is_focused_(false),
      hung_renderer_delay_(TimeDelta::FromMilliseconds(kHungRendererDelayMs)),
      new_content_rendering_delay_(
          TimeDelta::FromMilliseconds(kNewContentRenderingDelayMs)),
      current_content_source_id_(0),
      monitoring_composition_info_(false),
      compositor_frame_sink_binding_(this),
      frame_token_message_queue_(
          std::make_unique<FrameTokenMessageQueue>(this)),
      render_frame_metadata_provider_(frame_token_message_queue_.get()),
      frame_sink_id_(base::checked_cast<uint32_t>(process_->GetID()),
                     base::checked_cast<uint32_t>(routing_id_)),
      weak_factory_(this) {
  CHECK(delegate_);
  CHECK_NE(MSG_ROUTING_NONE, routing_id_);
  DCHECK(base::TaskScheduler::GetInstance())
      << "Ref. Prerequisite section of post_task.h";

  std::pair<RoutingIDWidgetMap::iterator, bool> result =
      g_routing_id_widget_map.Get().insert(std::make_pair(
          RenderWidgetHostID(process->GetID(), routing_id_), this));
  CHECK(result.second) << "Inserting a duplicate item!";
  process_->AddRoute(routing_id_, this);
  process_->AddWidget(this);

  latency_tracker_.Initialize(routing_id_, GetProcess()->GetID());

  SetupInputRouter();
  touch_emulator_.reset();
  SetWidget(std::move(widget));

  const auto* command_line = base::CommandLine::ForCurrentProcess();
  if (!command_line->HasSwitch(switches::kDisableHangMonitor)) {
    hang_monitor_timeout_.reset(new TimeoutMonitor(
        base::Bind(&RenderWidgetHostImpl::RendererIsUnresponsive,
                   weak_factory_.GetWeakPtr())));
  }

  if (!command_line->HasSwitch(switches::kDisableNewContentRenderingTimeout)) {
    new_content_rendering_timeout_.reset(new TimeoutMonitor(
        base::Bind(&RenderWidgetHostImpl::ClearDisplayedGraphics,
                   weak_factory_.GetWeakPtr())));
  }

  enable_surface_synchronization_ = features::IsSurfaceSynchronizationEnabled();
  enable_viz_ = base::FeatureList::IsEnabled(features::kVizDisplayCompositor);

  delegate_->RenderWidgetCreated(this);
}

RenderWidgetHostImpl::~RenderWidgetHostImpl() {
  if (!destroyed_)
    Destroy(false);
}

// static
RenderWidgetHost* RenderWidgetHost::FromID(
    int32_t process_id,
    int32_t routing_id) {
  return RenderWidgetHostImpl::FromID(process_id, routing_id);
}

// static
RenderWidgetHostImpl* RenderWidgetHostImpl::FromID(
    int32_t process_id,
    int32_t routing_id) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  RoutingIDWidgetMap* widgets = g_routing_id_widget_map.Pointer();
  RoutingIDWidgetMap::iterator it = widgets->find(
      RenderWidgetHostID(process_id, routing_id));
  return it == widgets->end() ? NULL : it->second;
}

// static
std::unique_ptr<RenderWidgetHostIterator>
RenderWidgetHost::GetRenderWidgetHosts() {
  std::unique_ptr<RenderWidgetHostIteratorImpl> hosts(
      new RenderWidgetHostIteratorImpl());
  for (auto& it : g_routing_id_widget_map.Get()) {
    RenderWidgetHost* widget = it.second;

    RenderViewHost* rvh = RenderViewHost::From(widget);
    if (!rvh) {
      hosts->Add(widget);
      continue;
    }

    // For RenderViewHosts, add only active ones.
    if (static_cast<RenderViewHostImpl*>(rvh)->is_active())
      hosts->Add(widget);
  }

  return std::move(hosts);
}

// static
std::unique_ptr<RenderWidgetHostIterator>
RenderWidgetHostImpl::GetAllRenderWidgetHosts() {
  std::unique_ptr<RenderWidgetHostIteratorImpl> hosts(
      new RenderWidgetHostIteratorImpl());
  for (auto& it : g_routing_id_widget_map.Get())
    hosts->Add(it.second);

  return std::move(hosts);
}

// static
RenderWidgetHostImpl* RenderWidgetHostImpl::From(RenderWidgetHost* rwh) {
  return static_cast<RenderWidgetHostImpl*>(rwh);
}

void RenderWidgetHostImpl::SetView(RenderWidgetHostViewBase* view) {
  if (view) {
    view_ = view->GetWeakPtr();
    if (enable_viz_) {
      if (!create_frame_sink_callback_.is_null())
        std::move(create_frame_sink_callback_).Run(view_->GetFrameSinkId());
    } else {
      if (renderer_compositor_frame_sink_.is_bound()) {
        view->DidCreateNewRendererCompositorFrameSink(
            renderer_compositor_frame_sink_.get());
      }
      // Views start out not needing begin frames, so only update its state
      // if the value has changed.
      if (needs_begin_frames_)
        view_->SetNeedsBeginFrames(needs_begin_frames_);
    }
  } else {
    view_.reset();
  }

  synthetic_gesture_controller_.reset();
}

RenderProcessHost* RenderWidgetHostImpl::GetProcess() const {
  return process_;
}

int RenderWidgetHostImpl::GetRoutingID() const {
  return routing_id_;
}

RenderWidgetHostViewBase* RenderWidgetHostImpl::GetView() const {
  return view_.get();
}

const viz::FrameSinkId& RenderWidgetHostImpl::GetFrameSinkId() const {
  return frame_sink_id_;
}

void RenderWidgetHostImpl::ResetSizeAndRepaintPendingFlags() {
  resize_ack_pending_ = false;
  if (repaint_ack_pending_) {
    TRACE_EVENT_ASYNC_END0(
        "renderer_host", "RenderWidgetHostImpl::repaint_ack_pending_", this);
  }
  repaint_ack_pending_ = false;
  if (old_resize_params_)
    old_resize_params_->new_size = gfx::Size();
}

void RenderWidgetHostImpl::SendScreenRects() {
  if (!renderer_initialized_ || waiting_for_screen_rects_ack_)
    return;

  if (is_hidden_) {
    // On GTK, this comes in for backgrounded tabs. Ignore, to match what
    // happens on Win & Mac, and when the view is shown it'll call this again.
    return;
  }

  if (!view_)
    return;

  last_view_screen_rect_ = view_->GetViewBounds();
  last_window_screen_rect_ = view_->GetBoundsInRootWindow();
  view_->WillSendScreenRects();
  Send(new ViewMsg_UpdateScreenRects(
      GetRoutingID(), last_view_screen_rect_, last_window_screen_rect_));
  waiting_for_screen_rects_ack_ = true;
}

void RenderWidgetHostImpl::SetFrameDepth(unsigned int depth) {
  if (frame_depth_ == depth)
    return;

  frame_depth_ = depth;
  UpdatePriority();
}

void RenderWidgetHostImpl::UpdatePriority() {
  if (!destroyed_)
    process_->UpdateClientPriority(this);
}

void RenderWidgetHostImpl::Init() {
  DCHECK(process_->HasConnection());

  renderer_initialized_ = true;

  SendScreenRects();
  WasResized();

  if (owner_delegate_)
    owner_delegate_->RenderWidgetDidInit();

  if (view_)
    view_->OnRenderWidgetInit();
}

void RenderWidgetHostImpl::InitForFrame() {
  DCHECK(process_->HasConnection());
  renderer_initialized_ = true;

  if (view_)
    view_->OnRenderWidgetInit();
}

void RenderWidgetHostImpl::ShutdownAndDestroyWidget(bool also_delete) {
  CancelKeyboardLock();
  RejectMouseLockOrUnlockIfNecessary();

  if (process_->HasConnection()) {
    // Tell the renderer object to close.
    bool rv = Send(new ViewMsg_Close(routing_id_));
    DCHECK(rv);
  }

  Destroy(also_delete);
}

bool RenderWidgetHostImpl::IsLoading() const {
  return is_loading_;
}

bool RenderWidgetHostImpl::OnMessageReceived(const IPC::Message &msg) {
  // Only process most messages if the RenderWidget is alive.
  if (!renderer_initialized())
    return false;

  if (owner_delegate_ && owner_delegate_->OnMessageReceived(msg))
    return true;

  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(RenderWidgetHostImpl, msg)
    IPC_MESSAGE_HANDLER(FrameHostMsg_RenderProcessGone, OnRenderProcessGone)
    IPC_MESSAGE_HANDLER(FrameHostMsg_HittestData, OnHittestData)
    IPC_MESSAGE_HANDLER(ViewHostMsg_Close, OnClose)
    IPC_MESSAGE_HANDLER(ViewHostMsg_UpdateScreenRects_ACK,
                        OnUpdateScreenRectsAck)
    IPC_MESSAGE_HANDLER(ViewHostMsg_RequestMove, OnRequestMove)
    IPC_MESSAGE_HANDLER(ViewHostMsg_SetTooltipText, OnSetTooltipText)
    IPC_MESSAGE_HANDLER(ViewHostMsg_ResizeOrRepaint_ACK, OnResizeOrRepaintACK)
    IPC_MESSAGE_HANDLER(ViewHostMsg_SetCursor, OnSetCursor)
    IPC_MESSAGE_HANDLER(ViewHostMsg_AutoscrollStart, OnAutoscrollStart)
    IPC_MESSAGE_HANDLER(ViewHostMsg_AutoscrollFling, OnAutoscrollFling)
    IPC_MESSAGE_HANDLER(ViewHostMsg_AutoscrollEnd, OnAutoscrollEnd)
    IPC_MESSAGE_HANDLER(ViewHostMsg_TextInputStateChanged,
                        OnTextInputStateChanged)
    IPC_MESSAGE_HANDLER(ViewHostMsg_LockMouse, OnLockMouse)
    IPC_MESSAGE_HANDLER(ViewHostMsg_UnlockMouse, OnUnlockMouse)
    IPC_MESSAGE_HANDLER(ViewHostMsg_ShowDisambiguationPopup,
                        OnShowDisambiguationPopup)
    IPC_MESSAGE_HANDLER(ViewHostMsg_SelectionBoundsChanged,
                        OnSelectionBoundsChanged)
    IPC_MESSAGE_HANDLER(ViewHostMsg_FocusedNodeTouched, OnFocusedNodeTouched)
    IPC_MESSAGE_HANDLER(DragHostMsg_StartDragging, OnStartDragging)
    IPC_MESSAGE_HANDLER(DragHostMsg_UpdateDragCursor, OnUpdateDragCursor)
    IPC_MESSAGE_HANDLER(ViewHostMsg_FrameSwapMessages,
                        OnFrameSwapMessagesReceived)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()

  if (!handled && input_router_ && input_router_->OnMessageReceived(msg))
    return true;

  if (!handled && view_ && view_->OnMessageReceived(msg))
    return true;

  return handled;
}

bool RenderWidgetHostImpl::Send(IPC::Message* msg) {
  DCHECK(IPC_MESSAGE_ID_CLASS(msg->type()) != InputMsgStart);
  return process_->Send(msg);
}

void RenderWidgetHostImpl::SetIsLoading(bool is_loading) {
  if (owner_delegate_)
    owner_delegate_->RenderWidgetWillSetIsLoading(is_loading);

  is_loading_ = is_loading;
  if (view_)
    view_->SetIsLoading(is_loading);
}

void RenderWidgetHostImpl::WasHidden() {
  if (is_hidden_)
    return;

  RejectMouseLockOrUnlockIfNecessary();

  TRACE_EVENT0("renderer_host", "RenderWidgetHostImpl::WasHidden");
  is_hidden_ = true;

  // Don't bother reporting hung state when we aren't active.
  StopHangMonitorTimeout();

  // If we have a renderer, then inform it that we are being hidden so it can
  // reduce its resource utilization.
  Send(new ViewMsg_WasHidden(routing_id_));

  // Tell the RenderProcessHost we were hidden.
  process_->UpdateClientPriority(this);

  bool is_visible = false;
  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_VISIBILITY_CHANGED,
      Source<RenderWidgetHost>(this),
      Details<bool>(&is_visible));
  for (auto& observer : observers_)
    observer.RenderWidgetHostVisibilityChanged(this, false);
}

void RenderWidgetHostImpl::WasShown(const ui::LatencyInfo& latency_info) {
  if (!is_hidden_)
    return;

  TRACE_EVENT0("renderer_host", "RenderWidgetHostImpl::WasShown");
  is_hidden_ = false;

  // If we navigated in background, clear the displayed graphics of the
  // previous page before going visible.
  ForceFirstFrameAfterNavigationTimeout();

  SendScreenRects();
  RestartHangMonitorTimeoutIfNecessary();

  // Always repaint on restore.
  bool needs_repainting = true;
  needs_repainting_on_restore_ = false;
  Send(new ViewMsg_WasShown(routing_id_, needs_repainting, latency_info));

  process_->UpdateClientPriority(this);

  bool is_visible = true;
  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_VISIBILITY_CHANGED,
      Source<RenderWidgetHost>(this),
      Details<bool>(&is_visible));
  for (auto& observer : observers_)
    observer.RenderWidgetHostVisibilityChanged(this, true);

  // It's possible for our size to be out of sync with the renderer. The
  // following is one case that leads to this:
  // 1. WasResized -> Send ViewMsg_Resize to render
  // 2. WasResized -> do nothing as resize_ack_pending_ is true
  // 3. WasHidden
  // 4. OnResizeOrRepaintACK from (1) processed. Does NOT invoke WasResized as
  //    view is hidden. Now renderer/browser out of sync with what they think
  //    size is.
  // By invoking WasResized the renderer is updated as necessary. WasResized
  // does nothing if the sizes are already in sync.
  //
  // TODO: ideally ViewMsg_WasShown would take a size. This way, the renderer
  // could handle both the restore and resize at once. This isn't that big a
  // deal as RenderWidget::WasShown delays updating, so that the resize from
  // WasResized is usually processed before the renderer is painted.
  WasResized();
}

#if defined(OS_ANDROID)
void RenderWidgetHostImpl::SetImportance(ChildProcessImportance importance) {
  if (importance_ == importance)
    return;
  importance_ = importance;
  process_->UpdateClientPriority(this);
}
#endif

bool RenderWidgetHostImpl::GetResizeParams(ResizeParams* resize_params) {
  *resize_params = ResizeParams();

  GetScreenInfo(&resize_params->screen_info);

  if (delegate_) {
    resize_params->is_fullscreen_granted =
        delegate_->IsFullscreenForCurrentTab();
    resize_params->display_mode = delegate_->GetDisplayMode(this);
  } else {
    resize_params->is_fullscreen_granted = false;
    resize_params->display_mode = blink::kWebDisplayModeBrowser;
  }

  resize_params->auto_resize_enabled = auto_resize_enabled_;
  resize_params->min_size_for_auto_resize = min_size_for_auto_resize_;
  resize_params->max_size_for_auto_resize = max_size_for_auto_resize_;
  resize_params->auto_resize_sequence_number =
      last_auto_resize_response_number_;

  if (view_) {
    resize_params->new_size = view_->GetRequestedRendererSize();
    resize_params->capture_sequence_number = view_->GetCaptureSequenceNumber();
    resize_params->compositor_viewport_pixel_size =
        view_->GetCompositorViewportPixelSize();
    resize_params->top_controls_height = view_->GetTopControlsHeight();
    resize_params->bottom_controls_height = view_->GetBottomControlsHeight();
    if (IsUseZoomForDSFEnabled()) {
      float device_scale = resize_params->screen_info.device_scale_factor;
      resize_params->top_controls_height *= device_scale;
      resize_params->bottom_controls_height *= device_scale;
    }
    resize_params->browser_controls_shrink_blink_size =
        view_->DoBrowserControlsShrinkBlinkSize();
    resize_params->visible_viewport_size = view_->GetVisibleViewportSize();
    // TODO(ccameron): GetLocalSurfaceId is not synchronized with the device
    // scale factor of the surface. Fix this.
    viz::LocalSurfaceId local_surface_id = view_->GetLocalSurfaceId();
    if (local_surface_id.is_valid())
      resize_params->local_surface_id = local_surface_id;
  }

  resize_params->content_source_id = current_content_source_id_;

  if (screen_orientation_type_for_testing_) {
    resize_params->screen_info.orientation_type =
        *screen_orientation_type_for_testing_;
  }

  if (screen_orientation_angle_for_testing_) {
    resize_params->screen_info.orientation_angle =
        *screen_orientation_angle_for_testing_;
  }

  const bool size_changed =
      !old_resize_params_ ||
      old_resize_params_->auto_resize_enabled !=
          resize_params->auto_resize_enabled ||
      (old_resize_params_->auto_resize_enabled &&
       (old_resize_params_->min_size_for_auto_resize !=
            resize_params->min_size_for_auto_resize ||
        old_resize_params_->max_size_for_auto_resize !=
            resize_params->max_size_for_auto_resize ||
        old_resize_params_->auto_resize_sequence_number !=
            resize_params->auto_resize_sequence_number)) ||
      (!old_resize_params_->auto_resize_enabled &&
       (old_resize_params_->new_size != resize_params->new_size ||
        (old_resize_params_->compositor_viewport_pixel_size.IsEmpty() &&
         !resize_params->compositor_viewport_pixel_size.IsEmpty())));

  bool dirty =
      size_changed ||
      old_resize_params_->screen_info != resize_params->screen_info ||
      old_resize_params_->compositor_viewport_pixel_size !=
          resize_params->compositor_viewport_pixel_size ||
      old_resize_params_->is_fullscreen_granted !=
          resize_params->is_fullscreen_granted ||
      old_resize_params_->display_mode != resize_params->display_mode ||
      old_resize_params_->top_controls_height !=
          resize_params->top_controls_height ||
      old_resize_params_->browser_controls_shrink_blink_size !=
          resize_params->browser_controls_shrink_blink_size ||
      old_resize_params_->bottom_controls_height !=
          resize_params->bottom_controls_height ||
      old_resize_params_->visible_viewport_size !=
          resize_params->visible_viewport_size ||
      (enable_surface_synchronization_ &&
       old_resize_params_->content_source_id !=
           resize_params->content_source_id) ||
      (enable_surface_synchronization_ &&
       old_resize_params_->local_surface_id !=
           resize_params->local_surface_id) ||
      old_resize_params_->capture_sequence_number !=
          resize_params->capture_sequence_number;

  // We don't expect to receive an ACK when the requested size or the physical
  // backing size is empty, or when the main viewport size didn't change.
  resize_params->needs_resize_ack =
      !auto_resize_enabled_ && g_check_for_pending_resize_ack &&
      !resize_params->new_size.IsEmpty() &&
      !resize_params->compositor_viewport_pixel_size.IsEmpty() &&
      (size_changed || next_resize_needs_resize_ack_) &&
      (!enable_surface_synchronization_ ||
       (resize_params->local_surface_id.has_value() &&
        resize_params->local_surface_id->is_valid()));

  return dirty;
}

void RenderWidgetHostImpl::SetInitialRenderSizeParams(
    const ResizeParams& resize_params) {
  resize_ack_pending_ = resize_params.needs_resize_ack;

  old_resize_params_ = std::make_unique<ResizeParams>(resize_params);
}

void RenderWidgetHostImpl::WasResized() {
  WasResized(false);
}

void RenderWidgetHostImpl::WasResized(bool scroll_focused_node_into_view) {
  // Skip if the |delegate_| has already been detached because
  // it's web contents is being deleted.
  if (resize_ack_pending_ || !process_->HasConnection() || !view_ ||
      !view_->HasSize() || !renderer_initialized_ || !delegate_ ||
      last_auto_resize_request_number_ != last_auto_resize_response_number_) {
    return;
  }

  std::unique_ptr<ResizeParams> params(new ResizeParams);
  if (!GetResizeParams(params.get()))
    return;
  params->scroll_focused_node_into_view = scroll_focused_node_into_view;

  ScreenInfo screen_info = params->screen_info;
  bool width_changed =
      !old_resize_params_ ||
      old_resize_params_->new_size.width() != params->new_size.width();
  if (Send(new ViewMsg_Resize(routing_id_, *params))) {
    resize_ack_pending_ = params->needs_resize_ack;
    next_resize_needs_resize_ack_ = false;
    old_resize_params_.swap(params);
  }

  if (delegate_)
    delegate_->RenderWidgetWasResized(this, screen_info, width_changed);
}

void RenderWidgetHostImpl::GotFocus() {
  Focus();
  if (owner_delegate_)
    owner_delegate_->RenderWidgetGotFocus();
  if (delegate_)
    delegate_->RenderWidgetGotFocus(this);
}

void RenderWidgetHostImpl::LostFocus() {
  Blur();
  if (owner_delegate_)
    owner_delegate_->RenderWidgetLostFocus();
  if (delegate_)
    delegate_->RenderWidgetLostFocus(this);
}

void RenderWidgetHostImpl::Focus() {
  RenderWidgetHostImpl* focused_widget =
      delegate_ ? delegate_->GetRenderWidgetHostWithPageFocus() : nullptr;

  if (!focused_widget)
    focused_widget = this;
  focused_widget->SetPageFocus(true);
}

void RenderWidgetHostImpl::Blur() {
  RenderWidgetHostImpl* focused_widget =
      delegate_ ? delegate_->GetRenderWidgetHostWithPageFocus() : nullptr;

  if (!focused_widget)
    focused_widget = this;
  focused_widget->SetPageFocus(false);
}

void RenderWidgetHostImpl::SetPageFocus(bool focused) {
  is_focused_ = focused;

  if (!focused) {
    // If there is a pending mouse lock request, we don't want to reject it at
    // this point. The user can switch focus back to this view and approve the
    // request later.
    if (IsMouseLocked())
      view_->UnlockMouse();

    if (IsKeyboardLocked())
      UnlockKeyboard();

    if (touch_emulator_)
      touch_emulator_->CancelTouch();
  } else if (keyboard_lock_allowed_) {
    LockKeyboard();
  }

  GetWidgetInputHandler()->SetFocus(focused);

  // Also send page-level focus state to other SiteInstances involved in
  // rendering the current FrameTree.
  if (RenderViewHost::From(this) && delegate_)
    delegate_->ReplicatePageFocus(focused);
}

void RenderWidgetHostImpl::LostCapture() {
  if (touch_emulator_)
    touch_emulator_->CancelTouch();

  GetWidgetInputHandler()->MouseCaptureLost();

  if (delegate_)
    delegate_->LostCapture(this);
}

void RenderWidgetHostImpl::SetActive(bool active) {
  Send(new ViewMsg_SetActive(routing_id_, active));
}

void RenderWidgetHostImpl::LostMouseLock() {
  if (delegate_)
    delegate_->LostMouseLock(this);
}

void RenderWidgetHostImpl::SendMouseLockLost() {
  Send(new ViewMsg_MouseLockLost(routing_id_));
}

void RenderWidgetHostImpl::ViewDestroyed() {
  CancelKeyboardLock();
  RejectMouseLockOrUnlockIfNecessary();

  // TODO(evanm): tracking this may no longer be necessary;
  // eliminate this function if so.
  SetView(nullptr);
}

#if defined(OS_MACOSX)
void RenderWidgetHostImpl::PauseForPendingResizeOrRepaints() {
  TRACE_EVENT0("browser",
      "RenderWidgetHostImpl::PauseForPendingResizeOrRepaints");

  // Do not pause if the view is hidden.
  if (is_hidden())
    return;

  // Do not pause if there is not a paint or resize already coming.
  if (!repaint_ack_pending_ && !resize_ack_pending_)
    return;

  // OnResizeOrRepaintACK posts a task to the default TaskRunner in auto-resize,
  // which is not the one that we pump in this nested loop, causing unexpected
  // behavior. It very well may be safe to do that post task to the TaskRunner
  // from ui::WindowResizeHelperMac (which we pump), but don't do that until
  // it is known to be safe.
  if (auto_resize_enabled_)
    return;

  if (!view_)
    return;

  // How long to (synchronously) wait for the renderer to respond with a
  // new frame when our current frame doesn't exist or is the wrong size.
  // This timeout impacts the "choppiness" of our window resize.
  const int kPaintMsgTimeoutMS = 167;

  TRACE_EVENT0("renderer_host", "RenderWidgetHostImpl::WaitForSurface");

  // We should not be asked to paint while we are hidden.  If we are hidden,
  // then it means that our consumer failed to call WasShown.
  DCHECK(!is_hidden_) << "WaitForSurface called while hidden!";

  // We should never be called recursively; this can theoretically lead to
  // infinite recursion and almost certainly leads to lower performance.
  DCHECK(!in_get_backing_store_) << "WaitForSurface called recursively!";
  base::AutoReset<bool> auto_reset_in_get_backing_store(
      &in_get_backing_store_, true);

  // We might have a surface that we can use already.
  if (!view_->ShouldContinueToPauseForFrame())
    return;

  // Pump a nested run loop until we time out or get a frame of the right
  // size.
  TimeTicks start_time = clock_->NowTicks();
  TimeDelta time_left = TimeDelta::FromMilliseconds(kPaintMsgTimeoutMS);
  TimeTicks timeout_time = start_time + time_left;
  while (1) {
    TRACE_EVENT0("renderer_host", "WaitForSurface::WaitForSingleTaskToRun");
    if (ui::WindowResizeHelperMac::Get()->WaitForSingleTaskToRun(time_left)) {
      if (!view_->ShouldContinueToPauseForFrame())
        break;
    }
    time_left = timeout_time - clock_->NowTicks();
    if (time_left <= TimeDelta::FromSeconds(0)) {
      TRACE_EVENT0("renderer_host", "WaitForSurface::Timeout");
      break;
    }
  }
}
#endif

bool RenderWidgetHostImpl::ScheduleComposite() {
  if (is_hidden_ || current_size_.IsEmpty() || repaint_ack_pending_ ||
      resize_ack_pending_) {
    return false;
  }

  // Send out a request to the renderer to paint the view if required.
  repaint_start_time_ = clock_->NowTicks();
  repaint_ack_pending_ = true;
  TRACE_EVENT_ASYNC_BEGIN0(
      "renderer_host", "RenderWidgetHostImpl::repaint_ack_pending_", this);
  Send(new ViewMsg_Repaint(routing_id_, current_size_));
  return true;
}

void RenderWidgetHostImpl::ProcessIgnoreInputEventsChanged(
    bool ignore_input_events) {
  if (ignore_input_events)
    StopHangMonitorTimeout();
  else
    RestartHangMonitorTimeoutIfNecessary();
}

void RenderWidgetHostImpl::StartHangMonitorTimeout(TimeDelta delay) {
  if (!hang_monitor_timeout_)
    return;
  hang_monitor_timeout_->Start(delay);
  hang_monitor_start_time_ = clock_->NowTicks();
}

void RenderWidgetHostImpl::RestartHangMonitorTimeoutIfNecessary() {
  if (hang_monitor_timeout_ && in_flight_event_count_ > 0 && !is_hidden_)
    hang_monitor_timeout_->Restart(hung_renderer_delay_);
}

bool RenderWidgetHostImpl::IsCurrentlyUnresponsive() const {
  return is_unresponsive_;
}

void RenderWidgetHostImpl::StopHangMonitorTimeout() {
  if (hang_monitor_timeout_)
    hang_monitor_timeout_->Stop();

  if (!hang_monitor_start_time_.is_null()) {
    base::TimeDelta elapsed = clock_->NowTicks() - hang_monitor_start_time_;
    const base::TimeDelta kMinimumHangTimeToReport =
        base::TimeDelta::FromSeconds(5);
    if (elapsed >= kMinimumHangTimeToReport)
      UMA_HISTOGRAM_LONG_TIMES("Renderer.Hung.Duration", elapsed);

    hang_monitor_start_time_ = TimeTicks();
  }
  RendererIsResponsive();
}

void RenderWidgetHostImpl::DidNavigate(uint32_t next_source_id) {
  current_content_source_id_ = next_source_id;
  did_receive_first_frame_after_navigation_ = false;

  if (enable_surface_synchronization_) {
    // Resize messages before navigation are not acked, so reset
    // |resize_ack_pending_| and make sure the next resize will be acked if the
    // last resize before navigation was supposed to be acked.
    next_resize_needs_resize_ack_ = resize_ack_pending_;
    resize_ack_pending_ = false;
    if (view_)
      view_->DidNavigate();
  } else {
    // It is possible for a compositor frame to arrive before the browser is
    // notified about the page being committed, in which case no timer is
    // necessary.
    if (last_received_content_source_id_ >= current_content_source_id_)
      return;
  }

  if (!new_content_rendering_timeout_)
    return;

  new_content_rendering_timeout_->Start(new_content_rendering_delay_);
}

void RenderWidgetHostImpl::ForwardMouseEvent(const WebMouseEvent& mouse_event) {
  // VrController moves the pointer during the scrolling and fling. To ensure
  // that scroll performance is not affected we drop mouse events during
  // scroll/fling.
  if (GetView()->IsInVR() &&
      (is_in_gesture_scroll_[blink::kWebGestureDeviceTouchpad] ||
       is_in_touchpad_gesture_fling_)) {
    return;
  }

  ForwardMouseEventWithLatencyInfo(mouse_event,
                                   ui::LatencyInfo(ui::SourceEventType::MOUSE));
  if (owner_delegate_)
    owner_delegate_->RenderWidgetDidForwardMouseEvent(mouse_event);
}

void RenderWidgetHostImpl::ForwardMouseEventWithLatencyInfo(
    const blink::WebMouseEvent& mouse_event,
    const ui::LatencyInfo& latency) {
  TRACE_EVENT2("input", "RenderWidgetHostImpl::ForwardMouseEvent", "x",
               mouse_event.PositionInWidget().x, "y",
               mouse_event.PositionInWidget().y);

  DCHECK_GE(mouse_event.GetType(), blink::WebInputEvent::kMouseTypeFirst);
  DCHECK_LE(mouse_event.GetType(), blink::WebInputEvent::kMouseTypeLast);

  for (size_t i = 0; i < mouse_event_callbacks_.size(); ++i) {
    if (mouse_event_callbacks_[i].Run(mouse_event))
      return;
  }

  if (ShouldDropInputEvents())
    return;

  if (touch_emulator_ && touch_emulator_->HandleMouseEvent(mouse_event))
    return;

  MouseEventWithLatencyInfo mouse_with_latency(mouse_event, latency);
  DispatchInputEventWithLatencyInfo(mouse_event, &mouse_with_latency.latency);
  input_router_->SendMouseEvent(mouse_with_latency);
}

void RenderWidgetHostImpl::ForwardWheelEvent(
    const WebMouseWheelEvent& wheel_event) {
  ForwardWheelEventWithLatencyInfo(wheel_event,
                                   ui::LatencyInfo(ui::SourceEventType::WHEEL));
}

void RenderWidgetHostImpl::ForwardWheelEventWithLatencyInfo(
    const blink::WebMouseWheelEvent& wheel_event,
    const ui::LatencyInfo& latency) {
  TRACE_EVENT2("input", "RenderWidgetHostImpl::ForwardWheelEvent", "dx",
               wheel_event.delta_x, "dy", wheel_event.delta_y);

  if (ShouldDropInputEvents())
    return;

  if (touch_emulator_ && touch_emulator_->HandleMouseWheelEvent(wheel_event))
    return;

  MouseWheelEventWithLatencyInfo wheel_with_latency(wheel_event, latency);
  DispatchInputEventWithLatencyInfo(wheel_event, &wheel_with_latency.latency);
  input_router_->SendWheelEvent(wheel_with_latency);
}

void RenderWidgetHostImpl::ForwardEmulatedGestureEvent(
    const blink::WebGestureEvent& gesture_event) {
  ForwardGestureEvent(gesture_event);
}

void RenderWidgetHostImpl::ForwardGestureEvent(
    const blink::WebGestureEvent& gesture_event) {
  ForwardGestureEventWithLatencyInfo(
      gesture_event,
      ui::WebInputEventTraits::CreateLatencyInfoForWebGestureEvent(
          gesture_event));
}

void RenderWidgetHostImpl::ForwardGestureEventWithLatencyInfo(
    const blink::WebGestureEvent& gesture_event,
    const ui::LatencyInfo& latency) {
  TRACE_EVENT1("input", "RenderWidgetHostImpl::ForwardGestureEvent", "type",
               WebInputEvent::GetName(gesture_event.GetType()));
  // Early out if necessary, prior to performing latency logic.
  if (ShouldDropInputEvents())
    return;

  bool scroll_update_needs_wrapping = false;
  if (gesture_event.GetType() == blink::WebInputEvent::kGestureScrollBegin) {
    // When a user starts scrolling while a fling is active, the GSB will arrive
    // when is_in_gesture_scroll_[gesture_event.SourceDevice()] is still true.
    // This is because the fling controller defers handling the GFC event
    // arrived before the GSB and doesn't send a GSE to end the fling; Instead,
    // it waits for a second GFS to arrive and boost the current active fling if
    // possible. While GFC handling is deferred the controller suppresses the
    // GSB and GSU events instead of sending them to the renderer and continues
    // to progress the fling. So, the renderer doesn't receive two GSB events
    // without any GSE in between.
    DCHECK(!is_in_gesture_scroll_[gesture_event.SourceDevice()] ||
           FlingCancellationIsDeferred());
    is_in_gesture_scroll_[gesture_event.SourceDevice()] = true;
  } else if (gesture_event.GetType() ==
             blink::WebInputEvent::kGestureScrollEnd) {
    DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);
    is_in_gesture_scroll_[gesture_event.SourceDevice()] = false;
    is_in_touchpad_gesture_fling_ = false;
    if (view_)
      view_->set_is_currently_scrolling_viewport(false);
  } else if (gesture_event.GetType() ==
             blink::WebInputEvent::kGestureFlingStart) {
    if (gesture_event.SourceDevice() ==
        blink::WebGestureDevice::kWebGestureDeviceTouchpad) {
      // TODO(sahel): Remove the VR specific case when motion events are used
      // for Android VR event processing and VR touchpad scrolling is handled by
      // sending wheel events rather than directly injecting Gesture Scroll
      // Events. https://crbug.com/797322
      if (GetView()->IsInVR()) {
        // Regardless of the state of the wheel scroll latching
        // WebContentsEventForwarder doesn't inject any GSE events before GFS.
        DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);

        // Reset the is_in_gesture_scroll since while scrolling in Android VR
        // the first wheel event sent by the FlingController will cause a GSB
        // generation in MouseWheelEventQueue. This is because GSU events before
        // the GFS are directly injected to RWHI rather than being generated
        // from wheel events in MouseWheelEventQueue.
        is_in_gesture_scroll_[gesture_event.SourceDevice()] = false;
      } else if (GetView()->wheel_scroll_latching_enabled()) {
        // When wheel scroll latching is enabled, no GSE is sent before GFS, so
        // is_in_gesture_scroll must be true.
        // TODO(sahel): This often gets tripped on Debug builds in ChromeOS
        // indicating some kind of gesture event ordering race.
        // https://crbug.com/821237.
        // DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);

        // The FlingController handles GFS with touchpad source and sends wheel
        // events to progress the fling, the wheel events will get processed by
        // the MouseWheelEventQueue and GSU events with inertial phase will be
        // sent to the renderer. is_in_gesture_scroll must stay true till the
        // fling progress is finished. Then the FlingController will generate
        // and send a wheel event with phaseEnded. MouseWheelEventQueue will
        // process the wheel event to generate and send a GSE which shows the
        // end of a scroll sequence.
      } else {  // !GetView()->IsInVR() &&
                // !GetView()->wheel_scroll_latching_enabled()

        // When wheel scroll latching is disabled a GSE is sent before a GFS.
        // The GSE has already finished the scroll sequence.
        DCHECK(!is_in_gesture_scroll_[gesture_event.SourceDevice()]);
      }

      is_in_touchpad_gesture_fling_ = true;
    } else {
      DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);

      // The FlingController handles GFS with touchscreen source and sends GSU
      // events with inertial state to the renderer to progress the fling.
      // is_in_gesture_scroll must stay true till the fling progress is
      // finished. Then the FlingController will generate and send a GSE which
      // shows the end of a scroll sequence and resets is_in_gesture_scroll_.
    }
  }

  // TODO(wjmaclean) Remove the code for supporting resending gesture events
  // when WebView transitions to OOPIF and BrowserPlugin is removed.
  // http://crbug.com/533069
  scroll_update_needs_wrapping =
      gesture_event.GetType() == blink::WebInputEvent::kGestureScrollUpdate &&
      gesture_event.resending_plugin_id != -1 &&
      !is_in_gesture_scroll_[gesture_event.SourceDevice()];

  // TODO(crbug.com/544782): Fix WebViewGuestScrollTest.TestGuestWheelScrolls-
  // Bubble to test the resending logic of gesture events.
  if (scroll_update_needs_wrapping) {
    ForwardGestureEventWithLatencyInfo(
        CreateScrollBeginForWrapping(gesture_event),
        ui::WebInputEventTraits::CreateLatencyInfoForWebGestureEvent(
            gesture_event));
  }

  // Delegate must be non-null, due to |ShouldDropInputEvents()| test.
  if (delegate_->PreHandleGestureEvent(gesture_event))
    return;

  GestureEventWithLatencyInfo gesture_with_latency(gesture_event, latency);
  DispatchInputEventWithLatencyInfo(gesture_event,
                                    &gesture_with_latency.latency);
  input_router_->SendGestureEvent(gesture_with_latency);

  if (scroll_update_needs_wrapping) {
    ForwardGestureEventWithLatencyInfo(
        CreateScrollEndForWrapping(gesture_event),
        ui::WebInputEventTraits::CreateLatencyInfoForWebGestureEvent(
            gesture_event));
  }
}

void RenderWidgetHostImpl::ForwardEmulatedTouchEvent(
      const blink::WebTouchEvent& touch_event) {
  TRACE_EVENT0("input", "RenderWidgetHostImpl::ForwardEmulatedTouchEvent");
  ui::LatencyInfo latency_info(ui::SourceEventType::TOUCH);
  TouchEventWithLatencyInfo touch_with_latency(touch_event, latency_info);
  DispatchInputEventWithLatencyInfo(touch_event, &touch_with_latency.latency);
  input_router_->SendTouchEvent(touch_with_latency);
}

void RenderWidgetHostImpl::ForwardTouchEventWithLatencyInfo(
    const blink::WebTouchEvent& touch_event,
    const ui::LatencyInfo& latency) {
  TRACE_EVENT0("input", "RenderWidgetHostImpl::ForwardTouchEvent");

  // Always forward TouchEvents for touch stream consistency. They will be
  // ignored if appropriate in FilterInputEvent().

  TouchEventWithLatencyInfo touch_with_latency(touch_event, latency);
  if (touch_emulator_ &&
      touch_emulator_->HandleTouchEvent(touch_with_latency.event)) {
    if (view_) {
      view_->ProcessAckedTouchEvent(
          touch_with_latency, INPUT_EVENT_ACK_STATE_CONSUMED);
    }
    return;
  }

  DispatchInputEventWithLatencyInfo(touch_event, &touch_with_latency.latency);
  input_router_->SendTouchEvent(touch_with_latency);
}

void RenderWidgetHostImpl::ForwardKeyboardEvent(
    const NativeWebKeyboardEvent& key_event) {
  ui::LatencyInfo latency_info;

  if (key_event.GetType() == WebInputEvent::kRawKeyDown ||
      key_event.GetType() == WebInputEvent::kChar) {
    latency_info.set_source_event_type(ui::SourceEventType::KEY_PRESS);
  }
  ForwardKeyboardEventWithLatencyInfo(key_event, latency_info);
}

void RenderWidgetHostImpl::ForwardKeyboardEventWithLatencyInfo(
    const NativeWebKeyboardEvent& key_event,
    const ui::LatencyInfo& latency) {
  ForwardKeyboardEventWithCommands(key_event, latency, nullptr, nullptr);
}

void RenderWidgetHostImpl::ForwardKeyboardEventWithCommands(
    const NativeWebKeyboardEvent& key_event,
    const ui::LatencyInfo& latency,
    const std::vector<EditCommand>* commands,
    bool* update_event) {
  TRACE_EVENT0("input", "RenderWidgetHostImpl::ForwardKeyboardEvent");
  if (owner_delegate_ &&
      !owner_delegate_->MayRenderWidgetForwardKeyboardEvent(key_event)) {
    return;
  }

  if (ShouldDropInputEvents())
    return;

  if (!process_->HasConnection())
    return;

  // First, let keypress listeners take a shot at handling the event.  If a
  // listener handles the event, it should not be propagated to the renderer.
  if (KeyPressListenersHandleEvent(key_event)) {
    // Some keypresses that are accepted by the listener may be followed by Char
    // and KeyUp events, which should be ignored.
    if (key_event.GetType() == WebKeyboardEvent::kRawKeyDown)
      suppress_events_until_keydown_ = true;
    return;
  }

  // Double check the type to make sure caller hasn't sent us nonsense that
  // will mess up our key queue.
  if (!WebInputEvent::IsKeyboardEventType(key_event.GetType()))
    return;

  if (suppress_events_until_keydown_) {
    // If the preceding RawKeyDown event was handled by the browser, then we
    // need to suppress all events generated by it until the next RawKeyDown or
    // KeyDown event.
    if (key_event.GetType() == WebKeyboardEvent::kKeyUp ||
        key_event.GetType() == WebKeyboardEvent::kChar)
      return;
    DCHECK(key_event.GetType() == WebKeyboardEvent::kRawKeyDown ||
           key_event.GetType() == WebKeyboardEvent::kKeyDown);
    suppress_events_until_keydown_ = false;
  }

  bool is_shortcut = false;

  // Only pre-handle the key event if it's not handled by the input method.
  if (delegate_ && !key_event.skip_in_browser) {
    // We need to set |suppress_events_until_keydown_| to true if
    // PreHandleKeyboardEvent() handles the event, but |this| may already be
    // destroyed at that time. So set |suppress_events_until_keydown_| true
    // here, then revert it afterwards when necessary.
    if (key_event.GetType() == WebKeyboardEvent::kRawKeyDown)
      suppress_events_until_keydown_ = true;

    // Tab switching/closing accelerators aren't sent to the renderer to avoid
    // a hung/malicious renderer from interfering.
    switch (delegate_->PreHandleKeyboardEvent(key_event)) {
      case KeyboardEventProcessingResult::HANDLED:
        return;
#if defined(USE_AURA)
      case KeyboardEventProcessingResult::HANDLED_DONT_UPDATE_EVENT:
        if (update_event)
          *update_event = false;
        return;
#endif
      case KeyboardEventProcessingResult::NOT_HANDLED:
        break;
      case KeyboardEventProcessingResult::NOT_HANDLED_IS_SHORTCUT:
        is_shortcut = true;
        break;
    }

    if (key_event.GetType() == WebKeyboardEvent::kRawKeyDown)
      suppress_events_until_keydown_ = false;
  }

  if (touch_emulator_ && touch_emulator_->HandleKeyboardEvent(key_event))
    return;
  NativeWebKeyboardEventWithLatencyInfo key_event_with_latency(key_event,
                                                               latency);
  key_event_with_latency.event.is_browser_shortcut = is_shortcut;
  DispatchInputEventWithLatencyInfo(key_event, &key_event_with_latency.latency);
  // TODO(foolip): |InputRouter::SendKeyboardEvent()| may filter events, in
  // which the commands will be treated as belonging to the next key event.
  // WidgetInputHandler::SetEditCommandsForNextKeyEvent should only be sent if
  // WidgetInputHandler::DispatchEvent is, but has to be sent first.
  // https://crbug.com/684298
  if (commands && !commands->empty()) {
    GetWidgetInputHandler()->SetEditCommandsForNextKeyEvent(*commands);
  }
  input_router_->SendKeyboardEvent(key_event_with_latency);
}

void RenderWidgetHostImpl::QueueSyntheticGesture(
    std::unique_ptr<SyntheticGesture> synthetic_gesture,
    base::OnceCallback<void(SyntheticGesture::Result)> on_complete) {
  if (!synthetic_gesture_controller_ && view_) {
    synthetic_gesture_controller_ =
        std::make_unique<SyntheticGestureController>(
            this, view_->CreateSyntheticGestureTarget());
  }
  if (synthetic_gesture_controller_) {
    synthetic_gesture_controller_->QueueSyntheticGesture(
        std::move(synthetic_gesture), std::move(on_complete));
  }
}

void RenderWidgetHostImpl::SetCursor(const WebCursor& cursor) {
  if (!view_)
    return;
  view_->UpdateCursor(cursor);
}

void RenderWidgetHostImpl::ShowContextMenuAtPoint(
    const gfx::Point& point,
    const ui::MenuSourceType source_type) {
  Send(new ViewMsg_ShowContextMenu(GetRoutingID(), source_type, point));
}

void RenderWidgetHostImpl::SendCursorVisibilityState(bool is_visible) {
  GetWidgetInputHandler()->CursorVisibilityChanged(is_visible);
}

int64_t RenderWidgetHostImpl::GetLatencyComponentId() const {
  return latency_tracker_.latency_component_id();
}

// static
void RenderWidgetHostImpl::DisableResizeAckCheckForTesting() {
  g_check_for_pending_resize_ack = false;
}

void RenderWidgetHostImpl::AddKeyPressEventCallback(
    const KeyPressEventCallback& callback) {
  key_press_event_callbacks_.push_back(callback);
}

void RenderWidgetHostImpl::RemoveKeyPressEventCallback(
    const KeyPressEventCallback& callback) {
  for (size_t i = 0; i < key_press_event_callbacks_.size(); ++i) {
    if (key_press_event_callbacks_[i].Equals(callback)) {
      key_press_event_callbacks_.erase(
          key_press_event_callbacks_.begin() + i);
      return;
    }
  }
}

void RenderWidgetHostImpl::AddMouseEventCallback(
    const MouseEventCallback& callback) {
  mouse_event_callbacks_.push_back(callback);
}

void RenderWidgetHostImpl::RemoveMouseEventCallback(
    const MouseEventCallback& callback) {
  for (size_t i = 0; i < mouse_event_callbacks_.size(); ++i) {
    if (mouse_event_callbacks_[i].Equals(callback)) {
      mouse_event_callbacks_.erase(mouse_event_callbacks_.begin() + i);
      return;
    }
  }
}

void RenderWidgetHostImpl::AddInputEventObserver(
    RenderWidgetHost::InputEventObserver* observer) {
  if (!input_event_observers_.HasObserver(observer))
    input_event_observers_.AddObserver(observer);
}

void RenderWidgetHostImpl::RemoveInputEventObserver(
    RenderWidgetHost::InputEventObserver* observer) {
  input_event_observers_.RemoveObserver(observer);
}

void RenderWidgetHostImpl::AddObserver(RenderWidgetHostObserver* observer) {
  observers_.AddObserver(observer);
}

void RenderWidgetHostImpl::RemoveObserver(RenderWidgetHostObserver* observer) {
  observers_.RemoveObserver(observer);
}

void RenderWidgetHostImpl::GetScreenInfo(ScreenInfo* result) {
  TRACE_EVENT0("renderer_host", "RenderWidgetHostImpl::GetScreenInfo");
  if (view_)
    view_->GetScreenInfo(result);
  else
    DisplayUtil::GetDefaultScreenInfo(result);

  // TODO(sievers): find a way to make this done another way so the method
  // can be const.
  if (IsUseZoomForDSFEnabled())
    input_router_->SetDeviceScaleFactor(result->device_scale_factor);
}

void RenderWidgetHostImpl::DragTargetDragEnter(
    const DropData& drop_data,
    const gfx::PointF& client_pt,
    const gfx::PointF& screen_pt,
    WebDragOperationsMask operations_allowed,
    int key_modifiers) {
  DragTargetDragEnterWithMetaData(DropDataToMetaData(drop_data), client_pt,
                                  screen_pt, operations_allowed, key_modifiers);
}

void RenderWidgetHostImpl::DragTargetDragEnterWithMetaData(
    const std::vector<DropData::Metadata>& metadata,
    const gfx::PointF& client_pt,
    const gfx::PointF& screen_pt,
    WebDragOperationsMask operations_allowed,
    int key_modifiers) {
  Send(new DragMsg_TargetDragEnter(GetRoutingID(), metadata, client_pt,
                                   screen_pt, operations_allowed,
                                   key_modifiers));
}

void RenderWidgetHostImpl::DragTargetDragOver(
    const gfx::PointF& client_pt,
    const gfx::PointF& screen_pt,
    WebDragOperationsMask operations_allowed,
    int key_modifiers) {
  Send(new DragMsg_TargetDragOver(GetRoutingID(), client_pt, screen_pt,
                                  operations_allowed, key_modifiers));
}

void RenderWidgetHostImpl::DragTargetDragLeave(
    const gfx::PointF& client_point,
    const gfx::PointF& screen_point) {
  Send(new DragMsg_TargetDragLeave(GetRoutingID(), client_point, screen_point));
}

void RenderWidgetHostImpl::DragTargetDrop(const DropData& drop_data,
                                          const gfx::PointF& client_pt,
                                          const gfx::PointF& screen_pt,
                                          int key_modifiers) {
  DropData drop_data_with_permissions(drop_data);
  GrantFileAccessFromDropData(&drop_data_with_permissions);
  Send(new DragMsg_TargetDrop(GetRoutingID(), drop_data_with_permissions,
                              client_pt, screen_pt, key_modifiers));
}

void RenderWidgetHostImpl::DragSourceEndedAt(
    const gfx::PointF& client_pt,
    const gfx::PointF& screen_pt,
    blink::WebDragOperation operation) {
  Send(new DragMsg_SourceEnded(GetRoutingID(),
                               client_pt,
                               screen_pt,
                               operation));
}

void RenderWidgetHostImpl::DragSourceSystemDragEnded() {
  Send(new DragMsg_SourceSystemDragEnded(GetRoutingID()));
}

void RenderWidgetHostImpl::FilterDropData(DropData* drop_data) {
#if DCHECK_IS_ON()
  drop_data->view_id = GetRoutingID();
#endif  // DCHECK_IS_ON()

  GetProcess()->FilterURL(true, &drop_data->url);
  if (drop_data->did_originate_from_renderer) {
    drop_data->filenames.clear();
  }
}

void RenderWidgetHostImpl::SetCursor(const CursorInfo& cursor_info) {
  WebCursor cursor;
  cursor.InitFromCursorInfo(cursor_info);
  SetCursor(cursor);
}

RenderProcessHost::Priority RenderWidgetHostImpl::GetPriority() {
  RenderProcessHost::Priority priority = {
    is_hidden_,
    frame_depth_,
#if defined(OS_ANDROID)
    importance_,
#endif
  };
  if (owner_delegate_ &&
      !owner_delegate_->ShouldContributePriorityToProcess()) {
    priority.is_hidden = true;
    priority.frame_depth = RenderProcessHostImpl::kMaxFrameDepthForPriority;
#if defined(OS_ANDROID)
    priority.importance = ChildProcessImportance::NORMAL;
#endif
  }
  return priority;
}

mojom::WidgetInputHandler* RenderWidgetHostImpl::GetWidgetInputHandler() {
  if (associated_widget_input_handler_)
    return associated_widget_input_handler_.get();
  if (widget_input_handler_)
    return widget_input_handler_.get();
  // TODO(dtapuska): Remove the need for the unbound interface. It is
  // possible that a RVHI may make calls to a WidgetInputHandler when
  // the main frame is remote. This is because of ordering issues during
  // widget shutdown, so we present an UnboundWidgetInputHandler had
  // DLOGS the message calls.
  return g_unbound_input_handler.Pointer();
}

void RenderWidgetHostImpl::NotifyScreenInfoChanged() {
  // The resize message (which may not happen immediately) will carry with it
  // the screen info as well as the new size (if the screen has changed scale
  // factor).
  WasResized();

  if (touch_emulator_) {
    touch_emulator_->SetDeviceScaleFactor(GetScaleFactorForView(view_.get()));
  }
}

void RenderWidgetHostImpl::GetSnapshotFromBrowser(
    const GetSnapshotFromBrowserCallback& callback,
    bool from_surface) {
  int id = next_browser_snapshot_id_++;
  if (from_surface) {
    pending_surface_browser_snapshots_.insert(std::make_pair(id, callback));
    ui::LatencyInfo latency_info;
    latency_info.AddLatencyNumber(ui::BROWSER_SNAPSHOT_FRAME_NUMBER_COMPONENT,
                                  GetLatencyComponentId(), id);
    Send(new ViewMsg_ForceRedraw(GetRoutingID(), latency_info));
    return;
  }

#if defined(OS_MACOSX)
  // MacOS version of underlying GrabViewSnapshot() blocks while
  // display/GPU are in a power-saving mode, so make sure display
  // does not go to sleep for the duration of reading a snapshot.
  if (pending_browser_snapshots_.empty())
    GetWakeLock()->RequestWakeLock();
#endif
  pending_browser_snapshots_.insert(std::make_pair(id, callback));
  ui::LatencyInfo latency_info;
  latency_info.AddLatencyNumber(ui::BROWSER_SNAPSHOT_FRAME_NUMBER_COMPONENT,
                                GetLatencyComponentId(), id);
  Send(new ViewMsg_ForceRedraw(GetRoutingID(), latency_info));
}

void RenderWidgetHostImpl::SelectionChanged(const base::string16& text,
                                            uint32_t offset,
                                            const gfx::Range& range) {
  if (view_)
    view_->SelectionChanged(text, static_cast<size_t>(offset), range);
}

void RenderWidgetHostImpl::OnSelectionBoundsChanged(
    const ViewHostMsg_SelectionBounds_Params& params) {
  if (view_)
    view_->SelectionBoundsChanged(params);
}

void RenderWidgetHostImpl::OnFocusedNodeTouched(bool editable) {
  if (delegate_)
    delegate_->FocusedNodeTouched(editable);
}

void RenderWidgetHostImpl::OnStartDragging(
    const DropData& drop_data,
    blink::WebDragOperationsMask drag_operations_mask,
    const SkBitmap& bitmap,
    const gfx::Vector2d& bitmap_offset_in_dip,
    const DragEventSourceInfo& event_info) {
  RenderViewHostDelegateView* view = delegate_->GetDelegateView();
  if (!view || !GetView()) {
    // Need to clear drag and drop state in blink.
    DragSourceSystemDragEnded();
    return;
  }

  DropData filtered_data(drop_data);
  RenderProcessHost* process = GetProcess();
  ChildProcessSecurityPolicyImpl* policy =
      ChildProcessSecurityPolicyImpl::GetInstance();

  // Allow drag of Javascript URLs to enable bookmarklet drag to bookmark bar.
  if (!filtered_data.url.SchemeIs(url::kJavaScriptScheme))
    process->FilterURL(true, &filtered_data.url);
  process->FilterURL(false, &filtered_data.html_base_url);
  // Filter out any paths that the renderer didn't have access to. This prevents
  // the following attack on a malicious renderer:
  // 1. StartDragging IPC sent with renderer-specified filesystem paths that it
  //    doesn't have read permissions for.
  // 2. We initiate a native DnD operation.
  // 3. DnD operation immediately ends since mouse is not held down. DnD events
  //    still fire though, which causes read permissions to be granted to the
  //    renderer for any file paths in the drop.
  filtered_data.filenames.clear();
  for (const auto& file_info : drop_data.filenames) {
    if (policy->CanReadFile(GetProcess()->GetID(), file_info.path))
      filtered_data.filenames.push_back(file_info);
  }

  storage::FileSystemContext* file_system_context =
      GetProcess()->GetStoragePartition()->GetFileSystemContext();
  filtered_data.file_system_files.clear();
  for (size_t i = 0; i < drop_data.file_system_files.size(); ++i) {
    storage::FileSystemURL file_system_url =
        file_system_context->CrackURL(drop_data.file_system_files[i].url);
    if (policy->CanReadFileSystemFile(GetProcess()->GetID(), file_system_url))
      filtered_data.file_system_files.push_back(drop_data.file_system_files[i]);
  }

  float scale = GetScaleFactorForView(GetView());
  gfx::ImageSkia image(gfx::ImageSkiaRep(bitmap, scale));
  view->StartDragging(filtered_data, drag_operations_mask, image,
                      bitmap_offset_in_dip, event_info, this);
}

void RenderWidgetHostImpl::OnUpdateDragCursor(WebDragOperation current_op) {
  if (delegate_->OnUpdateDragCursor())
    return;

  RenderViewHostDelegateView* view = delegate_->GetDelegateView();
  if (view)
    view->UpdateDragCursor(current_op);
}

void RenderWidgetHostImpl::OnFrameSwapMessagesReceived(
    uint32_t frame_token,
    std::vector<IPC::Message> messages) {
  frame_token_message_queue_->OnFrameSwapMessagesReceived(frame_token,
                                                          std::move(messages));
}

void RenderWidgetHostImpl::RendererExited(base::TerminationStatus status,
                                          int exit_code) {
  if (!renderer_initialized_)
    return;

  // Clear this flag so that we can ask the next renderer for composition
  // updates.
  monitoring_composition_info_ = false;

  // Clearing this flag causes us to re-create the renderer when recovering
  // from a crashed renderer.
  renderer_initialized_ = false;

  waiting_for_screen_rects_ack_ = false;

  // Must reset these to ensure that keyboard events work with a new renderer.
  suppress_events_until_keydown_ = false;

  // Reset some fields in preparation for recovering from a crash.
  ResetSizeAndRepaintPendingFlags();
  current_size_.SetSize(0, 0);
  // After the renderer crashes, the view is destroyed and so the
  // RenderWidgetHost cannot track its visibility anymore. We assume such
  // RenderWidgetHost to be invisible for the sake of internal accounting - be
  // careful about changing this - see http://crbug.com/401859 and
  // http://crbug.com/522795.
  //
  // We need to at least make sure that the RenderProcessHost is notified about
  // the |is_hidden_| change, so that the renderer will have correct visibility
  // set when respawned.
  if (!is_hidden_) {
    is_hidden_ = true;
    if (!destroyed_)
      process_->UpdateClientPriority(this);
  }

  // Reset this to ensure the hung renderer mechanism is working properly.
  in_flight_event_count_ = 0;
  StopHangMonitorTimeout();

  if (view_) {
    view_->RenderProcessGone(status, exit_code);
    view_.reset();  // The View should be deleted by RenderProcessGone.
  }

  // Reconstruct the input router to ensure that it has fresh state for a new
  // renderer. Otherwise it may be stuck waiting for the old renderer to ack an
  // event. (In particular, the above call to view_->RenderProcessGone will
  // destroy the aura window, which may dispatch a synthetic mouse move.)
  SetupInputRouter();
  synthetic_gesture_controller_.reset();

  current_content_source_id_ = 0;

  frame_token_message_queue_->Reset();
}

void RenderWidgetHostImpl::UpdateTextDirection(WebTextDirection direction) {
  text_direction_updated_ = true;
  text_direction_ = direction;
}

void RenderWidgetHostImpl::CancelUpdateTextDirection() {
  if (text_direction_updated_)
    text_direction_canceled_ = true;
}

void RenderWidgetHostImpl::NotifyTextDirection() {
  if (text_direction_updated_) {
    if (!text_direction_canceled_)
      Send(new ViewMsg_SetTextDirection(GetRoutingID(), text_direction_));
    text_direction_updated_ = false;
    text_direction_canceled_ = false;
  }
}

void RenderWidgetHostImpl::ImeSetComposition(
    const base::string16& text,
    const std::vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int selection_start,
    int selection_end) {
  GetWidgetInputHandler()->ImeSetComposition(
      text, ime_text_spans, replacement_range, selection_start, selection_end);
}

void RenderWidgetHostImpl::ImeCommitText(
    const base::string16& text,
    const std::vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int relative_cursor_pos) {
  GetWidgetInputHandler()->ImeCommitText(
      text, ime_text_spans, replacement_range, relative_cursor_pos);
}

void RenderWidgetHostImpl::ImeFinishComposingText(bool keep_selection) {
  GetWidgetInputHandler()->ImeFinishComposingText(keep_selection);
}

void RenderWidgetHostImpl::ImeCancelComposition() {
  GetWidgetInputHandler()->ImeSetComposition(base::string16(),
                                             std::vector<ui::ImeTextSpan>(),
                                             gfx::Range::InvalidRange(), 0, 0);
}

void RenderWidgetHostImpl::RejectMouseLockOrUnlockIfNecessary() {
  DCHECK(!pending_mouse_lock_request_ || !IsMouseLocked());
  if (pending_mouse_lock_request_) {
    pending_mouse_lock_request_ = false;
    Send(new ViewMsg_LockMouse_ACK(routing_id_, false));
  } else if (IsMouseLocked()) {
    view_->UnlockMouse();
  }
}

bool RenderWidgetHostImpl::IsKeyboardLocked() const {
  return view_ ? view_->IsKeyboardLocked() : false;
}

void RenderWidgetHostImpl::GetContentRenderingTimeoutFrom(
    RenderWidgetHostImpl* other) {
  if (other->new_content_rendering_timeout_ &&
      other->new_content_rendering_timeout_->IsRunning()) {
    new_content_rendering_timeout_->Start(
        other->new_content_rendering_timeout_->GetCurrentDelay());
  }
}

bool RenderWidgetHostImpl::IsMouseLocked() const {
  return view_ ? view_->IsMouseLocked() : false;
}

void RenderWidgetHostImpl::SetAutoResize(bool enable,
                                         const gfx::Size& min_size,
                                         const gfx::Size& max_size) {
  auto_resize_enabled_ = enable;
  min_size_for_auto_resize_ = min_size;
  max_size_for_auto_resize_ = max_size;
}

void RenderWidgetHostImpl::Destroy(bool also_delete) {
  DCHECK(!destroyed_);
  destroyed_ = true;

  for (auto& observer : observers_)
    observer.RenderWidgetHostDestroyed(this);
  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_HOST_DESTROYED, Source<RenderWidgetHost>(this),
      NotificationService::NoDetails());

  // Tell the view to die.
  // Note that in the process of the view shutting down, it can call a ton
  // of other messages on us.  So if you do any other deinitialization here,
  // do it after this call to view_->Destroy().
  if (view_) {
    view_->Destroy();
    view_.reset();
  }

  // The display compositor has ownership of shared memory for each
  // SharedBitmapId that has been reported from the client. Since the client is
  // gone that memory can be freed. If we don't then it would leak.
  for (const auto& id : owned_bitmaps_)
    viz::ServerSharedBitmapManager::current()->ChildDeletedSharedBitmap(id);

  process_->RemoveWidget(this);
  process_->RemoveRoute(routing_id_);
  g_routing_id_widget_map.Get().erase(
      RenderWidgetHostID(process_->GetID(), routing_id_));

  if (delegate_)
    delegate_->RenderWidgetDeleted(this);

  if (also_delete) {
    CHECK(!owner_delegate_);
    delete this;
  }
}

void RenderWidgetHostImpl::RendererIsUnresponsive() {
  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_HOST_HANG,
      Source<RenderWidgetHost>(this),
      NotificationService::NoDetails());
  is_unresponsive_ = true;

  if (delegate_)
    delegate_->RendererUnresponsive(this);

  // Do not add code after this since the Delegate may delete this
  // RenderWidgetHostImpl in RendererUnresponsive.
}

void RenderWidgetHostImpl::RendererIsResponsive() {
  if (is_unresponsive_) {
    is_unresponsive_ = false;
    if (delegate_)
      delegate_->RendererResponsive(this);
  }
}

void RenderWidgetHostImpl::ClearDisplayedGraphics() {
  NotifyNewContentRenderingTimeoutForTesting();
  if (view_)
    view_->ClearCompositorFrame();
}

void RenderWidgetHostImpl::OnGpuSwapBuffersCompletedInternal(
    const ui::LatencyInfo& latency_info) {
  // Note that a compromised renderer can send LatencyInfo to a
  // RenderWidgetHostImpl other than its own. Be mindful of security
  // implications of the code you add here.
  ui::LatencyInfo::LatencyComponent window_snapshot_component;
  if (latency_info.FindLatency(ui::BROWSER_SNAPSHOT_FRAME_NUMBER_COMPONENT,
                               GetLatencyComponentId(),
                               &window_snapshot_component)) {
    int sequence_number =
        static_cast<int>(window_snapshot_component.sequence_number);
#if defined(OS_MACOSX) || defined(OS_WIN)
    // On Mac, when using CoreAnimation, or Win32 when using GDI, there is a
    // delay between when content is drawn to the screen, and when the
    // snapshot will actually pick up that content. Insert a manual delay of
    // 1/6th of a second (to simulate 10 frames at 60 fps) before actually
    // taking the snapshot.
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE,
        base::Bind(&RenderWidgetHostImpl::WindowSnapshotReachedScreen,
                   weak_factory_.GetWeakPtr(), sequence_number),
        TimeDelta::FromSecondsD(1. / 6));
#else
    WindowSnapshotReachedScreen(sequence_number);
#endif
  }

  latency_tracker_.OnGpuSwapBuffersCompleted(latency_info);
}

void RenderWidgetHostImpl::OnRenderProcessGone(int status, int exit_code) {
  // RenderFrameHost owns a RenderWidgetHost when it needs one, in which case
  // it handles destruction.
  if (!owned_by_render_frame_host_) {
    // TODO(evanm): This synchronously ends up calling "delete this".
    // Is that really what we want in response to this message?  I'm matching
    // previous behavior of the code here.
    Destroy(true);
  } else {
    RendererExited(static_cast<base::TerminationStatus>(status), exit_code);
  }
}

void RenderWidgetHostImpl::OnHittestData(
    const FrameHostMsg_HittestData_Params& params) {
  if (delegate_)
    delegate_->GetInputEventRouter()->OnHittestData(params);
}

void RenderWidgetHostImpl::OnClose() {
  ShutdownAndDestroyWidget(true);
}

void RenderWidgetHostImpl::OnSetTooltipText(
    const base::string16& tooltip_text,
    WebTextDirection text_direction_hint) {
  if (!GetView())
    return;

  // First, add directionality marks around tooltip text if necessary.
  // A naive solution would be to simply always wrap the text. However, on
  // windows, Unicode directional embedding characters can't be displayed on
  // systems that lack RTL fonts and are instead displayed as empty squares.
  //
  // To get around this we only wrap the string when we deem it necessary i.e.
  // when the locale direction is different than the tooltip direction hint.
  //
  // Currently, we use element's directionality as the tooltip direction hint.
  // An alternate solution would be to set the overall directionality based on
  // trying to detect the directionality from the tooltip text rather than the
  // element direction.  One could argue that would be a preferable solution
  // but we use the current approach to match Fx & IE's behavior.
  base::string16 wrapped_tooltip_text = tooltip_text;
  if (!tooltip_text.empty()) {
    if (text_direction_hint == blink::kWebTextDirectionLeftToRight) {
      // Force the tooltip to have LTR directionality.
      wrapped_tooltip_text =
          base::i18n::GetDisplayStringInLTRDirectionality(wrapped_tooltip_text);
    } else if (text_direction_hint == blink::kWebTextDirectionRightToLeft &&
               !base::i18n::IsRTL()) {
      // Force the tooltip to have RTL directionality.
      base::i18n::WrapStringWithRTLFormatting(&wrapped_tooltip_text);
    }
  }
  view_->SetTooltipText(wrapped_tooltip_text);
}

void RenderWidgetHostImpl::OnUpdateScreenRectsAck() {
  waiting_for_screen_rects_ack_ = false;
  if (!view_)
    return;

  if (view_->GetViewBounds() == last_view_screen_rect_ &&
      view_->GetBoundsInRootWindow() == last_window_screen_rect_) {
    return;
  }

  SendScreenRects();
}

void RenderWidgetHostImpl::OnRequestMove(const gfx::Rect& pos) {
  if (view_) {
    view_->SetBounds(pos);
    Send(new ViewMsg_Move_ACK(routing_id_));
  }
}

void RenderWidgetHostImpl::DidNotProduceFrame(const viz::BeginFrameAck& ack) {
  // |has_damage| is not transmitted.
  viz::BeginFrameAck modified_ack = ack;
  modified_ack.has_damage = false;

  if (view_)
    view_->OnDidNotProduceFrame(modified_ack);
}

void RenderWidgetHostImpl::DidAllocateSharedBitmap(
    mojo::ScopedSharedBufferHandle buffer,
    const viz::SharedBitmapId& id) {
  if (!viz::ServerSharedBitmapManager::current()->ChildAllocatedSharedBitmap(
          std::move(buffer), id)) {
    bad_message::ReceivedBadMessage(GetProcess(),
                                    bad_message::RWH_SHARED_BITMAP);
  }
  owned_bitmaps_.insert(id);
}

void RenderWidgetHostImpl::DidDeleteSharedBitmap(
    const viz::SharedBitmapId& id) {
  viz::ServerSharedBitmapManager::current()->ChildDeletedSharedBitmap(id);
  owned_bitmaps_.erase(id);
}

void RenderWidgetHostImpl::OnResizeOrRepaintACK(
    const ViewHostMsg_ResizeOrRepaint_ACK_Params& params) {
  TRACE_EVENT0("renderer_host", "RenderWidgetHostImpl::OnResizeOrRepaintACK");
  TimeTicks paint_start = clock_->NowTicks();

  // Update our knowledge of the RenderWidget's size.
  current_size_ = params.view_size;

  bool is_resize_ack =
      ViewHostMsg_ResizeOrRepaint_ACK_Flags::is_resize_ack(params.flags);

  // resize_ack_pending_ needs to be cleared before we call DidPaintRect, since
  // that will end up reaching GetBackingStore.
  if (is_resize_ack) {
    DCHECK(!g_check_for_pending_resize_ack || resize_ack_pending_);
    resize_ack_pending_ = false;
  }

  bool is_repaint_ack =
      ViewHostMsg_ResizeOrRepaint_ACK_Flags::is_repaint_ack(params.flags);
  if (is_repaint_ack) {
    DCHECK(repaint_ack_pending_);
    TRACE_EVENT_ASYNC_END0(
        "renderer_host", "RenderWidgetHostImpl::repaint_ack_pending_", this);
    repaint_ack_pending_ = false;
    TimeDelta delta = clock_->NowTicks() - repaint_start_time_;
    UMA_HISTOGRAM_TIMES("MPArch.RWH_RepaintDelta", delta);
  }

  DCHECK(!params.view_size.IsEmpty());

  DidCompleteResizeOrRepaint(params, paint_start);

  last_auto_resize_request_number_ = params.sequence_number;
  last_auto_resize_surface_id_ = params.child_allocated_local_surface_id;

  if (auto_resize_enabled_) {
    bool post_callback = new_auto_size_.IsEmpty();
    new_auto_size_ = params.view_size;
    if (post_callback) {
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::BindOnce(&RenderWidgetHostImpl::DelayedAutoResized,
                                    weak_factory_.GetWeakPtr()));
    }
  }

  // Log the time delta for processing a paint message. On platforms that don't
  // support asynchronous painting, this is equivalent to
  // MPArch.RWH_TotalPaintTime.
  TimeDelta delta = clock_->NowTicks() - paint_start;
  UMA_HISTOGRAM_TIMES("MPArch.RWH_OnMsgResizeOrRepaintACK", delta);
}

void RenderWidgetHostImpl::DidCompleteResizeOrRepaint(
    const ViewHostMsg_ResizeOrRepaint_ACK_Params& params,
    const TimeTicks& paint_start) {
  TRACE_EVENT0("renderer_host",
               "RenderWidgetHostImpl::DidCompleteResizeOrRepaint");

  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_HOST_DID_COMPLETE_RESIZE_OR_REPAINT,
      Source<RenderWidgetHost>(this), NotificationService::NoDetails());

  // We don't need to update the view if the view is hidden. We must do this
  // early return after the ACK is sent, however, or the renderer will not send
  // us more data.
  if (is_hidden_)
    return;

  // If we got a resize ack, then perhaps we have another resize to send?
  bool is_resize_ack =
      ViewHostMsg_ResizeOrRepaint_ACK_Flags::is_resize_ack(params.flags);
  if (is_resize_ack)
    WasResized();
}

void RenderWidgetHostImpl::OnSetCursor(const WebCursor& cursor) {
  SetCursor(cursor);
}

void RenderWidgetHostImpl::OnAutoscrollStart(const gfx::PointF& position) {
  WebGestureEvent scroll_begin = SyntheticWebGestureEventBuilder::Build(
      WebInputEvent::kGestureScrollBegin,
      blink::kWebGestureDeviceSyntheticAutoscroll);
  scroll_begin.SetPositionInWidget(position);

  ForwardGestureEventWithLatencyInfo(
      scroll_begin, ui::LatencyInfo(ui::SourceEventType::OTHER));
}

void RenderWidgetHostImpl::OnAutoscrollFling(const gfx::Vector2dF& velocity) {
  WebGestureEvent event = SyntheticWebGestureEventBuilder::Build(
      WebInputEvent::kGestureFlingStart,
      blink::kWebGestureDeviceSyntheticAutoscroll);
  event.data.fling_start.velocity_x = velocity.x();
  event.data.fling_start.velocity_y = velocity.y();

  ForwardGestureEventWithLatencyInfo(
      event, ui::LatencyInfo(ui::SourceEventType::OTHER));
}

void RenderWidgetHostImpl::OnAutoscrollEnd() {
  WebGestureEvent cancel_event = SyntheticWebGestureEventBuilder::Build(
      WebInputEvent::kGestureFlingCancel,
      blink::kWebGestureDeviceSyntheticAutoscroll);
  cancel_event.data.fling_cancel.prevent_boosting = true;

  ForwardGestureEventWithLatencyInfo(
      cancel_event, ui::LatencyInfo(ui::SourceEventType::OTHER));
}

TouchEmulator* RenderWidgetHostImpl::GetTouchEmulator() {
  if (!touch_emulator_) {
    touch_emulator_.reset(
        new TouchEmulator(this, GetScaleFactorForView(view_.get())));
  }
  return touch_emulator_.get();
}

void RenderWidgetHostImpl::OnTextInputStateChanged(
    const TextInputState& params) {
  if (view_)
    view_->TextInputStateChanged(params);
}

void RenderWidgetHostImpl::OnImeCompositionRangeChanged(
    const gfx::Range& range,
    const std::vector<gfx::Rect>& character_bounds) {
  if (view_)
    view_->ImeCompositionRangeChanged(range, character_bounds);
}

void RenderWidgetHostImpl::OnImeCancelComposition() {
  if (view_)
    view_->ImeCancelComposition();
}

void RenderWidgetHostImpl::OnInvalidFrameToken(uint32_t frame_token) {
  bad_message::ReceivedBadMessage(GetProcess(),
                                  bad_message::RWH_INVALID_FRAME_TOKEN);
}

void RenderWidgetHostImpl::OnMessageDispatchError(const IPC::Message& message) {
  RenderProcessHost* rph = GetProcess();
  rph->OnBadMessageReceived(message);
}

void RenderWidgetHostImpl::OnProcessSwapMessage(const IPC::Message& message) {
  RenderProcessHost* rph = GetProcess();
  rph->OnMessageReceived(message);
}

void RenderWidgetHostImpl::OnLockMouse(bool user_gesture,
                                       bool privileged) {
  if (pending_mouse_lock_request_) {
    Send(new ViewMsg_LockMouse_ACK(routing_id_, false));
    return;
  }

  pending_mouse_lock_request_ = true;
  if (delegate_) {
    delegate_->RequestToLockMouse(this, user_gesture,
                                  is_last_unlocked_by_target_,
                                  privileged && allow_privileged_mouse_lock_);
    // We need to reset |is_last_unlocked_by_target_| here as we don't know
    // request source in |LostMouseLock()|.
    is_last_unlocked_by_target_ = false;
    return;
  }

  if (privileged && allow_privileged_mouse_lock_) {
    // Directly approve to lock the mouse.
    GotResponseToLockMouseRequest(true);
  } else {
    // Otherwise, just reject it.
    GotResponseToLockMouseRequest(false);
  }
}

void RenderWidgetHostImpl::OnUnlockMouse() {
  // Got unlock request from renderer. Will update |is_last_unlocked_by_target_|
  // for silent re-lock.
  const bool was_mouse_locked = !pending_mouse_lock_request_ && IsMouseLocked();
  RejectMouseLockOrUnlockIfNecessary();
  if (was_mouse_locked)
    is_last_unlocked_by_target_ = true;
}

void RenderWidgetHostImpl::RequestKeyboardLock(
    base::Optional<base::flat_set<int>> keys_to_lock) {
  if (!delegate_) {
    CancelKeyboardLock();
    return;
  }

  DCHECK(!keys_to_lock.has_value() || !keys_to_lock.value().empty());
  keyboard_keys_to_lock_ = std::move(keys_to_lock);
  keyboard_lock_requested_ = true;

  const int esc_native_key_code =
      ui::KeycodeConverter::DomCodeToNativeKeycode(ui::DomCode::ESCAPE);
  const bool esc_requested =
      !keyboard_keys_to_lock_.has_value() ||
      base::ContainsKey(keyboard_keys_to_lock_.value(), esc_native_key_code);

  if (!delegate_->RequestKeyboardLock(this, esc_requested))
    CancelKeyboardLock();
}

void RenderWidgetHostImpl::CancelKeyboardLock() {
  if (delegate_)
    delegate_->CancelKeyboardLock(this);

  UnlockKeyboard();

  keyboard_lock_allowed_ = false;
  keyboard_lock_requested_ = false;
  keyboard_keys_to_lock_.reset();
}

void RenderWidgetHostImpl::OnShowDisambiguationPopup(
    const gfx::Rect& rect_pixels,
    const gfx::Size& size,
    base::SharedMemoryHandle handle) {
  DCHECK(!rect_pixels.IsEmpty());
  DCHECK(!size.IsEmpty());

  SkImageInfo info = SkImageInfo::MakeN32Premul(size.width(), size.height());
  size_t shm_size = info.computeMinByteSize();

  base::SharedMemory shm(handle, false /* read_only */);
  if (shm_size == 0 || !shm.Map(shm_size)) {
    bad_message::ReceivedBadMessage(GetProcess(),
                                    bad_message::RWH_SHARED_BITMAP);
    return;
  }

  SkBitmap zoomed_bitmap;
  zoomed_bitmap.installPixels(info, shm.memory(), info.minRowBytes());

  // Note that |rect| is in coordinates of pixels relative to the window origin.
  // Aura-based systems will want to convert this to DIPs.
  if (view_)
    view_->ShowDisambiguationPopup(rect_pixels, zoomed_bitmap);

  // It is assumed that the disambiguation popup will make a copy of the
  // provided zoomed image, so we delete |zoomed_bitmap| and free shared memory.
}

void RenderWidgetHostImpl::SetIgnoreInputEvents(bool ignore_input_events) {
  ignore_input_events_ = ignore_input_events;
}

bool RenderWidgetHostImpl::KeyPressListenersHandleEvent(
    const NativeWebKeyboardEvent& event) {
  if (event.skip_in_browser || event.GetType() != WebKeyboardEvent::kRawKeyDown)
    return false;

  for (size_t i = 0; i < key_press_event_callbacks_.size(); i++) {
    size_t original_size = key_press_event_callbacks_.size();
    if (key_press_event_callbacks_[i].Run(event))
      return true;

    // Check whether the callback that just ran removed itself, in which case
    // the iterator needs to be decremented to properly account for the removal.
    size_t current_size = key_press_event_callbacks_.size();
    if (current_size != original_size) {
      DCHECK_EQ(original_size - 1, current_size);
      --i;
    }
  }

  return false;
}

InputEventAckState RenderWidgetHostImpl::FilterInputEvent(
    const blink::WebInputEvent& event, const ui::LatencyInfo& latency_info) {
  // Don't ignore touch cancel events, since they may be sent while input
  // events are being ignored in order to keep the renderer from getting
  // confused about how many touches are active.
  if (ShouldDropInputEvents() && event.GetType() != WebInputEvent::kTouchCancel)
    return INPUT_EVENT_ACK_STATE_NO_CONSUMER_EXISTS;

  if (!process_->HasConnection())
    return INPUT_EVENT_ACK_STATE_UNKNOWN;

  if (delegate_) {
    if (event.GetType() == WebInputEvent::kMouseDown ||
        event.GetType() == WebInputEvent::kTouchStart) {
      delegate_->FocusOwningWebContents(this);
    }
    if (event.GetType() == WebInputEvent::kMouseDown ||
        event.GetType() == WebInputEvent::kGestureScrollBegin ||
        event.GetType() == WebInputEvent::kTouchStart ||
        event.GetType() == WebInputEvent::kRawKeyDown) {
      delegate_->OnUserInteraction(this, event.GetType());
    }
  }

  return view_ ? view_->FilterInputEvent(event)
               : INPUT_EVENT_ACK_STATE_NOT_CONSUMED;
}

void RenderWidgetHostImpl::IncrementInFlightEventCount() {
  ++in_flight_event_count_;
  if (!is_hidden_)
    StartHangMonitorTimeout(hung_renderer_delay_);
}

void RenderWidgetHostImpl::DecrementInFlightEventCount(
    InputEventAckSource ack_source) {
  --in_flight_event_count_;
  if (in_flight_event_count_ <= 0) {
    // Cancel pending hung renderer checks since the renderer is responsive.
    StopHangMonitorTimeout();
  } else {
    // Only restart the hang monitor timer if we got a response from the
    // main thread.
    if (ack_source == InputEventAckSource::MAIN_THREAD)
      RestartHangMonitorTimeoutIfNecessary();
  }
}

void RenderWidgetHostImpl::OnHasTouchEventHandlers(bool has_handlers) {
  has_touch_handler_ = has_handlers;
}

void RenderWidgetHostImpl::DidOverscroll(
    const ui::DidOverscrollParams& params) {
  if (view_)
    view_->DidOverscroll(params);
}

void RenderWidgetHostImpl::DidStopFlinging() {
  is_in_touchpad_gesture_fling_ = false;
  if (view_)
    view_->DidStopFlinging();
}

void RenderWidgetHostImpl::DidStartScrollingViewport() {
  if (view_)
    view_->set_is_currently_scrolling_viewport(true);
}
void RenderWidgetHostImpl::SetNeedsBeginFrameForFlingProgress() {
  browser_fling_needs_begin_frame_ = true;
  SetNeedsBeginFrame(true);
}

void RenderWidgetHostImpl::DispatchInputEventWithLatencyInfo(
    const blink::WebInputEvent& event,
    ui::LatencyInfo* latency) {
  latency_tracker_.OnInputEvent(event, latency);
  for (auto& observer : input_event_observers_)
    observer.OnInputEvent(event);
}

void RenderWidgetHostImpl::OnKeyboardEventAck(
    const NativeWebKeyboardEventWithLatencyInfo& event,
    InputEventAckSource ack_source,
    InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(event.event, &event.latency, ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result, event.event);

  const bool processed = (INPUT_EVENT_ACK_STATE_CONSUMED == ack_result);

  // We only send unprocessed key event upwards if we are not hidden,
  // because the user has moved away from us and no longer expect any effect
  // of this key event.
  if (delegate_ && !processed && !is_hidden() && !event.event.skip_in_browser) {
    delegate_->HandleKeyboardEvent(event.event);

    // WARNING: This RenderWidgetHostImpl can be deallocated at this point
    // (i.e.  in the case of Ctrl+W, where the call to
    // HandleKeyboardEvent destroys this RenderWidgetHostImpl).
  }
}

void RenderWidgetHostImpl::OnMouseEventAck(
    const MouseEventWithLatencyInfo& mouse_event,
    InputEventAckSource ack_source,
    InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(mouse_event.event, &mouse_event.latency,
                                   ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result,
                                         mouse_event.event);
}

void RenderWidgetHostImpl::OnWheelEventAck(
    const MouseWheelEventWithLatencyInfo& wheel_event,
    InputEventAckSource ack_source,
    InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(wheel_event.event, &wheel_event.latency,
                                   ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result,
                                         wheel_event.event);

  if (!is_hidden() && view_) {
    if (ack_result != INPUT_EVENT_ACK_STATE_CONSUMED &&
        delegate_ && delegate_->HandleWheelEvent(wheel_event.event)) {
      ack_result = INPUT_EVENT_ACK_STATE_CONSUMED;
    }
    view_->WheelEventAck(wheel_event.event, ack_result);
  }
}

void RenderWidgetHostImpl::OnGestureEventAck(
    const GestureEventWithLatencyInfo& event,
    InputEventAckSource ack_source,
    InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(event.event, &event.latency, ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result, event.event);

  if (touch_emulator_)
    touch_emulator_->OnGestureEventAck(event.event);

  if (view_)
    view_->GestureEventAck(event.event, ack_result);
}

void RenderWidgetHostImpl::OnTouchEventAck(
    const TouchEventWithLatencyInfo& event,
    InputEventAckSource ack_source,
    InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(event.event, &event.latency, ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result, event.event);

  if (touch_emulator_ &&
      touch_emulator_->HandleTouchEventAck(event.event, ack_result)) {
    return;
  }

  if (view_)
    view_->ProcessAckedTouchEvent(event, ack_result);
}

void RenderWidgetHostImpl::OnUnexpectedEventAck(UnexpectedEventAckType type) {
  if (type == BAD_ACK_MESSAGE) {
    bad_message::ReceivedBadMessage(process_, bad_message::RWH_BAD_ACK_MESSAGE);
  } else if (type == UNEXPECTED_EVENT_TYPE) {
    suppress_events_until_keydown_ = false;
  }
}

bool RenderWidgetHostImpl::ShouldDropInputEvents() const {
  return ignore_input_events_ || process_->IgnoreInputEvents() || !delegate_;
}

void RenderWidgetHostImpl::SetBackgroundOpaque(bool opaque) {
  Send(new ViewMsg_SetBackgroundOpaque(GetRoutingID(), opaque));
}

bool RenderWidgetHostImpl::GotResponseToLockMouseRequest(bool allowed) {
  if (!allowed) {
    RejectMouseLockOrUnlockIfNecessary();
    return false;
  }

  if (!pending_mouse_lock_request_) {
    // This is possible, e.g., the plugin sends us an unlock request before
    // the user allows to lock to mouse.
    return false;
  }

  pending_mouse_lock_request_ = false;
  if (!view_ || !view_->HasFocus()|| !view_->LockMouse()) {
    Send(new ViewMsg_LockMouse_ACK(routing_id_, false));
    return false;
  }

  Send(new ViewMsg_LockMouse_ACK(routing_id_, true));
  return true;
}

void RenderWidgetHostImpl::GotResponseToKeyboardLockRequest(bool allowed) {
  DCHECK(keyboard_lock_requested_);
  keyboard_lock_allowed_ = allowed;

  if (keyboard_lock_allowed_)
    LockKeyboard();
  else
    UnlockKeyboard();
}

void RenderWidgetHostImpl::DelayedAutoResized() {
  gfx::Size new_size = new_auto_size_;
  // Clear the new_auto_size_ since the empty value is used as a flag to
  // indicate that no callback is in progress (i.e. without this line
  // DelayedAutoResized will not get called again).
  new_auto_size_.SetSize(0, 0);
  if (!auto_resize_enabled_)
    return;

  if (view_) {
    viz::ScopedSurfaceIdAllocator scoped_allocator =
        view_->ResizeDueToAutoResize(new_size, last_auto_resize_request_number_,
                                     last_auto_resize_surface_id_.value());

    if (delegate_) {
      delegate_->ResizeDueToAutoResize(this, new_size,
                                       last_auto_resize_request_number_,
                                       last_auto_resize_surface_id_.value());
    }
  }
}

void RenderWidgetHostImpl::DetachDelegate() {
  delegate_ = nullptr;
  latency_tracker_.reset_delegate();
}

void RenderWidgetHostImpl::DidAllocateLocalSurfaceIdForAutoResize(
    uint64_t sequence_number) {
  last_auto_resize_response_number_ = sequence_number;
  WasResized();
}

void RenderWidgetHostImpl::DidReceiveRendererFrame() {
  view_->DidReceiveRendererFrame();
}

void RenderWidgetHostImpl::WindowSnapshotReachedScreen(int snapshot_id) {
  DCHECK(base::MessageLoopForUI::IsCurrent());

  if (!pending_surface_browser_snapshots_.empty()) {
    GetView()->CopyFromSurface(
        gfx::Rect(), gfx::Size(),
        base::BindOnce(&RenderWidgetHostImpl::OnSnapshotFromSurfaceReceived,
                       weak_factory_.GetWeakPtr(), snapshot_id, 0));
  }

  if (!pending_browser_snapshots_.empty()) {
#if defined(OS_ANDROID)
    // On Android, call sites should pass in the bounds with correct offset
    // to capture the intended content area.
    gfx::Rect snapshot_bounds(GetView()->GetViewBounds());
    snapshot_bounds.Offset(0, GetView()->GetNativeView()->content_offset());
#else
    gfx::Rect snapshot_bounds(GetView()->GetViewBounds().size());
#endif

    gfx::Image image;
    if (ui::GrabViewSnapshot(GetView()->GetNativeView(), snapshot_bounds,
                             &image)) {
      OnSnapshotReceived(snapshot_id, image);
      return;
    }

    ui::GrabViewSnapshotAsync(
        GetView()->GetNativeView(), snapshot_bounds,
        base::Bind(&RenderWidgetHostImpl::OnSnapshotReceived,
                   weak_factory_.GetWeakPtr(), snapshot_id));
  }
}

void RenderWidgetHostImpl::OnSnapshotFromSurfaceReceived(
    int snapshot_id,
    int retry_count,
    const SkBitmap& bitmap) {
  static constexpr int kMaxRetries = 5;
  if (bitmap.drawsNothing() && retry_count < kMaxRetries) {
    GetView()->CopyFromSurface(
        gfx::Rect(), gfx::Size(),
        base::BindOnce(&RenderWidgetHostImpl::OnSnapshotFromSurfaceReceived,
                       weak_factory_.GetWeakPtr(), snapshot_id,
                       retry_count + 1));
    return;
  }
  // If all retries have failed, we return an empty image.
  gfx::Image image;
  if (!bitmap.drawsNothing())
    image = gfx::Image::CreateFrom1xBitmap(bitmap);
  // Any pending snapshots with a lower ID than the one received are considered
  // to be implicitly complete, and returned the same snapshot data.
  PendingSnapshotMap::iterator it = pending_surface_browser_snapshots_.begin();
  while (it != pending_surface_browser_snapshots_.end()) {
    if (it->first <= snapshot_id) {
      it->second.Run(image);
      pending_surface_browser_snapshots_.erase(it++);
    } else {
      ++it;
    }
  }
}

void RenderWidgetHostImpl::OnSnapshotReceived(int snapshot_id,
                                              gfx::Image image) {
  // Any pending snapshots with a lower ID than the one received are considered
  // to be implicitly complete, and returned the same snapshot data.
  PendingSnapshotMap::iterator it = pending_browser_snapshots_.begin();
  while (it != pending_browser_snapshots_.end()) {
    if (it->first <= snapshot_id) {
      it->second.Run(image);
      pending_browser_snapshots_.erase(it++);
    } else {
      ++it;
    }
  }
#if defined(OS_MACOSX)
  if (pending_browser_snapshots_.empty())
    GetWakeLock()->CancelWakeLock();
#endif
}

// static
void RenderWidgetHostImpl::OnGpuSwapBuffersCompleted(
    const std::vector<ui::LatencyInfo>& latency_info) {
  for (size_t i = 0; i < latency_info.size(); i++) {
    std::set<RenderWidgetHostImpl*> rwhi_set;
    for (const auto& lc : latency_info[i].latency_components()) {
      if (lc.first.first == ui::INPUT_EVENT_LATENCY_BEGIN_RWH_COMPONENT ||
          lc.first.first == ui::BROWSER_SNAPSHOT_FRAME_NUMBER_COMPONENT ||
          lc.first.first == ui::TAB_SHOW_COMPONENT) {
        // Matches with GetLatencyComponentId
        int routing_id = lc.first.second & 0xffffffff;
        int process_id = (lc.first.second >> 32) & 0xffffffff;
        RenderWidgetHost* rwh =
            RenderWidgetHost::FromID(process_id, routing_id);
        if (!rwh) {
          continue;
        }
        RenderWidgetHostImpl* rwhi = RenderWidgetHostImpl::From(rwh);
        if (rwhi_set.insert(rwhi).second)
          rwhi->OnGpuSwapBuffersCompletedInternal(latency_info[i]);
      }
    }
  }
}

BrowserAccessibilityManager*
    RenderWidgetHostImpl::GetRootBrowserAccessibilityManager() {
  return delegate_ ? delegate_->GetRootBrowserAccessibilityManager() : nullptr;
}

BrowserAccessibilityManager*
    RenderWidgetHostImpl::GetOrCreateRootBrowserAccessibilityManager() {
  return delegate_ ? delegate_->GetOrCreateRootBrowserAccessibilityManager()
                   : nullptr;
}

void RenderWidgetHostImpl::GrantFileAccessFromDropData(DropData* drop_data) {
  DCHECK_EQ(GetRoutingID(), drop_data->view_id);
  RenderProcessHost* process = GetProcess();
  PrepareDropDataForChildProcess(
      drop_data, ChildProcessSecurityPolicyImpl::GetInstance(),
      process->GetID(), process->GetStoragePartition()->GetFileSystemContext());
}

void RenderWidgetHostImpl::RequestCompositionUpdates(bool immediate_request,
                                                     bool monitor_updates) {
  if (!immediate_request && monitor_updates == monitoring_composition_info_)
    return;
  monitoring_composition_info_ = monitor_updates;
  GetWidgetInputHandler()->RequestCompositionUpdates(immediate_request,
                                                     monitor_updates);
}

void RenderWidgetHostImpl::RequestCompositorFrameSink(
    viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
    viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client,
    mojom::RenderFrameMetadataObserverClientRequest
        render_frame_metadata_observer_client_request,
    mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer) {
  render_frame_metadata_provider_.Bind(
      std::move(render_frame_metadata_observer_client_request),
      std::move(render_frame_metadata_observer));
  if (enable_viz_) {
      // Connects the viz process end of CompositorFrameSink message pipes. The
      // renderer compositor may request a new CompositorFrameSink on context
      // loss, which will destroy the existing CompositorFrameSink.
      auto callback = base::BindOnce(
          [](viz::HostFrameSinkManager* manager,
             viz::mojom::CompositorFrameSinkRequest request,
             viz::mojom::CompositorFrameSinkClientPtr client,
             const viz::FrameSinkId& frame_sink_id) {
            manager->CreateCompositorFrameSink(
                frame_sink_id, std::move(request), std::move(client));
          },
          base::Unretained(GetHostFrameSinkManager()),
          std::move(compositor_frame_sink_request),
          std::move(compositor_frame_sink_client));

      if (view_)
        std::move(callback).Run(view_->GetFrameSinkId());
      else
        create_frame_sink_callback_ = std::move(callback);

      return;
  }

  if (compositor_frame_sink_binding_.is_bound())
    compositor_frame_sink_binding_.Close();
  compositor_frame_sink_binding_.Bind(
      std::move(compositor_frame_sink_request),
      BrowserMainLoop::GetInstance()->GetResizeTaskRunner());
  if (view_)
    view_->DidCreateNewRendererCompositorFrameSink(
        compositor_frame_sink_client.get());
  renderer_compositor_frame_sink_ = std::move(compositor_frame_sink_client);
}

bool RenderWidgetHostImpl::HasGestureStopped() {
  return !input_router_->HasPendingEvents();
}

void RenderWidgetHostImpl::SetNeedsBeginFrame(bool needs_begin_frames) {
  if (needs_begin_frames_ == needs_begin_frames)
    return;

  needs_begin_frames_ = needs_begin_frames || browser_fling_needs_begin_frame_;
  if (view_)
    view_->SetNeedsBeginFrames(needs_begin_frames_);
}

void RenderWidgetHostImpl::SetWantsAnimateOnlyBeginFrames() {
  if (view_)
    view_->SetWantsAnimateOnlyBeginFrames();
}

void RenderWidgetHostImpl::SubmitCompositorFrame(
    const viz::LocalSurfaceId& local_surface_id,
    viz::CompositorFrame frame,
    viz::mojom::HitTestRegionListPtr hit_test_region_list,
    uint64_t submit_time) {
  TRACE_EVENT_FLOW_END0(TRACE_DISABLED_BY_DEFAULT("cc.debug.ipc"),
                        "SubmitCompositorFrame", local_surface_id.hash());

  // Ensure there are no CopyOutputRequests stowed-away in the CompositorFrame.
  // For security/privacy reasons, renderers are not allowed to make copy
  // requests because they could use this to gain access to content from another
  // domain (e.g., in a child frame).
  if (frame.HasCopyOutputRequests()) {
    bad_message::ReceivedBadMessage(GetProcess(),
                                    bad_message::RWH_COPY_REQUEST_ATTEMPT);
    return;
  }

  bool tracing_enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(TRACE_DISABLED_BY_DEFAULT("cc.debug.ipc"),
                                     &tracing_enabled);
  if (tracing_enabled) {
    TimeDelta elapsed = clock_->NowTicks().since_origin() -
                        TimeDelta::FromMicroseconds(submit_time);
    TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("cc.debug.ipc"),
                         "SubmitCompositorFrame::TimeElapsed",
                         TRACE_EVENT_SCOPE_THREAD,
                         "elapsed time:", elapsed.InMicroseconds());
  }
  auto new_surface_properties =
      RenderWidgetSurfaceProperties::FromCompositorFrame(frame);

  if (local_surface_id == last_local_surface_id_ &&
      SurfacePropertiesMismatch(new_surface_properties,
                                last_surface_properties_)) {
    std::string error = base::StringPrintf(
        "[OOPIF? %d] %s\n", view_ && view_->IsRenderWidgetHostViewChildFrame(),
        new_surface_properties.ToDiffString(last_surface_properties_).c_str());
    LOG(ERROR) << "Surface invariants violation: " << error;

    static int invariants_violation_count = 0;
    ++invariants_violation_count;
    UMA_HISTOGRAM_COUNTS_1000("Compositing.SurfaceInvariantsViolations",
                              invariants_violation_count);

    if (features::IsSurfaceInvariantsViolationLoggingEnabled()) {
      static auto* crash_key = base::debug::AllocateCrashKeyString(
          "surface-invariants-violation", base::debug::CrashKeySize::Size256);
      base::debug::ScopedCrashKeyString key_value(crash_key, error);
      base::debug::DumpWithoutCrashing();
    }

    if (view_) {
      frame.metadata.begin_frame_ack.has_damage = false;
      view_->OnDidNotProduceFrame(frame.metadata.begin_frame_ack);
    }
    std::vector<viz::ReturnedResource> resources =
        viz::TransferableResource::ReturnResources(frame.resource_list);
    renderer_compositor_frame_sink_->DidReceiveCompositorFrameAck(resources);

    return;
  }

  last_local_surface_id_ = local_surface_id;
  last_surface_properties_ = new_surface_properties;

  last_received_content_source_id_ = frame.metadata.content_source_id;

  // |has_damage| is not transmitted.
  frame.metadata.begin_frame_ack.has_damage = true;

  last_frame_metadata_ = frame.metadata.Clone();

  bool is_mobile_optimized = IsMobileOptimizedFrame(frame.metadata);
  input_router_->NotifySiteIsMobileOptimized(is_mobile_optimized);
  if (touch_emulator_)
    touch_emulator_->SetDoubleTapSupportForPageEnabled(!is_mobile_optimized);

  if (enable_surface_synchronization_) {
    if (view_) {
      // If Surface Synchronization is on, then |new_content_rendering_timeout_|
      // is stopped in DidReceiveFirstFrameAfterNavigation.
      view_->SubmitCompositorFrame(local_surface_id, std::move(frame),
                                   std::move(hit_test_region_list));
      view_->DidReceiveRendererFrame();
    } else {
      std::vector<viz::ReturnedResource> resources =
          viz::TransferableResource::ReturnResources(frame.resource_list);
      renderer_compositor_frame_sink_->DidReceiveCompositorFrameAck(resources);
    }
  } else {
    // Ignore this frame if its content has already been unloaded. Source ID
    // is always zero for an OOPIF because we are only concerned with displaying
    // stale graphics on top-level frames. We accept frames that have a source
    // ID greater than |current_content_source_id_| because in some cases the
    // first compositor frame can arrive before the navigation commit message
    // that updates that value.
    if (view_ &&
        frame.metadata.content_source_id >= current_content_source_id_) {
      view_->SubmitCompositorFrame(local_surface_id, std::move(frame),
                                   std::move(hit_test_region_list));
      view_->DidReceiveRendererFrame();
    } else {
      if (view_) {
        frame.metadata.begin_frame_ack.has_damage = false;
        view_->OnDidNotProduceFrame(frame.metadata.begin_frame_ack);
      }
      std::vector<viz::ReturnedResource> resources =
          viz::TransferableResource::ReturnResources(frame.resource_list);
      renderer_compositor_frame_sink_->DidReceiveCompositorFrameAck(resources);
    }

    // After navigation, if a frame belonging to the new page is received, stop
    // the timer that triggers clearing the graphics of the last page.
    if (last_received_content_source_id_ >= current_content_source_id_) {
      did_receive_first_frame_after_navigation_ = true;
      if (new_content_rendering_timeout_ &&
          new_content_rendering_timeout_->IsRunning()) {
        new_content_rendering_timeout_->Stop();
      }
    }
  }

  if (delegate_)
    delegate_->DidReceiveCompositorFrame();
}

void RenderWidgetHostImpl::DidProcessFrame(uint32_t frame_token) {
  frame_token_message_queue_->DidProcessFrame(frame_token);
}

#if defined(OS_MACOSX)
device::mojom::WakeLock* RenderWidgetHostImpl::GetWakeLock() {
  // Here is a lazy binding, and will not reconnect after connection error.
  if (!wake_lock_) {
    device::mojom::WakeLockRequest request = mojo::MakeRequest(&wake_lock_);
    // In some testing contexts, the service manager connection isn't
    // initialized.
    if (ServiceManagerConnection::GetForProcess()) {
      service_manager::Connector* connector =
          ServiceManagerConnection::GetForProcess()->GetConnector();
      DCHECK(connector);
      device::mojom::WakeLockProviderPtr wake_lock_provider;
      connector->BindInterface(device::mojom::kServiceName,
                               mojo::MakeRequest(&wake_lock_provider));
      wake_lock_provider->GetWakeLockWithoutContext(
          device::mojom::WakeLockType::kPreventDisplaySleep,
          device::mojom::WakeLockReason::kOther, "GetSnapshot",
          std::move(request));
    }
  }
  return wake_lock_.get();
}
#endif

void RenderWidgetHostImpl::SetupInputRouter() {
  in_flight_event_count_ = 0;
  StopHangMonitorTimeout();
  associated_widget_input_handler_ = nullptr;
  widget_input_handler_ = nullptr;

  input_router_.reset(
      new InputRouterImpl(this, this, GetInputRouterConfigForPlatform()));

  // input_router_ recreated, need to update the force_enable_zoom_ state.
  input_router_->SetForceEnableZoom(force_enable_zoom_);

  if (IsUseZoomForDSFEnabled()) {
    input_router_->SetDeviceScaleFactor(GetScaleFactorForView(view_.get()));
  }
}

void RenderWidgetHostImpl::SetForceEnableZoom(bool enabled) {
  force_enable_zoom_ = enabled;
  input_router_->SetForceEnableZoom(enabled);
}

void RenderWidgetHostImpl::SetWidgetInputHandler(
    mojom::WidgetInputHandlerAssociatedPtr widget_input_handler,
    mojom::WidgetInputHandlerHostRequest host_request) {
  associated_widget_input_handler_ = std::move(widget_input_handler);
  input_router_->BindHost(std::move(host_request), true);
}

void RenderWidgetHostImpl::SetInputTargetClient(
    viz::mojom::InputTargetClientPtr input_target_client) {
  input_target_client_ = std::move(input_target_client);
}

void RenderWidgetHostImpl::SetWidget(mojom::WidgetPtr widget) {
  if (widget) {
    // If we have a bound handler ensure that we destroy the old input router.
    if (widget_input_handler_.get())
      SetupInputRouter();

    mojom::WidgetInputHandlerHostPtr host;
    mojom::WidgetInputHandlerHostRequest host_request =
        mojo::MakeRequest(&host);
    widget->SetupWidgetInputHandler(mojo::MakeRequest(&widget_input_handler_),
                                    std::move(host));
    input_router_->BindHost(std::move(host_request), false);
  }
}

void RenderWidgetHostImpl::ProgressFling(TimeTicks current_time) {
  browser_fling_needs_begin_frame_ = false;
  if (input_router_)
    input_router_->ProgressFling(current_time);
}

void RenderWidgetHostImpl::DidReceiveFirstFrameAfterNavigation() {
  DCHECK(enable_surface_synchronization_);
  did_receive_first_frame_after_navigation_ = true;
  if (!new_content_rendering_timeout_ ||
      !new_content_rendering_timeout_->IsRunning()) {
    return;
  }
  new_content_rendering_timeout_->Stop();
}

void RenderWidgetHostImpl::ForceFirstFrameAfterNavigationTimeout() {
  if (did_receive_first_frame_after_navigation_ ||
      !new_content_rendering_timeout_) {
    return;
  }
  new_content_rendering_timeout_->Stop();
  ClearDisplayedGraphics();
}

void RenderWidgetHostImpl::StopFling() {
  if (input_router_)
    input_router_->StopFling();
}

bool RenderWidgetHostImpl::FlingCancellationIsDeferred() const {
  if (input_router_)
    return input_router_->FlingCancellationIsDeferred();

  return false;
}

void RenderWidgetHostImpl::SetScreenOrientationForTesting(
    uint16_t angle,
    ScreenOrientationValues type) {
  screen_orientation_angle_for_testing_ = angle;
  screen_orientation_type_for_testing_ = type;
  WasResized();
}

// TODO(ericrk): On Android, with surface synchronization enabled,  we need to
// request a new surface ID when things like top/bottom control height or
// selection handles change. This will be enabled by child surface id
// generation. For now ignore these mismatches.  Remove this function when this
// issue is resolved: https://crbug.com/789259 and https://crbug.com/801350
bool RenderWidgetHostImpl::SurfacePropertiesMismatch(
    const RenderWidgetSurfaceProperties& first,
    const RenderWidgetSurfaceProperties& second) const {
#ifdef OS_ANDROID
  if (enable_surface_synchronization_) {
    // To make this comparison resistant to changes in
    // RenderWidgetSurfaceProperties, create new properties which are forced to
    // match only for those categories we want to ignore.
    RenderWidgetSurfaceProperties second_reduced = second;
    second_reduced.top_controls_height = first.top_controls_height;
    second_reduced.top_controls_shown_ratio = first.top_controls_shown_ratio;
    second_reduced.bottom_controls_height = first.bottom_controls_height;
    second_reduced.bottom_controls_shown_ratio =
        first.bottom_controls_shown_ratio;
    second_reduced.selection = first.selection;

    return first != second_reduced;
  }
#endif

  // For non-Android or when surface synchronization is not enabled, just use a
  // basic comparison.
  return first != second;
}

bool RenderWidgetHostImpl::LockKeyboard() {
  if (!keyboard_lock_allowed_ || !is_focused_ || !view_)
    return false;

  // KeyboardLock can be activated and deactivated several times per request,
  // for example when a fullscreen tab loses and gains focus multiple times,
  // so we need to retain a copy of the keys requested.
  base::Optional<base::flat_set<int>> copy_of_keys = keyboard_keys_to_lock_;
  return view_->LockKeyboard(std::move(copy_of_keys));
}

void RenderWidgetHostImpl::UnlockKeyboard() {
  if (IsKeyboardLocked())
    view_->UnlockKeyboard();
}

}  // namespace content

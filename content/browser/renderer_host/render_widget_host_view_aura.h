// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RENDERER_HOST_RENDER_WIDGET_HOST_VIEW_AURA_H_
#define CONTENT_BROWSER_RENDERER_HOST_RENDER_WIDGET_HOST_VIEW_AURA_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "base/callback.h"
#include "base/compiler_specific.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "build/build_config.h"
#include "cc/layers/deadline_policy.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "components/viz/common/frame_sinks/begin_frame_source.h"
#include "content/browser/accessibility/browser_accessibility_manager.h"
#include "content/browser/compositor/image_transport_factory.h"
#include "content/browser/compositor/owned_mailbox.h"
#include "content/browser/renderer_host/render_widget_host_view_base.h"
#include "content/browser/renderer_host/render_widget_host_view_event_handler.h"
#include "content/browser/renderer_host/text_input_manager.h"
#include "content/common/content_export.h"
#include "content/common/cursors/webcursor.h"
#include "content/public/common/context_menu_params.h"
#include "third_party/skia/include/core/SkRegion.h"
#include "ui/aura/client/cursor_client_observer.h"
#include "ui/aura/client/focus_change_observer.h"
#include "ui/aura/client/window_types.h"
#include "ui/aura/window_delegate.h"
#include "ui/aura/window_tree_host_observer.h"
#include "ui/base/ime/text_input_client.h"
#include "ui/display/display_observer.h"
#include "ui/gfx/geometry/insets.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/selection_bound.h"
#include "ui/wm/public/activation_delegate.h"

namespace wm {
class ScopedTooltipDisabler;
}

namespace gfx {
class Display;
class Point;
class Rect;
}

namespace ui {
class InputMethod;
class LocatedEvent;
#if defined(OS_WIN)
class OnScreenKeyboardObserver;
#endif
}

namespace content {
#if defined(OS_WIN)
class LegacyRenderWidgetHostHWND;
class DirectManipulationBrowserTest;
#endif

class CursorManager;
class DelegatedFrameHost;
class DelegatedFrameHostClient;
class RenderFrameHostImpl;
class RenderWidgetHostView;
class TouchSelectionControllerClientAura;

// RenderWidgetHostView class hierarchy described in render_widget_host_view.h.
class CONTENT_EXPORT RenderWidgetHostViewAura
    : public RenderWidgetHostViewBase,
      public RenderWidgetHostViewEventHandler::Delegate,
      public TextInputManager::Observer,
      public ui::TextInputClient,
      public display::DisplayObserver,
      public aura::WindowTreeHostObserver,
      public aura::WindowDelegate,
      public wm::ActivationDelegate,
      public aura::client::FocusChangeObserver,
      public aura::client::CursorClientObserver {
 public:
  // When |is_guest_view_hack| is true, this view isn't really the view for
  // the |widget|, a RenderWidgetHostViewGuest is.
  //
  // TODO(lazyboy): Remove |is_guest_view_hack| once BrowserPlugin has migrated
  // to use RWHVChildFrame (http://crbug.com/330264).
  // |is_mus_browser_plugin_guest| can be removed at the same time.
  RenderWidgetHostViewAura(RenderWidgetHost* host,
                           bool is_guest_view_hack,
                           bool is_mus_browser_plugin_guest);

  // RenderWidgetHostView implementation.
  void InitAsChild(gfx::NativeView parent_view) override;
  void SetSize(const gfx::Size& size) override;
  void SetBounds(const gfx::Rect& rect) override;
  gfx::NativeView GetNativeView() const override;
  gfx::NativeViewAccessible GetNativeViewAccessible() override;
  ui::TextInputClient* GetTextInputClient() override;
  bool HasFocus() const override;
  void Show() override;
  void Hide() override;
  bool IsShowing() override;
  void WasUnOccluded() override;
  void WasOccluded() override;
  gfx::Rect GetViewBounds() const override;
  void SetBackgroundColor(SkColor color) override;
  SkColor background_color() const override;
  bool IsMouseLocked() override;
  gfx::Size GetVisibleViewportSize() const override;
  void SetInsets(const gfx::Insets& insets) override;
  void FocusedNodeTouched(bool editable) override;
  void SetNeedsBeginFrames(bool needs_begin_frames) override;
  void SetWantsAnimateOnlyBeginFrames() override;
  TouchSelectionControllerClientManager*
  GetTouchSelectionControllerClientManager() override;

  // Overridden from RenderWidgetHostViewBase:
  void InitAsPopup(RenderWidgetHostView* parent_host_view,
                   const gfx::Rect& pos) override;
  void InitAsFullscreen(RenderWidgetHostView* reference_host_view) override;
  void Focus() override;
  void UpdateCursor(const WebCursor& cursor) override;
  void DisplayCursor(const WebCursor& cursor) override;
  CursorManager* GetCursorManager() override;
  void SetIsLoading(bool is_loading) override;
  void RenderProcessGone(base::TerminationStatus status,
                         int error_code) override;
  void Destroy() override;
  void SetTooltipText(const base::string16& tooltip_text) override;
  void DisplayTooltipText(const base::string16& tooltip_text) override;
  gfx::Size GetRequestedRendererSize() const override;
  uint32_t GetCaptureSequenceNumber() const override;
  bool IsSurfaceAvailableForCopy() const override;
  void CopyFromSurface(
      const gfx::Rect& src_rect,
      const gfx::Size& output_size,
      base::OnceCallback<void(const SkBitmap&)> callback) override;
  void EnsureSurfaceSynchronizedForLayoutTest() override;
  gfx::Vector2d GetOffsetFromRootSurface() override;
  gfx::Rect GetBoundsInRootWindow() override;
  void WheelEventAck(const blink::WebMouseWheelEvent& event,
                     InputEventAckState ack_result) override;
  void GestureEventAck(const blink::WebGestureEvent& event,
                       InputEventAckState ack_result) override;
  void DidOverscroll(const ui::DidOverscrollParams& params) override;
  void ProcessAckedTouchEvent(const TouchEventWithLatencyInfo& touch,
                              InputEventAckState ack_result) override;
  std::unique_ptr<SyntheticGestureTarget> CreateSyntheticGestureTarget()
      override;
  InputEventAckState FilterInputEvent(
      const blink::WebInputEvent& input_event) override;
  InputEventAckState FilterChildGestureEvent(
      const blink::WebGestureEvent& gesture_event) override;
  BrowserAccessibilityManager* CreateBrowserAccessibilityManager(
      BrowserAccessibilityDelegate* delegate, bool for_root_frame) override;
  gfx::AcceleratedWidget AccessibilityGetAcceleratedWidget() override;
  gfx::NativeViewAccessible AccessibilityGetNativeViewAccessible() override;
  void SetMainFrameAXTreeID(ui::AXTreeIDRegistry::AXTreeID id) override;
  bool LockMouse() override;
  void UnlockMouse() override;
  bool LockKeyboard(base::Optional<base::flat_set<int>> keys) override;
  void UnlockKeyboard() override;
  bool IsKeyboardLocked() override;
  void DidCreateNewRendererCompositorFrameSink(
      viz::mojom::CompositorFrameSinkClient* renderer_compositor_frame_sink)
      override;
  void SubmitCompositorFrame(
      const viz::LocalSurfaceId& local_surface_id,
      viz::CompositorFrame frame,
      viz::mojom::HitTestRegionListPtr hit_test_region_list) override;
  void OnDidNotProduceFrame(const viz::BeginFrameAck& ack) override;
  void ClearCompositorFrame() override;
  void DidStopFlinging() override;
  void OnDidNavigateMainFrameToNewPage() override;
  viz::FrameSinkId GetFrameSinkId() override;
  viz::LocalSurfaceId GetLocalSurfaceId() const override;
  bool TransformPointToLocalCoordSpace(const gfx::PointF& point,
                                       const viz::SurfaceId& original_surface,
                                       gfx::PointF* transformed_point) override;
  bool TransformPointToCoordSpaceForView(
      const gfx::PointF& point,
      RenderWidgetHostViewBase* target_view,
      gfx::PointF* transformed_point) override;
  viz::FrameSinkId GetRootFrameSinkId() override;
  viz::SurfaceId GetCurrentSurfaceId() const override;

  void FocusedNodeChanged(bool is_editable_node,
                          const gfx::Rect& node_bounds_in_screen) override;
  void ScheduleEmbed(ui::mojom::WindowTreeClientPtr client,
                     base::OnceCallback<void(const base::UnguessableToken&)>
                         callback) override;
  void OnSynchronizedDisplayPropertiesChanged() override;
  viz::ScopedSurfaceIdAllocator ResizeDueToAutoResize(
      const gfx::Size& new_size,
      uint64_t sequence_number,
      const viz::LocalSurfaceId& local_surface_id) override;

  bool IsLocalSurfaceIdAllocationSuppressed() const override;

  void DidNavigate() override;
  void TakeFallbackContentFrom(RenderWidgetHostView* view) override;

  // Overridden from ui::TextInputClient:
  void SetCompositionText(const ui::CompositionText& composition) override;
  void ConfirmCompositionText() override;
  void ClearCompositionText() override;
  void InsertText(const base::string16& text) override;
  void InsertChar(const ui::KeyEvent& event) override;
  ui::TextInputType GetTextInputType() const override;
  ui::TextInputMode GetTextInputMode() const override;
  base::i18n::TextDirection GetTextDirection() const override;
  int GetTextInputFlags() const override;
  bool CanComposeInline() const override;
  gfx::Rect GetCaretBounds() const override;
  bool GetCompositionCharacterBounds(uint32_t index,
                                     gfx::Rect* rect) const override;
  bool HasCompositionText() const override;
  bool GetTextRange(gfx::Range* range) const override;
  bool GetCompositionTextRange(gfx::Range* range) const override;
  bool GetSelectionRange(gfx::Range* range) const override;
  bool SetSelectionRange(const gfx::Range& range) override;
  bool DeleteRange(const gfx::Range& range) override;
  bool GetTextFromRange(const gfx::Range& range,
                        base::string16* text) const override;
  void OnInputMethodChanged() override;
  bool ChangeTextDirectionAndLayoutAlignment(
      base::i18n::TextDirection direction) override;
  void ExtendSelectionAndDelete(size_t before, size_t after) override;
  void EnsureCaretNotInRect(const gfx::Rect& rect) override;
  bool IsTextEditCommandEnabled(ui::TextEditCommand command) const override;
  void SetTextEditCommandForNextKeyEvent(ui::TextEditCommand command) override;
  const std::string& GetClientSourceInfo() const override;

  // Overridden from display::DisplayObserver:
  void OnDisplayAdded(const display::Display& new_display) override;
  void OnDisplayRemoved(const display::Display& old_display) override;
  void OnDisplayMetricsChanged(const display::Display& display,
                               uint32_t metrics) override;

  // Overridden from aura::WindowDelegate:
  gfx::Size GetMinimumSize() const override;
  gfx::Size GetMaximumSize() const override;
  void OnBoundsChanged(const gfx::Rect& old_bounds,
                       const gfx::Rect& new_bounds) override;
  gfx::NativeCursor GetCursor(const gfx::Point& point) override;
  int GetNonClientComponent(const gfx::Point& point) const override;
  bool ShouldDescendIntoChildForEventHandling(
      aura::Window* child,
      const gfx::Point& location) override;
  bool CanFocus() override;
  void OnCaptureLost() override;
  void OnPaint(const ui::PaintContext& context) override;
  void OnDeviceScaleFactorChanged(float old_device_scale_factor,
                                  float new_device_scale_factor) override;
  void OnWindowDestroying(aura::Window* window) override;
  void OnWindowDestroyed(aura::Window* window) override;
  void OnWindowTargetVisibilityChanged(bool visible) override;
  bool HasHitTestMask() const override;
  void GetHitTestMask(gfx::Path* mask) const override;

  // Overridden from ui::EventHandler:
  void OnKeyEvent(ui::KeyEvent* event) override;
  void OnMouseEvent(ui::MouseEvent* event) override;
  void OnScrollEvent(ui::ScrollEvent* event) override;
  void OnTouchEvent(ui::TouchEvent* event) override;
  void OnGestureEvent(ui::GestureEvent* event) override;

  // Overridden from wm::ActivationDelegate:
  bool ShouldActivate() const override;

  // Overridden from aura::client::CursorClientObserver:
  void OnCursorVisibilityChanged(bool is_visible) override;

  // Overridden from aura::client::FocusChangeObserver:
  void OnWindowFocused(aura::Window* gained_focus,
                       aura::Window* lost_focus) override;

  // Overridden from aura::WindowTreeHostObserver:
  void OnHostMovedInPixels(aura::WindowTreeHost* host,
                           const gfx::Point& new_origin_in_pixels) override;

  // RenderFrameMetadataProvider::Observer
  void OnRenderFrameMetadataChanged() override;

#if defined(OS_WIN)
  // Gets the HWND of the host window.
  HWND GetHostWindowHWND() const;

  // Updates the cursor clip region. Used for mouse locking.
  void UpdateMouseLockRegion();

  // Notification that the LegacyRenderWidgetHostHWND was destroyed.
  void OnLegacyWindowDestroyed();
#endif

  // Method to indicate if this instance is shutting down or closing.
  // TODO(shrikant): Discuss around to see if it makes sense to add this method
  // as part of RenderWidgetHostView.
  bool IsClosing() const { return in_shutdown_; }

  // Sets whether the overscroll controller should be enabled for this page.
  void SetOverscrollControllerEnabled(bool enabled);

  // TODO(mcnee): Tests needing this are BrowserPlugin specific. Remove after
  // removing BrowserPlugin (crbug.com/533069).
  void SetOverscrollControllerForTesting(
      std::unique_ptr<OverscrollController> controller);

  void SnapToPhysicalPixelBoundary();

  // Used in tests to set a mock client for touch selection controller. It will
  // create a new touch selection controller for the new client.
  void SetSelectionControllerClientForTest(
      std::unique_ptr<TouchSelectionControllerClientAura> client);

  // RenderWidgetHostViewEventHandler::Delegate:
  gfx::Rect ConvertRectToScreen(const gfx::Rect& rect) const override;
  void ForwardKeyboardEventWithLatencyInfo(const NativeWebKeyboardEvent& event,
                                           const ui::LatencyInfo& latency,
                                           bool* update_event) override;
  RenderFrameHostImpl* GetFocusedFrame() const;
  bool NeedsMouseCapture() override;
  void SetTooltipsEnabled(bool enable) override;
  void ShowContextMenu(const ContextMenuParams& params) override;
  void Shutdown() override;

  RenderWidgetHostViewEventHandler* event_handler() {
    return event_handler_.get();
  }

  void ScrollFocusedEditableNodeIntoRect(const gfx::Rect& rect);

 protected:
  ~RenderWidgetHostViewAura() override;

  // Exposed for tests.
  aura::Window* window() { return window_; }

  DelegatedFrameHost* GetDelegatedFrameHost() const {
    return delegated_frame_host_.get();
  }

 private:
  friend class DelegatedFrameHostClientAura;
  friend class InputMethodAuraTestBase;
  friend class RenderWidgetHostViewAuraTest;
  friend class RenderWidgetHostViewAuraCopyRequestTest;
  friend class TestInputMethodObserver;
#if defined(OS_WIN)
  friend class DirectManipulationBrowserTest;
#endif
  FRIEND_TEST_ALL_PREFIXES(InputMethodResultAuraTest,
                           FinishImeCompositionSession);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           PopupRetainsCaptureAfterMouseRelease);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, SetCompositionText);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, FocusedNodeChanged);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, TouchEventState);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           TouchEventPositionsArentRounded);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, TouchEventSyncAsync);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, Resize);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, SwapNotifiesWindow);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, MirrorLayers);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           SkippedDelegatedFrames);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           ResizeAfterReceivingFrame);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           ChildGeneratedResizeRoutesLocalSurfaceId);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, MissingFramesDontLock);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, OutputSurfaceIdChange);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           DiscardDelegatedFrames);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           DiscardDelegatedFramesWithLocking);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest, SoftwareDPIChange);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           UpdateCursorIfOverSelf);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           VisibleViewportTest);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           OverscrollResetsOnBlur);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           FinishCompositionByMouse);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           ForwardsBeginFrameAcks);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           VirtualKeyboardFocusEnsureCaretInRect);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraTest,
                           HitTestRegionListSubmitted);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           DropFallbackWhenHidden);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           CompositorFrameSinkChange);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           SurfaceChanges);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           DeviceScaleFactorChanges);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           HideThenShow);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           DropFallbackIfResizedWhileHidden);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           DontDropFallbackIfNotResizedWhileHidden);
  FRIEND_TEST_ALL_PREFIXES(SitePerProcessHitTestBrowserTest, PopupMenuTest);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           NewContentRenderingTimeout);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           AllocateLocalSurfaceIdOnEviction);
  FRIEND_TEST_ALL_PREFIXES(WebContentsViewAuraTest,
                           WebContentsViewReparent);
  FRIEND_TEST_ALL_PREFIXES(RenderWidgetHostViewAuraSurfaceSynchronizationTest,
                           TakeFallbackContent);

  class WindowObserver;
  friend class WindowObserver;

  class WindowAncestorObserver;
  friend class WindowAncestorObserver;

  // Allocate a new FrameSinkId if this object is the platform view of a
  // RenderWidgetHostViewGuest. This FrameSinkId will not be actually used in
  // any useful way. It's only created because this object always expects to
  // have a FrameSinkId. FrameSinkIds generated by this method do not
  // collide with FrameSinkIds used by RenderWidgetHostImpls.
  static viz::FrameSinkId AllocateFrameSinkIdForGuestViewHack();

  void CreateAuraWindow(aura::client::WindowType type);

  void CreateDelegatedFrameHostClient();

  void UpdateCursorIfOverSelf();

  void WasResized(const cc::DeadlinePolicy& deadline_policy,
                  const base::Optional<viz::LocalSurfaceId>&
                      child_allocated_local_surface_id);

  // Tracks whether SnapToPhysicalPixelBoundary() has been called.
  bool has_snapped_to_boundary() { return has_snapped_to_boundary_; }
  void ResetHasSnappedToBoundary() { has_snapped_to_boundary_ = false; }

  // Set the bounds of the window and handle size changes.  Assumes the caller
  // has already adjusted the origin of |rect| to conform to whatever coordinate
  // space is required by the aura::Window.
  void InternalSetBounds(const gfx::Rect& rect);

  // Handles propagation of surface properties when they are changed.
  void SyncSurfaceProperties(const cc::DeadlinePolicy& deadline_policy);

#if defined(OS_WIN)
  // Creates and/or updates the legacy dummy window which corresponds to
  // the bounds of the webcontents. It is needed for accessibility and
  // for scrolling to work in legacy drivers for trackpoints/trackpads, etc.
  void UpdateLegacyWin();

  bool UsesNativeWindowFrame() const;
#endif

  ui::InputMethod* GetInputMethod() const;

  // Get the focused view that should be used for retrieving the text selection.
  RenderWidgetHostViewBase* GetFocusedViewForTextSelection();

  // Returns whether the widget needs an input grab to work properly.
  bool NeedsInputGrab();

  // Sends an IPC to the renderer process to communicate whether or not
  // the mouse cursor is visible anywhere on the screen.
  void NotifyRendererOfCursorVisibilityState(bool is_visible);

  // If |clip| is non-empty and and doesn't contain |rect| or |clip| is empty
  // SchedulePaint() is invoked for |rect|.
  void SchedulePaintIfNotInClip(const gfx::Rect& rect, const gfx::Rect& clip);

  // Called after |window_| is parented to a WindowEventDispatcher.
  void AddedToRootWindow();

  // Called prior to removing |window_| from a WindowEventDispatcher.
  void RemovingFromRootWindow();

  // TextInputManager::Observer implementation.
  void OnUpdateTextInputStateCalled(TextInputManager* text_input_manager,
                                    RenderWidgetHostViewBase* updated_view,
                                    bool did_update_state) override;
  void OnImeCancelComposition(TextInputManager* text_input_manager,
                              RenderWidgetHostViewBase* updated_view) override;
  void OnSelectionBoundsChanged(
      TextInputManager* text_input_manager,
      RenderWidgetHostViewBase* updated_view) override;
  void OnTextSelectionChanged(TextInputManager* text_input_mangager,
                              RenderWidgetHostViewBase* updated_view) override;

  void OnBeginFrame(base::TimeTicks frame_time);

  // Detaches |this| from the input method object.
  void DetachFromInputMethod();

  // Dismisses a Web Popup on a mouse or touch press outside the popup and its
  // parent.
  void ApplyEventFilterForPopupExit(ui::LocatedEvent* event);

  // Converts |rect| from screen coordinate to window coordinate.
  gfx::Rect ConvertRectFromScreen(const gfx::Rect& rect) const;

  // Called when the parent window bounds change.
  void HandleParentBoundsChanged();

  // Called when the parent window hierarchy for our window changes.
  void ParentHierarchyChanged();

  // Helper function to create a selection controller.
  void CreateSelectionController();

  // Used to set the |popup_child_host_view_| on the |popup_parent_host_view_|
  // and to notify the |event_handler_|.
  void SetPopupChild(RenderWidgetHostViewAura* popup_child_host_view);

  // Tells DelegatedFrameHost whether we need to receive BeginFrames.
  void UpdateNeedsBeginFramesInternal();

  // Applies background color without notifying the RenderWidget about
  // opaqueness changes. This allows us to, when navigating to a new page,
  // transfer this color to that page. This allows us to pass this background
  // color to new views on navigation.
  void UpdateBackgroundColorFromRenderer(SkColor color);

  // Called when the window title is changed.
  void WindowTitleChanged();

  const bool is_mus_browser_plugin_guest_;

  // NOTE: this is null if |is_mus_browser_plugin_guest_| is true.
  aura::Window* window_;

  std::unique_ptr<DelegatedFrameHostClient> delegated_frame_host_client_;
  // NOTE: this may be null.
  std::unique_ptr<DelegatedFrameHost> delegated_frame_host_;

  std::unique_ptr<WindowObserver> window_observer_;

  // Tracks the ancestors of the RWHVA window for window location changes.
  std::unique_ptr<WindowAncestorObserver> ancestor_window_observer_;

  // Are we in the process of closing?  Tracked so fullscreen views can avoid
  // sending a second shutdown request to the host when they lose the focus
  // after requesting shutdown for another reason (e.g. Escape key).
  bool in_shutdown_;

  // True if in the process of handling a window bounds changed notification.
  bool in_bounds_changed_;

  // Our parent host view, if this is a popup.  NULL otherwise.
  RenderWidgetHostViewAura* popup_parent_host_view_;

  // Our child popup host. NULL if we do not have a child popup.
  RenderWidgetHostViewAura* popup_child_host_view_;

  class EventFilterForPopupExit;
  friend class EventFilterForPopupExit;
  std::unique_ptr<ui::EventHandler> event_filter_for_popup_exit_;

  // True when content is being loaded. Used to show an hourglass cursor.
  bool is_loading_;

  // The cursor for the page. This is passed up from the renderer.
  WebCursor current_cursor_;

  // Indicates if there is onging composition text.
  bool has_composition_text_;

  // Current tooltip text.
  base::string16 tooltip_;

  // The background color of the web content.
  SkColor background_color_;

  // Whether a request for begin frames has been issued.
  bool needs_begin_frames_;

  // Whether or not a frame observer has been added.
  bool added_frame_observer_;

  // Used to track the last cursor visibility update that was sent to the
  // renderer via NotifyRendererOfCursorVisibilityState().
  enum CursorVisibilityState {
    UNKNOWN,
    VISIBLE,
    NOT_VISIBLE,
  };
  CursorVisibilityState cursor_visibility_state_in_renderer_;

#if defined(OS_WIN)
  // The LegacyRenderWidgetHostHWND class provides a dummy HWND which is used
  // for accessibility, as the container for windowless plugins like
  // Flash/Silverlight, etc and for legacy drivers for trackpoints/trackpads,
  // etc.
  // The LegacyRenderWidgetHostHWND instance is created during the first call
  // to RenderWidgetHostViewAura::InternalSetBounds. The instance is destroyed
  // when the LegacyRenderWidgetHostHWND hwnd is destroyed.
  content::LegacyRenderWidgetHostHWND* legacy_render_widget_host_HWND_;

  // Set to true if the legacy_render_widget_host_HWND_ instance was destroyed
  // by Windows. This could happen if the browser window was destroyed by
  // DestroyWindow for e.g. This flag helps ensure that we don't try to create
  // the LegacyRenderWidgetHostHWND instance again as that would be a futile
  // exercise.
  bool legacy_window_destroyed_;

  // Contains a copy of the last context menu request parameters. Only set when
  // we receive a request to show the context menu on a long press.
  std::unique_ptr<ContextMenuParams> last_context_menu_params_;

  // Set to true if we requested the on screen keyboard to be displayed.
  bool virtual_keyboard_requested_;

  std::unique_ptr<ui::OnScreenKeyboardObserver> keyboard_observer_;

  gfx::Point last_mouse_move_location_;
#endif

  bool has_snapped_to_boundary_;

  // The last selection bounds reported to the view.
  gfx::SelectionBound selection_start_;
  gfx::SelectionBound selection_end_;

  gfx::Insets insets_;

  std::unique_ptr<wm::ScopedTooltipDisabler> tooltip_disabler_;

  // True when this view acts as a platform view hack for a
  // RenderWidgetHostViewGuest.
  bool is_guest_view_hack_;

  float device_scale_factor_;

  viz::mojom::CompositorFrameSinkClient* renderer_compositor_frame_sink_ =
      nullptr;

  // While this is a ui::EventHandler for targetting, |event_handler_| actually
  // provides an implementation, and directs events to |host_|.
  std::unique_ptr<RenderWidgetHostViewEventHandler> event_handler_;

  // If this object is the main view of a RenderWidgetHostImpl, this value
  // equals to the FrameSinkId of that widget. If this object is the platform
  // view of a RenderWidgetHostViewGuest, a new FrameSinkId will be created but
  // it won't be used to actually put anything on screen.
  const viz::FrameSinkId frame_sink_id_;

  std::unique_ptr<CursorManager> cursor_manager_;
  int tab_show_sequence_ = 0;

  // Latest capture sequence number which is incremented when the caller
  // requests surfaces be synchronized via
  // EnsureSurfaceSynchronizedForLayoutTest().
  uint32_t latest_capture_sequence_number_ = 0u;

  base::WeakPtrFactory<RenderWidgetHostViewAura> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetHostViewAura);
};

}  // namespace content

#endif  // CONTENT_BROWSER_RENDERER_HOST_RENDER_WIDGET_HOST_VIEW_AURA_H_

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/magnifier/magnification_controller.h"

#include <memory>
#include <utility>
#include <vector>

#include "ash/accelerators/accelerator_controller.h"
#include "ash/accessibility/accessibility_delegate.h"
#include "ash/display/root_window_transformers.h"
#include "ash/host/ash_window_tree_host.h"
#include "ash/host/root_window_transformer.h"
#include "ash/magnifier/magnifier_scale_utils.h"
#include "ash/public/cpp/config.h"
#include "ash/root_window_controller.h"
#include "ash/shell.h"
#include "ash/shell_port.h"
#include "base/numerics/ranges.h"
#include "base/synchronization/waitable_event.h"
#include "ui/aura/client/cursor_client.h"
#include "ui/aura/window.h"
#include "ui/aura/window_tree_host.h"
#include "ui/base/ime/input_method.h"
#include "ui/base/ime/text_input_client.h"
#include "ui/compositor/dip_util.h"
#include "ui/compositor/layer.h"
#include "ui/compositor/scoped_layer_animation_settings.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/events/event.h"
#include "ui/events/gestures/gesture_provider_aura.h"
#include "ui/gfx/geometry/point3_f.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/wm/core/compound_event_filter.h"
#include "ui/wm/core/coordinate_conversion.h"

namespace ash {

namespace {

constexpr float kMaxMagnifiedScale = 20.0f;
constexpr float kMinMagnifiedScaleThreshold = 1.1f;
constexpr float kNonMagnifiedScale = 1.0f;

constexpr float kInitialMagnifiedScale = 2.0f;
constexpr float kScrollScaleChangeFactor = 0.00125f;

constexpr float kZoomGestureLockThreshold = 0.2f;
constexpr float kScrollGestureLockThreshold = 2500.0f;

// Default animation parameters for redrawing the magnification window.
constexpr gfx::Tween::Type kDefaultAnimationTweenType = gfx::Tween::EASE_OUT;
constexpr int kDefaultAnimationDurationInMs = 100;

// Use linear transformation to make the magnifier window move smoothly
// to center the focus when user types in a text input field.
constexpr gfx::Tween::Type kCenterCaretAnimationTweenType = gfx::Tween::LINEAR;

// The delay of the timer for moving magnifier window for centering the text
// input focus.
constexpr int kMoveMagnifierDelayInMs = 10;

// Threadshold of panning. If the cursor moves to within pixels (in DIP) of
// |kCursorPanningMargin| from the edge, the view-port moves.
constexpr int kCursorPanningMargin = 100;

// Threadshold of panning. If the caret moves to within pixels (in DIP) of
// |kCaretPanningMargin| from the edge, the view-port moves.
constexpr int kCaretPanningMargin = 50;

void MoveCursorTo(aura::WindowTreeHost* host, const gfx::Point& root_location) {
  auto host_location_3f = gfx::Point3F(gfx::PointF(root_location));
  host->GetRootTransform().TransformPoint(&host_location_3f);
  host->MoveCursorToLocationInPixels(
      gfx::ToCeiledPoint(host_location_3f.AsPointF()));
}

ui::InputMethod* GetInputMethod(aura::Window* root_window) {
  if (root_window->GetHost())
    return root_window->GetHost()->GetInputMethod();
  return nullptr;
}

}  // namespace

class MagnificationController::GestureProviderClient
    : public ui::GestureProviderAuraClient {
 public:
  GestureProviderClient() = default;
  ~GestureProviderClient() override = default;

  // ui::GestureProviderAuraClient overrides:
  void OnGestureEvent(GestureConsumer* consumer,
                      ui::GestureEvent* event) override {
    // Do nothing. OnGestureEvent is for timer based gesture events, e.g. tap.
    // MagnificationController is interested only in pinch and scroll
    // gestures.
    DCHECK_NE(ui::ET_GESTURE_SCROLL_BEGIN, event->type());
    DCHECK_NE(ui::ET_GESTURE_SCROLL_END, event->type());
    DCHECK_NE(ui::ET_GESTURE_SCROLL_UPDATE, event->type());
    DCHECK_NE(ui::ET_GESTURE_PINCH_BEGIN, event->type());
    DCHECK_NE(ui::ET_GESTURE_PINCH_END, event->type());
    DCHECK_NE(ui::ET_GESTURE_PINCH_UPDATE, event->type());
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(GestureProviderClient);
};

MagnificationController::MagnificationController()
    : root_window_(Shell::GetPrimaryRootWindow()),
      scale_(kNonMagnifiedScale),
      original_scale_(kNonMagnifiedScale) {
  Shell::Get()->AddPreTargetHandler(this);
  root_window_->AddObserver(this);
  root_window_->GetHost()->GetEventSource()->AddEventRewriter(this);

  point_of_interest_in_root_ = root_window_->bounds().CenterPoint();

  gesture_provider_client_ = std::make_unique<GestureProviderClient>();
  gesture_provider_ = std::make_unique<ui::GestureProviderAura>(
      this, gesture_provider_client_.get());
}

MagnificationController::~MagnificationController() {
  ui::InputMethod* input_method = GetInputMethod(root_window_);
  if (input_method)
    input_method->RemoveObserver(this);

  root_window_->GetHost()->GetEventSource()->RemoveEventRewriter(this);
  root_window_->RemoveObserver(this);

  Shell::Get()->RemovePreTargetHandler(this);
}

void MagnificationController::SetEnabled(bool enabled) {
  ui::InputMethod* input_method = GetInputMethod(root_window_);
  if (enabled) {
    if (!is_enabled_ && input_method)
      input_method->AddObserver(this);

    Shell* shell = Shell::Get();
    float scale =
        shell->accessibility_delegate()->GetSavedScreenMagnifierScale();
    if (scale <= 0.0f)
      scale = kInitialMagnifiedScale;
    ValidateScale(&scale);

    // Do nothing, if already enabled with same scale.
    if (is_enabled_ && scale == scale_)
      return;

    is_enabled_ = enabled;
    RedrawKeepingMousePosition(scale, true, false);
    shell->accessibility_delegate()->SaveScreenMagnifierScale(scale);
  } else {
    // Do nothing, if already disabled.
    if (!is_enabled_)
      return;

    if (input_method)
      input_method->RemoveObserver(this);

    RedrawKeepingMousePosition(kNonMagnifiedScale, true, false);
    is_enabled_ = enabled;
  }
}

bool MagnificationController::IsEnabled() const {
  return is_enabled_;
}

void MagnificationController::SetKeepFocusCentered(bool keep_focus_centered) {
  keep_focus_centered_ = keep_focus_centered;
}

bool MagnificationController::KeepFocusCentered() const {
  return keep_focus_centered_;
}

void MagnificationController::SetScale(float scale, bool animate) {
  if (!is_enabled_)
    return;

  ValidateScale(&scale);
  Shell::Get()->accessibility_delegate()->SaveScreenMagnifierScale(scale);
  RedrawKeepingMousePosition(scale, animate, false);
}

void MagnificationController::StepToNextScaleValue(int delta_index) {
  SetScale(magnifier_scale_utils::GetNextMagnifierScaleValue(
               delta_index, GetScale(), kNonMagnifiedScale, kMaxMagnifiedScale),
           true /* animate */);
}

void MagnificationController::MoveWindow(int x, int y, bool animate) {
  if (!is_enabled_)
    return;

  Redraw(gfx::PointF(x, y), scale_, animate);
}

void MagnificationController::MoveWindow(const gfx::Point& point,
                                         bool animate) {
  if (!is_enabled_)
    return;

  Redraw(gfx::PointF(point), scale_, animate);
}

gfx::Point MagnificationController::GetWindowPosition() const {
  return gfx::ToFlooredPoint(origin_);
}

void MagnificationController::SetScrollDirection(ScrollDirection direction) {
  scroll_direction_ = direction;
  StartOrStopScrollIfNecessary();
}

gfx::Rect MagnificationController::GetViewportRect() const {
  return gfx::ToEnclosingRect(GetWindowRectDIP(scale_));
}

void MagnificationController::CenterOnPoint(const gfx::Point& point_in_screen) {
  gfx::Point point_in_root = point_in_screen;
  ::wm::ConvertPointFromScreen(root_window_, &point_in_root);

  MoveMagnifierWindowCenterPoint(point_in_root);
}

void MagnificationController::HandleFocusedNodeChanged(
    bool is_editable_node,
    const gfx::Rect& node_bounds_in_screen) {
  // The editable node is handled by OnCaretBoundsChanged.
  if (is_editable_node)
    return;

  // Nothing to recenter on.
  if (node_bounds_in_screen.IsEmpty())
    return;

  gfx::Rect node_bounds_in_root = node_bounds_in_screen;
  ::wm::ConvertRectFromScreen(root_window_, &node_bounds_in_root);
  if (GetViewportRect().Contains(node_bounds_in_root))
    return;

  MoveMagnifierWindowFollowRect(node_bounds_in_root);
}

void MagnificationController::SwitchTargetRootWindow(
    aura::Window* new_root_window,
    bool redraw_original_root_window) {
  DCHECK(new_root_window);

  if (new_root_window == root_window_)
    return;

  // Stores the previous scale.
  float scale = GetScale();

  // Unmagnify the previous root window.
  root_window_->RemoveObserver(this);
  // TODO: This may need to remove the IME observer from the old root window
  // and add it to the new root window. https://crbug.com/820464

  // Do not move mouse back to its original position (point at border of the
  // root window) after redrawing as doing so will trigger root window switch
  // again.
  if (redraw_original_root_window)
    RedrawKeepingMousePosition(1.0f, true, true);
  root_window_ = new_root_window;
  RedrawKeepingMousePosition(scale, true, true);

  root_window_->AddObserver(this);
}

void MagnificationController::OnCaretBoundsChanged(
    const ui::TextInputClient* client) {
  // caret bounds in screen coordinates.
  const gfx::Rect caret_bounds = client->GetCaretBounds();
  // Note: OnCaretBoundsChanged could be fired OnTextInputTypeChanged during
  // which the caret position is not set a meaning position, and we do not
  // need to adjust the view port position based on the bogus caret position.
  // This is only a transition period, the caret position will be fixed upon
  // focusing right after.
  if (caret_bounds.width() == 0 && caret_bounds.height() == 0)
    return;

  gfx::Point new_caret_point = caret_bounds.CenterPoint();
  // |caret_point_| in |root_window_| coordinates.
  ::wm::ConvertPointFromScreen(root_window_, &new_caret_point);

  // When the caret point was not actually changed, nothing should happen.
  // OnCaretBoundsChanged could be fired on every event that may change the
  // caret bounds, in particular a window creation/movement, that may not result
  // in an actual movement.
  if (new_caret_point == caret_point_)
    return;
  caret_point_ = new_caret_point;

  // If the feature for centering the text input focus is disabled, the
  // magnifier window will be moved to follow the focus with a panning margin.
  if (!KeepFocusCentered()) {
    // Visible window_rect in |root_window_| coordinates.
    const gfx::Rect visible_window_rect = GetViewportRect();
    const int panning_margin = kCaretPanningMargin / scale_;
    MoveMagnifierWindowFollowPoint(caret_point_, panning_margin, panning_margin,
                                   visible_window_rect.width() / 2,
                                   visible_window_rect.height() / 2);
    return;
  }

  // Move the magnifier window to center the focus with a little delay.
  // In Gmail compose window, when user types a blank space, it will insert
  // a non-breaking space(NBSP). NBSP will be replaced with a blank space
  // character when user types a non-blank space character later, which causes
  // OnCaretBoundsChanged be called twice. The first call moves the caret back
  // to the character position just before NBSP, replaces the NBSP with blank
  // space plus the new character, then the second call will move caret to the
  // position after the new character. In order to avoid the magnifier window
  // being moved back and forth with these two OnCaretBoundsChanged events, we
  // defer moving magnifier window until the |move_magnifier_timer_| fires,
  // when the caret settles eventually.
  move_magnifier_timer_.Stop();
  move_magnifier_timer_.Start(
      FROM_HERE,
      base::TimeDelta::FromMilliseconds(
          disable_move_magnifier_delay_ ? 0 : kMoveMagnifierDelayInMs),
      this, &MagnificationController::OnMoveMagnifierTimer);
}

void MagnificationController::OnImplicitAnimationsCompleted() {
  if (!is_on_animation_)
    return;

  if (move_cursor_after_animation_) {
    MoveCursorTo(root_window_->GetHost(), position_after_animation_);
    move_cursor_after_animation_ = false;

    aura::client::CursorClient* cursor_client =
        aura::client::GetCursorClient(root_window_);
    if (cursor_client)
      cursor_client->EnableMouseEvents();
    else if (Shell::GetAshConfig() == Config::MASH)
      ShellPort::Get()->SetCursorTouchVisible(true);
  }

  is_on_animation_ = false;

  StartOrStopScrollIfNecessary();
}

void MagnificationController::OnWindowDestroying(aura::Window* root_window) {
  if (root_window == root_window_) {
    // There must be at least one root window because this controller is
    // destroyed before the root windows get destroyed.
    DCHECK(root_window);

    aura::Window* target_root_window = Shell::GetRootWindowForNewWindows();
    CHECK(target_root_window);

    // The destroyed root window must not be target.
    CHECK_NE(target_root_window, root_window);
    // Don't redraw the old root window as it's being destroyed.
    SwitchTargetRootWindow(target_root_window, false);
    point_of_interest_in_root_ = target_root_window->bounds().CenterPoint();
  }
}

void MagnificationController::OnWindowBoundsChanged(
    aura::Window* window,
    const gfx::Rect& old_bounds,
    const gfx::Rect& new_bounds,
    ui::PropertyChangeReason reason) {
  // TODO(yoshiki): implement here. crbug.com/230979
}

void MagnificationController::OnMouseEvent(ui::MouseEvent* event) {
  aura::Window* target = static_cast<aura::Window*>(event->target());
  aura::Window* current_root = target->GetRootWindow();
  gfx::Rect root_bounds = current_root->bounds();

  if (root_bounds.Contains(event->root_location())) {
    // This must be before |SwitchTargetRootWindow()|.
    if (event->type() != ui::ET_MOUSE_CAPTURE_CHANGED)
      point_of_interest_in_root_ = event->root_location();

    if (current_root != root_window_) {
      DCHECK(current_root);
      SwitchTargetRootWindow(current_root, true);
    }

    if (IsMagnified() && event->type() == ui::ET_MOUSE_MOVED &&
        event->pointer_details().pointer_type !=
            ui::EventPointerType::POINTER_TYPE_PEN) {
      OnMouseMove(event->root_location());
    }
  }
}

void MagnificationController::OnScrollEvent(ui::ScrollEvent* event) {
  if (event->IsAltDown() && event->IsControlDown()) {
    if (event->type() == ui::ET_SCROLL_FLING_START) {
      event->StopPropagation();
      return;
    } else if (event->type() == ui::ET_SCROLL_FLING_CANCEL) {
      float scale = GetScale();
      // Jump back to exactly 1.0 if we are just a tiny bit zoomed in.
      // TODO(katie): These events are not fired after every scroll, which means
      // we don't always jump back to 1.0. Look into why they are missing.
      if (scale < kMinMagnifiedScaleThreshold) {
        scale = kNonMagnifiedScale;
        SetScale(scale, true);
      }
      event->StopPropagation();
      return;
    }

    if (event->type() == ui::ET_SCROLL) {
      SetScale(magnifier_scale_utils::GetScaleFromScroll(
                   event->y_offset() * kScrollScaleChangeFactor, GetScale(),
                   kMaxMagnifiedScale, kNonMagnifiedScale),
               false /* animate */);
      event->StopPropagation();
      return;
    }
  }
}

void MagnificationController::OnTouchEvent(ui::TouchEvent* event) {
  aura::Window* target = static_cast<aura::Window*>(event->target());
  aura::Window* current_root = target->GetRootWindow();

  gfx::Rect root_bounds = current_root->bounds();
  if (!root_bounds.Contains(event->root_location()))
    return;

  point_of_interest_in_root_ = event->root_location();

  if (current_root != root_window_)
    SwitchTargetRootWindow(current_root, true);
}

ui::EventRewriteStatus MagnificationController::RewriteEvent(
    const ui::Event& event,
    std::unique_ptr<ui::Event>* rewritten_event) {
  if (!IsEnabled())
    return ui::EVENT_REWRITE_CONTINUE;

  if (!event.IsTouchEvent())
    return ui::EVENT_REWRITE_CONTINUE;

  const ui::TouchEvent* touch_event = event.AsTouchEvent();

  if (touch_event->type() == ui::ET_TOUCH_PRESSED) {
    touch_points_++;
    press_event_map_[touch_event->pointer_details().id] =
        std::make_unique<ui::TouchEvent>(*touch_event);
  } else if (touch_event->type() == ui::ET_TOUCH_RELEASED) {
    touch_points_--;
    press_event_map_.erase(touch_event->pointer_details().id);
  }

  ui::TouchEvent touch_event_copy = *touch_event;
  if (gesture_provider_->OnTouchEvent(&touch_event_copy)) {
    gesture_provider_->OnTouchEventAck(
        touch_event_copy.unique_event_id(), false /* event_consumed */,
        false /* is_source_touch_event_set_non_blocking */);
  } else {
    return ui::EVENT_REWRITE_DISCARD;
  }

  // User can change zoom level with two fingers pinch and pan around with two
  // fingers scroll. Once MagnificationController detects one of those two
  // gestures, it starts consuming all touch events with cancelling existing
  // touches. If cancel_pressed_touches is set to true, ET_TOUCH_CANCELLED
  // events are dispatched for existing touches after the next for-loop.
  bool cancel_pressed_touches = ProcessGestures();

  if (cancel_pressed_touches) {
    DCHECK_EQ(2u, press_event_map_.size());

    // MagnificationController starts consuming all touch events after it
    // cancells existing touches.
    consume_touch_event_ = true;

    auto it = press_event_map_.begin();

    std::unique_ptr<ui::TouchEvent> rewritten_touch_event =
        std::make_unique<ui::TouchEvent>(ui::ET_TOUCH_CANCELLED, gfx::Point(),
                                         touch_event->time_stamp(),
                                         it->second->pointer_details());
    rewritten_touch_event->set_location_f(it->second->location_f());
    rewritten_touch_event->set_root_location_f(it->second->root_location_f());
    rewritten_touch_event->set_flags(it->second->flags());
    *rewritten_event = std::move(rewritten_touch_event);

    // The other event is cancelled in NextDispatchEvent.
    press_event_map_.erase(it);

    return ui::EVENT_REWRITE_DISPATCH_ANOTHER;
  }

  bool discard = consume_touch_event_;

  // Reset state once no point is touched on the screen.
  if (touch_points_ == 0) {
    consume_touch_event_ = false;
    locked_gesture_ = NO_GESTURE;

    // Jump back to exactly 1.0 if we are just a tiny bit zoomed in.
    if (scale_ < kMinMagnifiedScaleThreshold) {
      SetScale(kNonMagnifiedScale, true /* animate */);
    }
  }

  if (discard)
    return ui::EVENT_REWRITE_DISCARD;

  return ui::EVENT_REWRITE_CONTINUE;
}

ui::EventRewriteStatus MagnificationController::NextDispatchEvent(
    const ui::Event& last_event,
    std::unique_ptr<ui::Event>* new_event) {
  DCHECK_EQ(1u, press_event_map_.size());

  auto it = press_event_map_.begin();

  std::unique_ptr<ui::TouchEvent> event = std::make_unique<ui::TouchEvent>(
      ui::ET_TOUCH_CANCELLED, gfx::Point(), last_event.time_stamp(),
      it->second->pointer_details());
  event->set_location_f(it->second->location_f());
  event->set_root_location_f(it->second->root_location_f());
  event->set_flags(it->second->flags());
  *new_event = std::move(event);

  press_event_map_.erase(it);

  DCHECK_EQ(0u, press_event_map_.size());

  return ui::EVENT_REWRITE_REWRITTEN;
}

bool MagnificationController::Redraw(const gfx::PointF& position,
                                     float scale,
                                     bool animate) {
  const gfx::PointF position_in_dip =
      ui::ConvertPointToDIP(root_window_->layer(), position);
  return RedrawDIP(position_in_dip, scale,
                   animate ? kDefaultAnimationDurationInMs : 0,
                   kDefaultAnimationTweenType);
}

bool MagnificationController::RedrawDIP(const gfx::PointF& position_in_dip,
                                        float scale,
                                        int duration_in_ms,
                                        gfx::Tween::Type tween_type) {
  DCHECK(root_window_);

  float x = position_in_dip.x();
  float y = position_in_dip.y();

  ValidateScale(&scale);

  if (x < 0)
    x = 0;
  if (y < 0)
    y = 0;

  const gfx::Size host_size_in_dip = GetHostSizeDIP();
  const gfx::SizeF window_size_in_dip = GetWindowRectDIP(scale).size();
  float max_x = host_size_in_dip.width() - window_size_in_dip.width();
  float max_y = host_size_in_dip.height() - window_size_in_dip.height();
  if (x > max_x)
    x = max_x;
  if (y > max_y)
    y = max_y;

  // Does nothing if both the origin and the scale are not changed.
  if (origin_.x() == x && origin_.y() == y && scale == scale_) {
    return false;
  }

  origin_.set_x(x);
  origin_.set_y(y);
  scale_ = scale;

  // Creates transform matrix.
  gfx::Transform transform;
  // Flips the signs intentionally to convert them from the position of the
  // magnification window.
  transform.Scale(scale_, scale_);
  transform.Translate(-origin_.x(), -origin_.y());

  ui::ScopedLayerAnimationSettings settings(
      root_window_->layer()->GetAnimator());
  settings.AddObserver(this);
  settings.SetPreemptionStrategy(
      ui::LayerAnimator::IMMEDIATELY_ANIMATE_TO_NEW_TARGET);
  settings.SetTweenType(tween_type);
  settings.SetTransitionDuration(
      base::TimeDelta::FromMilliseconds(duration_in_ms));

  display::Display display =
      display::Screen::GetScreen()->GetDisplayNearestWindow(root_window_);
  std::unique_ptr<RootWindowTransformer> transformer(
      CreateRootWindowTransformerForDisplay(root_window_, display));
  RootWindowController::ForWindow(root_window_)
      ->ash_host()
      ->SetRootWindowTransformer(std::move(transformer));

  if (duration_in_ms > 0)
    is_on_animation_ = true;

  return true;
}

void MagnificationController::StartOrStopScrollIfNecessary() {
  // This value controls the scrolling speed.
  const int kMoveOffset = 40;
  if (is_on_animation_) {
    if (scroll_direction_ == SCROLL_NONE)
      root_window_->layer()->GetAnimator()->StopAnimating();
    return;
  }

  gfx::PointF new_origin = origin_;
  switch (scroll_direction_) {
    case SCROLL_NONE:
      // No need to take action.
      return;
    case SCROLL_LEFT:
      new_origin.Offset(-kMoveOffset, 0);
      break;
    case SCROLL_RIGHT:
      new_origin.Offset(kMoveOffset, 0);
      break;
    case SCROLL_UP:
      new_origin.Offset(0, -kMoveOffset);
      break;
    case SCROLL_DOWN:
      new_origin.Offset(0, kMoveOffset);
      break;
  }
  RedrawDIP(new_origin, scale_, kDefaultAnimationDurationInMs,
            kDefaultAnimationTweenType);
}

void MagnificationController::RedrawKeepingMousePosition(
    float scale,
    bool animate,
    bool ignore_mouse_change) {
  gfx::Point mouse_in_root = point_of_interest_in_root_;
  // mouse_in_root is invalid value when the cursor is hidden.
  if (!root_window_->bounds().Contains(mouse_in_root))
    mouse_in_root = root_window_->bounds().CenterPoint();

  const gfx::PointF origin = gfx::PointF(
      mouse_in_root.x() - (scale_ / scale) * (mouse_in_root.x() - origin_.x()),
      mouse_in_root.y() - (scale_ / scale) * (mouse_in_root.y() - origin_.y()));
  bool changed =
      RedrawDIP(origin, scale, animate ? kDefaultAnimationDurationInMs : 0,
                kDefaultAnimationTweenType);
  if (!ignore_mouse_change && changed)
    AfterAnimationMoveCursorTo(mouse_in_root);
}

void MagnificationController::OnMouseMove(const gfx::Point& location) {
  DCHECK(root_window_);

  gfx::Point mouse(location);
  int margin = kCursorPanningMargin / scale_;  // No need to consider DPI.
  MoveMagnifierWindowFollowPoint(mouse, margin, margin, margin, margin);
}

void MagnificationController::AfterAnimationMoveCursorTo(
    const gfx::Point& location) {
  DCHECK(root_window_);

  aura::client::CursorClient* cursor_client =
      aura::client::GetCursorClient(root_window_);
  if (cursor_client) {
    // When cursor is invisible, do not move or show the cursor after the
    // animation.
    if (!cursor_client->IsCursorVisible())
      return;
    cursor_client->DisableMouseEvents();
  } else if (Shell::GetAshConfig() == Config::MASH) {
    ShellPort::Get()->SetCursorTouchVisible(false);
  }
  move_cursor_after_animation_ = true;
  position_after_animation_ = location;
}

bool MagnificationController::IsMagnified() const {
  return scale_ >= kMinMagnifiedScaleThreshold;
}

gfx::RectF MagnificationController::GetWindowRectDIP(float scale) const {
  const gfx::Size size_in_dip = root_window_->bounds().size();
  const float width = size_in_dip.width() / scale;
  const float height = size_in_dip.height() / scale;

  return gfx::RectF(origin_.x(), origin_.y(), width, height);
}

gfx::Size MagnificationController::GetHostSizeDIP() const {
  return root_window_->bounds().size();
}

void MagnificationController::ValidateScale(float* scale) {
  *scale = base::ClampToRange(*scale, kNonMagnifiedScale, kMaxMagnifiedScale);
  DCHECK(kNonMagnifiedScale <= *scale && *scale <= kMaxMagnifiedScale);
}

bool MagnificationController::ProcessGestures() {
  bool cancel_pressed_touches = false;

  std::vector<std::unique_ptr<ui::GestureEvent>> gestures =
      gesture_provider_->GetAndResetPendingGestures();
  for (const auto& gesture : gestures) {
    const ui::GestureEventDetails& details = gesture->details();

    if (details.touch_points() != 2)
      continue;

    if (gesture->type() == ui::ET_GESTURE_PINCH_BEGIN) {
      original_scale_ = scale_;

      // Start consuming touch events with cancelling existing touches.
      if (!consume_touch_event_)
        cancel_pressed_touches = true;
    } else if (gesture->type() == ui::ET_GESTURE_PINCH_UPDATE) {
      if (locked_gesture_ == NO_GESTURE || locked_gesture_ == ZOOM) {
        float scale = GetScale() * details.scale();
        ValidateScale(&scale);

        if (locked_gesture_ == NO_GESTURE &&
            std::abs(scale - original_scale_) > kZoomGestureLockThreshold) {
          locked_gesture_ = MagnificationController::ZOOM;
        }

        RedrawDIP(origin_, scale, 0, kDefaultAnimationTweenType);
      }
    } else if (gesture->type() == ui::ET_GESTURE_SCROLL_BEGIN) {
      original_origin_ = origin_;

      // Start consuming all touch events with cancelling existing touches.
      if (!consume_touch_event_)
        cancel_pressed_touches = true;
    } else if (gesture->type() == ui::ET_GESTURE_SCROLL_UPDATE) {
      if (locked_gesture_ == NO_GESTURE || locked_gesture_ == SCROLL) {
        // Divide by scale to keep scroll speed same at any scale.
        float new_x = origin_.x() + (-1.0f * details.scroll_x() / scale_);
        float new_y = origin_.y() + (-1.0f * details.scroll_y() / scale_);

        if (locked_gesture_ == NO_GESTURE) {
          float diff_x = (new_x - original_origin_.x()) * scale_;
          float diff_y = (new_y - original_origin_.y()) * scale_;
          float squared_distance = (diff_x * diff_x) + (diff_y * diff_y);
          if (squared_distance > kScrollGestureLockThreshold) {
            locked_gesture_ = SCROLL;
          }
        }

        RedrawDIP(gfx::PointF(new_x, new_y), scale_, 0,
                  kDefaultAnimationTweenType);
      }
    }
  }

  return cancel_pressed_touches;
}

void MagnificationController::MoveMagnifierWindowFollowPoint(
    const gfx::Point& point,
    int x_panning_margin,
    int y_panning_margin,
    int x_target_margin,
    int y_target_margin) {
  DCHECK(root_window_);
  bool start_zoom = false;

  const gfx::Rect window_rect = GetViewportRect();
  const int left = window_rect.x();
  const int right = window_rect.right();

  int x_diff = 0;
  if (point.x() < left + x_panning_margin) {
    // Panning left.
    x_diff = point.x() - (left + x_target_margin);
    start_zoom = true;
  } else if (right - x_panning_margin < point.x()) {
    // Panning right.
    x_diff = point.x() - (right - x_target_margin);
    start_zoom = true;
  }
  int x = left + x_diff;

  const int top = window_rect.y();
  const int bottom = window_rect.bottom();

  int y_diff = 0;
  if (point.y() < top + y_panning_margin) {
    // Panning up.
    y_diff = point.y() - (top + y_target_margin);
    start_zoom = true;
  } else if (bottom - y_panning_margin < point.y()) {
    // Panning down.
    y_diff = point.y() - (bottom - y_target_margin);
    start_zoom = true;
  }
  int y = top + y_diff;
  if (start_zoom && !is_on_animation_) {
    bool ret = RedrawDIP(gfx::PointF(x, y), scale_,
                         0,  // No animation on panning.
                         kDefaultAnimationTweenType);

    if (ret) {
      // If the magnified region is moved, hides the mouse cursor and moves it.
      if (x_diff != 0 || y_diff != 0)
        MoveCursorTo(root_window_->GetHost(), point);
    }
  }
}

void MagnificationController::MoveMagnifierWindowCenterPoint(
    const gfx::Point& point) {
  DCHECK(root_window_);

  const gfx::Rect window_rect = GetViewportRect();
  if (point == window_rect.CenterPoint())
    return;

  if (!is_on_animation_) {
    // With animation on panning.
    RedrawDIP(
        gfx::PointF(window_rect.origin() + (point - window_rect.CenterPoint())),
        scale_, kDefaultAnimationDurationInMs, kCenterCaretAnimationTweenType);
  }
}

void MagnificationController::MoveMagnifierWindowFollowRect(
    const gfx::Rect& rect) {
  DCHECK(root_window_);
  bool should_pan = false;

  const gfx::Rect viewport_rect = GetViewportRect();
  const int left = viewport_rect.x();
  const int right = viewport_rect.right();
  const gfx::Point rect_center = rect.CenterPoint();

  int x = left;
  if (rect.x() < left || right < rect.right()) {
    // Panning horizontally.
    x = rect_center.x() - viewport_rect.width() / 2;
    should_pan = true;
  }

  const int top = viewport_rect.y();
  const int bottom = viewport_rect.bottom();

  int y = top;
  if (rect.y() < top || bottom < rect.bottom()) {
    // Panning vertically.
    y = rect_center.y() - viewport_rect.height() / 2;
    should_pan = true;
  }

  if (should_pan) {
    if (is_on_animation_) {
      root_window_->layer()->GetAnimator()->StopAnimating();
      is_on_animation_ = false;
    }
    RedrawDIP(gfx::PointF(x, y), scale_,
              0,  // No animation on panning.
              kDefaultAnimationTweenType);
  }
}

void MagnificationController::OnMoveMagnifierTimer() {
  MoveMagnifierWindowCenterPoint(caret_point_);
}

}  // namespace ash

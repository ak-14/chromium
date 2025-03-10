// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/vr/elements/ui_element.h"

#include <limits>

#include "base/logging.h"
#include "base/numerics/ranges.h"
#include "base/stl_util.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "chrome/browser/vr/model/camera_model.h"
#include "third_party/blink/public/platform/web_gesture_event.h"
#include "third_party/skia/include/core/SkRRect.h"
#include "third_party/skia/include/core/SkRect.h"
#include "ui/gfx/geometry/angle_conversions.h"
#include "ui/gfx/geometry/rect_f.h"

namespace vr {

namespace {

constexpr bool kEnableOptimizedTreeWalks = true;
constexpr float kHitTestResolutionInMeter = 0.000001f;

int AllocateId() {
  static int g_next_id = 1;
  return g_next_id++;
}

bool GetRayPlaneDistance(const gfx::Point3F& ray_origin,
                         const gfx::Vector3dF& ray_vector,
                         const gfx::Point3F& plane_origin,
                         const gfx::Vector3dF& plane_normal,
                         float* distance) {
  float denom = gfx::DotProduct(-ray_vector, plane_normal);
  if (denom == 0) {
    return false;
  }
  gfx::Vector3dF rel = ray_origin - plane_origin;
  *distance = gfx::DotProduct(plane_normal, rel) / denom;
  return true;
}

#ifndef NDEBUG
constexpr char kRed[] = "\x1b[31m";
constexpr char kGreen[] = "\x1b[32m";
constexpr char kBlue[] = "\x1b[34m";
constexpr char kCyan[] = "\x1b[36m";
constexpr char kYellow[] = "\x1b[33m";
constexpr char kReset[] = "\x1b[0m";

void DumpTransformOperations(const cc::TransformOperations& ops,
                             std::ostringstream* os) {
  if (!ops.at(0).IsIdentity()) {
    const auto& translate = ops.at(0).translate;
    *os << "t(" << translate.x << ", " << translate.y << ", " << translate.z
        << ") ";
  }

  if (ops.size() < 2u) {
    return;
  }

  if (!ops.at(1).IsIdentity()) {
    const auto& rotate = ops.at(1).rotate;
    if (rotate.axis.x > 0.0f) {
      *os << "rx(" << rotate.angle << ") ";
    } else if (rotate.axis.y > 0.0f) {
      *os << "ry(" << rotate.angle << ") ";
    } else if (rotate.axis.z > 0.0f) {
      *os << "rz(" << rotate.angle << ") ";
    }
  }

  if (!ops.at(2).IsIdentity()) {
    const auto& scale = ops.at(2).scale;
    *os << "s(" << scale.x << ", " << scale.y << ", " << scale.z << ") ";
  }
}
#endif

}  // namespace

EventHandlers::EventHandlers() = default;
EventHandlers::~EventHandlers() = default;
EventHandlers::EventHandlers(const EventHandlers& other) = default;

UiElement::UiElement() : id_(AllocateId()) {
  animation_.set_target(this);
  layout_offset_.AppendTranslate(0, 0, 0);
  transform_operations_.AppendTranslate(0, 0, 0);
  transform_operations_.AppendRotate(1, 0, 0, 0);
  transform_operations_.AppendScale(1, 1, 1);
}

UiElement::~UiElement() {
  animation_.set_target(nullptr);
}

void UiElement::SetName(UiElementName name) {
  name_ = name;
  OnSetName();
}

void UiElement::OnSetName() {}

void UiElement::SetType(UiElementType type) {
  type_ = type;
  OnSetType();
}

UiElement* UiElement::GetDescendantByType(UiElementType type) {
  if (type_ == type)
    return this;

  for (auto& child : children_) {
    auto* result = child->GetDescendantByType(type);
    if (result)
      return result;
  }
  return nullptr;
}

void UiElement::OnSetType() {}

void UiElement::SetDrawPhase(DrawPhase draw_phase) {
  draw_phase_ = draw_phase;
  OnSetDrawPhase();
}

void UiElement::OnSetDrawPhase() {}

void UiElement::set_focusable(bool focusable) {
  focusable_ = focusable;
  OnSetFocusable();
}

void UiElement::OnSetFocusable() {}

void UiElement::Render(UiElementRenderer* renderer,
                       const CameraModel& model) const {
  // Elements without an overridden implementation of Render should have their
  // draw phase set to kPhaseNone and should, consequently, be filtered out when
  // the UiRenderer collects elements to draw. Therefore, if we invoke this
  // function, it is an error.
  NOTREACHED() << "element: " << DebugName();
}

void UiElement::Initialize(SkiaSurfaceProvider* provider) {}

void UiElement::OnHoverEnter(const gfx::PointF& position) {
  if (GetSounds().hover_enter != kSoundNone && audio_delegate_) {
    audio_delegate_->PlaySound(GetSounds().hover_enter);
  }

  if (event_handlers_.hover_enter) {
    event_handlers_.hover_enter.Run();
  } else if (parent() && bubble_events()) {
    parent()->OnHoverEnter(position);
  }
}

void UiElement::OnHoverLeave() {
  if (GetSounds().hover_leave != kSoundNone && audio_delegate_) {
    audio_delegate_->PlaySound(GetSounds().hover_leave);
  }
  if (event_handlers_.hover_leave) {
    event_handlers_.hover_leave.Run();
  } else if (parent() && bubble_events()) {
    parent()->OnHoverLeave();
  }
}

void UiElement::OnMove(const gfx::PointF& position) {
  if (GetSounds().move != kSoundNone && audio_delegate_) {
    audio_delegate_->PlaySound(GetSounds().move);
  }
  if (event_handlers_.hover_move) {
    event_handlers_.hover_move.Run(position);
  } else if (parent() && bubble_events()) {
    parent()->OnMove(position);
  }
}

void UiElement::OnButtonDown(const gfx::PointF& position) {
  if (GetSounds().button_down != kSoundNone && audio_delegate_) {
    audio_delegate_->PlaySound(GetSounds().button_down);
  }
  if (event_handlers_.button_down) {
    event_handlers_.button_down.Run();
  } else if (parent() && bubble_events()) {
    parent()->OnButtonDown(position);
  }
}

void UiElement::OnButtonUp(const gfx::PointF& position) {
  if (GetSounds().button_up != kSoundNone && audio_delegate_) {
    audio_delegate_->PlaySound(GetSounds().button_up);
  }
  if (event_handlers_.button_up) {
    event_handlers_.button_up.Run();
  } else if (parent() && bubble_events()) {
    parent()->OnButtonUp(position);
  }
}

void UiElement::OnFlingCancel(std::unique_ptr<blink::WebGestureEvent> gesture,
                              const gfx::PointF& position) {}
void UiElement::OnScrollBegin(std::unique_ptr<blink::WebGestureEvent> gesture,
                              const gfx::PointF& position) {}
void UiElement::OnScrollUpdate(std::unique_ptr<blink::WebGestureEvent> gesture,
                               const gfx::PointF& position) {}
void UiElement::OnScrollEnd(std::unique_ptr<blink::WebGestureEvent> gesture,
                            const gfx::PointF& position) {}

void UiElement::OnFocusChanged(bool focused) {
  NOTREACHED();
}

void UiElement::OnInputEdited(const EditedText& info) {
  NOTREACHED();
}

void UiElement::OnInputCommitted(const EditedText& info) {
  NOTREACHED();
}

void UiElement::RequestFocus() {
  NOTREACHED();
}

void UiElement::RequestUnfocus() {
  NOTREACHED();
}

void UiElement::UpdateInput(const EditedText& info) {
  NOTREACHED();
}

bool UiElement::DoBeginFrame(const gfx::Transform& head_pose) {
  // TODO(mthiesse): This is overly cautious. We may have keyframe_models but
  // not trigger any updates, so we should refine this logic and have
  // Animation::Tick return a boolean. Similarly, the bindings update may have
  // had no visual effect and dirtiness should be related to setting properties
  // that do indeed cause visual updates.
  bool keyframe_models_updated = animation_.keyframe_models().size() > 0;
  animation_.Tick(last_frame_time_);
  set_update_phase(kUpdatedAnimations);
  bool begin_frame_updated = OnBeginFrame(head_pose);
  UpdateComputedOpacity();
  bool was_visible_at_any_point = IsVisible() || updated_visibility_this_frame_;
  bool dirty = (begin_frame_updated || keyframe_models_updated ||
                updated_bindings_this_frame_) &&
               was_visible_at_any_point;

  if (!kEnableOptimizedTreeWalks || was_visible_at_any_point ||
      visibility_bindings_depend_on_child_visibility_) {
    for (auto& child : children_)
      dirty |= child->DoBeginFrame(head_pose);
  }

  return dirty;
}

bool UiElement::OnBeginFrame(const gfx::Transform& head_pose) {
  return false;
}

bool UiElement::PrepareToDraw() {
  return false;
}

bool UiElement::UpdateTexture() {
  return false;
}

bool UiElement::IsHitTestable() const {
  return IsVisible() && hit_testable_;
}

void UiElement::SetSize(float width, float height) {
  animation_.TransitionSizeTo(last_frame_time_, BOUNDS, size_,
                              gfx::SizeF(width, height));
  OnSetSize(gfx::SizeF(width, height));
}

void UiElement::OnSetSize(const gfx::SizeF& size) {}

void UiElement::SetVisible(bool visible) {
  SetOpacity(visible ? opacity_when_visible_ : 0.0);
}

void UiElement::SetVisibleImmediately(bool visible) {
  opacity_ = visible ? opacity_when_visible_ : 0.0;
  animation_.RemoveKeyframeModels(OPACITY);
}

bool UiElement::IsVisible() const {
  DCHECK(update_phase_ >= kUpdatedComputedOpacity ||
         FrameLifecycle::phase() >= kUpdatedComputedOpacity);
  // TODO(crbug.com/832216): we shouldn't need to check opacity() here.
  return update_phase_ != kDirty && opacity() > 0.0f &&
         computed_opacity() > 0.0f;
}

bool UiElement::IsVisibleAndOpaque() const {
  DCHECK(update_phase_ >= kUpdatedComputedOpacity ||
         FrameLifecycle::phase() >= kUpdatedComputedOpacity);
  // TODO(crbug.com/832216): we shouldn't need to check opacity() here.
  return update_phase_ != kDirty && opacity() == 1.0f &&
         computed_opacity() == 1.0f;
}

bool UiElement::IsOrWillBeLocallyVisible() const {
  return opacity() > 0.0f || GetTargetOpacity() > 0.0f;
}

gfx::SizeF UiElement::size() const {
  DCHECK_LE(kUpdatedSize, update_phase_);
  return size_;
}

void UiElement::SetLayoutOffset(float x, float y) {
  if (x_centering() == LEFT) {
    x += size_.width() / 2;
    if (!bounds_contain_padding_)
      x -= left_padding_;
  } else if (x_centering() == RIGHT) {
    x -= size_.width() / 2;
    if (!bounds_contain_padding_)
      x += right_padding_;
  }
  if (y_centering() == TOP) {
    y -= size_.height() / 2;
    if (!bounds_contain_padding_)
      y += top_padding_;
  } else if (y_centering() == BOTTOM) {
    y += size_.height() / 2;
    if (!bounds_contain_padding_)
      y -= bottom_padding_;
  }

  if (x == layout_offset_.at(0).translate.x &&
      y == layout_offset_.at(0).translate.y &&
      !IsAnimatingProperty(LAYOUT_OFFSET)) {
    return;
  }

  cc::TransformOperations operations = layout_offset_;
  cc::TransformOperation& op = operations.at(0);
  op.translate = {x, y, 0};
  op.Bake();
  animation_.TransitionTransformOperationsTo(last_frame_time_, LAYOUT_OFFSET,
                                             layout_offset_, operations);
}

void UiElement::SetTranslate(float x, float y, float z) {
  if (x == transform_operations_.at(kTranslateIndex).translate.x &&
      y == transform_operations_.at(kTranslateIndex).translate.y &&
      z == transform_operations_.at(kTranslateIndex).translate.z &&
      !IsAnimatingProperty(TRANSFORM)) {
    return;
  }

  cc::TransformOperations operations = transform_operations_;
  cc::TransformOperation& op = operations.at(kTranslateIndex);
  op.translate = {x, y, z};
  op.Bake();
  animation_.TransitionTransformOperationsTo(last_frame_time_, TRANSFORM,
                                             transform_operations_, operations);
}

void UiElement::SetRotate(float x, float y, float z, float radians) {
  float degrees = gfx::RadToDeg(radians);

  if (x == transform_operations_.at(kRotateIndex).rotate.axis.x &&
      y == transform_operations_.at(kRotateIndex).rotate.axis.y &&
      z == transform_operations_.at(kRotateIndex).rotate.axis.z &&
      degrees == transform_operations_.at(kRotateIndex).rotate.angle &&
      !IsAnimatingProperty(TRANSFORM)) {
    return;
  }

  cc::TransformOperations operations = transform_operations_;
  cc::TransformOperation& op = operations.at(kRotateIndex);
  op.rotate.axis = {x, y, z};
  op.rotate.angle = degrees;
  op.Bake();
  animation_.TransitionTransformOperationsTo(last_frame_time_, TRANSFORM,
                                             transform_operations_, operations);
}

void UiElement::SetScale(float x, float y, float z) {
  if (x == transform_operations_.at(kScaleIndex).scale.x &&
      y == transform_operations_.at(kScaleIndex).scale.y &&
      z == transform_operations_.at(kScaleIndex).scale.z &&
      !IsAnimatingProperty(TRANSFORM)) {
    return;
  }

  cc::TransformOperations operations = transform_operations_;
  cc::TransformOperation& op = operations.at(kScaleIndex);
  op.scale = {x, y, z};
  op.Bake();
  animation_.TransitionTransformOperationsTo(last_frame_time_, TRANSFORM,
                                             transform_operations_, operations);
}

void UiElement::SetOpacity(float opacity) {
  animation_.TransitionFloatTo(last_frame_time_, OPACITY, opacity_, opacity);
}

void UiElement::SetCornerRadii(const CornerRadii& radii) {
  corner_radii_ = radii;
  OnSetCornerRadii(radii);
}

void UiElement::OnSetCornerRadii(const CornerRadii& radii) {}

gfx::SizeF UiElement::GetTargetSize() const {
  return animation_.GetTargetSizeValue(TargetProperty::BOUNDS, size_);
}

cc::TransformOperations UiElement::GetTargetTransform() const {
  return animation_.GetTargetTransformOperationsValue(TargetProperty::TRANSFORM,
                                                      transform_operations_);
}

gfx::Transform UiElement::ComputeTargetWorldSpaceTransform() const {
  gfx::Transform m;
  for (const UiElement* current = this; current; current = current->parent()) {
    m.ConcatTransform(current->GetTargetLocalTransform());
  }
  return m;
}

float UiElement::GetTargetOpacity() const {
  return animation_.GetTargetFloatValue(TargetProperty::OPACITY, opacity_);
}

float UiElement::ComputeTargetOpacity() const {
  float opacity = 1.0;
  for (const UiElement* current = this; current; current = current->parent()) {
    opacity *= current->GetTargetOpacity();
  }
  return opacity;
}

float UiElement::computed_opacity() const {
  DCHECK_LE(kUpdatedComputedOpacity, update_phase_) << DebugName();
  return computed_opacity_;
}

float UiElement::ComputedAndLocalOpacityForTest() const {
  return computed_opacity();
}

bool UiElement::LocalHitTest(const gfx::PointF& point) const {
  if (point.x() < 0.0f || point.x() > 1.0f || point.y() < 0.0f ||
      point.y() > 1.0f) {
    return false;
  } else if (corner_radii_.IsZero()) {
    return point.x() >= 0.0f && point.x() <= 1.0f && point.y() >= 0.0f &&
           point.y() <= 1.0f;
  }

  float width = size().width();
  float height = size().height();
  SkRRect rrect;
  SkVector radii[4] = {
      {corner_radii_.upper_left, corner_radii_.upper_left},
      {corner_radii_.upper_right, corner_radii_.upper_right},
      {corner_radii_.lower_right, corner_radii_.lower_right},
      {corner_radii_.lower_left, corner_radii_.lower_left},
  };
  rrect.setRectRadii(SkRect::MakeWH(width, height), radii);

  float left = std::min(point.x() * width, width - kHitTestResolutionInMeter);
  float top = std::min(point.y() * height, height - kHitTestResolutionInMeter);
  SkRect point_rect =
      SkRect::MakeLTRB(left, top, left + kHitTestResolutionInMeter,
                       top + kHitTestResolutionInMeter);
  return rrect.contains(point_rect);
}

void UiElement::HitTest(const HitTestRequest& request,
                        HitTestResult* result) const {
  gfx::Vector3dF ray_vector = request.ray_target - request.ray_origin;
  ray_vector.GetNormalized(&ray_vector);
  result->type = HitTestResult::Type::kNone;
  float distance_to_plane;
  if (!GetRayDistance(request.ray_origin, ray_vector, &distance_to_plane)) {
    return;
  }

  if (distance_to_plane < 0 ||
      distance_to_plane > request.max_distance_to_plane) {
    return;
  }

  result->type = HitTestResult::Type::kHitsPlane;
  result->distance_to_plane = distance_to_plane;
  result->hit_point =
      request.ray_origin + gfx::ScaleVector3d(ray_vector, distance_to_plane);
  gfx::PointF unit_xy_point = GetUnitRectangleCoordinates(result->hit_point);
  result->local_hit_point.set_x(0.5f + unit_xy_point.x());
  result->local_hit_point.set_y(0.5f - unit_xy_point.y());
  if (LocalHitTest(result->local_hit_point)) {
    result->type = HitTestResult::Type::kHits;
  }
}

const gfx::Transform& UiElement::world_space_transform() const {
  DCHECK_LE(kUpdatedWorldSpaceTransform, update_phase_);
  return world_space_transform_;
}

bool UiElement::IsWorldPositioned() const {
  return true;
}

std::string UiElement::DebugName() const {
  return base::StringPrintf(
      "%s%s%s",
      UiElementNameToString(name() == kNone ? owner_name_for_test() : name())
          .c_str(),
      type() == kTypeNone ? "" : ":",
      type() == kTypeNone ? "" : UiElementTypeToString(type()).c_str());
}

#ifndef NDEBUG
void DumpLines(const std::vector<size_t>& counts,
               const std::vector<const UiElement*>& ancestors,
               std::ostringstream* os) {
  for (size_t i = 0; i < counts.size(); ++i) {
    size_t current_count = counts[i];
    if (i + 1 < counts.size()) {
      current_count++;
    }
    if (ancestors[ancestors.size() - i - 1]->children().size() >
        current_count) {
      *os << "| ";
    } else {
      *os << "  ";
    }
  }
}

void UiElement::DumpHierarchy(std::vector<size_t> counts,
                              std::ostringstream* os,
                              bool include_bindings) const {
  // Put our ancestors in a vector for easy reverse traversal.
  std::vector<const UiElement*> ancestors;
  for (const UiElement* ancestor = parent(); ancestor;
       ancestor = ancestor->parent()) {
    ancestors.push_back(ancestor);
  }
  DCHECK_EQ(counts.size(), ancestors.size());

  *os << kBlue;
  for (size_t i = 0; i < counts.size(); ++i) {
    if (i + 1 == counts.size()) {
      *os << "+-";
    } else if (ancestors[ancestors.size() - i - 1]->children().size() >
               counts[i] + 1) {
      *os << "| ";
    } else {
      *os << "  ";
    }
  }
  *os << kReset;

  if (update_phase_ < kUpdatedComputedOpacity || !IsVisible()) {
    *os << kBlue;
  }

  *os << DebugName() << kReset << " " << kCyan << DrawPhaseToString(draw_phase_)
      << " " << kReset;

  if (update_phase_ >= kUpdatedSize) {
    if (size().width() != 0.0f || size().height() != 0.0f) {
      *os << kRed << "[" << size().width() << ", " << size().height() << "] "
          << kReset;
    }
  }

  if (update_phase_ >= kUpdatedWorldSpaceTransform) {
    *os << kGreen;
    DumpGeometry(os);
  }

  counts.push_back(0u);

  if (include_bindings) {
    std::ostringstream binding_stream;
    for (auto& binding : bindings_) {
      std::string binding_text = binding->ToString();
      if (binding_text.empty())
        continue;
      binding_stream << binding->ToString() << std::endl;
    }

    auto split_bindings =
        base::SplitString(binding_stream.str(), "\n", base::TRIM_WHITESPACE,
                          base::SPLIT_WANT_NONEMPTY);
    if (!split_bindings.empty()) {
      ancestors.insert(ancestors.begin(), this);
    }
    for (const auto& split : split_bindings) {
      *os << std::endl << kBlue;
      DumpLines(counts, ancestors, os);
      *os << kGreen << split;
    }
  }

  *os << kReset << std::endl;

  for (auto& child : children_) {
    child->DumpHierarchy(counts, os, include_bindings);
    counts.back()++;
  }
}

void UiElement::DumpGeometry(std::ostringstream* os) const {
  DumpTransformOperations(transform_operations_, os);
  *os << kYellow;
  DumpTransformOperations(layout_offset_, os);
}
#endif

void UiElement::SetSounds(Sounds sounds, AudioDelegate* delegate) {
  sounds_ = sounds;
  audio_delegate_ = delegate;
}

void UiElement::OnUpdatedWorldSpaceTransform() {}

void UiElement::AddChild(std::unique_ptr<UiElement> child) {
  for (UiElement* current = this; current; current = current->parent())
    current->set_descendants_updated(true);
  child->parent_ = this;
  children_.push_back(std::move(child));
}

std::unique_ptr<UiElement> UiElement::RemoveChild(UiElement* to_remove) {
  for (UiElement* current = this; current; current = current->parent())
    current->set_descendants_updated(true);
  DCHECK_EQ(this, to_remove->parent_);
  to_remove->parent_ = nullptr;
  size_t old_size = children_.size();

  auto it = std::find_if(std::begin(children_), std::end(children_),
                         [to_remove](const std::unique_ptr<UiElement>& child) {
                           return child.get() == to_remove;
                         });
  DCHECK(it != std::end(children_));

  std::unique_ptr<UiElement> removed(it->release());
  children_.erase(it);
  DCHECK_NE(old_size, children_.size());
  return removed;
}

void UiElement::AddBinding(std::unique_ptr<BindingBase> binding) {
  bindings_.push_back(std::move(binding));
}

void UiElement::UpdateBindings() {
  bool should_recur = IsOrWillBeLocallyVisible();
  updated_bindings_this_frame_ = false;
  for (auto& binding : bindings_) {
    if (binding->Update())
      updated_bindings_this_frame_ = true;
  }
  should_recur |= IsOrWillBeLocallyVisible();

  set_update_phase(kUpdatedBindings);
  if (!should_recur && kEnableOptimizedTreeWalks)
    return;

  for (auto& child : children_)
    child->UpdateBindings();
}

gfx::Point3F UiElement::GetCenter() const {
  gfx::Point3F center;
  world_space_transform_.TransformPoint(&center);
  return center;
}

gfx::PointF UiElement::GetUnitRectangleCoordinates(
    const gfx::Point3F& world_point) const {
  gfx::Point3F origin;
  gfx::Vector3dF x_axis(1, 0, 0);
  gfx::Vector3dF y_axis(0, 1, 0);
  world_space_transform_.TransformPoint(&origin);
  world_space_transform_.TransformVector(&x_axis);
  world_space_transform_.TransformVector(&y_axis);
  gfx::Vector3dF origin_to_world = world_point - origin;
  float x = gfx::DotProduct(origin_to_world, x_axis) /
            gfx::DotProduct(x_axis, x_axis);
  float y = gfx::DotProduct(origin_to_world, y_axis) /
            gfx::DotProduct(y_axis, y_axis);
  return gfx::PointF(x, y);
}

gfx::Vector3dF UiElement::GetNormal() const {
  gfx::Vector3dF x_axis(1, 0, 0);
  gfx::Vector3dF y_axis(0, 1, 0);
  world_space_transform_.TransformVector(&x_axis);
  world_space_transform_.TransformVector(&y_axis);
  gfx::Vector3dF normal = CrossProduct(x_axis, y_axis);
  normal.GetNormalized(&normal);
  return normal;
}

bool UiElement::GetRayDistance(const gfx::Point3F& ray_origin,
                               const gfx::Vector3dF& ray_vector,
                               float* distance) const {
  return GetRayPlaneDistance(ray_origin, ray_vector, GetCenter(), GetNormal(),
                             distance);
}

void UiElement::NotifyClientFloatAnimated(float value,
                                          int target_property_id,
                                          cc::KeyframeModel* keyframe_model) {
  opacity_ = base::ClampToRange(value, 0.0f, 1.0f);
}

void UiElement::NotifyClientTransformOperationsAnimated(
    const cc::TransformOperations& operations,
    int target_property_id,
    cc::KeyframeModel* keyframe_model) {
  if (target_property_id == TRANSFORM) {
    transform_operations_ = operations;
  } else if (target_property_id == LAYOUT_OFFSET) {
    layout_offset_ = operations;
  } else {
    NOTREACHED();
  }
  local_transform_ = layout_offset_.Apply() * transform_operations_.Apply();
  world_space_transform_dirty_ = true;
}

void UiElement::NotifyClientSizeAnimated(const gfx::SizeF& size,
                                         int target_property_id,
                                         cc::KeyframeModel* keyframe_model) {
  if (size_ == size)
    return;
  size_ = size;
  world_space_transform_dirty_ = true;
}

void UiElement::SetTransitionedProperties(
    const std::set<TargetProperty>& properties) {
  std::set<int> converted_properties(properties.begin(), properties.end());
  animation_.SetTransitionedProperties(converted_properties);
}

void UiElement::SetTransitionDuration(base::TimeDelta delta) {
  animation_.SetTransitionDuration(delta);
}

void UiElement::AddKeyframeModel(
    std::unique_ptr<cc::KeyframeModel> keyframe_model) {
  animation_.AddKeyframeModel(std::move(keyframe_model));
}

void UiElement::RemoveKeyframeModel(int keyframe_model_id) {
  animation_.RemoveKeyframeModel(keyframe_model_id);
}

void UiElement::RemoveKeyframeModels(int target_property) {
  animation_.RemoveKeyframeModels(target_property);
}

bool UiElement::IsAnimatingProperty(TargetProperty property) const {
  return animation_.IsAnimatingProperty(static_cast<int>(property));
}

bool UiElement::SizeAndLayOut() {
  if (!IsVisible() && kEnableOptimizedTreeWalks)
    return false;
  bool changed = false;
  for (auto& child : children_)
    changed |= child->SizeAndLayOut();
  changed |= PrepareToDraw();
  set_update_phase(kUpdatedSize);
  DoLayOutChildren();
  set_update_phase(kUpdatedLayout);
  return changed;
}

void UiElement::DoLayOutChildren() {
  LayOutChildren();
  if (!bounds_contain_children_) {
    DCHECK_EQ(0.0f, right_padding_);
    DCHECK_EQ(0.0f, left_padding_);
    DCHECK_EQ(0.0f, top_padding_);
    DCHECK_EQ(0.0f, bottom_padding_);
    return;
  }

  bool requires_relayout = false;
  gfx::RectF bounds;
  for (auto& child : children_) {
    if (!child->IsVisible())
      continue;

    gfx::RectF outer_bounds(child->size());
    gfx::RectF inner_bounds(child->size());
    if (!child->bounds_contain_padding_) {
      inner_bounds.Inset(child->left_padding_, child->bottom_padding_,
                         child->right_padding_, child->top_padding_);
    }
    gfx::SizeF size = inner_bounds.size();
    if (child->x_anchoring() != NONE || child->y_anchoring() != NONE) {
      DCHECK(!child->contributes_to_parent_bounds());
      requires_relayout = true;
    }
    if (size.IsEmpty() || !child->contributes_to_parent_bounds())
      continue;

    gfx::Vector2dF delta =
        outer_bounds.CenterPoint() - inner_bounds.CenterPoint();
    gfx::Point3F child_center(child->local_origin() - delta);
    gfx::Vector3dF corner_offset(size.width(), size.height(), 0);
    corner_offset.Scale(-0.5);
    gfx::Point3F child_upper_left = child_center + corner_offset;
    gfx::Point3F child_lower_right = child_center - corner_offset;

    child->LocalTransform().TransformPoint(&child_upper_left);
    child->LocalTransform().TransformPoint(&child_lower_right);
    gfx::RectF local_rect =
        gfx::RectF(child_upper_left.x(), child_upper_left.y(),
                   child_lower_right.x() - child_upper_left.x(),
                   child_lower_right.y() - child_upper_left.y());
    bounds.Union(local_rect);
  }

  bounds.Inset(-left_padding_, -bottom_padding_, -right_padding_,
               -top_padding_);
  bounds.set_origin(bounds.CenterPoint());
  if (local_origin_ != bounds.origin()) {
    world_space_transform_dirty_ = true;
    local_origin_ = bounds.origin();
  }
  if (bounds.size() == GetTargetSize())
    return;

  SetSize(bounds.width(), bounds.height());

  if (requires_relayout)
    LayOutChildren();
}

void UiElement::LayOutChildren() {
  DCHECK_LE(kUpdatedSize, update_phase_);
  for (auto& child : children_) {
    if (!child->IsVisible())
      continue;
    // To anchor a child, use the parent's size to find its edge.
    float x_offset = 0.0f;
    if (child->x_anchoring() == LEFT) {
      x_offset = -0.5f * size().width();
      if (!child->bounds_contain_padding())
        x_offset += left_padding_;
    } else if (child->x_anchoring() == RIGHT) {
      x_offset = 0.5f * size().width();
      if (!child->bounds_contain_padding())
        x_offset -= right_padding_;
    }
    float y_offset = 0.0f;
    if (child->y_anchoring() == TOP) {
      y_offset = 0.5f * size().height();
      if (!child->bounds_contain_padding())
        y_offset -= top_padding_;
    } else if (child->y_anchoring() == BOTTOM) {
      y_offset = -0.5f * size().height();
      if (!child->bounds_contain_padding())
        y_offset += bottom_padding_;
    }
    child->SetLayoutOffset(x_offset, y_offset);
  }
}

UiElement* UiElement::FirstLaidOutChild() const {
  auto i = std::find_if(
      children_.begin(), children_.end(),
      [](const std::unique_ptr<UiElement>& e) { return e->requires_layout(); });
  return i == children_.end() ? nullptr : i->get();
}

UiElement* UiElement::LastLaidOutChild() const {
  auto i = std::find_if(
      children_.rbegin(), children_.rend(),
      [](const std::unique_ptr<UiElement>& e) { return e->requires_layout(); });
  return i == children_.rend() ? nullptr : i->get();
}

void UiElement::UpdateComputedOpacity() {
  bool was_visible = computed_opacity_ > 0.0f;
  set_computed_opacity(opacity_);
  if (parent_) {
    set_computed_opacity(computed_opacity_ * parent_->computed_opacity());
  }
  set_update_phase(kUpdatedComputedOpacity);
  updated_visibility_this_frame_ = IsVisible() != was_visible;
}

void UiElement::UpdateWorldSpaceTransform(bool parent_changed) {
  if (!IsVisible() && !updated_visibility_this_frame_ &&
      kEnableOptimizedTreeWalks)
    return;

  bool changed = false;
  if (ShouldUpdateWorldSpaceTransform(parent_changed)) {
    gfx::Transform transform;
    transform.Translate(local_origin_.x(), local_origin_.y());

    if (!size_.IsEmpty()) {
      transform.Scale(size_.width(), size_.height());
    }

    // Compute an inheritable transformation that can be applied to this
    // element, and it's children, if applicable.
    gfx::Transform inheritable = LocalTransform();

    if (parent_) {
      inheritable.ConcatTransform(parent_->inheritable_transform());
    }

    transform.ConcatTransform(inheritable);
    set_world_space_transform(transform);
    set_inheritable_transform(inheritable);
    changed = true;
  }

  set_update_phase(kUpdatedWorldSpaceTransform);
  for (auto& child : children_) {
    child->UpdateWorldSpaceTransform(changed);
  }

  OnUpdatedWorldSpaceTransform();
}

gfx::Transform UiElement::LocalTransform() const {
  return local_transform_;
}

gfx::Transform UiElement::GetTargetLocalTransform() const {
  return layout_offset_.Apply() * GetTargetTransform().Apply();
}

const Sounds& UiElement::GetSounds() const {
  return sounds_;
}

bool UiElement::ShouldUpdateWorldSpaceTransform(
    bool parent_transform_changed) const {
  return parent_transform_changed || world_space_transform_dirty_;
}

}  // namespace vr

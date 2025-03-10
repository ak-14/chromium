// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_PLATFORM_GRAPHICS_PAINT_TRANSFORM_PAINT_PROPERTY_NODE_H_
#define THIRD_PARTY_BLINK_RENDERER_PLATFORM_GRAPHICS_PAINT_TRANSFORM_PAINT_PROPERTY_NODE_H_

#include "third_party/blink/renderer/platform/geometry/float_point_3d.h"
#include "third_party/blink/renderer/platform/graphics/compositing_reasons.h"
#include "third_party/blink/renderer/platform/graphics/compositor_element_id.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper_transform_cache.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/scroll_paint_property_node.h"
#include "third_party/blink/renderer/platform/platform_export.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/transforms/transformation_matrix.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

#include <iosfwd>

namespace blink {

// A transform (e.g., created by css "transform" or "perspective", or for
// internal positioning such as paint offset or scrolling) along with a
// reference to the parent TransformPaintPropertyNode. The scroll tree is
// referenced by transform nodes and a transform node with an associated scroll
// node will be a 2d transform for scroll offset.
//
// The transform tree is rooted at a node with no parent. This root node should
// not be modified.
class PLATFORM_EXPORT TransformPaintPropertyNode
    : public PaintPropertyNode<TransformPaintPropertyNode> {
 public:
  // To make it less verbose and more readable to construct and update a node,
  // a struct with default values is used to represent the state.
  struct State {
    TransformationMatrix matrix;
    FloatPoint3D origin;
    bool flattens_inherited_transform = false;
    unsigned rendering_context_id = 0;
    CompositingReasons direct_compositing_reasons = CompositingReason::kNone;
    CompositorElementId compositor_element_id;
    scoped_refptr<const ScrollPaintPropertyNode> scroll;

    bool operator==(const State& o) const {
      return matrix == o.matrix && origin == o.origin &&
             flattens_inherited_transform == o.flattens_inherited_transform &&
             (!RuntimeEnabledFeatures::SlimmingPaintV2Enabled() ||
              (rendering_context_id == o.rendering_context_id &&
               direct_compositing_reasons == o.direct_compositing_reasons &&
               compositor_element_id == o.compositor_element_id)) &&
             scroll == o.scroll;
    }
  };

  // This node is really a sentinel, and does not represent a real transform
  // space.
  static TransformPaintPropertyNode* Root();

  static scoped_refptr<TransformPaintPropertyNode> Create(
      scoped_refptr<const TransformPaintPropertyNode> parent,
      const State& state) {
    return base::AdoptRef(
        new TransformPaintPropertyNode(std::move(parent), state));
  }

  bool Update(scoped_refptr<const TransformPaintPropertyNode> parent,
              const State& state) {
    bool parent_changed = SetParent(parent);
    if (state == state_)
      return parent_changed;

    SetChanged();
    state_ = state;
    Validate();
    return true;
  }

  const TransformationMatrix& Matrix() const { return state_.matrix; }
  const FloatPoint3D& Origin() const { return state_.origin; }

  // The associated scroll node, or nullptr otherwise.
  const ScrollPaintPropertyNode* ScrollNode() const {
    return state_.scroll.get();
  }

  // If this is a scroll offset translation (i.e., has an associated scroll
  // node), returns this. Otherwise, returns the transform node that this node
  // scrolls with respect to. This can require a full ancestor traversal.
  const TransformPaintPropertyNode& NearestScrollTranslationNode() const;

  // If true, content with this transform node (or its descendant) appears in
  // the plane of its parent. This is implemented by flattening the total
  // accumulated transform from its ancestors.
  bool FlattensInheritedTransform() const {
    return state_.flattens_inherited_transform;
  }

  bool HasDirectCompositingReasons() const {
    return state_.direct_compositing_reasons != CompositingReason::kNone;
  }

  bool RequiresCompositingForAnimation() const {
    return state_.direct_compositing_reasons &
           CompositingReason::kComboActiveAnimation;
  }

  const CompositorElementId& GetCompositorElementId() const {
    return state_.compositor_element_id;
  }

  // Content whose transform nodes have a common rendering context ID are 3D
  // sorted. If this is 0, content will not be 3D sorted.
  unsigned RenderingContextId() const { return state_.rendering_context_id; }
  bool HasRenderingContext() const { return state_.rendering_context_id; }

#if DCHECK_IS_ON()
  // The clone function is used by FindPropertiesNeedingUpdate.h for recording
  // a transform node before it has been updated, to later detect changes.
  scoped_refptr<TransformPaintPropertyNode> Clone() const {
    return base::AdoptRef(new TransformPaintPropertyNode(Parent(), state_));
  }

  // The equality operator is used by FindPropertiesNeedingUpdate.h for checking
  // if a transform node has changed.
  bool operator==(const TransformPaintPropertyNode& o) const {
    return Parent() == o.Parent() && state_ == o.state_;
  }
#endif

  std::unique_ptr<JSONObject> ToJSON() const;

 private:
  TransformPaintPropertyNode(
      scoped_refptr<const TransformPaintPropertyNode> parent,
      const State& state)
      : PaintPropertyNode(std::move(parent)), state_(state) {
    Validate();
  }

  void Validate() const {
#if DCHECK_IS_ON()
    if (state_.scroll) {
      // If there is an associated scroll node, this can only be a 2d
      // translation for scroll offset.
      DCHECK(state_.matrix.IsIdentityOr2DTranslation());
      // The scroll compositor element id should be stored on the scroll node.
      DCHECK(!state_.compositor_element_id);
    }
#endif
  }

  // For access to getTransformCache() and setCachedTransform.
  friend class GeometryMapper;
  friend class GeometryMapperTest;
  friend class GeometryMapperTransformCache;

  const GeometryMapperTransformCache& GetTransformCache() const {
    if (!transform_cache_)
      transform_cache_.reset(new GeometryMapperTransformCache);
    transform_cache_->UpdateIfNeeded(*this);
    return *transform_cache_;
  }

  State state_;
  mutable std::unique_ptr<GeometryMapperTransformCache> transform_cache_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_PLATFORM_GRAPHICS_PAINT_TRANSFORM_PAINT_PROPERTY_NODE_H_

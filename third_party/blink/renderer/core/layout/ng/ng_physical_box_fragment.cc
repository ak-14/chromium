// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/ng/ng_physical_box_fragment.h"

#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/ng/ng_outline_utils.h"

namespace blink {

NGPhysicalBoxFragment::NGPhysicalBoxFragment(
    LayoutObject* layout_object,
    const ComputedStyle& style,
    NGPhysicalSize size,
    Vector<scoped_refptr<NGPhysicalFragment>>& children,
    const NGPixelSnappedPhysicalBoxStrut& padding,
    const NGPhysicalOffsetRect& contents_visual_rect,
    Vector<NGBaseline>& baselines,
    NGBoxType box_type,
    bool is_old_layout_root,
    unsigned border_edges,  // NGBorderEdges::Physical
    scoped_refptr<NGBreakToken> break_token)
    : NGPhysicalContainerFragment(layout_object,
                                  style,
                                  size,
                                  kFragmentBox,
                                  box_type,
                                  children,
                                  contents_visual_rect,
                                  std::move(break_token)),
      baselines_(std::move(baselines)),
      padding_(padding) {
  DCHECK(baselines.IsEmpty());  // Ensure move semantics is used.
  is_old_layout_root_ = is_old_layout_root;
  border_edge_ = border_edges;

  // Compute visual contribution from descendant outlines.
  NGOutlineUtils::FragmentMap anchor_fragment_map;
  NGOutlineUtils::OutlineRectMap outline_rect_map;
  NGOutlineUtils::CollectDescendantOutlines(
      *this, NGPhysicalOffset(), &anchor_fragment_map, &outline_rect_map);
  for (auto& anchor_iter : anchor_fragment_map) {
    const NGPhysicalFragment* fragment = anchor_iter.value;
    Vector<LayoutRect>* outline_rects =
        &outline_rect_map.find(anchor_iter.key)->value;
    descendant_outlines_.Unite(NGOutlineUtils::ComputeEnclosingOutline(
        fragment->Style(), *outline_rects));
  }
  GetLayoutObject()->SetOutlineMayBeAffectedByDescendants(
      !descendant_outlines_.IsEmpty());
}

const NGBaseline* NGPhysicalBoxFragment::Baseline(
    const NGBaselineRequest& request) const {
  for (const auto& baseline : baselines_) {
    if (baseline.request == request)
      return &baseline;
  }
  return nullptr;
}

bool NGPhysicalBoxFragment::HasSelfPaintingLayer() const {
  const LayoutObject* layout_object = GetLayoutObject();
  DCHECK(layout_object);
  DCHECK(layout_object->IsBoxModelObject());
  return ToLayoutBoxModelObject(layout_object)->HasSelfPaintingLayer();
}

bool NGPhysicalBoxFragment::ChildrenInline() const {
  const LayoutObject* layout_object = GetLayoutObject();
  DCHECK(layout_object);
  return layout_object->ChildrenInline();
}

bool NGPhysicalBoxFragment::HasOverflowClip() const {
  const LayoutObject* layout_object = GetLayoutObject();
  DCHECK(layout_object);
  return layout_object->HasOverflowClip();
}

bool NGPhysicalBoxFragment::ShouldClipOverflow() const {
  const LayoutObject* layout_object = GetLayoutObject();
  DCHECK(layout_object);
  return layout_object->IsBox() &&
         ToLayoutBox(layout_object)->ShouldClipOverflow();
}

NGPhysicalOffsetRect NGPhysicalBoxFragment::SelfVisualRect() const {
  const ComputedStyle& style = Style();
  LayoutRect visual_rect({}, Size().ToLayoutSize());

  DCHECK(GetLayoutObject());
  if (style.HasVisualOverflowingEffect()) {
    if (GetLayoutObject()->IsBox()) {
      visual_rect.Expand(style.BoxDecorationOutsets());
      if (style.HasOutline()) {
        Vector<LayoutRect> outline_rects;
        // The result rects are in coordinates of this object's border box.
        AddSelfOutlineRects(&outline_rects, LayoutPoint());
        LayoutRect rect = UnionRectEvenIfEmpty(outline_rects);
        rect.Inflate(style.OutlineOutsetExtent());
        visual_rect.Unite(rect);
      }
    } else {
      // TODO(kojii): Implement for inline boxes.
      DCHECK(GetLayoutObject()->IsLayoutInline());
      visual_rect.Expand(style.BoxDecorationOutsets());
    }
  }
  visual_rect.Unite(descendant_outlines_.ToLayoutRect());
  return NGPhysicalOffsetRect(visual_rect);
}

void NGPhysicalBoxFragment::AddSelfOutlineRects(
    Vector<LayoutRect>* outline_rects,
    const LayoutPoint& additional_offset) const {
  DCHECK(outline_rects);
  // TODO(kojii): Implement. This is quite incomplete yet.

  // bool include_block_visual_overflow =
  // layout_object->OutlineRectsShouldIncludeBlockVisualOverflow();

  //
  LayoutRect outline_rect(additional_offset, Size().ToLayoutSize());
  // LayoutRect outline_rect = VisualRect();
  // outline_rect.MoveBy(additional_offset);
  // outline_rect.Inflate(-Style().OutlineOffset());
  // outline_rect.Inflate(-Style().OutlineWidth());

  outline_rects->push_back(outline_rect);
}

NGPhysicalOffsetRect NGPhysicalBoxFragment::VisualRectWithContents() const {
  if (HasOverflowClip() || Style().HasMask())
    return SelfVisualRect();

  NGPhysicalOffsetRect visual_rect = SelfVisualRect();
  visual_rect.Unite(ContentsVisualRect());
  return visual_rect;
}

PositionWithAffinity NGPhysicalBoxFragment::PositionForPoint(
    const NGPhysicalOffset& point) const {
  if (!IsBlockFlow())
    return PositionForPointInInlineLevelBox(point);

  return PositionForPointInInlineFormattingContext(point);
}

scoped_refptr<NGPhysicalFragment> NGPhysicalBoxFragment::CloneWithoutOffset()
    const {
  Vector<scoped_refptr<NGPhysicalFragment>> children_copy(children_);
  Vector<NGBaseline> baselines_copy(baselines_);
  scoped_refptr<NGPhysicalFragment> physical_fragment =
      base::AdoptRef(new NGPhysicalBoxFragment(
          layout_object_, Style(), size_, children_copy, padding_,
          contents_visual_rect_, baselines_copy, BoxType(), is_old_layout_root_,
          border_edge_, break_token_));
  return physical_fragment;
}

}  // namespace blink

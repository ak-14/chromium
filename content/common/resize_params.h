// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_RESIZE_PARAMS_H_
#define CONTENT_COMMON_RESIZE_PARAMS_H_

#include "base/optional.h"
#include "components/viz/common/surfaces/local_surface_id.h"
#include "content/common/content_export.h"
#include "content/public/common/screen_info.h"
#include "third_party/blink/public/platform/web_display_mode.h"
#include "ui/gfx/geometry/size.h"

namespace content {

struct CONTENT_EXPORT ResizeParams {
  ResizeParams();
  ResizeParams(const ResizeParams& other);
  ~ResizeParams();

  ResizeParams& operator=(const ResizeParams& other);

  // Information about the screen (dpi, depth, etc..).
  ScreenInfo screen_info;

  // Whether or not blink should be in auto-resize mode.
  bool auto_resize_enabled = false;

  // The minimum size for Blink if auto-resize is enabled.
  gfx::Size min_size_for_auto_resize;

  // The maximum size for Blink if auto-resize is enabled.
  gfx::Size max_size_for_auto_resize;

  // This variable is increased after each auto-resize. If the
  // renderer receives a ResizeParams with stale auto_resize_seqence_number,
  // then the resize request is dropped.
  uint64_t auto_resize_sequence_number = 0u;

  // The size for the widget in DIPs.
  gfx::Size new_size;

  // The size of compositor's viewport in pixels. Note that this may differ
  // from a ScaleToCeiledSize of |new_size| due to Android's keyboard or due
  // to rounding particulars.
  gfx::Size compositor_viewport_pixel_size;

  // Whether or not Blink's viewport size should be shrunk by the height of the
  // URL-bar (always false on platforms where URL-bar hiding isn't supported).
  bool browser_controls_shrink_blink_size = false;

  // Whether or not the focused node should be scrolled into view after the
  // resize.
  bool scroll_focused_node_into_view = false;

  // The height of the top controls (always 0 on platforms where URL-bar hiding
  // isn't supported).
  float top_controls_height = 0.f;

  // The height of the bottom controls.
  float bottom_controls_height = 0.f;

  // The local surface ID to use (if valid).
  base::Optional<viz::LocalSurfaceId> local_surface_id;

  // The size of the visible viewport, which may be smaller than the view if the
  // view is partially occluded (e.g. by a virtual keyboard).  The size is in
  // DPI-adjusted pixels.
  gfx::Size visible_viewport_size;

  // Indicates whether tab-initiated fullscreen was granted.
  bool is_fullscreen_granted = false;

  // The display mode.
  blink::WebDisplayMode display_mode = blink::kWebDisplayModeUndefined;

  // If set, requests the renderer to reply with a
  // ViewHostMsg_ResizeOrRepaint_ACK with the
  // ViewHostMsg_ResizeOrRepaint_ACK_Flags::IS_RESIZE_ACK bit set in flags.
  bool needs_resize_ack = false;

  // This variable is increased after each cross-document navigation. If the
  // renderer receives a ResizeParams with stale content_source_id, it still
  // performs the resize but doesn't use the given LocalSurfaceId.
  uint32_t content_source_id = 0u;

  // This represents the latest capture sequence number requested. When this is
  // incremented, that means the caller wants to synchronize surfaces which
  // should cause a new LocalSurfaceId to be generated.
  uint32_t capture_sequence_number = 0u;
};

}  // namespace content

#endif  // CONTENT_COMMON_RESIZE_PARAMS_H_

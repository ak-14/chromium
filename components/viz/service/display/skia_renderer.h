// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_VIZ_SERVICE_DISPLAY_SKIA_RENDERER_H_
#define COMPONENTS_VIZ_SERVICE_DISPLAY_SKIA_RENDERER_H_

#include "base/macros.h"
#include "cc/cc_export.h"
#include "components/viz/service/display/direct_renderer.h"
#include "components/viz/service/display/sync_query_collection.h"
#include "components/viz/service/viz_service_export.h"
#include "gpu/vulkan/buildflags.h"
#include "ui/latency/latency_info.h"

class SkNWayCanvas;

namespace cc {
class OutputSurface;
class RenderPassDrawQuad;
}  // namespace cc

namespace viz {
class DebugBorderDrawQuad;
class PictureDrawQuad;
class SolidColorDrawQuad;
class TextureDrawQuad;
class TileDrawQuad;

class VIZ_SERVICE_EXPORT SkiaRenderer : public DirectRenderer {
 public:
  SkiaRenderer(const RendererSettings* settings,
               OutputSurface* output_surface,
               cc::DisplayResourceProvider* resource_provider);

  ~SkiaRenderer() override;

  void SwapBuffers(std::vector<ui::LatencyInfo> latency_info) override;

  void SetDisablePictureQuadImageFiltering(bool disable) {
    disable_picture_quad_image_filtering_ = disable;
  }

 protected:
  bool CanPartialSwap() override;
  void UpdateRenderPassTextures(
      const RenderPassList& render_passes_in_draw_order,
      const base::flat_map<RenderPassId, RenderPassRequirements>&
          render_passes_in_frame) override;
  void AllocateRenderPassResourceIfNeeded(
      const RenderPassId& render_pass_id,
      const RenderPassRequirements& requirements) override;
  bool IsRenderPassResourceAllocated(
      const RenderPassId& render_pass_id) const override;
  gfx::Size GetRenderPassBackingPixelSize(
      const RenderPassId& render_pass_id) override;
  void BindFramebufferToOutputSurface() override;
  void BindFramebufferToTexture(const RenderPassId render_pass_id) override;
  void SetScissorTestRect(const gfx::Rect& scissor_rect) override;
  void PrepareSurfaceForPass(SurfaceInitializationMode initialization_mode,
                             const gfx::Rect& render_pass_scissor) override;
  void DoDrawQuad(const DrawQuad* quad, const gfx::QuadF* draw_region) override;
  void BeginDrawingFrame() override;
  void FinishDrawingFrame() override;
  bool FlippedFramebuffer() const override;
  void EnsureScissorTestEnabled() override;
  void EnsureScissorTestDisabled() override;
  void CopyDrawnRenderPass(std::unique_ptr<CopyOutputRequest> request) override;
  void SetEnableDCLayers(bool enable) override;
  void DidChangeVisibility() override;
  void FinishDrawingQuadList() override;
  void GenerateMipmap() override;

 private:
  struct DrawRenderPassDrawQuadParams;

  void ClearCanvas(SkColor color);
  void ClearFramebuffer();
  void SetClipRect(const gfx::Rect& rect);

  void DrawDebugBorderQuad(const DebugBorderDrawQuad* quad);
  void DrawPictureQuad(const PictureDrawQuad* quad);
  void DrawRenderPassQuad(const RenderPassDrawQuad* quad);
  void DrawSolidColorQuad(const SolidColorDrawQuad* quad);
  void DrawTextureQuad(const TextureDrawQuad* quad);
  void DrawTileQuad(const TileDrawQuad* quad);
  void DrawUnsupportedQuad(const DrawQuad* quad);
  bool CalculateRPDQParams(sk_sp<SkImage> src_image,
                           const RenderPassDrawQuad* quad,
                           DrawRenderPassDrawQuadParams* params);

  bool ShouldApplyBackgroundFilters(
      const RenderPassDrawQuad* quad,
      const cc::FilterOperations* background_filters) const;
  gfx::Rect GetBackdropBoundingBoxForRenderPassQuad(
      const RenderPassDrawQuad* quad,
      const gfx::Transform& contents_device_transform,
      const cc::FilterOperations* background_filters,
      gfx::Rect* unclipped_rect) const;
  sk_sp<SkImage> ApplyBackgroundFilters(SkImageFilter* filter,
                                        const RenderPassDrawQuad* quad,
                                        sk_sp<SkImage> src_image,
                                        const gfx::Rect& rect) const;

  sk_sp<SkImage> GetBackdropImage(const gfx::Rect& bounding_rect) const;
  sk_sp<SkShader> GetBackgroundFilterShader(
      const RenderPassDrawQuad* quad,
      SkShader::TileMode content_tile_mode) const;

  // A map from RenderPass id to the texture used to draw the RenderPass from.
  struct RenderPassBacking {
    sk_sp<SkSurface> render_pass_surface;
    bool mipmap;
    gfx::ColorSpace color_space;
    RenderPassBacking(GrContext* gr_context,
                      const gfx::Size& size,
                      bool mipmap,
                      bool capability_bgra8888,
                      const gfx::ColorSpace& color_space);
    ~RenderPassBacking();
    RenderPassBacking(RenderPassBacking&&);
    RenderPassBacking& operator=(RenderPassBacking&&);
  };
  base::flat_map<RenderPassId, RenderPassBacking> render_pass_backings_;

  bool disable_picture_quad_image_filtering_ = false;

  bool is_scissor_enabled_ = false;
  gfx::Rect scissor_rect_;

  sk_sp<SkSurface> root_surface_;
  sk_sp<SkSurface> non_root_surface_;
  sk_sp<SkSurface> overdraw_surface_;
  std::unique_ptr<SkCanvas> overdraw_canvas_;
  std::unique_ptr<SkNWayCanvas> nway_canvas_;
  SkCanvas* root_canvas_ = nullptr;
  SkCanvas* current_canvas_ = nullptr;
  SkSurface* current_surface_ = nullptr;
  SkPaint current_paint_;

  base::Optional<SyncQueryCollection> sync_queries_;
  bool use_swap_with_bounds_ = false;

  gfx::Rect swap_buffer_rect_;
  std::vector<gfx::Rect> swap_content_bounds_;

  DISALLOW_COPY_AND_ASSIGN(SkiaRenderer);
};

}  // namespace viz

#endif  // COMPONENTS_VIZ_SERVICE_DISPLAY_SKIA_RENDERER_H_

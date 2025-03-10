// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_VR_TEST_FAKE_UI_ELEMENT_RENDERER_H_
#define CHROME_BROWSER_VR_TEST_FAKE_UI_ELEMENT_RENDERER_H_

#include "base/macros.h"
#include "chrome/browser/vr/ui_element_renderer.h"

namespace vr {

class FakeUiElementRenderer : public UiElementRenderer {
 public:
  FakeUiElementRenderer();
  ~FakeUiElementRenderer() override;

  bool called() const { return called_; }
  float opacity() const { return opacity_; }

  void DrawTexturedQuad(int texture_data_handle,
                        int overlay_texture_data_handle,
                        TextureLocation texture_location,
                        const gfx::Transform& view_proj_matrix,
                        const gfx::RectF& copy_rect,
                        float opacity,
                        const gfx::SizeF& element_size,
                        float corner_radius,
                        bool blend) override;

  void DrawGradientQuad(const gfx::Transform& view_proj_matrix,
                        const SkColor edge_color,
                        const SkColor center_color,
                        float opacity,
                        const gfx::SizeF& element_size,
                        const CornerRadii& corner_radii) override;

  void DrawGradientGridQuad(const gfx::Transform& view_proj_matrix,
                            const SkColor edge_color,
                            const SkColor center_color,
                            const SkColor grid_color,
                            int gridline_count,
                            float opacity) override;

  void DrawController(float opacity,
                      const gfx::Transform& model_view_proj_matrix) override;

  void DrawLaser(float opacity,
                 const gfx::Transform& view_proj_matrix) override;

  void DrawReticle(float opacity,
                   const gfx::Transform& view_proj_matrix) override;

  void DrawShadow(const gfx::Transform& model_view_proj_matrix,
                  const gfx::SizeF& element_size,
                  float x_padding,
                  float y_padding,
                  float y_offset,
                  SkColor color,
                  float opacity,
                  float corner_radius) override;

  void DrawStars(float t,
                 const gfx::Transform& model_view_proj_matrix) override;

 private:
  float opacity_ = -1.f;
  float called_ = false;

  DISALLOW_COPY_AND_ASSIGN(FakeUiElementRenderer);
};

}  // namespace vr

#endif  // CHROME_BROWSER_VR_TEST_FAKE_UI_ELEMENT_RENDERER_H_

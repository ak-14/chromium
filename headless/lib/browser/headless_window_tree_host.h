// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HEADLESS_LIB_BROWSER_HEADLESS_WINDOW_TREE_HOST_H_
#define HEADLESS_LIB_BROWSER_HEADLESS_WINDOW_TREE_HOST_H_

#if defined(USE_AURA)

#include <memory>

#include "base/macros.h"
#include "ui/aura/window_tree_host.h"
#include "ui/events/platform/platform_event_dispatcher.h"
#include "ui/gfx/geometry/rect.h"

namespace aura {
namespace client {
class FocusClient;
class WindowParentingClient;
}
}

namespace headless {

class HeadlessWindowTreeHost : public aura::WindowTreeHost,
                               public ui::PlatformEventDispatcher {
 public:
  HeadlessWindowTreeHost(const gfx::Rect& bounds,
                         bool external_begin_frames_enabled);
  ~HeadlessWindowTreeHost() override;

  void SetParentWindow(gfx::NativeWindow window);

  // ui::PlatformEventDispatcher:
  bool CanDispatchEvent(const ui::PlatformEvent& event) override;
  uint32_t DispatchEvent(const ui::PlatformEvent& event) override;

  // WindowTreeHost:
  ui::EventSource* GetEventSource() override;
  gfx::AcceleratedWidget GetAcceleratedWidget() override;
  void ShowImpl() override;
  void HideImpl() override;
  gfx::Rect GetBoundsInPixels() const override;
  void SetBoundsInPixels(const gfx::Rect& bounds,
                         const viz::LocalSurfaceId& local_surface_id) override;
  gfx::Point GetLocationOnScreenInPixels() const override;
  void SetCapture() override;
  void ReleaseCapture() override;
  bool CaptureSystemKeyEventsImpl(
      base::Optional<base::flat_set<int>> keys) override;
  void ReleaseSystemKeyEventCapture() override;
  bool IsKeyLocked(int native_key_code) override;
  void SetCursorNative(gfx::NativeCursor cursor_type) override;
  void MoveCursorToScreenLocationInPixels(const gfx::Point& location) override;
  void OnCursorVisibilityChangedNative(bool show) override;

 private:
  gfx::Rect bounds_;
  std::unique_ptr<aura::client::FocusClient> focus_client_;
  std::unique_ptr<aura::client::WindowParentingClient> window_parenting_client_;

  DISALLOW_COPY_AND_ASSIGN(HeadlessWindowTreeHost);
};

}  // namespace headless

#else   // defined(USE_AURA)
class HeadlessWindowTreeHost {};
#endif  // defined(USE_AURA)

#endif  // HEADLESS_LIB_BROWSER_HEADLESS_WINDOW_TREE_HOST_H_

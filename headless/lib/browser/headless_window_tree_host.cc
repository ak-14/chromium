// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "headless/lib/browser/headless_window_tree_host.h"

#include "base/containers/flat_set.h"
#include "components/viz/common/surfaces/frame_sink_id.h"
#include "headless/lib/browser/headless_focus_client.h"
#include "headless/lib/browser/headless_window_parenting_client.h"
#include "ui/aura/window.h"
#include "ui/gfx/icc_profile.h"

namespace headless {

HeadlessWindowTreeHost::HeadlessWindowTreeHost(
    const gfx::Rect& bounds,
    bool external_begin_frames_enabled)
    : bounds_(bounds) {
  CreateCompositor(viz::FrameSinkId(), false, external_begin_frames_enabled);
  OnAcceleratedWidgetAvailable();

  focus_client_.reset(new HeadlessFocusClient());
  aura::client::SetFocusClient(window(), focus_client_.get());
}

HeadlessWindowTreeHost::~HeadlessWindowTreeHost() {
  window_parenting_client_.reset();
  DestroyCompositor();
  DestroyDispatcher();
}

void HeadlessWindowTreeHost::SetParentWindow(gfx::NativeWindow window) {
  window_parenting_client_.reset(new HeadlessWindowParentingClient(window));
}

bool HeadlessWindowTreeHost::CanDispatchEvent(const ui::PlatformEvent& event) {
  return false;
}

uint32_t HeadlessWindowTreeHost::DispatchEvent(const ui::PlatformEvent& event) {
  return 0;
}

ui::EventSource* HeadlessWindowTreeHost::GetEventSource() {
  return this;
}

gfx::AcceleratedWidget HeadlessWindowTreeHost::GetAcceleratedWidget() {
  return gfx::AcceleratedWidget();
}

gfx::Rect HeadlessWindowTreeHost::GetBoundsInPixels() const {
  return bounds_;
}

void HeadlessWindowTreeHost::SetBoundsInPixels(
    const gfx::Rect& bounds,
    const viz::LocalSurfaceId& local_surface_id) {
  bool origin_changed = bounds_.origin() != bounds.origin();
  bool size_changed = bounds_.size() != bounds.size();
  bounds_ = bounds;
  if (origin_changed)
    OnHostMovedInPixels(bounds.origin());
  if (size_changed)
    OnHostResizedInPixels(bounds.size(), local_surface_id);
}

void HeadlessWindowTreeHost::ShowImpl() {}

void HeadlessWindowTreeHost::HideImpl() {}

gfx::Point HeadlessWindowTreeHost::GetLocationOnScreenInPixels() const {
  return gfx::Point();
}

void HeadlessWindowTreeHost::SetCapture() {}

void HeadlessWindowTreeHost::ReleaseCapture() {}

bool HeadlessWindowTreeHost::CaptureSystemKeyEventsImpl(
    base::Optional<base::flat_set<int>> keys) {
  return false;
}

void HeadlessWindowTreeHost::ReleaseSystemKeyEventCapture() {}

bool HeadlessWindowTreeHost::IsKeyLocked(int native_key_code) {
  return false;
}

void HeadlessWindowTreeHost::SetCursorNative(gfx::NativeCursor cursor_type) {}

void HeadlessWindowTreeHost::MoveCursorToScreenLocationInPixels(
    const gfx::Point& location) {}

void HeadlessWindowTreeHost::OnCursorVisibilityChangedNative(bool show) {}

}  // namespace headless

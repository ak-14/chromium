// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_UI_WS2_TEST_WINDOW_TREE_CLIENT_H_
#define SERVICES_UI_WS2_TEST_WINDOW_TREE_CLIENT_H_

#include "base/component_export.h"
#include "base/macros.h"
#include "services/ui/public/interfaces/window_tree.mojom.h"
#include "services/ui/ws2/test_change_tracker.h"

namespace ui {
namespace ws2 {

// WindowTreeClient implementation that logs all changes to a tracker.
class TestWindowTreeClient : public mojom::WindowTreeClient,
                             public TestChangeTracker::Delegate {
 public:
  TestWindowTreeClient();
  ~TestWindowTreeClient() override;

  mojom::WindowTree* tree() { return tree_.get(); }
  TestChangeTracker* tracker() { return &tracker_; }
  Id root_window_id() const { return root_window_id_; }

  // Sets whether changes to the bounds of the root should be tracked. Normally
  // they are ignored (as during startup we often times get random size
  // changes).
  void set_track_root_bounds_changes(bool value) {
    track_root_bounds_changes_ = value;
  }

  // TestChangeTracker::Delegate:
  void OnChangeAdded() override;

  // mojom::WindowTreeClient:
  void OnEmbed(
      mojom::WindowDataPtr root,
      mojom::WindowTreePtr tree,
      int64_t display_id,
      Id focused_window_id,
      bool drawn,
      const base::Optional<viz::LocalSurfaceId>& local_surface_id) override;
  void OnEmbedFromToken(
      const base::UnguessableToken& token,
      mojom::WindowDataPtr root,
      int64_t display_id,
      const base::Optional<viz::LocalSurfaceId>& local_surface_id) override;
  void OnEmbeddedAppDisconnected(Id window_id) override;
  void OnUnembed(Id window_id) override;
  void OnCaptureChanged(Id new_capture_window_id,
                        Id old_capture_window_id) override;
  void OnFrameSinkIdAllocated(Id window_id,
                              const viz::FrameSinkId& frame_sink_id) override;
  void OnTopLevelCreated(
      uint32_t change_id,
      mojom::WindowDataPtr data,
      int64_t display_id,
      bool drawn,
      const base::Optional<viz::LocalSurfaceId>& local_surface_id) override;
  void OnWindowBoundsChanged(
      Id window_id,
      const gfx::Rect& old_bounds,
      const gfx::Rect& new_bounds,
      const base::Optional<viz::LocalSurfaceId>& local_surface_id) override;
  void OnWindowTransformChanged(Id window_id,
                                const gfx::Transform& old_transform,
                                const gfx::Transform& new_transform) override;
  void OnClientAreaChanged(
      Id window_id,
      const gfx::Insets& new_client_area,
      const std::vector<gfx::Rect>& new_additional_client_areas) override;
  void OnTransientWindowAdded(Id window_id, Id transient_window_id) override;
  void OnTransientWindowRemoved(Id window_id, Id transient_window_id) override;
  void OnWindowHierarchyChanged(
      Id window,
      Id old_parent,
      Id new_parent,
      std::vector<mojom::WindowDataPtr> windows) override;
  void OnWindowReordered(Id window_id,
                         Id relative_window_id,
                         mojom::OrderDirection direction) override;
  void OnWindowDeleted(Id window) override;
  void OnWindowVisibilityChanged(Id window, bool visible) override;
  void OnWindowOpacityChanged(Id window,
                              float old_opacity,
                              float new_opacity) override;
  void OnWindowParentDrawnStateChanged(Id window, bool drawn) override;
  void OnWindowInputEvent(
      uint32_t event_id,
      Id window_id,
      int64_t display_id,
      Id display_root_window_id,
      const gfx::PointF& event_location_in_screen_pixel_layout,
      std::unique_ptr<ui::Event> event,
      bool matches_pointer_watcher) override;
  void OnPointerEventObserved(std::unique_ptr<ui::Event>,
                              Id window_id,
                              int64_t display_id) override;
  void OnWindowSharedPropertyChanged(
      Id window,
      const std::string& name,
      const base::Optional<std::vector<uint8_t>>& new_data) override;
  void OnWindowFocused(Id focused_window_id) override;
  void OnWindowCursorChanged(Id window_id, ui::CursorData cursor) override;
  void OnDragDropStart(
      const std::unordered_map<std::string, std::vector<uint8_t>>& drag_data)
      override;
  void OnWindowSurfaceChanged(Id window_id,
                              const viz::SurfaceInfo& surface_info) override;
  void OnDragEnter(Id window,
                   uint32_t key_state,
                   const gfx::Point& position,
                   uint32_t effect_bitmask,
                   OnDragEnterCallback callback) override;
  void OnDragOver(Id window,
                  uint32_t key_state,
                  const gfx::Point& position,
                  uint32_t effect_bitmask,
                  OnDragOverCallback callback) override;
  void OnDragLeave(Id window) override;
  void OnCompleteDrop(Id window,
                      uint32_t key_state,
                      const gfx::Point& position,
                      uint32_t effect_bitmask,
                      OnCompleteDropCallback callback) override;
  void OnPerformDragDropCompleted(uint32_t change_id,
                                  bool success,
                                  uint32_t action_taken) override;
  void OnDragDropDone() override;
  void OnChangeCompleted(uint32_t change_id, bool success) override;
  void RequestClose(Id window_id) override;
  void GetWindowManager(
      mojo::AssociatedInterfaceRequest<mojom::WindowManager> internal) override;

 protected:
  TestChangeTracker tracker_;
  mojom::WindowTreePtr tree_;
  Id root_window_id_ = 0;
  bool track_root_bounds_changes_ = false;

  DISALLOW_COPY_AND_ASSIGN(TestWindowTreeClient);
};

}  // namespace ws2
}  // namespace ui

#endif  // SERVICES_UI_WS2_TEST_WINDOW_TREE_CLIENT_H_

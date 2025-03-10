// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/viz/service/frame_sinks/direct_layer_tree_frame_sink.h"

#include <memory>

#include "base/bind.h"
#include "cc/trees/layer_tree_frame_sink_client.h"
#include "components/viz/common/quads/compositor_frame.h"
#include "components/viz/common/quads/draw_quad.h"
#include "components/viz/common/quads/surface_draw_quad.h"
#include "components/viz/common/surfaces/frame_sink_id.h"
#include "components/viz/common/surfaces/parent_local_surface_id_allocator.h"
#include "components/viz/service/display/display.h"
#include "components/viz/service/frame_sinks/compositor_frame_sink_support_manager.h"
#include "components/viz/service/frame_sinks/frame_sink_manager_impl.h"
#include "components/viz/service/surfaces/surface.h"

namespace viz {

DirectLayerTreeFrameSink::DirectLayerTreeFrameSink(
    const FrameSinkId& frame_sink_id,
    CompositorFrameSinkSupportManager* support_manager,
    FrameSinkManagerImpl* frame_sink_manager,
    Display* display,
    mojom::DisplayClient* display_client,
    scoped_refptr<ContextProvider> context_provider,
    scoped_refptr<RasterContextProvider> worker_context_provider,
    scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
    gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
    bool use_viz_hit_test)
    : LayerTreeFrameSink(std::move(context_provider),
                         std::move(worker_context_provider),
                         std::move(compositor_task_runner),
                         gpu_memory_buffer_manager),
      frame_sink_id_(frame_sink_id),
      support_manager_(support_manager),
      frame_sink_manager_(frame_sink_manager),
      display_(display),
      display_client_(display_client),
      use_viz_hit_test_(use_viz_hit_test),
      weak_factory_(this) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  capabilities_.must_always_swap = true;
  // Display and DirectLayerTreeFrameSink share a GL context, so sync
  // points aren't needed when passing resources between them.
  capabilities_.delegated_sync_points_required = false;
}

DirectLayerTreeFrameSink::~DirectLayerTreeFrameSink() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

bool DirectLayerTreeFrameSink::BindToClient(
    cc::LayerTreeFrameSinkClient* client) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!cc::LayerTreeFrameSink::BindToClient(client))
    return false;

  constexpr bool is_root = true;
  support_ = support_manager_->CreateCompositorFrameSinkSupport(
      this, frame_sink_id_, is_root,
      capabilities_.delegated_sync_points_required);
  begin_frame_source_ = std::make_unique<ExternalBeginFrameSource>(this);
  client_->SetBeginFrameSource(begin_frame_source_.get());

  // Avoid initializing GL context here, as this should be sharing the
  // Display's context.
  display_->Initialize(this, frame_sink_manager_->surface_manager());

  if (use_viz_hit_test_)
    support_->SetUpHitTest(display_);

  return true;
}

void DirectLayerTreeFrameSink::DetachFromClient() {
  client_->SetBeginFrameSource(nullptr);
  begin_frame_source_.reset();

  // Unregister the SurfaceFactoryClient here instead of the dtor so that only
  // one client is alive for this namespace at any given time.
  support_.reset();

  cc::LayerTreeFrameSink::DetachFromClient();
}

void DirectLayerTreeFrameSink::SubmitCompositorFrame(CompositorFrame frame) {
  DCHECK(frame.metadata.begin_frame_ack.has_damage);
  DCHECK_LE(BeginFrameArgs::kStartingFrameNumber,
            frame.metadata.begin_frame_ack.sequence_number);

  if (!local_surface_id_.is_valid() ||
      frame.size_in_pixels() != last_swap_frame_size_ ||
      frame.device_scale_factor() != device_scale_factor_) {
    local_surface_id_ = parent_local_surface_id_allocator_.GenerateId();
    last_swap_frame_size_ = frame.size_in_pixels();
    device_scale_factor_ = frame.device_scale_factor();
    display_->SetLocalSurfaceId(local_surface_id_, device_scale_factor_);
  }

  auto hit_test_region_list = CreateHitTestData(frame);
  support_->SubmitCompositorFrame(local_surface_id_, std::move(frame),
                                  std::move(hit_test_region_list));
}

void DirectLayerTreeFrameSink::DidNotProduceFrame(const BeginFrameAck& ack) {
  DCHECK(!ack.has_damage);
  DCHECK_LE(BeginFrameArgs::kStartingFrameNumber, ack.sequence_number);
  support_->DidNotProduceFrame(ack);
}

void DirectLayerTreeFrameSink::DidAllocateSharedBitmap(
    mojo::ScopedSharedBufferHandle buffer,
    const SharedBitmapId& id) {
  bool ok = support_->DidAllocateSharedBitmap(std::move(buffer), id);
  DCHECK(ok);
}

void DirectLayerTreeFrameSink::DidDeleteSharedBitmap(const SharedBitmapId& id) {
  support_->DidDeleteSharedBitmap(id);
}

void DirectLayerTreeFrameSink::DisplayOutputSurfaceLost() {
  is_lost_ = true;
  client_->DidLoseLayerTreeFrameSink();
}

void DirectLayerTreeFrameSink::DisplayWillDrawAndSwap(
    bool will_draw_and_swap,
    const RenderPassList& render_passes) {
  if (support_->GetHitTestAggregator())
    support_->GetHitTestAggregator()->Aggregate(display_->CurrentSurfaceId());
}

void DirectLayerTreeFrameSink::DisplayDidDrawAndSwap() {
  // This notification is not relevant to our client outside of tests. We
  // unblock the client from DidDrawCallback() when the surface is going to
  // be drawn.
}

void DirectLayerTreeFrameSink::DisplayDidReceiveCALayerParams(
    const gfx::CALayerParams& ca_layer_params) {
  // If |ca_layer_params| should have content only when there exists a client
  // to send it to.
  DCHECK(ca_layer_params.is_empty || display_client_);
  if (display_client_)
    display_client_->OnDisplayReceivedCALayerParams(ca_layer_params);
}

void DirectLayerTreeFrameSink::DidReceiveCompositorFrameAck(
    const std::vector<ReturnedResource>& resources) {
  // Submitting a CompositorFrame can synchronously draw and dispatch a frame
  // ack. PostTask to ensure the client is notified on a new stack frame.
  compositor_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &DirectLayerTreeFrameSink::DidReceiveCompositorFrameAckInternal,
          weak_factory_.GetWeakPtr(), resources));
}

void DirectLayerTreeFrameSink::DidReceiveCompositorFrameAckInternal(
    const std::vector<ReturnedResource>& resources) {
  client_->ReclaimResources(resources);
  client_->DidReceiveCompositorFrameAck();
}

void DirectLayerTreeFrameSink::DidPresentCompositorFrame(
    uint32_t presentation_token,
    base::TimeTicks time,
    base::TimeDelta refresh,
    uint32_t flags) {
  client_->DidPresentCompositorFrame(presentation_token, time, refresh, flags);
}

void DirectLayerTreeFrameSink::DidDiscardCompositorFrame(
    uint32_t presentation_token) {
  client_->DidDiscardCompositorFrame(presentation_token);
}

void DirectLayerTreeFrameSink::OnBeginFrame(const BeginFrameArgs& args) {
  begin_frame_source_->OnBeginFrame(args);
}

void DirectLayerTreeFrameSink::ReclaimResources(
    const std::vector<ReturnedResource>& resources) {
  client_->ReclaimResources(resources);
}

void DirectLayerTreeFrameSink::OnBeginFramePausedChanged(bool paused) {
  begin_frame_source_->OnSetBeginFrameSourcePaused(paused);
}

void DirectLayerTreeFrameSink::OnNeedsBeginFrames(bool needs_begin_frame) {
  support_->SetNeedsBeginFrame(needs_begin_frame);
}

void DirectLayerTreeFrameSink::OnContextLost() {
  // The display will be listening for OnContextLost(). Do nothing here.
}

mojom::HitTestRegionListPtr DirectLayerTreeFrameSink::CreateHitTestData(
    const CompositorFrame& frame) const {
  auto hit_test_region_list = mojom::HitTestRegionList::New();
  hit_test_region_list->flags =
      mojom::kHitTestMouse | mojom::kHitTestTouch | mojom::kHitTestMine;
  hit_test_region_list->bounds.set_size(frame.size_in_pixels());

  for (const auto& render_pass : frame.render_pass_list) {
    // Skip the render_pass if the transform is not invertible (i.e. it will not
    // be able to receive events).
    gfx::Transform transform_from_root_target;
    if (!render_pass->transform_to_root_target.GetInverse(
            &transform_from_root_target)) {
      continue;
    }

    for (const DrawQuad* quad : render_pass->quad_list) {
      if (quad->material == DrawQuad::SURFACE_CONTENT) {
        const SurfaceDrawQuad* surface_quad =
            SurfaceDrawQuad::MaterialCast(quad);

        // Skip the quad if the FrameSinkId between fallback and primary is not
        // the same, because we don't know which FrameSinkId would be used to
        // draw this quad.
        if (surface_quad->fallback_surface_id.has_value() &&
            surface_quad->fallback_surface_id->frame_sink_id() !=
                surface_quad->primary_surface_id.frame_sink_id()) {
          continue;
        }

        // Skip the quad if the transform is not invertible (i.e. it will not
        // be able to receive events).
        gfx::Transform target_to_quad_transform;
        if (!quad->shared_quad_state->quad_to_target_transform.GetInverse(
                &target_to_quad_transform)) {
          continue;
        }

        auto hit_test_region = mojom::HitTestRegion::New();
        hit_test_region->frame_sink_id =
            surface_quad->primary_surface_id.frame_sink_id();
        hit_test_region->flags = mojom::kHitTestMouse | mojom::kHitTestTouch |
                                 mojom::kHitTestChildSurface;
        hit_test_region->rect = surface_quad->rect;
        hit_test_region->transform =
            target_to_quad_transform * transform_from_root_target;
        hit_test_region_list->regions.push_back(std::move(hit_test_region));
      }
    }
  }
  return hit_test_region_list;
}

}  // namespace viz

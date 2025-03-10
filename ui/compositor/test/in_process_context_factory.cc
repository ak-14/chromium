// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/compositor/test/in_process_context_factory.h"

#include <limits>
#include <utility>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/threading/thread.h"
#include "cc/base/switches.h"
#include "cc/test/pixel_test_output_surface.h"
#include "components/viz/common/frame_sinks/begin_frame_source.h"
#include "components/viz/common/frame_sinks/delay_based_time_source.h"
#include "components/viz/common/gpu/context_provider.h"
#include "components/viz/common/surfaces/parent_local_surface_id_allocator.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/service/display/display.h"
#include "components/viz/service/display/display_scheduler.h"
#include "components/viz/service/display/output_surface_client.h"
#include "components/viz/service/display/output_surface_frame.h"
#include "components/viz/service/frame_sinks/direct_layer_tree_frame_sink.h"
#include "components/viz/service/frame_sinks/frame_sink_manager_impl.h"
#include "gpu/command_buffer/client/context_support.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/common/context_creation_attribs.h"
#include "ui/compositor/compositor_switches.h"
#include "ui/compositor/layer.h"
#include "ui/compositor/reflector.h"
#include "ui/compositor/test/in_process_context_provider.h"
#include "ui/display/display_switches.h"
#include "ui/gfx/presentation_feedback.h"
#include "ui/gfx/switches.h"
#include "ui/gl/gl_implementation.h"
#include "ui/gl/gl_utils.h"
#include "ui/gl/test/gl_surface_test_support.h"

#if !defined(GPU_SURFACE_HANDLE_IS_ACCELERATED_WINDOW)
#include "gpu/ipc/common/gpu_surface_tracker.h"
#endif

namespace ui {
namespace {
// The client_id used here should not conflict with the client_id generated
// from RenderWidgetHostImpl and client_id(0) used by aura::WindowPortMus.
constexpr uint32_t kDefaultClientId = std::numeric_limits<uint32_t>::max();

class FakeReflector : public Reflector {
 public:
  FakeReflector() {}
  ~FakeReflector() override {}
  void OnMirroringCompositorResized() override {}
  void AddMirroringLayer(Layer* layer) override {}
  void RemoveMirroringLayer(Layer* layer) override {}
};

// An OutputSurface implementation that directly draws and swaps to an actual
// GL surface.
class DirectOutputSurface : public viz::OutputSurface {
 public:
  explicit DirectOutputSurface(
      scoped_refptr<InProcessContextProvider> context_provider)
      : viz::OutputSurface(context_provider), weak_ptr_factory_(this) {
    capabilities_.flipped_output_surface = true;
  }

  ~DirectOutputSurface() override {}

  // viz::OutputSurface implementation.
  void BindToClient(viz::OutputSurfaceClient* client) override {
    client_ = client;
  }
  void EnsureBackbuffer() override {}
  void DiscardBackbuffer() override {}
  void BindFramebuffer() override {
    context_provider()->ContextGL()->BindFramebuffer(GL_FRAMEBUFFER, 0);
  }
  void SetDrawRectangle(const gfx::Rect& rect) override {}
  void Reshape(const gfx::Size& size,
               float device_scale_factor,
               const gfx::ColorSpace& color_space,
               bool has_alpha,
               bool use_stencil) override {
    context_provider()->ContextGL()->ResizeCHROMIUM(
        size.width(), size.height(), device_scale_factor,
        gl::GetGLColorSpace(color_space), has_alpha);
  }
  void SwapBuffers(viz::OutputSurfaceFrame frame) override {
    DCHECK(context_provider_.get());
    if (frame.sub_buffer_rect) {
      context_provider_->ContextSupport()->PartialSwapBuffers(
          *frame.sub_buffer_rect);
    } else {
      context_provider_->ContextSupport()->Swap();
    }
    gpu::gles2::GLES2Interface* gl = context_provider_->ContextGL();
    gpu::SyncToken sync_token;
    gl->GenUnverifiedSyncTokenCHROMIUM(sync_token.GetData());

    context_provider_->ContextSupport()->SignalSyncToken(
        sync_token, base::BindOnce(&DirectOutputSurface::OnSwapBuffersComplete,
                                   weak_ptr_factory_.GetWeakPtr(), ++swap_id_));
  }
  uint32_t GetFramebufferCopyTextureFormat() override {
    auto* gl = static_cast<InProcessContextProvider*>(context_provider());
    return gl->GetCopyTextureInternalFormat();
  }
  viz::OverlayCandidateValidator* GetOverlayCandidateValidator()
      const override {
    return nullptr;
  }
  bool IsDisplayedAsOverlayPlane() const override { return false; }
  unsigned GetOverlayTextureId() const override { return 0; }
  gfx::BufferFormat GetOverlayBufferFormat() const override {
    return gfx::BufferFormat::RGBX_8888;
  }
  bool SurfaceIsSuspendForRecycle() const override { return false; }
  bool HasExternalStencilTest() const override { return false; }
  void ApplyExternalStencil() override {}
#if BUILDFLAG(ENABLE_VULKAN)
  gpu::VulkanSurface* GetVulkanSurface() override { return nullptr; }
#endif

 private:
  void OnSwapBuffersComplete(uint64_t swap_id) {
    client_->DidReceiveSwapBuffersAck(swap_id);
    client_->DidReceivePresentationFeedback(swap_id,
                                            gfx::PresentationFeedback());
  }

  viz::OutputSurfaceClient* client_ = nullptr;
  uint64_t swap_id_ = 0;
  base::WeakPtrFactory<DirectOutputSurface> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(DirectOutputSurface);
};

}  // namespace

struct InProcessContextFactory::PerCompositorData {
  gpu::SurfaceHandle surface_handle = gpu::kNullSurfaceHandle;
  std::unique_ptr<viz::BeginFrameSource> begin_frame_source;
  std::unique_ptr<viz::Display> display;
  SkMatrix44 output_color_matrix;
};

InProcessContextFactory::InProcessContextFactory(
    viz::HostFrameSinkManager* host_frame_sink_manager,
    viz::FrameSinkManagerImpl* frame_sink_manager)
    : frame_sink_id_allocator_(kDefaultClientId),
      use_test_surface_(true),
      disable_vsync_(base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kDisableVsyncForTests)),
      host_frame_sink_manager_(host_frame_sink_manager),
      frame_sink_manager_(frame_sink_manager) {
  DCHECK(host_frame_sink_manager);
  DCHECK_NE(gl::GetGLImplementation(), gl::kGLImplementationNone)
      << "If running tests, ensure that main() is calling "
      << "gl::GLSurfaceTestSupport::InitializeOneOff()";

#if defined(OS_WIN)
  renderer_settings_.finish_rendering_on_resize = true;
#elif defined(OS_MACOSX)
  renderer_settings_.release_overlay_resources_after_gpu_query = true;
#endif
}

InProcessContextFactory::~InProcessContextFactory() {
  DCHECK(per_compositor_data_.empty());
}

void InProcessContextFactory::SendOnLostResources() {
  for (auto& observer : observer_list_)
    observer.OnLostResources();
}

void InProcessContextFactory::SetUseFastRefreshRateForTests() {
  refresh_rate_ = 200.0;
}

void InProcessContextFactory::CreateLayerTreeFrameSink(
    base::WeakPtr<Compositor> compositor) {
  // Try to reuse existing shared worker context provider.
  bool shared_worker_context_provider_lost = false;
  if (shared_worker_context_provider_) {
    // Note: If context is lost, delete reference after releasing the lock.
    base::AutoLock lock(*shared_worker_context_provider_->GetLock());
    if (shared_worker_context_provider_->ContextGL()
            ->GetGraphicsResetStatusKHR() != GL_NO_ERROR) {
      shared_worker_context_provider_lost = true;
    }
  }
  if (!shared_worker_context_provider_ || shared_worker_context_provider_lost) {
    constexpr bool support_locking = true;
    shared_worker_context_provider_ = InProcessContextProvider::CreateOffscreen(
        &gpu_memory_buffer_manager_, &image_factory_, nullptr, support_locking);
    auto result = shared_worker_context_provider_->BindToCurrentThread();
    if (result != gpu::ContextResult::kSuccess)
      shared_worker_context_provider_ = nullptr;
  }

  gpu::ContextCreationAttribs attribs;
  attribs.alpha_size = 8;
  attribs.blue_size = 8;
  attribs.green_size = 8;
  attribs.red_size = 8;
  attribs.depth_size = 0;
  attribs.stencil_size = 0;
  attribs.samples = 0;
  attribs.sample_buffers = 0;
  attribs.fail_if_major_perf_caveat = false;
  attribs.bind_generates_resource = false;
  PerCompositorData* data = per_compositor_data_[compositor.get()].get();
  if (!data)
    data = CreatePerCompositorData(compositor.get());

  constexpr bool support_locking = false;
  scoped_refptr<InProcessContextProvider> context_provider =
      InProcessContextProvider::Create(
          attribs, shared_worker_context_provider_.get(),
          &gpu_memory_buffer_manager_, &image_factory_, data->surface_handle,
          "UICompositor", support_locking);

  std::unique_ptr<viz::OutputSurface> display_output_surface;
  if (use_test_surface_) {
    bool flipped_output_surface = false;
    display_output_surface = std::make_unique<cc::PixelTestOutputSurface>(
        context_provider, flipped_output_surface);
  } else {
    display_output_surface =
        std::make_unique<DirectOutputSurface>(context_provider);
  }

  std::unique_ptr<viz::BeginFrameSource> begin_frame_source;
  if (disable_vsync_) {
    begin_frame_source = std::make_unique<viz::BackToBackBeginFrameSource>(
        std::make_unique<viz::DelayBasedTimeSource>(
            compositor->task_runner().get()));
  } else {
    auto time_source = std::make_unique<viz::DelayBasedTimeSource>(
        compositor->task_runner().get());
    time_source->SetTimebaseAndInterval(
        base::TimeTicks(),
        base::TimeDelta::FromMicroseconds(base::Time::kMicrosecondsPerSecond /
                                          refresh_rate_));
    begin_frame_source = std::make_unique<viz::DelayBasedBeginFrameSource>(
        std::move(time_source), viz::BeginFrameSource::kNotRestartableId);
  }
  auto scheduler = std::make_unique<viz::DisplayScheduler>(
      begin_frame_source.get(), compositor->task_runner().get(),
      display_output_surface->capabilities().max_frames_pending);

  data->display = std::make_unique<viz::Display>(
      &shared_bitmap_manager_, renderer_settings_, compositor->frame_sink_id(),
      std::move(display_output_surface), std::move(scheduler),
      compositor->task_runner());
  GetFrameSinkManager()->RegisterBeginFrameSource(begin_frame_source.get(),
                                                  compositor->frame_sink_id());
  // Note that we are careful not to destroy a prior |data->begin_frame_source|
  // until we have reset |data->display|.
  data->begin_frame_source = std::move(begin_frame_source);

  auto* display = per_compositor_data_[compositor.get()]->display.get();
  auto layer_tree_frame_sink = std::make_unique<viz::DirectLayerTreeFrameSink>(
      compositor->frame_sink_id(), GetHostFrameSinkManager(),
      GetFrameSinkManager(), display, nullptr /* display_client */,
      context_provider, shared_worker_context_provider_,
      compositor->task_runner(), &gpu_memory_buffer_manager_,
      false /* use_viz_hit_test */);
  compositor->SetLayerTreeFrameSink(std::move(layer_tree_frame_sink));

  data->display->Resize(compositor->size());
}

std::unique_ptr<Reflector> InProcessContextFactory::CreateReflector(
    Compositor* mirrored_compositor,
    Layer* mirroring_layer) {
  return base::WrapUnique(new FakeReflector);
}

void InProcessContextFactory::RemoveReflector(Reflector* reflector) {
}

scoped_refptr<viz::ContextProvider>
InProcessContextFactory::SharedMainThreadContextProvider() {
  if (shared_main_thread_contexts_ &&
      shared_main_thread_contexts_->ContextGL()->GetGraphicsResetStatusKHR() ==
          GL_NO_ERROR)
    return shared_main_thread_contexts_;

  constexpr bool support_locking = false;
  shared_main_thread_contexts_ = InProcessContextProvider::CreateOffscreen(
      &gpu_memory_buffer_manager_, &image_factory_, nullptr, support_locking);
  auto result = shared_main_thread_contexts_->BindToCurrentThread();
  if (result != gpu::ContextResult::kSuccess)
    shared_main_thread_contexts_ = NULL;

  return shared_main_thread_contexts_;
}

void InProcessContextFactory::RemoveCompositor(Compositor* compositor) {
  PerCompositorDataMap::iterator it = per_compositor_data_.find(compositor);
  if (it == per_compositor_data_.end())
    return;
  PerCompositorData* data = it->second.get();
  GetFrameSinkManager()->UnregisterBeginFrameSource(
      data->begin_frame_source.get());
  DCHECK(data);
#if !defined(GPU_SURFACE_HANDLE_IS_ACCELERATED_WINDOW)
  if (data->surface_handle)
    gpu::GpuSurfaceTracker::Get()->RemoveSurface(data->surface_handle);
#endif
  per_compositor_data_.erase(it);
}

double InProcessContextFactory::GetRefreshRate() const {
  return refresh_rate_;
}

gpu::GpuMemoryBufferManager*
InProcessContextFactory::GetGpuMemoryBufferManager() {
  return &gpu_memory_buffer_manager_;
}

cc::TaskGraphRunner* InProcessContextFactory::GetTaskGraphRunner() {
  return &task_graph_runner_;
}

viz::FrameSinkId InProcessContextFactory::AllocateFrameSinkId() {
  return frame_sink_id_allocator_.NextFrameSinkId();
}

viz::HostFrameSinkManager* InProcessContextFactory::GetHostFrameSinkManager() {
  return host_frame_sink_manager_;
}

void InProcessContextFactory::SetDisplayVisible(ui::Compositor* compositor,
                                                bool visible) {
  if (!per_compositor_data_.count(compositor))
    return;
  per_compositor_data_[compositor]->display->SetVisible(visible);
}

void InProcessContextFactory::ResizeDisplay(ui::Compositor* compositor,
                                            const gfx::Size& size) {
  if (!per_compositor_data_.count(compositor))
    return;
  per_compositor_data_[compositor]->display->Resize(size);
}

void InProcessContextFactory::SetDisplayColorMatrix(ui::Compositor* compositor,
                                                    const SkMatrix44& matrix) {
  auto iter = per_compositor_data_.find(compositor);
  if (iter == per_compositor_data_.end())
    return;

  iter->second->output_color_matrix = matrix;
  iter->second->display->SetColorMatrix(matrix);
}

void InProcessContextFactory::AddObserver(ContextFactoryObserver* observer) {
  observer_list_.AddObserver(observer);
}

void InProcessContextFactory::RemoveObserver(ContextFactoryObserver* observer) {
  observer_list_.RemoveObserver(observer);
}

viz::FrameSinkManagerImpl* InProcessContextFactory::GetFrameSinkManager() {
  return frame_sink_manager_;
}

SkMatrix44 InProcessContextFactory::GetOutputColorMatrix(
    Compositor* compositor) const {
  auto iter = per_compositor_data_.find(compositor);
  if (iter == per_compositor_data_.end())
    return SkMatrix44(SkMatrix44::kIdentity_Constructor);

  return iter->second->output_color_matrix;
}

void InProcessContextFactory::ResetOutputColorMatrixToIdentity(
    ui::Compositor* compositor) {
  auto iter = per_compositor_data_.find(compositor);
  if (iter == per_compositor_data_.end())
    return;

  iter->second->output_color_matrix.setIdentity();
}

InProcessContextFactory::PerCompositorData*
InProcessContextFactory::CreatePerCompositorData(ui::Compositor* compositor) {
  DCHECK(!per_compositor_data_[compositor]);

  gfx::AcceleratedWidget widget = compositor->widget();

  auto data = std::make_unique<PerCompositorData>();
  if (widget == gfx::kNullAcceleratedWidget) {
    data->surface_handle = gpu::kNullSurfaceHandle;
  } else {
#if defined(GPU_SURFACE_HANDLE_IS_ACCELERATED_WINDOW)
    data->surface_handle = widget;
#else
    gpu::GpuSurfaceTracker* tracker = gpu::GpuSurfaceTracker::Get();
    data->surface_handle = tracker->AddSurfaceForNativeWidget(
        gpu::GpuSurfaceTracker::SurfaceRecord(
            widget
#if defined(OS_ANDROID)
            // We have to provide a surface too, but we don't have one.  For
            // now, we don't proide it, since nobody should ask anyway.
            // If we ever provide a valid surface here, then GpuSurfaceTracker
            // can be more strict about enforcing it.
            ,
            nullptr
#endif
            ));
#endif
  }

  PerCompositorData* return_ptr = data.get();
  per_compositor_data_[compositor] = std::move(data);
  return return_ptr;
}

}  // namespace ui

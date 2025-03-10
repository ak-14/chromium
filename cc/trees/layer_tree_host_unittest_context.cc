// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "build/build_config.h"
#include "cc/layers/heads_up_display_layer.h"
#include "cc/layers/layer_impl.h"
#include "cc/layers/painted_scrollbar_layer.h"
#include "cc/layers/picture_layer.h"
#include "cc/layers/texture_layer.h"
#include "cc/layers/texture_layer_impl.h"
#include "cc/layers/video_layer.h"
#include "cc/layers/video_layer_impl.h"
#include "cc/paint/filter_operations.h"
#include "cc/paint/paint_flags.h"
#include "cc/resources/ui_resource_manager.h"
#include "cc/test/fake_content_layer_client.h"
#include "cc/test/fake_layer_tree_host_client.h"
#include "cc/test/fake_painted_scrollbar_layer.h"
#include "cc/test/fake_picture_layer.h"
#include "cc/test/fake_picture_layer_impl.h"
#include "cc/test/fake_resource_provider.h"
#include "cc/test/fake_scoped_ui_resource.h"
#include "cc/test/fake_scrollbar.h"
#include "cc/test/fake_video_frame_provider.h"
#include "cc/test/layer_tree_test.h"
#include "cc/test/render_pass_test_utils.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/layer_tree_host_impl.h"
#include "cc/trees/layer_tree_impl.h"
#include "cc/trees/single_thread_proxy.h"
#include "components/viz/common/resources/single_release_callback.h"
#include "components/viz/test/test_context_provider.h"
#include "components/viz/test/test_layer_tree_frame_sink.h"
#include "components/viz/test/test_shared_bitmap_manager.h"
#include "components/viz/test/test_web_graphics_context_3d.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "media/base/media.h"

using media::VideoFrame;

namespace cc {
namespace {

// Returns a fake TimeTicks based on the given microsecond offset.
base::TimeTicks TicksFromMicroseconds(int64_t micros) {
  return base::TimeTicks() + base::TimeDelta::FromMicroseconds(micros);
}

// These tests deal with losing the 3d graphics context.
class LayerTreeHostContextTest : public LayerTreeTest {
 public:
  LayerTreeHostContextTest()
      : LayerTreeTest(),
        context3d_(nullptr),
        times_to_fail_create_(0),
        times_to_lose_during_commit_(0),
        times_to_lose_during_draw_(0),
        times_to_fail_recreate_(0),
        times_to_expect_create_failed_(0),
        times_create_failed_(0),
        committed_at_least_once_(false),
        context_should_support_io_surface_(false),
        fallback_context_works_(false),
        async_layer_tree_frame_sink_creation_(false) {
    media::InitializeMediaLibrary();
  }

  void LoseContext() {
    // CreateDisplayLayerTreeFrameSink happens on a different thread, so lock
    // context3d_ to make sure we don't set it to null after recreating it
    // there.
    base::AutoLock lock(context3d_lock_);
    // For sanity-checking tests, they should only call this when the
    // context is not lost.
    CHECK(context3d_);
    context3d_->loseContextCHROMIUM(GL_GUILTY_CONTEXT_RESET_ARB,
                                    GL_INNOCENT_CONTEXT_RESET_ARB);
    context3d_ = nullptr;
  }

  std::unique_ptr<viz::TestLayerTreeFrameSink> CreateLayerTreeFrameSink(
      const viz::RendererSettings& renderer_settings,
      double refresh_rate,
      scoped_refptr<viz::ContextProvider> compositor_context_provider,
      scoped_refptr<viz::RasterContextProvider> worker_context_provider)
      override {
    base::AutoLock lock(context3d_lock_);

    std::unique_ptr<viz::TestWebGraphicsContext3D> compositor_context3d =
        viz::TestWebGraphicsContext3D::Create();
    if (context_should_support_io_surface_) {
      compositor_context3d->set_have_extension_io_surface(true);
      compositor_context3d->set_have_extension_egl_image(true);
    }
    context3d_ = compositor_context3d.get();

    if (times_to_fail_create_) {
      --times_to_fail_create_;
      ExpectCreateToFail();
      context3d_->loseContextCHROMIUM(GL_GUILTY_CONTEXT_RESET_ARB,
                                      GL_INNOCENT_CONTEXT_RESET_ARB);
    }

    return LayerTreeTest::CreateLayerTreeFrameSink(
        renderer_settings, refresh_rate,
        viz::TestContextProvider::Create(std::move(compositor_context3d)),
        std::move(worker_context_provider));
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame,
                                   DrawResult draw_result) override {
    if (draw_result == DRAW_ABORTED_MISSING_HIGH_RES_CONTENT) {
      // Only valid for single-threaded compositing, which activates
      // immediately and will try to draw again when content has finished.
      DCHECK(!host_impl->task_runner_provider()->HasImplThread());
      return draw_result;
    }
    EXPECT_EQ(DRAW_SUCCESS, draw_result);
    if (!times_to_lose_during_draw_)
      return draw_result;

    --times_to_lose_during_draw_;
    LoseContext();

    times_to_fail_create_ = times_to_fail_recreate_;
    times_to_fail_recreate_ = 0;

    return draw_result;
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    committed_at_least_once_ = true;

    if (!times_to_lose_during_commit_)
      return;
    --times_to_lose_during_commit_;
    LoseContext();

    times_to_fail_create_ = times_to_fail_recreate_;
    times_to_fail_recreate_ = 0;
  }

  void DidFailToInitializeLayerTreeFrameSink() override {
    ++times_create_failed_;
  }

  void TearDown() override {
    LayerTreeTest::TearDown();
    EXPECT_EQ(times_to_expect_create_failed_, times_create_failed_);
  }

  void ExpectCreateToFail() { ++times_to_expect_create_failed_; }

 protected:
  // Protects use of context3d_ so LoseContext and
  // CreateDisplayLayerTreeFrameSink can both use it on different threads.
  base::Lock context3d_lock_;
  viz::TestWebGraphicsContext3D* context3d_;

  int times_to_fail_create_;
  int times_to_lose_during_commit_;
  int times_to_lose_during_draw_;
  int times_to_fail_recreate_;
  int times_to_expect_create_failed_;
  int times_create_failed_;
  bool committed_at_least_once_;
  bool context_should_support_io_surface_;
  bool fallback_context_works_;
  bool async_layer_tree_frame_sink_creation_;
};

class LayerTreeHostContextTestLostContextSucceeds
    : public LayerTreeHostContextTest {
 public:
  LayerTreeHostContextTestLostContextSucceeds()
      : LayerTreeHostContextTest(),
        test_case_(0),
        num_losses_(0),
        num_losses_last_test_case_(-1),
        recovered_context_(true),
        first_initialized_(false) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void RequestNewLayerTreeFrameSink() override {
    if (async_layer_tree_frame_sink_creation_) {
      MainThreadTaskRunner()->PostTask(
          FROM_HERE,
          base::BindOnce(&LayerTreeHostContextTestLostContextSucceeds::
                             AsyncRequestNewLayerTreeFrameSink,
                         base::Unretained(this)));
    } else {
      AsyncRequestNewLayerTreeFrameSink();
    }
  }

  void AsyncRequestNewLayerTreeFrameSink() {
    LayerTreeHostContextTest::RequestNewLayerTreeFrameSink();
  }

  void DidInitializeLayerTreeFrameSink() override {
    if (first_initialized_)
      ++num_losses_;
    else
      first_initialized_ = true;

    recovered_context_ = true;
  }

  void AfterTest() override { EXPECT_EQ(11u, test_case_); }

  void DidCommitAndDrawFrame() override {
    // If the last frame had a context loss, then we'll commit again to
    // recover.
    if (!recovered_context_)
      return;
    if (times_to_lose_during_commit_)
      return;
    if (times_to_lose_during_draw_)
      return;

    recovered_context_ = false;
    if (NextTestCase())
      InvalidateAndSetNeedsCommit();
    else
      EndTest();
  }

  virtual void InvalidateAndSetNeedsCommit() {
    // Cause damage so we try to draw.
    layer_tree_host()->root_layer()->SetNeedsDisplay();
    layer_tree_host()->SetNeedsCommit();
  }

  bool NextTestCase() {
    static const TestCase kTests[] = {
        // Losing the context and failing to recreate it (or losing it again
        // immediately) a small number of times should succeed.
        {
            1,      // times_to_lose_during_commit
            0,      // times_to_lose_during_draw
            0,      // times_to_fail_recreate
            false,  // fallback_context_works
            false,  // async_layer_tree_frame_sink_creation
        },
        {
            0,      // times_to_lose_during_commit
            1,      // times_to_lose_during_draw
            0,      // times_to_fail_recreate
            false,  // fallback_context_works
            false,  // async_layer_tree_frame_sink_creation
        },
        {
            1,      // times_to_lose_during_commit
            0,      // times_to_lose_during_draw
            3,      // times_to_fail_recreate
            false,  // fallback_context_works
            false,  // async_layer_tree_frame_sink_creation
        },
        {
            0,      // times_to_lose_during_commit
            1,      // times_to_lose_during_draw
            3,      // times_to_fail_recreate
            false,  // fallback_context_works
            false,  // async_layer_tree_frame_sink_creation
        },
        {
            0,      // times_to_lose_during_commit
            1,      // times_to_lose_during_draw
            3,      // times_to_fail_recreate
            false,  // fallback_context_works
            true,   // async_layer_tree_frame_sink_creation
        },
        // Losing the context and recreating it any number of times should
        // succeed.
        {
            10,     // times_to_lose_during_commit
            0,      // times_to_lose_during_draw
            0,      // times_to_fail_recreate
            false,  // fallback_context_works
            false,  // async_layer_tree_frame_sink_creation
        },
        {
            0,      // times_to_lose_during_commit
            10,     // times_to_lose_during_draw
            0,      // times_to_fail_recreate
            false,  // fallback_context_works
            false,  // async_layer_tree_frame_sink_creation
        },
        {
            10,     // times_to_lose_during_commit
            0,      // times_to_lose_during_draw
            0,      // times_to_fail_recreate
            false,  // fallback_context_works
            true,   // async_layer_tree_frame_sink_creation
        },
        {
            0,      // times_to_lose_during_commit
            10,     // times_to_lose_during_draw
            0,      // times_to_fail_recreate
            false,  // fallback_context_works
            true,   // async_layer_tree_frame_sink_creation
        },
        // Losing the context, failing to reinitialize it, and making a fallback
        // context should work.
        {
            0,      // times_to_lose_during_commit
            1,      // times_to_lose_during_draw
            0,      // times_to_fail_recreate
            true,   // fallback_context_works
            false,  // async_layer_tree_frame_sink_creation
        },
        {
            0,     // times_to_lose_during_commit
            1,     // times_to_lose_during_draw
            0,     // times_to_fail_recreate
            true,  // fallback_context_works
            true,  // async_layer_tree_frame_sink_creation
        },
    };

    if (test_case_ >= arraysize(kTests))
      return false;
    // Make sure that we lost our context at least once in the last test run so
    // the test did something.
    EXPECT_GT(num_losses_, num_losses_last_test_case_);
    num_losses_last_test_case_ = num_losses_;

    times_to_lose_during_commit_ =
        kTests[test_case_].times_to_lose_during_commit;
    times_to_lose_during_draw_ = kTests[test_case_].times_to_lose_during_draw;
    times_to_fail_recreate_ = kTests[test_case_].times_to_fail_recreate;
    fallback_context_works_ = kTests[test_case_].fallback_context_works;
    async_layer_tree_frame_sink_creation_ =
        kTests[test_case_].async_layer_tree_frame_sink_creation;
    ++test_case_;
    return true;
  }

  struct TestCase {
    int times_to_lose_during_commit;
    int times_to_lose_during_draw;
    int times_to_fail_recreate;
    bool fallback_context_works;
    bool async_layer_tree_frame_sink_creation;
  };

 protected:
  size_t test_case_;
  int num_losses_;
  int num_losses_last_test_case_;
  bool recovered_context_;
  bool first_initialized_;
};

// Disabled because of crbug.com/736392
// SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostContextTestLostContextSucceeds);

class LayerTreeHostClientNotVisibleDoesNotCreateLayerTreeFrameSink
    : public LayerTreeHostContextTest {
 public:
  LayerTreeHostClientNotVisibleDoesNotCreateLayerTreeFrameSink()
      : LayerTreeHostContextTest() {}

  void WillBeginTest() override {
    // Override to not become visible.
    DCHECK(!layer_tree_host()->IsVisible());
  }

  void BeginTest() override {
    PostSetNeedsCommitToMainThread();
    EndTest();
  }

  void RequestNewLayerTreeFrameSink() override {
    ADD_FAILURE() << "RequestNewLayerTreeFrameSink() should not be called";
  }

  void DidInitializeLayerTreeFrameSink() override { EXPECT_TRUE(false); }

  void AfterTest() override {}
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostClientNotVisibleDoesNotCreateLayerTreeFrameSink);

// This tests the LayerTreeFrameSink release logic in the following sequence.
// SetUp LTH and create and init LayerTreeFrameSink.
// LTH::SetVisible(false);
// LTH::ReleaseLayerTreeFrameSink();
// ...
// LTH::SetVisible(true);
// Create and init new LayerTreeFrameSink
class LayerTreeHostClientTakeAwayLayerTreeFrameSink
    : public LayerTreeHostContextTest {
 public:
  LayerTreeHostClientTakeAwayLayerTreeFrameSink()
      : LayerTreeHostContextTest(), setos_counter_(0) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void RequestNewLayerTreeFrameSink() override {
    if (layer_tree_host()->IsVisible()) {
      setos_counter_++;
      LayerTreeHostContextTest::RequestNewLayerTreeFrameSink();
    }
  }

  void HideAndReleaseLayerTreeFrameSink() {
    EXPECT_TRUE(layer_tree_host()->GetTaskRunnerProvider()->IsMainThread());
    layer_tree_host()->SetVisible(false);
    std::unique_ptr<LayerTreeFrameSink> surface =
        layer_tree_host()->ReleaseLayerTreeFrameSink();
    CHECK(surface);
    MainThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &LayerTreeHostClientTakeAwayLayerTreeFrameSink::MakeVisible,
            base::Unretained(this)));
  }

  void DidInitializeLayerTreeFrameSink() override {
    EXPECT_TRUE(layer_tree_host()->IsVisible());
    if (setos_counter_ == 1) {
      MainThreadTaskRunner()->PostTask(
          FROM_HERE,
          base::BindOnce(&LayerTreeHostClientTakeAwayLayerTreeFrameSink::
                             HideAndReleaseLayerTreeFrameSink,
                         base::Unretained(this)));
    } else {
      EndTest();
    }
  }

  void MakeVisible() {
    EXPECT_TRUE(layer_tree_host()->GetTaskRunnerProvider()->IsMainThread());
    layer_tree_host()->SetVisible(true);
  }

  void AfterTest() override {}

  int setos_counter_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostClientTakeAwayLayerTreeFrameSink);

class MultipleCompositeDoesNotCreateLayerTreeFrameSink
    : public LayerTreeHostContextTest {
 public:
  MultipleCompositeDoesNotCreateLayerTreeFrameSink()
      : LayerTreeHostContextTest(), request_count_(0) {}

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->single_thread_proxy_scheduler = false;
    settings->use_zero_copy = true;
  }

  void RequestNewLayerTreeFrameSink() override {
    EXPECT_GE(1, ++request_count_);
    EndTest();
  }

  void BeginTest() override {
    layer_tree_host()->Composite(TicksFromMicroseconds(1), false);
    layer_tree_host()->Composite(TicksFromMicroseconds(2), false);
  }

  void DidInitializeLayerTreeFrameSink() override { EXPECT_TRUE(false); }

  void AfterTest() override {}

  int request_count_;
};

// This test uses Composite() which only exists for single thread.
SINGLE_THREAD_TEST_F(MultipleCompositeDoesNotCreateLayerTreeFrameSink);

// This test makes sure that once a SingleThreadProxy issues a
// DidFailToInitializeLayerTreeFrameSink, that future Composite calls will not
// trigger additional requests for output surfaces.
class FailedCreateDoesNotCreateExtraLayerTreeFrameSink
    : public LayerTreeHostContextTest {
 public:
  FailedCreateDoesNotCreateExtraLayerTreeFrameSink()
      : LayerTreeHostContextTest(), num_requests_(0), has_failed_(false) {
    times_to_fail_create_ = 1;
  }

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->single_thread_proxy_scheduler = false;
    settings->use_zero_copy = true;
  }

  void RequestNewLayerTreeFrameSink() override {
    num_requests_++;
    // There should be one initial request and then one request from
    // the LayerTreeTest test hooks DidFailToInitializeLayerTreeFrameSink
    // (which is hard to skip).  This second request is just ignored and is test
    // cruft.
    EXPECT_LE(num_requests_, 2);
    if (num_requests_ > 1)
      return;
    LayerTreeHostContextTest::RequestNewLayerTreeFrameSink();
  }

  void BeginTest() override {
    // First composite tries to create a surface.
    layer_tree_host()->Composite(TicksFromMicroseconds(1), false);
    EXPECT_EQ(num_requests_, 2);
    EXPECT_TRUE(has_failed_);

    // Second composite should not request or fail.
    layer_tree_host()->Composite(TicksFromMicroseconds(2), false);
    EXPECT_EQ(num_requests_, 2);
    EndTest();
  }

  void DidInitializeLayerTreeFrameSink() override { EXPECT_TRUE(false); }

  void DidFailToInitializeLayerTreeFrameSink() override {
    LayerTreeHostContextTest::DidFailToInitializeLayerTreeFrameSink();
    EXPECT_FALSE(has_failed_);
    has_failed_ = true;
  }

  void AfterTest() override {}

  int num_requests_;
  bool has_failed_;
};

// This test uses Composite() which only exists for single thread.
SINGLE_THREAD_TEST_F(FailedCreateDoesNotCreateExtraLayerTreeFrameSink);

class LayerTreeHostContextTestCommitAfterDelayedLayerTreeFrameSink
    : public LayerTreeHostContextTest {
 public:
  LayerTreeHostContextTestCommitAfterDelayedLayerTreeFrameSink()
      : LayerTreeHostContextTest(), creating_output_(false) {}

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->single_thread_proxy_scheduler = false;
    settings->use_zero_copy = true;
  }

  void RequestNewLayerTreeFrameSink() override {
    MainThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &LayerTreeHostContextTestCommitAfterDelayedLayerTreeFrameSink::
                CreateAndSetLayerTreeFrameSink,
            base::Unretained(this)));
  }

  void CreateAndSetLayerTreeFrameSink() {
    creating_output_ = true;
    LayerTreeHostContextTest::RequestNewLayerTreeFrameSink();
  }

  void BeginTest() override {
    layer_tree_host()->Composite(TicksFromMicroseconds(1), false);
  }

  void ScheduleComposite() override {
    if (creating_output_)
      EndTest();
  }

  void AfterTest() override {}

  bool creating_output_;
};

// This test uses Composite() which only exists for single thread.
SINGLE_THREAD_TEST_F(
    LayerTreeHostContextTestCommitAfterDelayedLayerTreeFrameSink);

class LayerTreeHostContextTestAvoidUnnecessaryComposite
    : public LayerTreeHostContextTest {
 public:
  LayerTreeHostContextTestAvoidUnnecessaryComposite()
      : LayerTreeHostContextTest(), in_composite_(false) {}

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->single_thread_proxy_scheduler = false;
    settings->use_zero_copy = true;
  }

  void RequestNewLayerTreeFrameSink() override {
    LayerTreeHostContextTest::RequestNewLayerTreeFrameSink();
    EndTest();
  }

  void BeginTest() override {
    in_composite_ = true;
    layer_tree_host()->Composite(TicksFromMicroseconds(1), false);
    in_composite_ = false;
  }

  void ScheduleComposite() override { EXPECT_FALSE(in_composite_); }

  void AfterTest() override {}

  bool in_composite_;
};

// This test uses Composite() which only exists for single thread.
SINGLE_THREAD_TEST_F(LayerTreeHostContextTestAvoidUnnecessaryComposite);

// This test uses PictureLayer to check for a working context.
class LayerTreeHostContextTestLostContextSucceedsWithContent
    : public LayerTreeHostContextTestLostContextSucceeds {
 public:
  void SetupTree() override {
    root_ = Layer::Create();
    root_->SetBounds(gfx::Size(10, 10));
    root_->SetIsDrawable(true);

    // Paint non-solid color.
    PaintFlags flags;
    flags.setColor(SkColorSetARGB(100, 80, 200, 200));
    client_.add_draw_rect(gfx::Rect(5, 5), flags);

    layer_ = FakePictureLayer::Create(&client_);
    layer_->SetBounds(gfx::Size(10, 10));
    layer_->SetIsDrawable(true);

    root_->AddChild(layer_);

    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostContextTest::SetupTree();
    client_.set_bounds(root_->bounds());
  }

  void InvalidateAndSetNeedsCommit() override {
    // Invalidate the render surface so we don't try to use a cached copy of the
    // surface.  We want to make sure to test the drawing paths for drawing to
    // a child surface.
    layer_->SetNeedsDisplay();
    LayerTreeHostContextTestLostContextSucceeds::InvalidateAndSetNeedsCommit();
  }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    FakePictureLayerImpl* picture_impl = static_cast<FakePictureLayerImpl*>(
        host_impl->active_tree()->LayerById(layer_->id()));
    EXPECT_TRUE(picture_impl->HighResTiling()
                    ->TileAt(0, 0)
                    ->draw_info()
                    .IsReadyToDraw());
  }

 protected:
  FakeContentLayerClient client_;
  scoped_refptr<Layer> root_;
  scoped_refptr<Layer> layer_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostContextTestLostContextSucceedsWithContent);

class LayerTreeHostContextTestCreateLayerTreeFrameSinkFailsOnce
    : public LayerTreeHostContextTest {
 public:
  LayerTreeHostContextTestCreateLayerTreeFrameSinkFailsOnce()
      : times_to_fail_(1), times_initialized_(0) {
    times_to_fail_create_ = times_to_fail_;
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidInitializeLayerTreeFrameSink() override { times_initialized_++; }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override { EndTest(); }

  void AfterTest() override {
    EXPECT_EQ(times_to_fail_, times_create_failed_);
    EXPECT_NE(0, times_initialized_);
  }

 private:
  int times_to_fail_;
  int times_initialized_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostContextTestCreateLayerTreeFrameSinkFailsOnce);

class LayerTreeHostContextTestLostContextAndEvictTextures
    : public LayerTreeHostContextTest {
 public:
  LayerTreeHostContextTestLostContextAndEvictTextures()
      : LayerTreeHostContextTest(),
        impl_host_(nullptr),
        num_commits_(0),
        lost_context_(false) {}

  void SetupTree() override {
    // Paint non-solid color.
    PaintFlags flags;
    flags.setColor(SkColorSetARGB(100, 80, 200, 200));
    client_.add_draw_rect(gfx::Rect(5, 5), flags);

    scoped_refptr<FakePictureLayer> picture_layer =
        FakePictureLayer::Create(&client_);
    picture_layer->SetBounds(gfx::Size(10, 20));
    client_.set_bounds(picture_layer->bounds());
    layer_tree_host()->SetRootLayer(picture_layer);

    LayerTreeHostContextTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void PostEvictTextures() {
    if (HasImplThread()) {
      ImplThreadTaskRunner()->PostTask(
          FROM_HERE,
          base::BindOnce(&LayerTreeHostContextTestLostContextAndEvictTextures::
                             EvictTexturesOnImplThread,
                         base::Unretained(this)));
    } else {
      DebugScopedSetImplThread impl(task_runner_provider());
      EvictTexturesOnImplThread();
    }
  }

  void EvictTexturesOnImplThread() {
    impl_host_->EvictTexturesForTesting();

    if (lose_after_evict_) {
      LoseContext();
      lost_context_ = true;
    }
  }

  void DidCommitAndDrawFrame() override {
    if (num_commits_ > 1)
      return;
    PostEvictTextures();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    LayerTreeHostContextTest::CommitCompleteOnThread(impl);
    if (num_commits_ > 1)
      return;
    ++num_commits_;
    if (!lose_after_evict_) {
      LoseContext();
      lost_context_ = true;
    }
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    FakePictureLayerImpl* picture_impl = static_cast<FakePictureLayerImpl*>(
        impl->active_tree()->root_layer_for_testing());
    EXPECT_TRUE(picture_impl->HighResTiling()
                    ->TileAt(0, 0)
                    ->draw_info()
                    .IsReadyToDraw());

    impl_host_ = impl;
    if (lost_context_)
      EndTest();
  }

  void DidInitializeLayerTreeFrameSink() override {}

  void AfterTest() override {}

 protected:
  bool lose_after_evict_;
  FakeContentLayerClient client_;
  LayerTreeHostImpl* impl_host_;
  int num_commits_;
  bool lost_context_;
};

TEST_F(LayerTreeHostContextTestLostContextAndEvictTextures,
       LoseAfterEvict_SingleThread) {
  lose_after_evict_ = true;
  RunTest(CompositorMode::SINGLE_THREADED);
}

TEST_F(LayerTreeHostContextTestLostContextAndEvictTextures,
       LoseAfterEvict_MultiThread) {
  lose_after_evict_ = true;
  RunTest(CompositorMode::THREADED);
}

TEST_F(LayerTreeHostContextTestLostContextAndEvictTextures,
       LoseBeforeEvict_SingleThread) {
  lose_after_evict_ = false;
  RunTest(CompositorMode::SINGLE_THREADED);
}

TEST_F(LayerTreeHostContextTestLostContextAndEvictTextures,
       LoseBeforeEvict_MultiThread) {
  lose_after_evict_ = false;
  RunTest(CompositorMode::THREADED);
}

class LayerTreeHostContextTestLayersNotified : public LayerTreeHostContextTest {
 public:
  LayerTreeHostContextTestLayersNotified()
      : LayerTreeHostContextTest(), num_commits_(0) {}

  void SetupTree() override {
    root_ = FakePictureLayer::Create(&client_);
    child_ = FakePictureLayer::Create(&client_);
    grandchild_ = FakePictureLayer::Create(&client_);

    root_->AddChild(child_);
    child_->AddChild(grandchild_);

    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostContextTest::SetupTree();
    client_.set_bounds(root_->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    LayerTreeHostContextTest::DidActivateTreeOnThread(host_impl);

    FakePictureLayerImpl* root_picture = nullptr;
    FakePictureLayerImpl* child_picture = nullptr;
    FakePictureLayerImpl* grandchild_picture = nullptr;

    root_picture = static_cast<FakePictureLayerImpl*>(
        host_impl->active_tree()->root_layer_for_testing());
    child_picture = static_cast<FakePictureLayerImpl*>(
        host_impl->active_tree()->LayerById(child_->id()));
    grandchild_picture = static_cast<FakePictureLayerImpl*>(
        host_impl->active_tree()->LayerById(grandchild_->id()));

    ++num_commits_;
    switch (num_commits_) {
      case 1:
        EXPECT_EQ(0u, root_picture->release_resources_count());
        EXPECT_EQ(0u, child_picture->release_resources_count());
        EXPECT_EQ(0u, grandchild_picture->release_resources_count());

        // Lose the context and struggle to recreate it.
        LoseContext();
        times_to_fail_create_ = 1;
        break;
      case 2:
        EXPECT_TRUE(root_picture->release_resources_count());
        EXPECT_TRUE(child_picture->release_resources_count());
        EXPECT_TRUE(grandchild_picture->release_resources_count());

        EndTest();
        break;
      default:
        NOTREACHED();
    }
  }

  void AfterTest() override {}

 private:
  int num_commits_;

  FakeContentLayerClient client_;
  scoped_refptr<Layer> root_;
  scoped_refptr<Layer> child_;
  scoped_refptr<Layer> grandchild_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostContextTestLayersNotified);

class LayerTreeHostContextTestDontUseLostResources
    : public LayerTreeHostContextTest {
 public:
  LayerTreeHostContextTestDontUseLostResources() : lost_context_(false) {
    context_should_support_io_surface_ = true;

    child_context_provider_ = viz::TestContextProvider::Create();
    auto result = child_context_provider_->BindToCurrentThread();
    CHECK_EQ(result, gpu::ContextResult::kSuccess);
    shared_bitmap_manager_ = std::make_unique<viz::TestSharedBitmapManager>();
    child_resource_provider_ =
        FakeResourceProvider::CreateLayerTreeResourceProvider(
            child_context_provider_.get());
  }

  static void EmptyReleaseCallback(const gpu::SyncToken& sync_token,
                                   bool lost) {}

  void SetupTree() override {
    gpu::gles2::GLES2Interface* gl = child_context_provider_->ContextGL();

    gpu::Mailbox mailbox;
    gl->GenMailboxCHROMIUM(mailbox.name);

    gpu::SyncToken sync_token;
    gl->GenSyncTokenCHROMIUM(sync_token.GetData());

    scoped_refptr<Layer> root = Layer::Create();
    root->SetBounds(gfx::Size(10, 10));
    root->SetIsDrawable(true);

    scoped_refptr<PictureLayer> layer = PictureLayer::Create(&client_);
    layer->SetBounds(gfx::Size(10, 10));
    layer->SetIsDrawable(true);
    root->AddChild(layer);

    scoped_refptr<TextureLayer> texture =
        TextureLayer::CreateForMailbox(nullptr);
    texture->SetBounds(gfx::Size(10, 10));
    texture->SetIsDrawable(true);
    auto resource = viz::TransferableResource::MakeGL(
        mailbox, GL_LINEAR, GL_TEXTURE_2D, sync_token);
    texture->SetTransferableResource(
        resource, viz::SingleReleaseCallback::Create(
                      base::Bind(&LayerTreeHostContextTestDontUseLostResources::
                                     EmptyReleaseCallback)));
    root->AddChild(texture);

    scoped_refptr<PictureLayer> mask = PictureLayer::Create(&client_);
    mask->SetBounds(gfx::Size(10, 10));
    client_.set_bounds(mask->bounds());

    scoped_refptr<PictureLayer> layer_with_mask =
        PictureLayer::Create(&client_);
    layer_with_mask->SetBounds(gfx::Size(10, 10));
    layer_with_mask->SetIsDrawable(true);
    layer_with_mask->SetMaskLayer(mask.get());
    root->AddChild(layer_with_mask);

    scoped_refptr<VideoLayer> video_color =
        VideoLayer::Create(&color_frame_provider_, media::VIDEO_ROTATION_0);
    video_color->SetBounds(gfx::Size(10, 10));
    video_color->SetIsDrawable(true);
    root->AddChild(video_color);

    scoped_refptr<VideoLayer> video_hw =
        VideoLayer::Create(&hw_frame_provider_, media::VIDEO_ROTATION_0);
    video_hw->SetBounds(gfx::Size(10, 10));
    video_hw->SetIsDrawable(true);
    root->AddChild(video_hw);

    scoped_refptr<VideoLayer> video_scaled_hw =
        VideoLayer::Create(&scaled_hw_frame_provider_, media::VIDEO_ROTATION_0);
    video_scaled_hw->SetBounds(gfx::Size(10, 10));
    video_scaled_hw->SetIsDrawable(true);
    root->AddChild(video_scaled_hw);

    color_video_frame_ = VideoFrame::CreateColorFrame(
        gfx::Size(4, 4), 0x80, 0x80, 0x80, base::TimeDelta());
    ASSERT_TRUE(color_video_frame_);
    gpu::MailboxHolder holders[media::VideoFrame::kMaxPlanes] = {
        gpu::MailboxHolder(mailbox, sync_token, GL_TEXTURE_2D)};
    hw_video_frame_ = VideoFrame::WrapNativeTextures(
        media::PIXEL_FORMAT_ARGB, holders,
        media::VideoFrame::ReleaseMailboxCB(), gfx::Size(4, 4),
        gfx::Rect(0, 0, 4, 4), gfx::Size(4, 4), base::TimeDelta());
    ASSERT_TRUE(hw_video_frame_);
    scaled_hw_video_frame_ = VideoFrame::WrapNativeTextures(
        media::PIXEL_FORMAT_ARGB, holders,
        media::VideoFrame::ReleaseMailboxCB(), gfx::Size(4, 4),
        gfx::Rect(0, 0, 3, 2), gfx::Size(4, 4), base::TimeDelta());
    ASSERT_TRUE(scaled_hw_video_frame_);

    color_frame_provider_.set_frame(color_video_frame_);
    hw_frame_provider_.set_frame(hw_video_frame_);
    scaled_hw_frame_provider_.set_frame(scaled_hw_video_frame_);

    // Enable the hud.
    LayerTreeDebugState debug_state;
    debug_state.show_property_changed_rects = true;
    layer_tree_host()->SetDebugState(debug_state);

    scoped_refptr<PaintedScrollbarLayer> scrollbar =
        PaintedScrollbarLayer::Create(
            std::unique_ptr<Scrollbar>(new FakeScrollbar), layer->element_id());
    scrollbar->SetBounds(gfx::Size(10, 10));
    scrollbar->SetIsDrawable(true);
    root->AddChild(scrollbar);

    layer_tree_host()->SetRootLayer(root);
    LayerTreeHostContextTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    LayerTreeHostContextTest::CommitCompleteOnThread(host_impl);

    if (host_impl->active_tree()->source_frame_number() == 3) {
      // On the third commit we're recovering from context loss. Hardware
      // video frames should not be reused by the VideoFrameProvider, but
      // software frames can be.
      hw_frame_provider_.set_frame(nullptr);
      scaled_hw_frame_provider_.set_frame(nullptr);
    }
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame,
                                   DrawResult draw_result) override {
    if (host_impl->active_tree()->source_frame_number() == 2) {
      // Lose the context after draw on the second commit. This will cause
      // a third commit to recover.
      context3d_->set_times_bind_texture_succeeds(0);
    }
    return draw_result;
  }

  void RequestNewLayerTreeFrameSink() override {
    // This will get called twice:
    // First when we create the initial LayerTreeFrameSink...
    if (layer_tree_host()->SourceFrameNumber() > 0) {
      // ... and then again after we forced the context to be lost.
      lost_context_ = true;
    }
    LayerTreeHostContextTest::RequestNewLayerTreeFrameSink();
  }

  void DidCommitAndDrawFrame() override {
    ASSERT_TRUE(layer_tree_host()->hud_layer());
    // End the test once we know the 3nd frame drew.
    if (layer_tree_host()->SourceFrameNumber() < 5) {
      layer_tree_host()->root_layer()->SetNeedsDisplay();
      layer_tree_host()->SetNeedsCommit();
    } else {
      EndTest();
    }
  }

  void AfterTest() override { EXPECT_TRUE(lost_context_); }

 private:
  FakeContentLayerClient client_;
  bool lost_context_;

  scoped_refptr<viz::TestContextProvider> child_context_provider_;
  std::unique_ptr<viz::SharedBitmapManager> shared_bitmap_manager_;
  std::unique_ptr<ResourceProvider> child_resource_provider_;

  scoped_refptr<VideoFrame> color_video_frame_;
  scoped_refptr<VideoFrame> hw_video_frame_;
  scoped_refptr<VideoFrame> scaled_hw_video_frame_;

  FakeVideoFrameProvider color_frame_provider_;
  FakeVideoFrameProvider hw_frame_provider_;
  FakeVideoFrameProvider scaled_hw_frame_provider_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostContextTestDontUseLostResources);

class LayerTreeHostContextTestImplSidePainting
    : public LayerTreeHostContextTest {
 public:
  void SetupTree() override {
    scoped_refptr<Layer> root = Layer::Create();
    root->SetBounds(gfx::Size(10, 10));
    root->SetIsDrawable(true);

    scoped_refptr<PictureLayer> picture = PictureLayer::Create(&client_);
    picture->SetBounds(gfx::Size(10, 10));
    client_.set_bounds(picture->bounds());
    picture->SetIsDrawable(true);
    root->AddChild(picture);

    layer_tree_host()->SetRootLayer(root);
    LayerTreeHostContextTest::SetupTree();
  }

  void BeginTest() override {
    times_to_lose_during_commit_ = 1;
    PostSetNeedsCommitToMainThread();
  }

  void AfterTest() override {}

  void DidInitializeLayerTreeFrameSink() override { EndTest(); }

 private:
  FakeContentLayerClient client_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostContextTestImplSidePainting);

class ScrollbarLayerLostContext : public LayerTreeHostContextTest {
 public:
  ScrollbarLayerLostContext() : commits_(0) {}

  void BeginTest() override {
    scoped_refptr<Layer> scroll_layer = Layer::Create();
    scrollbar_layer_ = FakePaintedScrollbarLayer::Create(
        false, true, scroll_layer->element_id());
    scrollbar_layer_->SetBounds(gfx::Size(10, 100));
    layer_tree_host()->root_layer()->AddChild(scrollbar_layer_);
    layer_tree_host()->root_layer()->AddChild(scroll_layer);
    PostSetNeedsCommitToMainThread();
  }

  void AfterTest() override {}

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    LayerTreeHostContextTest::CommitCompleteOnThread(impl);

    ++commits_;
    switch (commits_) {
      case 1:
        // First (regular) update, we should upload 2 resources (thumb, and
        // backtrack).
        EXPECT_EQ(1, scrollbar_layer_->update_count());
        LoseContext();
        break;
      case 2:
        // Second update, after the lost context, we should still upload 2
        // resources even if the contents haven't changed.
        EXPECT_EQ(2, scrollbar_layer_->update_count());
        EndTest();
        break;
      default:
        NOTREACHED();
    }
  }

 private:
  int commits_;
  scoped_refptr<FakePaintedScrollbarLayer> scrollbar_layer_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(ScrollbarLayerLostContext);

class UIResourceLostTest : public LayerTreeHostContextTest {
 public:
  UIResourceLostTest() : time_step_(0) {}
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }
  void AfterTest() override {}

  // This is called on the main thread after each commit and
  // DidActivateTreeOnThread, with the value of time_step_ at the time
  // of the call to DidActivateTreeOnThread. Similar tests will do
  // work on the main thread in DidCommit but that is unsuitable because
  // the main thread work for these tests must happen after
  // DidActivateTreeOnThread, which happens after DidCommit with impl-side
  // painting.
  virtual void StepCompleteOnMainThread(int time_step) = 0;

  // Called after DidActivateTreeOnThread. If this is done during the commit,
  // the call to StepCompleteOnMainThread will not occur until after
  // the commit completes, because the main thread is blocked.
  void PostStepCompleteToMainThread() {
    task_runner_provider()->MainThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(&UIResourceLostTest::StepCompleteOnMainThreadInternal,
                       base::Unretained(this), time_step_));
  }

  void PostLoseContextToImplThread() {
    EXPECT_TRUE(layer_tree_host()->GetTaskRunnerProvider()->IsMainThread());
    ImplThreadTaskRunner()->PostTask(
        FROM_HERE, base::BindOnce(&LayerTreeHostContextTest::LoseContext,
                                  base::Unretained(this)));
  }

 protected:
  int time_step_;
  std::unique_ptr<FakeScopedUIResource> ui_resource_;

 private:
  void StepCompleteOnMainThreadInternal(int step) {
    EXPECT_TRUE(layer_tree_host()->GetTaskRunnerProvider()->IsMainThread());
    StepCompleteOnMainThread(step);
  }
};

class UIResourceLostTestSimple : public UIResourceLostTest {
 public:
  // This is called when the new layer tree has been activated.
  virtual void StepCompleteOnImplThread(LayerTreeHostImpl* impl) = 0;

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    StepCompleteOnImplThread(impl);
    PostStepCompleteToMainThread();
    ++time_step_;
  }
};

// Losing context after an UI resource has been created.
class UIResourceLostAfterCommit : public UIResourceLostTestSimple {
 public:
  void StepCompleteOnMainThread(int step) override {
    EXPECT_TRUE(layer_tree_host()->GetTaskRunnerProvider()->IsMainThread());
    switch (step) {
      case 0:
        ui_resource_ = FakeScopedUIResource::Create(
            layer_tree_host()->GetUIResourceManager());
        // Expects a valid UIResourceId.
        EXPECT_NE(0, ui_resource_->id());
        PostSetNeedsCommitToMainThread();
        break;
      case 4:
        // Release resource before ending the test.
        ui_resource_ = nullptr;
        EndTest();
        break;
      case 5:
        NOTREACHED();
        break;
    }
  }

  void StepCompleteOnImplThread(LayerTreeHostImpl* impl) override {
    LayerTreeHostContextTest::CommitCompleteOnThread(impl);
    switch (time_step_) {
      case 1:
        // The resource should have been created on LTHI after the commit.
        EXPECT_NE(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        LoseContext();
        break;
      case 3:
        // The resources should have been recreated. The bitmap callback should
        // have been called once with the resource_lost flag set to true.
        EXPECT_EQ(1, ui_resource_->lost_resource_count);
        // Resource Id on the impl-side have been recreated as well. Note
        // that the same UIResourceId persists after the context lost.
        EXPECT_NE(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
        PostSetNeedsCommitToMainThread();
        break;
    }
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(UIResourceLostAfterCommit);

// Losing context before UI resource requests can be commited.  Three sequences
// of creation/deletion are considered:
// 1. Create one resource -> Context Lost => Expect the resource to have been
// created.
// 2. Delete an existing resource (test_id0_) -> create a second resource
// (test_id1_) -> Context Lost => Expect the test_id0_ to be removed and
// test_id1_ to have been created.
// 3. Create one resource -> Delete that same resource -> Context Lost => Expect
// the resource to not exist in the manager.
class UIResourceLostBeforeCommit : public UIResourceLostTestSimple {
 public:
  UIResourceLostBeforeCommit() : test_id0_(0), test_id1_(0) {}

  void StepCompleteOnMainThread(int step) override {
    switch (step) {
      case 0:
        ui_resource_ = FakeScopedUIResource::Create(
            layer_tree_host()->GetUIResourceManager());
        // Lose the context on the impl thread before the commit.
        PostLoseContextToImplThread();
        break;
      case 2:
        // Sequence 2:
        // Currently one resource has been created.
        test_id0_ = ui_resource_->id();
        // Delete this resource.
        ui_resource_ = nullptr;
        // Create another resource.
        ui_resource_ = FakeScopedUIResource::Create(
            layer_tree_host()->GetUIResourceManager());
        test_id1_ = ui_resource_->id();
        // Sanity check that two resource creations return different ids.
        EXPECT_NE(test_id0_, test_id1_);
        // Lose the context on the impl thread before the commit.
        PostLoseContextToImplThread();
        break;
      case 3:
        // Clear the manager of resources.
        ui_resource_ = nullptr;
        PostSetNeedsCommitToMainThread();
        break;
      case 4:
        // Sequence 3:
        ui_resource_ = FakeScopedUIResource::Create(
            layer_tree_host()->GetUIResourceManager());
        test_id0_ = ui_resource_->id();
        // Sanity check the UIResourceId should not be 0.
        EXPECT_NE(0, test_id0_);
        // Usually ScopedUIResource are deleted from the manager in their
        // destructor (so usually ui_resource_ = nullptr).  But here we need
        // ui_resource_ for the next step, so call DeleteUIResource directly.
        layer_tree_host()->GetUIResourceManager()->DeleteUIResource(test_id0_);
        // Delete the resouce and then lose the context.
        PostLoseContextToImplThread();
        break;
      case 5:
        // Release resource before ending the test.
        ui_resource_ = nullptr;
        EndTest();
        break;
      case 6:
        NOTREACHED();
        break;
    }
  }

  void StepCompleteOnImplThread(LayerTreeHostImpl* impl) override {
    LayerTreeHostContextTest::CommitCompleteOnThread(impl);
    switch (time_step_) {
      case 1:
        // Sequence 1 (continued):
        // The first context lost happens before the resources were created,
        // and because it resulted in no resources being destroyed, it does not
        // trigger resource re-creation.
        EXPECT_EQ(1, ui_resource_->resource_create_count);
        EXPECT_EQ(0, ui_resource_->lost_resource_count);
        // Resource Id on the impl-side has been created.
        PostSetNeedsCommitToMainThread();
        break;
      case 3:
        // Sequence 2 (continued):
        // The previous resource should have been deleted.
        EXPECT_EQ(0u, impl->ResourceIdForUIResource(test_id0_));
        // The second resource should have been created.
        EXPECT_NE(0u, impl->ResourceIdForUIResource(test_id1_));
        // The second resource was not actually uploaded before the context
        // was lost, so it only got created once.
        EXPECT_EQ(1, ui_resource_->resource_create_count);
        EXPECT_EQ(0, ui_resource_->lost_resource_count);
        break;
      case 5:
        // Sequence 3 (continued):
        // Expect the resource callback to have been called once.
        EXPECT_EQ(1, ui_resource_->resource_create_count);
        // No "resource lost" callbacks.
        EXPECT_EQ(0, ui_resource_->lost_resource_count);
        // The UI resource id should not be valid
        EXPECT_EQ(0u, impl->ResourceIdForUIResource(test_id0_));
        break;
    }
  }

 private:
  UIResourceId test_id0_;
  UIResourceId test_id1_;
};

// http://crbug.com/803532 : Flaky on Win 7 (dbg).
#if defined(NDEBUG) || !defined(OS_WIN)
SINGLE_THREAD_TEST_F(UIResourceLostBeforeCommit);
#endif
MULTI_THREAD_TEST_F(UIResourceLostBeforeCommit);

// Losing UI resource before the pending trees is activated but after the
// commit.  Impl-side-painting only.
class UIResourceLostBeforeActivateTree : public UIResourceLostTest {
  void StepCompleteOnMainThread(int step) override {
    EXPECT_TRUE(layer_tree_host()->GetTaskRunnerProvider()->IsMainThread());
    switch (step) {
      case 0:
        ui_resource_ = FakeScopedUIResource::Create(
            layer_tree_host()->GetUIResourceManager());
        PostSetNeedsCommitToMainThread();
        break;
      case 3:
        test_id_ = ui_resource_->id();
        ui_resource_ = nullptr;
        PostSetNeedsCommitToMainThread();
        break;
      case 5:
        // Release resource before ending the test.
        ui_resource_ = nullptr;
        EndTest();
        break;
      case 6:
        // Make sure no extra commits happened.
        NOTREACHED();
    }
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    LayerTreeHostContextTest::CommitCompleteOnThread(impl);
    switch (time_step_) {
      case 2:
        PostSetNeedsCommitToMainThread();
        break;
      case 4:
        PostSetNeedsCommitToMainThread();
        break;
    }
  }

  void WillActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    switch (time_step_) {
      case 1:
        // The resource creation callback has been called.
        EXPECT_EQ(1, ui_resource_->resource_create_count);
        // The resource is not yet lost (sanity check).
        EXPECT_EQ(0, ui_resource_->lost_resource_count);
        // The resource should not have been created yet on the impl-side.
        EXPECT_EQ(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
        LoseContext();
        break;
      case 3:
        LoseContext();
        break;
    }
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    LayerTreeHostContextTest::DidActivateTreeOnThread(impl);
    switch (time_step_) {
      case 1:
        // The pending requests on the impl-side should not have been processed
        // since the context was lost. But we should have marked the resource as
        // evicted instead.
        EXPECT_EQ(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
        EXPECT_TRUE(impl->EvictedUIResourcesExist());
        break;
      case 2:
        // The "lost resource" callback should have been called once and it
        // should have gotten recreated now and shouldn't be marked as evicted
        // anymore.
        EXPECT_EQ(1, ui_resource_->lost_resource_count);
        EXPECT_NE(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
        EXPECT_FALSE(impl->EvictedUIResourcesExist());
        break;
      case 4:
        // The resource is deleted and should not be in the manager.  Use
        // test_id_ since ui_resource_ has been deleted.
        EXPECT_EQ(0u, impl->ResourceIdForUIResource(test_id_));
        break;
    }

    PostStepCompleteToMainThread();
    ++time_step_;
  }

 private:
  UIResourceId test_id_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(UIResourceLostBeforeActivateTree);

// Resources evicted explicitly and by visibility changes.
class UIResourceLostEviction : public UIResourceLostTestSimple {
 public:
  void StepCompleteOnMainThread(int step) override {
    EXPECT_TRUE(layer_tree_host()->GetTaskRunnerProvider()->IsMainThread());
    switch (step) {
      case 0:
        ui_resource_ = FakeScopedUIResource::Create(
            layer_tree_host()->GetUIResourceManager());
        ui_resource2_ = FakeScopedUIResource::Create(
            layer_tree_host()->GetUIResourceManager());
        EXPECT_NE(0, ui_resource_->id());
        EXPECT_NE(0, ui_resource2_->id());
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        // Make the tree not visible.
        PostSetVisibleToMainThread(false);
        ui_resource2_->DeleteResource();
        ui_resource3_ = FakeScopedUIResource::Create(
            layer_tree_host()->GetUIResourceManager());
        break;
      case 3:
        // Release resources before ending the test.
        ui_resource_ = nullptr;
        ui_resource2_ = nullptr;
        ui_resource3_ = nullptr;
        EndTest();
        break;
      case 4:
        NOTREACHED();
    }
  }

  void DidSetVisibleOnImplTree(LayerTreeHostImpl* impl, bool visible) override {
    if (!visible) {
      // All resources should have been evicted.
      ASSERT_EQ(0u, context3d_->NumTextures());
      EXPECT_EQ(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
      EXPECT_EQ(0u, impl->ResourceIdForUIResource(ui_resource2_->id()));
      EXPECT_EQ(0u, impl->ResourceIdForUIResource(ui_resource3_->id()));
      EXPECT_EQ(2, ui_resource_->resource_create_count);
      EXPECT_EQ(1, ui_resource_->lost_resource_count);
      // Drawing is disabled both because of the evicted resources and
      // because the renderer is not visible.
      EXPECT_FALSE(impl->CanDraw());
      // Make the renderer visible again.
      PostSetVisibleToMainThread(true);
    }
  }

  void StepCompleteOnImplThread(LayerTreeHostImpl* impl) override {
    LayerTreeHostContextTest::CommitCompleteOnThread(impl);
    switch (time_step_) {
      case 1:
        // The first two resources should have been created on LTHI after the
        // commit.
        ASSERT_EQ(2u, context3d_->NumTextures());
        EXPECT_NE(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
        EXPECT_NE(0u, impl->ResourceIdForUIResource(ui_resource2_->id()));
        EXPECT_EQ(1, ui_resource_->resource_create_count);
        EXPECT_EQ(0, ui_resource_->lost_resource_count);
        EXPECT_TRUE(impl->CanDraw());
        // Evict all UI resources. This will trigger a commit.
        impl->EvictAllUIResources();
        ASSERT_EQ(0u, context3d_->NumTextures());
        EXPECT_EQ(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
        EXPECT_EQ(0u, impl->ResourceIdForUIResource(ui_resource2_->id()));
        EXPECT_EQ(1, ui_resource_->resource_create_count);
        EXPECT_EQ(0, ui_resource_->lost_resource_count);
        EXPECT_FALSE(impl->CanDraw());
        break;
      case 2:
        // The first two resources should have been recreated.
        ASSERT_EQ(2u, context3d_->NumTextures());
        EXPECT_NE(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
        EXPECT_EQ(2, ui_resource_->resource_create_count);
        EXPECT_EQ(1, ui_resource_->lost_resource_count);
        EXPECT_NE(0u, impl->ResourceIdForUIResource(ui_resource2_->id()));
        EXPECT_EQ(2, ui_resource2_->resource_create_count);
        EXPECT_EQ(1, ui_resource2_->lost_resource_count);
        EXPECT_TRUE(impl->CanDraw());
        break;
      case 3:
        // The first resource should have been recreated after visibility was
        // restored.
        ASSERT_EQ(2u, context3d_->NumTextures());
        EXPECT_NE(0u, impl->ResourceIdForUIResource(ui_resource_->id()));
        EXPECT_EQ(3, ui_resource_->resource_create_count);
        EXPECT_EQ(2, ui_resource_->lost_resource_count);

        // This resource was deleted.
        EXPECT_EQ(0u, impl->ResourceIdForUIResource(ui_resource2_->id()));
        EXPECT_EQ(2, ui_resource2_->resource_create_count);
        EXPECT_EQ(1, ui_resource2_->lost_resource_count);

        // This resource should have been created now.
        EXPECT_NE(0u, impl->ResourceIdForUIResource(ui_resource3_->id()));
        EXPECT_EQ(1, ui_resource3_->resource_create_count);
        EXPECT_EQ(0, ui_resource3_->lost_resource_count);
        EXPECT_TRUE(impl->CanDraw());
        break;
    }
  }

 private:
  std::unique_ptr<FakeScopedUIResource> ui_resource2_;
  std::unique_ptr<FakeScopedUIResource> ui_resource3_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(UIResourceLostEviction);

class LayerTreeHostContextTestLoseAfterSendingBeginMainFrame
    : public LayerTreeHostContextTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillBeginMainFrame() override {
    // Don't begin a frame with a lost surface.
    EXPECT_FALSE(lost_);

    if (deferred_)
      return;
    deferred_ = true;

    // Defer commits before the BeginFrame completes, causing it to be delayed.
    layer_tree_host()->SetDeferCommits(true);
    // Meanwhile, lose the context while we are in defer commits.
    ImplThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(&LayerTreeHostContextTestLoseAfterSendingBeginMainFrame::
                           LoseContextOnImplThread,
                       base::Unretained(this)));

    // After the first frame, we will lose the context and then not start
    // allowing commits until that happens. The 2nd frame should not happen
    // before DidInitializeLayerTreeFrameSink occurs.
    lost_ = true;
  }

  void DidInitializeLayerTreeFrameSink() override {
    EXPECT_TRUE(lost_);
    lost_ = false;
  }

  void LoseContextOnImplThread() {
    LoseContext();

    // After losing the context, stop deferring commits.
    PostSetDeferCommitsToMainThread(false);
  }

  void DidCommitAndDrawFrame() override { EndTest(); }

  void AfterTest() override {}

  bool deferred_ = false;
  bool lost_ = true;
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostContextTestLoseAfterSendingBeginMainFrame);

class LayerTreeHostContextTestWorkerContextLostRecovery : public LayerTreeTest {
 protected:
  void SetupTree() override {
    PaintFlags flags;
    client_.set_fill_with_nonsolid_color(true);
    client_.add_draw_rect(gfx::Rect(5, 5), flags);

    scoped_refptr<FakePictureLayer> picture_layer =
        FakePictureLayer::Create(&client_);
    picture_layer->SetBounds(gfx::Size(10, 20));
    client_.set_bounds(picture_layer->bounds());
    layer_tree_host()->SetRootLayer(picture_layer);

    LayerTreeTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillPrepareTilesOnThread(LayerTreeHostImpl* host_impl) override {
    if (did_lose_context)
      return;
    did_lose_context = true;
    viz::RasterContextProvider::ScopedRasterContextLock scoped_context(
        host_impl->layer_tree_frame_sink()->worker_context_provider());
    gpu::raster::RasterInterface* ri = scoped_context.RasterInterface();
    ri->LoseContextCHROMIUM(GL_GUILTY_CONTEXT_RESET_ARB,
                            GL_INNOCENT_CONTEXT_RESET_ARB);
  }

  void DidInitializeLayerTreeFrameSink() override { num_frame_sinks_++; }

  void DidCommitAndDrawFrame() override { EndTest(); }

  void AfterTest() override {
    EXPECT_TRUE(did_lose_context);
    EXPECT_EQ(num_frame_sinks_, 2);
  }

  FakeContentLayerClient client_;
  bool did_lose_context = false;
  int num_frame_sinks_ = 0;
};

MULTI_THREAD_TEST_F(LayerTreeHostContextTestWorkerContextLostRecovery);

}  // namespace
}  // namespace cc

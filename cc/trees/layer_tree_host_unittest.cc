// Copyright 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cc/trees/layer_tree_host.h"

#include <stddef.h>
#include <stdint.h>

#include <algorithm>

#include "base/auto_reset.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "cc/animation/timing_function.h"
#include "cc/input/scroll_elasticity_helper.h"
#include "cc/layers/content_layer_client.h"
#include "cc/layers/heads_up_display_layer.h"
#include "cc/layers/layer_impl.h"
#include "cc/layers/painted_scrollbar_layer.h"
#include "cc/layers/picture_layer.h"
#include "cc/layers/solid_color_layer.h"
#include "cc/layers/video_layer.h"
#include "cc/paint/image_animation_count.h"
#include "cc/resources/ui_resource_manager.h"
#include "cc/test/fake_content_layer_client.h"
#include "cc/test/fake_layer_tree_host_client.h"
#include "cc/test/fake_paint_image_generator.h"
#include "cc/test/fake_painted_scrollbar_layer.h"
#include "cc/test/fake_picture_layer.h"
#include "cc/test/fake_picture_layer_impl.h"
#include "cc/test/fake_proxy.h"
#include "cc/test/fake_recording_source.h"
#include "cc/test/fake_scoped_ui_resource.h"
#include "cc/test/fake_video_frame_provider.h"
#include "cc/test/geometry_test_utils.h"
#include "cc/test/layer_test_common.h"
#include "cc/test/layer_tree_test.h"
#include "cc/test/push_properties_counting_layer.h"
#include "cc/test/push_properties_counting_layer_impl.h"
#include "cc/test/render_pass_test_utils.h"
#include "cc/test/skia_common.h"
#include "cc/trees/clip_node.h"
#include "cc/trees/effect_node.h"
#include "cc/trees/frame_rate_counter.h"
#include "cc/trees/layer_tree_host_common.h"
#include "cc/trees/layer_tree_host_impl.h"
#include "cc/trees/layer_tree_impl.h"
#include "cc/trees/scroll_node.h"
#include "cc/trees/single_thread_proxy.h"
#include "cc/trees/swap_promise.h"
#include "cc/trees/swap_promise_manager.h"
#include "cc/trees/transform_node.h"
#include "components/ukm/test_ukm_recorder.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "components/viz/common/frame_sinks/copy_output_request.h"
#include "components/viz/common/frame_sinks/copy_output_result.h"
#include "components/viz/common/quads/draw_quad.h"
#include "components/viz/common/quads/render_pass_draw_quad.h"
#include "components/viz/common/quads/tile_draw_quad.h"
#include "components/viz/service/display/output_surface.h"
#include "components/viz/test/begin_frame_args_test.h"
#include "components/viz/test/fake_output_surface.h"
#include "components/viz/test/test_layer_tree_frame_sink.h"
#include "components/viz/test/test_web_graphics_context_3d.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/khronos/GLES2/gl2.h"
#include "third_party/khronos/GLES2/gl2ext.h"
#include "third_party/skia/include/core/SkPicture.h"
#include "third_party/skia/include/gpu/GrContext.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

using testing::_;
using testing::AnyNumber;
using testing::AtLeast;
using testing::Mock;

namespace cc {
namespace {
const char kUserInteraction[] = "Compositor.UserInteraction";
const char kCheckerboardArea[] = "CheckerboardedContentArea";
const char kCheckerboardAreaRatio[] = "CheckerboardedContentAreaRatio";
const char kMissingTiles[] = "NumMissingTiles";

class LayerTreeHostTest : public LayerTreeTest {};

class LayerTreeHostTestHasImplThreadTest : public LayerTreeHostTest {
 public:
  LayerTreeHostTestHasImplThreadTest() : single_threaded_(false) {}

  void RunTest(CompositorMode mode) override {
    single_threaded_ = mode == CompositorMode::SINGLE_THREADED;
    LayerTreeHostTest::RunTest(mode);
  }

  void BeginTest() override {
    EXPECT_EQ(single_threaded_, !HasImplThread());
    EndTest();
  }

  void AfterTest() override { EXPECT_EQ(single_threaded_, !HasImplThread()); }

 private:
  bool single_threaded_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestHasImplThreadTest);

class LayerTreeHostTestSetNeedsCommitInsideLayout : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void UpdateLayerTreeHost(
      LayerTreeHostClient::VisualStateUpdate requested_update) override {
    // This shouldn't cause a second commit to happen.
    layer_tree_host()->SetNeedsCommit();
  }

  void DidCommit() override {
    EXPECT_EQ(1, layer_tree_host()->SourceFrameNumber());
    EndTest();
  }

  void AfterTest() override {}
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestSetNeedsCommitInsideLayout);

class LayerTreeHostTestFrameOrdering : public LayerTreeHostTest {
 protected:
  enum MainOrder : int {
    MAIN_START = 1,
    MAIN_LAYOUT,
    MAIN_COMMIT_COMPLETE,
    MAIN_DID_BEGIN_FRAME,
    MAIN_END,
  };

  enum ImplOrder : int {
    IMPL_START = 1,
    IMPL_READY_TO_COMMIT,
    IMPL_COMMIT,
    IMPL_COMMIT_COMPLETE,
    IMPL_ACTIVATE,
    IMPL_DRAW,
    IMPL_END,
  };

  template <typename T>
  bool CheckStep(T next, T* var) {
    int expected = next - 1;
    EXPECT_EQ(expected, *var);
    bool correct = expected == *var;
    *var = next;
    return correct;
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void UpdateLayerTreeHost(
      LayerTreeHostClient::VisualStateUpdate requested_update) override {
    EXPECT_TRUE(CheckStep(MAIN_LAYOUT, &main_));
  }

  void DidCommit() override {
    EXPECT_TRUE(CheckStep(MAIN_COMMIT_COMPLETE, &main_));
  }

  void DidBeginMainFrame() override {
    EXPECT_TRUE(CheckStep(MAIN_DID_BEGIN_FRAME, &main_));
  }

  void ReadyToCommitOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_TRUE(CheckStep(IMPL_READY_TO_COMMIT, &impl_));
  }

  void BeginCommitOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_TRUE(CheckStep(IMPL_COMMIT, &impl_));
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_TRUE(CheckStep(IMPL_COMMIT_COMPLETE, &impl_));
  }

  void WillActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_TRUE(CheckStep(IMPL_ACTIVATE, &impl_));
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_TRUE(CheckStep(IMPL_DRAW, &impl_));
    EndTest();
  }

  void AfterTest() override {
    EXPECT_TRUE(CheckStep(MAIN_END, &main_));
    EXPECT_TRUE(CheckStep(IMPL_END, &impl_));
  }

  MainOrder main_ = MAIN_START;
  ImplOrder impl_ = IMPL_START;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestFrameOrdering);

class LayerTreeHostTestSetNeedsUpdateInsideLayout : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void UpdateLayerTreeHost(
      LayerTreeHostClient::VisualStateUpdate requested_update) override {
    // This shouldn't cause a second commit to happen.
    layer_tree_host()->SetNeedsUpdateLayers();
  }

  void DidCommit() override {
    EXPECT_EQ(1, layer_tree_host()->SourceFrameNumber());
    EndTest();
  }

  void AfterTest() override {}
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestSetNeedsUpdateInsideLayout);

// Test if the LTHI receives ReadyToActivate notifications from the TileManager
// when no raster tasks get scheduled.
class LayerTreeHostTestReadyToActivateEmpty : public LayerTreeHostTest {
 public:
  LayerTreeHostTestReadyToActivateEmpty()
      : did_notify_ready_to_activate_(false),
        all_tiles_required_for_activation_are_ready_to_draw_(false),
        required_for_activation_count_(0) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    const std::vector<PictureLayerImpl*>& layers =
        impl->sync_tree()->picture_layers();
    required_for_activation_count_ = 0;
    for (auto* layer : layers) {
      FakePictureLayerImpl* fake_layer =
          static_cast<FakePictureLayerImpl*>(layer);
      required_for_activation_count_ +=
          fake_layer->CountTilesRequiredForActivation();
    }
  }

  void NotifyReadyToActivateOnThread(LayerTreeHostImpl* impl) override {
    did_notify_ready_to_activate_ = true;
    all_tiles_required_for_activation_are_ready_to_draw_ =
        impl->tile_manager()->IsReadyToActivate();
    EndTest();
  }

  void AfterTest() override {
    EXPECT_TRUE(did_notify_ready_to_activate_);
    EXPECT_TRUE(all_tiles_required_for_activation_are_ready_to_draw_);
    EXPECT_EQ(size_t(0), required_for_activation_count_);
  }

 protected:
  bool did_notify_ready_to_activate_;
  bool all_tiles_required_for_activation_are_ready_to_draw_;
  size_t required_for_activation_count_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestReadyToActivateEmpty);

// Test if the LTHI receives ReadyToActivate notifications from the TileManager
// when some raster tasks flagged as REQUIRED_FOR_ACTIVATION got scheduled.
class LayerTreeHostTestReadyToActivateNonEmpty
    : public LayerTreeHostTestReadyToActivateEmpty {
 public:
  void SetupTree() override {
    client_.set_fill_with_nonsolid_color(true);
    scoped_refptr<FakePictureLayer> root_layer =
        FakePictureLayer::Create(&client_);
    root_layer->SetBounds(gfx::Size(1024, 1024));
    root_layer->SetIsDrawable(true);

    layer_tree_host()->SetRootLayer(root_layer);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer->bounds());
  }

  void AfterTest() override {
    EXPECT_TRUE(did_notify_ready_to_activate_);
    EXPECT_TRUE(all_tiles_required_for_activation_are_ready_to_draw_);
    EXPECT_LE(size_t(1), required_for_activation_count_);
  }

 private:
  FakeContentLayerClient client_;
};

// No single thread test because the commit goes directly to the active tree in
// single thread mode, so notify ready to activate is skipped.
MULTI_THREAD_TEST_F(LayerTreeHostTestReadyToActivateNonEmpty);

// Test if the LTHI receives ReadyToDraw notifications from the TileManager when
// no raster tasks get scheduled.
class LayerTreeHostTestReadyToDrawEmpty : public LayerTreeHostTest {
 public:
  LayerTreeHostTestReadyToDrawEmpty()
      : did_notify_ready_to_draw_(false),
        all_tiles_required_for_draw_are_ready_to_draw_(false),
        required_for_draw_count_(0) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void NotifyReadyToDrawOnThread(LayerTreeHostImpl* impl) override {
    did_notify_ready_to_draw_ = true;
    const std::vector<PictureLayerImpl*>& layers =
        impl->active_tree()->picture_layers();
    all_tiles_required_for_draw_are_ready_to_draw_ =
        impl->tile_manager()->IsReadyToDraw();
    for (auto* layer : layers) {
      FakePictureLayerImpl* fake_layer =
          static_cast<FakePictureLayerImpl*>(layer);
      required_for_draw_count_ += fake_layer->CountTilesRequiredForDraw();
    }

    EndTest();
  }

  void AfterTest() override {
    EXPECT_TRUE(did_notify_ready_to_draw_);
    EXPECT_TRUE(all_tiles_required_for_draw_are_ready_to_draw_);
    EXPECT_EQ(size_t(0), required_for_draw_count_);
  }

 protected:
  bool did_notify_ready_to_draw_;
  bool all_tiles_required_for_draw_are_ready_to_draw_;
  size_t required_for_draw_count_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestReadyToDrawEmpty);

// Test if the LTHI receives ReadyToDraw notifications from the TileManager when
// some raster tasks flagged as REQUIRED_FOR_DRAW got scheduled.
class LayerTreeHostTestReadyToDrawNonEmpty
    : public LayerTreeHostTestReadyToDrawEmpty {
 public:
  void SetupTree() override {
    client_.set_fill_with_nonsolid_color(true);
    scoped_refptr<FakePictureLayer> root_layer =
        FakePictureLayer::Create(&client_);
    root_layer->SetBounds(gfx::Size(1024, 1024));
    root_layer->SetIsDrawable(true);

    layer_tree_host()->SetRootLayer(root_layer);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer->bounds());
  }

  void AfterTest() override {
    EXPECT_TRUE(did_notify_ready_to_draw_);
    EXPECT_TRUE(all_tiles_required_for_draw_are_ready_to_draw_);
    EXPECT_LE(size_t(1), required_for_draw_count_);
  }

 private:
  FakeContentLayerClient client_;
};

// Note: With this test setup, we only get tiles flagged as REQUIRED_FOR_DRAW in
// single threaded mode.
SINGLE_THREAD_TEST_F(LayerTreeHostTestReadyToDrawNonEmpty);

// This tests if we get the READY_TO_DRAW signal and draw if we become invisible
// and then become visible again.
class LayerTreeHostTestReadyToDrawVisibility : public LayerTreeHostTest {
 public:
  LayerTreeHostTestReadyToDrawVisibility()
      : LayerTreeHostTest(),
        toggled_visibility_(false),
        did_notify_ready_to_draw_(false),
        did_draw_(false) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void SetupTree() override {
    client_.set_fill_with_nonsolid_color(true);
    scoped_refptr<FakePictureLayer> root_layer =
        FakePictureLayer::Create(&client_);
    root_layer->SetBounds(gfx::Size(1024, 1024));
    client_.set_bounds(root_layer->bounds());
    root_layer->SetIsDrawable(true);

    layer_tree_host()->SetRootLayer(root_layer);
    LayerTreeHostTest::SetupTree();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    if (!toggled_visibility_) {
      {
        DebugScopedSetMainThread main(task_runner_provider());
        layer_tree_host()->SetVisible(false);
      }
      toggled_visibility_ = true;
      EXPECT_FALSE(host_impl->visible());
    }
  }

  void NotifyReadyToDrawOnThread(LayerTreeHostImpl* host_impl) override {
    // Sometimes the worker thread posts NotifyReadyToDraw in the extremely
    // short duration of time between PrepareTiles and SetVisible(false) so we
    // might get two NotifyReadyToDraw signals for this test.
    did_notify_ready_to_draw_ = true;
  }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_FALSE(did_draw_);
    did_draw_ = true;
    EndTest();
  }

  void DidFinishImplFrameOnThread(LayerTreeHostImpl* host_impl) override {
    if (!host_impl->visible()) {
      {
        DebugScopedSetMainThread main(task_runner_provider());
        layer_tree_host()->SetVisible(true);
      }
      EXPECT_TRUE(host_impl->visible());
    }
  }

  void AfterTest() override {
    EXPECT_TRUE(did_notify_ready_to_draw_);
    EXPECT_TRUE(did_draw_);
  }

 private:
  FakeContentLayerClient client_;
  bool toggled_visibility_;
  bool did_notify_ready_to_draw_;
  bool did_draw_;
};

// Note: With this test setup, we only get tiles flagged as REQUIRED_FOR_DRAW in
// single threaded mode.
SINGLE_THREAD_TEST_F(LayerTreeHostTestReadyToDrawVisibility);

class LayerTreeHostContextCacheTest : public LayerTreeHostTest {
 public:
  std::unique_ptr<viz::TestLayerTreeFrameSink> CreateLayerTreeFrameSink(
      const viz::RendererSettings& renderer_settings,
      double refresh_rate,
      scoped_refptr<viz::ContextProvider> compositor_context_provider,
      scoped_refptr<viz::RasterContextProvider> worker_context_provider)
      override {
    // Create the main viz::ContextProvider with a MockContextSupport.
    auto main_support = std::make_unique<MockContextSupport>();
    mock_main_context_support_ = main_support.get();
    auto test_main_context_provider = viz::TestContextProvider::Create(
        viz::TestWebGraphicsContext3D::Create(), std::move(main_support));

    // Create the main viz::ContextProvider with a MockContextSupport.
    auto worker_support = std::make_unique<MockContextSupport>();
    mock_worker_context_support_ = worker_support.get();
    auto test_worker_context_provider = viz::TestContextProvider::CreateWorker(
        viz::TestWebGraphicsContext3D::Create(), std::move(worker_support));

    // At init, visibility is set to true, so SetAggressivelyFreeResources will
    // be disabled.
    EXPECT_CALL(*mock_main_context_support_,
                SetAggressivelyFreeResources(false));
    EXPECT_CALL(*mock_worker_context_support_,
                SetAggressivelyFreeResources(false));

    return LayerTreeHostTest::CreateLayerTreeFrameSink(
        renderer_settings, refresh_rate, std::move(test_main_context_provider),
        std::move(test_worker_context_provider));
  }

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->gpu_rasterization_forced = true;
  }

  void BeginTest() override {}
  void AfterTest() override {}

 protected:
  class MockContextSupport : public viz::TestContextSupport {
   public:
    MockContextSupport() = default;
    MOCK_METHOD1(SetAggressivelyFreeResources,
                 void(bool aggressively_free_resources));
  };

  MockContextSupport* mock_main_context_support_;
  MockContextSupport* mock_worker_context_support_;
};

// Test if the LTH successfully frees resources on the main/worker
// ContextSupport when visibility is set to false.
class LayerTreeHostFreesContextResourcesOnInvisible
    : public LayerTreeHostContextCacheTest {
 public:
  void InitializedRendererOnThread(LayerTreeHostImpl* host_impl,
                                   bool success) override {
    // Ensure that our initialization expectations have completed.
    Mock::VerifyAndClearExpectations(mock_main_context_support_);
    Mock::VerifyAndClearExpectations(mock_worker_context_support_);

    // Update visibility and make sure resources are freed.
    EXPECT_CALL(*mock_main_context_support_,
                SetAggressivelyFreeResources(true));
    EXPECT_CALL(*mock_worker_context_support_,
                SetAggressivelyFreeResources(true))
        .WillOnce(testing::Invoke([this](bool is_visible) { EndTest(); }));
    PostSetVisibleToMainThread(false);
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostFreesContextResourcesOnInvisible);

// Test if the LTH successfully frees worker context resources when the hard
// memory limit is set to zero.
class LayerTreeHostFreesWorkerContextResourcesOnZeroMemoryLimit
    : public LayerTreeHostContextCacheTest {
 public:
  void InitializedRendererOnThread(LayerTreeHostImpl* host_impl,
                                   bool success) override {
    // Ensure that our initialization expectations have completed.
    Mock::VerifyAndClearExpectations(mock_worker_context_support_);

    // Worker context support should start freeing resources when hard memory
    // limit is zeroed.
    EXPECT_CALL(*mock_worker_context_support_,
                SetAggressivelyFreeResources(true))
        .WillOnce(testing::Invoke([this](bool is_visible) {
          // Main context is unchanged. It will start freeing on destruction.
          EXPECT_CALL(*mock_main_context_support_,
                      SetAggressivelyFreeResources(true));
          EndTest();
        }));
    ManagedMemoryPolicy zero_policy(
        0, gpu::MemoryAllocation::CUTOFF_ALLOW_NOTHING, 0);
    host_impl->SetMemoryPolicy(zero_policy);
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostFreesWorkerContextResourcesOnZeroMemoryLimit);

// Test if the LTH successfully frees worker context resources when hard memory
// limit is set to zero while using a synchronous compositor (Android WebView).
class LayerTreeHostFreesWorkerContextResourcesOnZeroMemoryLimitSynchronous
    : public LayerTreeHostFreesWorkerContextResourcesOnZeroMemoryLimit {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    LayerTreeHostContextCacheTest::InitializeSettings(settings);
    settings->using_synchronous_renderer_compositor = true;
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostFreesWorkerContextResourcesOnZeroMemoryLimitSynchronous);

// Test if the LTH successfully frees main and worker resources when the
// OutputSurface is destroyed.
class LayerTreeHostFreeContextResourcesOnDestroy
    : public LayerTreeHostContextCacheTest {
 public:
  void WillBeginImplFrameOnThread(LayerTreeHostImpl* host_impl,
                                  const viz::BeginFrameArgs& args) override {
    // Ensure that our initialization expectations have completed.
    Mock::VerifyAndClearExpectations(mock_main_context_support_);
    Mock::VerifyAndClearExpectations(mock_worker_context_support_);

    // We leave the LTHI visible, so it start freeing resources on destruction.
    EXPECT_CALL(*mock_worker_context_support_,
                SetAggressivelyFreeResources(true));
    EXPECT_CALL(*mock_main_context_support_,
                SetAggressivelyFreeResources(true));
    EndTest();
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostFreeContextResourcesOnDestroy);

// Test if the LTH successfully frees and stops freeing context resources
// when the LayerTreeFrameSink is lost and recreated.
class LayerTreeHostCacheBehaviorOnLayerTreeFrameSinkRecreated
    : public LayerTreeHostContextCacheTest {
 public:
  void WillBeginImplFrameOnThread(LayerTreeHostImpl* host_impl,
                                  const viz::BeginFrameArgs& args) override {
    // This code is run once, to trigger recreation of our LayerTreeFrameSink.
    if (test_state_ != TestState::INIT)
      return;

    // Ensure that our initialization expectations have completed.
    Mock::VerifyAndClearExpectations(mock_main_context_support_);
    Mock::VerifyAndClearExpectations(mock_worker_context_support_);

    // LayerTreeFrameSink lost expectations.
    EXPECT_CALL(*mock_worker_context_support_,
                SetAggressivelyFreeResources(true));
    EXPECT_CALL(*mock_main_context_support_,
                SetAggressivelyFreeResources(true));
    host_impl->DidLoseLayerTreeFrameSink();
    test_state_ = TestState::RECREATED;
  }

  void InitializedRendererOnThread(LayerTreeHostImpl* host_impl,
                                   bool success) override {
    // This is run after we have recreated our LayerTreeFrameSink.
    if (test_state_ != TestState::RECREATED)
      return;

    // Ensure that our expectations have completed.
    Mock::VerifyAndClearExpectations(mock_main_context_support_);
    Mock::VerifyAndClearExpectations(mock_worker_context_support_);

    // Destruction exptectations.
    EXPECT_CALL(*mock_worker_context_support_,
                SetAggressivelyFreeResources(true));
    EXPECT_CALL(*mock_main_context_support_,
                SetAggressivelyFreeResources(true));
    EndTest();
    test_state_ = TestState::DONE;
  }

 private:
  enum class TestState { INIT, RECREATED, DONE };
  TestState test_state_ = TestState::INIT;
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostCacheBehaviorOnLayerTreeFrameSinkRecreated);

// Two setNeedsCommits in a row should lead to at least 1 commit and at least 1
// draw with frame 0.
class LayerTreeHostTestSetNeedsCommit1 : public LayerTreeHostTest {
 public:
  LayerTreeHostTestSetNeedsCommit1() : num_commits_(0), num_draws_(0) {}

  void BeginTest() override {
    PostSetNeedsCommitToMainThread();
    PostSetNeedsCommitToMainThread();
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    num_draws_++;
    if (!impl->active_tree()->source_frame_number())
      EndTest();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    num_commits_++;
  }

  void AfterTest() override {
    EXPECT_LE(1, num_commits_);
    EXPECT_LE(1, num_draws_);
  }

 private:
  int num_commits_;
  int num_draws_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestSetNeedsCommit1);

// A SetNeedsCommit should lead to 1 commit. Issuing a second commit after that
// first committed frame draws should lead to another commit.
class LayerTreeHostTestSetNeedsCommit2 : public LayerTreeHostTest {
 public:
  LayerTreeHostTestSetNeedsCommit2() : num_commits_(0), num_draws_(0) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override { ++num_draws_; }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    ++num_commits_;
    switch (num_commits_) {
      case 1:
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        EndTest();
        break;
      default:
        NOTREACHED();
    }
  }

  void AfterTest() override {
    EXPECT_EQ(2, num_commits_);
    EXPECT_LE(1, num_draws_);
  }

 private:
  int num_commits_;
  int num_draws_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestSetNeedsCommit2);

// Verify that we pass property values in PushPropertiesTo.
class LayerTreeHostTestPushPropertiesTo : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    scoped_refptr<Layer> root = Layer::Create();
    root->SetBounds(gfx::Size(10, 10));
    layer_tree_host()->SetRootLayer(root);
    LayerTreeHostTest::SetupTree();
  }

  enum Properties {
    STARTUP,
    BOUNDS,
    HIDE_LAYER_AND_SUBTREE,
    DRAWS_CONTENT,
    DONE,
  };

  void BeginTest() override {
    index_ = STARTUP;
    PostSetNeedsCommitToMainThread();
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    VerifyAfterValues(impl->active_tree()->root_layer_for_testing());
  }

  void DidCommitAndDrawFrame() override {
    SetBeforeValues(layer_tree_host()->root_layer());
    VerifyBeforeValues(layer_tree_host()->root_layer());

    ++index_;
    if (index_ == DONE) {
      EndTest();
      return;
    }

    SetAfterValues(layer_tree_host()->root_layer());
  }

  void AfterTest() override {}

  void VerifyBeforeValues(Layer* layer) {
    EXPECT_EQ(gfx::Size(10, 10).ToString(), layer->bounds().ToString());
    EXPECT_FALSE(layer->hide_layer_and_subtree());
    EXPECT_FALSE(layer->DrawsContent());
  }

  void SetBeforeValues(Layer* layer) {
    layer->SetBounds(gfx::Size(10, 10));
    layer->SetHideLayerAndSubtree(false);
    layer->SetIsDrawable(false);
  }

  void VerifyAfterValues(LayerImpl* layer) {
    EffectTree& tree = layer->layer_tree_impl()->property_trees()->effect_tree;
    EffectNode* node = tree.Node(layer->effect_tree_index());
    switch (static_cast<Properties>(index_)) {
      case STARTUP:
      case DONE:
        break;
      case BOUNDS:
        EXPECT_EQ(gfx::Size(20, 20).ToString(), layer->bounds().ToString());
        break;
      case HIDE_LAYER_AND_SUBTREE:
        EXPECT_EQ(tree.EffectiveOpacity(node), 0.f);
        break;
      case DRAWS_CONTENT:
        EXPECT_TRUE(layer->DrawsContent());
        break;
    }
  }

  void SetAfterValues(Layer* layer) {
    switch (static_cast<Properties>(index_)) {
      case STARTUP:
      case DONE:
        break;
      case BOUNDS:
        layer->SetBounds(gfx::Size(20, 20));
        break;
      case HIDE_LAYER_AND_SUBTREE:
        layer->SetHideLayerAndSubtree(true);
        break;
      case DRAWS_CONTENT:
        layer->SetIsDrawable(true);
        break;
    }
  }

  int index_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestPushPropertiesTo);

class LayerTreeHostTestPushNodeOwnerToNodeIdMap : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root_ = Layer::Create();
    child_ = Layer::Create();
    root_->AddChild(child_);
    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // child_ should create transform, effect node.
        child_->SetForceRenderSurfaceForTesting(true);
        break;
      case 2:
        // child_ should create a scroll node.
        child_->SetScrollable(gfx::Size(1, 1));
        break;
      case 3:
        // child_ should create a clip node.
        child_->SetMasksToBounds(true);
        break;
      case 4:
        // child_ should only create the scroll-related nodes.
        child_->SetMasksToBounds(false);
        child_->SetForceRenderSurfaceForTesting(false);
        // Should have no effect because empty bounds do not prevent scrolling.
        child_->SetScrollable(gfx::Size(0, 0));
    }
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    PropertyTrees* property_trees = impl->sync_tree()->property_trees();
    const TransformNode* root_transform_node =
        property_trees->transform_tree.Node(root_->transform_tree_index());
    const TransformNode* child_transform_node =
        property_trees->transform_tree.Node(child_->transform_tree_index());
    const EffectNode* root_effect_node =
        property_trees->effect_tree.Node(root_->effect_tree_index());
    const EffectNode* child_effect_node =
        property_trees->effect_tree.Node(child_->effect_tree_index());
    const ClipNode* root_clip_node =
        property_trees->clip_tree.Node(root_->clip_tree_index());
    const ClipNode* child_clip_node =
        property_trees->clip_tree.Node(child_->clip_tree_index());
    const ScrollNode* root_scroll_node =
        property_trees->scroll_tree.Node(root_->scroll_tree_index());
    const ScrollNode* child_scroll_node =
        property_trees->scroll_tree.Node(child_->scroll_tree_index());
    switch (impl->sync_tree()->source_frame_number()) {
      case 0:
        // root_ should create transform, scroll and effect tree nodes but not
        // a clip node.
        EXPECT_NE(nullptr, root_transform_node);
        EXPECT_NE(nullptr, root_effect_node);
        EXPECT_NE(nullptr, root_scroll_node);
        EXPECT_NE(nullptr, root_clip_node);
        EXPECT_EQ(root_transform_node, child_transform_node);
        EXPECT_EQ(child_effect_node, root_effect_node);
        EXPECT_EQ(root_clip_node, child_clip_node);
        EXPECT_EQ(root_scroll_node, child_scroll_node);

        break;
      case 1:
        // child_ should create a transfrom, effect nodes but not a scroll, clip
        // node.
        EXPECT_NE(root_transform_node, child_transform_node);
        EXPECT_NE(child_effect_node, root_effect_node);
        EXPECT_EQ(root_clip_node, child_clip_node);
        EXPECT_EQ(root_scroll_node, child_scroll_node);

        break;
      case 2:
        // child_ should create a scroll node.
        EXPECT_NE(root_scroll_node, child_scroll_node);
        break;
      case 3:
        // child_ should create a clip node.
        EXPECT_NE(root_clip_node, child_clip_node);
        break;
      case 4:
        // child_ should only create the scroll-related nodes.
        EXPECT_EQ(child_transform_node->id, child_scroll_node->transform_id);
        EXPECT_EQ(child_effect_node, root_effect_node);
        EXPECT_EQ(root_clip_node, child_clip_node);
        EXPECT_NE(root_scroll_node, child_scroll_node);
        EndTest();
        break;
    }
  }

  void AfterTest() override {}

 private:
  scoped_refptr<Layer> root_;
  scoped_refptr<Layer> child_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestPushNodeOwnerToNodeIdMap);

class LayerTreeHostTestPushElementIdToNodeIdMap : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root_ = Layer::Create();
    child_ = Layer::Create();
    root_->AddChild(child_);
    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        child_->SetForceRenderSurfaceForTesting(true);
        child_->AddMainThreadScrollingReasons(
            MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects);
        break;
      case 2:
        child_->SetForceRenderSurfaceForTesting(false);
        child_->ClearMainThreadScrollingReasons(
            MainThreadScrollingReason::kHasBackgroundAttachmentFixedObjects);
        break;
    }
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    PropertyTrees* property_trees = impl->sync_tree()->property_trees();
    LayerImpl* child_impl_ = impl->sync_tree()->LayerById(child_->id());
    switch (impl->sync_tree()->source_frame_number()) {
      case 0:
        EXPECT_EQ(2U, child_impl_->layer_tree_impl()
                          ->property_trees()
                          ->transform_tree.size());
        EXPECT_EQ(2U, child_impl_->layer_tree_impl()
                          ->property_trees()
                          ->effect_tree.size());
        EXPECT_EQ(2U, child_impl_->layer_tree_impl()
                          ->property_trees()
                          ->scroll_tree.size());
        EXPECT_TRUE(property_trees->element_id_to_transform_node_index.find(
                        child_->element_id()) ==
                    property_trees->element_id_to_transform_node_index.end());
        EXPECT_TRUE(property_trees->element_id_to_effect_node_index.find(
                        child_->element_id()) ==
                    property_trees->element_id_to_effect_node_index.end());
        EXPECT_TRUE(property_trees->element_id_to_scroll_node_index.find(
                        child_->element_id()) ==
                    property_trees->element_id_to_scroll_node_index.end());
        break;
      case 1:
        EXPECT_EQ(3U, child_impl_->layer_tree_impl()
                          ->property_trees()
                          ->transform_tree.size());
        EXPECT_EQ(3U, child_impl_->layer_tree_impl()
                          ->property_trees()
                          ->effect_tree.size());
        EXPECT_EQ(3U, child_impl_->layer_tree_impl()
                          ->property_trees()
                          ->scroll_tree.size());
        EXPECT_EQ(
            2, property_trees
                   ->element_id_to_transform_node_index[child_->element_id()]);
        EXPECT_EQ(2,
                  property_trees
                      ->element_id_to_effect_node_index[child_->element_id()]);
        EXPECT_EQ(2,
                  property_trees
                      ->element_id_to_scroll_node_index[child_->element_id()]);
        break;
      case 2:
        EXPECT_EQ(2U, child_impl_->layer_tree_impl()
                          ->property_trees()
                          ->transform_tree.size());
        EXPECT_EQ(2U, child_impl_->layer_tree_impl()
                          ->property_trees()
                          ->effect_tree.size());
        EXPECT_TRUE(property_trees->element_id_to_transform_node_index.find(
                        child_->element_id()) ==
                    property_trees->element_id_to_transform_node_index.end());
        EXPECT_TRUE(property_trees->element_id_to_effect_node_index.find(
                        child_->element_id()) ==
                    property_trees->element_id_to_effect_node_index.end());
        EXPECT_TRUE(property_trees->element_id_to_scroll_node_index.find(
                        child_->element_id()) ==
                    property_trees->element_id_to_scroll_node_index.end());
        break;
    }
    EndTest();
  }

  void AfterTest() override {}

 private:
  scoped_refptr<Layer> root_;
  scoped_refptr<Layer> child_;
};

// Validates that, for a layer with a compositor element id set on it, mappings
// from compositor element id to transform/effect node indexes are created as
// part of building a layer's property tree and are present on the impl thread.
SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestPushElementIdToNodeIdMap);

class LayerTreeHostTestSurfaceDamage : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root_ = Layer::Create();
    child_ = Layer::Create();
    grand_child_ = Layer::Create();

    layer_tree_host()->SetRootLayer(root_);
    root_->AddChild(child_);
    child_->AddChild(grand_child_);

    root_->SetBounds(gfx::Size(50, 50));
    root_->SetMasksToBounds(true);
    child_->SetForceRenderSurfaceForTesting(true);

    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        grand_child_->SetOpacity(0.9f);
        break;
      case 2:
        root_->SetBounds(gfx::Size(20, 20));
        break;
      case 3:
        child_->SetDoubleSided(false);
        break;
    }
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    LayerImpl* root_impl = impl->active_tree()->LayerById(root_->id());
    LayerImpl* child_impl = impl->active_tree()->LayerById(child_->id());
    switch (impl->active_tree()->source_frame_number()) {
      case 0:
        EXPECT_TRUE(GetRenderSurface(root_impl)->AncestorPropertyChanged());
        EXPECT_TRUE(GetRenderSurface(child_impl)->AncestorPropertyChanged());
        PostSetNeedsCommitToMainThread();
        break;
      case 1:
        EXPECT_FALSE(GetRenderSurface(root_impl)->AncestorPropertyChanged());
        EXPECT_FALSE(GetRenderSurface(child_impl)->AncestorPropertyChanged());
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        EXPECT_TRUE(GetRenderSurface(root_impl)->AncestorPropertyChanged());
        EXPECT_TRUE(GetRenderSurface(child_impl)->AncestorPropertyChanged());
        PostSetNeedsCommitToMainThread();
        break;
      case 3:
        EXPECT_FALSE(GetRenderSurface(root_impl)->AncestorPropertyChanged());
        EXPECT_TRUE(GetRenderSurface(child_impl)->AncestorPropertyChanged());
        EndTest();
        PostSetNeedsCommitToMainThread();
        break;
      case 4:
        EXPECT_FALSE(GetRenderSurface(root_impl)->AncestorPropertyChanged());
        EXPECT_FALSE(GetRenderSurface(child_impl)->AncestorPropertyChanged());
        EndTest();
        break;
    }

    return draw_result;
  }

  void AfterTest() override {}

 private:
  scoped_refptr<Layer> root_;
  scoped_refptr<Layer> child_;
  scoped_refptr<Layer> grand_child_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestSurfaceDamage);

// When settings->enable_early_damage_check is true, verify that invalidate is
// not called when changes to a layer don't cause visible damage.
class LayerTreeHostTestNoDamageCausesNoInvalidate : public LayerTreeHostTest {
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->using_synchronous_renderer_compositor = true;
    settings->enable_early_damage_check = true;
  }

 protected:
  void SetupTree() override {
    root_ = Layer::Create();

    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(10, 10), 1.f,
                                               viz::LocalSurfaceId());

    layer_tree_host()->SetRootLayer(root_);

    // Translate the root layer past the viewport.
    gfx::Transform translation;
    translation.Translate(100, 100);
    root_->SetTransform(translation);

    root_->SetBounds(gfx::Size(50, 50));

    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    // This does not damage the frame because the root layer is outside the
    // viewport.
    if (layer_tree_host()->SourceFrameNumber() == 2)
      root_->SetOpacity(0.9f);
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    PostSetNeedsCommitToMainThread();
    return draw_result;
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    switch (impl->active_tree()->source_frame_number()) {
      // This gives us some assurance that invalidates happen before this call,
      // so invalidating on frame 2 will cause a failure before the test ends.
      case 0:
        EXPECT_TRUE(first_frame_invalidate_before_commit_);
        break;
      case 2:
        EndTest();
    }
  }

  void DidInvalidateLayerTreeFrameSink(LayerTreeHostImpl* impl) override {
    switch (impl->active_tree()->source_frame_number()) {
      // Be sure that invalidates happen before commits, so the below failure
      // works.
      case 0:
        first_frame_invalidate_before_commit_ = true;
        break;
      // Frame 1 will invalidate, even though it has no damage. The early
      // damage check that prevents frame 2 from invalidating only runs if
      // a previous frame did not have damage.

      // This frame should not cause an invalidate, since there is no visible
      // damage.
      case 2:
        ADD_FAILURE();
    }
  }

  void AfterTest() override {}

 private:
  scoped_refptr<Layer> root_;
  bool first_frame_invalidate_before_commit_ = false;
};

// This behavior is specific to Android WebView, which only uses
// multi-threaded compositor.
MULTI_THREAD_TEST_F(LayerTreeHostTestNoDamageCausesNoInvalidate);

// When settings->enable_early_damage_check is true, verify that the early
// damage check is turned off after |settings->damaged_frame_limit| frames
// have consecutive damage.
// The test verifies that frames come in as follows:
// 0: visible damage as the root appears; invalidated
// 1: no visible damage; invalidate because all previous frames had damage
// 2: no visible damage; check early since frame 1 had no damage; no invalidate
// 3: visible damage
// ... (visible damage)
// 3 + damaged_frame_limit - 1: visible damage
// 3 + damaged_frame_limit: no visible damage, but invalidate because all of
// the last |damaged_frame_limit| frames had damage.
class LayerTreeHostTestEarlyDamageCheckStops : public LayerTreeHostTest {
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->using_synchronous_renderer_compositor = true;
    settings->enable_early_damage_check = true;
    damaged_frame_limit_ = settings->damaged_frame_limit;
  }

 protected:
  void SetupTree() override {
    root_ = Layer::Create();
    child_ = Layer::Create();
    root_->AddChild(child_);

    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(100, 100), 1.f,
                                               viz::LocalSurfaceId());

    layer_tree_host()->SetRootLayer(root_);
    root_->SetBounds(gfx::Size(50, 50));
    child_->SetBounds(gfx::Size(50, 50));

    // Translate the child layer past the viewport.
    gfx::Transform translation;
    translation.Translate(200, 200);
    child_->SetTransform(translation);

    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillBeginMainFrame() override {
    int frame = layer_tree_host()->SourceFrameNumber();
    // Change the child layer each frame. Since the child layer is translated
    // past the viewport, it should not cause damage, but webview will still
    // invalidate if the frame doesn't check for damage early.
    child_->SetOpacity(1.0 / (float)(frame + 1));

    // For |damaged_frame_limit| consecutive frames, cause actual damage.
    if (frame >= 3 && frame < (damaged_frame_limit_ + 3)) {
      root_->SetOpacity(1.0 / (float)frame);
    }
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    PostSetNeedsCommitToMainThread();
  }

  void DidInvalidateLayerTreeFrameSink(LayerTreeHostImpl* impl) override {
    int frame_number = impl->active_tree()->source_frame_number();
    // Frames 0 and 1 invalidate because the early damage check is not enabled
    // during this setup. But frames 1 and 2 are not damaged, so the early
    // check should prevent frame 2 from invalidating.
    if (frame_number == 2) {
      ADD_FAILURE();
    } else if (frame_number > 2) {
      invalidate_count_++;
    }

    // Frame number |damaged_frame_limit_ + 3| was not damaged, but it should
    // invalidate since the previous |damaged_frame_limit_| frames had damage
    // and should have turned off the early damage check.
    if (frame_number == damaged_frame_limit_ + 3) {
      EndTest();
      return;
    }
  }

  void AfterTest() override {
    // We should invalidate |damaged_frame_limit_| frames that had actual damage
    // and one additional frame after, since the early check is disabled.
    EXPECT_EQ(invalidate_count_, damaged_frame_limit_ + 1);
  }

 private:
  scoped_refptr<Layer> root_;
  scoped_refptr<Layer> child_;
  int invalidate_count_ = 0;
  int damaged_frame_limit_;
};

// This behavior is specific to Android WebView, which only uses
// multi-threaded compositor.
MULTI_THREAD_TEST_F(LayerTreeHostTestEarlyDamageCheckStops);

// Verify CanDraw() is false until first commit.
class LayerTreeHostTestCantDrawBeforeCommit : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void ReadyToCommitOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_FALSE(host_impl->CanDraw());
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_TRUE(host_impl->CanDraw());
    EndTest();
  }

  void AfterTest() override {}
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestCantDrawBeforeCommit);

// Verify CanDraw() is false until first commit+activate.
class LayerTreeHostTestCantDrawBeforeCommitActivate : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_FALSE(host_impl->CanDraw());
  }

  void WillActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_FALSE(host_impl->CanDraw());
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_TRUE(host_impl->CanDraw());
    EndTest();
  }

  void AfterTest() override {}
};

// Single thread mode commits directly to the active tree, so CanDraw()
// is true by the time WillActivateTreeOnThread is called.
MULTI_THREAD_TEST_F(LayerTreeHostTestCantDrawBeforeCommitActivate);

// Verify damage status of property trees is preserved after commit.
class LayerTreeHostTestPropertyTreesChangedSync : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root_ = Layer::Create();
    child_ = Layer::Create();
    // This is to force the child to create a transform and effect node.
    child_->SetForceRenderSurfaceForTesting(true);
    root_->AddChild(child_);
    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostTest::SetupTree();
  }

  enum Animations {
    OPACITY,
    TRANSFORM,
    FILTER,
    END,
  };

  void BeginTest() override {
    index_ = OPACITY;
    PostSetNeedsCommitToMainThread();
  }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 2:
        // We rebuild property trees for this case to test the code path of
        // damage status synchronization when property trees are different.
        layer_tree_host()->property_trees()->needs_rebuild = true;
        break;
      default:
        EXPECT_FALSE(layer_tree_host()->property_trees()->needs_rebuild);
    }
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    gfx::Transform transform;
    FilterOperations filters;
    LayerImpl* root = impl->active_tree()->root_layer_for_testing();
    switch (static_cast<Animations>(index_)) {
      case OPACITY:
        index_++;
        impl->active_tree()->ResetAllChangeTracking();
        impl->active_tree()->SetOpacityMutated(root->element_id(), 0.5f);
        PostSetNeedsCommitToMainThread();
        break;
      case TRANSFORM:
        index_++;
        EXPECT_TRUE(impl->active_tree()
                        ->LayerById(root_->id())
                        ->LayerPropertyChanged());
        impl->active_tree()->ResetAllChangeTracking();
        EXPECT_FALSE(impl->active_tree()
                         ->LayerById(root_->id())
                         ->LayerPropertyChanged());
        EXPECT_FALSE(impl->active_tree()
                         ->LayerById(child_->id())
                         ->LayerPropertyChanged());
        transform.Translate(10, 10);
        impl->active_tree()->SetTransformMutated(root->element_id(), transform);
        PostSetNeedsCommitToMainThread();
        break;
      case FILTER:
        index_++;
        EXPECT_TRUE(root->LayerPropertyChanged());
        EXPECT_TRUE(impl->active_tree()
                        ->LayerById(child_->id())
                        ->LayerPropertyChanged());
        impl->active_tree()->ResetAllChangeTracking();
        EXPECT_FALSE(root->LayerPropertyChanged());
        EXPECT_FALSE(impl->active_tree()
                         ->LayerById(child_->id())
                         ->LayerPropertyChanged());
        filters.Append(FilterOperation::CreateOpacityFilter(0.5f));
        impl->active_tree()->SetFilterMutated(root->element_id(), filters);
        PostSetNeedsCommitToMainThread();
        break;
      case END:
        EXPECT_TRUE(root->LayerPropertyChanged());
        EndTest();
        break;
    }
  }

  void AfterTest() override {}

 private:
  int index_;
  scoped_refptr<Layer> root_;
  scoped_refptr<Layer> child_;
};

SINGLE_THREAD_TEST_F(LayerTreeHostTestPropertyTreesChangedSync);

// Simple base class for tests that just need to mutate the layer tree
// host and observe results without any impl thread, multi-layer, or
// multi-frame antics.
class LayerTreeHostTestLayerListsTest : public LayerTreeHostTest {
 public:
  explicit LayerTreeHostTestLayerListsTest(bool use_layer_lists)
      : use_layer_lists_(use_layer_lists) {}

 protected:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->use_layer_lists = use_layer_lists_;
  }

  void SetupTree() override {
    root_ = Layer::Create();
    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostTest::SetupTree();
  }

  void AfterTest() override {}

  scoped_refptr<Layer> root_;

 private:
  bool use_layer_lists_;
};

class LayerTreeHostTestAnimationOpacityMutatedNotUsingLayerLists
    : public LayerTreeHostTestLayerListsTest {
 public:
  LayerTreeHostTestAnimationOpacityMutatedNotUsingLayerLists()
      : LayerTreeHostTestLayerListsTest(false) {}

 protected:
  void BeginTest() override {
    EXPECT_EQ(1.0f, root_->opacity());
    layer_tree_host()->SetElementOpacityMutated(root_->element_id(),
                                                ElementListType::ACTIVE, 0.3f);
    // When not using layer lists, opacity is stored on the layer.
    EXPECT_EQ(0.3f, root_->opacity());
    EndTest();
  }
};

SINGLE_THREAD_TEST_F(
    LayerTreeHostTestAnimationOpacityMutatedNotUsingLayerLists);

class LayerTreeHostTestAnimationOpacityMutatedUsingLayerLists
    : public LayerTreeHostTestLayerListsTest {
 public:
  LayerTreeHostTestAnimationOpacityMutatedUsingLayerLists()
      : LayerTreeHostTestLayerListsTest(true) {}

 protected:
  void BeginTest() override {
    // Insert a dummy effect node to observe its mutation. This would
    // normally have been created by PaintArtifactCompositor.
    int effect_node_id =
        layer_tree_host()->property_trees()->effect_tree.Insert(
            EffectNode(), EffectTree::kInvalidNodeId);
    layer_tree_host()
        ->property_trees()
        ->element_id_to_effect_node_index[root_->element_id()] = effect_node_id;

    EXPECT_EQ(1.0f, root_->opacity());
    EXPECT_EQ(1.0f,
              layer_tree_host()
                  ->property_trees()
                  ->effect_tree.FindNodeFromElementId(root_->element_id())
                  ->opacity);

    layer_tree_host()->SetElementOpacityMutated(root_->element_id(),
                                                ElementListType::ACTIVE, 0.3f);

    // When using layer lists, we don't have to store the opacity on the layer.
    EXPECT_EQ(1.0f, root_->opacity());
    // The opacity should have been set directly on the effect node instead.
    EXPECT_EQ(0.3f,
              layer_tree_host()
                  ->property_trees()
                  ->effect_tree.FindNodeFromElementId(root_->element_id())
                  ->opacity);
    EndTest();
  }
};

SINGLE_THREAD_TEST_F(LayerTreeHostTestAnimationOpacityMutatedUsingLayerLists);

class LayerTreeHostTestAnimationTransformMutatedNotUsingLayerLists
    : public LayerTreeHostTestLayerListsTest {
 public:
  LayerTreeHostTestAnimationTransformMutatedNotUsingLayerLists()
      : LayerTreeHostTestLayerListsTest(false) {}

 protected:
  void BeginTest() override {
    EXPECT_EQ(gfx::Transform(), root_->transform());
    gfx::Transform expected_transform;
    expected_transform.Translate(42, 42);
    layer_tree_host()->SetElementTransformMutated(
        root_->element_id(), ElementListType::ACTIVE, expected_transform);
    // When not using layer lists, transform is stored on the layer.
    EXPECT_EQ(expected_transform, root_->transform());
    EndTest();
  }
};

SINGLE_THREAD_TEST_F(
    LayerTreeHostTestAnimationTransformMutatedNotUsingLayerLists);

class LayerTreeHostTestAnimationTransformMutatedUsingLayerLists
    : public LayerTreeHostTestLayerListsTest {
 public:
  LayerTreeHostTestAnimationTransformMutatedUsingLayerLists()
      : LayerTreeHostTestLayerListsTest(true) {}

 protected:
  void BeginTest() override {
    // Insert a dummy transform node to observe its mutation. This would
    // normally have been created by PaintArtifactCompositor.
    int transform_node_id =
        layer_tree_host()->property_trees()->transform_tree.Insert(
            TransformNode(), TransformTree::kInvalidNodeId);
    layer_tree_host()
        ->property_trees()
        ->element_id_to_transform_node_index[root_->element_id()] =
        transform_node_id;

    EXPECT_EQ(gfx::Transform(), root_->transform());
    EXPECT_EQ(gfx::Transform(),
              layer_tree_host()
                  ->property_trees()
                  ->transform_tree.FindNodeFromElementId(root_->element_id())
                  ->local);

    gfx::Transform expected_transform;
    expected_transform.Translate(42, 42);
    layer_tree_host()->SetElementTransformMutated(
        root_->element_id(), ElementListType::ACTIVE, expected_transform);

    // When using layer lists, we don't have to store the transform on the
    // layer.
    EXPECT_EQ(gfx::Transform(), root_->transform());
    // The transform should have been set directly on the transform node
    // instead.
    EXPECT_EQ(expected_transform,
              layer_tree_host()
                  ->property_trees()
                  ->transform_tree.FindNodeFromElementId(root_->element_id())
                  ->local);
    EndTest();
  }
};

SINGLE_THREAD_TEST_F(LayerTreeHostTestAnimationTransformMutatedUsingLayerLists);

class LayerTreeHostTestAnimationFilterMutatedNotUsingLayerLists
    : public LayerTreeHostTestLayerListsTest {
 public:
  LayerTreeHostTestAnimationFilterMutatedNotUsingLayerLists()
      : LayerTreeHostTestLayerListsTest(false) {}

 protected:
  void BeginTest() override {
    FilterOperations filters;
    EXPECT_EQ(FilterOperations(), root_->filters());
    filters.Append(FilterOperation::CreateOpacityFilter(0.5f));
    layer_tree_host()->SetElementFilterMutated(
        root_->element_id(), ElementListType::ACTIVE, filters);
    // When not using layer lists, filters are just stored directly on the
    // layer.
    EXPECT_EQ(filters, root_->filters());
    EndTest();
  }
};

SINGLE_THREAD_TEST_F(LayerTreeHostTestAnimationFilterMutatedNotUsingLayerLists);

class LayerTreeHostTestAnimationFilterMutatedUsingLayerLists
    : public LayerTreeHostTestLayerListsTest {
 public:
  LayerTreeHostTestAnimationFilterMutatedUsingLayerLists()
      : LayerTreeHostTestLayerListsTest(true) {}

 protected:
  void BeginTest() override {
    // Insert a dummy effect node to observe its mutation. This would
    // normally have been created by PaintArtifactCompositor.
    int effect_node_id =
        layer_tree_host()->property_trees()->effect_tree.Insert(
            EffectNode(), EffectTree::kInvalidNodeId);
    layer_tree_host()
        ->property_trees()
        ->element_id_to_effect_node_index[root_->element_id()] = effect_node_id;

    EXPECT_EQ(FilterOperations(), root_->filters());
    EXPECT_EQ(FilterOperations(),
              layer_tree_host()
                  ->property_trees()
                  ->effect_tree.FindNodeFromElementId(root_->element_id())
                  ->filters);

    FilterOperations filters;
    filters.Append(FilterOperation::CreateOpacityFilter(0.5f));
    layer_tree_host()->SetElementFilterMutated(
        root_->element_id(), ElementListType::ACTIVE, filters);

    // When using layer lists, we don't have to store the filters on the layer.
    EXPECT_EQ(FilterOperations(), root_->filters());
    // The filter should have been set directly on the effect node instead.
    EXPECT_EQ(filters,
              layer_tree_host()
                  ->property_trees()
                  ->effect_tree.FindNodeFromElementId(root_->element_id())
                  ->filters);
    EndTest();
  }
};

SINGLE_THREAD_TEST_F(LayerTreeHostTestAnimationFilterMutatedUsingLayerLists);

class LayerTreeHostTestEffectTreeSync : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root_ = Layer::Create();
    layer_tree_host()->SetRootLayer(root_);
    blur_filter_.Append(FilterOperation::CreateBlurFilter(0.5f));
    brightness_filter_.Append(FilterOperation::CreateBrightnessFilter(0.25f));
    sepia_filter_.Append(FilterOperation::CreateSepiaFilter(0.75f));
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    EffectTree& effect_tree = layer_tree_host()->property_trees()->effect_tree;
    EffectNode* node = effect_tree.Node(root_->effect_tree_index());
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        node->opacity = 0.5f;
        node->is_currently_animating_opacity = true;
        break;
      case 2:
        node->is_currently_animating_opacity = true;
        break;
      case 3:
        node->is_currently_animating_opacity = false;
        break;
      case 4:
        node->opacity = 0.25f;
        node->is_currently_animating_opacity = true;
        break;
      case 5:
        node->filters = blur_filter_;
        node->is_currently_animating_filter = true;
        break;
      case 6:
        node->is_currently_animating_filter = true;
        break;
      case 7:
        node->is_currently_animating_filter = false;
        break;
      case 8:
        node->filters = sepia_filter_;
        node->is_currently_animating_filter = true;
        break;
    }
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    EffectTree& effect_tree = impl->sync_tree()->property_trees()->effect_tree;
    LayerImpl* root = impl->sync_tree()->root_layer_for_testing();
    EffectNode* node = effect_tree.Node(root->effect_tree_index());
    switch (impl->sync_tree()->source_frame_number()) {
      case 0:
        impl->sync_tree()->SetOpacityMutated(root->element_id(), 0.75f);
        PostSetNeedsCommitToMainThread();
        break;
      case 1:
        EXPECT_EQ(node->opacity, 0.75f);
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        EXPECT_EQ(node->opacity, 0.75f);
        impl->sync_tree()->SetOpacityMutated(root->element_id(), 0.75f);
        PostSetNeedsCommitToMainThread();
        break;
      case 3:
        EXPECT_EQ(node->opacity, 0.5f);
        PostSetNeedsCommitToMainThread();
        break;
      case 4:
        EXPECT_EQ(node->opacity, 0.25f);
        impl->sync_tree()->SetFilterMutated(root->element_id(),
                                            brightness_filter_);
        PostSetNeedsCommitToMainThread();
        break;
      case 5:
        EXPECT_EQ(node->filters, brightness_filter_);
        PostSetNeedsCommitToMainThread();
        break;
      case 6:
        EXPECT_EQ(node->filters, brightness_filter_);
        impl->sync_tree()->SetFilterMutated(root->element_id(),
                                            brightness_filter_);
        PostSetNeedsCommitToMainThread();
        break;
      case 7:
        EXPECT_EQ(node->filters, blur_filter_);
        PostSetNeedsCommitToMainThread();
        break;
      case 8:
        EXPECT_EQ(node->filters, sepia_filter_);
        EndTest();
        break;
    }
  }

  void AfterTest() override {}

 private:
  scoped_refptr<Layer> root_;
  FilterOperations blur_filter_;
  FilterOperations brightness_filter_;
  FilterOperations sepia_filter_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestEffectTreeSync);

class LayerTreeHostTestTransformTreeSync : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root_ = Layer::Create();
    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    TransformTree& transform_tree =
        layer_tree_host()->property_trees()->transform_tree;
    TransformNode* node = transform_tree.Node(root_->transform_tree_index());
    gfx::Transform rotate10;
    rotate10.Rotate(10.f);
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        node->local = rotate10;
        node->is_currently_animating = true;
        break;
      case 2:
        node->is_currently_animating = true;
        break;
      case 3:
        node->is_currently_animating = false;
        break;
      case 4:
        node->local = gfx::Transform();
        node->is_currently_animating = true;
        break;
    }
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    TransformTree& transform_tree =
        impl->sync_tree()->property_trees()->transform_tree;
    const LayerImpl* root_layer = impl->sync_tree()->root_layer_for_testing();
    const TransformNode* node =
        transform_tree.Node(root_layer->transform_tree_index());
    gfx::Transform rotate10;
    rotate10.Rotate(10.f);
    gfx::Transform rotate20;
    rotate20.Rotate(20.f);
    switch (impl->sync_tree()->source_frame_number()) {
      case 0:
        impl->sync_tree()->SetTransformMutated(root_layer->element_id(),
                                               rotate20);
        PostSetNeedsCommitToMainThread();
        break;
      case 1:
        EXPECT_EQ(node->local, rotate20);
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        EXPECT_EQ(node->local, rotate20);
        impl->sync_tree()->SetTransformMutated(root_layer->element_id(),
                                               rotate20);
        PostSetNeedsCommitToMainThread();
        break;
      case 3:
        EXPECT_EQ(node->local, rotate10);
        PostSetNeedsCommitToMainThread();
        break;
      case 4:
        EXPECT_EQ(node->local, gfx::Transform());
        EndTest();
    }
  }

  void AfterTest() override {}

 private:
  scoped_refptr<Layer> root_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestTransformTreeSync);

// Verify damage status is updated even when the transform tree doesn't need
// to be updated at draw time.
class LayerTreeHostTestTransformTreeDamageIsUpdated : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root_ = Layer::Create();
    child_ = Layer::Create();
    grand_child_ = Layer::Create();

    root_->SetBounds(gfx::Size(50, 50));

    // Make sure child is registered for animation.
    child_->SetElementId(ElementId(2));

    // Make sure child and grand_child have transform nodes.
    gfx::Transform rotation;
    rotation.RotateAboutZAxis(45.0);
    child_->SetTransform(rotation);
    grand_child_->SetTransform(rotation);

    root_->AddChild(child_);
    child_->AddChild(grand_child_);
    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    if (layer_tree_host()->SourceFrameNumber() == 1) {
      gfx::Transform scale;
      scale.Scale(2.0, 2.0);
      layer_tree_host()->SetElementTransformMutated(
          child_->element_id(), ElementListType::ACTIVE, scale);
    }
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    if (impl->sync_tree()->source_frame_number() == 0)
      PostSetNeedsCommitToMainThread();
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    if (impl->active_tree()->source_frame_number() == 1) {
      EXPECT_FALSE(
          impl->active_tree()->LayerById(root_->id())->LayerPropertyChanged());
      EXPECT_TRUE(
          impl->active_tree()->LayerById(child_->id())->LayerPropertyChanged());
      EXPECT_TRUE(impl->active_tree()
                      ->LayerById(grand_child_->id())
                      ->LayerPropertyChanged());
      EndTest();
    }

    return draw_result;
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    if (impl->active_tree()->source_frame_number() == 0) {
      gfx::Transform scale;
      scale.Scale(2.0, 2.0);
      impl->active_tree()->SetTransformMutated(child_->element_id(), scale);
    }
  }

  void AfterTest() override {}

 private:
  scoped_refptr<Layer> root_;
  scoped_refptr<Layer> child_;
  scoped_refptr<Layer> grand_child_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestTransformTreeDamageIsUpdated);

class UpdateCountingLayer : public Layer {
 public:
  bool Update() override {
    update_count_++;
    return false;
  }

  int update_count() const { return update_count_; }

 private:
  ~UpdateCountingLayer() override = default;

  int update_count_ = 0;
};

// Test that when mask layers switches layers, this gets pushed onto impl.
// Also test that mask layer is in the layer update list even if its owning
// layer isn't.
class LayerTreeHostTestSwitchMaskLayer : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    scoped_refptr<Layer> root = Layer::Create();
    root->SetBounds(gfx::Size(10, 10));
    child_layer_ = base::MakeRefCounted<UpdateCountingLayer>();
    child_layer_->SetBounds(gfx::Size(10, 10));
    mask_layer_ = base::MakeRefCounted<UpdateCountingLayer>();
    mask_layer_->SetBounds(gfx::Size(10, 10));
    child_layer_->SetMaskLayer(mask_layer_.get());
    root->AddChild(child_layer_);
    layer_tree_host()->SetRootLayer(root);
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override {
    index_ = 0;
    PostSetNeedsCommitToMainThread();
  }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // Root and mask layer should have the same source frame number as they
        // will be in the layer update list but the child is not as it has empty
        // bounds.
        EXPECT_EQ(mask_layer_->update_count(), 1);
        EXPECT_EQ(child_layer_->update_count(), 0);

        layer_tree_host()->root_layer()->RemoveAllChildren();
        layer_tree_host()->root_layer()->SetMaskLayer(mask_layer_.get());
        break;
    }
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    switch (index_) {
      case 0:
        index_++;
        EXPECT_FALSE(
            GetRenderSurface(impl->sync_tree()->root_layer_for_testing())
                ->MaskLayer());
        break;
      case 1:
        EXPECT_TRUE(
            GetRenderSurface(impl->sync_tree()->root_layer_for_testing())
                ->MaskLayer());
        EndTest();
        break;
    }
  }

  void AfterTest() override {}

  scoped_refptr<UpdateCountingLayer> mask_layer_;
  scoped_refptr<UpdateCountingLayer> child_layer_;
  int index_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestSwitchMaskLayer);

// 1 setNeedsRedraw after the first commit has completed should lead to 1
// additional draw.
class LayerTreeHostTestSetNeedsRedraw : public LayerTreeHostTest {
 public:
  LayerTreeHostTestSetNeedsRedraw() : num_commits_(0), num_draws_(0) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_EQ(0, impl->active_tree()->source_frame_number());
    if (!num_draws_) {
      // Redraw again to verify that the second redraw doesn't commit.
      PostSetNeedsRedrawToMainThread();
    } else {
      EndTest();
    }
    num_draws_++;
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_EQ(0, num_draws_);
    num_commits_++;
  }

  void AfterTest() override {
    EXPECT_GE(2, num_draws_);
    EXPECT_EQ(1, num_commits_);
  }

 private:
  int num_commits_;
  int num_draws_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestSetNeedsRedraw);

// After setNeedsRedrawRect(invalid_rect) the final damage_rect
// must contain invalid_rect.
class LayerTreeHostTestSetNeedsRedrawRect : public LayerTreeHostTest {
 public:
  LayerTreeHostTestSetNeedsRedrawRect()
      : num_draws_(0), bounds_(50, 50), invalid_rect_(10, 10, 20, 20) {}

  void BeginTest() override {
    root_layer_ = FakePictureLayer::Create(&client_);
    root_layer_->SetIsDrawable(true);
    root_layer_->SetBounds(bounds_);
    layer_tree_host()->SetRootLayer(root_layer_);
    layer_tree_host()->SetViewportSizeAndScale(bounds_, 1.f,
                                               viz::LocalSurfaceId());
    PostSetNeedsCommitToMainThread();
    client_.set_bounds(root_layer_->bounds());
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(DRAW_SUCCESS, draw_result);

    gfx::Rect root_damage_rect;
    if (!frame_data->render_passes.empty())
      root_damage_rect = frame_data->render_passes.back()->damage_rect;

    if (!num_draws_) {
      // If this is the first frame, expect full frame damage.
      EXPECT_EQ(root_damage_rect, gfx::Rect(bounds_));
    } else {
      // Check that invalid_rect_ is indeed repainted.
      EXPECT_TRUE(root_damage_rect.Contains(invalid_rect_));
    }

    return draw_result;
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    if (!num_draws_) {
      PostSetNeedsRedrawRectToMainThread(invalid_rect_);
    } else {
      EndTest();
    }
    num_draws_++;
  }

  void AfterTest() override { EXPECT_EQ(2, num_draws_); }

 private:
  int num_draws_;
  const gfx::Size bounds_;
  const gfx::Rect invalid_rect_;
  FakeContentLayerClient client_;
  scoped_refptr<FakePictureLayer> root_layer_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestSetNeedsRedrawRect);

// Ensure the texture size of the pending and active trees are identical when a
// layer is not in the viewport and a resize happens on the viewport
class LayerTreeHostTestGpuRasterDeviceSizeChanged : public LayerTreeHostTest {
 public:
  LayerTreeHostTestGpuRasterDeviceSizeChanged()
      : num_draws_(0), bounds_(500, 64), invalid_rect_(10, 10, 20, 20) {}

  void BeginTest() override {
    client_.set_fill_with_nonsolid_color(true);
    root_layer_ = FakePictureLayer::Create(&client_);
    root_layer_->SetIsDrawable(true);
    gfx::Transform transform;
    // Translate the layer out of the viewport to force it to not update its
    // tile size via PushProperties.
    transform.Translate(10000.0, 10000.0);
    root_layer_->SetTransform(transform);
    root_layer_->SetBounds(bounds_);
    layer_tree_host()->SetRootLayer(root_layer_);
    layer_tree_host()->SetViewportSizeAndScale(bounds_, 1.f,
                                               viz::LocalSurfaceId());

    PostSetNeedsCommitToMainThread();
    client_.set_bounds(root_layer_->bounds());
  }

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->gpu_rasterization_forced = true;
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    if (num_draws_ == 2) {
      auto* pending_tree = host_impl->pending_tree();
      auto* pending_layer_impl = static_cast<FakePictureLayerImpl*>(
          pending_tree->root_layer_for_testing());
      EXPECT_NE(pending_layer_impl, nullptr);

      auto* active_tree = host_impl->pending_tree();
      auto* active_layer_impl = static_cast<FakePictureLayerImpl*>(
          active_tree->root_layer_for_testing());
      EXPECT_NE(pending_layer_impl, nullptr);

      auto* active_tiling_set = active_layer_impl->picture_layer_tiling_set();
      auto* active_tiling = active_tiling_set->tiling_at(0);
      auto* pending_tiling_set = pending_layer_impl->picture_layer_tiling_set();
      auto* pending_tiling = pending_tiling_set->tiling_at(0);
      EXPECT_EQ(
          pending_tiling->TilingDataForTesting().max_texture_size().width(),
          active_tiling->TilingDataForTesting().max_texture_size().width());
    }
  }

  void DidCommitAndDrawFrame() override {
    // On the second commit, resize the viewport.
    if (num_draws_ == 1) {
      layer_tree_host()->SetViewportSizeAndScale(gfx::Size(400, 64), 1.f,
                                                 viz::LocalSurfaceId());
    }
    if (num_draws_ < 2) {
      layer_tree_host()->SetNeedsRedrawRect(invalid_rect_);
      layer_tree_host()->SetNeedsCommit();
      num_draws_++;
    } else {
      EndTest();
    }
  }

  void AfterTest() override {}

 private:
  int num_draws_;
  const gfx::Size bounds_;
  const gfx::Rect invalid_rect_;
  FakeContentLayerClient client_;
  scoped_refptr<FakePictureLayer> root_layer_;
};

// As there's no pending tree in single-threaded case, this test should run
// only for multi-threaded case.
MULTI_THREAD_TEST_F(LayerTreeHostTestGpuRasterDeviceSizeChanged);

class LayerTreeHostTestNoExtraCommitFromInvalidate : public LayerTreeHostTest {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->layer_transforms_should_scale_layer_contents = true;
  }

  void SetupTree() override {
    root_layer_ = Layer::Create();
    root_layer_->SetBounds(gfx::Size(10, 20));

    scaled_layer_ = FakePictureLayer::Create(&client_);
    scaled_layer_->SetBounds(gfx::Size(1, 1));
    root_layer_->AddChild(scaled_layer_);

    layer_tree_host()->SetRootLayer(root_layer_);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer_->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->active_tree()->source_frame_number() == 1)
      EndTest();
  }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // SetBounds grows the layer and exposes new content.
        scaled_layer_->SetBounds(gfx::Size(4, 4));
        break;
      default:
        // No extra commits.
        EXPECT_EQ(2, layer_tree_host()->SourceFrameNumber());
    }
  }

  void AfterTest() override {
    EXPECT_EQ(gfx::Size(4, 4).ToString(), scaled_layer_->bounds().ToString());
  }

 private:
  FakeContentLayerClient client_;
  scoped_refptr<Layer> root_layer_;
  scoped_refptr<Layer> scaled_layer_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestNoExtraCommitFromInvalidate);

class LayerTreeHostTestNoExtraCommitFromScrollbarInvalidate
    : public LayerTreeHostTest {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->layer_transforms_should_scale_layer_contents = true;
  }

  void SetupTree() override {
    root_layer_ = Layer::Create();
    root_layer_->SetBounds(gfx::Size(10, 20));

    bool paint_scrollbar = true;
    bool has_thumb = false;
    scrollbar_ = FakePaintedScrollbarLayer::Create(paint_scrollbar, has_thumb,
                                                   root_layer_->element_id());
    scrollbar_->SetPosition(gfx::PointF(0.f, 10.f));
    scrollbar_->SetBounds(gfx::Size(10, 10));

    root_layer_->AddChild(scrollbar_);

    layer_tree_host()->SetRootLayer(root_layer_);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer_->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->active_tree()->source_frame_number() == 1)
      EndTest();
  }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // Changing the device scale factor causes a commit. It also changes
        // the content bounds of |scrollbar_|, which should not generate
        // a second commit as a result.
        layer_tree_host()->SetViewportSizeAndScale(
            layer_tree_host()->device_viewport_size(), 4.f,
            layer_tree_host()->local_surface_id());
        break;
      default:
        // No extra commits.
        EXPECT_EQ(2, layer_tree_host()->SourceFrameNumber());
        break;
    }
  }

  void AfterTest() override {}

 private:
  FakeContentLayerClient client_;
  scoped_refptr<Layer> root_layer_;
  scoped_refptr<FakePaintedScrollbarLayer> scrollbar_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostTestNoExtraCommitFromScrollbarInvalidate);

class LayerTreeHostTestDeviceScaleFactorChange : public LayerTreeHostTest {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->layer_transforms_should_scale_layer_contents = true;
  }

  void SetupTree() override {
    root_layer_ = Layer::Create();
    root_layer_->SetBounds(gfx::Size(10, 20));

    child_layer_ = FakePictureLayer::Create(&client_);
    child_layer_->SetBounds(gfx::Size(10, 10));
    root_layer_->AddChild(child_layer_);

    layer_tree_host()->SetRootLayer(root_layer_);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer_->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    if (layer_tree_host()->SourceFrameNumber() == 1) {
      layer_tree_host()->SetViewportSizeAndScale(
          layer_tree_host()->device_viewport_size(), 4.f,
          layer_tree_host()->local_surface_id());
    }
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->sync_tree()->source_frame_number() == 1) {
      EXPECT_EQ(4.f, host_impl->sync_tree()->device_scale_factor());
      if (host_impl->pending_tree()) {
        // The active tree's device scale factor shouldn't change until
        // activation.
        EXPECT_EQ(1.f, host_impl->active_tree()->device_scale_factor());
      }
    }
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    if (host_impl->active_tree()->source_frame_number() == 0) {
      EXPECT_EQ(1.f, host_impl->active_tree()->device_scale_factor());
    } else {
      gfx::Rect root_damage_rect =
          frame_data->render_passes.back()->damage_rect;
      EXPECT_EQ(
          gfx::Rect(
              host_impl->active_tree()->root_layer_for_testing()->bounds()),
          root_damage_rect);
      EXPECT_EQ(4.f, host_impl->active_tree()->device_scale_factor());
      EndTest();
    }

    return draw_result;
  }

  void AfterTest() override {}

 private:
  FakeContentLayerClient client_;
  scoped_refptr<Layer> root_layer_;
  scoped_refptr<Layer> child_layer_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestDeviceScaleFactorChange);

class LayerTreeHostTestRasterColorSpaceChange : public LayerTreeHostTest {
 public:
  void SetupTree() override {
    space1_ = gfx::ColorSpace::CreateXYZD50();
    space2_ = gfx::ColorSpace::CreateSRGB();

    root_layer_ = Layer::Create();
    root_layer_->SetBounds(gfx::Size(10, 20));

    child_layer_ = FakePictureLayer::Create(&client_);
    child_layer_->SetBounds(gfx::Size(10, 10));
    root_layer_->AddChild(child_layer_);

    layer_tree_host()->SetRootLayer(root_layer_);
    layer_tree_host()->SetRasterColorSpace(space1_);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer_->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(DRAW_SUCCESS, draw_result);

    int source_frame = host_impl->active_tree()->source_frame_number();
    switch (source_frame) {
      case 0:
        // The first frame will have full damage, and should be in the initial
        // color space.
        EXPECT_FALSE(frame_data->has_no_damage);
        EXPECT_TRUE(space1_ == host_impl->active_tree()->raster_color_space());
        break;
      case 1:
        // Empty commit.
        EXPECT_TRUE(frame_data->has_no_damage);
        EXPECT_TRUE(space1_ == host_impl->active_tree()->raster_color_space());
        break;
      case 2:
        // The change from space1 to space2 should cause full damage.
        EXPECT_FALSE(frame_data->has_no_damage);
        EXPECT_TRUE(space2_ == host_impl->active_tree()->raster_color_space());
        break;
      case 3:
        // Empty commit with the color space set to space2 redundantly.
        EXPECT_TRUE(frame_data->has_no_damage);
        EXPECT_TRUE(space2_ == host_impl->active_tree()->raster_color_space());
        break;
      case 4:
        // The change from space2 to space1 should cause full damage.
        EXPECT_FALSE(frame_data->has_no_damage);
        EXPECT_TRUE(space1_ == host_impl->active_tree()->raster_color_space());
        break;
      case 5:
        // Empty commit.
        EXPECT_TRUE(frame_data->has_no_damage);
        EXPECT_TRUE(space1_ == host_impl->active_tree()->raster_color_space());
        EndTest();
        break;
      default:
        NOTREACHED();
        break;
    }

    if (!frame_data->has_no_damage) {
      gfx::Rect root_damage_rect =
          frame_data->render_passes.back()->damage_rect;
      EXPECT_EQ(
          gfx::Rect(
              host_impl->active_tree()->root_layer_for_testing()->bounds()),
          root_damage_rect);
    }

    return draw_result;
  }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        EXPECT_FALSE(child_layer_->NeedsDisplayForTesting());
        layer_tree_host()->SetRasterColorSpace(space2_);
        EXPECT_TRUE(child_layer_->NeedsDisplayForTesting());
        break;
      case 3:
        // The redundant SetRasterColorSpace should cause no commit and no
        // damage. Force a commit for the test to continue.
        layer_tree_host()->SetRasterColorSpace(space2_);
        PostSetNeedsCommitToMainThread();
        EXPECT_FALSE(child_layer_->NeedsDisplayForTesting());
        break;
      case 4:
        EXPECT_FALSE(child_layer_->NeedsDisplayForTesting());
        layer_tree_host()->SetRasterColorSpace(space1_);
        EXPECT_TRUE(child_layer_->NeedsDisplayForTesting());
        break;
      case 5:
        EXPECT_FALSE(child_layer_->NeedsDisplayForTesting());
        PostSetNeedsCommitToMainThread();
        break;
      case 6:
        break;
      default:
        NOTREACHED();
        break;
    }
  }

  void AfterTest() override {}

 private:
  gfx::ColorSpace space1_;
  gfx::ColorSpace space2_;
  FakeContentLayerClient client_;
  scoped_refptr<Layer> root_layer_;
  scoped_refptr<Layer> child_layer_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestRasterColorSpaceChange);

class LayerTreeHostTestSetNeedsCommitWithForcedRedraw
    : public LayerTreeHostTest {
 public:
  LayerTreeHostTestSetNeedsCommitWithForcedRedraw()
      : num_draws_(0), bounds_(50, 50), invalid_rect_(10, 10, 20, 20) {}

  void BeginTest() override {
    root_layer_ = FakePictureLayer::Create(&client_);
    root_layer_->SetIsDrawable(true);
    root_layer_->SetBounds(bounds_);
    layer_tree_host()->SetRootLayer(root_layer_);
    layer_tree_host()->SetViewportSizeAndScale(bounds_, 1.f,
                                               viz::LocalSurfaceId());
    PostSetNeedsCommitToMainThread();
    client_.set_bounds(root_layer_->bounds());
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    if (num_draws_ == 3) {
      host_impl->SetViewportDamage(invalid_rect_);
      host_impl->SetNeedsRedraw();
    }
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(DRAW_SUCCESS, draw_result);

    gfx::Rect root_damage_rect;
    if (!frame_data->render_passes.empty())
      root_damage_rect = frame_data->render_passes.back()->damage_rect;

    switch (num_draws_) {
      case 0:
        EXPECT_EQ(gfx::Rect(bounds_), root_damage_rect);
        break;
      case 1:
      case 2:
        EXPECT_EQ(gfx::Rect(), root_damage_rect);
        break;
      case 3:
        EXPECT_EQ(invalid_rect_, root_damage_rect);
        break;
      case 4:
        EXPECT_EQ(gfx::Rect(bounds_), root_damage_rect);
        break;
      default:
        NOTREACHED();
    }

    return draw_result;
  }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    switch (num_draws_) {
      case 0:
      case 1:
        // Cycle through a couple of empty commits to ensure we're observing the
        // right behavior
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        // Should force full frame damage on the next commit
        PostSetNeedsCommitWithForcedRedrawToMainThread();
        host_impl->BlockNotifyReadyToActivateForTesting(true);
        break;
      case 3:
        host_impl->BlockNotifyReadyToActivateForTesting(false);
        break;
      default:
        EndTest();
        break;
    }
    num_draws_++;
  }

  void AfterTest() override { EXPECT_EQ(5, num_draws_); }

 private:
  int num_draws_;
  const gfx::Size bounds_;
  const gfx::Rect invalid_rect_;
  FakeContentLayerClient client_;
  scoped_refptr<FakePictureLayer> root_layer_;
};

// This test blocks activation which is not supported for single thread mode.
MULTI_THREAD_BLOCKNOTIFY_TEST_F(
    LayerTreeHostTestSetNeedsCommitWithForcedRedraw);

// Tests that if a layer is not drawn because of some reason in the parent then
// its damage is preserved until the next time it is drawn.
class LayerTreeHostTestUndrawnLayersDamageLater : public LayerTreeHostTest {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    // If we don't set the minimum contents scale, it's harder to verify whether
    // the damage we get is correct. For other scale amounts, please see
    // LayerTreeHostTestDamageWithScale.
    settings->minimum_contents_scale = 1.f;
  }

  void SetupTree() override {
    root_layer_ = FakePictureLayer::Create(&client_);
    root_layer_->SetIsDrawable(true);
    root_layer_->SetBounds(gfx::Size(50, 50));
    layer_tree_host()->SetRootLayer(root_layer_);

    // The initially transparent layer has a larger child layer, which is
    // not initially drawn because of the this (parent) layer.
    parent_layer_ = FakePictureLayer::Create(&client_);
    parent_layer_->SetBounds(gfx::Size(15, 15));
    parent_layer_->SetOpacity(0.0f);
    root_layer_->AddChild(parent_layer_);

    child_layer_ = FakePictureLayer::Create(&client_);
    child_layer_->SetBounds(gfx::Size(25, 25));
    parent_layer_->AddChild(child_layer_);
    client_.set_bounds(root_layer_->bounds());

    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(DRAW_SUCCESS, draw_result);

    gfx::Rect root_damage_rect;
    if (!frame_data->render_passes.empty())
      root_damage_rect = frame_data->render_passes.back()->damage_rect;

    // The first time, the whole view needs be drawn.
    // Afterwards, just the opacity of surface_layer1 is changed a few times,
    // and each damage should be the bounding box of it and its child. If this
    // was working improperly, the damage might not include its childs bounding
    // box.
    switch (host_impl->active_tree()->source_frame_number()) {
      case 0:
        EXPECT_EQ(gfx::Rect(root_layer_->bounds()), root_damage_rect);
        break;
      case 1:
      case 2:
      case 3:
        EXPECT_EQ(gfx::Rect(child_layer_->bounds()), root_damage_rect);
        break;
      default:
        NOTREACHED();
    }

    return draw_result;
  }

  void DidCommitAndDrawFrame() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // Test not owning the surface.
        parent_layer_->SetOpacity(1.0f);
        break;
      case 2:
        parent_layer_->SetOpacity(0.0f);
        break;
      case 3:
        // Test owning the surface.
        parent_layer_->SetOpacity(0.5f);
        parent_layer_->SetForceRenderSurfaceForTesting(true);
        break;
      case 4:
        EndTest();
        break;
      default:
        NOTREACHED();
    }
  }

  void AfterTest() override {}

 private:
  FakeContentLayerClient client_;
  scoped_refptr<FakePictureLayer> root_layer_;
  scoped_refptr<FakePictureLayer> parent_layer_;
  scoped_refptr<FakePictureLayer> child_layer_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestUndrawnLayersDamageLater);

// Tests that if a layer is not drawn because of some reason in the parent then
// its damage is preserved until the next time it is drawn.
class LayerTreeHostTestDamageWithScale : public LayerTreeHostTest {
 public:
  LayerTreeHostTestDamageWithScale() = default;

  void SetupTree() override {
    client_.set_fill_with_nonsolid_color(true);

    std::unique_ptr<FakeRecordingSource> recording(new FakeRecordingSource);
    root_layer_ = FakePictureLayer::CreateWithRecordingSource(
        &client_, std::move(recording));
    root_layer_->SetBounds(gfx::Size(50, 50));

    recording.reset(new FakeRecordingSource);
    child_layer_ = FakePictureLayer::CreateWithRecordingSource(
        &client_, std::move(recording));
    child_layer_->SetBounds(gfx::Size(25, 25));
    child_layer_->SetIsDrawable(true);
    child_layer_->SetContentsOpaque(true);
    root_layer_->AddChild(child_layer_);

    layer_tree_host()->SetRootLayer(root_layer_);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer_->bounds());
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    // Force the layer to have a tiling at 1.3f scale. Note that if we simply
    // add tiling, it will be gone by the time we draw because of aggressive
    // cleanup. AddTilingUntilNextDraw ensures that it remains there during
    // damage calculation.
    FakePictureLayerImpl* child_layer_impl = static_cast<FakePictureLayerImpl*>(
        host_impl->active_tree()->LayerById(child_layer_->id()));
    child_layer_impl->AddTilingUntilNextDraw(1.3f);
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(DRAW_SUCCESS, draw_result);

    gfx::Rect root_damage_rect;
    if (!frame_data->render_passes.empty())
      root_damage_rect = frame_data->render_passes.back()->damage_rect;

    // The first time, the whole view needs be drawn.
    // Afterwards, just the opacity of surface_layer1 is changed a few times,
    // and each damage should be the bounding box of it and its child. If this
    // was working improperly, the damage might not include its childs bounding
    // box.
    switch (host_impl->active_tree()->source_frame_number()) {
      case 0:
        EXPECT_EQ(gfx::Rect(root_layer_->bounds()), root_damage_rect);
        break;
      case 1: {
        FakePictureLayerImpl* child_layer_impl =
            static_cast<FakePictureLayerImpl*>(
                host_impl->active_tree()->LayerById(child_layer_->id()));
        // We remove tilings pretty aggressively if they are not ideal. Add this
        // back in so that we can compare
        // child_layer_impl->GetEnclosingRectInTargetSpace to the damage.
        child_layer_impl->AddTilingUntilNextDraw(1.3f);

        EXPECT_EQ(gfx::Rect(26, 26), root_damage_rect);
        EXPECT_EQ(child_layer_impl->GetEnclosingRectInTargetSpace(),
                  root_damage_rect);
        EXPECT_TRUE(child_layer_impl->GetEnclosingRectInTargetSpace().Contains(
            gfx::Rect(child_layer_->bounds())));
        break;
      }
      default:
        NOTREACHED();
    }

    return draw_result;
  }

  void DidCommitAndDrawFrame() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1: {
        // Test not owning the surface.
        child_layer_->SetOpacity(0.5f);
        break;
      }
      case 2:
        EndTest();
        break;
      default:
        NOTREACHED();
    }
  }

  void AfterTest() override {}

 private:
  FakeContentLayerClient client_;
  scoped_refptr<Layer> root_layer_;
  scoped_refptr<Layer> child_layer_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestDamageWithScale);

// This test verifies that properties on the layer tree host are commited
// to the impl side.
class LayerTreeHostTestCommit : public LayerTreeHostTest {
 public:
  LayerTreeHostTestCommit() = default;

  void BeginTest() override {
    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(20, 20), 1.f,
                                               viz::LocalSurfaceId());
    layer_tree_host()->set_background_color(SK_ColorGRAY);
    layer_tree_host()->SetEventListenerProperties(
        EventListenerClass::kMouseWheel, EventListenerProperties::kPassive);
    layer_tree_host()->SetEventListenerProperties(
        EventListenerClass::kTouchStartOrMove,
        EventListenerProperties::kBlocking);
    layer_tree_host()->SetEventListenerProperties(
        EventListenerClass::kTouchEndOrCancel,
        EventListenerProperties::kBlockingAndPassive);
    layer_tree_host()->SetHaveScrollEventHandlers(true);

    PostSetNeedsCommitToMainThread();
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_EQ(gfx::Rect(20, 20), impl->DeviceViewport());
    EXPECT_EQ(SK_ColorGRAY, impl->active_tree()->background_color());
    EXPECT_EQ(EventListenerProperties::kPassive,
              impl->active_tree()->event_listener_properties(
                  EventListenerClass::kMouseWheel));
    EXPECT_EQ(EventListenerProperties::kBlocking,
              impl->active_tree()->event_listener_properties(
                  EventListenerClass::kTouchStartOrMove));
    EXPECT_EQ(EventListenerProperties::kBlockingAndPassive,
              impl->active_tree()->event_listener_properties(
                  EventListenerClass::kTouchEndOrCancel));
    EXPECT_TRUE(impl->active_tree()->have_scroll_event_handlers());

    EndTest();
  }

  void AfterTest() override {}
};

MULTI_THREAD_TEST_F(LayerTreeHostTestCommit);

// This test verifies that LayerTreeHostImpl's current frame time gets
// updated in consecutive frames when it doesn't draw due to tree
// activation failure.
class LayerTreeHostTestFrameTimeUpdatesAfterActivationFails
    : public LayerTreeHostTest {
 public:
  LayerTreeHostTestFrameTimeUpdatesAfterActivationFails()
      : frame_count_with_pending_tree_(0) {}

  void BeginTest() override {
    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(20, 20), 1.f,
                                               viz::LocalSurfaceId());
    layer_tree_host()->set_background_color(SK_ColorGRAY);

    PostSetNeedsCommitToMainThread();
  }

  void BeginCommitOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_EQ(frame_count_with_pending_tree_, 0);
    impl->BlockNotifyReadyToActivateForTesting(true);
  }

  void WillBeginImplFrameOnThread(LayerTreeHostImpl* impl,
                                  const viz::BeginFrameArgs& args) override {
    if (impl->pending_tree())
      frame_count_with_pending_tree_++;

    if (frame_count_with_pending_tree_ == 1) {
      EXPECT_EQ(base::TimeTicks(), first_frame_time_);
      first_frame_time_ = impl->CurrentBeginFrameArgs().frame_time;
    } else if (frame_count_with_pending_tree_ == 2) {
      impl->BlockNotifyReadyToActivateForTesting(false);
    }
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_GT(frame_count_with_pending_tree_, 1);
    EXPECT_NE(base::TimeTicks(), first_frame_time_);
    EXPECT_NE(first_frame_time_, impl->CurrentBeginFrameArgs().frame_time);
    EndTest();
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_GT(frame_count_with_pending_tree_, 1);
  }

  void AfterTest() override {}

 private:
  int frame_count_with_pending_tree_;
  base::TimeTicks first_frame_time_;
};

// This test blocks activation which is not supported for single thread mode.
MULTI_THREAD_BLOCKNOTIFY_TEST_F(
    LayerTreeHostTestFrameTimeUpdatesAfterActivationFails);

// This test verifies that LayerTreeHostImpl's current frame time gets
// updated in consecutive frames when it draws in each frame.
class LayerTreeHostTestFrameTimeUpdatesAfterDraw : public LayerTreeHostTest {
 public:
  LayerTreeHostTestFrameTimeUpdatesAfterDraw() : frame_(0) {}

  void BeginTest() override {
    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(20, 20), 1.f,
                                               viz::LocalSurfaceId());
    layer_tree_host()->set_background_color(SK_ColorGRAY);

    PostSetNeedsCommitToMainThread();
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    frame_++;
    if (frame_ == 1) {
      first_frame_time_ = impl->CurrentBeginFrameArgs().frame_time;
      impl->SetNeedsRedraw();

      // Since we might use a low-resolution clock on Windows, we need to
      // make sure that the clock has incremented past first_frame_time_.
      while (first_frame_time_ == base::TimeTicks::Now()) {
      }

      return;
    }

    EXPECT_NE(first_frame_time_, impl->CurrentBeginFrameArgs().frame_time);
    EndTest();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    // Ensure there isn't a commit between the two draws, to ensure that a
    // commit isn't required for updating the current frame time. We can
    // only check for this in the multi-threaded case, since in the single-
    // threaded case there will always be a commit between consecutive draws.
    if (HasImplThread())
      EXPECT_EQ(0, frame_);
  }

  void AfterTest() override {}

 private:
  int frame_;
  base::TimeTicks first_frame_time_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestFrameTimeUpdatesAfterDraw);

// Verifies that StartPageScaleAnimation events propagate correctly
// from LayerTreeHost to LayerTreeHostImpl in the MT compositor.
class LayerTreeHostTestStartPageScaleAnimation : public LayerTreeHostTest {
 public:
  LayerTreeHostTestStartPageScaleAnimation() = default;

  void SetupTree() override {
    LayerTreeHostTest::SetupTree();

    Layer* root_layer = layer_tree_host()->root_layer();

    scoped_refptr<FakePictureLayer> layer = FakePictureLayer::Create(&client_);
    layer->set_always_update_resources(true);
    scroll_layer_ = layer;

    scroll_layer_->SetBounds(gfx::Size(2 * root_layer->bounds().width(),
                                       2 * root_layer->bounds().height()));
    scroll_layer_->SetScrollOffset(gfx::ScrollOffset());

    CreateVirtualViewportLayers(root_layer, scroll_layer_, root_layer->bounds(),
                                root_layer->bounds(), layer_tree_host());

    layer_tree_host()->SetPageScaleFactorAndLimits(1.f, 0.5f, 2.f);
    client_.set_bounds(root_layer->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void ApplyViewportDeltas(const gfx::Vector2dF& scroll_delta,
                           const gfx::Vector2dF&,
                           const gfx::Vector2dF& elastic_overscroll_delta,
                           float scale,
                           float) override {
    gfx::ScrollOffset offset = scroll_layer_->scroll_offset();
    scroll_layer_->SetScrollOffset(ScrollOffsetWithDelta(offset, scroll_delta));
    layer_tree_host()->SetPageScaleFactorAndLimits(scale, 0.5f, 2.f);
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    // We get one commit before the first draw, and the animation doesn't happen
    // until the second draw.
    switch (impl->active_tree()->source_frame_number()) {
      case 0:
        EXPECT_EQ(1.f, impl->active_tree()->current_page_scale_factor());
        // We'll start an animation when we get back to the main thread.
        break;
      case 1:
        EXPECT_EQ(1.f, impl->active_tree()->current_page_scale_factor());
        // Once the animation starts, an ImplFrame will be requested. However,
        // main frames may be happening in the mean-time due to high-latency
        // mode. If one happens before the next impl frame, then the source
        // frame number may increment twice instead of just once.
        break;
      case 2:
      case 3:
        EXPECT_EQ(1.25f, impl->active_tree()->current_page_scale_factor());
        EndTest();
        break;
    }
  }

  void DidCommitAndDrawFrame() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        layer_tree_host()->StartPageScaleAnimation(gfx::Vector2d(), false,
                                                   1.25f, base::TimeDelta());
        break;
    }
  }

  void AfterTest() override {}

  FakeContentLayerClient client_;
  scoped_refptr<Layer> scroll_layer_;
};

// Single thread proxy does not support impl-side page scale changes.
MULTI_THREAD_TEST_F(LayerTreeHostTestStartPageScaleAnimation);

class ViewportDeltasAppliedDuringPinch : public LayerTreeHostTest {
 protected:
  ViewportDeltasAppliedDuringPinch() : sent_gesture_(false) {}

  void SetupTree() override {
    scoped_refptr<Layer> root_clip = Layer::Create();
    root_clip->SetBounds(gfx::Size(500, 500));
    scoped_refptr<Layer> page_scale_layer = Layer::Create();
    page_scale_layer->SetBounds(gfx::Size(500, 500));

    scoped_refptr<Layer> pinch = Layer::Create();
    pinch->SetBounds(gfx::Size(500, 500));
    pinch->SetScrollable(gfx::Size(200, 200));
    pinch->SetIsContainerForFixedPositionLayers(true);
    page_scale_layer->AddChild(pinch);
    root_clip->AddChild(page_scale_layer);

    LayerTreeHost::ViewportLayers viewport_layers;
    viewport_layers.page_scale = page_scale_layer;
    viewport_layers.inner_viewport_container = root_clip;
    viewport_layers.inner_viewport_scroll = pinch;
    layer_tree_host()->RegisterViewportLayers(viewport_layers);
    layer_tree_host()->SetPageScaleFactorAndLimits(1.f, 1.f, 4.f);
    layer_tree_host()->SetRootLayer(root_clip);
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    if (!sent_gesture_) {
      host_impl->PinchGestureBegin();
      host_impl->PinchGestureUpdate(2, gfx::Point(100, 100));
      host_impl->PinchGestureEnd(gfx::Point(100, 100), true);
      sent_gesture_ = true;
    }
  }

  void ApplyViewportDeltas(const gfx::Vector2dF& inner,
                           const gfx::Vector2dF& outer,
                           const gfx::Vector2dF& elastic_overscroll_delta,
                           float scale_delta,
                           float top_controls_delta) override {
    EXPECT_TRUE(sent_gesture_);
    EXPECT_EQ(gfx::Vector2dF(50, 50), inner);
    EXPECT_EQ(2, scale_delta);

    auto* scroll_layer = layer_tree_host()->inner_viewport_scroll_layer();
    EXPECT_EQ(gfx::ScrollOffset(50, 50), scroll_layer->scroll_offset());
    EndTest();
  }

  void AfterTest() override { EXPECT_TRUE(sent_gesture_); }

  bool sent_gesture_;
};

MULTI_THREAD_TEST_F(ViewportDeltasAppliedDuringPinch);

class LayerTreeHostTestSetVisible : public LayerTreeHostTest {
 public:
  LayerTreeHostTestSetVisible() : num_draws_(0) {}

  void BeginTest() override {
    PostSetNeedsCommitToMainThread();
  }

  void WillCommit() override {
    PostSetVisibleToMainThread(false);
    // This is suppressed while we're invisible.
    PostSetNeedsRedrawToMainThread();
    // Triggers the redraw.
    PostSetVisibleToMainThread(true);
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    EXPECT_TRUE(impl->visible());
    ++num_draws_;
    EndTest();
  }

  void AfterTest() override { EXPECT_EQ(1, num_draws_); }

 private:
  int num_draws_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestSetVisible);

class LayerTreeHostTestDeviceScaleFactorScalesViewportAndLayers
    : public LayerTreeHostTest {
 public:
  LayerTreeHostTestDeviceScaleFactorScalesViewportAndLayers() = default;

  void BeginTest() override {
    client_.set_fill_with_nonsolid_color(true);
    root_layer_ = FakePictureLayer::Create(&client_);
    child_layer_ = FakePictureLayer::Create(&client_);

    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(60, 60), 1.5f,
                                               viz::LocalSurfaceId());
    EXPECT_EQ(gfx::Size(60, 60), layer_tree_host()->device_viewport_size());

    root_layer_->AddChild(child_layer_);

    root_layer_->SetIsDrawable(true);
    root_layer_->SetBounds(gfx::Size(30, 30));

    child_layer_->SetIsDrawable(true);
    child_layer_->SetPosition(gfx::PointF(2.f, 2.f));
    child_layer_->SetBounds(gfx::Size(10, 10));
    client_.set_bounds(gfx::Size(10, 10));

    layer_tree_host()->SetRootLayer(root_layer_);

    PostSetNeedsCommitToMainThread();
    client_.set_bounds(root_layer_->bounds());
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    // Should only do one commit.
    EXPECT_EQ(0, impl->active_tree()->source_frame_number());
    // Device scale factor should come over to impl.
    EXPECT_NEAR(impl->active_tree()->device_scale_factor(), 1.5f, 0.00001f);

    // Device viewport is scaled.
    EXPECT_EQ(gfx::Rect(60, 60), impl->DeviceViewport());

    FakePictureLayerImpl* root = static_cast<FakePictureLayerImpl*>(
        impl->active_tree()->root_layer_for_testing());
    FakePictureLayerImpl* child = static_cast<FakePictureLayerImpl*>(
        impl->active_tree()->LayerById(child_layer_->id()));

    // Positions remain in layout pixels.
    EXPECT_EQ(gfx::PointF(), root->position());
    EXPECT_EQ(gfx::PointF(2.f, 2.f), child->position());

    // Compute all the layer transforms for the frame.
    LayerTreeHostImpl::FrameData frame_data;
    impl->PrepareToDraw(&frame_data);
    impl->DidDrawAllLayers(frame_data);

    const RenderSurfaceList& render_surface_list =
        *frame_data.render_surface_list;

    // Both layers should be drawing into the root render surface.
    ASSERT_EQ(1u, render_surface_list.size());
    ASSERT_EQ(GetRenderSurface(root), render_surface_list[0]);
    ASSERT_EQ(2, GetRenderSurface(root)->num_contributors());

    // The root render surface is the size of the viewport.
    EXPECT_EQ(gfx::Rect(0, 0, 60, 60), GetRenderSurface(root)->content_rect());

    // The max tiling scale of the child should be scaled.
    EXPECT_FLOAT_EQ(1.5f, child->MaximumTilingContentsScale());

    gfx::Transform scale_transform;
    scale_transform.Scale(impl->active_tree()->device_scale_factor(),
                          impl->active_tree()->device_scale_factor());

    // The root layer is scaled by 2x.
    gfx::Transform root_screen_space_transform = scale_transform;
    gfx::Transform root_draw_transform = scale_transform;

    EXPECT_EQ(root_draw_transform, root->DrawTransform());
    EXPECT_EQ(root_screen_space_transform, root->ScreenSpaceTransform());

    // The child is at position 2,2, which is transformed to 3,3 after the scale
    gfx::Transform child_transform;
    child_transform.Translate(3.f, 3.f);
    child_transform.Scale(child->MaximumTilingContentsScale(),
                          child->MaximumTilingContentsScale());

    EXPECT_TRANSFORMATION_MATRIX_EQ(child_transform, child->DrawTransform());
    EXPECT_TRANSFORMATION_MATRIX_EQ(child_transform,
                                    child->ScreenSpaceTransform());

    EndTest();
  }

  void AfterTest() override {}

 private:
  FakeContentLayerClient client_;
  scoped_refptr<FakePictureLayer> root_layer_;
  scoped_refptr<FakePictureLayer> child_layer_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestDeviceScaleFactorScalesViewportAndLayers);

class LayerTreeHostTestContinuousInvalidate : public LayerTreeHostTest {
 public:
  LayerTreeHostTestContinuousInvalidate()
      : num_commit_complete_(0), num_draw_layers_(0) {}

  void BeginTest() override {
    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(10, 10), 1.f,
                                               viz::LocalSurfaceId());
    layer_tree_host()->root_layer()->SetBounds(gfx::Size(10, 10));

    layer_ = FakePictureLayer::Create(&client_);
    layer_->SetBounds(gfx::Size(10, 10));
    layer_->SetPosition(gfx::PointF(0.f, 0.f));
    layer_->SetIsDrawable(true);
    layer_tree_host()->root_layer()->AddChild(layer_);

    PostSetNeedsCommitToMainThread();
    client_.set_bounds(layer_->bounds());
  }

  void DidCommitAndDrawFrame() override {
    if (num_draw_layers_ == 2)
      return;
    layer_->SetNeedsDisplay();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    if (num_draw_layers_ == 1)
      num_commit_complete_++;
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    num_draw_layers_++;
    if (num_draw_layers_ == 2)
      EndTest();
  }

  void AfterTest() override {
    // Check that we didn't commit twice between first and second draw.
    EXPECT_EQ(1, num_commit_complete_);
  }

 private:
  FakeContentLayerClient client_;
  scoped_refptr<Layer> layer_;
  int num_commit_complete_;
  int num_draw_layers_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestContinuousInvalidate);

class LayerTreeHostTestDeferCommits : public LayerTreeHostTest {
 public:
  LayerTreeHostTestDeferCommits() = default;

  void BeginTest() override {
    // Start with commits deferred.
    PostSetDeferCommitsToMainThread(true);
    PostSetNeedsCommitToMainThread();
  }

  void WillBeginImplFrameOnThread(LayerTreeHostImpl* host_impl,
                                  const viz::BeginFrameArgs& args) override {
    // Impl frames happen while commits are deferred.
    num_will_begin_impl_frame_++;
    switch (num_will_begin_impl_frame_) {
      case 1:
      case 2:
      case 3:
      case 4:
        // Post a number of frames to increase the chance that, if there exist
        // bugs, an unexpected BeginMainFrame will be issued.
        PostSetNeedsCommitToMainThread();
        PostSetNeedsRedrawToMainThread();
        break;
      case 5:
        MainThreadTaskRunner()->PostTask(
            FROM_HERE,
            // Unretained because the test should not end before allowing
            // commits via this running.
            base::BindOnce(&LayerTreeHostTestDeferCommits::AllowCommits,
                           base::Unretained(this)));
        break;
      default:
        // Sometimes |num_will_begin_impl_frame_| will be greater than 5 if the
        // main thread is slow to respond.
        break;
    }
  }

  void WillBeginMainFrame() override {
    EXPECT_TRUE(IsCommitAllowed());
    num_send_begin_main_frame_++;
    EndTest();
  }

  void AfterTest() override {
    EXPECT_GE(num_will_begin_impl_frame_, 5);
    EXPECT_EQ(1, num_send_begin_main_frame_);
  }

  virtual void AllowCommits() {
    allow_commits_ = true;
    layer_tree_host()->SetDeferCommits(false);
  }

  virtual bool IsCommitAllowed() const { return allow_commits_; }

 private:
  bool allow_commits_ = false;
  int num_will_begin_impl_frame_ = 0;
  int num_send_begin_main_frame_ = 0;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestDeferCommits);

// This verifies that changing the size of a LayerTreeHost without providing a
// LocalSurfaceId defers commits.
class LayerTreeHostInvalidLocalSurfaceIdDefersCommit
    : public LayerTreeHostTestDeferCommits {
 public:
  LayerTreeHostInvalidLocalSurfaceIdDefersCommit() = default;
  void InitializeSettings(LayerTreeSettings* settings) override {
    // With surface synchronization turned on, commits are deferred until a
    // LocalSurfaceId has been assigned. The set up code sets the size of the
    // LayerTreeHost (using SetViewportSizeAndScale()), without providing a
    // LocalSurfaceId. So, commits should be deferred until we set an id later
    // during the test (in AllowCommits() override below).
    settings->enable_surface_synchronization = true;
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void AllowCommits() override {
    local_surface_id_ = allocator_.GenerateId();
    PostSetLocalSurfaceIdToMainThread(local_surface_id_);
  }

  bool IsCommitAllowed() const override { return local_surface_id_.is_valid(); }

 private:
  viz::ParentLocalSurfaceIdAllocator allocator_;
  viz::LocalSurfaceId local_surface_id_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostInvalidLocalSurfaceIdDefersCommit);

// This verifies that we can abort a commit inside the main frame, and
// we don't leave any weird states around if we never allow the commit
// to happen.
class LayerTreeHostTestDeferCommitsInsideBeginMainFrame
    : public LayerTreeHostTest {
 public:
  LayerTreeHostTestDeferCommitsInsideBeginMainFrame() = default;

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillBeginMainFrame() override {
    ++begin_main_frame_count_;
    if (allow_commits_)
      return;

    // This should prevent the commit from happening.
    layer_tree_host()->SetDeferCommits(true);
    // Wait to see if the commit happens. It's possible the deferred
    // commit happens when it shouldn't but takes long enough that
    // this passes. But it won't fail when it shouldn't.
    MainThreadTaskRunner()->PostDelayedTask(
        FROM_HERE,
        // Unretained because the test doesn't end before this runs.
        base::BindOnce(&LayerTreeTest::EndTest, base::Unretained(this)),
        base::TimeDelta::FromMilliseconds(100));
  }

  void DidCommit() override { ++commit_count_; }

  void AfterTest() override {
    EXPECT_EQ(0, commit_count_);
    EXPECT_EQ(1, begin_main_frame_count_);
  }

 private:
  bool allow_commits_ = false;
  int commit_count_ = 0;
  int begin_main_frame_count_ = 0;
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostTestDeferCommitsInsideBeginMainFrame);

// This verifies that we can abort a commit inside the main frame, and
// we will finish the commit once it is allowed.
class LayerTreeHostTestDeferCommitsInsideBeginMainFrameWithCommitAfter
    : public LayerTreeHostTest {
 public:
  LayerTreeHostTestDeferCommitsInsideBeginMainFrameWithCommitAfter() = default;

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillBeginMainFrame() override {
    ++begin_main_frame_count_;
    if (allow_commits_)
      return;

    // This should prevent the commit from happening.
    layer_tree_host()->SetDeferCommits(true);
    // Wait to see if the commit happens. It's possible the deferred
    // commit happens when it shouldn't but takes long enough that
    // this passes. But it won't fail when it shouldn't.
    MainThreadTaskRunner()->PostDelayedTask(
        FROM_HERE,
        // Unretained because the test doesn't end before this runs.
        base::BindOnce(
            &LayerTreeHostTestDeferCommitsInsideBeginMainFrameWithCommitAfter::
                AllowCommits,
            base::Unretained(this)),
        base::TimeDelta::FromMilliseconds(100));
  }

  void AllowCommits() {
    // Once we've waited and seen that commit did not happen, we
    // allow commits and should see this one go through.
    allow_commits_ = true;
    layer_tree_host()->SetDeferCommits(false);
  }

  void DidCommit() override {
    ++commit_count_;
    EXPECT_TRUE(allow_commits_);
    EndTest();
  }

  void AfterTest() override {
    EXPECT_EQ(1, commit_count_);
    EXPECT_EQ(2, begin_main_frame_count_);
    // The commit should not have been aborted.
    EXPECT_EQ(1, ready_to_commit_count_);
  }

  void ReadyToCommitOnThread(LayerTreeHostImpl* host_impl) override {
    ++ready_to_commit_count_;
  }

 private:
  bool allow_commits_ = false;
  int commit_count_ = 0;
  int begin_main_frame_count_ = 0;
  int ready_to_commit_count_ = 0;
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostTestDeferCommitsInsideBeginMainFrameWithCommitAfter);

// This verifies that animate_only BeginFrames only run animation/layout
// updates, i.e. abort commits after the animate stage and only request layer
// tree updates for layout.
//
// The tests sends four Begin(Main)Frames in sequence: three animate_only
// Begin(Main)Frames followed by a normal Begin(Main)Frame. The first three
// should result in aborted commits, whereas the last one should complete the
// previously aborted commits.
//
// Between BeginMainFrames 2 and 3, the client also requests a new commit
// (SetNeedsCommit), but not between BeginMainFrames 1 and 2. In multi-threaded
// mode, ProxyMain will run the animate pipeline stage only for BeginMainFrames
// 1 and 3, as no new commit was requested between 1 and 2.
//
// The test uses the full-pipeline mode to ensure that each BeginFrame also
// incurs a BeginMainFrame.
class LayerTreeHostTestAnimateOnlyBeginFrames
    : public LayerTreeHostTest,
      public viz::ExternalBeginFrameSourceClient {
 public:
  LayerTreeHostTestAnimateOnlyBeginFrames()
      : external_begin_frame_source_(this) {
    UseBeginFrameSource(&external_begin_frame_source_);
  }

  void IssueBeginFrame(bool animate_only) {
    ++begin_frame_count_;

    last_begin_frame_time_ += viz::BeginFrameArgs::DefaultInterval();
    uint64_t sequence_number = next_begin_frame_sequence_number_++;

    auto args = viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, viz::BeginFrameArgs::kManualSourceId,
        sequence_number, last_begin_frame_time_,
        last_begin_frame_time_ + viz::BeginFrameArgs::DefaultInterval(),
        viz::BeginFrameArgs::DefaultInterval(), viz::BeginFrameArgs::NORMAL);
    args.animate_only = animate_only;

    external_begin_frame_source_.OnBeginFrame(args);
  }

  void PostIssueBeginFrame(bool animate_only) {
    // Post a new task so that BeginFrame is not issued within same callstack.
    ImplThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &LayerTreeHostTestAnimateOnlyBeginFrames::IssueBeginFrame,
            base::Unretained(this), animate_only));
  }

  // viz::ExternalBeginFrameSourceClient implementation:
  void OnNeedsBeginFrames(bool needs_begin_frames) override {
    if (needs_begin_frames) {
      EXPECT_EQ(0, begin_frame_count_);
      // Send a first animation_only BeginFrame.
      PostIssueBeginFrame(true);
    }
  }

  // LayerTreeHostTest implementation:
  void BeginTest() override {
    PostSetNeedsCommitToMainThread();
    // OnNeedsBeginFrames(true) will be called during tree initialization.
  }

  void WillBeginMainFrame() override { ++will_begin_main_frame_count_; }

  void DidSendBeginMainFrameOnThread(LayerTreeHostImpl* host_impl) override {
    ++sent_begin_main_frame_count_;
    EXPECT_EQ(begin_frame_count_, sent_begin_main_frame_count_);
  }

  void DidFinishImplFrameOnThread(LayerTreeHostImpl* host_impl) override {
    if (begin_frame_count_ < 3) {
      if (begin_frame_count_ == 2) {
        // Request another commit before sending the third BeginMainFrame.
        PostSetNeedsCommitToMainThread();
      }

      // Send another animation_only BeginFrame.
      PostIssueBeginFrame(true);
    } else if (begin_frame_count_ == 3) {
      PostIssueBeginFrame(false);
    }
  }

  void UpdateLayerTreeHost(
      LayerTreeHostClient::VisualStateUpdate requested_update) override {
    ++update_layer_tree_host_count_;

    if (begin_frame_count_ < 4) {
      // First three BeginFrames are animate_only, so only kPrePaint updates are
      // requested.
      EXPECT_EQ(LayerTreeHostClient::VisualStateUpdate::kPrePaint,
                requested_update);
    } else {
      EXPECT_EQ(4, begin_frame_count_);
      // Last BeginFrame is normal, so all updates are requested.
      EXPECT_EQ(LayerTreeHostClient::VisualStateUpdate::kAll, requested_update);
    }
  }

  void DidCommit() override {
    ++commit_count_;

    // Fourth BeginMainFrame should lead to commit.
    EXPECT_EQ(4, begin_frame_count_);
    EXPECT_EQ(4, sent_begin_main_frame_count_);

    EndTest();
  }

  void ReadyToCommitOnThread(LayerTreeHostImpl* host_impl) override {
    ++ready_to_commit_count_;
  }

  void AfterTest() override {
    EXPECT_EQ(1, commit_count_);
    EXPECT_EQ(4, begin_frame_count_);
    EXPECT_EQ(4, sent_begin_main_frame_count_);

    if (HasImplThread()) {
      // ProxyMain aborts the second BeginMainFrame before running the animate
      // pipeline stage, since no further updates were made since the first one.
      // Thus, we expect not to be called for the second BeginMainFrame.
      EXPECT_EQ(3, will_begin_main_frame_count_);
      EXPECT_EQ(3, update_layer_tree_host_count_);
    } else {
      EXPECT_EQ(4, will_begin_main_frame_count_);
      EXPECT_EQ(4, update_layer_tree_host_count_);
    }

    // The final commit should not have been aborted.
    EXPECT_EQ(1, ready_to_commit_count_);
  }

 protected:
  void InitializeSettings(LayerTreeSettings* settings) override {
    // Use full-pipeline mode to make BeginFrame handling deterministic.
    EXPECT_FALSE(settings->wait_for_all_pipeline_stages_before_draw);
    settings->wait_for_all_pipeline_stages_before_draw = true;
  }

 private:
  viz::ExternalBeginFrameSource external_begin_frame_source_;

  base::TimeTicks last_begin_frame_time_ = base::TimeTicks::Now();
  uint64_t next_begin_frame_sequence_number_ =
      viz::BeginFrameArgs::kStartingFrameNumber;
  int commit_count_ = 0;
  int begin_frame_count_ = 0;
  int sent_begin_main_frame_count_ = 0;
  int will_begin_main_frame_count_ = 0;
  int update_layer_tree_host_count_ = 0;
  int ready_to_commit_count_ = 0;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestAnimateOnlyBeginFrames);

class LayerTreeHostTestCompositeImmediatelyStateTransitions
    : public LayerTreeHostTest {
 public:
  enum {
    kInvalid,
    kStartedTest,
    kStartedImplFrame,
    kStartedMainFrame,
    kStartedCommit,
    kCompletedCommit,
    kCompletedMainFrame,
    kCompletedImplFrame,
  };

  LayerTreeHostTestCompositeImmediatelyStateTransitions()
      : current_state_(kInvalid), current_begin_frame_args_() {}

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->single_thread_proxy_scheduler = false;
    settings->use_zero_copy = true;
  }

  void BeginTest() override {
    current_state_ = kStartedTest;
    PostCompositeImmediatelyToMainThread();
  }

  void WillBeginImplFrameOnThread(LayerTreeHostImpl* host_impl,
                                  const viz::BeginFrameArgs& args) override {
    EXPECT_EQ(current_state_, kStartedTest);
    current_state_ = kStartedImplFrame;

    EXPECT_FALSE(current_begin_frame_args_.IsValid());
    EXPECT_TRUE(args.IsValid());
    current_begin_frame_args_ = args;
  }
  void WillBeginMainFrame() override {
    EXPECT_EQ(current_state_, kStartedImplFrame);
    current_state_ = kStartedMainFrame;
  }
  void BeginMainFrame(const viz::BeginFrameArgs& args) override {
    EXPECT_EQ(current_state_, kStartedMainFrame);
    EXPECT_EQ(args.frame_time, current_begin_frame_args_.frame_time);
  }
  void BeginCommitOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_EQ(current_state_, kStartedMainFrame);
    current_state_ = kStartedCommit;
  }
  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_EQ(current_state_, kStartedCommit);
    current_state_ = kCompletedCommit;
  }
  void DidBeginMainFrame() override {
    EXPECT_EQ(current_state_, kCompletedCommit);
    current_state_ = kCompletedMainFrame;
  }
  void DidFinishImplFrameOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_EQ(current_state_, kCompletedMainFrame);
    current_state_ = kCompletedImplFrame;
    EndTest();
  }
  void AfterTest() override { EXPECT_EQ(current_state_, kCompletedImplFrame); }

 private:
  int current_state_;
  viz::BeginFrameArgs current_begin_frame_args_;
};

SINGLE_THREAD_TEST_F(LayerTreeHostTestCompositeImmediatelyStateTransitions);

class LayerTreeHostTestLCDChange : public LayerTreeHostTest {
 public:
  void SetupTree() override {
    num_tiles_rastered_ = 0;

    scoped_refptr<Layer> root_layer = PictureLayer::Create(&client_);
    client_.set_fill_with_nonsolid_color(true);
    root_layer->SetIsDrawable(true);
    root_layer->SetBounds(gfx::Size(10, 10));
    root_layer->SetContentsOpaque(true);

    layer_tree_host()->SetRootLayer(root_layer);

    // The expectations are based on the assumption that the default
    // LCD settings are:
    EXPECT_TRUE(layer_tree_host()->GetSettings().can_use_lcd_text);

    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommitAndDrawFrame() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        // Change layer opacity that should trigger lcd change.
        layer_tree_host()->root_layer()->SetOpacity(.5f);
        break;
      case 3:
        // Change layer opacity that should not trigger lcd change.
        layer_tree_host()->root_layer()->SetOpacity(1.f);
        break;
      case 4:
        EndTest();
        break;
    }
  }

  void NotifyTileStateChangedOnThread(LayerTreeHostImpl* host_impl,
                                      const Tile* tile) override {
    ++num_tiles_rastered_;
  }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    PictureLayerImpl* root_layer = static_cast<PictureLayerImpl*>(
        host_impl->active_tree()->root_layer_for_testing());
    bool can_use_lcd_text =
        host_impl->active_tree()->root_layer_for_testing()->CanUseLCDText();
    switch (host_impl->active_tree()->source_frame_number()) {
      case 0:
        // The first draw.
        EXPECT_EQ(1, num_tiles_rastered_);
        EXPECT_TRUE(can_use_lcd_text);
        EXPECT_TRUE(root_layer->RasterSourceUsesLCDTextForTesting());
        break;
      case 1:
        // Nothing changed on the layer.
        EXPECT_EQ(1, num_tiles_rastered_);
        EXPECT_TRUE(can_use_lcd_text);
        EXPECT_TRUE(root_layer->RasterSourceUsesLCDTextForTesting());
        break;
      case 2:
        // LCD text was disabled; it should be re-rastered with LCD text off.
        EXPECT_EQ(2, num_tiles_rastered_);
        EXPECT_FALSE(can_use_lcd_text);
        EXPECT_FALSE(root_layer->RasterSourceUsesLCDTextForTesting());
        break;
      case 3:
        // LCD text was enabled, but it's sticky and stays off.
        EXPECT_EQ(2, num_tiles_rastered_);
        EXPECT_TRUE(can_use_lcd_text);
        EXPECT_FALSE(root_layer->RasterSourceUsesLCDTextForTesting());
        break;
    }
  }

  void AfterTest() override {}

 private:
  FakeContentLayerClient client_;
  int num_tiles_rastered_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestLCDChange);

class LayerTreeHostTestBeginFrameNotificationShutdownWhileEnabled
    : public LayerTreeHostTest {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->using_synchronous_renderer_compositor = true;
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    // The BeginFrame notification is turned off now but will get enabled
    // once we return. End test while it's enabled.
    ImplThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(&LayerTreeHostTest::EndTest, base::Unretained(this)));
  }

  void AfterTest() override {}
};

MULTI_THREAD_TEST_F(
    LayerTreeHostTestBeginFrameNotificationShutdownWhileEnabled);

class LayerTreeHostTestAbortedCommitDoesntStall : public LayerTreeHostTest {
 protected:
  LayerTreeHostTestAbortedCommitDoesntStall()
      : commit_count_(0), commit_abort_count_(0), commit_complete_count_(0) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    commit_count_++;
    if (commit_count_ == 4) {
      // After two aborted commits, request a real commit now to make sure a
      // real commit following an aborted commit will still complete and
      // end the test even when the Impl thread is idle.
      layer_tree_host()->SetNeedsCommit();
    }
  }

  void BeginMainFrameAbortedOnThread(LayerTreeHostImpl* host_impl,
                                     CommitEarlyOutReason reason) override {
    commit_abort_count_++;
    // Initiate another abortable commit.
    host_impl->SetNeedsCommit();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    commit_complete_count_++;
    if (commit_complete_count_ == 1) {
      // Initiate an abortable commit after the first commit.
      host_impl->SetNeedsCommit();
    } else {
      EndTest();
    }
  }

  void AfterTest() override {
    EXPECT_EQ(commit_count_, 5);
    EXPECT_EQ(commit_abort_count_, 3);
    EXPECT_EQ(commit_complete_count_, 2);
  }

  int commit_count_;
  int commit_abort_count_;
  int commit_complete_count_;
};

class OnDrawLayerTreeFrameSink : public viz::TestLayerTreeFrameSink {
 public:
  OnDrawLayerTreeFrameSink(
      scoped_refptr<viz::ContextProvider> compositor_context_provider,
      scoped_refptr<viz::RasterContextProvider> worker_context_provider,
      gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
      const viz::RendererSettings& renderer_settings,
      base::SingleThreadTaskRunner* task_runner,
      bool synchronous_composite,
      double refresh_rate,
      base::Closure invalidate_callback)
      : TestLayerTreeFrameSink(std::move(compositor_context_provider),
                               std::move(worker_context_provider),
                               gpu_memory_buffer_manager,
                               renderer_settings,
                               task_runner,
                               synchronous_composite,
                               false /* disable_display_vsync */,
                               refresh_rate),
        invalidate_callback_(std::move(invalidate_callback)) {}

  // TestLayerTreeFrameSink overrides.
  void Invalidate() override { invalidate_callback_.Run(); }

  void OnDraw(bool resourceless_software_draw) {
    gfx::Transform identity;
    gfx::Rect empty_rect;
    client_->OnDraw(identity, empty_rect, resourceless_software_draw);
  }

 private:
  const base::Closure invalidate_callback_;
};

class LayerTreeHostTestAbortedCommitDoesntStallSynchronousCompositor
    : public LayerTreeHostTestAbortedCommitDoesntStall {
 protected:
  void InitializeSettings(LayerTreeSettings* settings) override {
    LayerTreeHostTestAbortedCommitDoesntStall::InitializeSettings(settings);
    settings->using_synchronous_renderer_compositor = true;
  }

  std::unique_ptr<viz::TestLayerTreeFrameSink> CreateLayerTreeFrameSink(
      const viz::RendererSettings& renderer_settings,
      double refresh_rate,
      scoped_refptr<viz::ContextProvider> compositor_context_provider,
      scoped_refptr<viz::RasterContextProvider> worker_context_provider)
      override {
    auto on_draw_callback = base::Bind(
        &LayerTreeHostTestAbortedCommitDoesntStallSynchronousCompositor::
            CallOnDraw,
        base::Unretained(this));
    auto frame_sink = std::make_unique<OnDrawLayerTreeFrameSink>(
        compositor_context_provider, std::move(worker_context_provider),
        gpu_memory_buffer_manager(), renderer_settings, ImplThreadTaskRunner(),
        false /* synchronous_composite */, refresh_rate,
        std::move(on_draw_callback));
    layer_tree_frame_sink_ = frame_sink.get();
    return std::move(frame_sink);
  }

  void CallOnDraw() {
    if (!TestEnded()) {
      // Synchronous compositor does not draw unless told to do so by the output
      // surface. But it needs to be done on a new stack frame.
      bool resourceless_software_draw = false;
      ImplThreadTaskRunner()->PostTask(
          FROM_HERE, base::BindOnce(&OnDrawLayerTreeFrameSink::OnDraw,
                                    base::Unretained(layer_tree_frame_sink_),
                                    resourceless_software_draw));
    }
  }

  OnDrawLayerTreeFrameSink* layer_tree_frame_sink_ = nullptr;
};

MULTI_THREAD_TEST_F(
    LayerTreeHostTestAbortedCommitDoesntStallSynchronousCompositor);

class LayerTreeHostTestUninvertibleTransformDoesNotBlockActivation
    : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    LayerTreeHostTest::SetupTree();

    scoped_refptr<Layer> layer = PictureLayer::Create(&client_);
    layer->SetTransform(gfx::Transform(0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
    layer->SetBounds(gfx::Size(10, 10));
    layer_tree_host()->root_layer()->AddChild(layer);
    client_.set_bounds(layer->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    EndTest();
  }

  void AfterTest() override {}

  FakeContentLayerClient client_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostTestUninvertibleTransformDoesNotBlockActivation);

class LayerTreeHostTestNumFramesPending : public LayerTreeHostTest {
 public:
  void BeginTest() override {
    frame_ = 0;
    PostSetNeedsCommitToMainThread();
  }

  // Round 1: commit + draw
  // Round 2: commit only (no draw/swap)
  // Round 3: draw only (no commit)

  void DidCommit() override {
    int commit = layer_tree_host()->SourceFrameNumber();
    switch (commit) {
      case 2:
        // Round 2 done.
        EXPECT_EQ(1, frame_);
        layer_tree_host()->SetNeedsRedrawRect(
            gfx::Rect(layer_tree_host()->device_viewport_size()));
        break;
    }
  }

  void DidReceiveCompositorFrameAck() override {
    int commit = layer_tree_host()->SourceFrameNumber();
    ++frame_;
    switch (frame_) {
      case 1:
        // Round 1 done.
        EXPECT_EQ(1, commit);
        layer_tree_host()->SetNeedsCommit();
        break;
      case 2:
        // Round 3 done.
        EXPECT_EQ(2, commit);
        EndTest();
        break;
    }
  }

  void AfterTest() override {}

 protected:
  int frame_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestNumFramesPending);

// Test for UI Resource management.
class LayerTreeHostTestUIResource : public LayerTreeHostTest {
 public:
  LayerTreeHostTestUIResource() : num_ui_resources_(0) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    int frame = layer_tree_host()->SourceFrameNumber();
    switch (frame) {
      case 1:
        CreateResource();
        CreateResource();
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        // Usually ScopedUIResource are deleted from the manager in their
        // destructor.  Here we just want to test that a direct call to
        // DeleteUIResource works.
        layer_tree_host()->GetUIResourceManager()->DeleteUIResource(
            ui_resources_[0]->id());
        PostSetNeedsCommitToMainThread();
        break;
      case 3:
        // DeleteUIResource can be called with an invalid id.
        layer_tree_host()->GetUIResourceManager()->DeleteUIResource(
            ui_resources_[0]->id());
        PostSetNeedsCommitToMainThread();
        break;
      case 4:
        CreateResource();
        CreateResource();
        PostSetNeedsCommitToMainThread();
        break;
      case 5:
        ClearResources();
        EndTest();
        break;
    }
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    auto* context = static_cast<viz::TestContextProvider*>(
                        impl->layer_tree_frame_sink()->context_provider())
                        ->TestContext3d();

    int frame = impl->active_tree()->source_frame_number();
    switch (frame) {
      case 0:
        ASSERT_EQ(0u, context->NumTextures());
        break;
      case 1:
        // Created two textures.
        ASSERT_EQ(2u, context->NumTextures());
        break;
      case 2:
        // One texture left after one deletion.
        ASSERT_EQ(1u, context->NumTextures());
        break;
      case 3:
        // Resource manager state should not change when delete is called on an
        // invalid id.
        ASSERT_EQ(1u, context->NumTextures());
        break;
      case 4:
        // Creation after deletion: two more creates should total up to
        // three textures.
        ASSERT_EQ(3u, context->NumTextures());
        break;
    }
  }

  void AfterTest() override {}

 private:
  // Must clear all resources before exiting.
  void ClearResources() {
    for (int i = 0; i < num_ui_resources_; i++)
      ui_resources_[i] = nullptr;
  }

  void CreateResource() {
    ui_resources_[num_ui_resources_++] =
        FakeScopedUIResource::Create(layer_tree_host()->GetUIResourceManager());
  }

  std::unique_ptr<FakeScopedUIResource> ui_resources_[5];
  int num_ui_resources_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestUIResource);

class LayerTreeHostTestLayersPushProperties : public LayerTreeHostTest {
 protected:
  void BeginTest() override {
    num_commits_ = 0;
    expected_push_properties_root_ = 0;
    expected_push_properties_child_ = 0;
    expected_push_properties_grandchild_ = 0;
    expected_push_properties_child2_ = 0;
    expected_push_properties_other_root_ = 0;
    expected_push_properties_leaf_layer_ = 0;
    PostSetNeedsCommitToMainThread();
  }

  void SetupTree() override {
    root_ = PushPropertiesCountingLayer::Create();
    child_ = PushPropertiesCountingLayer::Create();
    child2_ = PushPropertiesCountingLayer::Create();
    grandchild_ = PushPropertiesCountingLayer::Create();
    leaf_always_pushing_layer_ = PushPropertiesCountingLayer::Create();
    leaf_always_pushing_layer_->set_persist_needs_push_properties(true);

    root_->AddChild(child_);
    root_->AddChild(child2_);
    child_->AddChild(grandchild_);
    child2_->AddChild(leaf_always_pushing_layer_);

    other_root_ = PushPropertiesCountingLayer::Create();

    // Don't set the root layer here.
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_->bounds());
  }

  void DidCommitAndDrawFrame() override {
    EXPECT_EQ(expected_push_properties_root_, root_->push_properties_count())
        << "num_commits: " << num_commits_;
    EXPECT_EQ(expected_push_properties_child_, child_->push_properties_count())
        << "num_commits: " << num_commits_;
    EXPECT_EQ(expected_push_properties_grandchild_,
              grandchild_->push_properties_count())
        << "num_commits: " << num_commits_;
    EXPECT_EQ(expected_push_properties_child2_,
              child2_->push_properties_count())
        << "num_commits: " << num_commits_;
    EXPECT_EQ(expected_push_properties_other_root_,
              other_root_->push_properties_count())
        << "num_commits: " << num_commits_;
    EXPECT_EQ(expected_push_properties_leaf_layer_,
              leaf_always_pushing_layer_->push_properties_count())
        << "num_commits: " << num_commits_;

    ++num_commits_;

    // The scrollbar layer always needs to be pushed.
    if (root_->layer_tree_host()) {
      EXPECT_FALSE(root_->layer_tree_host()->LayerNeedsPushPropertiesForTesting(
          root_.get()));
    }
    if (child2_->layer_tree_host()) {
      EXPECT_FALSE(
          child2_->layer_tree_host()->LayerNeedsPushPropertiesForTesting(
              child2_.get()));
    }
    if (leaf_always_pushing_layer_->layer_tree_host()) {
      EXPECT_TRUE(leaf_always_pushing_layer_->layer_tree_host()
                      ->LayerNeedsPushPropertiesForTesting(
                          leaf_always_pushing_layer_.get()));
    }

    // child_ and grandchild_ don't persist their need to push properties.
    if (child_->layer_tree_host()) {
      EXPECT_FALSE(
          child_->layer_tree_host()->LayerNeedsPushPropertiesForTesting(
              child_.get()));
    }
    if (grandchild_->layer_tree_host()) {
      EXPECT_FALSE(
          grandchild_->layer_tree_host()->LayerNeedsPushPropertiesForTesting(
              grandchild_.get()));
    }

    if (other_root_->layer_tree_host()) {
      EXPECT_FALSE(
          other_root_->layer_tree_host()->LayerNeedsPushPropertiesForTesting(
              other_root_.get()));
    }

    switch (num_commits_) {
      case 1:
        layer_tree_host()->SetRootLayer(root_);
        // Layers added to the tree get committed.
        ++expected_push_properties_root_;
        ++expected_push_properties_child_;
        ++expected_push_properties_grandchild_;
        ++expected_push_properties_child2_;
        break;
      case 2:
        layer_tree_host()->SetNeedsCommit();
        // No layers need commit.
        break;
      case 3:
        layer_tree_host()->SetRootLayer(other_root_);
        // Layers added to the tree get committed.
        ++expected_push_properties_other_root_;
        break;
      case 4:
        layer_tree_host()->SetRootLayer(root_);
        // Layers added to the tree get committed.
        ++expected_push_properties_root_;
        ++expected_push_properties_child_;
        ++expected_push_properties_grandchild_;
        ++expected_push_properties_child2_;
        break;
      case 5:
        layer_tree_host()->SetNeedsCommit();
        // No layers need commit.
        break;
      case 6:
        child_->RemoveFromParent();
        // No layers need commit.
        break;
      case 7:
        root_->AddChild(child_);
        // Layers added to the tree get committed.
        ++expected_push_properties_child_;
        ++expected_push_properties_grandchild_;
        break;
      case 8:
        grandchild_->RemoveFromParent();
        // No layers need commit.
        break;
      case 9:
        child_->AddChild(grandchild_);
        // Layers added to the tree get committed.
        ++expected_push_properties_grandchild_;
        break;
      case 10:
        layer_tree_host()->SetViewportSizeAndScale(gfx::Size(20, 20), 1.f,
                                                   viz::LocalSurfaceId());
        // No layers need commit.
        break;
      case 11:
        layer_tree_host()->SetPageScaleFactorAndLimits(1.f, 0.8f, 1.1f);
        // No layers need commit.
        break;
      case 12:
        child_->MakePushProperties();
        // The modified layer needs commit
        ++expected_push_properties_child_;
        ++expected_push_properties_grandchild_;
        break;
      case 13:
        child2_->MakePushProperties();
        // The modified layer needs commit
        ++expected_push_properties_child2_;
        break;
      case 14:
        child_->RemoveFromParent();
        root_->AddChild(child_);
        // Layers added to the tree get committed.
        ++expected_push_properties_child_;
        ++expected_push_properties_grandchild_;
        break;
      case 15:
        grandchild_->MakePushProperties();
        // The modified layer needs commit
        ++expected_push_properties_grandchild_;
        break;
      case 16:
        // SetNeedsDisplay does not always set needs commit (so call it
        // explicitly), but is a property change.
        child_->SetNeedsDisplay();
        ++expected_push_properties_child_;
        layer_tree_host()->SetNeedsCommit();
        break;
      case 17:
        EndTest();
        break;
    }

    // The leaf layer always pushes.
    if (leaf_always_pushing_layer_->layer_tree_host())
      ++expected_push_properties_leaf_layer_;
  }

  void AfterTest() override {}

  int num_commits_;
  FakeContentLayerClient client_;
  scoped_refptr<PushPropertiesCountingLayer> root_;
  scoped_refptr<PushPropertiesCountingLayer> child_;
  scoped_refptr<PushPropertiesCountingLayer> child2_;
  scoped_refptr<PushPropertiesCountingLayer> grandchild_;
  scoped_refptr<PushPropertiesCountingLayer> other_root_;
  scoped_refptr<PushPropertiesCountingLayer> leaf_always_pushing_layer_;
  size_t expected_push_properties_root_;
  size_t expected_push_properties_child_;
  size_t expected_push_properties_child2_;
  size_t expected_push_properties_grandchild_;
  size_t expected_push_properties_other_root_;
  size_t expected_push_properties_leaf_layer_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestLayersPushProperties);

class LayerTreeHostTestImplLayersPushProperties
    : public LayerTreeHostTestLayersPushProperties {
 protected:
  void BeginTest() override {
    expected_push_properties_root_impl_ = 0;
    expected_push_properties_child_impl_ = 0;
    expected_push_properties_grandchild_impl_ = 0;
    expected_push_properties_child2_impl_ = 0;
    expected_push_properties_grandchild2_impl_ = 0;
    LayerTreeHostTestLayersPushProperties::BeginTest();
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    // These commits are in response to the changes made in
    // LayerTreeHostTestLayersPushProperties::DidCommitAndDrawFrame()
    switch (num_commits_) {
      case 0:
        // Tree hasn't been setup yet don't bother to check anything.
        return;
      case 1:
        // Root gets set up, Everyone is initialized.
        ++expected_push_properties_root_impl_;
        ++expected_push_properties_child_impl_;
        ++expected_push_properties_grandchild_impl_;
        ++expected_push_properties_child2_impl_;
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 2:
        // Tree doesn't change but the one leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 3:
        // Root is swapped here.
        // Clear the expected push properties the tree will be rebuilt.
        expected_push_properties_root_impl_ = 0;
        expected_push_properties_child_impl_ = 0;
        expected_push_properties_grandchild_impl_ = 0;
        expected_push_properties_child2_impl_ = 0;
        expected_push_properties_grandchild2_impl_ = 0;

        // Make sure the new root is pushed.
        EXPECT_EQ(1u, static_cast<PushPropertiesCountingLayerImpl*>(
                          host_impl->active_tree()->root_layer_for_testing())
                          ->push_properties_count());
        return;
      case 4:
        // Root is swapped back all of the layers in the tree get pushed.
        ++expected_push_properties_root_impl_;
        ++expected_push_properties_child_impl_;
        ++expected_push_properties_grandchild_impl_;
        ++expected_push_properties_child2_impl_;
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 5:
        // Tree doesn't change but the one leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 6:
        // First child is removed. Structure of the tree changes.
        expected_push_properties_child_impl_ = 0;
        expected_push_properties_grandchild_impl_ = 0;

        // The leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 7:
        // The leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;

        // Child is added back. New layers are initialized.
        ++expected_push_properties_grandchild_impl_;
        ++expected_push_properties_child_impl_;
        break;
      case 8:
        // Leaf is removed.
        expected_push_properties_grandchild_impl_ = 0;

        // Always pushing.
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 9:
        // Leaf is added back
        ++expected_push_properties_grandchild_impl_;

        // The leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 10:
        // The leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 11:
        // The leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 12:
        // The leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;

        // This child position was changed. So the subtree needs to push
        // properties.
        ++expected_push_properties_child_impl_;
        ++expected_push_properties_grandchild_impl_;
        break;
      case 13:
        // The position of this child was changed.
        ++expected_push_properties_child2_impl_;

        // The leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 14:
        // Second child is removed from tree. Don't discard counts because
        // they are added back before commit.

        // The leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;

        // Second child added back.
        ++expected_push_properties_child_impl_;
        ++expected_push_properties_grandchild_impl_;

        break;
      case 15:
        // The position of this child was changed.
        ++expected_push_properties_grandchild_impl_;

        // The leaf that always pushes is pushed.
        ++expected_push_properties_grandchild2_impl_;
        break;
      case 16:
        // Second child is invalidated with SetNeedsDisplay
        ++expected_push_properties_child_impl_;

        // The leaf that always pushed is pushed.
        ++expected_push_properties_grandchild2_impl_;
        break;
    }

    PushPropertiesCountingLayerImpl* root_impl_ = nullptr;
    PushPropertiesCountingLayerImpl* child_impl_ = nullptr;
    PushPropertiesCountingLayerImpl* child2_impl_ = nullptr;
    PushPropertiesCountingLayerImpl* grandchild_impl_ = nullptr;
    PushPropertiesCountingLayerImpl* leaf_always_pushing_layer_impl_ = nullptr;

    // Pull the layers that we need from the tree assuming the same structure
    // as LayerTreeHostTestLayersPushProperties
    root_impl_ = static_cast<PushPropertiesCountingLayerImpl*>(
        host_impl->active_tree()->root_layer_for_testing());

    LayerTreeImpl* impl = root_impl_->layer_tree_impl();
    if (impl->LayerById(child_->id())) {
      child_impl_ = static_cast<PushPropertiesCountingLayerImpl*>(
          impl->LayerById(child_->id()));

      if (impl->LayerById(grandchild_->id()))
        grandchild_impl_ = static_cast<PushPropertiesCountingLayerImpl*>(
            impl->LayerById(grandchild_->id()));
    }

    if (impl->LayerById(child2_->id())) {
      child2_impl_ = static_cast<PushPropertiesCountingLayerImpl*>(
          impl->LayerById(child2_->id()));

      if (impl->LayerById(leaf_always_pushing_layer_->id()))
        leaf_always_pushing_layer_impl_ =
            static_cast<PushPropertiesCountingLayerImpl*>(
                impl->LayerById(leaf_always_pushing_layer_->id()));
    }

    if (root_impl_)
      EXPECT_EQ(expected_push_properties_root_impl_,
                root_impl_->push_properties_count());
    if (child_impl_)
      EXPECT_EQ(expected_push_properties_child_impl_,
                child_impl_->push_properties_count());
    if (grandchild_impl_)
      EXPECT_EQ(expected_push_properties_grandchild_impl_,
                grandchild_impl_->push_properties_count());
    if (child2_impl_)
      EXPECT_EQ(expected_push_properties_child2_impl_,
                child2_impl_->push_properties_count());
    if (leaf_always_pushing_layer_impl_)
      EXPECT_EQ(expected_push_properties_grandchild2_impl_,
                leaf_always_pushing_layer_impl_->push_properties_count());
  }

  size_t expected_push_properties_root_impl_;
  size_t expected_push_properties_child_impl_;
  size_t expected_push_properties_child2_impl_;
  size_t expected_push_properties_grandchild_impl_;
  size_t expected_push_properties_grandchild2_impl_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestImplLayersPushProperties);

class LayerTreeHostTestPropertyChangesDuringUpdateArePushed
    : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void SetupTree() override {
    root_ = Layer::Create();
    root_->SetBounds(gfx::Size(1, 1));

    bool paint_scrollbar = true;
    bool has_thumb = false;
    scrollbar_layer_ = FakePaintedScrollbarLayer::Create(
        paint_scrollbar, has_thumb, root_->element_id());

    root_->AddChild(scrollbar_layer_);

    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostTest::SetupTree();
  }

  void DidCommitAndDrawFrame() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 0:
        break;
      case 1: {
        // During update, the ignore_set_needs_commit_ bit is set to true to
        // avoid causing a second commit to be scheduled. If a property change
        // is made during this, however, it needs to be pushed in the upcoming
        // commit.
        std::unique_ptr<base::AutoReset<bool>> ignore =
            scrollbar_layer_->IgnoreSetNeedsCommit();

        scrollbar_layer_->SetBounds(gfx::Size(30, 30));

        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            scrollbar_layer_.get()));
        layer_tree_host()->SetNeedsCommit();

        scrollbar_layer_->reset_push_properties_count();
        EXPECT_EQ(0u, scrollbar_layer_->push_properties_count());
        break;
      }
      case 2:
        EXPECT_EQ(1u, scrollbar_layer_->push_properties_count());
        EndTest();
        break;
    }
  }

  void AfterTest() override {}

  scoped_refptr<Layer> root_;
  scoped_refptr<FakePaintedScrollbarLayer> scrollbar_layer_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestPropertyChangesDuringUpdateArePushed);

class LayerTreeHostTestSetDrawableCausesCommit : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void SetupTree() override {
    root_ = PushPropertiesCountingLayer::Create();
    child_ = PushPropertiesCountingLayer::Create();
    root_->AddChild(child_);

    layer_tree_host()->SetRootLayer(root_);
    LayerTreeHostTest::SetupTree();
  }

  void DidCommitAndDrawFrame() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 0:
        break;
      case 1: {
        // During update, the ignore_set_needs_commit_ bit is set to true to
        // avoid causing a second commit to be scheduled. If a property change
        // is made during this, however, it needs to be pushed in the upcoming
        // commit.
        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_EQ(0, root_->NumDescendantsThatDrawContent());
        root_->reset_push_properties_count();
        child_->reset_push_properties_count();
        child_->SetIsDrawable(true);
        EXPECT_EQ(1, root_->NumDescendantsThatDrawContent());
        EXPECT_EQ(0u, root_->push_properties_count());
        EXPECT_EQ(0u, child_->push_properties_count());
        EXPECT_TRUE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(

            layer_tree_host()->LayerNeedsPushPropertiesForTesting(
                child_.get()));
        break;
      }
      case 2:
        EXPECT_EQ(1u, root_->push_properties_count());
        EXPECT_EQ(1u, child_->push_properties_count());
        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EndTest();
        break;
    }
  }

  void AfterTest() override {}

  scoped_refptr<PushPropertiesCountingLayer> root_;
  scoped_refptr<PushPropertiesCountingLayer> child_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestSetDrawableCausesCommit);

class LayerTreeHostTestCasePushPropertiesThreeGrandChildren
    : public LayerTreeHostTest {
 protected:
  void BeginTest() override {
    expected_push_properties_root_ = 0;
    expected_push_properties_child_ = 0;
    expected_push_properties_grandchild1_ = 0;
    expected_push_properties_grandchild2_ = 0;
    expected_push_properties_grandchild3_ = 0;
    PostSetNeedsCommitToMainThread();
  }

  void SetupTree() override {
    root_ = PushPropertiesCountingLayer::Create();
    child_ = PushPropertiesCountingLayer::Create();
    grandchild1_ = PushPropertiesCountingLayer::Create();
    grandchild2_ = PushPropertiesCountingLayer::Create();
    grandchild3_ = PushPropertiesCountingLayer::Create();

    root_->AddChild(child_);
    child_->AddChild(grandchild1_);
    child_->AddChild(grandchild2_);
    child_->AddChild(grandchild3_);

    // Don't set the root layer here.
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_->bounds());
  }

  void AfterTest() override {}

  FakeContentLayerClient client_;
  scoped_refptr<PushPropertiesCountingLayer> root_;
  scoped_refptr<PushPropertiesCountingLayer> child_;
  scoped_refptr<PushPropertiesCountingLayer> grandchild1_;
  scoped_refptr<PushPropertiesCountingLayer> grandchild2_;
  scoped_refptr<PushPropertiesCountingLayer> grandchild3_;
  size_t expected_push_properties_root_;
  size_t expected_push_properties_child_;
  size_t expected_push_properties_grandchild1_;
  size_t expected_push_properties_grandchild2_;
  size_t expected_push_properties_grandchild3_;
};

class LayerTreeHostTestPushPropertiesAddingToTreeRequiresPush
    : public LayerTreeHostTestCasePushPropertiesThreeGrandChildren {
 protected:
  void DidCommitAndDrawFrame() override {
    int last_source_frame_number = layer_tree_host()->SourceFrameNumber() - 1;
    switch (last_source_frame_number) {
      case 0:
        // All layers will need push properties as we set their layer tree host
        layer_tree_host()->SetRootLayer(root_);
        EXPECT_TRUE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));
        break;
      case 1:
        EndTest();
        break;
    }
  }
};

MULTI_THREAD_TEST_F(LayerTreeHostTestPushPropertiesAddingToTreeRequiresPush);

class LayerTreeHostTestPushPropertiesRemovingChildStopsRecursion
    : public LayerTreeHostTestCasePushPropertiesThreeGrandChildren {
 protected:
  void DidCommitAndDrawFrame() override {
    int last_source_frame_number = layer_tree_host()->SourceFrameNumber() - 1;
    switch (last_source_frame_number) {
      case 0:
        layer_tree_host()->SetRootLayer(root_);
        break;
      case 1:
        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        grandchild1_->RemoveFromParent();
        grandchild1_->SetPosition(gfx::PointF(1.f, 1.f));

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        child_->AddChild(grandchild1_);

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        grandchild2_->SetPosition(gfx::PointF(1.f, 1.f));

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        // grandchild2_ will still need a push properties.
        grandchild1_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));

        // grandchild3_ does not need a push properties, so recursing should
        // no longer be needed.
        grandchild2_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EndTest();
        break;
    }
  }
};

MULTI_THREAD_TEST_F(LayerTreeHostTestPushPropertiesRemovingChildStopsRecursion);

class LayerTreeHostTestPushPropertiesRemovingChildStopsRecursionWithPersistence
    : public LayerTreeHostTestCasePushPropertiesThreeGrandChildren {
 protected:
  void DidCommitAndDrawFrame() override {
    int last_source_frame_number = layer_tree_host()->SourceFrameNumber() - 1;
    switch (last_source_frame_number) {
      case 0:
        layer_tree_host()->SetRootLayer(root_);
        grandchild1_->set_persist_needs_push_properties(true);
        grandchild2_->set_persist_needs_push_properties(true);
        break;
      case 1:
        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        // grandchild2_ will still need a push properties.
        grandchild1_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));

        // grandchild3_ does not need a push properties, so recursing should
        // no longer be needed.
        grandchild2_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EndTest();
        break;
    }
  }
};

MULTI_THREAD_TEST_F(
    LayerTreeHostTestPushPropertiesRemovingChildStopsRecursionWithPersistence);

class LayerTreeHostTestPushPropertiesSetPropertiesWhileOutsideTree
    : public LayerTreeHostTestCasePushPropertiesThreeGrandChildren {
 protected:
  void DidCommitAndDrawFrame() override {
    int last_source_frame_number = layer_tree_host()->SourceFrameNumber() - 1;
    switch (last_source_frame_number) {
      case 0:
        layer_tree_host()->SetRootLayer(root_);
        break;
      case 1:
        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        // Change grandchildren while their parent is not in the tree.
        child_->RemoveFromParent();
        grandchild1_->SetPosition(gfx::PointF(1.f, 1.f));
        grandchild2_->SetPosition(gfx::PointF(1.f, 1.f));
        root_->AddChild(child_);

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        grandchild1_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));

        grandchild2_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));

        grandchild3_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));

        EndTest();
        break;
    }
  }
};

MULTI_THREAD_TEST_F(
    LayerTreeHostTestPushPropertiesSetPropertiesWhileOutsideTree);

class LayerTreeHostTestPushPropertiesSetPropertyInParentThenChild
    : public LayerTreeHostTestCasePushPropertiesThreeGrandChildren {
 protected:
  void DidCommitAndDrawFrame() override {
    int last_source_frame_number = layer_tree_host()->SourceFrameNumber() - 1;
    switch (last_source_frame_number) {
      case 0:
        layer_tree_host()->SetRootLayer(root_);
        break;
      case 1:
        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        child_->SetPosition(gfx::PointF(1.f, 1.f));
        grandchild1_->SetPosition(gfx::PointF(1.f, 1.f));
        grandchild2_->SetPosition(gfx::PointF(1.f, 1.f));

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        grandchild1_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));

        grandchild2_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));

        child_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));

        EndTest();
        break;
    }
  }
};

MULTI_THREAD_TEST_F(
    LayerTreeHostTestPushPropertiesSetPropertyInParentThenChild);

class LayerTreeHostTestPushPropertiesSetPropertyInChildThenParent
    : public LayerTreeHostTestCasePushPropertiesThreeGrandChildren {
 protected:
  void DidCommitAndDrawFrame() override {
    int last_source_frame_number = layer_tree_host()->SourceFrameNumber() - 1;
    switch (last_source_frame_number) {
      case 0:
        layer_tree_host()->SetRootLayer(root_);
        break;
      case 1:
        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        grandchild1_->SetPosition(gfx::PointF(1.f, 1.f));
        grandchild2_->SetPosition(gfx::PointF(1.f, 1.f));
        child_->SetPosition(gfx::PointF(1.f, 1.f));

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild1_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild2_.get()));
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            grandchild3_.get()));

        grandchild1_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));

        grandchild2_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));
        EXPECT_TRUE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_.get()));

        child_->RemoveFromParent();

        EXPECT_FALSE(
            layer_tree_host()->LayerNeedsPushPropertiesForTesting(root_.get()));

        EndTest();
        break;
    }
  }
};

MULTI_THREAD_TEST_F(
    LayerTreeHostTestPushPropertiesSetPropertyInChildThenParent);

// This test verifies that the tree activation callback is invoked correctly.
class LayerTreeHostTestTreeActivationCallback : public LayerTreeHostTest {
 public:
  LayerTreeHostTestTreeActivationCallback()
      : num_commits_(0), callback_count_(0) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    ++num_commits_;
    switch (num_commits_) {
      case 1:
        EXPECT_EQ(0, callback_count_);
        callback_count_ = 0;
        SetCallback(host_impl, true);
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        EXPECT_EQ(1, callback_count_);
        callback_count_ = 0;
        SetCallback(host_impl, false);
        PostSetNeedsCommitToMainThread();
        break;
      case 3:
        EXPECT_EQ(0, callback_count_);
        callback_count_ = 0;
        EndTest();
        break;
      default:
        ADD_FAILURE() << num_commits_;
        EndTest();
        break;
    }
    return LayerTreeHostTest::PrepareToDrawOnThread(host_impl, frame_data,
                                                    draw_result);
  }

  void AfterTest() override { EXPECT_EQ(3, num_commits_); }

  void SetCallback(LayerTreeHostImpl* host_impl, bool enable) {
    host_impl->SetTreeActivationCallback(
        enable
            ? base::Bind(
                  &LayerTreeHostTestTreeActivationCallback::ActivationCallback,
                  base::Unretained(this))
            : base::Closure());
  }

  void ActivationCallback() { ++callback_count_; }

  int num_commits_;
  int callback_count_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestTreeActivationCallback);

class LayerInvalidateCausesDraw : public LayerTreeHostTest {
 public:
  LayerInvalidateCausesDraw() : num_commits_(0), num_draws_(0) {}

  void BeginTest() override {
    ASSERT_TRUE(invalidate_layer_)
        << "Derived tests must set this in SetupTree";

    // One initial commit.
    PostSetNeedsCommitToMainThread();
  }

  void DidCommitAndDrawFrame() override {
    // After commit, invalidate the layer.  This should cause a commit.
    if (layer_tree_host()->SourceFrameNumber() == 1)
      invalidate_layer_->SetNeedsDisplay();
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    num_draws_++;
    if (impl->active_tree()->source_frame_number() == 1)
      EndTest();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    num_commits_++;
  }

  void AfterTest() override {
    EXPECT_GE(2, num_commits_);
    EXPECT_GE(2, num_draws_);
  }

 protected:
  scoped_refptr<Layer> invalidate_layer_;

 private:
  int num_commits_;
  int num_draws_;
};

// VideoLayer must support being invalidated and then passing that along
// to the compositor thread, even though no resources are updated in
// response to that invalidation.
class LayerTreeHostTestVideoLayerInvalidate : public LayerInvalidateCausesDraw {
 public:
  void SetupTree() override {
    LayerTreeHostTest::SetupTree();
    scoped_refptr<VideoLayer> video_layer =
        VideoLayer::Create(&provider_, media::VIDEO_ROTATION_0);
    video_layer->SetBounds(gfx::Size(10, 10));
    video_layer->SetIsDrawable(true);
    layer_tree_host()->root_layer()->AddChild(video_layer);

    invalidate_layer_ = video_layer;
  }

 private:
  FakeVideoFrameProvider provider_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestVideoLayerInvalidate);

class LayerTreeHostTestPushHiddenLayer : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root_layer_ = Layer::Create();
    root_layer_->SetPosition(gfx::PointF());
    root_layer_->SetBounds(gfx::Size(10, 10));

    parent_layer_ = SolidColorLayer::Create();
    parent_layer_->SetPosition(gfx::PointF());
    parent_layer_->SetBounds(gfx::Size(10, 10));
    parent_layer_->SetIsDrawable(true);
    root_layer_->AddChild(parent_layer_);

    child_layer_ = SolidColorLayer::Create();
    child_layer_->SetPosition(gfx::PointF());
    child_layer_->SetBounds(gfx::Size(10, 10));
    child_layer_->SetIsDrawable(true);
    parent_layer_->AddChild(child_layer_);

    layer_tree_host()->SetRootLayer(root_layer_);
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommitAndDrawFrame() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // The layer type used does not need to push properties every frame.
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_layer_.get()));

        // Change the bounds of the child layer, but make it skipped
        // by CalculateDrawProperties.
        parent_layer_->SetOpacity(0.f);
        child_layer_->SetBounds(gfx::Size(5, 5));
        break;
      case 2:
        // The bounds of the child layer were pushed to the impl side.
        EXPECT_FALSE(layer_tree_host()->LayerNeedsPushPropertiesForTesting(
            child_layer_.get()));

        EndTest();
        break;
    }
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    LayerImpl* child = impl->active_tree()->LayerById(child_layer_->id());

    switch (impl->active_tree()->source_frame_number()) {
      case 1:
        EXPECT_EQ(gfx::Size(5, 5).ToString(), child->bounds().ToString());
        break;
    }
  }

  void AfterTest() override {}

  scoped_refptr<Layer> root_layer_;
  scoped_refptr<SolidColorLayer> parent_layer_;
  scoped_refptr<SolidColorLayer> child_layer_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestPushHiddenLayer);

class LayerTreeHostTestUpdateLayerInEmptyViewport : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root_layer_ = FakePictureLayer::Create(&client_);
    root_layer_->SetBounds(gfx::Size(10, 10));

    layer_tree_host()->SetRootLayer(root_layer_);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer_->bounds());
  }

  void BeginTest() override {
    // The viewport is empty, but we still need to update layers on the main
    // thread.
    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(0, 0), 1.f,
                                               viz::LocalSurfaceId());
    PostSetNeedsCommitToMainThread();
  }

  void DidCommit() override {
    // The layer should be updated even though the viewport is empty, so we
    // are capable of drawing it on the impl tree.
    EXPECT_GT(root_layer_->update_count(), 0);
    EndTest();
  }

  void AfterTest() override {}

  FakeContentLayerClient client_;
  scoped_refptr<FakePictureLayer> root_layer_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestUpdateLayerInEmptyViewport);

class LayerTreeHostTestElasticOverscroll : public LayerTreeHostTest {
 public:
  LayerTreeHostTestElasticOverscroll()
      : scroll_elasticity_helper_(nullptr), num_draws_(0) {}

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_elastic_overscroll = true;
  }

  void SetupTree() override {
    root_layer_ = Layer::Create();
    root_layer_->SetBounds(gfx::Size(10, 10));

    scoped_refptr<Layer> inner_viewport_container_layer = Layer::Create();
    inner_viewport_container_layer->SetBounds(gfx::Size(10, 10));
    scoped_refptr<Layer> overscroll_elasticity_layer = Layer::Create();
    scoped_refptr<Layer> page_scale_layer = Layer::Create();
    scoped_refptr<Layer> inner_viewport_scroll_layer = Layer::Create();
    inner_viewport_scroll_layer->SetScrollable(
        inner_viewport_container_layer->bounds());
    inner_viewport_scroll_layer->SetIsContainerForFixedPositionLayers(true);

    root_layer_->AddChild(inner_viewport_container_layer);
    inner_viewport_container_layer->AddChild(overscroll_elasticity_layer);
    overscroll_elasticity_layer->AddChild(page_scale_layer);
    page_scale_layer->AddChild(inner_viewport_scroll_layer);

    scoped_refptr<Layer> content_layer = FakePictureLayer::Create(&client_);
    content_layer_id_ = content_layer->id();
    content_layer->SetBounds(gfx::Size(10, 10));
    inner_viewport_scroll_layer->AddChild(content_layer);

    layer_tree_host()->SetRootLayer(root_layer_);
    LayerTreeHost::ViewportLayers viewport_layers;
    viewport_layers.overscroll_elasticity = overscroll_elasticity_layer;
    viewport_layers.page_scale = page_scale_layer;
    viewport_layers.inner_viewport_container = inner_viewport_container_layer;
    viewport_layers.inner_viewport_scroll = inner_viewport_scroll_layer;
    layer_tree_host()->RegisterViewportLayers(viewport_layers);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(content_layer->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->sync_tree()->source_frame_number() == 0) {
      scroll_elasticity_helper_ = host_impl->CreateScrollElasticityHelper();
    }
  }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    num_draws_++;
    LayerImpl* content_layer_impl =
        host_impl->active_tree()->LayerById(content_layer_id_);
    gfx::Transform expected_draw_transform;
    switch (num_draws_) {
      case 1:
        // Initially, there's no overscroll.
        EXPECT_EQ(expected_draw_transform, content_layer_impl->DrawTransform());

        // Begin overscrolling. This should be reflected in the draw transform
        // the next time we draw.
        scroll_elasticity_helper_->SetStretchAmount(gfx::Vector2dF(5.f, 6.f));
        break;
      case 2:
        expected_draw_transform.Translate(-5.0, -6.0);
        EXPECT_EQ(expected_draw_transform, content_layer_impl->DrawTransform());

        scroll_elasticity_helper_->SetStretchAmount(gfx::Vector2dF(3.f, 2.f));
        break;
      case 3:
        expected_draw_transform.Translate(-3.0, -2.0);
        EXPECT_EQ(expected_draw_transform, content_layer_impl->DrawTransform());

        scroll_elasticity_helper_->SetStretchAmount(gfx::Vector2dF());
        break;
      case 4:
        EXPECT_EQ(expected_draw_transform, content_layer_impl->DrawTransform());
        EndTest();
        break;
      default:
        NOTREACHED();
    }
  }

  void AfterTest() override {}

 private:
  FakeContentLayerClient client_;
  scoped_refptr<Layer> root_layer_;
  ScrollElasticityHelper* scroll_elasticity_helper_;
  int content_layer_id_;
  int num_draws_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestElasticOverscroll);

struct TestSwapPromiseResult {
  TestSwapPromiseResult()
      : did_activate_called(false),
        did_swap_called(false),
        did_not_swap_called(false),
        dtor_called(false),
        reason(SwapPromise::COMMIT_FAILS) {}

  bool did_activate_called;
  bool did_swap_called;
  bool did_not_swap_called;
  bool dtor_called;
  SwapPromise::DidNotSwapReason reason;
  base::Lock lock;
};

class TestSwapPromise : public SwapPromise {
 public:
  explicit TestSwapPromise(TestSwapPromiseResult* result) : result_(result) {}

  ~TestSwapPromise() override {
    base::AutoLock lock(result_->lock);
    result_->dtor_called = true;
  }

  void DidActivate() override {
    base::AutoLock lock(result_->lock);
    EXPECT_FALSE(result_->did_activate_called);
    EXPECT_FALSE(result_->did_swap_called);
    EXPECT_FALSE(result_->did_not_swap_called);
    result_->did_activate_called = true;
  }

  void WillSwap(viz::CompositorFrameMetadata* metadata,
                FrameTokenAllocator* frame_token_allocator) override {
    base::AutoLock lock(result_->lock);
    EXPECT_FALSE(result_->did_swap_called);
    EXPECT_FALSE(result_->did_not_swap_called);
    result_->did_swap_called = true;
  }

  void DidSwap() override {}

  DidNotSwapAction DidNotSwap(DidNotSwapReason reason) override {
    base::AutoLock lock(result_->lock);
    EXPECT_FALSE(result_->did_swap_called);
    EXPECT_FALSE(result_->did_not_swap_called);
    EXPECT_FALSE(result_->did_activate_called &&
                 reason != DidNotSwapReason::SWAP_FAILS);
    result_->did_not_swap_called = true;
    result_->reason = reason;
    return DidNotSwapAction::BREAK_PROMISE;
  }

  int64_t TraceId() const override { return 0; }

 private:
  // Not owned.
  TestSwapPromiseResult* result_;
};

class PinnedLayerTreeSwapPromise : public LayerTreeHostTest {
 protected:
  void BeginTest() override {
    layer_tree_host()->SetNeedsCommitWithForcedRedraw();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    int frame = host_impl->active_tree()->source_frame_number();
    if (frame == -1) {
      host_impl->active_tree()->QueuePinnedSwapPromise(
          std::make_unique<TestSwapPromise>(
              &pinned_active_swap_promise_result_));
      host_impl->pending_tree()->QueueSwapPromise(
          std::make_unique<TestSwapPromise>(&pending_swap_promise_result_));
      host_impl->active_tree()->QueueSwapPromise(
          std::make_unique<TestSwapPromise>(&active_swap_promise_result_));
    }
  }

  void DisplayDidDrawAndSwapOnThread() override { EndTest(); }

  void AfterTest() override {
    // The pending swap promise should activate and swap.
    EXPECT_TRUE(pending_swap_promise_result_.did_activate_called);
    EXPECT_TRUE(pending_swap_promise_result_.did_swap_called);

    // The active swap promise should fail to swap (it is cancelled by
    // the activation of a new frame).
    EXPECT_FALSE(active_swap_promise_result_.did_activate_called);
    EXPECT_FALSE(active_swap_promise_result_.did_swap_called);
    EXPECT_TRUE(active_swap_promise_result_.did_not_swap_called);
    EXPECT_EQ(active_swap_promise_result_.reason, SwapPromise::SWAP_FAILS);

    // The pinned active swap promise should not activate, but should swap.
    EXPECT_FALSE(pinned_active_swap_promise_result_.did_activate_called);
    EXPECT_TRUE(pinned_active_swap_promise_result_.did_swap_called);
  }

  TestSwapPromiseResult pending_swap_promise_result_;
  TestSwapPromiseResult active_swap_promise_result_;
  TestSwapPromiseResult pinned_active_swap_promise_result_;
};

MULTI_THREAD_TEST_F(PinnedLayerTreeSwapPromise);

class LayerTreeHostTestBreakSwapPromise : public LayerTreeHostTest {
 protected:
  LayerTreeHostTestBreakSwapPromise()
      : commit_count_(0), commit_complete_count_(0) {}

  void WillBeginMainFrame() override {
    ASSERT_LE(commit_count_, 2);
    std::unique_ptr<SwapPromise> swap_promise(
        new TestSwapPromise(&swap_promise_result_[commit_count_]));
    layer_tree_host()->GetSwapPromiseManager()->QueueSwapPromise(
        std::move(swap_promise));
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    commit_count_++;
    if (commit_count_ == 2) {
      // This commit will finish.
      layer_tree_host()->SetNeedsCommit();
    }
  }

  void WillActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->pending_tree()) {
      int frame = host_impl->pending_tree()->source_frame_number();
      base::AutoLock lock(swap_promise_result_[frame].lock);
      EXPECT_FALSE(swap_promise_result_[frame].did_activate_called);
      EXPECT_FALSE(swap_promise_result_[frame].did_swap_called);
    }
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    int frame = host_impl->active_tree()->source_frame_number();
    base::AutoLock lock(swap_promise_result_[frame].lock);
    EXPECT_TRUE(swap_promise_result_[frame].did_activate_called);
    EXPECT_FALSE(swap_promise_result_[frame].did_swap_called);
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    commit_complete_count_++;
    if (commit_complete_count_ == 1) {
      // This commit will be aborted because no actual update.
      PostSetNeedsUpdateLayersToMainThread();
    }
  }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    int frame = host_impl->active_tree()->source_frame_number();
    if (frame == 2) {
      EndTest();
    }
  }

  void AfterTest() override {
    // 3 commits are scheduled. 2 completes. 1 is aborted.
    EXPECT_EQ(commit_count_, 3);
    EXPECT_EQ(commit_complete_count_, 2);

    {
      // The first commit completes and causes swap buffer which finishes
      // the promise.
      base::AutoLock lock(swap_promise_result_[0].lock);
      EXPECT_TRUE(swap_promise_result_[0].did_swap_called);
      EXPECT_FALSE(swap_promise_result_[0].did_not_swap_called);
      EXPECT_TRUE(swap_promise_result_[0].dtor_called);
    }

    {
      // The second commit is aborted since it contains no updates.
      base::AutoLock lock(swap_promise_result_[1].lock);
      EXPECT_FALSE(swap_promise_result_[1].did_activate_called);
      EXPECT_FALSE(swap_promise_result_[1].did_swap_called);
      EXPECT_TRUE(swap_promise_result_[1].did_not_swap_called);
      EXPECT_EQ(SwapPromise::COMMIT_NO_UPDATE, swap_promise_result_[1].reason);
      EXPECT_TRUE(swap_promise_result_[1].dtor_called);
    }

    {
      // The last commit completes but it does not cause swap buffer because
      // there is no damage in the frame data.
      base::AutoLock lock(swap_promise_result_[2].lock);
      EXPECT_TRUE(swap_promise_result_[2].did_activate_called);
      EXPECT_FALSE(swap_promise_result_[2].did_swap_called);
      EXPECT_TRUE(swap_promise_result_[2].did_not_swap_called);
      EXPECT_EQ(SwapPromise::SWAP_FAILS, swap_promise_result_[2].reason);
      EXPECT_TRUE(swap_promise_result_[2].dtor_called);
    }
  }

  int commit_count_;
  int commit_complete_count_;
  TestSwapPromiseResult swap_promise_result_[3];
};

MULTI_THREAD_TEST_F(LayerTreeHostTestBreakSwapPromise);

class LayerTreeHostTestKeepSwapPromise : public LayerTreeHostTest {
 public:
  LayerTreeHostTestKeepSwapPromise() = default;

  void BeginTest() override {
    layer_ = SolidColorLayer::Create();
    layer_->SetIsDrawable(true);
    layer_->SetBounds(gfx::Size(10, 10));
    layer_tree_host()->SetRootLayer(layer_);
    gfx::Size bounds(100, 100);
    layer_tree_host()->SetViewportSizeAndScale(bounds, 1.f,
                                               viz::LocalSurfaceId());
    PostSetNeedsCommitToMainThread();
  }

  void DidCommit() override {
    MainThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(&LayerTreeHostTestKeepSwapPromise::ChangeFrame,
                       base::Unretained(this)));
  }

  void ChangeFrame() {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        layer_->SetBounds(gfx::Size(10, 11));
        layer_tree_host()->GetSwapPromiseManager()->QueueSwapPromise(
            std::make_unique<TestSwapPromise>(&swap_promise_result_));
        break;
      case 2:
        break;
      default:
        NOTREACHED();
        break;
    }
  }

  void WillActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->pending_tree()) {
      if (host_impl->pending_tree()->source_frame_number() == 1) {
        base::AutoLock lock(swap_promise_result_.lock);
        EXPECT_FALSE(swap_promise_result_.did_activate_called);
        EXPECT_FALSE(swap_promise_result_.did_swap_called);
        SetCallback(host_impl, true);
      } else {
        SetCallback(host_impl, false);
      }
    }
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->active_tree()->source_frame_number() == 1) {
      base::AutoLock lock(swap_promise_result_.lock);
      EXPECT_TRUE(swap_promise_result_.did_activate_called);
      EXPECT_FALSE(swap_promise_result_.did_swap_called);
    }
  }

  void ActivationCallback() {
    // DidActivate needs to happen before the tree activation callback.
    base::AutoLock lock(swap_promise_result_.lock);
    EXPECT_TRUE(swap_promise_result_.did_activate_called);
  }

  void SetCallback(LayerTreeHostImpl* host_impl, bool enable) {
    host_impl->SetTreeActivationCallback(
        enable
            ? base::Bind(&LayerTreeHostTestKeepSwapPromise::ActivationCallback,
                         base::Unretained(this))
            : base::Closure());
  }

  void DisplayDidDrawAndSwapOnThread() override {
    if (num_swaps_++ >= 1) {
      // The commit changes layers so it should cause a swap.
      base::AutoLock lock(swap_promise_result_.lock);
      EXPECT_TRUE(swap_promise_result_.did_swap_called);
      EXPECT_FALSE(swap_promise_result_.did_not_swap_called);
      EXPECT_TRUE(swap_promise_result_.dtor_called);
      EndTest();
    }
  }

  void AfterTest() override {}

 private:
  int num_swaps_ = 0;
  scoped_refptr<Layer> layer_;
  TestSwapPromiseResult swap_promise_result_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestKeepSwapPromise);

class LayerTreeHostTestKeepSwapPromiseMFBA : public LayerTreeHostTest {
 public:
  LayerTreeHostTestKeepSwapPromiseMFBA() = default;

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->main_frame_before_activation_enabled = true;
  }

  void BeginTest() override {
    layer_ = SolidColorLayer::Create();
    layer_->SetIsDrawable(true);
    layer_->SetBounds(gfx::Size(10, 10));
    layer_tree_host()->SetRootLayer(layer_);
    gfx::Size bounds(100, 100);
    layer_tree_host()->SetViewportSizeAndScale(bounds, 1.f,
                                               viz::LocalSurfaceId());
    PostSetNeedsCommitToMainThread();
  }

  void BeginCommitOnThread(LayerTreeHostImpl* host_impl) override {
    // Safe to check frame number here because main thread is blocked.
    if (layer_tree_host()->SourceFrameNumber() == 0) {
      host_impl->BlockNotifyReadyToActivateForTesting(true);
    } else {
      NOTREACHED();
    }
  }

  void DidCommit() override {
    MainThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(&LayerTreeHostTestKeepSwapPromiseMFBA::ChangeFrame,
                       base::Unretained(this)));
  }

  void BeginMainFrameAbortedOnThread(LayerTreeHostImpl* host_impl,
                                     CommitEarlyOutReason reason) override {
    base::AutoLock lock(swap_promise_result_.lock);
    EXPECT_FALSE(swap_promise_result_.did_not_swap_called);
    EXPECT_FALSE(swap_promise_result_.did_activate_called);
    EXPECT_FALSE(swap_promise_result_.did_swap_called);
    host_impl->BlockNotifyReadyToActivateForTesting(false);
  }

  void ChangeFrame() {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // Make no changes so that we abort the next commit caused by queuing
        // the swap promise.
        layer_tree_host()->GetSwapPromiseManager()->QueueSwapPromise(
            std::make_unique<TestSwapPromise>(&swap_promise_result_));
        layer_tree_host()->SetNeedsUpdateLayers();
        break;
      case 2:
        break;
      default:
        NOTREACHED();
        break;
    }
  }

  void WillActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->pending_tree()) {
      if (host_impl->pending_tree()->source_frame_number() == 1) {
        base::AutoLock lock(swap_promise_result_.lock);
        EXPECT_FALSE(swap_promise_result_.did_activate_called);
        EXPECT_FALSE(swap_promise_result_.did_swap_called);
        SetCallback(host_impl, true);
      } else {
        SetCallback(host_impl, false);
      }
    }
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->active_tree()->source_frame_number() == 1) {
      base::AutoLock lock(swap_promise_result_.lock);
      EXPECT_TRUE(swap_promise_result_.did_activate_called);
      EXPECT_FALSE(swap_promise_result_.did_swap_called);
    }
  }

  void ActivationCallback() {
    // DidActivate needs to happen before the tree activation callback.
    base::AutoLock lock(swap_promise_result_.lock);
    EXPECT_TRUE(swap_promise_result_.did_activate_called);
  }

  void SetCallback(LayerTreeHostImpl* host_impl, bool enable) {
    host_impl->SetTreeActivationCallback(
        enable ? base::Bind(
                     &LayerTreeHostTestKeepSwapPromiseMFBA::ActivationCallback,
                     base::Unretained(this))
               : base::Closure());
  }

  void DisplayDidDrawAndSwapOnThread() override {
    num_swaps_++;
    base::AutoLock lock(swap_promise_result_.lock);
    EXPECT_TRUE(swap_promise_result_.did_swap_called);
    EXPECT_FALSE(swap_promise_result_.did_not_swap_called);
    EXPECT_TRUE(swap_promise_result_.dtor_called);
    EndTest();
  }

  void AfterTest() override { EXPECT_EQ(1, num_swaps_); }

 private:
  int num_swaps_ = 0;
  scoped_refptr<Layer> layer_;
  TestSwapPromiseResult swap_promise_result_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestKeepSwapPromiseMFBA);

class LayerTreeHostTestBreakSwapPromiseForVisibility
    : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void SetVisibleFalseAndQueueSwapPromise() {
    layer_tree_host()->SetVisible(false);
    std::unique_ptr<SwapPromise> swap_promise(
        new TestSwapPromise(&swap_promise_result_));
    layer_tree_host()->GetSwapPromiseManager()->QueueSwapPromise(
        std::move(swap_promise));
  }

  void WillBeginImplFrameOnThread(LayerTreeHostImpl* impl,
                                  const viz::BeginFrameArgs& args) override {
    MainThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(&LayerTreeHostTestBreakSwapPromiseForVisibility::
                           SetVisibleFalseAndQueueSwapPromise,
                       base::Unretained(this)));
  }

  void BeginMainFrameAbortedOnThread(LayerTreeHostImpl* host_impl,
                                     CommitEarlyOutReason reason) override {
    EndTest();
  }

  void AfterTest() override {
    {
      base::AutoLock lock(swap_promise_result_.lock);
      EXPECT_FALSE(swap_promise_result_.did_activate_called);
      EXPECT_FALSE(swap_promise_result_.did_swap_called);
      EXPECT_TRUE(swap_promise_result_.did_not_swap_called);
      EXPECT_EQ(SwapPromise::COMMIT_FAILS, swap_promise_result_.reason);
      EXPECT_TRUE(swap_promise_result_.dtor_called);
    }
  }

  TestSwapPromiseResult swap_promise_result_;
};

// Flaky: https://crbug.com/657910
// SINGLE_AND_MULTI_THREAD_TEST_F(
//     LayerTreeHostTestBreakSwapPromiseForVisibility);

class SimpleSwapPromiseMonitor : public SwapPromiseMonitor {
 public:
  SimpleSwapPromiseMonitor(LayerTreeHost* layer_tree_host,
                           LayerTreeHostImpl* layer_tree_host_impl,
                           int* set_needs_commit_count,
                           int* set_needs_redraw_count)
      : SwapPromiseMonitor(
            (layer_tree_host ? layer_tree_host->GetSwapPromiseManager()
                             : nullptr),
            layer_tree_host_impl),
        set_needs_commit_count_(set_needs_commit_count) {}

  ~SimpleSwapPromiseMonitor() override = default;

  void OnSetNeedsCommitOnMain() override { (*set_needs_commit_count_)++; }

  void OnSetNeedsRedrawOnImpl() override {
    ADD_FAILURE() << "Should not get called on main thread.";
  }

  void OnForwardScrollUpdateToMainThreadOnImpl() override {
    ADD_FAILURE() << "Should not get called on main thread.";
  }

 private:
  int* set_needs_commit_count_;
};

class LayerTreeHostTestSwapPromiseDuringCommit : public LayerTreeHostTest {
 protected:
  LayerTreeHostTestSwapPromiseDuringCommit() = default;

  void WillBeginMainFrame() override {
    if (TestEnded())
      return;

    std::unique_ptr<SwapPromise> swap_promise(
        new TestSwapPromise(&swap_promise_result_[0]));
    int set_needs_commit_count = 0;
    int set_needs_redraw_count = 0;

    {
      std::unique_ptr<SimpleSwapPromiseMonitor> swap_promise_monitor(
          new SimpleSwapPromiseMonitor(layer_tree_host(), nullptr,
                                       &set_needs_commit_count,
                                       &set_needs_redraw_count));
      layer_tree_host()->QueueSwapPromise(std::move(swap_promise));
      // Queueing a swap promise from WillBeginMainFrame should not cause
      // another commit to be scheduled.
      EXPECT_EQ(0, set_needs_commit_count);
    }
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidBeginMainFrame() override {
    if (TestEnded())
      return;

    std::unique_ptr<SwapPromise> swap_promise(
        new TestSwapPromise(&swap_promise_result_[1]));
    int set_needs_commit_count = 0;
    int set_needs_redraw_count = 0;

    {
      std::unique_ptr<SimpleSwapPromiseMonitor> swap_promise_monitor(
          new SimpleSwapPromiseMonitor(layer_tree_host(), nullptr,
                                       &set_needs_commit_count,
                                       &set_needs_redraw_count));
      layer_tree_host()->QueueSwapPromise(std::move(swap_promise));
      // Queueing a swap promise from DidBeginMainFrame should cause a
      // subsequent main frame to be scheduled.
      EXPECT_EQ(1, set_needs_commit_count);
    }

    EndTest();
  }

  void AfterTest() override {}

  TestSwapPromiseResult swap_promise_result_[2];
};

MULTI_THREAD_TEST_F(LayerTreeHostTestSwapPromiseDuringCommit);

class LayerTreeHostTestSimpleSwapPromiseMonitor : public LayerTreeHostTest {
 public:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillBeginMainFrame() override {
    if (TestEnded())
      return;

    int set_needs_commit_count = 0;
    int set_needs_redraw_count = 0;

    {
      std::unique_ptr<SimpleSwapPromiseMonitor> swap_promise_monitor(
          new SimpleSwapPromiseMonitor(layer_tree_host(), nullptr,
                                       &set_needs_commit_count,
                                       &set_needs_redraw_count));
      layer_tree_host()->SetNeedsCommit();
      EXPECT_EQ(1, set_needs_commit_count);
      EXPECT_EQ(0, set_needs_redraw_count);
    }

    // Now the monitor is destroyed, SetNeedsCommit() is no longer being
    // monitored.
    layer_tree_host()->SetNeedsCommit();
    EXPECT_EQ(1, set_needs_commit_count);
    EXPECT_EQ(0, set_needs_redraw_count);

    {
      std::unique_ptr<SimpleSwapPromiseMonitor> swap_promise_monitor(
          new SimpleSwapPromiseMonitor(layer_tree_host(), nullptr,
                                       &set_needs_commit_count,
                                       &set_needs_redraw_count));
      layer_tree_host()->SetNeedsUpdateLayers();
      EXPECT_EQ(2, set_needs_commit_count);
      EXPECT_EQ(0, set_needs_redraw_count);
    }

    {
      std::unique_ptr<SimpleSwapPromiseMonitor> swap_promise_monitor(
          new SimpleSwapPromiseMonitor(layer_tree_host(), nullptr,
                                       &set_needs_commit_count,
                                       &set_needs_redraw_count));
      layer_tree_host()->SetNeedsAnimate();
      EXPECT_EQ(3, set_needs_commit_count);
      EXPECT_EQ(0, set_needs_redraw_count);
    }

    EndTest();
  }

  void AfterTest() override {}
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestSimpleSwapPromiseMonitor);

class LayerTreeHostTestHighResRequiredAfterEvictingUIResources
    : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    LayerTreeHostTest::SetupTree();
    ui_resource_ =
        FakeScopedUIResource::Create(layer_tree_host()->GetUIResourceManager());
    client_.set_bounds(layer_tree_host()->root_layer()->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    host_impl->EvictAllUIResources();
    // Existence of evicted UI resources will trigger NEW_CONTENT_TAKES_PRIORITY
    // mode. Active tree should require high-res to draw after entering this
    // mode to ensure that high-res tiles are also required for a pending tree
    // to be activated.
    EXPECT_TRUE(host_impl->RequiresHighResToDraw());
  }

  void DidCommit() override {
    int frame = layer_tree_host()->SourceFrameNumber();
    switch (frame) {
      case 1:
        PostSetNeedsCommitToMainThread();
        break;
      case 2:
        ui_resource_ = nullptr;
        EndTest();
        break;
    }
  }

  void AfterTest() override {}

  FakeContentLayerClient client_;
  std::unique_ptr<FakeScopedUIResource> ui_resource_;
};

// This test is flaky, see http://crbug.com/386199
// MULTI_THREAD_TEST_F(LayerTreeHostTestHighResRequiredAfterEvictingUIResources)

class LayerTreeHostTestGpuRasterizationDefault : public LayerTreeHostTest {
 protected:
  void InitializeSettings(LayerTreeSettings* settings) override {
    EXPECT_FALSE(settings->gpu_rasterization_forced);
  }

  void SetupTree() override {
    LayerTreeHostTest::SetupTree();

    std::unique_ptr<FakeRecordingSource> recording_source(
        new FakeRecordingSource);
    recording_source_ = recording_source.get();

    scoped_refptr<FakePictureLayer> layer =
        FakePictureLayer::CreateWithRecordingSource(
            &layer_client_, std::move(recording_source));
    layer_ = layer.get();
    layer->SetBounds(gfx::Size(10, 10));
    layer->SetIsDrawable(true);
    layer_tree_host()->root_layer()->AddChild(layer);
    layer_client_.set_bounds(layer_->bounds());
  }

  void BeginTest() override {
    // Verify default value.
    EXPECT_FALSE(layer_tree_host()->has_gpu_rasterization_trigger());

    // Setting gpu rasterization trigger does not enable gpu rasterization.
    layer_tree_host()->SetHasGpuRasterizationTrigger(true);
    EXPECT_TRUE(layer_tree_host()->has_gpu_rasterization_trigger());

    PostSetNeedsCommitToMainThread();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_FALSE(layer_->HasSlowPaths());

    EXPECT_FALSE(host_impl->pending_tree()->use_gpu_rasterization());
    EXPECT_FALSE(host_impl->use_gpu_rasterization());
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_FALSE(layer_->HasSlowPaths());

    EXPECT_FALSE(host_impl->active_tree()->use_gpu_rasterization());
    EXPECT_FALSE(host_impl->use_gpu_rasterization());
    EndTest();
  }

  void AfterTest() override {}

  FakeContentLayerClient layer_client_;
  FakePictureLayer* layer_;
  FakeRecordingSource* recording_source_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestGpuRasterizationDefault);

class LayerTreeHostTestEmptyLayerGpuRasterization : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    LayerTreeHostTest::SetupTree();

    std::unique_ptr<FakeRecordingSource> recording_source(
        new FakeRecordingSource);
    recording_source_ = recording_source.get();

    scoped_refptr<FakePictureLayer> layer =
        FakePictureLayer::CreateWithRecordingSource(
            &layer_client_, std::move(recording_source));
    layer_ = layer.get();
    layer->SetBounds(gfx::Size());
    layer->SetIsDrawable(true);
    layer_tree_host()->root_layer()->AddChild(layer);
    layer_client_.set_bounds(layer->bounds());
  }

  void BeginTest() override {
    // Setting gpu rasterization trigger does not enable gpu rasterization.
    layer_tree_host()->SetHasGpuRasterizationTrigger(true);
    EXPECT_TRUE(layer_tree_host()->has_gpu_rasterization_trigger());

    PostSetNeedsCommitToMainThread();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_FALSE(layer_->HasSlowPaths());

    EXPECT_FALSE(host_impl->pending_tree()->use_gpu_rasterization());
    EXPECT_FALSE(host_impl->use_gpu_rasterization());
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_FALSE(layer_->HasSlowPaths());

    EXPECT_FALSE(host_impl->active_tree()->use_gpu_rasterization());
    EXPECT_FALSE(host_impl->use_gpu_rasterization());
    EndTest();
  }

  void AfterTest() override {}

  FakeContentLayerClient layer_client_;
  FakePictureLayer* layer_;
  FakeRecordingSource* recording_source_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestEmptyLayerGpuRasterization);

class LayerTreeHostWithGpuRasterizationTest : public LayerTreeHostTest {
 protected:
  std::unique_ptr<viz::TestLayerTreeFrameSink> CreateLayerTreeFrameSink(
      const viz::RendererSettings& renderer_settings,
      double refresh_rate,
      scoped_refptr<viz::ContextProvider> ignored_compositor_context_provider,
      scoped_refptr<viz::RasterContextProvider> ignored_worker_context_provider)
      override {
    auto context_provider = viz::TestContextProvider::Create();
    context_provider->UnboundTestContext3d()->SetMaxSamples(4);
    context_provider->UnboundTestContext3d()
        ->set_support_multisample_compatibility(false);
    context_provider->UnboundTestContext3d()->set_gpu_rasterization(true);
    auto worker_context_provider = viz::TestContextProvider::CreateWorker();
    worker_context_provider->UnboundTestContext3d()->SetMaxSamples(4);
    worker_context_provider->UnboundTestContext3d()
        ->set_support_multisample_compatibility(false);
    worker_context_provider->UnboundTestContext3d()->set_gpu_rasterization(
        true);
    return LayerTreeHostTest::CreateLayerTreeFrameSink(
        renderer_settings, refresh_rate, std::move(context_provider),
        std::move(worker_context_provider));
  }
  void SetupTree() override {
    LayerTreeHostTest::SetupTree();

    std::unique_ptr<FakeRecordingSource> recording_source(
        new FakeRecordingSource);
    recording_source_ = recording_source.get();

    scoped_refptr<FakePictureLayer> layer =
        FakePictureLayer::CreateWithRecordingSource(
            &layer_client_, std::move(recording_source));
    layer_ = layer.get();
    layer->SetBounds(gfx::Size(10, 10));
    layer->SetIsDrawable(true);
    layer_tree_host()->root_layer()->AddChild(layer);
    layer_client_.set_bounds(layer_->bounds());
  }

  FakeContentLayerClient layer_client_;
  FakePictureLayer* layer_;
  FakeRecordingSource* recording_source_;
};

class LayerTreeHostTestGpuRasterizationEnabled
    : public LayerTreeHostWithGpuRasterizationTest {
 protected:
  void BeginTest() override {
    // Verify default value.
    EXPECT_FALSE(layer_tree_host()->has_gpu_rasterization_trigger());

    // Gpu rasterization trigger is relevant.
    layer_tree_host()->SetHasGpuRasterizationTrigger(true);
    EXPECT_TRUE(layer_tree_host()->has_gpu_rasterization_trigger());

    // Content-based veto is relevant as well.
    layer_->set_force_content_has_slow_paths(true);

    // Veto will take effect when layers are updated.
    // The results will be verified after commit is completed below.
    // Since we are manually marking the source as containing slow paths,
    // make sure that the layer gets a chance to update.
    layer_->SetNeedsDisplay();
    PostSetNeedsCommitToMainThread();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    // Ensure the slow path bit sticks.
    EXPECT_TRUE(layer_->HasSlowPaths());

    EXPECT_TRUE(host_impl->pending_tree()->use_gpu_rasterization());
    EXPECT_TRUE(host_impl->use_gpu_rasterization());
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_TRUE(layer_->HasSlowPaths());

    EXPECT_TRUE(host_impl->active_tree()->use_gpu_rasterization());
    EXPECT_TRUE(host_impl->use_gpu_rasterization());
    EndTest();
  }

  void AfterTest() override {}
};

MULTI_THREAD_TEST_F(LayerTreeHostTestGpuRasterizationEnabled);

class LayerTreeHostTestGpuRasterizationReenabled
    : public LayerTreeHostWithGpuRasterizationTest {
 protected:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->gpu_rasterization_msaa_sample_count = 4;
  }

  void BeginTest() override {
    // Verify default value.
    EXPECT_FALSE(layer_tree_host()->has_gpu_rasterization_trigger());

    // Gpu rasterization trigger is relevant.
    layer_tree_host()->SetHasGpuRasterizationTrigger(true);
    EXPECT_TRUE(layer_tree_host()->has_gpu_rasterization_trigger());

    // Content-based veto is relevant as well.
    layer_->set_force_content_has_slow_paths(true);

    // Veto will take effect when layers are updated.
    // The results will be verified after commit is completed below.
    // Since we are manually marking the source as containing slow paths,
    // make sure that the layer gets a chance to update.
    layer_->SetNeedsDisplay();
    PostSetNeedsCommitToMainThread();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    SCOPED_TRACE(base::StringPrintf("commit %d", num_commits_));
    if (expected_use_msaa_) {
      EXPECT_TRUE(host_impl->use_msaa());
    } else {
      EXPECT_FALSE(host_impl->use_msaa());
    }

    ++num_commits_;
    switch (num_commits_) {
      case 1:
        layer_->set_force_content_has_slow_paths(false);
        break;
      case 30:
        layer_->set_force_content_has_slow_paths(true);
        break;
      case 31:
        layer_->set_force_content_has_slow_paths(false);
        break;
      case 90:
        expected_use_msaa_ = false;
        break;
    }
    PostSetNeedsCommitToMainThread();
    if (num_commits_ > 100)
      EndTest();
  }

  void AfterTest() override {}

  int num_commits_ = 0;
  bool expected_use_msaa_ = true;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestGpuRasterizationReenabled);

class LayerTreeHostTestGpuRasterizationNonAASticky
    : public LayerTreeHostWithGpuRasterizationTest {
 protected:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->gpu_rasterization_msaa_sample_count = 4;
  }

  void BeginTest() override {
    // Verify default value.
    EXPECT_FALSE(layer_tree_host()->has_gpu_rasterization_trigger());

    // Gpu rasterization trigger is relevant.
    layer_tree_host()->SetHasGpuRasterizationTrigger(true);
    EXPECT_TRUE(layer_tree_host()->has_gpu_rasterization_trigger());

    // Start without slow paths, but no non-aa paint.
    layer_->set_force_content_has_slow_paths(true);
    layer_->set_force_content_has_non_aa_paint(false);

    // The results will be verified after commit is completed below.
    layer_->SetNeedsDisplay();
    PostSetNeedsCommitToMainThread();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    SCOPED_TRACE(base::StringPrintf("commit %d", num_commits_));
    if (expected_use_msaa_) {
      EXPECT_TRUE(host_impl->use_msaa());
    } else {
      EXPECT_FALSE(host_impl->use_msaa());
    }

    ++num_commits_;
    switch (num_commits_) {
      case 30:
        layer_->set_force_content_has_non_aa_paint(true);
        expected_use_msaa_ = false;
        break;
      case 31:
        layer_->set_force_content_has_non_aa_paint(false);
        break;
    }
    PostSetNeedsCommitToMainThread();
    if (num_commits_ > 100)
      EndTest();
  }

  void AfterTest() override {}

  int num_commits_ = 0;
  bool expected_use_msaa_ = true;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestGpuRasterizationNonAASticky);

class LayerTreeHostTestGpuRasterizationForced : public LayerTreeHostTest {
 protected:
  void InitializeSettings(LayerTreeSettings* settings) override {
    EXPECT_FALSE(settings->gpu_rasterization_forced);
    settings->gpu_rasterization_forced = true;
  }

  void SetupTree() override {
    LayerTreeHostTest::SetupTree();

    std::unique_ptr<FakeRecordingSource> recording_source(
        new FakeRecordingSource);
    recording_source_ = recording_source.get();

    scoped_refptr<FakePictureLayer> layer =
        FakePictureLayer::CreateWithRecordingSource(
            &layer_client_, std::move(recording_source));
    layer_ = layer.get();

    layer->SetBounds(gfx::Size(10, 10));
    layer->SetIsDrawable(true);
    layer_tree_host()->root_layer()->AddChild(layer);
    layer_client_.set_bounds(layer_->bounds());
  }

  void BeginTest() override {
    // Verify default value.
    EXPECT_FALSE(layer_tree_host()->has_gpu_rasterization_trigger());

    // With gpu rasterization forced, gpu rasterization trigger is irrelevant.
    layer_tree_host()->SetHasGpuRasterizationTrigger(true);
    EXPECT_TRUE(layer_tree_host()->has_gpu_rasterization_trigger());

    // Content-based veto is irrelevant as well.
    layer_->set_force_content_has_slow_paths(true);

    // Veto will take effect when layers are updated.
    // The results will be verified after commit is completed below.
    // Since we are manually marking the source as containing slow paths,
    // make sure that the layer gets a chance to update.
    layer_->SetNeedsDisplay();
    PostSetNeedsCommitToMainThread();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    // Ensure the slow-paths bit sticks.
    EXPECT_TRUE(layer_->HasSlowPaths());

    EXPECT_TRUE(host_impl->sync_tree()->use_gpu_rasterization());
    EXPECT_TRUE(host_impl->use_gpu_rasterization());
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    EXPECT_TRUE(layer_->HasSlowPaths());

    EXPECT_TRUE(host_impl->active_tree()->use_gpu_rasterization());
    EXPECT_TRUE(host_impl->use_gpu_rasterization());
    EndTest();
  }

  void AfterTest() override {}

  FakeContentLayerClient layer_client_;
  FakePictureLayer* layer_;
  FakeRecordingSource* recording_source_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestGpuRasterizationForced);

class LayerTreeHostTestWillBeginImplFrameHasDidFinishImplFrame
    : public LayerTreeHostTest {
 public:
  enum { kExpectedNumImplFrames = 10 };

  LayerTreeHostTestWillBeginImplFrameHasDidFinishImplFrame()
      : will_begin_impl_frame_count_(0), did_finish_impl_frame_count_(0) {}

  void BeginTest() override {
    // Test terminates when a main frame is no longer expected so request that
    // this message is actually sent.
    layer_tree_host()->RequestBeginMainFrameNotExpected(true);

    PostSetNeedsCommitToMainThread();
  }

  void WillBeginImplFrameOnThread(LayerTreeHostImpl* host_impl,
                                  const viz::BeginFrameArgs& args) override {
    EXPECT_EQ(will_begin_impl_frame_count_, did_finish_impl_frame_count_);
    EXPECT_FALSE(TestEnded());
    will_begin_impl_frame_count_++;
  }

  void DidFinishImplFrameOnThread(LayerTreeHostImpl* host_impl) override {
    did_finish_impl_frame_count_++;
    EXPECT_EQ(will_begin_impl_frame_count_, did_finish_impl_frame_count_);

    // Request a number of commits to cause multiple impl frames. We expect to
    // get one more impl frames than the number of commits requested because
    // after a commit it takes one frame to become idle.
    if (did_finish_impl_frame_count_ < kExpectedNumImplFrames - 1)
      PostSetNeedsCommitToMainThread();
  }

  void BeginMainFrameNotExpectedSoon() override { EndTest(); }

  void AfterTest() override {
    EXPECT_GT(will_begin_impl_frame_count_, 0);
    EXPECT_GT(did_finish_impl_frame_count_, 0);
    EXPECT_EQ(will_begin_impl_frame_count_, did_finish_impl_frame_count_);

    // TODO(mithro): Figure out why the multithread version of this test
    // sometimes has one more frame then expected. Possibly related to
    // http://crbug.com/443185
    if (!HasImplThread()) {
      EXPECT_EQ(will_begin_impl_frame_count_, kExpectedNumImplFrames);
      EXPECT_EQ(did_finish_impl_frame_count_, kExpectedNumImplFrames);
    }
  }

 private:
  int will_begin_impl_frame_count_;
  int did_finish_impl_frame_count_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeHostTestWillBeginImplFrameHasDidFinishImplFrame);

::testing::AssertionResult AssertFrameTimeContained(
    const char* haystack_expr,
    const char* needle_expr,
    const std::vector<viz::BeginFrameArgs> haystack,
    const viz::BeginFrameArgs needle) {
  auto failure = ::testing::AssertionFailure()
                 << needle.frame_time << " (" << needle_expr
                 << ") not found in " << haystack_expr;

  if (haystack.size() == 0) {
    failure << " which is empty.";
  } else {
    failure << " which contains:\n";
    for (size_t i = 0; i < haystack.size(); i++) {
      if (haystack[i].frame_time == needle.frame_time)
        return ::testing::AssertionSuccess();
      failure << "  [" << i << "]: " << haystack[i].frame_time << "\n";
    }
  }

  return failure;
}

class LayerTreeHostTestBeginMainFrameTimeIsAlsoImplTime
    : public LayerTreeHostTest {
 public:
  LayerTreeHostTestBeginMainFrameTimeIsAlsoImplTime()
      : impl_frame_args_(), will_begin_impl_frame_count_(0) {}

  void BeginTest() override {
    // Test terminates when a main frame is no longer expected so request that
    // this message is actually sent.
    layer_tree_host()->RequestBeginMainFrameNotExpected(true);
    // Kick off the test with a commit.
    PostSetNeedsCommitToMainThread();
  }

  void WillBeginImplFrameOnThread(LayerTreeHostImpl* impl,
                                  const viz::BeginFrameArgs& args) override {
    impl_frame_args_.push_back(args);

    will_begin_impl_frame_count_++;
    if (will_begin_impl_frame_count_ < 10)
      PostSetNeedsCommitToMainThread();
  }

  void BeginMainFrame(const viz::BeginFrameArgs& args) override {
    ASSERT_GT(impl_frame_args_.size(), 0U)
        << "BeginMainFrame called before BeginImplFrame called!";
    EXPECT_PRED_FORMAT2(AssertFrameTimeContained, impl_frame_args_, args);
  }

  void BeginMainFrameNotExpectedSoon() override { EndTest(); }

  void AfterTest() override {
    EXPECT_GT(impl_frame_args_.size(), 0U);
    EXPECT_GE(will_begin_impl_frame_count_, 10);
  }

 private:
  std::vector<viz::BeginFrameArgs> impl_frame_args_;
  int will_begin_impl_frame_count_;
};

// TODO(mithro): Re-enable the multi-threaded version of this test
// http://crbug.com/537621
// SINGLE_AND_MULTI_THREAD_TEST_F(
//    LayerTreeHostTestBeginMainFrameTimeIsAlsoImplTime);
SINGLE_THREAD_TEST_F(LayerTreeHostTestBeginMainFrameTimeIsAlsoImplTime);

class LayerTreeHostTestActivateOnInvisible : public LayerTreeHostTest {
 public:
  LayerTreeHostTestActivateOnInvisible()
      : activation_count_(0), visible_(true) {}

  void BeginTest() override {
    // Kick off the test with a commit.
    PostSetNeedsCommitToMainThread();
  }

  void BeginCommitOnThread(LayerTreeHostImpl* host_impl) override {
    // Make sure we don't activate using the notify signal from tile manager.
    host_impl->BlockNotifyReadyToActivateForTesting(true);
  }

  void DidCommit() override { layer_tree_host()->SetVisible(false); }

  void DidSetVisibleOnImplTree(LayerTreeHostImpl* host_impl,
                               bool visible) override {
    visible_ = visible;

    // Once invisible, we can go visible again.
    if (!visible) {
      PostSetVisibleToMainThread(true);
    } else if (activation_count_) {
      EXPECT_TRUE(host_impl->RequiresHighResToDraw());
      EndTest();
    }
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    ++activation_count_;
    EXPECT_FALSE(visible_);
  }

  void AfterTest() override {
    // Ensure we activated even though the signal was blocked.
    EXPECT_EQ(1, activation_count_);
    EXPECT_TRUE(visible_);
  }

 private:
  int activation_count_;
  bool visible_;
};

// TODO(vmpstr): Enable with single thread impl-side painting.
// This test blocks activation which is not supported for single thread mode.
MULTI_THREAD_BLOCKNOTIFY_TEST_F(LayerTreeHostTestActivateOnInvisible);

class LayerTreeHostTestRenderSurfaceEffectTreeIndex : public LayerTreeHostTest {
 public:
  LayerTreeHostTestRenderSurfaceEffectTreeIndex() = default;

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void SetupTree() override {
    root_ = Layer::Create();
    child_ = Layer::Create();
    grand_child_ = Layer::Create();

    layer_tree_host()->SetRootLayer(root_);
    root_->AddChild(child_);
    child_->AddChild(grand_child_);

    root_->SetBounds(gfx::Size(50, 50));
    child_->SetBounds(gfx::Size(50, 50));
    grand_child_->SetBounds(gfx::Size(50, 50));
    child_->SetForceRenderSurfaceForTesting(true);
    grand_child_->SetForceRenderSurfaceForTesting(true);

    LayerTreeHostTest::SetupTree();
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    if (host_impl->sync_tree()->source_frame_number() >= 1) {
      LayerImpl* grand_child_impl =
          host_impl->sync_tree()->LayerById(grand_child_->id());
      EXPECT_EQ(grand_child_impl->effect_tree_index(),
                GetRenderSurface(grand_child_impl)->EffectTreeIndex());
    }
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* host_impl) override {
    LayerImpl* grand_child_impl =
        host_impl->active_tree()->LayerById(grand_child_->id());
    switch (host_impl->active_tree()->source_frame_number()) {
      case 0:
        PostSetNeedsCommitToMainThread();
        break;
      case 1:
      case 2:
        EXPECT_EQ(grand_child_impl->effect_tree_index(),
                  GetRenderSurface(grand_child_impl)->EffectTreeIndex());
        PostSetNeedsCommitToMainThread();
        break;
      case 3:
        EXPECT_EQ(grand_child_impl->effect_tree_index(),
                  GetRenderSurface(grand_child_impl)->EffectTreeIndex());
        EndTest();
    }
  }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 2:
        // Setting an empty viewport causes draws to get skipped, so the active
        // tree won't update draw properties.
        layer_tree_host()->SetViewportSizeAndScale(gfx::Size(), 1.f,
                                                   viz::LocalSurfaceId());
        child_->SetForceRenderSurfaceForTesting(false);
        break;
      case 3:
        layer_tree_host()->SetViewportSizeAndScale(root_->bounds(), 1.f,
                                                   viz::LocalSurfaceId());
    }
  }

  void AfterTest() override {}

 private:
  scoped_refptr<Layer> root_;
  scoped_refptr<Layer> child_;
  scoped_refptr<Layer> grand_child_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestRenderSurfaceEffectTreeIndex);

// Do a synchronous composite and assert that the swap promise succeeds.
class LayerTreeHostTestSynchronousCompositeSwapPromise
    : public LayerTreeHostTest {
 public:
  LayerTreeHostTestSynchronousCompositeSwapPromise() = default;

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->single_thread_proxy_scheduler = false;
    settings->use_zero_copy = true;
  }

  std::unique_ptr<viz::TestLayerTreeFrameSink> CreateLayerTreeFrameSink(
      const viz::RendererSettings& renderer_settings,
      double refresh_rate,
      scoped_refptr<viz::ContextProvider> compositor_context_provider,
      scoped_refptr<viz::RasterContextProvider> worker_context_provider)
      override {
    constexpr bool disable_display_vsync = false;
    bool synchronous_composite =
        !HasImplThread() &&
        !layer_tree_host()->GetSettings().single_thread_proxy_scheduler;
    return std::make_unique<viz::TestLayerTreeFrameSink>(
        compositor_context_provider, std::move(worker_context_provider),
        gpu_memory_buffer_manager(), renderer_settings, ImplThreadTaskRunner(),
        synchronous_composite, disable_display_vsync, refresh_rate);
  }

  void BeginTest() override {
    // Successful composite.
    const bool raster = true;
    std::unique_ptr<SwapPromise> swap_promise0(
        new TestSwapPromise(&swap_promise_result_[0]));
    layer_tree_host()->GetSwapPromiseManager()->QueueSwapPromise(
        std::move(swap_promise0));
    layer_tree_host()->Composite(base::TimeTicks::Now(), raster);

    // Fail to swap (no damage) if not reclaiming resources from the Display.
    std::unique_ptr<SwapPromise> swap_promise1(
        new TestSwapPromise(&swap_promise_result_[1]));
    layer_tree_host()->GetSwapPromiseManager()->QueueSwapPromise(
        std::move(swap_promise1));
    layer_tree_host()->SetNeedsCommit();
    layer_tree_host()->Composite(base::TimeTicks::Now(), raster);

    // Fail to draw (not visible).
    std::unique_ptr<SwapPromise> swap_promise2(
        new TestSwapPromise(&swap_promise_result_[2]));
    layer_tree_host()->GetSwapPromiseManager()->QueueSwapPromise(
        std::move(swap_promise2));
    layer_tree_host()->SetNeedsDisplayOnAllLayers();
    layer_tree_host()->SetVisible(false);
    layer_tree_host()->Composite(base::TimeTicks::Now(), raster);

    EndTest();
  }

  void DidCommit() override {
    commit_count_++;
    ASSERT_LE(commit_count_, 3);
  }

  void AfterTest() override {
    EXPECT_EQ(3, commit_count_);

    // Initial swap promise should have succeded.
    {
      base::AutoLock lock(swap_promise_result_[0].lock);
      EXPECT_TRUE(swap_promise_result_[0].did_swap_called);
      EXPECT_FALSE(swap_promise_result_[0].did_not_swap_called);
      EXPECT_TRUE(swap_promise_result_[0].dtor_called);
    }

    // Second swap promise fails to swap.
    {
      base::AutoLock lock(swap_promise_result_[1].lock);
      EXPECT_TRUE(swap_promise_result_[1].did_activate_called);
      EXPECT_FALSE(swap_promise_result_[1].did_swap_called);
      EXPECT_TRUE(swap_promise_result_[1].did_not_swap_called);
      EXPECT_EQ(SwapPromise::SWAP_FAILS, swap_promise_result_[1].reason);
      EXPECT_TRUE(swap_promise_result_[1].dtor_called);
    }

    // Third swap promises also fails to swap (and draw).
    {
      base::AutoLock lock(swap_promise_result_[2].lock);
      EXPECT_TRUE(swap_promise_result_[2].did_activate_called);
      EXPECT_FALSE(swap_promise_result_[2].did_swap_called);
      EXPECT_TRUE(swap_promise_result_[2].did_not_swap_called);
      EXPECT_EQ(SwapPromise::SWAP_FAILS, swap_promise_result_[2].reason);
      EXPECT_TRUE(swap_promise_result_[2].dtor_called);
    }
  }

  int commit_count_ = 0;
  TestSwapPromiseResult swap_promise_result_[3];
};

// Synchronous composite is a single-threaded only feature.
SINGLE_THREAD_TEST_F(LayerTreeHostTestSynchronousCompositeSwapPromise);

// Make sure page scale and top control deltas are applied to the client even
// when the LayerTreeHost doesn't have a root layer.
class LayerTreeHostAcceptsDeltasFromImplWithoutRootLayer
    : public LayerTreeHostTest {
 public:
  LayerTreeHostAcceptsDeltasFromImplWithoutRootLayer()
      : deltas_sent_to_client_(false) {}

  void BeginTest() override {
    layer_tree_host()->SetRootLayer(nullptr);
    info_.page_scale_delta = 3.14f;
    info_.top_controls_delta = 2.73f;

    PostSetNeedsCommitToMainThread();
  }

  void BeginMainFrame(const viz::BeginFrameArgs& args) override {
    EXPECT_EQ(nullptr, layer_tree_host()->root_layer());

    layer_tree_host()->ApplyScrollAndScale(&info_);
    EndTest();
  }

  void ApplyViewportDeltas(const gfx::Vector2dF& inner,
                           const gfx::Vector2dF& outer,
                           const gfx::Vector2dF& elastic_overscroll_delta,
                           float scale_delta,
                           float top_controls_delta) override {
    EXPECT_EQ(info_.page_scale_delta, scale_delta);
    EXPECT_EQ(info_.top_controls_delta, top_controls_delta);
    deltas_sent_to_client_ = true;
  }

  void AfterTest() override { EXPECT_TRUE(deltas_sent_to_client_); }

  ScrollAndScaleSet info_;
  bool deltas_sent_to_client_;
};

MULTI_THREAD_TEST_F(LayerTreeHostAcceptsDeltasFromImplWithoutRootLayer);

class LayerTreeHostTestCrispUpAfterPinchEnds : public LayerTreeHostTest {
 protected:
  LayerTreeHostTestCrispUpAfterPinchEnds()
      : playback_allowed_event_(base::WaitableEvent::ResetPolicy::MANUAL,
                                base::WaitableEvent::InitialState::SIGNALED) {}

  void SetupTree() override {
    frame_ = 1;
    posted_ = false;
    client_.set_fill_with_nonsolid_color(true);

    scoped_refptr<Layer> root_clip = Layer::Create();
    root_clip->SetBounds(gfx::Size(500, 500));
    scoped_refptr<Layer> page_scale_layer = Layer::Create();
    page_scale_layer->SetBounds(gfx::Size(500, 500));

    scoped_refptr<Layer> pinch = Layer::Create();
    pinch->SetBounds(gfx::Size(500, 500));
    pinch->SetScrollable(gfx::Size(500, 500));
    pinch->SetIsContainerForFixedPositionLayers(true);
    page_scale_layer->AddChild(pinch);
    root_clip->AddChild(page_scale_layer);

    std::unique_ptr<FakeRecordingSource> recording(new FakeRecordingSource);
    recording->SetPlaybackAllowedEvent(&playback_allowed_event_);
    scoped_refptr<FakePictureLayer> layer =
        FakePictureLayer::CreateWithRecordingSource(&client_,
                                                    std::move(recording));
    layer->SetBounds(gfx::Size(500, 500));
    layer->SetContentsOpaque(true);
    // Avoid LCD text on the layer so we don't cause extra commits when we
    // pinch.
    pinch->AddChild(layer);

    LayerTreeHost::ViewportLayers viewport_layers;
    viewport_layers.page_scale = page_scale_layer;
    viewport_layers.inner_viewport_container = root_clip;
    viewport_layers.inner_viewport_scroll = pinch;
    layer_tree_host()->RegisterViewportLayers(viewport_layers);
    layer_tree_host()->SetPageScaleFactorAndLimits(1.f, 1.f, 4.f);
    layer_tree_host()->SetRootLayer(root_clip);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_clip->bounds());
  }

  // Returns the delta scale of all quads in the frame's root pass from their
  // ideal, or 0 if they are not all the same.
  float FrameQuadScaleDeltaFromIdeal(LayerTreeHostImpl::FrameData* frame_data) {
    if (frame_data->has_no_damage)
      return 0.f;
    float frame_scale = 0.f;
    viz::RenderPass* root_pass = frame_data->render_passes.back().get();
    for (auto* draw_quad : root_pass->quad_list) {
      // Checkerboards mean an incomplete frame.
      if (draw_quad->material != viz::DrawQuad::TILED_CONTENT)
        return 0.f;
      const viz::TileDrawQuad* quad =
          viz::TileDrawQuad::MaterialCast(draw_quad);
      float quad_scale =
          quad->tex_coord_rect.width() / static_cast<float>(quad->rect.width());
      float transform_scale = SkMScalarToFloat(
          quad->shared_quad_state->quad_to_target_transform.matrix().get(0, 0));
      float scale = quad_scale / transform_scale;
      if (frame_scale != 0.f && frame_scale != scale)
        return 0.f;
      frame_scale = scale;
    }
    return frame_scale;
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    float quad_scale_delta = FrameQuadScaleDeltaFromIdeal(frame_data);
    switch (frame_) {
      case 1:
        // Drew at page scale 1 before any pinching.
        EXPECT_EQ(1.f, host_impl->active_tree()->current_page_scale_factor());
        EXPECT_EQ(1.f, quad_scale_delta);
        PostNextAfterDraw(host_impl);
        break;
      case 2:
        if (quad_scale_delta != 1.f)
          break;
        // Drew at page scale 1.5 after pinching in.
        EXPECT_EQ(1.5f, host_impl->active_tree()->current_page_scale_factor());
        EXPECT_EQ(1.f, quad_scale_delta);
        PostNextAfterDraw(host_impl);
        break;
      case 3:
        // By pinching out, we will create a new tiling and raster it. This may
        // cause some additional draws, though we should still be drawing with
        // the old 1.5 tiling.
        if (frame_data->has_no_damage)
          break;
        // Drew at page scale 1 with the 1.5 tiling while pinching out.
        EXPECT_EQ(1.f, host_impl->active_tree()->current_page_scale_factor());
        EXPECT_EQ(1.5f, quad_scale_delta);
        // We don't PostNextAfterDraw here, instead we wait for the new tiling
        // to finish rastering so we don't get any noise in further steps.
        break;
      case 4:
        // Drew at page scale 1 with the 1.5 tiling after pinching out completed
        // while waiting for texture uploads to complete.
        EXPECT_EQ(1.f, host_impl->active_tree()->current_page_scale_factor());
        // This frame will not have any damage, since it's actually the same as
        // the last frame, and should contain no incomplete tiles. We just want
        // to make sure we drew here at least once after the pinch ended to be
        // sure that drawing after pinch doesn't leave us at the wrong scale
        EXPECT_TRUE(frame_data->has_no_damage);
        PostNextAfterDraw(host_impl);
        break;
      case 5:
        if (quad_scale_delta != 1.f)
          break;
        // Drew at scale 1 after texture uploads are done.
        EXPECT_EQ(1.f, host_impl->active_tree()->current_page_scale_factor());
        EXPECT_EQ(1.f, quad_scale_delta);
        EndTest();
        break;
    }
    return draw_result;
  }

  void PostNextAfterDraw(LayerTreeHostImpl* host_impl) {
    if (posted_)
      return;
    posted_ = true;
    ImplThreadTaskRunner()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&LayerTreeHostTestCrispUpAfterPinchEnds::Next,
                       base::Unretained(this), host_impl),
        // Use a delay to allow raster/upload to happen in between frames. This
        // should cause flakiness if we fail to block raster/upload when
        // desired.
        base::TimeDelta::FromMilliseconds(16 * 4));
  }

  void Next(LayerTreeHostImpl* host_impl) {
    ++frame_;
    posted_ = false;
    switch (frame_) {
      case 2:
        // Pinch zoom in.
        host_impl->PinchGestureBegin();
        host_impl->PinchGestureUpdate(1.5f, gfx::Point(100, 100));
        host_impl->PinchGestureEnd(gfx::Point(100, 100), true);
        break;
      case 3:
        // Pinch zoom back to 1.f but don't end it.
        host_impl->PinchGestureBegin();
        host_impl->PinchGestureUpdate(1.f / 1.5f, gfx::Point(100, 100));
        break;
      case 4:
        // End the pinch, but delay tile production.
        playback_allowed_event_.Reset();
        host_impl->PinchGestureEnd(gfx::Point(100, 100), true);
        break;
      case 5:
        // Let tiles complete.
        playback_allowed_event_.Signal();
        break;
    }
  }

  void NotifyTileStateChangedOnThread(LayerTreeHostImpl* host_impl,
                                      const Tile* tile) override {
    if (frame_ == 3) {
      // On frame 3, we will have a lower res tile complete for the pinch-out
      // gesture even though it's not displayed. We wait for it here to prevent
      // flakiness.
      EXPECT_EQ(gfx::AxisTransform2d(0.75f, gfx::Vector2dF()),
                tile->raster_transform());
      PostNextAfterDraw(host_impl);
    }
    // On frame_ == 4, we are preventing texture uploads from completing,
    // so this verifies they are not completing before frame_ == 5.
    // Flaky failures here indicate we're failing to prevent uploads from
    // completing.
    EXPECT_NE(4, frame_) << tile->contents_scale_key();
  }

  void AfterTest() override {}

  FakeContentLayerClient client_;
  int frame_;
  bool posted_;
  base::WaitableEvent playback_allowed_event_;
};

// This test does pinching on the impl side which is not supported in single
// thread.
MULTI_THREAD_TEST_F(LayerTreeHostTestCrispUpAfterPinchEnds);

class LayerTreeHostTestCrispUpAfterPinchEndsWithOneCopy
    : public LayerTreeHostTestCrispUpAfterPinchEnds {
 protected:
  std::unique_ptr<viz::OutputSurface> CreateDisplayOutputSurfaceOnThread(
      scoped_refptr<viz::ContextProvider> compositor_context_provider)
      override {
    scoped_refptr<viz::TestContextProvider> display_context_provider =
        viz::TestContextProvider::Create();
    viz::TestWebGraphicsContext3D* context3d =
        display_context_provider->UnboundTestContext3d();
    context3d->set_support_sync_query(true);
#if defined(OS_MACOSX)
    context3d->set_support_texture_rectangle(true);
#endif
    display_context_provider->BindToCurrentThread();
    return LayerTreeTest::CreateDisplayOutputSurfaceOnThread(
        std::move(display_context_provider));
  }
};

// This test does pinching on the impl side which is not supported in single
// thread.
MULTI_THREAD_TEST_F(LayerTreeHostTestCrispUpAfterPinchEndsWithOneCopy);

class RasterizeWithGpuRasterizationCreatesResources : public LayerTreeHostTest {
 protected:
  RasterizeWithGpuRasterizationCreatesResources() = default;

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->gpu_rasterization_forced = true;
  }

  void SetupTree() override {
    client_.set_fill_with_nonsolid_color(true);

    scoped_refptr<Layer> root = Layer::Create();
    root->SetBounds(gfx::Size(500, 500));
    client_.set_bounds(root->bounds());

    std::unique_ptr<FakeRecordingSource> recording(new FakeRecordingSource);
    scoped_refptr<FakePictureLayer> layer =
        FakePictureLayer::CreateWithRecordingSource(&client_,
                                                    std::move(recording));
    layer->SetBounds(gfx::Size(500, 500));
    layer->SetContentsOpaque(true);
    root->AddChild(layer);

    layer_tree_host()->SetRootLayer(root);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_NE(0u, host_impl->resource_pool()->resource_count());
    EndTest();
    return draw_result;
  }
  void AfterTest() override {}

  FakeContentLayerClient client_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(RasterizeWithGpuRasterizationCreatesResources);

class GpuRasterizationRasterizesBorderTiles : public LayerTreeHostTest {
 protected:
  GpuRasterizationRasterizesBorderTiles() : viewport_size_(1024, 2048) {}

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->gpu_rasterization_forced = true;
  }

  void SetupTree() override {
    client_.set_fill_with_nonsolid_color(true);

    std::unique_ptr<FakeRecordingSource> recording(new FakeRecordingSource);
    scoped_refptr<FakePictureLayer> root =
        FakePictureLayer::CreateWithRecordingSource(&client_,
                                                    std::move(recording));
    root->SetBounds(gfx::Size(10000, 10000));
    client_.set_bounds(root->bounds());
    root->SetContentsOpaque(true);

    layer_tree_host()->SetRootLayer(root);
    LayerTreeHostTest::SetupTree();
    layer_tree_host()->SetViewportSizeAndScale(viewport_size_, 1.f,
                                               viz::LocalSurfaceId());
    client_.set_bounds(root->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(15u, host_impl->resource_pool()->resource_count());
    EndTest();
    return draw_result;
  }

  void AfterTest() override {}

 private:
  FakeContentLayerClient client_;
  gfx::Size viewport_size_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(GpuRasterizationRasterizesBorderTiles);

class LayerTreeHostTestContinuousDrawWhenCreatingVisibleTiles
    : public LayerTreeHostTest {
 protected:
  LayerTreeHostTestContinuousDrawWhenCreatingVisibleTiles()
      : playback_allowed_event_(base::WaitableEvent::ResetPolicy::MANUAL,
                                base::WaitableEvent::InitialState::SIGNALED) {}

  void SetupTree() override {
    step_ = 1;
    continuous_draws_ = 0;
    client_.set_fill_with_nonsolid_color(true);

    scoped_refptr<Layer> root_clip = Layer::Create();
    root_clip->SetBounds(gfx::Size(500, 500));
    scoped_refptr<Layer> page_scale_layer = Layer::Create();
    page_scale_layer->SetBounds(gfx::Size(500, 500));

    scoped_refptr<Layer> pinch = Layer::Create();
    pinch->SetBounds(gfx::Size(500, 500));
    pinch->SetScrollable(gfx::Size(500, 500));
    pinch->SetIsContainerForFixedPositionLayers(true);
    page_scale_layer->AddChild(pinch);
    root_clip->AddChild(page_scale_layer);

    std::unique_ptr<FakeRecordingSource> recording(new FakeRecordingSource);
    recording->SetPlaybackAllowedEvent(&playback_allowed_event_);
    scoped_refptr<FakePictureLayer> layer =
        FakePictureLayer::CreateWithRecordingSource(&client_,
                                                    std::move(recording));
    layer->SetBounds(gfx::Size(500, 500));
    layer->SetContentsOpaque(true);
    // Avoid LCD text on the layer so we don't cause extra commits when we
    // pinch.
    pinch->AddChild(layer);

    LayerTreeHost::ViewportLayers viewport_layers;
    viewport_layers.page_scale = page_scale_layer;
    viewport_layers.inner_viewport_container = root_clip;
    viewport_layers.inner_viewport_scroll = pinch;
    layer_tree_host()->RegisterViewportLayers(viewport_layers);
    layer_tree_host()->SetPageScaleFactorAndLimits(1.f, 1.f, 4.f);
    layer_tree_host()->SetRootLayer(root_clip);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_clip->bounds());
  }

  // Returns the delta scale of all quads in the frame's root pass from their
  // ideal, or 0 if they are not all the same.
  float FrameQuadScaleDeltaFromIdeal(LayerTreeHostImpl::FrameData* frame_data) {
    if (frame_data->has_no_damage)
      return 0.f;
    float frame_scale = 0.f;
    viz::RenderPass* root_pass = frame_data->render_passes.back().get();
    for (auto* draw_quad : root_pass->quad_list) {
      const viz::TileDrawQuad* quad =
          viz::TileDrawQuad::MaterialCast(draw_quad);
      float quad_scale =
          quad->tex_coord_rect.width() / static_cast<float>(quad->rect.width());
      float transform_scale = SkMScalarToFloat(
          quad->shared_quad_state->quad_to_target_transform.matrix().get(0, 0));
      float scale = quad_scale / transform_scale;
      if (frame_scale != 0.f && frame_scale != scale)
        return 0.f;
      frame_scale = scale;
    }
    return frame_scale;
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    float quad_scale_delta = FrameQuadScaleDeltaFromIdeal(frame_data);
    switch (step_) {
      case 1:
        // Drew at scale 1 before any pinching.
        EXPECT_EQ(1.f, host_impl->active_tree()->current_page_scale_factor());
        EXPECT_EQ(1.f, quad_scale_delta);
        break;
      case 2:
        if (quad_scale_delta != 1.f / 1.5f)
          break;
        // Drew at scale 1 still though the ideal is 1.5.
        EXPECT_EQ(1.5f, host_impl->active_tree()->current_page_scale_factor());
        EXPECT_EQ(1.f / 1.5f, quad_scale_delta);
        break;
      case 3:
        // Continuous draws are attempted.
        EXPECT_EQ(1.5f, host_impl->active_tree()->current_page_scale_factor());
        if (!frame_data->has_no_damage)
          EXPECT_EQ(1.f / 1.5f, quad_scale_delta);
        break;
      case 4:
        if (quad_scale_delta != 1.f)
          break;
        // Drew at scale 1.5 when all the tiles completed.
        EXPECT_EQ(1.5f, host_impl->active_tree()->current_page_scale_factor());
        EXPECT_EQ(1.f, quad_scale_delta);
        break;
      case 5:
        // TODO(danakj): We get more draws before the NotifyReadyToDraw
        // because it is asynchronous from the previous draw and happens late.
        break;
      case 6:
        // NotifyReadyToDraw happened. If we were already inside a frame, we may
        // try to draw once more.
        break;
      case 7:
        NOTREACHED() << "No draws should happen once we have a complete frame.";
        break;
    }
    return draw_result;
  }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override {
    switch (step_) {
      case 1:
        // Delay tile production.
        playback_allowed_event_.Reset();
        // Pinch zoom in to cause new tiles to be required.
        host_impl->PinchGestureBegin();
        host_impl->PinchGestureUpdate(1.5f, gfx::Point(100, 100));
        host_impl->PinchGestureEnd(gfx::Point(100, 100), true);
        ++step_;
        break;
      case 2:
        ++step_;
        break;
      case 3:
        // We should continue to try draw while there are incomplete visible
        // tiles.
        if (++continuous_draws_ > 5) {
          // Allow the tiles to complete.
          playback_allowed_event_.Signal();
          ++step_;
        }
        break;
      case 4:
        ++step_;
        break;
      case 5:
        // Waiting for NotifyReadyToDraw.
        break;
      case 6:
        // NotifyReadyToDraw happened.
        ++step_;
        break;
    }
  }

  void NotifyReadyToDrawOnThread(LayerTreeHostImpl* host_impl) override {
    if (step_ == 5) {
      ++step_;
      // NotifyReadyToDraw has happened, we may draw once more, but should not
      // get any more draws after that. End the test after a timeout to watch
      // for any extraneous draws.
      // TODO(brianderson): We could remove this delay and instead wait until
      // the viz::BeginFrameSource decides it doesn't need to send frames
      // anymore, or test that it already doesn't here.
      EndTestAfterDelayMs(16 * 4);
    }
  }

  void NotifyTileStateChangedOnThread(LayerTreeHostImpl* host_impl,
                                      const Tile* tile) override {
    // On step_ == 2, we are preventing texture uploads from completing,
    // so this verifies they are not completing before step_ == 3.
    // Flaky failures here indicate we're failing to prevent uploads from
    // completing.
    EXPECT_NE(2, step_);
  }

  void AfterTest() override { EXPECT_GT(continuous_draws_, 5); }

  FakeContentLayerClient client_;
  int step_;
  int continuous_draws_;
  base::WaitableEvent playback_allowed_event_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestContinuousDrawWhenCreatingVisibleTiles);

class LayerTreeHostTestOneActivatePerPrepareTiles : public LayerTreeHostTest {
 public:
  LayerTreeHostTestOneActivatePerPrepareTiles()
      : notify_ready_to_activate_count_(0u),
        scheduled_prepare_tiles_count_(0) {}

  void SetupTree() override {
    client_.set_fill_with_nonsolid_color(true);
    scoped_refptr<FakePictureLayer> root_layer =
        FakePictureLayer::Create(&client_);
    root_layer->SetBounds(gfx::Size(1500, 1500));
    root_layer->SetIsDrawable(true);

    layer_tree_host()->SetRootLayer(root_layer);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer->bounds());
  }

  void BeginTest() override {
    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(16, 16), 1.f,
                                               viz::LocalSurfaceId());
    PostSetNeedsCommitToMainThread();
  }

  void InitializedRendererOnThread(LayerTreeHostImpl* host_impl,
                                   bool success) override {
    ASSERT_TRUE(success);
    host_impl->tile_manager()->SetScheduledRasterTaskLimitForTesting(1);
  }

  void NotifyReadyToActivateOnThread(LayerTreeHostImpl* impl) override {
    ++notify_ready_to_activate_count_;
    EndTestAfterDelayMs(100);
  }

  void WillPrepareTilesOnThread(LayerTreeHostImpl* impl) override {
    ++scheduled_prepare_tiles_count_;
  }

  void AfterTest() override {
    // Expect at most a notification for each scheduled prepare tiles, plus one
    // for the initial commit (which doesn't go through scheduled actions).
    // The reason this is not an equality is because depending on timing, we
    // might get a prepare tiles but not yet get a notification that we're
    // ready to activate. The intent of a test is to ensure that we don't
    // get more than one notification per prepare tiles, so this is OK.
    EXPECT_LE(notify_ready_to_activate_count_,
              1u + scheduled_prepare_tiles_count_);
  }

 protected:
  FakeContentLayerClient client_;
  size_t notify_ready_to_activate_count_;
  size_t scheduled_prepare_tiles_count_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestOneActivatePerPrepareTiles);

class LayerTreeHostTestActivationCausesPrepareTiles : public LayerTreeHostTest {
 public:
  LayerTreeHostTestActivationCausesPrepareTiles()
      : scheduled_prepare_tiles_count_(0) {}

  void SetupTree() override {
    client_.set_fill_with_nonsolid_color(true);
    scoped_refptr<FakePictureLayer> root_layer =
        FakePictureLayer::Create(&client_);
    root_layer->SetBounds(gfx::Size(150, 150));
    root_layer->SetIsDrawable(true);

    layer_tree_host()->SetRootLayer(root_layer);
    LayerTreeHostTest::SetupTree();
    client_.set_bounds(root_layer->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void NotifyReadyToActivateOnThread(LayerTreeHostImpl* impl) override {
    // Ensure we've already activated.
    EXPECT_FALSE(impl->pending_tree());

    // After activating, we either need to prepare tiles, or we've already
    // called a scheduled prepare tiles. This is done because activation might
    // cause us to have to memory available (old active tree is gone), so we
    // need to ensure we will get a PrepareTiles call.
    if (!impl->prepare_tiles_needed())
      EXPECT_GE(scheduled_prepare_tiles_count_, 1);
    EndTest();
  }

  void WillPrepareTilesOnThread(LayerTreeHostImpl* impl) override {
    ++scheduled_prepare_tiles_count_;
  }

  void AfterTest() override {}

 protected:
  FakeContentLayerClient client_;
  int scheduled_prepare_tiles_count_;
};

// This test is testing activation from a pending tree and doesn't make sense
// with single thread commit-to-active.
MULTI_THREAD_TEST_F(LayerTreeHostTestActivationCausesPrepareTiles);

// This tests an assertion that DidCommit and WillCommit happen in the same
// stack frame with no tasks that run between them.  Various embedders of
// cc depend on this logic.  ui::Compositor holds a compositor lock between
// these events and the inspector timeline wants begin/end CompositeLayers
// to be properly nested with other begin/end events.
class LayerTreeHostTestNoTasksBetweenWillAndDidCommit
    : public LayerTreeHostTest {
 public:
  LayerTreeHostTestNoTasksBetweenWillAndDidCommit() : did_commit_(false) {}

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillCommit() override {
    MainThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(&LayerTreeHostTestNoTasksBetweenWillAndDidCommit::
                           EndTestShouldRunAfterDidCommit,
                       base::Unretained(this)));
  }

  void EndTestShouldRunAfterDidCommit() {
    EXPECT_TRUE(did_commit_);
    EndTest();
  }

  void DidCommit() override {
    EXPECT_FALSE(did_commit_);
    did_commit_ = true;
  }

  void AfterTest() override { EXPECT_TRUE(did_commit_); }

 private:
  bool did_commit_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestNoTasksBetweenWillAndDidCommit);

class LayerTreeHostTestUpdateCopyRequests : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    root = Layer::Create();
    child = Layer::Create();
    root->AddChild(child);
    layer_tree_host()->SetRootLayer(root);
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        EXPECT_TRUE(root->has_copy_requests_in_target_subtree());
        break;
    }
  }

  void DidCommit() override {
    gfx::Transform transform;
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        child->RequestCopyOfOutput(
            viz::CopyOutputRequest::CreateStubForTesting());
        transform.Scale(2.0, 2.0);
        child->SetTransform(transform);
        break;
      case 2:
        // By changing the scale of a layer which already owns a transform node,
        // a commit will be triggered but a property tree rebuild will not, this
        // is used to test sure that clearing copy requestts does trigger a
        // rebuild whenever next commit happens.
        transform.Scale(1.5, 1.5);
        child->SetTransform(transform);
        break;
      case 3:
        EXPECT_FALSE(root->has_copy_requests_in_target_subtree());
        EndTest();
        break;
    }
  }

  void AfterTest() override {}

 private:
  scoped_refptr<Layer> root;
  scoped_refptr<Layer> child;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestUpdateCopyRequests);

class LayerTreeTestMaskLayerForSurfaceWithContentRectNotAtOrigin
    : public LayerTreeTest {
 protected:
  void SetupTree() override {
    // The masked layer has bounds 50x50, but it has a child that causes
    // the surface bounds to be larger. It also has a parent that clips the
    // masked layer and its surface.

    scoped_refptr<Layer> root = Layer::Create();

    scoped_refptr<FakePictureLayer> content_layer =
        FakePictureLayer::Create(&client_);

    std::unique_ptr<RecordingSource> recording_source =
        FakeRecordingSource::CreateFilledRecordingSource(gfx::Size(100, 100));
    PaintFlags paint1, paint2;
    static_cast<FakeRecordingSource*>(recording_source.get())
        ->add_draw_rect_with_flags(gfx::Rect(0, 0, 100, 90), paint1);
    static_cast<FakeRecordingSource*>(recording_source.get())
        ->add_draw_rect_with_flags(gfx::Rect(0, 90, 100, 10), paint2);
    client_.set_fill_with_nonsolid_color(true);
    static_cast<FakeRecordingSource*>(recording_source.get())->Rerecord();

    scoped_refptr<FakePictureLayer> mask_layer =
        FakePictureLayer::CreateWithRecordingSource(
            &client_, std::move(recording_source));
    content_layer->SetMaskLayer(mask_layer.get());

    gfx::Size root_size(100, 100);
    root->SetBounds(root_size);

    gfx::Size layer_size(100, 100);
    content_layer->SetBounds(layer_size);

    gfx::Size mask_size(100, 100);
    mask_layer->SetBounds(mask_size);
    mask_layer->SetLayerMaskType(Layer::LayerMaskType::MULTI_TEXTURE_MASK);
    mask_layer_id_ = mask_layer->id();

    layer_tree_host()->SetRootLayer(root);
    LayerTreeTest::SetupTree();
    scoped_refptr<Layer> outer_viewport_scroll_layer = Layer::Create();
    outer_viewport_scroll_layer->SetBounds(layer_size);
    CreateVirtualViewportLayers(root.get(), outer_viewport_scroll_layer,
                                gfx::Size(50, 50), gfx::Size(50, 50),
                                layer_tree_host());
    layer_tree_host()->outer_viewport_container_layer()->SetMasksToBounds(true);
    outer_viewport_scroll_layer->AddChild(content_layer);

    client_.set_bounds(root->bounds());
    outer_viewport_scroll_layer->SetScrollOffset(gfx::ScrollOffset(50, 50));
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(2u, frame_data->render_passes.size());
    viz::RenderPass* root_pass = frame_data->render_passes.back().get();
    EXPECT_EQ(2u, root_pass->quad_list.size());

    // There's a solid color quad under everything.
    EXPECT_EQ(viz::DrawQuad::SOLID_COLOR,
              root_pass->quad_list.back()->material);

    EXPECT_EQ(viz::DrawQuad::RENDER_PASS,
              root_pass->quad_list.front()->material);
    const viz::RenderPassDrawQuad* render_pass_quad =
        viz::RenderPassDrawQuad::MaterialCast(root_pass->quad_list.front());
    EXPECT_EQ(gfx::Rect(50, 50, 50, 50).ToString(),
              render_pass_quad->rect.ToString());
    if (host_impl->settings().enable_mask_tiling) {
      PictureLayerImpl* mask_layer_impl = static_cast<PictureLayerImpl*>(
          host_impl->active_tree()->LayerById(mask_layer_id_));
      gfx::SizeF texture_size(
          mask_layer_impl->CalculateTileSize(mask_layer_impl->bounds()));
      EXPECT_EQ(
          gfx::RectF(50.f / texture_size.width(), 50.f / texture_size.height(),
                     50.f / texture_size.width(), 50.f / texture_size.height())
              .ToString(),
          render_pass_quad->mask_uv_rect.ToString());
    } else {
      EXPECT_EQ(gfx::ScaleRect(gfx::RectF(50.f, 50.f, 50.f, 50.f), 1.f / 100.f)
                    .ToString(),
                render_pass_quad->mask_uv_rect.ToString());
    }
    EndTest();
    return draw_result;
  }

  void AfterTest() override {}

  int mask_layer_id_;
  FakeContentLayerClient client_;
};

class LayerTreeTestSingleTextureMaskLayerForSurfaceWithContentRectNotAtOrigin
    : public LayerTreeTestMaskLayerForSurfaceWithContentRectNotAtOrigin {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_mask_tiling = false;
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeTestSingleTextureMaskLayerForSurfaceWithContentRectNotAtOrigin);

class LayerTreeTestMultiTextureMaskLayerForSurfaceWithContentRectNotAtOrigin
    : public LayerTreeTestMaskLayerForSurfaceWithContentRectNotAtOrigin {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_mask_tiling = true;
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeTestMultiTextureMaskLayerForSurfaceWithContentRectNotAtOrigin);

class LayerTreeTestMaskLayerForSurfaceWithClippedLayer : public LayerTreeTest {
 protected:
  void SetupTree() override {
    // The masked layer has bounds 50x50, but it has a child that causes
    // the surface bounds to be larger. It also has a parent that clips the
    // masked layer and its surface.

    scoped_refptr<Layer> root = Layer::Create();

    scoped_refptr<Layer> clipping_layer = Layer::Create();
    root->AddChild(clipping_layer);

    scoped_refptr<FakePictureLayer> content_layer =
        FakePictureLayer::Create(&client_);
    clipping_layer->AddChild(content_layer);

    scoped_refptr<FakePictureLayer> content_child_layer =
        FakePictureLayer::Create(&client_);
    content_layer->AddChild(content_child_layer);

    std::unique_ptr<RecordingSource> recording_source =
        FakeRecordingSource::CreateFilledRecordingSource(gfx::Size(50, 50));
    PaintFlags paint1, paint2;
    static_cast<FakeRecordingSource*>(recording_source.get())
        ->add_draw_rect_with_flags(gfx::Rect(0, 0, 50, 40), paint1);
    static_cast<FakeRecordingSource*>(recording_source.get())
        ->add_draw_rect_with_flags(gfx::Rect(0, 40, 50, 10), paint2);
    client_.set_fill_with_nonsolid_color(true);
    static_cast<FakeRecordingSource*>(recording_source.get())->Rerecord();

    scoped_refptr<FakePictureLayer> mask_layer =
        FakePictureLayer::CreateWithRecordingSource(
            &client_, std::move(recording_source));
    content_layer->SetMaskLayer(mask_layer.get());

    gfx::Size root_size(100, 100);
    root->SetBounds(root_size);

    gfx::PointF clipping_origin(20.f, 10.f);
    gfx::Size clipping_size(10, 20);
    clipping_layer->SetBounds(clipping_size);
    clipping_layer->SetPosition(clipping_origin);
    clipping_layer->SetMasksToBounds(true);

    gfx::Size layer_size(50, 50);
    content_layer->SetBounds(layer_size);
    content_layer->SetPosition(gfx::PointF() -
                               clipping_origin.OffsetFromOrigin());

    gfx::Size child_size(50, 50);
    content_child_layer->SetBounds(child_size);
    content_child_layer->SetPosition(gfx::PointF(20.f, 0.f));

    gfx::Size mask_size(50, 50);
    mask_layer->SetBounds(mask_size);
    mask_layer->SetLayerMaskType(Layer::LayerMaskType::MULTI_TEXTURE_MASK);
    mask_layer_id_ = mask_layer->id();

    layer_tree_host()->SetRootLayer(root);
    LayerTreeTest::SetupTree();
    client_.set_bounds(root->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(2u, frame_data->render_passes.size());
    viz::RenderPass* root_pass = frame_data->render_passes.back().get();
    EXPECT_EQ(2u, root_pass->quad_list.size());

    // There's a solid color quad under everything.
    EXPECT_EQ(viz::DrawQuad::SOLID_COLOR,
              root_pass->quad_list.back()->material);

    // The surface is clipped to 10x20.
    EXPECT_EQ(viz::DrawQuad::RENDER_PASS,
              root_pass->quad_list.front()->material);
    const viz::RenderPassDrawQuad* render_pass_quad =
        viz::RenderPassDrawQuad::MaterialCast(root_pass->quad_list.front());
    EXPECT_EQ(gfx::Rect(20, 10, 10, 20).ToString(),
              render_pass_quad->rect.ToString());
    // The masked layer is 50x50, but the surface size is 10x20. So the texture
    // coords in the mask are scaled by 10/50 and 20/50.
    // The surface is clipped to (20,10) so the mask texture coords are offset
    // by 20/50 and 10/50
    if (host_impl->settings().enable_mask_tiling) {
      PictureLayerImpl* mask_layer_impl = static_cast<PictureLayerImpl*>(
          host_impl->active_tree()->LayerById(mask_layer_id_));
      gfx::SizeF texture_size(
          mask_layer_impl->CalculateTileSize(mask_layer_impl->bounds()));
      EXPECT_EQ(
          gfx::RectF(20.f / texture_size.width(), 10.f / texture_size.height(),
                     10.f / texture_size.width(), 20.f / texture_size.height())
              .ToString(),
          render_pass_quad->mask_uv_rect.ToString());
    } else {
      EXPECT_EQ(gfx::ScaleRect(gfx::RectF(20.f, 10.f, 10.f, 20.f), 1.f / 50.f)
                    .ToString(),
                render_pass_quad->mask_uv_rect.ToString());
    }
    EndTest();
    return draw_result;
  }

  void AfterTest() override {}

  int mask_layer_id_;
  FakeContentLayerClient client_;
};

class LayerTreeTestSingleTextureMaskLayerForSurfaceWithClippedLayer
    : public LayerTreeTestMaskLayerForSurfaceWithClippedLayer {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_mask_tiling = false;
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeTestSingleTextureMaskLayerForSurfaceWithClippedLayer);

class LayerTreeTestMultiTextureMaskLayerForSurfaceWithClippedLayer
    : public LayerTreeTestMaskLayerForSurfaceWithClippedLayer {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_mask_tiling = true;
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(
    LayerTreeTestMultiTextureMaskLayerForSurfaceWithClippedLayer);

class LayerTreeTestMaskLayerWithScaling : public LayerTreeTest {
 protected:
  void SetupTree() override {
    // Root
    //  |
    //  +-- Scaling Layer (adds a 2x scale)
    //       |
    //       +-- Content Layer
    //             +--Mask

    scoped_refptr<Layer> root = Layer::Create();

    scoped_refptr<Layer> scaling_layer = Layer::Create();
    root->AddChild(scaling_layer);

    scoped_refptr<FakePictureLayer> content_layer =
        FakePictureLayer::Create(&client_);
    scaling_layer->AddChild(content_layer);

    std::unique_ptr<RecordingSource> recording_source =
        FakeRecordingSource::CreateFilledRecordingSource(gfx::Size(100, 100));
    PaintFlags paint1, paint2;
    static_cast<FakeRecordingSource*>(recording_source.get())
        ->add_draw_rect_with_flags(gfx::Rect(0, 0, 100, 10), paint1);
    static_cast<FakeRecordingSource*>(recording_source.get())
        ->add_draw_rect_with_flags(gfx::Rect(0, 10, 100, 90), paint2);
    client_.set_fill_with_nonsolid_color(true);
    static_cast<FakeRecordingSource*>(recording_source.get())->Rerecord();

    scoped_refptr<FakePictureLayer> mask_layer =
        FakePictureLayer::CreateWithRecordingSource(
            &client_, std::move(recording_source));
    content_layer->SetMaskLayer(mask_layer.get());

    gfx::Size root_size(100, 100);
    root->SetBounds(root_size);

    gfx::Size scaling_layer_size(50, 50);
    scaling_layer->SetBounds(scaling_layer_size);
    gfx::Transform scale;
    scale.Scale(2.f, 2.f);
    scaling_layer->SetTransform(scale);

    content_layer->SetBounds(scaling_layer_size);

    mask_layer->SetBounds(scaling_layer_size);
    mask_layer->SetLayerMaskType(Layer::LayerMaskType::MULTI_TEXTURE_MASK);

    layer_tree_host()->SetRootLayer(root);
    LayerTreeTest::SetupTree();
    client_.set_bounds(root->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(2u, frame_data->render_passes.size());
    viz::RenderPass* root_pass = frame_data->render_passes.back().get();
    EXPECT_EQ(2u, root_pass->quad_list.size());

    // There's a solid color quad under everything.
    EXPECT_EQ(viz::DrawQuad::SOLID_COLOR,
              root_pass->quad_list.back()->material);

    EXPECT_EQ(viz::DrawQuad::RENDER_PASS,
              root_pass->quad_list.front()->material);
    const viz::RenderPassDrawQuad* render_pass_quad =
        viz::RenderPassDrawQuad::MaterialCast(root_pass->quad_list.front());
    switch (host_impl->active_tree()->source_frame_number()) {
      case 0:
        // Check that the tree scaling is correctly taken into account for the
        // mask, that should fully map onto the quad.
        EXPECT_EQ(gfx::Rect(0, 0, 100, 100).ToString(),
                  render_pass_quad->rect.ToString());
        if (host_impl->settings().enable_mask_tiling) {
          EXPECT_EQ(
              gfx::RectF(0.f, 0.f, 100.f / 128.f, 100.f / 128.f).ToString(),
              render_pass_quad->mask_uv_rect.ToString());
        } else {
          EXPECT_EQ(gfx::RectF(0.f, 0.f, 1.f, 1.f).ToString(),
                    render_pass_quad->mask_uv_rect.ToString());
        }
        break;
      case 1:
        // Applying a DSF should change the render surface size, but won't
        // affect which part of the mask is used.
        EXPECT_EQ(gfx::Rect(0, 0, 200, 200).ToString(),
                  render_pass_quad->rect.ToString());
        if (host_impl->settings().enable_mask_tiling) {
          EXPECT_EQ(
              gfx::RectF(0.f, 0.f, 100.f / 128.f, 100.f / 128.f).ToString(),
              render_pass_quad->mask_uv_rect.ToString());
        } else {
          EXPECT_EQ(gfx::RectF(0.f, 0.f, 1.f, 1.f).ToString(),
                    render_pass_quad->mask_uv_rect.ToString());
        }
        EndTest();
        break;
    }
    return draw_result;
  }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        gfx::Size double_root_size(200, 200);
        layer_tree_host()->SetViewportSizeAndScale(double_root_size, 2.f,
                                                   viz::LocalSurfaceId());
        break;
    }
  }

  void AfterTest() override {}

  FakeContentLayerClient client_;
};

class LayerTreeTestSingleTextureMaskLayerWithScaling
    : public LayerTreeTestMaskLayerWithScaling {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_mask_tiling = false;
    settings->layer_transforms_should_scale_layer_contents = true;
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeTestSingleTextureMaskLayerWithScaling);

class LayerTreeTestMultiTextureMaskLayerWithScaling
    : public LayerTreeTestMaskLayerWithScaling {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_mask_tiling = true;
    settings->layer_transforms_should_scale_layer_contents = true;
  }
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeTestMultiTextureMaskLayerWithScaling);

class LayerTreeTestMaskWithNonExactTextureSize : public LayerTreeTest {
 protected:
  void SetupTree() override {
    // The masked layer has bounds 100x100, but is allocated a 120x150 texture.

    scoped_refptr<Layer> root = Layer::Create();

    scoped_refptr<FakePictureLayer> content_layer =
        FakePictureLayer::Create(&client_);
    root->AddChild(content_layer);

    std::unique_ptr<RecordingSource> recording_source =
        FakeRecordingSource::CreateFilledRecordingSource(gfx::Size(100, 100));
    PaintFlags paint1, paint2;
    static_cast<FakeRecordingSource*>(recording_source.get())
        ->add_draw_rect_with_flags(gfx::Rect(0, 0, 100, 90), paint1);
    static_cast<FakeRecordingSource*>(recording_source.get())
        ->add_draw_rect_with_flags(gfx::Rect(0, 90, 100, 10), paint2);
    client_.set_fill_with_nonsolid_color(true);
    static_cast<FakeRecordingSource*>(recording_source.get())->Rerecord();

    scoped_refptr<FakePictureLayer> mask_layer =
        FakePictureLayer::CreateWithRecordingSource(
            &client_, std::move(recording_source));
    content_layer->SetMaskLayer(mask_layer.get());

    gfx::Size root_size(100, 100);
    root->SetBounds(root_size);

    gfx::Size layer_size(100, 100);
    content_layer->SetBounds(layer_size);

    gfx::Size mask_size(100, 100);
    gfx::Size mask_texture_size(120, 150);
    mask_layer->SetBounds(mask_size);
    mask_layer->SetLayerMaskType(Layer::LayerMaskType::SINGLE_TEXTURE_MASK);
    mask_layer->set_fixed_tile_size(mask_texture_size);

    layer_tree_host()->SetRootLayer(root);
    LayerTreeTest::SetupTree();
    client_.set_bounds(root->bounds());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(2u, frame_data->render_passes.size());
    viz::RenderPass* root_pass = frame_data->render_passes.back().get();
    EXPECT_EQ(2u, root_pass->quad_list.size());

    // There's a solid color quad under everything.
    EXPECT_EQ(viz::DrawQuad::SOLID_COLOR,
              root_pass->quad_list.back()->material);

    // The surface is 100x100
    EXPECT_EQ(viz::DrawQuad::RENDER_PASS,
              root_pass->quad_list.front()->material);
    const viz::RenderPassDrawQuad* render_pass_quad =
        viz::RenderPassDrawQuad::MaterialCast(root_pass->quad_list.front());
    EXPECT_EQ(gfx::Rect(0, 0, 100, 100).ToString(),
              render_pass_quad->rect.ToString());
    // The mask layer is 100x100, but is backed by a 120x150 image.
    EXPECT_EQ(gfx::RectF(0.0f, 0.0f, 100.f / 120.0f, 100.f / 150.0f).ToString(),
              render_pass_quad->mask_uv_rect.ToString());
    EndTest();
    return draw_result;
  }

  void AfterTest() override {}

  int mask_layer_id_;
  FakeContentLayerClient client_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeTestMaskWithNonExactTextureSize);

class LayerTreeTestPageScaleFlags : public LayerTreeTest {
 protected:
  void SetupTree() override {
    // -root
    //   -pre page scale
    //   -page scale
    //     -inner viewport scroll
    //       -page scale grandchild
    //   -post page scale

    scoped_refptr<Layer> root = Layer::Create();
    scoped_refptr<Layer> pre_page_scale = Layer::Create();
    scoped_refptr<Layer> page_scale = Layer::Create();
    scoped_refptr<Layer> inner_viewport_scroll = Layer::Create();
    scoped_refptr<Layer> page_scale_grandchild = Layer::Create();
    scoped_refptr<Layer> post_page_scale = Layer::Create();

    root->AddChild(pre_page_scale);
    root->AddChild(page_scale);
    root->AddChild(post_page_scale);

    page_scale->AddChild(inner_viewport_scroll);
    inner_viewport_scroll->AddChild(page_scale_grandchild);
    inner_viewport_scroll->SetIsContainerForFixedPositionLayers(true);

    layer_tree_host()->SetRootLayer(root);
    LayerTreeTest::SetupTree();

    LayerTreeHost::ViewportLayers viewport_layers;
    viewport_layers.inner_viewport_container = root;
    viewport_layers.page_scale = page_scale;
    viewport_layers.inner_viewport_scroll = inner_viewport_scroll;
    layer_tree_host()->RegisterViewportLayers(viewport_layers);

    affected_by_page_scale_.push_back(page_scale->id());
    affected_by_page_scale_.push_back(inner_viewport_scroll->id());
    affected_by_page_scale_.push_back(page_scale_grandchild->id());

    not_affected_by_page_scale_.push_back(root->id());
    not_affected_by_page_scale_.push_back(pre_page_scale->id());
    not_affected_by_page_scale_.push_back(post_page_scale->id());
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void CommitCompleteOnThread(LayerTreeHostImpl* host_impl) override {
    LayerTreeHostCommon::CallFunctionForEveryLayer(
        host_impl->sync_tree(), [this](LayerImpl* layer) {
          const std::vector<int>& list =
              layer->IsAffectedByPageScale()
                  ? this->affected_by_page_scale_
                  : this->not_affected_by_page_scale_;
          EXPECT_TRUE(std::find(list.begin(), list.end(), layer->id()) !=
                      list.end());
        });

    EndTest();
  }

  void AfterTest() override {}

  std::vector<int> affected_by_page_scale_;
  std::vector<int> not_affected_by_page_scale_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeTestPageScaleFlags);

class LayerTreeHostTestDestroyWhileInitializingOutputSurface
    : public LayerTreeHostTest {
 protected:
  void BeginTest() override {
    // By ending the test immediately we start initialization of an output
    // surface but destroy the LTH before it completes. This test verifies
    // that this works correctly and the output surface is destroyed on
    // the correct thread.
    EndTest();
  }

  void AfterTest() override {}
};

MULTI_THREAD_TEST_F(LayerTreeHostTestDestroyWhileInitializingOutputSurface);

// Makes sure that painted_device_scale_factor is propagated to the
// frame's metadata.
class LayerTreeHostTestPaintedDeviceScaleFactor : public LayerTreeHostTest {
 protected:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->use_painted_device_scale_factor = true;
    LayerTreeHostTest::InitializeSettings(settings);
  }

  void SetupTree() override {
    SetInitialDeviceScaleFactor(2.f);
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override {
    EXPECT_EQ(1.0f, layer_tree_host()->device_scale_factor());
    PostSetNeedsCommitToMainThread();
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(DRAW_SUCCESS, draw_result);
    EXPECT_EQ(2.0f, host_impl->active_tree()->painted_device_scale_factor());
    EXPECT_EQ(1.0f, host_impl->active_tree()->device_scale_factor());
    return draw_result;
  }

  void DisplayReceivedCompositorFrameOnThread(
      const viz::CompositorFrame& frame) override {
    EXPECT_EQ(2.0f, frame.metadata.device_scale_factor);
    EndTest();
  }

  void AfterTest() override {}
};
SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestPaintedDeviceScaleFactor);

// Makes sure that viz::LocalSurfaceId is propagated to the LayerTreeFrameSink.
class LayerTreeHostTestLocalSurfaceId : public LayerTreeHostTest {
 protected:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_surface_synchronization = true;
  }

  void BeginTest() override {
    expected_local_surface_id_ = allocator_.GenerateId();
    PostSetLocalSurfaceIdToMainThread(expected_local_surface_id_);
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(DRAW_SUCCESS, draw_result);
    EXPECT_EQ(expected_local_surface_id_,
              host_impl->active_tree()->local_surface_id());
    return draw_result;
  }

  void DisplayReceivedLocalSurfaceIdOnThread(
      const viz::LocalSurfaceId& local_surface_id) override {
    EXPECT_EQ(expected_local_surface_id_, local_surface_id);
    EndTest();
  }

  void AfterTest() override {}

  viz::LocalSurfaceId expected_local_surface_id_;
  viz::ParentLocalSurfaceIdAllocator allocator_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestLocalSurfaceId);

// The GPU image decode controller hands images off to Skia for rasterization.
// When used with large images, the images in question could be deleted before
// Skia was done with them, causing a crash. This test performs an end-to-end
// check of large image rasterization to ensure we do not hit this crash.
// Note that this code path won't always hit the crash, even when incorrect
// behavior occurs, so this is more of a sanity check.
// TODO(ericrk): We should improve this so that we can reliably detect the
// crash.
class GpuRasterizationSucceedsWithLargeImage : public LayerTreeHostTest {
 protected:
  GpuRasterizationSucceedsWithLargeImage()
      : viewport_size_(1024, 2048), large_image_size_(20000, 10) {}

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->gpu_rasterization_forced = true;

    // Set to 0 to force at-raster GPU image decode.
    settings->decoded_image_working_set_budget_bytes = 0;
  }

  void SetupTree() override {
    client_.set_fill_with_nonsolid_color(true);

    std::unique_ptr<FakeRecordingSource> recording =
        FakeRecordingSource::CreateFilledRecordingSource(
            gfx::Size(10000, 10000));

    recording->add_draw_image(CreateDiscardablePaintImage(large_image_size_),
                              gfx::Point(0, 0));
    recording->Rerecord();

    scoped_refptr<FakePictureLayer> root =
        FakePictureLayer::CreateWithRecordingSource(&client_,
                                                    std::move(recording));
    root->SetBounds(gfx::Size(10000, 10000));
    client_.set_bounds(root->bounds());
    root->SetContentsOpaque(true);

    layer_tree_host()->SetRootLayer(root);
    LayerTreeHostTest::SetupTree();
    layer_tree_host()->SetViewportSizeAndScale(viewport_size_, 1.f,
                                               viz::LocalSurfaceId());
    client_.set_bounds(root->bounds());
  }

  void InitializedRendererOnThread(LayerTreeHostImpl* host_impl,
                                   bool success) override {
    // Check that our large_image_size_ is greater than max texture size. We do
    // this here to ensure that our otuput surface exists.

    // Retrieve max texture size from Skia.
    viz::ContextProvider* context_provider =
        host_impl->layer_tree_frame_sink()->context_provider();
    ASSERT_TRUE(context_provider);

    GrContext* gr_context = context_provider->GrContext();
    ASSERT_TRUE(gr_context);
    const uint32_t max_texture_size = gr_context->maxTextureSize();
    ASSERT_GT(static_cast<uint32_t>(large_image_size_.width()),
              max_texture_size);
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override { EndTest(); }

  void AfterTest() override {}

 private:
  FakeContentLayerClient client_;
  const gfx::Size viewport_size_;
  const gfx::Size large_image_size_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(GpuRasterizationSucceedsWithLargeImage);

class LayerTreeHostTestSubmitFrameMetadata : public LayerTreeHostTest {
 protected:
  void BeginTest() override {
    layer_tree_host()->SetPageScaleFactorAndLimits(1.f, 0.5f, 4.f);
    PostSetNeedsCommitToMainThread();
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(DRAW_SUCCESS, draw_result);
    EXPECT_EQ(0, num_swaps_);
    drawn_viewport_ = host_impl->DeviceViewport();
    return draw_result;
  }

  void DisplayReceivedCompositorFrameOnThread(
      const viz::CompositorFrame& frame) override {
    EXPECT_EQ(1, ++num_swaps_);

    EXPECT_EQ(drawn_viewport_, frame.render_pass_list.back()->output_rect);
    EXPECT_EQ(0.5f, frame.metadata.min_page_scale_factor);
    EXPECT_EQ(4.f, frame.metadata.max_page_scale_factor);

    EXPECT_EQ(0u, frame.resource_list.size());
    EXPECT_EQ(1u, frame.render_pass_list.size());

    EndTest();
  }

  void AfterTest() override {}

  int num_swaps_ = 0;
  gfx::Rect drawn_viewport_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestSubmitFrameMetadata);

class LayerTreeHostTestSubmitFrameResources : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame,
                                   DrawResult draw_result) override {
    frame->render_passes.clear();

    viz::RenderPass* child_pass =
        AddRenderPass(&frame->render_passes, 2, gfx::Rect(3, 3, 10, 10),
                      gfx::Transform(), FilterOperations());
    gpu::SyncToken mailbox_sync_token;
    AddOneOfEveryQuadType(child_pass, host_impl->resource_provider(), 0,
                          &mailbox_sync_token);

    viz::RenderPass* pass =
        AddRenderPass(&frame->render_passes, 1, gfx::Rect(3, 3, 10, 10),
                      gfx::Transform(), FilterOperations());
    AddOneOfEveryQuadType(pass, host_impl->resource_provider(), child_pass->id,
                          &mailbox_sync_token);
    return draw_result;
  }

  void DisplayReceivedCompositorFrameOnThread(
      const viz::CompositorFrame& frame) override {
    EXPECT_EQ(2u, frame.render_pass_list.size());
    // Each render pass has 10 resources in it. And the root render pass has a
    // mask resource used when drawing the child render pass. The number 10 may
    // change if AppendOneOfEveryQuadType() is updated, and the value here
    // should be updated accordingly.
    EXPECT_EQ(21u, frame.resource_list.size());

    EndTest();
  }

  void AfterTest() override {}
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestSubmitFrameResources);

// Ensure that content_source_id is propagated to the frame's metadata.
class LayerTreeHostTestContentSourceId : public LayerTreeHostTest {
 protected:
  void BeginTest() override {
    layer_tree_host()->SetContentSourceId(5);
    PostSetNeedsCommitToMainThread();
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* host_impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    EXPECT_EQ(DRAW_SUCCESS, draw_result);
    EXPECT_EQ(5U, host_impl->active_tree()->content_source_id());
    return draw_result;
  }

  void DisplayReceivedCompositorFrameOnThread(
      const viz::CompositorFrame& frame) override {
    EXPECT_EQ(5U, frame.metadata.content_source_id);
    EndTest();
  }

  void AfterTest() override {}
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestContentSourceId);

class LayerTreeHostTestBeginFrameAcks : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillBeginImplFrameOnThread(LayerTreeHostImpl* impl,
                                  const viz::BeginFrameArgs& args) override {
    EXPECT_TRUE(args.IsValid());
    current_begin_frame_args_ = args;
  }

  DrawResult PrepareToDrawOnThread(LayerTreeHostImpl* impl,
                                   LayerTreeHostImpl::FrameData* frame_data,
                                   DrawResult draw_result) override {
    frame_data_ = frame_data;
    return draw_result;
  }

  void DisplayReceivedCompositorFrameOnThread(
      const viz::CompositorFrame& frame) override {
    if (compositor_frame_submitted_)
      return;
    compositor_frame_submitted_ = true;

    EXPECT_EQ(
        viz::BeginFrameAck(current_begin_frame_args_.source_id,
                           current_begin_frame_args_.sequence_number, true),
        frame.metadata.begin_frame_ack);
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    if (layers_drawn_)
      return;
    layers_drawn_ = true;

    EXPECT_TRUE(frame_data_);
    EXPECT_TRUE(compositor_frame_submitted_);
    EXPECT_EQ(
        viz::BeginFrameAck(current_begin_frame_args_.source_id,
                           current_begin_frame_args_.sequence_number, true),
        frame_data_->begin_frame_ack);
    EndTest();
  }

  void AfterTest() override { EXPECT_TRUE(layers_drawn_); }

 private:
  bool compositor_frame_submitted_ = false;
  bool layers_drawn_ = false;
  viz::BeginFrameArgs current_begin_frame_args_;
  LayerTreeHostImpl::FrameData* frame_data_;
};

MULTI_THREAD_BLOCKNOTIFY_TEST_F(LayerTreeHostTestBeginFrameAcks);

class LayerTreeHostTestQueueImageDecode : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_checker_imaging = true;
    settings->min_image_bytes_to_checker = 512 * 1024;
  }

  void WillBeginMainFrame() override {
    if (!first_)
      return;
    first_ = false;

    image_ = DrawImage(CreateDiscardablePaintImage(gfx::Size(400, 400)),
                       SkIRect::MakeWH(400, 400), kNone_SkFilterQuality,
                       SkMatrix::I(), PaintImage::kDefaultFrameIndex,
                       gfx::ColorSpace());
    auto callback =
        base::Bind(&LayerTreeHostTestQueueImageDecode::ImageDecodeFinished,
                   base::Unretained(this));
    // Schedule the decode twice for the same image.
    layer_tree_host()->QueueImageDecode(image_.paint_image(), callback);
    layer_tree_host()->QueueImageDecode(image_.paint_image(), callback);
  }

  void ReadyToCommitOnThread(LayerTreeHostImpl* impl) override {
    if (one_commit_done_)
      return;
    EXPECT_TRUE(
        impl->tile_manager()->checker_image_tracker().ShouldCheckerImage(
            image_, WhichTree::PENDING_TREE));
    // Reset the tracker as if it has never seen this image.
    impl->tile_manager()->checker_image_tracker().ClearTracker(true);
  }

  void CommitCompleteOnThread(LayerTreeHostImpl* impl) override {
    one_commit_done_ = true;
    EXPECT_FALSE(
        impl->tile_manager()->checker_image_tracker().ShouldCheckerImage(
            image_, WhichTree::PENDING_TREE));
  }

  void ImageDecodeFinished(bool decode_succeeded) {
    EXPECT_TRUE(decode_succeeded);
    ++finished_decode_count_;
    EXPECT_LE(finished_decode_count_, 2);
    if (finished_decode_count_ == 2)
      EndTest();
  }

  void AfterTest() override {}

 private:
  bool first_ = true;
  bool one_commit_done_ = false;
  int finished_decode_count_ = 0;
  DrawImage image_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestQueueImageDecode);

class LayerTreeHostTestQueueImageDecodeNonLazy : public LayerTreeHostTest {
 protected:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillBeginMainFrame() override {
    if (!first_)
      return;
    first_ = false;

    bitmap_.allocN32Pixels(10, 10);
    PaintImage image = PaintImageBuilder::WithDefault()
                           .set_id(PaintImage::GetNextId())
                           .set_image(SkImage::MakeFromBitmap(bitmap_),
                                      PaintImage::GetNextContentId())
                           .TakePaintImage();
    auto callback = base::Bind(
        &LayerTreeHostTestQueueImageDecodeNonLazy::ImageDecodeFinished,
        base::Unretained(this));
    layer_tree_host()->QueueImageDecode(image, callback);
  }

  void ImageDecodeFinished(bool decode_succeeded) {
    EXPECT_TRUE(decode_succeeded);
    EndTest();
  }

  void AfterTest() override {}

 private:
  bool first_ = true;
  SkBitmap bitmap_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestQueueImageDecodeNonLazy);

class LayerTreeHostTestHudLayerWithLayerLists : public LayerTreeHostTest {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->initial_debug_state.show_paint_rects = true;
    settings->use_layer_lists = true;
  }

  void SetupTree() override {
    LayerTreeHostTest::SetupTree();

    // Build the property trees for the root layer.
    layer_tree_host()->BuildPropertyTreesForTesting();

    // The HUD layer should not have been setup by the property tree building.
    DCHECK_EQ(layer_tree_host()->hud_layer(), nullptr);
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DrawLayersOnThread(LayerTreeHostImpl* host_impl) override { EndTest(); }

  void DidCommit() override {
    auto* hud = layer_tree_host()->hud_layer();
    DCHECK(hud);
    auto* root_layer = layer_tree_host()->root_layer();
    DCHECK_EQ(hud->transform_tree_index(), root_layer->transform_tree_index());
    DCHECK_EQ(hud->clip_tree_index(), root_layer->clip_tree_index());
    DCHECK_EQ(hud->effect_tree_index(), root_layer->effect_tree_index());
    DCHECK_EQ(hud->scroll_tree_index(), root_layer->scroll_tree_index());
  }

  void AfterTest() override {}
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestHudLayerWithLayerLists);

// Verifies that LayerTreeHostClient does not receive frame acks from a released
// LayerTreeFrameSink.
class LayerTreeHostTestDiscardAckAfterRelease : public LayerTreeHostTest {
 protected:
  void SetupTree() override {
    scoped_refptr<Layer> root = Layer::Create();
    root->SetBounds(gfx::Size(10, 10));
    layer_tree_host()->SetRootLayer(std::move(root));
    LayerTreeHostTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void WillReceiveCompositorFrameAckOnThread(
      LayerTreeHostImpl* host_impl) override {
    // This method is called before ack is posted to main thread. This ensures
    // that WillReceiveCompositorFrameAck which we PostTask below will be called
    // before DidReceiveCompositorFrameAck.
    MainThreadTaskRunner()->PostTask(
        FROM_HERE, base::Bind(&LayerTreeHostTestDiscardAckAfterRelease::
                                  WillReceiveCompositorFrameAck,
                              base::Unretained(this)));
  }

  void WillReceiveCompositorFrameAck() {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // For the first commit, don't release the LayerTreeFrameSink. We must
        // receive the ack later on.
        break;
      case 2:
        // Release the LayerTreeFrameSink for the second commit. We'll later
        // check that the ack is discarded.
        layer_tree_host()->SetVisible(false);
        layer_tree_host()->ReleaseLayerTreeFrameSink();
        break;
      default:
        NOTREACHED();
    }
  }

  void DidReceiveCompositorFrameAckOnThread(
      LayerTreeHostImpl* host_impl) override {
    // Since this method is called after ack is posted to main thread, we can be
    // sure that if the ack is not discarded, it will be definitely received
    // before we are in CheckFrameAck.
    MainThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::Bind(&LayerTreeHostTestDiscardAckAfterRelease::CheckFrameAck,
                   base::Unretained(this)));
  }

  void DidReceiveCompositorFrameAck() override { received_ack_ = true; }

  void CheckFrameAck() {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // LayerTreeFrameSink was not released. We must receive the ack.
        EXPECT_TRUE(received_ack_);
        // Cause damage so that we draw and swap.
        layer_tree_host()->root_layer()->SetBackgroundColor(SK_ColorGREEN);
        break;
      case 2:
        // LayerTreeFrameSink was released. The ack must be discarded.
        EXPECT_FALSE(received_ack_);
        EndTest();
        break;
      default:
        NOTREACHED();
    }
    received_ack_ = false;
  }

  void AfterTest() override {}

 private:
  bool received_ack_ = false;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestDiscardAckAfterRelease);

class LayerTreeHostTestImageAnimation : public LayerTreeHostTest {
 public:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  virtual void AddImageOp(const PaintImage& image) = 0;

  void SetupTree() override {
    gfx::Size layer_size(1000, 500);
    content_layer_client_.set_bounds(layer_size);
    content_layer_client_.set_fill_with_nonsolid_color(true);
    std::vector<FrameMetadata> frames = {
        FrameMetadata(true, base::TimeDelta::FromSeconds(1)),
        FrameMetadata(true, base::TimeDelta::FromSeconds(1)),
        FrameMetadata(true, base::TimeDelta::FromSeconds(1))};
    generator_ = sk_make_sp<FakePaintImageGenerator>(
        SkImageInfo::MakeN32Premul(500, 500, SkColorSpace::MakeSRGB()), frames);
    PaintImage image =
        PaintImageBuilder::WithDefault()
            .set_id(PaintImage::GetNextId())
            .set_paint_image_generator(generator_)
            .set_frame_index(0u)
            .set_animation_type(PaintImage::AnimationType::ANIMATED)
            .set_repetition_count(kAnimationLoopOnce)
            .TakePaintImage();
    AddImageOp(image);

    layer_tree_host()->SetRootLayer(
        FakePictureLayer::Create(&content_layer_client_));
    layer_tree_host()->root_layer()->SetBounds(layer_size);
    LayerTreeTest::SetupTree();
  }

  void WillPrepareToDrawOnThread(LayerTreeHostImpl* host_impl) override {
    gfx::Rect image_rect(-1, -1, 502, 502);
    auto* layer = static_cast<PictureLayerImpl*>(
        host_impl->active_tree()->root_layer_for_testing());
    switch (++draw_count_) {
      case 1:
        // First draw, everything is invalid.
        EXPECT_EQ(layer->InvalidationForTesting().bounds(),
                  gfx::Rect(layer->bounds()));
        EXPECT_EQ(layer->update_rect(), gfx::Rect(layer->bounds()));
        EXPECT_EQ(generator_->frames_decoded().size(), 1u);
        EXPECT_EQ(generator_->frames_decoded().count(0u), 1u);
        break;
      case 2:
        // Every frame after the first one should invalidate only the image.
        EXPECT_EQ(layer->InvalidationForTesting().bounds(), image_rect);
        EXPECT_EQ(layer->update_rect(), image_rect);
        EXPECT_EQ(generator_->frames_decoded().size(), 2u);
        EXPECT_EQ(generator_->frames_decoded().count(1u), 1u);
        break;
      case 3:
        EXPECT_EQ(layer->InvalidationForTesting().bounds(), image_rect);
        EXPECT_EQ(layer->update_rect(), image_rect);
        EXPECT_EQ(generator_->frames_decoded().size(), 3u);
        EXPECT_EQ(generator_->frames_decoded().count(2u), 1u);
        break;
      default:
        // Only 3 draws should happen for 3 frames of the animate image.
        NOTREACHED();
    }

    if (draw_count_ == 3)
      EndTest();
  }

  void AfterTest() override {
    EXPECT_EQ(generator_->frames_decoded().size(), 3u);
  }

 protected:
  FakeContentLayerClient content_layer_client_;
  sk_sp<FakePaintImageGenerator> generator_;
  int draw_count_ = 0;
};

class LayerTreeHostTestImageAnimationDrawImage
    : public LayerTreeHostTestImageAnimation {
  void AddImageOp(const PaintImage& image) override {
    content_layer_client_.add_draw_image(image, gfx::Point(0, 0), PaintFlags());
  }
};

MULTI_THREAD_TEST_F(LayerTreeHostTestImageAnimationDrawImage);

class LayerTreeHostTestImageAnimationDrawImageShader
    : public LayerTreeHostTestImageAnimation {
  void AddImageOp(const PaintImage& image) override {
    PaintFlags flags;
    flags.setShader(
        PaintShader::MakeImage(image, SkShader::TileMode::kRepeat_TileMode,
                               SkShader::TileMode::kRepeat_TileMode, nullptr));
    content_layer_client_.add_draw_rect(gfx::Rect(500, 500), flags);
  }
};

MULTI_THREAD_TEST_F(LayerTreeHostTestImageAnimationDrawImageShader);

class LayerTreeHostTestImageAnimationDrawRecordShader
    : public LayerTreeHostTestImageAnimation {
  void AddImageOp(const PaintImage& image) override {
    auto record = sk_make_sp<PaintOpBuffer>();
    record->push<DrawImageOp>(image, 0.f, 0.f, nullptr);
    PaintFlags flags;
    flags.setShader(PaintShader::MakePaintRecord(
        record, SkRect::MakeWH(500, 500), SkShader::TileMode::kClamp_TileMode,
        SkShader::TileMode::kClamp_TileMode, nullptr));
    content_layer_client_.add_draw_rect(gfx::Rect(500, 500), flags);
  }
};

MULTI_THREAD_TEST_F(LayerTreeHostTestImageAnimationDrawRecordShader);

class LayerTreeHostTestImageAnimationPaintFilter
    : public LayerTreeHostTestImageAnimation {
  void AddImageOp(const PaintImage& image) override {
    auto record = sk_make_sp<PaintOpBuffer>();
    record->push<DrawImageOp>(image, 0.f, 0.f, nullptr);
    PaintFlags flags;
    flags.setImageFilter(
        sk_make_sp<RecordPaintFilter>(record, SkRect::MakeWH(500, 500)));
    content_layer_client_.add_draw_rect(gfx::Rect(500, 500), flags);
  }
};

MULTI_THREAD_TEST_F(LayerTreeHostTestImageAnimationPaintFilter);

class LayerTreeHostTestImageAnimationSynchronousScheduling
    : public LayerTreeHostTestImageAnimationDrawImage {
 public:
  void InitializeSettings(LayerTreeSettings* settings) override {
    LayerTreeHostTestImageAnimation::InitializeSettings(settings);
    settings->using_synchronous_renderer_compositor = true;
  }
};

MULTI_THREAD_TEST_F(LayerTreeHostTestImageAnimationSynchronousScheduling);

class LayerTreeHostTestImageDecodingHints : public LayerTreeHostTest {
 public:
  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void SetupTree() override {
    gfx::Size layer_size(100, 100);
    content_layer_client_.set_bounds(layer_size);
    content_layer_client_.set_fill_with_nonsolid_color(true);
    PaintImage async_image =
        PaintImageBuilder::WithCopy(
            CreateDiscardablePaintImage(gfx::Size(10, 10)))
            .set_id(1)
            .set_decoding_mode(PaintImage::DecodingMode::kAsync)
            .TakePaintImage();
    PaintImage sync_image =
        PaintImageBuilder::WithCopy(
            CreateDiscardablePaintImage(gfx::Size(10, 10)))
            .set_id(2)
            .set_decoding_mode(PaintImage::DecodingMode::kSync)
            .TakePaintImage();
    PaintImage unspecified_image =
        PaintImageBuilder::WithCopy(
            CreateDiscardablePaintImage(gfx::Size(10, 10)))
            .set_id(3)
            .set_decoding_mode(PaintImage::DecodingMode::kUnspecified)
            .TakePaintImage();
    content_layer_client_.add_draw_image(async_image, gfx::Point(0, 0),
                                         PaintFlags());
    content_layer_client_.add_draw_image(sync_image, gfx::Point(1, 2),
                                         PaintFlags());
    content_layer_client_.add_draw_image(unspecified_image, gfx::Point(3, 4),
                                         PaintFlags());

    layer_tree_host()->SetRootLayer(
        FakePictureLayer::Create(&content_layer_client_));
    layer_tree_host()->root_layer()->SetBounds(layer_size);
    LayerTreeTest::SetupTree();
  }

  void WillPrepareToDrawOnThread(LayerTreeHostImpl* host_impl) override {
    auto& tracker = host_impl->tile_manager()->checker_image_tracker();
    EXPECT_EQ(tracker.get_decoding_mode_hint_for_testing(1),
              PaintImage::DecodingMode::kAsync);
    EXPECT_EQ(tracker.get_decoding_mode_hint_for_testing(2),
              PaintImage::DecodingMode::kSync);
    EXPECT_EQ(tracker.get_decoding_mode_hint_for_testing(3),
              PaintImage::DecodingMode::kUnspecified);
    EndTest();
  }

  void AfterTest() override {}

 private:
  FakeContentLayerClient content_layer_client_;
};

MULTI_THREAD_TEST_F(LayerTreeHostTestImageDecodingHints);

class LayerTreeHostTestCheckerboardUkm : public LayerTreeHostTest {
 public:
  LayerTreeHostTestCheckerboardUkm() : url_(GURL("https://example.com")) {}

  void BeginTest() override {
    PostSetNeedsCommitToMainThread();
    layer_tree_host()->SetURLForUkm(url_);
  }

  void SetupTree() override {
    gfx::Size layer_size(100, 100);
    content_layer_client_.set_bounds(layer_size);
    content_layer_client_.set_fill_with_nonsolid_color(true);
    layer_tree_host()->SetRootLayer(
        FakePictureLayer::Create(&content_layer_client_));
    layer_tree_host()->root_layer()->SetBounds(layer_size);
    LayerTreeTest::SetupTree();
  }

  void DidActivateTreeOnThread(LayerTreeHostImpl* impl) override {
    if (impl->active_tree()->source_frame_number() != 0)
      return;

    // We have an active tree. Start a pinch gesture so we start recording
    // stats.
    impl->PinchGestureBegin();
  }

  void DrawLayersOnThread(LayerTreeHostImpl* impl) override {
    if (!impl->pinch_gesture_active())
      return;

    // We just drew a frame, stats for it should have been recorded. End the
    // gesture so they are flushed to the recorder.
    impl->PinchGestureEnd(gfx::Point(50, 50), false);

    // RenewTreePriority will run when the smoothness expiration timer fires.
    // Synthetically do it here so the UkmManager is notified.
    impl->RenewTreePriorityForTesting();

    auto* recorder = static_cast<ukm::TestUkmRecorder*>(
        impl->ukm_manager()->recorder_for_testing());

    const auto& entries = recorder->GetEntriesByName(kUserInteraction);
    EXPECT_EQ(1u, entries.size());
    for (const auto* entry : entries) {
      recorder->ExpectEntrySourceHasUrl(entry, url_);
      recorder->ExpectEntryMetric(entry, kCheckerboardArea, 0);
      recorder->ExpectEntryMetric(entry, kMissingTiles, 0);
      recorder->ExpectEntryMetric(entry, kCheckerboardAreaRatio, 0);
    }

    EndTest();
  }

  void AfterTest() override {}

 private:
  const GURL url_;
  FakeContentLayerClient content_layer_client_;
};

// Only multi-thread mode needs to record UKMs.
MULTI_THREAD_TEST_F(LayerTreeHostTestCheckerboardUkm);

class DontUpdateLayersWithEmptyBounds : public LayerTreeTest {
 protected:
  void SetupTree() override {
    auto root = FakePictureLayer::Create(&root_client_);
    child_ = FakePictureLayer::Create(&child_client_);
    mask_ = FakePictureLayer::Create(&mask_client_);

    // Add a lot of draw ops, to make sure the recording source
    // hits the early out and avoids being detected as solid color even
    // though it is empty. This ensures we hit later code paths that would
    // early out if solid color in CanHaveTilings().
    PaintFlags flags;
    flags.setColor(SK_ColorRED);
    for (int i = 0; i < 100; ++i) {
      child_client_.add_draw_rect(gfx::Rect(3, 3), flags);
      mask_client_.add_draw_rect(gfx::Rect(2, 2), flags);
    }

    root_client_.set_bounds(gfx::Size(10, 10));
    root->SetBounds(gfx::Size(10, 10));

    child_client_.set_bounds(gfx::Size(9, 9));
    child_->SetBounds(gfx::Size(9, 9));
    mask_client_.set_bounds(gfx::Size(9, 9));
    mask_->SetBounds(gfx::Size(9, 9));

    child_->SetMaskLayer(mask_.get());
    root->AddChild(child_);
    layer_tree_host()->SetRootLayer(std::move(root));
    LayerTreeTest::SetupTree();
  }

  void BeginTest() override { PostSetNeedsCommitToMainThread(); }

  void DidCommit() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        // The child and mask are updated when they have non-empty bounds.
        EXPECT_EQ(1, child_->update_count());
        EXPECT_EQ(1, mask_->update_count());

        // The child and mask become empty bounds.
        child_client_.set_bounds(gfx::Size());
        child_->SetBounds(gfx::Size());
        mask_client_.set_bounds(gfx::Size());
        mask_->SetBounds(gfx::Size());
        break;
      case 2: {
        scoped_refptr<RasterSource> child_raster =
            child_->GetRecordingSourceForTesting()->CreateRasterSource();
        EXPECT_FALSE(child_raster->IsSolidColor());
        scoped_refptr<RasterSource> mask_raster =
            mask_->GetRecordingSourceForTesting()->CreateRasterSource();
        EXPECT_FALSE(mask_raster->IsSolidColor());
      }

        // The child and mask are not updated when they have empty bounds.
        EXPECT_EQ(1, child_->update_count());
        EXPECT_EQ(1, mask_->update_count());
        EndTest();
        break;
      default:
        ADD_FAILURE() << layer_tree_host()->SourceFrameNumber();
    }
  }

  void AfterTest() override {}

  scoped_refptr<FakePictureLayer> child_;
  scoped_refptr<FakePictureLayer> mask_;
  FakeContentLayerClient root_client_;
  FakeContentLayerClient child_client_;
  FakeContentLayerClient mask_client_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(DontUpdateLayersWithEmptyBounds);

// Verifies that if we have a new LocalSurfaceId we submit a CompositorFrame
// even if there is no damage.
class LayerTreeHostTestNewLocalSurfaceIdForcesDraw : public LayerTreeHostTest {
 public:
  LayerTreeHostTestNewLocalSurfaceIdForcesDraw() {}

  void InitializeSettings(LayerTreeSettings* settings) override {
    settings->enable_surface_synchronization = true;
  }

  void BeginTest() override {
    layer_tree_host()->SetViewportSizeAndScale(gfx::Size(10, 10), 1.f,
                                               viz::LocalSurfaceId());
    layer_tree_host()->root_layer()->SetBounds(gfx::Size(10, 10));
    local_surface_id_ = allocator_.GenerateId();
    PostSetLocalSurfaceIdToMainThread(local_surface_id_);
  }

  void DidReceiveCompositorFrameAck() override {
    switch (layer_tree_host()->SourceFrameNumber()) {
      case 1:
        local_surface_id_ = allocator_.GenerateId();
        PostSetLocalSurfaceIdToMainThread(local_surface_id_);
        break;
      case 2:
        EndTest();
        break;
      default:
        NOTREACHED();
    }
  }

  void AfterTest() override {}
  viz::LocalSurfaceId local_surface_id_;
  viz::ParentLocalSurfaceIdAllocator allocator_;
};

SINGLE_AND_MULTI_THREAD_TEST_F(LayerTreeHostTestNewLocalSurfaceIdForcesDraw);

}  // namespace
}  // namespace cc

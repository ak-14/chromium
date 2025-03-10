// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/android/overscroll_controller_android.h"
#include <memory>
#include "base/macros.h"
#include "cc/layers/layer.h"
#include "content/public/common/use_zoom_for_dsf_policy.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_gesture_event.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "ui/android/overscroll_glow.h"
#include "ui/android/overscroll_refresh.h"
#include "ui/android/resources/resource_manager_impl.h"
#include "ui/android/window_android_compositor.h"
#include "ui/events/base_event_utils.h"
#include "ui/events/blink/did_overscroll_params.h"

using ui::EdgeEffectBase;
using ui::ResourceManager;
using ui::OverscrollGlow;
using ui::OverscrollGlowClient;
using ui::OverscrollRefresh;
using ui::WindowAndroidCompositor;
using ::testing::_;
using ::testing::Return;

namespace content {

namespace {

class MockCompositor : public WindowAndroidCompositor {
 public:
  ~MockCompositor() override {}
  base::WeakPtr<ui::WindowAndroidCompositor> GetWeakPtr() override {
    return nullptr;
  }
  void IncrementReadbackRequestCount() override {}
  void DecrementReadbackRequestCount() override {}
  void RequestCopyOfOutputOnRootLayer(
      std::unique_ptr<viz::CopyOutputRequest>) override {}
  void SetNeedsAnimate() override {}
  MOCK_METHOD0(GetResourceManager, ResourceManager&());
  MOCK_METHOD0(GetFrameSinkId, viz::FrameSinkId());
  void AddChildFrameSink(const viz::FrameSinkId& frame_sink_id) override {}
  void RemoveChildFrameSink(const viz::FrameSinkId& frame_sink_id) override {}
  std::unique_ptr<ui::CompositorLock> GetCompositorLock(
      ui::CompositorLockClient* client,
      base::TimeDelta timeout) override {
    return nullptr;
  }
  bool IsDrawingFirstVisibleFrame() const override { return false; }
};

class MockGlowClient : public OverscrollGlowClient {
 public:
  MOCK_METHOD0(CreateEdgeEffect, std::unique_ptr<EdgeEffectBase>());
};

class MockGlow : public OverscrollGlow {
 public:
  MockGlow() : OverscrollGlow(new MockGlowClient()) {}
  MOCK_METHOD5(OnOverscrolled,
               bool(base::TimeTicks,
                    gfx::Vector2dF,
                    gfx::Vector2dF,
                    gfx::Vector2dF,
                    gfx::Vector2dF));
};

class MockRefresh : public OverscrollRefresh {
 public:
  MockRefresh() : OverscrollRefresh() {}
  MOCK_METHOD0(OnOverscrolled, void());
  MOCK_METHOD0(Reset, void());
  MOCK_CONST_METHOD0(IsActive, bool());
  MOCK_CONST_METHOD0(IsAwaitingScrollUpdateAck, bool());
};

class OverscrollControllerAndroidUnitTest : public testing::Test {
 public:
  OverscrollControllerAndroidUnitTest() {
    dip_scale_ = 560;
    std::unique_ptr<MockGlow> glow_ptr = std::make_unique<MockGlow>();
    std::unique_ptr<MockRefresh> refresh_ptr = std::make_unique<MockRefresh>();
    compositor_ = std::make_unique<MockCompositor>();
    glow_ = glow_ptr.get();
    refresh_ = refresh_ptr.get();
    controller_ = OverscrollControllerAndroid::CreateForTests(
        compositor_.get(), dip_scale_, std::move(glow_ptr),
        std::move(refresh_ptr));
  }

  ui::DidOverscrollParams CreateVerticalOverscrollParams() {
    ui::DidOverscrollParams params;
    params.accumulated_overscroll = gfx::Vector2dF(0, 1);
    params.latest_overscroll_delta = gfx::Vector2dF(0, 1);
    params.current_fling_velocity = gfx::Vector2dF(0, 1);
    params.causal_event_viewport_point = gfx::PointF(100, 100);
    if (IsUseZoomForDSFEnabled()) {
      params.accumulated_overscroll.Scale(dip_scale_);
      params.latest_overscroll_delta.Scale(dip_scale_);
      params.current_fling_velocity.Scale(dip_scale_);
      params.causal_event_viewport_point.Scale(dip_scale_);
    }
    return params;
  }

 protected:
  MockGlow* glow_;
  MockRefresh* refresh_;
  std::unique_ptr<MockCompositor> compositor_;
  std::unique_ptr<OverscrollControllerAndroid> controller_;
  float dip_scale_;
};

TEST_F(OverscrollControllerAndroidUnitTest,
       OverscrollBehaviorAutoAllowsGlowAndNavigation) {
  ui::DidOverscrollParams params = CreateVerticalOverscrollParams();
  params.overscroll_behavior.y = cc::OverscrollBehavior::
      OverscrollBehaviorType::kOverscrollBehaviorTypeAuto;

  EXPECT_CALL(*refresh_, OnOverscrolled());
  EXPECT_CALL(*refresh_, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*refresh_, IsAwaitingScrollUpdateAck()).Times(0);
  EXPECT_CALL(*glow_, OnOverscrolled(_, _, _, _, _)).Times(0);

  controller_->OnOverscrolled(params);
  testing::Mock::VerifyAndClearExpectations(&refresh_);
}

TEST_F(OverscrollControllerAndroidUnitTest,
       OverscrollBehaviorContainPreventsNavigation) {
  ui::DidOverscrollParams params = CreateVerticalOverscrollParams();
  params.overscroll_behavior.y = cc::OverscrollBehavior::
      OverscrollBehaviorType::kOverscrollBehaviorTypeContain;

  EXPECT_CALL(*refresh_, OnOverscrolled()).Times(0);
  EXPECT_CALL(*refresh_, Reset());
  EXPECT_CALL(*refresh_, IsActive()).WillOnce(Return(false));
  EXPECT_CALL(*refresh_, IsAwaitingScrollUpdateAck()).WillOnce(Return(false));
  EXPECT_CALL(*glow_,
              OnOverscrolled(_, gfx::Vector2dF(0, 560), gfx::Vector2dF(0, 560),
                             gfx::Vector2dF(0, 560), _));

  controller_->OnOverscrolled(params);
  testing::Mock::VerifyAndClearExpectations(refresh_);
  testing::Mock::VerifyAndClearExpectations(glow_);

  // Test that the "contain" set on x-axis would not affect navigation.
  params.overscroll_behavior.y = cc::OverscrollBehavior::
      OverscrollBehaviorType::kOverscrollBehaviorTypeAuto;
  params.overscroll_behavior.x = cc::OverscrollBehavior::
      OverscrollBehaviorType::kOverscrollBehaviorTypeContain;

  EXPECT_CALL(*refresh_, OnOverscrolled());
  EXPECT_CALL(*refresh_, Reset()).Times(0);
  EXPECT_CALL(*refresh_, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*refresh_, IsAwaitingScrollUpdateAck()).Times(0);
  EXPECT_CALL(*glow_, OnOverscrolled(_, _, _, _, _)).Times(0);

  controller_->OnOverscrolled(params);
  testing::Mock::VerifyAndClearExpectations(refresh_);
  testing::Mock::VerifyAndClearExpectations(glow_);
}

TEST_F(OverscrollControllerAndroidUnitTest,
       OverscrollBehaviorNonePreventsNavigationAndGlow) {
  ui::DidOverscrollParams params = CreateVerticalOverscrollParams();
  params.overscroll_behavior.y = cc::OverscrollBehavior::
      OverscrollBehaviorType::kOverscrollBehaviorTypeNone;

  EXPECT_CALL(*refresh_, OnOverscrolled()).Times(0);
  EXPECT_CALL(*refresh_, Reset());
  EXPECT_CALL(*refresh_, IsActive()).WillOnce(Return(false));
  EXPECT_CALL(*refresh_, IsAwaitingScrollUpdateAck()).WillOnce(Return(false));
  EXPECT_CALL(*glow_, OnOverscrolled(_, gfx::Vector2dF(), gfx::Vector2dF(),
                                     gfx::Vector2dF(), _));

  controller_->OnOverscrolled(params);
  testing::Mock::VerifyAndClearExpectations(refresh_);
  testing::Mock::VerifyAndClearExpectations(glow_);

  // Test that the "none" set on y-axis would not affect glow on x-axis.
  params.accumulated_overscroll = gfx::Vector2dF(1, 1);
  params.latest_overscroll_delta = gfx::Vector2dF(1, 1);
  params.current_fling_velocity = gfx::Vector2dF(1, 1);
  if (IsUseZoomForDSFEnabled()) {
    params.accumulated_overscroll.Scale(dip_scale_);
    params.latest_overscroll_delta.Scale(dip_scale_);
    params.current_fling_velocity.Scale(dip_scale_);
  }

  EXPECT_CALL(*refresh_, OnOverscrolled()).Times(0);
  EXPECT_CALL(*refresh_, Reset());
  EXPECT_CALL(*refresh_, IsActive()).WillOnce(Return(false));
  EXPECT_CALL(*refresh_, IsAwaitingScrollUpdateAck()).WillOnce(Return(false));
  EXPECT_CALL(*glow_,
              OnOverscrolled(_, gfx::Vector2dF(560, 0), gfx::Vector2dF(560, 0),
                             gfx::Vector2dF(560, 0), _));

  controller_->OnOverscrolled(params);
  testing::Mock::VerifyAndClearExpectations(refresh_);
  testing::Mock::VerifyAndClearExpectations(glow_);
}

TEST_F(OverscrollControllerAndroidUnitTest,
       ConsumedUpdateDoesNotResetEnabledRefresh) {
  ui::DidOverscrollParams params = CreateVerticalOverscrollParams();
  params.overscroll_behavior.y = cc::OverscrollBehavior::
      OverscrollBehaviorType::kOverscrollBehaviorTypeAuto;

  EXPECT_CALL(*refresh_, OnOverscrolled());
  EXPECT_CALL(*refresh_, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*refresh_, IsAwaitingScrollUpdateAck()).WillOnce(Return(false));
  EXPECT_CALL(*refresh_, Reset()).Times(0);

  // Enable the refresh effect.
  controller_->OnOverscrolled(params);

  // Generate a consumed scroll update.
  blink::WebGestureEvent event(
      blink::WebInputEvent::kGestureScrollUpdate,
      blink::WebInputEvent::kNoModifiers,
      ui::EventTimeStampToSeconds(ui::EventTimeForNow()));
  controller_->OnGestureEventAck(event, INPUT_EVENT_ACK_STATE_CONSUMED);

  testing::Mock::VerifyAndClearExpectations(&refresh_);
}

}  // namespace

}  // namespace content

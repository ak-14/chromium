// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/media/capture/frame_sink_video_capture_device.h"

#include <memory>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/containers/flat_map.h"
#include "content/public/test/test_browser_thread_bundle.h"
#include "content/public/test/test_utils.h"
#include "media/base/video_frame.h"
#include "media/capture/video/video_frame_receiver.h"
#include "media/capture/video_capture_types.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "services/viz/privileged/interfaces/compositing/frame_sink_video_capture.mojom.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/native_widget_types.h"

using testing::_;
using testing::ByRef;
using testing::Eq;
using testing::Expectation;
using testing::Ge;
using testing::NiceMock;
using testing::NotNull;
using testing::SaveArg;
using testing::Sequence;
using testing::StrNe;

namespace content {
namespace {

// Threading notes: Throughout these tests, the UI thread (the main test
// thread) represents the executor of all external-to-device operations. This
// means that it represents everything that runs on the UI thread in the browser
// process, plus anything that would run in the VIZ process. The IO thread is
// used as the "device thread" for content::FrameSinkVideoCaptureDevice.
#define DCHECK_ON_DEVICE_THREAD() DCHECK_CURRENTLY_ON(BrowserThread::IO)
#define DCHECK_NOT_ON_DEVICE_THREAD() DCHECK_CURRENTLY_ON(BrowserThread::UI)

// Convenience macro to block the test procedure and run all pending UI tasks.
#define RUN_UI_TASKS() RunAllPendingInMessageLoop(BrowserThread::UI)

// Convenience macro to post a task to run on the device thread.
#define POST_DEVICE_TASK(closure) \
  BrowserThread::PostTask(BrowserThread::IO, FROM_HERE, closure)

// Convenience macro to block the test procedure until all pending tasks have
// run on the device thread.
#define WAIT_FOR_DEVICE_TASKS() RunAllPendingInMessageLoop(BrowserThread::IO)

// Capture parameters.
constexpr gfx::Size kResolution = gfx::Size(320, 180);
constexpr int kMaxFrameRate = 25;  // It evenly divides 1 million usec.
constexpr base::TimeDelta kMinCapturePeriod = base::TimeDelta::FromMicroseconds(
    base::Time::kMicrosecondsPerSecond / kMaxFrameRate);
constexpr media::VideoPixelFormat kFormat = media::PIXEL_FORMAT_I420;

// Helper to return the capture parameters packaged in a VideoCaptureParams.
media::VideoCaptureParams GetCaptureParams() {
  media::VideoCaptureParams params;
  params.requested_format =
      media::VideoCaptureFormat(kResolution, kMaxFrameRate, kFormat);
  return params;
}

// Mock for the FrameSinkVideoCapturer running in the VIZ process.
class MockFrameSinkVideoCapturer : public viz::mojom::FrameSinkVideoCapturer {
 public:
  MockFrameSinkVideoCapturer() : binding_(this) {}

  bool is_bound() const { return binding_.is_bound(); }

  void Bind(viz::mojom::FrameSinkVideoCapturerRequest request) {
    DCHECK_NOT_ON_DEVICE_THREAD();
    binding_.Bind(std::move(request));
  }

  MOCK_METHOD2(SetFormat,
               void(media::VideoPixelFormat format,
                    media::ColorSpace color_space));
  MOCK_METHOD1(SetMinCapturePeriod, void(base::TimeDelta min_period));
  MOCK_METHOD1(SetMinSizeChangePeriod, void(base::TimeDelta));
  MOCK_METHOD3(SetResolutionConstraints,
               void(const gfx::Size& min_size,
                    const gfx::Size& max_size,
                    bool use_fixed_aspect_ratio));
  MOCK_METHOD1(SetAutoThrottlingEnabled, void(bool));
  MOCK_METHOD1(ChangeTarget, void(const viz::FrameSinkId& frame_sink_id));
  void Start(viz::mojom::FrameSinkVideoConsumerPtr consumer) final {
    DCHECK_NOT_ON_DEVICE_THREAD();
    consumer_ = std::move(consumer);
    MockStart(consumer_.get());
  }
  MOCK_METHOD1(MockStart, void(viz::mojom::FrameSinkVideoConsumer* consumer));
  void Stop() final {
    DCHECK_NOT_ON_DEVICE_THREAD();
    consumer_.reset();
    MockStop();
  }
  MOCK_METHOD0(MockStop, void());
  MOCK_METHOD0(RequestRefreshFrame, void());

 private:
  mojo::Binding<viz::mojom::FrameSinkVideoCapturer> binding_;
  viz::mojom::FrameSinkVideoConsumerPtr consumer_;
};

// Represents the FrameSinkVideoConsumerFrameCallbacks instance in the VIZ
// process.
class MockFrameSinkVideoConsumerFrameCallbacks
    : public viz::mojom::FrameSinkVideoConsumerFrameCallbacks {
 public:
  MockFrameSinkVideoConsumerFrameCallbacks() : binding_(this) {}

  void Bind(viz::mojom::FrameSinkVideoConsumerFrameCallbacksRequest request) {
    DCHECK_NOT_ON_DEVICE_THREAD();
    binding_.Bind(std::move(request));
  }

  MOCK_METHOD0(Done, void());
  MOCK_METHOD1(ProvideFeedback, void(double utilization));

 private:
  mojo::Binding<viz::mojom::FrameSinkVideoConsumerFrameCallbacks> binding_;
};

// Mock for the VideoFrameReceiver, the point-of-injection of video frames into
// the video capture stack. It's mocked methods are called on the device thread.
// Some methods stash objects of interest, which test code must grab via the
// TakeXYZ() utility methods (called on the main thread).
class MockVideoFrameReceiver : public media::VideoFrameReceiver {
 public:
  using Buffer = media::VideoCaptureDevice::Client::Buffer;

  ~MockVideoFrameReceiver() override {
    DCHECK_ON_DEVICE_THREAD();
    EXPECT_TRUE(handle_providers_.empty());
    EXPECT_TRUE(feedback_ids_.empty());
    EXPECT_TRUE(access_permissions_.empty());
    EXPECT_TRUE(frame_infos_.empty());
  }

  void OnNewBufferHandle(
      int buffer_id,
      std::unique_ptr<Buffer::HandleProvider> handle_provider) final {
    DCHECK_ON_DEVICE_THREAD();
    auto* const raw_pointer = handle_provider.get();
    handle_providers_[buffer_id] = std::move(handle_provider);
    MockOnNewBufferHandle(buffer_id, raw_pointer);
  }
  MOCK_METHOD2(MockOnNewBufferHandle,
               void(int buffer_id, Buffer::HandleProvider* handle_provider));
  void OnFrameReadyInBuffer(
      int buffer_id,
      int frame_feedback_id,
      std::unique_ptr<Buffer::ScopedAccessPermission> buffer_read_permission,
      media::mojom::VideoFrameInfoPtr frame_info) final {
    DCHECK_ON_DEVICE_THREAD();
    feedback_ids_[buffer_id] = frame_feedback_id;
    auto* const raw_pointer_to_permission = buffer_read_permission.get();
    access_permissions_[buffer_id] = std::move(buffer_read_permission);
    auto* const raw_pointer_to_info = frame_info.get();
    frame_infos_[buffer_id] = std::move(frame_info);
    MockOnFrameReadyInBuffer(buffer_id, frame_feedback_id,
                             raw_pointer_to_permission, raw_pointer_to_info);
  }
  MOCK_METHOD4(MockOnFrameReadyInBuffer,
               void(int buffer_id,
                    int frame_feedback_id,
                    Buffer::ScopedAccessPermission* buffer_read_permission,
                    const media::mojom::VideoFrameInfo* frame_info));
  MOCK_METHOD1(OnBufferRetired, void(int buffer_id));
  MOCK_METHOD0(OnError, void());
  MOCK_METHOD1(OnLog, void(const std::string& message));
  MOCK_METHOD0(OnStarted, void());
  void OnStartedUsingGpuDecode() final { NOTREACHED(); }

  mojo::ScopedSharedBufferHandle TakeBufferHandle(int buffer_id) {
    DCHECK_NOT_ON_DEVICE_THREAD();
    const auto it = handle_providers_.find(buffer_id);
    if (it == handle_providers_.end()) {
      ADD_FAILURE() << "Missing entry for buffer_id=" << buffer_id;
      return mojo::ScopedSharedBufferHandle();
    }
    auto buffer = it->second->GetHandleForInterProcessTransit(true);
    handle_providers_.erase(it);
    return buffer;
  }

  int TakeFeedbackId(int buffer_id) {
    DCHECK_NOT_ON_DEVICE_THREAD();
    const auto it = feedback_ids_.find(buffer_id);
    if (it == feedback_ids_.end()) {
      ADD_FAILURE() << "Missing entry for buffer_id=" << buffer_id;
      return -1;
    }
    const int feedback_id = it->second;
    feedback_ids_.erase(it);
    return feedback_id;
  }

  void ReleaseAccessPermission(int buffer_id) {
    DCHECK_NOT_ON_DEVICE_THREAD();
    const auto it = access_permissions_.find(buffer_id);
    if (it == access_permissions_.end()) {
      ADD_FAILURE() << "Missing entry for buffer_id=" << buffer_id;
      return;
    }
    access_permissions_.erase(it);
  }

  media::mojom::VideoFrameInfoPtr TakeVideoFrameInfo(int buffer_id) {
    DCHECK_NOT_ON_DEVICE_THREAD();
    const auto it = frame_infos_.find(buffer_id);
    if (it == frame_infos_.end()) {
      ADD_FAILURE() << "Missing entry for buffer_id=" << buffer_id;
      return media::mojom::VideoFrameInfoPtr();
    }
    media::mojom::VideoFrameInfoPtr info = std::move(it->second);
    frame_infos_.erase(it);
    return info;
  }

 private:
  base::flat_map<int, std::unique_ptr<Buffer::HandleProvider>>
      handle_providers_;
  base::flat_map<int, int> feedback_ids_;
  base::flat_map<int, std::unique_ptr<Buffer::ScopedAccessPermission>>
      access_permissions_;
  base::flat_map<int, media::mojom::VideoFrameInfoPtr> frame_infos_;
};

// Convenience macros to make a non-blocking FrameSinkVideoCaptureDevice method
// call on the device thread.
#define POST_DEVICE_METHOD_CALL0(method)                                \
  POST_DEVICE_TASK(base::BindOnce(&FrameSinkVideoCaptureDevice::method, \
                                  base::Unretained(device_.get())))
#define POST_DEVICE_METHOD_CALL(method, ...)                            \
  POST_DEVICE_TASK(base::BindOnce(&FrameSinkVideoCaptureDevice::method, \
                                  base::Unretained(device_.get()),      \
                                  __VA_ARGS__))

class FrameSinkVideoCaptureDeviceTest : public testing::Test {
 public:
  FrameSinkVideoCaptureDeviceTest()
      : browser_threads_(TestBrowserThreadBundle::REAL_IO_THREAD) {}

  ~FrameSinkVideoCaptureDeviceTest() override { EXPECT_FALSE(device_); }

  void SetUp() override {
    // Create the FrameSinkVideoCaptureDevice on the device thread, and block
    // until complete.
    POST_DEVICE_TASK(base::BindOnce(
        [](FrameSinkVideoCaptureDeviceTest* test) {
          test->device_ = std::make_unique<FrameSinkVideoCaptureDevice>();
        },
        this));
    WAIT_FOR_DEVICE_TASKS();

    // Set an override to "create" the mock capturer instance instead of the
    // real thing.
    device_->SetCapturerCreatorForTesting(base::BindRepeating(
        [](MockFrameSinkVideoCapturer* capturer) {
          DCHECK_CURRENTLY_ON(BrowserThread::UI);
          viz::mojom::FrameSinkVideoCapturerPtr capturer_ptr;
          capturer->Bind(mojo::MakeRequest(&capturer_ptr));
          return capturer_ptr.PassInterface();
        },
        &capturer_));
  }

  void TearDown() override {
    // Destroy the FrameSinkVideoCaptureDevice on the device thread, and block
    // until complete.
    POST_DEVICE_TASK(base::BindOnce(
        [](FrameSinkVideoCaptureDeviceTest* test) { test->device_.reset(); },
        this));
    WAIT_FOR_DEVICE_TASKS();
    // Some objects owned by the FrameSinkVideoCaptureDevice may need to be
    // deleted on the UI thread, so run those tasks now.
    RUN_UI_TASKS();
  }

  // Starts-up the FrameSinkVideoCaptureDevice: Sets a frame sink target,
  // creates a capturer, sets the capture parameters; and checks that the mock
  // capturer receives the correct mojo method calls.
  void AllocateAndStartSynchronouslyWithExpectations(
      std::unique_ptr<media::VideoFrameReceiver> receiver) {
    EXPECT_CALL(capturer_, SetFormat(kFormat, _));
    EXPECT_CALL(capturer_, SetMinCapturePeriod(kMinCapturePeriod));
    EXPECT_CALL(capturer_,
                SetResolutionConstraints(kResolution, kResolution, _));
    constexpr viz::FrameSinkId frame_sink_id(1, 1);
    EXPECT_CALL(capturer_, ChangeTarget(frame_sink_id));
    EXPECT_CALL(capturer_, MockStart(NotNull()));

    EXPECT_FALSE(capturer_.is_bound());
    POST_DEVICE_METHOD_CALL(OnTargetChanged, frame_sink_id);
    POST_DEVICE_METHOD_CALL(AllocateAndStartWithReceiver, GetCaptureParams(),
                            std::move(receiver));
    WAIT_FOR_DEVICE_TASKS();
    RUN_UI_TASKS();  // Run the task to create the capturer.
    EXPECT_TRUE(capturer_.is_bound());
    WAIT_FOR_DEVICE_TASKS();  // Run the task where the interface is bound, etc.
  }

  // Stops the FrameSinkVideoCaptureDevice and optionally checks that the mock
  // capturer received the Stop() call.
  void StopAndDeAllocateSynchronouslyWithExpectations(
      bool capturer_stopped_also) {
    EXPECT_CALL(capturer_, MockStop()).Times(capturer_stopped_also ? 1 : 0);
    POST_DEVICE_METHOD_CALL0(StopAndDeAllocate);
    WAIT_FOR_DEVICE_TASKS();
  }

  // Simulates what the VIZ capturer would do: Allocates a shared memory buffer,
  // populates it with video content, and calls OnFrameCaptured().
  void SimulateFrameCapture(
      int frame_number,
      MockFrameSinkVideoConsumerFrameCallbacks* callbacks) {
    // Allocate a buffer and fill it with values based on |frame_number|.
    const size_t buffer_size =
        media::VideoFrame::AllocationSize(kFormat, kResolution);
    mojo::ScopedSharedBufferHandle buffer =
        mojo::SharedBufferHandle::Create(buffer_size);
    memset(buffer->Map(buffer_size).get(), GetFrameFillValue(frame_number),
           buffer_size);

    viz::mojom::FrameSinkVideoConsumerFrameCallbacksPtr callbacks_ptr;
    callbacks->Bind(mojo::MakeRequest(&callbacks_ptr));
    // |callbacks_ptr| is bound on the main thread, so it needs to be re-bound
    // to the device thread before calling OnFrameCaptured().
    POST_DEVICE_TASK(base::BindOnce(
        [](FrameSinkVideoCaptureDevice* device,
           mojo::ScopedSharedBufferHandle buffer, size_t buffer_size,
           int frame_number,
           mojo::InterfacePtrInfo<
               viz::mojom::FrameSinkVideoConsumerFrameCallbacks>
               callbacks_info) {
          device->OnFrameCaptured(
              std::move(buffer), buffer_size,
              media::mojom::VideoFrameInfo::New(
                  kMinCapturePeriod * frame_number,
                  base::Value(base::Value::Type::DICTIONARY), kFormat,
                  kResolution, gfx::Rect(kResolution)),
              gfx::Rect(kResolution), gfx::Rect(kResolution),
              viz::mojom::FrameSinkVideoConsumerFrameCallbacksPtr(
                  std::move(callbacks_info)));
        },
        base::Unretained(device_.get()), std::move(buffer), buffer_size,
        frame_number, callbacks_ptr.PassInterface()));
  }

  // Returns a byte value based on the given |frame_number|.
  static constexpr uint8_t GetFrameFillValue(int frame_number) {
    return (frame_number % 0x3f) << 2;
  }

  // Returns true if the |buffer| is filled with the correct byte value for the
  // given |frame_number|.
  static bool IsExpectedBufferContentForFrame(
      int frame_number,
      mojo::ScopedSharedBufferHandle buffer) {
    const size_t buffer_size =
        media::VideoFrame::AllocationSize(kFormat, kResolution);
    const auto mapping = buffer->Map(buffer_size);
    const uint8_t* src = static_cast<uint8_t*>(mapping.get());
    const uint8_t expected_value = GetFrameFillValue(frame_number);
    for (size_t i = 0; i < buffer_size; ++i) {
      if (src[i] != expected_value) {
        return false;
      }
    }
    return true;
  }

 private:
  // See the threading notes at top of this file.
  TestBrowserThreadBundle browser_threads_;

 protected:
  NiceMock<MockFrameSinkVideoCapturer> capturer_;
  std::unique_ptr<FrameSinkVideoCaptureDevice> device_;
};

// Tests a racy start condition: Ensure that nothing bad happens if
// StopAndDeAllocate() is called before the capturer creation completes.
TEST_F(FrameSinkVideoCaptureDeviceTest,
       AllocatesAndDeallocatesBeforeCapturerCreated) {
  auto receiver = std::make_unique<MockVideoFrameReceiver>();
  EXPECT_CALL(*receiver, OnStarted()).Times(0);
  EXPECT_CALL(*receiver, OnError()).Times(0);

  EXPECT_CALL(capturer_, SetFormat(_, _)).Times(0);
  EXPECT_CALL(capturer_, SetMinCapturePeriod(_)).Times(0);
  EXPECT_CALL(capturer_, SetResolutionConstraints(_, _, _)).Times(0);
  EXPECT_CALL(capturer_, ChangeTarget(_)).Times(0);
  EXPECT_CALL(capturer_, MockStart(_)).Times(0);

  EXPECT_FALSE(capturer_.is_bound());
  POST_DEVICE_METHOD_CALL(AllocateAndStartWithReceiver, GetCaptureParams(),
                          std::move(receiver));
  // A task is pending on the UI thread to create the capturer. Call
  // StopAndDeAllocate() before that task runs.
  POST_DEVICE_METHOD_CALL0(StopAndDeAllocate);
  WAIT_FOR_DEVICE_TASKS();

  // Now, run the task on the UI thread, which will post the reply back to the
  // device thread.
  RUN_UI_TASKS();
  EXPECT_TRUE(capturer_.is_bound());

  // Now, when the reply task on the device thread is run, the
  // FrameSinkVideoCaptureDevice should realize that StopAndDeAllocate() was
  // called in the meantime and abort.
  WAIT_FOR_DEVICE_TASKS();
}

// Tests a normal session, progressing through the start, frame capture, and
// stop phases.
TEST_F(FrameSinkVideoCaptureDeviceTest, CapturesAndDeliversFrames) {
  auto receiver_ptr = std::make_unique<MockVideoFrameReceiver>();
  auto* const receiver = receiver_ptr.get();
  EXPECT_CALL(*receiver, OnStarted());
  EXPECT_CALL(*receiver, OnError()).Times(0);

  AllocateAndStartSynchronouslyWithExpectations(std::move(receiver_ptr));
  // From this point, there is no reason the capturer should be re-started.
  EXPECT_CALL(capturer_, MockStart(_)).Times(0);

  // Run 24 frames through the pipeline, one at a time. Then, run 24 more, two
  // at a time. Then, run 24 more, three at a time.
  constexpr int kNumFramesToDeliver = 24;
  constexpr int kMaxSimultaneousFrames = 3;
  int next_frame_number = 0;
  for (int in_flight_count = 1; in_flight_count <= kMaxSimultaneousFrames;
       ++in_flight_count) {
    for (int iteration = 0; iteration < kNumFramesToDeliver; ++iteration) {
      int buffer_ids[kMaxSimultaneousFrames] = {-1};
      MockFrameSinkVideoConsumerFrameCallbacks
          callbackses[kMaxSimultaneousFrames];

      // Simulate |in_flight_count| frame captures and expect the frames to be
      // delivered to the VideoFrameReceiver.
      const int first_frame_number = next_frame_number;
      for (int i = 0; i < in_flight_count; ++i) {
        Expectation new_buffer_called =
            EXPECT_CALL(*receiver, MockOnNewBufferHandle(Ge(0), NotNull()))
                .WillOnce(SaveArg<0>(&buffer_ids[i]));
        EXPECT_CALL(*receiver,
                    MockOnFrameReadyInBuffer(Eq(ByRef(buffer_ids[i])), Ge(0),
                                             NotNull(), NotNull()))
            .After(new_buffer_called);
        SimulateFrameCapture(next_frame_number, &callbackses[i]);
        ++next_frame_number;
        WAIT_FOR_DEVICE_TASKS();
      }

      // Confirm the VideoFrameReceiver was provided the correct buffer and
      // VideoFrameInfo struct for each frame in this batch.
      for (int frame_number = first_frame_number;
           frame_number < next_frame_number; ++frame_number) {
        const int buffer_id = buffer_ids[frame_number - first_frame_number];

        auto buffer = receiver->TakeBufferHandle(buffer_id);
        ASSERT_TRUE(buffer.is_valid());
        EXPECT_TRUE(
            IsExpectedBufferContentForFrame(frame_number, std::move(buffer)));

        const auto info = receiver->TakeVideoFrameInfo(buffer_id);
        ASSERT_TRUE(info);
        EXPECT_EQ(kMinCapturePeriod * frame_number, info->timestamp);
        EXPECT_EQ(kFormat, info->pixel_format);
        EXPECT_EQ(kResolution, info->coded_size);
        EXPECT_EQ(gfx::Rect(kResolution), info->visible_rect);
      }

      // Simulate the receiver providing the feedback and done notifications for
      // each frame and expect the FrameSinkVideoCaptureDevice to process these
      // notifications.
      for (int frame_number = first_frame_number;
           frame_number < next_frame_number; ++frame_number) {
        const int buffer_id = buffer_ids[frame_number - first_frame_number];
        MockFrameSinkVideoConsumerFrameCallbacks& callbacks =
            callbackses[frame_number - first_frame_number];

        const double fake_utilization =
            static_cast<double>(frame_number) / kNumFramesToDeliver;
        EXPECT_CALL(callbacks, ProvideFeedback(fake_utilization));
        EXPECT_CALL(callbacks, Done());
        EXPECT_CALL(*receiver, OnBufferRetired(buffer_id));

        const int feedback_id = receiver->TakeFeedbackId(buffer_id);
        POST_DEVICE_METHOD_CALL(OnUtilizationReport, feedback_id,
                                fake_utilization);
        receiver->ReleaseAccessPermission(buffer_id);
        WAIT_FOR_DEVICE_TASKS();
      }
    }
  }

  StopAndDeAllocateSynchronouslyWithExpectations(true /* capturer will stop */);
}

// Tests that a client request to Suspend() should stop consumption and ignore
// all refresh requests. Likewise, a client request to Resume() will
// re-establish consumption and allow refresh requests to propagate to the
// capturer again.
TEST_F(FrameSinkVideoCaptureDeviceTest, SuspendsAndResumes) {
  AllocateAndStartSynchronouslyWithExpectations(
      std::make_unique<NiceMock<MockVideoFrameReceiver>>());

  // A started device should have started the capturer, and any refresh frame
  // requests from the client should be propagated to it.
  {
    EXPECT_CALL(capturer_, RequestRefreshFrame());
    POST_DEVICE_METHOD_CALL0(RequestRefreshFrame);
    WAIT_FOR_DEVICE_TASKS();
  }

  // Simulate a client request that capture be suspended. The capturer should
  // receive a Stop() message.
  {
    EXPECT_CALL(capturer_, MockStart(_)).Times(0);
    EXPECT_CALL(capturer_, MockStop());
    POST_DEVICE_METHOD_CALL0(MaybeSuspend);
    WAIT_FOR_DEVICE_TASKS();
  }

  // A suspended device should not propagate any refresh frame requests.
  {
    EXPECT_CALL(capturer_, RequestRefreshFrame()).Times(0);
    POST_DEVICE_METHOD_CALL0(RequestRefreshFrame);
    WAIT_FOR_DEVICE_TASKS();
  }

  // Simulate a client request that capture be resumed. The capturer should
  // receive a Start() message.
  {
    EXPECT_CALL(capturer_, MockStart(NotNull()));
    EXPECT_CALL(capturer_, MockStop()).Times(0);
    POST_DEVICE_METHOD_CALL0(Resume);
    WAIT_FOR_DEVICE_TASKS();
  }

  // Now refresh frame requests should propagate again.
  {
    EXPECT_CALL(capturer_, RequestRefreshFrame());
    POST_DEVICE_METHOD_CALL0(RequestRefreshFrame);
    WAIT_FOR_DEVICE_TASKS();
  }

  StopAndDeAllocateSynchronouslyWithExpectations(true /* capturer will stop */);
}

// Tests that the FrameSinkVideoCaptureDevice will shutdown on a fatal error and
// refuse to be started again.
TEST_F(FrameSinkVideoCaptureDeviceTest, ShutsDownOnFatalError) {
  auto receiver_ptr = std::make_unique<MockVideoFrameReceiver>();
  auto* receiver = receiver_ptr.get();
  Sequence sequence;
  EXPECT_CALL(*receiver, OnStarted()).InSequence(sequence);
  EXPECT_CALL(*receiver, OnLog(StrNe(""))).InSequence(sequence);
  EXPECT_CALL(*receiver, OnError()).InSequence(sequence);

  AllocateAndStartSynchronouslyWithExpectations(std::move(receiver_ptr));

  // Notify the device that the target frame sink was lost. This should stop
  // consumption, unbind the capturer, log an error with the VideoFrameReceiver,
  // and destroy the VideoFrameReceiver.
  {
    EXPECT_CALL(capturer_, MockStop());
    POST_DEVICE_METHOD_CALL0(OnTargetPermanentlyLost);
    WAIT_FOR_DEVICE_TASKS();
  }

  // Shutdown the device. However, the fatal error already stopped consumption,
  // so don't expect the capturer to be stopped again.
  StopAndDeAllocateSynchronouslyWithExpectations(false);

  // Now, any further attempts to start the FrameSinkVideoCaptureDevice again
  // should fail. The VideoFrameReceiver will be provided the same error
  // message.
  receiver_ptr = std::make_unique<MockVideoFrameReceiver>();
  receiver = receiver_ptr.get();
  {
    EXPECT_CALL(*receiver, OnStarted()).Times(0);
    EXPECT_CALL(*receiver, OnLog(StrNe("")));
    EXPECT_CALL(*receiver, OnError());
    EXPECT_CALL(capturer_, MockStart(_)).Times(0);

    POST_DEVICE_METHOD_CALL(AllocateAndStartWithReceiver, GetCaptureParams(),
                            std::move(receiver_ptr));
    WAIT_FOR_DEVICE_TASKS();
  }
}

}  // namespace
}  // namespace content

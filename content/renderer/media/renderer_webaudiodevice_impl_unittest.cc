// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/media/renderer_webaudiodevice_impl.h"

#include "base/bind.h"
#include "base/message_loop/message_loop.h"
#include "base/strings/stringprintf.h"
#include "build/build_config.h"
#include "content/renderer/media/audio_device_factory.h"
#include "media/base/audio_capturer_source.h"
#include "media/base/limits.h"
#include "media/base/mock_audio_renderer_sink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::_;

namespace content {

namespace {

const int kHardwareSampleRate = 44100;
const int kHardwareBufferSize = 128;
const int kRenderFrameId = 100;

int MockFrameIdFromCurrentContext() {
  return kRenderFrameId;
}

media::AudioParameters MockGetOutputDeviceParameters(
    int frame_id,
    int session_id,
    const std::string& device_id) {
  return media::AudioParameters(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                media::CHANNEL_LAYOUT_STEREO,
                                kHardwareSampleRate, 16, kHardwareBufferSize);
}

class RendererWebAudioDeviceImplUnderTest : public RendererWebAudioDeviceImpl {
 public:
  RendererWebAudioDeviceImplUnderTest(
      media::ChannelLayout layout,
      int channels,
      const blink::WebAudioLatencyHint& latency_hint,
      blink::WebAudioDevice::RenderCallback* callback,
      int session_id)
      : RendererWebAudioDeviceImpl(layout,
                                   channels,
                                   latency_hint,
                                   callback,
                                   session_id,
                                   base::Bind(&MockGetOutputDeviceParameters),
                                   base::Bind(&MockFrameIdFromCurrentContext)) {
  }
};

}  // namespace

class RendererWebAudioDeviceImplTest
    : public blink::WebAudioDevice::RenderCallback,
      public AudioDeviceFactory,
      public testing::Test {
 protected:
  RendererWebAudioDeviceImplTest() {}

  void SetupDevice(blink::WebAudioLatencyHint latencyHint) {
    webaudio_device_.reset(new RendererWebAudioDeviceImplUnderTest(
        media::CHANNEL_LAYOUT_MONO, 1, latencyHint, this, 0));
    webaudio_device_->SetMediaTaskRunnerForTesting(message_loop_.task_runner());
  }

  void SetupDevice(media::ChannelLayout layout, int channels) {
    webaudio_device_.reset(new RendererWebAudioDeviceImplUnderTest(
        layout, channels,
        blink::WebAudioLatencyHint(
            blink::WebAudioLatencyHint::kCategoryInteractive),
        this, 0));
    webaudio_device_->SetMediaTaskRunnerForTesting(message_loop_.task_runner());
  }

  MOCK_METHOD1(CreateAudioCapturerSource,
               scoped_refptr<media::AudioCapturerSource>(int));
  MOCK_METHOD3(CreateFinalAudioRendererSink,
               scoped_refptr<media::AudioRendererSink>(int,
                                                       int,
                                                       const std::string&));
  MOCK_METHOD4(
      CreateSwitchableAudioRendererSink,
      scoped_refptr<media::SwitchableAudioRendererSink>(SourceType,
                                                        int,
                                                        int,
                                                        const std::string&));

  scoped_refptr<media::AudioRendererSink> CreateAudioRendererSink(
      SourceType source_type,
      int render_frame_id,
      int session_id,
      const std::string& device_id) {
    scoped_refptr<media::MockAudioRendererSink> mock_sink =
        new media::MockAudioRendererSink(
            device_id, media::OUTPUT_DEVICE_STATUS_OK,
            MockGetOutputDeviceParameters(render_frame_id, session_id,
                                          device_id));

    EXPECT_CALL(*mock_sink.get(), Start());
    EXPECT_CALL(*mock_sink.get(), Play());
    EXPECT_CALL(*mock_sink.get(), Stop());

    return mock_sink;
  }

  void TearDown() override { webaudio_device_.reset(); }

  std::unique_ptr<RendererWebAudioDeviceImpl> webaudio_device_;
  base::MessageLoop message_loop_;
};

TEST_F(RendererWebAudioDeviceImplTest, ChannelLayout) {
  for (int ch = 1; ch < static_cast<int>(media::limits::kMaxChannels); ++ch) {
    SCOPED_TRACE(base::StringPrintf("ch == %d", ch));

    media::ChannelLayout layout = media::GuessChannelLayout(ch);
    if (layout == media::CHANNEL_LAYOUT_UNSUPPORTED)
      layout = media::CHANNEL_LAYOUT_DISCRETE;

    SetupDevice(layout, ch);
    media::AudioParameters sink_params =
        webaudio_device_->get_sink_params_for_testing();
    EXPECT_TRUE(sink_params.IsValid());
    EXPECT_EQ(layout, sink_params.channel_layout());
    EXPECT_EQ(ch, sink_params.channels());
  }
}

TEST_F(RendererWebAudioDeviceImplTest, TestLatencyHintValues) {
  blink::WebAudioLatencyHint interactiveLatencyHint(
      blink::WebAudioLatencyHint::kCategoryInteractive);
  int interactiveBufferSize =
      media::AudioLatency::GetInteractiveBufferSize(kHardwareBufferSize);
  SetupDevice(interactiveLatencyHint);

  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), interactiveBufferSize);

  webaudio_device_->Start();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), interactiveBufferSize);

  webaudio_device_->Stop();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), interactiveBufferSize);

  webaudio_device_->Start();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), interactiveBufferSize);

  webaudio_device_->Stop();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), interactiveBufferSize);

  blink::WebAudioLatencyHint balancedLatencyHint(
      blink::WebAudioLatencyHint::kCategoryBalanced);
  int balancedBufferSize = media::AudioLatency::GetRtcBufferSize(
      kHardwareSampleRate, kHardwareBufferSize);
  SetupDevice(balancedLatencyHint);

  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), balancedBufferSize);

  webaudio_device_->Start();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), balancedBufferSize);

  webaudio_device_->Stop();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), balancedBufferSize);

  webaudio_device_->Start();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), balancedBufferSize);

  webaudio_device_->Stop();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), balancedBufferSize);

  blink::WebAudioLatencyHint playbackLatencyHint(
      blink::WebAudioLatencyHint::kCategoryPlayback);
  int playbackBufferSize = media::AudioLatency::GetHighLatencyBufferSize(
      kHardwareSampleRate, kHardwareBufferSize);
  SetupDevice(playbackLatencyHint);

  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), playbackBufferSize);

  webaudio_device_->Start();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), playbackBufferSize);

  webaudio_device_->Stop();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), playbackBufferSize);

  webaudio_device_->Start();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), playbackBufferSize);

  webaudio_device_->Stop();
  EXPECT_EQ(webaudio_device_->SampleRate(), kHardwareSampleRate);
  EXPECT_EQ(webaudio_device_->FramesPerBuffer(), playbackBufferSize);

  EXPECT_GE(playbackBufferSize, balancedBufferSize);
  EXPECT_GE(balancedBufferSize, interactiveBufferSize);
}

}  // namespace content

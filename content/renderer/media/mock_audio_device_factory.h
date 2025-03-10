// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_MEDIA_MOCK_AUDIO_DEVICE_FACTORY_H_
#define CONTENT_RENDERER_MEDIA_MOCK_AUDIO_DEVICE_FACTORY_H_

#include <string>

#include "content/renderer/media/audio_device_factory.h"
#include "media/base/audio_capturer_source.h"
#include "media/base/audio_renderer_sink.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace content {

// MockAudioDeviceFactory creates an instance of this.
class MockCapturerSource : public media::AudioCapturerSource {
 public:
  MockCapturerSource();
  MOCK_METHOD3(Initialize, void(const media::AudioParameters& params,
                                CaptureCallback* callback,
                                int session_id));
  MOCK_METHOD0(Start, void());
  MOCK_METHOD0(Stop, void());
  MOCK_METHOD1(SetAutomaticGainControl, void(bool enable));
  void SetVolume(double volume) override;

 protected:
  ~MockCapturerSource() override;
};

// Creates one MockCapturerSource instance for unit testing. This replaces the
// need for unit tests to open a real platform audio output. Instantiating this
// class sets the global content::AudioDeviceFactory implementation to |this|.
class MockAudioDeviceFactory : public AudioDeviceFactory {
 public:
  MockAudioDeviceFactory();
  ~MockAudioDeviceFactory() override;

  // Returns the MockCapturerSource created by this factory.
  const scoped_refptr<MockCapturerSource>& mock_capturer_source() const {
    return mock_capturer_source_;
  }

  // These methods are just mocked because tests currently don't need them to be
  // implemented.
  MOCK_METHOD3(
      CreateFinalAudioRendererSink,
      scoped_refptr<media::AudioRendererSink>(int render_frame_id,
                                              int sesssion_id,
                                              const std::string& device_id));
  MOCK_METHOD4(
      CreateAudioRendererSink,
      scoped_refptr<media::AudioRendererSink>(SourceType source_type,
                                              int render_frame_id,
                                              int sesssion_id,
                                              const std::string& device_id));
  MOCK_METHOD4(CreateSwitchableAudioRendererSink,
               scoped_refptr<media::SwitchableAudioRendererSink>(
                   SourceType source_type,
                   int render_frame_id,
                   int sesssion_id,
                   const std::string& device_id));

  // Returns mock_capturer_source_ once. If called a second time, the process
  // will crash.
  scoped_refptr<media::AudioCapturerSource> CreateAudioCapturerSource(
      int render_frame_id) override;

 private:
  scoped_refptr<MockCapturerSource> mock_capturer_source_;
  bool did_create_once_;

  DISALLOW_COPY_AND_ASSIGN(MockAudioDeviceFactory);
};

}  // namespace content

#endif  // CONTENT_RENDERER_MEDIA_MOCK_AUDIO_DEVICE_FACTORY_H_

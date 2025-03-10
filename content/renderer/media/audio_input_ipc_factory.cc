// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/media/audio_input_ipc_factory.h"

#include <utility>

#include "base/logging.h"
#include "base/sequenced_task_runner.h"
#include "content/common/media/renderer_audio_input_stream_factory.mojom.h"
#include "content/renderer/media/mojo_audio_input_ipc.h"
#include "content/renderer/render_frame_impl.h"
#include "services/service_manager/public/cpp/interface_provider.h"

namespace content {

namespace {

void CreateMojoAudioInputStreamOnMainThread(
    int frame_id,
    mojom::RendererAudioInputStreamFactoryClientPtr client,
    int32_t session_id,
    const media::AudioParameters& params,
    bool automatic_gain_control,
    uint32_t total_segments) {
  RenderFrameImpl* frame = RenderFrameImpl::FromRoutingID(frame_id);
  if (frame) {
    frame->GetAudioInputStreamFactory()->CreateStream(
        std::move(client), session_id, params, automatic_gain_control,
        total_segments);
  }
}

void CreateMojoAudioInputStream(
    scoped_refptr<base::SequencedTaskRunner> main_task_runner,
    int frame_id,
    mojom::RendererAudioInputStreamFactoryClientPtr client,
    int32_t session_id,
    const media::AudioParameters& params,
    bool automatic_gain_control,
    uint32_t total_segments) {
  main_task_runner->PostTask(
      FROM_HERE, base::BindOnce(&CreateMojoAudioInputStreamOnMainThread,
                                frame_id, std::move(client), session_id, params,
                                automatic_gain_control, total_segments));
}

}  // namespace

AudioInputIPCFactory* AudioInputIPCFactory::instance_ = nullptr;

AudioInputIPCFactory::AudioInputIPCFactory(
    scoped_refptr<base::SequencedTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner)
    : main_task_runner_(std::move(main_task_runner)),
      io_task_runner_(std::move(io_task_runner)) {
  DCHECK(!instance_);
  instance_ = this;
}

AudioInputIPCFactory::~AudioInputIPCFactory() {
  DCHECK_EQ(instance_, this);
  instance_ = nullptr;
}

std::unique_ptr<media::AudioInputIPC> AudioInputIPCFactory::CreateAudioInputIPC(
    int frame_id) const {
  return std::make_unique<MojoAudioInputIPC>(base::BindRepeating(
      &CreateMojoAudioInputStream, main_task_runner_, frame_id));
}

}  // namespace content

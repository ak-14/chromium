// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include "media/gpu/ipc/service/picture_buffer_manager.h"

#include "base/macros.h"
#include "base/memory/scoped_refptr.h"
#include "base/test/mock_callback.h"
#include "base/test/scoped_task_environment.h"
#include "media/gpu/fake_command_buffer_helper.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace media {

namespace {

// TODO(sandersd): Should be part of //media, as it is used by
// MojoVideoDecoderService (production code) as well.
class StaticSyncTokenClient : public VideoFrame::SyncTokenClient {
 public:
  explicit StaticSyncTokenClient(const gpu::SyncToken& sync_token)
      : sync_token_(sync_token) {}

  void GenerateSyncToken(gpu::SyncToken* sync_token) final {
    *sync_token = sync_token_;
  }

  void WaitSyncToken(const gpu::SyncToken& sync_token) final {}

 private:
  gpu::SyncToken sync_token_;

  DISALLOW_COPY_AND_ASSIGN(StaticSyncTokenClient);
};

}  // namespace

class PictureBufferManagerImplTest : public testing::Test {
 public:
  explicit PictureBufferManagerImplTest() {
    // TODO(sandersd): Use a separate thread for the GPU task runner.
    cbh_ = base::MakeRefCounted<FakeCommandBufferHelper>(
        environment_.GetMainThreadTaskRunner());
    pbm_ = PictureBufferManager::Create(reuse_cb_.Get());
  }

  ~PictureBufferManagerImplTest() override {}

 protected:
  void Initialize() {
    pbm_->Initialize(environment_.GetMainThreadTaskRunner(), cbh_);
  }

  std::vector<PictureBuffer> CreateARGBPictureBuffers(uint32_t count) {
    return pbm_->CreatePictureBuffers(count, PIXEL_FORMAT_ARGB, 1,
                                      gfx::Size(320, 240), GL_TEXTURE_2D);
  }

  PictureBuffer CreateARGBPictureBuffer() {
    std::vector<PictureBuffer> picture_buffers = CreateARGBPictureBuffers(1);
    DCHECK_EQ(picture_buffers.size(), 1U);
    return picture_buffers[0];
  }

  scoped_refptr<VideoFrame> CreateVideoFrame(int32_t picture_buffer_id) {
    return pbm_->CreateVideoFrame(
        Picture(picture_buffer_id,              // picture_buffer_id
                0,                              // bitstream_buffer_id
                gfx::Rect(),                    // visible_rect (ignored)
                gfx::ColorSpace::CreateSRGB(),  // color_space
                false),                         // allow_overlay
        base::TimeDelta(),                      // timestamp
        gfx::Rect(),                            // visible_rect
        gfx::Size());                           // natural_size
  }

  gpu::SyncToken GenerateSyncToken(scoped_refptr<VideoFrame> video_frame) {
    gpu::SyncToken sync_token(gpu::GPU_IO,
                              gpu::CommandBufferId::FromUnsafeValue(1),
                              next_release_count_++);
    StaticSyncTokenClient sync_token_client(sync_token);
    video_frame->UpdateReleaseSyncToken(&sync_token_client);
    return sync_token;
  }

  base::test::ScopedTaskEnvironment environment_;

  uint64_t next_release_count_ = 1;
  testing::StrictMock<
      base::MockCallback<PictureBufferManager::ReusePictureBufferCB>>
      reuse_cb_;
  scoped_refptr<FakeCommandBufferHelper> cbh_;
  scoped_refptr<PictureBufferManager> pbm_;

  DISALLOW_COPY_AND_ASSIGN(PictureBufferManagerImplTest);
};

TEST_F(PictureBufferManagerImplTest, CreateAndDestroy) {}

TEST_F(PictureBufferManagerImplTest, Initialize) {
  Initialize();
}

TEST_F(PictureBufferManagerImplTest, CreatePictureBuffer) {
  Initialize();
  PictureBuffer pb = CreateARGBPictureBuffer();
  EXPECT_TRUE(cbh_->HasTexture(pb.client_texture_ids()[0]));
}

TEST_F(PictureBufferManagerImplTest, CreatePictureBuffer_ContextLost) {
  Initialize();
  cbh_->ContextLost();
  std::vector<PictureBuffer> pbs = CreateARGBPictureBuffers(1);
  EXPECT_TRUE(pbs.empty());
}

TEST_F(PictureBufferManagerImplTest, ReusePictureBuffer) {
  Initialize();
  PictureBuffer pb = CreateARGBPictureBuffer();
  scoped_refptr<VideoFrame> frame = CreateVideoFrame(pb.id());

  // Dropping the frame does not immediately trigger reuse.
  gpu::SyncToken sync_token = GenerateSyncToken(frame);
  frame = nullptr;
  environment_.RunUntilIdle();

  // Completing the SyncToken wait does.
  EXPECT_CALL(reuse_cb_, Run(pb.id()));
  cbh_->ReleaseSyncToken(sync_token);
  environment_.RunUntilIdle();
}

TEST_F(PictureBufferManagerImplTest, DismissPictureBuffer_Available) {
  Initialize();
  PictureBuffer pb = CreateARGBPictureBuffer();
  pbm_->DismissPictureBuffer(pb.id());

  // Allocated textures should be deleted soon.
  environment_.RunUntilIdle();
  EXPECT_FALSE(cbh_->HasTexture(pb.client_texture_ids()[0]));
}

TEST_F(PictureBufferManagerImplTest, DismissPictureBuffer_Output) {
  Initialize();
  PictureBuffer pb = CreateARGBPictureBuffer();
  scoped_refptr<VideoFrame> frame = CreateVideoFrame(pb.id());
  pbm_->DismissPictureBuffer(pb.id());

  // Allocated textures should not be deleted while the VideoFrame exists.
  environment_.RunUntilIdle();
  EXPECT_TRUE(cbh_->HasTexture(pb.client_texture_ids()[0]));

  // Or after it has been returned.
  gpu::SyncToken sync_token = GenerateSyncToken(frame);
  frame = nullptr;
  environment_.RunUntilIdle();
  EXPECT_TRUE(cbh_->HasTexture(pb.client_texture_ids()[0]));

  // Until the SyncToken has been waited for. (Reuse callback should not be
  // called for a dismissed picture buffer.)
  cbh_->ReleaseSyncToken(sync_token);
  environment_.RunUntilIdle();
  EXPECT_FALSE(cbh_->HasTexture(pb.client_texture_ids()[0]));
}

TEST_F(PictureBufferManagerImplTest, CanReadWithoutStalling) {
  // Works before Initialize().
  EXPECT_TRUE(pbm_->CanReadWithoutStalling());

  // True before any picture buffers are allocated.
  Initialize();
  EXPECT_TRUE(pbm_->CanReadWithoutStalling());

  // True when a picture buffer is available.
  PictureBuffer pb = CreateARGBPictureBuffer();
  EXPECT_TRUE(pbm_->CanReadWithoutStalling());

  // False when all picture buffers are used.
  scoped_refptr<VideoFrame> frame = CreateVideoFrame(pb.id());
  EXPECT_FALSE(pbm_->CanReadWithoutStalling());

  // True once a picture buffer is returned.
  frame = nullptr;
  EXPECT_TRUE(pbm_->CanReadWithoutStalling());

  // True after all picture buffers have been dismissed.
  pbm_->DismissPictureBuffer(pb.id());
  EXPECT_TRUE(pbm_->CanReadWithoutStalling());
}

}  // namespace media

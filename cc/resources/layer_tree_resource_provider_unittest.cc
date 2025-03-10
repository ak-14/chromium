// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cc/resources/layer_tree_resource_provider.h"

#include <memory>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "components/viz/common/resources/single_release_callback.h"
#include "components/viz/test/test_context_provider.h"
#include "components/viz/test/test_gpu_memory_buffer_manager.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::_;

namespace cc {
namespace {

class LayerTreeResourceProviderTest : public testing::TestWithParam<bool> {
 protected:
  LayerTreeResourceProviderTest()
      : use_gpu_(GetParam()),
        context_provider_(viz::TestContextProvider::Create()),
        bound_(context_provider_->BindToCurrentThread()),
        provider_(std::make_unique<LayerTreeResourceProvider>(
            use_gpu_ ? context_provider_.get() : nullptr,
            &gpu_memory_buffer_manager_,
            delegated_sync_points_required_,
            resource_settings_)) {
    DCHECK_EQ(bound_, gpu::ContextResult::kSuccess);
  }

  gpu::Mailbox MailboxFromChar(char value) {
    gpu::Mailbox mailbox;
    memset(mailbox.name, value, sizeof(mailbox.name));
    return mailbox;
  }

  gpu::SyncToken SyncTokenFromUInt(uint32_t value) {
    return gpu::SyncToken(gpu::CommandBufferNamespace::GPU_IO,
                          gpu::CommandBufferId::FromUnsafeValue(0x123), value);
  }

  viz::TransferableResource MakeTransferableResource(
      bool gpu,
      char mailbox_char,
      uint32_t sync_token_value) {
    viz::TransferableResource r;
    r.id = mailbox_char;
    r.is_software = !gpu;
    r.filter = 456;
    r.size = gfx::Size(10, 11);
    r.mailbox_holder.mailbox = MailboxFromChar(mailbox_char);
    if (gpu) {
      r.mailbox_holder.sync_token = SyncTokenFromUInt(sync_token_value);
      r.mailbox_holder.texture_target = 6;
    }
    if (!gpu)
      r.shared_bitmap_sequence_number = sync_token_value;
    return r;
  }

  void Shutdown() { provider_.reset(); }

  bool use_gpu() const { return use_gpu_; }
  LayerTreeResourceProvider& provider() const { return *provider_; }

 private:
  bool use_gpu_;
  scoped_refptr<viz::TestContextProvider> context_provider_;
  gpu::ContextResult bound_;
  viz::TestGpuMemoryBufferManager gpu_memory_buffer_manager_;
  bool delegated_sync_points_required_ = true;
  viz::ResourceSettings resource_settings_;
  std::unique_ptr<LayerTreeResourceProvider> provider_;
};

INSTANTIATE_TEST_CASE_P(LayerTreeResourceProviderTests,
                        LayerTreeResourceProviderTest,
                        ::testing::Values(false, true));

class MockReleaseCallback {
 public:
  MOCK_METHOD2(Released, void(const gpu::SyncToken& token, bool lost));
};

TEST_P(LayerTreeResourceProviderTest, TransferableResourceReleased) {
  MockReleaseCallback release;
  viz::TransferableResource tran = MakeTransferableResource(use_gpu(), 'a', 15);
  viz::ResourceId id = provider().ImportResource(
      tran, viz::SingleReleaseCallback::Create(base::Bind(
                &MockReleaseCallback::Released, base::Unretained(&release))));
  // The local id is different.
  EXPECT_NE(id, tran.id);

  // The same SyncToken that was sent is returned when the resource was never
  // exported. The SyncToken may be from any context, and the ReleaseCallback
  // may need to wait on it before interacting with the resource on its context.
  EXPECT_CALL(release, Released(tran.mailbox_holder.sync_token, false));
  provider().RemoveImportedResource(id);
}

TEST_P(LayerTreeResourceProviderTest, TransferableResourceSendToParent) {
  MockReleaseCallback release;
  viz::TransferableResource tran = MakeTransferableResource(use_gpu(), 'a', 15);
  tran.buffer_format = gfx::BufferFormat::RGBX_8888;
  viz::ResourceId id = provider().ImportResource(
      tran, viz::SingleReleaseCallback::Create(base::Bind(
                &MockReleaseCallback::Released, base::Unretained(&release))));

  // Export the resource.
  std::vector<viz::ResourceId> to_send = {id};
  std::vector<viz::TransferableResource> exported;
  provider().PrepareSendToParent(to_send, &exported);
  ASSERT_EQ(exported.size(), 1u);

  // Exported resource matches except for the id which was mapped
  // to the local ResourceProvider, and the sync token should be
  // verified if it's a gpu resource.
  gpu::SyncToken verified_sync_token = tran.mailbox_holder.sync_token;
  if (!tran.is_software)
    verified_sync_token.SetVerifyFlush();
  EXPECT_EQ(exported[0].id, id);
  EXPECT_EQ(exported[0].is_software, tran.is_software);
  EXPECT_EQ(exported[0].filter, tran.filter);
  EXPECT_EQ(exported[0].size, tran.size);
  EXPECT_EQ(exported[0].mailbox_holder.mailbox, tran.mailbox_holder.mailbox);
  EXPECT_EQ(exported[0].mailbox_holder.sync_token, verified_sync_token);
  EXPECT_EQ(exported[0].mailbox_holder.texture_target,
            tran.mailbox_holder.texture_target);
  EXPECT_EQ(exported[0].shared_bitmap_sequence_number,
            tran.shared_bitmap_sequence_number);
  EXPECT_EQ(exported[0].buffer_format, tran.buffer_format);

  // Exported resources are not released when removed, until the export returns.
  EXPECT_CALL(release, Released(_, _)).Times(0);
  provider().RemoveImportedResource(id);

  // Return the resource, with a sync token if using gpu.
  std::vector<viz::ReturnedResource> returned;
  returned.push_back({});
  returned.back().id = exported[0].id;
  if (use_gpu())
    returned.back().sync_token = SyncTokenFromUInt(31);
  returned.back().count = 1;
  returned.back().lost = false;

  // The sync token is given to the ReleaseCallback.
  EXPECT_CALL(release, Released(returned[0].sync_token, false));
  provider().ReceiveReturnsFromParent(returned);
}

TEST_P(LayerTreeResourceProviderTest, TransferableResourceSendTwoToParent) {
  viz::TransferableResource tran[] = {
      MakeTransferableResource(use_gpu(), 'a', 15),
      MakeTransferableResource(use_gpu(), 'b', 16)};
  viz::ResourceId id1 = provider().ImportResource(
      tran[0], viz::SingleReleaseCallback::Create(base::DoNothing()));
  viz::ResourceId id2 = provider().ImportResource(
      tran[1], viz::SingleReleaseCallback::Create(base::DoNothing()));

  // Export the resource.
  std::vector<viz::ResourceId> to_send = {id1, id2};
  std::vector<viz::TransferableResource> exported;
  provider().PrepareSendToParent(to_send, &exported);
  ASSERT_EQ(exported.size(), 2u);

  // Exported resource matches except for the id which was mapped
  // to the local ResourceProvider, and the sync token should be
  // verified if it's a gpu resource.
  for (int i = 0; i < 2; ++i) {
    gpu::SyncToken verified_sync_token = tran[i].mailbox_holder.sync_token;
    if (!tran[i].is_software)
      verified_sync_token.SetVerifyFlush();
    EXPECT_EQ(exported[i].id, to_send[i]);
    EXPECT_EQ(exported[i].is_software, tran[i].is_software);
    EXPECT_EQ(exported[i].filter, tran[i].filter);
    EXPECT_EQ(exported[i].size, tran[i].size);
    EXPECT_EQ(exported[i].mailbox_holder.mailbox,
              tran[i].mailbox_holder.mailbox);
    EXPECT_EQ(exported[i].mailbox_holder.sync_token, verified_sync_token);
    EXPECT_EQ(exported[i].mailbox_holder.texture_target,
              tran[i].mailbox_holder.texture_target);
    EXPECT_EQ(exported[i].shared_bitmap_sequence_number,
              tran[i].shared_bitmap_sequence_number);
    EXPECT_EQ(exported[i].buffer_format, tran[i].buffer_format);
  }
}

TEST_P(LayerTreeResourceProviderTest,
       TransferableResourceSendToParentTwoTimes) {
  viz::TransferableResource tran = MakeTransferableResource(use_gpu(), 'a', 15);
  viz::ResourceId id = provider().ImportResource(
      tran, viz::SingleReleaseCallback::Create(base::DoNothing()));

  // Export the resource.
  std::vector<viz::ResourceId> to_send = {id};
  std::vector<viz::TransferableResource> exported;
  provider().PrepareSendToParent(to_send, &exported);
  ASSERT_EQ(exported.size(), 1u);
  EXPECT_EQ(exported[0].id, id);

  // Return the resource, with a sync token if using gpu.
  std::vector<viz::ReturnedResource> returned;
  returned.push_back({});
  returned.back().id = exported[0].id;
  if (use_gpu())
    returned.back().sync_token = SyncTokenFromUInt(31);
  returned.back().count = 1;
  returned.back().lost = false;
  provider().ReceiveReturnsFromParent(returned);

  // Then export again, it still sends.
  exported.clear();
  provider().PrepareSendToParent(to_send, &exported);
  ASSERT_EQ(exported.size(), 1u);
  EXPECT_EQ(exported[0].id, id);
}

TEST_P(LayerTreeResourceProviderTest,
       TransferableResourceLostOnShutdownIfExported) {
  MockReleaseCallback release;
  viz::TransferableResource tran = MakeTransferableResource(use_gpu(), 'a', 15);
  viz::ResourceId id = provider().ImportResource(
      tran, viz::SingleReleaseCallback::Create(base::Bind(
                &MockReleaseCallback::Released, base::Unretained(&release))));

  // Export the resource.
  std::vector<viz::ResourceId> to_send = {id};
  std::vector<viz::TransferableResource> exported;
  provider().PrepareSendToParent(to_send, &exported);

  EXPECT_CALL(release, Released(_, true));
  Shutdown();
}

TEST_P(LayerTreeResourceProviderTest, TransferableResourceRemovedAfterReturn) {
  MockReleaseCallback release;
  viz::TransferableResource tran = MakeTransferableResource(use_gpu(), 'a', 15);
  viz::ResourceId id = provider().ImportResource(
      tran, viz::SingleReleaseCallback::Create(base::Bind(
                &MockReleaseCallback::Released, base::Unretained(&release))));

  // Export the resource.
  std::vector<viz::ResourceId> to_send = {id};
  std::vector<viz::TransferableResource> exported;
  provider().PrepareSendToParent(to_send, &exported);

  // Return the resource. This does not release the resource back to
  // the client.
  std::vector<viz::ReturnedResource> returned;
  returned.push_back({});
  returned.back().id = exported[0].id;
  if (use_gpu())
    returned.back().sync_token = SyncTokenFromUInt(31);
  returned.back().count = 1;
  returned.back().lost = false;

  EXPECT_CALL(release, Released(_, _)).Times(0);
  provider().ReceiveReturnsFromParent(returned);

  // Once removed, the resource is released.
  EXPECT_CALL(release, Released(returned[0].sync_token, false));
  provider().RemoveImportedResource(id);
}

TEST_P(LayerTreeResourceProviderTest, TransferableResourceExportedTwice) {
  MockReleaseCallback release;
  viz::TransferableResource tran = MakeTransferableResource(use_gpu(), 'a', 15);
  viz::ResourceId id = provider().ImportResource(
      tran, viz::SingleReleaseCallback::Create(base::Bind(
                &MockReleaseCallback::Released, base::Unretained(&release))));

  // Export the resource once.
  std::vector<viz::ResourceId> to_send = {id};
  std::vector<viz::TransferableResource> exported;
  provider().PrepareSendToParent(to_send, &exported);

  // Exported resources are not released when removed, until all exports are
  // returned.
  EXPECT_CALL(release, Released(_, _)).Times(0);
  provider().RemoveImportedResource(id);

  // Export the resource twice.
  exported = {};
  provider().PrepareSendToParent(to_send, &exported);

  // Return the resource the first time.
  std::vector<viz::ReturnedResource> returned;
  returned.push_back({});
  returned.back().id = exported[0].id;
  if (use_gpu())
    returned.back().sync_token = SyncTokenFromUInt(31);
  returned.back().count = 1;
  returned.back().lost = false;
  provider().ReceiveReturnsFromParent(returned);

  // And a second time, with a different sync token. Now the ReleaseCallback can
  // happen, using the latest sync token.
  if (use_gpu())
    returned.back().sync_token = SyncTokenFromUInt(47);
  EXPECT_CALL(release, Released(returned[0].sync_token, false));
  provider().ReceiveReturnsFromParent(returned);
}

TEST_P(LayerTreeResourceProviderTest, TransferableResourceReturnedTwiceAtOnce) {
  MockReleaseCallback release;
  viz::TransferableResource tran = MakeTransferableResource(use_gpu(), 'a', 15);
  viz::ResourceId id = provider().ImportResource(
      tran, viz::SingleReleaseCallback::Create(base::Bind(
                &MockReleaseCallback::Released, base::Unretained(&release))));

  // Export the resource once.
  std::vector<viz::ResourceId> to_send = {id};
  std::vector<viz::TransferableResource> exported;
  provider().PrepareSendToParent(to_send, &exported);

  // Exported resources are not released when removed, until all exports are
  // returned.
  EXPECT_CALL(release, Released(_, _)).Times(0);
  provider().RemoveImportedResource(id);

  // Export the resource twice.
  exported = {};
  provider().PrepareSendToParent(to_send, &exported);

  // Return both exports at once.
  std::vector<viz::ReturnedResource> returned;
  returned.push_back({});
  returned.back().id = exported[0].id;
  if (use_gpu())
    returned.back().sync_token = SyncTokenFromUInt(31);
  returned.back().count = 2;
  returned.back().lost = false;

  // When returned, the ReleaseCallback can happen, using the latest sync token.
  EXPECT_CALL(release, Released(returned[0].sync_token, false));
  provider().ReceiveReturnsFromParent(returned);
}

TEST_P(LayerTreeResourceProviderTest, TransferableResourceLostOnReturn) {
  MockReleaseCallback release;
  viz::TransferableResource tran = MakeTransferableResource(use_gpu(), 'a', 15);
  viz::ResourceId id = provider().ImportResource(
      tran, viz::SingleReleaseCallback::Create(base::Bind(
                &MockReleaseCallback::Released, base::Unretained(&release))));

  // Export the resource once.
  std::vector<viz::ResourceId> to_send = {id};
  std::vector<viz::TransferableResource> exported;
  provider().PrepareSendToParent(to_send, &exported);

  // Exported resources are not released when removed, until all exports are
  // returned.
  EXPECT_CALL(release, Released(_, _)).Times(0);
  provider().RemoveImportedResource(id);

  // Export the resource twice.
  exported = {};
  provider().PrepareSendToParent(to_send, &exported);

  // Return the resource the first time, not lost.
  std::vector<viz::ReturnedResource> returned;
  returned.push_back({});
  returned.back().id = exported[0].id;
  returned.back().count = 1;
  returned.back().lost = false;
  provider().ReceiveReturnsFromParent(returned);

  // Return a second time, as lost. The ReturnCallback should report it lost.
  returned.back().lost = true;
  EXPECT_CALL(release, Released(_, true));
  provider().ReceiveReturnsFromParent(returned);
}

TEST_P(LayerTreeResourceProviderTest, TransferableResourceLostOnFirstReturn) {
  MockReleaseCallback release;
  viz::TransferableResource tran = MakeTransferableResource(use_gpu(), 'a', 15);
  viz::ResourceId id = provider().ImportResource(
      tran, viz::SingleReleaseCallback::Create(base::Bind(
                &MockReleaseCallback::Released, base::Unretained(&release))));

  // Export the resource once.
  std::vector<viz::ResourceId> to_send = {id};
  std::vector<viz::TransferableResource> exported;
  provider().PrepareSendToParent(to_send, &exported);

  // Exported resources are not released when removed, until all exports are
  // returned.
  EXPECT_CALL(release, Released(_, _)).Times(0);
  provider().RemoveImportedResource(id);

  // Export the resource twice.
  exported = {};
  provider().PrepareSendToParent(to_send, &exported);

  // Return the resource the first time, marked as lost.
  std::vector<viz::ReturnedResource> returned;
  returned.push_back({});
  returned.back().id = exported[0].id;
  returned.back().count = 1;
  returned.back().lost = true;
  provider().ReceiveReturnsFromParent(returned);

  // Return a second time, not lost. The first lost signal should not be lost.
  returned.back().lost = false;
  EXPECT_CALL(release, Released(_, true));
  provider().ReceiveReturnsFromParent(returned);
}

}  // namespace
}  // namespace cc

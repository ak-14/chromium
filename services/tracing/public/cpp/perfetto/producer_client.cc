// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/tracing/public/cpp/perfetto/producer_client.h"

#include <utility>

#include "base/task_scheduler/post_task.h"
#include "services/tracing/public/cpp/perfetto/shared_memory.h"
#include "third_party/perfetto/include/perfetto/tracing/core/commit_data_request.h"
#include "third_party/perfetto/include/perfetto/tracing/core/shared_memory_arbiter.h"
#include "third_party/perfetto/include/perfetto/tracing/core/trace_writer.h"

namespace tracing {

// TODO(oysteine): Use a new sequence here once Perfetto handles multi-threading
// properly.
ProducerClient::ProducerClient()
    : perfetto_task_runner_(base::SequencedTaskRunnerHandle::Get()) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

ProducerClient::~ProducerClient() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

// static
void ProducerClient::DeleteSoon(
    std::unique_ptr<ProducerClient> producer_client) {
  producer_client->GetTaskRunner()->DeleteSoon(FROM_HERE,
                                               std::move(producer_client));
}

base::SequencedTaskRunner* ProducerClient::GetTaskRunner() {
  return perfetto_task_runner_.task_runner();
}

// The Mojo binding should run on the same sequence as the one we get
// callbacks from Perfetto on, to avoid additional PostTasks.
mojom::ProducerClientPtr ProducerClient::CreateAndBindProducerClient() {
  DCHECK(!binding_);
  mojom::ProducerClientPtr producer_client;

  GetTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ProducerClient::BindOnSequence, base::Unretained(this),
                     mojo::MakeRequest(&producer_client)));

  return producer_client;
}

mojom::ProducerHostRequest ProducerClient::CreateProducerHostRequest() {
  return mojo::MakeRequest(&producer_host_);
}

void ProducerClient::BindOnSequence(mojom::ProducerClientRequest request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  binding_ = std::make_unique<mojo::Binding<mojom::ProducerClient>>(
      this, std::move(request));
}

void ProducerClient::OnTracingStart(
    mojo::ScopedSharedBufferHandle shared_memory) {
  // TODO(oysteine): In next CLs plumb this through the service.
  const size_t kShmemBufferPageSize = 4096;

  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(producer_host_);
  if (!shared_memory_) {
    shared_memory_ =
        std::make_unique<MojoSharedMemory>(std::move(shared_memory));

    shared_memory_arbiter_ = perfetto::SharedMemoryArbiter::CreateInstance(
        shared_memory_.get(), kShmemBufferPageSize, this,
        &perfetto_task_runner_);
  } else {
    // TODO(oysteine): This is assuming the SMB is the same, currently. Swapping
    // out SharedMemoryBuffers would require more thread synchronization.
    DCHECK_EQ(shared_memory_->shared_buffer()->value(), shared_memory->value());
  }
}

void ProducerClient::CreateDataSourceInstance(
    uint64_t id,
    mojom::DataSourceConfigPtr data_source_config) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // TODO(oysteine): Create the relevant data source instance here.
}

void ProducerClient::TearDownDataSourceInstance(uint64_t id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  enabled_data_source_instance_.reset();

  // TODO(oysteine): Yak shave: Can only destroy these once the TraceWriters
  // are all cleaned up; have to figure out the TLS bits.
  // shared_memory_arbiter_ = nullptr;
  // shared_memory_ = nullptr;
}

void ProducerClient::Flush(uint64_t flush_request_id,
                           const std::vector<uint64_t>& data_source_ids) {
  NOTREACHED();
}

void ProducerClient::RegisterDataSource(const perfetto::DataSourceDescriptor&) {
  NOTREACHED();
}

void ProducerClient::UnregisterDataSource(const std::string& name) {
  NOTREACHED();
}

void ProducerClient::CommitData(const perfetto::CommitDataRequest& commit,
                                CommitDataCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // The CommitDataRequest which the SharedMemoryArbiter uses to
  // signal Perfetto that individual chunks have finished being
  // written and is ready for consumption, needs to be serialized
  // into the corresponding Mojo class and sent over to the
  // service-side.
  auto new_data_request = mojom::CommitDataRequest::New();

  for (auto& chunk : commit.chunks_to_move()) {
    auto new_chunk = mojom::ChunksToMove::New();
    new_chunk->page = chunk.page();
    new_chunk->chunk = chunk.chunk();
    new_chunk->target_buffer = chunk.target_buffer();
    new_data_request->chunks_to_move.push_back(std::move(new_chunk));
  }

  for (auto& chunk_patch : commit.chunks_to_patch()) {
    auto new_chunk_patch = mojom::ChunksToPatch::New();
    new_chunk_patch->target_buffer = chunk_patch.target_buffer();
    new_chunk_patch->writer_id = chunk_patch.writer_id();
    new_chunk_patch->chunk_id = chunk_patch.chunk_id();

    for (auto& patch : chunk_patch.patches()) {
      auto new_patch = mojom::ChunkPatch::New();
      new_patch->offset = patch.offset();
      new_patch->data = patch.data();
      new_chunk_patch->patches.push_back(std::move(new_patch));
    }

    new_chunk_patch->has_more_patches = chunk_patch.has_more_patches();
    new_data_request->chunks_to_patch.push_back(std::move(new_chunk_patch));
  }

  producer_host_->CommitData(std::move(new_data_request));
}

perfetto::SharedMemory* ProducerClient::shared_memory() const {
  return shared_memory_.get();
}

size_t ProducerClient::shared_buffer_page_size_kb() const {
  NOTREACHED();
  return 0;
}

void ProducerClient::NotifyFlushComplete(perfetto::FlushRequestID) {
  NOTREACHED();
}

std::unique_ptr<perfetto::TraceWriter> ProducerClient::CreateTraceWriter(
    perfetto::BufferID target_buffer) {
  DCHECK(shared_memory_arbiter_);
  return shared_memory_arbiter_->CreateTraceWriter(target_buffer);
}

}  // namespace tracing

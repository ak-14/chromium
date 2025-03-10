// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cc/tiles/software_image_decode_cache.h"

#include <stdint.h>

#include "base/format_macros.h"
#include "base/macros.h"
#include "base/memory/memory_coordinator_client_registry.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/stringprintf.h"
#include "base/trace_event/memory_dump_manager.h"
#include "cc/base/devtools_instrumentation.h"
#include "cc/base/histograms.h"
#include "cc/raster/tile_task.h"
#include "cc/tiles/mipmap_util.h"
#include "ui/gfx/skia_util.h"

using base::trace_event::MemoryAllocatorDump;
using base::trace_event::MemoryDumpLevelOfDetail;

namespace cc {
namespace {

bool UseCacheForDrawImage(const DrawImage& draw_image) {
  // Lazy generated images are have their decode cached.
  sk_sp<SkImage> sk_image = draw_image.paint_image().GetSkImage();
  if (sk_image->isLazyGenerated())
    return true;

  // Cache images that need to be converted to a non-sRGB color space.
  // TODO(ccameron): Consider caching when any color conversion is required.
  // https://crbug.com/791828
  const gfx::ColorSpace& dst_color_space = draw_image.target_color_space();
  if (dst_color_space.IsValid() &&
      dst_color_space != gfx::ColorSpace::CreateSRGB()) {
    return true;
  }

  return false;
}

// The number of entries to keep around in the cache. This limit can be breached
// if more items are locked. That is, locked items ignore this limit.
// Depending on the memory state of the system, we limit the amount of items
// differently.
const size_t kNormalMaxItemsInCacheForSoftware = 1000;
const size_t kThrottledMaxItemsInCacheForSoftware = 100;
const size_t kSuspendedMaxItemsInCacheForSoftware = 0;

class AutoRemoveKeyFromTaskMap {
 public:
  AutoRemoveKeyFromTaskMap(
      std::unordered_map<SoftwareImageDecodeCache::CacheKey,
                         scoped_refptr<TileTask>,
                         SoftwareImageDecodeCache::CacheKeyHash>* task_map,
      const SoftwareImageDecodeCache::CacheKey& key)
      : task_map_(task_map), key_(key) {}
  ~AutoRemoveKeyFromTaskMap() { task_map_->erase(key_); }

 private:
  std::unordered_map<SoftwareImageDecodeCache::CacheKey,
                     scoped_refptr<TileTask>,
                     SoftwareImageDecodeCache::CacheKeyHash>* task_map_;
  const SoftwareImageDecodeCache::CacheKey& key_;
};

class SoftwareImageDecodeTaskImpl : public TileTask {
 public:
  SoftwareImageDecodeTaskImpl(
      SoftwareImageDecodeCache* cache,
      const SoftwareImageDecodeCache::CacheKey& image_key,
      const PaintImage& paint_image,
      SoftwareImageDecodeCache::DecodeTaskType task_type,
      const ImageDecodeCache::TracingInfo& tracing_info)
      : TileTask(true),
        cache_(cache),
        image_key_(image_key),
        paint_image_(paint_image),
        task_type_(task_type),
        tracing_info_(tracing_info) {}

  // Overridden from Task:
  void RunOnWorkerThread() override {
    TRACE_EVENT2("cc", "SoftwareImageDecodeTaskImpl::RunOnWorkerThread", "mode",
                 "software", "source_prepare_tiles_id",
                 tracing_info_.prepare_tiles_id);
    devtools_instrumentation::ScopedImageDecodeTask image_decode_task(
        paint_image_.GetSkImage().get(),
        devtools_instrumentation::ScopedImageDecodeTask::kSoftware,
        ImageDecodeCache::ToScopedTaskType(tracing_info_.task_type));
    cache_->DecodeImageInTask(image_key_, paint_image_, task_type_);
  }

  // Overridden from TileTask:
  void OnTaskCompleted() override {
    cache_->OnImageDecodeTaskCompleted(image_key_, task_type_);
  }

 protected:
  ~SoftwareImageDecodeTaskImpl() override = default;

 private:
  SoftwareImageDecodeCache* cache_;
  SoftwareImageDecodeCache::CacheKey image_key_;
  PaintImage paint_image_;
  SoftwareImageDecodeCache::DecodeTaskType task_type_;
  const ImageDecodeCache::TracingInfo tracing_info_;

  DISALLOW_COPY_AND_ASSIGN(SoftwareImageDecodeTaskImpl);
};

SkSize GetScaleAdjustment(const SoftwareImageDecodeCache::CacheKey& key) {
  // If the requested filter quality did not require scale, then the adjustment
  // is identity.
  if (key.type() != SoftwareImageDecodeCache::CacheKey::kSubrectAndScale) {
    return SkSize::Make(1.f, 1.f);
  } else {
    return MipMapUtil::GetScaleAdjustmentForSize(key.src_rect().size(),
                                                 key.target_size());
  }
}

// Returns the filter quality to be used with the decoded result of the image.
// Note that in most cases this yields Low filter quality, meaning bilinear
// interpolation. This is because the processing for the image would have
// already been done, including scaling down to a mip level. So what remains is
// to do a bilinear interpolation. The exception to this is if the developer
// specified a pixelated effect, which results in a None filter quality (nearest
// neighbor).
SkFilterQuality GetDecodedFilterQuality(
    const SoftwareImageDecodeCache::CacheKey& key) {
  return key.is_nearest_neighbor() ? kNone_SkFilterQuality
                                   : kLow_SkFilterQuality;
}

void RecordLockExistingCachedImageHistogram(TilePriority::PriorityBin bin,
                                            bool success) {
  switch (bin) {
    case TilePriority::NOW:
      UMA_HISTOGRAM_BOOLEAN("Renderer4.LockExistingCachedImage.Software.NOW",
                            success);
      break;
    case TilePriority::SOON:
      UMA_HISTOGRAM_BOOLEAN("Renderer4.LockExistingCachedImage.Software.SOON",
                            success);
      break;
    case TilePriority::EVENTUALLY:
      UMA_HISTOGRAM_BOOLEAN(
          "Renderer4.LockExistingCachedImage.Software.EVENTUALLY", success);
      break;
  }
}

}  // namespace

SoftwareImageDecodeCache::SoftwareImageDecodeCache(
    SkColorType color_type,
    size_t locked_memory_limit_bytes)
    : decoded_images_(ImageMRUCache::NO_AUTO_EVICT),
      locked_images_budget_(locked_memory_limit_bytes),
      color_type_(color_type),
      max_items_in_cache_(kNormalMaxItemsInCacheForSoftware) {
  // In certain cases, ThreadTaskRunnerHandle isn't set (Android Webview).
  // Don't register a dump provider in these cases.
  if (base::ThreadTaskRunnerHandle::IsSet()) {
    base::trace_event::MemoryDumpManager::GetInstance()->RegisterDumpProvider(
        this, "cc::SoftwareImageDecodeCache",
        base::ThreadTaskRunnerHandle::Get());
  }
  // Register this component with base::MemoryCoordinatorClientRegistry.
  base::MemoryCoordinatorClientRegistry::GetInstance()->Register(this);
}

SoftwareImageDecodeCache::~SoftwareImageDecodeCache() {
  // It is safe to unregister, even if we didn't register in the constructor.
  base::trace_event::MemoryDumpManager::GetInstance()->UnregisterDumpProvider(
      this);
  // Unregister this component with memory_coordinator::ClientRegistry.
  base::MemoryCoordinatorClientRegistry::GetInstance()->Unregister(this);

  // TODO(vmpstr): If we don't have a client name, it may cause problems in
  // unittests, since most tests don't set the name but some do. The UMA system
  // expects the name to be always the same. This assertion is violated in the
  // tests that do set the name.
  if (GetClientNameForMetrics()) {
    UMA_HISTOGRAM_CUSTOM_COUNTS(
        base::StringPrintf("Compositing.%s.CachedImagesCount.Software",
                           GetClientNameForMetrics()),
        lifetime_max_items_in_cache_, 1, 1000, 20);
  }
}

ImageDecodeCache::TaskResult SoftwareImageDecodeCache::GetTaskForImageAndRef(
    const DrawImage& image,
    const TracingInfo& tracing_info) {
  DCHECK_EQ(tracing_info.task_type, TaskType::kInRaster);
  return GetTaskForImageAndRefInternal(image, tracing_info,
                                       DecodeTaskType::USE_IN_RASTER_TASKS);
}

ImageDecodeCache::TaskResult
SoftwareImageDecodeCache::GetOutOfRasterDecodeTaskForImageAndRef(
    const DrawImage& image) {
  return GetTaskForImageAndRefInternal(
      image, TracingInfo(0, TilePriority::NOW, TaskType::kOutOfRaster),
      DecodeTaskType::USE_OUT_OF_RASTER_TASKS);
}

ImageDecodeCache::TaskResult
SoftwareImageDecodeCache::GetTaskForImageAndRefInternal(
    const DrawImage& image,
    const TracingInfo& tracing_info,
    DecodeTaskType task_type) {
  CacheKey key = CacheKey::FromDrawImage(image, color_type_);
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
               "SoftwareImageDecodeCache::GetTaskForImageAndRefInternal", "key",
               key.ToString());

  // If the target size is empty, we can skip this image during draw (and thus
  // we don't need to decode it or ref it).
  if (key.target_size().IsEmpty())
    return TaskResult(false);

  if (!UseCacheForDrawImage(image))
    return TaskResult(false);

  base::AutoLock lock(lock_);

  bool new_image_fits_in_memory =
      locked_images_budget_.AvailableMemoryBytes() >= key.locked_bytes();

  // Get or generate the cache entry.
  auto decoded_it = decoded_images_.Get(key);
  CacheEntry* cache_entry = nullptr;
  if (decoded_it == decoded_images_.end()) {
    // There is no reason to create a new entry if we know it won't fit anyway.
    if (!new_image_fits_in_memory)
      return TaskResult(false);
    cache_entry = AddCacheEntry(key);
    if (task_type == DecodeTaskType::USE_OUT_OF_RASTER_TASKS)
      cache_entry->mark_out_of_raster();
  } else {
    cache_entry = decoded_it->second.get();
  }
  DCHECK(cache_entry);

  if (!cache_entry->is_budgeted) {
    if (!new_image_fits_in_memory) {
      // We don't need to ref anything here because this image will be at
      // raster.
      return TaskResult(false);
    }
    AddBudgetForImage(key, cache_entry);
  }
  DCHECK(cache_entry->is_budgeted);

  // The rest of the code will return either true or a task, so we should ref
  // the image once now for the caller to unref.
  ++cache_entry->ref_count;

  // If we already have a locked entry, then we can just use that. Otherwise
  // we'll have to create a task.
  if (cache_entry->is_locked)
    return TaskResult(true);

  scoped_refptr<TileTask>& task =
      task_type == DecodeTaskType::USE_IN_RASTER_TASKS
          ? cache_entry->in_raster_task
          : cache_entry->out_of_raster_task;
  if (!task) {
    // Ref image once for the decode task.
    ++cache_entry->ref_count;
    task = base::MakeRefCounted<SoftwareImageDecodeTaskImpl>(
        this, key, image.paint_image(), task_type, tracing_info);
  }
  return TaskResult(task);
}

void SoftwareImageDecodeCache::AddBudgetForImage(const CacheKey& key,
                                                 CacheEntry* entry) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
               "SoftwareImageDecodeCache::AddBudgetForImage", "key",
               key.ToString());
  lock_.AssertAcquired();

  DCHECK(!entry->is_budgeted);
  DCHECK_GE(locked_images_budget_.AvailableMemoryBytes(), key.locked_bytes());
  locked_images_budget_.AddUsage(key.locked_bytes());
  entry->is_budgeted = true;
}

void SoftwareImageDecodeCache::RemoveBudgetForImage(const CacheKey& key,
                                                    CacheEntry* entry) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
               "SoftwareImageDecodeCache::RemoveBudgetForImage", "key",
               key.ToString());
  lock_.AssertAcquired();

  DCHECK(entry->is_budgeted);
  locked_images_budget_.SubtractUsage(key.locked_bytes());
  entry->is_budgeted = false;
}

void SoftwareImageDecodeCache::UnrefImage(const DrawImage& image) {
  const CacheKey& key = CacheKey::FromDrawImage(image, color_type_);
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
               "SoftwareImageDecodeCache::UnrefImage", "key", key.ToString());

  base::AutoLock lock(lock_);
  UnrefImage(key);
}

void SoftwareImageDecodeCache::UnrefImage(const CacheKey& key) {
  lock_.AssertAcquired();
  auto decoded_image_it = decoded_images_.Peek(key);
  DCHECK(decoded_image_it != decoded_images_.end());
  auto* entry = decoded_image_it->second.get();
  DCHECK_GT(entry->ref_count, 0);
  if (--entry->ref_count == 0) {
    if (entry->is_budgeted)
      RemoveBudgetForImage(key, entry);
    if (entry->is_locked)
      entry->Unlock();
  }
}

void SoftwareImageDecodeCache::DecodeImageInTask(const CacheKey& key,
                                                 const PaintImage& paint_image,
                                                 DecodeTaskType task_type) {
  TRACE_EVENT1("cc", "SoftwareImageDecodeCache::DecodeImageInTask", "key",
               key.ToString());
  base::AutoLock lock(lock_);

  auto image_it = decoded_images_.Peek(key);
  DCHECK(image_it != decoded_images_.end());
  auto* cache_entry = image_it->second.get();
  // These two checks must be true because we're running this from a task, which
  // means that we've budgeted this entry when we got the task and the ref count
  // is also held by the task (released in OnTaskCompleted).
  DCHECK_GT(cache_entry->ref_count, 0);
  DCHECK(cache_entry->is_budgeted);

  DecodeImageIfNecessary(key, paint_image, cache_entry);
  DCHECK(cache_entry->decode_failed || cache_entry->is_locked);
  RecordImageMipLevelUMA(
      MipMapUtil::GetLevelForSize(key.src_rect().size(), key.target_size()));
}

void SoftwareImageDecodeCache::DecodeImageIfNecessary(
    const CacheKey& key,
    const PaintImage& paint_image,
    CacheEntry* entry) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
               "SoftwareImageDecodeCache::DecodeImageIfNecessary", "key",
               key.ToString());
  lock_.AssertAcquired();
  DCHECK_GT(entry->ref_count, 0);

  if (key.target_size().IsEmpty())
    entry->decode_failed = true;

  if (entry->decode_failed)
    return;

  if (entry->memory) {
    if (entry->is_locked)
      return;

    bool lock_succeeded = entry->Lock();
    // TODO(vmpstr): Deprecate the prepaint split, since it doesn't matter.
    RecordLockExistingCachedImageHistogram(TilePriority::NOW, lock_succeeded);

    if (lock_succeeded)
      return;
  }

  std::unique_ptr<CacheEntry> local_cache_entry;
  // If we can use the original decode, we'll definitely need a decode.
  if (key.type() == CacheKey::kOriginal) {
    base::AutoUnlock release(lock_);
    local_cache_entry = Utils::DoDecodeImage(key, paint_image, color_type_);
  } else {
    // Use the full image decode to generate a scaled/subrected decode.
    // TODO(vmpstr): This part needs to handle decode to scale.
    base::Optional<CacheKey> candidate_key;
    auto image_keys_it = frame_key_to_image_keys_.find(key.frame_key());
    // We know that we must have at least our own |entry| in this list, so it
    // won't be empty.
    DCHECK(image_keys_it != frame_key_to_image_keys_.end());

    auto& available_keys = image_keys_it->second;
    std::sort(available_keys.begin(), available_keys.end(),
              [](const CacheKey& one, const CacheKey& two) {
                // Return true if |one| scale is less than |two| scale.
                return one.target_size().width() < two.target_size().width() &&
                       one.target_size().height() < two.target_size().height();
              });

    for (auto& available_key : available_keys) {
      // Only consider keys coming from the same src rect, since otherwise the
      // resulting image was extracted using a different src.
      if (available_key.src_rect() != key.src_rect())
        continue;

      // that are at least as big as the required |key|.
      if (available_key.target_size().width() < key.target_size().width() ||
          available_key.target_size().height() < key.target_size().height()) {
        continue;
      }
      auto image_it = decoded_images_.Peek(available_key);
      DCHECK(image_it != decoded_images_.end());
      auto* available_entry = image_it->second.get();
      if (available_entry->is_locked || available_entry->Lock()) {
        candidate_key.emplace(available_key);
        break;
      }
    }

    if (!candidate_key) {
      // IMPORTANT: There is a bit of a subtlety here. We would normally want to
      // generate a new candidate with the key.src_rect() as the src_rect. This
      // would ensure that when scaling we won't need to peek pixels, since it's
      // unclear how to adjust the src rect to account for the candidate scale
      // if the candidate came from above.
      //
      // However, if the key type is kSubrectOriginal, then this would generate
      // an exactly same key as we want in the first place, causing infinite
      // recursion. (There is a CHECK guard for this below, since this is a
      // pretty bad case.)
      //
      // Since kSubrectOriginal means we have no scale, to remedy the situation
      // we use the full image rect as the src for this temporary candidate.
      // This way the GenerateCacheEntryFromCandidate() function will simply
      // extract the subset and be done with it.
      auto src_rect =
          key.type() == CacheKey::kSubrectOriginal
              ? SkIRect::MakeWH(paint_image.width(), paint_image.height())
              : gfx::RectToSkIRect(key.src_rect());
      DrawImage candidate_draw_image(
          paint_image, src_rect, kNone_SkFilterQuality, SkMatrix::I(),
          key.frame_key().frame_index(), key.target_color_space());
      candidate_key.emplace(
          CacheKey::FromDrawImage(candidate_draw_image, color_type_));
    }
    CHECK(*candidate_key != key) << key.ToString();

    auto decoded_draw_image =
        GetDecodedImageForDrawInternal(*candidate_key, paint_image);
    if (!decoded_draw_image.image()) {
      local_cache_entry = nullptr;
    } else {
      base::AutoUnlock release(lock_);
      // IMPORTANT: More subtleties:
      // If the candidate could have used the original decode, that means we
      // need to extractSubset from it. In all other cases, this would have
      // already been done to generate the candidate.
      local_cache_entry = Utils::GenerateCacheEntryFromCandidate(
          key, decoded_draw_image, candidate_key->type() == CacheKey::kOriginal,
          color_type_);
    }

    // Unref to balance the GetDecodedImageForDrawInternal() call.
    UnrefImage(*candidate_key);
  }

  if (!local_cache_entry) {
    entry->decode_failed = true;
    return;
  }

  // Just in case someone else did this already, just unlock our work.
  // TODO(vmpstr): It's possible to have a pending decode state where the
  // thread would just block on a cv and wait for that decode to finish
  // instead of actually doing the work.
  if (entry->memory) {
    // This would have to be locked because we hold a ref count on the entry. So
    // if someone ever populated the entry with memory, they would not be able
    // to unlock it.
    DCHECK(entry->is_locked);
    // Unlock our local memory though.
    local_cache_entry->Unlock();
  } else {
    local_cache_entry->MoveImageMemoryTo(entry);
    DCHECK(entry->is_locked);
  }
}

DecodedDrawImage SoftwareImageDecodeCache::GetDecodedImageForDraw(
    const DrawImage& draw_image) {
  // Non-cached images are be used for raster directly.
  if (!UseCacheForDrawImage(draw_image)) {
    return DecodedDrawImage(draw_image.paint_image().GetSkImage(),
                            SkSize::Make(0, 0), SkSize::Make(1.f, 1.f),
                            draw_image.filter_quality(),
                            true /* is_budgeted */);
  }

  base::AutoLock hold(lock_);
  return GetDecodedImageForDrawInternal(
      CacheKey::FromDrawImage(draw_image, color_type_),
      draw_image.paint_image());
}

DecodedDrawImage SoftwareImageDecodeCache::GetDecodedImageForDrawInternal(
    const CacheKey& key,
    const PaintImage& paint_image) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
               "SoftwareImageDecodeCache::GetDecodedImageForDrawInternal",
               "key", key.ToString());

  lock_.AssertAcquired();
  auto decoded_it = decoded_images_.Get(key);
  CacheEntry* cache_entry = nullptr;
  if (decoded_it == decoded_images_.end())
    cache_entry = AddCacheEntry(key);
  else
    cache_entry = decoded_it->second.get();

  // We'll definitely ref this cache entry and use it.
  ++cache_entry->ref_count;
  cache_entry->mark_used();

  DecodeImageIfNecessary(key, paint_image, cache_entry);
  auto decoded_image = cache_entry->image();
  if (!decoded_image)
    return DecodedDrawImage();

  auto decoded_draw_image =
      DecodedDrawImage(std::move(decoded_image), cache_entry->src_rect_offset(),
                       GetScaleAdjustment(key), GetDecodedFilterQuality(key),
                       cache_entry->is_budgeted);
  return decoded_draw_image;
}

void SoftwareImageDecodeCache::DrawWithImageFinished(
    const DrawImage& image,
    const DecodedDrawImage& decoded_image) {
  if (!UseCacheForDrawImage(image))
    return;

  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
               "SoftwareImageDecodeCache::DrawWithImageFinished", "key",
               CacheKey::FromDrawImage(image, color_type_).ToString());
  UnrefImage(image);
}

void SoftwareImageDecodeCache::ReduceCacheUsageUntilWithinLimit(size_t limit) {
  TRACE_EVENT0("cc",
               "SoftwareImageDecodeCache::ReduceCacheUsageUntilWithinLimit");
  lifetime_max_items_in_cache_ =
      std::max(lifetime_max_items_in_cache_, decoded_images_.size());
  for (auto it = decoded_images_.rbegin();
       decoded_images_.size() > limit && it != decoded_images_.rend();) {
    EraseCacheEntry(&it);
  }
}

void SoftwareImageDecodeCache::ReduceCacheUsage() {
  base::AutoLock lock(lock_);
  ReduceCacheUsageUntilWithinLimit(max_items_in_cache_);
}

void SoftwareImageDecodeCache::ClearCache() {
  base::AutoLock lock(lock_);
  ReduceCacheUsageUntilWithinLimit(0);
}

size_t SoftwareImageDecodeCache::GetMaximumMemoryLimitBytes() const {
  return locked_images_budget_.total_limit_bytes();
}

void SoftwareImageDecodeCache::OnImageDecodeTaskCompleted(
    const CacheKey& key,
    DecodeTaskType task_type) {
  base::AutoLock hold(lock_);

  auto image_it = decoded_images_.Peek(key);
  DCHECK(image_it != decoded_images_.end());
  CacheEntry* cache_entry = image_it->second.get();
  auto& task = task_type == DecodeTaskType::USE_IN_RASTER_TASKS
                   ? cache_entry->in_raster_task
                   : cache_entry->out_of_raster_task;
  task = nullptr;

  UnrefImage(key);
}

bool SoftwareImageDecodeCache::OnMemoryDump(
    const base::trace_event::MemoryDumpArgs& args,
    base::trace_event::ProcessMemoryDump* pmd) {
  base::AutoLock lock(lock_);

  if (args.level_of_detail == MemoryDumpLevelOfDetail::BACKGROUND) {
    std::string dump_name = base::StringPrintf(
        "cc/image_memory/cache_0x%" PRIXPTR, reinterpret_cast<uintptr_t>(this));
    MemoryAllocatorDump* dump = pmd->CreateAllocatorDump(dump_name);
    dump->AddScalar("locked_size", MemoryAllocatorDump::kUnitsBytes,
                    locked_images_budget_.GetCurrentUsageSafe());
  } else {
    for (const auto& image_pair : decoded_images_) {
      int image_id = static_cast<int>(image_pair.first.frame_key().hash());
      CacheEntry* entry = image_pair.second.get();
      DCHECK(entry);
      // We might not have memory for this cache entry, depending on where int
      // he CacheEntry lifecycle we are. If we don't have memory, then we don't
      // have to record it in the dump.
      if (!entry->memory)
        continue;

      std::string dump_name = base::StringPrintf(
          "cc/image_memory/cache_0x%" PRIXPTR "/%s/image_%" PRIu64 "_id_%d",
          reinterpret_cast<uintptr_t>(this),
          entry->is_budgeted ? "budgeted" : "at_raster", entry->tracing_id(),
          image_id);
      // CreateMemoryAllocatorDump will automatically add tracking values for
      // the total size. We also add a "locked_size" below.
      MemoryAllocatorDump* dump =
          entry->memory->CreateMemoryAllocatorDump(dump_name.c_str(), pmd);
      DCHECK(dump);
      size_t locked_bytes =
          entry->is_locked ? image_pair.first.locked_bytes() : 0u;
      dump->AddScalar("locked_size", MemoryAllocatorDump::kUnitsBytes,
                      locked_bytes);
    }
  }

  // Memory dump can't fail, always return true.
  return true;
}

void SoftwareImageDecodeCache::OnMemoryStateChange(base::MemoryState state) {
  {
    base::AutoLock hold(lock_);
    switch (state) {
      case base::MemoryState::NORMAL:
        max_items_in_cache_ = kNormalMaxItemsInCacheForSoftware;
        break;
      case base::MemoryState::THROTTLED:
        max_items_in_cache_ = kThrottledMaxItemsInCacheForSoftware;
        break;
      case base::MemoryState::SUSPENDED:
        max_items_in_cache_ = kSuspendedMaxItemsInCacheForSoftware;
        break;
      case base::MemoryState::UNKNOWN:
        NOTREACHED();
        return;
    }
  }
}

void SoftwareImageDecodeCache::OnPurgeMemory() {
  base::AutoLock lock(lock_);
  ReduceCacheUsageUntilWithinLimit(0);
}

SoftwareImageDecodeCache::CacheEntry* SoftwareImageDecodeCache::AddCacheEntry(
    const CacheKey& key) {
  lock_.AssertAcquired();

  frame_key_to_image_keys_[key.frame_key()].push_back(key);

  PaintImage::ContentId content_id = key.frame_key().content_id();
  content_id_to_cache_keys_[content_id].insert(key);
  ContentIdSet& content_ids_for_stable_id =
      stable_id_to_content_ids_[key.stable_id()];
  content_ids_for_stable_id.insert(content_id);

  auto it = decoded_images_.Put(key, std::make_unique<CacheEntry>());
  it->second.get()->mark_cached();

  // If we have more than two content ids for this stable id, then try to erase
  // all images for all content ids except for the most recent two (and also
  // |key|'s content id, in case it is not one of the most recent two).
  if (content_ids_for_stable_id.size() > 2) {
    ContentIdSet content_ids_to_remove = content_ids_for_stable_id;
    content_ids_to_remove.erase(*content_ids_to_remove.rbegin());
    content_ids_to_remove.erase(*content_ids_to_remove.rbegin());
    content_ids_to_remove.erase(content_id);
    for (auto content_id_to_erase : content_ids_to_remove) {
      CacheKeySet cache_keys_to_remove =
          content_id_to_cache_keys_[content_id_to_erase];
      for (const CacheKey& key : cache_keys_to_remove) {
        auto found = decoded_images_.Peek(key);
        DCHECK(found != decoded_images_.end());
        auto found_reversed = std::make_reverse_iterator(found);
        EraseCacheEntry(&found_reversed);
      }
    }
  }

  return it->second.get();
}

void SoftwareImageDecodeCache::EraseCacheEntry(
    ImageMRUCache::reverse_iterator* it) {
  if ((*it)->second->ref_count != 0) {
    ++(*it);
    return;
  }
  const CacheKey& key = (*it)->first;
  PaintImage::ContentId content_id = key.frame_key().content_id();
  PaintImage::Id stable_id = key.stable_id();

  // Remove from |content_id_to_cache_keys_|.
  auto found_cache_key_set = content_id_to_cache_keys_.find(content_id);
  DCHECK(found_cache_key_set != content_id_to_cache_keys_.end());
  found_cache_key_set->second.erase(key);
  // If this erases the last entry for |content_id|, then...
  if (found_cache_key_set->second.empty()) {
    // Erase |content_id| from |content_id_to_cache_keys_|.
    content_id_to_cache_keys_.erase(found_cache_key_set);
    // Erase |content_id| from |stable_id_to_content_ids_[stable_id]|.
    auto found_content_id_set = stable_id_to_content_ids_.find(stable_id);
    DCHECK(found_content_id_set != stable_id_to_content_ids_.end());
    auto found_content_id = found_content_id_set->second.find(content_id);
    DCHECK(found_content_id != found_content_id_set->second.end());
    found_content_id_set->second.erase(found_content_id);
    // If that empties |stable_id_to_content_ids_[stable_id]|, then erase
    // |stable_id| from |stable_id_to_content_ids_|.
    if (found_content_id_set->second.empty()) {
      stable_id_to_content_ids_.erase(found_content_id_set);
    }
  }

  // Remove from |frame_key_to_image_keys_|.
  auto vector_it = frame_key_to_image_keys_.find(key.frame_key());
  auto item_it =
      std::find(vector_it->second.begin(), vector_it->second.end(), key);
  DCHECK(item_it != vector_it->second.end());
  vector_it->second.erase(item_it);
  if (vector_it->second.empty())
    frame_key_to_image_keys_.erase(vector_it);

  // Remove from the MRU cache.
  *it = decoded_images_.Erase(*it);
  return;
}

// MemoryBudget ----------------------------------------------------------------
SoftwareImageDecodeCache::MemoryBudget::MemoryBudget(size_t limit_bytes)
    : limit_bytes_(limit_bytes), current_usage_bytes_(0u) {}

size_t SoftwareImageDecodeCache::MemoryBudget::AvailableMemoryBytes() const {
  size_t usage = GetCurrentUsageSafe();
  return usage >= limit_bytes_ ? 0u : (limit_bytes_ - usage);
}

void SoftwareImageDecodeCache::MemoryBudget::AddUsage(size_t usage) {
  current_usage_bytes_ += usage;
}

void SoftwareImageDecodeCache::MemoryBudget::SubtractUsage(size_t usage) {
  DCHECK_GE(current_usage_bytes_.ValueOrDefault(0u), usage);
  current_usage_bytes_ -= usage;
}

void SoftwareImageDecodeCache::MemoryBudget::ResetUsage() {
  current_usage_bytes_ = 0;
}

size_t SoftwareImageDecodeCache::MemoryBudget::GetCurrentUsageSafe() const {
  return current_usage_bytes_.ValueOrDie();
}

}  // namespace cc

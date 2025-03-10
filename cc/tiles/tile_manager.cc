// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cc/tiles/tile_manager.h"

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <limits>
#include <string>

#include "base/bind.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/metrics/histogram.h"
#include "base/numerics/safe_conversions.h"
#include "base/optional.h"
#include "base/sys_info.h"
#include "base/threading/thread_checker.h"
#include "base/trace_event/trace_event_argument.h"
#include "cc/base/devtools_instrumentation.h"
#include "cc/base/histograms.h"
#include "cc/layers/picture_layer_impl.h"
#include "cc/raster/playback_image_provider.h"
#include "cc/raster/raster_buffer.h"
#include "cc/raster/task_category.h"
#include "cc/tiles/frame_viewer_instrumentation.h"
#include "cc/tiles/tile.h"
#include "components/viz/common/resources/resource_sizes.h"
#include "ui/gfx/geometry/axis_transform2d.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace cc {
namespace {

// Flag to indicate whether we should try and detect that
// a tile is of solid color.
const bool kUseColorEstimator = true;

DEFINE_SCOPED_UMA_HISTOGRAM_AREA_TIMER(
    ScopedSoftwareRasterTaskTimer,
    "Compositing.%s.RasterTask.RasterUs.Software",
    "Compositing.%s.RasterTask.RasterPixelsPerMs2.Software");

DEFINE_SCOPED_UMA_HISTOGRAM_AREA_TIMER(
    ScopedGpuRasterTaskTimer,
    "Compositing.%s.RasterTask.RasterUs.Gpu",
    "Compositing.%s.RasterTask.RasterPixelsPerMs2.Gpu");

class ScopedRasterTaskTimer {
 public:
  explicit ScopedRasterTaskTimer(bool use_gpu_rasterization) {
    if (use_gpu_rasterization)
      gpu_timer_.emplace();
    else
      software_timer_.emplace();
  }

  void SetArea(int area) {
    if (software_timer_)
      software_timer_->SetArea(area);
    if (gpu_timer_)
      gpu_timer_->SetArea(area);
  }

 private:
  base::Optional<ScopedSoftwareRasterTaskTimer> software_timer_;
  base::Optional<ScopedGpuRasterTaskTimer> gpu_timer_;
};

class RasterTaskImpl : public TileTask {
 public:
  RasterTaskImpl(TileManager* tile_manager,
                 Tile* tile,
                 ResourcePool::InUsePoolResource resource,
                 scoped_refptr<RasterSource> raster_source,
                 const RasterSource::PlaybackSettings& playback_settings,
                 TileResolution tile_resolution,
                 gfx::Rect invalidated_rect,
                 uint64_t source_prepare_tiles_id,
                 std::unique_ptr<RasterBuffer> raster_buffer,
                 TileTask::Vector* dependencies,
                 bool is_gpu_rasterization,
                 PlaybackImageProvider image_provider)
      : TileTask(!is_gpu_rasterization, dependencies),
        tile_manager_(tile_manager),
        tile_id_(tile->id()),
        resource_(std::move(resource)),
        raster_source_(std::move(raster_source)),
        content_rect_(tile->content_rect()),
        invalid_content_rect_(invalidated_rect),
        raster_transform_(tile->raster_transform()),
        playback_settings_(playback_settings),
        tile_resolution_(tile_resolution),
        layer_id_(tile->layer_id()),
        source_prepare_tiles_id_(source_prepare_tiles_id),
        tile_tracing_id_(static_cast<void*>(tile)),
        new_content_id_(tile->id()),
        source_frame_number_(tile->source_frame_number()),
        is_gpu_rasterization_(is_gpu_rasterization),
        raster_buffer_(std::move(raster_buffer)),
        image_provider_(std::move(image_provider)) {
    DCHECK(origin_thread_checker_.CalledOnValidThread());
    playback_settings_.image_provider = &image_provider_;
  }

  // Overridden from Task:
  void RunOnWorkerThread() override {
    TRACE_EVENT1("cc", "RasterizerTaskImpl::RunOnWorkerThread",
                 "source_prepare_tiles_id", source_prepare_tiles_id_);

    DCHECK(raster_source_.get());
    DCHECK(raster_buffer_);

    frame_viewer_instrumentation::ScopedRasterTask raster_task(
        tile_tracing_id_, tile_resolution_, source_frame_number_, layer_id_);
    ScopedRasterTaskTimer timer(is_gpu_rasterization_);
    timer.SetArea(content_rect_.size().GetArea());

    DCHECK(raster_source_);

    raster_buffer_->Playback(raster_source_.get(), content_rect_,
                             invalid_content_rect_, new_content_id_,
                             raster_transform_, playback_settings_);
  }

  // Overridden from TileTask:
  void OnTaskCompleted() override {
    DCHECK(origin_thread_checker_.CalledOnValidThread());

    // Here calling state().IsCanceled() is thread-safe, because this task is
    // already concluded as FINISHED or CANCELLED and no longer will be worked
    // upon by task graph runner.
    raster_buffer_ = nullptr;
    tile_manager_->OnRasterTaskCompleted(tile_id_, std::move(resource_),
                                         state().IsCanceled());
  }

 protected:
  ~RasterTaskImpl() override {
    DCHECK(origin_thread_checker_.CalledOnValidThread());
    DCHECK(!raster_buffer_);
    DCHECK(!resource_);
  }

 private:
  base::ThreadChecker origin_thread_checker_;

  // The following members are needed for processing completion of this task on
  // origin thread. These are not thread-safe and should be accessed only in
  // origin thread. Ensure their access by checking CalledOnValidThread().
  TileManager* tile_manager_;
  Tile::Id tile_id_;
  ResourcePool::InUsePoolResource resource_;

  // The following members should be used for running the task.
  scoped_refptr<RasterSource> raster_source_;
  gfx::Rect content_rect_;
  gfx::Rect invalid_content_rect_;
  gfx::AxisTransform2d raster_transform_;
  RasterSource::PlaybackSettings playback_settings_;
  TileResolution tile_resolution_;
  int layer_id_;
  uint64_t source_prepare_tiles_id_;
  void* tile_tracing_id_;
  uint64_t new_content_id_;
  int source_frame_number_;
  bool is_gpu_rasterization_;
  std::unique_ptr<RasterBuffer> raster_buffer_;
  PlaybackImageProvider image_provider_;

  DISALLOW_COPY_AND_ASSIGN(RasterTaskImpl);
};

TaskCategory TaskCategoryForTileTask(TileTask* task,
                                     bool use_foreground_category) {
  if (!task->supports_concurrent_execution())
    return TASK_CATEGORY_NONCONCURRENT_FOREGROUND;

  if (use_foreground_category)
    return TASK_CATEGORY_FOREGROUND;

  return TASK_CATEGORY_BACKGROUND;
}

bool IsForegroundCategory(uint16_t category) {
  TaskCategory enum_category = static_cast<TaskCategory>(category);
  switch (enum_category) {
    case TASK_CATEGORY_NONCONCURRENT_FOREGROUND:
    case TASK_CATEGORY_FOREGROUND:
      return true;
    case TASK_CATEGORY_BACKGROUND:
      return false;
  }

  DCHECK(false);
  return false;
}

// Task priorities that make sure that the task set done tasks run before any
// other remaining tasks.
const size_t kRequiredForActivationDoneTaskPriority = 1u;
const size_t kRequiredForDrawDoneTaskPriority = 2u;
const size_t kAllDoneTaskPriority = 3u;

// For correctness, |kTileTaskPriorityBase| must be greater than
// all task set done task priorities.
size_t kTileTaskPriorityBase = 10u;

void InsertNodeForTask(TaskGraph* graph,
                       TileTask* task,
                       uint16_t category,
                       uint16_t priority,
                       size_t dependencies) {
  DCHECK(std::find_if(graph->nodes.begin(), graph->nodes.end(),
                      [&task](const TaskGraph::Node& node) {
                        return node.task == task;
                      }) == graph->nodes.end());
  graph->nodes.emplace_back(task, category, priority, dependencies);
}

void InsertNodeForDecodeTask(TaskGraph* graph,
                             TileTask* task,
                             bool use_foreground_category,
                             uint16_t priority) {
  uint32_t dependency_count = 0u;
  if (task->dependencies().size()) {
    DCHECK_EQ(task->dependencies().size(), 1u);
    auto* dependency = task->dependencies()[0].get();
    if (!dependency->HasCompleted()) {
      InsertNodeForDecodeTask(graph, dependency, use_foreground_category,
                              priority);
      graph->edges.emplace_back(dependency, task);
      dependency_count = 1u;
    }
  }
  InsertNodeForTask(graph, task,
                    TaskCategoryForTileTask(task, use_foreground_category),
                    priority, dependency_count);
}

void InsertNodesForRasterTask(TaskGraph* graph,
                              TileTask* raster_task,
                              const TileTask::Vector& decode_tasks,
                              size_t priority,
                              bool use_foreground_category) {
  size_t dependencies = 0u;

  // Insert image decode tasks.
  for (TileTask::Vector::const_iterator it = decode_tasks.begin();
       it != decode_tasks.end(); ++it) {
    TileTask* decode_task = it->get();

    // Skip if already decoded.
    if (decode_task->HasCompleted())
      continue;

    dependencies++;

    // Add decode task if it doesn't already exist in graph.
    TaskGraph::Node::Vector::iterator decode_it =
        std::find_if(graph->nodes.begin(), graph->nodes.end(),
                     [decode_task](const TaskGraph::Node& node) {
                       return node.task == decode_task;
                     });

    // In rare circumstances, a background category task may come in before a
    // foreground category task. In these cases, upgrade any background category
    // dependencies of the current task.
    // TODO(ericrk): Task iterators should be updated to avoid this.
    // crbug.com/594851
    // TODO(ericrk): This should handle dependencies recursively.
    // crbug.com/605234
    if (decode_it != graph->nodes.end() && use_foreground_category &&
        !IsForegroundCategory(decode_it->category)) {
      decode_it->category = TASK_CATEGORY_FOREGROUND;
    }

    if (decode_it == graph->nodes.end()) {
      InsertNodeForDecodeTask(graph, decode_task, use_foreground_category,
                              priority);
    }

    graph->edges.emplace_back(decode_task, raster_task);
  }

  InsertNodeForTask(
      graph, raster_task,
      TaskCategoryForTileTask(raster_task, use_foreground_category), priority,
      dependencies);
}

class TaskSetFinishedTaskImpl : public TileTask {
 public:
  explicit TaskSetFinishedTaskImpl(
      base::SequencedTaskRunner* task_runner,
      const base::Closure& on_task_set_finished_callback)
      : TileTask(true),
        task_runner_(task_runner),
        on_task_set_finished_callback_(on_task_set_finished_callback) {}

  // Overridden from Task:
  void RunOnWorkerThread() override {
    TRACE_EVENT0("cc", "TaskSetFinishedTaskImpl::RunOnWorkerThread");
    TaskSetFinished();
  }

  // Overridden from TileTask:
  void OnTaskCompleted() override {}

 protected:
  ~TaskSetFinishedTaskImpl() override = default;

  void TaskSetFinished() {
    task_runner_->PostTask(FROM_HERE, on_task_set_finished_callback_);
  }

 private:
  base::SequencedTaskRunner* task_runner_;
  const base::Closure on_task_set_finished_callback_;

  DISALLOW_COPY_AND_ASSIGN(TaskSetFinishedTaskImpl);
};

}  // namespace

RasterTaskCompletionStats::RasterTaskCompletionStats()
    : completed_count(0u), canceled_count(0u) {}

std::unique_ptr<base::trace_event::ConvertableToTraceFormat>
RasterTaskCompletionStatsAsValue(const RasterTaskCompletionStats& stats) {
  std::unique_ptr<base::trace_event::TracedValue> state(
      new base::trace_event::TracedValue());
  state->SetInteger("completed_count",
                    base::saturated_cast<int>(stats.completed_count));
  state->SetInteger("canceled_count",
                    base::saturated_cast<int>(stats.canceled_count));
  return std::move(state);
}

TileManager::TileManager(
    TileManagerClient* client,
    base::SequencedTaskRunner* origin_task_runner,
    scoped_refptr<base::SequencedTaskRunner> image_worker_task_runner,
    size_t scheduled_raster_task_limit,
    const TileManagerSettings& tile_manager_settings)
    : client_(client),
      task_runner_(origin_task_runner),
      resource_pool_(nullptr),
      tile_task_manager_(nullptr),
      scheduled_raster_task_limit_(scheduled_raster_task_limit),
      tile_manager_settings_(tile_manager_settings),
      use_gpu_rasterization_(false),
      all_tiles_that_need_to_be_rasterized_are_scheduled_(true),
      did_check_for_completed_tasks_since_last_schedule_tasks_(true),
      did_oom_on_last_assign_(false),
      image_controller_(origin_task_runner,
                        std::move(image_worker_task_runner)),
      checker_image_tracker_(&image_controller_,
                             this,
                             tile_manager_settings_.enable_checker_imaging,
                             tile_manager_settings_.min_image_bytes_to_checker),
      more_tiles_need_prepare_check_notifier_(
          task_runner_,
          base::Bind(&TileManager::CheckIfMoreTilesNeedToBePrepared,
                     base::Unretained(this))),
      signals_check_notifier_(task_runner_,
                              base::Bind(&TileManager::FlushAndIssueSignals,
                                         base::Unretained(this))),
      has_scheduled_tile_tasks_(false),
      prepare_tiles_count_(0u),
      next_tile_id_(0u),
      task_set_finished_weak_ptr_factory_(this),
      ready_to_draw_callback_weak_ptr_factory_(this) {}

TileManager::~TileManager() {
  FinishTasksAndCleanUp();
}

void TileManager::FinishTasksAndCleanUp() {
  if (!tile_task_manager_)
    return;

  global_state_ = GlobalStateThatImpactsTilePriority();

  // This cancels tasks if possible, finishes pending tasks, and release any
  // uninitialized resources.
  tile_task_manager_->Shutdown();

  raster_buffer_provider_->Shutdown();

  tile_task_manager_->CheckForCompletedTasks();

  tile_task_manager_ = nullptr;
  resource_pool_ = nullptr;
  more_tiles_need_prepare_check_notifier_.Cancel();
  signals_check_notifier_.Cancel();
  task_set_finished_weak_ptr_factory_.InvalidateWeakPtrs();
  ready_to_draw_callback_weak_ptr_factory_.InvalidateWeakPtrs();
  raster_buffer_provider_ = nullptr;

  // Ask the tracker to drop any locked decodes since we will be destroying the
  // decode cache.
  bool can_clear_decode_policy_tracking = false;
  checker_image_tracker_.ClearTracker(can_clear_decode_policy_tracking);
  image_controller_.SetImageDecodeCache(nullptr);
  locked_image_tasks_.clear();
}

void TileManager::SetResources(ResourcePool* resource_pool,
                               ImageDecodeCache* image_decode_cache,
                               TaskGraphRunner* task_graph_runner,
                               RasterBufferProvider* raster_buffer_provider,
                               bool use_gpu_rasterization) {
  DCHECK(!tile_task_manager_);
  DCHECK(task_graph_runner);

  use_gpu_rasterization_ = use_gpu_rasterization;
  resource_pool_ = resource_pool;
  image_controller_.SetImageDecodeCache(image_decode_cache);
  tile_task_manager_ = TileTaskManagerImpl::Create(task_graph_runner);
  raster_buffer_provider_ = raster_buffer_provider;
}

void TileManager::Release(Tile* tile) {
  if (tile->raster_task_scheduled_with_checker_images())
    num_of_tiles_with_checker_images_--;
  DCHECK_GE(num_of_tiles_with_checker_images_, 0);

  FreeResourcesForTile(tile);
  tiles_.erase(tile->id());
}

void TileManager::DidFinishRunningTileTasksRequiredForActivation() {
  TRACE_EVENT0("cc",
               "TileManager::DidFinishRunningTileTasksRequiredForActivation");
  TRACE_EVENT_ASYNC_STEP_INTO1("cc", "ScheduledTasks", this, "running", "state",
                               ScheduledTasksStateAsValue());
  // TODO(vmpstr): Temporary check to debug crbug.com/642927.
  CHECK(tile_task_manager_);
  signals_.activate_tile_tasks_completed = true;
  signals_check_notifier_.Schedule();
}

void TileManager::DidFinishRunningTileTasksRequiredForDraw() {
  TRACE_EVENT0("cc", "TileManager::DidFinishRunningTileTasksRequiredForDraw");
  TRACE_EVENT_ASYNC_STEP_INTO1("cc", "ScheduledTasks", this, "running", "state",
                               ScheduledTasksStateAsValue());
  // TODO(vmpstr): Temporary check to debug crbug.com/642927.
  CHECK(tile_task_manager_);
  signals_.draw_tile_tasks_completed = true;
  signals_check_notifier_.Schedule();
}

void TileManager::DidFinishRunningAllTileTasks() {
  TRACE_EVENT0("cc", "TileManager::DidFinishRunningAllTileTasks");
  TRACE_EVENT_ASYNC_END0("cc", "ScheduledTasks", this);
  DCHECK(resource_pool_);
  DCHECK(tile_task_manager_);

  has_scheduled_tile_tasks_ = false;

  if (all_tiles_that_need_to_be_rasterized_are_scheduled_ &&
      !resource_pool_->ResourceUsageTooHigh()) {
    // TODO(ericrk): We should find a better way to safely handle re-entrant
    // notifications than always having to schedule a new task.
    // http://crbug.com/498439
    // TODO(vmpstr): Temporary check to debug crbug.com/642927.
    CHECK(tile_task_manager_);
    signals_.all_tile_tasks_completed = true;
    signals_check_notifier_.Schedule();
    return;
  }

  more_tiles_need_prepare_check_notifier_.Schedule();
}

bool TileManager::PrepareTiles(
    const GlobalStateThatImpactsTilePriority& state) {
  ++prepare_tiles_count_;

  TRACE_EVENT1("cc", "TileManager::PrepareTiles", "prepare_tiles_id",
               prepare_tiles_count_);

  if (!tile_task_manager_) {
    TRACE_EVENT_INSTANT0("cc", "PrepareTiles aborted",
                         TRACE_EVENT_SCOPE_THREAD);
    return false;
  }

  signals_ = Signals();
  global_state_ = state;

  // Ensure that we don't schedule any decode work for checkered images until
  // the raster work for visible tiles is complete. This is done in
  // FlushAndIssueSignals when the ready to activate/draw signals are dispatched
  // to the client.
  checker_image_tracker_.SetNoDecodesAllowed();

  // We need to call CheckForCompletedTasks() once in-between each call
  // to ScheduleTasks() to prevent canceled tasks from being scheduled.
  if (!did_check_for_completed_tasks_since_last_schedule_tasks_) {
    tile_task_manager_->CheckForCompletedTasks();
    did_check_for_completed_tasks_since_last_schedule_tasks_ = true;
  }

  PrioritizedWorkToSchedule prioritized_work = AssignGpuMemoryToTiles();

  // Inform the client that will likely require a draw if the highest priority
  // tile that will be rasterized is required for draw.
  client_->SetIsLikelyToRequireADraw(
      !prioritized_work.tiles_to_raster.empty() &&
      prioritized_work.tiles_to_raster.front().tile()->required_for_draw());

  // Schedule tile tasks.
  ScheduleTasks(std::move(prioritized_work));

  TRACE_EVENT_INSTANT1("cc", "DidPrepareTiles", TRACE_EVENT_SCOPE_THREAD,
                       "state", BasicStateAsValue());
  return true;
}

void TileManager::CheckForCompletedTasks() {
  TRACE_EVENT0("cc", "TileManager::CheckForCompletedTasks");

  if (!tile_task_manager_) {
    TRACE_EVENT_INSTANT0("cc", "TileManager::CheckForCompletedTasksAborted",
                         TRACE_EVENT_SCOPE_THREAD);
    return;
  }

  tile_task_manager_->CheckForCompletedTasks();
  did_check_for_completed_tasks_since_last_schedule_tasks_ = true;

  CheckPendingGpuWorkAndIssueSignals();

  TRACE_EVENT_INSTANT1(
      "cc", "TileManager::CheckForCompletedTasksFinished",
      TRACE_EVENT_SCOPE_THREAD, "stats",
      RasterTaskCompletionStatsAsValue(raster_task_completion_stats_));
  raster_task_completion_stats_ = RasterTaskCompletionStats();
}

void TileManager::DidModifyTilePriorities() {
  pending_tile_requirements_dirty_ = true;
}

std::unique_ptr<base::trace_event::ConvertableToTraceFormat>
TileManager::BasicStateAsValue() const {
  std::unique_ptr<base::trace_event::TracedValue> value(
      new base::trace_event::TracedValue());
  BasicStateAsValueInto(value.get());
  return std::move(value);
}

void TileManager::BasicStateAsValueInto(
    base::trace_event::TracedValue* state) const {
  state->SetInteger("tile_count", base::saturated_cast<int>(tiles_.size()));
  state->SetBoolean("did_oom_on_last_assign", did_oom_on_last_assign_);
  state->BeginDictionary("global_state");
  global_state_.AsValueInto(state);
  state->EndDictionary();
}

std::unique_ptr<EvictionTilePriorityQueue>
TileManager::FreeTileResourcesUntilUsageIsWithinLimit(
    std::unique_ptr<EvictionTilePriorityQueue> eviction_priority_queue,
    const MemoryUsage& limit,
    MemoryUsage* usage) {
  while (usage->Exceeds(limit)) {
    if (!eviction_priority_queue) {
      eviction_priority_queue =
          client_->BuildEvictionQueue(global_state_.tree_priority);
    }
    if (eviction_priority_queue->IsEmpty())
      break;

    Tile* tile = eviction_priority_queue->Top().tile();
    *usage -= MemoryUsage::FromTile(tile);
    FreeResourcesForTileAndNotifyClientIfTileWasReadyToDraw(tile);
    eviction_priority_queue->Pop();
  }
  return eviction_priority_queue;
}

std::unique_ptr<EvictionTilePriorityQueue>
TileManager::FreeTileResourcesWithLowerPriorityUntilUsageIsWithinLimit(
    std::unique_ptr<EvictionTilePriorityQueue> eviction_priority_queue,
    const MemoryUsage& limit,
    const TilePriority& other_priority,
    MemoryUsage* usage) {
  while (usage->Exceeds(limit)) {
    if (!eviction_priority_queue) {
      eviction_priority_queue =
          client_->BuildEvictionQueue(global_state_.tree_priority);
    }
    if (eviction_priority_queue->IsEmpty())
      break;

    const PrioritizedTile& prioritized_tile = eviction_priority_queue->Top();
    if (!other_priority.IsHigherPriorityThan(prioritized_tile.priority()))
      break;

    Tile* tile = prioritized_tile.tile();
    *usage -= MemoryUsage::FromTile(tile);
    FreeResourcesForTileAndNotifyClientIfTileWasReadyToDraw(tile);
    eviction_priority_queue->Pop();
  }
  return eviction_priority_queue;
}

bool TileManager::TilePriorityViolatesMemoryPolicy(
    const TilePriority& priority) {
  switch (global_state_.memory_limit_policy) {
    case ALLOW_NOTHING:
      return true;
    case ALLOW_ABSOLUTE_MINIMUM:
      return priority.priority_bin > TilePriority::NOW;
    case ALLOW_PREPAINT_ONLY:
      return priority.priority_bin > TilePriority::SOON;
    case ALLOW_ANYTHING:
      return priority.distance_to_visible ==
             std::numeric_limits<float>::infinity();
  }
  NOTREACHED();
  return true;
}

TileManager::PrioritizedWorkToSchedule TileManager::AssignGpuMemoryToTiles() {
  TRACE_EVENT_BEGIN0("cc", "TileManager::AssignGpuMemoryToTiles");

  DCHECK(resource_pool_);
  DCHECK(tile_task_manager_);

  // Now give memory out to the tiles until we're out, and build
  // the needs-to-be-rasterized queue.
  unsigned schedule_priority = 1u;
  all_tiles_that_need_to_be_rasterized_are_scheduled_ = true;
  bool had_enough_memory_to_schedule_tiles_needed_now = true;

  MemoryUsage hard_memory_limit(global_state_.hard_memory_limit_in_bytes,
                                global_state_.num_resources_limit);
  MemoryUsage soft_memory_limit(global_state_.soft_memory_limit_in_bytes,
                                global_state_.num_resources_limit);
  MemoryUsage memory_usage(resource_pool_->memory_usage_bytes(),
                           resource_pool_->resource_count());

  RasterColorSpace raster_color_space = client_->GetRasterColorSpace();

  std::unique_ptr<RasterTilePriorityQueue> raster_priority_queue(
      client_->BuildRasterQueue(global_state_.tree_priority,
                                RasterTilePriorityQueue::Type::ALL));
  std::unique_ptr<EvictionTilePriorityQueue> eviction_priority_queue;
  PrioritizedWorkToSchedule work_to_schedule;
  for (; !raster_priority_queue->IsEmpty(); raster_priority_queue->Pop()) {
    const PrioritizedTile& prioritized_tile = raster_priority_queue->Top();
    Tile* tile = prioritized_tile.tile();
    TilePriority priority = prioritized_tile.priority();

    if (TilePriorityViolatesMemoryPolicy(priority)) {
      TRACE_EVENT_INSTANT0(
          "cc", "TileManager::AssignGpuMemory tile violates memory policy",
          TRACE_EVENT_SCOPE_THREAD);
      break;
    }

    bool tile_is_needed_now = priority.priority_bin == TilePriority::NOW;
    if (!tile->is_solid_color_analysis_performed() &&
        tile->use_picture_analysis() && kUseColorEstimator) {
      // We analyze for solid color here, to decide to continue
      // or drop the tile for scheduling and raster.
      // TODO(sohanjg): Check if we could use a shared analysis
      // canvas which is reset between tiles.
      tile->set_solid_color_analysis_performed(true);
      SkColor color = SK_ColorTRANSPARENT;
      bool is_solid_color =
          prioritized_tile.raster_source()->PerformSolidColorAnalysis(
              tile->enclosing_layer_rect(), &color);
      if (is_solid_color) {
        tile->draw_info().set_solid_color(color);
        client_->NotifyTileStateChanged(tile);
        continue;
      }
    }

    // Prepaint tiles that are far away are only processed for images.
    if (tile->is_prepaint() && prioritized_tile.is_process_for_images_only()) {
      work_to_schedule.tiles_to_process_for_images.push_back(prioritized_tile);
      continue;
    }

    // Tiles in the raster queue should either require raster or decode for
    // checker-images. If this tile does not need raster, process it only to
    // build the decode queue for checkered images.
    // Note that performing this check after the solid color analysis is not
    // necessary for correctness.
    if (!tile->draw_info().NeedsRaster()) {
      DCHECK(tile->draw_info().is_checker_imaged());
      DCHECK(prioritized_tile.should_decode_checkered_images_for_tile());

      AddCheckeredImagesToDecodeQueue(
          prioritized_tile, raster_color_space.color_space,
          CheckerImageTracker::DecodeType::kRaster,
          &work_to_schedule.checker_image_decode_queue);
      continue;
    }

    // We won't be able to schedule this tile, so break out early.
    if (work_to_schedule.tiles_to_raster.size() >=
        scheduled_raster_task_limit_) {
      all_tiles_that_need_to_be_rasterized_are_scheduled_ = false;
      break;
    }

    DCHECK(tile->draw_info().mode() == TileDrawInfo::OOM_MODE ||
           !tile->draw_info().IsReadyToDraw());

    // If the tile already has a raster_task, then the memory used by it is
    // already accounted for in memory_usage. Otherwise, we'll have to acquire
    // more memory to create a raster task.
    MemoryUsage memory_required_by_tile_to_be_scheduled;
    if (!tile->raster_task_.get()) {
      memory_required_by_tile_to_be_scheduled = MemoryUsage::FromConfig(
          tile->desired_texture_size(), DetermineResourceFormat(tile));
    }

    // This is the memory limit that will be used by this tile. Depending on
    // the tile priority, it will be one of hard_memory_limit or
    // soft_memory_limit.
    MemoryUsage& tile_memory_limit =
        tile_is_needed_now ? hard_memory_limit : soft_memory_limit;

    const MemoryUsage& scheduled_tile_memory_limit =
        tile_memory_limit - memory_required_by_tile_to_be_scheduled;
    eviction_priority_queue =
        FreeTileResourcesWithLowerPriorityUntilUsageIsWithinLimit(
            std::move(eviction_priority_queue), scheduled_tile_memory_limit,
            priority, &memory_usage);
    bool memory_usage_is_within_limit =
        !memory_usage.Exceeds(scheduled_tile_memory_limit);

    // If we couldn't fit the tile into our current memory limit, then we're
    // done.
    if (!memory_usage_is_within_limit) {
      if (tile_is_needed_now)
        had_enough_memory_to_schedule_tiles_needed_now = false;
      all_tiles_that_need_to_be_rasterized_are_scheduled_ = false;
      break;
    }

    // If the tile has a scheduled task that will rasterize a resource with
    // checker-imaged content, add those images to the decode queue. Note that
    // we add all images as we process the raster priority queue to ensure that
    // images are added to the decode queue in raster priority order.
    if (tile->HasRasterTask()) {
      if (tile->raster_task_scheduled_with_checker_images() &&
          prioritized_tile.should_decode_checkered_images_for_tile()) {
        AddCheckeredImagesToDecodeQueue(
            prioritized_tile, raster_color_space.color_space,
            CheckerImageTracker::DecodeType::kRaster,
            &work_to_schedule.checker_image_decode_queue);
      }
    } else {
      // Creating the raster task here will acquire resources, but
      // this resource usage has already been accounted for above.
      auto raster_task = CreateRasterTask(
          prioritized_tile, client_->GetRasterColorSpace(), &work_to_schedule);
      if (!raster_task) {
        continue;
      }

      tile->raster_task_ = std::move(raster_task);
    }

    tile->scheduled_priority_ = schedule_priority++;
    memory_usage += memory_required_by_tile_to_be_scheduled;
    work_to_schedule.tiles_to_raster.push_back(prioritized_tile);
  }

  // Note that we should try and further reduce memory in case the above loop
  // didn't reduce memory. This ensures that we always release as many resources
  // as possible to stay within the memory limit.
  eviction_priority_queue = FreeTileResourcesUntilUsageIsWithinLimit(
      std::move(eviction_priority_queue), hard_memory_limit, &memory_usage);

  // At this point, if we ran out of memory when allocating resources and we
  // couldn't go past even the NOW bin, this means we have evicted resources
  // from all tiles with a lower priority while we still might have resources
  // holding checker-imaged content. The invalidations for these resources will
  // be generated only if the skipped images are decoded. So we must schedule
  // decodes for these tiles to update their content.
  if (!had_enough_memory_to_schedule_tiles_needed_now &&
      num_of_tiles_with_checker_images_ > 0) {
    for (; !raster_priority_queue->IsEmpty(); raster_priority_queue->Pop()) {
      const PrioritizedTile& prioritized_tile = raster_priority_queue->Top();

      if (prioritized_tile.priority().priority_bin > TilePriority::NOW)
        break;

      if (!prioritized_tile.should_decode_checkered_images_for_tile())
        continue;

      Tile* tile = prioritized_tile.tile();
      if (tile->draw_info().is_checker_imaged() ||
          tile->raster_task_scheduled_with_checker_images()) {
        AddCheckeredImagesToDecodeQueue(
            prioritized_tile, raster_color_space.color_space,
            CheckerImageTracker::DecodeType::kRaster,
            &work_to_schedule.checker_image_decode_queue);
      }
    }
  }

  // The hard_limit for low-end devices is 8MB, so we set the max_value for the
  // histogram to be 8200KB.
  if (had_enough_memory_to_schedule_tiles_needed_now &&
      base::SysInfo::AmountOfPhysicalMemoryMB() <= 512) {
    int64_t tiles_gpu_memory_kb = memory_usage.memory_bytes() / 1024;
    UMA_HISTOGRAM_CUSTOM_COUNTS("TileManager.TilesGPUMemoryUsage",
                                tiles_gpu_memory_kb, 1, 8200, 100);
  }

  UMA_HISTOGRAM_BOOLEAN("TileManager.ExceededMemoryBudget",
                        !had_enough_memory_to_schedule_tiles_needed_now);
  did_oom_on_last_assign_ = !had_enough_memory_to_schedule_tiles_needed_now;

  memory_stats_from_last_assign_.total_budget_in_bytes =
      global_state_.hard_memory_limit_in_bytes;
  memory_stats_from_last_assign_.total_bytes_used = memory_usage.memory_bytes();
  DCHECK_GE(memory_stats_from_last_assign_.total_bytes_used, 0);
  memory_stats_from_last_assign_.had_enough_memory =
      had_enough_memory_to_schedule_tiles_needed_now;

  TRACE_EVENT_END2("cc", "TileManager::AssignGpuMemoryToTiles",
                   "all_tiles_that_need_to_be_rasterized_are_scheduled",
                   all_tiles_that_need_to_be_rasterized_are_scheduled_,
                   "had_enough_memory_to_schedule_tiles_needed_now",
                   had_enough_memory_to_schedule_tiles_needed_now);
  return work_to_schedule;
}

void TileManager::FreeResourcesForTile(Tile* tile) {
  TileDrawInfo& draw_info = tile->draw_info();

  if (draw_info.is_checker_imaged())
    num_of_tiles_with_checker_images_--;
  DCHECK_GE(num_of_tiles_with_checker_images_, 0);

  if (draw_info.has_resource()) {
    resource_pool_->ReleaseResource(draw_info.TakeResource());
    pending_gpu_work_tiles_.erase(tile);
  }
}

void TileManager::FreeResourcesForTileAndNotifyClientIfTileWasReadyToDraw(
    Tile* tile) {
  bool was_ready_to_draw = tile->draw_info().IsReadyToDraw();
  FreeResourcesForTile(tile);
  if (was_ready_to_draw)
    client_->NotifyTileStateChanged(tile);
}

void TileManager::PartitionImagesForCheckering(
    const PrioritizedTile& prioritized_tile,
    const gfx::ColorSpace& raster_color_space,
    std::vector<DrawImage>* sync_decoded_images,
    std::vector<PaintImage>* checkered_images,
    const gfx::Rect* invalidated_rect,
    base::flat_map<PaintImage::Id, size_t>* image_to_frame_index) {
  Tile* tile = prioritized_tile.tile();
  std::vector<const DrawImage*> images_in_tile;
  gfx::Rect enclosing_rect = tile->enclosing_layer_rect();
  if (invalidated_rect) {
    enclosing_rect = ToEnclosingRect(
        tile->raster_transform().InverseMapRect(gfx::RectF(*invalidated_rect)));
  }
  prioritized_tile.raster_source()->GetDiscardableImagesInRect(enclosing_rect,
                                                               &images_in_tile);
  WhichTree tree = tile->tiling()->tree();

  for (const auto* original_draw_image : images_in_tile) {
    const auto& image = original_draw_image->paint_image();
    size_t frame_index = client_->GetFrameIndexForImage(image, tree);
    if (image_to_frame_index)
      (*image_to_frame_index)[image.stable_id()] = frame_index;

    DrawImage draw_image(*original_draw_image, tile->raster_transform().scale(),
                         frame_index, raster_color_space);
    if (checker_image_tracker_.ShouldCheckerImage(draw_image, tree))
      checkered_images->push_back(draw_image.paint_image());
    else
      sync_decoded_images->push_back(std::move(draw_image));
  }
}

void TileManager::AddCheckeredImagesToDecodeQueue(
    const PrioritizedTile& prioritized_tile,
    const gfx::ColorSpace& raster_color_space,
    CheckerImageTracker::DecodeType decode_type,
    CheckerImageTracker::ImageDecodeQueue* image_decode_queue) {
  Tile* tile = prioritized_tile.tile();
  std::vector<const DrawImage*> images_in_tile;
  prioritized_tile.raster_source()->GetDiscardableImagesInRect(
      tile->enclosing_layer_rect(), &images_in_tile);
  WhichTree tree = tile->tiling()->tree();

  for (const auto* original_draw_image : images_in_tile) {
    size_t frame_index = client_->GetFrameIndexForImage(
        original_draw_image->paint_image(), tree);
    DrawImage draw_image(*original_draw_image, tile->raster_transform().scale(),
                         frame_index, raster_color_space);
    if (checker_image_tracker_.ShouldCheckerImage(draw_image, tree)) {
      image_decode_queue->emplace_back(draw_image.paint_image(), decode_type);
    }
  }
}

void TileManager::ScheduleTasks(PrioritizedWorkToSchedule work_to_schedule) {
  const std::vector<PrioritizedTile>& tiles_that_need_to_be_rasterized =
      work_to_schedule.tiles_to_raster;
  TRACE_EVENT1("cc", "TileManager::ScheduleTasks", "count",
               tiles_that_need_to_be_rasterized.size());

  DCHECK(did_check_for_completed_tasks_since_last_schedule_tasks_);

  if (!has_scheduled_tile_tasks_) {
    TRACE_EVENT_ASYNC_BEGIN0("cc", "ScheduledTasks", this);
  }

  // Cancel existing OnTaskSetFinished callbacks.
  task_set_finished_weak_ptr_factory_.InvalidateWeakPtrs();

  // Even when scheduling an empty set of tiles, the TTWP does some work, and
  // will always trigger a DidFinishRunningTileTasks notification. Because of
  // this we unconditionally set |has_scheduled_tile_tasks_| to true.
  has_scheduled_tile_tasks_ = true;

  // Track the number of dependents for each *_done task.
  size_t required_for_activate_count = 0;
  size_t required_for_draw_count = 0;
  size_t all_count = 0;

  size_t priority = kTileTaskPriorityBase;

  graph_.Reset();

  gfx::ColorSpace raster_color_space =
      client_->GetRasterColorSpace().color_space;

  scoped_refptr<TileTask> required_for_activation_done_task =
      CreateTaskSetFinishedTask(
          &TileManager::DidFinishRunningTileTasksRequiredForActivation);
  scoped_refptr<TileTask> required_for_draw_done_task =
      CreateTaskSetFinishedTask(
          &TileManager::DidFinishRunningTileTasksRequiredForDraw);
  scoped_refptr<TileTask> all_done_task =
      CreateTaskSetFinishedTask(&TileManager::DidFinishRunningAllTileTasks);

  // Build a new task queue containing all task currently needed. Tasks
  // are added in order of priority, highest priority task first.
  for (auto& prioritized_tile : tiles_that_need_to_be_rasterized) {
    Tile* tile = prioritized_tile.tile();

    DCHECK(tile->draw_info().requires_resource());
    DCHECK(!tile->draw_info().has_resource());
    DCHECK(tile->HasRasterTask());

    TileTask* task = tile->raster_task_.get();

    DCHECK(!task->HasCompleted());

    if (tile->required_for_activation()) {
      required_for_activate_count++;
      graph_.edges.emplace_back(task, required_for_activation_done_task.get());
    }
    if (tile->required_for_draw()) {
      required_for_draw_count++;
      graph_.edges.emplace_back(task, required_for_draw_done_task.get());
    }
    all_count++;
    graph_.edges.emplace_back(task, all_done_task.get());

    // A tile should use a foreground task cateogry if it is either blocking
    // future compositing (required for draw or required for activation), or if
    // it has a priority bin of NOW for another reason (low resolution tiles).
    bool use_foreground_category =
        tile->required_for_draw() || tile->required_for_activation() ||
        prioritized_tile.priority().priority_bin == TilePriority::NOW;
    InsertNodesForRasterTask(&graph_, task, task->dependencies(), priority++,
                             use_foreground_category);
  }

  const std::vector<PrioritizedTile>& tiles_to_process_for_images =
      work_to_schedule.tiles_to_process_for_images;
  std::vector<DrawImage> new_locked_images;
  for (const PrioritizedTile& prioritized_tile : tiles_to_process_for_images) {
    std::vector<DrawImage> sync_decoded_images;
    std::vector<PaintImage> checkered_images;
    PartitionImagesForCheckering(prioritized_tile, raster_color_space,
                                 &sync_decoded_images, &checkered_images,
                                 nullptr);

    // Add the sync decoded images to |new_locked_images| so they can be added
    // to the task graph.
    new_locked_images.insert(
        new_locked_images.end(),
        std::make_move_iterator(sync_decoded_images.begin()),
        std::make_move_iterator(sync_decoded_images.end()));

    // For checkered-images, send them to the decode service.
    for (auto& image : checkered_images) {
      work_to_schedule.checker_image_decode_queue.emplace_back(
          std::move(image), CheckerImageTracker::DecodeType::kPreDecode);
    }
  }

  new_locked_images.insert(new_locked_images.end(),
                           work_to_schedule.extra_prepaint_images.begin(),
                           work_to_schedule.extra_prepaint_images.end());

  // TODO(vmpstr): SOON is misleading here, but these images can come from
  // several diffent tiles. Rethink what we actually want to trace here. Note
  // that I'm using SOON, since it can't be NOW (these are prepaint).
  ImageDecodeCache::TracingInfo tracing_info(
      prepare_tiles_count_, TilePriority::SOON,
      ImageDecodeCache::TaskType::kInRaster);
  std::vector<scoped_refptr<TileTask>> new_locked_image_tasks =
      image_controller_.SetPredecodeImages(std::move(new_locked_images),
                                           tracing_info);
  work_to_schedule.extra_prepaint_images.clear();

  for (auto& task : new_locked_image_tasks) {
    auto decode_it = std::find_if(graph_.nodes.begin(), graph_.nodes.end(),
                                  [&task](const TaskGraph::Node& node) {
                                    return node.task == task.get();
                                  });
    // If this task is already in the graph, then we don't have to insert it.
    if (decode_it != graph_.nodes.end())
      continue;

    InsertNodeForDecodeTask(&graph_, task.get(), false, priority++);
    all_count++;
    graph_.edges.emplace_back(task.get(), all_done_task.get());
  }

  // The old locked images tasks have to stay around until past the
  // ScheduleTasks call below, so we do a swap instead of a move.
  // TODO(crbug.com/647402): Have the tile_task_manager keep a ref on the tasks,
  // since it makes it awkward for the callers to keep refs on tasks that only
  // exist within the task graph runner.
  locked_image_tasks_.swap(new_locked_image_tasks);

  // We must reduce the amount of unused resources before calling
  // ScheduleTasks to prevent usage from rising above limits.
  resource_pool_->ReduceResourceUsage();
  image_controller_.ReduceMemoryUsage();

  // Insert nodes for our task completion tasks. We enqueue these using
  // NONCONCURRENT_FOREGROUND category this is the highest prioirty category and
  // we'd like to run these tasks as soon as possible.
  InsertNodeForTask(&graph_, required_for_activation_done_task.get(),
                    TASK_CATEGORY_NONCONCURRENT_FOREGROUND,
                    kRequiredForActivationDoneTaskPriority,
                    required_for_activate_count);
  InsertNodeForTask(&graph_, required_for_draw_done_task.get(),
                    TASK_CATEGORY_NONCONCURRENT_FOREGROUND,
                    kRequiredForDrawDoneTaskPriority, required_for_draw_count);
  InsertNodeForTask(&graph_, all_done_task.get(),
                    TASK_CATEGORY_NONCONCURRENT_FOREGROUND,
                    kAllDoneTaskPriority, all_count);

  // Schedule running of |raster_queue_|. This replaces any previously
  // scheduled tasks and effectively cancels all tasks not present
  // in |raster_queue_|.
  tile_task_manager_->ScheduleTasks(&graph_);

  // Schedule running of the checker-image decode queue. This replaces the
  // previously scheduled queue and effectively cancels image decodes from the
  // previous queue, if not already started.
  checker_image_tracker_.ScheduleImageDecodeQueue(
      std::move(work_to_schedule.checker_image_decode_queue));

  did_check_for_completed_tasks_since_last_schedule_tasks_ = false;

  TRACE_EVENT_ASYNC_STEP_INTO1("cc", "ScheduledTasks", this, "running", "state",
                               ScheduledTasksStateAsValue());
}

scoped_refptr<TileTask> TileManager::CreateRasterTask(
    const PrioritizedTile& prioritized_tile,
    const RasterColorSpace& raster_color_space,
    PrioritizedWorkToSchedule* work_to_schedule) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
               "TileManager::CreateRasterTask");
  Tile* tile = prioritized_tile.tile();
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
               "TileManager::CreateRasterTask", "Tile", tile->id());

  // Get the resource.
  ResourcePool::InUsePoolResource resource;
  uint64_t resource_content_id = 0;
  gfx::Rect invalidated_rect = tile->invalidated_content_rect();
  if (UsePartialRaster() && tile->invalidated_id()) {
    resource = resource_pool_->TryAcquireResourceForPartialRaster(
        tile->id(), tile->invalidated_content_rect(), tile->invalidated_id(),
        &invalidated_rect);
  }

  bool partial_tile_decode = false;
  if (resource) {
    resource_content_id = tile->invalidated_id();
    DCHECK_EQ(DetermineResourceFormat(tile), resource.format());
    partial_tile_decode = true;
  } else {
    resource = resource_pool_->AcquireResource(tile->desired_texture_size(),
                                               DetermineResourceFormat(tile),
                                               raster_color_space.color_space);
    DCHECK(resource);
  }

  // For LOW_RESOLUTION tiles, we don't draw or predecode images.
  RasterSource::PlaybackSettings playback_settings;
  const bool skip_images =
      prioritized_tile.priority().resolution == LOW_RESOLUTION;
  playback_settings.use_lcd_text = tile->can_use_lcd_text();

  // Create and queue all image decode tasks that this tile depends on. Note
  // that we need to store the images for decode tasks in
  // |scheduled_draw_images_| since the tile might have been destroyed by the
  // time the raster task finishes.
  TileTask::Vector decode_tasks;
  std::vector<DrawImage>& sync_decoded_images =
      scheduled_draw_images_[tile->id()];
  sync_decoded_images.clear();
  std::vector<PaintImage> checkered_images;
  base::flat_map<PaintImage::Id, size_t> image_id_to_current_frame_index;
  if (!skip_images) {
    PartitionImagesForCheckering(
        prioritized_tile, raster_color_space.color_space, &sync_decoded_images,
        &checkered_images, partial_tile_decode ? &invalidated_rect : nullptr,
        &image_id_to_current_frame_index);
  }

  // Get the tasks for the required images.
  ImageDecodeCache::TracingInfo tracing_info(
      prepare_tiles_count_, prioritized_tile.priority().priority_bin,
      ImageDecodeCache::TaskType::kInRaster);
  bool has_at_raster_images = false;
  image_controller_.GetTasksForImagesAndRef(
      &sync_decoded_images, &decode_tasks, &has_at_raster_images, tracing_info);

  const bool has_checker_images = !checkered_images.empty();
  tile->set_raster_task_scheduled_with_checker_images(has_checker_images);
  if (has_checker_images)
    num_of_tiles_with_checker_images_++;

  // Don't allow at-raster prepaint tiles, because they could be very slow
  // and block high-priority tasks.
  if (has_at_raster_images && tile->is_prepaint()) {
    work_to_schedule->extra_prepaint_images.insert(
        work_to_schedule->extra_prepaint_images.end(),
        sync_decoded_images.begin(), sync_decoded_images.end());
    // This will unref the images, but ScheduleTasks will schedule them
    // right away anyway.
    OnRasterTaskCompleted(tile->id(), std::move(resource),
                          true /* was_canceled */);
    return nullptr;
  }

  PaintImageIdFlatSet images_to_skip;
  for (const auto& image : checkered_images) {
    DCHECK(!image.ShouldAnimate());

    images_to_skip.insert(image.stable_id());

    // This can be the case for tiles on the active tree that will be replaced
    // or are occluded on the pending tree. While we still need to continue
    // skipping images for these tiles, we don't need to decode them since
    // they will not be required on the next active tree.
    if (prioritized_tile.should_decode_checkered_images_for_tile()) {
      work_to_schedule->checker_image_decode_queue.emplace_back(
          image, CheckerImageTracker::DecodeType::kRaster);
    }
  }

  std::unique_ptr<RasterBuffer> raster_buffer =
      raster_buffer_provider_->AcquireBufferForRaster(
          resource, resource_content_id, tile->invalidated_id());

  base::Optional<PlaybackImageProvider::Settings> settings;
  if (!skip_images) {
    settings.emplace();
    settings->images_to_skip = std::move(images_to_skip);
    settings->image_to_current_frame_index =
        std::move(image_id_to_current_frame_index);
  }

  PlaybackImageProvider image_provider(image_controller_.cache(),
                                       raster_color_space.color_space,
                                       std::move(settings));

  playback_settings.raster_color_space = raster_color_space;
  return base::MakeRefCounted<RasterTaskImpl>(
      this, tile, std::move(resource), prioritized_tile.raster_source(),
      playback_settings, prioritized_tile.priority().resolution,
      invalidated_rect, prepare_tiles_count_, std::move(raster_buffer),
      &decode_tasks, use_gpu_rasterization_, std::move(image_provider));
}

void TileManager::ResetSignalsForTesting() {
  signals_ = Signals();
}

void TileManager::OnRasterTaskCompleted(
    Tile::Id tile_id,
    ResourcePool::InUsePoolResource resource,
    bool was_canceled) {
  auto found = tiles_.find(tile_id);
  Tile* tile = nullptr;
  bool raster_task_was_scheduled_with_checker_images = false;
  if (found != tiles_.end()) {
    tile = found->second;
    tile->raster_task_ = nullptr;
    raster_task_was_scheduled_with_checker_images =
        tile->set_raster_task_scheduled_with_checker_images(false);
    if (raster_task_was_scheduled_with_checker_images)
      num_of_tiles_with_checker_images_--;
  }

  // Unref all the images.
  auto images_it = scheduled_draw_images_.find(tile_id);
  // Every raster task unconditionally creates sync_decoded_images_ entry in
  // CreateRasterTask. This is the only place it's cleared. So we should have
  // the images_it here that doesn't point to end. This check is here to debug
  // crbug.com/757049.
  CHECK(images_it != scheduled_draw_images_.end());
  image_controller_.UnrefImages(images_it->second);
  scheduled_draw_images_.erase(images_it);

  if (was_canceled) {
    ++raster_task_completion_stats_.canceled_count;
    resource_pool_->ReleaseResource(std::move(resource));
    return;
  }

  resource_pool_->OnContentReplaced(resource, tile_id);
  ++raster_task_completion_stats_.completed_count;

  if (!tile) {
    resource_pool_->ReleaseResource(std::move(resource));
    return;
  }

  // Once raster is done, allow the resource to be exported to the display
  // compositor, by giving it a ResourceId.
  resource_pool_->PrepareForExport(resource);

  // In SMOOTHNESS_TAKES_PRIORITY mode, we wait for GPU work to complete for a
  // tile before setting it as ready to draw.
  bool is_ready_for_draw = true;
  if (global_state_.tree_priority == SMOOTHNESS_TAKES_PRIORITY) {
    is_ready_for_draw =
        raster_buffer_provider_->IsResourceReadyToDraw(resource);
  }

  TileDrawInfo& draw_info = tile->draw_info();
  bool needs_swizzle =
      raster_buffer_provider_->IsResourceSwizzleRequired(!tile->is_opaque());
  bool is_premultiplied =
      raster_buffer_provider_->IsResourcePremultiplied(!tile->is_opaque());
  draw_info.SetResource(std::move(resource),
                        raster_task_was_scheduled_with_checker_images,
                        needs_swizzle, is_premultiplied);
  if (raster_task_was_scheduled_with_checker_images)
    num_of_tiles_with_checker_images_++;

  if (!is_ready_for_draw) {
    pending_gpu_work_tiles_.insert(tile);
  } else {
    draw_info.set_resource_ready_for_draw();
    client_->NotifyTileStateChanged(tile);
  }
}

void TileManager::SetDecodedImageTracker(
    DecodedImageTracker* decoded_image_tracker) {
  // TODO(vmpstr): If the tile manager needs to request out-of-raster decodes,
  // it should retain and use |decoded_image_tracker| here.
  decoded_image_tracker->set_image_controller(&image_controller_);
}

std::unique_ptr<Tile> TileManager::CreateTile(const Tile::CreateInfo& info,
                                              int layer_id,
                                              int source_frame_number,
                                              int flags,
                                              bool can_use_lcd_text) {
  // We need to have a tile task worker pool to do anything meaningful with
  // tiles.
  DCHECK(tile_task_manager_);
  std::unique_ptr<Tile> tile(new Tile(this, info, layer_id, source_frame_number,
                                      flags, can_use_lcd_text));
  DCHECK(tiles_.find(tile->id()) == tiles_.end());

  tiles_[tile->id()] = tile.get();
  return tile;
}

bool TileManager::AreRequiredTilesReadyToDraw(
    RasterTilePriorityQueue::Type type) const {
  std::unique_ptr<RasterTilePriorityQueue> raster_priority_queue(
      client_->BuildRasterQueue(global_state_.tree_priority, type));
  // It is insufficient to check whether the raster queue we constructed is
  // empty. The reason for this is that there are situations (rasterize on
  // demand) when the tile both needs raster and it's ready to draw. Hence, we
  // have to iterate the queue to check whether the required tiles are ready to
  // draw.
  for (; !raster_priority_queue->IsEmpty(); raster_priority_queue->Pop()) {
    const auto& prioritized_tile = raster_priority_queue->Top();
    // TODO(vmpstr): Check to debug crbug.com/622080. Remove when fixed.
    CHECK_EQ(prioritized_tile.priority().priority_bin, TilePriority::NOW);
    if (!prioritized_tile.tile()->draw_info().IsReadyToDraw())
      return false;
  }

#if DCHECK_IS_ON()
  std::unique_ptr<RasterTilePriorityQueue> all_queue(
      client_->BuildRasterQueue(global_state_.tree_priority, type));
  for (; !all_queue->IsEmpty(); all_queue->Pop()) {
    Tile* tile = all_queue->Top().tile();
    DCHECK(!tile->required_for_activation() ||
           tile->draw_info().IsReadyToDraw());
  }
#endif
  return true;
}

bool TileManager::IsReadyToActivate() const {
  TRACE_EVENT0("cc", "TileManager::IsReadyToActivate");
  return pending_required_for_activation_callback_id_ == 0 &&
         AreRequiredTilesReadyToDraw(
             RasterTilePriorityQueue::Type::REQUIRED_FOR_ACTIVATION);
}

bool TileManager::IsReadyToDraw() const {
  TRACE_EVENT0("cc", "TileManager::IsReadyToDraw");
  return pending_required_for_draw_callback_id_ == 0 &&
         AreRequiredTilesReadyToDraw(
             RasterTilePriorityQueue::Type::REQUIRED_FOR_DRAW);
}

void TileManager::FlushAndIssueSignals() {
  TRACE_EVENT0("cc", "TileManager::FlushAndIssueSignals");
  tile_task_manager_->CheckForCompletedTasks();
  did_check_for_completed_tasks_since_last_schedule_tasks_ = true;

  raster_buffer_provider_->Flush();
  CheckPendingGpuWorkAndIssueSignals();
}

void TileManager::IssueSignals() {
  // Ready to activate.
  if (signals_.activate_tile_tasks_completed &&
      signals_.activate_gpu_work_completed &&
      !signals_.did_notify_ready_to_activate) {
    if (IsReadyToActivate()) {
      TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
                   "TileManager::IssueSignals - ready to activate");
      signals_.did_notify_ready_to_activate = true;
      client_->NotifyReadyToActivate();
    }
  }

  // Ready to draw.
  if (signals_.draw_tile_tasks_completed && signals_.draw_gpu_work_completed &&
      !signals_.did_notify_ready_to_draw) {
    if (IsReadyToDraw()) {
      TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
                   "TileManager::IssueSignals - ready to draw");
      signals_.did_notify_ready_to_draw = true;
      client_->NotifyReadyToDraw();
    }
  }

  // All tile tasks completed.
  if (signals_.all_tile_tasks_completed &&
      !signals_.did_notify_all_tile_tasks_completed) {
    if (!has_scheduled_tile_tasks_) {
      TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("cc.debug"),
                   "TileManager::IssueSignals - all tile tasks completed");
      signals_.did_notify_all_tile_tasks_completed = true;
      client_->NotifyAllTileTasksCompleted();
    }
  }

  // Allow decodes for rasterized tiles if all required for draw/activate tiles
  // are done. And pre-decode tiles once all tile tasks are done.
  // Note that the order is important here, since all signals could have become
  // true and in that case we want to allow the most decodes.
  if (signals_.did_notify_all_tile_tasks_completed) {
    checker_image_tracker_.SetMaxDecodePriorityAllowed(
        CheckerImageTracker::DecodeType::kPreDecode);
  } else if (signals_.did_notify_ready_to_activate &&
             signals_.did_notify_ready_to_draw) {
    checker_image_tracker_.SetMaxDecodePriorityAllowed(
        CheckerImageTracker::DecodeType::kRaster);
  }
}

void TileManager::CheckIfMoreTilesNeedToBePrepared() {
  tile_task_manager_->CheckForCompletedTasks();
  did_check_for_completed_tasks_since_last_schedule_tasks_ = true;

  // When OOM, keep re-assigning memory until we reach a steady state
  // where top-priority tiles are initialized.
  PrioritizedWorkToSchedule work_to_schedule = AssignGpuMemoryToTiles();

  // Inform the client that will likely require a draw if the highest priority
  // tile that will be rasterized is required for draw.
  client_->SetIsLikelyToRequireADraw(
      !work_to_schedule.tiles_to_raster.empty() &&
      work_to_schedule.tiles_to_raster.front().tile()->required_for_draw());

  // |tiles_that_need_to_be_rasterized| will be empty when we reach a
  // steady memory state. Keep scheduling tasks until we reach this state.
  if (!work_to_schedule.tiles_to_raster.empty()) {
    ScheduleTasks(std::move(work_to_schedule));
    return;
  }

  // If we're not in SMOOTHNESS_TAKES_PRIORITY  mode, we should unlock all
  // images since we're technically going idle here at least for this frame.
  if (global_state_.tree_priority != SMOOTHNESS_TAKES_PRIORITY) {
    image_controller_.SetPredecodeImages(std::vector<DrawImage>(),
                                         ImageDecodeCache::TracingInfo());
    locked_image_tasks_.clear();
  }

  resource_pool_->ReduceResourceUsage();
  image_controller_.ReduceMemoryUsage();

  // TODO(vmpstr): Temporary check to debug crbug.com/642927.
  CHECK(tile_task_manager_);

  // Schedule all checks in case we're left with solid color tiles only.
  signals_.activate_tile_tasks_completed = true;
  signals_.draw_tile_tasks_completed = true;
  signals_.all_tile_tasks_completed = true;
  signals_check_notifier_.Schedule();

  // We don't reserve memory for required-for-activation tiles during
  // accelerated gestures, so we just postpone activation when we don't
  // have these tiles, and activate after the accelerated gesture.
  // Likewise if we don't allow any tiles (as is the case when we're
  // invisible), if we have tiles that aren't ready, then we shouldn't
  // activate as activation can cause checkerboards.
  bool wait_for_all_required_tiles =
      global_state_.tree_priority == SMOOTHNESS_TAKES_PRIORITY ||
      global_state_.memory_limit_policy == ALLOW_NOTHING;

  // If we have tiles left to raster for activation, and we don't allow
  // activating without them, then skip activation and return early.
  if (wait_for_all_required_tiles)
    return;

  // Mark any required tiles that have not been been assigned memory after
  // reaching a steady memory state as OOM. This ensures that we activate/draw
  // even when OOM. Note that we can't reuse the queue we used for
  // AssignGpuMemoryToTiles, since the AssignGpuMemoryToTiles call could have
  // evicted some tiles that would not be picked up by the old raster queue.
  MarkTilesOutOfMemory(client_->BuildRasterQueue(
      global_state_.tree_priority,
      RasterTilePriorityQueue::Type::REQUIRED_FOR_ACTIVATION));
  MarkTilesOutOfMemory(client_->BuildRasterQueue(
      global_state_.tree_priority,
      RasterTilePriorityQueue::Type::REQUIRED_FOR_DRAW));

  // TODO(vmpstr): Temporary check to debug crbug.com/642927.
  CHECK(tile_task_manager_);

  DCHECK(IsReadyToActivate());
  DCHECK(IsReadyToDraw());
}

void TileManager::MarkTilesOutOfMemory(
    std::unique_ptr<RasterTilePriorityQueue> queue) const {
  // Mark required tiles as OOM so that we can activate/draw without them.
  for (; !queue->IsEmpty(); queue->Pop()) {
    Tile* tile = queue->Top().tile();
    if (tile->draw_info().IsReadyToDraw())
      continue;
    tile->draw_info().set_oom();
    client_->NotifyTileStateChanged(tile);
  }
}

const PaintImageIdFlatSet& TileManager::TakeImagesToInvalidateOnSyncTree() {
  return checker_image_tracker_.TakeImagesToInvalidateOnSyncTree();
}

void TileManager::DidActivateSyncTree() {
  checker_image_tracker_.DidActivateSyncTree();
}

void TileManager::ClearCheckerImageTracking(
    bool can_clear_decode_policy_tracking) {
  checker_image_tracker_.ClearTracker(can_clear_decode_policy_tracking);
}

void TileManager::SetCheckerImagingForceDisabled(bool force_disable) {
  checker_image_tracker_.set_force_disabled(force_disable);
}

void TileManager::NeedsInvalidationForCheckerImagedTiles() {
  client_->RequestImplSideInvalidationForCheckerImagedTiles();
}

viz::ResourceFormat TileManager::DetermineResourceFormat(
    const Tile* tile) const {
  return raster_buffer_provider_->GetResourceFormat(!tile->is_opaque());
}

std::unique_ptr<base::trace_event::ConvertableToTraceFormat>
TileManager::ScheduledTasksStateAsValue() const {
  std::unique_ptr<base::trace_event::TracedValue> state(
      new base::trace_event::TracedValue());
  state->BeginDictionary("tasks_pending");
  state->SetBoolean("activate_tile_tasks_completed",
                    signals_.activate_tile_tasks_completed);
  state->SetBoolean("draw_tile_tasks_completed",
                    signals_.draw_tile_tasks_completed);
  state->SetBoolean("all_tile_tasks_completed",
                    signals_.all_tile_tasks_completed);
  state->EndDictionary();
  return std::move(state);
}

bool TileManager::UsePartialRaster() const {
  return tile_manager_settings_.use_partial_raster &&
         raster_buffer_provider_->CanPartialRasterIntoProvidedResource();
}

void TileManager::CheckPendingGpuWorkAndIssueSignals() {
  TRACE_EVENT2("cc", "TileManager::CheckPendingGpuWorkAndIssueSignals",
               "pending_gpu_work_tiles", pending_gpu_work_tiles_.size(),
               "tree_priority",
               TreePriorityToString(global_state_.tree_priority));

  std::vector<const ResourcePool::InUsePoolResource*> required_for_activation;
  std::vector<const ResourcePool::InUsePoolResource*> required_for_draw;

  for (auto it = pending_gpu_work_tiles_.begin();
       it != pending_gpu_work_tiles_.end();) {
    Tile* tile = *it;
    DCHECK(tile->draw_info().has_resource());
    const ResourcePool::InUsePoolResource& resource =
        tile->draw_info().GetResource();

    // Update requirements first so that if the tile has become required
    // it will force a redraw.
    if (pending_tile_requirements_dirty_)
      tile->tiling()->UpdateRequiredStatesOnTile(tile);

    if (global_state_.tree_priority != SMOOTHNESS_TAKES_PRIORITY ||
        raster_buffer_provider_->IsResourceReadyToDraw(resource)) {
      tile->draw_info().set_resource_ready_for_draw();
      client_->NotifyTileStateChanged(tile);
      it = pending_gpu_work_tiles_.erase(it);
      continue;
    }

    // TODO(ericrk): If a tile in our list no longer has valid tile priorities,
    // it may still report that it is required, and unnecessarily delay
    // activation. crbug.com/687265
    if (tile->required_for_activation())
      required_for_activation.push_back(&resource);
    if (tile->required_for_draw())
      required_for_draw.push_back(&resource);

    ++it;
  }

  if (required_for_activation.empty()) {
    pending_required_for_activation_callback_id_ = 0;
  } else {
    pending_required_for_activation_callback_id_ =
        raster_buffer_provider_->SetReadyToDrawCallback(
            required_for_activation,
            base::Bind(&TileManager::CheckPendingGpuWorkAndIssueSignals,
                       ready_to_draw_callback_weak_ptr_factory_.GetWeakPtr()),
            pending_required_for_activation_callback_id_);
  }

  if (required_for_draw.empty()) {
    pending_required_for_draw_callback_id_ = 0;
  } else {
    pending_required_for_draw_callback_id_ =
        raster_buffer_provider_->SetReadyToDrawCallback(
            required_for_draw,
            base::Bind(&TileManager::CheckPendingGpuWorkAndIssueSignals,
                       ready_to_draw_callback_weak_ptr_factory_.GetWeakPtr()),
            pending_required_for_draw_callback_id_);
  }

  // Update our signals now that we know whether we have pending resources.
  signals_.activate_gpu_work_completed =
      (pending_required_for_activation_callback_id_ == 0);
  signals_.draw_gpu_work_completed =
      (pending_required_for_draw_callback_id_ == 0);

  // We've just updated all pending tile requirements if necessary.
  pending_tile_requirements_dirty_ = false;

  IssueSignals();
}

// Utility function that can be used to create a "Task set finished" task that
// posts |callback| to |task_runner| when run.
scoped_refptr<TileTask> TileManager::CreateTaskSetFinishedTask(
    void (TileManager::*callback)()) {
  return base::MakeRefCounted<TaskSetFinishedTaskImpl>(
      task_runner_,
      base::Bind(callback, task_set_finished_weak_ptr_factory_.GetWeakPtr()));
}

std::unique_ptr<base::trace_event::ConvertableToTraceFormat>
TileManager::ActivationStateAsValue() {
  auto state = std::make_unique<base::trace_event::TracedValue>();
  ActivationStateAsValueInto(state.get());
  return std::move(state);
}

void TileManager::ActivationStateAsValueInto(
    base::trace_event::TracedValue* state) {
  state->SetString("tree_priority",
                   TreePriorityToString(global_state_.tree_priority));
  state->SetInteger("soft_memory_limit",
                    global_state_.soft_memory_limit_in_bytes);
  state->SetInteger("hard_memory_limit",
                    global_state_.soft_memory_limit_in_bytes);
  state->SetInteger("pending_required_for_activation_callback_id",
                    pending_required_for_activation_callback_id_);
  state->SetInteger("current_memory_usage",
                    resource_pool_->memory_usage_bytes());
  state->SetInteger("current_resource_usage", resource_pool_->resource_count());

  // Use a custom tile_as_value, instead of Tile::AsValueInto, since we don't
  // need all of the state that would be captured by other functions.
  auto tile_as_value = [](const PrioritizedTile& prioritized_tile,
                          base::trace_event::TracedValue* value) {
    Tile* tile = prioritized_tile.tile();
    TilePriority priority = prioritized_tile.priority();

    value->SetInteger("id", tile->id());
    value->SetString("content_rect", tile->content_rect().ToString());
    value->SetDouble("contents_scale", tile->contents_scale_key());
    value->SetBoolean("is_ready_to_draw", tile->draw_info().IsReadyToDraw());
    value->SetString("resolution", TileResolutionToString(priority.resolution));
    value->SetString("priority_bin",
                     TilePriorityBinToString(priority.priority_bin));
    value->SetDouble("distance_to_visible", priority.distance_to_visible);
    value->SetBoolean("required_for_activation",
                      tile->required_for_activation());
    value->SetBoolean("required_for_draw", tile->required_for_draw());
  };

  std::unique_ptr<RasterTilePriorityQueue> raster_priority_queue(
      client_->BuildRasterQueue(global_state_.tree_priority,
                                RasterTilePriorityQueue::Type::ALL));
  state->BeginArray("raster_tiles");
  for (; !raster_priority_queue->IsEmpty(); raster_priority_queue->Pop()) {
    state->BeginDictionary();
    tile_as_value(raster_priority_queue->Top(), state);
    state->EndDictionary();
  }
  state->EndArray();

  std::unique_ptr<RasterTilePriorityQueue> required_priority_queue(
      client_->BuildRasterQueue(
          global_state_.tree_priority,
          RasterTilePriorityQueue::Type::REQUIRED_FOR_ACTIVATION));
  state->BeginArray("activation_tiles");
  for (; !required_priority_queue->IsEmpty(); required_priority_queue->Pop()) {
    state->BeginDictionary();
    tile_as_value(required_priority_queue->Top(), state);
    state->EndDictionary();
  }
  state->EndArray();
}

TileManager::MemoryUsage::MemoryUsage()
    : memory_bytes_(0), resource_count_(0) {}

TileManager::MemoryUsage::MemoryUsage(size_t memory_bytes,
                                      size_t resource_count)
    : memory_bytes_(static_cast<int64_t>(memory_bytes)),
      resource_count_(static_cast<int>(resource_count)) {
  // MemoryUsage is constructed using size_ts, since it deals with memory and
  // the inputs are typically size_t. However, during the course of usage (in
  // particular operator-=) can cause internal values to become negative.
  // Thus, member variables are signed.
  DCHECK_LE(memory_bytes,
            static_cast<size_t>(std::numeric_limits<int64_t>::max()));
  DCHECK_LE(resource_count,
            static_cast<size_t>(std::numeric_limits<int>::max()));
}

// static
TileManager::MemoryUsage TileManager::MemoryUsage::FromConfig(
    const gfx::Size& size,
    viz::ResourceFormat format) {
  // We can use UncheckedSizeInBytes here since this is used with a tile
  // size which is determined by the compositor (it's at most max texture
  // size).
  return MemoryUsage(
      viz::ResourceSizes::UncheckedSizeInBytes<size_t>(size, format), 1);
}

// static
TileManager::MemoryUsage TileManager::MemoryUsage::FromTile(const Tile* tile) {
  const TileDrawInfo& draw_info = tile->draw_info();
  if (draw_info.has_resource()) {
    return MemoryUsage::FromConfig(draw_info.resource_size(),
                                   draw_info.resource_format());
  }
  return MemoryUsage();
}

TileManager::MemoryUsage& TileManager::MemoryUsage::operator+=(
    const MemoryUsage& other) {
  memory_bytes_ += other.memory_bytes_;
  resource_count_ += other.resource_count_;
  return *this;
}

TileManager::MemoryUsage& TileManager::MemoryUsage::operator-=(
    const MemoryUsage& other) {
  memory_bytes_ -= other.memory_bytes_;
  resource_count_ -= other.resource_count_;
  return *this;
}

TileManager::MemoryUsage TileManager::MemoryUsage::operator-(
    const MemoryUsage& other) {
  MemoryUsage result = *this;
  result -= other;
  return result;
}

bool TileManager::MemoryUsage::Exceeds(const MemoryUsage& limit) const {
  return memory_bytes_ > limit.memory_bytes_ ||
         resource_count_ > limit.resource_count_;
}

TileManager::PrioritizedWorkToSchedule::PrioritizedWorkToSchedule() = default;
TileManager::PrioritizedWorkToSchedule::PrioritizedWorkToSchedule(
    PrioritizedWorkToSchedule&& other) = default;
TileManager::PrioritizedWorkToSchedule::~PrioritizedWorkToSchedule() = default;

}  // namespace cc

// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RENDERER_HOST_INPUT_RENDER_WIDGET_HOST_LATENCY_TRACKER_H_
#define CONTENT_BROWSER_RENDERER_HOST_INPUT_RENDER_WIDGET_HOST_LATENCY_TRACKER_H_

#include <stdint.h>

#include <vector>

#include "base/macros.h"
#include "content/browser/renderer_host/event_with_latency_info.h"
#include "content/common/content_export.h"
#include "content/public/common/input_event_ack_state.h"
#include "ui/latency/latency_info.h"
#include "ui/latency/latency_tracker.h"

namespace content {

class RenderWidgetHostDelegate;

// Utility class for tracking the latency of events passing through
// a given RenderWidgetHost.
class CONTENT_EXPORT RenderWidgetHostLatencyTracker
    : public ui::LatencyTracker {
 public:
  RenderWidgetHostLatencyTracker(bool metric_sampling,
                                 RenderWidgetHostDelegate* delegate);
  virtual ~RenderWidgetHostLatencyTracker();

  // Associates the latency tracker with a given route and process.
  // Called once after the RenderWidgetHost is fully initialized.
  void Initialize(int routing_id, int process_id);

  void ComputeInputLatencyHistograms(blink::WebInputEvent::Type type,
                                     int64_t latency_component_id,
                                     const ui::LatencyInfo& latency,
                                     InputEventAckState ack_result);

  // Populates the LatencyInfo with relevant entries for latency tracking.
  // Called when an event is received by the RenderWidgetHost, prior to
  // that event being forwarded to the renderer (via the InputRouter).
  void OnInputEvent(const blink::WebInputEvent& event,
                    ui::LatencyInfo* latency);

  // Populates the LatencyInfo with relevant entries for latency tracking, also
  // terminating latency tracking for events that did not trigger rendering and
  // performing relevant UMA latency reporting. Called when an event is ack'ed
  // to the RenderWidgetHost (from the InputRouter).
  void OnInputEventAck(const blink::WebInputEvent& event,
                       ui::LatencyInfo* latency,
                       InputEventAckState ack_result);

  void reset_delegate() { render_widget_host_delegate_ = nullptr; }

  // Returns the ID that uniquely describes this component to the latency
  // subsystem.
  int64_t latency_component_id() const { return latency_component_id_; }

 private:
  int64_t last_event_id_;
  int64_t latency_component_id_;
  bool has_seen_first_gesture_scroll_update_;
  bool set_url_for_ukm_ = false;
  // Whether the current stream of touch events includes more than one active
  // touch point. This is set in OnInputEvent, and cleared in OnInputEventAck.
  bool active_multi_finger_gesture_;
  // Whether the touch start for the current stream of touch events had its
  // default action prevented. Only valid for single finger gestures.
  bool touch_start_default_prevented_;

  RenderWidgetHostDelegate* render_widget_host_delegate_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetHostLatencyTracker);
};

}  // namespace content

#endif  // CONTENT_BROWSER_RENDERER_HOST_INPUT_RENDER_WIDGET_HOST_LATENCY_TRACKER_H_

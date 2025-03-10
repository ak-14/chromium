// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_EVENTS_POINTER_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_EVENTS_POINTER_EVENT_H_

#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/pointer_event_init.h"

namespace blink {

class CORE_EXPORT PointerEvent final : public MouseEvent {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static PointerEvent* Create(const AtomicString& type,
                              const PointerEventInit& initializer,
                              TimeTicks platform_time_stamp) {
    return new PointerEvent(type, initializer, platform_time_stamp);
  }
  static PointerEvent* Create(const AtomicString& type,
                              const PointerEventInit& initializer) {
    return PointerEvent::Create(type, initializer, CurrentTimeTicks());
  }

  int pointerId() const { return pointer_id_; }
  double width() const { return width_; }
  double height() const { return height_; }
  float pressure() const { return pressure_; }
  long tiltX() const { return tilt_x_; }
  long tiltY() const { return tilt_y_; }
  float tangentialPressure() const { return tangential_pressure_; }
  long twist() const { return twist_; }
  const String& pointerType() const { return pointer_type_; }
  bool isPrimary() const { return is_primary_; }

  short button() const override { return RawButton(); }
  bool IsMouseEvent() const override;
  bool IsPointerEvent() const override;

  // TODO(eirage): Remove these override of coordinates getters when
  // fractional mouseevent flag is removed.
  double screenX() const override;
  double screenY() const override;
  double clientX() const override;
  double clientY() const override;
  double pageX() const override;
  double pageY() const override;

  void ReceivedTarget() override;

  // Always return null for fromElement and toElement because these fields
  // (inherited from MouseEvents) are non-standard.
  Node* fromElement() const final;
  Node* toElement() const final;

  HeapVector<Member<PointerEvent>> getCoalescedEvents();

  DispatchEventResult DispatchEvent(EventDispatcher&) override;

  virtual void Trace(blink::Visitor*);

 private:
  PointerEvent(const AtomicString&,
               const PointerEventInit&,
               TimeTicks platform_time_stamp);

  int pointer_id_;
  double width_;
  double height_;
  float pressure_;
  long tilt_x_;
  long tilt_y_;
  float tangential_pressure_;
  long twist_;
  String pointer_type_;
  bool is_primary_;

  bool coalesced_events_targets_dirty_;

  HeapVector<Member<PointerEvent>> coalesced_events_;
};

DEFINE_EVENT_TYPE_CASTS(PointerEvent);

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_CORE_EVENTS_POINTER_EVENT_H_

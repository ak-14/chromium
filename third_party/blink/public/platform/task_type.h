// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_PUBLIC_PLATFORM_TASK_TYPE_H_
#define THIRD_PARTY_BLINK_PUBLIC_PLATFORM_TASK_TYPE_H_

namespace blink {

// A list of task sources known to Blink according to the spec.
// This enum is used for a histogram and it should not be re-numbered.
enum class TaskType : unsigned {
  ///////////////////////////////////////
  // Speced tasks should use one of the following task types
  ///////////////////////////////////////

  // Speced tasks and related internal tasks should be posted to one of
  // the following task runners. These task runners may be throttled.

  // This value is used as a default value in cases where TaskType
  // isn't supported yet. Don't use outside platform/scheduler code.
  kDeprecatedNone = 0,

  // https://html.spec.whatwg.org/multipage/webappapis.html#generic-task-sources
  //
  // This task source is used for features that react to DOM manipulations, such
  // as things that happen in a non-blocking fashion when an element is inserted
  // into the document.
  kDOMManipulation = 1,
  // This task source is used for features that react to user interaction, for
  // example keyboard or mouse input. Events sent in response to user input
  // (e.g. click events) must be fired using tasks queued with the user
  // interaction task source.
  kUserInteraction = 2,
  // This task source is used for features that trigger in response to network
  // activity.
  kNetworking = 3,
  // This task source is used for control messages between kNetworking tasks.
  kNetworkingControl = 4,
  // This task source is used to queue calls to history.back() and similar APIs.
  kHistoryTraversal = 5,

  // https://html.spec.whatwg.org/multipage/embedded-content.html#the-embed-element
  // This task source is used for the embed element setup steps.
  kEmbed = 6,

  // https://html.spec.whatwg.org/multipage/embedded-content.html#media-elements
  // This task source is used for all tasks queued in the [Media elements]
  // section and subsections of the spec unless explicitly specified otherwise.
  kMediaElementEvent = 7,

  // https://html.spec.whatwg.org/multipage/scripting.html#the-canvas-element
  // This task source is used to invoke the result callback of
  // HTMLCanvasElement.toBlob().
  kCanvasBlobSerialization = 8,

  // https://html.spec.whatwg.org/multipage/webappapis.html#event-loop-processing-model
  // This task source is used when an algorithm requires a microtask to be
  // queued.
  kMicrotask = 9,

  // https://html.spec.whatwg.org/multipage/webappapis.html#timers
  // This task source is used to queue tasks queued by setInterval() and similar
  // APIs.
  kJavascriptTimer = 10,

  // https://html.spec.whatwg.org/multipage/comms.html#sse-processing-model
  // This task source is used for any tasks that are queued by EventSource
  // objects.
  kRemoteEvent = 11,

  // https://html.spec.whatwg.org/multipage/comms.html#feedback-from-the-protocol
  // The task source for all tasks queued in the [WebSocket] section of the
  // spec.
  kWebSocket = 12,

  // https://html.spec.whatwg.org/multipage/comms.html#web-messaging
  // This task source is used for the tasks in cross-document messaging.
  kPostedMessage = 13,

  // https://html.spec.whatwg.org/multipage/comms.html#message-ports
  kUnshippedPortMessage = 14,

  // https://www.w3.org/TR/FileAPI/#blobreader-task-source
  // This task source is used for all tasks queued in the FileAPI spec to read
  // byte sequences associated with Blob and File objects.
  kFileReading = 15,

  // https://www.w3.org/TR/IndexedDB/#request-api
  kDatabaseAccess = 16,

  // https://w3c.github.io/presentation-api/#common-idioms
  // This task source is used for all tasks in the Presentation API spec.
  kPresentation = 17,

  // https://www.w3.org/TR/2016/WD-generic-sensor-20160830/#sensor-task-source
  // This task source is used for all tasks in the Sensor API spec.
  kSensor = 18,

  // https://w3c.github.io/performance-timeline/#performance-timeline
  kPerformanceTimeline = 19,

  // https://www.khronos.org/registry/webgl/specs/latest/1.0/#5.15
  // This task source is used for all tasks in the WebGL spec.
  kWebGL = 20,

  // https://www.w3.org/TR/requestidlecallback/#start-an-event-loop-s-idle-period
  kIdleTask = 21,

  // Use MiscPlatformAPI for a task that is defined in the spec but is not yet
  // associated with any specific task runner in the spec. MiscPlatformAPI is
  // not encouraged for stable and matured APIs. The spec should define the task
  // runner explicitly.
  // The task runner may be throttled.
  kMiscPlatformAPI = 22,

  ///////////////////////////////////////
  // The following task types are DEPRECATED! Use kInternal* instead.
  ///////////////////////////////////////

  // Other internal tasks that cannot fit any of the above task runners
  // can be posted here, but the usage is not encouraged. The task runner
  // may be throttled.
  //
  // UnspecedTimer should be used for all other purposes.
  kUnspecedTimer = 23,

  // Tasks that must not be throttled should be posted here, but the usage
  // should be very limited.
  kUnthrottled = 25,

  ///////////////////////////////////////
  // Not-speced tasks should use one of the following task types
  ///////////////////////////////////////

  // Tasks used for all tasks associated with loading page content.
  kInternalLoading = 24,

  // Tasks for tests or mock objects.
  kInternalTest = 26,

  // Tasks that are posting back the result from the WebCrypto task runner to
  // the Blink thread that initiated the call and holds the Promise. Tasks with
  // this type are posted by:
  // * //components/webcrypto
  kInternalWebCrypto = 27,

  // Tasks to execute IndexedDB's callbacks. Tasks with this type are posted by:
  // * //content/renderer/indexed_db
  kInternalIndexedDB = 28,

  // Tasks to execute media-related things like logging or playback. Tasks with
  // this type are mainly posted by:
  // * //content/renderer/media
  // * //media
  kInternalMedia = 29,

  // Tasks to execute things for real-time media processing like recording.
  // Tasks with this type are mainly posted by:
  // * //content/renderer/media
  // * //media
  kInternalMediaRealTime = 30,

  // Tasks to execute IPC (legacy IPC and mojo).
  kInternalIPC = 31,

  // Tasks related to user interaction like clicking or inputting texts.
  kInternalUserInteraction = 32,

  // Tasks related to the inspector.
  kInternalInspector = 33,

  // Tasks related to animation like blinking caret or CSS animation.
  kInternalAnimation = 34,

  // Tasks related to accessbility. Tasks with this type are mainly posted by:
  // * //content/renderer/accessibility
  // * //third_party/blink/renderer/modules/accessibility
  kInternalAccessibility = 35,

  kCount = 36,
};

}  // namespace blink

#endif

// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_NOTIFICATIONS_NOTIFICATION_MANAGER_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_NOTIFICATIONS_NOTIFICATION_MANAGER_H_

#include "third_party/blink/public/platform/modules/notifications/notification_service.mojom-blink.h"
#include "third_party/blink/public/platform/modules/notifications/web_notification_manager.h"
#include "third_party/blink/public/platform/modules/permissions/permission.mojom-blink.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_notification_permission_callback.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/wtf/noncopyable.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class ScriptPromise;
class ScriptPromiseResolver;
class ScriptState;
struct WebNotificationData;

// The notification manager, unique to the execution context, is responsible for
// connecting and communicating with the Mojo notification service.
//
// TODO(peter): Make the NotificationManager responsible for resource loading.
class NotificationManager final
    : public GarbageCollectedFinalized<NotificationManager>,
      public Supplement<ExecutionContext> {
  USING_GARBAGE_COLLECTED_MIXIN(NotificationManager);
  WTF_MAKE_NONCOPYABLE(NotificationManager);

 public:
  static const char kSupplementName[];

  static NotificationManager* From(ExecutionContext* context);

  ~NotificationManager();

  // Returns the notification permission status of the current origin. This
  // method is synchronous to support the Notification.permission getter.
  mojom::blink::PermissionStatus GetPermissionStatus();

  ScriptPromise RequestPermission(
      ScriptState* script_state,
      V8NotificationPermissionCallback* deprecated_callback);

  // Shows a notification that is not tied to any service worker.
  //
  // Compares |token| against the token of all currently displayed
  // notifications and if there's a match, replaces the older notification;
  // else displays a new notification.
  void DisplayNonPersistentNotification(
      const String& token,
      const WebNotificationData& notification_data,
      std::unique_ptr<WebNotificationResources> notification_resources,
      mojom::blink::NonPersistentNotificationListenerPtr event_listener);

  // Closes the notification that was most recently displayed with this token.
  void CloseNonPersistentNotification(const String& token);

  // Shows a notification from a service worker.
  void DisplayPersistentNotification(
      blink::WebServiceWorkerRegistration* service_worker_registration,
      const blink::WebNotificationData& notification_data,
      std::unique_ptr<blink::WebNotificationResources> notification_resources,
      ScriptPromiseResolver* resolver);

  // Closes a persistent notification identified by its notification id.
  void ClosePersistentNotification(const WebString& notification_id);

  // Asynchronously gets the persistent notifications belonging to the Service
  // Worker Registration. If |filter_tag| is not an empty string, only the
  // notification with the given tag will be considered. Will take ownership of
  // the WebNotificationGetCallbacks object.
  void GetNotifications(
      WebServiceWorkerRegistration* service_worker_registration,
      const WebString& filter_tag,
      ScriptPromiseResolver* resolver);

  virtual void Trace(blink::Visitor* visitor);

 private:
  explicit NotificationManager(ExecutionContext& context);

  void DidDisplayPersistentNotification(
      ScriptPromiseResolver* resolver,
      mojom::blink::PersistentNotificationError error);

  void DidGetNotifications(
      ScriptPromiseResolver* resolver,
      const Vector<String>& notification_ids,
      const Vector<WebNotificationData>& notification_datas);

  // Returns an initialized NotificationServicePtr. A connection will be
  // established the first time this method is called.
  const mojom::blink::NotificationServicePtr& GetNotificationService();

  void OnPermissionRequestComplete(
      ScriptPromiseResolver* resolver,
      V8PersistentCallbackFunction<V8NotificationPermissionCallback>*
          deprecated_callback,
      mojom::blink::PermissionStatus status);

  void OnNotificationServiceConnectionError();
  void OnPermissionServiceConnectionError();

  mojom::blink::NotificationServicePtr notification_service_;
  mojom::blink::PermissionServicePtr permission_service_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_NOTIFICATIONS_NOTIFICATION_MANAGER_H_

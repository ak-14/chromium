// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_WORKERS_WORKER_OR_WORKLET_GLOBAL_SCOPE_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_WORKERS_WORKER_OR_WORKLET_GLOBAL_SCOPE_H_

#include "services/network/public/mojom/fetch_api.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_cache_options.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/web_feature_forward.h"
#include "third_party/blink/renderer/core/workers/worker_clients.h"
#include "third_party/blink/renderer/core/workers/worker_event_queue.h"
#include "third_party/blink/renderer/platform/scheduler/child/worker_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/bit_vector.h"

namespace blink {

class Modulator;
class ModuleTreeClient;
class ResourceFetcher;
class V8AbstractEventListener;
class WorkerOrWorkletScriptController;
class WorkerReportingProxy;
class WorkerThread;

class CORE_EXPORT WorkerOrWorkletGlobalScope : public EventTargetWithInlineData,
                                               public ExecutionContext,
                                               public SecurityContext {
 public:
  using SecurityContext::GetSecurityOrigin;
  using SecurityContext::GetContentSecurityPolicy;
  using SecurityContext::GetCOWL;

  WorkerOrWorkletGlobalScope(v8::Isolate*,
                             WorkerClients*,
                             WorkerReportingProxy&);
  ~WorkerOrWorkletGlobalScope() override;

  // EventTarget
  const AtomicString& InterfaceName() const override;

  // ScriptWrappable
  v8::Local<v8::Object> Wrap(v8::Isolate*,
                             v8::Local<v8::Object> creation_context) final;
  v8::Local<v8::Object> AssociateWithWrapper(
      v8::Isolate*,
      const WrapperTypeInfo*,
      v8::Local<v8::Object> wrapper) final;
  bool HasPendingActivity() const override;

  // ExecutionContext
  bool IsWorkerOrWorkletGlobalScope() const final { return true; }
  bool IsJSExecutionForbidden() const final;
  void DisableEval(const String& error_message) final;
  bool CanExecuteScripts(ReasonForCallingCanExecuteScripts) final;
  EventQueue* GetEventQueue() const final;

  // SecurityContext
  void DidUpdateSecurityOrigin() final {}

  // Returns true when the WorkerOrWorkletGlobalScope is closing (e.g. via
  // WorkerGlobalScope#close() method). If this returns true, the worker is
  // going to be shutdown after the current task execution. Globals that
  // don't support close operation should always return false.
  virtual bool IsClosing() const = 0;

  // Should be called before destroying the global scope object. Allows
  // sub-classes to perform any cleanup needed.
  virtual void Dispose();

  void RegisterEventListener(V8AbstractEventListener*);
  void DeregisterEventListener(V8AbstractEventListener*);

  void SetModulator(Modulator*);

  // Called from UseCounter to record API use in this execution context.
  void CountFeature(WebFeature);

  // Called from UseCounter to record deprecated API use in this execution
  // context.
  void CountDeprecation(WebFeature);

  // May return nullptr if this global scope is not threaded (i.e.,
  // MainThreadWorkletGlobalScope) or after dispose() is called.
  virtual WorkerThread* GetThread() const = 0;

  ResourceFetcher* Fetcher() const override;
  ResourceFetcher* EnsureFetcher();

  WorkerClients* Clients() const { return worker_clients_.Get(); }

  WorkerOrWorkletScriptController* ScriptController() {
    return script_controller_.Get();
  }

  WorkerReportingProxy& ReportingProxy() { return reporting_proxy_; }

  void Trace(blink::Visitor*) override;
  void TraceWrappers(const ScriptWrappableVisitor*) const override;

  scheduler::WorkerScheduler* GetScheduler() override;
  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner(TaskType) override;

 protected:
  void ApplyContentSecurityPolicyFromVector(
      const Vector<CSPHeaderAndType>& headers);

  // Implementation of the "fetch a module worker script graph" algorithm in the
  // HTML spec:
  // https://html.spec.whatwg.org/multipage/webappapis.html#fetch-a-module-worker-script-tree
  void FetchModuleScript(const KURL& module_url_record,
                         network::mojom::FetchCredentialsMode,
                         ModuleTreeClient*);

 private:
  CrossThreadPersistent<WorkerClients> worker_clients_;
  Member<ResourceFetcher> resource_fetcher_;
  Member<WorkerOrWorkletScriptController> script_controller_;
  Member<WorkerEventQueue> event_queue_;

  WorkerReportingProxy& reporting_proxy_;

  HeapHashSet<Member<V8AbstractEventListener>> event_listeners_;

  // This is the set of features that this worker has used.
  BitVector used_features_;

  // LocalDOMWindow::modulator_ workaround equivalent.
  // TODO(kouhei): Remove this.
  TraceWrapperMember<Modulator> modulator_;
};

DEFINE_TYPE_CASTS(
    WorkerOrWorkletGlobalScope,
    ExecutionContext,
    context,
    (context->IsWorkerGlobalScope() || context->IsWorkletGlobalScope()),
    (context.IsWorkerGlobalScope() || context.IsWorkletGlobalScope()));

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_CORE_WORKERS_WORKER_OR_WORKLET_GLOBAL_SCOPE_H_

// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_FETCH_BODY_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_FETCH_BODY_H_

#include "third_party/blink/renderer/bindings/core/v8/active_script_wrappable.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/dom/context_lifecycle_observer.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class BodyStreamBuffer;
class ExecutionContext;
class ScriptState;

// This class represents Body mix-in defined in the fetch spec
// https://fetch.spec.whatwg.org/#body-mixin.
//
// Note: This class has body stream and its predicate whereas in the current
// spec only Response has it and Request has a byte stream defined in the
// Encoding spec. The spec should be fixed shortly to be aligned with this
// implementation.
class CORE_EXPORT Body : public ScriptWrappable,
                         public ActiveScriptWrappable<Body>,
                         public ContextClient {
  DEFINE_WRAPPERTYPEINFO();
  USING_GARBAGE_COLLECTED_MIXIN(Body);

 public:
  explicit Body(ExecutionContext*);

  ScriptPromise arrayBuffer(ScriptState*);
  ScriptPromise blob(ScriptState*);
  ScriptPromise formData(ScriptState*);
  ScriptPromise json(ScriptState*);
  ScriptPromise labeledJson(ScriptState*);
  ScriptPromise text(ScriptState*);
  ScriptValue body(ScriptState*);
  virtual BodyStreamBuffer* BodyBuffer() = 0;
  virtual const BodyStreamBuffer* BodyBuffer() const = 0;

  virtual bool bodyUsed();
  bool IsBodyLocked();

  // ScriptWrappable override.
  bool HasPendingActivity() const override;

  void Trace(blink::Visitor* visitor) override {
    ScriptWrappable::Trace(visitor);
    ContextClient::Trace(visitor);
  }

 private:
  // TODO(e_hakkinen): Fix |MimeType()| to always contain parameters and
  // remove |ContentType()|.
  virtual String ContentType() const = 0;
  virtual String MimeType() const = 0;
  virtual String Origin() const = 0;

  // Body consumption algorithms will reject with a TypeError in a number of
  // error conditions. This method wraps those up into one call which returns
  // an empty ScriptPromise if the consumption may proceed, and a
  // ScriptPromise rejected with a TypeError if it ought to be blocked.
  ScriptPromise RejectInvalidConsumption(ScriptState*);
  DISALLOW_COPY_AND_ASSIGN(Body);
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_CORE_FETCH_BODY_H_

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_H_

#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/cowl/cowl_parser.h"
#include "third_party/blink/renderer/core/cowl/label.h"
#include "third_party/blink/renderer/core/cowl/privilege.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/inspector/console_types.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/weborigin/security_violation_reporting_policy.h"

namespace blink {

class ConsoleMessage;
class Document;
class SecurityOrigin;

class CORE_EXPORT COWL final : public GarbageCollectedFinalized<COWL> {

 public:
  static COWL* Create();
  ~COWL();
  void Trace(blink::Visitor*);

  void BindToExecutionContext(ExecutionContext*);
  void SetupSelf(const SecurityOrigin&);
  void ApplySideEffectsToExecutionContext();

  bool IsCOWLAttributeEnabled(const LocalFrame*);
  Document* GetDocument() const;
  static SandboxFlags GetSandboxFlags();

  bool ContextTainting(Label* conf, Label* integrity);
  bool WriteCheck(Label* obj_conf, Label* obj_int) const;

  Label* EffectiveConfidentiality() const;
  Label* EffectiveIntegrity() const;

  bool AllowRequest(const KURL&) const;
  bool AllowResponse(const ResourceRequest&,
                     const ResourceResponse&) const;
  void AddCtxHeader(ResourceRequest&) const;
  bool ProcessCtxHeader(const LocalFrame*,
                        const AtomicString&,
                        const KURL&);

  void LogToConsole(const String& message, MessageLevel = kErrorMessageLevel) const;
  void LogToConsole(ConsoleMessage*, LocalFrame* = nullptr) const;

  bool IsEnabled() const { return enabled_; }
  void Enable() { enabled_ = true; }

  Label* GetConfidentiality() const { return confidentiality_; }
  void SetConfidentiality(Label* confidentiality) { confidentiality_ = confidentiality; }

  Label* GetIntegrity() const { return integrity_; }
  void SetIntegrity(Label* integrity) { integrity_ = integrity; }

  Privilege* GetPrivilege() const { return privilege_; }
  void SetPrivilege(Privilege* privilege) { privilege_ = privilege; }

 private:
  COWL();

  bool enabled_;
  Member<Label> confidentiality_;
  Member<Label> integrity_;
  Member<Privilege> privilege_;

  Member<ExecutionContext> execution_context_;
};

}  // namespace blink

#endif // THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_H_

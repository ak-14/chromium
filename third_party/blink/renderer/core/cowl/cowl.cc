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

#include "third_party/blink/renderer/core/cowl/cowl.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/frame_owner.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

COWL* COWL::Create() { return new COWL(); }

COWL::COWL()
  : enabled_(false),
    confidentiality_(nullptr),
    integrity_(nullptr),
    privilege_(nullptr),
    execution_context_(nullptr) {}

COWL::~COWL() {}

void COWL::BindToExecutionContext(ExecutionContext* execution_context) {
  execution_context_ = execution_context;
  ApplySideEffectsToExecutionContext();
}

void COWL::SetupSelf(const SecurityOrigin& security_origin) {
  confidentiality_ = Label::Create();
  integrity_ = Label::Create();
  privilege_ = Privilege::Create(security_origin.ToString());
}

void COWL::ApplySideEffectsToExecutionContext() {
  DCHECK(execution_context_ &&
      execution_context_->GetSecurityContext().GetSecurityOrigin());
  SecurityContext& security_context = execution_context_->GetSecurityContext();

  if (!enabled_)
    SetupSelf(*security_context.GetSecurityOrigin());

  Document* document = this->GetDocument();
  if (document && IsCOWLAttributeEnabled(document->GetFrame())) {
      document->EnforceSandboxFlags(GetSandboxFlags());
      enabled_ = true;
  }
}

bool COWL::IsCOWLAttributeEnabled(const LocalFrame* frame) {
  if (frame && !frame->IsMainFrame() && frame->Owner())
    return frame->Owner()->Cowl();
  return false;
}

Document* COWL::GetDocument() const {
  return (execution_context_ && execution_context_->IsDocument())
    ? ToDocument(execution_context_)
    : nullptr;
}

SandboxFlags COWL::GetSandboxFlags() {
  SandboxFlags mask = kSandboxPlugins
                    | kSandboxDocumentDomain
                    | kSandboxOrigin
                    | kSandboxNavigation
                    | kSandboxTopNavigation
                    | kSandboxPropagatesToAuxiliaryBrowsingContexts;
  return mask;
}

bool COWL::ContextTainting(Label* conf, Label* integrity) {
  Label* new_conf = confidentiality_->and_(conf)->Downgrade(privilege_);
  Label* new_int = integrity_->or_(integrity)->Downgrade(privilege_);

  if (!enabled_ && !(new_conf->IsEmpty() && new_int->IsEmpty()))
    return false;

  confidentiality_ = new_conf;
  integrity_ = new_int;
  return true;
}

bool COWL::WriteCheck(Label* obj_conf, Label* obj_int) const {
  Label* current_conf = EffectiveConfidentiality();
  Label* current_int = EffectiveIntegrity();

  if (!obj_conf->subsumes(current_conf) || !current_int->subsumes(obj_int))
    return false;

  return true;
}

Label* COWL::EffectiveConfidentiality() const {
  return confidentiality_->Downgrade(privilege_);
}

Label* COWL::EffectiveIntegrity() const {
  return integrity_->Upgrade(privilege_);
}

void COWL::LogToConsole(const String& message, MessageLevel level) const {
  LogToConsole(ConsoleMessage::Create(kSecurityMessageSource, level, message));
}

void COWL::LogToConsole(ConsoleMessage* console_message,
    LocalFrame* frame) const {
  if (frame)
    frame->GetDocument()->AddConsoleMessage(console_message);
  else if (execution_context_)
    execution_context_->AddConsoleMessage(console_message);
}

void COWL::Trace(blink::Visitor* visitor) {
  visitor->Trace(confidentiality_);
  visitor->Trace(integrity_);
  visitor->Trace(privilege_);
  visitor->Trace(execution_context_);
}

}  // namespace blink

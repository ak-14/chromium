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

bool COWL::AllowRequest(const KURL& url) const {
  if (!enabled_)
    return true;

  String origin = SecurityOrigin::Create(url)->ToString();
  Label* conf = EffectiveConfidentiality();
  Label* dst_conf = Label::Create(origin);
  if (dst_conf->subsumes(conf))
    return true;

  String message = "COWL::context labeled " + conf->toString() +
                   " attempted to leak data to a remote server: " + origin;
  LogToConsole(ConsoleMessage::Create(kSecurityMessageSource,
        kErrorMessageLevel,
        message));
  return false;
}

bool COWL::AllowResponse(const ResourceRequest& request,
                         const ResourceResponse& response) const {
  const AtomicString& sec_cowl = response.HttpHeaderField(HTTPNames::Sec_COWL);
  if (sec_cowl.IsEmpty())
    return true;

  WebURLRequest::RequestContext request_context = request.GetRequestContext();
  if (request_context == WebURLRequest::kRequestContextLocation)
    return true;

  CommaDelimitedHeaderSet headers;
  ParseCommaDelimitedHeader(sec_cowl, headers);
  String data_header;
  for (String header : headers) {
    if (header.StartsWith("data"))
      data_header = header;
  }

  String self = SecurityOrigin::Create(response.Url())->ToString();
  Label* conf; Label* integrity;
  COWLParser::ParseLabeledDataHeader(data_header, self, conf, integrity);

  if (!conf || !integrity) {
    String message = "COWL::The server supplied a malformed Sec-COWL header";
    LogToConsole(ConsoleMessage::Create(kSecurityMessageSource,
          kErrorMessageLevel,
          message));
    return false;
  }

  Label* effective_conf = conf->Downgrade(privilege_);
  if (confidentiality_->subsumes(effective_conf) && integrity->subsumes(EffectiveIntegrity()))
    return true;

  String message = "COWL::Current context's label is not allowed to receive "
                   "data with server specified labels";
  LogToConsole(ConsoleMessage::Create(kSecurityMessageSource,
        kErrorMessageLevel,
        message));
  return false;
}

void COWL::AddCtxHeader(ResourceRequest& request) const {
  if (!enabled_ || request.GetReferrerPolicy() == kReferrerPolicyNever)
    return;

  String ctx_header = String::Format(
      "ctx-confidentiality %s; "
      "ctx-integrity %s; "
      "ctx-privilege %s",
      confidentiality_->toString().Utf8().data(),
      integrity_->toString().Utf8().data(),
      privilege_->asLabel()->toString().Utf8().data()
      );
  request.AddHTTPHeaderField(HTTPNames::Sec_COWL, AtomicString(ctx_header));
}

bool COWL::ProcessCtxHeader(const LocalFrame* frame,
                            const AtomicString& sec_cowl,
                            const KURL& url) {
  if (sec_cowl.IsEmpty())
    return true;

  if (!IsCOWLAttributeEnabled(frame)) {
    String message = "COWL::The application attempted to embed confined content outside a cowl iframe";
    LogToConsole(ConsoleMessage::Create(kSecurityMessageSource,
          kErrorMessageLevel,
          message));
    return false;
  }

  CommaDelimitedHeaderSet headers;
  ParseCommaDelimitedHeader(sec_cowl, headers);
  String ctx_header;
  for (String header : headers) {
    if (header.StartsWith("ctx"))
      ctx_header = header;
  }

  String self = SecurityOrigin::Create(url)->ToString();
  Label* conf; Label* integrity; Privilege* priv;
  COWLParser::ParseLabeledContextHeader(ctx_header, self, conf, integrity, priv);

  if (!conf || !integrity || !priv) {
    String message = "COWL::The server supplied a malformed Sec-COWL header";
    LogToConsole(ConsoleMessage::Create(kSecurityMessageSource,
          kErrorMessageLevel,
          message));
    return false;
  }

  if (!privilege_->asLabel()->subsumes(priv->asLabel())) {
    String message = "COWL::The server supplied a privilege that it is not trusted for";
    LogToConsole(ConsoleMessage::Create(kSecurityMessageSource,
          kErrorMessageLevel,
          message));
    return false;
  }

  Label* effective_int = integrity_->Upgrade(privilege_);
  if (!effective_int->subsumes(integrity)) {
    String message = "COWL::The server supplied an integrity label that it is not trusted for";
    LogToConsole(ConsoleMessage::Create(kSecurityMessageSource,
          kErrorMessageLevel,
          message));
    return false;
  }

  confidentiality_ = conf;
  integrity_ = integrity;
  privilege_ = priv;
  enabled_ = true;

  return true;
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

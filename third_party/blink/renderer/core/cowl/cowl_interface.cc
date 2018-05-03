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

#include "third_party/blink/renderer/core/cowl/cowl_interface.h"

namespace blink {

Label* COWLInterface::confidentiality(const ScriptState* script_state, ExceptionState& exception_state) {
  COWL* cowl = GetCOWL(script_state);
  if (!cowl->IsEnabled()) {
    exception_state.ThrowDOMException(kNotAllowedError, "COWL interface is only available to iframes with cowl attribute");
    return nullptr;
  }
  return cowl->GetConfidentiality();
}

void COWLInterface::setConfidentiality(ScriptState* script_state, Label* conf, ExceptionState& exception_state) {
  COWL* cowl = GetCOWL(script_state);
  if (!cowl->IsEnabled()) {
    exception_state.ThrowDOMException(kNotAllowedError, "COWL interface is only available to iframes with cowl attribute");
    return;
  }
  Label* current_int = cowl->GetIntegrity();
  if (!cowl->WriteCheck(conf, current_int)) {
    exception_state.ThrowSecurityError("Label is not above the current label");
    return;
  }
  cowl->SetConfidentiality(conf);
}

Label* COWLInterface::integrity(const ScriptState* script_state, ExceptionState& exception_state) {
  COWL* cowl = GetCOWL(script_state);
  if (!cowl->IsEnabled()) {
    exception_state.ThrowDOMException(kNotAllowedError, "COWL interface is only available to iframes with cowl attribute");
    return nullptr;
  }
  return cowl->GetIntegrity();
}

void COWLInterface::setIntegrity(ScriptState* script_state, Label* integrity, ExceptionState& exception_state) {
  COWL* cowl = GetCOWL(script_state);
  if (!cowl->IsEnabled()) {
    exception_state.ThrowDOMException(kNotAllowedError, "COWL interface is only available to iframes with cowl attribute");
    return;
  }
  Label* current_conf = cowl->GetConfidentiality();
  if (!cowl->WriteCheck(current_conf, integrity)) {
    exception_state.ThrowSecurityError("Label is not below the current label");
    return;
  }
  cowl->SetIntegrity(integrity);
}

Privilege* COWLInterface::privilege(const ScriptState* script_state, ExceptionState& exception_state) {
  COWL* cowl = GetCOWL(script_state);
  if (!cowl->IsEnabled()) {
    exception_state.ThrowDOMException(kNotAllowedError, "COWL interface is only available to iframes with cowl attribute");
    return nullptr;
  }
  return cowl->GetPrivilege();
}

void COWLInterface::setPrivilege(ScriptState* script_state, Privilege* priv, ExceptionState& exception_state) {
  COWL* cowl = GetCOWL(script_state);
  if (!cowl->IsEnabled()) {
    exception_state.ThrowDOMException(kNotAllowedError, "COWL interface is only available to iframes with cowl attribute");
    return;
  }
  cowl->SetPrivilege(priv);
}

// Internal functions
COWL* COWLInterface::GetCOWL(const ScriptState* script_state) {
  return ExecutionContext::From(script_state)->GetSecurityContext().GetCOWL();
}

void COWLInterface::Trace(blink::Visitor* visitor) {
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink

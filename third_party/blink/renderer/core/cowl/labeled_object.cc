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

#include "third_party/blink/renderer/core/cowl/labeled_object.h"

#include "third_party/blink/renderer/core/cowl/cowl.h"
#include "third_party/blink/renderer/core/cowl/label.h"
#include "third_party/blink/renderer/core/cowl/privilege.h"

namespace blink {

LabeledObject* LabeledObject::Create(ScriptState* script_state, ScriptValue obj,
                                     CILabel& labels, ExceptionState& exception_state) {
  COWL* cowl = ExecutionContext::From(script_state)->GetSecurityContext().GetCOWL();
  Label* confidentiality;
  if (labels.hasConfidentiality())
    confidentiality = labels.confidentiality();
  else
    confidentiality = cowl->GetConfidentiality();

  Label* integrity;
  if (labels.hasIntegrity())
    integrity = labels.integrity();
  else
    integrity = cowl->GetIntegrity();

  if (!cowl->WriteCheck(confidentiality, integrity)) {
    exception_state.ThrowSecurityError("Label of blob is not above current label or below current clearance");
    return nullptr;
  }
  ScriptValue obj_clone = StructuredClone(script_state, obj, exception_state);
  return new LabeledObject(obj_clone, confidentiality, integrity);
}

Label* LabeledObject::confidentiality() const {
  return confidentiality_;
}

Label* LabeledObject::integrity() const {
  return integrity_;
}

ScriptValue LabeledObject::protectedObject(ScriptState* script_state,
                                           ExceptionState& exception_state) const {
  COWL* cowl = ExecutionContext::From(script_state)->GetSecurityContext().GetCOWL();
  if (!cowl->ContextTainting(confidentiality_, integrity_)) {
    exception_state.ThrowSecurityError(
        "Unconfined context with insufficient privileges; create a cowl iframe to inspect protected data");
    return ScriptValue::CreateNull(script_state);
  }
  ScriptValue obj_clone = StructuredClone(script_state, obj_, exception_state);
  return obj_clone;
}

LabeledObject* LabeledObject::clone(ScriptState* script_state, CILabel& labels,
                                    ExceptionState& exception_state) const {
  Label* new_conf;
  if (labels.hasConfidentiality())
    new_conf = labels.confidentiality();
  else
    new_conf = confidentiality_;

  Label* new_int;
  if (labels.hasIntegrity())
    new_int = labels.integrity();
  else
    new_int = integrity_;

  COWL* cowl = ExecutionContext::From(script_state)->GetSecurityContext().GetCOWL();
  Privilege* priv = cowl->GetPrivilege();

  if (!new_conf->subsumes(confidentiality_, priv)) {
    exception_state.ThrowSecurityError("Confidentiality label needs to be more restrictive");
    return nullptr;
  }
  if (!integrity_->subsumes(new_int, priv)) {
    exception_state.ThrowSecurityError("Check integrity label");
    return nullptr;
  }
  ScriptValue obj_clone =  StructuredClone(script_state, obj_, exception_state);
  return new LabeledObject(obj_clone, new_conf, new_int);
}

// Internal functions
LabeledObject* LabeledObject::CreateFromLabeledJSON(
      v8::Local<v8::Value> labeled_json,
      const String& origin,
      v8::Isolate* isolate) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  ScriptState* script_state = ScriptState::From(context);

  v8::Local<v8::Object> response_object = labeled_json.As<v8::Object>();

  v8::Local<v8::Value> conf_value;
  if (!response_object->Get(context, v8::String::NewFromUtf8(isolate, "confidentiality")).ToLocal(&conf_value))
    return nullptr;

  v8::Local<v8::Value> integrity_value;
  if (!response_object->Get(context, v8::String::NewFromUtf8(isolate, "integrity")).ToLocal(&integrity_value))
    return nullptr;

  v8::Local<v8::Value> obj_value;
  if (!response_object->Get(context, v8::String::NewFromUtf8(isolate, "object")).ToLocal(&obj_value))
    return nullptr;

  String conf_expr = ToCoreStringWithNullCheck(conf_value.As<v8::String>());
  String integrity_expr = ToCoreStringWithNullCheck(integrity_value.As<v8::String>());
  ScriptValue obj = ScriptValue(script_state, obj_value);

  Label* conf = COWLParser::ParseLabelExpression(conf_expr, origin);
  Label* integrity  = COWLParser::ParseLabelExpression(integrity_expr, origin);

  return new LabeledObject(obj, conf, integrity);
}

String LabeledObject::ToLabeledJSON() const {
  v8::Local<v8::Value> value = obj_.V8Value();
  ScriptState* script_state = obj_.GetScriptState();
  v8::Local<v8::Context> context = obj_.GetContext();

  V8ObjectBuilder builder(script_state);
  builder.AddString("confidentiality", confidentiality_->toString());
  builder.AddString("integrity", integrity_->toString());
  builder.Add("object", value);
  ScriptValue json_object = builder.GetScriptValue();

  String body = ToCoreStringWithNullCheck(
      v8::JSON::Stringify(context, json_object.V8Value().As<v8::Object>()).ToLocalChecked());
  return body;
}

bool LabeledObject::AllowSend(String url) const {
  scoped_refptr<SecurityOrigin> origin = SecurityOrigin::CreateFromString(url);
  Label* remote_conf = Label::Create(origin->ToString());
  if (!remote_conf)
    return false;

  ScriptState* script_state = obj_.GetScriptState();
  COWL* cowl = ExecutionContext::From(script_state)->GetSecurityContext().GetCOWL();
  Privilege* priv = cowl->GetPrivilege();

  if (!remote_conf->subsumes(confidentiality_, priv))
    return false;

  return true;
}

String LabeledObject::GetDataHeader() const {
  String header = String::Format(
      "data-confidentiality %s; "
      "data-integrity %s",
      confidentiality_->toString().Utf8().data(),
      integrity_->toString().Utf8().data()
      );
  return header;
}

ScriptValue LabeledObject::StructuredClone(ScriptState* script_state,
                                           ScriptValue obj,
                                           ExceptionState& exception_state) {
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Value> value = obj.V8Value();
  scoped_refptr<SerializedScriptValue> serialized =
                                SerializedScriptValue::SerializeAndSwallowExceptions(isolate, value);
  v8::Local<v8::Value> result = serialized->Deserialize(isolate);
  if (result->IsNull()) {
    exception_state.ThrowDOMException(kDataCloneError, "Object cannot be serialized");
    return ScriptValue::CreateNull(script_state);
  }
  ScriptValue obj_clone = ScriptValue(script_state, result);
  return obj_clone;
}

void LabeledObject::Trace(blink::Visitor* visitor) {
  visitor->Trace(confidentiality_);
  visitor->Trace(integrity_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink

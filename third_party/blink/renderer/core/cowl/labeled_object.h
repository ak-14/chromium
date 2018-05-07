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

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_COWL_LABELED_OBJECT_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_COWL_LABELED_OBJECT_H_

#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_ci_label.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"

namespace blink {

class Label;

class CORE_EXPORT LabeledObject final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public: // labeled_object.idl implementation
  static LabeledObject* Create(ScriptState*, ScriptValue, CILabel&, ExceptionState&);

  Label* confidentiality() const;
  Label* integrity() const;

  ScriptValue protectedObject(ScriptState*, ExceptionState&) const;
  LabeledObject* clone(ScriptState*, CILabel&, ExceptionState&) const;

 public: // Internal functions
  static LabeledObject* CreateFromLabeledJSON(v8::Local<v8::Value> labeled_json,
                                              const String& origin,
                                              v8::Isolate* isolate);
  String ToLabeledJSON() const;

  bool AllowSend(String url) const;
  String GetDataHeader() const;

  const ScriptValue GetObj() const { return obj_; }
  static ScriptValue StructuredClone(ScriptState*, ScriptValue, ExceptionState&);

  void Trace(blink::Visitor*);

 private:
  LabeledObject(ScriptValue obj, Label* conf, Label* integrity)
      : obj_(obj),
        confidentiality_(conf),
        integrity_(integrity) {}

  ScriptValue obj_;
  Member<Label> confidentiality_;
  Member<Label> integrity_;
};

}  // namespace blink

#endif // THIRD_PARTY_BLINK_RENDERER_CORE_COWL_LABELED_OBJECT_H_

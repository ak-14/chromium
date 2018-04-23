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

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_COWL_PRIVILEGE_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_COWL_PRIVILEGE_H_

#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class Label;

class CORE_EXPORT Privilege final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public: // privilege.idl implementation
  static Privilege* Create();
  static Privilege* CreateForJSConstructor();
  Label* asLabel() const;
  Privilege* combine(Privilege*) const;
  Privilege* delegate(Label*, ExceptionState&) const;

 public: // Internal functions
  static Privilege* Create(Label*);
  static Privilege* Create(const String&);

  void Trace(blink::Visitor*);

 private:
  Privilege();
  explicit Privilege(Label* label) : label_(label) {}

  Member<Label> label_;
};

}  // namespace blink

#endif // THIRD_PARTY_BLINK_RENDERER_CORE_COWL_PRIVILEGE_H_

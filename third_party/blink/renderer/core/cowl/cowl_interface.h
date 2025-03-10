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

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_INTERFACE_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_INTERFACE_H_

#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/cowl/cowl.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"

namespace blink {

class CORE_EXPORT COWLInterface final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public: // cowl.idl implementation
  static Label* confidentiality(const ScriptState*, ExceptionState&);
  static void setConfidentiality(ScriptState*, Label*, ExceptionState&);

  static Label* integrity(const ScriptState*, ExceptionState&);
  static void setIntegrity(ScriptState*, Label*, ExceptionState&);

  static Privilege* privilege(const ScriptState*, ExceptionState&);
  static void setPrivilege(ScriptState*, Privilege*, ExceptionState&);

 public: // Internal functions
  static COWL* GetCOWL(const ScriptState*);

  void Trace(blink::Visitor*);
};

}  // namespace blink

#endif // THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_INTERFACE_H_

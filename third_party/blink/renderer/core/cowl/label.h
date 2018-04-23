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

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_COWL_LABEL_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_COWL_LABEL_H_

#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/cowl/cowl_principal.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class Privilege;

typedef Vector<COWLPrincipal> DisjunctionSet;
typedef Vector<DisjunctionSet> DisjunctionSetArray;

class CORE_EXPORT Label final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public: // label.idl implementation
  static Label* Create(ExceptionState&);
  static Label* Create(const String& principal, ExceptionState&);
  bool equals(Label*) const;
  bool subsumes(Label*) const;
  bool subsumes(Label*, Privilege*) const;
  Label* and_(Label*) const;
  Label* and_(const String& principal, ExceptionState&) const;
  Label* or_(Label*) const;
  Label* or_(const String& principal, ExceptionState&) const;
  String toString() const;

 public: // Internal functions
  static Label* Create();
  static Label* Create(const String& principal);
  static Label* Create(const DisjunctionSetArray& roles);

  Label* and_(const String& principal) const;
  Label* or_(const String& principal) const;
  void InternalAnd(const DisjunctionSet&);
  void InternalOr(const DisjunctionSet&);

  Label* Clone() const;
  Label* Upgrade(Privilege*) const;
  Label* Downgrade(Privilege*) const;

  bool IsEmpty() const;
  bool Contains(const DisjunctionSet&) const;
  void RemoveRolesSubsumedBy(const DisjunctionSet&);

  const DisjunctionSetArray GetRoles() const { return roles_; }

  void Trace(blink::Visitor*);

 private:
  Label() {}
  explicit Label(const DisjunctionSet& role) { roles_.push_back(role); }
  explicit Label(const DisjunctionSetArray& roles) : roles_(roles) {}

  DisjunctionSetArray roles_;
};

//
// Internals
//
class DisjunctionSetUtils {
 public:
  static bool Subsumes(const DisjunctionSet&, const DisjunctionSet&);
  static void Or(DisjunctionSet&, const DisjunctionSet&);
  static void InsertSorted(DisjunctionSet&, const COWLPrincipal&);
  static String ToString(const DisjunctionSet&);
};

}  // namespace blink

#endif // THIRD_PARTY_BLINK_RENDERER_CORE_COWL_LABEL_H_

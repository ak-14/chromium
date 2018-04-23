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

#include "third_party/blink/renderer/core/cowl/label.h"

#include <algorithm>
#include <iterator>
#include "third_party/blink/renderer/core/cowl/cowl_parser.h"
#include "third_party/blink/renderer/core/cowl/privilege.h"

namespace blink {

Label* Label::Create(ExceptionState& exception_state) {
  return Create();
}

Label* Label::Create(const String& principal, ExceptionState& exception_state) {
  Label* label = Create(principal);

  if (!label)
    exception_state.ThrowTypeError("Invalid principal");

  return label;
}

bool Label::equals(Label* other) const {
  if (other == this)
    return true;

  DisjunctionSetArray other_roles = other->GetRoles();

  if (other_roles.size() != roles_.size())
    return false;

  for (size_t i = 0; i < roles_.size(); ++i) {
    if (!other_roles.Contains(roles_[i]))
      return false;
  }
  return true;
}

bool Label::subsumes(Label* other) const {
  if (other == this)
    return true;

  DisjunctionSetArray other_roles = other->GetRoles();

  if (other_roles.size() > roles_.size())
    return false;

  for (size_t i = 0; i < other_roles.size(); ++i) {
    if (!Contains(other_roles[i]))
      return false;
  }
  return true;
}

bool Label::subsumes(Label* other, Privilege* priv) const {
  return and_(priv->asLabel())->subsumes(other);
}

Label* Label::and_(Label* label) const {
  Label* _this = Clone();

  DisjunctionSetArray other_roles = label->GetRoles();
  for (size_t i = 0; i < other_roles.size(); ++i) {
    _this->InternalAnd(other_roles[i]);
  }
  return _this;
}

Label* Label::and_(const String& principal, ExceptionState& exception_state) const {
  Label* label = Create(principal, exception_state);
  if (!label)
    return nullptr;
  return and_(label);
}

Label* Label::or_(Label* label) const {
  Label* result = new Label();

  DisjunctionSetArray other_roles = label->GetRoles();
  for (size_t i = 0; i < other_roles.size(); ++i) {
    Label tmp(roles_);
    tmp.InternalOr(other_roles[i]);

    result = result->and_(&tmp);
  }
  return result;
}

Label* Label::or_(const String& principal, ExceptionState& exception_state) const {
  Label* label = Create(principal, exception_state);
  if (!label)
    return nullptr;
  return or_(label);
}

String Label::toString() const {
  if (IsEmpty())
    return "'none'";

  size_t roles_length = roles_.size();
  String retval = "";
  if (roles_length > 1)
    retval = "(";

  for (size_t i = 0; i < roles_length; ++i) {
    String role = DisjunctionSetUtils::ToString(roles_[i]);
    retval = retval + role;
    if (i != (roles_length -1))
      retval = retval + ") AND (";
  }
  if (roles_length > 1)
    retval = retval + ")";

  return retval;
}

// Internal functions
Label* Label::Create() {
  return new Label();
}

Label* Label::Create(const String& principal) {
  COWLPrincipalType principal_type = COWLParser::ValidatePrincipal(principal);

  if (principal_type == COWLPrincipalType::kInvalidPrincipal) {
    return nullptr;
  }
  COWLPrincipal new_principal = COWLPrincipal(principal, principal_type);
  DisjunctionSet role({new_principal});
  return new Label(role);
}

Label* Label::Create(const DisjunctionSetArray& roles) {
  return new Label(roles);
}

Label* Label::and_(const String& principal) const {
  Label* label = Create(principal);
  if (!label)
    return nullptr;
  return and_(label);
}

Label* Label::or_(const String& principal) const {
  Label* label = Create(principal);
  if (!label)
    return nullptr;
  return or_(label);
}

void Label::InternalAnd(const DisjunctionSet& role) {
  if (!Contains(role)) {
    RemoveRolesSubsumedBy(role);
    roles_.push_back(role);
  }
}

void Label::InternalOr(const DisjunctionSet& role) {
  if (IsEmpty())
    return;

  Label tmp_label;
  for (size_t i = 0; i < roles_.size(); ++i) {
    DisjunctionSet& n_role = roles_[i];
    DisjunctionSetUtils::Or(n_role, role);

    tmp_label.InternalAnd(n_role);
  }
  DisjunctionSetArray new_roles = tmp_label.GetRoles();
  roles_.swap(new_roles);
}

bool Label::IsEmpty() const {
  return roles_.IsEmpty();
}

Label* Label::Clone() const {
  Label* label = Create();
  for (size_t i = 0; i < roles_.size(); ++i) {
    DisjunctionSet dset = roles_[i];
    label->roles_.push_back(dset);
  }
  return label;
}

Label* Label::Upgrade(Privilege* priv) const {
  return this->and_(priv->asLabel());
}

Label* Label::Downgrade(Privilege* priv) const {
  Label* new_label = Label::Create();
  Label* priv_label = priv->asLabel();
  for (size_t i = 0; i < roles_.size(); ++i) {
    DisjunctionSet role = roles_[i];
    Label curr(role);
    if (!priv_label->subsumes(&curr))
      new_label->InternalAnd(role);
  }
  return new_label;
}

bool Label::Contains(const DisjunctionSet& role) const {
  for (size_t i = 0; i < roles_.size(); ++i) {
    if (DisjunctionSetUtils::Subsumes(roles_[i], role))
      return true;
  }
  return false;
}

void Label::RemoveRolesSubsumedBy(const DisjunctionSet& role) {
  auto pred = [&role] (DisjunctionSet& dset) {
    return DisjunctionSetUtils::Subsumes(dset, role);
  };
  auto new_last = std::remove_if(roles_.begin(), roles_.end(), pred);
  DisjunctionSetArray new_roles;
  std::copy(roles_.begin(), new_last, std::back_inserter(new_roles));
  roles_.swap(new_roles);
}

void Label::Trace(blink::Visitor* visitor) {
  ScriptWrappable::Trace(visitor);
}

//
// Internals
//
bool DisjunctionSetUtils::Subsumes(
    const DisjunctionSet& dset1,
    const DisjunctionSet& dset2) {
  if (&dset1 == &dset2)
    return true;

  if (dset2.size() < dset1.size())
    return false;

  for (const COWLPrincipal& p : dset1) {
    if (!dset2.Contains(p))
      return false;
  }
  return true;
}

void DisjunctionSetUtils::Or(DisjunctionSet& dset1, const DisjunctionSet& dset2) {
  for (const COWLPrincipal& p : dset2) {
    if (!dset1.Contains(p))
      DisjunctionSetUtils::InsertSorted(dset1, p);
  }
}

void DisjunctionSetUtils::InsertSorted(
    DisjunctionSet& dset,
    const COWLPrincipal& principal) {
  auto it = std::lower_bound(dset.begin(), dset.end(), principal);
  size_t position = std::distance(dset.begin(), it);
  dset.insert(position, principal);
}

String DisjunctionSetUtils::ToString(const DisjunctionSet& dset) {
  String retval = "";
  for (size_t i = 0; i < dset.size(); ++i) {
    const COWLPrincipal& principal = dset[i];
    retval = retval + principal.ToString();

    if (i != (dset.size() - 1))
      retval = retval + " OR ";
  }
  return retval;
}

}  // namespace blink

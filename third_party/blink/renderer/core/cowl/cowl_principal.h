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

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_PRINCIPAL_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_PRINCIPAL_H_

#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

enum class COWLPrincipalType {
  kOriginPrincipal = 0,
  kAppPrincipal = 1,
  kUniquePrincipal = 2,
  kInvalidPrincipal = 3,
};

class COWLPrincipal final {
 public:
  COWLPrincipal(const String& principal, const COWLPrincipalType principal_type)
    : principal_(principal), principal_type_(principal_type) {}

  bool IsOriginPrincipal() const {
    return principal_type_ == COWLPrincipalType::kOriginPrincipal;
  }
  String ToString() const {
    return principal_;
  }
  COWLPrincipalType GetType() const {
    return principal_type_;
  }
  bool operator== (const COWLPrincipal& other) const {
    return principal_ == other.principal_;
  }
  bool operator!= (const COWLPrincipal& other) const {
    return !(principal_ == other.principal_);
  }
  bool operator< (const COWLPrincipal& other) const {
    return CodePointCompareLessThan(principal_, other.principal_);
  }

 private:
  String principal_;
  COWLPrincipalType principal_type_;
};

}  // namespace blink

#endif // THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_PRINCIPAL_H_

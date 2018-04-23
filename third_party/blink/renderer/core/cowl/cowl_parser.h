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

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_PARSER_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_PARSER_H_

#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/cowl/cowl_principal.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class Label;
class Privilege;

class CORE_EXPORT COWLParser {

 public:
   static COWLPrincipalType ValidatePrincipal(const String&);
   static Label* ParseLabelExpression(const String& principal, const String& self_url);
   static void ParseLabeledDataHeader(const String& expr, const String& self_url, Label*& out_conf, Label*& out_int);
   static void ParseLabeledContextHeader(const String& expr, const String& self_url, Label*& out_conf, Label*& out_int, Privilege*& out_priv);
};

}  // namespace blink

#endif // THIRD_PARTY_BLINK_RENDERER_CORE_COWL_COWL_PARSER_H_

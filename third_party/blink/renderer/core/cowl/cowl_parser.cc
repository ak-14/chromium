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

#include "third_party/blink/renderer/core/cowl/cowl_parser.h"

#include "third_party/blink/renderer/core/cowl/label.h"
#include "third_party/blink/renderer/core/cowl/privilege.h"
#include "third_party/blink/renderer/platform/uuid.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/parsing_utilities.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

static bool IsAllowedScheme(String scheme) {
  return (EqualIgnoringASCIICase("https", scheme) || EqualIgnoringASCIICase("http", scheme));
}

// unique-principal-expression = "unique:" UUID
static bool IsUniquePrincipal(String principal) {
  return (principal.StartsWithIgnoringCase("unique:") && IsValidUUID(principal.Substring(7)));
}

// app-principal-expression = "app:" 1*( ALPHA / DIGIT / "-" )
static bool IsAppPrincipal(String principal) {
  if (principal.StartsWithIgnoringCase("app:")) {
    String app = principal.Substring(4);
    Vector<UChar> characters;
    app.AppendTo(characters);

    const UChar *start = characters.data();
    const UChar *end = start + characters.size();

    if (start == end)
      return false;

    SkipWhile<UChar, IsHostCharacter>(start, end);

    if (start == end)
      return true;
  }
  return false;
}

// origin-principal-expression = "'self'" / host-source
static bool IsOriginPrincipal(String principal) {
  if (principal == "'self'")
    return true;

  KURL kurl = KURL(NullURL(), principal);
  String origin = SecurityOrigin::Create(kurl)->ToString();
  if (kurl.IsValid() && IsAllowedScheme(kurl.Protocol()) && EqualIgnoringASCIICase(origin, principal))
    return true;

  return false;
}

// principal-expression = origin-principal-expression 
//                      / app-principal-expression 
//                      / unique-principal-expression
COWLPrincipalType COWLParser::ValidatePrincipal(const String& principal) {
  if (IsUniquePrincipal(principal))
    return COWLPrincipalType::kUniquePrincipal;

  if (IsAppPrincipal(principal))
    return COWLPrincipalType::kAppPrincipal;

  if (IsOriginPrincipal(principal))
    return COWLPrincipalType::kOriginPrincipal;

  return COWLPrincipalType::kInvalidPrincipal;
}


// label-expression = empty-label / and-expression / or-expression / principal-expression
// and-expression   = *WSP "(" or-expression *WSP ")" *( 1*WSP "AND" WSP and-expression )
// or-expression    = *WSP principal-expression *( 1*WSP "OR" WSP or-expression ) 
// empty-label      = "'none'"
Label* COWLParser::ParseLabelExpression(const String& expression, const String& self_url) {
  Label* label = Label::Create();

  String label_expr = expression.SimplifyWhiteSpace();

  if (label_expr == "'none'")
    return label;

  Vector<String> and_tokens;
  label_expr.Split("AND", and_tokens);

  for (unsigned i = 0; i < and_tokens.size(); ++i) {
    String and_expr = and_tokens[i].SimplifyWhiteSpace();

    if (and_tokens.size() > 1) {

      if (!and_expr.StartsWith('(') || !and_expr.EndsWith(')'))
        return nullptr;

      and_expr.Remove(0, 1);
      and_expr.Remove(and_expr.length() - 1, 1);
    }

    Label* or_expr = nullptr;

    Vector<String> or_tokens;
    and_expr.Split("OR", or_tokens);

    for (unsigned i = 0; i < or_tokens.size(); ++i) {
      String principal = or_tokens[i].SimplifyWhiteSpace();

      if (principal == "'self'")
        principal = self_url;

      if (!or_expr)
        or_expr = Label::Create(principal);
      else
        or_expr = or_expr->or_(principal);

      if (!or_expr)
        return nullptr;
    }
    label = label->and_(or_expr);
  }
  return label;
}

// data-metadata       = data-directive *( ";" [ data-directive ] )
// data-directive      = *WSP data-directive-name 1*WSP label-expression
// data-directive-name = "data-confidentiality" / "data-integrity"
void COWLParser::ParseLabeledDataHeader(const String& expr, const String& self_url, Label*& out_conf, Label*& out_int) {
  Label* confidentiality = nullptr;
  Label* integrity = nullptr;

  Vector<String> tokens;
  expr.Split(';', tokens);
  for (unsigned i = 0; i < tokens.size(); ++i) {
    String tok = tokens[i].SimplifyWhiteSpace();

    size_t space_index = tok.find(' ');
    if (space_index == kNotFound)
      break;

    String directive_name = tok.Substring(0, space_index);
    String directive_value = tok.Substring(space_index);

    Label* label = COWLParser::ParseLabelExpression(directive_value, self_url);

    if (directive_name == "data-confidentiality" && !confidentiality) {
      confidentiality = label;
    } else if (directive_name == "data-integrity" && !integrity) {
      integrity = label;
    } else {
      break;
    }
  }
  out_conf = confidentiality;
  out_int = integrity;
}

// ctx-metadata       = ctx-directive *( ";" [ ctx-directive ] )
// ctx-directive      = *WSP ctx-directive-name 1*WSP label-expression
// ctx-directive-name = "ctx-confidentiality" / "ctx-integrity" / "ctx-privilege"
void COWLParser::ParseLabeledContextHeader(const String& expr, const String& self_url, Label*& out_conf, Label*& out_int, Privilege*& out_priv) {
  Label* confidentiality = nullptr;
  Label* integrity = nullptr;
  Privilege* privilege = nullptr;

  Vector<String> tokens;
  expr.Split(';', tokens);

  for (unsigned i = 0; i < tokens.size(); ++i) {
    String tok = tokens[i].SimplifyWhiteSpace();

    size_t space_index = tok.find(' ');
    if (space_index == kNotFound)
      break;

    String directive_name = tok.Substring(0, space_index);
    String directive_value = tok.Substring(space_index);

    Label* label = COWLParser::ParseLabelExpression(directive_value, self_url);
    if (!label)
      break;

    if (directive_name == "ctx-confidentiality" && !confidentiality) {
      confidentiality = label;
    } else if (directive_name == "ctx-integrity" && !integrity) {
      integrity = label;
    } else if (directive_name == "ctx-privilege" && !privilege && label) {
      privilege = Privilege::Create(label);
    } else {
      break;
    }
  }
  out_conf = confidentiality;
  out_int = integrity;
  out_priv = privilege;
}

}  // namespace blink

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
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/googletest/src/googletest/include/gtest/gtest.h"

namespace blink {

TEST(COWLParserTest, ValidatePrincipal) {
  String principal;
  struct TestCase {
    String principal;
    COWLPrincipalType expected;
  } cases[] = {
    // Valid unique principals
    {"unique:a0281e1f-8412-4068-a7ed-e3f234d7fd5a", COWLPrincipalType::kUniquePrincipal},

    // Invalid unique principals
    {"unique:123213-invalid", COWLPrincipalType::kInvalidPrincipal},
    {"unique:", COWLPrincipalType::kInvalidPrincipal},

    // Valid app principals
    {"app:user1", COWLPrincipalType::kAppPrincipal},

    // Invalid app principals
    {"app:user1.", COWLPrincipalType::kInvalidPrincipal},
    {"app:", COWLPrincipalType::kInvalidPrincipal},

    // Valid origin principals
    {"'self'", COWLPrincipalType::kOriginPrincipal},
    {"https://a.com", COWLPrincipalType::kOriginPrincipal},
    {"https://a.com:1234", COWLPrincipalType::kOriginPrincipal},
    {"https://a", COWLPrincipalType::kOriginPrincipal},
    {"HTTPS://A.COM", COWLPrincipalType::kOriginPrincipal},
    {"http://a.com", COWLPrincipalType::kOriginPrincipal},

    // Invalid origins principals
    {"https:a.com", COWLPrincipalType::kInvalidPrincipal},
    {"https//a.com", COWLPrincipalType::kInvalidPrincipal},
    {"https:/a.com", COWLPrincipalType::kInvalidPrincipal},
    {"https://a.com/", COWLPrincipalType::kInvalidPrincipal},
    {"a.com", COWLPrincipalType::kInvalidPrincipal},
    {"ftp://a.com", COWLPrincipalType::kInvalidPrincipal},
  };
  for (const auto& test : cases) {
    EXPECT_EQ(test.expected, COWLParser::ValidatePrincipal(test.principal))
      << "COWLParser::ValidatePrincipal fail to parse: " << test.principal;
  }
}

TEST(COWLParserTest, ParseLabelExpression) {
  String expr, url, expected;
  Label *label;

  url = "https://a.com";

  // Valid expressions
  expr = "  'none'  ";
  expected = "'none'";
  label = COWLParser::ParseLabelExpression(expr, url);
  ASSERT_TRUE(label);
  EXPECT_EQ(label->toString(), expected);

  expr = " https://b.com  ";
  expected = "https://b.com";
  label = COWLParser::ParseLabelExpression(expr, url);
  ASSERT_TRUE(label);
  EXPECT_EQ(label->toString(), expected);

  expr = " 'self' OR https://b.com  ";
  expected = "https://a.com OR https://b.com";
  label = COWLParser::ParseLabelExpression(expr, url);
  ASSERT_TRUE(label);
  EXPECT_EQ(label->toString(), expected);

  expr = "  (  https://b.com   OR   app:user1  )   AND   (  'self'   OR   unique:a0281e1f-8412-4068-a7ed-e3f234d7fd5a  )  ";
  expected = "(app:user1 OR https://b.com) AND (https://a.com OR unique:a0281e1f-8412-4068-a7ed-e3f234d7fd5a)";
  label = COWLParser::ParseLabelExpression(expr, url);
  ASSERT_TRUE(label);
  EXPECT_EQ(label->toString(), expected);

  // Invalid: missing parentheses
  expr = " 'self' OR https://b.com  AND   https://c.com";
  expected = "";
  label = COWLParser::ParseLabelExpression(expr, url);
  ASSERT_FALSE(label);

  // Invalid: one principal is not valid
  expr = "  (  https://b.edu   OR   app:user1  )   AND   (  'self'   OR   unique:a0281e1f-invalid  )  ";
  expected = "";
  label = COWLParser::ParseLabelExpression(expr, url);
  ASSERT_FALSE(label);
}

TEST(COWLParserTest, ParseLabeledDataHeader) {
  String expr, url, expected;
  Label *conf, *integrity;

  expr = "data-confidentiality ('self') AND (https://b.com);"
         "data-integrity 'self'";
  url = "https://a.com";
  expected = "(https://a.com) AND (https://b.com)";
  conf = integrity = nullptr;
  COWLParser::ParseLabeledDataHeader(expr, url, conf, integrity);
  ASSERT_TRUE(conf);
  ASSERT_TRUE(integrity);
  EXPECT_EQ(conf->toString(), expected);
  EXPECT_EQ(integrity->toString(), "https://a.com");

  expr = "data-confidentiality app:user1;"
         "data-integrity b.com";
  url = "https://a.com";
  expected = "";
  conf = integrity = nullptr;
  COWLParser::ParseLabeledDataHeader(expr, url, conf, integrity);
  ASSERT_TRUE(conf);
  ASSERT_FALSE(integrity);
  EXPECT_EQ(conf->toString(), "app:user1");
}

TEST(COWLParserTest, ParseLabeledContextHeader) {
  String expr, url, expected;
  Label *conf, *integrity;
  Privilege *priv;

  expr = "ctx-confidentiality 'none';"
         "ctx-integrity 'self';"
         "ctx-privilege (https://university.edu OR app:user1) AND (unique:a0281e1f-8412-4068-a7ed-e3f234d7fd5a)";
  url = "https://a.com";
  expected = "(app:user1 OR https://university.edu) AND (unique:a0281e1f-8412-4068-a7ed-e3f234d7fd5a)";
  conf = integrity = nullptr;
  priv = nullptr;
  COWLParser::ParseLabeledContextHeader(expr, url, conf, integrity, priv);
  ASSERT_TRUE(conf);
  ASSERT_TRUE(integrity);
  ASSERT_TRUE(priv);
  EXPECT_EQ(conf->toString(), "'none'");
  EXPECT_EQ(integrity->toString(), "https://a.com");
  EXPECT_EQ(priv->asLabel()->toString(), expected);
}

}  // namespace blink

// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/frame/use_counter.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"

namespace blink {

typedef struct {
  const char* input;
  const int a;
  const int b;
} ANPlusBTestCase;

TEST(CSSSelectorParserTest, ValidANPlusB) {
  ANPlusBTestCase test_cases[] = {
      {"odd", 2, 1},
      {"OdD", 2, 1},
      {"even", 2, 0},
      {"EveN", 2, 0},
      {"0", 0, 0},
      {"8", 0, 8},
      {"+12", 0, 12},
      {"-14", 0, -14},

      {"0n", 0, 0},
      {"16N", 16, 0},
      {"-19n", -19, 0},
      {"+23n", 23, 0},
      {"n", 1, 0},
      {"N", 1, 0},
      {"+n", 1, 0},
      {"-n", -1, 0},
      {"-N", -1, 0},

      {"6n-3", 6, -3},
      {"-26N-33", -26, -33},
      {"n-18", 1, -18},
      {"+N-5", 1, -5},
      {"-n-7", -1, -7},

      {"0n+0", 0, 0},
      {"10n+5", 10, 5},
      {"10N +5", 10, 5},
      {"10n -5", 10, -5},
      {"N+6", 1, 6},
      {"n +6", 1, 6},
      {"+n -7", 1, -7},
      {"-N -8", -1, -8},
      {"-n+9", -1, 9},

      {"33N- 22", 33, -22},
      {"+n- 25", 1, -25},
      {"N- 46", 1, -46},
      {"n- 0", 1, 0},
      {"-N- 951", -1, -951},
      {"-n- 951", -1, -951},

      {"29N + 77", 29, 77},
      {"29n - 77", 29, -77},
      {"+n + 61", 1, 61},
      {"+N - 63", 1, -63},
      {"+n/**/- 48", 1, -48},
      {"-n + 81", -1, 81},
      {"-N - 88", -1, -88},

      {"3091970736n + 1", std::numeric_limits<int>::max(), 1},
      {"-3091970736n + 1", std::numeric_limits<int>::min(), 1},
      // B is calculated as +ve first, then negated.
      {"N- 3091970736", 1, -std::numeric_limits<int>::max()},
      {"N+ 3091970736", 1, std::numeric_limits<int>::max()},
  };

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case.input);

    std::pair<int, int> ab;
    CSSTokenizer tokenizer(test_case.input);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    bool passed = CSSSelectorParser::ConsumeANPlusB(range, ab);
    EXPECT_TRUE(passed);
    EXPECT_EQ(test_case.a, ab.first);
    EXPECT_EQ(test_case.b, ab.second);
  }
}

TEST(CSSSelectorParserTest, InvalidANPlusB) {
  // Some of these have token range prefixes which are valid <an+b> and could
  // in theory be valid in consumeANPlusB, but this behaviour isn't needed
  // anywhere and not implemented.
  const char* test_cases[] = {
      " odd",     "+ n",     "3m+4",  "12n--34",  "12n- -34",
      "12n- +34", "23n-+43", "10n 5", "10n + +5", "10n + -5",
  };

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case);

    std::pair<int, int> ab;
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    bool passed = CSSSelectorParser::ConsumeANPlusB(range, ab);
    EXPECT_FALSE(passed);
  }
}

TEST(CSSSelectorParserTest, ShadowDomPseudoInCompound) {
  const char* test_cases[][2] = {{"::content", "::content"},
                                 {".a::content", ".a::content"},
                                 {"::content.a", "::content.a"},
                                 {"::content.a.b", "::content.a.b"},
                                 {".a::content.b", ".a::content.b"},
                                 {"::content:not(#id)", "::content:not(#id)"}};

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case[0]);
    CSSTokenizer tokenizer(test_case[0]);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kHTMLStandardMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_STREQ(test_case[1], list.SelectorsText().Ascii().data());
  }
}

TEST(CSSSelectorParserTest, PseudoElementsInCompoundLists) {
  const char* test_cases[] = {":not(::before)",
                              ":not(::content)",
                              ":host(::before)",
                              ":host(::content)",
                              ":host-context(::before)",
                              ":host-context(::content)",
                              ":-webkit-any(::after, ::before)",
                              ":-webkit-any(::content, span)"};

  for (auto test_case : test_cases) {
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kHTMLStandardMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_FALSE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, ValidSimpleAfterPseudoElementInCompound) {
  const char* test_cases[] = {"::-webkit-volume-slider:hover",
                              "::selection:window-inactive",
                              "::-webkit-scrollbar:disabled",
                              "::-webkit-volume-slider:not(:hover)",
                              "::-webkit-scrollbar:not(:horizontal)",
                              "::slotted(span)::before",
                              "::slotted(div)::after"};

  for (auto test_case : test_cases) {
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kHTMLStandardMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_TRUE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, InvalidSimpleAfterPseudoElementInCompound) {
  const char* test_cases[] = {
      "::before#id",
      "::after:hover",
      ".class::content::before",
      "::shadow.class",
      "::selection:window-inactive::before",
      "::-webkit-volume-slider.class",
      "::before:not(.a)",
      "::shadow:not(::after)",
      "::-webkit-scrollbar:vertical:not(:first-child)",
      "video::-webkit-media-text-track-region-container.scrolling",
      "div ::before.a",
      "::slotted(div):hover",
      "::slotted(div)::slotted(span)",
      "::slotted(div)::before:hover",
      "::slotted(div)::before::slotted(span)",
      "::slotted(*)::first-letter",
      "::slotted(.class)::first-line",
      "::slotted([attr])::-webkit-scrollbar"};

  for (auto test_case : test_cases) {
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kHTMLStandardMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_FALSE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, WorkaroundForInvalidCustomPseudoInUAStyle) {
  // See crbug.com/578131
  const char* test_cases[] = {
      "video::-webkit-media-text-track-region-container.scrolling",
      "input[type=\"range\" i]::-webkit-media-slider-container > div"};

  for (auto test_case : test_cases) {
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kUASheetMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_TRUE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, ValidPseudoElementInNonRightmostCompound) {
  const char* test_cases[] = {"::content *", "::content div::before"};

  for (auto test_case : test_cases) {
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kHTMLStandardMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_TRUE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, InvalidPseudoElementInNonRightmostCompound) {
  const char* test_cases[] = {"::-webkit-volume-slider *", "::before *",
                              "::-webkit-scrollbar *", "::cue *",
                              "::selection *"};

  for (auto test_case : test_cases) {
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kHTMLStandardMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_FALSE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, UnresolvedNamespacePrefix) {
  const char* test_cases[] = {"ns|div", "div ns|div", "div ns|div "};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  for (auto test_case : test_cases) {
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_FALSE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, SerializedUniversal) {
  const char* test_cases[][2] = {
      {"*::-webkit-volume-slider", "::-webkit-volume-slider"},
      {"*::cue(i)", "::cue(i)"},
      {"*:host-context(.x)", "*:host-context(.x)"},
      {"*:host", "*:host"},
      {"|*::-webkit-volume-slider", "|*::-webkit-volume-slider"},
      {"|*::cue(i)", "|*::cue(i)"},
      {"*|*::-webkit-volume-slider", "::-webkit-volume-slider"},
      {"*|*::cue(i)", "::cue(i)"},
      {"ns|*::-webkit-volume-slider", "ns|*::-webkit-volume-slider"},
      {"ns|*::cue(i)", "ns|*::cue(i)"}};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);
  sheet->ParserAddNamespace("ns", "http://ns.org");

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case[0]);
    CSSTokenizer tokenizer(test_case[0]);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_TRUE(list.IsValid());
    EXPECT_STREQ(test_case[1], list.SelectorsText().Ascii().data());
  }
}

TEST(CSSSelectorParserTest, InvalidDescendantCombinatorInLiveProfile) {
  const char* test_cases[] = {"div >>>> span", "div >>> span", "div >> span"};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kInsecureContext,
      CSSParserContext::kLiveProfile);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_FALSE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, InvalidDescendantCombinatorInSnapshotProfile) {
  const char* test_cases[] = {"div >>>> span", "div >> span", "div >> > span",
                              "div > >> span", "div > > > span"};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kInsecureContext,
      CSSParserContext::kSnapshotProfile);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_FALSE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, ShadowPiercingCombinatorInSnapshotProfile) {
  const char* test_cases[][2] = {{"div >>> span", "div >>> span"},
                                 {"div >>/**/> span", "div >>> span"},
                                 {"div >/**/>> span", "div >>> span"},
                                 {"div >/**/>/**/> span", "div >>> span"}};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kInsecureContext,
      CSSParserContext::kSnapshotProfile);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case[0]);
    CSSTokenizer tokenizer(test_case[0]);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_TRUE(list.IsValid());
    EXPECT_STREQ(test_case[1], list.SelectorsText().Ascii().data());
  }
}

TEST(CSSSelectorParserTest, AttributeSelectorUniversalInvalid) {
  const char* test_cases[] = {"[*]", "[*|*]"};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_FALSE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, InternalPseudo) {
  const char* test_cases[] = {"::-internal-whatever",
                              "::-internal-media-controls-text-track-list",
                              ":-internal-list-box",
                              ":-internal-shadow-host-has-appearance",
                              ":-internal-spatial-navigation-focus",
                              ":-internal-video-persistent",
                              ":-internal-video-persistent-ancestor"};
  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);

    CSSSelectorList author_list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kHTMLStandardMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_FALSE(author_list.IsValid());

    CSSSelectorList ua_list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kUASheetMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_TRUE(ua_list.IsValid());
  }
}

TEST(CSSSelectorParserTest, InvalidNestingPseudoMatches) {
  // :matches() is currently not supported within these pseudo classes as they
  // currently do not support complex selector arguments (:matches() does
  // support this and the expansion of :matches() may provide complex selector
  // arguments to these pseudo classes). Most of these test cases should
  // eventually be removed once they support complex selector arguments.
  const char* test_cases[] = {":-webkit-any(:matches(.a))",
                              "::cue(:matches(.a))",
                              ":cue(:matches(.a))",
                              ":host(:matches(.a))",
                              ":host-context(:matches(.a))",
                              ":lang(:matches(.a))",
                              ":not(:matches(.a))",
                              ":nth-child(:matches(.a))",
                              ":nth-last-child(:matches(.a))",
                              ":nth-last-of-type(:matches(.a))",
                              ":nth-of-type(:matches(.a))",
                              "::slotted(:matches(.a))"};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_FALSE(list.IsValid());
  }
}

TEST(CSSSelectorParserTest, InvalidPseudoMatchesArguments) {
  // Pseudo-elements are not valid within :matches() as per the spec:
  // https://drafts.csswg.org/selectors-4/#matches
  const char* test_cases[] = {":matches(::-webkit-progress-bar)",
                              ":matches(::-webkit-progress-value)",
                              ":matches(::-webkit-slider-runnable-track)",
                              ":matches(::-webkit-slider-thumb)",
                              ":matches(::after)",
                              ":matches(::backdrop)",
                              ":matches(::before)",
                              ":matches(::cue)",
                              ":matches(::first-letter)",
                              ":matches(::first-line)",
                              ":matches(::grammar-error)",
                              ":matches(::marker)",
                              ":matches(::placeholder)",
                              ":matches(::selection)",
                              ":matches(::slotted)",
                              ":matches(::spelling-error)",
                              ":matches(:after)",
                              ":matches(:before)",
                              ":matches(:cue)",
                              ":matches(:first-letter)",
                              ":matches(:first-line)"};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_FALSE(list.IsValid());
  }
}

namespace {

const auto TagLocalName = [](const CSSSelector* selector) {
  return selector->TagQName().LocalName();
};

const auto AttributeLocalName = [](const CSSSelector* selector) {
  return selector->Attribute().LocalName();
};

const auto SelectorValue = [](const CSSSelector* selector) {
  return selector->Value();
};

struct ASCIILowerTestCase {
  const char* input;
  const char16_t* expected;
  std::function<AtomicString(const CSSSelector*)> getter;
};

}  // namespace

TEST(CSSSelectorParserTest, ASCIILowerHTMLStrict) {
  const ASCIILowerTestCase test_cases[] = {
      {"\\212a bd", u"\u212abd", TagLocalName},
      {"[\\212alass]", u"\u212alass", AttributeLocalName},
      {".\\212alass", u"\u212alass", SelectorValue},
      {"#\\212alass", u"\u212alass", SelectorValue}};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case.input);
    CSSTokenizer tokenizer(test_case.input);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_TRUE(list.IsValid());
    const CSSSelector* selector = list.First();
    ASSERT_TRUE(selector);
    EXPECT_EQ(AtomicString(test_case.expected), test_case.getter(selector));
  }
}

TEST(CSSSelectorParserTest, ASCIILowerHTMLQuirks) {
  const ASCIILowerTestCase test_cases[] = {
      {"\\212a bd", u"\u212abd", TagLocalName},
      {"[\\212alass]", u"\u212alass", AttributeLocalName},
      {".\\212aLASS", u"\u212alass", SelectorValue},
      {"#\\212aLASS", u"\u212alass", SelectorValue}};

  CSSParserContext* context = CSSParserContext::Create(
      kHTMLQuirksMode, SecureContextMode::kInsecureContext);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case.input);
    CSSTokenizer tokenizer(test_case.input);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list =
        CSSSelectorParser::ParseSelector(range, context, sheet);
    EXPECT_TRUE(list.IsValid());
    const CSSSelector* selector = list.First();
    ASSERT_TRUE(selector);
    EXPECT_EQ(AtomicString(test_case.expected), test_case.getter(selector));
  }
}

TEST(CSSSelectorParserTest, ShadowPartPseudoElementValid) {
  const char* test_cases[] = {"::part(ident)",
                              "host::part(ident)",
                              "host::part(ident):hover"};

  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case);
    CSSTokenizer tokenizer(test_case);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorList list = CSSSelectorParser::ParseSelector(
        range,
        CSSParserContext::Create(kHTMLStandardMode,
                                 SecureContextMode::kInsecureContext),
        nullptr);
    EXPECT_STREQ(test_case, list.SelectorsText().Ascii().data());
  }
}

TEST(CSSSelectorParserTest, UseCountShadowPseudo) {
  std::unique_ptr<DummyPageHolder> dummy_holder =
      DummyPageHolder::Create(IntSize(500, 500));
  Document* doc = &dummy_holder->GetDocument();
  CSSParserContext* context = CSSParserContext::Create(
      kHTMLStandardMode, SecureContextMode::kSecureContext,
      CSSParserContext::kLiveProfile, doc);
  StyleSheetContents* sheet = StyleSheetContents::Create(context);

  auto ExpectCount = [doc, context, sheet](const char* selector,
                                           WebFeature feature) {
    EXPECT_FALSE(UseCounter::IsCounted(*doc, feature));

    CSSTokenizer tokenizer(selector);
    const auto tokens = tokenizer.TokenizeToEOF();
    CSSParserTokenRange range(tokens);
    CSSSelectorParser::ParseSelector(range, context, sheet);

    EXPECT_TRUE(UseCounter::IsCounted(*doc, feature));
  };

  ExpectCount("::cue", WebFeature::kCSSSelectorCue);
  ExpectCount("::-internal-media-controls-overlay-cast-button",
              WebFeature::kCSSSelectorInternalMediaControlsOverlayCastButton);
  ExpectCount("::-webkit-calendar-picker-indicator",
              WebFeature::kCSSSelectorWebkitCalendarPickerIndicator);
  ExpectCount("::-webkit-clear-button",
              WebFeature::kCSSSelectorWebkitClearButton);
  ExpectCount("::-webkit-color-swatch",
              WebFeature::kCSSSelectorWebkitColorSwatch);
  ExpectCount("::-webkit-color-swatch-wrapper",
              WebFeature::kCSSSelectorWebkitColorSwatchWrapper);
  ExpectCount("::-webkit-date-and-time-value",
              WebFeature::kCSSSelectorWebkitDateAndTimeValue);
  ExpectCount("::-webkit-datetime-edit",
              WebFeature::kCSSSelectorWebkitDatetimeEdit);
  ExpectCount("::-webkit-datetime-edit-ampm-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditAmpmField);
  ExpectCount("::-webkit-datetime-edit-day-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditDayField);
  ExpectCount("::-webkit-datetime-edit-fields-wrapper",
              WebFeature::kCSSSelectorWebkitDatetimeEditFieldsWrapper);
  ExpectCount("::-webkit-datetime-edit-hour-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditHourField);
  ExpectCount("::-webkit-datetime-edit-millisecond-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditMillisecondField);
  ExpectCount("::-webkit-datetime-edit-minute-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditMinuteField);
  ExpectCount("::-webkit-datetime-edit-month-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditMonthField);
  ExpectCount("::-webkit-datetime-edit-second-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditSecondField);
  ExpectCount("::-webkit-datetime-edit-text",
              WebFeature::kCSSSelectorWebkitDatetimeEditText);
  ExpectCount("::-webkit-datetime-edit-week-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditWeekField);
  ExpectCount("::-webkit-datetime-edit-year-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditYearField);
  ExpectCount("::-webkit-details-marker",
              WebFeature::kCSSSelectorWebkitDetailsMarker);
  ExpectCount("::-webkit-file-upload-button",
              WebFeature::kCSSSelectorWebkitFileUploadButton);
  ExpectCount("::-webkit-inner-spin-button",
              WebFeature::kCSSSelectorWebkitInnerSpinButton);
  ExpectCount("::-webkit-input-placeholder",
              WebFeature::kCSSSelectorWebkitInputPlaceholder);
  ExpectCount("::-webkit-media-controls",
              WebFeature::kCSSSelectorWebkitMediaControls);
  ExpectCount("::-webkit-media-controls-current-time-display",
              WebFeature::kCSSSelectorWebkitMediaControlsCurrentTimeDisplay);
  ExpectCount("::-webkit-media-controls-enclosure",
              WebFeature::kCSSSelectorWebkitMediaControlsEnclosure);
  ExpectCount("::-webkit-media-controls-fullscreen-button",
              WebFeature::kCSSSelectorWebkitMediaControlsFullscreenButton);
  ExpectCount("::-webkit-media-controls-mute-button",
              WebFeature::kCSSSelectorWebkitMediaControlsMuteButton);
  ExpectCount("::-webkit-media-controls-overlay-enclosure",
              WebFeature::kCSSSelectorWebkitMediaControlsOverlayEnclosure);
  ExpectCount("::-webkit-media-controls-overlay-play-button",
              WebFeature::kCSSSelectorWebkitMediaControlsOverlayPlayButton);
  ExpectCount("::-webkit-media-controls-panel",
              WebFeature::kCSSSelectorWebkitMediaControlsPanel);
  ExpectCount("::-webkit-media-controls-play-button",
              WebFeature::kCSSSelectorWebkitMediaControlsPlayButton);
  ExpectCount("::-webkit-media-controls-timeline",
              WebFeature::kCSSSelectorWebkitMediaControlsTimeline);
  ExpectCount("::-webkit-media-controls-timeline-container",
              WebFeature::kCSSSelectorWebkitMediaControlsTimelineContainer);
  ExpectCount("::-webkit-media-controls-time-remaining-display",
              WebFeature::kCSSSelectorWebkitMediaControlsTimeRemainingDisplay);
  ExpectCount(
      "::-webkit-media-controls-toggle-closed-captions-button",
      WebFeature::kCSSSelectorWebkitMediaControlsToggleClosedCaptionsButton);
  ExpectCount("::-webkit-media-controls-volume-slider",
              WebFeature::kCSSSelectorWebkitMediaControlsVolumeSlider);
  ExpectCount("::-webkit-media-slider-container",
              WebFeature::kCSSSelectorWebkitMediaSliderContainer);
  ExpectCount("::-webkit-media-slider-thumb",
              WebFeature::kCSSSelectorWebkitMediaSliderThumb);
  ExpectCount("::-webkit-media-text-track-container",
              WebFeature::kCSSSelectorWebkitMediaTextTrackContainer);
  ExpectCount("::-webkit-media-text-track-display",
              WebFeature::kCSSSelectorWebkitMediaTextTrackDisplay);
  ExpectCount("::-webkit-media-text-track-region",
              WebFeature::kCSSSelectorWebkitMediaTextTrackRegion);
  ExpectCount("::-webkit-media-text-track-region-container",
              WebFeature::kCSSSelectorWebkitMediaTextTrackRegionContainer);
  ExpectCount("::-webkit-meter-bar", WebFeature::kCSSSelectorWebkitMeterBar);
  ExpectCount("::-webkit-meter-even-less-good-value",
              WebFeature::kCSSSelectorWebkitMeterEvenLessGoodValue);
  ExpectCount("::-webkit-meter-inner-element",
              WebFeature::kCSSSelectorWebkitMeterInnerElement);
  ExpectCount("::-webkit-meter-optimum-value",
              WebFeature::kCSSSelectorWebkitMeterOptimumValue);
  ExpectCount("::-webkit-meter-suboptimum-value",
              WebFeature::kCSSSelectorWebkitMeterSuboptimumValue);
  ExpectCount("::-webkit-progress-bar",
              WebFeature::kCSSSelectorWebkitProgressBar);
  ExpectCount("::-webkit-progress-inner-element",
              WebFeature::kCSSSelectorWebkitProgressInnerElement);
  ExpectCount("::-webkit-progress-value",
              WebFeature::kCSSSelectorWebkitProgressValue);
  ExpectCount("::-webkit-search-cancel-button",
              WebFeature::kCSSSelectorWebkitSearchCancelButton);
  ExpectCount("::-webkit-slider-container",
              WebFeature::kCSSSelectorWebkitSliderContainer);
  ExpectCount("::-webkit-slider-runnable-track",
              WebFeature::kCSSSelectorWebkitSliderRunnableTrack);
  ExpectCount("::-webkit-slider-thumb",
              WebFeature::kCSSSelectorWebkitSliderThumb);
  ExpectCount("::-webkit-textfield-decoration-container",
              WebFeature::kCSSSelectorWebkitTextfieldDecorationContainer);
  ExpectCount("::-webkit-unrecognized",
              WebFeature::kCSSSelectorWebkitUnknownPseudo);
}

}  // namespace blink

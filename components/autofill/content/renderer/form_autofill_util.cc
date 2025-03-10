// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/autofill/content/renderer/form_autofill_util.h"

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "base/command_line.h"
#include "base/i18n/case_conversion.h"
#include "base/logging.h"
#include "base/no_destructor.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "components/autofill/core/common/autofill_data_validation.h"
#include "components/autofill/core/common/autofill_features.h"
#include "components/autofill/core/common/autofill_regexes.h"
#include "components/autofill/core/common/autofill_switches.h"
#include "components/autofill/core/common/autofill_util.h"
#include "components/autofill/core/common/form_data.h"
#include "components/autofill/core/common/form_field_data.h"
#include "third_party/blink/public/platform/url_conversion.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_element_collection.h"
#include "third_party/blink/public/web/web_form_control_element.h"
#include "third_party/blink/public/web/web_form_element.h"
#include "third_party/blink/public/web/web_input_element.h"
#include "third_party/blink/public/web/web_label_element.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_option_element.h"
#include "third_party/blink/public/web/web_select_element.h"

using autofill::FormFieldData;
using blink::WebDocument;
using blink::WebElement;
using blink::WebElementCollection;
using blink::WebFormControlElement;
using blink::WebFormElement;
using blink::WebInputElement;
using blink::WebLabelElement;
using blink::WebLocalFrame;
using blink::WebNode;
using blink::WebOptionElement;
using blink::WebSelectElement;
using blink::WebString;
using blink::WebVector;

namespace autofill {
namespace form_util {

const size_t kMaxParseableFields = 200;

namespace {

// A bit field mask for FillForm functions to not fill some fields.
enum FieldFilterMask {
  FILTER_NONE                      = 0,
  FILTER_DISABLED_ELEMENTS         = 1 << 0,
  FILTER_READONLY_ELEMENTS         = 1 << 1,
  // Filters non-focusable elements with the exception of select elements, which
  // are sometimes made non-focusable because they are present for accessibility
  // while a prettier, non-<select> dropdown is shown. We still want to autofill
  // the non-focusable <select>.
  FILTER_NON_FOCUSABLE_ELEMENTS    = 1 << 2,
  FILTER_ALL_NON_EDITABLE_ELEMENTS = FILTER_DISABLED_ELEMENTS |
                                     FILTER_READONLY_ELEMENTS |
                                     FILTER_NON_FOCUSABLE_ELEMENTS,
};

// If true, operations causing layout computation should be avoided. Set by
// ScopedLayoutPreventer.
bool g_prevent_layout = false;

void TruncateString(base::string16* str, size_t max_length) {
  if (str->length() > max_length)
    str->resize(max_length);
}

bool IsOptionElement(const WebElement& element) {
  CR_DEFINE_STATIC_LOCAL(WebString, kOption, ("option"));
  return element.HasHTMLTagName(kOption);
}

bool IsScriptElement(const WebElement& element) {
  CR_DEFINE_STATIC_LOCAL(WebString, kScript, ("script"));
  return element.HasHTMLTagName(kScript);
}

bool IsNoScriptElement(const WebElement& element) {
  CR_DEFINE_STATIC_LOCAL(WebString, kNoScript, ("noscript"));
  return element.HasHTMLTagName(kNoScript);
}

bool HasTagName(const WebNode& node, const blink::WebString& tag) {
  return node.IsElementNode() && node.ToConst<WebElement>().HasHTMLTagName(tag);
}

bool IsElementInControlElementSet(
    const WebElement& element,
    const std::vector<WebFormControlElement>& control_elements) {
  if (!element.IsFormControlElement())
    return false;
  const WebFormControlElement form_control_element =
      element.ToConst<WebFormControlElement>();
  return base::ContainsValue(control_elements, form_control_element);
}

bool IsElementInsideFormOrFieldSet(const WebElement& element) {
  for (WebNode parent_node = element.ParentNode(); !parent_node.IsNull();
       parent_node = parent_node.ParentNode()) {
    if (!parent_node.IsElementNode())
      continue;

    WebElement cur_element = parent_node.To<WebElement>();
    if (cur_element.HasHTMLTagName("form") ||
        cur_element.HasHTMLTagName("fieldset")) {
      return true;
    }
  }
  return false;
}

// Returns true if |node| is an element and it is a container type that
// InferLabelForElement() can traverse.
bool IsTraversableContainerElement(const WebNode& node) {
  if (!node.IsElementNode())
    return false;

  const WebElement element = node.ToConst<WebElement>();
  return element.HasHTMLTagName("dd") || element.HasHTMLTagName("div") ||
         element.HasHTMLTagName("fieldset") || element.HasHTMLTagName("li") ||
         element.HasHTMLTagName("td") || element.HasHTMLTagName("table");
}

// Returns the colspan for a <td> / <th>. Defaults to 1.
size_t CalculateTableCellColumnSpan(const WebElement& element) {
  DCHECK(element.HasHTMLTagName("td") || element.HasHTMLTagName("th"));

  size_t span = 1;
  if (element.HasAttribute("colspan")) {
    base::string16 colspan = element.GetAttribute("colspan").Utf16();
    // Do not check return value to accept imperfect conversions.
    base::StringToSizeT(colspan, &span);
    // Handle overflow.
    if (span == std::numeric_limits<size_t>::max())
      span = 1;
    span = std::max(span, static_cast<size_t>(1));
  }

  return span;
}

// Appends |suffix| to |prefix| so that any intermediary whitespace is collapsed
// to a single space.  If |force_whitespace| is true, then the resulting string
// is guaranteed to have a space between |prefix| and |suffix|.  Otherwise, the
// result includes a space only if |prefix| has trailing whitespace or |suffix|
// has leading whitespace.
// A few examples:
//  * CombineAndCollapseWhitespace("foo", "bar", false)       -> "foobar"
//  * CombineAndCollapseWhitespace("foo", "bar", true)        -> "foo bar"
//  * CombineAndCollapseWhitespace("foo ", "bar", false)      -> "foo bar"
//  * CombineAndCollapseWhitespace("foo", " bar", false)      -> "foo bar"
//  * CombineAndCollapseWhitespace("foo", " bar", true)       -> "foo bar"
//  * CombineAndCollapseWhitespace("foo   ", "   bar", false) -> "foo bar"
//  * CombineAndCollapseWhitespace(" foo", "bar ", false)     -> " foobar "
//  * CombineAndCollapseWhitespace(" foo", "bar ", true)      -> " foo bar "
const base::string16 CombineAndCollapseWhitespace(
    const base::string16& prefix,
    const base::string16& suffix,
    bool force_whitespace) {
  base::string16 prefix_trimmed;
  base::TrimPositions prefix_trailing_whitespace =
      base::TrimWhitespace(prefix, base::TRIM_TRAILING, &prefix_trimmed);

  // Recursively compute the children's text.
  base::string16 suffix_trimmed;
  base::TrimPositions suffix_leading_whitespace =
      base::TrimWhitespace(suffix, base::TRIM_LEADING, &suffix_trimmed);

  if (prefix_trailing_whitespace || suffix_leading_whitespace ||
      force_whitespace) {
    return prefix_trimmed + base::ASCIIToUTF16(" ") + suffix_trimmed;
  }
  return prefix_trimmed + suffix_trimmed;
}

// This is a helper function for the FindChildText() function (see below).
// Search depth is limited with the |depth| parameter.
// |divs_to_skip| is a list of <div> tags to ignore if encountered.
base::string16 FindChildTextInner(const WebNode& node,
                                  int depth,
                                  const std::set<WebNode>& divs_to_skip) {
  if (depth <= 0 || node.IsNull())
    return base::string16();

  // Skip over comments.
  if (node.IsCommentNode())
    return FindChildTextInner(node.NextSibling(), depth - 1, divs_to_skip);

  if (!node.IsElementNode() && !node.IsTextNode())
    return base::string16();

  // Ignore elements known not to contain inferable labels.
  if (node.IsElementNode()) {
    const WebElement element = node.ToConst<WebElement>();
    if (IsOptionElement(element) || IsScriptElement(element) ||
        IsNoScriptElement(element) ||
        (element.IsFormControlElement() &&
         IsAutofillableElement(element.ToConst<WebFormControlElement>()))) {
      return base::string16();
    }

    if (element.HasHTMLTagName("div") && base::ContainsKey(divs_to_skip, node))
      return base::string16();
  }

  // Extract the text exactly at this node.
  base::string16 node_text = node.NodeValue().Utf16();

  // Recursively compute the children's text.
  // Preserve inter-element whitespace separation.
  base::string16 child_text =
      FindChildTextInner(node.FirstChild(), depth - 1, divs_to_skip);
  bool add_space = node.IsTextNode() && node_text.empty();
  node_text = CombineAndCollapseWhitespace(node_text, child_text, add_space);

  // Recursively compute the siblings' text.
  // Again, preserve inter-element whitespace separation.
  base::string16 sibling_text =
      FindChildTextInner(node.NextSibling(), depth - 1, divs_to_skip);
  add_space = node.IsTextNode() && node_text.empty();
  node_text = CombineAndCollapseWhitespace(node_text, sibling_text, add_space);

  return node_text;
}

// Same as FindChildText() below, but with a list of div nodes to skip.
// TODO(thestig): See if other FindChildText() callers can benefit from this.
base::string16 FindChildTextWithIgnoreList(
    const WebNode& node,
    const std::set<WebNode>& divs_to_skip) {
  if (node.IsTextNode())
    return node.NodeValue().Utf16();

  WebNode child = node.FirstChild();

  const int kChildSearchDepth = 10;
  base::string16 node_text =
      FindChildTextInner(child, kChildSearchDepth, divs_to_skip);
  base::TrimWhitespace(node_text, base::TRIM_ALL, &node_text);
  return node_text;
}

bool IsLabelValid(base::StringPiece16 inferred_label,
                  const std::vector<base::char16>& stop_words) {
  // If |inferred_label| has any character other than those in |stop_words|.
  auto* first_non_stop_word =
      std::find_if(inferred_label.begin(), inferred_label.end(),
                   [&stop_words](base::char16 c) {
                     return !base::ContainsValue(stop_words, c);
                   });
  return first_non_stop_word != inferred_label.end();
}

// Shared function for InferLabelFromPrevious() and InferLabelFromNext().
bool InferLabelFromSibling(const WebFormControlElement& element,
                           const std::vector<base::char16>& stop_words,
                           bool forward,
                           base::string16* label,
                           FormFieldData::LabelSource* label_source) {
  base::string16 inferred_label;
  FormFieldData::LabelSource inferred_label_source =
      FormFieldData::LabelSource::UNKNOWN;
  WebNode sibling = element;
  while (true) {
    sibling = forward ? sibling.NextSibling() : sibling.PreviousSibling();
    if (sibling.IsNull())
      break;

    // Skip over comments.
    if (sibling.IsCommentNode())
      continue;

    // Otherwise, only consider normal HTML elements and their contents.
    if (!sibling.IsElementNode() && !sibling.IsTextNode())
      break;

    // A label might be split across multiple "lightweight" nodes.
    // Coalesce any text contained in multiple consecutive
    //  (a) plain text nodes or
    //  (b) inline HTML elements that are essentially equivalent to text nodes.
    CR_DEFINE_STATIC_LOCAL(WebString, kBold, ("b"));
    CR_DEFINE_STATIC_LOCAL(WebString, kStrong, ("strong"));
    CR_DEFINE_STATIC_LOCAL(WebString, kSpan, ("span"));
    CR_DEFINE_STATIC_LOCAL(WebString, kFont, ("font"));
    if (sibling.IsTextNode() || HasTagName(sibling, kBold) ||
        HasTagName(sibling, kStrong) || HasTagName(sibling, kSpan) ||
        HasTagName(sibling, kFont)) {
      base::string16 value = FindChildText(sibling);
      // A text node's value will be empty if it is for a line break.
      bool add_space = sibling.IsTextNode() && value.empty();
      inferred_label_source = FormFieldData::LabelSource::COMBINED;
      inferred_label =
          CombineAndCollapseWhitespace(value, inferred_label, add_space);
      continue;
    }

    // If we have identified a partial label and have reached a non-lightweight
    // element, consider the label to be complete.
    base::string16 trimmed_label;
    base::TrimWhitespace(inferred_label, base::TRIM_ALL, &trimmed_label);
    if (!trimmed_label.empty()) {
      inferred_label_source = FormFieldData::LabelSource::COMBINED;
      break;
    }

    // <img> and <br> tags often appear between the input element and its
    // label text, so skip over them.
    CR_DEFINE_STATIC_LOCAL(WebString, kImage, ("img"));
    CR_DEFINE_STATIC_LOCAL(WebString, kBreak, ("br"));
    if (HasTagName(sibling, kImage) || HasTagName(sibling, kBreak))
      continue;

    // We only expect <p> and <label> tags to contain the full label text.
    CR_DEFINE_STATIC_LOCAL(WebString, kPage, ("p"));
    CR_DEFINE_STATIC_LOCAL(WebString, kLabel, ("label"));
    bool has_label_tag = HasTagName(sibling, kLabel);
    if (HasTagName(sibling, kPage) || has_label_tag) {
      inferred_label = FindChildText(sibling);
      inferred_label_source = has_label_tag
                                  ? FormFieldData::LabelSource::LABEL_TAG
                                  : FormFieldData::LabelSource::P_TAG;
    }

    break;
  }

  base::TrimWhitespace(inferred_label, base::TRIM_ALL, &inferred_label);
  if (IsLabelValid(inferred_label, stop_words)) {
    *label = std::move(inferred_label);
    *label_source = inferred_label_source;
    return true;
  }
  return false;
}

// Helper for |InferLabelForElement()| that infers a label, if possible, from
// a previous sibling of |element|,
// e.g. Some Text <input ...>
// or   Some <span>Text</span> <input ...>
// or   <p>Some Text</p><input ...>
// or   <label>Some Text</label> <input ...>
// or   Some Text <img><input ...>
// or   <b>Some Text</b><br/> <input ...>.
bool InferLabelFromPrevious(const WebFormControlElement& element,
                            const std::vector<base::char16>& stop_words,
                            base::string16* label,
                            FormFieldData::LabelSource* label_source) {
  return InferLabelFromSibling(element, stop_words, false /* forward? */, label,
                               label_source);
}

// Same as InferLabelFromPrevious(), but in the other direction.
// Useful for cases like: <span><input type="checkbox">Label For Checkbox</span>
bool InferLabelFromNext(const WebFormControlElement& element,
                        const std::vector<base::char16>& stop_words,
                        base::string16* label,
                        FormFieldData::LabelSource* label_source) {
  return InferLabelFromSibling(element, stop_words, true /* forward? */, label,
                               label_source);
}

// Helper for |InferLabelForElement()| that infers a label, if possible, from
// the placeholder text. e.g. <input placeholder="foo">
base::string16 InferLabelFromPlaceholder(const WebFormControlElement& element) {
  CR_DEFINE_STATIC_LOCAL(WebString, kPlaceholder, ("placeholder"));
  if (element.HasAttribute(kPlaceholder))
    return element.GetAttribute(kPlaceholder).Utf16();

  return base::string16();
}

// Helper for |InferLabelForElement()| that infers a label, if possible, from
// the aria-label. e.g. <input aria-label="foo">
base::string16 InferLabelFromAriaLabel(const WebFormControlElement& element) {
  static const base::NoDestructor<WebString> kAriaLabel("aria-label");
  if (element.HasAttribute(*kAriaLabel))
    return element.GetAttribute(*kAriaLabel).Utf16();

  return base::string16();
}

// Helper for |InferLabelForElement()| that infers a label, from
// the value attribute when it is present and user has not typed in (if
// element's value attribute is same as the element's value).
base::string16 InferLabelFromValueAttr(const WebFormControlElement& element) {
  CR_DEFINE_STATIC_LOCAL(WebString, kValue, ("value"));
  if (element.HasAttribute(kValue) &&
      element.GetAttribute(kValue) == element.Value()) {
    return element.GetAttribute(kValue).Utf16();
  }

  return base::string16();
}

// Helper for |InferLabelForElement()| that infers a label, if possible, from
// enclosing list item,
// e.g. <li>Some Text<input ...><input ...><input ...></li>
base::string16 InferLabelFromListItem(const WebFormControlElement& element) {
  WebNode parent = element.ParentNode();
  CR_DEFINE_STATIC_LOCAL(WebString, kListItem, ("li"));
  while (!parent.IsNull() && parent.IsElementNode() &&
         !parent.To<WebElement>().HasHTMLTagName(kListItem)) {
    parent = parent.ParentNode();
  }

  if (!parent.IsNull() && HasTagName(parent, kListItem))
    return FindChildText(parent);

  return base::string16();
}

// Helper for |InferLabelForElement()| that infers a label, if possible, from
// enclosing label,
// e.g. <label>Some Text<input ...><input ...><input ...></label>
base::string16 InferLabelFromEnclosingLabel(
    const WebFormControlElement& element) {
  WebNode parent = element.ParentNode();
  CR_DEFINE_STATIC_LOCAL(WebString, kLabel, ("label"));
  while (!parent.IsNull() && parent.IsElementNode() &&
         !parent.To<WebElement>().HasHTMLTagName(kLabel)) {
    parent = parent.ParentNode();
  }

  if (!parent.IsNull() && HasTagName(parent, kLabel))
    return FindChildText(parent);

  return base::string16();
}

// Helper for |InferLabelForElement()| that infers a label, if possible, from
// surrounding table structure,
// e.g. <tr><td>Some Text</td><td><input ...></td></tr>
// or   <tr><th>Some Text</th><td><input ...></td></tr>
// or   <tr><td><b>Some Text</b></td><td><b><input ...></b></td></tr>
// or   <tr><th><b>Some Text</b></th><td><b><input ...></b></td></tr>
base::string16 InferLabelFromTableColumn(const WebFormControlElement& element) {
  CR_DEFINE_STATIC_LOCAL(WebString, kTableCell, ("td"));
  WebNode parent = element.ParentNode();
  while (!parent.IsNull() && parent.IsElementNode() &&
         !parent.To<WebElement>().HasHTMLTagName(kTableCell)) {
    parent = parent.ParentNode();
  }

  if (parent.IsNull())
    return base::string16();

  // Check all previous siblings, skipping non-element nodes, until we find a
  // non-empty text block.
  base::string16 inferred_label;
  WebNode previous = parent.PreviousSibling();
  CR_DEFINE_STATIC_LOCAL(WebString, kTableHeader, ("th"));
  while (inferred_label.empty() && !previous.IsNull()) {
    if (HasTagName(previous, kTableCell) || HasTagName(previous, kTableHeader))
      inferred_label = FindChildText(previous);

    previous = previous.PreviousSibling();
  }

  return inferred_label;
}

// Helper for |InferLabelForElement()| that infers a label, if possible, from
// surrounding table structure,
//
// If there are multiple cells and the row with the input matches up with the
// previous row, then look for a specific cell within the previous row.
// e.g. <tr><td>Input 1 label</td><td>Input 2 label</td></tr>
//      <tr><td><input name="input 1"></td><td><input name="input2"></td></tr>
//
// Otherwise, just look in the entire previous row.
// e.g. <tr><td>Some Text</td></tr><tr><td><input ...></td></tr>
base::string16 InferLabelFromTableRow(const WebFormControlElement& element) {
  CR_DEFINE_STATIC_LOCAL(WebString, kTableCell, ("td"));
  base::string16 inferred_label;

  // First find the <td> that contains |element|.
  WebNode cell = element.ParentNode();
  while (!cell.IsNull()) {
    if (cell.IsElementNode() &&
        cell.To<WebElement>().HasHTMLTagName(kTableCell)) {
      break;
    }
    cell = cell.ParentNode();
  }

  // Not in a cell - bail out.
  if (cell.IsNull())
    return inferred_label;

  // Count the cell holding |element|.
  size_t cell_count = CalculateTableCellColumnSpan(cell.To<WebElement>());
  size_t cell_position = 0;
  size_t cell_position_end = cell_count - 1;

  // Count cells to the left to figure out |element|'s cell's position.
  for (WebNode cell_it = cell.PreviousSibling(); !cell_it.IsNull();
       cell_it = cell_it.PreviousSibling()) {
    if (cell_it.IsElementNode() &&
        cell_it.To<WebElement>().HasHTMLTagName(kTableCell)) {
      cell_position += CalculateTableCellColumnSpan(cell_it.To<WebElement>());
    }
  }

  // Count cells to the right.
  for (WebNode cell_it = cell.NextSibling(); !cell_it.IsNull();
       cell_it = cell_it.NextSibling()) {
    if (cell_it.IsElementNode() &&
        cell_it.To<WebElement>().HasHTMLTagName(kTableCell)) {
      cell_count += CalculateTableCellColumnSpan(cell_it.To<WebElement>());
    }
  }

  // Combine left + right.
  cell_count += cell_position;
  cell_position_end += cell_position;

  // Find the current row.
  CR_DEFINE_STATIC_LOCAL(WebString, kTableRow, ("tr"));
  WebNode parent = element.ParentNode();
  while (!parent.IsNull() && parent.IsElementNode() &&
         !parent.To<WebElement>().HasHTMLTagName(kTableRow)) {
    parent = parent.ParentNode();
  }

  if (parent.IsNull())
    return inferred_label;

  // Now find the previous row.
  WebNode row_it = parent.PreviousSibling();
  while (!row_it.IsNull()) {
    if (row_it.IsElementNode() &&
        row_it.To<WebElement>().HasHTMLTagName(kTableRow)) {
      break;
    }
    row_it = row_it.PreviousSibling();
  }

  // If there exists a previous row, check its cells and size. If they align
  // with the current row, infer the label from the cell above.
  if (!row_it.IsNull()) {
    WebNode matching_cell;
    size_t prev_row_count = 0;
    WebNode prev_row_it = row_it.FirstChild();
    CR_DEFINE_STATIC_LOCAL(WebString, kTableHeader, ("th"));
    while (!prev_row_it.IsNull()) {
      if (prev_row_it.IsElementNode()) {
        WebElement prev_row_element = prev_row_it.To<WebElement>();
        if (prev_row_element.HasHTMLTagName(kTableCell) ||
            prev_row_element.HasHTMLTagName(kTableHeader)) {
          size_t span = CalculateTableCellColumnSpan(prev_row_element);
          size_t prev_row_count_end = prev_row_count + span - 1;
          if (prev_row_count == cell_position &&
              prev_row_count_end == cell_position_end) {
            matching_cell = prev_row_it;
          }
          prev_row_count += span;
        }
      }
      prev_row_it = prev_row_it.NextSibling();
    }
    if ((cell_count == prev_row_count) && !matching_cell.IsNull()) {
      inferred_label = FindChildText(matching_cell);
      if (!inferred_label.empty())
        return inferred_label;
    }
  }

  // If there is no previous row, or if the previous row and current row do not
  // align, check all previous siblings, skipping non-element nodes, until we
  // find a non-empty text block.
  WebNode previous = parent.PreviousSibling();
  while (inferred_label.empty() && !previous.IsNull()) {
    if (HasTagName(previous, kTableRow))
      inferred_label = FindChildText(previous);

    previous = previous.PreviousSibling();
  }

  return inferred_label;
}

// Helper for |InferLabelForElement()| that infers a label, if possible, from
// a surrounding div table,
// e.g. <div>Some Text<span><input ...></span></div>
// e.g. <div>Some Text</div><div><input ...></div>
//
// Because this is already traversing the <div> structure, if it finds a <label>
// sibling along the way, infer from that <label>.
base::string16 InferLabelFromDivTable(const WebFormControlElement& element) {
  WebNode node = element.ParentNode();
  bool looking_for_parent = true;
  std::set<WebNode> divs_to_skip;

  // Search the sibling and parent <div>s until we find a candidate label.
  base::string16 inferred_label;
  CR_DEFINE_STATIC_LOCAL(WebString, kDiv, ("div"));
  CR_DEFINE_STATIC_LOCAL(WebString, kLabel, ("label"));
  while (inferred_label.empty() && !node.IsNull()) {
    if (HasTagName(node, kDiv)) {
      if (looking_for_parent)
        inferred_label = FindChildTextWithIgnoreList(node, divs_to_skip);
      else
        inferred_label = FindChildText(node);

      // Avoid sibling DIVs that contain autofillable fields.
      if (!looking_for_parent && !inferred_label.empty()) {
        CR_DEFINE_STATIC_LOCAL(WebString, kSelector,
                               ("input, select, textarea"));
        WebElement result_element = node.QuerySelector(kSelector);
        if (!result_element.IsNull()) {
          inferred_label.clear();
          divs_to_skip.insert(node);
        }
      }

      looking_for_parent = false;
    } else if (!looking_for_parent && HasTagName(node, kLabel)) {
      WebLabelElement label_element = node.To<WebLabelElement>();
      if (label_element.CorrespondingControl().IsNull())
        inferred_label = FindChildText(node);
    } else if (looking_for_parent && IsTraversableContainerElement(node)) {
      // If the element is in a non-div container, its label most likely is too.
      break;
    }

    if (node.PreviousSibling().IsNull()) {
      // If there are no more siblings, continue walking up the tree.
      looking_for_parent = true;
    }

    node = looking_for_parent ? node.ParentNode() : node.PreviousSibling();
  }

  return inferred_label;
}

// Helper for |InferLabelForElement()| that infers a label, if possible, from
// a surrounding definition list,
// e.g. <dl><dt>Some Text</dt><dd><input ...></dd></dl>
// e.g. <dl><dt><b>Some Text</b></dt><dd><b><input ...></b></dd></dl>
base::string16 InferLabelFromDefinitionList(
    const WebFormControlElement& element) {
  CR_DEFINE_STATIC_LOCAL(WebString, kDefinitionData, ("dd"));
  WebNode parent = element.ParentNode();
  while (!parent.IsNull() && parent.IsElementNode() &&
         !parent.To<WebElement>().HasHTMLTagName(kDefinitionData))
    parent = parent.ParentNode();

  if (parent.IsNull() || !HasTagName(parent, kDefinitionData))
    return base::string16();

  // Skip by any intervening text nodes.
  WebNode previous = parent.PreviousSibling();
  while (!previous.IsNull() && previous.IsTextNode())
    previous = previous.PreviousSibling();

  CR_DEFINE_STATIC_LOCAL(WebString, kDefinitionTag, ("dt"));
  if (previous.IsNull() || !HasTagName(previous, kDefinitionTag))
    return base::string16();

  return FindChildText(previous);
}

// Returns the element type for all ancestor nodes in CAPS, starting with the
// parent node.
std::vector<std::string> AncestorTagNames(
    const WebFormControlElement& element) {
  std::vector<std::string> tag_names;
  for (WebNode parent_node = element.ParentNode(); !parent_node.IsNull();
       parent_node = parent_node.ParentNode()) {
    if (!parent_node.IsElementNode())
      continue;

    tag_names.push_back(parent_node.To<WebElement>().TagName().Utf8());
  }
  return tag_names;
}

// Infers corresponding label for |element| from surrounding context in the DOM,
// e.g. the contents of the preceding <p> tag or text element.
bool InferLabelForElement(const WebFormControlElement& element,
                          const std::vector<base::char16>& stop_words,
                          base::string16* label,
                          FormFieldData::LabelSource* label_source) {
  if (IsCheckableElement(ToWebInputElement(&element))) {
    if (InferLabelFromNext(element, stop_words, label, label_source))
      return true;
  }

  if (InferLabelFromPrevious(element, stop_words, label, label_source))
    return true;

  // If we didn't find a label, check for placeholder text.
  base::string16 inferred_label = InferLabelFromPlaceholder(element);
  if (IsLabelValid(inferred_label, stop_words)) {
    *label_source = FormFieldData::LabelSource::PLACE_HOLDER;
    *label = std::move(inferred_label);
    return true;
  }

  // If we didn't find a placeholder, check for aria-label text.
  inferred_label = InferLabelFromAriaLabel(element);
  if (IsLabelValid(inferred_label, stop_words)) {
    *label_source = FormFieldData::LabelSource::ARIA_LABEL;
    *label = std::move(inferred_label);
    return true;
  }

  // For all other searches that involve traversing up the tree, the search
  // order is based on which tag is the closest ancestor to |element|.
  std::vector<std::string> tag_names = AncestorTagNames(element);
  std::set<std::string> seen_tag_names;
  FormFieldData::LabelSource ancestor_label_source =
      FormFieldData::LabelSource::UNKNOWN;
  for (const std::string& tag_name : tag_names) {
    if (base::ContainsKey(seen_tag_names, tag_name))
      continue;

    seen_tag_names.insert(tag_name);
    if (tag_name == "LABEL") {
      ancestor_label_source = FormFieldData::LabelSource::LABEL_TAG;
      inferred_label = InferLabelFromEnclosingLabel(element);
    } else if (tag_name == "DIV") {
      ancestor_label_source = FormFieldData::LabelSource::DIV_TABLE;
      inferred_label = InferLabelFromDivTable(element);
    } else if (tag_name == "TD") {
      ancestor_label_source = FormFieldData::LabelSource::TD_TAG;
      inferred_label = InferLabelFromTableColumn(element);
      if (!IsLabelValid(inferred_label, stop_words))
        inferred_label = InferLabelFromTableRow(element);
    } else if (tag_name == "DD") {
      ancestor_label_source = FormFieldData::LabelSource::DD_TAG;
      inferred_label = InferLabelFromDefinitionList(element);
    } else if (tag_name == "LI") {
      ancestor_label_source = FormFieldData::LabelSource::LI_TAG;
      inferred_label = InferLabelFromListItem(element);
    } else if (tag_name == "FIELDSET") {
      break;
    }

    if (IsLabelValid(inferred_label, stop_words)) {
      *label_source = ancestor_label_source;
      *label = std::move(inferred_label);
      return true;
    }
  }

  // If we didn't find a label, check the value attr used as the placeholder.
  inferred_label = InferLabelFromValueAttr(element);
  if (IsLabelValid(inferred_label, stop_words)) {
    *label_source = FormFieldData::LabelSource::VALUE;
    *label = std::move(inferred_label);
    return true;
  }
  return false;
}

// Fills |option_strings| with the values of the <option> elements present in
// |select_element|.
void GetOptionStringsFromElement(const WebSelectElement& select_element,
                                 std::vector<base::string16>* option_values,
                                 std::vector<base::string16>* option_contents) {
  DCHECK(!select_element.IsNull());

  option_values->clear();
  option_contents->clear();
  WebVector<WebElement> list_items = select_element.GetListItems();

  // Constrain the maximum list length to prevent a malicious site from DOS'ing
  // the browser, without entirely breaking autocomplete for some extreme
  // legitimate sites: http://crbug.com/49332 and http://crbug.com/363094
  if (list_items.size() > kMaxListSize)
    return;

  option_values->reserve(list_items.size());
  option_contents->reserve(list_items.size());
  for (size_t i = 0; i < list_items.size(); ++i) {
    if (IsOptionElement(list_items[i])) {
      const WebOptionElement option = list_items[i].ToConst<WebOptionElement>();
      option_values->push_back(option.Value().Utf16());
      option_contents->push_back(option.GetText().Utf16());
    }
  }
}

// The callback type used by |ForEachMatchingFormField()|.
typedef void (*Callback)(const FormFieldData&,
                         bool, /* is_initiating_element */
                         blink::WebFormControlElement*);

void ForEachMatchingFormFieldCommon(
    std::vector<WebFormControlElement>* control_elements,
    const WebElement& initiating_element,
    const FormData& data,
    FieldFilterMask filters,
    bool force_override,
    const Callback& callback) {
  DCHECK(control_elements);
  if (control_elements->size() != data.fields.size()) {
    // This case should be reachable only for pathological websites and tests,
    // which add or remove form fields while the user is interacting with the
    // Autofill popup.
    return;
  }

  // It's possible that the site has injected fields into the form after the
  // page has loaded, so we can't assert that the size of the cached control
  // elements is equal to the size of the fields in |form|.  Fortunately, the
  // one case in the wild where this happens, paypal.com signup form, the fields
  // are appended to the end of the form and are not visible.
  for (size_t i = 0; i < control_elements->size(); ++i) {
    WebFormControlElement* element = &(*control_elements)[i];
    bool is_initiating_element = (*element == initiating_element);

    // Only autofill empty fields (or those with the field's default value
    // attribute) and the field that initiated the filling, i.e. the field the
    // user is currently editing and interacting with.
    const WebInputElement* input_element = ToWebInputElement(element);
    CR_DEFINE_STATIC_LOCAL(WebString, kValue, ("value"));
    CR_DEFINE_STATIC_LOCAL(WebString, kPlaceholder, ("placeholder"));

    if (!force_override && !is_initiating_element &&
        // A text field, with a non-empty value that is NOT the value of the
        // input field's "value" or "placeholder" attribute, is skipped.
        // Some sites fill the fields with formatting string. To tell the
        // difference between the values entered by the user and the site, we'll
        // sanitize the value. If the sanitized value is empty, it means that
        // the site has filled the field, in this case, the field is not
        // skipped.
        (IsAutofillableInputElement(input_element) ||
         IsTextAreaElement(*element)) &&
        !SanitizedFieldIsEmpty(element->Value().Utf16()) &&
        (!element->HasAttribute(kValue) ||
         element->GetAttribute(kValue) != element->Value()) &&
        (!element->HasAttribute(kPlaceholder) ||
         base::i18n::ToLower(element->GetAttribute(kPlaceholder).Utf16()) !=
             base::i18n::ToLower(element->Value().Utf16())))
      continue;

    DCHECK(!g_prevent_layout || !(filters & FILTER_NON_FOCUSABLE_ELEMENTS))
        << "The callsite of this code wanted to both prevent layout and check "
           "isFocusable. Pick one.";
    if (((filters & FILTER_DISABLED_ELEMENTS) && !element->IsEnabled()) ||
        ((filters & FILTER_READONLY_ELEMENTS) && element->IsReadOnly()) ||
        // See description for FILTER_NON_FOCUSABLE_ELEMENTS.
        ((filters & FILTER_NON_FOCUSABLE_ELEMENTS) && !element->IsFocusable() &&
         !IsSelectElement(*element)))
      continue;

    callback(data.fields[i], is_initiating_element, element);
  }
}

// For each autofillable field in |data| that matches a field in the |form|,
// the |callback| is invoked with the corresponding |form| field data.
void ForEachMatchingFormField(const WebFormElement& form_element,
                              const WebElement& initiating_element,
                              const FormData& data,
                              FieldFilterMask filters,
                              bool force_override,
                              const Callback& callback) {
  std::vector<WebFormControlElement> control_elements =
      ExtractAutofillableElementsInForm(form_element);
  ForEachMatchingFormFieldCommon(&control_elements, initiating_element, data,
                                 filters, force_override, callback);
}

// For each autofillable field in |data| that matches a field in the set of
// unowned autofillable form fields, the |callback| is invoked with the
// corresponding |data| field.
void ForEachMatchingUnownedFormField(const WebElement& initiating_element,
                                     const FormData& data,
                                     FieldFilterMask filters,
                                     bool force_override,
                                     const Callback& callback) {
  if (initiating_element.IsNull())
    return;

  std::vector<WebFormControlElement> control_elements =
      GetUnownedAutofillableFormFieldElements(
          initiating_element.GetDocument().All(), nullptr);
  if (!IsElementInControlElementSet(initiating_element, control_elements))
    return;

  ForEachMatchingFormFieldCommon(&control_elements, initiating_element, data,
                                 filters, force_override, callback);
}

// Sets the |field|'s value to the value in |data|.
// Also sets the "autofilled" attribute, causing the background to be yellow.
void FillFormField(const FormFieldData& data,
                   bool is_initiating_node,
                   blink::WebFormControlElement* field) {
  // Nothing to fill.
  if (data.value.empty())
    return;

  if (!data.is_autofilled)
    return;

  WebInputElement* input_element = ToWebInputElement(field);
  if (IsCheckableElement(input_element)) {
    input_element->SetChecked(IsChecked(data.check_status), true);
  } else {
    base::string16 value = data.value;
    if (IsTextInput(input_element) || IsMonthInput(input_element)) {
      // If the maxlength attribute contains a negative value, maxLength()
      // returns the default maxlength value.
      TruncateString(&value, input_element->MaxLength());
    }
    field->SetAutofillValue(blink::WebString::FromUTF16(value));
  }
  // Setting the form might trigger JavaScript, which is capable of
  // destroying the frame.
  if (!field->GetDocument().GetFrame())
    return;

  field->SetAutofilled(true);

  if (is_initiating_node &&
      ((IsTextInput(input_element) || IsMonthInput(input_element)) ||
       IsTextAreaElement(*field))) {
    int length = field->Value().length();
    field->SetSelectionRange(length, length);
    // Clear the current IME composition (the underline), if there is one.
    field->GetDocument().GetFrame()->UnmarkText();
  }
}

// Sets the |field|'s "suggested" (non JS visible) value to the value in |data|.
// Also sets the "autofilled" attribute, causing the background to be yellow.
void PreviewFormField(const FormFieldData& data,
                      bool is_initiating_node,
                      blink::WebFormControlElement* field) {
  // Nothing to preview.
  if (data.value.empty())
    return;

  if (!data.is_autofilled)
    return;

  // Preview input, textarea and select fields. For input fields, excludes
  // checkboxes and radio buttons, as there is no provision for
  // setSuggestedCheckedValue in WebInputElement.
  WebInputElement* input_element = ToWebInputElement(field);
  if (IsTextInput(input_element) || IsMonthInput(input_element)) {
    // If the maxlength attribute contains a negative value, maxLength()
    // returns the default maxlength value.
    input_element->SetSuggestedValue(blink::WebString::FromUTF16(
        data.value.substr(0, input_element->MaxLength())));
    input_element->SetAutofilled(true);
  } else if (IsTextAreaElement(*field) || IsSelectElement(*field)) {
    field->SetSuggestedValue(blink::WebString::FromUTF16(data.value));
    field->SetAutofilled(true);
  }

  if (is_initiating_node &&
      (IsTextInput(input_element) || IsTextAreaElement(*field))) {
    // Select the part of the text that the user didn't type.
    PreviewSuggestion(field->SuggestedValue().Utf16(), field->Value().Utf16(),
                      field);
  }
}

// Extracts the fields from |control_elements| with |extract_mask| to
// |form_fields|. The extracted fields are also placed in |element_map|.
// |form_fields| and |element_map| should start out empty.
// |fields_extracted| should have as many elements as |control_elements|,
// initialized to false.
// Returns true if the number of fields extracted is within
// [1, kMaxParseableFields].
bool ExtractFieldsFromControlElements(
    const WebVector<WebFormControlElement>& control_elements,
    const FieldValueAndPropertiesMaskMap* field_value_and_properties_map,
    ExtractMask extract_mask,
    std::vector<std::unique_ptr<FormFieldData>>* form_fields,
    std::vector<bool>* fields_extracted,
    std::map<WebFormControlElement, FormFieldData*>* element_map) {
  DCHECK(form_fields->empty());
  DCHECK(element_map->empty());
  DCHECK_EQ(control_elements.size(), fields_extracted->size());

  for (size_t i = 0; i < control_elements.size(); ++i) {
    const WebFormControlElement& control_element = control_elements[i];

    if (!IsAutofillableElement(control_element))
      continue;

    // Create a new FormFieldData, fill it out and map it to the field's name.
    auto form_field = std::make_unique<FormFieldData>();
    WebFormControlElementToFormField(control_element,
                                     field_value_and_properties_map,
                                     extract_mask, form_field.get());
    (*element_map)[control_element] = form_field.get();
    form_fields->push_back(std::move(form_field));
    (*fields_extracted)[i] = true;

    // To avoid overly expensive computation, we impose a maximum number of
    // allowable fields.
    if (form_fields->size() > kMaxParseableFields)
      return false;
  }

  // Succeeded if fields were extracted.
  return !form_fields->empty();
}

// For each label element, get the corresponding form control element, use the
// form control element's name as a key into the
// <WebFormControlElement, FormFieldData> map to find the previously created
// FormFieldData and set the FormFieldData's label to the
// label.firstChild().nodeValue() of the label element.
void MatchLabelsAndFields(
    const WebElementCollection& labels,
    std::map<WebFormControlElement, FormFieldData*>* element_map) {
  CR_DEFINE_STATIC_LOCAL(WebString, kFor, ("for"));
  CR_DEFINE_STATIC_LOCAL(WebString, kHidden, ("hidden"));

  for (WebElement item = labels.FirstItem(); !item.IsNull();
       item = labels.NextItem()) {
    WebLabelElement label = item.To<WebLabelElement>();
    WebElement control = label.CorrespondingControl();
    FormFieldData* field_data = nullptr;

    if (control.IsNull()) {
      // Sometimes site authors will incorrectly specify the corresponding
      // field element's name rather than its id, so we compensate here.
      base::string16 element_name = label.GetAttribute(kFor).Utf16();
      if (element_name.empty())
        continue;
      // Look through the list for elements with this name. There can actually
      // be more than one. In this case, the label may not be particularly
      // useful, so just discard it.
      for (const auto& iter : *element_map) {
        if (iter.second->name == element_name) {
          if (field_data) {
            field_data = nullptr;
            break;
          }
          field_data = iter.second;
        }
      }
    } else if (control.IsFormControlElement()) {
      WebFormControlElement form_control = control.To<WebFormControlElement>();
      if (form_control.FormControlTypeForAutofill() == kHidden)
        continue;
      // Typical case: look up |field_data| in |element_map|.
      auto iter = element_map->find(form_control);
      if (iter == element_map->end())
        continue;
      field_data = iter->second;
    }

    if (!field_data)
      continue;

    base::string16 label_text = FindChildText(label);

    // Concatenate labels because some sites might have multiple label
    // candidates.
    if (!field_data->label.empty() && !label_text.empty())
      field_data->label += base::ASCIIToUTF16(" ");
    field_data->label += label_text;
  }
}

// Common function shared by WebFormElementToFormData() and
// UnownedFormElementsAndFieldSetsToFormData(). Either pass in:
// 1) |form_element| and an empty |fieldsets|.
// or
// 2) a NULL |form_element|.
//
// If |field| is not NULL, then |form_control_element| should be not NULL.
bool FormOrFieldsetsToFormData(
    const blink::WebFormElement* form_element,
    const blink::WebFormControlElement* form_control_element,
    const std::vector<blink::WebElement>& fieldsets,
    const WebVector<WebFormControlElement>& control_elements,
    const FieldValueAndPropertiesMaskMap* field_value_and_properties_map,
    ExtractMask extract_mask,
    FormData* form,
    FormFieldData* field) {
  CR_DEFINE_STATIC_LOCAL(WebString, kLabel, ("label"));

  if (form_element)
    DCHECK(fieldsets.empty());
  if (field)
    DCHECK(form_control_element);

  // A map from a FormFieldData's name to the FormFieldData itself.
  std::map<WebFormControlElement, FormFieldData*> element_map;

  // The extracted FormFields. We use pointers so we can store them in
  // |element_map|.
  std::vector<std::unique_ptr<FormFieldData>> form_fields;

  // A vector of bools that indicate whether each field in the form meets the
  // requirements and thus will be in the resulting |form|.
  std::vector<bool> fields_extracted(control_elements.size(), false);

  if (!ExtractFieldsFromControlElements(
          control_elements, field_value_and_properties_map, extract_mask,
          &form_fields, &fields_extracted, &element_map)) {
    return false;
  }

  if (form_element) {
    // Loop through the label elements inside the form element.  For each label
    // element, get the corresponding form control element, use the form control
    // element's name as a key into the <name, FormFieldData> map to find the
    // previously created FormFieldData and set the FormFieldData's label to the
    // label.firstChild().nodeValue() of the label element.
    WebElementCollection labels =
        form_element->GetElementsByHTMLTagName(kLabel);
    DCHECK(!labels.IsNull());
    MatchLabelsAndFields(labels, &element_map);
  } else {
    // Same as the if block, but for all the labels in fieldsets.
    for (size_t i = 0; i < fieldsets.size(); ++i) {
      WebElementCollection labels =
          fieldsets[i].GetElementsByHTMLTagName(kLabel);
      DCHECK(!labels.IsNull());
      MatchLabelsAndFields(labels, &element_map);
    }
  }

  // List of characters a label can't be entirely made of (this list can grow).
  // Since the term |stop_words| is a known text processing concept we use here
  // it to refer to such characters. They are not to be confused with words.
  std::vector<base::char16> stop_words;
  stop_words.push_back(static_cast<base::char16>(' '));
  stop_words.push_back(static_cast<base::char16>('*'));
  stop_words.push_back(static_cast<base::char16>(':'));
  stop_words.push_back(static_cast<base::char16>('-'));
  stop_words.push_back(static_cast<base::char16>(L'\u2013'));
  stop_words.push_back(static_cast<base::char16>('('));
  stop_words.push_back(static_cast<base::char16>(')'));

  // Loop through the form control elements, extracting the label text from
  // the DOM.  We use the |fields_extracted| vector to make sure we assign the
  // extracted label to the correct field, as it's possible |form_fields| will
  // not contain all of the elements in |control_elements|.
  for (size_t i = 0, field_idx = 0;
       i < control_elements.size() && field_idx < form_fields.size(); ++i) {
    // This field didn't meet the requirements, so don't try to find a label
    // for it.
    if (!fields_extracted[i])
      continue;

    const WebFormControlElement& control_element = control_elements[i];
    if (form_fields[field_idx]->label.empty()) {
      InferLabelForElement(control_element, stop_words,
                           &(form_fields[field_idx]->label),
                           &(form_fields[field_idx]->label_source));
    }
    TruncateString(&form_fields[field_idx]->label, kMaxDataLength);

    if (field && *form_control_element == control_element)
      *field = *form_fields[field_idx];

    ++field_idx;
  }

  // Copy the created FormFields into the resulting FormData object.
  for (const auto& field : form_fields)
    form->fields.push_back(*field);
  return true;
}

bool UnownedFormElementsAndFieldSetsToFormData(
    const std::vector<blink::WebElement>& fieldsets,
    const std::vector<blink::WebFormControlElement>& control_elements,
    const blink::WebFormControlElement* element,
    const blink::WebDocument& document,
    const FieldValueAndPropertiesMaskMap* field_value_and_properties_map,
    ExtractMask extract_mask,
    FormData* form,
    FormFieldData* field) {
  form->origin = GetCanonicalOriginForDocument(document);
  if (document.GetFrame() && document.GetFrame()->Top()) {
    form->main_frame_origin = document.GetFrame()->Top()->GetSecurityOrigin();
  } else {
    form->main_frame_origin = url::Origin();
    NOTREACHED();
  }

  form->is_form_tag = false;

  return FormOrFieldsetsToFormData(
      nullptr, element, fieldsets, control_elements,
      field_value_and_properties_map, extract_mask, form, field);
}

}  // namespace

ScopedLayoutPreventer::ScopedLayoutPreventer() {
  DCHECK(!g_prevent_layout) << "Is any other instance of ScopedLayoutPreventer "
                               "alive in the same process?";
  g_prevent_layout = true;
}

ScopedLayoutPreventer::~ScopedLayoutPreventer() {
  DCHECK(g_prevent_layout) << "Is any other instance of ScopedLayoutPreventer "
                              "alive in the same process?";
  g_prevent_layout = false;
}

GURL StripAuthAndParams(const GURL& gurl) {
  GURL::Replacements rep;
  rep.ClearUsername();
  rep.ClearPassword();
  rep.ClearQuery();
  rep.ClearRef();
  return gurl.ReplaceComponents(rep);
}

bool ExtractFormData(const WebFormElement& form_element, FormData* data) {
  return WebFormElementToFormData(
      form_element, WebFormControlElement(), nullptr,
      static_cast<form_util::ExtractMask>(form_util::EXTRACT_VALUE |
                                          form_util::EXTRACT_OPTION_TEXT |
                                          form_util::EXTRACT_OPTIONS),
      data, nullptr);
}

bool IsFormVisible(blink::WebLocalFrame* frame,
                   const blink::WebFormElement& form_element,
                   const GURL& canonical_action,
                   const GURL& canonical_origin,
                   const FormData& form_data) {
  const GURL frame_origin = GetCanonicalOriginForDocument(frame->GetDocument());
  blink::WebVector<WebFormElement> forms;
  frame->GetDocument().Forms(forms);

  // Omitting the action attribute would result in |canonical_origin| for
  // hierarchical schemes like http:, and in an empty URL for non-hierarchical
  // schemes like about: or data: etc.
  const bool action_is_empty = canonical_action.is_empty()
                               || canonical_action == canonical_origin;

  // Since empty or unspecified action fields are automatically set to page URL,
  // action field for forms cannot be used for comparing (all forms with
  // empty/unspecified actions have the same value). If an action field is set
  // to the page URL, this method checks ALL fields of the form instead (using
  // FormData.SameFormAs). This is also true if the action was set to the page
  // URL on purpose.
  for (const WebFormElement& form : forms) {
    if (!AreFormContentsVisible(form))
      continue;

    // Try to match the WebFormElement reference first.
    if (!form_element.IsNull() && form == form_element) {
      return true;  // Form still exists.
    }

    GURL iter_canonical_action = GetCanonicalActionForForm(form);
    bool form_action_is_empty = iter_canonical_action.is_empty() ||
                                iter_canonical_action == frame_origin;
    if (action_is_empty != form_action_is_empty)
      continue;

    if (action_is_empty) {  // Both actions are empty, compare all fields.
      FormData extracted_form_data;
      WebFormElementToFormData(form, WebFormControlElement(), nullptr,
                               EXTRACT_NONE, &extracted_form_data, nullptr);
      if (form_data.SameFormAs(extracted_form_data)) {
        return true;  // Form still exists.
      }
    } else {  // Both actions are non-empty, compare actions only.
      if (canonical_action == iter_canonical_action) {
        return true;  // Form still exists.
      }
    }
  }

  return false;
}

bool IsSomeControlElementVisible(
    const WebVector<WebFormControlElement>& control_elements) {
  for (const WebFormControlElement& control_element : control_elements) {
    if (IsWebElementVisible(control_element))
      return true;
  }
  return false;
}

bool AreFormContentsVisible(const WebFormElement& form) {
  WebVector<WebFormControlElement> control_elements;
  form.GetFormControlElements(control_elements);
  return IsSomeControlElementVisible(control_elements);
}

GURL GetCanonicalActionForForm(const WebFormElement& form) {
  WebString action = form.Action();
  if (action.IsNull())
    action = WebString("");  // missing 'action' attribute implies current URL.
  GURL full_action(form.GetDocument().CompleteURL(action));
  return StripAuthAndParams(full_action);
}

GURL GetCanonicalOriginForDocument(const WebDocument& document) {
  GURL full_origin(document.Url());
  return StripAuthAndParams(full_origin);
}

bool IsMonthInput(const WebInputElement* element) {
  CR_DEFINE_STATIC_LOCAL(WebString, kMonth, ("month"));
  return element && !element->IsNull() &&
         element->FormControlTypeForAutofill() == kMonth;
}

// All text fields, including password fields, should be extracted.
bool IsTextInput(const WebInputElement* element) {
  return element && !element->IsNull() && element->IsTextField();
}

bool IsSelectElement(const WebFormControlElement& element) {
  // Static for improved performance.
  CR_DEFINE_STATIC_LOCAL(WebString, kSelectOne, ("select-one"));
  return !element.IsNull() &&
         element.FormControlTypeForAutofill() == kSelectOne;
}

bool IsTextAreaElement(const WebFormControlElement& element) {
  // Static for improved performance.
  CR_DEFINE_STATIC_LOCAL(WebString, kTextArea, ("textarea"));
  return !element.IsNull() && element.FormControlTypeForAutofill() == kTextArea;
}

bool IsCheckableElement(const WebInputElement* element) {
  if (!element || element->IsNull())
    return false;

  return element->IsCheckbox() || element->IsRadioButton();
}

bool IsAutofillableInputElement(const WebInputElement* element) {
  return IsTextInput(element) ||
         IsMonthInput(element) ||
         IsCheckableElement(element);
}

bool IsAutofillableElement(const WebFormControlElement& element) {
  const WebInputElement* input_element = ToWebInputElement(&element);
  return IsAutofillableInputElement(input_element) ||
         IsSelectElement(element) || IsTextAreaElement(element);
}

const base::string16 GetFormIdentifier(const WebFormElement& form) {
  base::string16 identifier = form.GetName().Utf16();
  CR_DEFINE_STATIC_LOCAL(WebString, kId, ("id"));
  if (identifier.empty())
    identifier = form.GetAttribute(kId).Utf16();

  return identifier;
}

bool IsWebElementVisible(const blink::WebElement& element) {
  // hasNonEmptyLayoutSize might trigger layout, but it didn't cause problems so
  // far. If the layout is prohibited, hasNonEmptyLayoutSize is still used. See
  // details in crbug.com/595078.
  bool res = g_prevent_layout ? element.HasNonEmptyLayoutSize()
                              : element.IsFocusable();
  return res;
}

std::vector<blink::WebFormControlElement> ExtractAutofillableElementsFromSet(
    const WebVector<WebFormControlElement>& control_elements) {
  std::vector<blink::WebFormControlElement> autofillable_elements;
  for (size_t i = 0; i < control_elements.size(); ++i) {
    WebFormControlElement element = control_elements[i];
    if (!IsAutofillableElement(element))
      continue;

    autofillable_elements.push_back(element);
  }
  return autofillable_elements;
}

std::vector<WebFormControlElement> ExtractAutofillableElementsInForm(
    const WebFormElement& form_element) {
  WebVector<WebFormControlElement> control_elements;
  form_element.GetFormControlElements(control_elements);

  return ExtractAutofillableElementsFromSet(control_elements);
}

void WebFormControlElementToFormField(
    const WebFormControlElement& element,
    const FieldValueAndPropertiesMaskMap* field_value_and_properties_map,
    ExtractMask extract_mask,
    FormFieldData* field) {
  DCHECK(field);
  DCHECK(!element.IsNull());
  CR_DEFINE_STATIC_LOCAL(WebString, kAutocomplete, ("autocomplete"));
  CR_DEFINE_STATIC_LOCAL(WebString, kId, ("id"));
  CR_DEFINE_STATIC_LOCAL(WebString, kRole, ("role"));
  CR_DEFINE_STATIC_LOCAL(WebString, kPlaceholder, ("placeholder"));
  CR_DEFINE_STATIC_LOCAL(WebString, kClass, ("class"));

  // Save both id and name attributes, if present. If there is only one of them,
  // it will be saved to |name|. See HTMLFormControlElement::nameForAutofill.
  field->name = element.NameForAutofill().Utf16();
  base::string16 id = element.GetAttribute(kId).Utf16();
  if (id != field->name)
    field->id = id;

  field->form_control_type = element.FormControlTypeForAutofill().Utf8();
  field->autocomplete_attribute = element.GetAttribute(kAutocomplete).Utf8();
  if (field->autocomplete_attribute.size() > kMaxDataLength) {
    // Discard overly long attribute values to avoid DOS-ing the browser
    // process.  However, send over a default string to indicate that the
    // attribute was present.
    field->autocomplete_attribute = "x-max-data-length-exceeded";
  }
  if (base::LowerCaseEqualsASCII(element.GetAttribute(kRole).Utf16(),
                                 "presentation"))
    field->role = FormFieldData::ROLE_ATTRIBUTE_PRESENTATION;

  field->placeholder = element.GetAttribute(kPlaceholder).Utf16();
  if (element.HasAttribute(kClass))
    field->css_classes = element.GetAttribute(kClass).Utf16();

  if (field_value_and_properties_map) {
    FieldValueAndPropertiesMaskMap::const_iterator it =
        field_value_and_properties_map->find(element);
    if (it != field_value_and_properties_map->end())
      field->properties_mask = it->second.second;
  }

  if (!IsAutofillableElement(element))
    return;

  const WebInputElement* input_element = ToWebInputElement(&element);
  if (IsAutofillableInputElement(input_element) ||
      IsTextAreaElement(element) ||
      IsSelectElement(element)) {
    field->is_autofilled = element.IsAutofilled();
    if (!g_prevent_layout)
      field->is_focusable = element.IsFocusable();
    field->should_autocomplete = element.AutoComplete();

    // Use 'text-align: left|right' if set or 'direction' otherwise.
    // See crbug.com/482339
    field->text_direction = element.DirectionForFormData() == "rtl"
                                ? base::i18n::RIGHT_TO_LEFT
                                : base::i18n::LEFT_TO_RIGHT;
    if (element.AlignmentForFormData() == "left")
      field->text_direction = base::i18n::LEFT_TO_RIGHT;
    else if (element.AlignmentForFormData() == "right")
      field->text_direction = base::i18n::RIGHT_TO_LEFT;
    field->is_enabled = element.IsEnabled();
  }

  if (IsAutofillableInputElement(input_element)) {
    if (IsTextInput(input_element))
      field->max_length = input_element->MaxLength();

    SetCheckStatus(field, IsCheckableElement(input_element),
                   input_element->IsChecked());
  } else if (IsTextAreaElement(element)) {
    // Nothing more to do in this case.
  } else if (extract_mask & EXTRACT_OPTIONS) {
    // Set option strings on the field if available.
    DCHECK(IsSelectElement(element));
    const WebSelectElement select_element = element.ToConst<WebSelectElement>();
    GetOptionStringsFromElement(select_element,
                                &field->option_values,
                                &field->option_contents);
  }

  if (!(extract_mask & EXTRACT_VALUE))
    return;

  base::string16 value = element.Value().Utf16();

  if (IsSelectElement(element) && (extract_mask & EXTRACT_OPTION_TEXT)) {
    const WebSelectElement select_element = element.ToConst<WebSelectElement>();
    // Convert the |select_element| value to text if requested.
    WebVector<WebElement> list_items = select_element.GetListItems();
    for (size_t i = 0; i < list_items.size(); ++i) {
      if (IsOptionElement(list_items[i])) {
        const WebOptionElement option_element =
            list_items[i].ToConst<WebOptionElement>();
        if (option_element.Value().Utf16() == value) {
          value = option_element.GetText().Utf16();
          break;
        }
      }
    }
  }

  // Constrain the maximum data length to prevent a malicious site from DOS'ing
  // the browser: http://crbug.com/49332
  TruncateString(&value, kMaxDataLength);

  field->value = value;
}

bool WebFormElementToFormData(
    const blink::WebFormElement& form_element,
    const blink::WebFormControlElement& form_control_element,
    const FieldValueAndPropertiesMaskMap* field_value_and_properties_map,
    ExtractMask extract_mask,
    FormData* form,
    FormFieldData* field) {
  WebLocalFrame* frame = form_element.GetDocument().GetFrame();
  if (!frame)
    return false;

  form->name = GetFormIdentifier(form_element);
  form->origin = GetCanonicalOriginForDocument(frame->GetDocument());
  form->action = frame->GetDocument().CompleteURL(form_element.Action());
  if (frame->Top()) {
    form->main_frame_origin = frame->Top()->GetSecurityOrigin();
  } else {
    form->main_frame_origin = url::Origin();
    NOTREACHED();
  }
  // If the completed URL is not valid, just use the action we get from
  // WebKit.
  if (!form->action.is_valid())
    form->action = GURL(blink::WebStringToGURL(form_element.Action()));

  WebVector<WebFormControlElement> control_elements;
  form_element.GetFormControlElements(control_elements);

  std::vector<blink::WebElement> dummy_fieldset;
  return FormOrFieldsetsToFormData(
      &form_element, &form_control_element, dummy_fieldset, control_elements,
      field_value_and_properties_map, extract_mask, form, field);
}

std::vector<WebFormControlElement> GetUnownedFormFieldElements(
    const WebElementCollection& elements,
    std::vector<WebElement>* fieldsets) {
  std::vector<WebFormControlElement> unowned_fieldset_children;
  for (WebElement element = elements.FirstItem(); !element.IsNull();
       element = elements.NextItem()) {
    if (element.IsFormControlElement()) {
      WebFormControlElement control = element.To<WebFormControlElement>();
      if (control.Form().IsNull())
        unowned_fieldset_children.push_back(control);
    }

    if (fieldsets && element.HasHTMLTagName("fieldset") &&
        !IsElementInsideFormOrFieldSet(element)) {
      fieldsets->push_back(element);
    }
  }
  return unowned_fieldset_children;
}

std::vector<WebFormControlElement> GetUnownedAutofillableFormFieldElements(
    const WebElementCollection& elements,
    std::vector<WebElement>* fieldsets) {
  return ExtractAutofillableElementsFromSet(
      GetUnownedFormFieldElements(elements, fieldsets));
}

bool UnownedCheckoutFormElementsAndFieldSetsToFormData(
    const std::vector<blink::WebElement>& fieldsets,
    const std::vector<blink::WebFormControlElement>& control_elements,
    const blink::WebFormControlElement* element,
    const blink::WebDocument& document,
    ExtractMask extract_mask,
    FormData* form,
    FormFieldData* field) {
  if (!base::FeatureList::IsEnabled(
          features::kAutofillRestrictUnownedFieldsToFormlessCheckout)) {
    return UnownedFormElementsAndFieldSetsToFormData(
        fieldsets, control_elements, element, document, nullptr, extract_mask,
        form, field);
  }

  // Only attempt formless Autofill on checkout flows. This avoids the many
  // false positives found on the non-checkout web. See
  // http://crbug.com/462375.
  WebElement html_element = document.DocumentElement();

  // For now this restriction only applies to English-language pages, because
  // the keywords are not translated. Note that an empty "lang" attribute
  // counts as English.
  std::string lang;
  if (!html_element.IsNull())
    lang = html_element.GetAttribute("lang").Utf8();
  if (!lang.empty() &&
      !base::StartsWith(lang, "en", base::CompareCase::INSENSITIVE_ASCII)) {
    return UnownedFormElementsAndFieldSetsToFormData(
        fieldsets, control_elements, element, document, nullptr, extract_mask,
        form, field);
  }

  // A potential problem is that this only checks document.title(), but should
  // actually check the main frame's title. Thus it may make bad decisions for
  // iframes.
  base::string16 title(base::ToLowerASCII(document.Title().Utf16()));

  // Don't check the path for url's without a standard format path component,
  // such as data:.
  std::string path;
  GURL url(document.Url());
  if (url.IsStandard())
    path = base::ToLowerASCII(url.path());

  const char* const kKeywords[] = {
    "payment",
    "checkout",
    "address",
    "delivery",
    "shipping",
    "wallet"
  };

  for (const auto* keyword : kKeywords) {
    // Compare char16 elements of |title| with char elements of |keyword| using
    // operator==.
    auto title_pos = std::search(title.begin(), title.end(),
                                 keyword, keyword + strlen(keyword));
    if (title_pos != title.end() ||
        path.find(keyword) != std::string::npos) {
      form->is_formless_checkout = true;
      // Found a keyword: treat this as an unowned form.
      return UnownedFormElementsAndFieldSetsToFormData(
          fieldsets, control_elements, element, document, nullptr, extract_mask,
          form, field);
    }
  }

  // Since it's not a checkout flow, only add fields that have a non-"off"
  // autocomplete attribute to the formless autofill.
  CR_DEFINE_STATIC_LOCAL(WebString, kOffAttribute, ("off"));
  CR_DEFINE_STATIC_LOCAL(WebString, kFalseAttribute, ("false"));
  std::vector<WebFormControlElement> elements_with_autocomplete;
  for (const WebFormControlElement& element : control_elements) {
    blink::WebString autocomplete = element.GetAttribute("autocomplete");
    if (autocomplete.length() && autocomplete != kOffAttribute &&
        autocomplete != kFalseAttribute) {
      elements_with_autocomplete.push_back(element);
    }
  }

  if (elements_with_autocomplete.empty())
    return false;

  return UnownedFormElementsAndFieldSetsToFormData(
      fieldsets, elements_with_autocomplete, element, document, nullptr,
      extract_mask, form, field);
}

bool UnownedPasswordFormElementsAndFieldSetsToFormData(
    const std::vector<blink::WebElement>& fieldsets,
    const std::vector<blink::WebFormControlElement>& control_elements,
    const blink::WebFormControlElement* element,
    const blink::WebDocument& document,
    const FieldValueAndPropertiesMaskMap* field_value_and_properties_map,
    ExtractMask extract_mask,
    FormData* form,
    FormFieldData* field) {
  return UnownedFormElementsAndFieldSetsToFormData(
      fieldsets, control_elements, element, document,
      field_value_and_properties_map, extract_mask, form, field);
}


bool FindFormAndFieldForFormControlElement(const WebFormControlElement& element,
                                           FormData* form,
                                           FormFieldData* field) {
  DCHECK(!element.IsNull());

  if (!IsAutofillableElement(element))
    return false;

  ExtractMask extract_mask =
      static_cast<ExtractMask>(EXTRACT_VALUE | EXTRACT_OPTIONS);
  const WebFormElement form_element = element.Form();
  if (form_element.IsNull()) {
    // No associated form, try the synthetic form for unowned form elements.
    WebDocument document = element.GetDocument();
    std::vector<WebElement> fieldsets;
    std::vector<WebFormControlElement> control_elements =
        GetUnownedAutofillableFormFieldElements(document.All(), &fieldsets);
    return UnownedCheckoutFormElementsAndFieldSetsToFormData(
        fieldsets, control_elements, &element, document, extract_mask,
        form, field);
  }

  return WebFormElementToFormData(form_element, element, nullptr, extract_mask,
                                  form, field);
}

void FillForm(const FormData& form, const WebFormControlElement& element) {
  WebFormElement form_element = element.Form();
  if (form_element.IsNull()) {
    ForEachMatchingUnownedFormField(element,
                                    form,
                                    FILTER_ALL_NON_EDITABLE_ELEMENTS,
                                    false, /* dont force override */
                                    &FillFormField);
    return;
  }

  ForEachMatchingFormField(form_element,
                           element,
                           form,
                           FILTER_ALL_NON_EDITABLE_ELEMENTS,
                           false, /* dont force override */
                           &FillFormField);
}

void FillFormIncludingNonFocusableElements(const FormData& form_data,
                                           const WebFormElement& form_element) {
  if (form_element.IsNull()) {
    NOTREACHED();
    return;
  }

  FieldFilterMask filter_mask = static_cast<FieldFilterMask>(
      FILTER_DISABLED_ELEMENTS | FILTER_READONLY_ELEMENTS);
  ForEachMatchingFormField(form_element,
                           WebInputElement(),
                           form_data,
                           filter_mask,
                           true, /* force override */
                           &FillFormField);
}

void PreviewForm(const FormData& form, const WebFormControlElement& element) {
  WebFormElement form_element = element.Form();
  if (form_element.IsNull()) {
    ForEachMatchingUnownedFormField(element,
                                    form,
                                    FILTER_ALL_NON_EDITABLE_ELEMENTS,
                                    false, /* dont force override */
                                    &PreviewFormField);
    return;
  }

  ForEachMatchingFormField(form_element,
                           element,
                           form,
                           FILTER_ALL_NON_EDITABLE_ELEMENTS,
                           false, /* dont force override */
                           &PreviewFormField);
}

bool ClearPreviewedFormWithElement(const WebFormControlElement& element,
                                   bool was_autofilled) {
  WebFormElement form_element = element.Form();
  std::vector<WebFormControlElement> control_elements;
  if (form_element.IsNull()) {
    control_elements = GetUnownedAutofillableFormFieldElements(
        element.GetDocument().All(), nullptr);
    if (!IsElementInControlElementSet(element, control_elements))
      return false;
  } else {
    control_elements = ExtractAutofillableElementsInForm(form_element);
  }

  for (size_t i = 0; i < control_elements.size(); ++i) {
    // There might be unrelated elements in this form which have already been
    // auto-filled.  For example, the user might have already filled the address
    // part of a form and now be dealing with the credit card section.  We only
    // want to reset the auto-filled status for fields that were previewed.
    WebFormControlElement control_element = control_elements[i];

    // Only text input, textarea and select elements can be previewed.
    WebInputElement* input_element = ToWebInputElement(&control_element);
    if (!IsTextInput(input_element) &&
        !IsMonthInput(input_element) &&
        !IsTextAreaElement(control_element) &&
        !IsSelectElement(control_element))
      continue;

    // If the element is not auto-filled, we did not preview it,
    // so there is nothing to reset.
    if (!control_element.IsAutofilled())
      continue;

    if ((IsTextInput(input_element) || IsMonthInput(input_element) ||
         IsTextAreaElement(control_element) ||
         IsSelectElement(control_element)) &&
        control_element.SuggestedValue().IsEmpty())
      continue;

    // Clear the suggested value. For the initiating node, also restore the
    // original value.
    if (IsTextInput(input_element) || IsMonthInput(input_element) ||
        IsTextAreaElement(control_element)) {
      control_element.SetSuggestedValue(WebString());
      bool is_initiating_node = (element == control_element);
      if (is_initiating_node) {
        control_element.SetAutofilled(was_autofilled);
        // Clearing the suggested value in the focused node (above) can cause
        // selection to be lost. We force selection range to restore the text
        // cursor.
        int length = control_element.Value().length();
        control_element.SetSelectionRange(length, length);
      } else {
        control_element.SetAutofilled(false);
      }
    } else if (IsSelectElement(control_element)) {
      control_element.SetSuggestedValue(WebString());
      control_element.SetAutofilled(false);
    }
  }

  return true;
}

bool IsWebpageEmpty(const blink::WebLocalFrame* frame) {
  blink::WebDocument document = frame->GetDocument();

  return IsWebElementEmpty(document.Head()) &&
         IsWebElementEmpty(document.Body());
}

bool IsWebElementEmpty(const blink::WebElement& root) {
  CR_DEFINE_STATIC_LOCAL(WebString, kScript, ("script"));
  CR_DEFINE_STATIC_LOCAL(WebString, kMeta, ("meta"));
  CR_DEFINE_STATIC_LOCAL(WebString, kTitle, ("title"));

  if (root.IsNull())
    return true;

  for (WebNode child = root.FirstChild(); !child.IsNull();
       child = child.NextSibling()) {
    if (child.IsTextNode() && !base::ContainsOnlyChars(child.NodeValue().Utf8(),
                                                       base::kWhitespaceASCII))
      return false;

    if (!child.IsElementNode())
      continue;

    WebElement element = child.To<WebElement>();
    if (!element.HasHTMLTagName(kScript) && !element.HasHTMLTagName(kMeta) &&
        !element.HasHTMLTagName(kTitle))
      return false;
  }
  return true;
}

void PreviewSuggestion(const base::string16& suggestion,
                       const base::string16& user_input,
                       blink::WebFormControlElement* input_element) {
  size_t selection_start = user_input.length();
  if (IsFeatureSubstringMatchEnabled()) {
    size_t offset = GetTextSelectionStart(suggestion, user_input, false);
    // Zero selection start is for password manager, which can show usernames
    // that do not begin with the user input value.
    selection_start = (offset == base::string16::npos) ? 0 : offset;
  }

  input_element->SetSelectionRange(selection_start, suggestion.length());
}

base::string16 FindChildText(const WebNode& node) {
  return FindChildTextWithIgnoreList(node, std::set<WebNode>());
}

base::string16 FindChildTextWithIgnoreListForTesting(
    const WebNode& node,
    const std::set<WebNode>& divs_to_skip) {
  return FindChildTextWithIgnoreList(node, divs_to_skip);
}

bool InferLabelForElementForTesting(const WebFormControlElement& element,
                                    const std::vector<base::char16>& stop_words,
                                    base::string16* label,
                                    FormFieldData::LabelSource* label_source) {
  return InferLabelForElement(element, stop_words, label, label_source);
}

}  // namespace form_util
}  // namespace autofill

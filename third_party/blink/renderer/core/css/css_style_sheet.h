/*
 * (C) 1999-2003 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2004, 2006, 2007, 2008, 2009, 2010, 2012 Apple Inc. All rights
 * reserved.
 *
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

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_CSS_CSS_STYLE_SHEET_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_CSS_CSS_STYLE_SHEET_H_

#include "base/macros.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/css/css_rule.h"
#include "third_party/blink/renderer/core/css/media_query_evaluator.h"
#include "third_party/blink/renderer/core/css/style_sheet.h"
#include "third_party/blink/renderer/core/dom/tree_scope.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/wtf/noncopyable.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/text/text_position.h"

namespace blink {

class CSSImportRule;
class CSSRule;
class CSSRuleList;
class CSSStyleSheet;
class CSSStyleSheetInit;
class Document;
class ExceptionState;
class MediaQuerySet;
class SecurityOrigin;
class StyleSheetContents;

class CORE_EXPORT CSSStyleSheet final : public StyleSheet {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static const Document* SingleOwnerDocument(const CSSStyleSheet*);

  static CSSStyleSheet* Create(Document&, const String&, ExceptionState&);
  static CSSStyleSheet* Create(Document&,
                               const String&,
                               const CSSStyleSheetInit&,
                               ExceptionState&);

  static CSSStyleSheet* Create(StyleSheetContents*,
                               CSSImportRule* owner_rule = nullptr);
  static CSSStyleSheet* Create(StyleSheetContents*, Node& owner_node);
  static CSSStyleSheet* CreateInline(
      Node&,
      const KURL&,
      const TextPosition& start_position = TextPosition::MinimumPosition(),
      const WTF::TextEncoding& = WTF::TextEncoding());
  static CSSStyleSheet* CreateInline(
      StyleSheetContents*,
      Node& owner_node,
      const TextPosition& start_position = TextPosition::MinimumPosition());

  ~CSSStyleSheet() override;

  CSSStyleSheet* parentStyleSheet() const override;
  Node* ownerNode() const override { return owner_node_; }
  MediaList* media() override;
  String href() const override;
  String title() const override { return title_; }
  bool disabled() const override { return is_disabled_; }
  void setDisabled(bool) override;

  CSSRuleList* cssRules(ExceptionState&);
  unsigned insertRule(const String& rule, unsigned index, ExceptionState&);
  void deleteRule(unsigned index, ExceptionState&);

  // IE Extensions
  CSSRuleList* rules(ExceptionState&);
  int addRule(const String& selector,
              const String& style,
              int index,
              ExceptionState&);
  int addRule(const String& selector, const String& style, ExceptionState&);
  void removeRule(unsigned index, ExceptionState& exception_state) {
    deleteRule(index, exception_state);
  }

  // For CSSRuleList.
  unsigned length() const;
  CSSRule* item(unsigned index);

  void ClearOwnerNode() override;

  CSSRule* ownerRule() const override { return owner_rule_; }
  KURL BaseURL() const override;
  bool IsLoading() const override;

  void ClearOwnerRule() { owner_rule_ = nullptr; }
  Document* OwnerDocument() const;
  const MediaQuerySet* MediaQueries() const { return media_queries_.get(); }
  void SetMediaQueries(scoped_refptr<MediaQuerySet>);
  bool MatchesMediaQueries(const MediaQueryEvaluator&);
  bool HasMediaQueryResults() const {
    return !viewport_dependent_media_query_results_.IsEmpty() ||
           !device_dependent_media_query_results_.IsEmpty();
  }
  const MediaQueryResultList& ViewportDependentMediaQueryResults() const {
    return viewport_dependent_media_query_results_;
  }
  const MediaQueryResultList& DeviceDependentMediaQueryResults() const {
    return device_dependent_media_query_results_;
  }
  void SetTitle(const String& title) { title_ = title; }
  // Set by LinkStyle iff CORS-enabled fetch of stylesheet succeeded from this
  // origin.
  void SetAllowRuleAccessFromOrigin(
      scoped_refptr<const SecurityOrigin> allowed_origin);

  void AddedConstructedToTreeScope(TreeScope* tree_scope) {
    constructed_tree_scopes_.insert(tree_scope);
  }

  void RemovedConstructedFromTreeScope(TreeScope* tree_scope) {
    constructed_tree_scopes_.erase(tree_scope);
  }

  class RuleMutationScope {
    STACK_ALLOCATED();

   public:
    explicit RuleMutationScope(CSSStyleSheet*);
    explicit RuleMutationScope(CSSRule*);
    ~RuleMutationScope();

   private:
    Member<CSSStyleSheet> style_sheet_;
    DISALLOW_COPY_AND_ASSIGN(RuleMutationScope);
  };

  void WillMutateRules();
  void DidMutateRules();
  void DidMutate();

  class InspectorMutationScope {
    STACK_ALLOCATED();

   public:
    explicit InspectorMutationScope(CSSStyleSheet*);
    ~InspectorMutationScope();

   private:
    Member<CSSStyleSheet> style_sheet_;
    DISALLOW_COPY_AND_ASSIGN(InspectorMutationScope);
  };

  void EnableRuleAccessForInspector();
  void DisableRuleAccessForInspector();

  StyleSheetContents* Contents() const { return contents_.Get(); }

  bool IsInline() const { return is_inline_stylesheet_; }
  TextPosition StartPositionInSource() const { return start_position_; }

  bool SheetLoaded();
  bool LoadCompleted() const { return load_completed_; }
  void StartLoadingDynamicSheet();
  void SetText(const String&);
  void SetMedia(MediaList*);
  void SetAlternateFromConstructor(bool);
  bool IsAlternate() const;
  bool CanBeActivated(const String& current_preferrable_name) const;

  virtual void Trace(blink::Visitor*);

 private:
  CSSStyleSheet(StyleSheetContents*, CSSImportRule* owner_rule);
  CSSStyleSheet(StyleSheetContents*,
                Node& owner_node,
                bool is_inline_stylesheet,
                const TextPosition& start_position);

  bool IsCSSStyleSheet() const override { return true; }
  String type() const override { return "text/css"; }

  void ReattachChildRuleCSSOMWrappers();

  bool CanAccessRules() const;

  void SetLoadCompleted(bool);

  FRIEND_TEST_ALL_PREFIXES(
      CSSStyleSheetTest,
      CSSStyleSheetConstructionWithEmptyCSSStyleSheetInitAndText);
  FRIEND_TEST_ALL_PREFIXES(
      CSSStyleSheetTest,
      CSSStyleSheetConstructionWithoutEmptyCSSStyleSheetInitAndText);
  bool AlternateFromConstructor() const { return alternate_from_constructor_; }

  Member<StyleSheetContents> contents_;
  bool is_inline_stylesheet_ = false;
  bool is_disabled_ = false;
  bool load_completed_ = false;
  // This alternate variable is only used for constructed CSSStyleSheet.
  // For other CSSStyleSheet, consult the alternate attribute.
  bool alternate_from_constructor_ = false;
  bool enable_rule_access_for_inspector_ = false;
  String title_;
  scoped_refptr<MediaQuerySet> media_queries_;
  MediaQueryResultList viewport_dependent_media_query_results_;
  MediaQueryResultList device_dependent_media_query_results_;

  scoped_refptr<const SecurityOrigin> allow_rule_access_from_origin_;

  Member<Node> owner_node_;
  Member<CSSRule> owner_rule_;
  HeapHashSet<Member<TreeScope>> constructed_tree_scopes_;

  TextPosition start_position_;
  Member<MediaList> media_cssom_wrapper_;
  mutable HeapVector<Member<CSSRule>> child_rule_cssom_wrappers_;
  mutable Member<CSSRuleList> rule_list_cssom_wrapper_;
  DISALLOW_COPY_AND_ASSIGN(CSSStyleSheet);
};

inline CSSStyleSheet::RuleMutationScope::RuleMutationScope(CSSStyleSheet* sheet)
    : style_sheet_(sheet) {
  style_sheet_->WillMutateRules();
}

inline CSSStyleSheet::RuleMutationScope::RuleMutationScope(CSSRule* rule)
    : style_sheet_(rule ? rule->parentStyleSheet() : nullptr) {
  if (style_sheet_)
    style_sheet_->WillMutateRules();
}

inline CSSStyleSheet::RuleMutationScope::~RuleMutationScope() {
  if (style_sheet_)
    style_sheet_->DidMutateRules();
}

DEFINE_TYPE_CASTS(CSSStyleSheet,
                  StyleSheet,
                  sheet,
                  sheet->IsCSSStyleSheet(),
                  sheet.IsCSSStyleSheet());

}  // namespace blink

#endif

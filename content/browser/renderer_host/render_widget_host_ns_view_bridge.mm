// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import "content/browser/renderer_host/render_widget_host_ns_view_bridge.h"

#import <Cocoa/Cocoa.h>

#include "base/mac/scoped_cftyperef.h"
#import "base/mac/scoped_nsobject.h"
#include "base/strings/sys_string_conversions.h"
#import "content/browser/renderer_host/popup_window_mac.h"
#import "content/browser/renderer_host/render_widget_host_view_cocoa.h"
#include "content/common/cursors/webcursor.h"
#import "skia/ext/skia_utils_mac.h"
#import "ui/base/cocoa/animation_utils.h"
#include "ui/display/display_observer.h"
#include "ui/display/screen.h"
#include "ui/gfx/mac/coordinate_conversion.h"

namespace content {

namespace {

// Bridge to a locally-hosted NSView -- this is always instantiated in the same
// process as the NSView. The caller of this interface may exist in another
// process.
class RenderWidgetHostViewNSViewBridgeLocal
    : public RenderWidgetHostNSViewBridge,
      public display::DisplayObserver {
 public:
  explicit RenderWidgetHostViewNSViewBridgeLocal(
      RenderWidgetHostNSViewClient* client);
  ~RenderWidgetHostViewNSViewBridgeLocal() override;
  RenderWidgetHostViewCocoa* GetRenderWidgetHostViewCocoa() override;

  void InitAsPopup(const gfx::Rect& content_rect,
                   blink::WebPopupType popup_type) override;
  void MakeFirstResponder() override;
  void SetBounds(const gfx::Rect& rect) override;
  void SetBackgroundColor(SkColor color) override;
  void SetVisible(bool visible) override;
  void SetTooltipText(const base::string16& display_text) override;
  void SetTextSelection(const base::string16& text,
                        size_t offset,
                        const gfx::Range& range) override;
  void SetCompositionRangeInfo(const gfx::Range& range) override;
  void CancelComposition() override;
  void SetShowingContextMenu(bool showing) override;
  void DisplayCursor(const WebCursor& cursor) override;
  void SetCursorLocked(bool locked) override;
  void ShowDictionaryOverlayForSelection() override;
  void ShowDictionaryOverlay(
      const mac::AttributedStringCoder::EncodedString& encoded_string,
      gfx::Point baseline_point) override;
  void LockKeyboard(base::Optional<base::flat_set<int>> keys) override;
  void UnlockKeyboard() override;

 private:
  bool IsPopup() const {
    // TODO(ccameron): If this is not equivalent to |popup_window_| then
    // there are bugs.
    return popup_type_ != blink::kWebPopupTypeNone;
  }

  // display::DisplayObserver implementation.
  void OnDisplayMetricsChanged(const display::Display& display,
                               uint32_t metrics) override;

  // The NSView used for input and display.
  base::scoped_nsobject<RenderWidgetHostViewCocoa> cocoa_view_;

  // The window used for popup widgets, and its helper.
  std::unique_ptr<PopupWindowMac> popup_window_;
  blink::WebPopupType popup_type_ = blink::kWebPopupTypeNone;

  // The background CoreAnimation layer which is hosted by |cocoa_view_|.
  base::scoped_nsobject<CALayer> background_layer_;

  // Cached copy of the tooltip text, to avoid redundant calls.
  base::string16 tooltip_text_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetHostViewNSViewBridgeLocal);
};

RenderWidgetHostViewNSViewBridgeLocal::RenderWidgetHostViewNSViewBridgeLocal(
    RenderWidgetHostNSViewClient* client) {
  display::Screen::GetScreen()->AddObserver(this);

  cocoa_view_.reset([[RenderWidgetHostViewCocoa alloc] initWithClient:client]);

  background_layer_.reset([[CALayer alloc] init]);
  [cocoa_view_ setLayer:background_layer_];
  [cocoa_view_ setWantsLayer:YES];
}

RenderWidgetHostViewNSViewBridgeLocal::
    ~RenderWidgetHostViewNSViewBridgeLocal() {
  [cocoa_view_ setClientDisconnected];
  [cocoa_view_ removeFromSuperview];
  cocoa_view_.autorelease();
  display::Screen::GetScreen()->RemoveObserver(this);
  popup_window_.reset();
}

RenderWidgetHostViewCocoa*
RenderWidgetHostViewNSViewBridgeLocal::GetRenderWidgetHostViewCocoa() {
  return cocoa_view_;
}

void RenderWidgetHostViewNSViewBridgeLocal::InitAsPopup(
    const gfx::Rect& content_rect,
    blink::WebPopupType popup_type) {
  popup_type_ = popup_type;
  popup_window_ =
      std::make_unique<PopupWindowMac>(content_rect, popup_type_, cocoa_view_);
}

void RenderWidgetHostViewNSViewBridgeLocal::MakeFirstResponder() {
  [[cocoa_view_ window] makeFirstResponder:cocoa_view_];
}

void RenderWidgetHostViewNSViewBridgeLocal::SetBounds(const gfx::Rect& rect) {
  // |rect.size()| is view coordinates, |rect.origin| is screen coordinates,
  // TODO(thakis): fix, http://crbug.com/73362

  // During the initial creation of the RenderWidgetHostView in
  // WebContentsImpl::CreateRenderViewForRenderManager, SetSize is called with
  // an empty size. In the Windows code flow, it is not ignored because
  // subsequent sizing calls from the OS flow through TCVW::WasSized which calls
  // SetSize() again. On Cocoa, we rely on the Cocoa view struture and resizer
  // flags to keep things sized properly. On the other hand, if the size is not
  // empty then this is a valid request for a pop-up.
  if (rect.size().IsEmpty())
    return;

  // Ignore the position of |rect| for non-popup rwhvs. This is because
  // background tabs do not have a window, but the window is required for the
  // coordinate conversions. Popups are always for a visible tab.
  //
  // Note: If |cocoa_view_| has been removed from the view hierarchy, it's still
  // valid for resizing to be requested (e.g., during tab capture, to size the
  // view to screen-capture resolution). In this case, simply treat the view as
  // relative to the screen.
  BOOL isRelativeToScreen =
      IsPopup() || ![[cocoa_view_ superview] isKindOfClass:[BaseView class]];
  if (isRelativeToScreen) {
    // The position of |rect| is screen coordinate system and we have to
    // consider Cocoa coordinate system is upside-down and also multi-screen.
    NSRect frame = gfx::ScreenRectToNSRect(rect);
    if (IsPopup())
      [popup_window_->window() setFrame:frame display:YES];
    else
      [cocoa_view_ setFrame:frame];
  } else {
    BaseView* superview = static_cast<BaseView*>([cocoa_view_ superview]);
    gfx::Rect rect2 = [superview flipNSRectToRect:[cocoa_view_ frame]];
    rect2.set_width(rect.width());
    rect2.set_height(rect.height());
    [cocoa_view_ setFrame:[superview flipRectToNSRect:rect2]];
  }
}

void RenderWidgetHostViewNSViewBridgeLocal::SetBackgroundColor(SkColor color) {
  ScopedCAActionDisabler disabler;
  base::ScopedCFTypeRef<CGColorRef> cg_color(
      skia::CGColorCreateFromSkColor(color));
  [background_layer_ setBackgroundColor:cg_color];
}

void RenderWidgetHostViewNSViewBridgeLocal::SetVisible(bool visible) {
  ScopedCAActionDisabler disabler;
  [cocoa_view_ setHidden:!visible];
}

void RenderWidgetHostViewNSViewBridgeLocal::SetTooltipText(
    const base::string16& tooltip_text) {
  // Called from the renderer to tell us what the tooltip text should be. It
  // calls us frequently so we need to cache the value to prevent doing a lot
  // of repeat work.
  if (tooltip_text == tooltip_text_ || ![[cocoa_view_ window] isKeyWindow])
    return;
  tooltip_text_ = tooltip_text;

  // Maximum number of characters we allow in a tooltip.
  const size_t kMaxTooltipLength = 1024;

  // Clamp the tooltip length to kMaxTooltipLength. It's a DOS issue on
  // Windows; we're just trying to be polite. Don't persist the trimmed
  // string, as then the comparison above will always fail and we'll try to
  // set it again every single time the mouse moves.
  base::string16 display_text = tooltip_text_;
  if (tooltip_text_.length() > kMaxTooltipLength)
    display_text = tooltip_text_.substr(0, kMaxTooltipLength);

  NSString* tooltip_nsstring = base::SysUTF16ToNSString(display_text);
  [cocoa_view_ setToolTipAtMousePoint:tooltip_nsstring];
}

void RenderWidgetHostViewNSViewBridgeLocal::SetCompositionRangeInfo(
    const gfx::Range& range) {
  [cocoa_view_ setCompositionRange:range];
  [cocoa_view_ setMarkedRange:range.ToNSRange()];
}

void RenderWidgetHostViewNSViewBridgeLocal::CancelComposition() {
  [cocoa_view_ cancelComposition];
}

void RenderWidgetHostViewNSViewBridgeLocal::SetTextSelection(
    const base::string16& text,
    size_t offset,
    const gfx::Range& range) {
  [cocoa_view_ setTextSelectionText:text offset:offset range:range];
  // Updates markedRange when there is no marked text so that retrieving
  // markedRange immediately after calling setMarkdText: returns the current
  // caret position.
  if (![cocoa_view_ hasMarkedText]) {
    [cocoa_view_ setMarkedRange:range.ToNSRange()];
  }
}

void RenderWidgetHostViewNSViewBridgeLocal::SetShowingContextMenu(
    bool showing) {
  [cocoa_view_ setShowingContextMenu:showing];
}

void RenderWidgetHostViewNSViewBridgeLocal::OnDisplayMetricsChanged(
    const display::Display& display,
    uint32_t changed_metrics) {
  // Note that -updateScreenProperties is also be called by the notification
  // NSWindowDidChangeBackingPropertiesNotification (some of these calls
  // will be redundant).
  [cocoa_view_ updateScreenProperties];
}

void RenderWidgetHostViewNSViewBridgeLocal::DisplayCursor(
    const WebCursor& cursor) {
  WebCursor non_const_cursor = cursor;
  [cocoa_view_ updateCursor:non_const_cursor.GetNativeCursor()];
}

void RenderWidgetHostViewNSViewBridgeLocal::SetCursorLocked(bool locked) {
  if (locked) {
    CGAssociateMouseAndMouseCursorPosition(NO);
    [NSCursor hide];
  } else {
    // Unlock position of mouse cursor and unhide it.
    CGAssociateMouseAndMouseCursorPosition(YES);
    [NSCursor unhide];
  }
}

void RenderWidgetHostViewNSViewBridgeLocal::
    ShowDictionaryOverlayForSelection() {
  NSRange selection_range = [cocoa_view_ selectedRange];
  [cocoa_view_ showLookUpDictionaryOverlayFromRange:selection_range];
}

void RenderWidgetHostViewNSViewBridgeLocal::ShowDictionaryOverlay(
    const mac::AttributedStringCoder::EncodedString& encoded_string,
    gfx::Point baseline_point) {
  NSAttributedString* string =
      mac::AttributedStringCoder::Decode(&encoded_string);
  if ([string length] == 0)
    return;
  NSPoint flipped_baseline_point = {
      baseline_point.x(), [cocoa_view_ frame].size.height - baseline_point.y(),
  };
  [cocoa_view_ showDefinitionForAttributedString:string
                                         atPoint:flipped_baseline_point];
}

void RenderWidgetHostViewNSViewBridgeLocal::LockKeyboard(
    base::Optional<base::flat_set<int>> keys) {
  [cocoa_view_ lockKeyboard:std::move(keys)];
}

void RenderWidgetHostViewNSViewBridgeLocal::UnlockKeyboard() {
  [cocoa_view_ unlockKeyboard];
}

}  // namespace

// static
std::unique_ptr<RenderWidgetHostNSViewBridge>
RenderWidgetHostNSViewBridge::Create(RenderWidgetHostNSViewClient* client) {
  return std::make_unique<RenderWidgetHostViewNSViewBridgeLocal>(client);
}

}  // namespace content

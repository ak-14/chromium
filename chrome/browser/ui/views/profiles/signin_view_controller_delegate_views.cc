// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/profiles/signin_view_controller_delegate_views.h"

#include "base/macros.h"
#include "build/build_config.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/profiles/profile_avatar_icon_util.h"
#include "chrome/browser/signin/signin_promo.h"
#include "chrome/browser/signin/unified_consent_helper.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/tabs/tab_strip_model.h"
#include "chrome/browser/ui/views/frame/browser_view.h"
#include "chrome/browser/ui/views_mode_controller.h"
#include "chrome/browser/ui/webui/signin/sync_confirmation_ui.h"
#include "chrome/common/url_constants.h"
#include "components/constrained_window/constrained_window_views.h"
#include "components/web_modal/web_contents_modal_dialog_host.h"
#include "content/public/browser/render_widget_host_view.h"
#include "content/public/browser/web_contents.h"
#include "ui/views/controls/webview/webview.h"
#include "ui/views/widget/widget.h"

namespace {

const int kFixedGaiaViewHeight = 612;
const int kModalDialogWidth = 448;
const int kModalDialogWidthForDice = 512;
const int kSyncConfirmationDialogHeight = 487;
const int kSigninErrorDialogHeight = 164;

int GetSyncConfirmationDialogPreferredHeight(Profile* profile) {
  // If sync is disabled, then the sync confirmation dialog looks like an error
  // dialog and thus it has the same preferred size.
  return profile->IsSyncAllowed() ? kSyncConfirmationDialogHeight
                                  : kSigninErrorDialogHeight;
}

int GetSyncConfirmationDialogPreferredWidth(Profile* profile) {
  // With Unity-enabled profiles, we show a different sync confirmation dialog
  // which uses a different width.
  return IsUnifiedConsentEnabled(profile) && profile->IsSyncAllowed()
             ? kModalDialogWidthForDice
             : kModalDialogWidth;
}

}  // namespace

SigninViewControllerDelegateViews::SigninViewControllerDelegateViews(
    SigninViewController* signin_view_controller,
    std::unique_ptr<views::WebView> content_view,
    Browser* browser,
    ui::ModalType dialog_modal_type,
    bool wait_for_size)
    : SigninViewControllerDelegate(signin_view_controller,
                                   content_view->GetWebContents(),
                                   browser),
      content_view_(content_view.release()),
      modal_signin_widget_(nullptr),
      dialog_modal_type_(dialog_modal_type) {
  DCHECK(dialog_modal_type == ui::MODAL_TYPE_CHILD ||
         dialog_modal_type == ui::MODAL_TYPE_WINDOW)
      << "Unsupported dialog modal type " << dialog_modal_type;
  if (!wait_for_size)
    DisplayModal();
}

SigninViewControllerDelegateViews::~SigninViewControllerDelegateViews() {}

// views::DialogDelegateView:
views::View* SigninViewControllerDelegateViews::GetContentsView() {
  return content_view_;
}

views::Widget* SigninViewControllerDelegateViews::GetWidget() {
  return content_view_->GetWidget();
}

const views::Widget* SigninViewControllerDelegateViews::GetWidget() const {
  return content_view_->GetWidget();
}

void SigninViewControllerDelegateViews::DeleteDelegate() {
  ResetSigninViewControllerDelegate();
  delete this;
}

ui::ModalType SigninViewControllerDelegateViews::GetModalType() const {
  return dialog_modal_type_;
}

bool SigninViewControllerDelegateViews::ShouldShowCloseButton() const {
  return false;
}

int SigninViewControllerDelegateViews::GetDialogButtons() const {
  return ui::DIALOG_BUTTON_NONE;
}

void SigninViewControllerDelegateViews::PerformClose() {
  if (modal_signin_widget_)
    modal_signin_widget_->Close();
}

void SigninViewControllerDelegateViews::ResizeNativeView(int height) {
  int max_height = browser()
                       ->window()
                       ->GetWebContentsModalDialogHost()
                       ->GetMaximumDialogSize()
                       .height();
  content_view_->SetPreferredSize(gfx::Size(
      content_view_->GetPreferredSize().width(), std::min(height, max_height)));

  if (!modal_signin_widget_) {
    // The modal wasn't displayed yet so just show it with the already resized
    // view.
    DisplayModal();
  }
}

void SigninViewControllerDelegateViews::DisplayModal() {
  DCHECK(!modal_signin_widget_);

  content::WebContents* host_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();

  // Avoid displaying the sign-in modal view if there are no active web
  // contents. This happens if the user closes the browser window before this
  // dialog has a chance to be displayed.
  if (!host_web_contents)
    return;

  gfx::NativeWindow window = host_web_contents->GetTopLevelNativeWindow();
  switch (dialog_modal_type_) {
    case ui::MODAL_TYPE_WINDOW:
      modal_signin_widget_ =
          constrained_window::CreateBrowserModalDialogViews(this, window);
      modal_signin_widget_->Show();
      break;
    case ui::MODAL_TYPE_CHILD:
      modal_signin_widget_ = constrained_window::ShowWebModalDialogViews(
          this, browser()->tab_strip_model()->GetActiveWebContents());
      break;
    default:
      NOTREACHED() << "Unsupported dialog modal type " << dialog_modal_type_;
  }
  content_view_->RequestFocus();
}

// static
std::unique_ptr<views::WebView>
SigninViewControllerDelegateViews::CreateGaiaWebView(
    content::WebContentsDelegate* delegate,
    profiles::BubbleViewMode mode,
    Browser* browser,
    signin_metrics::AccessPoint access_point) {
  GURL url =
      signin::GetSigninURLFromBubbleViewMode(
          browser->profile(), mode, access_point);

  int max_height = browser
      ->window()
      ->GetWebContentsModalDialogHost()
      ->GetMaximumDialogSize().height();
  // Adds Gaia signin webview.
  const gfx::Size pref_size(kModalDialogWidth,
                            std::min(kFixedGaiaViewHeight, max_height));
  views::WebView* web_view = new views::WebView(browser->profile());
  web_view->LoadInitialURL(url);

  if (delegate)
    web_view->GetWebContents()->SetDelegate(delegate);

  web_view->SetPreferredSize(pref_size);
  content::RenderWidgetHostView* rwhv =
      web_view->GetWebContents()->GetRenderWidgetHostView();
  if (rwhv)
    rwhv->SetBackgroundColor(profiles::kAvatarBubbleGaiaBackgroundColor);

  return std::unique_ptr<views::WebView>(web_view);
}

std::unique_ptr<views::WebView>
SigninViewControllerDelegateViews::CreateSyncConfirmationWebView(
    Browser* browser,
    bool is_consent_bump) {
  return CreateDialogWebView(
      browser,
      is_consent_bump ? chrome::kChromeUISyncConsentBumpURL
                      : chrome::kChromeUISyncConfirmationURL,
      GetSyncConfirmationDialogPreferredHeight(browser->profile()),
      GetSyncConfirmationDialogPreferredWidth(browser->profile()));
}

std::unique_ptr<views::WebView>
SigninViewControllerDelegateViews::CreateSigninErrorWebView(Browser* browser) {
  return CreateDialogWebView(browser, chrome::kChromeUISigninErrorURL,
                             kSigninErrorDialogHeight, base::nullopt);
}

std::unique_ptr<views::WebView>
SigninViewControllerDelegateViews::CreateDialogWebView(
    Browser* browser,
    const std::string& url,
    int dialog_height,
    base::Optional<int> opt_width) {
  int dialog_width = opt_width.value_or(kModalDialogWidth);
  views::WebView* web_view = new views::WebView(browser->profile());
  web_view->LoadInitialURL(GURL(url));

  SigninWebDialogUI* web_dialog_ui = static_cast<SigninWebDialogUI*>(
      web_view->GetWebContents()->GetWebUI()->GetController());
  web_dialog_ui->InitializeMessageHandlerWithBrowser(browser);

  int max_height = browser->window()
                       ->GetWebContentsModalDialogHost()
                       ->GetMaximumDialogSize()
                       .height();
  web_view->SetPreferredSize(
      gfx::Size(dialog_width, std::min(dialog_height, max_height)));

  return std::unique_ptr<views::WebView>(web_view);
}

SigninViewControllerDelegate*
SigninViewControllerDelegate::CreateModalSigninDelegate(
    SigninViewController* signin_view_controller,
    profiles::BubbleViewMode mode,
    Browser* browser,
    signin_metrics::AccessPoint access_point) {
#if defined(OS_MACOSX)
  if (views_mode_controller::IsViewsBrowserCocoa()) {
    return CreateModalSigninDelegateCocoa(signin_view_controller, mode, browser,
                                          access_point);
  }
#endif
  return new SigninViewControllerDelegateViews(
      signin_view_controller,
      SigninViewControllerDelegateViews::CreateGaiaWebView(
          nullptr, mode, browser, access_point),
      browser, ui::MODAL_TYPE_CHILD, false);
}

SigninViewControllerDelegate*
SigninViewControllerDelegate::CreateSyncConfirmationDelegate(
    SigninViewController* signin_view_controller,
    Browser* browser,
    bool is_consent_bump) {
#if defined(OS_MACOSX)
  if (views_mode_controller::IsViewsBrowserCocoa()) {
    return CreateSyncConfirmationDelegateCocoa(signin_view_controller, browser);
  }
#endif
  return new SigninViewControllerDelegateViews(
      signin_view_controller,
      SigninViewControllerDelegateViews::CreateSyncConfirmationWebView(
          browser, is_consent_bump),
      browser, ui::MODAL_TYPE_WINDOW, true);
}

SigninViewControllerDelegate*
SigninViewControllerDelegate::CreateSigninErrorDelegate(
    SigninViewController* signin_view_controller,
    Browser* browser) {
#if defined(OS_MACOSX)
  if (views_mode_controller::IsViewsBrowserCocoa()) {
    return CreateSigninErrorDelegateCocoa(signin_view_controller, browser);
  }
#endif
  return new SigninViewControllerDelegateViews(
      signin_view_controller,
      SigninViewControllerDelegateViews::CreateSigninErrorWebView(browser),
      browser, ui::MODAL_TYPE_WINDOW, true);
}

// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import "ios/chrome/browser/ui/browser_view_controller.h"

#import <AssetsLibrary/AssetsLibrary.h>
#import <MobileCoreServices/MobileCoreServices.h>
#import <QuartzCore/QuartzCore.h>

#include <stdint.h>
#include <cmath>
#include <memory>

#include "base/base64.h"
#include "base/command_line.h"
#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/i18n/rtl.h"
#include "base/ios/block_types.h"
#include "base/ios/ios_util.h"
#include "base/logging.h"
#include "base/mac/bind_objc_block.h"
#include "base/mac/bundle_locations.h"
#include "base/mac/foundation_util.h"
#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics.h"
#include "base/metrics/user_metrics_action.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "components/bookmarks/browser/base_bookmark_model_observer.h"
#include "components/bookmarks/browser/bookmark_model.h"
#include "components/favicon/ios/web_favicon_driver.h"
#include "components/feature_engagement/public/event_constants.h"
#include "components/feature_engagement/public/feature_constants.h"
#include "components/feature_engagement/public/tracker.h"
#include "components/image_fetcher/ios/ios_image_data_fetcher_wrapper.h"
#include "components/infobars/core/infobar_manager.h"
#import "components/language/ios/browser/ios_language_detection_tab_helper.h"
#include "components/payments/core/features.h"
#include "components/prefs/pref_service.h"
#include "components/reading_list/core/reading_list_model.h"
#include "components/search_engines/search_engines_pref_names.h"
#include "components/search_engines/template_url_service.h"
#include "components/sessions/core/session_types.h"
#include "components/sessions/core/tab_restore_service_helper.h"
#include "components/signin/core/browser/account_reconcilor.h"
#include "components/signin/core/browser/signin_metrics.h"
#import "components/signin/ios/browser/account_consistency_service.h"
#include "components/signin/ios/browser/active_state_manager.h"
#include "components/strings/grit/components_strings.h"
#include "components/toolbar/toolbar_model_impl.h"
#include "ios/chrome/app/tests_hook.h"
#import "ios/chrome/browser/app_launcher/app_launcher_tab_helper.h"
#import "ios/chrome/browser/autofill/autofill_tab_helper.h"
#include "ios/chrome/browser/bookmarks/bookmark_model_factory.h"
#include "ios/chrome/browser/browser_state/chrome_browser_state.h"
#include "ios/chrome/browser/chrome_url_constants.h"
#include "ios/chrome/browser/chrome_url_util.h"
#import "ios/chrome/browser/download/download_manager_tab_helper.h"
#import "ios/chrome/browser/download/pass_kit_tab_helper.h"
#include "ios/chrome/browser/experimental_flags.h"
#import "ios/chrome/browser/favicon/favicon_loader.h"
#include "ios/chrome/browser/favicon/ios_chrome_favicon_loader_factory.h"
#include "ios/chrome/browser/feature_engagement/tracker_factory.h"
#include "ios/chrome/browser/feature_engagement/tracker_util.h"
#import "ios/chrome/browser/find_in_page/find_in_page_controller.h"
#import "ios/chrome/browser/find_in_page/find_in_page_model.h"
#import "ios/chrome/browser/find_in_page/find_tab_helper.h"
#include "ios/chrome/browser/first_run/first_run.h"
#import "ios/chrome/browser/geolocation/omnibox_geolocation_controller.h"
#include "ios/chrome/browser/infobars/infobar_container_delegate_ios.h"
#include "ios/chrome/browser/infobars/infobar_container_ios.h"
#import "ios/chrome/browser/infobars/infobar_container_state_delegate.h"
#include "ios/chrome/browser/infobars/infobar_container_view.h"
#include "ios/chrome/browser/infobars/infobar_manager_impl.h"
#import "ios/chrome/browser/language/url_language_histogram_factory.h"
#import "ios/chrome/browser/metrics/new_tab_page_uma.h"
#import "ios/chrome/browser/metrics/size_class_recorder.h"
#include "ios/chrome/browser/metrics/tab_usage_recorder.h"
#import "ios/chrome/browser/passwords/password_controller.h"
#include "ios/chrome/browser/passwords/password_tab_helper.h"
#include "ios/chrome/browser/pref_names.h"
#import "ios/chrome/browser/prerender/preload_controller_delegate.h"
#import "ios/chrome/browser/prerender/prerender_service.h"
#import "ios/chrome/browser/prerender/prerender_service_factory.h"
#include "ios/chrome/browser/reading_list/offline_url_utils.h"
#include "ios/chrome/browser/reading_list/reading_list_model_factory.h"
#include "ios/chrome/browser/search_engines/template_url_service_factory.h"
#include "ios/chrome/browser/sessions/ios_chrome_tab_restore_service_factory.h"
#include "ios/chrome/browser/sessions/session_util.h"
#include "ios/chrome/browser/sessions/tab_restore_service_delegate_impl_ios.h"
#include "ios/chrome/browser/sessions/tab_restore_service_delegate_impl_ios_factory.h"
#import "ios/chrome/browser/signin/account_consistency_service_factory.h"
#include "ios/chrome/browser/signin/account_reconcilor_factory.h"
#import "ios/chrome/browser/snapshots/snapshot_cache.h"
#import "ios/chrome/browser/snapshots/snapshot_generator_delegate.h"
#import "ios/chrome/browser/snapshots/snapshot_overlay.h"
#import "ios/chrome/browser/snapshots/snapshot_tab_helper.h"
#import "ios/chrome/browser/ssl/captive_portal_detector_tab_helper.h"
#import "ios/chrome/browser/ssl/captive_portal_detector_tab_helper_delegate.h"
#import "ios/chrome/browser/store_kit/store_kit_coordinator.h"
#import "ios/chrome/browser/store_kit/store_kit_tab_helper.h"
#import "ios/chrome/browser/tabs/legacy_tab_helper.h"
#import "ios/chrome/browser/tabs/tab.h"
#import "ios/chrome/browser/tabs/tab_dialog_delegate.h"
#import "ios/chrome/browser/tabs/tab_model.h"
#import "ios/chrome/browser/tabs/tab_model_observer.h"
#import "ios/chrome/browser/tabs/tab_private.h"
#import "ios/chrome/browser/translate/chrome_ios_translate_client.h"
#import "ios/chrome/browser/translate/language_selection_handler.h"
#import "ios/chrome/browser/ui/activity_services/activity_service_legacy_coordinator.h"
#import "ios/chrome/browser/ui/activity_services/requirements/activity_service_presentation.h"
#import "ios/chrome/browser/ui/alert_coordinator/alert_coordinator.h"
#import "ios/chrome/browser/ui/alert_coordinator/repost_form_coordinator.h"
#import "ios/chrome/browser/ui/app_launcher/app_launcher_coordinator.h"
#import "ios/chrome/browser/ui/authentication/re_signin_infobar_delegate.h"
#import "ios/chrome/browser/ui/background_generator.h"
#import "ios/chrome/browser/ui/bookmarks/bookmark_interaction_controller.h"
#include "ios/chrome/browser/ui/bookmarks/bookmark_model_bridge_observer.h"
#import "ios/chrome/browser/ui/browser_container_view_controller.h"
#import "ios/chrome/browser/ui/browser_view_controller_dependency_factory.h"
#import "ios/chrome/browser/ui/browser_view_controller_helper.h"
#import "ios/chrome/browser/ui/bubble/bubble_util.h"
#import "ios/chrome/browser/ui/bubble/bubble_view_controller_presenter.h"
#import "ios/chrome/browser/ui/chrome_web_view_factory.h"
#import "ios/chrome/browser/ui/commands/application_commands.h"
#import "ios/chrome/browser/ui/commands/browser_commands.h"
#import "ios/chrome/browser/ui/commands/command_dispatcher.h"
#import "ios/chrome/browser/ui/commands/open_new_tab_command.h"
#import "ios/chrome/browser/ui/commands/open_url_command.h"
#import "ios/chrome/browser/ui/commands/popup_menu_commands.h"
#import "ios/chrome/browser/ui/commands/reading_list_add_command.h"
#import "ios/chrome/browser/ui/commands/show_signin_command.h"
#import "ios/chrome/browser/ui/commands/snackbar_commands.h"
#import "ios/chrome/browser/ui/commands/toolbar_commands.h"
#import "ios/chrome/browser/ui/content_suggestions/ntp_home_constant.h"
#import "ios/chrome/browser/ui/context_menu/context_menu_coordinator.h"
#import "ios/chrome/browser/ui/dialogs/dialog_presenter.h"
#import "ios/chrome/browser/ui/dialogs/java_script_dialog_presenter_impl.h"
#import "ios/chrome/browser/ui/download/download_manager_coordinator.h"
#import "ios/chrome/browser/ui/download/legacy_download_manager_controller.h"
#import "ios/chrome/browser/ui/download/pass_kit_coordinator.h"
#import "ios/chrome/browser/ui/elements/activity_overlay_coordinator.h"
#import "ios/chrome/browser/ui/external_file_controller.h"
#import "ios/chrome/browser/ui/external_search/external_search_coordinator.h"
#import "ios/chrome/browser/ui/find_bar/find_bar_controller_ios.h"
#import "ios/chrome/browser/ui/first_run/welcome_to_chrome_view_controller.h"
#import "ios/chrome/browser/ui/fullscreen/fullscreen_controller.h"
#import "ios/chrome/browser/ui/fullscreen/fullscreen_controller_factory.h"
#import "ios/chrome/browser/ui/fullscreen/fullscreen_foreground_animator.h"
#import "ios/chrome/browser/ui/fullscreen/fullscreen_scroll_end_animator.h"
#import "ios/chrome/browser/ui/fullscreen/fullscreen_scroll_to_top_animator.h"
#import "ios/chrome/browser/ui/fullscreen/fullscreen_ui_element.h"
#import "ios/chrome/browser/ui/fullscreen/fullscreen_ui_updater.h"
#import "ios/chrome/browser/ui/history_popup/requirements/tab_history_presentation.h"
#import "ios/chrome/browser/ui/history_popup/tab_history_legacy_coordinator.h"
#import "ios/chrome/browser/ui/image_util/image_saver.h"
#import "ios/chrome/browser/ui/key_commands_provider.h"
#import "ios/chrome/browser/ui/location_bar_notification_names.h"
#import "ios/chrome/browser/ui/main/main_feature_flags.h"
#import "ios/chrome/browser/ui/main_content/main_content_ui.h"
#import "ios/chrome/browser/ui/main_content/main_content_ui_broadcasting_util.h"
#import "ios/chrome/browser/ui/main_content/main_content_ui_state.h"
#import "ios/chrome/browser/ui/main_content/web_scroll_view_main_content_ui_forwarder.h"
#import "ios/chrome/browser/ui/new_foreground_tab_fullscreen_disabler.h"
#import "ios/chrome/browser/ui/ntp/new_tab_page_controller.h"
#import "ios/chrome/browser/ui/ntp/recent_tabs/recent_tabs_handset_coordinator.h"
#import "ios/chrome/browser/ui/overscroll_actions/overscroll_actions_controller.h"
#import "ios/chrome/browser/ui/page_info/page_info_legacy_coordinator.h"
#import "ios/chrome/browser/ui/page_info/requirements/page_info_presentation.h"
#import "ios/chrome/browser/ui/page_not_available_controller.h"
#import "ios/chrome/browser/ui/payments/payment_request_manager.h"
#import "ios/chrome/browser/ui/popup_menu/popup_menu_coordinator.h"
#import "ios/chrome/browser/ui/popup_menu/popup_menu_flags.h"
#import "ios/chrome/browser/ui/presenters/vertical_animation_container.h"
#import "ios/chrome/browser/ui/print/print_controller.h"
#import "ios/chrome/browser/ui/qr_scanner/qr_scanner_legacy_coordinator.h"
#import "ios/chrome/browser/ui/qr_scanner/requirements/qr_scanner_presenting.h"
#import "ios/chrome/browser/ui/reading_list/offline_page_native_content.h"
#import "ios/chrome/browser/ui/reading_list/reading_list_coordinator.h"
#import "ios/chrome/browser/ui/reading_list/reading_list_menu_notifier.h"
#import "ios/chrome/browser/ui/recent_tabs/recent_tabs_coordinator.h"
#include "ios/chrome/browser/ui/rtl_geometry.h"
#import "ios/chrome/browser/ui/sad_tab/sad_tab_legacy_coordinator.h"
#import "ios/chrome/browser/ui/settings/sync_utils/sync_util.h"
#import "ios/chrome/browser/ui/side_swipe/side_swipe_controller.h"
#import "ios/chrome/browser/ui/signin_interaction/public/signin_presenter.h"
#import "ios/chrome/browser/ui/snackbar/snackbar_coordinator.h"
#import "ios/chrome/browser/ui/stack_view/card_view.h"
#import "ios/chrome/browser/ui/stack_view/page_animation_util.h"
#import "ios/chrome/browser/ui/static_content/static_html_native_content.h"
#import "ios/chrome/browser/ui/tab_switcher/tab_switcher_controller.h"
#import "ios/chrome/browser/ui/tabs/requirements/tab_strip_constants.h"
#import "ios/chrome/browser/ui/tabs/requirements/tab_strip_presentation.h"
#import "ios/chrome/browser/ui/tabs/tab_strip_legacy_coordinator.h"
#import "ios/chrome/browser/ui/toolbar/adaptive/adaptive_toolbar_coordinator.h"
#import "ios/chrome/browser/ui/toolbar/adaptive/adaptive_toolbar_view_controller.h"
#import "ios/chrome/browser/ui/toolbar/adaptive/primary_toolbar_coordinator.h"
#import "ios/chrome/browser/ui/toolbar/adaptive/secondary_toolbar_coordinator.h"
#import "ios/chrome/browser/ui/toolbar/adaptive/toolbar_coordinator_adaptor.h"
#import "ios/chrome/browser/ui/toolbar/buttons/toolbar_constants.h"
#import "ios/chrome/browser/ui/toolbar/clean/toolbar_coordinator.h"
#import "ios/chrome/browser/ui/toolbar/legacy/toolbar_controller_constants.h"
#import "ios/chrome/browser/ui/toolbar/legacy_toolbar_ui_updater.h"
#import "ios/chrome/browser/ui/toolbar/public/primary_toolbar_coordinator.h"
#import "ios/chrome/browser/ui/toolbar/public/toolbar_controller_base_feature.h"
#include "ios/chrome/browser/ui/toolbar/toolbar_model_delegate_ios.h"
#import "ios/chrome/browser/ui/toolbar/toolbar_snapshot_providing.h"
#import "ios/chrome/browser/ui/toolbar/toolbar_ui.h"
#import "ios/chrome/browser/ui/toolbar/toolbar_ui_broadcasting_util.h"
#import "ios/chrome/browser/ui/tools_menu/public/tools_menu_configuration_provider.h"
#import "ios/chrome/browser/ui/tools_menu/public/tools_menu_presentation_provider.h"
#import "ios/chrome/browser/ui/tools_menu/tools_menu_configuration.h"
#import "ios/chrome/browser/ui/tools_menu/tools_menu_view_item.h"
#import "ios/chrome/browser/ui/translate/language_selection_coordinator.h"
#include "ios/chrome/browser/ui/ui_util.h"
#import "ios/chrome/browser/ui/uikit_ui_util.h"
#import "ios/chrome/browser/ui/util/constraints_ui_util.h"
#import "ios/chrome/browser/ui/util/named_guide.h"
#import "ios/chrome/browser/ui/util/named_guide_util.h"
#import "ios/chrome/browser/ui/util/pasteboard_util.h"
#import "ios/chrome/browser/ui/voice/text_to_speech_player.h"
#include "ios/chrome/browser/upgrade/upgrade_center.h"
#import "ios/chrome/browser/voice/voice_search_navigations_tab_helper.h"
#import "ios/chrome/browser/web/blocked_popup_tab_helper.h"
#import "ios/chrome/browser/web/error_page_content.h"
#import "ios/chrome/browser/web/external_apps_launch_policy_decider.h"
#import "ios/chrome/browser/web/load_timing_tab_helper.h"
#import "ios/chrome/browser/web/page_placeholder_tab_helper.h"
#include "ios/chrome/browser/web/print_tab_helper.h"
#import "ios/chrome/browser/web/repost_form_tab_helper.h"
#import "ios/chrome/browser/web/repost_form_tab_helper_delegate.h"
#import "ios/chrome/browser/web/sad_tab_tab_helper.h"
#import "ios/chrome/browser/web/tab_id_tab_helper.h"
#include "ios/chrome/browser/web/web_state_printer.h"
#import "ios/chrome/browser/web_state_list/web_state_list.h"
#import "ios/chrome/browser/web_state_list/web_state_opener.h"
#import "ios/chrome/browser/webui/net_export_tab_helper.h"
#import "ios/chrome/browser/webui/net_export_tab_helper_delegate.h"
#import "ios/chrome/browser/webui/show_mail_composer_context.h"
#include "ios/chrome/grit/ios_chromium_strings.h"
#include "ios/chrome/grit/ios_strings.h"
#import "ios/net/request_tracker.h"
#include "ios/public/provider/chrome/browser/chrome_browser_provider.h"
#include "ios/public/provider/chrome/browser/ui/app_rating_prompt.h"
#include "ios/public/provider/chrome/browser/ui/default_ios_web_view_factory.h"
#import "ios/public/provider/chrome/browser/voice/voice_search_bar.h"
#import "ios/public/provider/chrome/browser/voice/voice_search_bar_owner.h"
#include "ios/public/provider/chrome/browser/voice/voice_search_controller.h"
#include "ios/public/provider/chrome/browser/voice/voice_search_controller_delegate.h"
#include "ios/public/provider/chrome/browser/voice/voice_search_provider.h"
#import "ios/third_party/material_components_ios/src/components/Snackbar/src/MaterialSnackbar.h"
#include "ios/web/public/navigation_item.h"
#import "ios/web/public/navigation_manager.h"
#include "ios/web/public/referrer_util.h"
#include "ios/web/public/ssl_status.h"
#include "ios/web/public/url_scheme_util.h"
#include "ios/web/public/user_agent.h"
#include "ios/web/public/web_client.h"
#import "ios/web/public/web_state/context_menu_params.h"
#import "ios/web/public/web_state/ui/crw_native_content_provider.h"
#import "ios/web/public/web_state/ui/crw_web_view_proxy.h"
#import "ios/web/public/web_state/web_state.h"
#import "ios/web/public/web_state/web_state_delegate_bridge.h"
#include "ios/web/public/web_thread.h"
#import "ios/web/web_state/ui/crw_web_controller.h"
#import "net/base/mac/url_conversions.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/ssl/ssl_info.h"
#include "net/url_request/url_request_context_getter.h"
#include "third_party/google_toolbox_for_mac/src/iPhone/GTMUIImage+Resize.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/l10n/l10n_util_mac.h"
#include "ui/base/page_transition_types.h"
#include "url/gurl.h"

#if !defined(__has_feature) || !__has_feature(objc_arc)
#error "This file requires ARC support."
#endif

using base::UserMetricsAction;
using bookmarks::BookmarkNode;

class InfoBarContainerDelegateIOS;

namespace {

const size_t kMaxURLDisplayChars = 32 * 1024;

typedef NS_ENUM(NSInteger, ContextMenuHistogram) {
  // Note: these values must match the ContextMenuOption enum in histograms.xml.
  ACTION_OPEN_IN_NEW_TAB = 0,
  ACTION_OPEN_IN_INCOGNITO_TAB = 1,
  ACTION_COPY_LINK_ADDRESS = 2,
  ACTION_SAVE_IMAGE = 6,
  ACTION_OPEN_IMAGE = 7,
  ACTION_OPEN_IMAGE_IN_NEW_TAB = 8,
  ACTION_SEARCH_BY_IMAGE = 11,
  ACTION_OPEN_JAVASCRIPT = 21,
  ACTION_READ_LATER = 22,
  NUM_ACTIONS = 23,
};

void Record(ContextMenuHistogram action, bool is_image, bool is_link) {
  if (is_image) {
    if (is_link) {
      UMA_HISTOGRAM_ENUMERATION("ContextMenu.SelectedOption.ImageLink", action,
                                NUM_ACTIONS);
    } else {
      UMA_HISTOGRAM_ENUMERATION("ContextMenu.SelectedOption.Image", action,
                                NUM_ACTIONS);
    }
  } else {
    UMA_HISTOGRAM_ENUMERATION("ContextMenu.SelectedOption.Link", action,
                              NUM_ACTIONS);
  }
}

// Returns the status bar background color.
UIColor* StatusBarBackgroundColor() {
  return [UIColor colorWithRed:0.149 green:0.149 blue:0.164 alpha:1];
}

// Duration of the toolbar animation.
const NSTimeInterval kLegacyFullscreenControllerToolbarAnimationDuration = 0.3;

const CGFloat kVoiceSearchBarHeight = 59.0;

// Dimensions to use when downsizing an image for search-by-image.
const CGFloat kSearchByImageMaxImageArea = 90000.0;
const CGFloat kSearchByImageMaxImageWidth = 600.0;
const CGFloat kSearchByImageMaxImageHeight = 400.0;

enum HeaderBehaviour {
  // The header moves completely out of the screen.
  Hideable = 0,
  // This header stays on screen and doesn't overlap with the content.
  Visible,
  // This header stay on screen and covers part of the content.
  Overlap
};

const CGFloat kIPadFindBarOverlap = 11;

bool IsURLAllowedInIncognito(const GURL& url) {
  // Most URLs are allowed in incognito; the following is an exception.
  return !(url.SchemeIs(kChromeUIScheme) && url.host() == kChromeUIHistoryHost);
}

// Snackbar category for browser view controller.
NSString* const kBrowserViewControllerSnackbarCategory =
    @"BrowserViewControllerSnackbarCategory";

}  // namespace

#pragma mark - HeaderDefinition helper

@interface HeaderDefinition : NSObject

// The header view.
@property(nonatomic, strong) UIView* view;
// How to place the view, and its behaviour when the headers move.
@property(nonatomic, assign) HeaderBehaviour behaviour;
// Reduces the height of a header to adjust for shadows.
@property(nonatomic, assign) CGFloat heightAdjustement;
// Nudges that particular header up by this number of points.
@property(nonatomic, assign) CGFloat inset;

- (instancetype)initWithView:(UIView*)view
             headerBehaviour:(HeaderBehaviour)behaviour
            heightAdjustment:(CGFloat)heightAdjustment
                       inset:(CGFloat)inset;

+ (instancetype)definitionWithView:(UIView*)view
                   headerBehaviour:(HeaderBehaviour)behaviour
                  heightAdjustment:(CGFloat)heightAdjustment
                             inset:(CGFloat)inset;

@end

@implementation HeaderDefinition
@synthesize view = _view;
@synthesize behaviour = _behaviour;
@synthesize heightAdjustement = _heightAdjustement;
@synthesize inset = _inset;

+ (instancetype)definitionWithView:(UIView*)view
                   headerBehaviour:(HeaderBehaviour)behaviour
                  heightAdjustment:(CGFloat)heightAdjustment
                             inset:(CGFloat)inset {
  return [[self alloc] initWithView:view
                    headerBehaviour:behaviour
                   heightAdjustment:heightAdjustment
                              inset:inset];
}

- (instancetype)initWithView:(UIView*)view
             headerBehaviour:(HeaderBehaviour)behaviour
            heightAdjustment:(CGFloat)heightAdjustment
                       inset:(CGFloat)inset {
  self = [super init];
  if (self) {
    _view = view;
    _behaviour = behaviour;
    _heightAdjustement = heightAdjustment;
    _inset = inset;
  }
  return self;
}

@end

#pragma mark - BVC

@interface BrowserViewController ()<ActivityServicePresentation,
                                    AppRatingPromptDelegate,
                                    CaptivePortalDetectorTabHelperDelegate,
                                    CRWNativeContentProvider,
                                    CRWWebStateDelegate,
                                    DialogPresenterDelegate,
                                    FullscreenUIElement,
                                    InfobarContainerStateDelegate,
                                    KeyCommandsPlumbing,
                                    MainContentUI,
                                    ManageAccountsDelegate,
                                    MFMailComposeViewControllerDelegate,
                                    NetExportTabHelperDelegate,
                                    OverscrollActionsControllerDelegate,
                                    PageInfoPresentation,
                                    PasswordControllerDelegate,
                                    PreloadControllerDelegate,
                                    QRScannerPresenting,
                                    RepostFormTabHelperDelegate,
                                    SideSwipeControllerDelegate,
                                    SigninPresenter,
                                    SnapshotGeneratorDelegate,
                                    TabDialogDelegate,
                                    TabHistoryPresentation,
                                    TabModelObserver,
                                    TabStripPresentation,
                                    ToolsMenuConfigurationProvider,
                                    UIGestureRecognizerDelegate,
                                    UpgradeCenterClient,
                                    VoiceSearchBarDelegate,
                                    VoiceSearchBarOwner,
                                    WebStatePrinter> {
  // The dependency factory passed on initialization.  Used to vend objects used
  // by the BVC.
  BrowserViewControllerDependencyFactory* _dependencyFactory;

  // The browser's tab model.
  TabModel* _model;

  // Facade objects used by |_toolbarCoordinator|.
  // Must outlive |_toolbarCoordinator|.
  std::unique_ptr<ToolbarModelDelegateIOS> _toolbarModelDelegate;
  std::unique_ptr<ToolbarModel> _toolbarModel;

  // Controller for edge swipe gestures for page and tab navigation.
  SideSwipeController* _sideSwipeController;

  // Handles displaying the context menu for all form factors.
  ContextMenuCoordinator* _contextMenuCoordinator;

  // Backing object for property of the same name.
  DialogPresenter* _dialogPresenter;

  // Handles presentation of JavaScript dialogs.
  std::unique_ptr<JavaScriptDialogPresenterImpl> _javaScriptDialogPresenter;

  // Handles command dispatching.
  CommandDispatcher* _dispatcher;

  // Keyboard commands provider.  It offloads most of the keyboard commands
  // management off of the BVC.
  KeyCommandsProvider* _keyCommandsProvider;

  // Used to inject Javascript implementing the PaymentRequest API and to
  // display the UI.
  PaymentRequestManager* _paymentRequestManager;

  // Used to display the Voice Search UI.  Nil if not visible.
  scoped_refptr<VoiceSearchController> _voiceSearchController;

  // Used to display the Reading List.
  ReadingListCoordinator* _readingListCoordinator;

  // Used to display the Find In Page UI. Nil if not visible.
  FindBarControllerIOS* _findBarController;

  // Used to display the Print UI. Nil if not visible.
  PrintController* _printController;

  // Adapter to let BVC be the delegate for WebState.
  std::unique_ptr<web::WebStateDelegateBridge> _webStateDelegate;

  // YES if new tab is animating in.
  BOOL _inNewTabAnimation;

  // YES if Voice Search should be started when the new tab animation is
  // finished.
  BOOL _startVoiceSearchAfterNewTabAnimation;
  // YES if a load was cancelled due to typing in the location bar.
  BOOL _locationBarEditCancelledLoad;
  // YES if waiting for a foreground tab due to expectNewForegroundTab.
  BOOL _expectingForegroundTab;

  // Whether or not -shutdown has been called.
  BOOL _isShutdown;

  // The ChromeBrowserState associated with this BVC.
  ios::ChromeBrowserState* _browserState;  // weak

  // Whether or not Incognito* is enabled.
  BOOL _isOffTheRecord;

  // The last point within |contentArea| that's received a touch.
  CGPoint _lastTapPoint;

  // The time at which |_lastTapPoint| was most recently set.
  CFTimeInterval _lastTapTime;

  // A single infobar container handles all infobars in all tabs. It keeps
  // track of infobars for current tab (accessed via infobar helper of
  // the current tab).
  std::unique_ptr<InfoBarContainerIOS> _infoBarContainer;

  // Bridge class to deliver container change notifications to BVC.
  std::unique_ptr<InfoBarContainerDelegateIOS> _infoBarContainerDelegate;

  // TODO(crbug.com/800266): Remove this object.
  // Voice search bar at the bottom of the view overlayed on |contentArea|
  // when displaying voice search results.
  UIView<VoiceSearchBar>* _voiceSearchBar;

  // The image fetcher used to save images and perform image-based searches.
  std::unique_ptr<image_fetcher::IOSImageDataFetcherWrapper> _imageFetcher;

  // Cached pointer to the bookmarks model.
  bookmarks::BookmarkModel* _bookmarkModel;  // weak

  // The controller that shows the bookmarking UI after the user taps the star
  // button.
  BookmarkInteractionController* _bookmarkInteractionController;

  // The currently displayed "Rate This App" dialog, if one exists.
  id<AppRatingPrompt> _rateThisAppDialog;

  // Native controller vended to tab before Tab is added to the tab model.
  __weak id _temporaryNativeController;

  // Notifies the toolbar menu of reading list changes.
  ReadingListMenuNotifier* _readingListMenuNotifier;

  // Coordinator for the share menu (Activity Services).
  ActivityServiceLegacyCoordinator* _activityServiceCoordinator;

  // Coordinator for displaying alerts.
  AlertCoordinator* _alertCoordinator;

  // Coordinator for the QR scanner.
  QRScannerLegacyCoordinator* _qrScannerCoordinator;

  // Coordinator for Tab History Popup.
  LegacyTabHistoryCoordinator* _tabHistoryCoordinator;

  // Coordinator for displaying Sad Tab.
  SadTabLegacyCoordinator* _sadTabCoordinator;

  // Coordinator for Page Info UI.
  PageInfoLegacyCoordinator* _pageInfoCoordinator;

  // Coordinator for displaying Repost Form dialog.
  RepostFormCoordinator* _repostFormCoordinator;

  // Coordinator for displaying snackbars.
  SnackbarCoordinator* _snackbarCoordinator;

  ToolbarCoordinatorAdaptor* _toolbarCoordinatorAdaptor;

  // Coordinator for the toolbar.
  ToolbarCoordinator* _toolbarCoordinator;

  // The toolbar UI updater for the toolbar managed by |_toolbarCoordinator|.
  LegacyToolbarUIUpdater* _toolbarUIUpdater;

  // The main content UI updater for the content displayed by this BVC.
  MainContentUIStateUpdater* _mainContentUIUpdater;

  // The forwarder for web scroll view interation events.
  WebScrollViewMainContentUIForwarder* _webMainContentUIForwarder;

  // The updater that adjusts the toolbar's layout for fullscreen events.
  std::unique_ptr<FullscreenUIUpdater> _fullscreenUIUpdater;

  // The fullscreen disabler for the new foreground tab animation.
  std::unique_ptr<NewForegroundTabFullscreenDisabler>
      _foregroundTabAnimationFullscreenDisabler;

  // Coordinator for the External Search UI.
  ExternalSearchCoordinator* _externalSearchCoordinator;

  // Coordinator for the Download Manager UI.
  DownloadManagerCoordinator* _downloadManagerCoordinator;

  // Coordinator for presenting SKStoreProductViewController.
  StoreKitCoordinator* _storeKitCoordinator;

  // Coordinator for the language selection UI.
  LanguageSelectionCoordinator* _languageSelectionCoordinator;

  // Coordinator for the PassKit UI presentation.
  PassKitCoordinator* _passKitCoordinator;

  // Coordinator for UI related to launching external apps.
  AppLauncherCoordinator* _appLauncherCoordinator;

  // Fake status bar view used to blend the toolbar into the status bar.
  UIView* _fakeStatusBarView;

  // Stores whether the Tab currently inserted was a pre-rendered Tab. This
  // is used to determine whether the pre-rendering animation should be played
  // or not.
  BOOL _insertedTabWasPrerenderedTab;

  // View Controller for container view.
  BrowserContainerViewController* _browserContainerViewController;
}

// The browser's side swipe controller.  Lazily instantiated on the first call.
@property(nonatomic, strong, readonly) SideSwipeController* sideSwipeController;
// The dialog presenter for this BVC's tab model.
@property(nonatomic, strong, readonly) DialogPresenter* dialogPresenter;
// The object that manages keyboard commands on behalf of the BVC.
@property(nonatomic, strong, readonly) KeyCommandsProvider* keyCommandsProvider;
// Whether the current tab can enable the request desktop menu item.
@property(nonatomic, assign, readonly) BOOL canUseDesktopUserAgent;
// Whether the sharing menu should be enabled.
@property(nonatomic, assign, readonly) BOOL canShowShareMenu;
// Helper method to check web controller canShowFindBar method.
@property(nonatomic, assign, readonly) BOOL canShowFindBar;
// Whether the controller's view is currently available.
// YES from viewWillAppear to viewWillDisappear.
@property(nonatomic, assign, getter=isVisible) BOOL visible;
// Whether the controller's view is currently visible.
// YES from viewDidAppear to viewWillDisappear.
@property(nonatomic, assign) BOOL viewVisible;
// Whether the controller should broadcast its UI.
@property(nonatomic, assign, getter=isBroadcasting) BOOL broadcasting;
// Whether the controller is currently dismissing a presented view controller.
@property(nonatomic, assign, getter=isDismissingModal) BOOL dismissingModal;
// Returns YES if the toolbar has not been scrolled out by fullscreen.
@property(nonatomic, assign, readonly, getter=isToolbarOnScreen)
    BOOL toolbarOnScreen;
// Whether a new tab animation is occurring.
@property(nonatomic, assign, getter=isInNewTabAnimation) BOOL inNewTabAnimation;
// Whether BVC prefers to hide the status bar. This value is used to determine
// the response from the |prefersStatusBarHidden| method.
@property(nonatomic, assign) BOOL hideStatusBar;
// Whether the VoiceSearchBar should be displayed.
@property(nonatomic, readonly) BOOL shouldShowVoiceSearchBar;
// Coordinator for displaying a modal overlay with activity indicator to prevent
// the user from interacting with the browser view.
@property(nonatomic, strong)
    ActivityOverlayCoordinator* activityOverlayCoordinator;
// A block to be run when the |tabWasAdded:| method completes the animation
// for the presentation of a new tab. Can be used to record performance metrics.
@property(nonatomic, strong, nullable)
    ProceduralBlock foregroundTabWasAddedCompletionBlock;
// Coordinator for Recent Tabs.
@property(nonatomic, strong) ChromeCoordinator* recentTabsCoordinator;
// Coordinator for tablet tab strip.
@property(nonatomic, strong) TabStripLegacyCoordinator* tabStripCoordinator;
// A weak reference to the view of the tab strip on tablet.
@property(nonatomic, weak) UIView* tabStripView;
// Helper for saving images.
@property(nonatomic, strong) ImageSaver* imageSaver;
// Helper for the bvc.
@property(nonatomic, strong) BrowserViewControllerHelper* helper;

// The user agent type used to load the currently visible page. User agent
// type is NONE if there is no visible page or visible page is a native
// page.
@property(nonatomic, assign, readonly) web::UserAgentType userAgentType;

// Returns the header views, all the chrome on top of the page, including the
// ones that cannot be scrolled off screen by full screen.
@property(nonatomic, strong, readonly) NSArray<HeaderDefinition*>* headerViews;

// Coordinator for the popup menus.
@property(nonatomic, strong) PopupMenuCoordinator* popupMenuCoordinator;

// Used to display the new tab tip in-product help promotion bubble. |nil| if
// the new tab tip bubble has not yet been presented. Once the bubble is
// dismissed, it remains allocated so that |userEngaged| remains accessible.
@property(nonatomic, strong)
    BubbleViewControllerPresenter* tabTipBubblePresenter;
// Used to display the new incognito tab tip in-product help promotion bubble.
@property(nonatomic, strong)
    BubbleViewControllerPresenter* incognitoTabTipBubblePresenter;

// Primary toolbar.
@property(nonatomic, strong) id<PrimaryToolbarCoordinator>
    primaryToolbarCoordinator;
// Secondary toolbar.
@property(nonatomic, strong)
    AdaptiveToolbarCoordinator* secondaryToolbarCoordinator;
// Interface object with the toolbars.
@property(nonatomic, strong) id<ToolbarCoordinating> toolbarInterface;

// Vertical offset for the primary toolbar, used for fullscreen.
@property(nonatomic, strong) NSLayoutConstraint* primaryToolbarOffsetConstraint;
// Height constraint for the primary toolbar.
@property(nonatomic, strong) NSLayoutConstraint* primaryToolbarHeightConstraint;
// Height constraint for the secondary toolbar.
@property(nonatomic, strong)
    NSLayoutConstraint* secondaryToolbarHeightConstraint;
// Height constraint for the frame the secondary toolbar would have if
// fullscreen was disabled.
@property(nonatomic, strong)
    NSLayoutConstraint* secondaryToolbarNoFullscreenHeightConstraint;
// Current Fullscreen progress for the footers.
@property(nonatomic, assign) CGFloat footerFullscreenProgress;
// Y-dimension offset for placement of the header.
@property(nonatomic, readonly) CGFloat headerOffset;
// Height of the header view for the tab model's current tab.
@property(nonatomic, readonly) CGFloat headerHeight;

// The webState of the active tab.
@property(nonatomic, readonly) web::WebState* currentWebState;

// BVC initialization
// ------------------
// If the BVC is initialized with a valid browser state & tab model immediately,
// the path is straightforward: functionality is enabled, and the UI is built
// when -viewDidLoad is called.
// If the BVC is initialized without a browser state or tab model, the tab model
// and browser state may or may not be provided before -viewDidLoad is called.
// In most cases, they will not, to improve startup performance.
// In order to handle this, initialization of various aspects of BVC have been
// broken out into the following functions, which have expectations (enforced
// with DCHECKs) regarding |_browserState|, |_model|, and [self isViewLoaded].

// Updates non-view-related functionality with the given browser state and tab
// model.
// Does not matter whether or not the view has been loaded.
- (void)updateWithTabModel:(TabModel*)model
              browserState:(ios::ChromeBrowserState*)browserState;
// On iOS7, iPad should match iOS6 status bar.  Install a simple black bar under
// the status bar to mimic this layout.
- (void)installFakeStatusBar;
// Builds the UI parts of tab strip and the toolbar.  Does not matter whether
// or not browser state and tab model are valid.
- (void)buildToolbarAndTabStrip;
// Sets up the constraints on the toolbar.
- (void)addConstraintsToToolbar;
// Updates view-related functionality with the given tab model and browser
// state. The view must have been loaded.  Uses |_browserState| and |_model|.
- (void)addUIFunctionalityForModelAndBrowserState;
// Sets the correct frame and hierarchy for subviews and helper views.  Only
// insert views on |initialLayout|.
- (void)setUpViewLayout:(BOOL)initialLayout;
// Makes |tab| the currently visible tab, displaying its view.
- (void)displayTab:(Tab*)tab;
// Initializes the bookmark interaction controller if not already initialized.
- (void)initializeBookmarkInteractionController;
// Installs the BVC as overscroll actions controller of |nativeContent| if
// needed. Sets the style of the overscroll actions toolbar.
- (void)setOverScrollActionControllerToStaticNativeContent:
    (StaticHtmlNativeContent*)nativeContent;

// UI Configuration, update and Layout
// -----------------------------------
// Updates the toolbar display based on the current tab.
- (void)updateToolbar;
// Starts or stops broadcasting the toolbar UI and main content UI depending on
// whether the BVC is visible and active.
- (void)updateBroadcastState;
// Updates |dialogPresenter|'s |active| property to account for the BVC's
// |active|, |visible|, and |inNewTabAnimation| properties.
- (void)updateDialogPresenterActiveState;
// Dismisses popups and modal dialogs that are displayed above the BVC upon size
// changes (e.g. rotation, resizing,…) or when the accessibility escape gesture
// is performed.
// TODO(crbug.com/522721): Support size changes for all popups and modal
// dialogs.
- (void)dismissPopups;
// Returns whether |tab| is scrolled to the top.
- (BOOL)isTabScrolledToTop:(Tab*)tab;
// Returns the footer view if one exists (e.g. the voice search bar).
- (UIView*)footerView;
// Returns the header height needed for |tab|.
- (CGFloat)headerHeightForTab:(Tab*)tab;
// Sets the frame for the headers.
- (void)setFramesForHeaders:(NSArray<HeaderDefinition*>*)headers
                   atOffset:(CGFloat)headerOffset;
// Adds a CardView on top of the contentArea either taking the size of the full
// screen or just the size of the space under the header.
// Returns the CardView that was added.
- (CardView*)addCardViewInFullscreen:(BOOL)fullScreen;

// Showing and Dismissing child UI
// -------------------------------
// Dismisses the "rate this app" dialog.
- (void)dismissRateThisAppDialog;

// Bubble Views
// ------------
// Returns a bubble associated with an in-product help promotion if
// it is valid to show the promotion and |nil| otherwise. |feature| is the
// base::Feature object associated with the given promotion. |direction| is the
// direction the bubble's arrow is pointing. |alignment| is the alignment of the
// arrow on the button. |text| is the text displayed by the bubble. This method
// requires that |self.browserState| is not NULL.
- (BubbleViewControllerPresenter*)
bubblePresenterForFeature:(const base::Feature&)feature
                direction:(BubbleArrowDirection)direction
                alignment:(BubbleAlignment)alignment
                     text:(NSString*)text;

// Waits to present a bubble associated with the new tab tip in-product help
// promotion until the feature engagement tracker database is fully initialized.
// Does not present the bubble if |tabTipBubblePresenter.userEngaged| is |YES|
// to prevent resetting |tabTipBubblePresenter| and affecting the value of
// |userEngaged|. Does not present the bubble if the feature engagement tracker
// determines it is not valid to present it. This method requires that
// |self.browserState| is not NULL.
- (void)presentNewTabTipBubbleOnInitialized;
// Optionally presents a bubble associated with the new tab tip in-product help
// promotion. If the feature engagement tracker determines it is valid to show
// the new tab tip, then it initializes |tabTipBubblePresenter| and presents
// the bubble. If it is not valid to show the new tab tip,
// |tabTipBubblePresenter| is set to |nil| and no bubble is shown. This method
// requires that |self.browserState| is not NULL.
- (void)presentNewTabTipBubble;
// Waits to present a bubble associated with the new incognito tab tip
// in-product help promotion until the feature engagement tracker database is
// fully initialized. This method requires that |self.browserState| is
// not NULL.
- (void)presentNewIncognitoTabTipBubbleOnInitialized;
// Presents a bubble associated with the new incognito tab tip in-product help
// promotion. This method requires that |self.browserState| is not NULL.
- (void)presentNewIncognitoTabTipBubble;

// Find Bar UI
// -----------
// Update find bar with model data. If |shouldFocus| is set to YES, the text
// field will become first responder.
- (void)updateFindBar:(BOOL)initialUpdate shouldFocus:(BOOL)shouldFocus;
// Hide find bar.
- (void)hideFindBarWithAnimation:(BOOL)animate;
// Shows find bar. If |selectText| is YES, all text inside the Find Bar
// textfield will be selected. If |shouldFocus| is set to YES, the textfield is
// set to be first responder.
- (void)showFindBarWithAnimation:(BOOL)animate
                      selectText:(BOOL)selectText
                     shouldFocus:(BOOL)shouldFocus;
// Redisplays the find bar if necessary furing a view controller size change,
// using the transition coordinator |coordinator|.
- (void)reshowFindBarIfNeededWithCoordinator:
    (id<UIViewControllerTransitionCoordinator>)coordinator;

// Alerts
// ------
// Shows a self-dismissing snackbar displaying |message|.
- (void)showSnackbar:(NSString*)message;
// Shows an alert dialog with |title| and |message|.
- (void)showErrorAlertWithStringTitle:(NSString*)title
                              message:(NSString*)message;

// Tap Handling
// ------------
// Record the last tap point based on the |originPoint| (if any) passed in
// |command|.
- (void)setLastTapPoint:(OpenNewTabCommand*)command;
// Returns the last stored |_lastTapPoint| if it's been set within the past
// second.
- (CGPoint)lastTapPoint;
// Store the tap CGPoint in |_lastTapPoint| and the current timestamp.
- (void)saveContentAreaTapLocation:(UIGestureRecognizer*)gestureRecognizer;

// Tab creation and selection
// --------------------------
// Called when either a tab finishes loading or when a tab with finished content
// is added directly to the model via pre-rendering. The tab must be non-nil and
// must be a member of the tab model controlled by this BrowserViewController.
- (void)tabLoadComplete:(Tab*)tab withSuccess:(BOOL)success;
// Adds a new tab with |url| and |postData| at the end of the model, and make it
// the selected tab and return it.
- (Tab*)addSelectedTabWithURL:(const GURL&)url
                     postData:(TemplateURLRef::PostContent*)postData
                   transition:(ui::PageTransition)transition;
// Internal method that all of the similar public and private methods call.
// Adds a new tab with |url| and |postData| (if not null) at |position| in the
// tab model (or at the end if |position is NSNotFound|, with |transition| as
// the page transition type. If |tabAddedCompletion| is nonnull, it's called
// synchronously after the tab is added.
- (Tab*)addSelectedTabWithURL:(const GURL&)url
                     postData:(TemplateURLRef::PostContent*)postData
                      atIndex:(NSUInteger)position
                   transition:(ui::PageTransition)transition
           tabAddedCompletion:(ProceduralBlock)tabAddedCompletion;
// Whether the given tab's URL is an application specific URL.
- (BOOL)isTabNativePage:(Tab*)tab;
// Returns the view to use when animating a page in or out, positioning it to
// fill the content area but not actually adding it to the view hierarchy.
- (UIImageView*)pageOpenCloseAnimationView;
// Add all delegates to the provided |tab|.
- (void)installDelegatesForTab:(Tab*)tab;
// Remove delegates from the provided |tab|.
- (void)uninstallDelegatesForTab:(Tab*)tab;
// Called when a tab is selected in the model. Make any required view changes.
// The notification will not be sent when the tab is already the selected tab.
// |notifyToolbar| indicates whether the toolbar is notified that the tab has
// changed.
- (void)tabSelected:(Tab*)tab notifyToolbar:(BOOL)notifyToolbar;
// Returns the native controller being used by |tab|'s web controller.
- (id)nativeControllerForTab:(Tab*)tab;

// Voice Search
// ------------
// Lazily instantiates |_voiceSearchController|.
- (void)ensureVoiceSearchControllerCreated;
// Lazily instantiates |_voiceSearchBar| and adds it to the view.
- (void)ensureVoiceSearchBarCreated;
// Shows/hides the voice search bar.
- (void)updateVoiceSearchBarVisibilityAnimated:(BOOL)animated;

// Reading List
// ------------
// Adds the given url to the reading list.
- (void)addToReadingListURL:(const GURL&)URL title:(NSString*)title;

// Recent Tabs
// ------------
// Creates the right RecentTabs Coordinator, once we stop supporting the legacy
// implementation we can delete this method and start the coordinator on
// |showRecentTabs|.
- (void)createRecentTabsCoordinator;

@end

@implementation BrowserViewController
// Public synthesized propeties.
@synthesize typingShield = _typingShield;
@synthesize active = _active;
// Private synthesized properties
@synthesize visible = _visible;
@synthesize viewVisible = _viewVisible;
@synthesize broadcasting = _broadcasting;
@synthesize dismissingModal = _dismissingModal;
@synthesize hideStatusBar = _hideStatusBar;
@synthesize activityOverlayCoordinator = _activityOverlayCoordinator;
@synthesize foregroundTabWasAddedCompletionBlock =
    _foregroundTabWasAddedCompletionBlock;
@synthesize recentTabsCoordinator = _recentTabsCoordinator;
@synthesize tabStripCoordinator = _tabStripCoordinator;
@synthesize tabStripView = _tabStripView;
@synthesize popupMenuCoordinator = _popupMenuCoordinator;
@synthesize tabTipBubblePresenter = _tabTipBubblePresenter;
@synthesize incognitoTabTipBubblePresenter = _incognitoTabTipBubblePresenter;
@synthesize primaryToolbarCoordinator = _primaryToolbarCoordinator;
@synthesize secondaryToolbarCoordinator = _secondaryToolbarCoordinator;
@synthesize primaryToolbarOffsetConstraint = _primaryToolbarOffsetConstraint;
@synthesize primaryToolbarHeightConstraint = _primaryToolbarHeightConstraint;
@synthesize secondaryToolbarHeightConstraint =
    _secondaryToolbarHeightConstraint;
@synthesize secondaryToolbarNoFullscreenHeightConstraint =
    _secondaryToolbarNoFullscreenHeightConstraint;
@synthesize footerFullscreenProgress = _footerFullscreenProgress;
@synthesize toolbarInterface = _toolbarInterface;
@synthesize imageSaver = _imageSaver;
@synthesize helper = _helper;
// DialogPresenterDelegate property
@synthesize dialogPresenterDelegateIsPresenting =
    _dialogPresenterDelegateIsPresenting;

#pragma mark - Object lifecycle

- (instancetype)
          initWithTabModel:(TabModel*)model
              browserState:(ios::ChromeBrowserState*)browserState
         dependencyFactory:(BrowserViewControllerDependencyFactory*)factory
applicationCommandEndpoint:(id<ApplicationCommands>)applicationCommandEndpoint {
  self = [super initWithNibName:nil bundle:base::mac::FrameworkBundle()];
  if (self) {
    DCHECK(factory);

    _dependencyFactory = factory;
    _dialogPresenter = [[DialogPresenter alloc] initWithDelegate:self
                                        presentingViewController:self];
    _dispatcher = [[CommandDispatcher alloc] init];
    [_dispatcher startDispatchingToTarget:self
                              forProtocol:@protocol(UrlLoader)];
    [_dispatcher startDispatchingToTarget:self
                              forProtocol:@protocol(BrowserCommands)];
    [_dispatcher startDispatchingToTarget:applicationCommandEndpoint
                              forProtocol:@protocol(ApplicationCommands)];
    // -startDispatchingToTarget:forProtocol: doesn't pick up protocols the
    // passed protocol conforms to, so ApplicationSettingsCommands is explicitly
    // dispatched to the endpoint as well. Since this is potentially
    // fragile, DCHECK that it should still work (if the endpoint is nonnull).
    DCHECK(!applicationCommandEndpoint ||
           [applicationCommandEndpoint
               conformsToProtocol:@protocol(ApplicationSettingsCommands)]);
    [_dispatcher
        startDispatchingToTarget:applicationCommandEndpoint
                     forProtocol:@protocol(ApplicationSettingsCommands)];
    // -startDispatchingToTarget:forProtocol: doesn't pick up protocols the
    // passed protocol conforms to, so BrowsingDataCommands is explicitly
    // dispatched to the endpoint as well. Since this is potentially
    // fragile, DCHECK that it should still work (if the endpoint is nonnull).
    DCHECK(!applicationCommandEndpoint ||
           [applicationCommandEndpoint
               conformsToProtocol:@protocol(BrowsingDataCommands)]);
    [_dispatcher startDispatchingToTarget:applicationCommandEndpoint
                              forProtocol:@protocol(BrowsingDataCommands)];

    _snackbarCoordinator = [[SnackbarCoordinator alloc] init];
    _snackbarCoordinator.dispatcher = _dispatcher;
    [_snackbarCoordinator start];

    _storeKitCoordinator =
        [[StoreKitCoordinator alloc] initWithBaseViewController:self];

    _languageSelectionCoordinator =
        [[LanguageSelectionCoordinator alloc] initWithBaseViewController:self];
    _languageSelectionCoordinator.presenter =
        [[VerticalAnimationContainer alloc] init];

    _passKitCoordinator =
        [[PassKitCoordinator alloc] initWithBaseViewController:self];

    // DownloadManagerCoordinator must be created before
    // DownloadManagerTabHelper.
    _downloadManagerCoordinator =
        [[DownloadManagerCoordinator alloc] initWithBaseViewController:self];
    _downloadManagerCoordinator.presenter =
        [[VerticalAnimationContainer alloc] init];

    _appLauncherCoordinator =
        [[AppLauncherCoordinator alloc] initWithBaseViewController:self];

    _javaScriptDialogPresenter.reset(
        new JavaScriptDialogPresenterImpl(_dialogPresenter));
    _webStateDelegate.reset(new web::WebStateDelegateBridge(self));
    // TODO(leng): Delay this.
    [[UpgradeCenter sharedInstance] registerClient:self
                                    withDispatcher:self.dispatcher];
    _inNewTabAnimation = NO;

    _footerFullscreenProgress = 1.0;

    if (model && browserState)
      [self updateWithTabModel:model browserState:browserState];
  }
  return self;
}

- (instancetype)initWithNibName:(NSString*)nibNameOrNil
                         bundle:(NSBundle*)nibBundleOrNil {
  NOTREACHED();
  return nil;
}

- (instancetype)initWithCoder:(NSCoder*)aDecoder {
  NOTREACHED();
  return nil;
}

- (void)dealloc {
  DCHECK(_isShutdown) << "-shutdown must be called before dealloc.";
}

#pragma mark - Public Properties

- (id<ApplicationCommands,
      BrowserCommands,
      OmniboxFocuser,
      PopupMenuCommands,
      FakeboxFocuser,
      SnackbarCommands,
      ToolbarCommands,
      UrlLoader>)dispatcher {
  return static_cast<id<ApplicationCommands, BrowserCommands, OmniboxFocuser,
                        PopupMenuCommands, FakeboxFocuser, SnackbarCommands,
                        ToolbarCommands, UrlLoader>>(_dispatcher);
}

- (UIView*)contentArea {
  return _browserContainerViewController.view;
}

- (void)setActive:(BOOL)active {
  if (_active == active) {
    return;
  }
  _active = active;

  // If not active, display an activity indicator overlay over the view to
  // prevent interaction with the web page.
  // TODO(crbug.com/637093): This coordinator should be managed by the
  // coordinator used to present BrowserViewController, when implemented.
  if (active) {
    [self.activityOverlayCoordinator stop];
    self.activityOverlayCoordinator = nil;
  } else if (!self.activityOverlayCoordinator) {
    self.activityOverlayCoordinator =
        [[ActivityOverlayCoordinator alloc] initWithBaseViewController:self];
    [self.activityOverlayCoordinator start];
  }

  if (_browserState) {
    ActiveStateManager* active_state_manager =
        ActiveStateManager::FromBrowserState(_browserState);
    active_state_manager->SetActive(active);
  }

  [_model setWebUsageEnabled:active];
  [self updateDialogPresenterActiveState];
  [self updateBroadcastState];

  if (active) {
    // Make sure the tab (if any; it's possible to get here without a current
    // tab if the caller is about to create one) ends up on screen completely.
    Tab* currentTab = [_model currentTab];
    // Force loading the view in case it was not loaded yet.
    [self loadViewIfNeeded];
    if (currentTab && _expectingForegroundTab) {
      PagePlaceholderTabHelper::FromWebState(currentTab.webState)
          ->AddPlaceholderForNextNavigation();
    }
    if (currentTab)
      [self displayTab:currentTab];
  } else {
    [_dialogPresenter cancelAllDialogs];
  }
  [_paymentRequestManager enablePaymentRequest:active];

  [self setNeedsStatusBarAppearanceUpdate];
}

- (BOOL)isPlayingTTS {
  return _voiceSearchController && _voiceSearchController->IsPlayingAudio();
}

- (TabModel*)tabModel {
  return _model;
}

- (ios::ChromeBrowserState*)browserState {
  return _browserState;
}

#pragma mark - Private Properties

- (SideSwipeController*)sideSwipeController {
  if (!_sideSwipeController) {
    _sideSwipeController =
        [[SideSwipeController alloc] initWithTabModel:_model
                                         browserState:_browserState];
    [_sideSwipeController setSnapshotDelegate:self];
    _sideSwipeController.toolbarInteractionHandler = self.toolbarInterface;
    _sideSwipeController.primaryToolbarSnapshotProvider =
        self.primaryToolbarCoordinator;
    _sideSwipeController.secondaryToolbarSnapshotProvider =
        self.secondaryToolbarCoordinator;
    [_sideSwipeController setSwipeDelegate:self];
    [_sideSwipeController setTabStripDelegate:self.tabStripCoordinator];
  }
  return _sideSwipeController;
}

- (DialogPresenter*)dialogPresenter {
  return _dialogPresenter;
}

- (KeyCommandsProvider*)keyCommandsProvider {
  if (!_keyCommandsProvider) {
    _keyCommandsProvider = [_dependencyFactory newKeyCommandsProvider];
  }
  return _keyCommandsProvider;
}

- (BOOL)canUseDesktopUserAgent {
  Tab* tab = [_model currentTab];
  if ([self isTabNativePage:tab])
    return NO;

  // If |useDesktopUserAgent| is |NO|, allow useDesktopUserAgent.
  return !tab.usesDesktopUserAgent;
}

// Whether the sharing menu should be shown.
- (BOOL)canShowShareMenu {
  const GURL& URL = [_model currentTab].webState->GetLastCommittedURL();
  return URL.is_valid() && !web::GetWebClient()->IsAppSpecificURL(URL);
}

- (BOOL)canShowFindBar {
  // Make sure web controller can handle find in page.
  Tab* tab = [_model currentTab];
  if (!tab) {
    return NO;
  }

  auto* helper = FindTabHelper::FromWebState(tab.webState);
  return (helper && helper->CurrentPageSupportsFindInPage() &&
          !helper->IsFindUIActive());
}

- (web::UserAgentType)userAgentType {
  web::WebState* webState = [_model currentTab].webState;
  if (!webState)
    return web::UserAgentType::NONE;
  web::NavigationItem* visibleItem =
      webState->GetNavigationManager()->GetVisibleItem();
  if (!visibleItem)
    return web::UserAgentType::NONE;

  return visibleItem->GetUserAgentType();
}

- (void)setVisible:(BOOL)visible {
  if (_visible == visible)
    return;

  _visible = visible;
}

- (void)setViewVisible:(BOOL)viewVisible {
  if (_viewVisible == viewVisible)
    return;
  _viewVisible = viewVisible;
  self.visible = viewVisible;
  [self updateDialogPresenterActiveState];
  [self updateBroadcastState];
}

- (void)setBroadcasting:(BOOL)broadcasting {
  if (_broadcasting == broadcasting)
    return;
  _broadcasting = broadcasting;
  // TODO(crbug.com/790886): Use the Browser's broadcaster once Browsers are
  // supported.
  FullscreenController* fullscreenController =
      FullscreenControllerFactory::GetInstance()->GetForBrowserState(
          _browserState);
  ChromeBroadcaster* broadcaster = fullscreenController->broadcaster();
  if (_broadcasting) {
    _toolbarUIUpdater = [[LegacyToolbarUIUpdater alloc]
        initWithToolbarUI:[[ToolbarUIState alloc] init]
             toolbarOwner:self
             webStateList:[_model webStateList]];
    [_toolbarUIUpdater startUpdating];
    StartBroadcastingToolbarUI(_toolbarUIUpdater.toolbarUI, broadcaster);

    _mainContentUIUpdater = [[MainContentUIStateUpdater alloc]
        initWithState:[[MainContentUIState alloc] init]];
    _webMainContentUIForwarder = [[WebScrollViewMainContentUIForwarder alloc]
        initWithUpdater:_mainContentUIUpdater
           webStateList:[_model webStateList]];
    StartBroadcastingMainContentUI(self, broadcaster);

    fullscreenController->AddObserver(_fullscreenUIUpdater.get());
    [self updateForFullscreenProgress:fullscreenController->GetProgress()];
  } else {
    StopBroadcastingToolbarUI(broadcaster);
    StopBroadcastingMainContentUI(broadcaster);
    [_toolbarUIUpdater stopUpdating];
    _toolbarUIUpdater = nil;
    _mainContentUIUpdater = nil;
    [_webMainContentUIForwarder disconnect];
    _webMainContentUIForwarder = nil;

    fullscreenController->RemoveObserver(_fullscreenUIUpdater.get());
  }
}

- (BOOL)isToolbarOnScreen {
  return self.headerHeight - [self currentHeaderOffset] > 0;
}

- (void)setInNewTabAnimation:(BOOL)inNewTabAnimation {
  if (_inNewTabAnimation == inNewTabAnimation)
    return;
  _inNewTabAnimation = inNewTabAnimation;
  [self updateDialogPresenterActiveState];
  [self updateBroadcastState];
}

- (BOOL)isInNewTabAnimation {
  return _inNewTabAnimation;
}

- (BOOL)shouldShowVoiceSearchBar {
  // On iPads, the voice search bar should only be shown for regular horizontal
  // size class configurations.  It should always be shown for voice search
  // results Tabs on iPhones, including configurations with regular horizontal
  // size classes (i.e. landscape iPhone 6 Plus).
  BOOL compactWidth = self.traitCollection.horizontalSizeClass ==
                      UIUserInterfaceSizeClassCompact;
  return self.tabModel.currentTab.isVoiceSearchResultsTab &&
         (!IsIPadIdiom() || compactWidth);
}

- (void)setHideStatusBar:(BOOL)hideStatusBar {
  if (_hideStatusBar == hideStatusBar)
    return;
  _hideStatusBar = hideStatusBar;
  [self setNeedsStatusBarAppearanceUpdate];
}

- (NSArray<HeaderDefinition*>*)headerViews {
  NSMutableArray<HeaderDefinition*>* results = [[NSMutableArray alloc] init];
  if (![self isViewLoaded])
    return results;

  if (!IsIPadIdiom()) {
    if (self.primaryToolbarCoordinator.viewController.view) {
      [results addObject:[HeaderDefinition
                             definitionWithView:self.primaryToolbarCoordinator
                                                    .viewController.view
                                headerBehaviour:Hideable
                               heightAdjustment:0.0
                                          inset:0.0]];
    }
  } else {
    if (self.tabStripView) {
      [results addObject:[HeaderDefinition definitionWithView:self.tabStripView
                                              headerBehaviour:Hideable
                                             heightAdjustment:0.0
                                                        inset:0.0]];
    }
    if (self.primaryToolbarCoordinator.viewController.view) {
      [results addObject:[HeaderDefinition
                             definitionWithView:self.primaryToolbarCoordinator
                                                    .viewController.view
                                headerBehaviour:Hideable
                               heightAdjustment:0.0
                                          inset:0.0]];
    }
    if ([_findBarController view]) {
      [results addObject:[HeaderDefinition
                             definitionWithView:[_findBarController view]
                                headerBehaviour:Overlap
                               heightAdjustment:0.0
                                          inset:kIPadFindBarOverlap]];
    }
  }
  return [results copy];
}

- (CGFloat)headerOffset {
  if (IsIPadIdiom())
    return StatusBarHeight();
  return 0.0;
}

- (CGFloat)headerHeight {
  return [self headerHeightForTab:[_model currentTab]];
}

- (web::WebState*)currentWebState {
  return [[_model currentTab] webState];
}

#pragma mark - Public methods

- (void)setPrimary:(BOOL)primary {
  [_model setPrimary:primary];
  if (primary) {
    [self updateDialogPresenterActiveState];
    [self updateBroadcastState];
  } else {
    self.dialogPresenter.active = false;
  }
}

- (void)shieldWasTapped:(id)sender {
  [self.dispatcher cancelOmniboxEdit];
}

- (void)userEnteredTabSwitcher {
  if ([self.tabTipBubblePresenter isUserEngaged]) {
    base::RecordAction(UserMetricsAction("NewTabTipTargetSelected"));
  }
}

- (void)presentBubblesIfEligible {
  [self presentNewTabTipBubbleOnInitialized];
  [self presentNewIncognitoTabTipBubbleOnInitialized];
}

- (void)browserStateDestroyed {
  [self setActive:NO];
  [_paymentRequestManager close];
  _paymentRequestManager = nil;
  [_model browserStateDestroyed];

  FullscreenController* fullscreenController =
      FullscreenControllerFactory::GetInstance()->GetForBrowserState(
          _browserState);
  _foregroundTabAnimationFullscreenDisabler->Disconnect();
  _foregroundTabAnimationFullscreenDisabler = nullptr;
  fullscreenController->RemoveObserver(_fullscreenUIUpdater.get());
  _fullscreenUIUpdater = nullptr;
  fullscreenController->SetWebStateList(nullptr);

  // Disconnect child coordinators.
  [_activityServiceCoordinator disconnect];
  [_qrScannerCoordinator disconnect];
  [_tabHistoryCoordinator disconnect];
  [self.popupMenuCoordinator stop];
  [_pageInfoCoordinator disconnect];
  [_externalSearchCoordinator disconnect];
  [self.tabStripCoordinator stop];
  self.tabStripCoordinator = nil;
  self.tabStripView = nil;

  _browserState = nullptr;
  [_dispatcher stopDispatchingToTarget:self];
  _dispatcher = nil;
}

- (Tab*)addSelectedTabWithURL:(const GURL&)url
                   transition:(ui::PageTransition)transition {
  return [self addSelectedTabWithURL:url
                             atIndex:[_model count]
                          transition:transition];
}

- (Tab*)addSelectedTabWithURL:(const GURL&)url
                      atIndex:(NSUInteger)position
                   transition:(ui::PageTransition)transition {
  return [self addSelectedTabWithURL:url
                             atIndex:position
                          transition:transition
                  tabAddedCompletion:nil];
}

- (Tab*)addSelectedTabWithURL:(const GURL&)url
                      atIndex:(NSUInteger)position
                   transition:(ui::PageTransition)transition
           tabAddedCompletion:(ProceduralBlock)tabAddedCompletion {
  return [self addSelectedTabWithURL:url
                            postData:NULL
                             atIndex:position
                          transition:transition
                  tabAddedCompletion:tabAddedCompletion];
}

- (void)expectNewForegroundTab {
  _expectingForegroundTab = YES;
}

- (void)startVoiceSearch {
  // Delay Voice Search until new tab animations have finished.
  if (self.inNewTabAnimation) {
    _startVoiceSearchAfterNewTabAnimation = YES;
    return;
  }

  // Keyboard shouldn't overlay the ecoutez window, so dismiss find in page and
  // dismiss the keyboard.
  [self closeFindInPage];
  [[_model currentTab].webController dismissKeyboard];

  // Ensure that voice search objects are created.
  [self ensureVoiceSearchControllerCreated];
  [self ensureVoiceSearchBarCreated];

  // Present voice search.
  [_voiceSearchBar prepareToPresentVoiceSearch];
  _voiceSearchController->StartRecognition(self, [_model currentTab]);
  [self.dispatcher cancelOmniboxEdit];
}

- (void)clearPresentedStateWithCompletion:(ProceduralBlock)completion
                           dismissOmnibox:(BOOL)dismissOmnibox {
  [_activityServiceCoordinator cancelShare];
  [_bookmarkInteractionController dismissBookmarkModalControllerAnimated:NO];
  [_bookmarkInteractionController dismissSnackbar];
  if (dismissOmnibox) {
    [self.dispatcher cancelOmniboxEdit];
  }
  [_dialogPresenter cancelAllDialogs];
  [self.dispatcher hidePageInfo];
  [self.tabTipBubblePresenter dismissAnimated:NO];
  [self.incognitoTabTipBubblePresenter dismissAnimated:NO];
  if (_voiceSearchController)
    _voiceSearchController->DismissMicPermissionsHelp();

  Tab* currentTab = [_model currentTab];
  [currentTab dismissModals];

  if (currentTab) {
    auto* findHelper = FindTabHelper::FromWebState(currentTab.webState);
    if (findHelper) {
      findHelper->StopFinding(^{
        [self updateFindBar:NO shouldFocus:NO];
      });
    }
  }

  [_paymentRequestManager cancelRequest];
  [_printController dismissAnimated:YES];
  _printController = nil;
  if (IsUIRefreshPhase1Enabled()) {
    [self.dispatcher dismissPopupMenuAnimated:NO];
  } else {
    [self.dispatcher dismissToolsMenu];
    [_tabHistoryCoordinator dismissHistoryPopup];
  }
  [_contextMenuCoordinator stop];
  [self dismissRateThisAppDialog];

  if (self.presentedViewController) {
    // Dismisses any other modal controllers that may be present, e.g. Recent
    // Tabs.
    //
    // Note that currently, some controllers like the bookmark ones were already
    // dismissed (in this example in -dismissBookmarkModalControllerAnimated:),
    // but are still reported as the presentedViewController.  Calling
    // |dismissViewControllerAnimated:completion:| again would dismiss the BVC
    // itself, so instead check the value of |self.dismissingModal| and only
    // call dismiss if one of the above calls has not already triggered a
    // dismissal.
    //
    // To ensure the completion is called, nil is passed to the call to dismiss,
    // and the completion is called explicitly below.
    if (!TabSwitcherPresentsBVCEnabled() || !self.dismissingModal) {
      [self dismissViewControllerAnimated:NO completion:nil];
    }
    // Dismissed controllers will be so after a delay. Queue the completion
    // callback after that.
    if (completion) {
      dispatch_after(
          dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
          dispatch_get_main_queue(), ^{
            completion();
          });
    }
  } else if (completion) {
    // If no view controllers are presented, we should be ok with dispatching
    // the completion block directly.
    dispatch_async(dispatch_get_main_queue(), completion);
  }
}

- (UIView<TabStripFoldAnimation>*)tabStripPlaceholderView {
  return [self.tabStripCoordinator placeholderView];
}

- (void)shutdown {
  DCHECK(!_isShutdown);
  _isShutdown = YES;
  [self.tabStripCoordinator stop];
  self.tabStripCoordinator = nil;
  [_toolbarCoordinator stop];
  _toolbarCoordinator = nil;
  [self.primaryToolbarCoordinator stop];
  self.primaryToolbarCoordinator = nil;
  [self.secondaryToolbarCoordinator stop];
  self.secondaryToolbarCoordinator = nil;
  [_downloadManagerCoordinator stop];
  _downloadManagerCoordinator = nil;
  self.toolbarInterface = nil;
  self.tabStripView = nil;
  _infoBarContainer = nil;
  _readingListMenuNotifier = nil;
  [_model removeObserver:self];
  [[UpgradeCenter sharedInstance] unregisterClient:self];
  if (_voiceSearchController)
    _voiceSearchController->SetDelegate(nil);
  [_rateThisAppDialog setDelegate:nil];
  [_model closeAllTabs];
  [_paymentRequestManager setActiveWebState:nullptr];
}

#pragma mark - NSObject

- (BOOL)accessibilityPerformEscape {
  [self dismissPopups];
  return YES;
}

#pragma mark - UIResponder

- (NSArray*)keyCommands {
  if (![self shouldRegisterKeyboardCommands]) {
    return nil;
  }
  return [self.keyCommandsProvider
      keyCommandsForConsumer:self
          baseViewController:self
                  dispatcher:self.dispatcher
                 editingText:![self isFirstResponder]];
}

#pragma mark - UIResponder helpers

// Whether the BVC should declare keyboard commands.
- (BOOL)shouldRegisterKeyboardCommands {
  if ([self presentedViewController])
    return NO;

  if (_voiceSearchController && _voiceSearchController->IsVisible())
    return NO;

  // If there is no first responder, try to make the webview the first
  // responder.
  if (!GetFirstResponder()) {
    web::WebState* webState = _model.currentTab.webState;
    if (webState)
      [webState->GetWebViewProxy() becomeFirstResponder];
  }

  return YES;
}

#pragma mark - UIViewController

// Perform additional set up after loading the view, typically from a nib.
- (void)viewDidLoad {
  CGRect initialViewsRect = self.view.bounds;
  initialViewsRect.origin.y += StatusBarHeight();
  initialViewsRect.size.height -= StatusBarHeight();
  UIViewAutoresizing initialViewAutoresizing =
      UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;

  // Clip the content to the bounds of the view. This prevents the WebView to
  // overflow outside of the BVC, which is particularly visible during rotation.
  // The WebView is overflowing its bounds to be displayed below the toolbars.
  self.view.clipsToBounds = YES;

  _browserContainerViewController =
      [[BrowserContainerViewController alloc] init];
  [self addChildViewController:_browserContainerViewController];
  self.contentArea.frame = initialViewsRect;
  self.typingShield = [[UIButton alloc] initWithFrame:initialViewsRect];
  self.typingShield.autoresizingMask = initialViewAutoresizing;
  self.typingShield.accessibilityIdentifier = @"Typing Shield";
  self.typingShield.accessibilityLabel = l10n_util::GetNSString(IDS_CANCEL);

  [self.typingShield addTarget:self
                        action:@selector(shieldWasTapped:)
              forControlEvents:UIControlEventTouchUpInside];
  self.view.autoresizingMask = initialViewAutoresizing;
  self.view.backgroundColor = [UIColor colorWithWhite:0.75 alpha:1.0];
  [self.view addSubview:self.contentArea];
  [_browserContainerViewController didMoveToParentViewController:self];
  [self.view addSubview:self.typingShield];
  [super viewDidLoad];

  // Install fake status bar for iPad iOS7
  [self installFakeStatusBar];
  [self buildToolbarAndTabStrip];
  [self setUpViewLayout:YES];
  [self addConstraintsToToolbar];

  // If the tab model and browser state are valid, finish initialization.
  if (_model && _browserState)
    [self addUIFunctionalityForModelAndBrowserState];

  // Add a tap gesture recognizer to save the last tap location for the source
  // location of the new tab animation.
  UITapGestureRecognizer* tapRecognizer = [[UITapGestureRecognizer alloc]
      initWithTarget:self
              action:@selector(saveContentAreaTapLocation:)];
  [tapRecognizer setDelegate:self];
  [tapRecognizer setCancelsTouchesInView:NO];
  [self.contentArea addGestureRecognizer:tapRecognizer];
}

- (void)viewSafeAreaInsetsDidChange {
  [super viewSafeAreaInsetsDidChange];
  if (IsIPhoneX() || IsUIRefreshPhase1Enabled()) {
    [self setUpViewLayout:NO];
  }
  // Update the heights of the toolbars to account for the new insets.
  self.primaryToolbarHeightConstraint.constant =
      [self primaryToolbarHeightWithInset];
  self.secondaryToolbarHeightConstraint.constant =
      [self secondaryToolbarHeightWithInset];
  self.secondaryToolbarNoFullscreenHeightConstraint.constant =
      [self secondaryToolbarHeightWithInset];
}

- (void)viewDidLayoutSubviews {
  [super viewDidLayoutSubviews];
  // Update the toolbar height to account for |topLayoutGuide| changes.
  self.primaryToolbarHeightConstraint.constant =
      [self primaryToolbarHeightWithInset];
}

- (void)viewDidAppear:(BOOL)animated {
  [super viewDidAppear:animated];
  self.viewVisible = YES;
  [self updateDialogPresenterActiveState];
  [self updateBroadcastState];

  // |viewDidAppear| can be called after |browserState| is destroyed. Since
  // |presentBubblesIfEligible| requires that |self.browserState| is not NULL,
  // check for |self.browserState| before calling the presenting the bubbles.
  if (self.browserState) {
    [self presentBubblesIfEligible];
  }
}

- (void)viewWillAppear:(BOOL)animated {
  [super viewWillAppear:animated];

  self.visible = YES;

  // Restore hidden infobars.
  if (IsIPadIdiom() && _infoBarContainer) {
    _infoBarContainer->RestoreInfobars();
  }

  // If the controller is suspended, or has been paged out due to low memory,
  // updating the view will be handled when it's displayed again.
  if (![_model webUsageEnabled] || !self.contentArea)
    return;
  // Update the displayed tab (if any; the switcher may not have created one
  // yet) in case it changed while showing the switcher.
  Tab* currentTab = [_model currentTab];
  if (currentTab)
    [self displayTab:currentTab];
}

- (void)viewWillDisappear:(BOOL)animated {
  self.viewVisible = NO;
  [self updateDialogPresenterActiveState];
  [self updateBroadcastState];
  web::WebState* activeWebState = [_model webStateList]->GetActiveWebState();
  if (activeWebState)
    activeWebState->WasHidden();
  [_bookmarkInteractionController dismissSnackbar];
  if (IsIPadIdiom() && _infoBarContainer) {
    _infoBarContainer->SuspendInfobars();
  }
  [super viewWillDisappear:animated];
}

- (BOOL)prefersStatusBarHidden {
  BOOL defaultValue = NO;
  if (IsUIRefreshPhase1Enabled()) {
    defaultValue = [super prefersStatusBarHidden];
  }
  return self.hideStatusBar || defaultValue;
}

// Called when in the foreground and the OS needs more memory. Release as much
// as possible.
- (void)didReceiveMemoryWarning {
  // Releases the view if it doesn't have a superview.
  [super didReceiveMemoryWarning];

  // Release any cached data, images, etc that aren't in use.
  // TODO(pinkerton): This feels like it should go in the MemoryPurger class,
  // but since the FaviconCache uses obj-c in the header, it can't be included
  // there.
  if (_browserState) {
    FaviconLoader* loader =
        IOSChromeFaviconLoaderFactory::GetForBrowserStateIfExists(
            _browserState);
    if (loader)
      loader->PurgeCache();
  }

  if (![self isViewLoaded]) {
    // Do not release |_infoBarContainer|, as this must have the same lifecycle
    // as the BrowserViewController.
    _browserContainerViewController = nil;
    self.typingShield = nil;
    if (_voiceSearchController)
      _voiceSearchController->SetDelegate(nil);
    _readingListCoordinator = nil;
    self.recentTabsCoordinator = nil;
    _toolbarCoordinator = nil;
    self.primaryToolbarCoordinator = nil;
    self.secondaryToolbarCoordinator = nil;
    self.toolbarInterface = nil;
    [_toolbarUIUpdater stopUpdating];
    _toolbarUIUpdater = nil;
    _toolbarModelDelegate = nil;
    _toolbarModel = nil;
    self.helper = nil;
    [self.tabStripCoordinator stop];
    self.tabStripCoordinator = nil;
    self.tabStripView = nil;
    _sideSwipeController = nil;
  }
}

- (void)traitCollectionDidChange:(UITraitCollection*)previousTraitCollection {
  [super traitCollectionDidChange:previousTraitCollection];
  // TODO(crbug.com/527092): - traitCollectionDidChange: is not always forwarded
  // because in some cases the presented view controller isn't a child of the
  // BVC in the view controller hierarchy (some intervening object isn't a
  // view controller).
  [self.presentedViewController
      traitCollectionDidChange:previousTraitCollection];
  // Update voice search bar visibility.
  [self updateVoiceSearchBarVisibilityAnimated:NO];
  // Change the height of the secondary toolbar to show/hide it.
  self.secondaryToolbarHeightConstraint.constant =
      [self secondaryToolbarHeightWithInset];
  self.secondaryToolbarNoFullscreenHeightConstraint.constant =
      [self secondaryToolbarHeightWithInset];
  [self updateFootersForFullscreenProgress:self.footerFullscreenProgress];

  // Update the toolbar visibility.
  [self updateToolbar];

  // Normally this happens in -viewSafeAreaInsetsDidChange, but added here to
  // support iOS10.
  if (IsUIRefreshPhase1Enabled() && !base::ios::IsRunningOnIOS11OrLater()) {
    [self setUpViewLayout:NO];
  }
}

- (void)viewWillTransitionToSize:(CGSize)size
       withTransitionCoordinator:
           (id<UIViewControllerTransitionCoordinator>)coordinator {
  [super viewWillTransitionToSize:size withTransitionCoordinator:coordinator];
  [self dismissPopups];
  [self reshowFindBarIfNeededWithCoordinator:coordinator];
}

- (void)dismissViewControllerAnimated:(BOOL)flag
                           completion:(void (^)())completion {
  if (TabSwitcherPresentsBVCEnabled() && !self.presentedViewController) {
    // TODO(crbug.com/801165): On iOS10, UIDocumentMenuViewController and
    // WKFileUploadPanel somehow combine to call dismiss twice instead of once.
    // The second call would dismiss the BVC itself, so look for that case and
    // return early.
    //
    // TODO(crbug.com/811671): A similar bug exists on all iOS versions with
    // WKFileUploadPanel and UIDocumentPickerViewController.
    //
    // To make M65 as safe as possible, return early whenever this method is
    // invoked but no VC appears to be presented.  These cases will always end
    // up dismissing the BVC itself, which would put the app into an
    // unresponsive state.
    return;
  }

  // Some calling code invokes |dismissViewControllerAnimated:completion:|
  // multiple times.  When the BVC is displayed using VC containment, multiple
  // calls are effectively idempotent because only the first call has any effect
  // and subsequent calls do nothing.  However, when the BVC is presented,
  // subsequent calls end up dismissing the BVC itself.  This is never what we
  // want, so check for this case and return early.  It is not enough to check
  // |self.dismissingModal| because some dismissals do not go through
  // -[BrowserViewController dismissViewControllerAnimated:completion:|.
  // TODO(crbug.com/782338): Fix callers and remove this early return.
  if (TabSwitcherPresentsBVCEnabled() &&
      (self.dismissingModal || self.presentedViewController.isBeingDismissed)) {
    return;
  }

  self.dismissingModal = YES;
  __weak BrowserViewController* weakSelf = self;
  [super dismissViewControllerAnimated:flag
                            completion:^{
                              BrowserViewController* strongSelf = weakSelf;
                              strongSelf.dismissingModal = NO;
                              strongSelf.dialogPresenterDelegateIsPresenting =
                                  NO;
                              if (completion)
                                completion();
                              [strongSelf.dialogPresenter tryToPresent];
                            }];
}

- (void)presentViewController:(UIViewController*)viewControllerToPresent
                     animated:(BOOL)flag
                   completion:(void (^)())completion {
  ProceduralBlock finalCompletionHandler = [completion copy];
  // TODO(crbug.com/580098) This is an interim fix for the flicker between the
  // launch screen and the FRE Animation. The fix is, if the FRE is about to be
  // presented, to show a temporary view of the launch screen and then remove it
  // when the controller for the FRE has been presented. This fix should be
  // removed when the FRE startup code is rewritten.
  BOOL firstRunLaunch = (FirstRun::IsChromeFirstRun() ||
                         experimental_flags::AlwaysDisplayFirstRun()) &&
                        !tests_hook::DisableFirstRun();
  // These if statements check that |presentViewController| is being called for
  // the FRE case.
  if (firstRunLaunch &&
      [viewControllerToPresent isKindOfClass:[UINavigationController class]]) {
    UINavigationController* navController =
        base::mac::ObjCCastStrict<UINavigationController>(
            viewControllerToPresent);
    if ([navController.topViewController
            isMemberOfClass:[WelcomeToChromeViewController class]]) {
      self.hideStatusBar = YES;

      // Load view from Launch Screen and add it to window.
      NSBundle* mainBundle = base::mac::FrameworkBundle();
      NSArray* topObjects =
          [mainBundle loadNibNamed:@"LaunchScreen" owner:self options:nil];
      UIViewController* launchScreenController =
          base::mac::ObjCCastStrict<UIViewController>([topObjects lastObject]);
      // |launchScreenView| is loaded as an autoreleased object, and is retained
      // by the |completion| block below.
      UIView* launchScreenView = launchScreenController.view;
      launchScreenView.userInteractionEnabled = NO;
      UIWindow* window = UIApplication.sharedApplication.keyWindow;
      launchScreenView.frame = window.bounds;
      [window addSubview:launchScreenView];

      // Replace the completion handler sent to the superclass with one which
      // removes |launchScreenView| and resets the status bar. If |completion|
      // exists, it is called from within the new completion handler.
      __weak BrowserViewController* weakSelf = self;
      finalCompletionHandler = ^{
        [launchScreenView removeFromSuperview];
        weakSelf.hideStatusBar = NO;
        if (completion)
          completion();
      };
    }
  }

  self.dialogPresenterDelegateIsPresenting = YES;
  if ([self.sideSwipeController inSwipe]) {
    [self.sideSwipeController resetContentView];
  }

  [super presentViewController:viewControllerToPresent
                      animated:flag
                    completion:finalCompletionHandler];
}

- (BOOL)shouldAutorotate {
  if (self.presentedViewController.beingPresented ||
      self.presentedViewController.beingDismissed) {
    // Don't rotate while a presentation or dismissal animation is occurring.
    return NO;
  } else if (_sideSwipeController &&
             ![self.sideSwipeController shouldAutorotate]) {
    // Don't auto rotate if side swipe controller view says not to.
    return NO;
  } else {
    return [super shouldAutorotate];
  }
}

- (UIStatusBarStyle)preferredStatusBarStyle {
  return (IsIPadIdiom() || _isOffTheRecord) ? UIStatusBarStyleLightContent
                                            : UIStatusBarStyleDefault;
}

#pragma mark - ** Private BVC Methods **

#pragma mark - Private Methods: BVC Initialization

- (void)updateWithTabModel:(TabModel*)model
              browserState:(ios::ChromeBrowserState*)browserState {
  DCHECK(model);
  DCHECK(browserState);
  DCHECK(!_model);
  DCHECK(!_browserState);
  _browserState = browserState;
  _isOffTheRecord = browserState->IsOffTheRecord() ? YES : NO;
  _model = model;

  [_model addObserver:self];

  if (!_isOffTheRecord) {
    [DefaultIOSWebViewFactory
        registerWebViewFactory:[ChromeWebViewFactory class]];
  }
  NSUInteger count = [_model count];
  for (NSUInteger index = 0; index < count; ++index)
    [self installDelegatesForTab:[_model tabAtIndex:index]];

  _imageFetcher = std::make_unique<image_fetcher::IOSImageDataFetcherWrapper>(
      _browserState->GetRequestContext());
  self.imageSaver = [[ImageSaver alloc] initWithBaseViewController:self];

  // Register for bookmark changed notification (BookmarkModel may be null
  // during testing, so explicitly support this).
  _bookmarkModel = ios::BookmarkModelFactory::GetForBrowserState(_browserState);

  // Add a FullscreenUIUpdater for self.
  FullscreenController* controller =
      FullscreenControllerFactory::GetInstance()->GetForBrowserState(
          _browserState);
  _fullscreenUIUpdater = std::make_unique<FullscreenUIUpdater>(self);
  // Crate the disabler for any new foreground tab animations in the tab model.
  _foregroundTabAnimationFullscreenDisabler =
      std::make_unique<NewForegroundTabFullscreenDisabler>(_model.webStateList,
                                                           controller);
  // Set the FullscreenController's WebStateList.
  controller->SetWebStateList(_model.webStateList);

  // When starting the browser with an open tab, it is necessary to reset the
  // clipsToBounds property of the WKWebView so the page can bleed behind the
  // toolbar.
  if (self.currentWebState && IsUIRefreshPhase1Enabled()) {
    self.currentWebState->GetWebViewProxy().scrollViewProxy.clipsToBounds = NO;
  }
}

- (void)installFakeStatusBar {
  CGFloat statusBarHeight = StatusBarHeight();
  CGRect statusBarFrame =
      CGRectMake(0, 0, [[self view] frame].size.width, statusBarHeight);
  _fakeStatusBarView = [[UIView alloc] initWithFrame:statusBarFrame];
  [_fakeStatusBarView setAutoresizingMask:UIViewAutoresizingFlexibleWidth];
  if (IsIPadIdiom()) {
    [_fakeStatusBarView setBackgroundColor:StatusBarBackgroundColor()];
    [_fakeStatusBarView setAutoresizingMask:UIViewAutoresizingFlexibleWidth];
    [_fakeStatusBarView layer].zPosition = 99;
    [[self view] addSubview:_fakeStatusBarView];
  } else {
    // Add a white bar on phone so that the status bar on the NTP is white.
    [_fakeStatusBarView setBackgroundColor:ntp_home::kNTPBackgroundColor()];
    [self.view insertSubview:_fakeStatusBarView atIndex:0];
  }
}

// Create the UI elements.  May or may not have valid browser state & tab model.
- (void)buildToolbarAndTabStrip {
  DCHECK([self isViewLoaded]);
  DCHECK(!_toolbarModelDelegate);

  // Initialize the prerender service before creating the toolbar controller.
  PrerenderService* prerenderService =
      PrerenderServiceFactory::GetForBrowserState(self.browserState);
  if (prerenderService) {
    prerenderService->SetDelegate(self);
  }

  // Create the toolbar model and controller.
  _toolbarModelDelegate.reset(
      new ToolbarModelDelegateIOS([_model webStateList]));
  _toolbarModel = std::make_unique<ToolbarModelImpl>(
      _toolbarModelDelegate.get(), kMaxURLDisplayChars);
  self.helper = [_dependencyFactory newBrowserViewControllerHelper];

  if (IsUIRefreshPhase1Enabled()) {
    PrimaryToolbarCoordinator* topToolbarCoordinator =
        [[PrimaryToolbarCoordinator alloc] initWithBrowserState:_browserState];
    self.primaryToolbarCoordinator = topToolbarCoordinator;
    topToolbarCoordinator.delegate = self;
    topToolbarCoordinator.URLLoader = self;
    topToolbarCoordinator.webStateList = [_model webStateList];
    topToolbarCoordinator.dispatcher = self.dispatcher;
    [topToolbarCoordinator start];

    SecondaryToolbarCoordinator* bottomToolbarCoordinator = [
        [SecondaryToolbarCoordinator alloc] initWithBrowserState:_browserState];
    self.secondaryToolbarCoordinator = bottomToolbarCoordinator;
    bottomToolbarCoordinator.webStateList = [_model webStateList];
    bottomToolbarCoordinator.dispatcher = self.dispatcher;
    [bottomToolbarCoordinator start];

    _toolbarCoordinatorAdaptor =
        [[ToolbarCoordinatorAdaptor alloc] initWithDispatcher:self.dispatcher];
    self.toolbarInterface = _toolbarCoordinatorAdaptor;
    [_toolbarCoordinatorAdaptor addToolbarCoordinator:topToolbarCoordinator];
    [_toolbarCoordinatorAdaptor addToolbarCoordinator:bottomToolbarCoordinator];
  } else {
    _toolbarCoordinator = [[ToolbarCoordinator alloc]
        initWithToolsMenuConfigurationProvider:self
                                    dispatcher:self.dispatcher
                                  browserState:_browserState];
    _toolbarCoordinator.webStateList = [_model webStateList];
    _toolbarCoordinator.delegate = self;
    _toolbarCoordinator.URLLoader = self;
    self.primaryToolbarCoordinator = _toolbarCoordinator;
    self.toolbarInterface = _toolbarCoordinator;

    [_toolbarCoordinator start];
  }

  self.sideSwipeController.toolbarInteractionHandler = self.toolbarInterface;
  self.sideSwipeController.primaryToolbarSnapshotProvider =
      self.primaryToolbarCoordinator;
  self.sideSwipeController.secondaryToolbarSnapshotProvider =
      self.secondaryToolbarCoordinator;

  [_dispatcher
      startDispatchingToTarget:self.primaryToolbarCoordinator.omniboxFocuser
                   forProtocol:@protocol(OmniboxFocuser)];
  [_dispatcher startDispatchingToTarget:self.primaryToolbarCoordinator
                            forProtocol:@protocol(FakeboxFocuser)];
  [self updateBroadcastState];
  if (_voiceSearchController)
    _voiceSearchController->SetDelegate(
        [self.primaryToolbarCoordinator voiceSearchDelegate]);

  if (IsIPadIdiom()) {
    self.tabStripCoordinator =
        [[TabStripLegacyCoordinator alloc] initWithBaseViewController:self];
    self.tabStripCoordinator.browserState = _browserState;
    self.tabStripCoordinator.dispatcher = _dispatcher;
    self.tabStripCoordinator.tabModel = _model;
    self.tabStripCoordinator.presentationProvider = self;
    self.tabStripCoordinator.animationWaitDuration =
        kLegacyFullscreenControllerToolbarAnimationDuration;
    [self.tabStripCoordinator start];
  }

  // Create infobar container.
  if (!_infoBarContainerDelegate) {
    _infoBarContainerDelegate.reset(new InfoBarContainerDelegateIOS(self));
    _infoBarContainer.reset(
        new InfoBarContainerIOS(_infoBarContainerDelegate.get()));
  }
}

// The height of the primary toolbar with the top safe area inset included.
- (CGFloat)primaryToolbarHeightWithInset {
  UIView* primaryToolbar = self.primaryToolbarCoordinator.viewController.view;
  CGFloat intrinsicHeight = primaryToolbar.intrinsicContentSize.height;
  if (IsUIRefreshPhase1Enabled() && !IsSplitToolbarMode()) {
    // When the adaptive toolbar is unsplit, add a margin.
    intrinsicHeight += kTopToolbarUnsplitMargin;
  }
  // If the primary toolbar is not the topmost header, it does not overlap with
  // the unsafe area.
  // TODO(crbug.com/806437): Update implementation such that this calculates the
  // topmost header's height.
  UIView* topmostHeader = [self.headerViews firstObject].view;
  if (primaryToolbar != topmostHeader)
    return intrinsicHeight;
  // If the primary toolbar is topmost, subtract the height of the portion of
  // the unsafe area.
  CGFloat unsafeHeight = 0.0;
  if (@available(iOS 11, *)) {
    unsafeHeight = self.view.safeAreaInsets.top;
  } else {
    unsafeHeight = self.topLayoutGuide.length;
  }
  // The topmost header is laid out |headerOffset| from the top of |view|, so
  // subtract that from the unsafe height.
  unsafeHeight -= self.headerOffset;
  return intrinsicHeight + unsafeHeight;
}

// The height of the secondary toolbar with the bottom safe area inset included.
// Returns 0 if the toolbar should be hidden.
- (CGFloat)secondaryToolbarHeightWithInset {
  if (!IsSplitToolbarMode(self))
    return 0;

  UIView* secondaryToolbar =
      self.secondaryToolbarCoordinator.viewController.view;
  // Add the safe area inset to the toolbar height.
  CGFloat unsafeHeight = 0.0;
  if (@available(iOS 11, *)) {
    unsafeHeight = self.view.safeAreaInsets.bottom;
  }
  return secondaryToolbar.intrinsicContentSize.height + unsafeHeight;
}

- (void)addConstraintsToToolbar {
  NSLayoutYAxisAnchor* topAnchor;
  // On iPad, the toolbar is underneath the tab strip.
  // On iPhone, it is underneath the top of the screen.
  if (IsIPadIdiom()) {
    topAnchor = self.tabStripView.bottomAnchor;
  } else {
    topAnchor = [self view].topAnchor;
  }

  // Create a constraint for the vertical positioning of the toolbar.
  UIView* primaryView = self.primaryToolbarCoordinator.viewController.view;
  self.primaryToolbarOffsetConstraint =
      [primaryView.topAnchor constraintEqualToAnchor:topAnchor];

  // Create a constraint for the height of the toolbar to include the unsafe
  // area height.
  self.primaryToolbarHeightConstraint = [primaryView.heightAnchor
      constraintEqualToConstant:[self primaryToolbarHeightWithInset]];

  [NSLayoutConstraint activateConstraints:@[
    self.primaryToolbarOffsetConstraint,
    self.primaryToolbarHeightConstraint,
    [self.primaryToolbarCoordinator.viewController.view.leadingAnchor
        constraintEqualToAnchor:[self view].leadingAnchor],
    [self.primaryToolbarCoordinator.viewController.view.trailingAnchor
        constraintEqualToAnchor:[self view].trailingAnchor],
  ]];

  if (self.secondaryToolbarCoordinator) {
    // Create a constraint for the height of the toolbar to include the unsafe
    // area height.
    UIView* secondaryView =
        self.secondaryToolbarCoordinator.viewController.view;
    self.secondaryToolbarHeightConstraint = [secondaryView.heightAnchor
        constraintEqualToConstant:[self secondaryToolbarHeightWithInset]];
    self.secondaryToolbarHeightConstraint.active = YES;

    AddSameConstraintsToSides(
        self.view, secondaryView,
        LayoutSides::kBottom | LayoutSides::kLeading | LayoutSides::kTrailing);

    UILayoutGuide* guide =
        [[NamedGuide alloc] initWithName:kSecondaryToolbarNoFullscreen];
    [self.view addLayoutGuide:guide];
    self.secondaryToolbarNoFullscreenHeightConstraint = [guide.heightAnchor
        constraintEqualToConstant:[self secondaryToolbarHeightWithInset]];
    self.secondaryToolbarNoFullscreenHeightConstraint.active = YES;

    AddSameConstraintsToSides(
        self.view, guide,
        LayoutSides::kBottom | LayoutSides::kLeading | LayoutSides::kTrailing);
  }
  [[self view] layoutIfNeeded];
}

// Enable functionality that only makes sense if the views are loaded and
// both browser state and tab model are valid.
- (void)addUIFunctionalityForModelAndBrowserState {
  DCHECK(_browserState);
  DCHECK(_toolbarModel);
  DCHECK(_model);
  DCHECK([self isViewLoaded]);

  [self.sideSwipeController addHorizontalGesturesToView:self.view];

  infobars::InfoBarManager* infoBarManager = nullptr;
  if (_model.currentTab) {
    DCHECK(_model.currentTab.webState);
    infoBarManager =
        InfoBarManagerImpl::FromWebState(_model.currentTab.webState);
  }
  _infoBarContainer->ChangeInfoBarManager(infoBarManager);

  // Create child coordinators.
  _activityServiceCoordinator = [[ActivityServiceLegacyCoordinator alloc]
      initWithBaseViewController:self];
  _activityServiceCoordinator.dispatcher = _dispatcher;
  _activityServiceCoordinator.tabModel = _model;
  _activityServiceCoordinator.browserState = _browserState;
  _activityServiceCoordinator.positionProvider =
      [self.primaryToolbarCoordinator activityServicePositioner];
  _activityServiceCoordinator.presentationProvider = self;

  _qrScannerCoordinator =
      [[QRScannerLegacyCoordinator alloc] initWithBaseViewController:self];
  _qrScannerCoordinator.dispatcher = _dispatcher;
  _qrScannerCoordinator.loadProvider =
      [self.primaryToolbarCoordinator QRScannerResultLoader];
  _qrScannerCoordinator.presentationProvider = self;

  // DownloadManagerCoordinator is already created.
  DCHECK(_downloadManagerCoordinator);
  _downloadManagerCoordinator.webStateList = [_model webStateList];

  if (IsUIRefreshPhase1Enabled()) {
    self.popupMenuCoordinator = [[PopupMenuCoordinator alloc]
        initWithBaseViewController:self
                      browserState:self.browserState];
    self.popupMenuCoordinator.dispatcher = _dispatcher;
    self.popupMenuCoordinator.webStateList = [_model webStateList];
    self.popupMenuCoordinator.UIUpdater = _toolbarCoordinatorAdaptor;
    [self.popupMenuCoordinator start];
  } else {
    _tabHistoryCoordinator = [[LegacyTabHistoryCoordinator alloc]
        initWithBaseViewController:self
                      browserState:_browserState];
    _tabHistoryCoordinator.dispatcher = _dispatcher;
    _tabHistoryCoordinator.tabModel = _model;
    _tabHistoryCoordinator.presentationProvider = self;
    _tabHistoryCoordinator.tabHistoryUIUpdater =
        [_toolbarCoordinator tabHistoryUIUpdater];
  }

  _sadTabCoordinator = [[SadTabLegacyCoordinator alloc] init];
  _sadTabCoordinator.baseViewController = self;
  _sadTabCoordinator.dispatcher = self.dispatcher;

  // If there are any existing SadTabHelpers in |_model|, update the helpers
  // delegate with the new |_sadTabCoordinator|.
  for (NSUInteger i = 0; i < _model.count; i++) {
    SadTabTabHelper* sadTabHelper =
        SadTabTabHelper::FromWebState([_model tabAtIndex:i].webState);
    DCHECK(sadTabHelper);
    if (sadTabHelper) {
      sadTabHelper->SetDelegate(_sadTabCoordinator);
    }
  }

  _pageInfoCoordinator = [[PageInfoLegacyCoordinator alloc]
      initWithBaseViewController:self
                    browserState:_browserState];
  _pageInfoCoordinator.dispatcher = _dispatcher;
  _pageInfoCoordinator.loader = self;
  _pageInfoCoordinator.presentationProvider = self;
  _pageInfoCoordinator.tabModel = _model;

  _externalSearchCoordinator = [[ExternalSearchCoordinator alloc] init];
  _externalSearchCoordinator.dispatcher = _dispatcher;

  if (base::FeatureList::IsEnabled(payments::features::kWebPayments)) {
    _paymentRequestManager = [[PaymentRequestManager alloc]
        initWithBaseViewController:self
                      browserState:_browserState
                        dispatcher:self.dispatcher];
    [_paymentRequestManager setToolbarModel:_toolbarModel.get()];
    [_paymentRequestManager setActiveWebState:[_model currentTab].webState];
  }
}

// Set the frame for the various views. View must be loaded.
- (void)setUpViewLayout:(BOOL)initialLayout {
  DCHECK([self isViewLoaded]);

  // Update the fake toolbar background height.
  CGRect fakeStatusBarFrame = _fakeStatusBarView.frame;
  fakeStatusBarFrame.size.height = StatusBarHeight();
  _fakeStatusBarView.frame = fakeStatusBarFrame;


  // Position the toolbar next, either at the top of the browser view or
  // directly under the tabstrip.
  if (initialLayout) {
    [self addChildViewController:self.primaryToolbarCoordinator.viewController];
    if (self.secondaryToolbarCoordinator)
      [self addChildViewController:self.secondaryToolbarCoordinator
                                       .viewController];
  }

  // Place the infobar container above the content area.
  InfoBarContainerView* infoBarContainerView = _infoBarContainer->view();
  if (initialLayout) {
    [self.view insertSubview:infoBarContainerView
                aboveSubview:self.contentArea];
  }

  // Place the toolbar controller above the infobar container and adds the
  // layout guides.
  if (initialLayout) {
    [[self view]
        insertSubview:self.primaryToolbarCoordinator.viewController.view
         aboveSubview:infoBarContainerView];
    if (self.secondaryToolbarCoordinator) {
      [[self view]
          insertSubview:self.secondaryToolbarCoordinator.viewController.view
           aboveSubview:self.primaryToolbarCoordinator.viewController.view];
    }
    NSArray<GuideName*>* guideNames = @[
      kOmniboxGuide,
      kBackButtonGuide,
      kForwardButtonGuide,
      kToolsMenuGuide,
      kTabSwitcherGuide,
      kSecondaryToolbar,
      kVoiceSearchButtonGuide,
    ];
    AddNamedGuidesToView(guideNames, self.view);
  }
  if (initialLayout) {
    [self.primaryToolbarCoordinator.viewController
        didMoveToParentViewController:self];
    if (self.secondaryToolbarCoordinator) {
      [self.secondaryToolbarCoordinator.viewController
          didMoveToParentViewController:self];
    }
  }

  // Adjust the content area to be under the toolbar, for fullscreen or below
  // the toolbar is not fullscreen.
  CGRect contentFrame = self.contentArea.frame;
  CGFloat marginWithHeader = StatusBarHeight();
  contentFrame.size.height = CGRectGetMaxY(contentFrame) - marginWithHeader;
  contentFrame.origin.y = marginWithHeader;
  self.contentArea.frame = contentFrame;

  if (initialLayout) {
    // Adjust the infobar container to be either at the bottom of the screen
    // (iPhone) or on the lower toolbar edge (iPad).
    CGRect infoBarFrame = contentFrame;
    infoBarFrame.origin.y = CGRectGetMaxY(contentFrame);
    infoBarFrame.size.height = 0;
    [infoBarContainerView setFrame:infoBarFrame];
  }

  // Attach the typing shield to the content area but have it hidden.
  self.typingShield.frame = self.contentArea.frame;
  if (initialLayout) {
    [self.view insertSubview:self.typingShield aboveSubview:self.contentArea];
    [self.typingShield setHidden:YES];
  }
}

- (void)displayTab:(Tab*)tab {
  DCHECK(tab);
  [self loadViewIfNeeded];

  if (!self.inNewTabAnimation) {
    // Hide findbar.  |updateToolbar| will restore the findbar later.
    [self hideFindBarWithAnimation:NO];

    // Make new content visible, resizing it first as the orientation may
    // have changed from the last time it was displayed.
    tab.view.frame = self.contentArea.bounds;
    [_browserContainerViewController displayContentView:tab.view];
  }
  [self updateToolbar];

  // Notify the WebState that it was displayed.
  DCHECK(tab.webState);
  tab.webState->WasShown();
}

- (void)initializeBookmarkInteractionController {
  if (_bookmarkInteractionController)
    return;
  _bookmarkInteractionController = [[BookmarkInteractionController alloc]
      initWithBrowserState:_browserState
                    loader:self
          parentController:self
                dispatcher:self.dispatcher];
}

- (void)setOverScrollActionControllerToStaticNativeContent:
    (StaticHtmlNativeContent*)nativeContent {
  if (!IsIPadIdiom()) {
    OverscrollActionsController* controller =
        [[OverscrollActionsController alloc]
            initWithScrollView:[nativeContent scrollView]];
    [controller setDelegate:self];
    OverscrollStyle style = _isOffTheRecord
                                ? OverscrollStyle::REGULAR_PAGE_INCOGNITO
                                : OverscrollStyle::REGULAR_PAGE_NON_INCOGNITO;
    controller.style = style;
    nativeContent.overscrollActionsController = controller;
  }
}

#pragma mark - Private Methods: UI Configuration, update and Layout

// Update the state of back and forward buttons, hiding the forward button if
// there is nowhere to go. Assumes the model's current tab is up to date.
- (void)updateToolbar {
  // If the BVC has been partially torn down for low memory, wait for the
  // view rebuild to handle toolbar updates.
  if (!(self.helper && _browserState))
    return;

  Tab* tab = [_model currentTab];
  if (![tab navigationManager])
    return;
  [_toolbarCoordinator updateToolsMenu];

  if (_insertedTabWasPrerenderedTab &&
      ![self.helper isToolbarLoading:self.currentWebState])
    [self.primaryToolbarCoordinator showPrerenderingAnimation];

  auto* findHelper = FindTabHelper::FromWebState(tab.webState);
  if (findHelper && findHelper->IsFindUIActive()) {
    [self showFindBarWithAnimation:NO
                        selectText:YES
                       shouldFocus:[_findBarController isFocused]];
  }

  // Hide the toolbar if displaying the compact NTP.
  web::NavigationItem* item = [tab navigationManager]->GetVisibleItem();
  BOOL isRegularXRegular = IsUIRefreshPhase1Enabled()
                               ? IsRegularXRegularSizeClass(self)
                               : IsIPadIdiom();
  BOOL hideToolbar = NO;
  if (item) {
    GURL url = item->GetURL();
    BOOL isNTP = url.GetOrigin() == kChromeUINewTabURL;
    hideToolbar = isNTP && !_isOffTheRecord &&
                  ![self.primaryToolbarCoordinator isOmniboxFirstResponder] &&
                  ![self.primaryToolbarCoordinator showingOmniboxPopup] &&
                  !isRegularXRegular;
  }
  [self.primaryToolbarCoordinator.viewController.view setHidden:hideToolbar];
}

- (void)updateBroadcastState {
  self.broadcasting = self.active && self.viewVisible;
}

- (void)updateDialogPresenterActiveState {
  self.dialogPresenter.active =
      self.active && self.viewVisible && !self.inNewTabAnimation;
}

- (void)dismissPopups {
  [self.dispatcher hidePageInfo];
  if (IsUIRefreshPhase1Enabled()) {
    [self.dispatcher dismissPopupMenuAnimated:NO];
  } else {
    [self.dispatcher dismissToolsMenu];
    [_tabHistoryCoordinator dismissHistoryPopup];
  }
  [self.tabTipBubblePresenter dismissAnimated:NO];
  [self.incognitoTabTipBubblePresenter dismissAnimated:NO];
}

- (BOOL)isTabScrolledToTop:(Tab*)tab {
  CGPoint scrollOffset =
      tab.webState->GetWebViewProxy().scrollViewProxy.contentOffset;

  // If there is a native controller, use the native controller's scroll offset.
  id nativeController = [self nativeControllerForTab:tab];
  if ([nativeController conformsToProtocol:@protocol(CRWNativeContent)] &&
      [nativeController respondsToSelector:@selector(scrollOffset)]) {
    scrollOffset = [nativeController scrollOffset];
  }
  return CGPointEqualToPoint(scrollOffset, CGPointZero);
}

- (UIView*)footerView {
  if (IsUIRefreshPhase1Enabled()) {
    return self.secondaryToolbarCoordinator.viewController.view;
  } else {
    return _voiceSearchBar;
  }
}

- (CGFloat)headerHeightForTab:(Tab*)tab {
  BOOL isRegularXRegular = IsUIRefreshPhase1Enabled()
                               ? IsRegularXRegularSizeClass(self)
                               : IsIPadIdiom();
  id nativeController = [self nativeControllerForTab:tab];
  if ([nativeController conformsToProtocol:@protocol(ToolbarOwner)] &&
      [nativeController respondsToSelector:@selector(toolbarHeight)] &&
      [nativeController toolbarHeight] > 0.0 && !isRegularXRegular) {
    // On iPhone, don't add any header height for ToolbarOwner native
    // controllers when they're displaying their own toolbar.
    return 0;
  }

  NSArray<HeaderDefinition*>* views = [self headerViews];

  CGFloat height = self.headerOffset;
  for (HeaderDefinition* header in views) {
    if (header.view && header.behaviour == Hideable) {
      height += CGRectGetHeight([header.view frame]) -
                header.heightAdjustement - header.inset;
    }
  }

  return height - StatusBarHeight();
}

- (void)setFramesForHeaders:(NSArray<HeaderDefinition*>*)headers
                   atOffset:(CGFloat)headerOffset {
  CGFloat height = self.headerOffset;
  for (HeaderDefinition* header in headers) {
    CGFloat yOrigin = height - headerOffset - header.inset;
    BOOL isPrimaryToolbar =
        header.view == self.primaryToolbarCoordinator.viewController.view;
    // Make sure the toolbarView's constraints are also updated.  Leaving the
    // -setFrame call to minimize changes in this CL -- otherwise the way
    // toolbar_view manages it's alpha changes would also need to be updated.
    // TODO(crbug.com/778822): This can be cleaned up when the new fullscreen
    // is enabled.
    if (isPrimaryToolbar && !IsIPadIdiom()) {
      self.primaryToolbarOffsetConstraint.constant = yOrigin;
    }
    CGRect frame = [header.view frame];
    frame.origin.y = yOrigin;
    [header.view setFrame:frame];
    if (header.behaviour != Overlap)
      height += CGRectGetHeight(frame);
  }
}

- (CardView*)addCardViewInFullscreen:(BOOL)fullScreen {
  CGRect frame = self.contentArea.frame;
  if (!fullScreen) {
    // Changing the origin here is unnecessary, it's set in page_animation_util.
    frame.size.height -= self.headerHeight;
  }

  CGFloat shortAxis = frame.size.width;
  CGFloat shortInset = kCardImageInsets.left + kCardImageInsets.right;
  shortAxis -= shortInset + 2 * page_animation_util::kCardMargin;
  CGFloat aspectRatio = frame.size.height / frame.size.width;
  CGFloat longAxis = std::floor(aspectRatio * shortAxis);
  CGFloat longInset = kCardImageInsets.top + kCardImageInsets.bottom;
  CGSize cardSize = CGSizeMake(shortAxis + shortInset, longAxis + longInset);
  CGRect cardFrame = {frame.origin, cardSize};

  CardView* card =
      [[CardView alloc] initWithFrame:cardFrame isIncognito:_isOffTheRecord];
  card.closeButtonSide = IsPortrait() ? CardCloseButtonSide::TRAILING
                                      : CardCloseButtonSide::LEADING;
  [self.contentArea addSubview:card];
  return card;
}

#pragma mark - Private Methods: Showing and Dismissing Child UI

- (void)dismissRateThisAppDialog {
  if (_rateThisAppDialog) {
    base::RecordAction(base::UserMetricsAction(
        "IOSRateThisAppDialogDismissedProgramatically"));
    [_rateThisAppDialog dismiss];
    _rateThisAppDialog = nil;
  }
}

#pragma mark - Private Methods: Bubble views

- (BubbleViewControllerPresenter*)
bubblePresenterForFeature:(const base::Feature&)feature
                direction:(BubbleArrowDirection)direction
                alignment:(BubbleAlignment)alignment
                     text:(NSString*)text {
  DCHECK(self.browserState);
  if (!feature_engagement::TrackerFactory::GetForBrowserState(self.browserState)
           ->ShouldTriggerHelpUI(feature)) {
    return nil;
  }
  // Capture |weakSelf| instead of the feature engagement tracker object
  // because |weakSelf| will safely become |nil| if it is deallocated, whereas
  // the feature engagement tracker will remain pointing to invalid memory if
  // its owner (the ChromeBrowserState) is deallocated.
  __weak BrowserViewController* weakSelf = self;
  void (^dismissalCallback)(void) = ^{
    BrowserViewController* strongSelf = weakSelf;
    if (strongSelf) {
      feature_engagement::TrackerFactory::GetForBrowserState(
          strongSelf.browserState)
          ->Dismissed(feature);
    }
  };

  BubbleViewControllerPresenter* bubbleViewControllerPresenter =
      [[BubbleViewControllerPresenter alloc] initWithText:text
                                           arrowDirection:direction
                                                alignment:alignment
                                        dismissalCallback:dismissalCallback];

  return bubbleViewControllerPresenter;
}

- (void)presentNewTabTipBubbleOnInitialized {
  DCHECK(self.browserState);
  // If the tab tip bubble has already been presented and the user is still
  // considered engaged, it can't be overwritten or set to |nil| or else it will
  // reset the |userEngaged| property. Once the user is not engaged, the bubble
  // can be safely overwritten or set to |nil|.
  if (!self.tabTipBubblePresenter.isUserEngaged) {
    __weak BrowserViewController* weakSelf = self;
    void (^onInitializedBlock)(bool) = ^(bool successfullyLoaded) {
      [weakSelf presentNewTabTipBubble];
    };

    // Because the new tab tip occurs on startup, the feature engagement
    // tracker's database is not guaranteed to be loaded by this time. For the
    // bubble to appear properly, a callback is used to guarantee the event data
    // is loaded before the check to see if the promotion should be displayed.
    feature_engagement::TrackerFactory::GetForBrowserState(self.browserState)
        ->AddOnInitializedCallback(base::BindBlockArc(onInitializedBlock));
  }
}

- (void)presentNewTabTipBubble {
  DCHECK(self.browserState);
  // If the BVC is not visible, do not present the bubble.
  if (!self.viewVisible)
    return;
  // Do not present the bubble if there is no current tab or if the current tab
  // is the NTP.
  Tab* currentTab = [self.tabModel currentTab];
  if (!currentTab)
    return;
  if (currentTab.webState->GetVisibleURL() == kChromeUINewTabURL)
    return;

  // Do not present the bubble if the tab is not scrolled to the top.
  if (![self isTabScrolledToTop:currentTab])
    return;

  NSString* text =
      l10n_util::GetNSStringWithFixup(IDS_IOS_NEW_TAB_IPH_PROMOTION_TEXT);
  CGPoint tabSwitcherAnchor;
  if (IsIPadIdiom()) {
    tabSwitcherAnchor = [self.tabStripCoordinator
        anchorPointForTabSwitcherButton:BubbleArrowDirectionUp];
  } else {
    UILayoutGuide* guide =
        [NamedGuide guideWithName:kTabSwitcherGuide view:self.view];
    DCHECK(guide);
    CGPoint anchorPoint =
        bubble_util::AnchorPoint(guide.layoutFrame, BubbleArrowDirectionUp);
    tabSwitcherAnchor = [guide.owningView convertPoint:anchorPoint
                                                toView:guide.owningView.window];
  }

  // If the feature engagement tracker does not consider it valid to display
  // the new tab tip, then end early to prevent the potential reassignment
  // of the existing |tabTipBubblePresenter| to nil.
  BubbleViewControllerPresenter* presenter =
      [self bubblePresenterForFeature:feature_engagement::kIPHNewTabTipFeature
                            direction:BubbleArrowDirectionUp
                            alignment:BubbleAlignmentTrailing
                                 text:text];
  if (!presenter)
    return;

  self.tabTipBubblePresenter = presenter;

  [self.tabTipBubblePresenter presentInViewController:self
                                                 view:self.view
                                          anchorPoint:tabSwitcherAnchor];
}

- (void)presentNewIncognitoTabTipBubbleOnInitialized {
  DCHECK(self.browserState);
  // Do not override |incognitoTabtipBubblePresenter| or set it to nil if the
  // user is still considered engaged.
  if (!self.incognitoTabTipBubblePresenter.isUserEngaged) {
    __weak BrowserViewController* weakSelf = self;
    void (^onInitializedBlock)(bool) = ^(bool successfullyLoaded) {
      [weakSelf presentNewIncognitoTabTipBubble];
    };

    // Use a callback in case the new incognito tab tip should be shown on
    // startup. This ensures that the tracker's database will be fully loaded
    // before checking if the promotion should be displayed.
    feature_engagement::TrackerFactory::GetForBrowserState(self.browserState)
        ->AddOnInitializedCallback(base::BindBlockArc(onInitializedBlock));
  }
}

- (void)presentNewIncognitoTabTipBubble {
  DCHECK(self.browserState);
  // If the BVC is not visible, do not present the bubble.
  if (!self.viewVisible)
    return;

  // Do not present the bubble if there is no current tab.
  Tab* currentTab = [self.tabModel currentTab];
  if (!currentTab)
    return;

  // Do not present the bubble if the tab is not scrolled to the top.
  if (![self isTabScrolledToTop:currentTab])
    return;

  NSString* text = l10n_util::GetNSStringWithFixup(
      IDS_IOS_NEW_INCOGNITO_TAB_IPH_PROMOTION_TEXT);
  CGPoint toolsButtonAnchor;
  UILayoutGuide* guide =
      [NamedGuide guideWithName:kToolsMenuGuide view:self.view];
  DCHECK(guide);
  CGPoint anchorPoint =
      bubble_util::AnchorPoint(guide.layoutFrame, BubbleArrowDirectionUp);
  toolsButtonAnchor = [guide.owningView convertPoint:anchorPoint
                                              toView:guide.owningView.window];

  // If the feature engagement tracker does not consider it valid to display
  // the incognito tab tip, then end early to prevent the potential reassignment
  // of the existing |incognitoTabTipBubblePresenter| to nil.
  BubbleViewControllerPresenter* presenter =
      [self bubblePresenterForFeature:feature_engagement::
                                          kIPHNewIncognitoTabTipFeature
                            direction:BubbleArrowDirectionUp
                            alignment:BubbleAlignmentTrailing
                                 text:text];
  if (!presenter)
    return;

  self.incognitoTabTipBubblePresenter = presenter;

  [self.incognitoTabTipBubblePresenter
      presentInViewController:self
                         view:self.view
                  anchorPoint:toolsButtonAnchor];
  [self.dispatcher triggerToolsMenuButtonAnimation];
}

#pragma mark - Private Methods: Find Bar UI

- (void)hideFindBarWithAnimation:(BOOL)animate {
  [_findBarController hideFindBarView:animate];
}

- (void)showFindBarWithAnimation:(BOOL)animate
                      selectText:(BOOL)selectText
                     shouldFocus:(BOOL)shouldFocus {
  DCHECK(_findBarController);
  Tab* tab = [_model currentTab];
  DCHECK(tab);
  CRWWebController* webController = tab.webController;

  CGRect referenceFrame = CGRectZero;
  if (IsIPadIdiom()) {
    referenceFrame = webController.visibleFrame;
    referenceFrame.origin.y -= kIPadFindBarOverlap;
  } else {
    referenceFrame = self.contentArea.frame;
  }

  CGRect omniboxFrame =
      [NamedGuide guideWithName:kOmniboxGuide view:self.view].layoutFrame;
  [_findBarController addFindBarView:animate
                            intoView:self.view
                           withFrame:referenceFrame
                      alignWithFrame:omniboxFrame
                          selectText:selectText];
  [self updateFindBar:YES shouldFocus:shouldFocus];
}

- (void)updateFindBar:(BOOL)initialUpdate shouldFocus:(BOOL)shouldFocus {
  // TODO(crbug.com/731045): This early return temporarily replaces a DCHECK.
  // For unknown reasons, this DCHECK sometimes was hit in the wild, resulting
  // in a crash.
  if (![_model currentTab]) {
    return;
  }
  auto* helper = FindTabHelper::FromWebState([_model currentTab].webState);
  if (helper && helper->IsFindUIActive()) {
    if (initialUpdate && !_isOffTheRecord) {
      helper->RestoreSearchTerm();
    }

    [self setFramesForHeaders:[self headerViews]
                     atOffset:[self currentHeaderOffset]];
    [_findBarController updateView:helper->GetFindResult()
                     initialUpdate:initialUpdate
                    focusTextfield:shouldFocus];
  } else {
    [self hideFindBarWithAnimation:YES];
  }
}

- (void)reshowFindBarIfNeededWithCoordinator:
    (id<UIViewControllerTransitionCoordinator>)coordinator {
  if (![_findBarController isFindInPageShown])
    return;

  // Record focused state.
  BOOL isFocusedBeforeReshow = [_findBarController isFocused];

  [self hideFindBarWithAnimation:NO];

  __weak BrowserViewController* weakSelf = self;
  void (^completion)(id<UIViewControllerTransitionCoordinatorContext>) =
      ^(id<UIViewControllerTransitionCoordinatorContext> context) {
        BrowserViewController* strongSelf = weakSelf;
        if (strongSelf)
          [strongSelf showFindBarWithAnimation:NO
                                    selectText:NO
                                   shouldFocus:isFocusedBeforeReshow];
      };

  BOOL enqueued =
      [coordinator animateAlongsideTransition:nil completion:completion];
  if (!enqueued) {
    completion(nil);
  }
}

#pragma mark - Private Methods: Alerts

- (void)showErrorAlertWithStringTitle:(NSString*)title
                              message:(NSString*)message {
  // Dismiss current alert.
  [_alertCoordinator stop];

  _alertCoordinator = [_dependencyFactory alertCoordinatorWithTitle:title
                                                            message:message
                                                     viewController:self];
  [_alertCoordinator start];
}

- (void)showSnackbar:(NSString*)text {
  MDCSnackbarMessage* message = [MDCSnackbarMessage messageWithText:text];
  message.accessibilityLabel = text;
  message.duration = 2.0;
  message.category = kBrowserViewControllerSnackbarCategory;
  [self.dispatcher showSnackbarMessage:message];
}

#pragma mark - Private Methods: Tap handling

- (void)setLastTapPoint:(OpenNewTabCommand*)command {
  if (CGPointEqualToPoint(command.originPoint, CGPointZero)) {
    _lastTapPoint = CGPointZero;
  } else {
    _lastTapPoint =
        [self.view.window convertPoint:command.originPoint toView:self.view];
  }
  _lastTapTime = CACurrentMediaTime();
}

- (CGPoint)lastTapPoint {
  if (CACurrentMediaTime() - _lastTapTime < 1) {
    return _lastTapPoint;
  }
  return CGPointZero;
}

- (void)saveContentAreaTapLocation:(UIGestureRecognizer*)gestureRecognizer {
  UIView* view = gestureRecognizer.view;
  CGPoint viewCoordinate = [gestureRecognizer locationInView:view];
  _lastTapPoint =
      [[view superview] convertPoint:viewCoordinate toView:self.view];
  _lastTapTime = CACurrentMediaTime();
}

#pragma mark - Private Methods: Tab creation and selection

// Called when either a tab finishes loading or when a tab with finished content
// is added directly to the model via pre-rendering.
- (void)tabLoadComplete:(Tab*)tab withSuccess:(BOOL)success {
  DCHECK(tab && ([_model indexOfTab:tab] != NSNotFound));

  // Persist the session on a delay.
  [_model saveSessionImmediately:NO];
}

- (Tab*)addSelectedTabWithURL:(const GURL&)url
                     postData:(TemplateURLRef::PostContent*)postData
                   transition:(ui::PageTransition)transition {
  return [self addSelectedTabWithURL:url
                            postData:postData
                             atIndex:[_model count]
                          transition:transition
                  tabAddedCompletion:nil];
}

- (Tab*)addSelectedTabWithURL:(const GURL&)URL
                     postData:(TemplateURLRef::PostContent*)postData
                      atIndex:(NSUInteger)position
                   transition:(ui::PageTransition)transition
           tabAddedCompletion:(ProceduralBlock)tabAddedCompletion {
  if (position == NSNotFound)
    position = [_model count];
  DCHECK(position <= [_model count]);

  web::NavigationManager::WebLoadParams params(URL);
  params.transition_type = transition;
  if (postData) {
    // Extract the content type and post params from |postData| and add them
    // to the load params.
    NSString* contentType = base::SysUTF8ToNSString(postData->first);
    NSData* data = [NSData dataWithBytes:(void*)postData->second.data()
                                  length:postData->second.length()];
    params.post_data = data;
    params.extra_headers = @{@"Content-Type" : contentType};
  }

  if (tabAddedCompletion) {
    if (self.foregroundTabWasAddedCompletionBlock) {
      ProceduralBlock oldForegroundTabWasAddedCompletionBlock =
          self.foregroundTabWasAddedCompletionBlock;
      self.foregroundTabWasAddedCompletionBlock = ^{
        oldForegroundTabWasAddedCompletionBlock();
        tabAddedCompletion();
      };
    } else {
      self.foregroundTabWasAddedCompletionBlock = tabAddedCompletion;
    }
  }

  Tab* tab = [_model insertTabWithLoadParams:params
                                      opener:nil
                                 openedByDOM:NO
                                     atIndex:position
                                inBackground:NO];
  return tab;
}

- (BOOL)isTabNativePage:(Tab*)tab {
  web::WebState* webState = tab.webState;
  if (!webState)
    return NO;
  web::NavigationItem* visibleItem =
      webState->GetNavigationManager()->GetVisibleItem();
  if (!visibleItem)
    return NO;
  return web::GetWebClient()->IsAppSpecificURL(visibleItem->GetURL());
}

- (UIImageView*)pageOpenCloseAnimationView {
  CGRect frame = self.contentArea.bounds;

  frame.size.height = frame.size.height - self.headerHeight;
  frame.origin.y = self.headerHeight;

  UIImageView* pageView = [[UIImageView alloc] initWithFrame:frame];
  CGPoint center = CGPointMake(CGRectGetMidX(frame), CGRectGetMidY(frame));
  pageView.center = center;

  pageView.backgroundColor = [UIColor whiteColor];
  return pageView;
}

- (void)installDelegatesForTab:(Tab*)tab {
  // Unregistration happens when the Tab is removed from the TabModel.
  DCHECK_NE(tab.webState->GetDelegate(), _webStateDelegate.get());

  // There should be no pre-rendered Tabs in TabModel.
  PrerenderService* prerenderService =
      PrerenderServiceFactory::GetForBrowserState(_browserState);
  DCHECK(!prerenderService ||
         !prerenderService->IsWebStatePrerendered(tab.webState));

  SnapshotTabHelper::FromWebState(tab.webState)->SetDelegate(self);

  // TODO(crbug.com/777557): do not pass the dispatcher to PasswordTabHelper.
  if (PasswordTabHelper* passwordTabHelper =
          PasswordTabHelper::FromWebState(tab.webState)) {
    passwordTabHelper->SetBaseViewController(self);
    passwordTabHelper->SetDispatcher(self.dispatcher);
    passwordTabHelper->SetPasswordControllerDelegate(self);
  }

  if (AutofillTabHelper* autofillTabHelper =
          AutofillTabHelper::FromWebState(tab.webState)) {
    autofillTabHelper->SetBaseViewController(self);
  }

  tab.dialogDelegate = self;
  if (!IsIPadIdiom()) {
    tab.overscrollActionsControllerDelegate = self;
  }
  // Install the proper CRWWebController delegates.
  tab.webController.nativeProvider = self;
  tab.webController.swipeRecognizerProvider = self.sideSwipeController;
  StoreKitTabHelper* tabHelper = StoreKitTabHelper::FromWebState(tab.webState);
  if (tabHelper)
    tabHelper->SetLauncher(_storeKitCoordinator);
  tab.webState->SetDelegate(_webStateDelegate.get());
  // BrowserViewController owns the coordinator that displays the Sad Tab.
  if (!SadTabTabHelper::FromWebState(tab.webState)) {
    SadTabTabHelper::CreateForWebState(tab.webState, _sadTabCoordinator);
  }
  PrintTabHelper::CreateForWebState(tab.webState, self);
  RepostFormTabHelper::CreateForWebState(tab.webState, self);
  NetExportTabHelper::CreateForWebState(tab.webState, self);
  CaptivePortalDetectorTabHelper::CreateForWebState(tab.webState, self);
  PassKitTabHelper::CreateForWebState(tab.webState, _passKitCoordinator);
  AppLauncherTabHelper::CreateForWebState(
      tab.webState, [[ExternalAppsLaunchPolicyDecider alloc] init],
      _appLauncherCoordinator);

  // DownloadManagerTabHelper cannot function without delegate.
  DCHECK(_downloadManagerCoordinator);
  DownloadManagerTabHelper::CreateForWebState(tab.webState,
                                              _downloadManagerCoordinator);

  // The language detection helper accepts a callback from the translate
  // client, so must be created after it.
  // This will explode if the webState doesn't have a JS injection manager
  // (this only comes up in unit tests), so check for that and bypass the
  // init of the translation helpers if needed.
  // TODO(crbug.com/785238): Remove the need for this check.
  if (tab.webState->GetJSInjectionReceiver()) {
    ChromeIOSTranslateClient::CreateForWebState(tab.webState,
                                                _languageSelectionCoordinator);
    language::IOSLanguageDetectionTabHelper::CreateForWebState(
        tab.webState,
        ChromeIOSTranslateClient::FromWebState(tab.webState)
            ->GetTranslateDriver()
            ->CreateLanguageDetectionCallback(),
        UrlLanguageHistogramFactory::GetForBrowserState(self.browserState));
  }

  if (AccountConsistencyService* accountConsistencyService =
          ios::AccountConsistencyServiceFactory::GetForBrowserState(
              self.browserState)) {
    accountConsistencyService->SetWebStateHandler(tab.webState, self);
  }
}

- (void)uninstallDelegatesForTab:(Tab*)tab {
  DCHECK_EQ(tab.webState->GetDelegate(), _webStateDelegate.get());

  // TODO(crbug.com/777557): do not pass the dispatcher to PasswordTabHelper.
  if (PasswordTabHelper* passwordTabHelper =
          PasswordTabHelper::FromWebState(tab.webState)) {
    passwordTabHelper->SetDispatcher(nil);
  }

  tab.dialogDelegate = nil;
  if (!IsIPadIdiom()) {
    tab.overscrollActionsControllerDelegate = nil;
  }
  tab.webController.nativeProvider = nil;
  tab.webController.swipeRecognizerProvider = nil;
  StoreKitTabHelper* tabHelper = StoreKitTabHelper::FromWebState(tab.webState);
  if (tabHelper)
    tabHelper->SetLauncher(nil);
  tab.webState->SetDelegate(nullptr);
  if (AccountConsistencyService* accountConsistencyService =
          ios::AccountConsistencyServiceFactory::GetForBrowserState(
              self.browserState)) {
    accountConsistencyService->RemoveWebStateHandler(tab.webState);
  }

  SnapshotTabHelper::FromWebState(tab.webState)->SetDelegate(nil);
}

- (void)tabSelected:(Tab*)tab notifyToolbar:(BOOL)notifyToolbar {
  DCHECK(tab);

  // Ignore changes while the tab stack view is visible (or while suspended).
  // The display will be refreshed when this view becomes active again.
  if (!self.visible || ![_model webUsageEnabled])
    return;

  [self displayTab:tab];

  if (_expectingForegroundTab && !self.inNewTabAnimation) {
    // Now that the new tab has been displayed, return to normal. Rather than
    // keep a reference to the previous tab, just turn off preview mode for all
    // tabs (since doing so is a no-op for the tabs that don't have it set).
    _expectingForegroundTab = NO;

    WebStateList* webStateList = _model.webStateList;
    for (int index = 0; index < webStateList->count(); ++index) {
      web::WebState* webState = webStateList->GetWebStateAt(index);
      PagePlaceholderTabHelper::FromWebState(webState)
          ->CancelPlaceholderForNextNavigation();
    }
  }
}

- (id)nativeControllerForTab:(Tab*)tab {
  id nativeController = tab.webController.nativeController;
  return nativeController ? nativeController : _temporaryNativeController;
}

#pragma mark - Private Methods: Voice Search

- (void)ensureVoiceSearchControllerCreated {
  if (!_voiceSearchController) {
    VoiceSearchProvider* provider =
        ios::GetChromeBrowserProvider()->GetVoiceSearchProvider();
    if (provider) {
      _voiceSearchController =
          provider->CreateVoiceSearchController(_browserState);
      _voiceSearchController->SetDelegate(
          [self.primaryToolbarCoordinator voiceSearchDelegate]);
    }
  }
}

- (void)ensureVoiceSearchBarCreated {
  if (_voiceSearchBar || IsUIRefreshPhase1Enabled())
    return;

  CGFloat width = CGRectGetWidth([[self view] bounds]);
  CGFloat y = CGRectGetHeight([[self view] bounds]) - kVoiceSearchBarHeight;
  CGRect frame = CGRectMake(0.0, y, width, kVoiceSearchBarHeight);
  _voiceSearchBar = ios::GetChromeBrowserProvider()
                        ->GetVoiceSearchProvider()
                        ->BuildVoiceSearchBar(frame, self.dispatcher);
  [_voiceSearchBar setVoiceSearchBarDelegate:self];
  [_voiceSearchBar setHidden:YES];
  [_voiceSearchBar setAutoresizingMask:UIViewAutoresizingFlexibleTopMargin |
                                       UIViewAutoresizingFlexibleWidth];
  [self.view insertSubview:_voiceSearchBar
              belowSubview:_infoBarContainer->view()];
}

- (void)updateVoiceSearchBarVisibilityAnimated:(BOOL)animated {
  // Voice search bar exists and is shown/hidden.
  BOOL show = self.shouldShowVoiceSearchBar;
  if (_voiceSearchBar && _voiceSearchBar.hidden != show)
    return;

  // Voice search bar doesn't exist and thus is not visible.
  if (!_voiceSearchBar && !show)
    return;

  if (animated)
    [_voiceSearchBar animateToBecomeVisible:show];
  else
    _voiceSearchBar.hidden = !show;
}

#pragma mark - Private Methods: Reading List

- (void)addToReadingListURL:(const GURL&)URL title:(NSString*)title {
  base::RecordAction(UserMetricsAction("MobileReadingListAdd"));

  ReadingListModel* readingModel =
      ReadingListModelFactory::GetForBrowserState(_browserState);
  readingModel->AddEntry(URL, base::SysNSStringToUTF8(title),
                         reading_list::ADDED_VIA_CURRENT_APP);

  TriggerHapticFeedbackForNotification(UINotificationFeedbackTypeSuccess);
  [self showSnackbar:l10n_util::GetNSString(
                         IDS_IOS_READING_LIST_SNACKBAR_MESSAGE)];
}

#pragma mark - Private Methods: Recent Tabs

- (void)createRecentTabsCoordinator {
  if (experimental_flags::IsRecentTabsUIRebootEnabled()) {
    // New RecentTabs UIReboot coordinator.
    RecentTabsCoordinator* recentTabsCoordinator = [
        [RecentTabsCoordinator alloc] initWithBaseViewController:self
                                                    browserState:_browserState];
    recentTabsCoordinator.loader = self;
    recentTabsCoordinator.dispatcher = self.dispatcher;
    self.recentTabsCoordinator = recentTabsCoordinator;
  } else {
    // Legacy RecentTabs coordinator.
    RecentTabsHandsetCoordinator* recentTabsCoordinator =
        [[RecentTabsHandsetCoordinator alloc] initWithBaseViewController:self];
    recentTabsCoordinator.loader = self;
    recentTabsCoordinator.dispatcher = self.dispatcher;
    recentTabsCoordinator.browserState = _browserState;
    self.recentTabsCoordinator = recentTabsCoordinator;
  }
}

#pragma mark - ** Protocol Implementations and Helpers **

#pragma mark - SnapshotGeneratorDelegate methods

- (BOOL)canTakeSnapshotForWebState:(web::WebState*)webState {
  DCHECK(webState);
  Tab* tab = LegacyTabHelper::GetTabForWebState(webState);
  DCHECK([self.tabModel indexOfTab:tab] != NSNotFound);
  PagePlaceholderTabHelper* pagePlaceholderTabHelper =
      PagePlaceholderTabHelper::FromWebState(webState);
  return !pagePlaceholderTabHelper->displaying_placeholder() &&
         !pagePlaceholderTabHelper->will_add_placeholder_for_next_navigation();
}

- (UIEdgeInsets)snapshotEdgeInsetsForWebState:(web::WebState*)webState {
  DCHECK(webState);
  Tab* tab = LegacyTabHelper::GetTabForWebState(webState);
  DCHECK([self.tabModel indexOfTab:tab] != NSNotFound);

  CGFloat headerHeight = [self headerHeightForTab:tab];
  id nativeController = [self nativeControllerForTab:tab];
  if ([nativeController respondsToSelector:@selector(toolbarHeight)])
    headerHeight += [nativeController toolbarHeight];
  return UIEdgeInsetsMake(headerHeight, 0.0, 0.0, 0.0);
}

- (NSArray<SnapshotOverlay*>*)snapshotOverlaysForWebState:
    (web::WebState*)webState {
  DCHECK(webState);
  Tab* tab = LegacyTabHelper::GetTabForWebState(webState);
  DCHECK([self.tabModel indexOfTab:tab] != NSNotFound);
  if (!self.tabModel.webUsageEnabled) {
    return @[];
  }

  NSMutableArray* overlays = [NSMutableArray array];
  UIView* voiceSearchView = [self voiceSearchOverlayViewForTab:tab];
  if (voiceSearchView) {
    CGFloat voiceSearchYOffset = [self voiceSearchOverlayYOffsetForTab:tab];
    SnapshotOverlay* voiceSearchOverlay =
        [[SnapshotOverlay alloc] initWithView:voiceSearchView
                                      yOffset:voiceSearchYOffset];
    [overlays addObject:voiceSearchOverlay];
  }
  UIView* infoBarView = [self infoBarOverlayViewForTab:tab];
  if (infoBarView) {
    CGFloat infoBarYOffset = [self infoBarOverlayYOffsetForTab:tab];
    SnapshotOverlay* infoBarOverlay =
        [[SnapshotOverlay alloc] initWithView:infoBarView
                                      yOffset:infoBarYOffset];
    [overlays addObject:infoBarOverlay];
  }

  UIView* downloadManagerView = _downloadManagerCoordinator.viewController.view;
  if (downloadManagerView) {
    CGFloat offset = [self downloadManagerOverlayYOffsetForTab:tab];
    SnapshotOverlay* downloadManagerOverlay =
        [[SnapshotOverlay alloc] initWithView:downloadManagerView
                                      yOffset:offset];
    [overlays addObject:downloadManagerOverlay];
  }

  return overlays;
}

- (void)willUpdateSnapshotForWebState:(web::WebState*)webState {
  DCHECK(webState);
  Tab* tab = LegacyTabHelper::GetTabForWebState(webState);
  DCHECK([self.tabModel indexOfTab:tab] != NSNotFound);
  id<CRWNativeContent> nativeController = [self nativeControllerForTab:tab];
  if ([nativeController respondsToSelector:@selector(willUpdateSnapshot)]) {
    [nativeController willUpdateSnapshot];
  }
  [tab willUpdateSnapshot];
}

- (void)didUpdateSnapshotForWebState:(web::WebState*)webState
                           withImage:(UIImage*)snapshot {
  DCHECK(webState);
  Tab* tab = LegacyTabHelper::GetTabForWebState(webState);
  DCHECK([self.tabModel indexOfTab:tab] != NSNotFound);
  [self.tabModel notifyTabSnapshotChanged:tab withImage:snapshot];
}

#pragma mark - SnapshotGeneratorDelegate helpers

// Provides a view that encompasses currently displayed infobar(s) or nil
// if no infobar is presented.
- (UIView*)infoBarOverlayViewForTab:(Tab*)tab {
  if (IsIPadIdiom()) {
    // Not using overlays on iPad because the content is pushed down by
    // infobar and the transition between snapshot and fresh page can
    // cause both snapshot and real infobars to appear at the same time.
    return nil;
  }
  Tab* currentTab = [_model currentTab];
  if (currentTab && tab == currentTab) {
    DCHECK(currentTab.webState);
    infobars::InfoBarManager* infoBarManager =
        InfoBarManagerImpl::FromWebState(currentTab.webState);
    if (infoBarManager->infobar_count() > 0) {
      DCHECK(_infoBarContainer);
      return _infoBarContainer->view();
    }
  }
  return nil;
}

// Returns a vertical infobar offset relative to the tab content.
- (CGFloat)infoBarOverlayYOffsetForTab:(Tab*)tab {
  if (tab != [_model currentTab] || !_infoBarContainer) {
    // There is no UI representation for non-current tabs or there is
    // no _infoBarContainer instantiated yet.
    // Return offset outside of tab.
    return CGRectGetMaxY(self.view.frame);
  } else if (IsIPadIdiom()) {
    // The infobars on iPad are display at the top of a tab.
    return CGRectGetMinY([[_model currentTab].webController visibleFrame]);
  } else {
    // The infobars on iPhone are displayed at the bottom of a tab.
    CGRect visibleFrame = [[_model currentTab].webController visibleFrame];
    return CGRectGetMaxY(visibleFrame) -
           CGRectGetHeight(_infoBarContainer->view().frame);
  }
}

// Returns a vertical download manager offset relative to the tab content.
- (CGFloat)downloadManagerOverlayYOffsetForTab:(Tab*)tab {
  return CGRectGetMaxY([tab.webController visibleFrame]) -
         CGRectGetHeight(_downloadManagerCoordinator.viewController.view.frame);
}

// Provides a view that encompasses the voice search bar if it's displayed or
// nil if the voice search bar isn't displayed.
- (UIView*)voiceSearchOverlayViewForTab:(Tab*)tab {
  Tab* currentTab = [_model currentTab];
  if (tab && tab == currentTab && tab.isVoiceSearchResultsTab &&
      _voiceSearchBar && ![_voiceSearchBar isHidden]) {
    return _voiceSearchBar;
  }
  return nil;
}

// Returns a vertical voice search bar offset relative to the tab content.
- (CGFloat)voiceSearchOverlayYOffsetForTab:(Tab*)tab {
  if (tab != [_model currentTab] || [_voiceSearchBar isHidden]) {
    // There is no UI representation for non-current tabs or there is
    // no visible voice search. Return offset outside of tab.
    return CGRectGetMaxY(self.view.frame);
  } else {
    // The voice search bar on iPhone is displayed at the bottom of a tab.
    CGRect visibleFrame = [[_model currentTab].webController visibleFrame];
    return CGRectGetMaxY(visibleFrame) - kVoiceSearchBarHeight;
  }
}

#pragma mark - PasswordControllerDelegate methods

- (BOOL)displaySignInNotification:(UIViewController*)viewController
                        fromTabId:(NSString*)tabId {
  // Check if the call comes from currently visible tab.
  if ([tabId isEqual:[_model currentTab].tabId]) {
    [self addChildViewController:viewController];
    [self.view addSubview:viewController.view];
    [viewController didMoveToParentViewController:self];
    return YES;
  } else {
    return NO;
  }
}

- (void)displaySavedPasswordList {
  [self.dispatcher showSavedPasswordsSettingsFromViewController:self];
}

#pragma mark - CRWWebStateDelegate methods.

- (web::WebState*)webState:(web::WebState*)webState
    createNewWebStateForURL:(const GURL&)URL
                  openerURL:(const GURL&)openerURL
            initiatedByUser:(BOOL)initiatedByUser {
  // Check if requested web state is a popup and block it if necessary.
  if (!initiatedByUser) {
    auto* helper = BlockedPopupTabHelper::FromWebState(webState);
    if (helper->ShouldBlockPopup(openerURL)) {
      // It's possible for a page to inject a popup into a window created via
      // window.open before its initial load is committed.  Rather than relying
      // on the last committed or pending NavigationItem's referrer policy, just
      // use ReferrerPolicyDefault.
      // TODO(crbug.com/719993): Update this to a more appropriate referrer
      // policy once referrer policies are correctly recorded in
      // NavigationItems.
      web::Referrer referrer(openerURL, web::ReferrerPolicyDefault);
      helper->HandlePopup(URL, referrer);
      return nil;
    }
  }

  // Requested web state should not be blocked from opening.
  Tab* currentTab = LegacyTabHelper::GetTabForWebState(webState);
  SnapshotTabHelper::FromWebState(currentTab.webState)
      ->UpdateSnapshot(/*with_overlays=*/true, /*visible_frame_only=*/true);

  Tab* childTab = [[self tabModel] insertOpenByDOMTabWithOpener:currentTab];

  return childTab.webState;
}

- (void)closeWebState:(web::WebState*)webState {
  // Only allow a web page to close itself if it was opened by DOM, or if there
  // are no navigation items.
  Tab* tab = LegacyTabHelper::GetTabForWebState(webState);
  DCHECK(webState->HasOpener() || ![tab navigationManager]->GetItemCount());

  if (![self tabModel])
    return;

  NSUInteger index = [[self tabModel] indexOfTab:tab];
  if (index != NSNotFound)
    [[self tabModel] closeTabAtIndex:index];
}

- (web::WebState*)webState:(web::WebState*)webState
         openURLWithParams:(const web::WebState::OpenURLParams&)params {
  switch (params.disposition) {
    case WindowOpenDisposition::NEW_FOREGROUND_TAB:
    case WindowOpenDisposition::NEW_BACKGROUND_TAB: {
      Tab* tab = [[self tabModel]
          insertTabWithURL:params.url
                  referrer:params.referrer
                transition:params.transition
                    opener:LegacyTabHelper::GetTabForWebState(webState)
               openedByDOM:NO
                   atIndex:TabModelConstants::kTabPositionAutomatically
              inBackground:(params.disposition ==
                            WindowOpenDisposition::NEW_BACKGROUND_TAB)];
      return tab.webState;
    }
    case WindowOpenDisposition::CURRENT_TAB: {
      web::NavigationManager::WebLoadParams loadParams(params.url);
      loadParams.referrer = params.referrer;
      loadParams.transition_type = params.transition;
      loadParams.is_renderer_initiated = params.is_renderer_initiated;
      webState->GetNavigationManager()->LoadURLWithParams(loadParams);
      return webState;
    }
    case WindowOpenDisposition::NEW_POPUP: {
      Tab* tab = [[self tabModel]
          insertTabWithURL:params.url
                  referrer:params.referrer
                transition:params.transition
                    opener:LegacyTabHelper::GetTabForWebState(webState)
               openedByDOM:YES
                   atIndex:TabModelConstants::kTabPositionAutomatically
              inBackground:NO];
      return tab.webState;
    }
    default:
      NOTIMPLEMENTED();
      return nullptr;
  };
}

- (void)webState:(web::WebState*)webState
    handleContextMenu:(const web::ContextMenuParams&)params {
  // Prevent context menu from displaying for a tab which is no longer the
  // current one.
  if (webState != [_model currentTab].webState) {
    return;
  }

  // No custom context menu if no valid url is available in |params|.
  if (!params.link_url.is_valid() && !params.src_url.is_valid()) {
    return;
  }

  DCHECK(_browserState);

  _contextMenuCoordinator =
      [[ContextMenuCoordinator alloc] initWithBaseViewController:self
                                                          params:params];

  NSString* title = nil;
  ProceduralBlock action = nil;

  __weak BrowserViewController* weakSelf = self;
  GURL link = params.link_url;
  bool isLink = link.is_valid();
  GURL imageUrl = params.src_url;
  bool isImage = imageUrl.is_valid();
  const GURL& lastCommittedURL = webState->GetLastCommittedURL();

  if (isLink) {
    if (link.SchemeIs(url::kJavaScriptScheme)) {
      // Open
      title = l10n_util::GetNSStringWithFixup(IDS_IOS_CONTENT_CONTEXT_OPEN);
      action = ^{
        Record(ACTION_OPEN_JAVASCRIPT, isImage, isLink);
        [weakSelf openJavascript:base::SysUTF8ToNSString(link.GetContent())];
      };
      [_contextMenuCoordinator addItemWithTitle:title action:action];
    }

    if (web::UrlHasWebScheme(link)) {
      web::Referrer referrer(lastCommittedURL, params.referrer_policy);

      // Open in New Tab.
      title = l10n_util::GetNSStringWithFixup(
          IDS_IOS_CONTENT_CONTEXT_OPENLINKNEWTAB);
      action = ^{
        Record(ACTION_OPEN_IN_NEW_TAB, isImage, isLink);
        // The "New Tab" item in the context menu opens a new tab in the current
        // browser state. |isOffTheRecord| indicates whether or not the current
        // browser state is incognito.
        [weakSelf webPageOrderedOpen:link
                            referrer:referrer
                         inIncognito:weakSelf.isOffTheRecord
                        inBackground:YES
                            appendTo:kCurrentTab];
      };
      [_contextMenuCoordinator addItemWithTitle:title action:action];
      if (!_isOffTheRecord) {
        // Open in Incognito Tab.
        title = l10n_util::GetNSStringWithFixup(
            IDS_IOS_CONTENT_CONTEXT_OPENLINKNEWINCOGNITOTAB);
        action = ^{
          Record(ACTION_OPEN_IN_INCOGNITO_TAB, isImage, isLink);
          [weakSelf webPageOrderedOpen:link
                              referrer:referrer
                           inIncognito:YES
                          inBackground:NO
                              appendTo:kCurrentTab];
        };
        [_contextMenuCoordinator addItemWithTitle:title action:action];
      }
    }
    if (link.SchemeIsHTTPOrHTTPS()) {
      NSString* innerText = params.link_text;
      if ([innerText length] > 0) {
        // Add to reading list.
        title = l10n_util::GetNSStringWithFixup(
            IDS_IOS_CONTENT_CONTEXT_ADDTOREADINGLIST);
        action = ^{
          Record(ACTION_READ_LATER, isImage, isLink);
          [weakSelf addToReadingListURL:link title:innerText];
        };
        [_contextMenuCoordinator addItemWithTitle:title action:action];
      }
    }
    // Copy Link.
    title = l10n_util::GetNSStringWithFixup(IDS_IOS_CONTENT_CONTEXT_COPY);
    action = ^{
      Record(ACTION_COPY_LINK_ADDRESS, isImage, isLink);
      StoreURLInPasteboard(link);
    };
    [_contextMenuCoordinator addItemWithTitle:title action:action];
  }
  if (isImage) {
    web::Referrer referrer(lastCommittedURL, params.referrer_policy);
    // Save Image.
    title = l10n_util::GetNSStringWithFixup(IDS_IOS_CONTENT_CONTEXT_SAVEIMAGE);
    action = ^{
      Record(ACTION_SAVE_IMAGE, isImage, isLink);
      [weakSelf saveImageAtURL:imageUrl referrer:referrer];
    };
    [_contextMenuCoordinator addItemWithTitle:title action:action];
    // Open Image.
    title = l10n_util::GetNSStringWithFixup(IDS_IOS_CONTENT_CONTEXT_OPENIMAGE);
    action = ^{
      Record(ACTION_OPEN_IMAGE, isImage, isLink);
      [weakSelf loadURL:imageUrl
                   referrer:referrer
                 transition:ui::PAGE_TRANSITION_LINK
          rendererInitiated:YES];
    };
    [_contextMenuCoordinator addItemWithTitle:title action:action];
    // Open Image In New Tab.
    title = l10n_util::GetNSStringWithFixup(
        IDS_IOS_CONTENT_CONTEXT_OPENIMAGENEWTAB);
    action = ^{
      Record(ACTION_OPEN_IMAGE_IN_NEW_TAB, isImage, isLink);
      [weakSelf webPageOrderedOpen:imageUrl
                          referrer:referrer
                      inBackground:true
                          appendTo:kCurrentTab];
    };
    [_contextMenuCoordinator addItemWithTitle:title action:action];

    TemplateURLService* service =
        ios::TemplateURLServiceFactory::GetForBrowserState(_browserState);
    const TemplateURL* defaultURL = service->GetDefaultSearchProvider();
    if (defaultURL && !defaultURL->image_url().empty() &&
        defaultURL->image_url_ref().IsValid(service->search_terms_data())) {
      title = l10n_util::GetNSStringF(IDS_IOS_CONTEXT_MENU_SEARCHWEBFORIMAGE,
                                      defaultURL->short_name());
      action = ^{
        Record(ACTION_SEARCH_BY_IMAGE, isImage, isLink);
        [weakSelf searchByImageAtURL:imageUrl referrer:referrer];
      };
      [_contextMenuCoordinator addItemWithTitle:title action:action];
    }
  }

  [_contextMenuCoordinator start];
}

- (void)webState:(web::WebState*)webState
    runRepostFormDialogWithCompletionHandler:(void (^)(BOOL))handler {
  // Display the action sheet with the arrow pointing at the top center of the
  // web contents.
  Tab* tab = LegacyTabHelper::GetTabForWebState(webState);
  UIView* view = webState->GetView();
  CGPoint dialogLocation =
      CGPointMake(CGRectGetMidX(view.frame),
                  CGRectGetMinY(view.frame) + [self headerHeightForTab:tab]);
  auto* helper = RepostFormTabHelper::FromWebState(webState);
  helper->PresentDialog(dialogLocation,
                        base::BindBlockArc(^(bool shouldContinue) {
                          handler(shouldContinue);
                        }));
}

- (web::JavaScriptDialogPresenter*)javaScriptDialogPresenterForWebState:
    (web::WebState*)webState {
  return _javaScriptDialogPresenter.get();
}

- (void)webState:(web::WebState*)webState
    didRequestHTTPAuthForProtectionSpace:(NSURLProtectionSpace*)protectionSpace
                      proposedCredential:(NSURLCredential*)proposedCredential
                       completionHandler:(void (^)(NSString* username,
                                                   NSString* password))handler {
  [self.dialogPresenter runAuthDialogForProtectionSpace:protectionSpace
                                     proposedCredential:proposedCredential
                                               webState:webState
                                      completionHandler:handler];
}

#pragma mark - CRWWebStateDelegate helpers

// Evaluates Javascript asynchronously using the current page context.
- (void)openJavascript:(NSString*)javascript {
  DCHECK(javascript);
  javascript = [javascript stringByRemovingPercentEncoding];
  web::WebState* webState = [[_model currentTab] webState];
  if (webState) {
    webState->ExecuteJavaScript(base::SysNSStringToUTF16(javascript));
  }
}

// Performs a search with the image at the given url. The referrer is used to
// download the image.
- (void)searchByImageAtURL:(const GURL&)url
                  referrer:(const web::Referrer)referrer {
  DCHECK(url.is_valid());
  __weak BrowserViewController* weakSelf = self;
  const GURL image_source_url = url;
  image_fetcher::IOSImageDataFetcherCallback callback =
      ^(NSData* data, const image_fetcher::RequestMetadata& metadata) {
        DCHECK(data);
        dispatch_async(dispatch_get_main_queue(), ^{
          [weakSelf searchByImageData:data atURL:image_source_url];
        });
      };
  _imageFetcher->FetchImageDataWebpDecoded(
      url, callback, web::ReferrerHeaderValueForNavigation(url, referrer),
      web::PolicyForNavigation(url, referrer));
}

// Performs a search using |data| and |imageURL| as inputs.
- (void)searchByImageData:(NSData*)data atURL:(const GURL&)imageURL {
  NSData* imageData = data;
  UIImage* image = [UIImage imageWithData:imageData];
  // Downsize the image if its area exceeds kSearchByImageMaxImageArea AND
  // (either its width exceeds kSearchByImageMaxImageWidth OR its height exceeds
  // kSearchByImageMaxImageHeight).
  if (image &&
      image.size.height * image.size.width > kSearchByImageMaxImageArea &&
      (image.size.width > kSearchByImageMaxImageWidth ||
       image.size.height > kSearchByImageMaxImageHeight)) {
    CGSize newImageSize =
        CGSizeMake(kSearchByImageMaxImageWidth, kSearchByImageMaxImageHeight);
    image = [image gtm_imageByResizingToSize:newImageSize
                         preserveAspectRatio:YES
                                   trimToFit:NO];
    imageData = UIImageJPEGRepresentation(image, 1.0);
  }

  char const* bytes = reinterpret_cast<const char*>([imageData bytes]);
  std::string byteString(bytes, [imageData length]);

  TemplateURLService* templateUrlService =
      ios::TemplateURLServiceFactory::GetForBrowserState(_browserState);
  const TemplateURL* defaultURL =
      templateUrlService->GetDefaultSearchProvider();
  DCHECK(!defaultURL->image_url().empty());
  DCHECK(defaultURL->image_url_ref().IsValid(
      templateUrlService->search_terms_data()));
  TemplateURLRef::SearchTermsArgs search_args(base::ASCIIToUTF16(""));
  search_args.image_url = imageURL;
  search_args.image_thumbnail_content = byteString;

  // Generate the URL and populate |post_content| with the content type and
  // HTTP body for the request.
  TemplateURLRef::PostContent post_content;
  GURL result(defaultURL->image_url_ref().ReplaceSearchTerms(
      search_args, templateUrlService->search_terms_data(), &post_content));
  [self addSelectedTabWithURL:result
                     postData:&post_content
                   transition:ui::PAGE_TRANSITION_TYPED];
}

// Saves the image at the given URL on the system's album.  The referrer is used
// to download the image.
- (void)saveImageAtURL:(const GURL&)url
              referrer:(const web::Referrer&)referrer {
  DCHECK(url.is_valid());

  image_fetcher::IOSImageDataFetcherCallback callback =
      ^(NSData* data, const image_fetcher::RequestMetadata& metadata) {
        [self.imageSaver saveImageData:data withMetadata:metadata];
      };
  _imageFetcher->FetchImageDataWebpDecoded(
      url, callback, web::ReferrerHeaderValueForNavigation(url, referrer),
      web::PolicyForNavigation(url, referrer));
}

- (BOOL)isTabWithIDCurrent:(NSString*)sessionID {
  return self.visible && [sessionID isEqualToString:[_model currentTab].tabId];
}

#pragma mark - OverscrollActionsControllerDelegate methods.

- (void)overscrollActionsController:(OverscrollActionsController*)controller
                   didTriggerAction:(OverscrollAction)action {
  switch (action) {
    case OverscrollAction::NEW_TAB:
      [self.dispatcher
          openNewTab:[OpenNewTabCommand
                         commandWithIncognito:self.isOffTheRecord]];
      break;
    case OverscrollAction::CLOSE_TAB:
      [self.dispatcher closeCurrentTab];
      break;
    case OverscrollAction::REFRESH:
      // Instruct the SnapshotTabHelper to ignore the next load event.
      // Attempting to snapshot while the overscroll "bounce back" animation is
      // occurring will cut the animation short.
      DCHECK(self.currentWebState);
      SnapshotTabHelper::FromWebState(self.currentWebState)->IgnoreNextLoad();
      [self reload];
      break;
    case OverscrollAction::NONE:
      NOTREACHED();
      break;
  }
}

- (BOOL)shouldAllowOverscrollActions {
  return YES;
}

- (UIView*)headerView {
  return self.primaryToolbarCoordinator.viewController.view;
}

- (UIView*)toolbarSnapshotView {
  return [self.primaryToolbarCoordinator.viewController.view
      snapshotViewAfterScreenUpdates:NO];
}

- (CGFloat)overscrollActionsControllerHeaderInset:
    (OverscrollActionsController*)controller {
  if (controller == [[[self tabModel] currentTab] overscrollActionsController])
    return self.headerHeight;
  else
    return 0;
}

- (CGFloat)overscrollHeaderHeight {
  return self.headerHeight + StatusBarHeight();
}

#pragma mark - CRWNativeContentProvider methods

// TODO(crbug.com/725241): This method is deprecated and should be removed by
// switching to DidFinishnavigation.
- (id<CRWNativeContent>)controllerForURL:(const GURL&)url
                               withError:(NSError*)error
                                  isPost:(BOOL)isPost {
  ErrorPageContent* errorPageContent =
      [[ErrorPageContent alloc] initWithLoader:self
                                  browserState:self.browserState
                                           url:url
                                         error:error
                                        isPost:isPost
                                   isIncognito:_isOffTheRecord];
  [self setOverScrollActionControllerToStaticNativeContent:errorPageContent];
  return errorPageContent;
}

- (BOOL)hasControllerForURL:(const GURL&)url {
  base::StringPiece host = url.host_piece();
  if (host == kChromeUIOfflineHost) {
    // Only allow offline URL that are fully specified.
    return reading_list::IsOfflineURLValid(
        url, ReadingListModelFactory::GetForBrowserState(_browserState));
  }
  return host == kChromeUINewTabHost;
}

- (id<CRWNativeContent>)controllerForURL:(const GURL&)url
                                webState:(web::WebState*)webState {
  DCHECK(url.SchemeIs(kChromeUIScheme));

  id<CRWNativeContent> nativeController = nil;
  base::StringPiece url_host = url.host_piece();
  if (url_host == kChromeUINewTabHost) {
    CGFloat fakeStatusBarHeight = _fakeStatusBarView.frame.size.height;
    UIEdgeInsets safeAreaInset = UIEdgeInsetsZero;
    if (@available(iOS 11.0, *)) {
      safeAreaInset = self.view.safeAreaInsets;
    }
    safeAreaInset.top = MAX(safeAreaInset.top - fakeStatusBarHeight, 0);

    NewTabPageController* pageController = [[NewTabPageController alloc]
                 initWithUrl:url
                      loader:self
                     focuser:self.dispatcher
                browserState:_browserState
             toolbarDelegate:self.toolbarInterface
                    tabModel:_model
        parentViewController:_browserContainerViewController
                  dispatcher:self.dispatcher
               safeAreaInset:safeAreaInset];
    pageController.swipeRecognizerProvider = self.sideSwipeController;
    nativeController = pageController;
  } else if (url_host == kChromeUIOfflineHost &&
             [self hasControllerForURL:url]) {
    StaticHtmlNativeContent* staticNativeController =
        [[OfflinePageNativeContent alloc] initWithLoader:self
                                            browserState:_browserState
                                                webState:webState
                                                     URL:url];
    [self setOverScrollActionControllerToStaticNativeContent:
              staticNativeController];
    nativeController = staticNativeController;
  } else if (url_host == kChromeUIExternalFileHost) {
    // Return an instance of the |ExternalFileController| only if the file is
    // still in the sandbox.
    NSString* filePath = [ExternalFileController pathForExternalFileURL:url];
    if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
      nativeController =
          [[ExternalFileController alloc] initWithURL:url
                                         browserState:_browserState];
    }
  } else if (url_host == kChromeUICrashHost) {
    // There is no native controller for kChromeUICrashHost, it is instead
    // handled as any other renderer crash by the SadTabTabHelper.
    // nativeController must be set to nil to prevent defaulting to a
    // PageNotAvailableController.
    nativeController = nil;
  } else {
    DCHECK(![self hasControllerForURL:url]);
    // In any other case the PageNotAvailableController is returned.
    nativeController = [[PageNotAvailableController alloc] initWithUrl:url];
  }
  // If a native controller is vended before its tab is added to the tab model,
  // use the temporary key and add it under the new tab's tabId in the
  // TabModelObserver callback.  This happens:
  // - when there is no current tab (occurs when vending the NTP controller for
  //   the first tab that is opened),
  // - when the current tab's url doesn't match |url| (occurs when a native
  //   controller is opened in a new tab)
  // - when the current tab's url matches |url| and there is already a native
  //   controller of the appropriate type vended to it (occurs when a native
  //   controller is opened in a new tab from a tab with a matching URL, e.g.
  //   opening an NTP when an NTP is already displayed in the current tab).
  // For normal page loads, history navigations, tab restorations, and crash
  // recoveries, the tab will already exist in the tab model and the tabId can
  // be used as the native controller key.
  // TODO(crbug.com/498568): To reduce complexity here, refactor the flow so
  // that native controllers vended here always correspond to the current tab.
  Tab* currentTab = [_model currentTab];
  if (!currentTab.webState ||
      currentTab.webState->GetLastCommittedURL() != url ||
      [currentTab.webController.nativeController
          isKindOfClass:[nativeController class]]) {
    _temporaryNativeController = nativeController;
  }
  return nativeController;
}

- (id<CRWNativeContent>)controllerForUnhandledContentAtURL:(const GURL&)URL
                                                  webState:
                                                      (web::WebState*)webState {
  LegacyDownloadManagerController* downloadController =
      [[LegacyDownloadManagerController alloc] initWithWebState:webState
                                              downloadURL:URL
                                       baseViewController:self];
  [downloadController start];
  return downloadController;
}

- (CGFloat)nativeContentHeaderHeightForWebState:(web::WebState*)webState {
  Tab* tab = LegacyTabHelper::GetTabForWebState(webState);
  BOOL isRegularXRegular = IsUIRefreshPhase1Enabled()
                               ? IsRegularXRegularSizeClass(self)
                               : IsIPadIdiom();
  if (IsUIRefreshPhase1Enabled() && tab &&
      tab.webState->GetVisibleURL() == kChromeUINewTabURL &&
      !isRegularXRegular) {
    // Also subtract the top safe area so the view will appear as full screen.
    // TODO(crbug.com/826369) Remove this once NTP is out of native content.
    if (@available(iOS 11, *)) {
      return -self.view.safeAreaInsets.top;
    } else {
      return -self.topLayoutGuide.length;
    }
  }
  return [self headerHeightForTab:tab];
}

- (CGFloat)nativeContentFooterHeightForWebState:(web::WebState*)webState {
  return self.secondaryToolbarHeightConstraint.constant;
}

#pragma mark - DialogPresenterDelegate methods

- (void)dialogPresenter:(DialogPresenter*)presenter
    willShowDialogForWebState:(web::WebState*)webState {
  WebStateList* webStateList = self.tabModel.webStateList;
  int indexOfWebState = webStateList->GetIndexOfWebState(webState);
  if (indexOfWebState != WebStateList::kInvalidIndex) {
    webStateList->ActivateWebStateAt(indexOfWebState);
    DCHECK([webState->GetView() isDescendantOfView:self.contentArea]);
  }
}

#pragma mark - FullscreenUIElement methods

- (void)updateForFullscreenProgress:(CGFloat)progress {
  [self updateHeadersForFullscreenProgress:progress];
  [self updateFootersForFullscreenProgress:progress];
  [self updateContentViewPaddingForFullscreenProgress:progress];
}

- (void)updateForFullscreenEnabled:(BOOL)enabled {
  if (!enabled)
    [self updateForFullscreenProgress:1.0];
}

- (void)finishFullscreenScrollWithAnimator:
    (FullscreenScrollEndAnimator*)animator {
  // If the headers are being hidden, it's possible that this will reveal a
  // portion of the webview beyond the top of the page's rendered content.  In
  // order to prevent that, update the top padding and content before the
  // animation begins.
  CGFloat finalProgress = animator.finalProgress;
  BOOL hidingHeaders = animator.finalProgress < animator.startProgress;
  if (hidingHeaders) {
    id<CRWWebViewProxy> webProxy = self.currentWebState->GetWebViewProxy();
    CRWWebViewScrollViewProxy* scrollProxy = webProxy.scrollViewProxy;
    CGPoint contentOffset = scrollProxy.contentOffset;
    if (contentOffset.y - scrollProxy.contentInset.top <
        webProxy.contentInset.top) {
      [self updateContentViewPaddingForFullscreenProgress:finalProgress];
      contentOffset.y = -scrollProxy.contentInset.top;
      scrollProxy.contentOffset = contentOffset;
    }
  }

  // Add animations to update the headers and footers.
  __weak BrowserViewController* weakSelf = self;
  [animator addAnimations:^{
    [weakSelf updateHeadersForFullscreenProgress:finalProgress];
    [weakSelf updateFootersForFullscreenProgress:finalProgress];
  }];

  // Animating layout changes of the rendered content in the WKWebView is not
  // supported, so update the content padding in the completion block of the
  // animator to trigger a rerender in the page's new viewport.
  __weak FullscreenScrollEndAnimator* weakAnimator = animator;
  [animator addCompletion:^(UIViewAnimatingPosition finalPosition) {
    [weakSelf updateContentViewPaddingForFullscreenProgress:
                  [weakAnimator progressForAnimatingPosition:finalPosition]];
  }];
}

- (void)scrollFullscreenToTopWithAnimator:
    (FullscreenScrollToTopAnimator*)animator {
  CGFloat finalProgress = animator.finalProgress;
  [animator addAnimations:^{
    [self updateHeadersForFullscreenProgress:finalProgress];
    [self updateFootersForFullscreenProgress:finalProgress];
    [self updateContentViewPaddingForFullscreenProgress:finalProgress];
  }];
}

- (void)showToolbarForForgroundWithAnimator:
    (FullscreenForegroundAnimator*)animator {
  CGFloat finalProgress = animator.finalProgress;
  [animator addAnimations:^{
    [self updateForFullscreenProgress:finalProgress];
  }];
}

#pragma mark - FullscreenUIElement helpers

// Translates the header views up and down according to |progress|, where a
// progress of 1.0 fully shows the headers and a progress of 0.0 fully hides
// them.
- (void)updateHeadersForFullscreenProgress:(CGFloat)progress {
  CGFloat toolbarHeightFullscreen = 0;
  if (IsUIRefreshPhase1Enabled()) {
    toolbarHeightFullscreen = kToolbarHeightFullscreen;
  }
  CGFloat offset = AlignValueToPixel(
      (1.0 - progress) * ([self toolbarHeight] - toolbarHeightFullscreen));
  [self setFramesForHeaders:[self headerViews] atOffset:offset];
}

// Translates the footer view up and down according to |progress|, where a
// progress of 1.0 fully shows the footer and a progress of 0.0 fully hides it.
- (void)updateFootersForFullscreenProgress:(CGFloat)progress {
  self.footerFullscreenProgress = progress;

  if (IsUIRefreshPhase1Enabled()) {
    self.secondaryToolbarHeightConstraint.constant =
        [self secondaryToolbarHeightWithInset] * progress;

    // Resize the infobars to take into account the changes in the toolbar.
    [self infoBarContainerStateDidChangeAnimated:NO];
  } else {
    if (![_model currentTab].isVoiceSearchResultsTab)
      return;

    UIView* footerView = [self footerView];
    DCHECK(footerView);
    CGRect frame = footerView.frame;
    frame.origin.y =
        AlignValueToPixel(CGRectGetMaxY(footerView.superview.bounds) -
                          progress * CGRectGetHeight(frame));
    footerView.frame = frame;
  }
}

// Updates the padding of the web view proxy. This either resets the frame of
// the WKWebView or the contentInsets of the WKWebView's UIScrollView, depending
// on the the proxy's |shouldUseViewContentInset| property.
- (void)updateContentViewPaddingForFullscreenProgress:(CGFloat)progress {
  if (self.currentWebState) {
    UIEdgeInsets contentPadding =
        self.currentWebState->GetWebViewProxy().contentInset;
    CGFloat toolbarHeightFullscreen = 0;
    if (IsUIRefreshPhase1Enabled()) {
      toolbarHeightFullscreen = kToolbarHeightFullscreen;
    }
    CGFloat toolbarHeightDelta = [self toolbarHeight] - toolbarHeightFullscreen;
    contentPadding.top = AlignValueToPixel(toolbarHeightFullscreen +
                                           progress * toolbarHeightDelta);
    contentPadding.bottom =
        AlignValueToPixel(progress * [self secondaryToolbarHeightWithInset]);
    self.currentWebState->GetWebViewProxy().contentInset = contentPadding;
  }
}

- (CGFloat)currentHeaderOffset {
  NSArray<HeaderDefinition*>* headers = [self headerViews];
  if (!headers.count)
    return 0.0;

  // Prerender tab does not have a toolbar, return |headerHeight| as promised by
  // API documentation.
  if (_insertedTabWasPrerenderedTab)
    return self.headerHeight;

  UIView* topHeader = headers[0].view;
  return -(topHeader.frame.origin.y - self.headerOffset);
}

#pragma mark - KeyCommandsPlumbing

- (BOOL)isOffTheRecord {
  return _isOffTheRecord;
}

- (NSUInteger)tabsCount {
  return [_model count];
}

- (BOOL)canGoBack {
  return [_model currentTab].canGoBack;
}

- (BOOL)canGoForward {
  return [_model currentTab].canGoForward;
}

- (void)focusTabAtIndex:(NSUInteger)index {
  if ([_model count] > index) {
    [_model setCurrentTab:[_model tabAtIndex:index]];
  }
}

- (void)focusNextTab {
  NSInteger currentTabIndex = [_model indexOfTab:[_model currentTab]];
  NSInteger modelCount = [_model count];
  if (currentTabIndex < modelCount - 1) {
    Tab* nextTab = [_model tabAtIndex:currentTabIndex + 1];
    [_model setCurrentTab:nextTab];
  } else {
    [_model setCurrentTab:[_model tabAtIndex:0]];
  }
}

- (void)focusPreviousTab {
  NSInteger currentTabIndex = [_model indexOfTab:[_model currentTab]];
  if (currentTabIndex > 0) {
    Tab* previousTab = [_model tabAtIndex:currentTabIndex - 1];
    [_model setCurrentTab:previousTab];
  } else {
    Tab* lastTab = [_model tabAtIndex:[_model count] - 1];
    [_model setCurrentTab:lastTab];
  }
}

- (void)reopenClosedTab {
  sessions::TabRestoreService* const tabRestoreService =
      IOSChromeTabRestoreServiceFactory::GetForBrowserState(_browserState);
  if (!tabRestoreService || tabRestoreService->entries().empty())
    return;

  const std::unique_ptr<sessions::TabRestoreService::Entry>& entry =
      tabRestoreService->entries().front();
  // Only handle the TAB type.
  if (entry->type != sessions::TabRestoreService::TAB)
    return;

  [self.dispatcher openNewTab:[OpenNewTabCommand command]];
  TabRestoreServiceDelegateImplIOS* const delegate =
      TabRestoreServiceDelegateImplIOSFactory::GetForBrowserState(
          _browserState);
  tabRestoreService->RestoreEntryById(delegate, entry->id,
                                      WindowOpenDisposition::CURRENT_TAB);
}

#pragma mark - MainContentUI

- (MainContentUIState*)mainContentUIState {
  return _mainContentUIUpdater.state;
}

#pragma mark - UrlLoader (Public)

- (void)loadURL:(const GURL&)url
             referrer:(const web::Referrer&)referrer
           transition:(ui::PageTransition)transition
    rendererInitiated:(BOOL)rendererInitiated {
  [[OmniboxGeolocationController sharedInstance]
      locationBarDidSubmitURL:url
                   transition:transition
                 browserState:_browserState];

  [_bookmarkInteractionController dismissBookmarkModalControllerAnimated:YES];
  if (transition & ui::PAGE_TRANSITION_FROM_ADDRESS_BAR) {
    BOOL isExpectingVoiceSearch = NO;
    web::WebState* webState = [_model currentTab].webState;
    if (webState) {
      isExpectingVoiceSearch =
          VoiceSearchNavigationTabHelper::FromWebState(webState)
              ->IsExpectingVoiceSearch();
    }
    new_tab_page_uma::RecordActionFromOmnibox(_browserState, url, transition,
                                              isExpectingVoiceSearch);
  }

  // NOTE: This check for the Crash Host URL is here to avoid the URL from
  // ending up in the history causing the app to crash at every subsequent
  // restart.
  if (url.host() == kChromeUIBrowserCrashHost) {
    [self induceBrowserCrash];
    // In debug the app can continue working even after the CHECK. Adding a
    // return avoids the crash url to be added to the history.
    return;
  }

  bool typed_or_generated_transition =
      PageTransitionCoreTypeIs(transition, ui::PAGE_TRANSITION_TYPED) ||
      PageTransitionCoreTypeIs(transition, ui::PAGE_TRANSITION_GENERATED);

  PrerenderService* prerenderService =
      PrerenderServiceFactory::GetForBrowserState(self.browserState);
  if (prerenderService && prerenderService->HasPrerenderForUrl(url)) {
    std::unique_ptr<web::WebState> newWebState =
        prerenderService->ReleasePrerenderContents();
    DCHECK(newWebState);

    Tab* oldTab = [_model currentTab];
    Tab* newTab = LegacyTabHelper::GetTabForWebState(newWebState.get());
    DCHECK(oldTab);
    DCHECK(newTab);

    bool canPruneItems =
        [newTab navigationManager]->CanPruneAllButLastCommittedItem();

    if (canPruneItems) {
      [newTab navigationManager]->CopyStateFromAndPrune(
          [oldTab navigationManager]);

      // Set _insertedTabWasPrerenderedTab to YES while the Tab is inserted
      // so that the correct toolbar height is used and animation are played.
      _insertedTabWasPrerenderedTab = YES;
      [_model webStateList]->ReplaceWebStateAt([_model indexOfTab:oldTab],
                                               std::move(newWebState));
      _insertedTabWasPrerenderedTab = NO;

      if ([newTab loadFinished]) {
        // If the page has finished loading, take a snapshot.  If the page is
        // still loading, do nothing, as the tab helper will automatically take
        // a snapshot once the load completes.
        SnapshotTabHelper::FromWebState(newTab.webState)
            ->UpdateSnapshot(
                /*with_overlays=*/true, /*visible_frame_only=*/true);
      }

      if (typed_or_generated_transition) {
        LoadTimingTabHelper::FromWebState(newTab.webState)
            ->DidPromotePrerenderTab();
      }

      [self tabLoadComplete:newTab withSuccess:newTab.loadFinished];
      return;
    }
  }

  GURL urlToLoad = url;
  if (prerenderService) {
    prerenderService->CancelPrerender();
  }

  // Some URLs are not allowed while in incognito.  If we are in incognito and
  // load a disallowed URL, instead create a new tab not in the incognito state.
  if (_isOffTheRecord && !IsURLAllowedInIncognito(url)) {
    [self webPageOrderedOpen:url
                    referrer:web::Referrer()
                 inIncognito:NO
                inBackground:NO
                    appendTo:kCurrentTab];
    return;
  }

  if (typed_or_generated_transition) {
    LoadTimingTabHelper::FromWebState([_model currentTab].webState)
        ->DidInitiatePageLoad();
  }

  // If this is a reload initiated from the omnibox.
  // TODO(crbug.com/730192): Add DCHECK to verify that whenever urlToLood is the
  // same as the old url, the transition type is ui::PAGE_TRANSITION_RELOAD.
  if (PageTransitionCoreTypeIs(transition, ui::PAGE_TRANSITION_RELOAD)) {
    [[_model currentTab] navigationManager]->Reload(
        web::ReloadType::NORMAL, true /* check_for_repost */);
    return;
  }

  web::NavigationManager::WebLoadParams params(urlToLoad);
  params.referrer = referrer;
  params.transition_type = transition;
  params.is_renderer_initiated = rendererInitiated;
  Tab* currentTab = [_model currentTab];
  DCHECK(currentTab);
  BOOL wasVoiceSearchTab = currentTab.isVoiceSearchResultsTab;
  currentTab.navigationManager->LoadURLWithParams(params);
  // When a Tab becomes a voice search Tab, the voice search bar doesn't need
  // to be animated on screen because the transition animator will handle the
  // animations.  When a Tab stops being a voice search Tab, the voice search
  // bar should be animated away.
  if (currentTab.isVoiceSearchResultsTab != wasVoiceSearchTab)
    [self updateVoiceSearchBarVisibilityAnimated:wasVoiceSearchTab];
}

- (void)loadJavaScriptFromLocationBar:(NSString*)script {
  PrerenderService* prerenderService =
      PrerenderServiceFactory::GetForBrowserState(self.browserState);
  if (prerenderService) {
    prerenderService->CancelPrerender();
  }
  DCHECK([_model currentTab]);
  if (self.currentWebState)
    self.currentWebState->ExecuteUserJavaScript(script);
}

// Load a new URL on a new page/tab.
- (void)webPageOrderedOpen:(const GURL&)URL
                  referrer:(const web::Referrer&)referrer
              inBackground:(BOOL)inBackground
                  appendTo:(OpenPosition)appendTo {
  Tab* adjacentTab = nil;
  if (appendTo == kCurrentTab)
    adjacentTab = [_model currentTab];
  [_model insertTabWithURL:URL
                  referrer:referrer
                transition:ui::PAGE_TRANSITION_LINK
                    opener:adjacentTab
               openedByDOM:NO
                   atIndex:TabModelConstants::kTabPositionAutomatically
              inBackground:inBackground];
}

- (void)webPageOrderedOpen:(const GURL&)url
                  referrer:(const web::Referrer&)referrer
               inIncognito:(BOOL)inIncognito
              inBackground:(BOOL)inBackground
                  appendTo:(OpenPosition)appendTo {
  // Send either the "New Tab Opened" or "New Incognito Tab" opened to the
  // feature_engagement::Tracker based on |inIncognito|.
  feature_engagement::NotifyNewTabEvent(_model.browserState, inIncognito);

  if (inIncognito == _isOffTheRecord) {
    [self webPageOrderedOpen:url
                    referrer:referrer
                inBackground:inBackground
                    appendTo:appendTo];
    return;
  }
  // When sending an open command that switches modes, ensure the tab
  // ends up appended to the end of the model, not just next to what is
  // currently selected in the other mode. This is done with the |append|
  // parameter.
  OpenUrlCommand* command = [[OpenUrlCommand alloc]
       initWithURL:url
          referrer:web::Referrer()  // Strip referrer when switching modes.
       inIncognito:inIncognito
      inBackground:inBackground
          appendTo:kLastTab];
  [self.dispatcher openURL:command];
}

- (void)loadSessionTab:(const sessions::SessionTab*)sessionTab {
  WebStateList* webStateList = [_model webStateList];
  webStateList->ReplaceWebStateAt(
      webStateList->active_index(),
      session_util::CreateWebStateWithNavigationEntries(
          [_model browserState], sessionTab->current_navigation_index,
          sessionTab->navigations));
}

#pragma mark - UrlLoader helpers

// Induce an intentional crash in the browser process.
- (void)induceBrowserCrash {
  CHECK(false);
  // Call another function, so that the above CHECK can't be tail-call
  // optimized. This ensures that this method's name will show up in the stack
  // for easier identification.
  CHECK(true);
}

#pragma mark - ToolbarCoordinatorDelegate (Public)

- (void)locationBarDidBecomeFirstResponder {
  [[NSNotificationCenter defaultCenter]
      postNotificationName:kLocationBarBecomesFirstResponderNotification
                    object:nil];
  [self.sideSwipeController setEnabled:NO];
  if ([[_model currentTab].webController wantsKeyboardShield]) {
    [self.view insertSubview:self.typingShield aboveSubview:self.contentArea];
    [self.typingShield setAlpha:0.0];
    [self.typingShield setHidden:NO];
    [UIView animateWithDuration:0.3
                     animations:^{
                       [self.typingShield setAlpha:1.0];
                     }];
  }
  [[OmniboxGeolocationController sharedInstance]
      locationBarDidBecomeFirstResponder:_browserState];

  [self.primaryToolbarCoordinator transitionToLocationBarFocusedState:YES];
}

- (void)locationBarDidResignFirstResponder {
  [self.sideSwipeController setEnabled:YES];
  [[NSNotificationCenter defaultCenter]
      postNotificationName:kLocationBarResignsFirstResponderNotification
                    object:nil];
  [UIView animateWithDuration:0.3
      animations:^{
        [self.typingShield setAlpha:0.0];
      }
      completion:^(BOOL finished) {
        // This can happen if one quickly resigns the omnibox and then taps
        // on the omnibox again during this animation. If the animation is
        // interrupted and the toolbar controller is first responder, it's safe
        // to assume |self.typingShield| shouldn't be hidden here.
        if (!finished &&
            [self.primaryToolbarCoordinator isOmniboxFirstResponder])
          return;
        [self.typingShield setHidden:YES];
      }];
  [[OmniboxGeolocationController sharedInstance]
      locationBarDidResignFirstResponder:_browserState];

  // If a load was cancelled by an omnibox edit, but nothing is loading when
  // editing ends (i.e., editing was cancelled), restart the cancelled load.
  if (_locationBarEditCancelledLoad) {
    _locationBarEditCancelledLoad = NO;

    web::WebState* webState = [_model currentTab].webState;
    if (webState && ![self.helper isToolbarLoading:webState])
      webState->GetNavigationManager()->Reload(web::ReloadType::NORMAL,
                                               false /* check_for_repost */);
  }
  [self.primaryToolbarCoordinator transitionToLocationBarFocusedState:NO];
}

- (void)locationBarBeganEdit {
  // On handsets, if a page is currently loading it should be stopped.
  if (!IsIPadIdiom() && [self.helper isToolbarLoading:self.currentWebState]) {
    [self.dispatcher stopLoading];
    _locationBarEditCancelledLoad = YES;
  }
}

- (ToolbarModel*)toolbarModel {
  return _toolbarModel.get();
}

- (BOOL)shouldDisplayHintText {
  return [[_model currentTab].webController wantsLocationBarHintText];
}

#pragma mark - ToolsMenuConfigurationProvider

- (void)prepareForToolsMenuPresentationByCoordinator:
    (ToolsMenuCoordinator*)coordinator {
  [self.dispatcher
      prepareForPopupMenuPresentation:PopupMenuCommandTypeToolsMenu];
}

- (ToolsMenuConfiguration*)menuConfigurationForToolsMenuCoordinator:
    (ToolsMenuCoordinator*)coordinator {
  ToolsMenuConfiguration* configuration =
      [[ToolsMenuConfiguration alloc] initWithDisplayView:[self view]
                                       baseViewController:self];
  configuration.requestStartTime = [NSDate date].timeIntervalSinceReferenceDate;

  if ([_model count] == 0)
    [configuration setNoOpenedTabs:YES];

  if (_isOffTheRecord)
    [configuration setInIncognito:YES];

  if (!_readingListMenuNotifier) {
    _readingListMenuNotifier = [[ReadingListMenuNotifier alloc]
        initWithReadingList:ReadingListModelFactory::GetForBrowserState(
                                _browserState)];
  }

  feature_engagement::Tracker* engagementTracker =
      feature_engagement::TrackerFactory::GetForBrowserState(_browserState);
  if (engagementTracker->ShouldTriggerHelpUI(
          feature_engagement::kIPHBadgedReadingListFeature)) {
    [configuration setShowReadingListNewBadge:YES];
    [configuration setEngagementTracker:engagementTracker];
  }
  [configuration setReadingListMenuNotifier:_readingListMenuNotifier];

  [configuration setUserAgentType:self.userAgentType];

  if (self.incognitoTabTipBubblePresenter.triggerFollowUpAction) {
    [configuration setHighlightNewIncognitoTabCell:YES];
    [self.incognitoTabTipBubblePresenter setTriggerFollowUpAction:NO];
  }

  return configuration;
}

- (BOOL)shouldHighlightBookmarkButtonForToolsMenuCoordinator:
    (ToolsMenuCoordinator*)coordinator {
  return [self.helper isWebStateBookmarked:self.currentWebState];
}

- (BOOL)shouldShowFindBarForToolsMenuCoordinator:
    (ToolsMenuCoordinator*)coordinator {
  return [_model currentTab] ? self.canShowFindBar : NO;
}

- (BOOL)shouldShowShareMenuForToolsMenuCoordinator:
    (ToolsMenuCoordinator*)coordinator {
  return [_model currentTab] ? self.canShowShareMenu : NO;
}

- (BOOL)isTabLoadingForToolsMenuCoordinator:(ToolsMenuCoordinator*)coordinator {
  return ([_model currentTab] && !IsIPadIdiom())
             ? [self.helper isToolbarLoading:self.currentWebState]
             : NO;
}

#pragma mark - BrowserCommands

- (void)goBack {
  [[_model currentTab] goBack];
}

- (void)goForward {
  [[_model currentTab] goForward];
}

- (void)stopLoading {
  [_model currentTab].webState->Stop();
}

- (void)reload {
  web::WebState* webState = [_model currentTab].webState;
  if (webState) {
    // |check_for_repost| is true because the reload is explicitly initiated
    // by the user.
    webState->GetNavigationManager()->Reload(web::ReloadType::NORMAL,
                                             true /* check_for_repost */);
  }
}

- (void)bookmarkPage {
  [self initializeBookmarkInteractionController];
  [_bookmarkInteractionController
      presentBookmarkForTab:[_model currentTab]
        currentlyBookmarked:
            [self.helper isWebStateBookmarkedByUser:self.currentWebState]];
}

- (void)openNewTab:(OpenNewTabCommand*)command {
  if (self.isOffTheRecord != command.incognito) {
    // Must take a snapshot of the tab before we switch the incognito mode
    // because the currentTab will change after the switch.
    Tab* currentTab = [_model currentTab];
    if (currentTab) {
      SnapshotTabHelper::FromWebState(currentTab.webState)
          ->UpdateSnapshot(/*with_overlays=*/true, /*visible_frame_only=*/true);
    }
    // Not for this browser state, send it on its way.
    [self.dispatcher switchModesAndOpenNewTab:command];
    return;
  }

  // Either send or don't send the "New Tab Opened" or "Incognito Tab Opened"
  // events to the feature_engagement::Tracker based on |command.userInitiated|
  // and |command.incognito|.
  feature_engagement::NotifyNewTabEventForCommand(_browserState, command);

  NSTimeInterval startTime = [NSDate timeIntervalSinceReferenceDate];
  BOOL offTheRecord = self.isOffTheRecord;
  ProceduralBlock oldForegroundTabWasAddedCompletionBlock =
      self.foregroundTabWasAddedCompletionBlock;
  __weak BrowserViewController* weakSelf = self;
  self.foregroundTabWasAddedCompletionBlock = ^{
    if (oldForegroundTabWasAddedCompletionBlock) {
      oldForegroundTabWasAddedCompletionBlock();
    }
    double duration = [NSDate timeIntervalSinceReferenceDate] - startTime;
    base::TimeDelta timeDelta = base::TimeDelta::FromSecondsD(duration);
    if (offTheRecord) {
      UMA_HISTOGRAM_TIMES("Toolbar.Menu.NewIncognitoTabPresentationDuration",
                          timeDelta);
    } else {
      UMA_HISTOGRAM_TIMES("Toolbar.Menu.NewTabPresentationDuration", timeDelta);
    }
    if (command.shouldFocusOmnibox) {
      [weakSelf.dispatcher focusOmnibox];
    }
  };

  [self setLastTapPoint:command];
  // When the tab switcher presentation experiment is enabled, the new tab can
  // be opened before BVC has been made visible onscreen.  Test for this case by
  // checking if the parent container VC is currently in the process of being
  // presented.
  DCHECK(self.visible || self.dismissingModal ||
         (TabSwitcherPresentsBVCEnabled() &&
          self.parentViewController.isBeingPresented));

  // In most cases, we want to take a snapshot of the current tab before opening
  // a new tab. However, if the current tab is not fully visible (did not finish
  // |-viewDidAppear:|, then we must not take an empty snapshot, replacing an
  // existing snapshot for the tab. This can happen when a new regular tab is
  // opened from an incognito tab. A different BVC is displayed, which may not
  // have enough time to finish appearing before a snapshot is requested.
  Tab* currentTab = [_model currentTab];
  if (currentTab && self.viewVisible) {
    SnapshotTabHelper::FromWebState(currentTab.webState)
        ->UpdateSnapshot(/*with_overlays=*/true, /*visible_frame_only=*/true);
  }
  [self addSelectedTabWithURL:GURL(kChromeUINewTabURL)
                   transition:ui::PAGE_TRANSITION_TYPED];
}

- (void)printTab {
  Tab* currentTab = [_model currentTab];
  // The UI should prevent users from printing non-printable pages. However, a
  // redirection to an un-printable page can happen before it is reflected in
  // the UI.
  if (![currentTab viewForPrinting]) {
    TriggerHapticFeedbackForNotification(UINotificationFeedbackTypeError);
    [self showSnackbar:l10n_util::GetNSString(IDS_IOS_CANNOT_PRINT_PAGE_ERROR)];
    return;
  }
  DCHECK(_browserState);
  if (!_printController) {
    _printController = [[PrintController alloc]
        initWithContextGetter:_browserState->GetRequestContext()];
  }
  [_printController printView:[currentTab viewForPrinting]
                    withTitle:[currentTab title]
               viewController:self];
}

- (void)addToReadingList:(ReadingListAddCommand*)command {
  [self addToReadingListURL:[command URL] title:[command title]];
}

- (void)showReadingList {
  _readingListCoordinator = [[ReadingListCoordinator alloc]
      initWithBaseViewController:self
                    browserState:self.browserState
                          loader:self];

  [_readingListCoordinator start];
}

- (void)preloadVoiceSearch {
  // Preload VoiceSearchController and views and view controllers needed
  // for voice search.
  [self ensureVoiceSearchControllerCreated];
  _voiceSearchController->PrepareToAppear();
}

- (void)closeAllIncognitoTabs {
  DCHECK(self.isOffTheRecord);
  [self.tabModel closeAllTabs];
}

#if !defined(NDEBUG)
- (void)viewSource {
  Tab* tab = [_model currentTab];
  DCHECK(tab);
  CRWWebController* webController = tab.webController;
  NSString* script = @"document.documentElement.outerHTML;";
  __weak Tab* weakTab = tab;
  __weak BrowserViewController* weakSelf = self;
  web::JavaScriptResultBlock completionHandlerBlock = ^(id result, NSError*) {
    Tab* strongTab = weakTab;
    if (!strongTab)
      return;
    if (![result isKindOfClass:[NSString class]])
      result = @"Not an HTML page";
    std::string base64HTML;
    base::Base64Encode(base::SysNSStringToUTF8(result), &base64HTML);
    GURL URL(std::string("data:text/plain;charset=utf-8;base64,") + base64HTML);
    web::Referrer referrer(strongTab.webState->GetLastCommittedURL(),
                           web::ReferrerPolicyDefault);

    [[weakSelf tabModel]
        insertTabWithURL:URL
                referrer:referrer
              transition:ui::PAGE_TRANSITION_LINK
                  opener:strongTab
             openedByDOM:YES
                 atIndex:TabModelConstants::kTabPositionAutomatically
            inBackground:NO];
  };
  [webController executeJavaScript:script
                 completionHandler:completionHandlerBlock];
}
#endif  // !defined(NDEBUG)

// TODO(crbug.com/634507) Remove base::TimeXXX::ToInternalValue().
- (void)showRateThisAppDialog {
  DCHECK(!_rateThisAppDialog);

  // Store the current timestamp whenever this dialog is shown.
  _browserState->GetPrefs()->SetInt64(prefs::kRateThisAppDialogLastShownTime,
                                      base::Time::Now().ToInternalValue());

  // iOS11 no longer supports the itms link to the app store. So, use a deep
  // link for iOS11 and the itms link for prior versions.
  NSURL* storeURL;
  if (base::ios::IsRunningOnIOS11OrLater()) {
    storeURL =
        [NSURL URLWithString:(@"https://itunes.apple.com/us/app/"
                              @"google-chrome-the-fast-and-secure-web-browser/"
                              @"id535886823?action=write-review")];
  } else {
    storeURL = [NSURL
        URLWithString:(@"itms-apps://itunes.apple.com/WebObjects/"
                       @"MZStore.woa/wa/"
                       @"viewContentsUserReviews?type=Purple+Software&id="
                       @"535886823&pt=9008&ct=rating")];
  }

  base::RecordAction(base::UserMetricsAction("IOSRateThisAppDialogShown"));
  [self clearPresentedStateWithCompletion:nil dismissOmnibox:YES];

  _rateThisAppDialog = ios::GetChromeBrowserProvider()->CreateAppRatingPrompt();
  [_rateThisAppDialog setAppStoreURL:storeURL];
  [_rateThisAppDialog setDelegate:self];
  [_rateThisAppDialog show];
}

- (void)showFindInPage {
  if (!self.canShowFindBar)
    return;

  if (!_findBarController) {
    _findBarController =
        [[FindBarControllerIOS alloc] initWithIncognito:_isOffTheRecord];
    _findBarController.dispatcher = self.dispatcher;
  }

  Tab* tab = [_model currentTab];
  DCHECK(tab);
  auto* helper = FindTabHelper::FromWebState(tab.webState);
  DCHECK(!helper->IsFindUIActive());
  helper->SetFindUIActive(true);
  [self showFindBarWithAnimation:YES selectText:YES shouldFocus:YES];
}

- (void)closeFindInPage {
  __weak BrowserViewController* weakSelf = self;
  Tab* currentTab = [_model currentTab];
  if (currentTab) {
    FindTabHelper::FromWebState(currentTab.webState)->StopFinding(^{
      [weakSelf updateFindBar:NO shouldFocus:NO];
    });
  }
}

- (void)searchFindInPage {
  DCHECK([_model currentTab]);
  auto* helper = FindTabHelper::FromWebState([_model currentTab].webState);
  __weak BrowserViewController* weakSelf = self;
  helper->StartFinding(
      [_findBarController searchTerm], ^(FindInPageModel* model) {
        BrowserViewController* strongSelf = weakSelf;
        if (!strongSelf) {
          return;
        }
        [strongSelf->_findBarController updateResultsCount:model];
      });

  if (!_isOffTheRecord)
    helper->PersistSearchTerm();
}

- (void)findNextStringInPage {
  Tab* currentTab = [_model currentTab];
  DCHECK(currentTab);
  // TODO(crbug.com/603524): Reshow find bar if necessary.
  FindTabHelper::FromWebState(currentTab.webState)
      ->ContinueFinding(FindTabHelper::FORWARD, ^(FindInPageModel* model) {
        [_findBarController updateResultsCount:model];
      });
}

- (void)findPreviousStringInPage {
  Tab* currentTab = [_model currentTab];
  DCHECK(currentTab);
  // TODO(crbug.com/603524): Reshow find bar if necessary.
  FindTabHelper::FromWebState(currentTab.webState)
      ->ContinueFinding(FindTabHelper::REVERSE, ^(FindInPageModel* model) {
        [_findBarController updateResultsCount:model];
      });
}

- (void)showHelpPage {
  GURL helpUrl(l10n_util::GetStringUTF16(IDS_IOS_TOOLS_MENU_HELP_URL));
  [self webPageOrderedOpen:helpUrl
                  referrer:web::Referrer()
              inBackground:NO
                  appendTo:kCurrentTab];
}

- (void)showBookmarksManager {
  [self initializeBookmarkInteractionController];
  [_bookmarkInteractionController presentBookmarks];
}

- (void)showRecentTabs {
  // TODO(crbug.com/825431): If BVC's clearPresentedState is ever called (such
  // as in tearDown after a failed egtest), then this coordinator is left in a
  // started state even though its corresponding VC is no longer on screen.
  // That causes issues when the coordinator is started again and we destroy the
  // old mediator without disconnecting it first.  Temporarily work around these
  // issues by not having a long lived coordinator.  A longer-term solution will
  // require finding a way to stop this coordinator so that the mediator is
  // properly disconnected and destroyed and does not live longer than its
  // associated VC.
  if (self.recentTabsCoordinator) {
    [self.recentTabsCoordinator stop];
    self.recentTabsCoordinator = nil;
  }
  [self createRecentTabsCoordinator];
  [self.recentTabsCoordinator start];
}

- (void)requestDesktopSite {
  [[_model currentTab] reloadWithUserAgentType:web::UserAgentType::DESKTOP];
}

- (void)requestMobileSite {
  [[_model currentTab] reloadWithUserAgentType:web::UserAgentType::MOBILE];
}

- (void)closeCurrentTab {
  Tab* currentTab = [_model currentTab];
  NSUInteger tabIndex = [_model indexOfTab:currentTab];
  if (tabIndex == NSNotFound)
    return;

  // TODO(crbug.com/688003): Evaluate if a screenshot of the tab is needed on
  // iPad.
  UIImageView* exitingPage = [self pageOpenCloseAnimationView];
  exitingPage.image =
      SnapshotTabHelper::FromWebState(currentTab.webState)
          ->UpdateSnapshot(/*with_overlays=*/true, /*visible_frame_only=*/true);

  // Close the actual tab, and add its image as a subview.
  [_model closeTabAtIndex:tabIndex];

  // Do not animate close in iPad.
  if (!IsIPadIdiom()) {
    [self.contentArea addSubview:exitingPage];
    page_animation_util::AnimateOutWithCompletion(
        exitingPage, 0, YES, IsPortrait(), ^{
          [exitingPage removeFromSuperview];
        });
  }
}

- (void)navigateToMemexTabSwitcher {
  // TODO(crbug.com/799601): Delete this once its not needed.
  const GURL memexURL("https://chrome-memex.appspot.com");
  [self loadURL:memexURL
               referrer:web::Referrer()
             transition:ui::PAGE_TRANSITION_LINK
      rendererInitiated:NO];
}

- (void)prepareForPopupMenuPresentation:(PopupMenuCommandType)type {
  DCHECK(_browserState);
  DCHECK(self.visible || self.dismissingModal);

  // Dismiss the omnibox (if open).
  [self.dispatcher cancelOmniboxEdit];
  // Dismiss the soft keyboard (if open).
  [[_model currentTab].webController dismissKeyboard];
  // Dismiss Find in Page focus.
  [self updateFindBar:NO shouldFocus:NO];

  switch (type) {
    case PopupMenuCommandTypeToolsMenu:
      if (self.incognitoTabTipBubblePresenter.isUserEngaged) {
        base::RecordAction(
            UserMetricsAction("NewIncognitoTabTipTargetSelected"));
      }
      break;
    case PopupMenuCommandTypeDefault:
      // Do nothing.
      break;
  }
}

#pragma mark - ToolbarOwner (Public)

- (CGFloat)toolbarHeight {
  return self.headerHeight;
}

- (CGRect)toolbarFrame {
  return _toolbarCoordinator.viewController.view.frame;
}

- (id<ToolbarSnapshotProviding>)toolbarSnapshotProvider {
  id<ToolbarSnapshotProviding> toolbarSnapshotProvider = nil;
  Tab* currentTab = [_model currentTab];
  if (_toolbarCoordinator.viewController.view.hidden && currentTab.webState &&
      UrlHasChromeScheme(currentTab.webState->GetLastCommittedURL())) {
    // Use the native content controller's toolbar when the BVC's is hidden.
    id nativeController = [self nativeControllerForTab:currentTab];
    if ([nativeController conformsToProtocol:@protocol(ToolbarOwner)]) {
      toolbarSnapshotProvider = [nativeController toolbarSnapshotProvider];
    }
  } else {
    toolbarSnapshotProvider = _toolbarCoordinator;
  }
  return toolbarSnapshotProvider;
}

#pragma mark - TabModelObserver methods

// Observer method, tab inserted.
- (void)tabModel:(TabModel*)model
    didInsertTab:(Tab*)tab
         atIndex:(NSUInteger)modelIndex
    inForeground:(BOOL)fg {
  DCHECK(tab);
  [self installDelegatesForTab:tab];

  if (fg) {
    [_paymentRequestManager setActiveWebState:tab.webState];
  }
}

// Observer method, active tab changed.
- (void)tabModel:(TabModel*)model
    didChangeActiveTab:(Tab*)newTab
           previousTab:(Tab*)previousTab
               atIndex:(NSUInteger)index {
  // TODO(rohitrao): tabSelected expects to always be called with a non-nil tab.
  // Currently this observer method is always called with a non-nil |newTab|,
  // but that may change in the future.  Remove this DCHECK when it does.
  DCHECK(newTab);
  if (_infoBarContainer) {
    DCHECK(newTab.webState);
    infobars::InfoBarManager* infoBarManager =
        InfoBarManagerImpl::FromWebState(newTab.webState);
    _infoBarContainer->ChangeInfoBarManager(infoBarManager);

    // Dismiss the language selector, if any; this is a no-op when there's
    // no language selector presented.
    [_languageSelectionCoordinator dismissLanguageSelector];
  }
  [self updateVoiceSearchBarVisibilityAnimated:NO];

  if (IsUIRefreshPhase1Enabled())
    self.currentWebState->GetWebViewProxy().scrollViewProxy.clipsToBounds = NO;

  [_paymentRequestManager setActiveWebState:newTab.webState];

  [self tabSelected:newTab notifyToolbar:YES];
}

- (void)tabModel:(TabModel*)model willStartLoadingTab:(Tab*)tab {
  // Stop any Find in Page searches and close the find bar when navigating to a
  // new page.
  [self closeFindInPage];

  // Dismiss the language selector, if any; this is a no-op when there's no
  // language selector presented.
  [_languageSelectionCoordinator dismissLanguageSelector];
}

- (void)tabModel:(TabModel*)model didChangeTab:(Tab*)tab {
  DCHECK(tab && ([_model indexOfTab:tab] != NSNotFound));
  if (tab == [_model currentTab]) {
    [self updateToolbar];
  }
}

- (void)tabModel:(TabModel*)model didStartLoadingTab:(Tab*)tab {
  if (tab == [_model currentTab]) {
    [self updateVoiceSearchBarVisibilityAnimated:NO];
  }
}

- (void)tabModel:(TabModel*)model
    didFinishLoadingTab:(Tab*)tab
                success:(BOOL)success {
  [self tabLoadComplete:tab withSuccess:success];
  if (IsIPadIdiom()) {
    UIUserInterfaceSizeClass sizeClass =
        self.view.window.traitCollection.horizontalSizeClass;
    [SizeClassRecorder pageLoadedWithHorizontalSizeClass:sizeClass];
  }
}

- (void)tabModel:(TabModel*)model
    newTabWillOpen:(Tab*)tab
      inBackground:(BOOL)background {
  DCHECK(tab);
  _temporaryNativeController = nil;

  // When adding new tabs, check what kind of reminder infobar should
  // be added to the new tab. Try to add only one of them.
  // This check is done when a new tab is added either through the Tools Menu
  // "New Tab" or through "New Tab" in Stack View Controller. This method
  // is called after a new tab has added and finished initial navigation.
  // If this is added earlier, the initial navigation may end up clearing
  // the infobar(s) that are just added. See http://crbug/340250 for details.
  web::WebState* webState = tab.webState;
  DCHECK(webState);

  infobars::InfoBarManager* infoBarManager =
      InfoBarManagerImpl::FromWebState(webState);
  [[UpgradeCenter sharedInstance] addInfoBarToManager:infoBarManager
                                             forTabId:[tab tabId]];
  if (!ReSignInInfoBarDelegate::Create(_browserState, tab,
                                       self /* id<SigninPresenter> */)) {
    DisplaySyncErrors(_browserState, tab, self /* id<SyncPresenter> */);
  }

  // The rest of this function initiates the new tab animation, which is
  // phone-specific.  Call the foreground tab added completion block; for
  // iPhones, this will get executed after the animation has finished.
  if (IsIPadIdiom()) {
    if (self.foregroundTabWasAddedCompletionBlock) {
      // This callback is called before webState is activated (on
      // kTabModelNewTabWillOpenNotification notification). Dispatch the
      // callback asynchronously to be sure the activation is complete.
      dispatch_async(dispatch_get_main_queue(), ^{
        // Test existence again as the block may have been deleted.
        if (self.foregroundTabWasAddedCompletionBlock) {
          self.foregroundTabWasAddedCompletionBlock();
          self.foregroundTabWasAddedCompletionBlock = nil;
        }
      });
    }
    return;
  }

  // Do nothing if browsing is currently suspended.  The BVC will set everything
  // up correctly when browsing resumes.
  if (!self.visible || ![_model webUsageEnabled])
    return;

  // Block that starts voice search at the end of new Tab animation if
  // necessary.
  ProceduralBlock startVoiceSearchIfNecessaryBlock = ^void() {
    if (_startVoiceSearchAfterNewTabAnimation) {
      _startVoiceSearchAfterNewTabAnimation = NO;
      [self startVoiceSearch];
    }
  };

  self.inNewTabAnimation = YES;
  CGRect oldContentAreaFrame = self.contentArea.frame;
  if (!background) {
    // Create the new page image, and load with the new tab snapshot except if
    // it is the NTP.
    CGFloat newPageOffset = 0;
    UIView* newPage = nil;
    CGFloat offset = 0;
    if (tab.webState->GetLastCommittedURL() == kChromeUINewTabURL &&
        !_isOffTheRecord && !IsIPadIdiom()) {
      offset = 0;
      // Temporary expand content area to take whole view space. Otherwise the
      // animated NTP will be clipped by content area bound. Previous frame is
      // stored in |oldContentAreaFrame| and will be reset back on animation
      // completion.
      self.contentArea.frame = self.view.frame;
      newPage = tab.view;
      newPage.userInteractionEnabled = NO;
      // Compute a frame for the new page by removing the status bar height from
      // the bounds of |self.view|.
      CGRect viewBounds, remainder;
      CGRectDivide(self.view.bounds, &remainder, &viewBounds, StatusBarHeight(),
                   CGRectMinYEdge);
      newPage.frame = viewBounds;
    } else {
      UIImageView* pageScreenshot = [self pageOpenCloseAnimationView];
      tab.view.frame = self.contentArea.bounds;
      pageScreenshot.image = SnapshotTabHelper::FromWebState(tab.webState)
                                 ->UpdateSnapshot(/*with_overlays=*/true,
                                                  /*visible_frame_only=*/true);
      newPage = pageScreenshot;
      offset =
          pageScreenshot.frame.size.height - pageScreenshot.image.size.height;
    }
    newPageOffset = newPage.frame.origin.y;

    [self.contentArea addSubview:newPage];
    CGPoint origin = [self lastTapPoint];
    page_animation_util::AnimateInPaperWithAnimationAndCompletion(
        newPage, -newPageOffset, offset, origin, _isOffTheRecord, NULL, ^{
          tab.view.frame = self.contentArea.bounds;
          newPage.userInteractionEnabled = YES;
          [newPage removeFromSuperview];
          self.inNewTabAnimation = NO;
          // Use the model's currentTab here because it is possible that it can
          // be reset to a new value before the new Tab animation finished (e.g.
          // if another Tab shows a dialog via |dialogPresenter|). However, that
          // tab's view hasn't been displayed yet because it was in a new tab
          // animation.
          Tab* currentTab = [_model currentTab];
          if (currentTab) {
            [self tabSelected:currentTab notifyToolbar:NO];
          }
          startVoiceSearchIfNecessaryBlock();

          if (self.foregroundTabWasAddedCompletionBlock) {
            self.foregroundTabWasAddedCompletionBlock();
            self.foregroundTabWasAddedCompletionBlock = nil;
          }
          self.contentArea.frame = oldContentAreaFrame;
        });
  } else {
    // SnapshotTabHelper::UpdateSnapshot will force a screen redraw, so take the
    // snapshot before adding the views needed for the background animation.
    Tab* topTab = [_model currentTab];
    UIImage* image =
        SnapshotTabHelper::FromWebState(topTab.webState)
            ->UpdateSnapshot(/*with_overlays=*/true,
                             /*visible_frame_only=*/self.isToolbarOnScreen);

    // The size of the |image| above can be wrong if the snapshot fails, grab
    // the correct size here.
    CGRect imageFrame = CGRectZero;
    if (self.isToolbarOnScreen) {
      imageFrame = UIEdgeInsetsInsetRect(
          self.contentArea.bounds,
          [self snapshotEdgeInsetsForWebState:topTab.webState]);
    } else {
      imageFrame = [topTab.webState->GetView() bounds];
    }

    // Add three layers in order on top of the contentArea for the animation:
    // 1. The black "background" screen.
    UIView* background = [[UIView alloc] initWithFrame:self.contentArea.bounds];
    InstallBackgroundInView(background);
    [self.contentArea addSubview:background];

    // 2. A CardView displaying the data from the current tab.
    CardView* topCard = [self addCardViewInFullscreen:!self.isToolbarOnScreen];
    NSString* title = [topTab title];
    if (![title length])
      title = [topTab urlDisplayString];
    [topCard setTitle:title];
    [topCard setImage:image];
    [topCard setFavicon:nil];

    favicon::FaviconDriver* faviconDriver =
        favicon::WebFaviconDriver::FromWebState(topTab.webState);
    if (faviconDriver && faviconDriver->FaviconIsValid()) {
      gfx::Image favicon = faviconDriver->GetFavicon();
      if (!favicon.IsEmpty())
        [topCard setFavicon:favicon.ToUIImage()];
    }

    // 3. A new, blank CardView to represent the new tab being added.
    // Launch the new background tab animation.
    page_animation_util::AnimateNewBackgroundPageWithCompletion(
        topCard, self.contentArea.frame, imageFrame, IsPortrait(), ^{
          [background removeFromSuperview];
          [topCard removeFromSuperview];
          self.inNewTabAnimation = NO;
          // Resnapshot the top card if it has its own toolbar, as the toolbar
          // will be captured in the new tab animation, but isn't desired for
          // the stack view snapshots.
          id nativeController = [self nativeControllerForTab:topTab];
          if ([nativeController conformsToProtocol:@protocol(ToolbarOwner)]) {
            SnapshotTabHelper::FromWebState(topTab.webState)
                ->UpdateSnapshot(/*with_overlays=*/true,
                                 /*visible_frame_only=*/true);
          }
          startVoiceSearchIfNecessaryBlock();
        });
    // Reset the foreground tab completion block so that it can never be
    // called more than once regardless of foreground/background tab
    // appearances.
    self.foregroundTabWasAddedCompletionBlock = nil;
  }
}

- (void)tabModel:(TabModel*)model didDeselectTab:(Tab*)tab {
  tab.webState->WasHidden();
  [self dismissPopups];
}

// Observer method, tab replaced.
- (void)tabModel:(TabModel*)model
    didReplaceTab:(Tab*)oldTab
          withTab:(Tab*)newTab
          atIndex:(NSUInteger)index {
  [self uninstallDelegatesForTab:oldTab];
  [self installDelegatesForTab:newTab];

  if (_infoBarContainer) {
    infobars::InfoBarManager* infoBarManager = nullptr;
    if (newTab) {
      DCHECK(newTab.webState);
      infoBarManager = InfoBarManagerImpl::FromWebState(newTab.webState);
    }
    _infoBarContainer->ChangeInfoBarManager(infoBarManager);
  }

  // Add |newTab|'s view to the hierarchy if it's the current Tab.
  if (self.active && model.currentTab == newTab)
    [self displayTab:newTab];

  if (newTab)
    [_paymentRequestManager setActiveWebState:newTab.webState];
}

// A tab has been removed, remove its views from display if necessary.
- (void)tabModel:(TabModel*)model
    didRemoveTab:(Tab*)tab
         atIndex:(NSUInteger)index {
  [self uninstallDelegatesForTab:tab];

  // Cancel dialogs for |tab|'s WebState.
  [self.dialogPresenter cancelDialogForWebState:tab.webState];

  // Ignore changes while the tab stack view is visible (or while suspended).
  // The display will be refreshed when this view becomes active again.
  if (!self.visible || !model.webUsageEnabled)
    return;

  // Remove the find bar for now.
  [self hideFindBarWithAnimation:NO];
}

- (void)tabModel:(TabModel*)model willRemoveTab:(Tab*)tab {
  if (tab == [model currentTab]) {
    [_browserContainerViewController displayContentView:nil];
  }

  [_paymentRequestManager stopTrackingWebState:tab.webState];

  [[UpgradeCenter sharedInstance] tabWillClose:tab.tabId];
  if ([model count] == 1) {  // About to remove the last tab.
    [_paymentRequestManager setActiveWebState:nullptr];
  }
}

#pragma mark - UpgradeCenterClient

- (void)showUpgrade:(UpgradeCenter*)center {
  if (!_model)
    return;

  // Add an infobar on all the open tabs.
  DCHECK(_model.webStateList);
  WebStateList* webStateList = _model.webStateList;
  for (int index = 0; index < webStateList->count(); ++index) {
    web::WebState* webState = webStateList->GetWebStateAt(index);
    NSString* tabId = TabIdTabHelper::FromWebState(webState)->tab_id();
    infobars::InfoBarManager* infoBarManager =
        InfoBarManagerImpl::FromWebState(webState);
    DCHECK(infoBarManager);
    [center addInfoBarToManager:infoBarManager forTabId:tabId];
  }
}

#pragma mark - InfobarContainerStateDelegate

- (void)infoBarContainerStateDidChangeAnimated:(BOOL)animated {
  InfoBarContainerView* infoBarContainerView = _infoBarContainer->view();
  DCHECK(infoBarContainerView);
  CGRect containerFrame = infoBarContainerView.frame;
  CGFloat height = [infoBarContainerView topmostVisibleInfoBarHeight];
  containerFrame.origin.y = CGRectGetMaxY(self.contentArea.frame) - height;
  containerFrame.size.height = height;

  BOOL isViewVisible = self.visible;
  ProceduralBlock animation = ^{
    [infoBarContainerView setFrame:containerFrame];
  };
  void (^completion)(BOOL) = ^(BOOL finished) {
    if (!isViewVisible)
      return;
    UIAccessibilityPostNotification(UIAccessibilityLayoutChangedNotification,
                                    infoBarContainerView);
  };
  if (animated) {
    [UIView animateWithDuration:0.1 animations:animation completion:completion];
  } else {
    animation();
    completion(YES);
  }
}

#pragma mark - UIGestureRecognizerDelegate

// Always return yes, as this tap should work with various recognizers,
// including UITextTapRecognizer, UILongPressGestureRecognizer,
// UIScrollViewPanGestureRecognizer and others.
- (BOOL)gestureRecognizer:(UIGestureRecognizer*)gestureRecognizer
    shouldRecognizeSimultaneouslyWithGestureRecognizer:
        (UIGestureRecognizer*)otherGestureRecognizer {
  return YES;
}

// Tap gestures should only be recognized within |contentArea|.
- (BOOL)gestureRecognizerShouldBegin:(UIGestureRecognizer*)gesture {
  CGPoint location = [gesture locationInView:self.view];

  // Only allow touches on descendant views of |contentArea|.
  UIView* hitView = [self.view hitTest:location withEvent:nil];
  return [hitView isDescendantOfView:self.contentArea];
}

#pragma mark - SideSwipeControllerDelegate

- (void)sideSwipeViewDismissAnimationDidEnd:(UIView*)sideSwipeView {
  DCHECK(!IsIPadIdiom());
  // Update frame incase orientation changed while |contentArea| was out of
  // the view hierarchy.
  self.contentArea.frame = sideSwipeView.frame;

  [self.view insertSubview:self.contentArea aboveSubview:_fakeStatusBarView];
  [self updateVoiceSearchBarVisibilityAnimated:NO];
  [self updateToolbar];

  // Reset horizontal stack view.
  [sideSwipeView removeFromSuperview];
  [self.sideSwipeController setInSwipe:NO];
  [_infoBarContainer->view() setHidden:NO];
}

- (UIView*)sideSwipeContentView {
  return self.contentArea;
}

- (void)sideSwipeRedisplayTab:(Tab*)tab {
  [self displayTab:tab];
}

- (BOOL)preventSideSwipe {
  BOOL isShowingToolsMenu = NO;
  if (IsUIRefreshPhase1Enabled()) {
    isShowingToolsMenu = [self.popupMenuCoordinator isShowingPopupMenu];
  } else {
    isShowingToolsMenu = [_toolbarCoordinator isShowingToolsMenu];
  }
  if (isShowingToolsMenu)
    return YES;

  if (_voiceSearchController && _voiceSearchController->IsVisible())
    return YES;

  if (!self.active)
    return YES;

  return NO;
}

- (void)updateAccessoryViewsForSideSwipeWithVisibility:(BOOL)visible {
  if (visible) {
    [self updateVoiceSearchBarVisibilityAnimated:NO];
    [self updateToolbar];
    [_infoBarContainer->view() setHidden:NO];
  } else {
    // Hide UI accessories such as find bar and first visit overlays
    // for welcome page.
    [self hideFindBarWithAnimation:NO];
    [_infoBarContainer->view() setHidden:YES];
    [_voiceSearchBar setHidden:YES];
  }
}

- (CGFloat)headerHeightForSideSwipe {
  return self.headerHeight;
}

- (BOOL)verifyToolbarViewPlacementInView:(UIView*)views {
  BOOL seenToolbar = NO;
  BOOL seenInfoBarContainer = NO;
  BOOL seenContentArea = NO;
  for (UIView* view in views.subviews) {
    if (view == _toolbarCoordinator.viewController.view)
      seenToolbar = YES;
    else if (view == _infoBarContainer->view())
      seenInfoBarContainer = YES;
    else if (view == self.contentArea)
      seenContentArea = YES;
    if ((seenToolbar && !seenInfoBarContainer) ||
        (seenInfoBarContainer && !seenContentArea))
      return NO;
  }
  return YES;
}

- (BOOL)canBeginToolbarSwipe {
  return ![self.primaryToolbarCoordinator isOmniboxFirstResponder] &&
         ![self.primaryToolbarCoordinator showingOmniboxPopup];
}

- (UIView*)topToolbarView {
  return self.primaryToolbarCoordinator.viewController.view;
}

#pragma mark - PreloadControllerDelegate methods

- (BOOL)preloadShouldUseDesktopUserAgent {
  return [_model currentTab].usesDesktopUserAgent;
}

- (BOOL)preloadHasNativeControllerForURL:(const GURL&)url {
  return [self hasControllerForURL:url];
}

- (CGFloat)
nativeContentHeaderHeightForPreloadController:(PreloadController*)controller
                                     webState:(web::WebState*)webState {
  return [self nativeContentHeaderHeightForWebState:webState];
}

#pragma mark - NetExportTabHelperDelegate

- (void)netExportTabHelper:(NetExportTabHelper*)tabHelper
    showMailComposerWithContext:(ShowMailComposerContext*)context {
  if (![MFMailComposeViewController canSendMail]) {
    NSString* alertTitle =
        l10n_util::GetNSString([context emailNotConfiguredAlertTitleId]);
    NSString* alertMessage =
        l10n_util::GetNSString([context emailNotConfiguredAlertMessageId]);
    [self showErrorAlertWithStringTitle:alertTitle message:alertMessage];
    return;
  }
  MFMailComposeViewController* mailViewController =
      [[MFMailComposeViewController alloc] init];
  [mailViewController setModalPresentationStyle:UIModalPresentationFormSheet];
  [mailViewController setToRecipients:[context toRecipients]];
  [mailViewController setSubject:[context subject]];
  [mailViewController setMessageBody:[context body] isHTML:NO];

  const base::FilePath& textFile = [context textFileToAttach];
  if (!textFile.empty()) {
    NSString* filename = base::SysUTF8ToNSString(textFile.value());
    NSData* data = [NSData dataWithContentsOfFile:filename];
    if (data) {
      NSString* displayName =
          base::SysUTF8ToNSString(textFile.BaseName().value());
      [mailViewController addAttachmentData:data
                                   mimeType:@"text/plain"
                                   fileName:displayName];
    }
  }

  [mailViewController setMailComposeDelegate:self];
  [self presentViewController:mailViewController animated:YES completion:nil];
}

#pragma mark - MFMailComposeViewControllerDelegate methods

- (void)mailComposeController:(MFMailComposeViewController*)controller
          didFinishWithResult:(MFMailComposeResult)result
                        error:(NSError*)error {
  [self dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - TabDialogDelegate methods

- (void)cancelDialogForTab:(Tab*)tab {
  [self.dialogPresenter cancelDialogForWebState:tab.webState];
}

#pragma mark - AppRatingPromptDelegate

- (void)userTappedRateApp:(UIView*)view {
  base::RecordAction(base::UserMetricsAction("IOSRateThisAppRateChosen"));
  _rateThisAppDialog = nil;
}

- (void)userTappedSendFeedback:(UIView*)view {
  base::RecordAction(base::UserMetricsAction("IOSRateThisAppFeedbackChosen"));
  _rateThisAppDialog = nil;
  [self.dispatcher showReportAnIssueFromViewController:self];
}

- (void)userTappedDismiss:(UIView*)view {
  base::RecordAction(base::UserMetricsAction("IOSRateThisAppDismissChosen"));
  _rateThisAppDialog = nil;
}

#pragma mark - VoiceSearchBarOwner

- (id<VoiceSearchBar>)voiceSearchBar {
  return _voiceSearchBar;
}

#pragma mark - VoiceSearchBarDelegate

- (BOOL)isTTSEnabledForVoiceSearchBar:(id<VoiceSearchBar>)voiceSearchBar {
  DCHECK_EQ(_voiceSearchBar, voiceSearchBar);
  [self ensureVoiceSearchControllerCreated];
  return _voiceSearchController->IsTextToSpeechEnabled() &&
         _voiceSearchController->IsTextToSpeechSupported();
}

- (void)voiceSearchBarDidUpdateButtonState:(id<VoiceSearchBar>)voiceSearchBar {
  DCHECK_EQ(_voiceSearchBar, voiceSearchBar);
  SnapshotTabHelper::FromWebState(self.tabModel.currentTab.webState)
      ->UpdateSnapshot(/*with_overlays=*/true, /*visible_frame_only=*/true);
}

#pragma mark - LogoAnimationControllerOwnerOwner (Public)

- (id<LogoAnimationControllerOwner>)logoAnimationControllerOwner {
  return [self currentLogoAnimationControllerOwner];
}

#pragma mark - LogoAnimationControllerOwnerOwner helpers

// The LogoAnimationControllerOwner to be used for the next logo transition
// animation.
- (id<LogoAnimationControllerOwner>)currentLogoAnimationControllerOwner {
  Protocol* ownerProtocol = @protocol(LogoAnimationControllerOwner);
  if ([_voiceSearchBar conformsToProtocol:ownerProtocol] &&
      self.shouldShowVoiceSearchBar) {
    // Use |_voiceSearchBar| for VoiceSearch results tab and dismissal
    // animations.
    return static_cast<id<LogoAnimationControllerOwner>>(_voiceSearchBar);
  }
  id currentNativeController =
      [self nativeControllerForTab:self.tabModel.currentTab];
  Protocol* possibleOwnerProtocol =
      @protocol(LogoAnimationControllerOwnerOwner);
  if ([currentNativeController conformsToProtocol:possibleOwnerProtocol] &&
      [currentNativeController logoAnimationControllerOwner]) {
    // If the current native controller is showing a GLIF view (e.g. the NTP
    // when there is no doodle), use that GLIFControllerOwner.
    return [currentNativeController logoAnimationControllerOwner];
  }
  return nil;
}

#pragma mark - ActivityServicePresentation

- (void)presentActivityServiceViewController:(UIViewController*)controller {
  [self presentViewController:controller animated:YES completion:nil];
}

- (void)activityServiceDidEndPresenting {
  self.dialogPresenterDelegateIsPresenting = NO;
  [self.dialogPresenter tryToPresent];
}

- (void)showActivityServiceErrorAlertWithStringTitle:(NSString*)title
                                             message:(NSString*)message {
  [self showErrorAlertWithStringTitle:title message:message];
}

#pragma mark - QRScannerPresenting

- (void)presentQRScannerViewController:(UIViewController*)controller {
  [self presentViewController:controller animated:YES completion:nil];
}

- (void)dismissQRScannerViewController:(UIViewController*)controller
                            completion:(void (^)(void))completion {
  DCHECK_EQ(controller, self.presentedViewController);
  [self dismissViewControllerAnimated:YES completion:completion];
}

#pragma mark - TabHistoryPresentation

- (UIView*)viewForTabHistoryPresentation {
  return self.view;
}

- (void)prepareForTabHistoryPresentation {
  [self.dispatcher prepareForPopupMenuPresentation:PopupMenuCommandTypeDefault];
}

#pragma mark - CaptivePortalDetectorTabHelperDelegate

- (void)captivePortalDetectorTabHelper:
            (CaptivePortalDetectorTabHelper*)tabHelper
                 connectWithLandingURL:(const GURL&)landingURL {
  [self addSelectedTabWithURL:landingURL transition:ui::PAGE_TRANSITION_TYPED];
}

#pragma mark - PageInfoPresentation

- (void)presentPageInfoView:(UIView*)pageInfoView {
  [pageInfoView setFrame:self.view.bounds];
  [self.view addSubview:pageInfoView];
}

- (void)prepareForPageInfoPresentation {
  // Dismiss the omnibox (if open).
  [self.dispatcher cancelOmniboxEdit];
}

- (CGPoint)convertToPresentationCoordinatesForOrigin:(CGPoint)origin {
  return [self.view convertPoint:origin fromView:nil];
}

#pragma mark - WebStatePrinter

- (void)printWebState:(web::WebState*)webState {
  if (webState == [_model currentTab].webState)
    [self.dispatcher printTab];
}

#pragma mark - RepostFormTabHelperDelegate

- (void)repostFormTabHelper:(RepostFormTabHelper*)helper
    presentRepostFormDialogForWebState:(web::WebState*)webState
                         dialogAtPoint:(CGPoint)location
                     completionHandler:(void (^)(BOOL))completion {
  _repostFormCoordinator =
      [[RepostFormCoordinator alloc] initWithBaseViewController:self
                                                 dialogLocation:location
                                                       webState:webState
                                              completionHandler:completion];
  [_repostFormCoordinator start];
}

- (void)repostFormTabHelperDismissRepostFormDialog:
    (RepostFormTabHelper*)helper {
  _repostFormCoordinator = nil;
}

#pragma mark - TabStripPresentation

- (BOOL)isTabStripFullyVisible {
  return ([self currentHeaderOffset] == 0.0f);
}

- (void)showTabStripView:(UIView*)tabStripView {
  DCHECK([self isViewLoaded]);
  DCHECK(tabStripView);
  self.tabStripView = tabStripView;
  CGRect tabStripFrame = [self.tabStripView frame];
  tabStripFrame.origin = CGPointZero;
  // TODO(crbug.com/256655): Move the origin.y below to -setUpViewLayout.
  // because the CGPointZero above will break reset the offset, but it's not
  // clear what removing that will do.
  tabStripFrame.origin.y = self.headerOffset;
  tabStripFrame.size.width = CGRectGetWidth([self view].bounds);
  [self.tabStripView setFrame:tabStripFrame];
  [[self view] addSubview:tabStripView];
}

#pragma mark - ManageAccountsDelegate

- (void)onManageAccounts {
  signin_metrics::LogAccountReconcilorStateOnGaiaResponse(
      ios::AccountReconcilorFactory::GetForBrowserState(self.browserState)
          ->GetState());
  [self.dispatcher showAccountsSettingsFromViewController:self];
}

- (void)onAddAccount {
  signin_metrics::LogAccountReconcilorStateOnGaiaResponse(
      ios::AccountReconcilorFactory::GetForBrowserState(self.browserState)
          ->GetState());
  [self.dispatcher showAddAccountFromViewController:self];
}

- (void)onGoIncognito:(const GURL&)url {
  // The user taps on go incognito from the mobile U-turn webpage (the web page
  // that displays all users accounts available in the content area). As the
  // user chooses to go to incognito, the mobile U-turn page is no longer
  // neeeded. The current solution is to go back in history. This has the
  // advantage of keeping the current browsing session and give a good user
  // experience when the user comes back from incognito.
  [self.tabModel.currentTab goBack];

  if (url.is_valid()) {
    OpenUrlCommand* command = [[OpenUrlCommand alloc]
         initWithURL:url
            referrer:web::Referrer()  // Strip referrer when switching modes.
         inIncognito:YES
        inBackground:NO
            appendTo:kLastTab];
    [self.dispatcher openURL:command];
  } else {
    [self.dispatcher openNewTab:[OpenNewTabCommand command]];
  }
}

#pragma mark - SyncPresenter (Public)

- (void)showReauthenticateSignin {
  [self.dispatcher
              showSignin:
                  [[ShowSigninCommand alloc]
                      initWithOperation:AUTHENTICATION_OPERATION_REAUTHENTICATE
                            accessPoint:signin_metrics::AccessPoint::
                                            ACCESS_POINT_UNKNOWN]
      baseViewController:self];
}

- (void)showSyncSettings {
  [self.dispatcher showSyncSettingsFromViewController:self];
}

- (void)showSyncPassphraseSettings {
  [self.dispatcher showSyncPassphraseSettingsFromViewController:self];
}

#pragma mark - SigninPresenter

- (void)showSignin:(ShowSigninCommand*)command {
  [self.dispatcher showSignin:command baseViewController:self];
}

@end

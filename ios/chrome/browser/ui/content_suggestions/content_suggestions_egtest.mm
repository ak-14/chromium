// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import <EarlGrey/EarlGrey.h>
#import <XCTest/XCTest.h>

#include <memory>
#include <vector>

#include "base/mac/foundation_util.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#import "base/test/ios/wait_util.h"
#include "base/test/scoped_command_line.h"
#include "components/keyed_service/ios/browser_state_keyed_service_factory.h"
#include "components/ntp_snippets/content_suggestion.h"
#include "components/ntp_snippets/content_suggestions_service.h"
#include "components/ntp_snippets/mock_content_suggestions_provider.h"
#include "components/reading_list/core/reading_list_entry.h"
#include "components/reading_list/core/reading_list_model.h"
#include "components/strings/grit/components_strings.h"
#include "ios/chrome/browser/browser_state/chrome_browser_state.h"
#include "ios/chrome/browser/chrome_switches.h"
#include "ios/chrome/browser/ntp_snippets/ios_chrome_content_suggestions_service_factory.h"
#include "ios/chrome/browser/ntp_snippets/ios_chrome_content_suggestions_service_factory_util.h"
#include "ios/chrome/browser/reading_list/reading_list_model_factory.h"
#import "ios/chrome/browser/ui/content_suggestions/cells/content_suggestions_header_item.h"
#import "ios/chrome/browser/ui/content_suggestions/cells/content_suggestions_learn_more_item.h"
#include "ios/chrome/browser/ui/content_suggestions/content_suggestions_collection_utils.h"
#import "ios/chrome/browser/ui/content_suggestions/ntp_home_constant.h"
#import "ios/chrome/browser/ui/content_suggestions/ntp_home_provider_test_singleton.h"
#import "ios/chrome/browser/ui/content_suggestions/ntp_home_test_utils.h"
#include "ios/chrome/browser/ui/ui_util.h"
#include "ios/chrome/grit/ios_strings.h"
#import "ios/chrome/test/app/chrome_test_util.h"
#import "ios/chrome/test/app/history_test_util.h"
#import "ios/chrome/test/app/tab_test_util.h"
#import "ios/chrome/test/earl_grey/chrome_earl_grey.h"
#import "ios/chrome/test/earl_grey/chrome_earl_grey_ui.h"
#import "ios/chrome/test/earl_grey/chrome_matchers.h"
#import "ios/chrome/test/earl_grey/chrome_test_case.h"
#import "ios/testing/wait_util.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "ui/strings/grit/ui_strings.h"

#if !defined(__has_feature) || !__has_feature(objc_arc)
#error "This file requires ARC support."
#endif

using namespace ntp_snippets;
using testing::_;
using testing::Invoke;
using testing::WithArg;

namespace {

const char kPageLoadedString[] = "Page loaded!";
const char kPageURL[] = "/test-page.html";
const char kPageTitle[] = "Page title!";

//  Scrolls the collection view in order to have the toolbar menu icon visible.
void ScrollUp() {
  [[[EarlGrey
      selectElementWithMatcher:grey_allOf(chrome_test_util::ToolsMenuButton(),
                                          grey_sufficientlyVisible(), nil)]
         usingSearchAction:grey_scrollInDirection(kGREYDirectionUp, 150)
      onElementWithMatcher:chrome_test_util::ContentSuggestionCollectionView()]
      assertWithMatcher:grey_notNil()];
}

// Provides responses for redirect and changed window location URLs.
std::unique_ptr<net::test_server::HttpResponse> StandardResponse(
    const net::test_server::HttpRequest& request) {
  if (request.relative_url != kPageURL) {
    return nullptr;
  }
  std::unique_ptr<net::test_server::BasicHttpResponse> http_response =
      std::make_unique<net::test_server::BasicHttpResponse>();
  http_response->set_code(net::HTTP_OK);
  http_response->set_content("<html><head><title>" + std::string(kPageTitle) +
                             "</title></head><body>" +
                             std::string(kPageLoadedString) + "</body></html>");
  return std::move(http_response);
}

// Returns a suggestion created from the |category|, |suggestion_id| and the
// |url|.
ContentSuggestion Suggestion(Category category,
                             std::string suggestion_id,
                             GURL url) {
  ContentSuggestion suggestion(category, suggestion_id, url);
  suggestion.set_title(base::UTF8ToUTF16(url.spec()));

  return suggestion;
}

// Select the cell with the |matcher| by scrolling the collection.
// 200 is a reasonable scroll displacement that works for all UI elements, while
// not being too slow.
GREYElementInteraction* CellWithMatcher(id<GREYMatcher> matcher) {
  return [[EarlGrey
      selectElementWithMatcher:grey_allOf(matcher, grey_sufficientlyVisible(),
                                          nil)]
         usingSearchAction:grey_scrollInDirection(kGREYDirectionDown, 200)
      onElementWithMatcher:chrome_test_util::ContentSuggestionCollectionView()];
}

}  // namespace

#pragma mark - TestCase

// Test case for the ContentSuggestion UI.
@interface ContentSuggestionsTestCase : ChromeTestCase

// Current non-incognito browser state.
@property(nonatomic, assign, readonly) ios::ChromeBrowserState* browserState;
// Mock provider from the singleton.
@property(nonatomic, assign, readonly) MockContentSuggestionsProvider* provider;
// Article category, used by the singleton.
@property(nonatomic, assign, readonly) Category category;

@end

@implementation ContentSuggestionsTestCase

#pragma mark - Setup/Teardown

+ (void)setUp {
  [super setUp];

  [self closeAllTabs];
  ios::ChromeBrowserState* browserState =
      chrome_test_util::GetOriginalBrowserState();

  // Sets the ContentSuggestionsService associated with this browserState to a
  // service with no provider registered, allowing to register fake providers
  // which do not require internet connection. The previous service is deleted.
  IOSChromeContentSuggestionsServiceFactory::GetInstance()->SetTestingFactory(
      browserState, CreateChromeContentSuggestionsService);

  ContentSuggestionsService* service =
      IOSChromeContentSuggestionsServiceFactory::GetForBrowserState(
          browserState);
  RegisterReadingListProvider(service, browserState);
  [[ContentSuggestionsTestSingleton sharedInstance]
      registerArticleProvider:service];
}

+ (void)tearDown {
  [self closeAllTabs];
  ios::ChromeBrowserState* browserState =
      chrome_test_util::GetOriginalBrowserState();
  ReadingListModelFactory::GetForBrowserState(browserState)->DeleteAllEntries();

  // Resets the Service associated with this browserState to a service with
  // default providers. The previous service is deleted.
  IOSChromeContentSuggestionsServiceFactory::GetInstance()->SetTestingFactory(
      browserState, CreateChromeContentSuggestionsServiceWithProviders);
  [super tearDown];
}

- (void)setUp {
  self.provider->FireCategoryStatusChanged(self.category,
                                           CategoryStatus::AVAILABLE);

  ReadingListModel* readingListModel =
      ReadingListModelFactory::GetForBrowserState(self.browserState);
  readingListModel->DeleteAllEntries();
  [super setUp];
}

- (void)tearDown {
  self.provider->FireCategoryStatusChanged(
      self.category, CategoryStatus::ALL_SUGGESTIONS_EXPLICITLY_DISABLED);
  GREYAssertTrue(chrome_test_util::ClearBrowsingHistory(),
                 @"Clearing Browsing History timed out");
  [[GREYUIThreadExecutor sharedInstance] drainUntilIdle];
  [super tearDown];
}

#pragma mark - Tests

// Tests that the additional items (when more is pressed) are kept when
// switching tabs.
- (void)testAdditionalItemsKept {
  // Set server up.
  self.testServer->RegisterRequestHandler(base::Bind(&StandardResponse));
  GREYAssertTrue(self.testServer->Start(), @"Test server failed to start.");
  const GURL pageURL = self.testServer->GetURL(kPageURL);

  // Add 3 suggestions, persisted accross page loads.
  std::vector<ContentSuggestion> suggestions;
  suggestions.emplace_back(
      Suggestion(self.category, "chromium1", GURL("http://chromium.org/1")));
  suggestions.emplace_back(
      Suggestion(self.category, "chromium2", GURL("http://chromium.org/2")));
  suggestions.emplace_back(
      Suggestion(self.category, "chromium3", GURL("http://chromium.org/3")));
  self.provider->FireSuggestionsChanged(self.category, std::move(suggestions));

  // Set up the action when "More" is tapped.
  AdditionalSuggestionsHelper helper(pageURL);
  EXPECT_CALL(*self.provider, FetchMock(_, _, _))
      .WillOnce(WithArg<2>(Invoke(
          &helper, &AdditionalSuggestionsHelper::SendAdditionalSuggestions)));

  // Tap on more, which adds 10 elements.
  [CellWithMatcher(chrome_test_util::ButtonWithAccessibilityLabelId(
      IDS_IOS_CONTENT_SUGGESTIONS_FOOTER_TITLE)) performAction:grey_tap()];

  // Make sure some items are loaded.
  [CellWithMatcher(grey_accessibilityID(@"AdditionalSuggestion2"))
      assertWithMatcher:grey_notNil()];

  // Open a new Tab.
  ScrollUp();
  [ChromeEarlGreyUI openNewTab];
  [ChromeEarlGrey waitForMainTabCount:2];

  // Go back to the previous tab.
  chrome_test_util::SelectTabAtIndexInCurrentMode(0);

  // Make sure the additional items are still displayed.
  [CellWithMatcher(grey_accessibilityID(@"AdditionalSuggestion2"))
      assertWithMatcher:grey_notNil()];
}

// Tests that after dismissing a ReadingList item, it is not displayed on the
// NTP. But it is still unread in the Reading List surface.
- (void)testSwipeToDismissReadingListItem {
  // TODO(crbug.com/807330): The collection view reading list section is not
  // used in ui refresh.
  if (IsUIRefreshPhase1Enabled()) {
    EARL_GREY_TEST_SKIPPED(@"ReadingList section does not exist in UI Refresh");
  }

  // Add two items to Reading List.
  std::string stdTitle1{"test title1"};
  std::string stdTitle2{"test title2"};
  NSString* title1 = base::SysUTF8ToNSString(stdTitle1);
  NSString* title2 = base::SysUTF8ToNSString(stdTitle2);
  ReadingListModel* readingListModel =
      ReadingListModelFactory::GetForBrowserState(self.browserState);
  readingListModel->AddEntry(GURL("http://chromium.org/2"), stdTitle2,
                             reading_list::ADDED_VIA_CURRENT_APP);
  readingListModel->AddEntry(GURL("http://chromium.org/1"), stdTitle1,
                             reading_list::ADDED_VIA_CURRENT_APP);

  // Check that the two items are present in a new tab.
  [ChromeEarlGreyUI openNewTab];
  [CellWithMatcher(grey_accessibilityID(title1))
      assertWithMatcher:grey_sufficientlyVisible()];
  [CellWithMatcher(grey_accessibilityID(title2))
      assertWithMatcher:grey_sufficientlyVisible()];

  // Swipe to dismiss the first one.
  [CellWithMatcher(grey_accessibilityID(title1))
      performAction:[GREYActions
                        actionForSwipeFastInDirection:kGREYDirectionLeft
                               xOriginStartPercentage:0.9
                               yOriginStartPercentage:0.5]];

  // Check the swiped item is dismissed.
  [[EarlGrey
      selectElementWithMatcher:grey_allOf(grey_accessibilityID(title1),
                                          grey_sufficientlyVisible(), nil)]
      assertWithMatcher:grey_nil()];

  // Check the dismissed item is not present when opening a new NTP.
  ScrollUp();
  [ChromeEarlGreyUI openNewTab];
  [CellWithMatcher(grey_accessibilityID(title2))
      assertWithMatcher:grey_sufficientlyVisible()];
  [[EarlGrey selectElementWithMatcher:grey_accessibilityID(title1)]
      assertWithMatcher:grey_nil()];

  // Open the Reading List surface.
  ScrollUp();
  [ChromeEarlGreyUI openToolsMenu];
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_TOOLS_MENU_READING_LIST)]
      performAction:grey_tap()];

  // Check that both entries are unread in the ReadingList surface.
  [[EarlGrey selectElementWithMatcher:chrome_test_util::
                                          StaticTextWithAccessibilityLabelId(
                                              IDS_IOS_READING_LIST_READ_HEADER)]
      assertWithMatcher:grey_notVisible()];

  [[EarlGrey selectElementWithMatcher:
                 chrome_test_util::StaticTextWithAccessibilityLabelId(
                     IDS_IOS_READING_LIST_UNREAD_HEADER)]
      assertWithMatcher:grey_sufficientlyVisible()];

  [[EarlGrey selectElementWithMatcher:
                 chrome_test_util::StaticTextWithAccessibilityLabel(title1)]
      assertWithMatcher:grey_sufficientlyVisible()];

  // On iPad two Reading List items are displayed as the Reading List view is
  // displayed modally, the NTP is still visible.
  [[EarlGrey
      selectElementWithMatcher:
          grey_allOf(chrome_test_util::StaticTextWithAccessibilityLabel(title2),
                     grey_not(grey_ancestor(
                         chrome_test_util::ContentSuggestionCollectionView())),
                     nil)] assertWithMatcher:grey_sufficientlyVisible()];

  // Close Reading List.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_READING_LIST_DONE_BUTTON)]
      performAction:grey_tap()];
}

// Tests that only the 3 most recent Reading List items are displayed.
- (void)testReadingListItem {
  // TODO(crbug.com/807330): The collection view reading list section is not
  // used in ui refresh.
  if (IsUIRefreshPhase1Enabled()) {
    EARL_GREY_TEST_SKIPPED(@"ReadingList section does not exist in UI Refresh");
  }

  // Create entry titles for 4 unread entries and 1 read entry.
  std::string stdTitle1{"test unread title1"};
  std::string stdTitle2{"test unread title2"};
  std::string stdTitle3{"test unread title3"};
  std::string stdTitle4{"test unread title4"};
  std::string stdReadTitle{"test read title"};
  NSString* title1 = base::SysUTF8ToNSString(stdTitle1);
  NSString* title2 = base::SysUTF8ToNSString(stdTitle2);
  NSString* title3 = base::SysUTF8ToNSString(stdTitle3);
  NSString* title4 = base::SysUTF8ToNSString(stdTitle4);
  NSString* readTitle = base::SysUTF8ToNSString(stdReadTitle);

  // Adds the entries: title1 is the oldest, title4 is the latest.
  ReadingListModel* readingListModel =
      ReadingListModelFactory::GetForBrowserState(self.browserState);
  readingListModel->AddEntry(GURL("http://chromium.org/1"), stdTitle1,
                             reading_list::ADDED_VIA_CURRENT_APP);
  readingListModel->AddEntry(GURL("http://chromium.org/2"), stdTitle2,
                             reading_list::ADDED_VIA_CURRENT_APP);
  readingListModel->AddEntry(GURL("http://chromium.org/3"), stdTitle3,
                             reading_list::ADDED_VIA_CURRENT_APP);
  readingListModel->AddEntry(GURL("http://chromium.org/5"), stdReadTitle,
                             reading_list::ADDED_VIA_CURRENT_APP);
  readingListModel->SetReadStatus(GURL("http://chromium.org/5"), true);
  readingListModel->AddEntry(GURL("http://chromium.org/4"), stdTitle4,
                             reading_list::ADDED_VIA_CURRENT_APP);

  // Check that only the first 3 unread items are displayed.
  [ChromeEarlGreyUI openNewTab];
  [CellWithMatcher(grey_accessibilityID(title4))
      assertWithMatcher:grey_sufficientlyVisible()];
  [CellWithMatcher(grey_accessibilityID(title3))
      assertWithMatcher:grey_sufficientlyVisible()];
  [CellWithMatcher(grey_accessibilityID(title2))
      assertWithMatcher:grey_sufficientlyVisible()];
  [[EarlGrey selectElementWithMatcher:grey_accessibilityID(readTitle)]
      assertWithMatcher:grey_nil()];
  [[EarlGrey selectElementWithMatcher:grey_accessibilityID(title1)]
      assertWithMatcher:grey_nil()];
}

// Tests that tapping "More" on the Reading List section opens the Reading List
// surface.
- (void)testMoreReadingListSection {
  // TODO(crbug.com/807330): The collection view reading list section is not
  // used in ui refresh.
  if (IsUIRefreshPhase1Enabled()) {
    EARL_GREY_TEST_SKIPPED(@"ReadingList section does not exist in UI Refresh");
  }
  // Add an entry to make sure the Reading List section is displayed.
  ReadingListModel* readingListModel =
      ReadingListModelFactory::GetForBrowserState(self.browserState);
  readingListModel->AddEntry(GURL("http://chromium.org/2"), "test title",
                             reading_list::ADDED_VIA_CURRENT_APP);

  // Tap More.
  [CellWithMatcher(chrome_test_util::StaticTextWithAccessibilityLabelId(
      IDS_IOS_CONTENT_SUGGESTIONS_FOOTER_TITLE)) performAction:grey_tap()];

  // Check the Reading List surface is opened.
  [[EarlGrey selectElementWithMatcher:chrome_test_util::
                                          StaticTextWithAccessibilityLabelId(
                                              IDS_IOS_TOOLS_MENU_READING_LIST)]
      assertWithMatcher:grey_sufficientlyVisible()];

  // Close Reading List.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_READING_LIST_DONE_BUTTON)]
      performAction:grey_tap()];
}

// Tests that a switch for the ContentSuggestions exists in the settings. The
// behavior depends on having a real remote provider, so it cannot be tested
// here.
- (void)testPrivacySwitch {
  [ChromeEarlGreyUI openSettingsMenu];
  [ChromeEarlGreyUI
      tapSettingsMenuButton:chrome_test_util::SettingsMenuPrivacyButton()];
  [[EarlGrey selectElementWithMatcher:
                 chrome_test_util::StaticTextWithAccessibilityLabelId(
                     IDS_IOS_OPTIONS_SEARCH_URL_SUGGESTIONS)]
      assertWithMatcher:grey_sufficientlyVisible()];
}

// Tests that the section titles are displayed only if there are two sections.
- (void)testSectionTitle {
  // TODO(crbug.com/807330): The collection view reading list section is not
  // used in ui refresh.
  if (IsUIRefreshPhase1Enabled()) {
    EARL_GREY_TEST_SKIPPED(@"ReadingList section does not exist in UI Refresh");
  }

  ReadingListModel* readingListModel =
      ReadingListModelFactory::GetForBrowserState(self.browserState);
  readingListModel->AddEntry(GURL("http://chromium.org"), "test title",
                             reading_list::ADDED_VIA_CURRENT_APP);

  [CellWithMatcher(chrome_test_util::StaticTextWithAccessibilityLabelId(
      IDS_NTP_READING_LIST_SUGGESTIONS_SECTION_HEADER))
      assertWithMatcher:grey_nil()];

  std::vector<ContentSuggestion> suggestions;
  suggestions.emplace_back(
      Suggestion(self.category, "chromium", GURL("http://chromium.org")));
  self.provider->FireSuggestionsChanged(self.category, std::move(suggestions));

  [CellWithMatcher(chrome_test_util::StaticTextWithAccessibilityLabelId(
      IDS_NTP_READING_LIST_SUGGESTIONS_SECTION_HEADER))
      assertWithMatcher:grey_sufficientlyVisible()];
}

// Tests that when tapping a suggestion, it is opened. When going back, the
// disposition of the collection takes into account the previous scroll, even
// when more is tapped.
- (void)testOpenPageAndGoBackWithMoreContent {
  // Set server up.
  self.testServer->RegisterRequestHandler(base::Bind(&StandardResponse));
  GREYAssertTrue(self.testServer->Start(), @"Test server failed to start.");
  const GURL pageURL = self.testServer->GetURL(kPageURL);

  // Add 3 suggestions, persisted accross page loads.
  std::vector<ContentSuggestion> suggestions;
  suggestions.emplace_back(
      Suggestion(self.category, "chromium1", GURL("http://chromium.org/1")));
  suggestions.emplace_back(
      Suggestion(self.category, "chromium2", GURL("http://chromium.org/2")));
  suggestions.emplace_back(
      Suggestion(self.category, "chromium3", GURL("http://chromium.org/3")));
  self.provider->FireSuggestionsChanged(self.category, std::move(suggestions));

  // Set up the action when "More" is tapped.
  AdditionalSuggestionsHelper helper(pageURL);
  EXPECT_CALL(*self.provider, FetchMock(_, _, _))
      .WillOnce(WithArg<2>(Invoke(
          &helper, &AdditionalSuggestionsHelper::SendAdditionalSuggestions)));

  // Tap on more, which adds 10 elements.
  [CellWithMatcher(chrome_test_util::ButtonWithAccessibilityLabelId(
      IDS_IOS_CONTENT_SUGGESTIONS_FOOTER_TITLE)) performAction:grey_tap()];

  // Make sure to scroll to the bottom.
  [CellWithMatcher(grey_accessibilityID(
      [ContentSuggestionsLearnMoreItem accessibilityIdentifier]))
      assertWithMatcher:grey_notNil()];

  // Open the last item.
  [CellWithMatcher(grey_accessibilityID(@"AdditionalSuggestion9"))
      performAction:grey_tap()];

  // Check that the page has been opened.
  [ChromeEarlGrey waitForWebViewContainingText:kPageLoadedString];
  [[EarlGrey selectElementWithMatcher:chrome_test_util::OmniboxText(
                                          pageURL.GetContent())]
      assertWithMatcher:grey_notNil()];
  [ChromeEarlGrey waitForMainTabCount:1];
  [ChromeEarlGrey waitForIncognitoTabCount:0];

  // Go back.
  [[EarlGrey selectElementWithMatcher:chrome_test_util::BackButton()]
      performAction:grey_tap()];

  // Test that the omnibox is visible and taking full width, before any scroll
  // happen on iPhone.
  if (!content_suggestions::IsRegularXRegularSizeClass()) {
    if (!IsUIRefreshPhase1Enabled()) {
      CGFloat collectionWidth = ntp_home::CollectionView().bounds.size.width;
      [[EarlGrey
          selectElementWithMatcher:grey_accessibilityID(
                                       ntp_home::FakeOmniboxAccessibilityID())]
          assertWithMatcher:grey_allOf(grey_sufficientlyVisible(),
                                       ntp_home::OmniboxWidthBetween(
                                           collectionWidth + 1, 1),
                                       nil)];
    }

    // Test that the omnibox is still pinned to the top of the screen and
    // under the safe area.
    CGFloat safeAreaTop = IsUIRefreshPhase1Enabled() ? StatusBarHeight() : 0;
    CGFloat contentOffset = ntp_home::CollectionView().contentOffset.y;
    CGFloat fakeOmniboxOrigin = ntp_home::FakeOmnibox().frame.origin.y;
    CGFloat pinnedOffset = contentOffset - (fakeOmniboxOrigin - safeAreaTop);
    [[EarlGrey selectElementWithMatcher:grey_accessibilityID(
                                            [ContentSuggestionsHeaderItem
                                                accessibilityIdentifier])]
        assertWithMatcher:ntp_home::HeaderPinnedOffset(pinnedOffset)];
  }

  // Check that the first items are visible as the collection should be
  // scrolled.
  [[EarlGrey
      selectElementWithMatcher:grey_accessibilityID(@"http://chromium.org/3")]
      assertWithMatcher:grey_sufficientlyVisible()];
}

// Tests that the "Learn More" cell is present only if there is a suggestion in
// the section.
- (void)testLearnMore {
  [[EarlGrey selectElementWithMatcher:chrome_test_util::
                                          ContentSuggestionCollectionView()]
      performAction:grey_scrollToContentEdge(kGREYContentEdgeBottom)];
  [[EarlGrey selectElementWithMatcher:grey_accessibilityID(
                                          [ContentSuggestionsLearnMoreItem
                                              accessibilityIdentifier])]
      assertWithMatcher:grey_nil()];

  std::vector<ContentSuggestion> suggestions;
  suggestions.emplace_back(
      Suggestion(self.category, "chromium", GURL("http://chromium.org")));
  self.provider->FireSuggestionsChanged(self.category, std::move(suggestions));

  [CellWithMatcher(grey_accessibilityID(
      [ContentSuggestionsLearnMoreItem accessibilityIdentifier]))
      assertWithMatcher:grey_sufficientlyVisible()];
}

// Tests that when long pressing a Reading List entry, a context menu is shown.
- (void)testReadingListLongPress {
  // TODO(crbug.com/807330): The collection view reading list section is not
  // used in ui refresh.
  if (IsUIRefreshPhase1Enabled()) {
    EARL_GREY_TEST_SKIPPED(@"ReadingList section does not exist in UI Refresh");
  }

  NSString* title = @"ReadingList test title";
  std::string sTitle{"ReadingList test title"};
  ReadingListModel* readingListModel =
      ReadingListModelFactory::GetForBrowserState(self.browserState);
  readingListModel->AddEntry(GURL("http://chromium.org"), sTitle,
                             reading_list::ADDED_VIA_CURRENT_APP);

  [CellWithMatcher(grey_accessibilityID(title)) performAction:grey_longPress()];

  if (!content_suggestions::IsRegularXRegularSizeClass()) {
    [[EarlGrey selectElementWithMatcher:
                   chrome_test_util::ButtonWithAccessibilityLabelId(
                       IDS_APP_CANCEL)] assertWithMatcher:grey_interactable()];
  }

  // No read later as it is already in the Reading List section.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_CONTENT_CONTEXT_ADDTOREADINGLIST)]
      assertWithMatcher:grey_nil()];
}

// Tests that "Open in New Tab" in context menu opens in a new tab.
- (void)testReadingListOpenNewTab {
  // TODO(crbug.com/807330): The collection view reading list section is not
  // used in ui refresh.
  if (IsUIRefreshPhase1Enabled()) {
    EARL_GREY_TEST_SKIPPED(@"ReadingList section does not exist in UI Refresh");
  }

  // Setup.
  [self setupReadingListContextMenu];
  const GURL pageURL = self.testServer->GetURL(kPageURL);

  // Open in new tab.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_CONTENT_CONTEXT_OPENLINKNEWTAB)]
      performAction:grey_tap()];

  // Check a new page in normal model is opened.
  [ChromeEarlGrey waitForMainTabCount:2];
  [ChromeEarlGrey waitForIncognitoTabCount:0];

  // Wait for the end of the new tab opening in background. This is needed as
  // the iOS 11 devices cannot complete this animations while checking if the
  // collection is present.
  base::test::ios::SpinRunLoopWithMinDelay(base::TimeDelta::FromSecondsD(1));

  // Check that the tab has been opened in background.
  ConditionBlock condition = ^{
    NSError* error = nil;
    [[EarlGrey selectElementWithMatcher:chrome_test_util::
                                            ContentSuggestionCollectionView()]
        assertWithMatcher:grey_sufficientlyVisible()
                    error:&error];
    return error == nil;
  };
  GREYAssert(testing::WaitUntilConditionOrTimeout(
                 testing::kWaitForUIElementTimeout, condition),
             @"Collection view not visible");

  // Check the page has been correctly opened.
  chrome_test_util::SelectTabAtIndexInCurrentMode(1);
  [ChromeEarlGrey waitForWebViewContainingText:kPageLoadedString];
  [[EarlGrey selectElementWithMatcher:chrome_test_util::OmniboxText(
                                          pageURL.GetContent())]
      assertWithMatcher:grey_notNil()];
}

// Tests that "Open in New Incognito Tab" in context menu opens in a new
// incognito tab.
- (void)testReadingListOpenNewIncognitoTab {
  // TODO(crbug.com/807330): The collection view reading list section is not
  // used in ui refresh.
  if (IsUIRefreshPhase1Enabled()) {
    EARL_GREY_TEST_SKIPPED(@"ReadingList section does not exist in UI Refresh");
  }

  // Setup.
  [self setupReadingListContextMenu];
  const GURL pageURL = self.testServer->GetURL(kPageURL);

  // Open in new incognito tab.
  [[EarlGrey selectElementWithMatcher:
                 chrome_test_util::ButtonWithAccessibilityLabelId(
                     IDS_IOS_CONTENT_CONTEXT_OPENLINKNEWINCOGNITOTAB)]
      performAction:grey_tap()];

  // Check that the tab has been opened in foreground.
  [ChromeEarlGrey waitForWebViewContainingText:kPageLoadedString];
  [[EarlGrey selectElementWithMatcher:chrome_test_util::OmniboxText(
                                          pageURL.GetContent())]
      assertWithMatcher:grey_notNil()];

  GREYAssertTrue(chrome_test_util::IsIncognitoMode(),
                 @"Test did not switch to incognito");

  // Check only one incognito tab has been opened.
  [ChromeEarlGrey waitForIncognitoTabCount:1];
  [ChromeEarlGrey waitForMainTabCount:1];
}

// Tests that "Remove" in context menu removes the entry.
- (void)testReadingListRemove {
  // TODO(crbug.com/807330): The collection view reading list section is not
  // used in ui refresh.
  if (IsUIRefreshPhase1Enabled()) {
    EARL_GREY_TEST_SKIPPED(@"ReadingList section does not exist in UI Refresh");
  }

  // Setup.
  NSString* title = @"ReadingList test title";
  [self setupReadingListContextMenu];
  const GURL pageURL = self.testServer->GetURL(kPageURL);

  // Remove the element.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_CONTENT_SUGGESTIONS_REMOVE)]
      performAction:grey_tap()];

  // Check the entry has been removed.
  [[EarlGrey
      selectElementWithMatcher:grey_allOf(grey_accessibilityID(title),
                                          grey_sufficientlyVisible(), nil)]
      assertWithMatcher:grey_nil()];

  // Check the entry is still unread in the Reading List model.
  ReadingListModel* readingListModel =
      ReadingListModelFactory::GetForBrowserState(self.browserState);
  GREYAssertEqual(1, readingListModel->unread_size(),
                  @"The number of unread entry has been changed.");
}

// Tests the "Open in New Tab" action of the Most Visited context menu.
- (void)testMostVisitedNewTab {
  [self setupMostVisitedTileLongPress];
  const GURL pageURL = self.testServer->GetURL(kPageURL);

  // Open in new tab.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_CONTENT_CONTEXT_OPENLINKNEWTAB)]
      performAction:grey_tap()];

  // Check a new page in normal model is opened.
  [ChromeEarlGrey waitForMainTabCount:2];
  [ChromeEarlGrey waitForIncognitoTabCount:0];

  // Check that the tab has been opened in background.
  ConditionBlock condition = ^{
    NSError* error = nil;
    [[EarlGrey selectElementWithMatcher:chrome_test_util::
                                            ContentSuggestionCollectionView()]
        assertWithMatcher:grey_notNil()
                    error:&error];
    return error == nil;
  };
  GREYAssert(testing::WaitUntilConditionOrTimeout(
                 testing::kWaitForUIElementTimeout, condition),
             @"Collection view not visible");

  // Check the page has been correctly opened.
  chrome_test_util::SelectTabAtIndexInCurrentMode(1);
  [ChromeEarlGrey waitForWebViewContainingText:kPageLoadedString];
  [[EarlGrey selectElementWithMatcher:chrome_test_util::OmniboxText(
                                          pageURL.GetContent())]
      assertWithMatcher:grey_notNil()];
}

// Tests the "Open in New Incognito Tab" action of the Most Visited context
// menu.
- (void)testMostVisitedNewIncognitoTab {
  [self setupMostVisitedTileLongPress];
  const GURL pageURL = self.testServer->GetURL(kPageURL);

  // Open in new incognito tab.
  [[EarlGrey selectElementWithMatcher:
                 chrome_test_util::ButtonWithAccessibilityLabelId(
                     IDS_IOS_CONTENT_CONTEXT_OPENLINKNEWINCOGNITOTAB)]
      performAction:grey_tap()];

  [ChromeEarlGrey waitForMainTabCount:1];
  [ChromeEarlGrey waitForIncognitoTabCount:1];

  // Check that the tab has been opened in foreground.
  [ChromeEarlGrey waitForWebViewContainingText:kPageLoadedString];
  [[EarlGrey selectElementWithMatcher:chrome_test_util::OmniboxText(
                                          pageURL.GetContent())]
      assertWithMatcher:grey_notNil()];

  GREYAssertTrue(chrome_test_util::IsIncognitoMode(),
                 @"Test did not switch to incognito");
}

// Tests the "Remove" action of the Most Visited context menu, and the "Undo"
// action.
- (void)testMostVisitedRemoveUndo {
  [self setupMostVisitedTileLongPress];
  const GURL pageURL = self.testServer->GetURL(kPageURL);
  NSString* pageTitle = base::SysUTF8ToNSString(kPageTitle);

  // Tap on remove.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_CONTENT_SUGGESTIONS_REMOVE)]
      performAction:grey_tap()];

  // Check the tile is removed.
  [[EarlGrey
      selectElementWithMatcher:
          grey_allOf(
              chrome_test_util::StaticTextWithAccessibilityLabel(pageTitle),
              grey_sufficientlyVisible(), nil)] assertWithMatcher:grey_nil()];

  // Check the snack bar notifying the user that an element has been removed is
  // displayed.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_NEW_TAB_MOST_VISITED_ITEM_REMOVED)]
      assertWithMatcher:grey_sufficientlyVisible()];

  // Tap on undo.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_NEW_TAB_UNDO_THUMBNAIL_REMOVE)]
      performAction:grey_tap()];

  // Check the tile is back.
  [[EarlGrey selectElementWithMatcher:
                 chrome_test_util::StaticTextWithAccessibilityLabel(pageTitle)]
      assertWithMatcher:grey_sufficientlyVisible()];
}

// Tests that the context menu has the correct actions.
- (void)testMostVisitedLongPress {
  [self setupMostVisitedTileLongPress];

  if (!content_suggestions::IsRegularXRegularSizeClass()) {
    [[EarlGrey selectElementWithMatcher:
                   chrome_test_util::ButtonWithAccessibilityLabelId(
                       IDS_APP_CANCEL)] assertWithMatcher:grey_interactable()];
  }

  // No read later.
  [[EarlGrey
      selectElementWithMatcher:chrome_test_util::ButtonWithAccessibilityLabelId(
                                   IDS_IOS_CONTENT_CONTEXT_ADDTOREADINGLIST)]
      assertWithMatcher:grey_nil()];
}

#pragma mark - Properties

- (ios::ChromeBrowserState*)browserState {
  return chrome_test_util::GetOriginalBrowserState();
}

- (MockContentSuggestionsProvider*)provider {
  return [[ContentSuggestionsTestSingleton sharedInstance] provider];
}

- (Category)category {
  return Category::FromKnownCategory(KnownCategories::ARTICLES);
}

#pragma mark - Test utils

// Setup a Reading List item and long press it to open the context menu.
- (void)setupReadingListContextMenu {
  self.testServer->RegisterRequestHandler(base::Bind(&StandardResponse));
  GREYAssertTrue(self.testServer->Start(), @"Test server failed to start.");
  const GURL pageURL = self.testServer->GetURL(kPageURL);
  std::string sTitle{"ReadingList test title"};
  NSString* title = @"ReadingList test title";
  ReadingListModel* readingListModel =
      ReadingListModelFactory::GetForBrowserState(self.browserState);
  readingListModel->AddEntry(pageURL, sTitle,
                             reading_list::ADDED_VIA_CURRENT_APP);
  [CellWithMatcher(grey_accessibilityID(title)) performAction:grey_longPress()];
  [ChromeEarlGrey waitForMainTabCount:1];
  [ChromeEarlGrey waitForIncognitoTabCount:0];
  GREYAssertEqual(1, readingListModel->unread_size(),
                  @"There should be only one unread entry.");
}

// Setup a most visited tile, and open the context menu by long pressing on it.
- (void)setupMostVisitedTileLongPress {
  self.testServer->RegisterRequestHandler(base::Bind(&StandardResponse));
  GREYAssertTrue(self.testServer->Start(), @"Test server failed to start.");
  const GURL pageURL = self.testServer->GetURL(kPageURL);
  NSString* pageTitle = base::SysUTF8ToNSString(kPageTitle);

  // Clear history and verify that the tile does not exist.
  GREYAssertTrue(chrome_test_util::ClearBrowsingHistory(),
                 @"Clearing Browsing History timed out");
  [[GREYUIThreadExecutor sharedInstance] drainUntilIdle];
  [ChromeEarlGrey loadURL:pageURL];
  [ChromeEarlGrey waitForWebViewContainingText:kPageLoadedString];

  // After loading URL, need to do another action before opening a new tab
  // with the icon present.
  [ChromeEarlGrey goBack];

  [[self class] closeAllTabs];
  chrome_test_util::OpenNewTab();
  // TODO(crbug.com/783192): ChromeEarlGrey should have a method to open a new
  // tab and synchronize with the UI.
  [[GREYUIThreadExecutor sharedInstance] drainUntilIdle];

  [[EarlGrey selectElementWithMatcher:
                 chrome_test_util::StaticTextWithAccessibilityLabel(pageTitle)]
      performAction:grey_longPress()];
}

@end

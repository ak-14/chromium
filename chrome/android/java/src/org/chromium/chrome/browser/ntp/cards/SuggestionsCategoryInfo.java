// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.ntp.cards;

import org.chromium.base.Log;
import org.chromium.chrome.browser.ntp.ContextMenuManager;
import org.chromium.chrome.browser.ntp.ContextMenuManager.ContextMenuItemId;
import org.chromium.chrome.browser.ntp.snippets.CategoryInt;
import org.chromium.chrome.browser.ntp.snippets.ContentSuggestionsCardLayout;
import org.chromium.chrome.browser.ntp.snippets.KnownCategories;
import org.chromium.chrome.browser.suggestions.ContentSuggestionsAdditionalAction;
import org.chromium.chrome.browser.suggestions.SuggestionsNavigationDelegate;

import javax.annotation.Nullable;

/**
 * Contains meta information about a Category. Equivalent of the CategoryInfo class in
 * components/ntp_snippets/category_info.h.
 */
public class SuggestionsCategoryInfo {
    private static final String TAG = "NtpCards";

    /**
     * Id of the category.
     */
    @CategoryInt
    private final int mCategory;

    /**
     * Localized title of the category.
     */
    private final String mTitle;

    /**
     * Layout of the cards to be used to display suggestions in this category.
     */
    @ContentSuggestionsCardLayout
    private final int mCardLayout;

    /**
     * The type of additional action supported by the category, or
     * {@link ContentSuggestionsAdditionalAction#NONE} if no such action is supported.
     * @see ActionItem
     */
    @ContentSuggestionsAdditionalAction
    private final int mAdditionalAction;

    /** Whether this category should be shown if it offers no suggestions. */
    private final boolean mShowIfEmpty;

    /**
     * Description text to use on the status card when there are no suggestions in this category.
     */
    private final String mNoSuggestionsMessage;

    public SuggestionsCategoryInfo(@CategoryInt int category, String title,
            @ContentSuggestionsCardLayout int cardLayout,
            @ContentSuggestionsAdditionalAction int additionalAction, boolean showIfEmpty,
            String noSuggestionsMessage) {
        mCategory = category;
        mTitle = title;
        mCardLayout = cardLayout;
        mAdditionalAction = additionalAction;
        mShowIfEmpty = showIfEmpty;
        mNoSuggestionsMessage = noSuggestionsMessage;
    }

    public String getTitle() {
        return mTitle;
    }

    @CategoryInt
    public int getCategory() {
        return mCategory;
    }

    @ContentSuggestionsCardLayout
    public int getCardLayout() {
        return mCardLayout;
    }

    @ContentSuggestionsAdditionalAction
    public int getAdditionalAction() {
        return mAdditionalAction;
    }

    public boolean showIfEmpty() {
        return mShowIfEmpty;
    }

    /** Returns whether the current category holds suggestions from a remote server. */
    public boolean isRemote() {
        return mCategory > KnownCategories.REMOTE_CATEGORIES_OFFSET;
    }

    /**
     * Returns the string to use as description for the status card that is displayed when there are
     * no suggestions available for the provided category.
     */
    public String getNoSuggestionsMessage() {
        return mNoSuggestionsMessage;
    }

    /**
     * @param menuItemId The ID for a context menu item.
     * @return Whether the given context menu item is supported by this category, or null if that
     *         decision does not depend on the category.
     */
    @Nullable
    public Boolean isContextMenuItemSupported(@ContextMenuItemId int menuItemId) {
        if (menuItemId == ContextMenuManager.ID_REMOVE) return null;

        if (mCategory == KnownCategories.RECENT_TABS) return false;

        if (mCategory == KnownCategories.DOWNLOADS) {
            if (menuItemId == ContextMenuManager.ID_OPEN_IN_INCOGNITO_TAB) return false;
            if (menuItemId == ContextMenuManager.ID_SAVE_FOR_OFFLINE) return false;
        }
        return true;
    }

    /**
     * Performs the View All action for the provided category, navigating navigating to the view
     * showing all the content.
     */
    public void performViewAllAction(SuggestionsNavigationDelegate navigationDelegate) {
        switch (mCategory) {
            case KnownCategories.BOOKMARKS:
                navigationDelegate.navigateToBookmarks();
                break;
            case KnownCategories.DOWNLOADS:
                navigationDelegate.navigateToDownloadManager();
                break;
            case KnownCategories.FOREIGN_TABS:
                navigationDelegate.navigateToRecentTabs();
                break;
            case KnownCategories.PHYSICAL_WEB_PAGES_DEPRECATED:
            case KnownCategories.RECENT_TABS:
            case KnownCategories.ARTICLES:
            default:
                Log.wtf(TAG, "'Empty State' action called for unsupported category: %d", mCategory);
                break;
        }
    }

    /**
     * Whether the Category supports fetching more content. Only Articles supports this at this
     * time.
     */
    public boolean isFetchMoreSupported() {
        return mCategory == KnownCategories.ARTICLES;
    }
}

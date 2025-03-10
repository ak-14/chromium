// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.contextual_suggestions;

import android.os.SystemClock;
import android.support.annotation.Nullable;
import android.webkit.URLUtil;

import org.chromium.base.ThreadUtils;
import org.chromium.base.VisibleForTesting;
import org.chromium.chrome.browser.tab.EmptyTabObserver;
import org.chromium.chrome.browser.tab.Tab;
import org.chromium.chrome.browser.tab.TabObserver;
import org.chromium.chrome.browser.tabmodel.TabModel.TabLaunchType;
import org.chromium.chrome.browser.tabmodel.TabModel.TabSelectionType;
import org.chromium.chrome.browser.tabmodel.TabModelSelector;
import org.chromium.chrome.browser.tabmodel.TabModelSelectorTabModelObserver;
import org.chromium.chrome.browser.util.UrlUtilities;
import org.chromium.content_public.browser.WebContents;

import java.util.HashMap;
import java.util.Map;

/**
 * A helper class responsible for determining when to trigger requests for suggestions and when to
 * clear state.
 */
class FetchHelper {
    /** A delegate used to fetch suggestions. */
    interface Delegate {
        /**
         * Request a suggestions fetch for the specified {@code url}.
         * @param url The url for which suggestions should be fetched.
         */
        void requestSuggestions(String url);

        /**
         * Called when the state should be reset e.g. when the user navigates away from a webpage.
         */
        void clearState();

        /**
         * Called when a document becomes eligible for fetching but the fetch is being delayed.
         */
        void reportFetchDelayed(WebContents webContents);
    }

    /** State of the tab with respect to fetching readiness */
    class TabFetchReadinessState {
        private long mFetchTimeBaselineMillis;
        private String mUrl;

        TabFetchReadinessState(String url) {
            updateUrl(url);
        }

        /**
         * Updates the URL and if the context is different from the current one, resets the time at
         * which we can start fetching suggestions.
         * @param url A new value for URL tracked by the tab state.
         */
        void updateUrl(String url) {
            mUrl = URLUtil.isNetworkUrl(url) ? url : null;
            mFetchTimeBaselineMillis = 0;
        }

        /** @return The current URL tracked by this tab state. */
        String getUrl() {
            return mUrl;
        }

        /** @return Whether the tab state is tracking a tab with valid page loaded. */
        boolean isTrackingPage() {
            return mUrl != null;
        }

        /**
         * Sets the baseline from which the fetch delay is calculated if it was not
         * already set (conceptually starting the timer).
         * @param fetchTimeBaselineMillis The new value to set the baseline fetch time to.
         * @return Whether the fetch time baseline was set.
         */
        boolean setFetchTimeBaselineMillis(long fetchTimeBaselineMillis) {
            if (!isTrackingPage()) return false;
            if (isFetchTimeBaselineSet()) return false;
            mFetchTimeBaselineMillis = fetchTimeBaselineMillis;
            return true;
        }

        /** @return The time at which fetch time baseline was established. */
        long getFetchTimeBaselineMillis() {
            return mFetchTimeBaselineMillis;
        }

        /** @return Whether the fetch timer is running. */
        boolean isFetchTimeBaselineSet() {
            return mFetchTimeBaselineMillis != 0;
        }

        /**
         * Checks whether the provided url is the same (ignoring fragments) as the one tracked by
         * tab state.
         * @param url A URL to check against the URL in the tab state.
         * @return Whether the URLs can be considered the same.
         */
        boolean isContextTheSame(String url) {
            return UrlUtilities.urlsMatchIgnoringFragments(url, mUrl);
        }
    }

    // TODO(fgorski): flip this to finch controlled setting.
    private final static long MINIMUM_FETCH_DELAY_MILLIS = 2 * 1000; // 2 seconds.
    private final Delegate mDelegate;
    private TabModelSelector mTabModelSelector;
    private TabModelSelectorTabModelObserver mTabModelObserver;
    private TabObserver mTabObserver;
    private final Map<Integer, TabFetchReadinessState> mObservedTabs = new HashMap<>();
    private boolean mFetchRequestedForCurrentTab = false;

    @Nullable
    private Tab mCurrentTab;

    /**
     * Construct a new {@link FetchHelper}.
     * @param delegate The {@link Delegate} used to fetch suggestions.
     * @param tabModelSelector The {@link TabModelSelector} for the containing Activity.
     */
    FetchHelper(Delegate delegate, TabModelSelector tabModelSelector) {
        mDelegate = delegate;
        init(tabModelSelector);
    }

    /**
     * Initializes the FetchHelper. Intended to encapsulate creating connections to native code,
     * so that this can be easily stubbed out during tests.
     */
    protected void init(TabModelSelector tabModelSelector) {
        mTabModelSelector = tabModelSelector;
        mTabObserver = new EmptyTabObserver() {
            @Override
            public void onUpdateUrl(Tab tab, String url) {
                assert !tab.isIncognito();
                if (tab == mCurrentTab) {
                    clearState();
                }
                getTabFetchReadinessState(tab).updateUrl(url);
            }

            @Override
            public void didFirstVisuallyNonEmptyPaint(Tab tab) {
                setTimeBaselineAndMaybeFetch(tab);
            }

            @Override
            public void onPageLoadFinished(Tab tab) {
                setTimeBaselineAndMaybeFetch(tab);
            }

            @Override
            public void onLoadStopped(Tab tab, boolean toDifferentDocument) {
                setTimeBaselineAndMaybeFetch(tab);
            }

            private void setTimeBaselineAndMaybeFetch(Tab tab) {
                assert !tab.isIncognito();
                if (getTabFetchReadinessState(tab).setFetchTimeBaselineMillis(
                            SystemClock.uptimeMillis())) {
                    maybeStartFetch(tab);
                }
            }
        };

        mTabModelObserver = new TabModelSelectorTabModelObserver(mTabModelSelector) {
            @Override
            public void didAddTab(Tab tab, TabLaunchType type) {
                startObservingTab(tab);
                if (maybeSetFetchReadinessBaseline(tab)) {
                    maybeStartFetch(tab);
                }
            }

            @Override
            public void didSelectTab(Tab tab, TabSelectionType type, int lastId) {
                if (tab == null) return;

                if (mCurrentTab != null && mCurrentTab != tab) {
                    clearState();
                }

                if (tab.isIncognito()) {
                    mCurrentTab = null;
                    return;
                }

                // Ensures that we start observing the tab, in case it was added to the tab model
                // before this class.
                startObservingTab(tab);
                mCurrentTab = tab;
                maybeStartFetch(tab);
            }

            @Override
            public void tabRemoved(Tab tab) {
                stopObservingTab(tab);
                if (tab == mCurrentTab) {
                    clearState();
                    mCurrentTab = null;
                }
            }
        };

        Tab currentTab = mTabModelSelector.getCurrentTab();
        if (currentTab == null) return;

        mTabModelObserver.didSelectTab(currentTab, TabSelectionType.FROM_USER, Tab.INVALID_TAB_ID);
        if (maybeSetFetchReadinessBaseline(mCurrentTab)) {
            maybeStartFetch(mCurrentTab);
        }
    }

    void destroy() {
        // Remove the observer from all tracked tabs.
        for (Integer tabId : mObservedTabs.keySet()) {
            Tab tab = mTabModelSelector.getTabById(tabId);
            if (tab == null) continue;
            tab.removeObserver(mTabObserver);
        }

        mObservedTabs.clear();
        mTabModelObserver.destroy();
    }

    /**
     * In case the tab is no longer loading the page, it would set the fetch readiness baselines
     * time.
     * @param tab Tab to be checked.
     * @return Whether the baseline time was set.
     */
    private boolean maybeSetFetchReadinessBaseline(final Tab tab) {
        if (isObservingTab(tab) && !tab.isLoading()) {
            return getTabFetchReadinessState(tab).setFetchTimeBaselineMillis(
                    SystemClock.uptimeMillis());
        }
        return false;
    }

    private void maybeStartFetch(Tab tab) {
        if (tab == null || tab != mCurrentTab) return;

        assert !tab.isIncognito();

        // Skip additional requests for current tab, until clearState is called.
        if (mFetchRequestedForCurrentTab) return;

        TabFetchReadinessState tabFetchReadinessState = getTabFetchReadinessState(mCurrentTab);

        // If we are not tracking a valid page, we can bail.
        if (!tabFetchReadinessState.isTrackingPage()) return;

        // Delay checks and calculations only make sense if the timer is running.
        if (!tabFetchReadinessState.isFetchTimeBaselineSet()) return;

        String url = tabFetchReadinessState.getUrl();
        long remainingFetchDelayMillis =
                SystemClock.uptimeMillis() - tabFetchReadinessState.getFetchTimeBaselineMillis();
        if (remainingFetchDelayMillis < MINIMUM_FETCH_DELAY_MILLIS) {
            postDelayedFetch(
                    url, mCurrentTab, MINIMUM_FETCH_DELAY_MILLIS - remainingFetchDelayMillis);
            return;
        }

        mFetchRequestedForCurrentTab = true;
        mDelegate.requestSuggestions(url);
    }

    private void postDelayedFetch(final String url, final Tab tab, long delayMillis) {
        mDelegate.reportFetchDelayed(tab.getWebContents());
        ThreadUtils.postOnUiThreadDelayed(new Runnable() {
            @Override
            public void run() {
                // Make sure that the tab is currently selected.
                if (tab != mCurrentTab) return;

                if (mFetchRequestedForCurrentTab) return;

                if (!isObservingTab(tab)) return;

                // URL in tab changed since the task was originally posted.
                if (!getTabFetchReadinessState(tab).isContextTheSame(url)) return;

                mFetchRequestedForCurrentTab = true;
                mDelegate.requestSuggestions(url);
            }
        }, delayMillis);
    }

    private void clearState() {
        mDelegate.clearState();
        mFetchRequestedForCurrentTab = false;
    }

    /**
     * Starts observing the tab.
     * @param tab The {@link Tab} to be observed.
     */
    private void startObservingTab(Tab tab) {
        if (tab != null && !isObservingTab(tab) && !tab.isIncognito()) {
            mObservedTabs.put(tab.getId(), new TabFetchReadinessState(tab.getUrl()));
            tab.addObserver(mTabObserver);
        }
    }

    /**
     * Stops observing the tab and removes its state.
     * @param tab The {@link Tab} that will no longer be observed.
     */
    private void stopObservingTab(Tab tab) {
        if (tab != null && isObservingTab(tab)) {
            mObservedTabs.remove(tab.getId());
            tab.removeObserver(mTabObserver);
        }
    }

    /** Whether the tab is currently observed. */
    @VisibleForTesting
    boolean isObservingTab(Tab tab) {
        return tab != null && mObservedTabs.containsKey(tab.getId());
    }

    private TabFetchReadinessState getTabFetchReadinessState(Tab tab) {
        if (tab == null) return null;
        return mObservedTabs.get(tab.getId());
    }
}

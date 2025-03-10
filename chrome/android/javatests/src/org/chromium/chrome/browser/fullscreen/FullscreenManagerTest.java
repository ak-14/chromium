// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.fullscreen;

// (http://crbug/642336)
// import static org.chromium.base.test.util.Restriction.RESTRICTION_TYPE_NON_LOW_END_DEVICE;

import android.graphics.Rect;
import android.graphics.Region;
import android.os.Build;
import android.os.SystemClock;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.LargeTest;
import android.support.test.filters.MediumTest;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.chromium.base.ThreadUtils;
import org.chromium.base.test.util.CallbackHelper;
import org.chromium.base.test.util.CommandLineFlags;
import org.chromium.base.test.util.DisabledTest;
import org.chromium.base.test.util.Feature;
import org.chromium.base.test.util.RetryOnFailure;
import org.chromium.base.test.util.UrlUtils;
import org.chromium.chrome.R;
import org.chromium.chrome.browser.ChromeFeatureList;
import org.chromium.chrome.browser.ChromeSwitches;
import org.chromium.chrome.browser.fullscreen.ChromeFullscreenManager.FullscreenListener;
import org.chromium.chrome.browser.omnibox.UrlBar;
import org.chromium.chrome.browser.tab.Tab;
import org.chromium.chrome.browser.tab.TabStateBrowserControlsVisibilityDelegate;
import org.chromium.chrome.browser.tab.TabWebContentsDelegateAndroid;
import org.chromium.chrome.test.ChromeJUnit4ClassRunner;
import org.chromium.chrome.test.ChromeTabbedActivityTestRule;
import org.chromium.chrome.test.util.FullscreenTestUtils;
import org.chromium.chrome.test.util.OmniboxTestUtils;
import org.chromium.chrome.test.util.PrerenderTestHelper;
import org.chromium.content.browser.test.util.Criteria;
import org.chromium.content.browser.test.util.CriteriaHelper;
import org.chromium.content.browser.test.util.JavaScriptUtils;
import org.chromium.content.browser.test.util.TestTouchUtils;
import org.chromium.content.browser.test.util.TouchCommon;
import org.chromium.content.browser.test.util.UiUtils;
import org.chromium.content_public.browser.RenderCoordinates;
import org.chromium.content_public.browser.SelectionPopupController;
import org.chromium.net.test.EmbeddedTestServer;

import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test suite for verifying the behavior of various fullscreen actions.
 */
@RunWith(ChromeJUnit4ClassRunner.class)
@CommandLineFlags.Add({
        ChromeSwitches.DISABLE_FIRST_RUN_EXPERIENCE,
        "disable-features=" + ChromeFeatureList.FULLSCREEN_ACTIVITY,
})
@RetryOnFailure
public class FullscreenManagerTest {
    @Rule
    public ChromeTabbedActivityTestRule mActivityTestRule = new ChromeTabbedActivityTestRule();

    private static final String LONG_HTML_WITH_AUTO_FOCUS_INPUT_TEST_PAGE =
            UrlUtils.encodeHtmlDataUri("<html>"
                    + "<body style='height:10000px;'>"
                    + "<p>The text input is focused automatically on load."
                    + " The browser controls should not hide when page is scrolled.</p><br/>"
                    + "<input id=\"input_text\" type=\"text\" autofocus/>"
                    + "</body>"
                    + "</html>");

    private static final String LONG_HTML_TEST_PAGE = UrlUtils.encodeHtmlDataUri(
            "<html><body style='height:10000px;'></body></html>");
    private static final String LONG_FULLSCREEN_API_HTML_TEST_PAGE = UrlUtils.encodeHtmlDataUri(
            "<html>"
            + "<head>"
            + "  <meta name=\"viewport\" "
            + "    content=\"width=device-width, initial-scale=1.0, maximum-scale=1.0\" />"
            + "  <script>"
            + "    function toggleFullScreen() {"
            + "      if (document.webkitIsFullScreen) {"
            + "        document.webkitCancelFullScreen();"
            + "      } else {"
            + "        document.body.webkitRequestFullScreen();"
            + "      }"
            + "    };"
            + "  </script>"
            + "  <style>"
            + "    body:-webkit-full-screen { background: red; width: 100%; }"
            + "  </style>"
            + "</head>"
            + "<body style='height:10000px;' onclick='toggleFullScreen();'>"
            + "</body>"
            + "</html>");

    @Before
    public void setUp() throws Exception {
        ThreadUtils.runOnUiThreadBlocking(new Runnable() {
            @Override
            public void run() {
                TabStateBrowserControlsVisibilityDelegate.disablePageLoadDelayForTests();
            }
        });
    }

    @Test
    @MediumTest
    @Feature({"Fullscreen"})
    public void testTogglePersistentFullscreen() throws InterruptedException {
        mActivityTestRule.startMainActivityWithURL(LONG_HTML_TEST_PAGE);

        Tab tab = mActivityTestRule.getActivity().getActivityTab();
        final TabWebContentsDelegateAndroid delegate = tab.getTabWebContentsDelegateAndroid();

        FullscreenTestUtils.waitForFullscreenFlag(tab, false, mActivityTestRule.getActivity());
        FullscreenTestUtils.waitForPersistentFullscreen(delegate, false);

        FullscreenTestUtils.togglePersistentFullscreenAndAssert(
                tab, true, mActivityTestRule.getActivity());

        FullscreenTestUtils.togglePersistentFullscreenAndAssert(
                tab, false, mActivityTestRule.getActivity());
    }

    @Test
    @LargeTest
    @Feature({"Fullscreen"})
    public void testPersistentFullscreenChangingUiFlags() throws InterruptedException {
        // Exiting fullscreen via UI Flags is not supported in versions prior to MR2.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) return;

        mActivityTestRule.startMainActivityWithURL(LONG_HTML_TEST_PAGE);

        final Tab tab = mActivityTestRule.getActivity().getActivityTab();
        final TabWebContentsDelegateAndroid delegate = tab.getTabWebContentsDelegateAndroid();

        FullscreenTestUtils.waitForFullscreenFlag(tab, false, mActivityTestRule.getActivity());
        FullscreenTestUtils.waitForPersistentFullscreen(delegate, false);

        FullscreenTestUtils.togglePersistentFullscreenAndAssert(
                tab, true, mActivityTestRule.getActivity());

        // There is a race condition in android when setting various system UI flags.
        // Adding this wait to allow the animation transitions to complete before continuing
        // the test (See https://b/10387660)
        UiUtils.settleDownUI(InstrumentationRegistry.getInstrumentation());

        ThreadUtils.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                View view = tab.getContentViewCore().getContainerView();
                view.setSystemUiVisibility(
                        view.getSystemUiVisibility() & ~View.SYSTEM_UI_FLAG_FULLSCREEN);
            }
        });
        FullscreenTestUtils.waitForFullscreenFlag(tab, true, mActivityTestRule.getActivity());
        FullscreenTestUtils.waitForPersistentFullscreen(delegate, true);
    }

    @Test
    @LargeTest
    @Feature({"Fullscreen"})
    public void testExitPersistentFullscreenAllowsManualFullscreen() throws InterruptedException {
        disableBrowserOverrides();
        mActivityTestRule.startMainActivityWithURL(LONG_FULLSCREEN_API_HTML_TEST_PAGE);

        ChromeFullscreenManager fullscreenManager =
                mActivityTestRule.getActivity().getFullscreenManager();
        int browserControlsHeight = fullscreenManager.getTopControlsHeight();

        Tab tab = mActivityTestRule.getActivity().getActivityTab();
        View view = tab.getView();
        final TabWebContentsDelegateAndroid delegate =
                tab.getTabWebContentsDelegateAndroid();

        TouchCommon.singleClickView(view);
        FullscreenTestUtils.waitForPersistentFullscreen(delegate, true);

        waitForBrowserControlsPosition(-browserControlsHeight);

        TestTouchUtils.sleepForDoubleTapTimeout(InstrumentationRegistry.getInstrumentation());
        TouchCommon.singleClickView(view);
        FullscreenTestUtils.waitForPersistentFullscreen(delegate, false);
        waitForBrowserControlsPosition(0);

        scrollBrowserControls(false);
        scrollBrowserControls(true);
    }

    @Test
    @LargeTest
    @Feature({"Fullscreen"})
    public void testManualHidingShowingBrowserControls() throws InterruptedException {
        disableBrowserOverrides();
        mActivityTestRule.startMainActivityWithURL(LONG_HTML_TEST_PAGE);

        final ChromeFullscreenManager fullscreenManager =
                mActivityTestRule.getActivity().getFullscreenManager();

        Assert.assertEquals(fullscreenManager.getTopControlOffset(), 0f, 0);

        waitForBrowserControlsToBeMoveable(mActivityTestRule.getActivity().getActivityTab());

        // Check that the URL bar has not grabbed focus (http://crbug/236365)
        UrlBar urlBar = (UrlBar) mActivityTestRule.getActivity().findViewById(R.id.url_bar);
        Assert.assertFalse("Url bar grabbed focus", urlBar.hasFocus());
    }

    @Test
    @LargeTest
    @Feature({"Fullscreen"})
    public void testHidingBrowserControlsRemovesSurfaceFlingerOverlay()
            throws InterruptedException {
        disableBrowserOverrides();
        mActivityTestRule.startMainActivityWithURL(LONG_HTML_TEST_PAGE);

        final ChromeFullscreenManager fullscreenManager =
                mActivityTestRule.getActivity().getFullscreenManager();

        Assert.assertEquals(fullscreenManager.getTopControlOffset(), 0f, 0);

        // Detect layouts. Note this doesn't actually need to be atomic (just final).
        final AtomicInteger layoutCount = new AtomicInteger();
        mActivityTestRule.getActivity()
                .getWindow()
                .getDecorView()
                .getViewTreeObserver()
                .addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener() {
                    @Override
                    public void onGlobalLayout() {
                        layoutCount.incrementAndGet();
                    }
                });

        // When the top-controls are removed, we need a layout to trigger the
        // transparent region for the app to be updated.
        scrollBrowserControls(false);
        CriteriaHelper.pollUiThread(
                new Criteria() {
                    @Override
                    public boolean isSatisfied() {
                        return layoutCount.get() > 0;
                    }
                });

        ThreadUtils.runOnUiThreadBlocking(new Runnable() {
            @Override
            public void run() {
                // Check that when the browser controls are gone, the entire decorView is contained
                // in the transparent region of the app.
                Rect visibleDisplayFrame = new Rect();
                Region transparentRegion = new Region();
                ViewGroup decorView =
                        (ViewGroup) mActivityTestRule.getActivity().getWindow().getDecorView();
                decorView.getWindowVisibleDisplayFrame(visibleDisplayFrame);
                decorView.gatherTransparentRegion(transparentRegion);
                Assert.assertTrue(transparentRegion.quickContains(visibleDisplayFrame));
            }
        });

        // Additional manual test that this is working:
        // - adb shell dumpsys SurfaceFlinger
        // - Observe that there is no 'Chrome' related overlay listed, only 'Surfaceview'.
    }

    @Test
    @LargeTest
    @Feature({"Fullscreen"})
    public void testManualFullscreenDisabledForChromePages() throws InterruptedException {
        disableBrowserOverrides();
        // The credits page was chosen as it is a chrome:// page that is long and would support
        // manual fullscreen if it were supported.
        mActivityTestRule.startMainActivityWithURL("chrome://credits");

        final ChromeFullscreenManager fullscreenManager =
                mActivityTestRule.getActivity().getFullscreenManager();
        int browserControlsHeight = fullscreenManager.getTopControlsHeight();

        Assert.assertEquals(fullscreenManager.getTopControlOffset(), 0f, 0);

        float dragX = 50f;
        float dragStartY = browserControlsHeight * 2;
        float dragFullY = dragStartY - browserControlsHeight;

        long downTime = SystemClock.uptimeMillis();
        TouchCommon.dragStart(mActivityTestRule.getActivity(), dragX, dragStartY, downTime);
        TouchCommon.dragTo(mActivityTestRule.getActivity(), dragX, dragX, dragStartY, dragFullY,
                100, downTime);
        waitForBrowserControlsPosition(0f);
        TouchCommon.dragEnd(mActivityTestRule.getActivity(), dragX, dragFullY, downTime);
        waitForBrowserControlsPosition(0f);
    }

    @Test
    @LargeTest
    @Feature({"Fullscreen"})
    public void testControlsShownOnUnresponsiveRenderer() throws InterruptedException {
        disableBrowserOverrides();
        mActivityTestRule.startMainActivityWithURL(LONG_HTML_TEST_PAGE);

        ChromeFullscreenManager fullscreenManager =
                mActivityTestRule.getActivity().getFullscreenManager();
        Assert.assertEquals(fullscreenManager.getTopControlOffset(), 0f, 0);

        scrollBrowserControls(false);

        Tab tab = mActivityTestRule.getActivity().getActivityTab();
        final TabWebContentsDelegateAndroid delegate =
                tab.getTabWebContentsDelegateAndroid();
        ThreadUtils.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                delegate.rendererUnresponsive();
            }
        });
        waitForBrowserControlsPosition(0f);

        ThreadUtils.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                delegate.rendererResponsive();
            }
        });

        // TODO(tedchoc): This is running into timing issues with the renderer offset logic.
        //waitForBrowserControlsToBeMoveable(getActivity().getActivityTab());
    }

    /*
    @LargeTest
    @Feature({"Fullscreen"})
    @Restriction(RESTRICTION_TYPE_NON_LOW_END_DEVICE)
    */
    @Test
    @DisabledTest(message = "crbug.com/642336")
    public void testPrerenderedPageSupportsManualHiding() throws InterruptedException {
        disableBrowserOverrides();
        mActivityTestRule.startMainActivityOnBlankPage();

        EmbeddedTestServer testServer =
                EmbeddedTestServer.createAndStartServer(InstrumentationRegistry.getContext());
        try {
            final Tab tab = mActivityTestRule.getActivity().getActivityTab();
            final String testUrl = testServer.getURL(
                    "/chrome/test/data/android/very_long_google.html");
            PrerenderTestHelper.prerenderUrl(testUrl, tab);
            Assert.assertTrue("loadUrl did not use pre-rendered page.",
                    PrerenderTestHelper.isLoadUrlResultPrerendered(
                            mActivityTestRule.loadUrl(testUrl)));

            UrlBar urlBar = (UrlBar) mActivityTestRule.getActivity().findViewById(R.id.url_bar);
            OmniboxTestUtils.toggleUrlBarFocus(urlBar, false);
            OmniboxTestUtils.waitForFocusAndKeyboardActive(urlBar, false);

            waitForBrowserControlsToBeMoveable(tab);
        } finally {
            testServer.stopAndDestroyServer();
        }
    }

    /* @LargeTest
     * @Feature({"Fullscreen"})
     */
    @Test
    @DisabledTest(message = "crbug.com/698413")
    public void testBrowserControlsShownWhenInputIsFocused()
            throws InterruptedException, TimeoutException {
        disableBrowserOverrides();
        mActivityTestRule.startMainActivityWithURL(LONG_HTML_WITH_AUTO_FOCUS_INPUT_TEST_PAGE);

        ChromeFullscreenManager fullscreenManager =
                mActivityTestRule.getActivity().getFullscreenManager();
        Assert.assertEquals(fullscreenManager.getTopControlOffset(), 0f, 0);

        int browserControlsHeight = fullscreenManager.getTopControlsHeight();
        float dragX = 50f;
        float dragStartY = browserControlsHeight * 3;
        float dragEndY = dragStartY - browserControlsHeight * 2;
        long downTime = SystemClock.uptimeMillis();
        TouchCommon.dragStart(mActivityTestRule.getActivity(), dragX, dragStartY, downTime);
        TouchCommon.dragTo(
                mActivityTestRule.getActivity(), dragX, dragX, dragStartY, dragEndY, 100, downTime);
        TouchCommon.dragEnd(mActivityTestRule.getActivity(), dragX, dragEndY, downTime);
        Assert.assertEquals(fullscreenManager.getTopControlOffset(), 0f, 0);

        Tab tab = mActivityTestRule.getActivity().getActivityTab();
        TouchCommon.singleClickView(tab.getView());
        JavaScriptUtils.executeJavaScriptAndWaitForResult(tab.getWebContents(),
                "document.getElementById('input_text').blur();");
        waitForEditableNodeToLoseFocus(tab);

        waitForBrowserControlsToBeMoveable(mActivityTestRule.getActivity().getActivityTab());
    }

    private void scrollBrowserControls(boolean show) {
        ChromeFullscreenManager fullscreenManager =
                mActivityTestRule.getActivity().getFullscreenManager();
        int browserControlsHeight = fullscreenManager.getTopControlsHeight();

        waitForPageToBeScrollable(mActivityTestRule.getActivity().getActivityTab());

        float dragX = 50f;
        // Use a larger scroll range than the height of the browser controls to ensure we overcome
        // the delay in a scroll start being sent.
        float dragStartY = browserControlsHeight * 3;
        float dragEndY = dragStartY - browserControlsHeight * 2;
        float expectedPosition = -browserControlsHeight;
        if (show) {
            expectedPosition = 0f;
            float tempDragStartY = dragStartY;
            dragStartY = dragEndY;
            dragEndY = tempDragStartY;
        }
        long downTime = SystemClock.uptimeMillis();
        TouchCommon.dragStart(mActivityTestRule.getActivity(), dragX, dragStartY, downTime);
        TouchCommon.dragTo(
                mActivityTestRule.getActivity(), dragX, dragX, dragStartY, dragEndY, 100, downTime);
        TouchCommon.dragEnd(mActivityTestRule.getActivity(), dragX, dragEndY, downTime);
        waitForBrowserControlsPosition(expectedPosition);
    }

    private void waitForBrowserControlsPosition(float position) {
        final ChromeFullscreenManager fullscreenManager =
                mActivityTestRule.getActivity().getFullscreenManager();
        CriteriaHelper.pollUiThread(Criteria.equals(position, new Callable<Float>() {
            @Override
            public Float call() {
                return fullscreenManager.getTopControlOffset();
            }
        }));
    }

    private void waitForPageToBeScrollable(final Tab tab) {
        CriteriaHelper.pollUiThread(new Criteria() {
            @Override
            public boolean isSatisfied() {
                return RenderCoordinates.fromWebContents(tab.getWebContents())
                               .getContentHeightPixInt()
                        > tab.getContentViewCore().getContainerView().getHeight();
            }
        });
    }

    /**
     * Waits for the browser controls to be moveable by user gesture.
     * <p>
     * This function requires the browser controls to start fully visible.  It till then ensure that
     * at some point the controls can be moved by user gesture.  It will then fully cycle the top
     * controls to entirely hidden and back to fully shown.
     */
    private void waitForBrowserControlsToBeMoveable(final Tab tab) throws InterruptedException {
        waitForBrowserControlsPosition(0f);

        final CallbackHelper contentMovedCallback = new CallbackHelper();
        final ChromeFullscreenManager fullscreenManager =
                mActivityTestRule.getActivity().getFullscreenManager();
        final float initialVisibleContentOffset = fullscreenManager.getTopVisibleContentOffset();

        fullscreenManager.addListener(new FullscreenListener() {
            @Override
            public void onControlsOffsetChanged(float topOffset, float bottomOffset,
                    boolean needsAnimate) {
                if (fullscreenManager.getTopVisibleContentOffset() != initialVisibleContentOffset) {
                    contentMovedCallback.notifyCalled();
                    fullscreenManager.removeListener(this);
                }
            }

            @Override
            public void onToggleOverlayVideoMode(boolean enabled) {
            }

            @Override
            public void onContentOffsetChanged(float offset) {
            }

            @Override
            public void onBottomControlsHeightChanged(int bottomControlsHeight) {
            }
        });

        float dragX = 50f;
        float dragStartY = tab.getView().getHeight() - 50f;

        for (int i = 0; i < 10; i++) {
            float dragEndY = dragStartY - fullscreenManager.getTopControlsHeight();

            long downTime = SystemClock.uptimeMillis();
            TouchCommon.dragStart(mActivityTestRule.getActivity(), dragX, dragStartY, downTime);
            TouchCommon.dragTo(mActivityTestRule.getActivity(), dragX, dragX, dragStartY, dragEndY,
                    100, downTime);
            TouchCommon.dragEnd(mActivityTestRule.getActivity(), dragX, dragEndY, downTime);

            try {
                contentMovedCallback.waitForCallback(0, 1, 500, TimeUnit.MILLISECONDS);

                scrollBrowserControls(false);
                scrollBrowserControls(true);

                return;
            } catch (TimeoutException e) {
                // Ignore and retry
            }
        }

        Assert.fail("Visible content never moved as expected.");
    }

    private void waitForEditableNodeToLoseFocus(final Tab tab) {
        CriteriaHelper.pollUiThread(new Criteria() {
            @Override
            public boolean isSatisfied() {
                SelectionPopupController controller =
                        SelectionPopupController.fromWebContents(tab.getWebContents());
                return !controller.isFocusedNodeEditable();
            }
        });
    }

    private void disableBrowserOverrides() {
        ThreadUtils.runOnUiThreadBlocking(new Runnable() {
            @Override
            public void run() {
                BrowserStateBrowserControlsVisibilityDelegate.disableForTesting();
            }
        });
    }
}

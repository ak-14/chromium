// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.content_public.browser;

import android.content.Context;
import android.content.res.Configuration;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;

import org.chromium.base.VisibleForTesting;
import org.chromium.content.browser.ContentViewCoreImpl;
import org.chromium.ui.base.ViewAndroidDelegate;
import org.chromium.ui.base.WindowAndroid;

/**
 * Provides a Java-side 'wrapper' around a WebContent (native) instance.
 * Contains all the major functionality necessary to manage the lifecycle of a ContentView without
 * being tied to the view system.
 *
 * WARNING: ContentViewCore is in the process of being broken up. Please do not add new stuff.
 * See https://crbug.com/598880.
 */
public interface ContentViewCore {
    /**
     * Create {@link ContentViewCore} object.
     * @param context The context used to create this object.
     * @param productVersion Product version for accessibility.
     * @param viewDelegate Delegate to add/remove anchor views.
     * @param internalDispatcher Handles dispatching all hidden or super methods to the
     *                           containerView.
     * @param webContents A WebContents instance to connect to.
     * @param windowAndroid An instance of the WindowAndroid.
     */
    public static ContentViewCore create(Context context, String productVersion,
            WebContents webContents, ViewAndroidDelegate viewDelegate,
            InternalAccessDelegate internalDispatcher, WindowAndroid windowAndroid) {
        return ContentViewCoreImpl.create(context, productVersion, webContents, viewDelegate,
                internalDispatcher, windowAndroid);
    }

    public static ContentViewCore fromWebContents(WebContents webContents) {
        return ContentViewCoreImpl.fromWebContents(webContents);
    }

    /**
     * Interface that consumers of {@link ContentViewCore} must implement to allow the proper
     * dispatching of view methods through the containing view.
     *
     * <p>
     * All methods with the "super_" prefix should be routed to the parent of the
     * implementing container view.
     */
    @SuppressWarnings("javadoc")
    public interface InternalAccessDelegate {
        /**
         * @see View#onKeyUp(keyCode, KeyEvent)
         */
        boolean super_onKeyUp(int keyCode, KeyEvent event);

        /**
         * @see View#dispatchKeyEvent(KeyEvent)
         */
        boolean super_dispatchKeyEvent(KeyEvent event);

        /**
         * @see View#onGenericMotionEvent(MotionEvent)
         */
        boolean super_onGenericMotionEvent(MotionEvent event);

        /**
         * @see View#onConfigurationChanged(Configuration)
         */
        void super_onConfigurationChanged(Configuration newConfig);

        /**
         * @see View#onScrollChanged(int, int, int, int)
         */
        void onScrollChanged(int lPix, int tPix, int oldlPix, int oldtPix);
    }

    /**
     * @return The ViewGroup that all view actions of this ContentViewCore should interact with.
     */
    ViewGroup getContainerView();

    /**
     * @return The WebContents currently being rendered.
     */
    WebContents getWebContents();

    /**
     * Updates the native {@link ContentViewCore} with a new window. This moves the NativeView and
     * attached it to the new NativeWindow linked with the given {@link WindowAndroid}.
     * @param windowAndroid The new {@link WindowAndroid} for this {@link ContentViewCore}.
     */
    void updateWindowAndroid(WindowAndroid windowAndroid);

    /**
     * Set the Container view Internals.
     * @param internalDispatcher Handles dispatching all hidden or super methods to the
     *                           containerView.
     */
    void setContainerViewInternals(InternalAccessDelegate internalDispatcher);

    /**
     * Destroy the internal state of the ContentView. This method may only be
     * called after the ContentView has been removed from the view system. No
     * other methods may be called on this ContentView after this method has
     * been called.
     * Warning: destroy() is not guranteed to be called in Android WebView.
     * Any object that relies solely on destroy() being called to be cleaned up
     * will leak in Android WebView. If appropriate, consider clean up in
     * onDetachedFromWindow() which is guaranteed to be called in Android WebView.
     */
    void destroy();

    /**
     * Returns true initially, false after destroy() has been called.
     * It is illegal to call any other method after destroy().
     */
    boolean isAlive();

    /**
     * @see View#onAttachedToWindow()
     */
    void onAttachedToWindow();

    /**
     * @see View#onDetachedFromWindow()
     */
    void onDetachedFromWindow();

    /**
     * @see View#onConfigurationChanged(Configuration)
     */
    void onConfigurationChanged(Configuration newConfig);

    /**
     * @see View#onGenericMotionEvent(MotionEvent)
     */
    boolean onGenericMotionEvent(MotionEvent event);

    /**
     * @see View#onKeyUp(int, KeyEvent)
     */
    boolean onKeyUp(int keyCode, KeyEvent event);

    /**
     * @see View#dispatchKeyEvent(KeyEvent)
     */
    boolean dispatchKeyEvent(KeyEvent event);

    /**
     * @see View#onWindowFocusChanged(boolean)
     */
    void onWindowFocusChanged(boolean hasWindowFocus);

    /**
     * @see View#scrollTo(int, int)
     */
    void scrollTo(float xPix, float yPix);

    /**
     * When the activity pauses, the content should lose focus.
     * TODO(mthiesse): See crbug.com/686232 for context. Desktop platforms use keyboard focus to
     * trigger blur/focus, and the equivalent to this on Android is Window focus. However, we don't
     * use Window focus because of the complexity around popups stealing Window focus.
     */
    void onPause();

    /**
     * When the activity resumes, the View#onFocusChanged may not be called, so we should restore
     * the View focus state.
     */
    void onResume();

    /**
     * Called when view-level focus for the container view has changed.
     * @param gainFocus {@code true} if the focus is gained, otherwise {@code false}.
     */
    void onViewFocusChanged(boolean gainFocus);

    /**
     * Sets whether the keyboard should be hidden when losing input focus.
     * @param hideKeyboardOnBlur {@code true} if we should hide soft keyboard when losing focus.
     */
    void setHideKeyboardOnBlur(boolean hideKeyboardOnBlur);

    /**
     * @see View#scrollBy(int, int)
     * Currently the ContentView scrolling happens in the native side. In
     * the Java view system, it is always pinned at (0, 0). scrollBy() and scrollTo()
     * are overridden, so that View's mScrollX and mScrollY will be unchanged at
     * (0, 0). This is critical for drawing ContentView correctly.
     */
    void scrollBy(float dxPix, float dyPix);

    /**
     * Enable or disable multi-touch zoom support.
     * @param supportsMultiTouchZoom {@code true} if the feature is enabled.
     */
    void updateMultiTouchZoomSupport(boolean supportsMultiTouchZoom);

    /**
     * Enable or disable double tap support.
     * @param supportsDoubleTap {@code true} if the feature is enabled.
     */
    void updateDoubleTapSupport(boolean supportsDoubleTap);

    // Test-only methods

    /**
     * @return The amount of the top controls height if controls are in the state
     *    of shrinking Blink's view size, otherwise 0.
     */
    @VisibleForTesting
    int getTopControlsShrinkBlinkHeightForTesting();

    /**
     * @return {@code true} if select popup is being shown.
     */
    @VisibleForTesting
    boolean isSelectPopupVisibleForTest();
}

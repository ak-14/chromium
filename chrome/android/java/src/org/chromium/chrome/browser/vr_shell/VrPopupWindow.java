// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.vr_shell;

import android.content.Context;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.MarginLayoutParams;
import android.widget.FrameLayout;
import android.widget.PopupWindow;

import org.chromium.ui.UiUtils;

/**
 * This class implements a VrPopupWindow which is similar to Android PopupWindow in VR.
 */
public class VrPopupWindow extends PopupWindow {
    private FrameLayout mVrPopupContainer;
    private VrDialogManager mVrDialogManager;
    private Context mContext;
    private boolean mIsShowing;
    private PopupWindow.OnDismissListener mOnDismissListener;

    public VrPopupWindow(Context context, VrDialogManager vrDialogManager) {
        super(context);
        mContext = context;
        mVrDialogManager = vrDialogManager;
    }

    @Override
    public void showAtLocation(View parent, int gravity, int x, int y) {
        View dialogView = getContentView();
        if (dialogView == null) return;
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                MarginLayoutParams.WRAP_CONTENT, MarginLayoutParams.WRAP_CONTENT, Gravity.CENTER);
        UiUtils.removeViewFromParent(dialogView);
        mVrPopupContainer = new FrameLayout(mContext);
        mVrPopupContainer.setLayoutParams(new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        mVrPopupContainer.setBackgroundDrawable(getBackground());
        mVrPopupContainer.addView(dialogView, params);
        mVrDialogManager.setDialogView(mVrPopupContainer);
        mVrDialogManager.initVrDialog(getWidth(), getHeight());
        mVrDialogManager.setDialogFloating();
        mVrDialogManager.setDialogLocation(x, y);
        mIsShowing = true;
    }

    @Override
    public void showAsDropDown(View anchor, int xoff, int yoff) {
        showAtLocation(anchor, Gravity.NO_GRAVITY, xoff, yoff);
    }

    @Override
    public boolean isShowing() {
        return mIsShowing;
    }

    @Override
    public void setOnDismissListener(PopupWindow.OnDismissListener onDismissListener) {
        mOnDismissListener = onDismissListener;
    }

    @Override
    public void dismiss() {
        if (!isShowing()) return;

        mVrDialogManager.setDialogView(null);
        mVrDialogManager.closeVrDialog();
        mVrPopupContainer = null;
        mIsShowing = false;
        if (mOnDismissListener != null) {
            mOnDismissListener.onDismiss();
        }
    }

    @Override
    public void update(int x, int y, int width, int height) {
        mVrDialogManager.setDialogLocation(x, y);
        mVrDialogManager.setDialogSize(width, height);
    }
}

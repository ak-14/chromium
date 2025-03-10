// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.download.ui;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.support.annotation.IntDef;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.text.format.Formatter;
import android.util.AttributeSet;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.chromium.base.ApiCompatibilityUtils;
import org.chromium.base.Callback;
import org.chromium.base.metrics.RecordHistogram;
import org.chromium.base.metrics.RecordUserAction;
import org.chromium.chrome.R;
import org.chromium.chrome.browser.download.DownloadUtils;
import org.chromium.chrome.browser.download.items.OfflineContentAggregatorFactory;
import org.chromium.chrome.browser.profiles.Profile;
import org.chromium.chrome.browser.util.FeatureUtilities;
import org.chromium.chrome.browser.util.ViewUtils;
import org.chromium.chrome.browser.widget.ListMenuButton;
import org.chromium.chrome.browser.widget.ListMenuButton.Item;
import org.chromium.chrome.browser.widget.MaterialProgressBar;
import org.chromium.chrome.browser.widget.ThumbnailProvider;
import org.chromium.chrome.browser.widget.TintedImageButton;
import org.chromium.chrome.browser.widget.selection.SelectableItemView;
import org.chromium.components.offline_items_collection.OfflineItem;
import org.chromium.components.offline_items_collection.OfflineItem.Progress;
import org.chromium.components.variations.VariationsAssociatedData;
import org.chromium.ui.UiUtils;

import java.util.List;

/**
 * The view for a downloaded item displayed in the Downloads list.
 */
public class DownloadItemView extends SelectableItemView<DownloadHistoryItemWrapper>
        implements ThumbnailProvider.ThumbnailRequest, ListMenuButton.Delegate {
    private static final String VARIATION_TRIAL_DOWNLOAD_HOME_MORE_BUTTON =
            "DownloadHomeMoreButton";
    private static final String VARIATION_PARAM_SHOW_MORE_BUTTON = "show_more_button";

    // Please treat this list as append only and keep it in sync with
    // Android.DownloadManager.List.View.Actions in enums.xml.
    @IntDef({VIEW_ACTION_OPEN, VIEW_ACTION_RESUME, VIEW_ACTION_PAUSE, VIEW_ACTION_CANCEL,
            VIEW_ACTION_MENU_SHARE, VIEW_ACTION_MENU_DELETE})
    public @interface ViewAction {}

    private static final int VIEW_ACTION_OPEN = 0;
    private static final int VIEW_ACTION_RESUME = 1;
    private static final int VIEW_ACTION_PAUSE = 2;
    private static final int VIEW_ACTION_CANCEL = 3;
    private static final int VIEW_ACTION_MENU_SHARE = 4;
    private static final int VIEW_ACTION_MENU_DELETE = 5;
    private static final int VIEW_ACTION_BOUNDARY = 6;

    /**
     * Set based on Chrome Variations to determine whether or not to show the "more" menu button on
     * this item.  This will be set only once the first time it is queried through
     * {@link #isMoreButtonEnabled()} and will not be set again for the current process lifetime to
     * avoid hitting the Chrome Variations system for each list item.
     */
    private static Boolean sMoreButtonEnabled;

    private final int mMargin;
    private final int mMarginSubsection;
    private final int mIconBackgroundColor;
    private final int mIconBackgroundColorSelected;
    private final ColorStateList mIconForegroundColorList;
    private final ColorStateList mCheckedIconForegroundColorList;
    private final int mIconBackgroundResId;

    private DownloadHistoryItemWrapper mItem;
    private int mIconResId;
    private int mIconSize;
    private Bitmap mThumbnailBitmap;

    // Controls common to completed and in-progress downloads.
    private LinearLayout mLayoutContainer;

    // Controls for completed downloads.
    private View mLayoutCompleted;
    private TextView mFilenameCompletedView;
    private TextView mDescriptionCompletedView;
    private ListMenuButton mMoreButton;

    // Controls for in-progress downloads.
    private View mLayoutInProgress;
    private TextView mFilenameInProgressView;
    private TextView mDownloadStatusView;
    private TextView mDownloadPercentageView;
    private MaterialProgressBar mProgressView;
    private TintedImageButton mPauseResumeButton;
    private View mCancelButton;

    /**
     * Constructor for inflating from XML.
     */
    public DownloadItemView(Context context, AttributeSet attrs) {
        super(context, attrs);
        mMargin = context.getResources().getDimensionPixelSize(R.dimen.list_item_default_margin);
        mMarginSubsection =
                context.getResources().getDimensionPixelSize(R.dimen.list_item_subsection_margin);
        mIconBackgroundColor = DownloadUtils.getIconBackgroundColor(context);
        mIconBackgroundColorSelected =
                ApiCompatibilityUtils.getColor(context.getResources(), R.color.google_grey_600);
        mIconSize = getResources().getDimensionPixelSize(R.dimen.list_item_start_icon_width);
        mCheckedIconForegroundColorList = DownloadUtils.getIconForegroundColorList(context);

        mIconBackgroundResId = R.drawable.list_item_icon_modern_bg;

        if (FeatureUtilities.isChromeModernDesignEnabled()) {
            mIconForegroundColorList = ApiCompatibilityUtils.getColorStateList(
                    context.getResources(), R.color.dark_mode_tint);
        } else {
            mIconForegroundColorList = DownloadUtils.getIconForegroundColorList(context);
        }
    }

    // ListMenuButton.Delegate implementation.
    @Override
    public Item[] getItems() {
        return new Item[] {new Item(getContext(), R.string.share, true),
                new Item(getContext(), R.string.delete, true)};
    }

    @Override
    public void onItemSelected(Item item) {
        if (item.getTextId() == R.string.share) {
            recordViewActionHistogram(VIEW_ACTION_MENU_SHARE);
            mItem.share();
        } else if (item.getTextId() == R.string.delete) {
            recordViewActionHistogram(VIEW_ACTION_MENU_DELETE);
            mItem.startRemove();
            RecordUserAction.record("Android.DownloadManager.RemoveItem");
        }
    }

    @Override
    protected void onFinishInflate() {
        super.onFinishInflate();
        mProgressView = (MaterialProgressBar) findViewById(R.id.download_progress_view);

        mLayoutContainer = (LinearLayout) findViewById(R.id.layout_container);
        mLayoutCompleted = findViewById(R.id.completed_layout);
        mLayoutInProgress = findViewById(R.id.progress_layout);

        mFilenameCompletedView = (TextView) findViewById(R.id.filename_completed_view);
        mDescriptionCompletedView = (TextView) findViewById(R.id.description_view);
        mMoreButton = (ListMenuButton) findViewById(R.id.more);

        mFilenameInProgressView = (TextView) findViewById(R.id.filename_progress_view);
        mDownloadStatusView = (TextView) findViewById(R.id.status_view);
        mDownloadPercentageView = (TextView) findViewById(R.id.percentage_view);

        mPauseResumeButton = (TintedImageButton) findViewById(R.id.pause_button);
        mCancelButton = findViewById(R.id.cancel_button);

        mMoreButton.setDelegate(this);
        mPauseResumeButton.setOnClickListener(view -> {
            if (mItem.isPaused()) {
                recordViewActionHistogram(VIEW_ACTION_RESUME);
                mItem.resume();
            } else if (!mItem.isComplete()) {
                recordViewActionHistogram(VIEW_ACTION_PAUSE);
                mItem.pause();
            }
        });
        mCancelButton.setOnClickListener(view -> {
            recordViewActionHistogram(VIEW_ACTION_CANCEL);
            mItem.cancel();
        });
    }

    @Override
    public @Nullable String getFilePath() {
        return mItem == null ? null : mItem.getFilePath();
    }

    @Override
    public @Nullable String getContentId() {
        return mItem == null ? "" : mItem.getId();
    }

    @Override
    public void onThumbnailRetrieved(@NonNull String contentId, @Nullable Bitmap thumbnail) {
        if (TextUtils.equals(getContentId(), contentId) && thumbnail != null
                && thumbnail.getWidth() > 0 && thumbnail.getHeight() > 0) {
            assert !thumbnail.isRecycled();
            setThumbnailBitmap(thumbnail);
        }
    }

    @Override
    public boolean getThumbnail(Callback<Bitmap> callback) {
        if (!mItem.isOfflinePage()) return false;
        OfflineContentAggregatorFactory.forProfile(Profile.getLastUsedProfile())
                .getVisualsForItem(((OfflineItem) mItem.getItem()).id, (id, visuals) -> {
                    if (visuals == null) {
                        callback.onResult(null);
                    } else {
                        callback.onResult(Bitmap.createScaledBitmap(
                                visuals.icon, mIconSize, mIconSize, false));
                    }
                });
        return true;
    }

    @Override
    public int getIconSize() {
        return mIconSize;
    }

    /**
     * Initialize the DownloadItemView. Must be called before the item can respond to click events.
     *
     * @param provider The BackendProvider that allows interacting with the data backends.
     * @param item     The item represented by this DownloadItemView.
     */
    public void displayItem(BackendProvider provider, DownloadHistoryItemWrapper item) {
        mItem = item;
        setItem(item);

        ApiCompatibilityUtils.setMarginStart(
                (MarginLayoutParams) mLayoutContainer.getLayoutParams(),
                item.isSuggested() ? mMarginSubsection : mMargin);

        // Cancel any previous thumbnail request for the previously displayed item.
        ThumbnailProvider thumbnailProvider = provider.getThumbnailProvider();
        thumbnailProvider.cancelRetrieval(this);

        int fileType = item.getFilterType();

        // Pick what icon to display for the item.
        mIconResId = DownloadUtils.getIconResId(fileType, DownloadUtils.ICON_SIZE_24_DP);

        // Request a thumbnail for the file to be sent to the ThumbnailCallback. This will happen
        // immediately if the thumbnail is cached or asynchronously if it has to be fetched from a
        // remote source.
        mThumbnailBitmap = null;
        if (item.isOfflinePage()
                || (fileType == DownloadFilter.FILTER_IMAGE && item.isComplete())) {
            thumbnailProvider.getThumbnail(this);
        } else {
            // TODO(dfalcantara): Get thumbnails for audio and video files when possible.
        }

        if (mThumbnailBitmap == null) updateIconView();

        Context context = mDescriptionCompletedView.getContext();
        mFilenameCompletedView.setText(item.getDisplayFileName());
        mFilenameInProgressView.setText(item.getDisplayFileName());

        String description = context.getString(R.string.download_manager_list_item_description,
                Formatter.formatFileSize(getContext(), item.getFileSize()),
                item.getDisplayHostname());
        mDescriptionCompletedView.setText(description);

        if (item.isComplete()) {
            showLayout(mLayoutCompleted);

            // To ensure that text views have correct width after recycling, we have to request
            // re-layout.
            mFilenameCompletedView.requestLayout();
        } else {
            showLayout(mLayoutInProgress);
            mDownloadStatusView.setText(item.getStatusString());

            Progress progress = item.getDownloadProgress();

            if (item.isPaused()) {
                mPauseResumeButton.setImageResource(R.drawable.ic_play_arrow_white_24dp);
                mPauseResumeButton.setContentDescription(
                        getContext().getString(R.string.download_notification_resume_button));
            } else {
                mPauseResumeButton.setImageResource(R.drawable.ic_pause_white_24dp);
                mPauseResumeButton.setContentDescription(
                        getContext().getString(R.string.download_notification_pause_button));
            }

            if (item.isPaused() || item.isPending()) {
                mProgressView.setIndeterminate(false);
            } else {
                mProgressView.setIndeterminate(progress.isIndeterminate());
            }

            if (!progress.isIndeterminate()) {
                mProgressView.setProgress(progress.getPercentage());
            }

            // Display the percentage downloaded in text form.
            // To avoid problems with RelativeLayout not knowing how to place views relative to
            // removed views in the hierarchy, this code instead makes the percentage View's width
            // to 0 by removing its text and eliminating the margin.
            if (progress.isIndeterminate()) {
                mDownloadPercentageView.setText(null);
                ApiCompatibilityUtils.setMarginEnd(
                        (MarginLayoutParams) mDownloadPercentageView.getLayoutParams(), 0);
            } else {
                mDownloadPercentageView.setText(
                        DownloadUtils.getPercentageString(progress.getPercentage()));
                ApiCompatibilityUtils.setMarginEnd(
                        (MarginLayoutParams) mDownloadPercentageView.getLayoutParams(), mMargin);
            }
        }

        mMoreButton.setContentDescriptionContext(item.getDisplayFileName());
        boolean canShowMore = item.isComplete() && isMoreButtonEnabled();
        mMoreButton.setVisibility(canShowMore ? View.VISIBLE : View.GONE);

        setLongClickable(item.isComplete());
    }

    private void setThumbnailBitmap(Bitmap thumbnail) {
        mThumbnailBitmap = thumbnail;
        updateIconView();
    }

    @Override
    public void onSelectionStateChange(List<DownloadHistoryItemWrapper> selectedItems) {
        super.onSelectionStateChange(selectedItems);
        mMoreButton.setClickable(mItem.isInteractive());
    }

    @Override
    public void onClick() {
        if (mItem != null && mItem.isComplete()) {
            recordViewActionHistogram(VIEW_ACTION_OPEN);
            mItem.open();
        }
    }

    @Override
    public boolean onLongClick(View view) {
        if (mItem != null && mItem.isComplete()) {
            return super.onLongClick(view);
        } else {
            return true;
        }
    }

    @Override
    protected void updateIconView() {
        if (isChecked()) {
            if (FeatureUtilities.isChromeModernDesignEnabled()) {
                mIconView.setBackgroundResource(mIconBackgroundResId);
                mIconView.getBackground().setLevel(
                        getResources().getInteger(R.integer.list_item_level_selected));
            } else {
                mIconView.setBackgroundColor(mIconBackgroundColorSelected);
            }
            mIconView.setImageDrawable(mCheckDrawable);
            mIconView.setTint(mCheckedIconForegroundColorList);
            mCheckDrawable.start();
        } else if (mThumbnailBitmap != null) {
            assert !mThumbnailBitmap.isRecycled();
            mIconView.setBackground(null);
            if (FeatureUtilities.isChromeModernDesignEnabled()) {
                mIconView.setImageDrawable(ViewUtils.createRoundedBitmapDrawable(
                        Bitmap.createScaledBitmap(mThumbnailBitmap, mIconSize, mIconSize, false),
                        getResources().getDimensionPixelSize(
                                R.dimen.list_item_start_icon_corner_radius)));
            } else {
                mIconView.setImageBitmap(mThumbnailBitmap);
            }
            mIconView.setTint(null);
        } else {
            if (FeatureUtilities.isChromeModernDesignEnabled()) {
                mIconView.setBackgroundResource(mIconBackgroundResId);
                mIconView.getBackground().setLevel(
                        getResources().getInteger(R.integer.list_item_level_default));
            } else {
                mIconView.setBackgroundColor(mIconBackgroundColor);
            }
            mIconView.setImageResource(mIconResId);
            mIconView.setTint(mIconForegroundColorList);
        }
    }

    private void showLayout(View layoutToShow) {
        if (mLayoutCompleted != layoutToShow) UiUtils.removeViewFromParent(mLayoutCompleted);
        if (mLayoutInProgress != layoutToShow) UiUtils.removeViewFromParent(mLayoutInProgress);

        if (layoutToShow.getParent() == null) {
            LinearLayout.LayoutParams params =
                    new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT);
            params.weight = 1;
            mLayoutContainer.addView(layoutToShow, params);

            // Move the menu button to the back of mLayoutContainer.
            mLayoutContainer.removeView(mMoreButton);
            mLayoutContainer.addView(mMoreButton);
        }
    }

    private static void recordViewActionHistogram(@ViewAction int action) {
        RecordHistogram.recordEnumeratedHistogram(
                "Android.DownloadManager.List.View.Action", action, VIEW_ACTION_BOUNDARY);
    }

    /**
     * Uses Chrome Variations to determine whether or not to show the "more" menu button.  This
     * value will be queried the first time this method is run and cached for future calls.  The
     * default value will be {@code true} if no Chrome Variation is found for this value.
     * @return Whether or not the "more" menu button should be shown.
     */
    private static boolean isMoreButtonEnabled() {
        if (sMoreButtonEnabled == null) {
            // Default the more button to true.  Any invalid non-empty value will set the result to
            // false though.
            sMoreButtonEnabled = true;

            String variationResult = VariationsAssociatedData.getVariationParamValue(
                    VARIATION_TRIAL_DOWNLOAD_HOME_MORE_BUTTON, VARIATION_PARAM_SHOW_MORE_BUTTON);
            if (!TextUtils.isEmpty(variationResult)) {
                sMoreButtonEnabled = Boolean.parseBoolean(variationResult);
            }
        }

        return sMoreButtonEnabled;
    }
}

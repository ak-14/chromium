// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chromecast.shell;

import android.app.Notification;
import android.app.Service;
import android.content.Intent;
import android.media.AudioManager;
import android.os.IBinder;
import android.widget.Toast;

import org.chromium.base.Log;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.chromecast.base.Both;
import org.chromium.chromecast.base.Controller;
import org.chromium.chromecast.base.Observable;
import org.chromium.chromecast.base.Unit;
import org.chromium.content_public.browser.WebContents;

/**
 * Service for "displaying" a WebContents in CastShell.
 * <p>
 * Typically, this class is controlled by CastContentWindowAndroid, which will
 * bind to this service.
 */
@JNINamespace("chromecast::shell")
public class CastWebContentsService extends Service {
    private static final String TAG = "cr_CastWebService";
    private static final boolean DEBUG = true;
    private static final int CAST_NOTIFICATION_ID = 100;

    private final Controller<Unit> mLifetimeController = new Controller<>();
    private final Controller<WebContents> mWebContentsState = new Controller<>();
    private String mInstanceId;
    private CastAudioManager mAudioManager;

    {
        // Construct an Observable that is deactivated when either mWebContentsState or
        // mLifetimeController is reset, and has the activation data of mWebContentsState.
        Observable<WebContents> hasWebContentsState =
                mWebContentsState.and(mLifetimeController).map(Both::getFirst);
        // React to web contents by presenting them in a headless view.
        hasWebContentsState.watch(CastWebContentsView.withoutLayout(this));
        hasWebContentsState.watch(() -> {
            if (DEBUG) Log.d(TAG, "show web contents");
            // TODO(thoren): Notification.Builder(Context) is deprecated in O. Use the
            // (Context, String) constructor when CastWebContentsService starts supporting O.
            Notification notification = new Notification.Builder(this).build();
            startForeground(CAST_NOTIFICATION_ID, notification);
            return () -> {
                if (DEBUG) Log.d(TAG, "detach web contents");
                stopForeground(true /*removeNotification*/);
                // Inform CastContentWindowAndroid we're detaching.
                CastWebContentsComponent.onComponentClosed(mInstanceId);
            };
        });
    }

    protected void handleIntent(Intent intent) {
        intent.setExtrasClassLoader(WebContents.class.getClassLoader());
        mInstanceId = intent.getData().getPath();

        WebContents webContents = CastWebContentsIntentUtils.getWebContents(intent);
        if (webContents == null) {
            Log.e(TAG, "Received null WebContents in intent.");
            return;
        }

        mWebContentsState.set(webContents);
    }

    @Override
    public void onDestroy() {
        if (DEBUG) Log.d(TAG, "onDestroy");

        mLifetimeController.reset();
        super.onDestroy();
    }

    @Override
    public void onCreate() {
        if (DEBUG) Log.d(TAG, "onCreate");
        if (!CastBrowserHelper.initializeBrowser(getApplicationContext())) {
            Toast.makeText(this, R.string.browser_process_initialization_failed, Toast.LENGTH_SHORT)
                    .show();
            stopSelf();
        }
        CastAudioManager.getAudioManager(this).requestAudioFocusWhen(
                mLifetimeController, AudioManager.STREAM_MUSIC, AudioManager.AUDIOFOCUS_GAIN);
        mLifetimeController.set(Unit.unit());
    }

    @Override
    public IBinder onBind(Intent intent) {
        if (DEBUG) Log.d(TAG, "onBind");
        handleIntent(intent);
        return null;
    }
}

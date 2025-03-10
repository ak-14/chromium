// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview
 * 'settings-reset-page' is the settings page containing reset
 * settings.
 *
 * Example:
 *
 *    <iron-animated-pages>
 *      <settings-reset-page prefs="{{prefs}}">
 *      </settings-reset-page>
 *      ... other pages ...
 *    </iron-animated-pages>
 */
Polymer({
  is: 'settings-reset-page',

  behaviors: [settings.RouteObserverBehavior],

  properties: {
    // <if expr="chromeos">
    /** @private */
    showPowerwashDialog_: Boolean,
    // </if>

    /** @private */
    allowPowerwash_: {
      type: Boolean,
      value: cr.isChromeOS ? loadTimeData.getBoolean('allowPowerwash') : false
    },

    // <if expr="_google_chrome and is_win">
    /** @private */
    showIncompatibleApplications_: {
      type: Boolean,
      value: function() {
        return loadTimeData.getBoolean('showIncompatibleApplications');
      },
    },
    // </if>
  },

  /**
   * settings.RouteObserverBehavior
   * @param {!settings.Route} route
   * @protected
   */
  currentRouteChanged: function(route) {
    const lazyRender =
        /** @type {!CrLazyRenderElement} */ (this.$.resetProfileDialog);

    if (route == settings.routes.TRIGGERED_RESET_DIALOG ||
        route == settings.routes.RESET_DIALOG) {
      /** @type {!SettingsResetProfileDialogElement} */ (lazyRender.get())
          .show();
    } else {
      const dialog = /** @type {?SettingsResetProfileDialogElement} */ (
          lazyRender.getIfExists());
      if (dialog)
        dialog.cancel();
    }
  },

  /** @private */
  onShowResetProfileDialog_: function() {
    settings.navigateTo(
        settings.routes.RESET_DIALOG, new URLSearchParams('origin=userclick'));
  },

  /** @private */
  onResetProfileDialogClose_: function() {
    settings.navigateToPreviousRoute();
    cr.ui.focusWithoutInk(assert(this.$.resetProfileArrow));
  },

  // <if expr="chromeos">
  /**
   * @param {!Event} e
   * @private
   */
  onShowPowerwashDialog_: function(e) {
    e.preventDefault();
    this.showPowerwashDialog_ = true;
  },

  /** @private */
  onPowerwashDialogClose_: function() {
    this.showPowerwashDialog_ = false;
    cr.ui.focusWithoutInk(assert(this.$.powerwashArrow));
  },
  // </if>

  // <if expr="_google_chrome and is_win">
  /** @private */
  onChromeCleanupTap_: function() {
    settings.navigateTo(settings.routes.CHROME_CLEANUP);
  },

  /** @private */
  onIncompatibleApplicationsTap_: function() {
    settings.navigateTo(settings.routes.INCOMPATIBLE_APPLICATIONS);
  },
  // </if>

});

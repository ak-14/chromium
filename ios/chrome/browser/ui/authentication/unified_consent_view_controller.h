// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IOS_CHROME_BROWSER_UI_AUTHENTICATION_UNIFIED_CONSENT_VIEW_CONTROLLER_H_
#define IOS_CHROME_BROWSER_UI_AUTHENTICATION_UNIFIED_CONSENT_VIEW_CONTROLLER_H_

#import <UIKit/UIKit.h>

#include <vector>

@class ChromeIdentity;
@class UnifiedConsentViewController;

// Delegate protocol for UnityConsentViewController.
@protocol UnifiedConsentViewControllerDelegate<NSObject>

// Called when the user taps on the settings link.
- (void)unifiedConsentViewControllerDidTapSettingsLink:
    (UnifiedConsentViewController*)controller;

// Called when the user taps on the IdentityPickerView.
- (void)unifiedConsentViewControllerDidTapIdentityPickerView:
    (UnifiedConsentViewController*)controller;

@end

// UnityConsentViewController is a sub view controller to ask for the user
// consent before the user can sign-in.
// All the string ids displayed by the view are available with
// |consentStringIds| and |openSettingsStringId|. Those can be used to record
// the consent agreed by the user.
@interface UnifiedConsentViewController : UIViewController

@property(nonatomic, weak) id<UnifiedConsentViewControllerDelegate> delegate;
// String id for text to open the settings (related to record the user consent).
@property(nonatomic, readonly) int openSettingsStringId;

// -[UnifiedConsentViewController init] should be used.
- (instancetype)initWithNibName:(NSString*)nibNameOrNil
                         bundle:(NSBundle*)nibBundleOrNil NS_UNAVAILABLE;
- (instancetype)initWithCoder:(NSCoder*)aDecoder NS_UNAVAILABLE;

// List of string ids used for the user consent. The string ids order matches
// the way they appear on the screen.
- (const std::vector<int>&)consentStringIds;

// Shows (if hidden) and updates the IdentityPickerView.
- (void)updateIdentityPickerViewWithUserFullName:(NSString*)fullName
                                           email:(NSString*)email;

// Updates the IdentityPickerView avatar.
- (void)updateIdentityPickerViewWithAvatar:(UIImage*)avatar;

// Hides the IdentityPickerView.
- (void)hideIdentityPickerView;

@end

#endif  // IOS_CHROME_BROWSER_UI_AUTHENTICATION_UNIFIED_CONSENT_VIEW_CONTROLLER_H_

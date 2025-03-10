// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IOS_WEB_VIEW_INTERNAL_AUTOFILL_CWV_AUTOFILL_CLIENT_IOS_BRIDGE_H_
#define IOS_WEB_VIEW_INTERNAL_AUTOFILL_CWV_AUTOFILL_CLIENT_IOS_BRIDGE_H_

#import "components/autofill/ios/browser/autofill_client_ios_bridge.h"

#include "base/callback.h"

namespace autofill {
class CreditCard;
}  // namespace autofill

// WebView extension of AutofillClientIOSBridge.
@protocol CWVAutofillClientIOSBridge<AutofillClientIOSBridge>

// Bridge for AutofillClient's method |ConfirmSaveCreditCardLocally|.
- (void)confirmSaveCreditCardLocally:(const autofill::CreditCard&)creditCard
                            callback:(const base::RepeatingClosure&)callback;

@end

#endif  // IOS_WEB_VIEW_INTERNAL_AUTOFILL_CWV_AUTOFILL_CLIENT_IOS_BRIDGE_H_

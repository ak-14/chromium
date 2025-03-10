// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_SAFE_BROWSING_FEATURES_H_
#define COMPONENTS_SAFE_BROWSING_FEATURES_H_

#include <stddef.h>
#include <algorithm>
#include <utility>
#include <vector>

#include "base/feature_list.h"
#include "base/macros.h"
#include "base/values.h"
namespace base {
class ListValue;
}  // namespace base

namespace safe_browsing {
// Features list
extern const base::Feature kAdSamplerCollectButDontSendFeature;
extern const base::Feature kAdSamplerTriggerFeature;
extern const base::Feature kCheckByURLLoaderThrottle;
// Gates logging of GaiaPasswordReuse user events.
extern const base::Feature kGaiaPasswordReuseReporting;
extern const base::Feature kGoogleBrandedPhishingWarning;

// Specifies which non-resource HTML Elements to collect based on their tag and
// attributes. It's a single param containing a comma-separated list of pairs.
// For example: "tag1,id,tag1,height,tag2,foo" - this will collect elements with
// tag "tag1" that have attribute "id" or "height" set, and elements of tag
// "tag2" if they have attribute "foo" set. All tag names and attributes should
// be lower case.
extern const base::Feature kThreatDomDetailsTagAndAttributeFeature;

// Controls the daily quota for data collection triggers. It's a single param
// containing a comma-separated list of pairs. The format of the param is
// "T1,Q1,T2,Q2,...Tn,Qn", where Tx is a TriggerType and Qx is how many reports
// that trigger is allowed to send per day.
extern const base::Feature kTriggerThrottlerDailyQuotaFeature;

// Controls whether to dispatch the SafetyNet check on a worker thread. Android
// only.
extern const base::Feature kDispatchSafetyNetCheckOffThread;

// Controls whether to add recent navigation events to referrer chain for SBER
// users if referrer chain is incomplete.
extern const base::Feature kAppendRecentNavigationEvents;

// Controls whether .rar files downloaded by the user are inspected for being
// unsafe.
extern const base::Feature kInspectDownloadedRarFiles;

// Controls the Password Protection for Enterprise V1 feature;
extern const base::Feature kEnterprisePasswordProtectionV1;

// Forces the chrome://reset-password page to be shown for review or testing
// purpose.
extern const base::Feature kForceEnableResetPasswordWebUI;

base::ListValue GetFeatureStatusList();

}  // namespace safe_browsing
#endif  // COMPONENTS_SAFE_BROWSING_FEATURES_H_

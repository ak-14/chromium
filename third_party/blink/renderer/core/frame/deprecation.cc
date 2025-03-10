// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/deprecation.h"

#include "services/service_manager/public/cpp/connector.h"
#include "third_party/blink/public/mojom/feature_policy/feature_policy.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/reporting.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/deprecation_report.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/report.h"
#include "third_party/blink/renderer/core/frame/reporting_context.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/workers/worker_or_worklet_global_scope.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

using blink::WebFeature;

namespace {

const char kChromeLoadTimesNavigationTiming[] =
    "chrome.loadTimes() is deprecated, instead use standardized API: "
    "Navigation Timing 2. "
    "https://www.chromestatus.com/features/5637885046816768.";
const char kChromeLoadTimesNextHopProtocol[] =
    "chrome.loadTimes() is deprecated, instead use standardized API: "
    "nextHopProtocol in Navigation Timing 2. "
    "https://www.chromestatus.com/features/5637885046816768.";

const char kChromeLoadTimesPaintTiming[] =
    "chrome.loadTimes() is deprecated, instead use standardized API: "
    "Paint Timing. "
    "https://www.chromestatus.com/features/5637885046816768.";

enum Milestone {
  kUnknown,
  kM60,
  kM61,
  kM62,
  kM63,
  kM64,
  kM65,
  kM66,
  kM67,
  kM68,
  kM69,
  kM70,
  kM71,
};

// Returns estimated milestone dates as human-readable strings.
const char* MilestoneString(Milestone milestone) {
  // These are the Estimated Stable Dates:
  // https://www.chromium.org/developers/calendar

  switch (milestone) {
    case kUnknown:
      return "";
    case kM60:
      return "M60, around August 2017";
    case kM61:
      return "M61, around September 2017";
    case kM62:
      return "M62, around October 2017";
    case kM63:
      return "M63, around December 2017";
    case kM64:
      return "M64, around January 2018";
    case kM65:
      return "M65, around March 2018";
    case kM66:
      return "M66, around April 2018";
    case kM67:
      return "M67, around May 2018";
    case kM68:
      return "M68, around July 2018";
    case kM69:
      return "M69, around September 2018";
    case kM70:
      return "M70, around October 2018";
    case kM71:
      return "M71, around December 2018";
  }

  NOTREACHED();
  return nullptr;
}

// Returns estimated milestone dates as milliseconds since January 1, 1970.
double MilestoneDate(Milestone milestone) {
  // These are the Estimated Stable Dates:
  // https://www.chromium.org/developers/calendar

  switch (milestone) {
    case kUnknown:
      return 0;
    case kM60:
      return 1500955200000;  // July 25, 2017.
    case kM61:
      return 1504584000000;  // September 5, 2017.
    case kM62:
      return 1508212800000;  // October 17, 2017.
    case kM63:
      return 1512450000000;  // December 5, 2017.
    case kM64:
      return 1516683600000;  // January 23, 2018.
    case kM65:
      return 1520312400000;  // March 6, 2018.
    case kM66:
      return 1523937600000;  // April 17, 2018.
    case kM67:
      return 1527566400000;  // May 29, 2018.
    case kM68:
      return 1532404800000;  // July 24, 2018.
    case kM69:
      return 1536033600000;  // September 4, 2018.
    case kM70:
      return 1539662400000;  // October 16, 2018.
    case kM71:
      return 1543899600000;  // December 4, 2018.
  }

  NOTREACHED();
  return 0;
}

struct DeprecationInfo {
  String id;
  Milestone anticipated_removal;
  String message;
};

String ReplacedBy(const char* feature, const char* replacement) {
  return String::Format("%s is deprecated. Please use %s instead.", feature,
                        replacement);
}

String WillBeRemoved(const char* feature,
                     Milestone milestone,
                     const char* details) {
  return String::Format(
      "%s is deprecated and will be removed in %s. See "
      "https://www.chromestatus.com/features/%s for more details.",
      feature, MilestoneString(milestone), details);
}

String ReplacedWillBeRemoved(const char* feature,
                             const char* replacement,
                             Milestone milestone,
                             const char* details) {
  return String::Format(
      "%s is deprecated and will be removed in %s. Please use %s instead. See "
      "https://www.chromestatus.com/features/%s for more details.",
      feature, MilestoneString(milestone), replacement, details);
}

String DeprecatedWillBeDisabledByFeaturePolicyInCrossOriginIframe(
    const char* function,
    const char* allow_string,
    Milestone milestone) {
  return String::Format(
      "%s usage in cross-origin iframes is deprecated and will be disabled in "
      "%s. To continue to use this feature, it must be enabled by the "
      "embedding document using Feature Policy, e.g. "
      "<iframe allow=\"%s\" ...>. See https://goo.gl/EuHzyv for more details.",
      function, MilestoneString(milestone), allow_string);
}

DeprecationInfo GetDeprecationInfo(WebFeature feature) {
  switch (feature) {
    // Quota
    case WebFeature::kPrefixedStorageInfo:
      return {"PrefixedStorageInfo", kUnknown,
              ReplacedBy("'window.webkitStorageInfo'",
                         "'navigator.webkitTemporaryStorage' or "
                         "'navigator.webkitPersistentStorage'")};

    case WebFeature::kConsoleMarkTimeline:
      return {"ConsoleMarkTimeline", kUnknown,
              ReplacedBy("'console.markTimeline'", "'console.timeStamp'")};

    case WebFeature::kPrefixedVideoSupportsFullscreen:
      return {"PrefixedVideoSupportsFullscreen", kUnknown,
              ReplacedBy("'HTMLVideoElement.webkitSupportsFullscreen'",
                         "'Document.fullscreenEnabled'")};

    case WebFeature::kPrefixedVideoDisplayingFullscreen:
      return {"PrefixedVideoDisplayingFullscreen", kUnknown,
              ReplacedBy("'HTMLVideoElement.webkitDisplayingFullscreen'",
                         "'Document.fullscreenElement'")};

    case WebFeature::kPrefixedVideoEnterFullscreen:
      return {"PrefixedVideoEnterFullscreen", kUnknown,
              ReplacedBy("'HTMLVideoElement.webkitEnterFullscreen()'",
                         "'Element.requestFullscreen()'")};

    case WebFeature::kPrefixedVideoExitFullscreen:
      return {"PrefixedVideoExitFullscreen", kUnknown,
              ReplacedBy("'HTMLVideoElement.webkitExitFullscreen()'",
                         "'Document.exitFullscreen()'")};

    case WebFeature::kPrefixedVideoEnterFullScreen:
      return {"PrefixedVideoEnterFullScreen", kUnknown,
              ReplacedBy("'HTMLVideoElement.webkitEnterFullScreen()'",
                         "'Element.requestFullscreen()'")};

    case WebFeature::kPrefixedVideoExitFullScreen:
      return {"PrefixedVideoExitFullScreen", kUnknown,
              ReplacedBy("'HTMLVideoElement.webkitExitFullScreen()'",
                         "'Document.exitFullscreen()'")};

    case WebFeature::kPrefixedRequestAnimationFrame:
      return {"PrefixedRequestAnimationFrame", kUnknown,
              "'webkitRequestAnimationFrame' is vendor-specific. Please use "
              "the standard 'requestAnimationFrame' instead."};

    case WebFeature::kPrefixedCancelAnimationFrame:
      return {"PrefixedCancelAnimationFrame", kUnknown,
              "'webkitCancelAnimationFrame' is vendor-specific. Please use the "
              "standard 'cancelAnimationFrame' instead."};

    case WebFeature::kPictureSourceSrc:
      return {"PictureSourceSrc", kUnknown,
              "<source src> with a <picture> parent is invalid and therefore "
              "ignored. Please use <source srcset> instead."};

    case WebFeature::kConsoleTimeline:
      return {"ConsoleTimeline", kUnknown,
              ReplacedBy("'console.timeline'", "'console.time'")};

    case WebFeature::kConsoleTimelineEnd:
      return {"ConsoleTimelineEnd", kUnknown,
              ReplacedBy("'console.timelineEnd'", "'console.timeEnd'")};

    case WebFeature::kXMLHttpRequestSynchronousInNonWorkerOutsideBeforeUnload:
      return {"XMLHttpRequestSynchronousInNonWorkerOutsideBeforeUnload",
              kUnknown,
              "Synchronous XMLHttpRequest on the main thread is deprecated "
              "because of its detrimental effects to the end user's "
              "experience. For more help, check https://xhr.spec.whatwg.org/."};

    case WebFeature::kPrefixedWindowURL:
      return {"PrefixedWindowURL", kUnknown,
              ReplacedBy("'webkitURL'", "'URL'")};

    case WebFeature::kRangeExpand:
      return {"RangeExpand", kUnknown,
              ReplacedBy("'Range.expand()'", "'Selection.modify()'")};

    // Blocked subresource requests:
    case WebFeature::kLegacyProtocolEmbeddedAsSubresource:
      return {"LegacyProtocolEmbeddedAsSubresource", kUnknown,
              String::Format(
                  "Subresource requests using legacy protocols (like `ftp:`) "
                  "are blocked. Please deliver web-accessible resources over "
                  "modern protocols like HTTPS. See "
                  "https://www.chromestatus.com/feature/5709390967472128 for "
                  "details.")};

    case WebFeature::kRequestedSubresourceWithEmbeddedCredentials:
      return {"RequestedSubresourceWithEmbeddedCredentials", kUnknown,
              "Subresource requests whose URLs contain embedded credentials "
              "(e.g. `https://user:pass@host/`) are blocked. See "
              "https://www.chromestatus.com/feature/5669008342777856 for more "
              "details."};

    // Blocked `<meta http-equiv="set-cookie" ...>`
    case WebFeature::kMetaSetCookie:
      return {"MetaSetCookie", kM65,
              String::Format(
                  "Setting cookies via `<meta http-equiv='Set-Cookie' ...>` no "
                  "longer works, as of M65. Consider switching to "
                  " `document.cookie = ...`, or to `Set-Cookie` HTTP headers "
                  "instead. See %s for more details.",
                  "https://www.chromestatus.com/feature/6170540112871424")};

    // Powerful features on insecure origins (https://goo.gl/rStTGz)
    case WebFeature::kDeviceMotionInsecureOrigin:
      return {"DeviceMotionInsecureOrigin", kUnknown,
              "The devicemotion event is deprecated on insecure origins, and "
              "support will be removed in the future. You should consider "
              "switching your application to a secure origin, such as HTTPS. "
              "See https://goo.gl/rStTGz for more details."};

    case WebFeature::kDeviceOrientationInsecureOrigin:
      return {"DeviceOrientationInsecureOrigin", kUnknown,
              "The deviceorientation event is deprecated on insecure origins, "
              "and support will be removed in the future. You should consider "
              "switching your application to a secure origin, such as HTTPS. "
              "See https://goo.gl/rStTGz for more details."};

    case WebFeature::kDeviceOrientationAbsoluteInsecureOrigin:
      return {"DeviceOrientationAbsoluteInsecureOrigin", kUnknown,
              "The deviceorientationabsolute event is deprecated on insecure "
              "origins, and support will be removed in the future. You should "
              "consider switching your application to a secure origin, such as "
              "HTTPS. See https://goo.gl/rStTGz for more details."};

    case WebFeature::kGeolocationInsecureOrigin:
    case WebFeature::kGeolocationInsecureOriginIframe:
      return {"GeolocationInsecureOrigin", kUnknown,
              "getCurrentPosition() and watchPosition() no longer work on "
              "insecure origins. To use this feature, you should consider "
              "switching your application to a secure origin, such as HTTPS. "
              "See https://goo.gl/rStTGz for more details."};

    case WebFeature::kGeolocationInsecureOriginDeprecatedNotRemoved:
    case WebFeature::kGeolocationInsecureOriginIframeDeprecatedNotRemoved:
      return {"GeolocationInsecureOriginDeprecatedNotRemoved", kUnknown,
              "getCurrentPosition() and watchPosition() are deprecated on "
              "insecure origins. To use this feature, you should consider "
              "switching your application to a secure origin, such as HTTPS. "
              "See https://goo.gl/rStTGz for more details."};

    case WebFeature::kGetUserMediaInsecureOrigin:
    case WebFeature::kGetUserMediaInsecureOriginIframe:
      return {
          "GetUserMediaInsecureOrigin", kUnknown,
          "getUserMedia() no longer works on insecure origins. To use this "
          "feature, you should consider switching your application to a "
          "secure origin, such as HTTPS. See https://goo.gl/rStTGz for more "
          "details."};

    case WebFeature::kMediaSourceAbortRemove:
      return {
          "MediaSourceAbortRemove", kUnknown,
          "Using SourceBuffer.abort() to abort remove()'s asynchronous "
          "range removal is deprecated due to specification change. Support "
          "will be removed in the future. You should instead await "
          "'updateend'. abort() is intended to only abort an asynchronous "
          "media append or reset parser state. See "
          "https://www.chromestatus.com/features/6107495151960064 for more "
          "details."};

    case WebFeature::kMediaSourceDurationTruncatingBuffered:
      return {
          "MediaSourceDurationTruncatingBuffered", kUnknown,
          "Setting MediaSource.duration below the highest presentation "
          "timestamp of any buffered coded frames is deprecated due to "
          "specification change. Support for implicit removal of truncated "
          "buffered media will be removed in the future. You should instead "
          "perform explicit remove(newDuration, oldDuration) on all "
          "sourceBuffers, where newDuration < oldDuration. See "
          "https://www.chromestatus.com/features/6107495151960064 for more "
          "details."};

    case WebFeature::kApplicationCacheManifestSelectInsecureOrigin:
    case WebFeature::kApplicationCacheAPIInsecureOrigin:
      return {
          "ApplicationCacheAPIInsecureOrigin", kM69,
          String::Format(
              "Application Cache is deprecated in non-secure contexts, and "
              "will be restricted to secure contexts in %s. Please consider "
              "migrating your application to HTTPS, and eventually shifting "
              "over to Service Workers. See https://goo.gl/rStTGz for more "
              "details.",
              MilestoneString(kM69))};

    case WebFeature::kNotificationInsecureOrigin:
    case WebFeature::kNotificationAPIInsecureOriginIframe:
    case WebFeature::kNotificationPermissionRequestedInsecureOrigin:
      return {
          "NotificationInsecureOrigin", kUnknown,
          String::Format(
              "The Notification API may no longer be used from insecure "
              "origins. "
              "You should consider switching your application to a secure "
              "origin, "
              "such as HTTPS. See https://goo.gl/rStTGz for more details.")};

    case WebFeature::kNotificationPermissionRequestedIframe:
      return {
          "NotificationPermissionRequestedIframe", kUnknown,
          String::Format(
              "Permission for the Notification API may no longer be requested "
              "from "
              "a cross-origin iframe. You should consider requesting "
              "permission "
              "from a top-level frame or opening a new window instead. See "
              "https://www.chromestatus.com/feature/6451284559265792 for more "
              "details.")};

    case WebFeature::kCSSDeepCombinator:
      return {"CSSDeepCombinator", kM65,
              "/deep/ combinator is no longer supported in CSS dynamic profile."
              "It is now effectively no-op, acting as if it were a descendant "
              "combinator. /deep/ combinator will be removed, and will be "
              "invalid at M65. You should remove it. See "
              "https://www.chromestatus.com/features/4964279606312960 for more "
              "details."};

    case WebFeature::kVREyeParametersOffset:
      return {"VREyeParametersOffset", kUnknown,
              ReplacedBy("VREyeParameters.offset",
                         "view matrices provided by VRFrameData")};

    case WebFeature::kCSSSelectorInternalMediaControlsOverlayCastButton:
      return {
          "CSSSelectorInternalMediaControlsOverlayCastButton", kM61,
          WillBeRemoved("-internal-media-controls-overlay-cast-button selector",
                        kM61, "5714245488476160")};

    case WebFeature::kSelectionAddRangeIntersect:
      return {
          "SelectionAddRangeIntersect", kUnknown,
          "The behavior that Selection.addRange() merges existing Range and "
          "the specified Range was removed. See "
          "https://www.chromestatus.com/features/6680566019653632 for more "
          "details."};

    case WebFeature::kRtcpMuxPolicyNegotiate:
      return {"RtcpMuxPolicyNegotiate", kM62,
              String::Format("The rtcpMuxPolicy option is being considered for "
                             "removal and may be removed no earlier than %s. "
                             "If you depend on it, "
                             "please see "
                             "https://www.chromestatus.com/features/"
                             "5654810086866944 "
                             "for more details.",
                             MilestoneString(kM62))};

    case WebFeature::kChildSrcAllowedWorkerThatScriptSrcBlocked:
      return {"ChildSrcAllowedWorkerThatScriptSrcBlocked", kM60,
              ReplacedWillBeRemoved("The 'child-src' directive",
                                    "the 'script-src' directive for Workers",
                                    kM60, "5922594955984896")};

    case WebFeature::kCanRequestURLHTTPContainingNewline:
      return {
          "CanRequestURLHTTPContainingNewline", kUnknown,
          "Resource requests whose URLs contained both removed whitespace "
          "(`\\n`, `\\r`, `\\t`) characters and less-than characters (`<`) "
          "are blocked. Please remove newlines and encode less-than "
          "characters from places like element attribute values in order to "
          "load these resources. See "
          "https://www.chromestatus.com/feature/5735596811091968 for more "
          "details."};

    case WebFeature::kPaymentRequestNetworkNameInSupportedMethods:
      return {
          "PaymentRequestNetworkNameInSupportedMethods", kM64,
          ReplacedWillBeRemoved(
              "Card issuer network (\"amex\", \"diners\", \"discover\", "
              "\"jcb\", "
              "\"mastercard\", \"mir\", \"unionpay\", \"visa\") as payment "
              "method",
              "payment method name \"basic-card\" with issuer network in the "
              "\"supportedNetworks\" field",
              kM64, "5725727580225536")};

    case WebFeature::kDeprecatedTimingFunctionStepMiddle:
      return {
          "DeprecatedTimingFunctionStepMiddle", kM62,
          WillBeRemoved("The step timing function with step position 'middle'",
                        kM62, "5189363944128512")};

    case WebFeature::kHTMLImportsHasStyleSheets:
      return {"HTMLImportsHasStyleSheets", kUnknown,
              "Styling master document from stylesheets defined in "
              "HTML Imports is deprecated. "
              "Please refer to "
              "https://goo.gl/EGXzpw for possible migration paths."};

    case WebFeature::
        kEncryptedMediaDisallowedByFeaturePolicyInCrossOriginIframe:
      return {"EncryptedMediaDisallowedByFeaturePolicyInCrossOriginIframe",
              kM64,
              DeprecatedWillBeDisabledByFeaturePolicyInCrossOriginIframe(
                  "requestMediaKeySystemAccess", "encrypted-media", kM64)};

    case WebFeature::kGeolocationDisallowedByFeaturePolicyInCrossOriginIframe:
      return {"GeolocationDisallowedByFeaturePolicyInCrossOriginIframe", kM64,
              DeprecatedWillBeDisabledByFeaturePolicyInCrossOriginIframe(
                  "getCurrentPosition and watchPosition", "geolocation", kM64)};

    case WebFeature::
        kGetUserMediaMicDisallowedByFeaturePolicyInCrossOriginIframe:
      return {"GetUserMediaMicDisallowedByFeaturePolicyInCrossOriginIframe",
              kM64,
              DeprecatedWillBeDisabledByFeaturePolicyInCrossOriginIframe(
                  "getUserMedia (microphone)", "microphone", kM64)};

    case WebFeature::
        kGetUserMediaCameraDisallowedByFeaturePolicyInCrossOriginIframe:
      return {"GetUserMediaCameraDisallowedByFeaturePolicyInCrossOriginIframe",
              kM64,
              DeprecatedWillBeDisabledByFeaturePolicyInCrossOriginIframe(
                  "getUserMedia (camera)", "camera", kM64)};

    case WebFeature::
        kRequestMIDIAccessDisallowedByFeaturePolicyInCrossOriginIframe:
      return {"RequestMIDIAccessDisallowedByFeaturePolicyInCrossOriginIframe",
              kM64,
              DeprecatedWillBeDisabledByFeaturePolicyInCrossOriginIframe(
                  "requestMIDIAccess", "midi", kM64)};

    case WebFeature::kPresentationRequestStartInsecureOrigin:
    case WebFeature::kPresentationReceiverInsecureOrigin:
      return {
          "PresentationInsecureOrigin", kM68,
          String("Using the Presentation API on insecure origins is "
                 "deprecated and will be removed in M68. You should consider "
                 "switching your application to a secure origin, such as "
                 "HTTPS. See "
                 "https://goo.gl/rStTGz for more details.")};

    case WebFeature::kPaymentRequestSupportedMethodsArray:
      return {"PaymentRequestSupportedMethodsArray", kM64,
              ReplacedWillBeRemoved(
                  "PaymentRequest's supportedMethods taking an array",
                  "a single string", kM64, "5177301645918208")};

    case WebFeature::kLocalCSSFileExtensionRejected:
      return {"LocalCSSFileExtensionRejected", kM64,
              String("CSS cannot be loaded from `file:` URLs unless they end "
                     "in a `.css` file extension.")};

    case WebFeature::kCreateObjectURLMediaStream:
      return {"CreateObjectURLMediaStreamDeprecated", kM68,
              ReplacedWillBeRemoved("URL.createObjectURL with media streams",
                                    "HTMLMediaElement.srcObject", kM68,
                                    "5618491470118912")};

    case WebFeature::kChromeLoadTimesRequestTime:
    case WebFeature::kChromeLoadTimesStartLoadTime:
    case WebFeature::kChromeLoadTimesCommitLoadTime:
    case WebFeature::kChromeLoadTimesFinishDocumentLoadTime:
    case WebFeature::kChromeLoadTimesFinishLoadTime:
    case WebFeature::kChromeLoadTimesNavigationType:
    case WebFeature::kChromeLoadTimesConnectionInfo:
      return {"ChromeLoadTimesConnectionInfo", kUnknown,
              kChromeLoadTimesNavigationTiming};

    case WebFeature::kChromeLoadTimesFirstPaintTime:
    case WebFeature::kChromeLoadTimesFirstPaintAfterLoadTime:
      return {"ChromeLoadTimesFirstPaintAfterLoadTime", kUnknown,
              kChromeLoadTimesPaintTiming};

    case WebFeature::kChromeLoadTimesWasFetchedViaSpdy:
    case WebFeature::kChromeLoadTimesWasNpnNegotiated:
    case WebFeature::kChromeLoadTimesNpnNegotiatedProtocol:
    case WebFeature::kChromeLoadTimesWasAlternateProtocolAvailable:
      return {"ChromeLoadTimesWasAlternateProtocolAvailable", kUnknown,
              kChromeLoadTimesNextHopProtocol};

    case WebFeature::kDataUriHasOctothorpe:
      return {"DataUriHasOctothorpe", kM68,
              ReplacedWillBeRemoved(
                  "Using unescaped '#' characters in a data URI body", "'%23'",
                  kM68, "5656049583390720")};

    case WebFeature::kImageInputTypeFormDataWithNonEmptyValue:
      return {"ImageInputTypeFormDataWithNonEmptyValue", kM68,
              WillBeRemoved("Extra form data if value attribute "
                            "is present with non-empty "
                            "value for <input type='image'>",
                            kM68, "5672688152477696")};

    case WebFeature::kV8Document_CreateTouch_Method:
      return {"V8Document_CreateTouch_Method", kM68,
              ReplacedWillBeRemoved("document.createTouch",
                                    "TouchEvent constructor", kM68,
                                    "5668612064935936")};

    case WebFeature::kV8Document_CreateTouchList_Method:
      return {"V8Document_CreateTouchList_Method", kM68,
              ReplacedWillBeRemoved("document.createTouchList",
                                    "TouchEvent constructor", kM68,
                                    "5668612064935936")};

    // Features that aren't deprecated don't have a deprecation message.
    default:
      return {"NotDeprecated", kUnknown, ""};
  }
}

}  // anonymous namespace

namespace blink {

Deprecation::Deprecation() : mute_count_(0) {
  css_property_deprecation_bits_.EnsureSize(numCSSPropertyIDs);
}

Deprecation::~Deprecation() = default;

void Deprecation::ClearSuppression() {
  css_property_deprecation_bits_.ClearAll();
}

void Deprecation::MuteForInspector() {
  mute_count_++;
}

void Deprecation::UnmuteForInspector() {
  mute_count_--;
}

void Deprecation::Suppress(CSSPropertyID unresolved_property) {
  DCHECK(isCSSPropertyIDWithName(unresolved_property));
  css_property_deprecation_bits_.QuickSet(unresolved_property);
}

bool Deprecation::IsSuppressed(CSSPropertyID unresolved_property) {
  DCHECK(isCSSPropertyIDWithName(unresolved_property));
  return css_property_deprecation_bits_.QuickGet(unresolved_property);
}

void Deprecation::WarnOnDeprecatedProperties(
    const LocalFrame* frame,
    CSSPropertyID unresolved_property) {
  Page* page = frame ? frame->GetPage() : nullptr;
  if (!page || page->GetDeprecation().mute_count_ ||
      page->GetDeprecation().IsSuppressed(unresolved_property))
    return;

  String message = DeprecationMessage(unresolved_property);
  if (!message.IsEmpty()) {
    page->GetDeprecation().Suppress(unresolved_property);
    ConsoleMessage* console_message = ConsoleMessage::Create(
        kDeprecationMessageSource, kWarningMessageLevel, message);
    frame->Console().AddMessage(console_message);
  }
}

String Deprecation::DeprecationMessage(CSSPropertyID unresolved_property) {
  // TODO: Add a switch here when there are properties that we intend to
  // deprecate.
  // Returning an empty string for now.
  return g_empty_string;
}

void Deprecation::CountDeprecation(const LocalFrame* frame,
                                   WebFeature feature) {
  if (!frame)
    return;
  Page* page = frame->GetPage();
  if (!page || page->GetDeprecation().mute_count_)
    return;

  if (!page->GetUseCounter().HasRecordedMeasurement(feature)) {
    page->GetUseCounter().RecordMeasurement(feature, *frame);
    GenerateReport(frame, feature);
  }
}

void Deprecation::CountDeprecation(ExecutionContext* context,
                                   WebFeature feature) {
  if (!context)
    return;
  if (context->IsDocument()) {
    Deprecation::CountDeprecation(*ToDocument(context), feature);
    return;
  }
  if (context->IsWorkerOrWorkletGlobalScope())
    ToWorkerOrWorkletGlobalScope(context)->CountDeprecation(feature);
}

void Deprecation::CountDeprecation(const Document& document,
                                   WebFeature feature) {
  Deprecation::CountDeprecation(document.GetFrame(), feature);
}

void Deprecation::CountDeprecationCrossOriginIframe(const LocalFrame* frame,
                                                    WebFeature feature) {
  // Check to see if the frame can script into the top level document.
  const SecurityOrigin* security_origin =
      frame->GetSecurityContext()->GetSecurityOrigin();
  Frame& top = frame->Tree().Top();
  if (!security_origin->CanAccess(
          top.GetSecurityContext()->GetSecurityOrigin()))
    CountDeprecation(frame, feature);
}

void Deprecation::CountDeprecationCrossOriginIframe(const Document& document,
                                                    WebFeature feature) {
  LocalFrame* frame = document.GetFrame();
  if (!frame)
    return;
  CountDeprecationCrossOriginIframe(frame, feature);
}

void Deprecation::CountDeprecationFeaturePolicy(
    const Document& document,
    mojom::FeaturePolicyFeature feature) {
  LocalFrame* frame = document.GetFrame();
  if (!frame)
    return;

  // If the feature is allowed, don't log a warning.
  if (frame->IsFeatureEnabled(feature))
    return;

  // If the feature is disabled, log a warning but only if the request is from a
  // cross-origin iframe. Ideally we would check here if the feature is actually
  // disabled due to the parent frame's policy (as opposed to the current frame
  // disabling the feature on itself) but that can't happen right now anyway
  // (until the general syntax is shipped) and this is also a good enough
  // approximation for deprecation messages.
  switch (feature) {
    case mojom::FeaturePolicyFeature::kEncryptedMedia:
      CountDeprecationCrossOriginIframe(
          frame,
          WebFeature::
              kEncryptedMediaDisallowedByFeaturePolicyInCrossOriginIframe);
      break;
    case mojom::FeaturePolicyFeature::kGeolocation:
      CountDeprecationCrossOriginIframe(
          frame,
          WebFeature::kGeolocationDisallowedByFeaturePolicyInCrossOriginIframe);
      break;
    case mojom::FeaturePolicyFeature::kMicrophone:
      CountDeprecationCrossOriginIframe(
          frame,
          WebFeature::
              kGetUserMediaMicDisallowedByFeaturePolicyInCrossOriginIframe);
      break;
    case mojom::FeaturePolicyFeature::kCamera:
      CountDeprecationCrossOriginIframe(
          frame,
          WebFeature::
              kGetUserMediaCameraDisallowedByFeaturePolicyInCrossOriginIframe);
      break;
    case mojom::FeaturePolicyFeature::kMidiFeature:
      CountDeprecationCrossOriginIframe(
          frame,
          WebFeature::
              kRequestMIDIAccessDisallowedByFeaturePolicyInCrossOriginIframe);
      break;
    default:
      NOTREACHED();
  }
}

void Deprecation::GenerateReport(const LocalFrame* frame, WebFeature feature) {
  DeprecationInfo info = GetDeprecationInfo(feature);

  // Send the deprecation message to the console as a warning.
  DCHECK(!info.message.IsEmpty());
  ConsoleMessage* console_message = ConsoleMessage::Create(
      kDeprecationMessageSource, kWarningMessageLevel, info.message);
  frame->Console().AddMessage(console_message);

  if (!frame || !frame->Client())
    return;

  Document* document = frame->GetDocument();

  // Construct the deprecation report.
  double removal_date = MilestoneDate(info.anticipated_removal);
  DeprecationReport* body = new DeprecationReport(
      info.id, removal_date, info.message, SourceLocation::Capture());
  Report* report = new Report("deprecation", document->Url().GetString(), body);

  // Send the deprecation report to any ReportingObservers.
  ReportingContext* reporting_context = ReportingContext::From(document);
  if (reporting_context->ObserverExists())
    reporting_context->QueueReport(report);

  // Send the deprecation report to the Reporting API.
  mojom::blink::ReportingServiceProxyPtr service;
  Platform* platform = Platform::Current();
  platform->GetConnector()->BindInterface(platform->GetBrowserServiceName(),
                                          &service);
  service->QueueDeprecationReport(document->Url(), info.id,
                                  WTF::Time::FromDoubleT(removal_date),
                                  info.message, body->sourceFile(),
                                  body->lineNumber(), body->columnNumber());
}

// static
String Deprecation::DeprecationMessage(WebFeature feature) {
  return GetDeprecationInfo(feature).message;
}

}  // namespace blink

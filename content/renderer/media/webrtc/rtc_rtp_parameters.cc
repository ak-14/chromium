// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/media/webrtc/rtc_rtp_parameters.h"

#include <utility>

#include "base/numerics/safe_conversions.h"

namespace {

// Relative weights for each priority as defined in RTCWEB-DATA
// https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel
const double kPriorityWeightVeryLow = 0.5;
const double kPriorityWeightLow = 1;
const double kPriorityWeightMedium = 2;
const double kPriorityWeightHigh = 4;

template <typename T, typename F>
base::Optional<T> ToBaseOptional(const rtc::Optional<F>& from) {
  if (from)
    return from.value();
  return base::nullopt;
}

template <typename T, typename F>
rtc::Optional<T> ToRtcOptional(const base::Optional<F>& from) {
  // TODO(orphis): Remove saturated_cast. https://crbug.com/webrtc/9143
  if (from)
    return base::saturated_cast<T>(from.value());
  return rtc::nullopt;
}

blink::WebRTCPriorityType PriorityFromDouble(double priority) {
  // Find the middle point between 2 priority weights to match them to a
  // WebRTC priority
  const double very_low_upper_bound =
      (kPriorityWeightVeryLow + kPriorityWeightLow) / 2;
  const double low_upper_bound =
      (kPriorityWeightLow + kPriorityWeightMedium) / 2;
  const double medium_upper_bound =
      (kPriorityWeightMedium + kPriorityWeightHigh) / 2;

  if (priority < webrtc::kDefaultBitratePriority * very_low_upper_bound) {
    return blink::WebRTCPriorityType::VeryLow;
  }
  if (priority < webrtc::kDefaultBitratePriority * low_upper_bound) {
    return blink::WebRTCPriorityType::Low;
  }
  if (priority < webrtc::kDefaultBitratePriority * medium_upper_bound) {
    return blink::WebRTCPriorityType::Medium;
  }
  return blink::WebRTCPriorityType::High;
}

double PriorityToDouble(blink::WebRTCPriorityType priority) {
  double result = 1;

  switch (priority) {
    case blink::WebRTCPriorityType::VeryLow:
      result = webrtc::kDefaultBitratePriority * kPriorityWeightVeryLow;
      break;
    case blink::WebRTCPriorityType::Low:
      result = webrtc::kDefaultBitratePriority * kPriorityWeightLow;
      break;
    case blink::WebRTCPriorityType::Medium:
      result = webrtc::kDefaultBitratePriority * kPriorityWeightMedium;
      break;
    case blink::WebRTCPriorityType::High:
      result = webrtc::kDefaultBitratePriority * kPriorityWeightHigh;
      break;
    default:
      NOTREACHED();
  }
  return result;
}

base::Optional<blink::WebRTCDtxStatus> FromRTCDtxStatus(
    rtc::Optional<webrtc::DtxStatus> status) {
  if (!status)
    return base::nullopt;

  blink::WebRTCDtxStatus result;
  switch (status.value()) {
    case webrtc::DtxStatus::DISABLED:
      result = blink::WebRTCDtxStatus::Disabled;
      break;
    case webrtc::DtxStatus::ENABLED:
      result = blink::WebRTCDtxStatus::Enabled;
      break;
    default:
      NOTREACHED();
  }
  return result;
}

rtc::Optional<webrtc::DtxStatus> ToRTCDtxStatus(
    base::Optional<blink::WebRTCDtxStatus> status) {
  if (!status)
    return rtc::nullopt;

  webrtc::DtxStatus result;
  switch (status.value()) {
    case blink::WebRTCDtxStatus::Disabled:
      result = webrtc::DtxStatus::DISABLED;
      break;
    case blink::WebRTCDtxStatus::Enabled:
      result = webrtc::DtxStatus::ENABLED;
      break;
    default:
      NOTREACHED();
  }
  return result;
}

base::Optional<blink::WebRTCDegradationPreference> FromRTCDegradationPreference(
    rtc::Optional<webrtc::DegradationPreference> degradation_preference) {
  if (!degradation_preference)
    return base::nullopt;

  blink::WebRTCDegradationPreference result;
  switch (degradation_preference.value()) {
    case webrtc::DegradationPreference::MAINTAIN_FRAMERATE:
      result = blink::WebRTCDegradationPreference::MaintainFramerate;
      break;
    case webrtc::DegradationPreference::MAINTAIN_RESOLUTION:
      result = blink::WebRTCDegradationPreference::MaintainResolution;
      break;
    case webrtc::DegradationPreference::BALANCED:
      result = blink::WebRTCDegradationPreference::Balanced;
      break;
    default:
      NOTREACHED();
  }
  return result;
}

}  // namespace

namespace content {

webrtc::DegradationPreference ToDegradationPreference(
    blink::WebRTCDegradationPreference degradation_preference) {
  webrtc::DegradationPreference result =
      webrtc::DegradationPreference::BALANCED;
  switch (degradation_preference) {
    case blink::WebRTCDegradationPreference::MaintainFramerate:
      result = webrtc::DegradationPreference::MAINTAIN_FRAMERATE;
      break;
    case blink::WebRTCDegradationPreference::MaintainResolution:
      result = webrtc::DegradationPreference::MAINTAIN_RESOLUTION;
      break;
    case blink::WebRTCDegradationPreference::Balanced:
      result = webrtc::DegradationPreference::BALANCED;
      break;
    default:
      NOTREACHED();
  }
  return result;
}

blink::WebRTCRtpParameters GetWebRTCRtpParameters(
    const webrtc::RtpParameters& parameters) {
  blink::WebVector<blink::WebRTCRtpEncodingParameters> encodings;
  encodings.reserve(parameters.encodings.size());
  for (const auto& encoding_parameter : parameters.encodings) {
    encodings.emplace_back(GetWebRTCRtpEncodingParameters(encoding_parameter));
  }

  blink::WebVector<blink::WebRTCRtpHeaderExtensionParameters> header_extensions;
  header_extensions.reserve(parameters.header_extensions.size());
  for (const auto& extension_parameter : parameters.header_extensions) {
    header_extensions.emplace_back(
        GetWebRTCRtpHeaderExtensionParameters(extension_parameter));
  }

  blink::WebVector<blink::WebRTCRtpCodecParameters> codec_parameters;
  codec_parameters.reserve(parameters.codecs.size());
  for (const auto& codec_parameter : parameters.codecs) {
    codec_parameters.emplace_back(GetWebRTCRtpCodecParameters(codec_parameter));
  }

  return blink::WebRTCRtpParameters(
      blink::WebString::FromASCII(parameters.transaction_id),
      blink::WebRTCRtcpParameters(), std::move(encodings), header_extensions,
      codec_parameters,
      FromRTCDegradationPreference(parameters.degradation_preference));
}

blink::WebRTCRtpEncodingParameters GetWebRTCRtpEncodingParameters(
    const webrtc::RtpEncodingParameters& encoding_parameters) {
  return blink::WebRTCRtpEncodingParameters(
      ToBaseOptional<uint8_t>(encoding_parameters.codec_payload_type),
      FromRTCDtxStatus(encoding_parameters.dtx), encoding_parameters.active,
      PriorityFromDouble(encoding_parameters.bitrate_priority),
      ToBaseOptional<uint32_t>(encoding_parameters.ptime),
      ToBaseOptional<uint32_t>(encoding_parameters.max_bitrate_bps),
      ToBaseOptional<uint32_t>(encoding_parameters.max_framerate),
      encoding_parameters.scale_framerate_down_by,
      blink::WebString::FromASCII(encoding_parameters.rid));
}

webrtc::RtpEncodingParameters FromWebRTCRtpEncodingParameters(
    const blink::WebRTCRtpEncodingParameters& web_encoding_parameter) {
  webrtc::RtpEncodingParameters encoding_parameter;
  encoding_parameter.codec_payload_type =
      ToRtcOptional<int>(web_encoding_parameter.CodecPayloadType());
  encoding_parameter.dtx = ToRTCDtxStatus(web_encoding_parameter.Dtx());
  encoding_parameter.active = web_encoding_parameter.Active();
  encoding_parameter.bitrate_priority =
      PriorityToDouble(web_encoding_parameter.Priority());
  encoding_parameter.ptime = ToRtcOptional<int>(web_encoding_parameter.Ptime());
  encoding_parameter.max_bitrate_bps =
      ToRtcOptional<int>(web_encoding_parameter.MaxBitrate());
  encoding_parameter.max_framerate =
      ToRtcOptional<int>(web_encoding_parameter.MaxFramerate());
  if (web_encoding_parameter.ScaleResolutionDownBy())
    encoding_parameter.scale_resolution_down_by =
        web_encoding_parameter.ScaleResolutionDownBy().value();
  if (web_encoding_parameter.Rid())
    encoding_parameter.rid = web_encoding_parameter.Rid().value().Ascii();
  return encoding_parameter;
}

blink::WebRTCRtpHeaderExtensionParameters GetWebRTCRtpHeaderExtensionParameters(
    const webrtc::RtpHeaderExtensionParameters& header_extension_parameters) {
  return blink::WebRTCRtpHeaderExtensionParameters(
      blink::WebString::FromASCII(header_extension_parameters.uri),
      header_extension_parameters.id, header_extension_parameters.encrypt);
}

// TODO(orphis): Copy the RTCP information
// https://crbug.com/webrtc/7580
blink::WebRTCRtcpParameters GetWebRTCRtcpParameters() {
  return blink::WebRTCRtcpParameters();
}

blink::WebRTCRtpCodecParameters GetWebRTCRtpCodecParameters(
    const webrtc::RtpCodecParameters& codec_parameters) {
  return blink::WebRTCRtpCodecParameters(
      codec_parameters.payload_type,
      blink::WebString::FromASCII(codec_parameters.mime_type()),
      ToBaseOptional<uint32_t>(codec_parameters.clock_rate),
      ToBaseOptional<uint16_t>(codec_parameters.num_channels),
      // TODO(orphis): Convert the parameters field to sdpFmtpLine
      // https://crbug.com/webrtc/7580
      blink::WebString());
}

}  // namespace content

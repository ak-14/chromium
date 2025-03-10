// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media/base/mime_util_internal.h"

#include "base/command_line.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "media/base/media.h"
#include "media/base/media_client.h"
#include "media/base/media_switches.h"
#include "media/base/video_codecs.h"
#include "media/base/video_color_space.h"
#include "media/media_buildflags.h"
#include "third_party/libaom/av1_buildflags.h"

#if defined(OS_ANDROID)
#include "base/android/build_info.h"

// TODO(dalecurtis): This include is not allowed by media/base since
// media/base/android is technically a different component. We should move
// mime_util*.{cc,h} out of media/base to fix this.
#include "media/base/android/media_codec_util.h"  // nogncheck
#endif

namespace media {
namespace internal {

// Wrapped to avoid static initializer startup cost.
const base::flat_map<std::string, MimeUtil::Codec>& GetStringToCodecMap() {
  static const base::flat_map<std::string, MimeUtil::Codec> kStringToCodecMap(
      {
        // We only allow this for WAV so it isn't ambiguous.
        {"1", MimeUtil::PCM},
        // avc1/avc3.XXXXXX may be unambiguous; handled by
        // ParseAVCCodecId(). hev1/hvc1.XXXXXX may be unambiguous; handled
        // by ParseHEVCCodecID(). vp9, vp9.0, vp09.xx.xx.xx.xx.xx.xx.xx may
        // be unambiguous; handled by ParseVp9CodecID().
        {"mp3", MimeUtil::MP3},
        // Following is the list of RFC 6381 compliant audio codec strings:
        //   mp4a.66     - MPEG-2 AAC MAIN
        //   mp4a.67     - MPEG-2 AAC LC
        //   mp4a.68     - MPEG-2 AAC SSR
        //   mp4a.69     - MPEG-2 extension to MPEG-1 (MP3)
        //   mp4a.6B     - MPEG-1 audio (MP3)
        //   mp4a.40.2   - MPEG-4 AAC LC
        //   mp4a.40.02  - MPEG-4 AAC LC (leading 0 in aud-oti for
        //   compatibility) mp4a.40.5   - MPEG-4 HE-AAC v1 (AAC LC + SBR)
        //   mp4a.40.05  - MPEG-4 HE-AAC v1 (AAC LC + SBR) (leading 0 in
        //   aud-oti
        //                 for compatibility)
        //   mp4a.40.29  - MPEG-4 HE-AAC v2 (AAC LC + SBR + PS)
        {"mp4a.66", MimeUtil::MPEG2_AAC}, {"mp4a.67", MimeUtil::MPEG2_AAC},
        {"mp4a.68", MimeUtil::MPEG2_AAC}, {"mp4a.69", MimeUtil::MP3},
        {"mp4a.6B", MimeUtil::MP3}, {"mp4a.40.2", MimeUtil::MPEG4_AAC},
        {"mp4a.40.02", MimeUtil::MPEG4_AAC},
        {"mp4a.40.5", MimeUtil::MPEG4_AAC},
        {"mp4a.40.05", MimeUtil::MPEG4_AAC},
        {"mp4a.40.29", MimeUtil::MPEG4_AAC},
#if BUILDFLAG(ENABLE_AC3_EAC3_AUDIO_DEMUXING)
        // TODO(servolk): Strictly speaking only mp4a.A5 and mp4a.A6 codec
        // ids are valid according to RFC 6381 section 3.3, 3.4. Lower-case
        // oti (mp4a.a5 and mp4a.a6) should be rejected. But we used to
        // allow those in older versions of Chromecast firmware and some
        // apps (notably MPL) depend on those codec types being supported,
        // so they should be allowed for now (crbug.com/564960).
        {"ac-3", MimeUtil::AC3}, {"mp4a.a5", MimeUtil::AC3},
        {"mp4a.A5", MimeUtil::AC3}, {"ec-3", MimeUtil::EAC3},
        {"mp4a.a6", MimeUtil::EAC3}, {"mp4a.A6", MimeUtil::EAC3},
#endif
        {"vorbis", MimeUtil::VORBIS}, {"opus", MimeUtil::OPUS},
        {"flac", MimeUtil::FLAC}, {"vp8", MimeUtil::VP8},
        {"vp8.0", MimeUtil::VP8}, {"theora", MimeUtil::THEORA},
// TODO(dalecurtis): This is not the correct final string. Fix before enabling
// by default. http://crbug.com/784607
#if BUILDFLAG(ENABLE_AV1_DECODER)
        {"av1", MimeUtil::AV1},
#endif
      },
      base::KEEP_FIRST_OF_DUPES);

  return kStringToCodecMap;
}

static bool ParseVp9CodecID(const std::string& mime_type_lower_case,
                            const std::string& codec_id,
                            VideoCodecProfile* out_profile,
                            uint8_t* out_level,
                            VideoColorSpace* out_color_space) {
  if (mime_type_lower_case == "video/mp4") {
    // Only new style is allowed for mp4.
    return ParseNewStyleVp9CodecID(codec_id, out_profile, out_level,
                                   out_color_space);
  } else if (mime_type_lower_case == "video/webm") {
    if (ParseNewStyleVp9CodecID(codec_id, out_profile, out_level,
                                out_color_space)) {
      return true;
    }

    return ParseLegacyVp9CodecID(codec_id, out_profile, out_level);
  }
  return false;
}

static bool IsValidH264Level(uint8_t level_idc) {
  // Valid levels taken from Table A-1 in ISO/IEC 14496-10.
  // Level_idc represents the standard level represented as decimal number
  // multiplied by ten, e.g. level_idc==32 corresponds to level==3.2
  return ((level_idc >= 10 && level_idc <= 13) ||
          (level_idc >= 20 && level_idc <= 22) ||
          (level_idc >= 30 && level_idc <= 32) ||
          (level_idc >= 40 && level_idc <= 42) ||
          (level_idc >= 50 && level_idc <= 51));
}

MimeUtil::MimeUtil() : allow_proprietary_codecs_(false) {
#if defined(OS_ANDROID)
  // When the unified media pipeline is enabled, we need support for both GPU
  // video decoders and MediaCodec; indicated by HasPlatformDecoderSupport().
  // When the Android pipeline is used, we only need access to MediaCodec.
  platform_info_.has_platform_decoders = HasPlatformDecoderSupport();
  platform_info_.has_platform_vp8_decoder =
      MediaCodecUtil::IsVp8DecoderAvailable();
  platform_info_.has_platform_vp9_decoder =
      MediaCodecUtil::IsVp9DecoderAvailable();
  platform_info_.supports_opus = PlatformHasOpusSupport();
#endif

  InitializeMimeTypeMaps();
}

MimeUtil::~MimeUtil() = default;

AudioCodec MimeUtilToAudioCodec(MimeUtil::Codec codec) {
  switch (codec) {
    case MimeUtil::PCM:
      return kCodecPCM;
    case MimeUtil::MP3:
      return kCodecMP3;
    case MimeUtil::AC3:
      return kCodecAC3;
    case MimeUtil::EAC3:
      return kCodecEAC3;
    case MimeUtil::MPEG2_AAC:
    case MimeUtil::MPEG4_AAC:
      return kCodecAAC;
    case MimeUtil::VORBIS:
      return kCodecVorbis;
    case MimeUtil::OPUS:
      return kCodecOpus;
    case MimeUtil::FLAC:
      return kCodecFLAC;
    default:
      break;
  }
  return kUnknownAudioCodec;
}

VideoCodec MimeUtilToVideoCodec(MimeUtil::Codec codec) {
  switch (codec) {
    case MimeUtil::AV1:
      return kCodecAV1;
    case MimeUtil::H264:
      return kCodecH264;
    case MimeUtil::HEVC:
      return kCodecHEVC;
    case MimeUtil::VP8:
      return kCodecVP8;
    case MimeUtil::VP9:
      return kCodecVP9;
    case MimeUtil::THEORA:
      return kCodecTheora;
    case MimeUtil::DOLBY_VISION:
      return kCodecDolbyVision;
    default:
      break;
  }
  return kUnknownVideoCodec;
}

SupportsType MimeUtil::AreSupportedCodecs(
    const std::vector<ParsedCodecResult>& parsed_codecs,
    const std::string& mime_type_lower_case,
    bool is_encrypted) const {
  DCHECK(!parsed_codecs.empty());
  DCHECK_EQ(base::ToLowerASCII(mime_type_lower_case), mime_type_lower_case);

  SupportsType combined_result = IsSupported;

  for (const auto& parsed_codec : parsed_codecs) {
    // Make conservative guesses to resolve ambiguity before checking platform
    // support. Historically we allowed some ambiguity in H264 and VP9 codec
    // strings, so we must continue to allow going forward. DO NOT ADD NEW
    // SUPPORT FOR MORE AMBIGUOUS STRINGS.
    VideoCodecProfile video_profile = parsed_codec.video_profile;
    uint8_t video_level = parsed_codec.video_level;
    if (parsed_codec.is_ambiguous) {
      switch (parsed_codec.codec) {
        case MimeUtil::H264:
          if (video_profile == VIDEO_CODEC_PROFILE_UNKNOWN)
            video_profile = H264PROFILE_BASELINE;
          if (!IsValidH264Level(video_level))
            video_level = 10;
          break;
        case MimeUtil::VP9:
          if (video_profile == VIDEO_CODEC_PROFILE_UNKNOWN)
            video_profile = VP9PROFILE_PROFILE0;
          if (video_level == 0)
            video_level = 10;
          break;
        case MimeUtil::MPEG4_AAC:
          // Nothing to do for AAC; no notion of profile / level to guess.
          break;
        default:
          NOTREACHED()
              << "Only VP9, H264, and AAC codec strings can be ambiguous.";
      }
    }

    // Check platform support.
    SupportsType result = IsCodecSupported(
        mime_type_lower_case, parsed_codec.codec, video_profile, video_level,
        parsed_codec.video_color_space, is_encrypted);
    if (result == IsNotSupported) {
      DVLOG(2) << __func__ << ": Codec " << parsed_codec.codec
               << " not supported by platform.";
      return IsNotSupported;
    }

    // If any codec is "MayBeSupported", return Maybe for the combined result.
    if (result == MayBeSupported ||
        // Downgrade to MayBeSupported if we had to guess the meaning of one of
        // the codec strings. Do not downgrade for VP9 because we historically
        // returned "Probably" for the old "vp9" string and cannot change to
        // returning "Maybe" as this will break sites.
        (result == IsSupported && parsed_codec.is_ambiguous &&
         parsed_codec.codec != MimeUtil::VP9)) {
      combined_result = MayBeSupported;
    }
  }

  return combined_result;
}

void MimeUtil::InitializeMimeTypeMaps() {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  allow_proprietary_codecs_ = true;
#endif

  AddSupportedMediaFormats();
}

// Each call to AddContainerWithCodecs() contains a media type
// (https://en.wikipedia.org/wiki/Media_type) and corresponding media codec(s)
// supported by these types/containers.
void MimeUtil::AddSupportedMediaFormats() {
  const CodecSet wav_codecs{PCM};
  const CodecSet ogg_audio_codecs{FLAC, OPUS, VORBIS};

#if !defined(OS_ANDROID)
  CodecSet ogg_video_codecs{THEORA, VP8};
#else
  CodecSet ogg_video_codecs;
#endif  // !defined(OS_ANDROID)

  CodecSet ogg_codecs(ogg_audio_codecs);
  ogg_codecs.insert(ogg_video_codecs.begin(), ogg_video_codecs.end());

  const CodecSet webm_audio_codecs{OPUS, VORBIS};
  CodecSet webm_video_codecs{VP8, VP9};
#if BUILDFLAG(ENABLE_AV1_DECODER)
  if (base::FeatureList::IsEnabled(kAv1Decoder))
    webm_video_codecs.emplace(AV1);
#endif

  CodecSet webm_codecs(webm_audio_codecs);
  webm_codecs.insert(webm_video_codecs.begin(), webm_video_codecs.end());

  const CodecSet mp3_codecs{MP3};

  CodecSet mp4_audio_codecs;
  mp4_audio_codecs.emplace(MP3);
  mp4_audio_codecs.emplace(FLAC);

  // Only VP9 with valid codec string vp09.xx.xx.xx.xx.xx.xx.xx is supported.
  // See ParseVp9CodecID for details.
  CodecSet mp4_video_codecs;
  mp4_video_codecs.emplace(VP9);

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  const CodecSet aac{MPEG2_AAC, MPEG4_AAC};
  mp4_audio_codecs.insert(aac.begin(), aac.end());

  CodecSet avc_and_aac(aac);
  avc_and_aac.emplace(H264);

#if BUILDFLAG(ENABLE_AC3_EAC3_AUDIO_DEMUXING)
  mp4_audio_codecs.emplace(AC3);
  mp4_audio_codecs.emplace(EAC3);
#endif  // BUILDFLAG(ENABLE_AC3_EAC3_AUDIO_DEMUXING)

  mp4_video_codecs.emplace(H264);
#if BUILDFLAG(ENABLE_HEVC_DEMUXING)
  mp4_video_codecs.emplace(HEVC);
#endif  // BUILDFLAG(ENABLE_HEVC_DEMUXING)

#if BUILDFLAG(ENABLE_DOLBY_VISION_DEMUXING)
  mp4_video_codecs.emplace(DOLBY_VISION);
#endif  // BUILDFLAG(ENABLE_DOLBY_VISION_DEMUXING)
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)
#if BUILDFLAG(ENABLE_AV1_DECODER)
  if (base::FeatureList::IsEnabled(kAv1Decoder))
    mp4_video_codecs.emplace(AV1);
#endif

  CodecSet mp4_codecs(mp4_audio_codecs);
  mp4_codecs.insert(mp4_video_codecs.begin(), mp4_video_codecs.end());

  const CodecSet implicit_codec;
  AddContainerWithCodecs("audio/wav", wav_codecs, false);
  AddContainerWithCodecs("audio/x-wav", wav_codecs, false);
  AddContainerWithCodecs("audio/webm", webm_audio_codecs, false);
  DCHECK(!webm_video_codecs.empty());
  AddContainerWithCodecs("video/webm", webm_codecs, false);
  AddContainerWithCodecs("audio/ogg", ogg_audio_codecs, false);
  // video/ogg is only supported if an appropriate video codec is supported.
  // Note: This assumes such codecs cannot be later excluded.
  if (!ogg_video_codecs.empty())
    AddContainerWithCodecs("video/ogg", ogg_codecs, false);
  // TODO(ddorwin): Should the application type support Opus?
  AddContainerWithCodecs("application/ogg", ogg_codecs, false);
  AddContainerWithCodecs("audio/flac", implicit_codec, false);
  AddContainerWithCodecs("audio/mpeg", mp3_codecs, false);  // Allow "mp3".
  AddContainerWithCodecs("audio/mp3", implicit_codec, false);
  AddContainerWithCodecs("audio/x-mp3", implicit_codec, false);
  AddContainerWithCodecs("audio/mp4", mp4_audio_codecs, false);
  DCHECK(!mp4_video_codecs.empty());
  AddContainerWithCodecs("video/mp4", mp4_codecs, false);

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  AddContainerWithCodecs("audio/aac", implicit_codec, true);  // AAC / ADTS.
  // These strings are supported for backwards compatibility only and thus only
  // support the codecs needed for compatibility.
  AddContainerWithCodecs("audio/x-m4a", aac, true);
  AddContainerWithCodecs("video/x-m4v", avc_and_aac, true);

#if BUILDFLAG(ENABLE_MSE_MPEG2TS_STREAM_PARSER)
  // TODO(ddorwin): Exactly which codecs should be supported?
  DCHECK(!mp4_video_codecs.empty());
  AddContainerWithCodecs("video/mp2t", mp4_codecs, true);
#endif  // BUILDFLAG(ENABLE_MSE_MPEG2TS_STREAM_PARSER)
#if defined(OS_ANDROID)
  // HTTP Live Streaming (HLS).
  CodecSet hls_codecs{H264,
                      // TODO(ddorwin): Is any MP3 codec string variant included
                      // in real queries?
                      MP3,
                      // Android HLS only supports MPEG4_AAC (missing demuxer
                      // support for MPEG2_AAC)
                      MPEG4_AAC};
  AddContainerWithCodecs("application/x-mpegurl", hls_codecs, true);
  AddContainerWithCodecs("application/vnd.apple.mpegurl", hls_codecs, true);
  AddContainerWithCodecs("audio/mpegurl", hls_codecs, true);
  // Not documented by Apple, but unfortunately used extensively by Apple and
  // others for both audio-only and audio+video playlists. See
  // https://crbug.com/675552 for details and examples.
  AddContainerWithCodecs("audio/x-mpegurl", hls_codecs, true);
#endif  // defined(OS_ANDROID)
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)
}

void MimeUtil::AddContainerWithCodecs(const std::string& mime_type,
                                      const CodecSet& codecs,
                                      bool is_proprietary_mime_type) {
#if !BUILDFLAG(USE_PROPRIETARY_CODECS)
  DCHECK(!is_proprietary_mime_type);
#endif

  media_format_map_[mime_type] = codecs;

  if (is_proprietary_mime_type)
    proprietary_media_containers_.push_back(mime_type);
}

bool MimeUtil::IsSupportedMediaMimeType(const std::string& mime_type) const {
  return media_format_map_.find(base::ToLowerASCII(mime_type)) !=
         media_format_map_.end();
}

void MimeUtil::SplitCodecsToVector(const std::string& codecs,
                                   std::vector<std::string>* codecs_out,
                                   bool strip) {
  *codecs_out =
      base::SplitString(base::TrimString(codecs, "\"", base::TRIM_ALL), ",",
                        base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);

  // Convert empty or all-whitespace input to 0 results.
  if (codecs_out->size() == 1 && (*codecs_out)[0].empty())
    codecs_out->clear();

  if (!strip)
    return;

  // Strip everything past the first '.'
  for (std::vector<std::string>::iterator it = codecs_out->begin();
       it != codecs_out->end(); ++it) {
    size_t found = it->find_first_of('.');
    if (found != std::string::npos)
      it->resize(found);
  }
}

bool MimeUtil::ParseVideoCodecString(const std::string& mime_type,
                                     const std::string& codec_id,
                                     bool* out_is_ambiguous,
                                     VideoCodec* out_codec,
                                     VideoCodecProfile* out_profile,
                                     uint8_t* out_level,
                                     VideoColorSpace* out_color_space) {
  DCHECK(out_is_ambiguous);
  DCHECK(out_codec);
  DCHECK(out_profile);
  DCHECK(out_level);
  DCHECK(out_color_space);

  // Internal parsing API expects a vector of codecs.
  std::vector<ParsedCodecResult> parsed_results;
  std::vector<std::string> codec_strings;
  if (!codec_id.empty())
    codec_strings.push_back(codec_id);

  if (!ParseCodecStrings(base::ToLowerASCII(mime_type), codec_strings,
                         &parsed_results)) {
    DVLOG(3) << __func__ << " Failed to parse mime/codec pair:" << mime_type
             << "; " << codec_id;
    return false;
  }

  CHECK_EQ(1U, parsed_results.size());
  *out_is_ambiguous = parsed_results[0].is_ambiguous;
  *out_codec = MimeUtilToVideoCodec(parsed_results[0].codec);
  *out_profile = parsed_results[0].video_profile;
  *out_level = parsed_results[0].video_level;
  *out_color_space = parsed_results[0].video_color_space;

  if (*out_codec == kUnknownVideoCodec) {
    DVLOG(3) << __func__ << " Codec string " << codec_id
             << " is not a VIDEO codec.";
    return false;
  }

  return true;
}

bool MimeUtil::ParseAudioCodecString(const std::string& mime_type,
                                     const std::string& codec_id,
                                     bool* out_is_ambiguous,
                                     AudioCodec* out_codec) {
  DCHECK(out_is_ambiguous);
  DCHECK(out_codec);

  // Internal parsing API expects a vector of codecs.
  std::vector<ParsedCodecResult> parsed_results;
  std::vector<std::string> codec_strings;
  if (!codec_id.empty())
    codec_strings.push_back(codec_id);

  if (!ParseCodecStrings(base::ToLowerASCII(mime_type), codec_strings,
                         &parsed_results)) {
    DVLOG(3) << __func__ << " Failed to parse mime/codec pair:" << mime_type
             << "; " << codec_id;
    return false;
  }

  CHECK_EQ(1U, parsed_results.size());
  *out_is_ambiguous = parsed_results[0].is_ambiguous;
  *out_codec = MimeUtilToAudioCodec(parsed_results[0].codec);

  if (*out_codec == kUnknownAudioCodec) {
    DVLOG(3) << __func__ << " Codec string " << codec_id
             << " is not an AUDIO codec.";
    return false;
  }

  return true;
}

SupportsType MimeUtil::IsSupportedMediaFormat(
    const std::string& mime_type,
    const std::vector<std::string>& codecs,
    bool is_encrypted) const {
  const std::string mime_type_lower_case = base::ToLowerASCII(mime_type);
  std::vector<ParsedCodecResult> parsed_results;
  if (!ParseCodecStrings(mime_type_lower_case, codecs, &parsed_results)) {
    DVLOG(3) << __func__ << " Media format unsupported; codec parsing failed "
             << mime_type << " " << base::JoinString(codecs, ",");
    return IsNotSupported;
  }

  if (parsed_results.empty()) {
    NOTREACHED() << __func__ << " Successful parsing should output results.";
    return IsNotSupported;
  }

  // We get here if the mime type expects to get a codecs parameter
  // but none was provided and no default codec was implied. In this case
  // the best we can do is say "maybe" because we don't have enough
  // information.
  if (codecs.empty() && parsed_results.size() == 1 &&
      parsed_results[0].codec == INVALID_CODEC) {
    DCHECK(parsed_results[0].is_ambiguous);
    return MayBeSupported;
  }

  return AreSupportedCodecs(parsed_results, mime_type_lower_case, is_encrypted);
}

// static
bool MimeUtil::IsCodecSupportedOnAndroid(
    Codec codec,
    const std::string& mime_type_lower_case,
    bool is_encrypted,
    const PlatformInfo& platform_info) {
  DVLOG(3) << __func__;
  DCHECK_NE(mime_type_lower_case, "");

  // Encrypted block support is never available without platform decoders.
  if (is_encrypted && !platform_info.has_platform_decoders)
    return false;

  // NOTE: We do not account for Media Source Extensions (MSE) within these
  // checks since it has its own isTypeSupported() which will handle platform
  // specific codec rejections.  See http://crbug.com/587303.

  switch (codec) {
    // ----------------------------------------------------------------------
    // The following codecs are never supported.
    // ----------------------------------------------------------------------
    case INVALID_CODEC:
    case THEORA:
      return false;

    // AV1 is not supported on Android yet.
    case AV1:
      return false;

    // ----------------------------------------------------------------------
    // The remaining codecs may be supported depending on platform abilities.
    // ----------------------------------------------------------------------
    case MPEG2_AAC:
      // MPEG2_AAC cannot be used in HLS (mpegurl suffix), but this is enforced
      // in the parsing step by excluding MPEG2_AAC from the list of
      // valid codecs to be used with HLS mime types.
      DCHECK(!base::EndsWith(mime_type_lower_case, "mpegurl",
                             base::CompareCase::SENSITIVE));
      FALLTHROUGH;
    case PCM:
    case MP3:
    case MPEG4_AAC:
    case FLAC:
    case VORBIS:
      // These codecs are always supported; via a platform decoder (when used
      // with MSE/EME), a software decoder (the unified pipeline), or with
      // MediaPlayer.
      DCHECK(!is_encrypted || platform_info.has_platform_decoders);
      return true;

    case OPUS:
      // If clear, the unified pipeline can always decode Opus in software.
      if (!is_encrypted)
        return true;

      // Otherwise, platform support is required.
      if (!platform_info.supports_opus) {
        DVLOG(3) << "Platform does not support opus";
        return false;
      }

      // MediaPlayer does not support Opus in ogg containers.
      if (base::EndsWith(mime_type_lower_case, "ogg",
                         base::CompareCase::SENSITIVE)) {
        return false;
      }

      DCHECK(!is_encrypted || platform_info.has_platform_decoders);
      return true;

    case H264:
      // When content is not encrypted we fall back to MediaPlayer, thus we
      // always support H264. For EME we need MediaCodec.
      return !is_encrypted || platform_info.has_platform_decoders;

    case HEVC:
#if BUILDFLAG(ENABLE_HEVC_DEMUXING)
      if (!platform_info.has_platform_decoders)
        return false;

#if defined(OS_ANDROID)
      // HEVC/H.265 is supported in Lollipop+ (API Level 21), according to
      // http://developer.android.com/reference/android/media/MediaFormat.html
      return base::android::BuildInfo::GetInstance()->sdk_int() >=
             base::android::SDK_VERSION_LOLLIPOP;
#else
      return true;
#endif  // defined(OS_ANDROID)
#else
      return false;
#endif  // BUILDFLAG(ENABLE_HEVC_DEMUXING)

    case VP8:
      // If clear, the unified pipeline can always decode VP8 in software.
      if (!is_encrypted)
        return true;

      if (is_encrypted)
        return platform_info.has_platform_vp8_decoder;

      // MediaPlayer can always play VP8. Note: This is incorrect for MSE, but
      // MSE does not use this code. http://crbug.com/587303.
      return true;

    case VP9: {
      if (base::CommandLine::ForCurrentProcess()->HasSwitch(
              switches::kReportVp9AsAnUnsupportedMimeType)) {
        return false;
      }

      // If clear, the unified pipeline can always decode VP9 in software.
      if (!is_encrypted)
        return true;

      if (!platform_info.has_platform_vp9_decoder)
        return false;

      // Encrypted content is demuxed so the container is irrelevant.
      if (is_encrypted)
        return true;

      // MediaPlayer only supports VP9 in WebM.
      return mime_type_lower_case == "video/webm";
    }

    case DOLBY_VISION:
      // This function is only called on Android which doesn't support Dolby
      // Vision.
      return false;

    case AC3:
    case EAC3:
#if BUILDFLAG(ENABLE_AC3_EAC3_AUDIO_DEMUXING)
      return true;
#else
      return false;
#endif
  }

  return false;
}

// Make a default ParsedCodecResult. Values should indicate "unspecified"
// where possible. Color space is an exception where we choose a default value
// because most codec strings will not describe a color space.
MimeUtil::ParsedCodecResult MakeDefaultParsedCodecResult() {
  return {
      MimeUtil::INVALID_CODEC, false, VIDEO_CODEC_PROFILE_UNKNOWN, 0,
      // We choose 709 as default color space elsewhere, so defaulting to 709
      // here as well. See here for context: https://crrev.com/1221903003/
      VideoColorSpace::REC709()};
}

bool MimeUtil::ParseCodecStrings(
    const std::string& mime_type_lower_case,
    const std::vector<std::string>& codecs,
    std::vector<ParsedCodecResult>* out_results) const {
  DCHECK(out_results);

  // Reject unrecognized mime types.
  MediaFormatMappings::const_iterator it_media_format_map =
      media_format_map_.find(mime_type_lower_case);
  if (it_media_format_map == media_format_map_.end()) {
    DVLOG(3) << __func__ << " Unrecognized mime type: " << mime_type_lower_case;
    return false;
  }

  const CodecSet& valid_codecs = it_media_format_map->second;
  if (valid_codecs.empty()) {
    // We get here if the mimetype does not expect a codecs parameter.
    if (!codecs.empty()) {
      DVLOG(3) << __func__
               << " Codecs unexpected for mime type:" << mime_type_lower_case;
      return false;
    }

    // Determine implied codec for mime type.
    ParsedCodecResult implied_result = MakeDefaultParsedCodecResult();
    if (!GetDefaultCodec(mime_type_lower_case, &implied_result.codec)) {
      NOTREACHED() << " Mime types must offer a default codec if no explicit "
                      "codecs are expected";
      return false;
    }
    out_results->push_back(implied_result);
    return true;
  }

  if (codecs.empty()) {
    // We get here if the mimetype expects to get a codecs parameter,
    // but didn't get one. If |mime_type_lower_case| does not have a default
    // codec, the string is considered ambiguous.
    ParsedCodecResult implied_result = MakeDefaultParsedCodecResult();
    implied_result.is_ambiguous =
        !GetDefaultCodec(mime_type_lower_case, &implied_result.codec);
    out_results->push_back(implied_result);
    return true;
  }

  // With empty cases handled, parse given codecs and check that they are valid
  // for combining with given mime type.
  for (std::string codec_string : codecs) {
    ParsedCodecResult result;

#if BUILDFLAG(ENABLE_MSE_MPEG2TS_STREAM_PARSER)
    if (mime_type_lower_case == "video/mp2t")
      codec_string = TranslateLegacyAvc1CodecIds(codec_string);
#endif

    if (!ParseCodecHelper(mime_type_lower_case, codec_string, &result)) {
      DVLOG(3) << __func__
               << " Failed to parse mime/codec pair: " << mime_type_lower_case
               << "; " << codec_string;
      return false;
    }
    DCHECK_NE(INVALID_CODEC, result.codec);

    // Fail if mime + codec is not a valid combination.
    if (valid_codecs.find(result.codec) == valid_codecs.end()) {
      DVLOG(3) << __func__
               << " Incompatible mime/codec pair: " << mime_type_lower_case
               << "; " << codec_string;
      return false;
    }

    out_results->push_back(result);
  }

  return true;
}

bool MimeUtil::ParseCodecHelper(const std::string& mime_type_lower_case,
                                const std::string& codec_id,
                                ParsedCodecResult* out_result) const {
  DCHECK_EQ(base::ToLowerASCII(mime_type_lower_case), mime_type_lower_case);
  DCHECK(out_result);

  *out_result = MakeDefaultParsedCodecResult();

  // Simple codecs can be found in the codec map.
  base::flat_map<std::string, Codec>::const_iterator itr =
      GetStringToCodecMap().find(codec_id);
  if (itr != GetStringToCodecMap().end()) {
    out_result->codec = itr->second;

    // Even "simple" video codecs should have an associated profile.
    if (MimeUtilToVideoCodec(out_result->codec) != kUnknownVideoCodec) {
      switch (out_result->codec) {
        case Codec::VP8:
          out_result->video_profile = VP8PROFILE_ANY;
          break;
        case Codec::THEORA:
          out_result->video_profile = THEORAPROFILE_ANY;
          break;
        case Codec::AV1: {
#if BUILDFLAG(ENABLE_AV1_DECODER)
          if (base::FeatureList::IsEnabled(kAv1Decoder)) {
            out_result->video_profile = AV1PROFILE_PROFILE0;
            break;
          }
#endif
          return false;
        }

        default:
          NOTREACHED();
      }
    }

    return true;
  }

  // Check codec string against short list of allowed ambiguous codecs.
  // Hard-coded to discourage expansion. DO NOT ADD TO THIS LIST. DO NOT
  // INCREASE PLACES WHERE |ambiguous_codec_string| = true.
  // NOTE: avc1/avc3.XXXXXX may be ambiguous handled after ParseAVCCodecId().
  if (codec_id == "avc1" || codec_id == "avc3") {
    out_result->codec = MimeUtil::H264;
    out_result->is_ambiguous = true;
    return true;
  } else if (codec_id == "mp4a.40") {
    out_result->codec = MimeUtil::MPEG4_AAC;
    out_result->is_ambiguous = true;
    return true;
  }

  // If |codec_id| is not in |kStringToCodecMap|, then we assume that it is
  // either VP9, H.264 or HEVC/H.265 codec ID because currently those are the
  // only ones that are not added to the |kStringToCodecMap| and require
  // parsing.
  VideoCodecProfile* out_profile = &out_result->video_profile;
  uint8_t* out_level = &out_result->video_level;
  VideoColorSpace* out_color_space = &out_result->video_color_space;
  if (ParseVp9CodecID(mime_type_lower_case, codec_id, out_profile, out_level,
                      out_color_space)) {
    out_result->codec = MimeUtil::VP9;
    // Original VP9 codec string did not describe the profile.
    if (out_result->video_profile == VIDEO_CODEC_PROFILE_UNKNOWN) {
      // New VP9 string should never be ambiguous.
      DCHECK(!base::StartsWith(codec_id, "vp09", base::CompareCase::SENSITIVE));
      out_result->is_ambiguous = true;
    }
    return true;
  }

  if (ParseAVCCodecId(codec_id, out_profile, out_level)) {
    out_result->codec = MimeUtil::H264;
    // Allowed string ambiguity since 2014. DO NOT ADD NEW CASES FOR AMBIGUITY.
    out_result->is_ambiguous = !IsValidH264Level(*out_level);
    return true;
  }

#if BUILDFLAG(ENABLE_HEVC_DEMUXING)
  if (ParseHEVCCodecId(codec_id, out_profile, out_level)) {
    out_result->codec = MimeUtil::HEVC;
    return true;
  }
#endif

#if BUILDFLAG(ENABLE_DOLBY_VISION_DEMUXING)
  if (ParseDolbyVisionCodecId(codec_id, out_profile, out_level)) {
    out_result->codec = MimeUtil::DOLBY_VISION;
    return true;
  }
#endif

  DVLOG(2) << __func__ << ": Unrecognized codec id \"" << codec_id << "\"";
  return false;
}

SupportsType MimeUtil::IsCodecSupported(const std::string& mime_type_lower_case,
                                        Codec codec,
                                        VideoCodecProfile video_profile,
                                        uint8_t video_level,
                                        const VideoColorSpace& color_space,
                                        bool is_encrypted) const {
  DVLOG(3) << __func__;

  DCHECK_EQ(base::ToLowerASCII(mime_type_lower_case), mime_type_lower_case);
  DCHECK_NE(codec, INVALID_CODEC);

  VideoCodec video_codec = MimeUtilToVideoCodec(codec);
  if (video_codec != kUnknownVideoCodec &&
      // Theora and VP8 do not have profiles/levels.
      video_codec != kCodecTheora && video_codec != kCodecVP8 &&
      // TODO(dalecurtis): AV1 has levels, but they aren't supported yet;
      // http://crbug.com/784993
      video_codec != kCodecAV1) {
    DCHECK_NE(video_profile, VIDEO_CODEC_PROFILE_UNKNOWN);
    DCHECK_GT(video_level, 0);
  }

  // Bail early for disabled proprietary codecs
  if (!allow_proprietary_codecs_ && IsCodecProprietary(codec)) {
    return IsNotSupported;
  }

  // Check for cases of ambiguous platform support.
  // TODO(chcunningham): DELETE THIS. Platform should know its capabilities.
  // Answer should come from MediaClient.
  bool ambiguous_platform_support = false;
  if (codec == MimeUtil::H264) {
    switch (video_profile) {
      // Always supported
      case H264PROFILE_BASELINE:
      case H264PROFILE_MAIN:
      case H264PROFILE_HIGH:
        break;
// HIGH10PROFILE is supported through fallback to the ffmpeg decoder
// which is not available on Android, or if FFMPEG is not used.
#if BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS)
      case H264PROFILE_HIGH10PROFILE:
        // FFmpeg is not generally used for encrypted videos, so we do not
        // know whether 10-bit is supported.
        ambiguous_platform_support = is_encrypted;
        break;
#endif
      default:
        ambiguous_platform_support = true;
    }
  } else if (codec == MimeUtil::VP9 && video_profile != VP9PROFILE_PROFILE0 &&
             is_encrypted) {
    // LibVPX is not generally used for encrypted videos, so we do not know
    // whether higher profiles are supported.
    // TODO(chcunningham/xhwang): Add details to indicate which key system will
    // be used and check support by querying the matching KeySystemProperties.
    ambiguous_platform_support = true;
  }

  AudioCodec audio_codec = MimeUtilToAudioCodec(codec);
  if (audio_codec != kUnknownAudioCodec) {
    AudioConfig audio_config = {audio_codec};

    // If MediaClient is provided use it to check for decoder support.
    MediaClient* media_client = GetMediaClient();
    if (media_client && !media_client->IsSupportedAudioConfig(audio_config))
      return IsNotSupported;

    // When no MediaClient is provided, assume default decoders are available
    // as described by media::IsSupportedAudioConfig().
    if (!media_client && !IsSupportedAudioConfig(audio_config))
      return IsNotSupported;
  }

  if (video_codec != kUnknownVideoCodec) {
    VideoConfig video_config = {video_codec, video_profile, video_level,
                                color_space};

    // If MediaClient is provided use it to check for decoder support.
    MediaClient* media_client = GetMediaClient();
    if (media_client && !media_client->IsSupportedVideoConfig(video_config))
      return IsNotSupported;

    // When no MediaClient is provided, assume default decoders are available
    // as described by media::IsSupportedVideoConfig().
    if (!media_client && !IsSupportedVideoConfig(video_config))
      return IsNotSupported;
  }

#if defined(OS_ANDROID)
  // TODO(chcunningham): Delete this. Android platform support should be
  // handled by (android specific) media::IsSupportedVideoConfig() above.
  if (!IsCodecSupportedOnAndroid(codec, mime_type_lower_case, is_encrypted,
                                 platform_info_)) {
    return IsNotSupported;
  }
#endif

  return ambiguous_platform_support ? MayBeSupported : IsSupported;
}

bool MimeUtil::IsCodecProprietary(Codec codec) const {
  switch (codec) {
    case INVALID_CODEC:
    case AC3:
    case EAC3:
    case MPEG2_AAC:
    case MPEG4_AAC:
    case H264:
    case HEVC:
    case DOLBY_VISION:
      return true;

    case MP3:
    case PCM:
    case VORBIS:
    case OPUS:
    case FLAC:
    case VP8:
    case VP9:
    case THEORA:
    case AV1:
      return false;
  }

  return true;
}

bool MimeUtil::GetDefaultCodec(const std::string& mime_type,
                               Codec* default_codec) const {
  // Codecs below are unambiguously implied by the mime type string. DO NOT add
  // default codecs for ambiguous mime types.

  if (mime_type == "audio/mpeg" || mime_type == "audio/mp3" ||
      mime_type == "audio/x-mp3") {
    *default_codec = MimeUtil::MP3;
    return true;
  }

  if (mime_type == "audio/aac") {
    *default_codec = MimeUtil::MPEG4_AAC;
    return true;
  }

  if (mime_type == "audio/flac") {
    *default_codec = MimeUtil::FLAC;
    return true;
  }

  return false;
}

}  // namespace internal
}  // namespace media

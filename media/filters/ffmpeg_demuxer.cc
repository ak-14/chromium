// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media/filters/ffmpeg_demuxer.h"

#include <algorithm>
#include <memory>
#include <set>
#include <utility>

#include "base/base64.h"
#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/sys_byteorder.h"
#include "base/task_runner_util.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "media/base/bind_to_current_loop.h"
#include "media/base/decrypt_config.h"
#include "media/base/demuxer_memory_limit.h"
#include "media/base/limits.h"
#include "media/base/media_log.h"
#include "media/base/media_tracks.h"
#include "media/base/sample_rates.h"
#include "media/base/timestamp_constants.h"
#include "media/base/video_codecs.h"
#include "media/base/webvtt_util.h"
#include "media/ffmpeg/ffmpeg_common.h"
#include "media/filters/ffmpeg_aac_bitstream_converter.h"
#include "media/filters/ffmpeg_bitstream_converter.h"
#include "media/filters/ffmpeg_glue.h"
#include "media/filters/ffmpeg_h264_to_annex_b_bitstream_converter.h"
#include "media/formats/mpeg/mpeg1_audio_stream_parser.h"
#include "media/formats/webm/webm_crypto_helpers.h"
#include "media/media_buildflags.h"
#include "third_party/ffmpeg/ffmpeg_features.h"

#if BUILDFLAG(ENABLE_HEVC_DEMUXING)
#include "media/filters/ffmpeg_h265_to_annex_b_bitstream_converter.h"
#endif

namespace media {

namespace {

void SetAVStreamDiscard(AVStream* stream, AVDiscard discard) {
  DCHECK(stream);
  stream->discard = discard;
}

}  // namespace

static base::Time ExtractTimelineOffset(
    container_names::MediaContainerName container,
    const AVFormatContext* format_context) {
  if (container == container_names::CONTAINER_WEBM) {
    const AVDictionaryEntry* entry =
        av_dict_get(format_context->metadata, "creation_time", NULL, 0);

    base::Time timeline_offset;

    // FFmpegDemuxerTests assume base::Time::FromUTCString() is used here.
    if (entry != NULL && entry->value != NULL &&
        base::Time::FromUTCString(entry->value, &timeline_offset)) {
      return timeline_offset;
    }
  }

  return base::Time();
}

static base::TimeDelta FramesToTimeDelta(int frames, double sample_rate) {
  return base::TimeDelta::FromMicroseconds(
      frames * base::Time::kMicrosecondsPerSecond / sample_rate);
}

static base::TimeDelta ExtractStartTime(AVStream* stream,
                                        base::TimeDelta start_time_estimate) {
  DCHECK(start_time_estimate != kNoTimestamp);
  if (stream->start_time == static_cast<int64_t>(AV_NOPTS_VALUE)) {
    return start_time_estimate == kInfiniteDuration ? base::TimeDelta()
                                                    : start_time_estimate;
  }

  // First try the lower of the estimate and the |start_time| value.
  base::TimeDelta start_time =
      std::min(ConvertFromTimeBase(stream->time_base, stream->start_time),
               start_time_estimate);

  // Next see if the first buffered pts value is usable.
  if (stream->pts_buffer[0] != static_cast<int64_t>(AV_NOPTS_VALUE)) {
    const base::TimeDelta buffered_pts =
        ConvertFromTimeBase(stream->time_base, stream->pts_buffer[0]);
    if (buffered_pts < start_time)
      start_time = buffered_pts;
  }

  // NOTE: Do not use AVStream->first_dts since |start_time| should be a
  // presentation timestamp.
  return start_time;
}

// Some videos just want to watch the world burn, with a height of 0; cap the
// "infinite" aspect ratio resulting.
const int kInfiniteRatio = 99999;

// Common aspect ratios (multiplied by 100 and truncated) used for histogramming
// video sizes.  These were taken on 20111103 from
// http://wikipedia.org/wiki/Aspect_ratio_(image)#Previous_and_currently_used_aspect_ratios
const int kCommonAspectRatios100[] = {
    100, 115, 133, 137, 143, 150, 155, 160,  166,
    175, 177, 185, 200, 210, 220, 221, 235,  237,
    240, 255, 259, 266, 276, 293, 400, 1200, kInfiniteRatio,
};

template <class T>  // T has int width() & height() methods.
static void UmaHistogramAspectRatio(const char* name, const T& size) {
  UMA_HISTOGRAM_CUSTOM_ENUMERATION(
      name,
      // Intentionally use integer division to truncate the result.
      size.height() ? (size.width() * 100) / size.height() : kInfiniteRatio,
      base::CustomHistogram::ArrayToCustomRanges(
          kCommonAspectRatios100, arraysize(kCommonAspectRatios100)));
}

// Record detected track counts by type corresponding to a src= playback.
// Counts are split into 50 buckets, capped into [0,100] range.
static void RecordDetectedTrackTypeStats(int audio_count,
                                         int video_count,
                                         int text_count) {
  UMA_HISTOGRAM_COUNTS_100("Media.DetectedTrackCount.Audio", audio_count);
  UMA_HISTOGRAM_COUNTS_100("Media.DetectedTrackCount.Video", video_count);
  UMA_HISTOGRAM_COUNTS_100("Media.DetectedTrackCount.Text", text_count);
}

// Record audio decoder config UMA stats corresponding to a src= playback.
static void RecordAudioCodecStats(const AudioDecoderConfig& audio_config) {
  UMA_HISTOGRAM_ENUMERATION("Media.AudioCodec", audio_config.codec(),
                            kAudioCodecMax + 1);
  UMA_HISTOGRAM_ENUMERATION("Media.AudioSampleFormat",
                            audio_config.sample_format(), kSampleFormatMax + 1);
  UMA_HISTOGRAM_ENUMERATION("Media.AudioChannelLayout",
                            audio_config.channel_layout(),
                            CHANNEL_LAYOUT_MAX + 1);
  AudioSampleRate asr;
  if (ToAudioSampleRate(audio_config.samples_per_second(), &asr)) {
    UMA_HISTOGRAM_ENUMERATION("Media.AudioSamplesPerSecond", asr,
                              kAudioSampleRateMax + 1);
  } else {
    UMA_HISTOGRAM_COUNTS("Media.AudioSamplesPerSecondUnexpected",
                         audio_config.samples_per_second());
  }
}

// Record video decoder config UMA stats corresponding to a src= playback.
static void RecordVideoCodecStats(container_names::MediaContainerName container,
                                  const VideoDecoderConfig& video_config,
                                  AVColorRange color_range,
                                  MediaLog* media_log) {
  media_log->RecordRapporWithSecurityOrigin("Media.OriginUrl.SRC.VideoCodec." +
                                            GetCodecName(video_config.codec()));

  // TODO(xhwang): Fix these misleading metric names. They should be something
  // like "Media.SRC.Xxxx". See http://crbug.com/716183.
  UMA_HISTOGRAM_ENUMERATION("Media.VideoCodec", video_config.codec(),
                            kVideoCodecMax + 1);
  if (container == container_names::CONTAINER_MOV) {
    UMA_HISTOGRAM_ENUMERATION("Media.SRC.VideoCodec.MP4", video_config.codec(),
                              kVideoCodecMax + 1);
  } else if (container == container_names::CONTAINER_WEBM) {
    UMA_HISTOGRAM_ENUMERATION("Media.SRC.VideoCodec.WebM", video_config.codec(),
                              kVideoCodecMax + 1);
  }

  // Drop UNKNOWN because U_H_E() uses one bucket for all values less than 1.
  if (video_config.profile() >= 0) {
    UMA_HISTOGRAM_ENUMERATION("Media.VideoCodecProfile", video_config.profile(),
                              VIDEO_CODEC_PROFILE_MAX + 1);
  }
  UMA_HISTOGRAM_COUNTS_10000("Media.VideoVisibleWidth",
                             video_config.visible_rect().width());
  UmaHistogramAspectRatio("Media.VideoVisibleAspectRatio",
                          video_config.visible_rect());
  UMA_HISTOGRAM_ENUMERATION("Media.VideoPixelFormatUnion",
                            video_config.format(), PIXEL_FORMAT_MAX + 1);
  UMA_HISTOGRAM_ENUMERATION("Media.VideoFrameColorSpace",
                            video_config.color_space(), COLOR_SPACE_MAX + 1);

  // Note the PRESUBMIT_IGNORE_UMA_MAX below, this silences the PRESUBMIT.py
  // check for uma enum max usage, since we're abusing
  // UMA_HISTOGRAM_ENUMERATION to report a discrete value.
  UMA_HISTOGRAM_ENUMERATION("Media.VideoColorRange", color_range,
                            AVCOL_RANGE_NB);  // PRESUBMIT_IGNORE_UMA_MAX
}

static const char kCodecNone[] = "none";

static const char* GetCodecName(enum AVCodecID id) {
  const AVCodecDescriptor* codec_descriptor = avcodec_descriptor_get(id);
  // If the codec name can't be determined, return none for tracking.
  return codec_descriptor ? codec_descriptor->name : kCodecNone;
}

static void SetTimeProperty(MediaLogEvent* event,
                            const std::string& key,
                            base::TimeDelta value) {
  if (value == kInfiniteDuration)
    event->params.SetString(key, "kInfiniteDuration");
  else if (value == kNoTimestamp)
    event->params.SetString(key, "kNoTimestamp");
  else
    event->params.SetDouble(key, value.InSecondsF());
}

std::unique_ptr<FFmpegDemuxerStream> FFmpegDemuxerStream::Create(
    FFmpegDemuxer* demuxer,
    AVStream* stream,
    MediaLog* media_log) {
  if (!demuxer || !stream)
    return nullptr;

  std::unique_ptr<FFmpegDemuxerStream> demuxer_stream;
  std::unique_ptr<AudioDecoderConfig> audio_config;
  std::unique_ptr<VideoDecoderConfig> video_config;

  if (stream->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
    audio_config.reset(new AudioDecoderConfig());

    // IsValidConfig() checks that the codec is supported and that the channel
    // layout and sample format are valid.
    //
    // TODO(chcunningham): Change AVStreamToAudioDecoderConfig to check
    // IsValidConfig internally and return a null scoped_ptr if not valid.
    if (!AVStreamToAudioDecoderConfig(stream, audio_config.get()) ||
        !audio_config->IsValidConfig()) {
      MEDIA_LOG(DEBUG, media_log) << "Warning, FFmpegDemuxer failed to create "
                                     "a valid audio decoder configuration from "
                                     "muxed stream";
      return nullptr;
    }

    MEDIA_LOG(INFO, media_log) << "FFmpegDemuxer: created audio stream, config "
                               << audio_config->AsHumanReadableString();
  } else if (stream->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
    video_config.reset(new VideoDecoderConfig());

    // IsValidConfig() checks that the codec is supported and that the channel
    // layout and sample format are valid.
    //
    // TODO(chcunningham): Change AVStreamToVideoDecoderConfig to check
    // IsValidConfig internally and return a null scoped_ptr if not valid.
    if (!AVStreamToVideoDecoderConfig(stream, video_config.get()) ||
        !video_config->IsValidConfig()) {
      MEDIA_LOG(DEBUG, media_log) << "Warning, FFmpegDemuxer failed to create "
                                     "a valid video decoder configuration from "
                                     "muxed stream";
      return nullptr;
    }

    MEDIA_LOG(INFO, media_log) << "FFmpegDemuxer: created video stream, config "
                               << video_config->AsHumanReadableString();
  }

  return base::WrapUnique(
      new FFmpegDemuxerStream(demuxer, stream, std::move(audio_config),
                              std::move(video_config), media_log));
}

static void UnmarkEndOfStreamAndClearError(AVFormatContext* format_context) {
  format_context->pb->eof_reached = 0;
  format_context->pb->error = 0;
}

//
// FFmpegDemuxerStream
//
FFmpegDemuxerStream::FFmpegDemuxerStream(
    FFmpegDemuxer* demuxer,
    AVStream* stream,
    std::unique_ptr<AudioDecoderConfig> audio_config,
    std::unique_ptr<VideoDecoderConfig> video_config,
    MediaLog* media_log)
    : demuxer_(demuxer),
      task_runner_(base::ThreadTaskRunnerHandle::Get()),
      stream_(stream),
      start_time_(kNoTimestamp),
      audio_config_(audio_config.release()),
      video_config_(video_config.release()),
      media_log_(media_log),
      type_(UNKNOWN),
      liveness_(LIVENESS_UNKNOWN),
      end_of_stream_(false),
      last_packet_timestamp_(kNoTimestamp),
      last_packet_duration_(kNoTimestamp),
      is_enabled_(true),
      waiting_for_keyframe_(false),
      aborted_(false),
      fixup_negative_timestamps_(false),
      fixup_chained_ogg_(false),
      num_discarded_packet_warnings_(0) {
  DCHECK(demuxer_);

  bool is_encrypted = false;

  // Determine our media format.
  switch (stream->codecpar->codec_type) {
    case AVMEDIA_TYPE_AUDIO:
      DCHECK(audio_config_.get() && !video_config_.get());
      type_ = AUDIO;
      is_encrypted = audio_config_->is_encrypted();
      break;
    case AVMEDIA_TYPE_VIDEO:
      DCHECK(video_config_.get() && !audio_config_.get());
      type_ = VIDEO;
      is_encrypted = video_config_->is_encrypted();
      break;
    case AVMEDIA_TYPE_SUBTITLE:
      DCHECK(!video_config_.get() && !audio_config_.get());
      type_ = TEXT;
      break;
    default:
      NOTREACHED();
      break;
  }

  // Calculate the duration.
  duration_ = ConvertStreamTimestamp(stream->time_base, stream->duration);

  if (is_encrypted) {
    AVDictionaryEntry* key = av_dict_get(stream->metadata, "enc_key_id", NULL,
                                         0);
    DCHECK(key);
    DCHECK(key->value);
    if (!key || !key->value)
      return;
    base::StringPiece base64_key_id(key->value);
    std::string enc_key_id;
    base::Base64Decode(base64_key_id, &enc_key_id);
    DCHECK(!enc_key_id.empty());
    if (enc_key_id.empty())
      return;

    encryption_key_id_.assign(enc_key_id);
    demuxer_->OnEncryptedMediaInitData(EmeInitDataType::WEBM, enc_key_id);
  }
}

FFmpegDemuxerStream::~FFmpegDemuxerStream() {
  DCHECK(!demuxer_);
  DCHECK(read_cb_.is_null());
  DCHECK(buffer_queue_.IsEmpty());
}

void FFmpegDemuxerStream::EnqueuePacket(ScopedAVPacket packet) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK(packet->size);
  DCHECK(packet->data);

  if (!demuxer_ || end_of_stream_) {
    NOTREACHED() << "Attempted to enqueue packet on a stopped stream";
    return;
  }

  if (waiting_for_keyframe_) {
    if (packet->flags & AV_PKT_FLAG_KEY)
      waiting_for_keyframe_ = false;
    else {
      DVLOG(3) << "Dropped non-keyframe pts=" << packet->pts;
      return;
    }
  }

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  // Convert the packet if there is a bitstream filter.
  if (bitstream_converter_ &&
      !bitstream_converter_->ConvertPacket(packet.get())) {
    MEDIA_LOG(ERROR, media_log_) << "Format conversion failed.";
  }
#endif

  scoped_refptr<DecoderBuffer> buffer;

  const bool is_audio = type() == AUDIO;
  if (type() == DemuxerStream::TEXT) {
    int id_size = 0;
    uint8_t* id_data = av_packet_get_side_data(
        packet.get(), AV_PKT_DATA_WEBVTT_IDENTIFIER, &id_size);

    int settings_size = 0;
    uint8_t* settings_data = av_packet_get_side_data(
        packet.get(), AV_PKT_DATA_WEBVTT_SETTINGS, &settings_size);

    std::vector<uint8_t> side_data;
    MakeSideData(id_data, id_data + id_size,
                 settings_data, settings_data + settings_size,
                 &side_data);

    buffer = DecoderBuffer::CopyFrom(packet->data, packet->size,
                                     side_data.data(), side_data.size());
  } else {
    int side_data_size = 0;
    uint8_t* side_data = av_packet_get_side_data(
        packet.get(), AV_PKT_DATA_MATROSKA_BLOCKADDITIONAL, &side_data_size);

    std::unique_ptr<DecryptConfig> decrypt_config;
    int data_offset = 0;
    if ((type() == DemuxerStream::AUDIO && audio_config_->is_encrypted()) ||
        (type() == DemuxerStream::VIDEO && video_config_->is_encrypted())) {
      if (!WebMCreateDecryptConfig(
              packet->data, packet->size,
              reinterpret_cast<const uint8_t*>(encryption_key_id_.data()),
              encryption_key_id_.size(), &decrypt_config, &data_offset)) {
        MEDIA_LOG(ERROR, media_log_) << "Creation of DecryptConfig failed.";
      }
    }

    // FFmpeg may return garbage packets for MP3 stream containers, so we need
    // to drop these to avoid decoder errors. The ffmpeg team maintains that
    // this behavior isn't ideal, but have asked for a significant refactoring
    // of the AVParser infrastructure to fix this, which is overkill for now.
    // See http://crbug.com/794782.
    //
    // This behavior may also occur with ADTS streams, but is rarer in practice
    // because ffmpeg's ADTS demuxer does more validation on the packets, so
    // when invalid data is received, av_read_frame() fails and playback ends.
    if (is_audio && demuxer_->container() == container_names::CONTAINER_MP3) {
      DCHECK(!data_offset);  // Only set for containers supporting encryption...

      // MP3 packets may be zero-padded according to ffmpeg, so trim until we
      // have the packet; adjust |data_offset| too so this work isn't repeated.
      uint8_t* packet_end = packet->data + packet->size;
      uint8_t* header_start = packet->data;
      while (header_start < packet_end && !*header_start) {
        ++header_start;
        ++data_offset;
      }

      if (packet_end - header_start < MPEG1AudioStreamParser::kHeaderSize ||
          !MPEG1AudioStreamParser::ParseHeader(nullptr, header_start,
                                               nullptr)) {
        LIMITED_MEDIA_LOG(INFO, media_log_, num_discarded_packet_warnings_, 5)
            << "Discarding invalid MP3 packet, ts: "
            << ConvertStreamTimestamp(stream_->time_base, packet->pts)
            << ", duration: "
            << ConvertStreamTimestamp(stream_->time_base, packet->duration);
        return;
      }
    }

    // If a packet is returned by FFmpeg's av_parser_parse2() the packet will
    // reference inner memory of FFmpeg.  As such we should transfer the packet
    // into memory we control.
    if (side_data_size > 0) {
      buffer = DecoderBuffer::CopyFrom(packet->data + data_offset,
                                       packet->size - data_offset, side_data,
                                       side_data_size);
    } else {
      buffer = DecoderBuffer::CopyFrom(packet->data + data_offset,
                                       packet->size - data_offset);
    }

    int skip_samples_size = 0;
    const uint32_t* skip_samples_ptr =
        reinterpret_cast<const uint32_t*>(av_packet_get_side_data(
            packet.get(), AV_PKT_DATA_SKIP_SAMPLES, &skip_samples_size));
    const int kSkipSamplesValidSize = 10;
    const int kSkipEndSamplesOffset = 1;
    if (skip_samples_size >= kSkipSamplesValidSize) {
      // Because FFmpeg rolls codec delay and skip samples into one we can only
      // allow front discard padding on the first buffer.  Otherwise the discard
      // helper can't figure out which data to discard.  See AudioDiscardHelper.
      int discard_front_samples = base::ByteSwapToLE32(*skip_samples_ptr);
      if (last_packet_timestamp_ != kNoTimestamp && discard_front_samples) {
        DLOG(ERROR) << "Skip samples are only allowed for the first packet.";
        discard_front_samples = 0;
      }

      const int discard_end_samples =
          base::ByteSwapToLE32(*(skip_samples_ptr + kSkipEndSamplesOffset));

      if (discard_front_samples || discard_end_samples) {
        DCHECK(is_audio);
        const int samples_per_second =
            audio_decoder_config().samples_per_second();
        buffer->set_discard_padding(std::make_pair(
            FramesToTimeDelta(discard_front_samples, samples_per_second),
            FramesToTimeDelta(discard_end_samples, samples_per_second)));
      }
    }

    if (decrypt_config)
      buffer->set_decrypt_config(std::move(decrypt_config));
  }

  if (packet->duration >= 0) {
    buffer->set_duration(
        ConvertStreamTimestamp(stream_->time_base, packet->duration));
  } else {
    // TODO(wolenetz): Remove when FFmpeg stops returning negative durations.
    // https://crbug.com/394418
    DVLOG(1) << "FFmpeg returned a buffer with a negative duration! "
             << packet->duration;
    buffer->set_duration(kNoTimestamp);
  }

  // Note: If pts is AV_NOPTS_VALUE, stream_timestamp will be kNoTimestamp.
  const base::TimeDelta stream_timestamp =
      ConvertStreamTimestamp(stream_->time_base, packet->pts);

  if (stream_timestamp == kNoTimestamp) {
    MEDIA_LOG(ERROR, media_log_) << "FFmpegDemuxer: PTS is not defined";
    demuxer_->NotifyDemuxerError(DEMUXER_ERROR_COULD_NOT_PARSE);
    return;
  }

  // If this file has negative timestamps don't rebase any other stream types
  // against the negative starting time.
  base::TimeDelta start_time = demuxer_->start_time();
  if (fixup_negative_timestamps_ && !is_audio &&
      start_time < base::TimeDelta()) {
    start_time = base::TimeDelta();
  }

  // Don't rebase timestamps for positive start times, the HTML Media Spec
  // details this in section "4.8.10.6 Offsets into the media resource." We
  // will still need to rebase timestamps before seeking with FFmpeg though.
  if (start_time > base::TimeDelta())
    start_time = base::TimeDelta();

  buffer->set_timestamp(stream_timestamp - start_time);

  if (packet->flags & AV_PKT_FLAG_DISCARD) {
    buffer->set_discard_padding(
        std::make_pair(kInfiniteDuration, base::TimeDelta()));
    if (buffer->timestamp() < base::TimeDelta()) {
      // These timestamps should never be used, but to ensure they are dropped
      // correctly give them unique timestamps.
      buffer->set_timestamp(last_packet_timestamp_ == kNoTimestamp
                                ? base::TimeDelta()
                                : last_packet_timestamp_ +
                                      base::TimeDelta::FromMicroseconds(1));
    }
  }

  // Only allow negative timestamps past if we know they'll be fixed up by the
  // code paths below; otherwise they should be treated as a parse error.
  if ((!fixup_chained_ogg_ || last_packet_timestamp_ == kNoTimestamp) &&
      buffer->timestamp() < base::TimeDelta()) {
    MEDIA_LOG(DEBUG, media_log_)
        << "FFmpegDemuxer: unfixable negative timestamp";
    demuxer_->NotifyDemuxerError(DEMUXER_ERROR_COULD_NOT_PARSE);
    return;
  }

  // If enabled, and no codec delay is present, mark audio packets with negative
  // timestamps for post-decode discard. If codec delay is present, discard is
  // handled by the decoder using that value.
  if (fixup_negative_timestamps_ && is_audio &&
      stream_timestamp < base::TimeDelta() &&
      buffer->duration() != kNoTimestamp &&
      !audio_decoder_config().codec_delay()) {
    DCHECK_EQ(buffer->discard_padding().first, base::TimeDelta());

    if (stream_timestamp + buffer->duration() < base::TimeDelta()) {
      DCHECK_EQ(buffer->discard_padding().second, base::TimeDelta());

      // Discard the entire packet if it's entirely before zero.
      buffer->set_discard_padding(
          std::make_pair(kInfiniteDuration, base::TimeDelta()));
    } else {
      // Only discard part of the frame if it overlaps zero.
      buffer->set_discard_padding(
          std::make_pair(-stream_timestamp, buffer->discard_padding().second));
    }
  }

  if (last_packet_timestamp_ != kNoTimestamp) {
    // FFmpeg doesn't support chained ogg correctly.  Instead of guaranteeing
    // continuity across links in the chain it uses the timestamp information
    // from each link directly.  Doing so can lead to timestamps which appear to
    // go backwards in time.
    //
    // If the new link starts with a negative timestamp or a timestamp less than
    // the original (positive) |start_time|, we will get a negative timestamp
    // here.
    //
    // Fixing chained ogg is non-trivial, so for now just reuse the last good
    // timestamp.  The decoder will rewrite the timestamps to be sample accurate
    // later.  See http://crbug.com/396864.
    //
    // Note: This will not work with codecs that have out of order frames like
    // H.264 with b-frames, but luckily you can't put those in ogg files...
    if (fixup_chained_ogg_ && buffer->timestamp() < last_packet_timestamp_) {
      buffer->set_timestamp(last_packet_timestamp_ +
                            (last_packet_duration_ != kNoTimestamp
                                 ? last_packet_duration_
                                 : base::TimeDelta::FromMicroseconds(1)));
    }

    // The demuxer should always output positive timestamps.
    DCHECK_GE(buffer->timestamp(), base::TimeDelta());

    if (last_packet_timestamp_ < buffer->timestamp()) {
      buffered_ranges_.Add(last_packet_timestamp_, buffer->timestamp());
      demuxer_->NotifyBufferingChanged();
    }
  }

  if (packet->flags & AV_PKT_FLAG_KEY)
    buffer->set_is_key_frame(true);

  last_packet_timestamp_ = buffer->timestamp();
  last_packet_duration_ = buffer->duration();

  const base::TimeDelta new_duration = last_packet_timestamp_;
  if (new_duration > duration_ || duration_ == kNoTimestamp)
    duration_ = new_duration;

  buffer_queue_.Push(std::move(buffer));
  SatisfyPendingRead();
}

void FFmpegDemuxerStream::SetEndOfStream() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  end_of_stream_ = true;
  SatisfyPendingRead();
}

void FFmpegDemuxerStream::FlushBuffers() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK(read_cb_.is_null()) << "There should be no pending read";

  // H264 and AAC require that we resend the header after flush.
  // Reset bitstream for converter to do so.
  // This is related to chromium issue 140371 (http://crbug.com/140371).
  ResetBitstreamConverter();

  buffer_queue_.Clear();
  end_of_stream_ = false;
  last_packet_timestamp_ = kNoTimestamp;
  last_packet_duration_ = kNoTimestamp;
  aborted_ = false;
}

void FFmpegDemuxerStream::Abort() {
  aborted_ = true;
  if (!read_cb_.is_null())
    base::ResetAndReturn(&read_cb_).Run(DemuxerStream::kAborted, nullptr);
}

void FFmpegDemuxerStream::Stop() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  buffer_queue_.Clear();
  if (!read_cb_.is_null()) {
    base::ResetAndReturn(&read_cb_).Run(
        DemuxerStream::kOk, DecoderBuffer::CreateEOSBuffer());
  }
  demuxer_ = NULL;
  stream_ = NULL;
  end_of_stream_ = true;
}

DemuxerStream::Type FFmpegDemuxerStream::type() const {
  DCHECK(task_runner_->BelongsToCurrentThread());
  return type_;
}

DemuxerStream::Liveness FFmpegDemuxerStream::liveness() const {
  DCHECK(task_runner_->BelongsToCurrentThread());
  return liveness_;
}

void FFmpegDemuxerStream::Read(const ReadCB& read_cb) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  CHECK(read_cb_.is_null()) << "Overlapping reads are not supported";
  read_cb_ = BindToCurrentLoop(read_cb);

  // Don't accept any additional reads if we've been told to stop.
  // The |demuxer_| may have been destroyed in the pipeline thread.
  //
  // TODO(scherkus): it would be cleaner to reply with an error message.
  if (!demuxer_) {
    base::ResetAndReturn(&read_cb_).Run(
        DemuxerStream::kOk, DecoderBuffer::CreateEOSBuffer());
    return;
  }

  if (!is_enabled_) {
    DVLOG(1) << "Read from disabled stream, returning EOS";
    base::ResetAndReturn(&read_cb_).Run(kOk, DecoderBuffer::CreateEOSBuffer());
    return;
  }

  if (aborted_) {
    base::ResetAndReturn(&read_cb_).Run(kAborted, nullptr);
    return;
  }

  SatisfyPendingRead();
}

void FFmpegDemuxerStream::EnableBitstreamConverter() {
  DCHECK(task_runner_->BelongsToCurrentThread());

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  InitBitstreamConverter();
#else
  NOTREACHED() << "Proprietary codecs not enabled.";
#endif
}

void FFmpegDemuxerStream::ResetBitstreamConverter() {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  if (bitstream_converter_)
    InitBitstreamConverter();
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)
}

void FFmpegDemuxerStream::InitBitstreamConverter() {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  switch (stream_->codecpar->codec_id) {
    case AV_CODEC_ID_H264:
      // Clear |extra_data| so that future (fallback) decoders will know that
      // conversion is forcibly enabled on this stream.
      //
      // TODO(sandersd): Ideally we would convert |extra_data| to concatenated
      // SPS/PPS data, but it's too late to be useful because Initialize() was
      // already called on GpuVideoDecoder, which is the only path that would
      // consume that data.
      if (video_config_)
        video_config_->SetExtraData(std::vector<uint8_t>());
      bitstream_converter_.reset(
          new FFmpegH264ToAnnexBBitstreamConverter(stream_->codecpar));
      break;
#if BUILDFLAG(ENABLE_HEVC_DEMUXING)
    case AV_CODEC_ID_HEVC:
      bitstream_converter_.reset(
          new FFmpegH265ToAnnexBBitstreamConverter(stream_->codecpar));
      break;
#endif
    case AV_CODEC_ID_AAC:
      bitstream_converter_.reset(
          new FFmpegAACBitstreamConverter(stream_->codecpar));
      break;
    default:
      break;
  }
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)
}

bool FFmpegDemuxerStream::SupportsConfigChanges() { return false; }

AudioDecoderConfig FFmpegDemuxerStream::audio_decoder_config() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK_EQ(type_, AUDIO);
  DCHECK(audio_config_.get());
  return *audio_config_;
}

VideoDecoderConfig FFmpegDemuxerStream::video_decoder_config() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK_EQ(type_, VIDEO);
  DCHECK(video_config_.get());
  return *video_config_;
}

bool FFmpegDemuxerStream::IsEnabled() const {
  DCHECK(task_runner_->BelongsToCurrentThread());
  return is_enabled_;
}

void FFmpegDemuxerStream::SetEnabled(bool enabled, base::TimeDelta timestamp) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK(demuxer_);
  DCHECK(demuxer_->ffmpeg_task_runner());
  if (enabled == is_enabled_)
    return;

  is_enabled_ = enabled;
  demuxer_->ffmpeg_task_runner()->PostTask(
      FROM_HERE, base::Bind(&SetAVStreamDiscard, av_stream(),
                            enabled ? AVDISCARD_DEFAULT : AVDISCARD_ALL));
  if (is_enabled_) {
    waiting_for_keyframe_ = true;
  }
  if (!is_enabled_ && !read_cb_.is_null()) {
    DVLOG(1) << "Read from disabled stream, returning EOS";
    base::ResetAndReturn(&read_cb_).Run(kOk, DecoderBuffer::CreateEOSBuffer());
  }
}

void FFmpegDemuxerStream::SetLiveness(Liveness liveness) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK_EQ(liveness_, LIVENESS_UNKNOWN);
  liveness_ = liveness;
}

Ranges<base::TimeDelta> FFmpegDemuxerStream::GetBufferedRanges() const {
  return buffered_ranges_;
}

void FFmpegDemuxerStream::SatisfyPendingRead() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  if (!read_cb_.is_null()) {
    if (!buffer_queue_.IsEmpty()) {
      base::ResetAndReturn(&read_cb_).Run(
          DemuxerStream::kOk, buffer_queue_.Pop());
    } else if (end_of_stream_) {
      base::ResetAndReturn(&read_cb_).Run(
          DemuxerStream::kOk, DecoderBuffer::CreateEOSBuffer());
    }
  }

  // Have capacity? Ask for more!
  if (HasAvailableCapacity() && !end_of_stream_) {
    demuxer_->NotifyCapacityAvailable();
  }
}

bool FFmpegDemuxerStream::HasAvailableCapacity() {
  // Try to have two second's worth of encoded data per stream.
  const base::TimeDelta kCapacity = base::TimeDelta::FromSeconds(2);
  return buffer_queue_.IsEmpty() || buffer_queue_.Duration() < kCapacity;
}

size_t FFmpegDemuxerStream::MemoryUsage() const {
  return buffer_queue_.data_size();
}

TextKind FFmpegDemuxerStream::GetTextKind() const {
  DCHECK_EQ(type_, DemuxerStream::TEXT);

  if (stream_->disposition & AV_DISPOSITION_CAPTIONS)
    return kTextCaptions;

  if (stream_->disposition & AV_DISPOSITION_DESCRIPTIONS)
    return kTextDescriptions;

  if (stream_->disposition & AV_DISPOSITION_METADATA)
    return kTextMetadata;

  return kTextSubtitles;
}

std::string FFmpegDemuxerStream::GetMetadata(const char* key) const {
  const AVDictionaryEntry* entry =
      av_dict_get(stream_->metadata, key, NULL, 0);
  return (entry == NULL || entry->value == NULL) ? "" : entry->value;
}

// static
base::TimeDelta FFmpegDemuxerStream::ConvertStreamTimestamp(
    const AVRational& time_base,
    int64_t timestamp) {
  if (timestamp == static_cast<int64_t>(AV_NOPTS_VALUE))
    return kNoTimestamp;

  return ConvertFromTimeBase(time_base, timestamp);
}

//
// FFmpegDemuxer
//
FFmpegDemuxer::FFmpegDemuxer(
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner,
    DataSource* data_source,
    const EncryptedMediaInitDataCB& encrypted_media_init_data_cb,
    const MediaTracksUpdatedCB& media_tracks_updated_cb,
    MediaLog* media_log)
    : host_(NULL),
      task_runner_(task_runner),
      // FFmpeg has no asynchronous API, so we use base::WaitableEvents inside
      // the BlockingUrlProtocol to handle hops to the render thread for network
      // reads and seeks.
      blocking_task_runner_(base::CreateSequencedTaskRunnerWithTraits(
          {base::MayBlock(), base::TaskPriority::USER_BLOCKING})),
      stopped_(false),
      pending_read_(false),
      data_source_(data_source),
      media_log_(media_log),
      bitrate_(0),
      start_time_(kNoTimestamp),
      text_enabled_(false),
      duration_known_(false),
      encrypted_media_init_data_cb_(encrypted_media_init_data_cb),
      media_tracks_updated_cb_(media_tracks_updated_cb),
      cancel_pending_seek_factory_(this),
      weak_factory_(this) {
  DCHECK(task_runner_.get());
  DCHECK(data_source_);
  DCHECK(!media_tracks_updated_cb_.is_null());
}

FFmpegDemuxer::~FFmpegDemuxer() {
  // NOTE: This class is not destroyed on |task_runner|, so we must ensure that
  // there are no outstanding WeakPtrs by the time we reach here.
  DCHECK(!weak_factory_.HasWeakPtrs());

  // There may be outstanding tasks in the blocking pool which are trying to use
  // these members, so release them in sequence with any outstanding calls. The
  // earlier call to Abort() on |data_source_| prevents further access to it.
  blocking_task_runner_->DeleteSoon(FROM_HERE, url_protocol_.release());
  blocking_task_runner_->DeleteSoon(FROM_HERE, glue_.release());
}

std::string FFmpegDemuxer::GetDisplayName() const {
  return "FFmpegDemuxer";
}

void FFmpegDemuxer::Initialize(DemuxerHost* host,
                               const PipelineStatusCB& status_cb,
                               bool enable_text_tracks) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  host_ = host;
  text_enabled_ = enable_text_tracks;
  weak_this_ = cancel_pending_seek_factory_.GetWeakPtr();

  // Give a WeakPtr to BlockingUrlProtocol since we'll need to release it on the
  // blocking thread pool.
  url_protocol_.reset(new BlockingUrlProtocol(
      data_source_, BindToCurrentLoop(base::Bind(
                        &FFmpegDemuxer::OnDataSourceError, weak_this_))));
  glue_.reset(new FFmpegGlue(url_protocol_.get()));
  AVFormatContext* format_context = glue_->format_context();

  // Disable ID3v1 tag reading to avoid costly seeks to end of file for data we
  // don't use.  FFmpeg will only read ID3v1 tags if no other metadata is
  // available, so add a metadata entry to ensure some is always present.
  av_dict_set(&format_context->metadata, "skip_id3v1_tags", "", 0);

  // Ensure ffmpeg doesn't give up too early while looking for stream params;
  // this does not increase the amount of data downloaded.  The default value
  // is 5 AV_TIME_BASE units (1 second each), which prevents some oddly muxed
  // streams from being detected properly; this value was chosen arbitrarily.
  format_context->max_analyze_duration = 60 * AV_TIME_BASE;

  // Open the AVFormatContext using our glue layer.
  base::PostTaskAndReplyWithResult(
      blocking_task_runner_.get(), FROM_HERE,
      base::Bind(&FFmpegGlue::OpenContext, base::Unretained(glue_.get())),
      base::Bind(&FFmpegDemuxer::OnOpenContextDone, weak_factory_.GetWeakPtr(),
                 status_cb));
}

void FFmpegDemuxer::AbortPendingReads() {
  DCHECK(task_runner_->BelongsToCurrentThread());

  // If Stop() has been called, then drop this call.
  if (stopped_)
    return;

  // This should only be called after the demuxer has been initialized.
  DCHECK_GT(streams_.size(), 0u);

  // Abort all outstanding reads.
  for (const auto& stream : streams_) {
    if (stream)
      stream->Abort();
  }

  // It's important to invalidate read/seek completion callbacks to avoid any
  // errors that occur because of the data source abort.
  weak_factory_.InvalidateWeakPtrs();
  data_source_->Abort();

  // Aborting the read may cause EOF to be marked, undo this.
  blocking_task_runner_->PostTask(
      FROM_HERE,
      base::Bind(&UnmarkEndOfStreamAndClearError, glue_->format_context()));
  pending_read_ = false;

  // TODO(dalecurtis): We probably should report PIPELINE_ERROR_ABORT here
  // instead to avoid any preroll work that may be started upon return, but
  // currently the PipelineImpl does not know how to handle this.
  if (!pending_seek_cb_.is_null())
    base::ResetAndReturn(&pending_seek_cb_).Run(PIPELINE_OK);
}

void FFmpegDemuxer::Stop() {
  DCHECK(task_runner_->BelongsToCurrentThread());

  // The order of Stop() and Abort() is important here.  If Abort() is called
  // first, control may pass into FFmpeg where it can destruct buffers that are
  // in the process of being fulfilled by the DataSource.
  data_source_->Stop();
  url_protocol_->Abort();

  for (const auto& stream : streams_) {
    if (stream)
      stream->Stop();
  }

  data_source_ = NULL;

  // Invalidate WeakPtrs on |task_runner_|, destruction may happen on another
  // thread. We don't need to wait for any outstanding tasks since they will all
  // fail to return after invalidating WeakPtrs.
  stopped_ = true;
  weak_factory_.InvalidateWeakPtrs();
  cancel_pending_seek_factory_.InvalidateWeakPtrs();
}

void FFmpegDemuxer::StartWaitingForSeek(base::TimeDelta seek_time) {}

void FFmpegDemuxer::CancelPendingSeek(base::TimeDelta seek_time) {
  if (task_runner_->BelongsToCurrentThread()) {
    AbortPendingReads();
  } else {
    // Don't use GetWeakPtr() here since we are on the wrong thread.
    task_runner_->PostTask(
        FROM_HERE, base::Bind(&FFmpegDemuxer::AbortPendingReads, weak_this_));
  }
}

void FFmpegDemuxer::Seek(base::TimeDelta time, const PipelineStatusCB& cb) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  CHECK(pending_seek_cb_.is_null());

  // FFmpeg requires seeks to be adjusted according to the lowest starting time.
  // Since EnqueuePacket() rebased negative timestamps by the start time, we
  // must correct the shift here.
  //
  // Additionally, to workaround limitations in how we expose seekable ranges to
  // Blink (http://crbug.com/137275), we also want to clamp seeks before the
  // start time to the start time.
  base::TimeDelta seek_time = start_time_ < base::TimeDelta()
                                  ? time + start_time_
                                  : time < start_time_ ? start_time_ : time;

  // When seeking in an opus stream we need to ensure we deliver enough data to
  // satisfy the seek preroll; otherwise the audio at the actual seek time will
  // not be entirely accurate.
  FFmpegDemuxerStream* audio_stream =
      GetFirstEnabledFFmpegStream(DemuxerStream::AUDIO);
  if (audio_stream) {
    const AudioDecoderConfig& config = audio_stream->audio_decoder_config();
    if (config.codec() == kCodecOpus)
      seek_time = std::max(start_time_, seek_time - config.seek_preroll());
  }

  // Choose the seeking stream based on whether it contains the seek time, if no
  // match can be found prefer the preferred stream.
  //
  // TODO(dalecurtis): Currently FFmpeg does not ensure that all streams in a
  // given container will demux all packets after the seek point.  Instead it
  // only guarantees that all packets after the file position of the seek will
  // be demuxed.  It's an open question whether FFmpeg should fix this:
  // http://lists.ffmpeg.org/pipermail/ffmpeg-devel/2014-June/159212.html
  // Tracked by http://crbug.com/387996.
  FFmpegDemuxerStream* demux_stream = FindPreferredStreamForSeeking(seek_time);
  DCHECK(demux_stream);
  const AVStream* seeking_stream = demux_stream->av_stream();
  DCHECK(seeking_stream);

  pending_seek_cb_ = cb;
  base::PostTaskAndReplyWithResult(
      blocking_task_runner_.get(), FROM_HERE,
      base::Bind(&av_seek_frame, glue_->format_context(), seeking_stream->index,
                 ConvertToTimeBase(seeking_stream->time_base, seek_time),
                 // Always seek to a timestamp <= to the desired timestamp.
                 AVSEEK_FLAG_BACKWARD),
      base::Bind(&FFmpegDemuxer::OnSeekFrameDone, weak_factory_.GetWeakPtr()));
}

base::Time FFmpegDemuxer::GetTimelineOffset() const {
  return timeline_offset_;
}

std::vector<DemuxerStream*> FFmpegDemuxer::GetAllStreams() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::vector<DemuxerStream*> result;
  // Put enabled streams at the beginning of the list so that
  // MediaResource::GetFirstStream returns the enabled stream if there is one.
  // TODO(servolk): Revisit this after media track switching is supported.
  for (const auto& stream : streams_) {
    if (stream && stream->IsEnabled())
      result.push_back(stream.get());
  }
  // And include disabled streams at the end of the list.
  for (const auto& stream : streams_) {
    if (stream && !stream->IsEnabled())
      result.push_back(stream.get());
  }
  return result;
}

FFmpegDemuxerStream* FFmpegDemuxer::GetFirstEnabledFFmpegStream(
    DemuxerStream::Type type) const {
  for (const auto& stream : streams_) {
    if (stream && stream->type() == type && stream->IsEnabled()) {
      return stream.get();
    }
  }
  return NULL;
}

base::TimeDelta FFmpegDemuxer::GetStartTime() const {
  return std::max(start_time_, base::TimeDelta());
}

void FFmpegDemuxer::AddTextStreams() {
  DCHECK(task_runner_->BelongsToCurrentThread());

  for (const auto& stream : streams_) {
    if (!stream || stream->type() != DemuxerStream::TEXT)
      continue;

    TextKind kind = stream->GetTextKind();
    std::string title = stream->GetMetadata("title");
    std::string language = stream->GetMetadata("language");

    // TODO: Implement "id" metadata in FFMPEG.
    // See: http://crbug.com/323183
    host_->AddTextStream(stream.get(),
                         TextTrackConfig(kind, title, language, std::string()));
  }
}

int64_t FFmpegDemuxer::GetMemoryUsage() const {
  int64_t allocation_size = 0;
  for (const auto& stream : streams_) {
    if (stream)
      allocation_size += stream->MemoryUsage();
  }
  return allocation_size;
}

void FFmpegDemuxer::OnEncryptedMediaInitData(
    EmeInitDataType init_data_type,
    const std::string& encryption_key_id) {
  std::vector<uint8_t> key_id_local(encryption_key_id.begin(),
                                    encryption_key_id.end());
  encrypted_media_init_data_cb_.Run(init_data_type, key_id_local);
}

void FFmpegDemuxer::NotifyCapacityAvailable() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  ReadFrameIfNeeded();
}

void FFmpegDemuxer::NotifyBufferingChanged() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  Ranges<base::TimeDelta> buffered;
  bool initialized_buffered_ranges = false;
  for (const auto& stream : streams_) {
    if (!stream)
      continue;
    if (initialized_buffered_ranges) {
      buffered = buffered.IntersectionWith(stream->GetBufferedRanges());
    } else {
      buffered = stream->GetBufferedRanges();
      initialized_buffered_ranges = true;
    }
  }
  host_->OnBufferedTimeRangesChanged(buffered);
}

// Helper for calculating the bitrate of the media based on information stored
// in |format_context| or failing that the size and duration of the media.
//
// Returns 0 if a bitrate could not be determined.
static int CalculateBitrate(AVFormatContext* format_context,
                            const base::TimeDelta& duration,
                            int64_t filesize_in_bytes) {
  // If there is a bitrate set on the container, use it.
  if (format_context->bit_rate > 0)
    return format_context->bit_rate;

  // Then try to sum the bitrates individually per stream.
  int bitrate = 0;
  for (size_t i = 0; i < format_context->nb_streams; ++i) {
    AVCodecParameters* codec_parameters = format_context->streams[i]->codecpar;
    bitrate += codec_parameters->bit_rate;
  }
  if (bitrate > 0)
    return bitrate;

  // See if we can approximate the bitrate as long as we have a filesize and
  // valid duration.
  if (duration.InMicroseconds() <= 0 || duration == kInfiniteDuration ||
      filesize_in_bytes == 0) {
    return 0;
  }

  // Do math in floating point as we'd overflow an int64_t if the filesize was
  // larger than ~1073GB.
  double bytes = filesize_in_bytes;
  double duration_us = duration.InMicroseconds();
  return bytes * 8000000.0 / duration_us;
}

void FFmpegDemuxer::OnOpenContextDone(const PipelineStatusCB& status_cb,
                                      bool result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  if (stopped_) {
    MEDIA_LOG(ERROR, media_log_) << GetDisplayName() << ": bad state";
    status_cb.Run(PIPELINE_ERROR_ABORT);
    return;
  }

#if defined(OS_ANDROID)
  if (glue_->detected_hls()) {
    MEDIA_LOG(INFO, media_log_)
        << GetDisplayName() << ": detected HLS manifest";
    status_cb.Run(DEMUXER_ERROR_DETECTED_HLS);
    return;
  }
#endif

  if (!result) {
    MEDIA_LOG(ERROR, media_log_) << GetDisplayName() << ": open context failed";
    status_cb.Run(DEMUXER_ERROR_COULD_NOT_OPEN);
    return;
  }

  // Fully initialize AVFormatContext by parsing the stream a little.
  base::PostTaskAndReplyWithResult(
      blocking_task_runner_.get(), FROM_HERE,
      base::Bind(&avformat_find_stream_info, glue_->format_context(),
                 static_cast<AVDictionary**>(NULL)),
      base::Bind(&FFmpegDemuxer::OnFindStreamInfoDone,
                 weak_factory_.GetWeakPtr(), status_cb));
}

void FFmpegDemuxer::OnFindStreamInfoDone(const PipelineStatusCB& status_cb,
                                         int result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  if (stopped_ || !data_source_) {
    MEDIA_LOG(ERROR, media_log_) << GetDisplayName() << ": bad state";
    status_cb.Run(PIPELINE_ERROR_ABORT);
    return;
  }

  if (result < 0) {
    MEDIA_LOG(ERROR, media_log_) << GetDisplayName()
                                 << ": find stream info failed";
    status_cb.Run(DEMUXER_ERROR_COULD_NOT_PARSE);
    return;
  }

  // Create demuxer stream entries for each possible AVStream. Each stream
  // is examined to determine if it is supported or not (is the codec enabled
  // for it in this release?). Unsupported streams are skipped, allowing for
  // partial playback. At least one audio or video stream must be playable.
  AVFormatContext* format_context = glue_->format_context();
  streams_.resize(format_context->nb_streams);

  // Estimate the start time for each stream by looking through the packets
  // buffered during avformat_find_stream_info().  These values will be
  // considered later when determining the actual stream start time.
  //
  // These packets haven't been completely processed yet, so only look through
  // these values if the AVFormatContext has a valid start time.
  //
  // If no estimate is found, the stream entry will be kInfiniteDuration.
  std::vector<base::TimeDelta> start_time_estimates(format_context->nb_streams,
                                                    kInfiniteDuration);
#if !BUILDFLAG(USE_SYSTEM_FFMPEG)
  const AVFormatInternal* internal = format_context->internal;
  if (internal && internal->packet_buffer &&
      format_context->start_time != static_cast<int64_t>(AV_NOPTS_VALUE)) {
    struct AVPacketList* packet_buffer = internal->packet_buffer;
    while (packet_buffer != internal->packet_buffer_end) {
      DCHECK_LT(static_cast<size_t>(packet_buffer->pkt.stream_index),
                start_time_estimates.size());
      const AVStream* stream =
          format_context->streams[packet_buffer->pkt.stream_index];
      if (packet_buffer->pkt.pts != static_cast<int64_t>(AV_NOPTS_VALUE)) {
        const base::TimeDelta packet_pts =
            ConvertFromTimeBase(stream->time_base, packet_buffer->pkt.pts);
        // We ignore kNoTimestamp here since -int64_t::min() is possible; see
        // https://crbug.com/700501. Technically this is a valid value, but in
        // practice shouldn't occur, so just ignore it when estimating.
        if (packet_pts != kNoTimestamp && packet_pts != kInfiniteDuration &&
            packet_pts < start_time_estimates[stream->index]) {
          start_time_estimates[stream->index] = packet_pts;
        }
      }
      packet_buffer = packet_buffer->next;
    }
  }
#endif  // !BUILDFLAG(USE_SYSTEM_FFMPEG)

  std::unique_ptr<MediaTracks> media_tracks(new MediaTracks());

  DCHECK(track_id_to_demux_stream_map_.empty());

  // If available, |start_time_| will be set to the lowest stream start time.
  start_time_ = kInfiniteDuration;

  base::TimeDelta max_duration;
  int detected_audio_track_count = 0;
  int detected_video_track_count = 0;
  int detected_text_track_count = 0;
  int supported_audio_track_count = 0;
  int supported_video_track_count = 0;
  bool has_opus_or_vorbis_audio = false;
  bool needs_negative_timestamp_fixup = false;
  for (size_t i = 0; i < format_context->nb_streams; ++i) {
    AVStream* stream = format_context->streams[i];
    const AVCodecParameters* codec_parameters = stream->codecpar;
    const AVMediaType codec_type = codec_parameters->codec_type;
    const AVCodecID codec_id = codec_parameters->codec_id;
    // Skip streams which are not properly detected.
    if (codec_id == AV_CODEC_ID_NONE) {
      stream->discard = AVDISCARD_ALL;
      continue;
    }

    if (codec_type == AVMEDIA_TYPE_AUDIO) {
      // Log the codec detected, whether it is supported or not, and whether or
      // not we have already detected a supported codec in another stream.
      base::UmaHistogramSparse("Media.DetectedAudioCodecHash",
                               HashCodecName(GetCodecName(codec_id)));
      detected_audio_track_count++;
    } else if (codec_type == AVMEDIA_TYPE_VIDEO) {
      // Log the codec detected, whether it is supported or not, and whether or
      // not we have already detected a supported codec in another stream.
      base::UmaHistogramSparse("Media.DetectedVideoCodecHash",
                               HashCodecName(GetCodecName(codec_id)));
      detected_video_track_count++;

#if BUILDFLAG(ENABLE_HEVC_DEMUXING)
      if (codec_id == AV_CODEC_ID_HEVC) {
        // If ffmpeg is built without HEVC parser/decoder support, it will be
        // able to demux HEVC based solely on container-provided information,
        // but unable to get some of the parameters without parsing the stream
        // (e.g. coded size needs to be read from SPS, pixel format is typically
        // deduced from decoder config in hvcC box). These are not really needed
        // when using external decoder (e.g. hardware decoder), so override them
        // to make sure this translates into a valid VideoDecoderConfig. Coded
        // size is overridden in AVStreamToVideoDecoderConfig().
        if (stream->codecpar->format == AV_PIX_FMT_NONE)
          stream->codecpar->format = AV_PIX_FMT_YUV420P;
      }
#endif
    } else if (codec_type == AVMEDIA_TYPE_SUBTITLE) {
      detected_text_track_count++;
      if (codec_id != AV_CODEC_ID_WEBVTT || !text_enabled_) {
        stream->discard = AVDISCARD_ALL;
        continue;
      }
    } else {
      stream->discard = AVDISCARD_ALL;
      continue;
    }

    // Attempt to create a FFmpegDemuxerStream from the AVStream. This will
    // return nullptr if the AVStream is invalid. Validity checks will verify
    // things like: codec, channel layout, sample/pixel format, etc...
    std::unique_ptr<FFmpegDemuxerStream> demuxer_stream =
        FFmpegDemuxerStream::Create(this, stream, media_log_);
    if (demuxer_stream.get()) {
      streams_[i] = std::move(demuxer_stream);
    } else {
      if (codec_type == AVMEDIA_TYPE_AUDIO) {
        MEDIA_LOG(INFO, media_log_)
            << GetDisplayName()
            << ": skipping invalid or unsupported audio track";
      } else if (codec_type == AVMEDIA_TYPE_VIDEO) {
        MEDIA_LOG(INFO, media_log_)
            << GetDisplayName()
            << ": skipping invalid or unsupported video track";
      }

      // This AVStream does not successfully convert.
      continue;
    }

    StreamParser::TrackId track_id = stream->id;
    std::string track_label = streams_[i]->GetMetadata("handler_name");
    std::string track_language = streams_[i]->GetMetadata("language");

    // Some metadata is named differently in FFmpeg for webm files.
    if (glue_->container() == container_names::CONTAINER_WEBM) {
      // TODO(servolk): FFmpeg doesn't set stream->id correctly for webm files.
      // Need to fix that and use it as track id. crbug.com/323183
      track_id =
          static_cast<StreamParser::TrackId>(media_tracks->tracks().size() + 1);
      track_label = streams_[i]->GetMetadata("title");
    }

    if (codec_type == AVMEDIA_TYPE_AUDIO) {
      ++supported_audio_track_count;
      streams_[i]->SetEnabled(supported_audio_track_count == 1,
                              base::TimeDelta());
    } else if (codec_type == AVMEDIA_TYPE_VIDEO) {
      ++supported_video_track_count;
      streams_[i]->SetEnabled(supported_video_track_count == 1,
                              base::TimeDelta());
    }

    if ((codec_type == AVMEDIA_TYPE_AUDIO &&
         media_tracks->getAudioConfig(track_id).IsValidConfig()) ||
        (codec_type == AVMEDIA_TYPE_VIDEO &&
         media_tracks->getVideoConfig(track_id).IsValidConfig())) {
      MEDIA_LOG(INFO, media_log_)
          << GetDisplayName()
          << ": skipping duplicate media stream id=" << track_id;
      continue;
    }

    // Note when we find our audio/video stream (we only want one of each) and
    // record src= playback UMA stats for the stream's decoder config.
    MediaTrack* media_track = nullptr;
    if (codec_type == AVMEDIA_TYPE_AUDIO) {
      AudioDecoderConfig audio_config = streams_[i]->audio_decoder_config();
      RecordAudioCodecStats(audio_config);

      media_track = media_tracks->AddAudioTrack(audio_config, track_id, "main",
                                                track_label, track_language);
      media_track->set_id(base::UintToString(track_id));
      DCHECK(track_id_to_demux_stream_map_.find(media_track->id()) ==
             track_id_to_demux_stream_map_.end());
      track_id_to_demux_stream_map_[media_track->id()] = streams_[i].get();
    } else if (codec_type == AVMEDIA_TYPE_VIDEO) {
      VideoDecoderConfig video_config = streams_[i]->video_decoder_config();

      RecordVideoCodecStats(glue_->container(), video_config,
                            stream->codecpar->color_range, media_log_);

      media_track = media_tracks->AddVideoTrack(video_config, track_id, "main",
                                                track_label, track_language);
      media_track->set_id(base::UintToString(track_id));
      DCHECK(track_id_to_demux_stream_map_.find(media_track->id()) ==
             track_id_to_demux_stream_map_.end());
      track_id_to_demux_stream_map_[media_track->id()] = streams_[i].get();
    }

    max_duration = std::max(max_duration, streams_[i]->duration());

    base::TimeDelta start_time =
        ExtractStartTime(stream, start_time_estimates[i]);

    // Note: This value is used for seeking, so we must take the true value and
    // not the one possibly clamped to zero below.
    if (start_time < start_time_)
      start_time_ = start_time;

    const bool is_opus_or_vorbis =
        codec_id == AV_CODEC_ID_OPUS || codec_id == AV_CODEC_ID_VORBIS;
    if (!has_opus_or_vorbis_audio)
      has_opus_or_vorbis_audio = is_opus_or_vorbis;

    if (codec_type == AVMEDIA_TYPE_AUDIO && start_time < base::TimeDelta() &&
        is_opus_or_vorbis) {
      needs_negative_timestamp_fixup = true;

      // Fixup the seeking information to avoid selecting the audio stream
      // simply because it has a lower starting time.
      start_time = base::TimeDelta();
    }

    streams_[i]->set_start_time(start_time);
  }

  RecordDetectedTrackTypeStats(detected_audio_track_count,
                               detected_video_track_count,
                               detected_text_track_count);

  if (media_tracks->tracks().empty()) {
    MEDIA_LOG(ERROR, media_log_) << GetDisplayName()
                                 << ": no supported streams";
    status_cb.Run(DEMUXER_ERROR_NO_SUPPORTED_STREAMS);
    return;
  }

  if (text_enabled_)
    AddTextStreams();

  if (format_context->duration != static_cast<int64_t>(AV_NOPTS_VALUE)) {
    // If there is a duration value in the container use that to find the
    // maximum between it and the duration from A/V streams.
    const AVRational av_time_base = {1, AV_TIME_BASE};
    max_duration =
        std::max(max_duration,
                 ConvertFromTimeBase(av_time_base, format_context->duration));
  } else {
    // The duration is unknown, in which case this is likely a live stream.
    max_duration = kInfiniteDuration;
  }

  // Chained ogg is only allowed on single track audio only opus/vorbis media.
  const bool needs_chained_ogg_fixup =
      glue_->container() == container_names::CONTAINER_OGG &&
      supported_audio_track_count == 1 && !supported_video_track_count &&
      has_opus_or_vorbis_audio;

  // FFmpeg represents audio data marked as before the beginning of stream as
  // having negative timestamps.  This data must be discarded after it has been
  // decoded, not before since it is used to warmup the decoder.  There are
  // currently two known cases for this: vorbis in ogg and opus.
  //
  // For API clarity, it was decided that the rest of the media pipeline should
  // not be exposed to negative timestamps.  Which means we need to rebase these
  // negative timestamps and mark them for discard post decoding.
  //
  // Post-decode frame dropping for packets with negative timestamps is outlined
  // in section A.2 in the Ogg Vorbis spec:
  // http://xiph.org/vorbis/doc/Vorbis_I_spec.html
  //
  // FFmpeg's use of negative timestamps for opus pre-skip is nonstandard, but
  // for more information on pre-skip see section 4.2 of the Ogg Opus spec:
  // https://tools.ietf.org/html/draft-ietf-codec-oggopus-08#section-4.2
  if (needs_negative_timestamp_fixup || needs_chained_ogg_fixup) {
    for (auto& stream : streams_) {
      if (!stream)
        continue;
      if (needs_negative_timestamp_fixup)
        stream->enable_negative_timestamp_fixups();
      if (needs_chained_ogg_fixup)
        stream->enable_chained_ogg_fixups();
    }
  }

  // If no start time could be determined, default to zero.
  if (start_time_ == kInfiniteDuration)
    start_time_ = base::TimeDelta();

  // MPEG-4 B-frames cause grief for a simple container like AVI. Enable PTS
  // generation so we always get timestamps, see http://crbug.com/169570
  if (glue_->container() == container_names::CONTAINER_AVI)
    format_context->flags |= AVFMT_FLAG_GENPTS;

  // For testing purposes, don't overwrite the timeline offset if set already.
  if (timeline_offset_.is_null()) {
    timeline_offset_ =
        ExtractTimelineOffset(glue_->container(), format_context);
  }

  // Since we're shifting the externally visible start time to zero, we need to
  // adjust the timeline offset to compensate.
  if (!timeline_offset_.is_null() && start_time_ < base::TimeDelta())
    timeline_offset_ += start_time_;

  if (max_duration == kInfiniteDuration && !timeline_offset_.is_null()) {
    SetLiveness(DemuxerStream::LIVENESS_LIVE);
  } else if (max_duration != kInfiniteDuration) {
    SetLiveness(DemuxerStream::LIVENESS_RECORDED);
  } else {
    SetLiveness(DemuxerStream::LIVENESS_UNKNOWN);
  }

  // Good to go: set the duration and bitrate and notify we're done
  // initializing.
  host_->SetDuration(max_duration);
  duration_ = max_duration;
  duration_known_ = (max_duration != kInfiniteDuration);

  int64_t filesize_in_bytes = 0;
  url_protocol_->GetSize(&filesize_in_bytes);
  bitrate_ = CalculateBitrate(format_context, max_duration, filesize_in_bytes);
  if (bitrate_ > 0)
    data_source_->SetBitrate(bitrate_);

  LogMetadata(format_context, max_duration);
  media_tracks_updated_cb_.Run(std::move(media_tracks));

  status_cb.Run(PIPELINE_OK);
}

void FFmpegDemuxer::LogMetadata(AVFormatContext* avctx,
                                base::TimeDelta max_duration) {
  // Use a single MediaLogEvent to batch all parameter updates at once; this
  // prevents throttling of events due to the large number of updates here.
  std::unique_ptr<MediaLogEvent> metadata_event =
      media_log_->CreateEvent(MediaLogEvent::PROPERTY_CHANGE);

  DCHECK_EQ(avctx->nb_streams, streams_.size());
  auto& params = metadata_event->params;
  int audio_track_count = 0;
  int video_track_count = 0;
  for (size_t i = 0; i < streams_.size(); ++i) {
    FFmpegDemuxerStream* stream = streams_[i].get();
    if (!stream)
      continue;
    if (stream->type() == DemuxerStream::AUDIO) {
      ++audio_track_count;
      std::string suffix = "";
      if (audio_track_count > 1)
        suffix = "_track" + base::IntToString(audio_track_count);
      const AVCodecParameters* audio_parameters = avctx->streams[i]->codecpar;
      const AudioDecoderConfig& audio_config = stream->audio_decoder_config();
      params.SetString("audio_codec_name" + suffix,
                       GetCodecName(audio_parameters->codec_id));
      params.SetInteger("audio_channels_count" + suffix,
                        audio_parameters->channels);
      params.SetString("audio_sample_format" + suffix,
                       SampleFormatToString(audio_config.sample_format()));
      params.SetInteger("audio_samples_per_second" + suffix,
                        audio_config.samples_per_second());
    } else if (stream->type() == DemuxerStream::VIDEO) {
      ++video_track_count;
      std::string suffix = "";
      if (video_track_count > 1)
        suffix = "_track" + base::IntToString(video_track_count);
      const AVStream* video_av_stream = avctx->streams[i];
      const AVCodecParameters* video_parameters = video_av_stream->codecpar;
      const VideoDecoderConfig& video_config = stream->video_decoder_config();
      params.SetString("video_codec_name" + suffix,
                       GetCodecName(video_parameters->codec_id));
      params.SetInteger("width" + suffix, video_parameters->width);
      params.SetInteger("height" + suffix, video_parameters->height);

      // AVCodecParameters has no time_base field. We use the one from AVStream
      // here.
      params.SetString(
          "time_base" + suffix,
          base::StringPrintf("%d/%d", video_av_stream->time_base.num,
                             video_av_stream->time_base.den));

      params.SetString("video_format" + suffix,
                       VideoPixelFormatToString(video_config.format()));
      params.SetBoolean("video_is_encrypted" + suffix,
                        video_config.is_encrypted());
    }
  }
  params.SetBoolean("found_audio_stream", (audio_track_count > 0));
  params.SetBoolean("found_video_stream", (video_track_count > 0));
  SetTimeProperty(metadata_event.get(), "max_duration", max_duration);
  SetTimeProperty(metadata_event.get(), "start_time", start_time_);
  metadata_event->params.SetInteger("bitrate", bitrate_);
  media_log_->AddEvent(std::move(metadata_event));
}

FFmpegDemuxerStream* FFmpegDemuxer::FindStreamWithLowestStartTimestamp(
    bool enabled) {
  FFmpegDemuxerStream* lowest_start_time_stream = nullptr;
  for (const auto& stream : streams_) {
    if (!stream || stream->IsEnabled() != enabled)
      continue;
    if (!lowest_start_time_stream ||
        stream->start_time() < lowest_start_time_stream->start_time()) {
      lowest_start_time_stream = stream.get();
    }
  }
  return lowest_start_time_stream;
}

FFmpegDemuxerStream* FFmpegDemuxer::FindPreferredStreamForSeeking(
    base::TimeDelta seek_time) {
  // If we have a selected/enabled video stream and its start time is lower
  // than the |seek_time| or unknown, then always prefer it for seeking.
  FFmpegDemuxerStream* video_stream = nullptr;
  for (const auto& stream : streams_) {
    if (stream && stream->type() == DemuxerStream::VIDEO &&
        stream->IsEnabled()) {
      video_stream = stream.get();
      if (video_stream->start_time() <= seek_time) {
        return video_stream;
      }
      break;
    }
  }

  // If video stream is not present or |seek_time| is lower than the video start
  // time, then try to find an enabled stream with the lowest start time.
  FFmpegDemuxerStream* lowest_start_time_enabled_stream =
      FindStreamWithLowestStartTimestamp(true);
  if (lowest_start_time_enabled_stream &&
      lowest_start_time_enabled_stream->start_time() <= seek_time) {
    return lowest_start_time_enabled_stream;
  }

  // If there's no enabled streams to consider from, try a disabled stream with
  // the lowest known start time.
  FFmpegDemuxerStream* lowest_start_time_disabled_stream =
      FindStreamWithLowestStartTimestamp(false);
  if (lowest_start_time_disabled_stream &&
      lowest_start_time_disabled_stream->start_time() <= seek_time) {
    return lowest_start_time_disabled_stream;
  }

  // Otherwise fall back to any other stream.
  for (const auto& stream : streams_) {
    if (stream)
      return stream.get();
  }

  NOTREACHED();
  return nullptr;
}

void FFmpegDemuxer::OnSeekFrameDone(int result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  CHECK(!pending_seek_cb_.is_null());

  if (stopped_) {
    MEDIA_LOG(ERROR, media_log_) << GetDisplayName() << ": bad state";
    base::ResetAndReturn(&pending_seek_cb_).Run(PIPELINE_ERROR_ABORT);
    return;
  }

  if (result < 0) {
    // Use VLOG(1) instead of NOTIMPLEMENTED() to prevent the message being
    // captured from stdout and contaminates testing.
    // TODO(scherkus): Implement this properly and signal error (BUG=23447).
    VLOG(1) << "Not implemented";
  }

  // Tell streams to flush buffers due to seeking.
  for (const auto& stream : streams_) {
    if (stream)
      stream->FlushBuffers();
  }

  // Resume reading until capacity.
  ReadFrameIfNeeded();

  // Notify we're finished seeking.
  base::ResetAndReturn(&pending_seek_cb_).Run(PIPELINE_OK);
}

void FFmpegDemuxer::FindAndEnableProperTracks(
    const std::vector<MediaTrack::Id>& track_ids,
    base::TimeDelta curr_time,
    DemuxerStream::Type track_type,
    TrackChangeCB change_completed_cb) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  std::set<FFmpegDemuxerStream*> enabled_streams;
  for (const auto& id : track_ids) {
    auto it = track_id_to_demux_stream_map_.find(id);
    if (it == track_id_to_demux_stream_map_.end())
      continue;
    FFmpegDemuxerStream* stream = it->second;
    DCHECK_EQ(track_type, stream->type());
    // TODO(servolk): Remove after multiple enabled audio tracks are supported
    // by the media::RendererImpl.
    if (!enabled_streams.empty()) {
      MEDIA_LOG(INFO, media_log_)
          << "Only one enabled audio track is supported, ignoring track " << id;
      continue;
    }
    enabled_streams.insert(stream);
    stream->SetEnabled(true, curr_time);
  }

  // First disable all streams that need to be disabled and then enable streams
  // that are enabled.
  for (const auto& stream : streams_) {
    if (stream && stream->type() == track_type &&
        enabled_streams.find(stream.get()) == enabled_streams.end()) {
      DVLOG(1) << __func__ << ": disabling stream " << stream.get();
      stream->SetEnabled(false, curr_time);
    }
  }

  std::vector<DemuxerStream*> streams(enabled_streams.begin(),
                                      enabled_streams.end());
  std::move(change_completed_cb).Run(track_type, streams);
}

void FFmpegDemuxer::OnEnabledAudioTracksChanged(
    const std::vector<MediaTrack::Id>& track_ids,
    base::TimeDelta curr_time,
    TrackChangeCB change_completed_cb) {
  FindAndEnableProperTracks(track_ids, curr_time, DemuxerStream::AUDIO,
                            std::move(change_completed_cb));
}

void FFmpegDemuxer::OnSelectedVideoTrackChanged(
    const std::vector<MediaTrack::Id>& track_ids,
    base::TimeDelta curr_time,
    TrackChangeCB change_completed_cb) {
  FindAndEnableProperTracks(track_ids, curr_time, DemuxerStream::VIDEO,
                            std::move(change_completed_cb));
}

void FFmpegDemuxer::ReadFrameIfNeeded() {
  DCHECK(task_runner_->BelongsToCurrentThread());

  // Make sure we have work to do before reading.
  if (stopped_ || !StreamsHaveAvailableCapacity() || pending_read_ ||
      !pending_seek_cb_.is_null()) {
    return;
  }

  // Allocate and read an AVPacket from the media. Save |packet_ptr| since
  // evaluation order of packet.get() and base::Passed(&packet) is
  // undefined.
  ScopedAVPacket packet(new AVPacket());
  AVPacket* packet_ptr = packet.get();

  pending_read_ = true;
  base::PostTaskAndReplyWithResult(
      blocking_task_runner_.get(), FROM_HERE,
      base::Bind(&av_read_frame, glue_->format_context(), packet_ptr),
      base::Bind(&FFmpegDemuxer::OnReadFrameDone, weak_factory_.GetWeakPtr(),
                 base::Passed(&packet)));
}

void FFmpegDemuxer::OnReadFrameDone(ScopedAVPacket packet, int result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK(pending_read_);
  pending_read_ = false;

  if (stopped_ || !pending_seek_cb_.is_null())
    return;

  // Consider the stream as ended if:
  // - either underlying ffmpeg returned an error
  // - or FFMpegDemuxer reached the maximum allowed memory usage.
  if (result < 0 || IsMaxMemoryUsageReached()) {
    if (result < 0) {
      MEDIA_LOG(DEBUG, media_log_)
          << GetDisplayName()
          << ": av_read_frame(): " << AVErrorToString(result);
    } else {
      MEDIA_LOG(DEBUG, media_log_)
          << GetDisplayName() << ": memory limit exceeded";
    }

    // Update the duration based on the highest elapsed time across all streams.
    base::TimeDelta max_duration;
    for (const auto& stream : streams_) {
      if (!stream)
        continue;

      base::TimeDelta duration = stream->duration();
      if (duration != kNoTimestamp && duration > max_duration)
        max_duration = duration;
    }

    if (duration_ == kInfiniteDuration || max_duration > duration_) {
      host_->SetDuration(max_duration);
      duration_known_ = true;
      duration_ = max_duration;
    }

    // If we have reached the end of stream, tell the downstream filters about
    // the event.
    StreamHasEnded();
    return;
  }

  // Queue the packet with the appropriate stream; we must defend against ffmpeg
  // giving us a bad stream index.  See http://crbug.com/698549 for example.
  if (packet->stream_index >= 0 &&
      static_cast<size_t>(packet->stream_index) < streams_.size()) {
    // Drop empty packets since they're ignored on the decoder side anyways.
    if (!packet->data || !packet->size) {
      DLOG(WARNING) << "Dropping empty packet, size: " << packet->size
                    << ", data: " << static_cast<void*>(packet->data);
    } else if (auto& demuxer_stream = streams_[packet->stream_index]) {
      if (demuxer_stream->IsEnabled())
        demuxer_stream->EnqueuePacket(std::move(packet));

      // If duration estimate was incorrect, update it and tell higher layers.
      if (duration_known_) {
        const base::TimeDelta duration = demuxer_stream->duration();
        if (duration != kNoTimestamp && duration > duration_) {
          duration_ = duration;
          host_->SetDuration(duration_);
        }
      }
    }
  }

  // Keep reading until we've reached capacity.
  ReadFrameIfNeeded();
}

bool FFmpegDemuxer::StreamsHaveAvailableCapacity() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  for (const auto& stream : streams_) {
    if (stream && stream->IsEnabled() && stream->HasAvailableCapacity())
      return true;
  }
  return false;
}

bool FFmpegDemuxer::IsMaxMemoryUsageReached() const {
  DCHECK(task_runner_->BelongsToCurrentThread());

  size_t memory_left = GetDemuxerMemoryLimit();
  for (const auto& stream : streams_) {
    if (!stream)
      continue;

    size_t stream_memory_usage = stream->MemoryUsage();
    if (stream_memory_usage > memory_left)
      return true;
    memory_left -= stream_memory_usage;
  }
  return false;
}

void FFmpegDemuxer::StreamHasEnded() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  for (const auto& stream : streams_) {
    if (stream)
      stream->SetEndOfStream();
  }
}

void FFmpegDemuxer::OnDataSourceError() {
  MEDIA_LOG(ERROR, media_log_) << GetDisplayName() << ": data source error";
  host_->OnDemuxerError(PIPELINE_ERROR_READ);
}

void FFmpegDemuxer::NotifyDemuxerError(PipelineStatus status) {
  MEDIA_LOG(ERROR, media_log_) << GetDisplayName()
                               << ": demuxer error: " << status;
  host_->OnDemuxerError(status);
}

void FFmpegDemuxer::SetLiveness(DemuxerStream::Liveness liveness) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  for (const auto& stream : streams_) {
    if (stream)
      stream->SetLiveness(liveness);
  }
}

}  // namespace media

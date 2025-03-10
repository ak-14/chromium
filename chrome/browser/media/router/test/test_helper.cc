// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/media/router/test/test_helper.h"

#include "base/base64.h"
#include "base/json/string_escape.h"
#include "base/strings/stringprintf.h"
#include "chrome/common/media_router/media_source.h"
#include "testing/gmock/include/gmock/gmock.h"

#if !defined(OS_ANDROID)
#include "services/network/public/cpp/simple_url_loader.h"
#include "url/gurl.h"
#endif

namespace media_router {

std::string PresentationConnectionMessageToString(
    const content::PresentationConnectionMessage& message) {
  if (!message.message && !message.data)
    return "null";
  std::string result;
  if (message.message) {
    result = "text=";
    base::EscapeJSONString(*message.message, true, &result);
  } else {
    const base::StringPiece src(
        reinterpret_cast<const char*>(message.data->data()),
        message.data->size());
    base::Base64Encode(src, &result);
    result = "binary=" + result;
  }
  return result;
}

MockIssuesObserver::MockIssuesObserver(IssueManager* issue_manager)
    : IssuesObserver(issue_manager) {}
MockIssuesObserver::~MockIssuesObserver() {}

MockMediaSinksObserver::MockMediaSinksObserver(MediaRouter* router,
                                               const MediaSource& source,
                                               const url::Origin& origin)
    : MediaSinksObserver(router, source, origin) {}
MockMediaSinksObserver::~MockMediaSinksObserver() {}

MockMediaRoutesObserver::MockMediaRoutesObserver(
    MediaRouter* router,
    const MediaSource::Id source_id)
    : MediaRoutesObserver(router, source_id) {}
MockMediaRoutesObserver::~MockMediaRoutesObserver() {}

MockPresentationConnectionProxy::MockPresentationConnectionProxy() {}
MockPresentationConnectionProxy::~MockPresentationConnectionProxy() {}

#if !defined(OS_ANDROID)
MockDialMediaSinkService::MockDialMediaSinkService() : DialMediaSinkService() {}
MockDialMediaSinkService::~MockDialMediaSinkService() = default;

MockCastMediaSinkService::MockCastMediaSinkService() : CastMediaSinkService() {}
MockCastMediaSinkService::~MockCastMediaSinkService() = default;

MockDialAppDiscoveryService::MockDialAppDiscoveryService()
    : DialAppDiscoveryService(/*connector=*/nullptr) {}
MockDialAppDiscoveryService::~MockDialAppDiscoveryService() = default;

void MockDialAppDiscoveryService::FetchDialAppInfo(
    const MediaSinkInternal& sink,
    const std::string& app_name,
    DialAppInfoCallback app_info_cb) {
  DoFetchDialAppInfo(sink.sink().id(), app_name);
  app_info_cb_ = std::move(app_info_cb);
}

DialAppDiscoveryService::DialAppInfoCallback
MockDialAppDiscoveryService::PassCallback() {
  return std::move(app_info_cb_);
}

TestDialURLFetcher::TestDialURLFetcher(
    DialURLFetcher::SuccessCallback success_cb,
    DialURLFetcher::ErrorCallback error_cb,
    network::TestURLLoaderFactory* factory)
    : DialURLFetcher(std::move(success_cb), std::move(error_cb)),
      factory_(factory) {}
TestDialURLFetcher::~TestDialURLFetcher() = default;

void TestDialURLFetcher::Start(const GURL& url,
                               const std::string& method,
                               const base::Optional<std::string>& post_data,
                               int max_retries) {
  DoStart(url, method, post_data, max_retries);
  DialURLFetcher::Start(url, method, post_data, max_retries);
}

void TestDialURLFetcher::StartDownload() {
  loader_->DownloadToString(
      factory_,
      base::BindOnce(&DialURLFetcher::ProcessResponse, base::Unretained(this)),
      256 * 1024);
}

net::IPEndPoint CreateIPEndPoint(int num) {
  net::IPAddress ip_address;
  CHECK(ip_address.AssignFromIPLiteral(
      base::StringPrintf("192.168.0.10%d", num)));
  return net::IPEndPoint(ip_address, 8009 + num);
}

MediaSinkInternal CreateDialSink(int num) {
  std::string friendly_name = base::StringPrintf("friendly name %d", num);
  std::string unique_id = base::StringPrintf("dial:<id%d>", num);
  net::IPEndPoint ip_endpoint = CreateIPEndPoint(num);

  media_router::MediaSink sink(unique_id, friendly_name,
                               media_router::SinkIconType::GENERIC,
                               MediaRouteProviderId::EXTENSION);
  media_router::DialSinkExtraData extra_data;
  extra_data.ip_address = ip_endpoint.address();
  extra_data.model_name = base::StringPrintf("model name %d", num);
  extra_data.app_url =
      GURL(base::StringPrintf("http://192.168.0.10%d/apps", num));
  return media_router::MediaSinkInternal(sink, extra_data);
}

MediaSinkInternal CreateCastSink(int num) {
  std::string friendly_name = base::StringPrintf("friendly name %d", num);
  std::string unique_id = base::StringPrintf("cast:<id%d>", num);
  net::IPEndPoint ip_endpoint = CreateIPEndPoint(num);

  MediaSink sink(unique_id, friendly_name, SinkIconType::CAST);
  CastSinkExtraData extra_data;
  extra_data.ip_endpoint = ip_endpoint;
  extra_data.port = ip_endpoint.port();
  extra_data.model_name = base::StringPrintf("model name %d", num);
  extra_data.cast_channel_id = num;
  extra_data.capabilities = cast_channel::CastDeviceCapability::AUDIO_OUT |
                            cast_channel::CastDeviceCapability::VIDEO_OUT;
  return MediaSinkInternal(sink, extra_data);
}

ParsedDialAppInfo CreateParsedDialAppInfo(const std::string& name,
                                          DialAppState app_state) {
  ParsedDialAppInfo app_info;
  app_info.name = name;
  app_info.state = app_state;
  return app_info;
}

std::unique_ptr<ParsedDialAppInfo> CreateParsedDialAppInfoPtr(
    const std::string& name,
    DialAppState app_state) {
  return std::make_unique<ParsedDialAppInfo>(
      CreateParsedDialAppInfo(name, app_state));
}

#endif  // !defined(OS_ANDROID)

}  // namespace media_router

// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/service_worker/service_worker_context_client.h"

#include <map>
#include <memory>
#include <utility>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_checker.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "content/common/service_worker/service_worker_event_dispatcher.mojom.h"
#include "content/common/service_worker/service_worker_messages.h"
#include "content/common/service_worker/service_worker_status_code.h"
#include "content/common/service_worker/service_worker_utils.h"
#include "content/public/common/content_features.h"
#include "content/public/common/push_event_payload.h"
#include "content/public/common/referrer.h"
#include "content/public/common/weak_wrapper_shared_url_loader_factory.h"
#include "content/public/renderer/content_renderer_client.h"
#include "content/public/renderer/document_state.h"
#include "content/public/renderer/worker_thread.h"
#include "content/renderer/loader/child_url_loader_factory_bundle.h"
#include "content/renderer/loader/request_extra_data.h"
#include "content/renderer/loader/web_data_consumer_handle_impl.h"
#include "content/renderer/loader/web_url_loader_impl.h"
#include "content/renderer/loader/web_url_request_util.h"
#include "content/renderer/notifications/notification_data_conversions.h"
#include "content/renderer/render_thread_impl.h"
#include "content/renderer/renderer_blink_platform_impl.h"
#include "content/renderer/service_worker/controller_service_worker_impl.h"
#include "content/renderer/service_worker/embedded_worker_instance_client_impl.h"
#include "content/renderer/service_worker/service_worker_dispatcher.h"
#include "content/renderer/service_worker/service_worker_fetch_context_impl.h"
#include "content/renderer/service_worker/service_worker_network_provider.h"
#include "content/renderer/service_worker/service_worker_provider_context.h"
#include "content/renderer/service_worker/service_worker_timeout_timer.h"
#include "content/renderer/service_worker/service_worker_type_converters.h"
#include "content/renderer/service_worker/service_worker_type_util.h"
#include "content/renderer/service_worker/web_service_worker_impl.h"
#include "content/renderer/service_worker/web_service_worker_provider_impl.h"
#include "content/renderer/service_worker/web_service_worker_registration_impl.h"
#include "ipc/ipc_message.h"
#include "ipc/ipc_message_macros.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "services/network/public/mojom/request_context_frame_type.mojom.h"
#include "storage/common/blob_storage/blob_handle.h"
#include "third_party/blink/public/common/message_port/message_port_channel.h"
#include "third_party/blink/public/mojom/blob/blob.mojom.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_client.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_error_type.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_event_status.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_object.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_registration.mojom.h"
#include "third_party/blink/public/platform/interface_provider.h"
#include "third_party/blink/public/platform/modules/background_fetch/web_background_fetch_settled_fetch.h"
#include "third_party/blink/public/platform/modules/notifications/web_notification_data.h"
#include "third_party/blink/public/platform/modules/payments/web_payment_handler_response.h"
#include "third_party/blink/public/platform/modules/payments/web_payment_request_event_data.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_client_query_options.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_error.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_network_provider.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_request.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_response.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/url_conversion.h"
#include "third_party/blink/public/platform/web_blob_registry.h"
#include "third_party/blink/public/platform/web_referrer_policy.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/web/modules/serviceworker/web_service_worker_context_client.h"
#include "third_party/blink/public/web/modules/serviceworker/web_service_worker_context_proxy.h"

using blink::WebURLRequest;
using blink::MessagePortChannel;

namespace content {

namespace {

// For now client must be a per-thread instance.
base::LazyInstance<base::ThreadLocalPointer<ServiceWorkerContextClient>>::
    Leaky g_worker_client_tls = LAZY_INSTANCE_INITIALIZER;

// Called on the main thread only and blink owns it.
class WebServiceWorkerNetworkProviderImpl
    : public blink::WebServiceWorkerNetworkProvider {
 public:
  explicit WebServiceWorkerNetworkProviderImpl(
      std::unique_ptr<ServiceWorkerNetworkProvider> provider)
      : provider_(std::move(provider)) {}

  // Blink calls this method for each request starting with the main script,
  // we tag them with the provider id.
  void WillSendRequest(WebURLRequest& request) override {
    auto extra_data = std::make_unique<RequestExtraData>();
    extra_data->set_service_worker_provider_id(provider_->provider_id());
    extra_data->set_originated_from_service_worker(true);
    // Service workers are only available in secure contexts, so all requests
    // are initiated in a secure context.
    extra_data->set_initiated_in_secure_context(true);
    request.SetExtraData(std::move(extra_data));
  }

  std::unique_ptr<blink::WebURLLoader> CreateURLLoader(
      const WebURLRequest& request,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override {
    RenderThreadImpl* render_thread = RenderThreadImpl::current();
    if (render_thread && provider_->script_loader_factory() &&
        ServiceWorkerUtils::IsServicificationEnabled() &&
        IsScriptRequest(request)) {
      // TODO(crbug.com/796425): Temporarily wrap the raw
      // mojom::URLLoaderFactory pointer into SharedURLLoaderFactory.
      return std::make_unique<WebURLLoaderImpl>(
          render_thread->resource_dispatcher(), std::move(task_runner),
          base::MakeRefCounted<WeakWrapperSharedURLLoaderFactory>(
              provider_->script_loader_factory()));
    }
    return nullptr;
  }

  int ProviderID() const override { return provider_->provider_id(); }

 private:
  static bool IsScriptRequest(const WebURLRequest& request) {
    auto request_context = request.GetRequestContext();
    return request_context == WebURLRequest::kRequestContextServiceWorker ||
           request_context == WebURLRequest::kRequestContextScript ||
           request_context == WebURLRequest::kRequestContextImport;
  }

  std::unique_ptr<ServiceWorkerNetworkProvider> provider_;
};

class StreamHandleListener
    : public blink::WebServiceWorkerStreamHandle::Listener {
 public:
  StreamHandleListener(
      blink::mojom::ServiceWorkerStreamCallbackPtr callback_ptr)
      : callback_ptr_(std::move(callback_ptr)) {}

  ~StreamHandleListener() override {}

  void OnAborted() override { callback_ptr_->OnAborted(); }
  void OnCompleted() override { callback_ptr_->OnCompleted(); }

 private:
  blink::mojom::ServiceWorkerStreamCallbackPtr callback_ptr_;
};

WebURLRequest::RequestContext GetBlinkRequestContext(
    RequestContextType request_context_type) {
  return static_cast<WebURLRequest::RequestContext>(request_context_type);
}

blink::WebServiceWorkerClientInfo ToWebServiceWorkerClientInfo(
    blink::mojom::ServiceWorkerClientInfoPtr client_info) {
  DCHECK(!client_info->client_uuid.empty());

  blink::WebServiceWorkerClientInfo web_client_info;

  web_client_info.uuid = blink::WebString::FromASCII(client_info->client_uuid);
  web_client_info.page_visibility_state = client_info->page_visibility_state;
  web_client_info.is_focused = client_info->is_focused;
  web_client_info.url = client_info->url;
  web_client_info.frame_type = client_info->frame_type;
  web_client_info.client_type = client_info->client_type;

  return web_client_info;
}

void ToWebServiceWorkerRequest(const network::ResourceRequest& request,
                               const std::string request_body_blob_uuid,
                               uint64_t request_body_blob_size,
                               blink::mojom::BlobPtrInfo request_body_blob,
                               const std::string& client_id,
                               blink::WebServiceWorkerRequest* web_request) {
  DCHECK(web_request);
  web_request->SetURL(blink::WebURL(request.url));
  web_request->SetMethod(blink::WebString::FromUTF8(request.method));
  if (!request.headers.IsEmpty()) {
    for (net::HttpRequestHeaders::Iterator it(request.headers); it.GetNext();) {
      web_request->SetHeader(blink::WebString::FromUTF8(it.name()),
                             blink::WebString::FromUTF8(it.value()));
    }
  }

  // Non-S13nServiceWorker: The body is provided as a blob.
  if (request_body_blob) {
    DCHECK(!ServiceWorkerUtils::IsServicificationEnabled());
    mojo::ScopedMessagePipeHandle blob_pipe = request_body_blob.PassHandle();
    web_request->SetBlob(blink::WebString::FromASCII(request_body_blob_uuid),
                         request_body_blob_size, std::move(blob_pipe));
  }
  // S13nServiceWorker: The body is provided in |request|.
  else if (request.request_body) {
    DCHECK(ServiceWorkerUtils::IsServicificationEnabled());
    blink::WebHTTPBody body =
        GetWebHTTPBodyForRequestBody(*request.request_body);
    body.SetUniqueBoundary();
    web_request->SetBody(body);
  }

  web_request->SetReferrer(blink::WebString::FromUTF8(request.referrer.spec()),
                           Referrer::NetReferrerPolicyToBlinkReferrerPolicy(
                               request.referrer_policy));
  web_request->SetMode(request.fetch_request_mode);
  web_request->SetIsMainResourceLoad(ServiceWorkerUtils::IsMainResourceType(
      static_cast<ResourceType>(request.resource_type)));
  web_request->SetCredentialsMode(request.fetch_credentials_mode);
  web_request->SetCacheMode(
      ServiceWorkerFetchRequest::GetCacheModeFromLoadFlags(request.load_flags));
  web_request->SetRedirectMode(request.fetch_redirect_mode);
  web_request->SetRequestContext(GetBlinkRequestContext(
      static_cast<RequestContextType>(request.fetch_request_context_type)));
  web_request->SetFrameType(request.fetch_frame_type);
  web_request->SetClientId(blink::WebString::FromUTF8(client_id));
  web_request->SetIsReload(ui::PageTransitionCoreTypeIs(
      static_cast<ui::PageTransition>(request.transition_type),
      ui::PAGE_TRANSITION_RELOAD));
  web_request->SetIntegrity(
      blink::WebString::FromUTF8(request.fetch_integrity));
  web_request->SetKeepalive(request.keepalive);
}

// Converts the |request| to its equivalent type in the Blink API.
// TODO(peter): Remove this when the Mojo FetchAPIRequest type exists.
void ToWebServiceWorkerRequest(const ServiceWorkerFetchRequest& request,
                               blink::WebServiceWorkerRequest* web_request) {
  DCHECK(web_request);

  web_request->SetURL(blink::WebURL(request.url));
  web_request->SetMethod(blink::WebString::FromUTF8(request.method));
  for (const auto& pair : request.headers) {
    web_request->SetHeader(blink::WebString::FromUTF8(pair.first),
                           blink::WebString::FromUTF8(pair.second));
  }
  web_request->SetReferrer(
      blink::WebString::FromUTF8(request.referrer.url.spec()),
      request.referrer.policy);
  web_request->SetMode(request.mode);
  web_request->SetIsMainResourceLoad(request.is_main_resource_load);
  web_request->SetCredentialsMode(request.credentials_mode);
  web_request->SetCacheMode(request.cache_mode);
  web_request->SetRedirectMode(request.redirect_mode);
  web_request->SetRequestContext(
      GetBlinkRequestContext(request.request_context_type));
  web_request->SetFrameType(request.frame_type);
  web_request->SetClientId(blink::WebString::FromUTF8(request.client_id));
  web_request->SetIsReload(request.is_reload);
  web_request->SetIntegrity(blink::WebString::FromUTF8(request.integrity));
  web_request->SetKeepalive(request.keepalive);
}

// Converts |response| to its equivalent type in the Blink API.
// TODO(peter): Remove this when the Mojo FetchAPIResponse type exists.
void ToWebServiceWorkerResponse(const ServiceWorkerResponse& response,
                                blink::WebServiceWorkerResponse* web_response) {
  DCHECK(web_response);

  std::vector<blink::WebURL> url_list;
  for (const GURL& url : response.url_list)
    url_list.push_back(blink::WebURL(url));

  web_response->SetURLList(blink::WebVector<blink::WebURL>(url_list));
  web_response->SetStatus(static_cast<unsigned short>(response.status_code));
  web_response->SetStatusText(blink::WebString::FromUTF8(response.status_text));
  web_response->SetResponseType(response.response_type);
  for (const auto& pair : response.headers) {
    web_response->SetHeader(blink::WebString::FromUTF8(pair.first),
                            blink::WebString::FromUTF8(pair.second));
  }
  if (!response.blob_uuid.empty()) {
    DCHECK(response.blob);
    mojo::ScopedMessagePipeHandle blob_pipe;
    if (response.blob)
      blob_pipe = response.blob->Clone().PassInterface().PassHandle();
    web_response->SetBlob(blink::WebString::FromASCII(response.blob_uuid),
                          response.blob_size, std::move(blob_pipe));
  }
  web_response->SetError(response.error);
  web_response->SetResponseTime(response.response_time);
  if (response.is_in_cache_storage) {
    web_response->SetCacheStorageCacheName(
        blink::WebString::FromUTF8(response.cache_storage_cache_name));
  }

  std::vector<blink::WebString> cors_exposed_header_names;
  for (const auto& name : response.cors_exposed_header_names)
    cors_exposed_header_names.push_back(blink::WebString::FromUTF8(name));

  web_response->SetCorsExposedHeaderNames(
      blink::WebVector<blink::WebString>(cors_exposed_header_names));
}

// Finds an event callback keyed by |event_id| from |map|, and runs the callback
// with |args|. Returns true if the callback was found and called, otherwise
// returns false.
template <typename MapType, class... Args>
bool RunEventCallback(MapType* map,
                      ServiceWorkerTimeoutTimer* timer,
                      int event_id,
                      Args... args) {
  auto iter = map->find(event_id);
  // The event may have been aborted.
  if (iter == map->end())
    return false;
  std::move(iter->second).Run(args...);
  map->erase(iter);
  timer->EndEvent(event_id);
  return true;
}

// Creates a callback which takes an |event_id|, which calls the given event's
// callback with ABORTED status and removes it from |map|.
template <typename MapType, typename... Args>
base::OnceCallback<void(int /* event_id */)> CreateAbortCallback(MapType* map,
                                                                 Args... args) {
  return base::BindOnce(
      [](MapType* map, Args... args, base::Time dispatched_time, int event_id) {
        auto iter = map->find(event_id);
        DCHECK(iter != map->end());
        std::move(iter->second)
            .Run(blink::mojom::ServiceWorkerEventStatus::ABORTED,
                 std::forward<Args>(args)..., dispatched_time);
        map->erase(iter);
      },
      map, std::forward<Args>(args)..., base::Time::Now());
}

void DidGetClients(
    std::unique_ptr<blink::WebServiceWorkerClientsCallbacks> callbacks,
    std::vector<blink::mojom::ServiceWorkerClientInfoPtr> clients) {
  blink::WebServiceWorkerClientsInfo info;
  blink::WebVector<blink::WebServiceWorkerClientInfo> web_clients(
      clients.size());
  for (size_t i = 0; i < clients.size(); ++i)
    web_clients[i] = ToWebServiceWorkerClientInfo(std::move(clients[i]));
  info.clients.Swap(web_clients);
  callbacks->OnSuccess(info);
}

void DidClaimClients(
    std::unique_ptr<blink::WebServiceWorkerClientsClaimCallbacks> callbacks,
    blink::mojom::ServiceWorkerErrorType error,
    const base::Optional<std::string>& error_msg) {
  if (error != blink::mojom::ServiceWorkerErrorType::kNone) {
    callbacks->OnError(blink::WebServiceWorkerError(
        error, blink::WebString::FromUTF8(*error_msg)));
    return;
  }
  DCHECK(!error_msg);
  callbacks->OnSuccess();
}

void DidGetClient(
    std::unique_ptr<blink::WebServiceWorkerClientCallbacks> callbacks,
    blink::mojom::ServiceWorkerClientInfoPtr client) {
  std::unique_ptr<blink::WebServiceWorkerClientInfo> web_client;
  if (client) {
    web_client = std::make_unique<blink::WebServiceWorkerClientInfo>(
        ToWebServiceWorkerClientInfo(std::move(client)));
  }
  callbacks->OnSuccess(std::move(web_client));
}

void DidSkipWaiting(
    std::unique_ptr<blink::WebServiceWorkerSkipWaitingCallbacks> callbacks,
    bool success) {
  // OnError() should not be called here since per spec the promise returned by
  // skipWaiting() can never reject.
  if (!success)
    return;
  callbacks->OnSuccess();
}

void DidOpenWindow(
    std::unique_ptr<blink::WebServiceWorkerClientCallbacks> callbacks,
    bool success,
    blink::mojom::ServiceWorkerClientInfoPtr client,
    const base::Optional<std::string>& error_msg) {
  if (!success) {
    DCHECK(!client);
    callbacks->OnError(blink::WebServiceWorkerError(
        blink::mojom::ServiceWorkerErrorType::kNavigation,
        blink::WebString::FromUTF8(*error_msg)));
    return;
  }

  std::unique_ptr<blink::WebServiceWorkerClientInfo> web_client;
  if (client) {
    web_client = std::make_unique<blink::WebServiceWorkerClientInfo>(
        ToWebServiceWorkerClientInfo(std::move(client)));
  }
  callbacks->OnSuccess(std::move(web_client));
}

void DidFocusClient(
    std::unique_ptr<blink::WebServiceWorkerClientCallbacks> callbacks,
    blink::mojom::ServiceWorkerClientInfoPtr client) {
  if (!client) {
    callbacks->OnError(blink::WebServiceWorkerError(
        blink::mojom::ServiceWorkerErrorType::kNotFound,
        "The client was not found."));
    return;
  }
  auto web_client = std::make_unique<blink::WebServiceWorkerClientInfo>(
      ToWebServiceWorkerClientInfo(std::move(client)));
  callbacks->OnSuccess(std::move(web_client));
}

void DidNavigateClient(
    std::unique_ptr<blink::WebServiceWorkerClientCallbacks> callbacks,
    bool success,
    blink::mojom::ServiceWorkerClientInfoPtr client,
    const base::Optional<std::string>& error_msg) {
  if (!success) {
    DCHECK(!client);
    callbacks->OnError(blink::WebServiceWorkerError(
        blink::mojom::ServiceWorkerErrorType::kNavigation,
        blink::WebString::FromUTF8(*error_msg)));
    return;
  }

  std::unique_ptr<blink::WebServiceWorkerClientInfo> web_client;
  if (client) {
    web_client = std::make_unique<blink::WebServiceWorkerClientInfo>(
        ToWebServiceWorkerClientInfo(std::move(client)));
  }
  callbacks->OnSuccess(std::move(web_client));
}

}  // namespace

// Holding data that needs to be bound to the worker context on the
// worker thread.
struct ServiceWorkerContextClient::WorkerContextData {
  explicit WorkerContextData(ServiceWorkerContextClient* owner)
      : event_dispatcher_binding(owner),
        weak_factory(owner),
        proxy_weak_factory(owner->proxy_) {}

  ~WorkerContextData() {
    DCHECK(thread_checker.CalledOnValidThread());
  }

  mojo::Binding<mojom::ServiceWorkerEventDispatcher> event_dispatcher_binding;

  blink::mojom::ServiceWorkerHostAssociatedPtr service_worker_host;

  // Maps for inflight event callbacks.
  // These are mapped from an event id issued from ServiceWorkerTimeoutTimer to
  // the Mojo callback to notify the end of the event.
  std::map<int, DispatchInstallEventCallback> install_event_callbacks;
  std::map<int, DispatchActivateEventCallback> activate_event_callbacks;
  std::map<int, DispatchBackgroundFetchAbortEventCallback>
      background_fetch_abort_event_callbacks;
  std::map<int, DispatchBackgroundFetchClickEventCallback>
      background_fetch_click_event_callbacks;
  std::map<int, DispatchBackgroundFetchFailEventCallback>
      background_fetch_fail_event_callbacks;
  std::map<int, DispatchBackgroundFetchedEventCallback>
      background_fetched_event_callbacks;
  std::map<int, DispatchSyncEventCallback> sync_event_callbacks;
  std::map<int, payments::mojom::PaymentHandlerResponseCallbackPtr>
      abort_payment_result_callbacks;
  std::map<int, DispatchCanMakePaymentEventCallback>
      abort_payment_event_callbacks;
  std::map<int, DispatchCanMakePaymentEventCallback>
      can_make_payment_event_callbacks;
  std::map<int, DispatchPaymentRequestEventCallback>
      payment_request_event_callbacks;
  std::map<int, DispatchNotificationClickEventCallback>
      notification_click_event_callbacks;
  std::map<int, DispatchNotificationCloseEventCallback>
      notification_close_event_callbacks;
  std::map<int, DispatchPushEventCallback> push_event_callbacks;
  std::map<int, DispatchFetchEventCallback> fetch_event_callbacks;
  std::map<int, DispatchExtendableMessageEventCallback> message_event_callbacks;

  // Maps for response callbacks.
  // These are mapped from an event id to the Mojo interface pointer which is
  // passed from the relevant DispatchSomeEvent() method.
  std::map<int, payments::mojom::PaymentHandlerResponseCallbackPtr>
      can_make_payment_result_callbacks;
  std::map<int, payments::mojom::PaymentHandlerResponseCallbackPtr>
      payment_response_callbacks;
  std::map<int, mojom::ServiceWorkerFetchResponseCallbackPtr>
      fetch_response_callbacks;

  // Inflight navigation preload requests.
  base::IDMap<std::unique_ptr<NavigationPreloadRequest>> preload_requests;

  // S13nServiceWorker
  // Timer triggered when the service worker considers it should be stopped or
  // an event should be aborted.
  std::unique_ptr<ServiceWorkerTimeoutTimer> timeout_timer;

  // S13nServiceWorker
  // |controller_impl| should be destroyed before |timeout_timer| since the
  // pipe needs to be disconnected before callbacks passed by
  // DispatchSomeEvent() get destructed, which may be stored in |timeout_timer|
  // as parameters of pending tasks added after a termination request.
  std::unique_ptr<ControllerServiceWorkerImpl> controller_impl;

  base::ThreadChecker thread_checker;
  base::WeakPtrFactory<ServiceWorkerContextClient> weak_factory;
  base::WeakPtrFactory<blink::WebServiceWorkerContextProxy> proxy_weak_factory;
};

class ServiceWorkerContextClient::NavigationPreloadRequest final
    : public network::mojom::URLLoaderClient {
 public:
  NavigationPreloadRequest(int fetch_event_id,
                           const GURL& url,
                           mojom::FetchEventPreloadHandlePtr preload_handle)
      : fetch_event_id_(fetch_event_id),
        url_(url),
        url_loader_(std::move(preload_handle->url_loader)),
        binding_(this, std::move(preload_handle->url_loader_client_request)) {}

  ~NavigationPreloadRequest() override {}

  void OnReceiveResponse(
      const network::ResourceResponseHead& response_head,
      network::mojom::DownloadedTempFilePtr downloaded_file) override {
    DCHECK(!response_);
    DCHECK(!downloaded_file);
    response_ = std::make_unique<blink::WebURLResponse>();
    // TODO(horo): Set report_security_info to true when DevTools is attached.
    const bool report_security_info = false;
    WebURLLoaderImpl::PopulateURLResponse(url_, response_head, response_.get(),
                                          report_security_info);
    MaybeReportResponseToClient();
  }

  void OnReceiveRedirect(
      const net::RedirectInfo& redirect_info,
      const network::ResourceResponseHead& response_head) override {
    DCHECK(!response_);
    DCHECK(net::HttpResponseHeaders::IsRedirectResponseCode(
        response_head.headers->response_code()));

    ServiceWorkerContextClient* client =
        ServiceWorkerContextClient::ThreadSpecificInstance();
    if (!client)
      return;
    response_ = std::make_unique<blink::WebURLResponse>();
    WebURLLoaderImpl::PopulateURLResponse(url_, response_head, response_.get(),
                                          false /* report_security_info */);
    client->OnNavigationPreloadResponse(fetch_event_id_, std::move(response_),
                                        nullptr);
    // This will delete |this|.
    client->OnNavigationPreloadComplete(
        fetch_event_id_, response_head.response_start,
        response_head.encoded_data_length, 0 /* encoded_body_length */,
        0 /* decoded_body_length */);
  }

  void OnDataDownloaded(int64_t data_length,
                        int64_t encoded_data_length) override {
    NOTREACHED();
  }

  void OnUploadProgress(int64_t current_position,
                        int64_t total_size,
                        OnUploadProgressCallback ack_callback) override {
    NOTREACHED();
  }

  void OnReceiveCachedMetadata(const std::vector<uint8_t>& data) override {}

  void OnTransferSizeUpdated(int32_t transfer_size_diff) override {
  }

  void OnStartLoadingResponseBody(
      mojo::ScopedDataPipeConsumerHandle body) override {
    DCHECK(!body_.is_valid());
    body_ = std::move(body);
    MaybeReportResponseToClient();
  }

  void OnComplete(const network::URLLoaderCompletionStatus& status) override {
    if (status.error_code != net::OK) {
      std::string message;
      std::string unsanitized_message;
      if (status.error_code == net::ERR_ABORTED) {
        message =
            "The service worker navigation preload request was cancelled "
            "before 'preloadResponse' settled. If you intend to use "
            "'preloadResponse', use waitUntil() or respondWith() to wait for "
            "the promise to settle.";
      } else {
        message =
            "The service worker navigation preload request failed with a "
            "network error.";
        unsanitized_message =
            "The service worker navigation preload request failed with network "
            "error: " +
            net::ErrorToString(status.error_code) + ".";
      }

      // This will delete |this|.
      ReportErrorToClient(message, unsanitized_message);
      return;
    }

    ServiceWorkerContextClient* client =
        ServiceWorkerContextClient::ThreadSpecificInstance();
    if (!client)
      return;
    if (response_) {
      // When the response body from the server is empty, OnComplete() is called
      // without OnStartLoadingResponseBody().
      DCHECK(!body_.is_valid());
      client->OnNavigationPreloadResponse(fetch_event_id_, std::move(response_),
                                          nullptr);
    }
    // This will delete |this|.
    client->OnNavigationPreloadComplete(
        fetch_event_id_, status.completion_time, status.encoded_data_length,
        status.encoded_body_length, status.decoded_body_length);
  }

 private:
  void MaybeReportResponseToClient() {
    if (!response_ || !body_.is_valid())
      return;
    ServiceWorkerContextClient* client =
        ServiceWorkerContextClient::ThreadSpecificInstance();
    if (!client)
      return;

    client->OnNavigationPreloadResponse(
        fetch_event_id_, std::move(response_),
        std::make_unique<WebDataConsumerHandleImpl>(std::move(body_)));
  }

  void ReportErrorToClient(const std::string& message,
                           const std::string& unsanitized_message) {
    ServiceWorkerContextClient* client =
        ServiceWorkerContextClient::ThreadSpecificInstance();
    if (!client)
      return;
    // This will delete |this|.
    client->OnNavigationPreloadError(
        fetch_event_id_, std::make_unique<blink::WebServiceWorkerError>(
                             blink::mojom::ServiceWorkerErrorType::kNetwork,
                             blink::WebString::FromUTF8(message),
                             blink::WebString::FromUTF8(unsanitized_message)));
  }

  const int fetch_event_id_;
  const GURL url_;
  network::mojom::URLLoaderPtr url_loader_;
  mojo::Binding<network::mojom::URLLoaderClient> binding_;

  std::unique_ptr<blink::WebURLResponse> response_;
  mojo::ScopedDataPipeConsumerHandle body_;
};

ServiceWorkerContextClient*
ServiceWorkerContextClient::ThreadSpecificInstance() {
  return g_worker_client_tls.Pointer()->Get();
}

ServiceWorkerContextClient::ServiceWorkerContextClient(
    int embedded_worker_id,
    int64_t service_worker_version_id,
    const GURL& service_worker_scope,
    const GURL& script_url,
    bool is_script_streaming,
    mojom::ServiceWorkerEventDispatcherRequest dispatcher_request,
    mojom::ControllerServiceWorkerRequest controller_request,
    blink::mojom::ServiceWorkerHostAssociatedPtrInfo service_worker_host,
    mojom::EmbeddedWorkerInstanceHostAssociatedPtrInfo instance_host,
    mojom::ServiceWorkerProviderInfoForStartWorkerPtr provider_info,
    std::unique_ptr<EmbeddedWorkerInstanceClientImpl> embedded_worker_client,
    scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> io_thread_task_runner)
    : embedded_worker_id_(embedded_worker_id),
      service_worker_version_id_(service_worker_version_id),
      service_worker_scope_(service_worker_scope),
      script_url_(script_url),
      main_thread_task_runner_(std::move(main_thread_task_runner)),
      io_thread_task_runner_(io_thread_task_runner),
      proxy_(nullptr),
      pending_dispatcher_request_(std::move(dispatcher_request)),
      pending_controller_request_(std::move(controller_request)),
      pending_service_worker_host_(std::move(service_worker_host)),
      embedded_worker_client_(std::move(embedded_worker_client)) {
  instance_host_ =
      mojom::ThreadSafeEmbeddedWorkerInstanceHostAssociatedPtr::Create(
          std::move(instance_host), main_thread_task_runner_);

  // Create a content::ServiceWorkerNetworkProvider for this data source so
  // we can observe its requests.
  pending_network_provider_ = ServiceWorkerNetworkProvider::CreateForController(
      std::move(provider_info));
  provider_context_ = pending_network_provider_->context();

  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1("ServiceWorker",
                                    "ServiceWorkerContextClient", this,
                                    "script_url", script_url_.spec());
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1(
      "ServiceWorker", "LOAD_SCRIPT", this, "Source",
      (is_script_streaming ? "InstalledScriptsManager" : "ResourceLoader"));
}

ServiceWorkerContextClient::~ServiceWorkerContextClient() {}

void ServiceWorkerContextClient::GetClient(
    const blink::WebString& id,
    std::unique_ptr<blink::WebServiceWorkerClientCallbacks> callbacks) {
  DCHECK(callbacks);
  context_->service_worker_host->GetClient(
      id.Utf8(), base::BindOnce(&DidGetClient, std::move(callbacks)));
}

void ServiceWorkerContextClient::GetClients(
    const blink::WebServiceWorkerClientQueryOptions& weboptions,
    std::unique_ptr<blink::WebServiceWorkerClientsCallbacks> callbacks) {
  DCHECK(callbacks);
  auto options = blink::mojom::ServiceWorkerClientQueryOptions::New(
      weboptions.include_uncontrolled, weboptions.client_type);
  context_->service_worker_host->GetClients(
      std::move(options), base::BindOnce(&DidGetClients, std::move(callbacks)));
}

void ServiceWorkerContextClient::OpenNewTab(
    const blink::WebURL& url,
    std::unique_ptr<blink::WebServiceWorkerClientCallbacks> callbacks) {
  DCHECK(callbacks);
  context_->service_worker_host->OpenNewTab(
      url, base::BindOnce(&DidOpenWindow, std::move(callbacks)));
}

void ServiceWorkerContextClient::OpenPaymentHandlerWindow(
    const blink::WebURL& url,
    std::unique_ptr<blink::WebServiceWorkerClientCallbacks> callbacks) {
  DCHECK(callbacks);
  context_->service_worker_host->OpenPaymentHandlerWindow(
      url, base::BindOnce(&DidOpenWindow, std::move(callbacks)));
}

void ServiceWorkerContextClient::SetCachedMetadata(const blink::WebURL& url,
                                                   const char* data,
                                                   size_t size) {
  DCHECK(context_->service_worker_host);
  context_->service_worker_host->SetCachedMetadata(
      url, std::vector<uint8_t>(data, data + size));
}

void ServiceWorkerContextClient::ClearCachedMetadata(const blink::WebURL& url) {
  DCHECK(context_->service_worker_host);
  context_->service_worker_host->ClearCachedMetadata(url);
}

void ServiceWorkerContextClient::WorkerReadyForInspection() {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  (*instance_host_)->OnReadyForInspection();
}

void ServiceWorkerContextClient::WorkerContextFailedToStart() {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(!proxy_);

  (*instance_host_)->OnScriptLoadFailed();
  (*instance_host_)->OnStopped();

  TRACE_EVENT_NESTABLE_ASYNC_END1("ServiceWorker", "ServiceWorkerContextClient",
                                  this, "Status", "WorkerContextFailedToStart");

  DCHECK(embedded_worker_client_);
  embedded_worker_client_->WorkerContextDestroyed();
}

void ServiceWorkerContextClient::WorkerScriptLoaded() {
  (*instance_host_)->OnScriptLoaded();
  TRACE_EVENT_NESTABLE_ASYNC_END0("ServiceWorker", "LOAD_SCRIPT", this);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("ServiceWorker", "START_WORKER_CONTEXT",
                                    this);
}

void ServiceWorkerContextClient::WorkerContextStarted(
    blink::WebServiceWorkerContextProxy* proxy) {
  DCHECK(!worker_task_runner_.get());
  DCHECK_NE(0, WorkerThread::GetCurrentId());
  worker_task_runner_ = base::ThreadTaskRunnerHandle::Get();
  // g_worker_client_tls.Pointer()->Get() could return nullptr if this context
  // gets deleted before workerContextStarted() is called.
  DCHECK(g_worker_client_tls.Pointer()->Get() == nullptr);
  DCHECK(!proxy_);
  g_worker_client_tls.Pointer()->Set(this);
  proxy_ = proxy;

  // Initialize pending callback maps. This needs to be freed on the
  // same thread before the worker context goes away in
  // willDestroyWorkerContext.
  context_.reset(new WorkerContextData(this));
  // Create ServiceWorkerDispatcher first for this worker thread to be used
  // later by TakeRegistrationForServiceWorkerGlobalScope() etc.
  ServiceWorkerDispatcher::GetOrCreateThreadSpecificInstance();

  DCHECK(pending_dispatcher_request_.is_pending());
  DCHECK(pending_controller_request_.is_pending());
  DCHECK(!context_->event_dispatcher_binding.is_bound());
  DCHECK(!context_->controller_impl);
  context_->event_dispatcher_binding.Bind(
      std::move(pending_dispatcher_request_));

  if (ServiceWorkerUtils::IsServicificationEnabled()) {
    context_->controller_impl = std::make_unique<ControllerServiceWorkerImpl>(
        std::move(pending_controller_request_), GetWeakPtr());
  }

  DCHECK(pending_service_worker_host_.is_valid());
  DCHECK(!context_->service_worker_host);
  context_->service_worker_host.Bind(std::move(pending_service_worker_host_));
  // Set ServiceWorkerGlobalScope#registration.
  proxy_->SetRegistration(WebServiceWorkerRegistrationImpl::CreateHandle(
      provider_context_->TakeRegistrationForServiceWorkerGlobalScope()));

  (*instance_host_)->OnThreadStarted(WorkerThread::GetCurrentId());

  TRACE_EVENT_NESTABLE_ASYNC_END0("ServiceWorker", "START_WORKER_CONTEXT",
                                  this);
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("ServiceWorker", "EVALUATE_SCRIPT", this);
}

void ServiceWorkerContextClient::DidEvaluateClassicScript(bool success) {
  DCHECK(worker_task_runner_->RunsTasksInCurrentSequence());
  (*instance_host_)->OnScriptEvaluated(success);

  // Schedule a task to send back WorkerStarted asynchronously,
  // so that at the time we send it we can be sure that the
  // worker run loop has been started.
  worker_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&ServiceWorkerContextClient::SendWorkerStarted,
                                GetWeakPtr()));

  TRACE_EVENT_NESTABLE_ASYNC_END1("ServiceWorker", "EVALUATE_SCRIPT", this,
                                  "Status", success ? "Success" : "Failure");
}

void ServiceWorkerContextClient::DidInitializeWorkerContext(
    v8::Local<v8::Context> context) {
  GetContentClient()
      ->renderer()
      ->DidInitializeServiceWorkerContextOnWorkerThread(
          context, service_worker_version_id_, service_worker_scope_,
          script_url_);
}

void ServiceWorkerContextClient::WillDestroyWorkerContext(
    v8::Local<v8::Context> context) {
  // At this point WillStopCurrentWorkerThread is already called, so
  // worker_task_runner_->RunsTasksInCurrentSequence() returns false
  // (while we're still on the worker thread).
  proxy_ = nullptr;

  blob_registry_.reset();

  // We have to clear callbacks now, as they need to be freed on the
  // same thread.
  context_.reset();

  // This also lets the message filter stop dispatching messages to
  // this client.
  g_worker_client_tls.Pointer()->Set(nullptr);

  GetContentClient()->renderer()->WillDestroyServiceWorkerContextOnWorkerThread(
      context, service_worker_version_id_, service_worker_scope_, script_url_);
}

void ServiceWorkerContextClient::WorkerContextDestroyed() {
  DCHECK(g_worker_client_tls.Pointer()->Get() == nullptr);

  // TODO(shimazu): The signals to the browser should be in the order:
  // (1) WorkerStopped (via mojo call EmbeddedWorkerInstanceHost.OnStopped())
  // (2) ProviderDestroyed (via mojo call
  // ServiceWorkerDispatcherHost.OnProviderDestroyed()), this is triggered by
  // the following EmbeddedWorkerInstanceClientImpl::WorkerContextDestroyed(),
  // which will eventually lead to destruction of the service worker provider.
  // But currently EmbeddedWorkerInstanceHost interface is associated with
  // EmbeddedWorkerInstanceClient interface, and ServiceWorkerDispatcherHost
  // interface is associated with the IPC channel, since they are using
  // different mojo message pipes, the FIFO ordering can not be guaranteed now.
  // This will be solved once ServiceWorkerProvider{Host,Client} are mojoified
  // and they are also associated with EmbeddedWorkerInstanceClient in other CLs
  // (https://crrev.com/2653493009 and https://crrev.com/2779763004).
  (*instance_host_)->OnStopped();

  DCHECK(embedded_worker_client_);
  main_thread_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&EmbeddedWorkerInstanceClientImpl::WorkerContextDestroyed,
                     std::move(embedded_worker_client_)));
}

void ServiceWorkerContextClient::CountFeature(
    blink::mojom::WebFeature feature) {
  (*instance_host_)->CountFeature(feature);
}

void ServiceWorkerContextClient::ReportException(
    const blink::WebString& error_message,
    int line_number,
    int column_number,
    const blink::WebString& source_url) {
  (*instance_host_)
      ->OnReportException(error_message.Utf16(), line_number, column_number,
                          blink::WebStringToGURL(source_url));
}

void ServiceWorkerContextClient::ReportConsoleMessage(
    int source,
    int level,
    const blink::WebString& message,
    int line_number,
    const blink::WebString& source_url) {
  (*instance_host_)
      ->OnReportConsoleMessage(source, level, message.Utf16(), line_number,
                               blink::WebStringToGURL(source_url));
}

void ServiceWorkerContextClient::DidHandleActivateEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->activate_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::DidHandleBackgroundFetchAbortEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->background_fetch_abort_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::DidHandleBackgroundFetchClickEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->background_fetch_click_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::DidHandleBackgroundFetchFailEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->background_fetch_fail_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::DidHandleBackgroundFetchedEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->background_fetched_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::DidHandleExtendableMessageEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->message_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::DidHandleInstallEvent(
    int event_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->install_event_callbacks,
                   context_->timeout_timer.get(), event_id, status,
                   proxy_->HasFetchEventHandler(),
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::RespondToFetchEventWithNoResponse(
    int fetch_event_id,
    double event_dispatch_time) {
  DCHECK(base::ContainsKey(context_->fetch_response_callbacks, fetch_event_id));
  const mojom::ServiceWorkerFetchResponseCallbackPtr& response_callback =
      context_->fetch_response_callbacks[fetch_event_id];
  DCHECK(response_callback.is_bound());
  response_callback->OnFallback(base::Time::FromDoubleT(event_dispatch_time));
  context_->fetch_response_callbacks.erase(fetch_event_id);
}

void ServiceWorkerContextClient::RespondToFetchEvent(
    int fetch_event_id,
    const blink::WebServiceWorkerResponse& web_response,
    double event_dispatch_time) {
  DCHECK(base::ContainsKey(context_->fetch_response_callbacks, fetch_event_id));
  ServiceWorkerResponse response(
      GetServiceWorkerResponseFromWebResponse(web_response));
  const mojom::ServiceWorkerFetchResponseCallbackPtr& response_callback =
      context_->fetch_response_callbacks[fetch_event_id];

  if (!response.blob_uuid.empty()) {
    // TODO(falken): Can we just keep |response.blob| and call OnResponse
    // directly?
    blink::mojom::BlobPtr blob_ptr;
    DCHECK(response.blob);
    blob_ptr = response.blob->TakeBlobPtr();
    response.blob = nullptr;
    response_callback->OnResponseBlob(
        response, std::move(blob_ptr),
        base::Time::FromDoubleT(event_dispatch_time));
  } else {
    response_callback->OnResponse(response,
                                  base::Time::FromDoubleT(event_dispatch_time));
  }
  context_->fetch_response_callbacks.erase(fetch_event_id);
}

void ServiceWorkerContextClient::RespondToFetchEventWithResponseStream(
    int fetch_event_id,
    const blink::WebServiceWorkerResponse& web_response,
    blink::WebServiceWorkerStreamHandle* web_body_as_stream,
    double event_dispatch_time) {
  DCHECK(base::ContainsKey(context_->fetch_response_callbacks, fetch_event_id));
  ServiceWorkerResponse response(
      GetServiceWorkerResponseFromWebResponse(web_response));
  const mojom::ServiceWorkerFetchResponseCallbackPtr& response_callback =
      context_->fetch_response_callbacks[fetch_event_id];
  blink::mojom::ServiceWorkerStreamHandlePtr body_as_stream =
      blink::mojom::ServiceWorkerStreamHandle::New();
  blink::mojom::ServiceWorkerStreamCallbackPtr callback_ptr;
  body_as_stream->callback_request = mojo::MakeRequest(&callback_ptr);
  body_as_stream->stream = web_body_as_stream->DrainStreamDataPipe();
  DCHECK(body_as_stream->stream.is_valid());

  web_body_as_stream->SetListener(
      std::make_unique<StreamHandleListener>(std::move(callback_ptr)));

  response_callback->OnResponseStream(
      response, std::move(body_as_stream),
      base::Time::FromDoubleT(event_dispatch_time));
  context_->fetch_response_callbacks.erase(fetch_event_id);
}

void ServiceWorkerContextClient::DidHandleFetchEvent(
    int event_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  // This TRACE_EVENT is used for perf benchmark to confirm if all of fetch
  // events have completed. (crbug.com/736697)
  TRACE_EVENT1("ServiceWorker",
               "ServiceWorkerContextClient::DidHandleFetchEvent", "event_id",
               event_id);
  if (RunEventCallback(&context_->fetch_event_callbacks,
                       context_->timeout_timer.get(), event_id, status,
                       base::Time::FromDoubleT(event_dispatch_time))) {
    context_->fetch_response_callbacks.erase(event_id);
  }
}

void ServiceWorkerContextClient::DidHandleNotificationClickEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->notification_click_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::DidHandleNotificationCloseEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->notification_close_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::DidHandlePushEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->push_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::DidHandleSyncEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  RunEventCallback(&context_->sync_event_callbacks,
                   context_->timeout_timer.get(), request_id, status,
                   base::Time::FromDoubleT(event_dispatch_time));
}

void ServiceWorkerContextClient::RespondToAbortPaymentEvent(
    int event_id,
    bool payment_aborted,
    double dispatch_event_time) {
  DCHECK(base::ContainsKey(context_->abort_payment_result_callbacks, event_id));
  const payments::mojom::PaymentHandlerResponseCallbackPtr& result_callback =
      context_->abort_payment_result_callbacks[event_id];
  result_callback->OnResponseForAbortPayment(
      payment_aborted, base::Time::FromDoubleT(dispatch_event_time));
  context_->abort_payment_result_callbacks.erase(event_id);
}

void ServiceWorkerContextClient::DidHandleAbortPaymentEvent(
    int event_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double dispatch_event_time) {
  if (RunEventCallback(&context_->abort_payment_event_callbacks,
                       context_->timeout_timer.get(), event_id, status,
                       base::Time::FromDoubleT(dispatch_event_time))) {
    context_->abort_payment_result_callbacks.erase(event_id);
  }
}

void ServiceWorkerContextClient::RespondToCanMakePaymentEvent(
    int event_id,
    bool can_make_payment,
    double dispatch_event_time) {
  DCHECK(
      base::ContainsKey(context_->can_make_payment_result_callbacks, event_id));
  const payments::mojom::PaymentHandlerResponseCallbackPtr& result_callback =
      context_->can_make_payment_result_callbacks[event_id];
  result_callback->OnResponseForCanMakePayment(
      can_make_payment, base::Time::FromDoubleT(dispatch_event_time));
  context_->can_make_payment_result_callbacks.erase(event_id);
}

void ServiceWorkerContextClient::DidHandleCanMakePaymentEvent(
    int event_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double dispatch_event_time) {
  if (RunEventCallback(&context_->can_make_payment_event_callbacks,
                       context_->timeout_timer.get(), event_id, status,
                       base::Time::FromDoubleT(dispatch_event_time))) {
    context_->can_make_payment_result_callbacks.erase(event_id);
  }
}

void ServiceWorkerContextClient::RespondToPaymentRequestEvent(
    int payment_request_id,
    const blink::WebPaymentHandlerResponse& web_response,
    double dispatch_event_time) {
  DCHECK(base::ContainsKey(context_->payment_response_callbacks,
                           payment_request_id));
  const payments::mojom::PaymentHandlerResponseCallbackPtr& response_callback =
      context_->payment_response_callbacks[payment_request_id];
  payments::mojom::PaymentHandlerResponsePtr response =
      payments::mojom::PaymentHandlerResponse::New();
  response->method_name = web_response.method_name.Utf8();
  response->stringified_details = web_response.stringified_details.Utf8();
  response_callback->OnResponseForPaymentRequest(
      std::move(response), base::Time::FromDoubleT(dispatch_event_time));
  context_->payment_response_callbacks.erase(payment_request_id);
}

void ServiceWorkerContextClient::DidHandlePaymentRequestEvent(
    int payment_request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double event_dispatch_time) {
  if (RunEventCallback(&context_->payment_request_event_callbacks,
                       context_->timeout_timer.get(), payment_request_id,
                       status, base::Time::FromDoubleT(event_dispatch_time))) {
    context_->payment_response_callbacks.erase(payment_request_id);
  }
}

std::unique_ptr<blink::WebServiceWorkerNetworkProvider>
ServiceWorkerContextClient::CreateServiceWorkerNetworkProvider() {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  return std::make_unique<WebServiceWorkerNetworkProviderImpl>(
      std::move(pending_network_provider_));
}

std::unique_ptr<blink::WebWorkerFetchContext>
ServiceWorkerContextClient::CreateServiceWorkerFetchContext() {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());

  scoped_refptr<ChildURLLoaderFactoryBundle> url_loader_factory_bundle =
      RenderThreadImpl::current()
          ->blink_platform_impl()
          ->CreateDefaultURLLoaderFactoryBundle();
  DCHECK(url_loader_factory_bundle);
  return std::make_unique<ServiceWorkerFetchContextImpl>(
      script_url_, url_loader_factory_bundle->Clone(),
      provider_context_->provider_id(),
      GetContentClient()->renderer()->CreateURLLoaderThrottleProvider(
          URLLoaderThrottleProviderType::kWorker),
      GetContentClient()
          ->renderer()
          ->CreateWebSocketHandshakeThrottleProvider());
}

std::unique_ptr<blink::WebServiceWorkerProvider>
ServiceWorkerContextClient::CreateServiceWorkerProvider() {
  DCHECK(main_thread_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(provider_context_);

  return std::make_unique<WebServiceWorkerProviderImpl>(
      provider_context_.get());
}

void ServiceWorkerContextClient::PostMessageToClient(
    const blink::WebString& uuid,
    blink::TransferableMessage message) {
  context_->service_worker_host->PostMessageToClient(uuid.Utf8(),
                                                     std::move(message));
}

void ServiceWorkerContextClient::Focus(
    const blink::WebString& uuid,
    std::unique_ptr<blink::WebServiceWorkerClientCallbacks> callbacks) {
  DCHECK(callbacks);
  context_->service_worker_host->FocusClient(
      uuid.Utf8(), base::BindOnce(&DidFocusClient, std::move(callbacks)));
}

void ServiceWorkerContextClient::Navigate(
    const blink::WebString& uuid,
    const blink::WebURL& url,
    std::unique_ptr<blink::WebServiceWorkerClientCallbacks> callbacks) {
  DCHECK(callbacks);
  context_->service_worker_host->NavigateClient(
      uuid.Utf8(), url,
      base::BindOnce(&DidNavigateClient, std::move(callbacks)));
}

void ServiceWorkerContextClient::SkipWaiting(
    std::unique_ptr<blink::WebServiceWorkerSkipWaitingCallbacks> callbacks) {
  DCHECK(callbacks);
  DCHECK(context_->service_worker_host);
  context_->service_worker_host->SkipWaiting(
      base::BindOnce(&DidSkipWaiting, std::move(callbacks)));
}

void ServiceWorkerContextClient::Claim(
    std::unique_ptr<blink::WebServiceWorkerClientsClaimCallbacks> callbacks) {
  DCHECK(callbacks);
  DCHECK(context_->service_worker_host);
  context_->service_worker_host->ClaimClients(
      base::BindOnce(&DidClaimClients, std::move(callbacks)));
}

void ServiceWorkerContextClient::DispatchOrQueueFetchEvent(
    mojom::DispatchFetchEventParamsPtr params,
    mojom::ServiceWorkerFetchResponseCallbackPtr response_callback,
    DispatchFetchEventCallback callback) {
  if (RequestedTermination()) {
    context_->timeout_timer->PushPendingTask(base::BindOnce(
        &ServiceWorkerContextClient::DispatchFetchEvent, GetWeakPtr(),
        std::move(params), std::move(response_callback), std::move(callback)));
    return;
  }
  DispatchFetchEvent(std::move(params), std::move(response_callback),
                     std::move(callback));
}

void ServiceWorkerContextClient::DispatchSyncEvent(
    const std::string& tag,
    bool last_chance,
    base::TimeDelta timeout,
    DispatchSyncEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchSyncEvent");
  int request_id = context_->timeout_timer->StartEventWithCustomTimeout(
      CreateAbortCallback(&context_->sync_event_callbacks), timeout);
  context_->sync_event_callbacks.emplace(request_id, std::move(callback));

  // TODO(jkarlin): Make this blink::WebString::FromUTF8Lenient once
  // https://crrev.com/1768063002/ lands.
  proxy_->DispatchSyncEvent(request_id, blink::WebString::FromUTF8(tag),
                            last_chance);
}

void ServiceWorkerContextClient::DispatchAbortPaymentEvent(
    int /* event_id */,  // TODO(shimazu): Remove this.
    payments::mojom::PaymentHandlerResponseCallbackPtr response_callback,
    DispatchAbortPaymentEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchAbortPaymentEvent");
  int event_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->abort_payment_event_callbacks));
  context_->abort_payment_event_callbacks.emplace(event_id,
                                                  std::move(callback));
  context_->abort_payment_result_callbacks.emplace(
      event_id, std::move(response_callback));
  proxy_->DispatchAbortPaymentEvent(event_id);
}

void ServiceWorkerContextClient::DispatchCanMakePaymentEvent(
    int /* event_id */,  // TODO(shimazu): Remove this.
    payments::mojom::CanMakePaymentEventDataPtr eventData,
    payments::mojom::PaymentHandlerResponseCallbackPtr response_callback,
    DispatchCanMakePaymentEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchCanMakePaymentEvent");
  int event_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->can_make_payment_event_callbacks));
  context_->can_make_payment_event_callbacks.emplace(event_id,
                                                     std::move(callback));
  context_->can_make_payment_result_callbacks.emplace(
      event_id, std::move(response_callback));

  blink::WebCanMakePaymentEventData webEventData =
      mojo::ConvertTo<blink::WebCanMakePaymentEventData>(std::move(eventData));
  proxy_->DispatchCanMakePaymentEvent(event_id, webEventData);
}

void ServiceWorkerContextClient::DispatchPaymentRequestEvent(
    int /* payment_request_id */,  // TODO(shimazu): Remove this.
    payments::mojom::PaymentRequestEventDataPtr eventData,
    payments::mojom::PaymentHandlerResponseCallbackPtr response_callback,
    DispatchPaymentRequestEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchPaymentRequestEvent");
  int event_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->payment_request_event_callbacks));
  context_->payment_request_event_callbacks.emplace(event_id,
                                                    std::move(callback));
  context_->payment_response_callbacks.emplace(event_id,
                                               std::move(response_callback));

  blink::WebPaymentRequestEventData webEventData =
      mojo::ConvertTo<blink::WebPaymentRequestEventData>(std::move(eventData));
  proxy_->DispatchPaymentRequestEvent(event_id, webEventData);
}

void ServiceWorkerContextClient::SendWorkerStarted() {
  DCHECK(worker_task_runner_->RunsTasksInCurrentSequence());
  mojom::EmbeddedWorkerStartTimingPtr timing =
      mojom::EmbeddedWorkerStartTiming::New();
  timing->start_worker_received_time = start_worker_received_time_;
  timing->blink_initialized_time = blink_initialized_time_;
  (*instance_host_)->OnStarted(std::move(timing));
  TRACE_EVENT_NESTABLE_ASYNC_END0("ServiceWorker", "ServiceWorkerContextClient",
                                  this);

  // Start the idle timer.
  context_->timeout_timer =
      std::make_unique<ServiceWorkerTimeoutTimer>(base::BindRepeating(
          &ServiceWorkerContextClient::OnIdleTimeout, base::Unretained(this)));
}

void ServiceWorkerContextClient::DispatchActivateEvent(
    DispatchActivateEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchActivateEvent");
  int request_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->activate_event_callbacks));
  context_->activate_event_callbacks.emplace(request_id, std::move(callback));
  proxy_->DispatchActivateEvent(request_id);
}

void ServiceWorkerContextClient::DispatchBackgroundFetchAbortEvent(
    const std::string& developer_id,
    DispatchBackgroundFetchAbortEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchBackgroundFetchAbortEvent");
  int request_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->background_fetch_abort_event_callbacks));
  context_->background_fetch_abort_event_callbacks.emplace(request_id,
                                                           std::move(callback));
  proxy_->DispatchBackgroundFetchAbortEvent(
      request_id, blink::WebString::FromUTF8(developer_id));
}

void ServiceWorkerContextClient::DispatchBackgroundFetchClickEvent(
    const std::string& developer_id,
    mojom::BackgroundFetchState state,
    DispatchBackgroundFetchClickEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchBackgroundFetchClickEvent");
  int request_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->background_fetch_click_event_callbacks));
  context_->background_fetch_click_event_callbacks.emplace(request_id,
                                                           std::move(callback));

  // TODO(peter): Use typemap when this is moved to blink-side.
  blink::WebServiceWorkerContextProxy::BackgroundFetchState web_state =
      mojo::ConvertTo<
          blink::WebServiceWorkerContextProxy::BackgroundFetchState>(state);
  proxy_->DispatchBackgroundFetchClickEvent(
      request_id, blink::WebString::FromUTF8(developer_id), web_state);
}

void ServiceWorkerContextClient::DispatchBackgroundFetchFailEvent(
    const std::string& developer_id,
    const std::vector<BackgroundFetchSettledFetch>& fetches,
    DispatchBackgroundFetchFailEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchBackgroundFetchFailEvent");
  int request_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->background_fetch_fail_event_callbacks));
  context_->background_fetch_fail_event_callbacks.emplace(request_id,
                                                          std::move(callback));

  blink::WebVector<blink::WebBackgroundFetchSettledFetch> web_fetches(
      fetches.size());
  for (size_t i = 0; i < fetches.size(); ++i) {
    ToWebServiceWorkerRequest(fetches[i].request, &web_fetches[i].request);
    ToWebServiceWorkerResponse(fetches[i].response, &web_fetches[i].response);
  }

  proxy_->DispatchBackgroundFetchFailEvent(
      request_id, blink::WebString::FromUTF8(developer_id), web_fetches);
}

void ServiceWorkerContextClient::DispatchBackgroundFetchedEvent(
    const std::string& developer_id,
    const std::string& unique_id,
    const std::vector<BackgroundFetchSettledFetch>& fetches,
    DispatchBackgroundFetchedEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchBackgroundFetchedEvent");
  int request_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->background_fetched_event_callbacks));
  context_->background_fetched_event_callbacks.emplace(request_id,
                                                       std::move(callback));

  blink::WebVector<blink::WebBackgroundFetchSettledFetch> web_fetches(
      fetches.size());
  for (size_t i = 0; i < fetches.size(); ++i) {
    ToWebServiceWorkerRequest(fetches[i].request, &web_fetches[i].request);
    ToWebServiceWorkerResponse(fetches[i].response, &web_fetches[i].response);
  }

  proxy_->DispatchBackgroundFetchedEvent(
      request_id, blink::WebString::FromUTF8(developer_id),
      blink::WebString::FromUTF8(unique_id), web_fetches);
}

void ServiceWorkerContextClient::DispatchInstallEvent(
    DispatchInstallEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchInstallEvent");

  int event_id = context_->timeout_timer->StartEvent(CreateAbortCallback(
      &context_->install_event_callbacks, false /* has_fetch_handler */));
  context_->install_event_callbacks.emplace(event_id, std::move(callback));
  proxy_->DispatchInstallEvent(event_id);
}

void ServiceWorkerContextClient::DispatchExtendableMessageEvent(
    mojom::ExtendableMessageEventPtr event,
    DispatchExtendableMessageEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchExtendableMessageEvent");
  int request_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->message_event_callbacks));
  context_->message_event_callbacks.emplace(request_id, std::move(callback));

  if (event->source_info_for_client) {
    blink::WebServiceWorkerClientInfo web_client =
        ToWebServiceWorkerClientInfo(std::move(event->source_info_for_client));
    proxy_->DispatchExtendableMessageEvent(request_id,
                                           std::move(event->message),
                                           event->source_origin, web_client);
    return;
  }

  DCHECK(event->source_info_for_service_worker->handle_id !=
             blink::mojom::kInvalidServiceWorkerHandleId &&
         event->source_info_for_service_worker->version_id !=
             blink::mojom::kInvalidServiceWorkerVersionId);
  scoped_refptr<WebServiceWorkerImpl> worker =
      ServiceWorkerDispatcher::GetThreadSpecificInstance()
          ->GetOrCreateServiceWorker(
              std::move(event->source_info_for_service_worker));
  proxy_->DispatchExtendableMessageEvent(
      request_id, std::move(event->message), event->source_origin,
      WebServiceWorkerImpl::CreateHandle(worker));
}

// S13nServiceWorker
void ServiceWorkerContextClient::DispatchFetchEvent(
    mojom::DispatchFetchEventParamsPtr params,
    mojom::ServiceWorkerFetchResponseCallbackPtr response_callback,
    DispatchFetchEventCallback callback) {
  int event_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->fetch_event_callbacks));
  context_->fetch_event_callbacks.emplace(event_id, std::move(callback));
  context_->fetch_response_callbacks.emplace(event_id,
                                             std::move(response_callback));

  // This TRACE_EVENT is used for perf benchmark to confirm if all of fetch
  // events have completed. (crbug.com/736697)
  TRACE_EVENT1("ServiceWorker",
               "ServiceWorkerContextClient::DispatchFetchEvent", "event_id",
               event_id);

  // Set up for navigation preload (FetchEvent#preloadResponse) if needed.
  const bool navigation_preload_sent = !!params->preload_handle;
  if (navigation_preload_sent) {
    SetupNavigationPreload(event_id, params->request.url,
                           std::move(params->preload_handle));
  }

  // Dispatch the event to the service worker execution context.
  blink::WebServiceWorkerRequest web_request;
  ToWebServiceWorkerRequest(
      std::move(params->request), params->request_body_blob_uuid,
      params->request_body_blob_size, std::move(params->request_body_blob),
      params->client_id, &web_request);
  proxy_->DispatchFetchEvent(event_id, web_request, navigation_preload_sent);
}

void ServiceWorkerContextClient::DispatchNotificationClickEvent(
    const std::string& notification_id,
    const PlatformNotificationData& notification_data,
    int action_index,
    const base::Optional<base::string16>& reply,
    DispatchNotificationClickEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchNotificationClickEvent");

  int request_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->notification_click_event_callbacks));
  context_->notification_click_event_callbacks.emplace(request_id,
                                                       std::move(callback));

  blink::WebString web_reply;
  if (reply)
    web_reply = blink::WebString::FromUTF16(reply.value());

  proxy_->DispatchNotificationClickEvent(
      request_id, blink::WebString::FromUTF8(notification_id),
      ToWebNotificationData(notification_data), action_index, web_reply);
}

void ServiceWorkerContextClient::DispatchNotificationCloseEvent(
    const std::string& notification_id,
    const PlatformNotificationData& notification_data,
    DispatchNotificationCloseEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchNotificationCloseEvent");

  int request_id = context_->timeout_timer->StartEvent(
      CreateAbortCallback(&context_->notification_close_event_callbacks));
  context_->notification_close_event_callbacks.emplace(request_id,
                                                       std::move(callback));
  proxy_->DispatchNotificationCloseEvent(
      request_id, blink::WebString::FromUTF8(notification_id),
      ToWebNotificationData(notification_data));
}

void ServiceWorkerContextClient::DispatchPushEvent(
    const PushEventPayload& payload,
    DispatchPushEventCallback callback) {
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerContextClient::DispatchPushEvent");

  int request_id = context_->timeout_timer->StartEventWithCustomTimeout(
      CreateAbortCallback(&context_->push_event_callbacks),
      base::TimeDelta::FromSeconds(mojom::kPushEventTimeoutSeconds));
  context_->push_event_callbacks.emplace(request_id, std::move(callback));

  // Only set data to be a valid string if the payload had decrypted data.
  blink::WebString data;
  if (!payload.is_null)
    data = blink::WebString::FromUTF8(payload.data);
  proxy_->DispatchPushEvent(request_id, data);
}

void ServiceWorkerContextClient::Ping(PingCallback callback) {
  std::move(callback).Run();
}

void ServiceWorkerContextClient::SetIdleTimerDelayToZero() {
  DCHECK(ServiceWorkerUtils::IsServicificationEnabled());
  DCHECK(context_);
  DCHECK(context_->timeout_timer);
  context_->timeout_timer->SetIdleTimerDelayToZero();
}

void ServiceWorkerContextClient::OnNavigationPreloadResponse(
    int fetch_event_id,
    std::unique_ptr<blink::WebURLResponse> response,
    std::unique_ptr<blink::WebDataConsumerHandle> data_consumer_handle) {
  proxy_->OnNavigationPreloadResponse(fetch_event_id, std::move(response),
                                      std::move(data_consumer_handle));
}

void ServiceWorkerContextClient::OnNavigationPreloadError(
    int fetch_event_id,
    std::unique_ptr<blink::WebServiceWorkerError> error) {
  proxy_->OnNavigationPreloadError(fetch_event_id, std::move(error));
  context_->preload_requests.Remove(fetch_event_id);
}

void ServiceWorkerContextClient::OnNavigationPreloadComplete(
    int fetch_event_id,
    base::TimeTicks completion_time,
    int64_t encoded_data_length,
    int64_t encoded_body_length,
    int64_t decoded_body_length) {
  proxy_->OnNavigationPreloadComplete(
      fetch_event_id, (completion_time - base::TimeTicks()).InSecondsF(),
      encoded_data_length, encoded_body_length, decoded_body_length);
  context_->preload_requests.Remove(fetch_event_id);
}

void ServiceWorkerContextClient::SetupNavigationPreload(
    int fetch_event_id,
    const GURL& url,
    mojom::FetchEventPreloadHandlePtr preload_handle) {
  auto preload_request = std::make_unique<NavigationPreloadRequest>(
      fetch_event_id, url, std::move(preload_handle));
  context_->preload_requests.AddWithID(std::move(preload_request),
                                       fetch_event_id);
}

void ServiceWorkerContextClient::OnIdleTimeout() {
  // ServiceWorkerTimeoutTimer::did_idle_timeout() returns true if
  // ServiceWorkerContextClient::OnIdleTiemout() has been called. It means
  // termination has been requested.
  DCHECK(RequestedTermination());
  (*instance_host_)->RequestTermination();
}

bool ServiceWorkerContextClient::RequestedTermination() const {
  return context_->timeout_timer->did_idle_timeout();
}

base::WeakPtr<ServiceWorkerContextClient>
ServiceWorkerContextClient::GetWeakPtr() {
  DCHECK(worker_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(context_);
  return context_->weak_factory.GetWeakPtr();
}

// static
void ServiceWorkerContextClient::ResetThreadSpecificInstanceForTesting() {
  g_worker_client_tls.Pointer()->Set(nullptr);
}

void ServiceWorkerContextClient::SetTimeoutTimerForTesting(
    std::unique_ptr<ServiceWorkerTimeoutTimer> timeout_timer) {
  DCHECK(context_);
  context_->timeout_timer = std::move(timeout_timer);
}

}  // namespace content

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See http://dev.chromium.org/developers/design-documents/multi-process-resource-loading

#ifndef CONTENT_RENDERER_LOADER_RESOURCE_DISPATCHER_H_
#define CONTENT_RENDERER_LOADER_RESOURCE_DISPATCHER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/containers/circular_deque.h"
#include "base/containers/hash_tables.h"
#include "base/macros.h"
#include "base/memory/linked_ptr.h"
#include "base/memory/shared_memory.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/time/time.h"
#include "content/common/content_export.h"
#include "content/public/common/resource_load_info.mojom.h"
#include "content/public/common/resource_type.h"
#include "content/public/common/url_loader_throttle.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "net/base/request_priority.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "url/gurl.h"

namespace base {
class WaitableEvent;
}

namespace net {
struct RedirectInfo;
}

namespace network {
struct ResourceResponseInfo;
struct ResourceRequest;
struct ResourceResponseHead;
struct URLLoaderCompletionStatus;
namespace mojom {
class URLLoaderFactory;
}
}

namespace content {
struct NavigationResponseOverrideParameters;
class RequestPeer;
class ResourceDispatcherDelegate;
struct SyncLoadResponse;
class ThrottlingURLLoader;
class URLLoaderClientImpl;

// This class serves as a communication interface to the ResourceDispatcherHost
// in the browser process. It can be used from any child process.
// Virtual methods are for tests.
class CONTENT_EXPORT ResourceDispatcher {
 public:
  // Generates ids for requests initiated by child processes unique to the
  // particular process, counted up from 0 (browser initiated requests count
  // down from -2).
  //
  // Public to be used by URLLoaderFactory and/or URLLoader implementations with
  // the need to perform additional requests besides the main request, e.g.,
  // CORS preflight requests.
  static int MakeRequestID();

  ResourceDispatcher();
  virtual ~ResourceDispatcher();

  // Call this method to load the resource synchronously (i.e., in one shot).
  // This is an alternative to the StartAsync method. Be warned that this method
  // will block the calling thread until the resource is fully downloaded or an
  // error occurs. It could block the calling thread for a long time, so only
  // use this if you really need it!  There is also no way for the caller to
  // interrupt this method. Errors are reported via the status field of the
  // response parameter.
  //
  // |routing_id| is used to associated the bridge with a frame's network
  // context.
  // |timeout| (in seconds) is used to abort the sync request on timeouts.
  // If |download_to_blob_registry| is not null, it is used to redirect the
  // download to a blob, using StartAsync's |pass_response_pipe_to_peer| flag.
  virtual void StartSync(
      std::unique_ptr<network::ResourceRequest> request,
      int routing_id,
      const net::NetworkTrafficAnnotationTag& traffic_annotation,
      SyncLoadResponse* response,
      scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
      std::vector<std::unique_ptr<URLLoaderThrottle>> throttles,
      double timeout,
      blink::mojom::BlobRegistryPtrInfo download_to_blob_registry);

  // Call this method to initiate the request. If this method succeeds, then
  // the peer's methods will be called asynchronously to report various events.
  // Returns the request id. |url_loader_factory| must be non-null.
  //
  // |routing_id| is used to associated the bridge with a frame's network
  // context.
  //
  // If |pass_response_pipe_to_peer| is true, the raw datapipe containing the
  // response body is passed on to |peer| without any extra processing. If it
  // is set to false instead OnReceivedData is called on the |peer| whenever a
  // chunk of data is available.
  //
  // You need to pass a non-null |loading_task_runner| to specify task queue to
  // execute loading tasks on.
  virtual int StartAsync(
      std::unique_ptr<network::ResourceRequest> request,
      int routing_id,
      scoped_refptr<base::SingleThreadTaskRunner> loading_task_runner,
      const net::NetworkTrafficAnnotationTag& traffic_annotation,
      bool is_sync,
      bool pass_response_pipe_to_peer,
      std::unique_ptr<RequestPeer> peer,
      scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
      std::vector<std::unique_ptr<URLLoaderThrottle>> throttles,
      std::unique_ptr<NavigationResponseOverrideParameters>
          response_override_params,
      base::OnceClosure* continue_navigation_function);

  network::mojom::DownloadedTempFilePtr TakeDownloadedTempFile(int request_id);

  // Removes a request from the |pending_requests_| list, returning true if the
  // request was found and removed.
  bool RemovePendingRequest(
      int request_id,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  // Cancels a request in the |pending_requests_| list.  The request will be
  // removed from the dispatcher as well.
  virtual void Cancel(int request_id,
                      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  // Toggles the is_deferred attribute for the specified request.
  virtual void SetDefersLoading(int request_id, bool value);

  // Indicates the priority of the specified request changed.
  void DidChangePriority(int request_id,
                         net::RequestPriority new_priority,
                         int intra_priority_value);

  // This does not take ownership of the delegate. It is expected that the
  // delegate have a longer lifetime than the ResourceDispatcher.
  void set_delegate(ResourceDispatcherDelegate* delegate) {
    delegate_ = delegate;
  }

  base::WeakPtr<ResourceDispatcher> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

  void OnTransferSizeUpdated(int request_id, int32_t transfer_size_diff);

  // This is used only when |this| is created for a worker thread.
  // Sets |terminate_sync_load_event_| which will be signaled from the main
  // thread when the worker thread is being terminated so that the sync requests
  // requested on the worker thread can be aborted.
  void set_terminate_sync_load_event(
      base::WaitableEvent* terminate_sync_load_event) {
    terminate_sync_load_event_ = terminate_sync_load_event;
  }

 private:
  friend class URLLoaderClientImpl;
  friend class URLResponseBodyConsumer;
  friend class ResourceDispatcherTest;

  struct PendingRequestInfo {
    PendingRequestInfo(std::unique_ptr<RequestPeer> peer,
                       ResourceType resource_type,
                       int render_frame_id,
                       const GURL& request_url,
                       const std::string& method,
                       const GURL& referrer,
                       bool download_to_file,
                       std::unique_ptr<NavigationResponseOverrideParameters>
                           response_override_params);

    ~PendingRequestInfo();

    std::unique_ptr<RequestPeer> peer;
    ResourceType resource_type;
    int render_frame_id;
    bool is_deferred = false;
    // Original requested url.
    GURL url;
    // The url, method and referrer of the latest response even in case of
    // redirection.
    GURL response_url;
    std::string response_method;
    GURL response_referrer;
    bool download_to_file;
    bool has_pending_redirect = false;
    base::TimeTicks request_start;
    base::TimeTicks response_start;
    base::TimeTicks completion_time;
    net::LoadTimingInfo load_timing_info;
    linked_ptr<base::SharedMemory> buffer;
    int buffer_size;
    net::IPAddress parsed_ip;
    bool network_accessed = false;
    std::string mime_type;
    std::unique_ptr<NavigationResponseOverrideParameters>
        navigation_response_override;
    bool should_follow_redirect = true;
    bool always_access_network = false;

    std::vector<content::mojom::RedirectInfoPtr> redirect_info_chain;

    // For mojo loading.
    std::unique_ptr<ThrottlingURLLoader> url_loader;
    std::unique_ptr<URLLoaderClientImpl> url_loader_client;
  };
  using PendingRequestMap = std::map<int, std::unique_ptr<PendingRequestInfo>>;

  // Helper to lookup the info based on the request_id.
  // May return NULL if the request as been canceled from the client side.
  PendingRequestInfo* GetPendingRequestInfo(int request_id);

  // Follows redirect, if any, for the given request.
  void FollowPendingRedirect(PendingRequestInfo* request_info);

  // Message response handlers, called by the message handler for this process.
  void OnUploadProgress(int request_id, int64_t position, int64_t size);
  void OnReceivedResponse(int request_id, const network::ResourceResponseHead&);
  void OnReceivedCachedMetadata(int request_id,
                                const std::vector<uint8_t>& data);
  void OnReceivedRedirect(
      int request_id,
      const net::RedirectInfo& redirect_info,
      const network::ResourceResponseHead& response_head,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);
  void OnStartLoadingResponseBody(int request_id,
                                  mojo::ScopedDataPipeConsumerHandle body);
  void OnDownloadedData(int request_id, int data_len, int encoded_data_length);
  void OnRequestComplete(int request_id,
                         const network::URLLoaderCompletionStatus& status);

  void ToResourceResponseInfo(
      const PendingRequestInfo& request_info,
      const network::ResourceResponseHead& browser_info,
      network::ResourceResponseInfo* renderer_info) const;

  base::TimeTicks ToRendererCompletionTime(
      const PendingRequestInfo& request_info,
      const base::TimeTicks& browser_completion_time) const;

  void ContinueForNavigation(int request_id);

  // All pending requests issued to the host
  PendingRequestMap pending_requests_;

  ResourceDispatcherDelegate* delegate_;

  base::WaitableEvent* terminate_sync_load_event_ = nullptr;

  base::WeakPtrFactory<ResourceDispatcher> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ResourceDispatcher);
};

}  // namespace content

#endif  // CONTENT_RENDERER_LOADER_RESOURCE_DISPATCHER_H_

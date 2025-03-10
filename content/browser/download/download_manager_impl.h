// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_DOWNLOAD_DOWNLOAD_MANAGER_IMPL_H_
#define CONTENT_BROWSER_DOWNLOAD_DOWNLOAD_MANAGER_IMPL_H_

#include <stdint.h>

#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/sequenced_task_runner_helpers.h"
#include "base/synchronization/lock.h"
#include "components/download/public/common/download_item_impl_delegate.h"
#include "components/download/public/common/download_url_parameters.h"
#include "components/download/public/common/url_download_handler.h"
#include "content/browser/loader/navigation_url_loader.h"
#include "content/common/content_export.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/download_manager.h"
#include "content/public/browser/download_manager_delegate.h"
#include "content/public/browser/ssl_status.h"
#include "services/metrics/public/cpp/ukm_source_id.h"
#include "services/network/public/mojom/url_loader.mojom.h"

namespace download {
class DownloadFileFactory;
class DownloadItemFactory;
class DownloadItemImpl;
class DownloadRequestHandleInterface;
class InProgressDownloadManager;
}

namespace content {
class ResourceContext;
class StoragePartitionImpl;

class CONTENT_EXPORT DownloadManagerImpl
    : public DownloadManager,
      public download::UrlDownloadHandler::Delegate,
      private download::DownloadItemImplDelegate {
 public:
  using DownloadItemImplCreated =
      base::Callback<void(download::DownloadItemImpl*)>;

  // Caller guarantees that |net_log| will remain valid
  // for the lifetime of DownloadManagerImpl (until Shutdown() is called).
  explicit DownloadManagerImpl(BrowserContext* browser_context);
  ~DownloadManagerImpl() override;

  // Implementation functions (not part of the DownloadManager interface).

  // Creates a download item for the SavePackage system.
  // Must be called on the UI thread.  Note that the DownloadManager
  // retains ownership.
  virtual void CreateSavePackageDownloadItem(
      const base::FilePath& main_file_path,
      const GURL& page_url,
      const std::string& mime_type,
      int render_process_id,
      int render_frame_id,
      std::unique_ptr<download::DownloadRequestHandleInterface> request_handle,
      const ukm::SourceId ukm_source_id,
      const DownloadItemImplCreated& item_created);

  // DownloadManager functions.
  void SetDelegate(DownloadManagerDelegate* delegate) override;
  DownloadManagerDelegate* GetDelegate() const override;
  void Shutdown() override;
  void GetAllDownloads(DownloadVector* result) override;
  void StartDownload(std::unique_ptr<download::DownloadCreateInfo> info,
                     std::unique_ptr<download::InputStream> stream,
                     scoped_refptr<download::DownloadURLLoaderFactoryGetter>
                         url_loader_factory_getter,
                     const download::DownloadUrlParameters::OnStartedCallback&
                         on_started) override;

  int RemoveDownloadsByURLAndTime(
      const base::Callback<bool(const GURL&)>& url_filter,
      base::Time remove_begin,
      base::Time remove_end) override;
  void DownloadUrl(
      std::unique_ptr<download::DownloadUrlParameters> parameters) override;
  void DownloadUrl(
      std::unique_ptr<download::DownloadUrlParameters> params,
      std::unique_ptr<storage::BlobDataHandle> blob_data_handle) override;
  void AddObserver(Observer* observer) override;
  void RemoveObserver(Observer* observer) override;
  download::DownloadItem* CreateDownloadItem(
      const std::string& guid,
      uint32_t id,
      const base::FilePath& current_path,
      const base::FilePath& target_path,
      const std::vector<GURL>& url_chain,
      const GURL& referrer_url,
      const GURL& site_url,
      const GURL& tab_url,
      const GURL& tab_refererr_url,
      const std::string& mime_type,
      const std::string& original_mime_type,
      base::Time start_time,
      base::Time end_time,
      const std::string& etag,
      const std::string& last_modified,
      int64_t received_bytes,
      int64_t total_bytes,
      const std::string& hash,
      download::DownloadItem::DownloadState state,
      download::DownloadDangerType danger_type,
      download::DownloadInterruptReason interrupt_reason,
      bool opened,
      base::Time last_access_time,
      bool transient,
      const std::vector<download::DownloadItem::ReceivedSlice>& received_slices)
      override;
  void PostInitialization(DownloadInitializationDependency dependency) override;
  bool IsManagerInitialized() const override;
  int InProgressCount() const override;
  int NonMaliciousInProgressCount() const override;
  BrowserContext* GetBrowserContext() const override;
  void CheckForHistoryFilesRemoval() override;
  download::DownloadItem* GetDownload(uint32_t id) override;
  download::DownloadItem* GetDownloadByGuid(const std::string& guid) override;

  // UrlDownloadHandler::Delegate implementation.
  void OnUrlDownloadStarted(
      std::unique_ptr<download::DownloadCreateInfo> download_create_info,
      std::unique_ptr<download::InputStream> stream,
      scoped_refptr<download::DownloadURLLoaderFactoryGetter>
          url_loader_factory_getter,
      const download::DownloadUrlParameters::OnStartedCallback& callback)
      override;
  void OnUrlDownloadStopped(download::UrlDownloadHandler* downloader) override;
  void OnUrlDownloadHandlerCreated(
      download::UrlDownloadHandler::UniqueUrlDownloadHandlerPtr downloader)
      override;

  // For testing; specifically, accessed from TestFileErrorInjector.
  void SetDownloadItemFactoryForTesting(
      std::unique_ptr<download::DownloadItemFactory> item_factory);
  void SetDownloadFileFactoryForTesting(
      std::unique_ptr<download::DownloadFileFactory> file_factory);
  virtual download::DownloadFileFactory* GetDownloadFileFactoryForTesting();

  // Helper function to initiate a download request. This function initiates
  // the download using functionality provided by the
  // ResourceDispatcherHostImpl::BeginURLRequest function. The function returns
  // the result of the downoad operation. Please see the
  // DownloadInterruptReason enum for information on possible return values.
  static download::DownloadInterruptReason BeginDownloadRequest(
      std::unique_ptr<net::URLRequest> url_request,
      ResourceContext* resource_context,
      download::DownloadUrlParameters* params);

  // Continue a navigation that ends up to be a download after it reaches the
  // OnResponseStarted() step. It has to be called on the UI thread.
  void InterceptNavigation(
      std::unique_ptr<network::ResourceRequest> resource_request,
      std::vector<GURL> url_chain,
      const base::Optional<std::string>& suggested_filename,
      scoped_refptr<network::ResourceResponse> response,
      network::mojom::URLLoaderClientEndpointsPtr url_loader_client_endpoints,
      net::CertStatus cert_status,
      int frame_tree_node_id);

 private:
  using DownloadSet = std::set<download::DownloadItem*>;
  using DownloadGuidMap =
      std::unordered_map<std::string, download::DownloadItemImpl*>;
  using DownloadItemImplVector = std::vector<download::DownloadItemImpl*>;

  // For testing.
  friend class DownloadManagerTest;
  friend class DownloadTest;

  void StartDownloadWithId(
      std::unique_ptr<download::DownloadCreateInfo> info,
      std::unique_ptr<download::InputStream> stream,
      scoped_refptr<download::DownloadURLLoaderFactoryGetter>
          url_loader_factory_getter,
      const download::DownloadUrlParameters::OnStartedCallback& on_started,
      bool new_download,
      uint32_t id);

  void CreateSavePackageDownloadItemWithId(
      const base::FilePath& main_file_path,
      const GURL& page_url,
      const std::string& mime_type,
      int render_process_id,
      int render_frame_id,
      std::unique_ptr<download::DownloadRequestHandleInterface> request_handle,
      const ukm::SourceId ukm_source_id,
      const DownloadItemImplCreated& on_started,
      uint32_t id);

  // Intercepts the download to another system if applicable. Returns true if
  // the download was intercepted.
  bool InterceptDownload(const download::DownloadCreateInfo& info);

  // Create a new active item based on the info.  Separate from
  // StartDownload() for testing.
  download::DownloadItemImpl* CreateActiveItem(
      uint32_t id,
      const download::DownloadCreateInfo& info);

  // Get next download id. |callback| is called on the UI thread and may
  // be called synchronously.
  void GetNextId(const DownloadIdCallback& callback);

  // Called with the result of DownloadManagerDelegate::CheckForFileExistence.
  // Updates the state of the file and then notifies this update to the file's
  // observer.
  void OnFileExistenceChecked(uint32_t download_id, bool result);

  // Overridden from DownloadItemImplDelegate
  void DetermineDownloadTarget(download::DownloadItemImpl* item,
                               const DownloadTargetCallback& callback) override;
  bool ShouldCompleteDownload(download::DownloadItemImpl* item,
                              const base::Closure& complete_callback) override;
  bool ShouldOpenFileBasedOnExtension(const base::FilePath& path) override;
  bool ShouldOpenDownload(download::DownloadItemImpl* item,
                          const ShouldOpenDownloadCallback& callback) override;
  void CheckForFileRemoval(download::DownloadItemImpl* download_item) override;
  std::string GetApplicationClientIdForFileScanning() const override;
  void ResumeInterruptedDownload(
      std::unique_ptr<download::DownloadUrlParameters> params,
      uint32_t id,
      const GURL& site_url) override;
  void OpenDownload(download::DownloadItemImpl* download) override;
  bool IsMostRecentDownloadItemAtFilePath(
      download::DownloadItemImpl* download) override;
  void ShowDownloadInShell(download::DownloadItemImpl* download) override;
  void DownloadRemoved(download::DownloadItemImpl* download) override;
  void DownloadInterrupted(download::DownloadItemImpl* download) override;
  base::Optional<download::DownloadEntry> GetInProgressEntry(
      download::DownloadItemImpl* download) override;
  bool IsOffTheRecord() const override;
  void ReportBytesWasted(download::DownloadItemImpl* download) override;

  // Helper method to start or resume a download.
  void BeginDownloadInternal(
      std::unique_ptr<download::DownloadUrlParameters> params,
      std::unique_ptr<storage::BlobDataHandle> blob_data_handle,
      uint32_t id,
      StoragePartitionImpl* storage_partition);

  void InterceptNavigationOnChecksComplete(
      ResourceRequestInfo::WebContentsGetter web_contents_getter,
      std::unique_ptr<network::ResourceRequest> resource_request,
      std::vector<GURL> url_chain,
      const base::Optional<std::string>& suggested_filename,
      scoped_refptr<network::ResourceResponse> response,
      net::CertStatus cert_status,
      network::mojom::URLLoaderClientEndpointsPtr url_loader_client_endpoints,
      bool is_download_allowed);

  // Factory for creation of downloads items.
  std::unique_ptr<download::DownloadItemFactory> item_factory_;

  // Factory for the creation of download files.
  std::unique_ptr<download::DownloadFileFactory> file_factory_;

  // |downloads_| is the owning set for all downloads known to the
  // DownloadManager.  This includes downloads started by the user in
  // this session, downloads initialized from the history system, and
  // "save page as" downloads.
  // TODO(asanka): Remove this container in favor of downloads_by_guid_ as a
  // part of http://crbug.com/593020.
  std::unordered_map<uint32_t, std::unique_ptr<download::DownloadItemImpl>>
      downloads_;

  // Same as the above, but maps from GUID to download item. Note that the
  // container is case sensitive. Hence the key needs to be normalized to
  // upper-case when inserting new elements here. Fortunately for us,
  // DownloadItemImpl already normalizes the string GUID.
  DownloadGuidMap downloads_by_guid_;

  // True if the download manager has been initialized and requires a shutdown.
  bool shutdown_needed_;

  // True if the download manager has been initialized and loaded all the data.
  bool initialized_;

  // Whether the history db and/or in progress cache are initialized.
  bool history_db_initialized_;
  bool in_progress_cache_initialized_;

  // Observers that want to be notified of changes to the set of downloads.
  base::ObserverList<Observer> observers_;

  // Stores information about in-progress download items.
  std::unique_ptr<download::DownloadItem::Observer>
      in_progress_download_observer_;

  // The current active browser context.
  BrowserContext* browser_context_;

  // Allows an embedder to control behavior. Guaranteed to outlive this object.
  DownloadManagerDelegate* delegate_;

  // TODO(qinmin): remove this once network service is enabled by default.
  std::vector<download::UrlDownloadHandler::UniqueUrlDownloadHandlerPtr>
      url_download_handlers_;

  std::unique_ptr<download::InProgressDownloadManager> in_progress_manager_;

  base::WeakPtrFactory<DownloadManagerImpl> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(DownloadManagerImpl);
};

}  // namespace content

#endif  // CONTENT_BROWSER_DOWNLOAD_DOWNLOAD_MANAGER_IMPL_H_

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The DownloadManager object manages the process of downloading, including
// updates to the history system and providing the information for displaying
// the downloads view in the Destinations tab. There is one DownloadManager per
// active browser context in Chrome.
//
// Download observers:
// Objects that are interested in notifications about new downloads, or progress
// updates for a given download must implement one of the download observer
// interfaces:
//   DownloadManager::Observer:
//     - allows observers, primarily views, to be notified when changes to the
//       set of all downloads (such as new downloads, or deletes) occur
// Use AddObserver() / RemoveObserver() on the appropriate download object to
// receive state updates.
//
// Download state persistence:
// The DownloadManager uses the history service for storing persistent
// information about the state of all downloads. The history system maintains a
// separate table for this called 'downloads'. At the point that the
// DownloadManager is constructed, we query the history service for the state of
// all persisted downloads.

#ifndef CONTENT_PUBLIC_BROWSER_DOWNLOAD_MANAGER_H_
#define CONTENT_PUBLIC_BROWSER_DOWNLOAD_MANAGER_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/sequenced_task_runner.h"
#include "base/time/time.h"
#include "components/download/public/common/download_interrupt_reasons.h"
#include "components/download/public/common/download_item.h"
#include "components/download/public/common/download_stream.mojom.h"
#include "components/download/public/common/download_url_parameters.h"
#include "components/download/public/common/input_stream.h"
#include "content/common/content_export.h"
#include "net/base/net_errors.h"
#include "storage/browser/blob/blob_data_handle.h"

class GURL;

namespace download {
struct DownloadCreateInfo;
class DownloadURLLoaderFactoryGetter;
}  // namespace download

namespace content {

class BrowserContext;
class DownloadManagerDelegate;

// Browser's download manager: manages all downloads and destination view.
class CONTENT_EXPORT DownloadManager : public base::SupportsUserData::Data {
 public:
  ~DownloadManager() override {}

  // Returns the task runner that's used for all download-related blocking
  // tasks, such as file IO.
  static scoped_refptr<base::SequencedTaskRunner> GetTaskRunner();

  // Sets/Gets the delegate for this DownloadManager. The delegate has to live
  // past its Shutdown method being called (by the DownloadManager).
  virtual void SetDelegate(DownloadManagerDelegate* delegate) = 0;
  virtual DownloadManagerDelegate* GetDelegate() const = 0;

  // Shutdown the download manager. Content calls this when BrowserContext is
  // being destructed. If the embedder needs this to be called earlier, it can
  // call it. In that case, the delegate's Shutdown() method will only be called
  // once.
  virtual void Shutdown() = 0;

  // Interface to implement for observers that wish to be informed of changes
  // to the DownloadManager's collection of downloads.
  class CONTENT_EXPORT Observer {
   public:
    // A download::DownloadItem was created. This item may be visible before the
    // filename is determined; in this case the return value of
    // GetTargetFileName() will be null.  This method may be called an arbitrary
    // number of times, e.g. when loading history on startup.  As a result,
    // consumers should avoid doing large amounts of work in
    // OnDownloadCreated().  TODO(<whoever>): When we've fully specified the
    // possible states of the download::DownloadItem in download_item.h, we
    // should remove the caveat above.
    virtual void OnDownloadCreated(DownloadManager* manager,
                                   download::DownloadItem* item) {}

    // Called when the download manager intercepted a download navigation but
    // didn't create the download item. Possible reasons:
    // 1. |delegate| is null.
    // 2. |delegate| doesn't allow the download.
    virtual void OnDownloadDropped(DownloadManager* manager) {}

    // Called when the download manager has finished loading the data.
    virtual void OnManagerInitialized() {}

    // Called when the DownloadManager is being destroyed to prevent Observers
    // from calling back to a stale pointer.
    virtual void ManagerGoingDown(DownloadManager* manager) {}

   protected:
    virtual ~Observer() {}
  };

  typedef std::vector<download::DownloadItem*> DownloadVector;

  // Add all download items to |downloads|, no matter the type or state, without
  // clearing |downloads| first.
  virtual void GetAllDownloads(DownloadVector* downloads) = 0;

  // Called by a download source (Currently DownloadResourceHandler)
  // to initiate the non-source portions of a download.
  // If the DownloadCreateInfo specifies an id, that id will be used.
  // If |url_loader_factory_getter| is provided, it can be used to issue
  // parallel download requests.
  virtual void StartDownload(
      std::unique_ptr<download::DownloadCreateInfo> info,
      std::unique_ptr<download::InputStream> stream,
      scoped_refptr<download::DownloadURLLoaderFactoryGetter>
          url_loader_factory_getter,
      const download::DownloadUrlParameters::OnStartedCallback& on_started) = 0;

  // Remove downloads whose URLs match the |url_filter| and are within
  // the given time constraints - after remove_begin (inclusive) and before
  // remove_end (exclusive). You may pass in null Time values to do an unbounded
  // delete in either direction.
  virtual int RemoveDownloadsByURLAndTime(
      const base::Callback<bool(const GURL&)>& url_filter,
      base::Time remove_begin,
      base::Time remove_end) = 0;

  // See download::DownloadUrlParameters for details about controlling the
  // download.
  virtual void DownloadUrl(
      std::unique_ptr<download::DownloadUrlParameters> parameters) = 0;

  // For downloads of blob URLs, the caller can pass a BlobDataHandle object so
  // that the blob will remain valid until the download starts. The
  // BlobDataHandle will be attached to the associated URLRequest.
  // If |blob_data_handle| is unspecified, and the blob URL cannot be mapped to
  // a blob by the time the download request starts, then the download will
  // fail.
  virtual void DownloadUrl(
      std::unique_ptr<download::DownloadUrlParameters> parameters,
      std::unique_ptr<storage::BlobDataHandle> blob_data_handle) = 0;

  // Allow objects to observe the download creation process.
  virtual void AddObserver(Observer* observer) = 0;

  // Remove a download observer from ourself.
  virtual void RemoveObserver(Observer* observer) = 0;

  // Called by the embedder, after creating the download manager, to let it know
  // about downloads from previous runs of the browser.
  virtual download::DownloadItem* CreateDownloadItem(
      const std::string& guid,
      uint32_t id,
      const base::FilePath& current_path,
      const base::FilePath& target_path,
      const std::vector<GURL>& url_chain,
      const GURL& referrer_url,
      const GURL& site_url,
      const GURL& tab_url,
      const GURL& tab_referrer_url,
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
      const std::vector<download::DownloadItem::ReceivedSlice>&
          received_slices) = 0;

  // Enum to describe which dependency was initialized in PostInitialization.
  enum DownloadInitializationDependency {
    DOWNLOAD_INITIALIZATION_DEPENDENCY_NONE,
    DOWNLOAD_INITIALIZATION_DEPENDENCY_HISTORY_DB,
    DOWNLOAD_INITIALIZATION_DEPENDENCY_IN_PROGRESS_CACHE,
  };

  // Called when download manager has loaded all the data, once when the history
  // db is initialized and once when the in-progress cache is initialized.
  virtual void PostInitialization(
      DownloadInitializationDependency dependency) = 0;

  // Returns if the manager has been initialized and loaded all the data.
  virtual bool IsManagerInitialized() const = 0;

  // The number of in progress (including paused) downloads.
  // Performance note: this loops over all items. If profiling finds that this
  // is too slow, use an AllDownloadItemNotifier to count in-progress items.
  virtual int InProgressCount() const = 0;

  // The number of in progress (including paused) downloads.
  // Performance note: this loops over all items. If profiling finds that this
  // is too slow, use an AllDownloadItemNotifier to count in-progress items.
  // This excludes downloads that are marked as malicious.
  virtual int NonMaliciousInProgressCount() const = 0;

  virtual BrowserContext* GetBrowserContext() const = 0;

  // Checks whether downloaded files still exist. Updates state of downloads
  // that refer to removed files. The check runs in the background and may
  // finish asynchronously after this method returns.
  virtual void CheckForHistoryFilesRemoval() = 0;

  // Get the download item for |id| if present, no matter what type of download
  // it is or state it's in.
  // DEPRECATED: Don't add new callers for GetDownload(uint32_t). Instead keep
  // track of the GUID and use GetDownloadByGuid(), or observe the
  // download::DownloadItem if you need to keep track of a specific download.
  // (http://crbug.com/593020)
  virtual download::DownloadItem* GetDownload(uint32_t id) = 0;

  // Get the download item for |guid|.
  virtual download::DownloadItem* GetDownloadByGuid(
      const std::string& guid) = 0;
};

}  // namespace content

#endif  // CONTENT_PUBLIC_BROWSER_DOWNLOAD_MANAGER_H_

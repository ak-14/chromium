// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/customization/customization_wallpaper_downloader.h"

#include <math.h>
#include <algorithm>
#include <utility>

#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/net/system_network_context_manager.h"
#include "content/public/browser/browser_thread.h"
#include "net/base/load_flags.h"
#include "net/http/http_status_code.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"

namespace chromeos {
namespace {
// This is temporary file suffix (for downloading or resizing).
const char kTemporarySuffix[] = ".tmp";

// Sleep between wallpaper retries (used multiplied by squared retry number).
const unsigned kRetrySleepSeconds = 10;

// Retry is infinite with increasing intervals. When calculated delay becomes
// longer than maximum (kMaxRetrySleepSeconds) it is set to the maximum.
const double kMaxRetrySleepSeconds = 6 * 3600;  // 6 hours

void CreateWallpaperDirectory(const base::FilePath& wallpaper_dir,
                              bool* success) {
  DCHECK(success);

  *success = CreateDirectoryAndGetError(wallpaper_dir, NULL);
  if (!*success) {
    NOTREACHED() << "Failed to create directory '" << wallpaper_dir.value()
                 << "'";
  }
}

void RenameTemporaryFile(const base::FilePath& from,
                         const base::FilePath& to,
                         bool* success) {
  DCHECK(success);

  base::File::Error error;
  if (base::ReplaceFile(from, to, &error)) {
    *success = true;
  } else {
    LOG(WARNING)
        << "Failed to rename temporary file of Customized Wallpaper. error="
        << error;
    *success = false;
  }
}

}  // namespace

CustomizationWallpaperDownloader::CustomizationWallpaperDownloader(
    const GURL& wallpaper_url,
    const base::FilePath& wallpaper_dir,
    const base::FilePath& wallpaper_downloaded_file,
    base::Callback<void(bool success, const GURL&)>
        on_wallpaper_fetch_completed)
    : wallpaper_url_(wallpaper_url),
      wallpaper_dir_(wallpaper_dir),
      wallpaper_downloaded_file_(wallpaper_downloaded_file),
      wallpaper_temporary_file_(wallpaper_downloaded_file.value() +
                                kTemporarySuffix),
      retries_(0),
      retry_delay_(base::TimeDelta::FromSeconds(kRetrySleepSeconds)),
      on_wallpaper_fetch_completed_(on_wallpaper_fetch_completed),
      weak_factory_(this) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
}

CustomizationWallpaperDownloader::~CustomizationWallpaperDownloader() {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
}

void CustomizationWallpaperDownloader::StartRequest() {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  DCHECK(wallpaper_url_.is_valid());

  auto resource_request = std::make_unique<network::ResourceRequest>();
  resource_request->url = wallpaper_url_;
  resource_request->load_flags =
      net::LOAD_BYPASS_CACHE | net::LOAD_DISABLE_CACHE |
      net::LOAD_DO_NOT_SAVE_COOKIES | net::LOAD_DO_NOT_SEND_COOKIES |
      net::LOAD_DO_NOT_SEND_AUTH_DATA;
  // TODO(crbug.com/833390): Add a real traffic annotation here.
  simple_loader_ = network::SimpleURLLoader::Create(std::move(resource_request),
                                                    MISSING_TRAFFIC_ANNOTATION);

  SystemNetworkContextManager* system_network_context_manager =
      g_browser_process->system_network_context_manager();
  // In unit tests, the browser process can return a null context manager
  if (!system_network_context_manager)
    return;

  network::mojom::URLLoaderFactory* loader_factory =
      system_network_context_manager->GetURLLoaderFactory();

  simple_loader_->DownloadToFile(
      loader_factory,
      base::BindOnce(&CustomizationWallpaperDownloader::OnSimpleLoaderComplete,
                     base::Unretained(this)),
      wallpaper_temporary_file_);
}

void CustomizationWallpaperDownloader::Retry() {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  ++retries_;

  const double delay_seconds = std::min(
      kMaxRetrySleepSeconds,
      static_cast<double>(retries_) * retries_ * retry_delay_.InSecondsF());
  const base::TimeDelta delay = base::TimeDelta::FromSecondsD(delay_seconds);

  VLOG(1) << "Schedule Customized Wallpaper download in " << delay.InSecondsF()
          << " seconds (retry = " << retries_ << ").";
  retry_current_delay_ = delay;
  request_scheduled_.Start(
      FROM_HERE, delay, this, &CustomizationWallpaperDownloader::StartRequest);
}

void CustomizationWallpaperDownloader::Start() {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  std::unique_ptr<bool> success(new bool(false));

  base::OnceClosure mkdir_closure =
      base::BindOnce(&CreateWallpaperDirectory, wallpaper_dir_,
                     base::Unretained(success.get()));
  base::OnceClosure on_created_closure = base::BindOnce(
      &CustomizationWallpaperDownloader::OnWallpaperDirectoryCreated,
      weak_factory_.GetWeakPtr(), base::Passed(std::move(success)));
  base::PostTaskWithTraitsAndReply(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::BACKGROUND},
      std::move(mkdir_closure), std::move(on_created_closure));
}

void CustomizationWallpaperDownloader::OnWallpaperDirectoryCreated(
    std::unique_ptr<bool> success) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  if (*success)
    StartRequest();
}

void CustomizationWallpaperDownloader::OnSimpleLoaderComplete(
    const base::FilePath& response_path) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);

  const bool error = response_path.empty();

  VLOG(1) << "CustomizationWallpaperDownloader::OnURLFetchComplete(): status="
          << simple_loader_->NetError();

  // Save the response_path before resetting SimplerURLLoader. It gets nulled
  // out afterwards.
  base::FilePath copy_response_path(response_path);
  simple_loader_.reset();

  if (error) {
    Retry();
    return;
  }

  std::unique_ptr<bool> success(new bool(false));

  base::OnceClosure rename_closure = base::BindOnce(
      &RenameTemporaryFile, copy_response_path, wallpaper_downloaded_file_,
      base::Unretained(success.get()));
  base::OnceClosure on_rename_closure = base::BindOnce(
      &CustomizationWallpaperDownloader::OnTemporaryFileRenamed,
      weak_factory_.GetWeakPtr(), base::Passed(std::move(success)));
  base::PostTaskWithTraitsAndReply(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::BACKGROUND},
      std::move(rename_closure), std::move(on_rename_closure));
}

void CustomizationWallpaperDownloader::OnTemporaryFileRenamed(
    std::unique_ptr<bool> success) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  on_wallpaper_fetch_completed_.Run(*success, wallpaper_url_);
}

}  //   namespace chromeos

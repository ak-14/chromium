// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_DRIVE_SERVICE_DRIVE_API_SERVICE_H_
#define COMPONENTS_DRIVE_SERVICE_DRIVE_API_SERVICE_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/sequence_checker.h"
#include "base/threading/thread_checker.h"
#include "components/drive/service/drive_service_interface.h"
#include "google_apis/drive/auth_service_interface.h"
#include "google_apis/drive/auth_service_observer.h"
#include "google_apis/drive/drive_api_url_generator.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

class GURL;
class OAuth2TokenService;

namespace base {
class FilePath;
class SequencedTaskRunner;
}

namespace google_apis {
class FilesListRequestRunner;
class RequestSender;
namespace drive {
class BatchUploadRequest;
}  // namespace drive
}  // namespace google_apis

namespace net {
class URLRequestContextGetter;
}  // namespace net

namespace drive {

// Builder for batch request returned by |DriveAPIService|.
class BatchRequestConfigurator : public BatchRequestConfiguratorInterface {
 public:
  BatchRequestConfigurator(
      const base::WeakPtr<google_apis::drive::BatchUploadRequest>&
          batch_request,
      base::SequencedTaskRunner* task_runner,
      const google_apis::DriveApiUrlGenerator& url_generator,
      const google_apis::CancelCallback& cancel_callback);
  ~BatchRequestConfigurator() override;

  // BatchRequestConfiguratorInterface overrides.
  google_apis::CancelCallback MultipartUploadNewFile(
      const std::string& content_type,
      int64_t content_length,
      const std::string& parent_resource_id,
      const std::string& title,
      const base::FilePath& local_file_path,
      const UploadNewFileOptions& options,
      const google_apis::FileResourceCallback& callback,
      const google_apis::ProgressCallback& progress_callback) override;
  google_apis::CancelCallback MultipartUploadExistingFile(
      const std::string& content_type,
      int64_t content_length,
      const std::string& resource_id,
      const base::FilePath& local_file_path,
      const UploadExistingFileOptions& options,
      const google_apis::FileResourceCallback& callback,
      const google_apis::ProgressCallback& progress_callback) override;
  void Commit() override;

 private:
  // Reference to batch request. It turns to null after committing.
  base::WeakPtr<google_apis::drive::BatchUploadRequest> batch_request_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  google_apis::DriveApiUrlGenerator url_generator_;
  google_apis::CancelCallback cancel_callback_;

  SEQUENCE_CHECKER(sequence_checker_);

  DISALLOW_COPY_AND_ASSIGN(BatchRequestConfigurator);
};

// This class provides Drive request calls using Drive V2 API.
// Details of API call are abstracted in each request class and this class
// works as a thin wrapper for the API.
class DriveAPIService : public DriveServiceInterface,
                        public google_apis::AuthServiceObserver {
 public:
  // |oauth2_token_service| is used for obtaining OAuth2 access tokens.
  // |url_request_context_getter| is used to initialize URLFetcher.
  // |blocking_task_runner| is used to run blocking tasks (like parsing JSON).
  // |base_url| is used to generate URLs for communication with the drive API.
  // |base_thumbnail_url| is used to generate URLs for downloading thumbnail
  // from image server.
  // |custom_user_agent| will be used for the User-Agent header in HTTP
  // requests issues through the service if the value is not empty.
  // |traffic_annotation| will be used to annotate the network request that will
  // be created to perform this service.
  DriveAPIService(OAuth2TokenService* oauth2_token_service,
                  net::URLRequestContextGetter* url_request_context_getter,
                  base::SequencedTaskRunner* blocking_task_runner,
                  const GURL& base_url,
                  const GURL& base_thumbnail_url,
                  const std::string& custom_user_agent,
                  const net::NetworkTrafficAnnotationTag& traffic_annotation);
  ~DriveAPIService() override;

  // DriveServiceInterface Overrides
  void Initialize(const std::string& account_id) override;
  void AddObserver(DriveServiceObserver* observer) override;
  void RemoveObserver(DriveServiceObserver* observer) override;
  bool CanSendRequest() const override;
  bool HasAccessToken() const override;
  void RequestAccessToken(
      const google_apis::AuthStatusCallback& callback) override;
  bool HasRefreshToken() const override;
  void ClearAccessToken() override;
  void ClearRefreshToken() override;
  std::string GetRootResourceId() const override;
  google_apis::CancelCallback GetAllTeamDriveList(
      const google_apis::TeamDriveListCallback& callback) override;
  google_apis::CancelCallback GetAllFileList(
      const google_apis::FileListCallback& callback) override;
  google_apis::CancelCallback GetFileListInDirectory(
      const std::string& directory_resource_id,
      const google_apis::FileListCallback& callback) override;
  google_apis::CancelCallback Search(
      const std::string& search_query,
      const google_apis::FileListCallback& callback) override;
  google_apis::CancelCallback SearchByTitle(
      const std::string& title,
      const std::string& directory_resource_id,
      const google_apis::FileListCallback& callback) override;
  google_apis::CancelCallback GetChangeList(
      int64_t start_changestamp,
      const google_apis::ChangeListCallback& callback) override;
  google_apis::CancelCallback GetRemainingTeamDriveList(
      const std::string& page_token,
      const google_apis::TeamDriveListCallback& callback) override;
  google_apis::CancelCallback GetRemainingChangeList(
      const GURL& next_link,
      const google_apis::ChangeListCallback& callback) override;
  google_apis::CancelCallback GetRemainingFileList(
      const GURL& next_link,
      const google_apis::FileListCallback& callback) override;
  google_apis::CancelCallback GetFileResource(
      const std::string& resource_id,
      const google_apis::FileResourceCallback& callback) override;
  google_apis::CancelCallback GetShareUrl(
      const std::string& resource_id,
      const GURL& embed_origin,
      const google_apis::GetShareUrlCallback& callback) override;
  google_apis::CancelCallback GetAboutResource(
      const google_apis::AboutResourceCallback& callback) override;
  google_apis::CancelCallback GetStartPageToken(
      const std::string& team_drive_id,
      const google_apis::StartPageTokenCallback& callback) override;
  google_apis::CancelCallback GetAppList(
      const google_apis::AppListCallback& callback) override;
  google_apis::CancelCallback DeleteResource(
      const std::string& resource_id,
      const std::string& etag,
      const google_apis::EntryActionCallback& callback) override;
  google_apis::CancelCallback TrashResource(
      const std::string& resource_id,
      const google_apis::EntryActionCallback& callback) override;
  google_apis::CancelCallback DownloadFile(
      const base::FilePath& local_cache_path,
      const std::string& resource_id,
      const google_apis::DownloadActionCallback& download_action_callback,
      const google_apis::GetContentCallback& get_content_callback,
      const google_apis::ProgressCallback& progress_callback) override;
  google_apis::CancelCallback CopyResource(
      const std::string& resource_id,
      const std::string& parent_resource_id,
      const std::string& new_title,
      const base::Time& last_modified,
      const google_apis::FileResourceCallback& callback) override;
  google_apis::CancelCallback UpdateResource(
      const std::string& resource_id,
      const std::string& parent_resource_id,
      const std::string& new_title,
      const base::Time& last_modified,
      const base::Time& last_viewed_by_me,
      const google_apis::drive::Properties& properties,
      const google_apis::FileResourceCallback& callback) override;
  google_apis::CancelCallback AddResourceToDirectory(
      const std::string& parent_resource_id,
      const std::string& resource_id,
      const google_apis::EntryActionCallback& callback) override;
  google_apis::CancelCallback RemoveResourceFromDirectory(
      const std::string& parent_resource_id,
      const std::string& resource_id,
      const google_apis::EntryActionCallback& callback) override;
  google_apis::CancelCallback AddNewDirectory(
      const std::string& parent_resource_id,
      const std::string& directory_title,
      const AddNewDirectoryOptions& options,
      const google_apis::FileResourceCallback& callback) override;
  google_apis::CancelCallback InitiateUploadNewFile(
      const std::string& content_type,
      int64_t content_length,
      const std::string& parent_resource_id,
      const std::string& title,
      const UploadNewFileOptions& options,
      const google_apis::InitiateUploadCallback& callback) override;
  google_apis::CancelCallback InitiateUploadExistingFile(
      const std::string& content_type,
      int64_t content_length,
      const std::string& resource_id,
      const UploadExistingFileOptions& options,
      const google_apis::InitiateUploadCallback& callback) override;
  google_apis::CancelCallback ResumeUpload(
      const GURL& upload_url,
      int64_t start_position,
      int64_t end_position,
      int64_t content_length,
      const std::string& content_type,
      const base::FilePath& local_file_path,
      const google_apis::drive::UploadRangeCallback& callback,
      const google_apis::ProgressCallback& progress_callback) override;
  google_apis::CancelCallback GetUploadStatus(
      const GURL& upload_url,
      int64_t content_length,
      const google_apis::drive::UploadRangeCallback& callback) override;
  google_apis::CancelCallback MultipartUploadNewFile(
      const std::string& content_type,
      int64_t content_length,
      const std::string& parent_resource_id,
      const std::string& title,
      const base::FilePath& local_file_path,
      const drive::UploadNewFileOptions& options,
      const google_apis::FileResourceCallback& callback,
      const google_apis::ProgressCallback& progress_callback) override;
  google_apis::CancelCallback MultipartUploadExistingFile(
      const std::string& content_type,
      int64_t content_length,
      const std::string& resource_id,
      const base::FilePath& local_file_path,
      const drive::UploadExistingFileOptions& options,
      const google_apis::FileResourceCallback& callback,
      const google_apis::ProgressCallback& progress_callback) override;
  google_apis::CancelCallback AuthorizeApp(
      const std::string& resource_id,
      const std::string& app_id,
      const google_apis::AuthorizeAppCallback& callback) override;
  google_apis::CancelCallback UninstallApp(
      const std::string& app_id,
      const google_apis::EntryActionCallback& callback) override;
  google_apis::CancelCallback AddPermission(
      const std::string& resource_id,
      const std::string& email,
      google_apis::drive::PermissionRole role,
      const google_apis::EntryActionCallback& callback) override;
  std::unique_ptr<BatchRequestConfiguratorInterface> StartBatchRequest()
      override;

 private:
  // AuthServiceObserver override.
  void OnOAuth2RefreshTokenChanged() override;

  // The class is expected to run on UI thread.
  base::ThreadChecker thread_checker_;

  OAuth2TokenService* oauth2_token_service_;
  scoped_refptr<net::URLRequestContextGetter> url_request_context_getter_;
  scoped_refptr<base::SequencedTaskRunner> blocking_task_runner_;
  std::unique_ptr<google_apis::RequestSender> sender_;
  std::unique_ptr<google_apis::FilesListRequestRunner>
      files_list_request_runner_;
  base::ObserverList<DriveServiceObserver> observers_;
  google_apis::DriveApiUrlGenerator url_generator_;
  const std::string custom_user_agent_;
  const net::NetworkTrafficAnnotationTag traffic_annotation_;

  DISALLOW_COPY_AND_ASSIGN(DriveAPIService);
};

}  // namespace drive

#endif  // COMPONENTS_DRIVE_SERVICE_DRIVE_API_SERVICE_H_

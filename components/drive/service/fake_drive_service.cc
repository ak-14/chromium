// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/drive/service/fake_drive_service.h"

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/files/file_util.h"
#include "base/json/json_string_value_serializer.h"
#include "base/logging.h"
#include "base/md5.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/values.h"
#include "components/drive/drive_api_util.h"
#include "google_apis/drive/drive_api_parser.h"
#include "google_apis/drive/test_util.h"
#include "net/base/escape.h"
#include "net/base/url_util.h"

using google_apis::AboutResource;
using google_apis::AboutResourceCallback;
using google_apis::AppList;
using google_apis::AppListCallback;
using google_apis::AuthStatusCallback;
using google_apis::AuthorizeAppCallback;
using google_apis::CancelCallback;
using google_apis::ChangeList;
using google_apis::ChangeListCallback;
using google_apis::ChangeResource;
using google_apis::DRIVE_FILE_ERROR;
using google_apis::DRIVE_NO_CONNECTION;
using google_apis::DRIVE_OTHER_ERROR;
using google_apis::DownloadActionCallback;
using google_apis::DriveApiErrorCode;
using google_apis::EntryActionCallback;
using google_apis::FileList;
using google_apis::FileListCallback;
using google_apis::FileResource;
using google_apis::FileResourceCallback;
using google_apis::GetContentCallback;
using google_apis::GetShareUrlCallback;
using google_apis::HTTP_BAD_REQUEST;
using google_apis::HTTP_CREATED;
using google_apis::HTTP_FORBIDDEN;
using google_apis::HTTP_NOT_FOUND;
using google_apis::HTTP_NO_CONTENT;
using google_apis::HTTP_PRECONDITION;
using google_apis::HTTP_RESUME_INCOMPLETE;
using google_apis::HTTP_SUCCESS;
using google_apis::InitiateUploadCallback;
using google_apis::ParentReference;
using google_apis::ProgressCallback;
using google_apis::StartPageToken;
using google_apis::TeamDriveList;
using google_apis::TeamDriveListCallback;
using google_apis::TeamDriveResource;
using google_apis::UploadRangeResponse;
using google_apis::drive::UploadRangeCallback;
namespace test_util = google_apis::test_util;

namespace drive {
namespace {

// Returns true if the entry matches with the search query.
// Supports queries consist of following format.
// - Phrases quoted by double/single quotes
// - AND search for multiple words/phrases segmented by space
// - Limited attribute search.  Only "title:" is supported.
bool EntryMatchWithQuery(const ChangeResource& entry,
                         const std::string& query) {
  base::StringTokenizer tokenizer(query, " ");
  tokenizer.set_quote_chars("\"'");
  while (tokenizer.GetNext()) {
    std::string key, value;
    const std::string& token = tokenizer.token();
    if (token.find(':') == std::string::npos) {
      base::TrimString(token, "\"'", &value);
    } else {
      base::StringTokenizer key_value(token, ":");
      key_value.set_quote_chars("\"'");
      if (!key_value.GetNext())
        return false;
      key = key_value.token();
      if (!key_value.GetNext())
        return false;
      base::TrimString(key_value.token(), "\"'", &value);
    }

    // TODO(peria): Deal with other attributes than title.
    if (!key.empty() && key != "title")
      return false;
    // Search query in the title.
    if (!entry.file() ||
        entry.file()->title().find(value) == std::string::npos)
      return false;
  }
  return true;
}

void ScheduleUploadRangeCallback(const UploadRangeCallback& callback,
                                 int64_t start_position,
                                 int64_t end_position,
                                 DriveApiErrorCode error,
                                 std::unique_ptr<FileResource> entry) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(callback,
                     UploadRangeResponse(error, start_position, end_position),
                     std::move(entry)));
}

void FileListCallbackAdapter(const FileListCallback& callback,
                             DriveApiErrorCode error,
                             std::unique_ptr<ChangeList> change_list) {
  std::unique_ptr<FileList> file_list;
  if (!change_list) {
    callback.Run(error, std::move(file_list));
    return;
  }

  file_list.reset(new FileList);
  file_list->set_next_link(change_list->next_link());
  for (size_t i = 0; i < change_list->items().size(); ++i) {
    const ChangeResource& entry = *change_list->items()[i];
    if (entry.file())
      file_list->mutable_items()->push_back(
          std::make_unique<FileResource>(*entry.file()));
  }
  callback.Run(error, std::move(file_list));
}

bool UserHasWriteAccess(google_apis::drive::PermissionRole user_permission) {
  switch (user_permission) {
    case google_apis::drive::PERMISSION_ROLE_OWNER:
    case google_apis::drive::PERMISSION_ROLE_WRITER:
      return true;
    case google_apis::drive::PERMISSION_ROLE_READER:
    case google_apis::drive::PERMISSION_ROLE_COMMENTER:
      break;
  }
  return false;
}

void CallFileResouceCallback(const FileResourceCallback& callback,
                             const UploadRangeResponse& response,
                             std::unique_ptr<FileResource> entry) {
  callback.Run(response.code, std::move(entry));
}

struct CallResumeUpload {
  CallResumeUpload() {}
  ~CallResumeUpload() {}

  void Run(DriveApiErrorCode code, const GURL& upload_url) {
    if (service) {
      service->ResumeUpload(
          upload_url,
          /* start position */ 0,
          /* end position */ content_length,
          content_length,
          content_type,
          local_file_path,
          base::Bind(&CallFileResouceCallback, callback),
          progress_callback);
    }
  }

  base::WeakPtr<FakeDriveService> service;
  int64_t content_length;
  std::string content_type;
  base::FilePath local_file_path;
  FileResourceCallback callback;
  ProgressCallback progress_callback;
};

}  // namespace

struct FakeDriveService::EntryInfo {
  EntryInfo()
      : user_permission(google_apis::drive::PERMISSION_ROLE_OWNER),
        visibility(google_apis::drive::FILE_VISIBILITY_DEFAULT) {}

  google_apis::ChangeResource change_resource;
  GURL share_url;
  std::string content_data;

  // Behaves in the same way as "userPermission" described in
  // https://developers.google.com/drive/v2/reference/files
  google_apis::drive::PermissionRole user_permission;

  google_apis::drive::FileVisibility visibility;
};

struct FakeDriveService::UploadSession {
  std::string content_type;
  int64_t content_length;
  std::string parent_resource_id;
  std::string resource_id;
  std::string etag;
  std::string title;

  int64_t uploaded_size;

  UploadSession()
      : content_length(0),
        uploaded_size(0) {}

  UploadSession(std::string content_type,
                int64_t content_length,
                std::string parent_resource_id,
                std::string resource_id,
                std::string etag,
                std::string title)
      : content_type(content_type),
        content_length(content_length),
        parent_resource_id(parent_resource_id),
        resource_id(resource_id),
        etag(etag),
        title(title),
        uploaded_size(0) {}
};

FakeDriveService::FakeDriveService()
    : about_resource_(new AboutResource),
      date_seq_(0),
      next_upload_sequence_number_(0),
      default_max_results_(0),
      resource_id_count_(0),
      team_drive_list_load_count_(0),
      file_list_load_count_(0),
      change_list_load_count_(0),
      directory_load_count_(0),
      about_resource_load_count_(0),
      app_list_load_count_(0),
      blocked_file_list_load_count_(0),
      start_page_token_load_count_(0),
      offline_(false),
      never_return_all_file_list_(false),
      share_url_base_("https://share_url/"),
      weak_ptr_factory_(this) {
  about_resource_->set_largest_change_id(654321);
  about_resource_->set_quota_bytes_total(9876543210);
  about_resource_->set_quota_bytes_used_aggregate(6789012345);
  about_resource_->set_root_folder_id(GetRootResourceId());
}

FakeDriveService::~FakeDriveService() {
  DCHECK(thread_checker_.CalledOnValidThread());
}

bool FakeDriveService::LoadAppListForDriveApi(
    const std::string& relative_path) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Load JSON data, which must be a dictionary.
  std::unique_ptr<base::Value> value = test_util::LoadJSONFile(relative_path);
  CHECK_EQ(base::Value::Type::DICTIONARY, value->type());
  app_info_value_.reset(
      static_cast<base::DictionaryValue*>(value.release()));
  return !!app_info_value_;
}

void FakeDriveService::AddApp(const std::string& app_id,
                              const std::string& app_name,
                              const std::string& product_id,
                              const std::string& create_url,
                              bool is_removable) {
  if (app_json_template_.empty()) {
    base::FilePath path =
        test_util::GetTestFilePath("drive/applist_app_template.json");
    CHECK(base::ReadFileToString(path, &app_json_template_));
  }

  std::string app_json = app_json_template_;
  base::ReplaceSubstringsAfterOffset(&app_json, 0, "$AppId", app_id);
  base::ReplaceSubstringsAfterOffset(&app_json, 0, "$AppName", app_name);
  base::ReplaceSubstringsAfterOffset(&app_json, 0, "$ProductId", product_id);
  base::ReplaceSubstringsAfterOffset(&app_json, 0, "$CreateUrl", create_url);
  base::ReplaceSubstringsAfterOffset(
      &app_json, 0, "$Removable", is_removable ? "true" : "false");

  JSONStringValueDeserializer json(app_json);
  std::string error_message;
  std::unique_ptr<base::Value> value(json.Deserialize(nullptr, &error_message));
  CHECK_EQ(base::Value::Type::DICTIONARY, value->type());

  base::ListValue* item_list;
  CHECK(app_info_value_->GetListWithoutPathExpansion("items", &item_list));
  item_list->Append(std::move(value));
}

void FakeDriveService::AddTeamDrive(const std::string& id,
                                    const std::string& name) {
  std::unique_ptr<TeamDriveResource> team_drive;
  team_drive.reset(new TeamDriveResource);
  team_drive->set_id(id);
  team_drive->set_name(name);
  team_drive_value_.push_back(std::move(team_drive));
}

void FakeDriveService::RemoveAppByProductId(const std::string& product_id) {
  base::ListValue* item_list;
  CHECK(app_info_value_->GetListWithoutPathExpansion("items", &item_list));
  for (size_t i = 0; i < item_list->GetSize(); ++i) {
    base::DictionaryValue* item;
    CHECK(item_list->GetDictionary(i, &item));
    const char kKeyProductId[] = "productId";
    std::string item_product_id;
    if (item->GetStringWithoutPathExpansion(kKeyProductId, &item_product_id) &&
        product_id == item_product_id) {
      item_list->Remove(i, nullptr);
      return;
    }
  }
}

bool FakeDriveService::HasApp(const std::string& app_id) const {
  base::ListValue* item_list;
  CHECK(app_info_value_->GetListWithoutPathExpansion("items", &item_list));
  for (size_t i = 0; i < item_list->GetSize(); ++i) {
    base::DictionaryValue* item;
    CHECK(item_list->GetDictionary(i, &item));
    const char kKeyId[] = "id";
    std::string item_id;
    if (item->GetStringWithoutPathExpansion(kKeyId, &item_id) &&
        item_id == app_id) {
      return true;
    }
  }

  return false;
}

void FakeDriveService::SetQuotaValue(int64_t used, int64_t total) {
  DCHECK(thread_checker_.CalledOnValidThread());

  about_resource_->set_quota_bytes_used_aggregate(used);
  about_resource_->set_quota_bytes_total(total);
}

void FakeDriveService::Initialize(const std::string& account_id) {
  DCHECK(thread_checker_.CalledOnValidThread());
}

void FakeDriveService::AddObserver(DriveServiceObserver* observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
}

void FakeDriveService::RemoveObserver(DriveServiceObserver* observer) {
  DCHECK(thread_checker_.CalledOnValidThread());
}

bool FakeDriveService::CanSendRequest() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return true;
}

bool FakeDriveService::HasAccessToken() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return true;
}

void FakeDriveService::RequestAccessToken(const AuthStatusCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());
  callback.Run(google_apis::HTTP_NOT_MODIFIED, "fake_access_token");
}

bool FakeDriveService::HasRefreshToken() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return true;
}

void FakeDriveService::ClearAccessToken() {
  DCHECK(thread_checker_.CalledOnValidThread());
}

void FakeDriveService::ClearRefreshToken() {
  DCHECK(thread_checker_.CalledOnValidThread());
}

std::string FakeDriveService::GetRootResourceId() const {
  return "fake_root";
}

void FakeDriveService::GetTeamDriveListInternal(
    int start_offset,
    int max_results,
    int* load_counter,
    const google_apis::TeamDriveListCallback& callback) {
  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, DRIVE_NO_CONNECTION,
                                  std::unique_ptr<TeamDriveList>()));
    return;
  }
  if (load_counter)
    ++*load_counter;

  std::unique_ptr<TeamDriveList> result;
  result.reset(new TeamDriveList);
  size_t next_start_offset = start_offset + max_results;
  if (next_start_offset < team_drive_value_.size()) {
    // Embed next start offset to next page token to be read in
    // GetRemainingTeamDriveList next time.
    result->set_next_page_token(base::NumberToString(next_start_offset));
  }
  for (size_t i = start_offset;
       i < std::min(next_start_offset, team_drive_value_.size()); ++i) {
    std::unique_ptr<TeamDriveResource> team_drive(new TeamDriveResource);
    team_drive->set_id(team_drive_value_[i]->id());
    team_drive->set_name(team_drive_value_[i]->name());
    result->mutable_items()->push_back(std::move(team_drive));
  }
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(callback, HTTP_SUCCESS, std::move(result)));
}

CancelCallback FakeDriveService::GetAllTeamDriveList(
    const TeamDriveListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  GetTeamDriveListInternal(0, default_max_results_,
                           &team_drive_list_load_count_, callback);

  return CancelCallback();
}

CancelCallback FakeDriveService::GetAllFileList(
    const FileListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (never_return_all_file_list_) {
    ++blocked_file_list_load_count_;
    return CancelCallback();
  }

  GetChangeListInternal(0,  // start changestamp
                        std::string(),  // empty search query
                        std::string(),  // no directory resource id,
                        0,  // start offset
                        default_max_results_,
                        &file_list_load_count_,
                        base::Bind(&FileListCallbackAdapter, callback));
  return CancelCallback();
}

CancelCallback FakeDriveService::GetFileListInDirectory(
    const std::string& directory_resource_id,
    const FileListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!directory_resource_id.empty());
  DCHECK(!callback.is_null());

  GetChangeListInternal(0,  // start changestamp
                        std::string(),  // empty search query
                        directory_resource_id,
                        0,  // start offset
                        default_max_results_,
                        &directory_load_count_,
                        base::Bind(&FileListCallbackAdapter, callback));
  return CancelCallback();
}

CancelCallback FakeDriveService::Search(
    const std::string& search_query,
    const FileListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!search_query.empty());
  DCHECK(!callback.is_null());

  GetChangeListInternal(0,  // start changestamp
                        search_query,
                        std::string(),  // no directory resource id,
                        0,              // start offset
                        default_max_results_, nullptr,
                        base::Bind(&FileListCallbackAdapter, callback));
  return CancelCallback();
}

CancelCallback FakeDriveService::SearchByTitle(
    const std::string& title,
    const std::string& directory_resource_id,
    const FileListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!title.empty());
  DCHECK(!callback.is_null());

  // Note: the search implementation here doesn't support quotation unescape,
  // so don't escape here.
  GetChangeListInternal(0,  // start changestamp
                        base::StringPrintf("title:'%s'", title.c_str()),
                        directory_resource_id,
                        0,  // start offset
                        default_max_results_, nullptr,
                        base::Bind(&FileListCallbackAdapter, callback));
  return CancelCallback();
}

CancelCallback FakeDriveService::GetChangeList(
    int64_t start_changestamp,
    const ChangeListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  GetChangeListInternal(start_changestamp,
                        std::string(),  // empty search query
                        std::string(),  // no directory resource id,
                        0,  // start offset
                        default_max_results_,
                        &change_list_load_count_,
                        callback);
  return CancelCallback();
}

CancelCallback FakeDriveService::GetRemainingChangeList(
    const GURL& next_link,
    const ChangeListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!next_link.is_empty());
  DCHECK(!callback.is_null());

  // "changestamp", "q", "parent" and "start-offset" are parameters to
  // implement "paging" of the result on FakeDriveService.
  // The URL should be the one filled in GetChangeListInternal of the
  // previous method invocation, so it should start with "http://localhost/?".
  // See also GetChangeListInternal.
  DCHECK_EQ(next_link.host(), "localhost");
  DCHECK_EQ(next_link.path(), "/");

  int64_t start_changestamp = 0;
  std::string search_query;
  std::string directory_resource_id;
  int start_offset = 0;
  int max_results = default_max_results_;
  base::StringPairs parameters;
  if (base::SplitStringIntoKeyValuePairs(
          next_link.query(), '=', '&', &parameters)) {
    for (size_t i = 0; i < parameters.size(); ++i) {
      if (parameters[i].first == "changestamp") {
        base::StringToInt64(parameters[i].second, &start_changestamp);
      } else if (parameters[i].first == "q") {
        search_query = net::UnescapeURLComponent(
            parameters[i].second,
            net::UnescapeRule::PATH_SEPARATORS |
                net::UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS);
      } else if (parameters[i].first == "parent") {
        directory_resource_id = net::UnescapeURLComponent(
            parameters[i].second,
            net::UnescapeRule::PATH_SEPARATORS |
                net::UnescapeRule::URL_SPECIAL_CHARS_EXCEPT_PATH_SEPARATORS);
      } else if (parameters[i].first == "start-offset") {
        base::StringToInt(parameters[i].second, &start_offset);
      } else if (parameters[i].first == "max-results") {
        base::StringToInt(parameters[i].second, &max_results);
      }
    }
  }

  GetChangeListInternal(start_changestamp, search_query, directory_resource_id,
                        start_offset, max_results, nullptr, callback);
  return CancelCallback();
}

CancelCallback FakeDriveService::GetRemainingTeamDriveList(
    const std::string& page_token,
    const TeamDriveListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!page_token.empty());
  DCHECK(!callback.is_null());

  // Next offset index to page token is embedded in the token.
  size_t start_offset;
  bool parse_success = base::StringToSizeT(page_token, &start_offset);
  DCHECK(parse_success);
  GetTeamDriveListInternal(start_offset, default_max_results_, nullptr,
                           callback);
  return CancelCallback();
}

CancelCallback FakeDriveService::GetRemainingFileList(
    const GURL& next_link,
    const FileListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!next_link.is_empty());
  DCHECK(!callback.is_null());

  return GetRemainingChangeList(
      next_link, base::Bind(&FileListCallbackAdapter, callback));
}

CancelCallback FakeDriveService::GetFileResource(
    const std::string& resource_id,
    const FileResourceCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, DRIVE_NO_CONNECTION,
                                  std::unique_ptr<FileResource>()));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (entry && entry->change_resource.file()) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, HTTP_SUCCESS,
                                  std::make_unique<FileResource>(
                                      *entry->change_resource.file())));
    return CancelCallback();
  }

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(callback, HTTP_NOT_FOUND,
                                std::unique_ptr<FileResource>()));
  return CancelCallback();
}

CancelCallback FakeDriveService::GetShareUrl(
    const std::string& resource_id,
    const GURL& /* embed_origin */,
    const GetShareUrlCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback,
                   DRIVE_NO_CONNECTION,
                   GURL()));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, HTTP_SUCCESS, entry->share_url));
    return CancelCallback();
  }

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(callback, HTTP_NOT_FOUND, GURL()));
  return CancelCallback();
}

CancelCallback FakeDriveService::GetAboutResource(
    const AboutResourceCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    std::unique_ptr<AboutResource> null;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::BindOnce(callback, DRIVE_NO_CONNECTION, std::move(null)));
    return CancelCallback();
  }

  ++about_resource_load_count_;
  std::unique_ptr<AboutResource> about_resource(
      new AboutResource(*about_resource_));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(callback, HTTP_SUCCESS, std::move(about_resource)));
  return CancelCallback();
}

CancelCallback FakeDriveService::GetStartPageToken(
    const std::string& team_drive_id,
    const google_apis::StartPageTokenCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    std::unique_ptr<StartPageToken> null;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::BindOnce(callback, DRIVE_NO_CONNECTION, std::move(null)));
    return CancelCallback();
  }

  ++start_page_token_load_count_;
  // TODO(slangley): Needs to support team_drive_id.
  std::unique_ptr<StartPageToken> start_page_token =
      std::make_unique<StartPageToken>();
  start_page_token->set_start_page_token(
      base::NumberToString(about_resource_->largest_change_id()));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(callback, HTTP_SUCCESS, std::move(start_page_token)));
  return CancelCallback();
}

CancelCallback FakeDriveService::GetAppList(const AppListCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());
  DCHECK(app_info_value_);

  if (offline_) {
    std::unique_ptr<AppList> null;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::BindOnce(callback, DRIVE_NO_CONNECTION, std::move(null)));
    return CancelCallback();
  }

  ++app_list_load_count_;
  std::unique_ptr<AppList> app_list(AppList::CreateFrom(*app_info_value_));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(callback, HTTP_SUCCESS, std::move(app_list)));
  return CancelCallback();
}

CancelCallback FakeDriveService::DeleteResource(
    const std::string& resource_id,
    const std::string& etag,
    const EntryActionCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, DRIVE_NO_CONNECTION));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, HTTP_NOT_FOUND));
    return CancelCallback();
  }

  ChangeResource* change = &entry->change_resource;
  const FileResource* file = change->file();
  if (change->is_deleted()) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, HTTP_NOT_FOUND));
    return CancelCallback();
  }

  if (!etag.empty() && etag != file->etag()) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, HTTP_PRECONDITION));
    return CancelCallback();
  }

  if (entry->user_permission != google_apis::drive::PERMISSION_ROLE_OWNER) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, HTTP_FORBIDDEN));
    return CancelCallback();
  }

  change->set_deleted(true);
  AddNewChangestamp(change);
  change->set_file(std::unique_ptr<FileResource>());
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(callback, HTTP_NO_CONTENT));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&FakeDriveService::NotifyObservers,
                 weak_ptr_factory_.GetWeakPtr()));
  return CancelCallback();
}

CancelCallback FakeDriveService::TrashResource(
    const std::string& resource_id,
    const EntryActionCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, DRIVE_NO_CONNECTION));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, HTTP_NOT_FOUND));
    return CancelCallback();
  }

  ChangeResource* change = &entry->change_resource;
  FileResource* file = change->mutable_file();
  if (change->is_deleted() || file->labels().is_trashed()) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, HTTP_NOT_FOUND));
    return CancelCallback();
  }

  if (entry->user_permission != google_apis::drive::PERMISSION_ROLE_OWNER) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, HTTP_FORBIDDEN));
    return CancelCallback();
  }

  file->mutable_labels()->set_trashed(true);
  AddNewChangestamp(change);
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(callback, HTTP_SUCCESS));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&FakeDriveService::NotifyObservers,
                 weak_ptr_factory_.GetWeakPtr()));
  return CancelCallback();
}

CancelCallback FakeDriveService::DownloadFile(
    const base::FilePath& local_cache_path,
    const std::string& resource_id,
    const DownloadActionCallback& download_action_callback,
    const GetContentCallback& get_content_callback,
    const ProgressCallback& progress_callback) {
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!download_action_callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(download_action_callback,
                   DRIVE_NO_CONNECTION,
                   base::FilePath()));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry || entry->change_resource.file()->IsHostedDocument()) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(download_action_callback, HTTP_NOT_FOUND, base::FilePath()));
    return CancelCallback();
  }

  const FileResource* file = entry->change_resource.file();
  const std::string& content_data = entry->content_data;
  int64_t file_size = file->file_size();
  DCHECK_EQ(static_cast<size_t>(file_size), content_data.size());

  if (!get_content_callback.is_null()) {
    const int64_t kBlockSize = 5;
    for (int64_t i = 0; i < file_size; i += kBlockSize) {
      const int64_t size = std::min(kBlockSize, file_size - i);
      std::unique_ptr<std::string> content_for_callback(
          new std::string(content_data.substr(i, size)));
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::BindOnce(get_content_callback, HTTP_SUCCESS,
                                    std::move(content_for_callback)));
    }
  }

  if (!test_util::WriteStringToFile(local_cache_path, content_data)) {
    // Failed to write the content.
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(download_action_callback,
                   DRIVE_FILE_ERROR, base::FilePath()));
    return CancelCallback();
  }

  if (!progress_callback.is_null()) {
    // See also the comment in ResumeUpload(). For testing that clients
    // can handle the case progress_callback is called multiple times,
    // here we invoke the callback twice.
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(progress_callback, file_size / 2, file_size));
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(progress_callback, file_size, file_size));
  }
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(download_action_callback,
                 HTTP_SUCCESS,
                 local_cache_path));
  return CancelCallback();
}

CancelCallback FakeDriveService::CopyResource(
    const std::string& resource_id,
    const std::string& in_parent_resource_id,
    const std::string& new_title,
    const base::Time& last_modified,
    const FileResourceCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, DRIVE_NO_CONNECTION,
                                  std::unique_ptr<FileResource>()));
    return CancelCallback();
  }

  const std::string& parent_resource_id = in_parent_resource_id.empty() ?
      GetRootResourceId() : in_parent_resource_id;

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, HTTP_NOT_FOUND,
                                  std::unique_ptr<FileResource>()));
    return CancelCallback();
  }

  // Make a copy and set the new resource ID and the new title.
  std::unique_ptr<EntryInfo> copied_entry(new EntryInfo);
  copied_entry->content_data = entry->content_data;
  copied_entry->share_url = entry->share_url;
  copied_entry->change_resource.set_type(ChangeResource::FILE);
  copied_entry->change_resource.set_file(
      std::make_unique<FileResource>(*entry->change_resource.file()));

  ChangeResource* new_change = &copied_entry->change_resource;
  FileResource* new_file = new_change->mutable_file();
  const std::string new_resource_id = GetNewResourceId();
  new_change->set_file_id(new_resource_id);
  new_file->set_file_id(new_resource_id);
  new_file->set_title(new_title);

  ParentReference parent;
  parent.set_file_id(parent_resource_id);
  std::vector<ParentReference> parents;
  parents.push_back(parent);
  *new_file->mutable_parents() = parents;

  if (!last_modified.is_null()) {
    new_file->set_modified_date(last_modified);
    new_file->set_modified_by_me_date(last_modified);
  }

  AddNewChangestamp(new_change);
  UpdateETag(new_file);

  // Add the new entry to the map.
  entries_[new_resource_id] = std::move(copied_entry);

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(callback, HTTP_SUCCESS,
                                std::make_unique<FileResource>(*new_file)));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&FakeDriveService::NotifyObservers,
                 weak_ptr_factory_.GetWeakPtr()));
  return CancelCallback();
}

CancelCallback FakeDriveService::UpdateResource(
    const std::string& resource_id,
    const std::string& parent_resource_id,
    const std::string& new_title,
    const base::Time& last_modified,
    const base::Time& last_viewed_by_me,
    const google_apis::drive::Properties& properties,
    const google_apis::FileResourceCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, DRIVE_NO_CONNECTION,
                                  std::unique_ptr<FileResource>()));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, HTTP_NOT_FOUND,
                                  std::unique_ptr<FileResource>()));
    return CancelCallback();
  }

  if (!UserHasWriteAccess(entry->user_permission)) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, HTTP_FORBIDDEN,
                                  std::unique_ptr<FileResource>()));
    return CancelCallback();
  }

  ChangeResource* change = &entry->change_resource;
  FileResource* file = change->mutable_file();

  if (!new_title.empty())
    file->set_title(new_title);

  // Set parent if necessary.
  if (!parent_resource_id.empty()) {
    ParentReference parent;
    parent.set_file_id(parent_resource_id);

    std::vector<ParentReference> parents;
    parents.push_back(parent);
    *file->mutable_parents() = parents;
  }

  if (!last_modified.is_null()) {
    file->set_modified_date(last_modified);
    file->set_modified_by_me_date(last_modified);
  }

  if (!last_viewed_by_me.is_null())
    file->set_last_viewed_by_me_date(last_viewed_by_me);

  AddNewChangestamp(change);
  UpdateETag(file);

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(callback, HTTP_SUCCESS,
                                std::make_unique<FileResource>(*file)));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&FakeDriveService::NotifyObservers,
                 weak_ptr_factory_.GetWeakPtr()));
  return CancelCallback();
}

CancelCallback FakeDriveService::AddResourceToDirectory(
    const std::string& parent_resource_id,
    const std::string& resource_id,
    const EntryActionCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, DRIVE_NO_CONNECTION));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, HTTP_NOT_FOUND));
    return CancelCallback();
  }

  ChangeResource* change = &entry->change_resource;
  // On the real Drive server, resources do not necessary shape a tree
  // structure. That is, each resource can have multiple parent.
  // We mimic the behavior here; AddResourceToDirectoy just adds
  // one more parent, not overwriting old ones.
  ParentReference parent;
  parent.set_file_id(parent_resource_id);
  change->mutable_file()->mutable_parents()->push_back(parent);

  AddNewChangestamp(change);
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(callback, HTTP_SUCCESS));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&FakeDriveService::NotifyObservers,
                 weak_ptr_factory_.GetWeakPtr()));
  return CancelCallback();
}

CancelCallback FakeDriveService::RemoveResourceFromDirectory(
    const std::string& parent_resource_id,
    const std::string& resource_id,
    const EntryActionCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, DRIVE_NO_CONNECTION));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(callback, HTTP_NOT_FOUND));
    return CancelCallback();
  }

  ChangeResource* change = &entry->change_resource;
  FileResource* file = change->mutable_file();
  std::vector<ParentReference>* parents = file->mutable_parents();
  for (size_t i = 0; i < parents->size(); ++i) {
    if ((*parents)[i].file_id() == parent_resource_id) {
      parents->erase(parents->begin() + i);
      AddNewChangestamp(change);
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(callback, HTTP_NO_CONTENT));
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE,
          base::Bind(&FakeDriveService::NotifyObservers,
                     weak_ptr_factory_.GetWeakPtr()));
      return CancelCallback();
    }
  }

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(callback, HTTP_NOT_FOUND));
  return CancelCallback();
}

CancelCallback FakeDriveService::AddNewDirectory(
    const std::string& parent_resource_id,
    const std::string& directory_title,
    const AddNewDirectoryOptions& options,
    const FileResourceCallback& callback) {
  return AddNewDirectoryWithResourceId(
      "",
      parent_resource_id.empty() ? GetRootResourceId() : parent_resource_id,
      directory_title,
      options,
      callback);
}

CancelCallback FakeDriveService::InitiateUploadNewFile(
    const std::string& content_type,
    int64_t content_length,
    const std::string& parent_resource_id,
    const std::string& title,
    const UploadNewFileOptions& options,
    const InitiateUploadCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, DRIVE_NO_CONNECTION, GURL()));
    return CancelCallback();
  }

  if (parent_resource_id != GetRootResourceId() &&
      !entries_.count(parent_resource_id)) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, HTTP_NOT_FOUND, GURL()));
    return CancelCallback();
  }

  GURL session_url = GetNewUploadSessionUrl();
  upload_sessions_[session_url] =
      UploadSession(content_type, content_length,
                    parent_resource_id,
                    "",  // resource_id
                    "",  // etag
                    title);

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(callback, HTTP_SUCCESS, session_url));
  return CancelCallback();
}

CancelCallback FakeDriveService::InitiateUploadExistingFile(
    const std::string& content_type,
    int64_t content_length,
    const std::string& resource_id,
    const UploadExistingFileOptions& options,
    const InitiateUploadCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, DRIVE_NO_CONNECTION, GURL()));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, HTTP_NOT_FOUND, GURL()));
    return CancelCallback();
  }

  if (!UserHasWriteAccess(entry->user_permission)) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, HTTP_FORBIDDEN, GURL()));
    return CancelCallback();
  }

  FileResource* file = entry->change_resource.mutable_file();
  if (!options.etag.empty() && options.etag != file->etag()) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, HTTP_PRECONDITION, GURL()));
    return CancelCallback();
  }
  // TODO(hashimoto): Update |file|'s metadata with |options|.

  GURL session_url = GetNewUploadSessionUrl();
  upload_sessions_[session_url] =
      UploadSession(content_type, content_length,
                    "",  // parent_resource_id
                    resource_id,
                    file->etag(),
                    "" /* title */);

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(callback, HTTP_SUCCESS, session_url));
  return CancelCallback();
}

CancelCallback FakeDriveService::GetUploadStatus(
    const GURL& upload_url,
    int64_t content_length,
    const UploadRangeCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());
  return CancelCallback();
}

CancelCallback FakeDriveService::ResumeUpload(
    const GURL& upload_url,
    int64_t start_position,
    int64_t end_position,
    int64_t content_length,
    const std::string& content_type,
    const base::FilePath& local_file_path,
    const UploadRangeCallback& callback,
    const ProgressCallback& progress_callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  FileResourceCallback completion_callback
      = base::Bind(&ScheduleUploadRangeCallback,
                   callback, start_position, end_position);

  if (offline_) {
    completion_callback.Run(DRIVE_NO_CONNECTION,
                            std::unique_ptr<FileResource>());
    return CancelCallback();
  }

  if (!upload_sessions_.count(upload_url)) {
    completion_callback.Run(HTTP_NOT_FOUND, std::unique_ptr<FileResource>());
    return CancelCallback();
  }

  UploadSession* session = &upload_sessions_[upload_url];

  // Chunks are required to be sent in such a ways that they fill from the start
  // of the not-yet-uploaded part with no gaps nor overlaps.
  if (session->uploaded_size != start_position) {
    completion_callback.Run(HTTP_BAD_REQUEST, std::unique_ptr<FileResource>());
    return CancelCallback();
  }

  if (!progress_callback.is_null()) {
    // In the real GDataWapi/Drive DriveService, progress is reported in
    // nondeterministic timing. In this fake implementation, we choose to call
    // it twice per one ResumeUpload. This is for making sure that client code
    // works fine even if the callback is invoked more than once; it is the
    // crucial difference of the progress callback from others.
    // Note that progress is notified in the relative offset in each chunk.
    const int64_t chunk_size = end_position - start_position;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(progress_callback, chunk_size / 2, chunk_size));
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(progress_callback, chunk_size, chunk_size));
  }

  if (content_length != end_position) {
    session->uploaded_size = end_position;
    completion_callback.Run(HTTP_RESUME_INCOMPLETE,
                            std::unique_ptr<FileResource>());
    return CancelCallback();
  }

  std::string content_data;
  if (!base::ReadFileToString(local_file_path, &content_data)) {
    session->uploaded_size = end_position;
    completion_callback.Run(DRIVE_FILE_ERROR, std::unique_ptr<FileResource>());
    return CancelCallback();
  }
  session->uploaded_size = end_position;

  // |resource_id| is empty if the upload is for new file.
  if (session->resource_id.empty()) {
    DCHECK(!session->parent_resource_id.empty());
    DCHECK(!session->title.empty());
    const EntryInfo* new_entry = AddNewEntry(
        "",  // auto generate resource id.
        session->content_type,
        content_data,
        session->parent_resource_id,
        session->title,
        false);  // shared_with_me
    if (!new_entry) {
      completion_callback.Run(HTTP_NOT_FOUND, std::unique_ptr<FileResource>());
      return CancelCallback();
    }

    completion_callback.Run(
        HTTP_CREATED,
        std::make_unique<FileResource>(*new_entry->change_resource.file()));
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&FakeDriveService::NotifyObservers,
                   weak_ptr_factory_.GetWeakPtr()));
    return CancelCallback();
  }

  EntryInfo* entry = FindEntryByResourceId(session->resource_id);
  if (!entry) {
    completion_callback.Run(HTTP_NOT_FOUND, std::unique_ptr<FileResource>());
    return CancelCallback();
  }

  ChangeResource* change = &entry->change_resource;
  FileResource* file = change->mutable_file();
  if (file->etag().empty() || session->etag != file->etag()) {
    completion_callback.Run(HTTP_PRECONDITION, std::unique_ptr<FileResource>());
    return CancelCallback();
  }

  file->set_md5_checksum(base::MD5String(content_data));
  entry->content_data = content_data;
  file->set_file_size(end_position);
  AddNewChangestamp(change);
  UpdateETag(file);

  completion_callback.Run(HTTP_SUCCESS, std::make_unique<FileResource>(*file));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&FakeDriveService::NotifyObservers,
                 weak_ptr_factory_.GetWeakPtr()));
  return CancelCallback();
}

CancelCallback FakeDriveService::MultipartUploadNewFile(
    const std::string& content_type,
    int64_t content_length,
    const std::string& parent_resource_id,
    const std::string& title,
    const base::FilePath& local_file_path,
    const UploadNewFileOptions& options,
    const FileResourceCallback& callback,
    const ProgressCallback& progress_callback) {
  CallResumeUpload* const call_resume_upload = new CallResumeUpload();
  call_resume_upload->service = weak_ptr_factory_.GetWeakPtr();
  call_resume_upload->content_type = content_type;
  call_resume_upload->content_length = content_length;
  call_resume_upload->local_file_path = local_file_path;
  call_resume_upload->callback = callback;
  call_resume_upload->progress_callback = progress_callback;
  InitiateUploadNewFile(
      content_type,
      content_length,
      parent_resource_id,
      title,
      options,
      base::Bind(&CallResumeUpload::Run, base::Owned(call_resume_upload)));
  return CancelCallback();
}

CancelCallback FakeDriveService::MultipartUploadExistingFile(
    const std::string& content_type,
    int64_t content_length,
    const std::string& resource_id,
    const base::FilePath& local_file_path,
    const UploadExistingFileOptions& options,
    const FileResourceCallback& callback,
    const ProgressCallback& progress_callback) {
  CallResumeUpload* const call_resume_upload = new CallResumeUpload();
  call_resume_upload->service = weak_ptr_factory_.GetWeakPtr();
  call_resume_upload->content_type = content_type;
  call_resume_upload->content_length = content_length;
  call_resume_upload->local_file_path = local_file_path;
  call_resume_upload->callback = callback;
  call_resume_upload->progress_callback = progress_callback;
  InitiateUploadExistingFile(
      content_type,
      content_length,
      resource_id,
      options,
      base::Bind(&CallResumeUpload::Run, base::Owned(call_resume_upload)));
  return CancelCallback();
}

CancelCallback FakeDriveService::AuthorizeApp(
    const std::string& resource_id,
    const std::string& app_id,
    const AuthorizeAppCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (entries_.count(resource_id) == 0) {
    callback.Run(google_apis::HTTP_NOT_FOUND, GURL());
    return CancelCallback();
  }

  callback.Run(HTTP_SUCCESS,
               GURL(base::StringPrintf(open_url_format_.c_str(),
                                       resource_id.c_str(),
                                       app_id.c_str())));
  return CancelCallback();
}

CancelCallback FakeDriveService::UninstallApp(
    const std::string& app_id,
    const google_apis::EntryActionCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, google_apis::DRIVE_NO_CONNECTION));
    return CancelCallback();
  }

  // Find app_id from app_info_value_ and delete.
  base::ListValue* items = nullptr;
  if (!app_info_value_->GetList("items", &items)) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, google_apis::HTTP_NOT_FOUND));
    return CancelCallback();
  }

  for (size_t i = 0; i < items->GetSize(); ++i) {
    base::DictionaryValue* item = nullptr;
    std::string id;
    if (items->GetDictionary(i, &item) && item->GetString("id", &id) &&
        id == app_id) {
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(callback, items->Remove(i, nullptr)
                                              ? google_apis::HTTP_NO_CONTENT
                                              : google_apis::HTTP_NOT_FOUND));
      return CancelCallback();
    }
  }

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(callback, google_apis::HTTP_NOT_FOUND));
  return CancelCallback();
}

void FakeDriveService::AddNewFile(const std::string& content_type,
                                  const std::string& content_data,
                                  const std::string& parent_resource_id,
                                  const std::string& title,
                                  bool shared_with_me,
                                  const FileResourceCallback& callback) {
  AddNewFileWithResourceId("", content_type, content_data, parent_resource_id,
                           title, shared_with_me, callback);
}

void FakeDriveService::AddNewFileWithResourceId(
    const std::string& resource_id,
    const std::string& content_type,
    const std::string& content_data,
    const std::string& parent_resource_id,
    const std::string& title,
    bool shared_with_me,
    const FileResourceCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, DRIVE_NO_CONNECTION,
                                  std::unique_ptr<FileResource>()));
    return;
  }

  const EntryInfo* new_entry = AddNewEntry(resource_id,
                                           content_type,
                                           content_data,
                                           parent_resource_id,
                                           title,
                                           shared_with_me);
  if (!new_entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, HTTP_NOT_FOUND,
                                  std::unique_ptr<FileResource>()));
    return;
  }

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(callback, HTTP_CREATED,
                                std::make_unique<FileResource>(
                                    *new_entry->change_resource.file())));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&FakeDriveService::NotifyObservers,
                 weak_ptr_factory_.GetWeakPtr()));
}

CancelCallback FakeDriveService::AddNewDirectoryWithResourceId(
    const std::string& resource_id,
    const std::string& parent_resource_id,
    const std::string& directory_title,
    const AddNewDirectoryOptions& options,
    const FileResourceCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, DRIVE_NO_CONNECTION,
                                  std::unique_ptr<FileResource>()));
    return CancelCallback();
  }

  const EntryInfo* new_entry = AddNewEntry(resource_id,
                                           util::kDriveFolderMimeType,
                                           "",  // content_data
                                           parent_resource_id,
                                           directory_title,
                                           false);  // shared_with_me
  if (!new_entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, HTTP_NOT_FOUND,
                                  std::unique_ptr<FileResource>()));
    return CancelCallback();
  }

  const google_apis::DriveApiErrorCode result =
      SetFileVisibility(new_entry->change_resource.file_id(),
                        options.visibility);
  DCHECK_EQ(HTTP_SUCCESS, result);

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(callback, HTTP_CREATED,
                                std::make_unique<FileResource>(
                                    *new_entry->change_resource.file())));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&FakeDriveService::NotifyObservers,
                 weak_ptr_factory_.GetWeakPtr()));
  return CancelCallback();
}

void FakeDriveService::SetLastModifiedTime(
    const std::string& resource_id,
    const base::Time& last_modified_time,
    const FileResourceCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, DRIVE_NO_CONNECTION,
                                  std::unique_ptr<FileResource>()));
    return;
  }

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, HTTP_NOT_FOUND,
                                  std::unique_ptr<FileResource>()));
    return;
  }

  ChangeResource* change = &entry->change_resource;
  FileResource* file = change->mutable_file();
  file->set_modified_date(last_modified_time);
  file->set_modified_by_me_date(last_modified_time);

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(callback, HTTP_SUCCESS,
                                std::make_unique<FileResource>(*file)));
}

google_apis::DriveApiErrorCode FakeDriveService::SetUserPermission(
    const std::string& resource_id,
    google_apis::drive::PermissionRole user_permission) {
  DCHECK(thread_checker_.CalledOnValidThread());

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry)
    return HTTP_NOT_FOUND;

  entry->user_permission = user_permission;
  return HTTP_SUCCESS;
}

google_apis::DriveApiErrorCode FakeDriveService::SetFileVisibility(
    const std::string& resource_id,
    google_apis::drive::FileVisibility visibility) {
  DCHECK(thread_checker_.CalledOnValidThread());

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry)
    return HTTP_NOT_FOUND;

  entry->visibility = visibility;
  return HTTP_SUCCESS;
}

google_apis::DriveApiErrorCode FakeDriveService::GetFileVisibility(
    const std::string& resource_id,
    google_apis::drive::FileVisibility* visibility) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(visibility);

  EntryInfo* entry = FindEntryByResourceId(resource_id);
  if (!entry)
    return HTTP_NOT_FOUND;

  *visibility = entry->visibility;
  return HTTP_SUCCESS;
}

void FakeDriveService::AddChangeObserver(ChangeObserver* change_observer) {
  change_observers_.AddObserver(change_observer);
}

void FakeDriveService::RemoveChangeObserver(ChangeObserver* change_observer) {
  change_observers_.RemoveObserver(change_observer);
}

FakeDriveService::EntryInfo* FakeDriveService::FindEntryByResourceId(
    const std::string& resource_id) {
  DCHECK(thread_checker_.CalledOnValidThread());

  auto it = entries_.find(resource_id);
  // Deleted entries don't have FileResource.
  return it != entries_.end() && it->second->change_resource.file()
             ? it->second.get()
             : nullptr;
}

std::string FakeDriveService::GetNewResourceId() {
  DCHECK(thread_checker_.CalledOnValidThread());

  ++resource_id_count_;
  return base::StringPrintf("resource_id_%d", resource_id_count_);
}

void FakeDriveService::UpdateETag(google_apis::FileResource* file) {
  file->set_etag(
      "etag_" + base::Int64ToString(about_resource_->largest_change_id()));
}

void FakeDriveService::AddNewChangestamp(google_apis::ChangeResource* change) {
  about_resource_->set_largest_change_id(
      about_resource_->largest_change_id() + 1);
  change->set_change_id(about_resource_->largest_change_id());
}

const FakeDriveService::EntryInfo* FakeDriveService::AddNewEntry(
    const std::string& given_resource_id,
    const std::string& content_type,
    const std::string& content_data,
    const std::string& parent_resource_id,
    const std::string& title,
    bool shared_with_me) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!parent_resource_id.empty() &&
      parent_resource_id != GetRootResourceId() &&
      !entries_.count(parent_resource_id)) {
    return nullptr;
  }

  const std::string resource_id =
      given_resource_id.empty() ? GetNewResourceId() : given_resource_id;
  if (entries_.count(resource_id))
    return nullptr;
  GURL upload_url = GURL("https://xxx/upload/" + resource_id);

  std::unique_ptr<EntryInfo> new_entry(new EntryInfo);
  ChangeResource* new_change = &new_entry->change_resource;
  FileResource* new_file = new FileResource;
  new_change->set_type(ChangeResource::FILE);
  new_change->set_file(base::WrapUnique(new_file));

  // Set the resource ID and the title
  new_change->set_file_id(resource_id);
  new_file->set_file_id(resource_id);
  new_file->set_title(title);
  // Set the contents, size and MD5 for a file.
  if (content_type != util::kDriveFolderMimeType &&
      !util::IsKnownHostedDocumentMimeType(content_type)) {
    new_entry->content_data = content_data;
    new_file->set_file_size(content_data.size());
    new_file->set_md5_checksum(base::MD5String(content_data));
  }

  if (shared_with_me) {
    // Set current time to mark the file as shared_with_me.
    new_file->set_shared_with_me_date(base::Time::Now());
  }

  std::string escaped_resource_id = net::EscapePath(resource_id);

  // Set mime type.
  new_file->set_mime_type(content_type);

  // Set alternate link if needed.
  if (content_type == util::kGoogleDocumentMimeType)
    new_file->set_alternate_link(GURL("https://document_alternate_link"));

  // Set parents.
  if (!parent_resource_id.empty()) {
    ParentReference parent;
    parent.set_file_id(parent_resource_id);
    std::vector<ParentReference> parents;
    parents.push_back(parent);
    *new_file->mutable_parents() = parents;
  }

  new_entry->share_url = net::AppendOrReplaceQueryParameter(
      share_url_base_, "name", title);

  AddNewChangestamp(new_change);
  UpdateETag(new_file);

  new_file->set_created_date(base::Time() +
                             base::TimeDelta::FromMilliseconds(++date_seq_));
  new_file->set_modified_by_me_date(
      base::Time() + base::TimeDelta::FromMilliseconds(++date_seq_));
  new_file->set_modified_date(base::Time() +
                              base::TimeDelta::FromMilliseconds(++date_seq_));

  EntryInfo* raw_new_entry = new_entry.get();
  entries_[resource_id] = std::move(new_entry);
  return raw_new_entry;
}

void FakeDriveService::GetChangeListInternal(
    int64_t start_changestamp,
    const std::string& search_query,
    const std::string& directory_resource_id,
    int start_offset,
    int max_results,
    int* load_counter,
    const ChangeListCallback& callback) {
  if (offline_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(callback, DRIVE_NO_CONNECTION,
                                  std::unique_ptr<ChangeList>()));
    return;
  }

  // Filter out entries per parameters like |directory_resource_id| and
  // |search_query|.
  std::vector<std::unique_ptr<ChangeResource>> entries;
  int num_entries_matched = 0;
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    const ChangeResource& entry = it->second->change_resource;
    bool should_exclude = false;

    // If |directory_resource_id| is set, exclude the entry if it's not in
    // the target directory.
    if (!directory_resource_id.empty()) {
      // Get the parent resource ID of the entry.
      std::string parent_resource_id;
      if (entry.file() && !entry.file()->parents().empty())
        parent_resource_id = entry.file()->parents()[0].file_id();

      if (directory_resource_id != parent_resource_id)
        should_exclude = true;
    }

    // If |search_query| is set, exclude the entry if it does not contain the
    // search query in the title.
    if (!should_exclude && !search_query.empty() &&
        !EntryMatchWithQuery(entry, search_query)) {
      should_exclude = true;
    }

    // If |start_changestamp| is set, exclude the entry if the
    // changestamp is older than |largest_changestamp|.
    // See https://developers.google.com/google-apps/documents-list/
    // #retrieving_all_changes_since_a_given_changestamp
    if (start_changestamp > 0 && entry.change_id() < start_changestamp)
      should_exclude = true;

    // If the caller requests other list than change list by specifying
    // zero-|start_changestamp|, exclude deleted entry from the result.
    const bool deleted = entry.is_deleted() ||
        (entry.file() && entry.file()->labels().is_trashed());
    if (!start_changestamp && deleted)
      should_exclude = true;

    // The entry matched the criteria for inclusion.
    if (!should_exclude)
      ++num_entries_matched;

    // If |start_offset| is set, exclude the entry if the entry is before the
    // start index. <= instead of < as |num_entries_matched| was
    // already incremented.
    if (start_offset > 0 && num_entries_matched <= start_offset)
      should_exclude = true;

    if (!should_exclude) {
      std::unique_ptr<ChangeResource> entry_copied(new ChangeResource);
      entry_copied->set_type(entry.type());
      entry_copied->set_change_id(entry.change_id());
      entry_copied->set_file_id(entry.file_id());
      entry_copied->set_deleted(entry.is_deleted());
      if (entry.type() == ChangeResource::FILE && entry.file()) {
        entry_copied->set_file(std::make_unique<FileResource>(*entry.file()));
      }
      if (entry.type() == ChangeResource::TEAM_DRIVE && entry.team_drive()) {
        entry_copied->set_team_drive(
            std::make_unique<TeamDriveResource>(*entry.team_drive()));
      }
      entry_copied->set_modification_date(entry.modification_date());
      entries.push_back(std::move(entry_copied));
    }
  }

  std::unique_ptr<ChangeList> change_list(new ChangeList);
  if (start_changestamp > 0 && start_offset == 0) {
    change_list->set_largest_change_id(about_resource_->largest_change_id());
  }

  // If |max_results| is set, trim the entries if the number exceeded the max
  // results.
  if (max_results > 0 && entries.size() > static_cast<size_t>(max_results)) {
    entries.erase(entries.begin() + max_results, entries.end());
    // Adds the next URL.
    // Here, we embed information which is needed for continuing the
    // GetChangeList request in the next invocation into url query
    // parameters.
    GURL next_url(base::StringPrintf(
        "http://localhost/?start-offset=%d&max-results=%d",
        start_offset + max_results,
        max_results));
    if (start_changestamp > 0) {
      next_url = net::AppendOrReplaceQueryParameter(
          next_url, "changestamp",
          base::Int64ToString(start_changestamp).c_str());
    }
    if (!search_query.empty()) {
      next_url = net::AppendOrReplaceQueryParameter(
          next_url, "q", search_query);
    }
    if (!directory_resource_id.empty()) {
      next_url = net::AppendOrReplaceQueryParameter(
          next_url, "parent", directory_resource_id);
    }

    change_list->set_next_link(next_url);
  }
  *change_list->mutable_items() = std::move(entries);

  if (load_counter)
    *load_counter += 1;
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(callback, HTTP_SUCCESS, std::move(change_list)));
}

GURL FakeDriveService::GetNewUploadSessionUrl() {
  return GURL("https://upload_session_url/" +
              base::Int64ToString(next_upload_sequence_number_++));
}

google_apis::CancelCallback FakeDriveService::AddPermission(
    const std::string& resource_id,
    const std::string& email,
    google_apis::drive::PermissionRole role,
    const google_apis::EntryActionCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  NOTREACHED();
  return CancelCallback();
}

std::unique_ptr<BatchRequestConfiguratorInterface>
FakeDriveService::StartBatchRequest() {
  DCHECK(thread_checker_.CalledOnValidThread());

  NOTREACHED();
  return std::unique_ptr<BatchRequestConfiguratorInterface>();
}

void FakeDriveService::NotifyObservers() {
  for (auto& observer : change_observers_)
    observer.OnNewChangeAvailable();
}

}  // namespace drive

// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/extensions/wallpaper_private_api.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/command_line.h"
#include "base/files/file_enumerator.h"
#include "base/macros.h"
#include "base/memory/ref_counted_memory.h"
#include "base/metrics/histogram_macros.h"
#include "base/path_service.h"
#include "base/sequenced_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/task_runner_util.h"
#include "base/values.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/chromeos/extensions/backdrop_wallpaper_handlers/backdrop_wallpaper_handlers.h"
#include "chrome/browser/chromeos/file_manager/path_util.h"
#include "chrome/browser/chromeos/profiles/profile_helper.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/sync/profile_sync_service_factory.h"
#include "chrome/browser/ui/ash/ash_util.h"
#include "chrome/browser/ui/ash/wallpaper_controller_client.h"
#include "chrome/common/chrome_paths.h"
#include "chrome/grit/generated_resources.h"
#include "chromeos/chromeos_switches.h"
#include "components/browser_sync/profile_sync_service.h"
#include "components/strings/grit/components_strings.h"
#include "components/user_manager/user.h"
#include "components/user_manager/user_manager.h"
#include "content/public/browser/browser_thread.h"
#include "extensions/browser/event_router.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/webui/web_ui_util.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/strings/grit/app_locale_settings.h"

using base::Value;
using content::BrowserThread;

namespace wallpaper_base = extensions::api::wallpaper;
namespace wallpaper_private = extensions::api::wallpaper_private;
namespace set_wallpaper_if_exists = wallpaper_private::SetWallpaperIfExists;
namespace set_wallpaper = wallpaper_private::SetWallpaper;
namespace set_custom_wallpaper = wallpaper_private::SetCustomWallpaper;
namespace set_custom_wallpaper_layout =
    wallpaper_private::SetCustomWallpaperLayout;
namespace get_thumbnail = wallpaper_private::GetThumbnail;
namespace save_thumbnail = wallpaper_private::SaveThumbnail;
namespace get_offline_wallpaper_list =
    wallpaper_private::GetOfflineWallpaperList;
namespace record_wallpaper_uma = wallpaper_private::RecordWallpaperUMA;
namespace get_collections_info = wallpaper_private::GetCollectionsInfo;
namespace get_images_info = wallpaper_private::GetImagesInfo;
namespace get_local_image_paths = wallpaper_private::GetLocalImagePaths;
namespace get_local_image_data = wallpaper_private::GetLocalImageData;

namespace {

// The time in seconds and retry limit to re-check the profile sync service
// status. Only after the profile sync service has been configured, we can get
// the correct value of the user sync preference of "syncThemes".
constexpr int kRetryDelay = 10;
constexpr int kRetryLimit = 3;

constexpr char kPngFilePattern[] = "*.[pP][nN][gG]";
constexpr char kJpgFilePattern[] = "*.[jJ][pP][gG]";
constexpr char kJpegFilePattern[] = "*.[jJ][pP][eE][gG]";

// The url suffix used by the old wallpaper picker.
constexpr char kHighResolutionSuffix[] = "_high_resolution.jpg";

#if defined(GOOGLE_CHROME_BUILD)
const char kWallpaperManifestBaseURL[] =
    "https://storage.googleapis.com/chromeos-wallpaper-public/manifest_";
#endif

bool IsOEMDefaultWallpaper() {
  return base::CommandLine::ForCurrentProcess()->HasSwitch(
      chromeos::switches::kDefaultWallpaperIsOem);
}

bool IsUsingNewWallpaperPicker() {
  return base::CommandLine::ForCurrentProcess()->HasSwitch(
      chromeos::switches::kNewWallpaperPicker);
}

// Returns a suffix to be appended to the base url of Backdrop wallpapers.
std::string GetBackdropWallpaperSuffix() {
  // FIFE url is used for Backdrop wallpapers and the desired image size should
  // be specified. Currently we are using two times the display size. This is
  // determined by trial and error and is subject to change.
  const gfx::Size& display_size =
      display::Screen::GetScreen()->GetPrimaryDisplay().size();
  return "=w" + std::to_string(
                    2 * std::max(display_size.width(), display_size.height()));
}

// Saves |data| as |file_name| to directory with |key|. Return false if the
// directory can not be found/created or failed to write file.
bool SaveData(int key,
              const std::string& file_name,
              const std::vector<char>& data) {
  base::FilePath data_dir;
  CHECK(PathService::Get(key, &data_dir));
  if (!base::DirectoryExists(data_dir) &&
      !base::CreateDirectory(data_dir)) {
    return false;
  }
  base::FilePath file_path = data_dir.Append(file_name);

  return base::PathExists(file_path) ||
         base::WriteFile(file_path, data.data(), data.size()) != -1;
}

// Gets |file_name| from directory with |key|. Return false if the directory can
// not be found or failed to read file to string |data|. Note if the |file_name|
// can not be found in the directory, return true with empty |data|. It is
// expected that we may try to access file which did not saved yet.
bool GetData(const base::FilePath& path, std::string* data) {
  base::FilePath data_dir = path.DirName();
  if (!base::DirectoryExists(data_dir) &&
      !base::CreateDirectory(data_dir))
    return false;

  return !base::PathExists(path) ||
         base::ReadFileToString(path, data);
}

// Gets the |User| for a given |BrowserContext|. The function will only return
// valid objects.
const user_manager::User* GetUserFromBrowserContext(
    content::BrowserContext* context) {
  Profile* profile = Profile::FromBrowserContext(context);
  DCHECK(profile);
  const user_manager::User* user =
      chromeos::ProfileHelper::Get()->GetUserByProfile(profile);
  DCHECK(user);
  return user;
}

ash::WallpaperType getWallpaperType(wallpaper_private::WallpaperSource source) {
  switch (source) {
    case wallpaper_private::WALLPAPER_SOURCE_ONLINE:
      return ash::ONLINE;
    case wallpaper_private::WALLPAPER_SOURCE_DAILY:
      return ash::DAILY;
    case wallpaper_private::WALLPAPER_SOURCE_CUSTOM:
      return ash::CUSTOMIZED;
    case wallpaper_private::WALLPAPER_SOURCE_OEM:
      return ash::DEFAULT;
    case wallpaper_private::WALLPAPER_SOURCE_THIRDPARTY:
      return ash::THIRDPARTY;
    default:
      return ash::ONLINE;
  }
}

// Helper function to get the list of image paths under |path| that match
// |pattern|.
void EnumerateImages(const base::FilePath& path,
                     const std::string& pattern,
                     std::vector<std::string>* result_out) {
  base::FileEnumerator image_enum(
      path, true /* recursive */, base::FileEnumerator::FILES,
      FILE_PATH_LITERAL(pattern),
      base::FileEnumerator::FolderSearchPolicy::ALL);

  for (base::FilePath image_path = image_enum.Next(); !image_path.empty();
       image_path = image_enum.Next()) {
    result_out->emplace_back(image_path.value());
  }
}

// Recursively retrieves the paths of the image files under |path|.
std::vector<std::string> GetImagePaths(const base::FilePath& path) {
  WallpaperFunctionBase::AssertCalledOnWallpaperSequence(
      WallpaperFunctionBase::GetNonBlockingTaskRunner());

  // TODO(crbug.com/810575): Add metrics on the number of files retrieved, and
  // support getting paths incrementally in case the user has a large number of
  // local images.
  std::vector<std::string> image_paths;
  EnumerateImages(path, kPngFilePattern, &image_paths);
  EnumerateImages(path, kJpgFilePattern, &image_paths);
  EnumerateImages(path, kJpegFilePattern, &image_paths);

  return image_paths;
}

}  // namespace

ExtensionFunction::ResponseAction WallpaperPrivateGetStringsFunction::Run() {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

#define SET_STRING(id, idr) \
  dict->SetString(id, l10n_util::GetStringUTF16(idr))
  SET_STRING("webFontFamily", IDS_WEB_FONT_FAMILY);
  SET_STRING("webFontSize", IDS_WEB_FONT_SIZE);
  SET_STRING("allCategoryLabel", IDS_WALLPAPER_MANAGER_ALL_CATEGORY_LABEL);
  SET_STRING("deleteCommandLabel", IDS_WALLPAPER_MANAGER_DELETE_COMMAND_LABEL);
  SET_STRING("customCategoryLabel",
             IsUsingNewWallpaperPicker()
                 ? IDS_WALLPAPER_MANAGER_MY_PHOTOS_CATEGORY_LABEL
                 : IDS_WALLPAPER_MANAGER_CUSTOM_CATEGORY_LABEL);
  SET_STRING("selectCustomLabel",
             IDS_WALLPAPER_MANAGER_SELECT_CUSTOM_LABEL);
  SET_STRING("positionLabel", IDS_WALLPAPER_MANAGER_POSITION_LABEL);
  SET_STRING("colorLabel", IDS_WALLPAPER_MANAGER_COLOR_LABEL);
  SET_STRING("refreshLabel", IDS_WALLPAPER_MANAGER_REFRESH_LABEL);
  SET_STRING("exploreLabel", IDS_WALLPAPER_MANAGER_EXPLORE_LABEL);
  SET_STRING("centerCroppedLayout",
             IDS_WALLPAPER_MANAGER_LAYOUT_CENTER_CROPPED);
  SET_STRING("centerLayout", IDS_WALLPAPER_MANAGER_LAYOUT_CENTER);
  SET_STRING("stretchLayout", IDS_WALLPAPER_MANAGER_LAYOUT_STRETCH);
  SET_STRING("connectionFailed", IDS_WALLPAPER_MANAGER_ACCESS_FAIL);
  SET_STRING("downloadFailed", IDS_WALLPAPER_MANAGER_DOWNLOAD_FAIL);
  SET_STRING("downloadCanceled", IDS_WALLPAPER_MANAGER_DOWNLOAD_CANCEL);
  SET_STRING("customWallpaperWarning",
             IDS_WALLPAPER_MANAGER_SHOW_CUSTOM_WALLPAPER_ON_START_WARNING);
  SET_STRING("accessFileFailure", IDS_WALLPAPER_MANAGER_ACCESS_FILE_FAILURE);
  SET_STRING("invalidWallpaper", IDS_WALLPAPER_MANAGER_INVALID_WALLPAPER);
  SET_STRING("noImagesAvailable", IDS_WALLPAPER_MANAGER_NO_IMAGES_AVAILABLE);
  SET_STRING("surpriseMeLabel", IsUsingNewWallpaperPicker()
                                    ? IDS_WALLPAPER_MANAGER_DAILY_REFRESH_LABEL
                                    : IDS_WALLPAPER_MANAGER_SURPRISE_ME_LABEL);
  SET_STRING("learnMore", IDS_LEARN_MORE);
  SET_STRING("currentWallpaperSetByMessage",
             IDS_CURRENT_WALLPAPER_SET_BY_MESSAGE);
  SET_STRING("currentlySetLabel", IDS_WALLPAPER_MANAGER_CURRENTLY_SET_LABEL);
  SET_STRING("confirmPreviewLabel",
             IDS_WALLPAPER_MANAGER_CONFIRM_PREVIEW_WALLPAPER_LABEL);
  SET_STRING("setSuccessfullyMessage",
             IDS_WALLPAPER_MANAGER_SET_SUCCESSFULLY_MESSAGE);
#undef SET_STRING

  const std::string& app_locale = g_browser_process->GetApplicationLocale();
  webui::SetLoadTimeDataDefaults(app_locale, dict.get());

#if defined(GOOGLE_CHROME_BUILD)
  dict->SetString("manifestBaseURL", kWallpaperManifestBaseURL);
#endif

  dict->SetBoolean("isOEMDefaultWallpaper", IsOEMDefaultWallpaper());
  dict->SetString("canceledWallpaper",
                  wallpaper_api_util::kCancelWallpaperMessage);
  dict->SetBoolean("useNewWallpaperPicker", IsUsingNewWallpaperPicker());
  dict->SetString("highResolutionSuffix", IsUsingNewWallpaperPicker()
                                              ? GetBackdropWallpaperSuffix()
                                              : kHighResolutionSuffix);

  WallpaperControllerClient::Get()->GetActiveUserWallpaperLocation(
      base::BindOnce(
          &WallpaperPrivateGetStringsFunction::OnWallpaperLocationReturned,
          this, std::move(dict)));
  return RespondLater();
}

void WallpaperPrivateGetStringsFunction::OnWallpaperLocationReturned(
    std::unique_ptr<base::DictionaryValue> dict,
    const std::string& location) {
  dict->SetString("currentWallpaper", location);
  Respond(OneArgument(std::move(dict)));
}

ExtensionFunction::ResponseAction
WallpaperPrivateGetSyncSettingFunction::Run() {
  BrowserThread::PostTask(
      BrowserThread::UI, FROM_HERE,
      base::BindOnce(&WallpaperPrivateGetSyncSettingFunction::
                         CheckProfileSyncServiceStatus,
                     this));
  return RespondLater();
}

void WallpaperPrivateGetSyncSettingFunction::CheckProfileSyncServiceStatus() {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

  if (retry_number > kRetryLimit) {
    // It's most likely that the wallpaper synchronization is enabled (It's
    // enabled by default so unless the user disables it explicitly it remains
    // enabled).
    dict->SetBoolean("syncThemes", true);
    Respond(OneArgument(std::move(dict)));
    return;
  }

  Profile* profile =  Profile::FromBrowserContext(browser_context());
  browser_sync::ProfileSyncService* sync_service =
      ProfileSyncServiceFactory::GetInstance()->GetForProfile(profile);
  if (!sync_service) {
    dict->SetBoolean("syncThemes", false);
    Respond(OneArgument(std::move(dict)));
    return;
  }

  if (sync_service->IsSyncActive() && sync_service->ConfigurationDone()) {
    dict->SetBoolean("syncThemes",
                     sync_service->GetActiveDataTypes().Has(syncer::THEMES));
    Respond(OneArgument(std::move(dict)));
    return;
  }

  // It's possible that the profile sync service hasn't finished configuring yet
  // when we're trying to query the user preference (this seems only happen for
  // the first time configuration). In this case GetActiveDataTypes() returns an
  // empty set. So re-check the status later.
  retry_number++;
  BrowserThread::PostDelayedTask(
      BrowserThread::UI, FROM_HERE,
      base::BindOnce(&WallpaperPrivateGetSyncSettingFunction::
                         CheckProfileSyncServiceStatus,
                     this),
      base::TimeDelta::FromSeconds(retry_number * kRetryDelay));
}

WallpaperPrivateSetWallpaperIfExistsFunction::
    WallpaperPrivateSetWallpaperIfExistsFunction() {}

WallpaperPrivateSetWallpaperIfExistsFunction::
    ~WallpaperPrivateSetWallpaperIfExistsFunction() {}

ExtensionFunction::ResponseAction
WallpaperPrivateSetWallpaperIfExistsFunction::Run() {
  std::unique_ptr<
      extensions::api::wallpaper_private::SetWallpaperIfExists::Params>
      params = set_wallpaper_if_exists::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(params);

  WallpaperControllerClient::Get()->SetOnlineWallpaperIfExists(
      GetUserFromBrowserContext(browser_context())->GetAccountId(),
      GURL(params->url),
      wallpaper_api_util::GetLayoutEnum(
          wallpaper_base::ToString(params->layout)),
      params->preview_mode,
      base::BindOnce(&WallpaperPrivateSetWallpaperIfExistsFunction::
                         OnSetOnlineWallpaperIfExistsCallback,
                     this));
  return RespondLater();
}

void WallpaperPrivateSetWallpaperIfExistsFunction::
    OnSetOnlineWallpaperIfExistsCallback(bool file_exists) {
  if (file_exists) {
    Respond(OneArgument(std::make_unique<base::Value>(true)));
  } else {
    auto args = std::make_unique<base::ListValue>();
    // TODO(crbug.com/830212): Do not send arguments when the function fails.
    // Call sites should inspect chrome.runtime.lastError instead.
    args->AppendBoolean(false);
    Respond(ErrorWithArguments(
        std::move(args), "The wallpaper doesn't exist in local file system."));
  }
}

WallpaperPrivateSetWallpaperFunction::WallpaperPrivateSetWallpaperFunction() {
}

WallpaperPrivateSetWallpaperFunction::~WallpaperPrivateSetWallpaperFunction() {
}

ExtensionFunction::ResponseAction WallpaperPrivateSetWallpaperFunction::Run() {
  std::unique_ptr<extensions::api::wallpaper_private::SetWallpaper::Params>
      params = set_wallpaper::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(params);

  WallpaperControllerClient::Get()->SetOnlineWallpaperFromData(
      GetUserFromBrowserContext(browser_context())->GetAccountId(),
      std::string(params->wallpaper.begin(), params->wallpaper.end()),
      GURL(params->url),
      wallpaper_api_util::GetLayoutEnum(
          wallpaper_base::ToString(params->layout)),
      params->preview_mode);

  return RespondNow(NoArguments());
}

WallpaperPrivateResetWallpaperFunction::
    WallpaperPrivateResetWallpaperFunction() {}

WallpaperPrivateResetWallpaperFunction::
    ~WallpaperPrivateResetWallpaperFunction() {}

ExtensionFunction::ResponseAction
WallpaperPrivateResetWallpaperFunction::Run() {
  const AccountId& account_id =
      user_manager::UserManager::Get()->GetActiveUser()->GetAccountId();

  WallpaperControllerClient::Get()->SetDefaultWallpaper(
      account_id, true /* show_wallpaper */);
  return RespondNow(NoArguments());
}

WallpaperPrivateSetCustomWallpaperFunction::
    WallpaperPrivateSetCustomWallpaperFunction() {}

WallpaperPrivateSetCustomWallpaperFunction::
    ~WallpaperPrivateSetCustomWallpaperFunction() {}

ExtensionFunction::ResponseAction
WallpaperPrivateSetCustomWallpaperFunction::Run() {
  params = set_custom_wallpaper::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(params);

  // Gets account id from the caller, ensuring multiprofile compatibility.
  const user_manager::User* user = GetUserFromBrowserContext(browser_context());
  account_id_ = user->GetAccountId();
  wallpaper_files_id_ =
      WallpaperControllerClient::Get()->GetFilesId(account_id_);

  StartDecode(params->wallpaper);

  return RespondLater();
}

void WallpaperPrivateSetCustomWallpaperFunction::OnWallpaperDecoded(
    const gfx::ImageSkia& image) {
  ash::WallpaperLayout layout = wallpaper_api_util::GetLayoutEnum(
      wallpaper_base::ToString(params->layout));
  wallpaper_api_util::RecordCustomWallpaperLayout(layout);

  WallpaperControllerClient::Get()->SetCustomWallpaper(
      account_id_, wallpaper_files_id_, params->file_name, layout, image,
      params->preview_mode);
  unsafe_wallpaper_decoder_ = nullptr;

  if (params->generate_thumbnail) {
    image.EnsureRepsForSupportedScales();
    scoped_refptr<base::RefCountedBytes> thumbnail_data;
    GenerateThumbnail(
        image, gfx::Size(kWallpaperThumbnailWidth, kWallpaperThumbnailHeight),
        &thumbnail_data);
    Respond(OneArgument(Value::CreateWithCopiedBuffer(
        reinterpret_cast<const char*>(thumbnail_data->front()),
        thumbnail_data->size())));
  } else {
    Respond(NoArguments());
  }
}

WallpaperPrivateSetCustomWallpaperLayoutFunction::
    WallpaperPrivateSetCustomWallpaperLayoutFunction() {}

WallpaperPrivateSetCustomWallpaperLayoutFunction::
    ~WallpaperPrivateSetCustomWallpaperLayoutFunction() {}

ExtensionFunction::ResponseAction
WallpaperPrivateSetCustomWallpaperLayoutFunction::Run() {
  std::unique_ptr<set_custom_wallpaper_layout::Params> params(
      set_custom_wallpaper_layout::Params::Create(*args_));
  EXTENSION_FUNCTION_VALIDATE(params);

  ash::WallpaperLayout new_layout = wallpaper_api_util::GetLayoutEnum(
      wallpaper_base::ToString(params->layout));
  wallpaper_api_util::RecordCustomWallpaperLayout(new_layout);
  WallpaperControllerClient::Get()->UpdateCustomWallpaperLayout(
      user_manager::UserManager::Get()->GetActiveUser()->GetAccountId(),
      new_layout);
  return RespondNow(NoArguments());
}

WallpaperPrivateMinimizeInactiveWindowsFunction::
    WallpaperPrivateMinimizeInactiveWindowsFunction() {
}

WallpaperPrivateMinimizeInactiveWindowsFunction::
    ~WallpaperPrivateMinimizeInactiveWindowsFunction() {
}

ExtensionFunction::ResponseAction
WallpaperPrivateMinimizeInactiveWindowsFunction::Run() {
  WallpaperControllerClient::Get()->MinimizeInactiveWindows(
      user_manager::UserManager::Get()->GetActiveUser()->username_hash());
  return RespondNow(NoArguments());
}

WallpaperPrivateRestoreMinimizedWindowsFunction::
    WallpaperPrivateRestoreMinimizedWindowsFunction() {
}

WallpaperPrivateRestoreMinimizedWindowsFunction::
    ~WallpaperPrivateRestoreMinimizedWindowsFunction() {
}

ExtensionFunction::ResponseAction
WallpaperPrivateRestoreMinimizedWindowsFunction::Run() {
  WallpaperControllerClient::Get()->RestoreMinimizedWindows(
      user_manager::UserManager::Get()->GetActiveUser()->username_hash());
  return RespondNow(NoArguments());
}

WallpaperPrivateGetThumbnailFunction::WallpaperPrivateGetThumbnailFunction() {
}

WallpaperPrivateGetThumbnailFunction::~WallpaperPrivateGetThumbnailFunction() {
}

ExtensionFunction::ResponseAction WallpaperPrivateGetThumbnailFunction::Run() {
  std::unique_ptr<get_thumbnail::Params> params(
      get_thumbnail::Params::Create(*args_));
  EXTENSION_FUNCTION_VALIDATE(params);

  base::FilePath thumbnail_path;
  if (params->source == wallpaper_private::WALLPAPER_SOURCE_ONLINE) {
    std::string file_name = GURL(params->url_or_file).ExtractFileName();
    CHECK(PathService::Get(chrome::DIR_CHROMEOS_WALLPAPER_THUMBNAILS,
                           &thumbnail_path));
    thumbnail_path = thumbnail_path.Append(file_name);
  } else {
    if (!IsOEMDefaultWallpaper())
      return RespondNow(Error("No OEM wallpaper."));

    // TODO(bshe): Small resolution wallpaper is used here as wallpaper
    // thumbnail. We should either resize it or include a wallpaper thumbnail in
    // addition to large and small wallpaper resolutions.
    thumbnail_path = base::CommandLine::ForCurrentProcess()->GetSwitchValuePath(
        chromeos::switches::kDefaultWallpaperSmall);
  }

  WallpaperFunctionBase::GetNonBlockingTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(&WallpaperPrivateGetThumbnailFunction::Get,
                                this, thumbnail_path));
  // WallpaperPrivateGetThumbnailFunction::Get will respond on UI thread
  // asynchronously.
  return RespondLater();
}

void WallpaperPrivateGetThumbnailFunction::Failure(
    const std::string& file_name) {
  Respond(Error(base::StringPrintf(
      "Failed to access wallpaper thumbnails for %s.", file_name.c_str())));
}

void WallpaperPrivateGetThumbnailFunction::FileNotLoaded() {
  // TODO(https://crbug.com/829657): This should fail instead of succeeding.
  Respond(NoArguments());
}

void WallpaperPrivateGetThumbnailFunction::FileLoaded(
    const std::string& data) {
  Respond(
      OneArgument(Value::CreateWithCopiedBuffer(data.c_str(), data.size())));
}

void WallpaperPrivateGetThumbnailFunction::Get(const base::FilePath& path) {
  WallpaperFunctionBase::AssertCalledOnWallpaperSequence(
      WallpaperFunctionBase::GetNonBlockingTaskRunner());
  std::string data;
  if (GetData(path, &data)) {
    if (data.empty()) {
      BrowserThread::PostTask(
          BrowserThread::UI, FROM_HERE,
          base::BindOnce(&WallpaperPrivateGetThumbnailFunction::FileNotLoaded,
                         this));
    } else {
      BrowserThread::PostTask(
          BrowserThread::UI, FROM_HERE,
          base::BindOnce(&WallpaperPrivateGetThumbnailFunction::FileLoaded,
                         this, data));
    }
  } else {
    BrowserThread::PostTask(
        BrowserThread::UI, FROM_HERE,
        base::BindOnce(&WallpaperPrivateGetThumbnailFunction::Failure, this,
                       path.BaseName().value()));
  }
}

WallpaperPrivateSaveThumbnailFunction::WallpaperPrivateSaveThumbnailFunction() {
}

WallpaperPrivateSaveThumbnailFunction::
    ~WallpaperPrivateSaveThumbnailFunction() {}

ExtensionFunction::ResponseAction WallpaperPrivateSaveThumbnailFunction::Run() {
  std::unique_ptr<save_thumbnail::Params> params(
      save_thumbnail::Params::Create(*args_));
  EXTENSION_FUNCTION_VALIDATE(params);

  WallpaperFunctionBase::GetNonBlockingTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&WallpaperPrivateSaveThumbnailFunction::Save, this,
                     params->data, GURL(params->url).ExtractFileName()));
  // WallpaperPrivateSaveThumbnailFunction::Save will repsond on UI thread
  // asynchronously.
  return RespondLater();
}

void WallpaperPrivateSaveThumbnailFunction::Failure(
    const std::string& file_name) {
  Respond(Error(base::StringPrintf("Failed to create/write thumbnail of %s.",
                                   file_name.c_str())));
}

void WallpaperPrivateSaveThumbnailFunction::Success() {
  Respond(NoArguments());
}

void WallpaperPrivateSaveThumbnailFunction::Save(const std::vector<char>& data,
                                                 const std::string& file_name) {
  WallpaperFunctionBase::AssertCalledOnWallpaperSequence(
      WallpaperFunctionBase::GetNonBlockingTaskRunner());
  if (SaveData(chrome::DIR_CHROMEOS_WALLPAPER_THUMBNAILS, file_name, data)) {
    BrowserThread::PostTask(
        BrowserThread::UI, FROM_HERE,
        base::BindOnce(&WallpaperPrivateSaveThumbnailFunction::Success, this));
  } else {
    BrowserThread::PostTask(
        BrowserThread::UI, FROM_HERE,
        base::BindOnce(&WallpaperPrivateSaveThumbnailFunction::Failure, this,
                       file_name));
  }
}

WallpaperPrivateGetOfflineWallpaperListFunction::
    WallpaperPrivateGetOfflineWallpaperListFunction() {
}

WallpaperPrivateGetOfflineWallpaperListFunction::
    ~WallpaperPrivateGetOfflineWallpaperListFunction() {
}

ExtensionFunction::ResponseAction
WallpaperPrivateGetOfflineWallpaperListFunction::Run() {
  WallpaperControllerClient::Get()->GetOfflineWallpaperList(
      base::BindOnce(&WallpaperPrivateGetOfflineWallpaperListFunction::
                         OnOfflineWallpaperListReturned,
                     this));
  return RespondLater();
}

void WallpaperPrivateGetOfflineWallpaperListFunction::
    OnOfflineWallpaperListReturned(const std::vector<std::string>& file_names) {
  auto results = std::make_unique<base::ListValue>();
  results->AppendStrings(file_names);
  Respond(OneArgument(std::move(results)));
}

ExtensionFunction::ResponseAction
WallpaperPrivateRecordWallpaperUMAFunction::Run() {
  std::unique_ptr<record_wallpaper_uma::Params> params(
      record_wallpaper_uma::Params::Create(*args_));
  EXTENSION_FUNCTION_VALIDATE(params);

  ash::WallpaperType source = getWallpaperType(params->source);
  UMA_HISTOGRAM_ENUMERATION("Ash.Wallpaper.Source", source,
                            ash::WALLPAPER_TYPE_COUNT);
  return RespondNow(NoArguments());
}

WallpaperPrivateGetCollectionsInfoFunction::
    WallpaperPrivateGetCollectionsInfoFunction() = default;

WallpaperPrivateGetCollectionsInfoFunction::
    ~WallpaperPrivateGetCollectionsInfoFunction() = default;

ExtensionFunction::ResponseAction
WallpaperPrivateGetCollectionsInfoFunction::Run() {
  collection_info_fetcher_ =
      std::make_unique<backdrop_wallpaper_handlers::CollectionInfoFetcher>();
  collection_info_fetcher_->Start(base::BindOnce(
      &WallpaperPrivateGetCollectionsInfoFunction::OnCollectionsInfoFetched,
      this));
  return RespondLater();
}

void WallpaperPrivateGetCollectionsInfoFunction::OnCollectionsInfoFetched(
    bool success,
    const std::vector<extensions::api::wallpaper_private::CollectionInfo>&
        collections_info_list) {
  if (!success) {
    Respond(Error("Collection names are not available."));
    return;
  }
  Respond(ArgumentList(
      get_collections_info::Results::Create(collections_info_list)));
}

WallpaperPrivateGetImagesInfoFunction::WallpaperPrivateGetImagesInfoFunction() =
    default;

WallpaperPrivateGetImagesInfoFunction::
    ~WallpaperPrivateGetImagesInfoFunction() = default;

ExtensionFunction::ResponseAction WallpaperPrivateGetImagesInfoFunction::Run() {
  std::unique_ptr<get_images_info::Params> params(
      get_images_info::Params::Create(*args_));
  EXTENSION_FUNCTION_VALIDATE(params);

  image_info_fetcher_ =
      std::make_unique<backdrop_wallpaper_handlers::ImageInfoFetcher>(
          params->collection_id);
  image_info_fetcher_->Start(base::BindOnce(
      &WallpaperPrivateGetImagesInfoFunction::OnImagesInfoFetched, this));
  return RespondLater();
}

void WallpaperPrivateGetImagesInfoFunction::OnImagesInfoFetched(
    bool success,
    const std::vector<extensions::api::wallpaper_private::ImageInfo>&
        images_info_list) {
  if (!success) {
    Respond(Error("Images info is not available."));
    return;
  }
  Respond(ArgumentList(get_images_info::Results::Create(images_info_list)));
}

WallpaperPrivateGetLocalImagePathsFunction::
    WallpaperPrivateGetLocalImagePathsFunction() = default;

WallpaperPrivateGetLocalImagePathsFunction::
    ~WallpaperPrivateGetLocalImagePathsFunction() = default;

ExtensionFunction::ResponseAction
WallpaperPrivateGetLocalImagePathsFunction::Run() {
  base::FilePath path = file_manager::util::GetDownloadsFolderForProfile(
      Profile::FromBrowserContext(browser_context()));
  base::PostTaskAndReplyWithResult(
      WallpaperFunctionBase::GetNonBlockingTaskRunner(), FROM_HERE,
      base::BindOnce(&GetImagePaths, path),
      base::BindOnce(
          &WallpaperPrivateGetLocalImagePathsFunction::OnGetImagePathsComplete,
          this));
  return RespondLater();
}

void WallpaperPrivateGetLocalImagePathsFunction::OnGetImagePathsComplete(
    const std::vector<std::string>& image_paths) {
  Respond(ArgumentList(get_local_image_paths::Results::Create(image_paths)));
}

WallpaperPrivateGetLocalImageDataFunction::
    WallpaperPrivateGetLocalImageDataFunction() = default;

WallpaperPrivateGetLocalImageDataFunction::
    ~WallpaperPrivateGetLocalImageDataFunction() = default;

ExtensionFunction::ResponseAction
WallpaperPrivateGetLocalImageDataFunction::Run() {
  std::unique_ptr<get_local_image_data::Params> params(
      get_local_image_data::Params::Create(*args_));
  EXTENSION_FUNCTION_VALIDATE(params);

  // TODO(crbug.com/811564): Create file backed blob instead.
  auto image_data = std::make_unique<std::string>();
  std::string* image_data_ptr = image_data.get();
  base::PostTaskAndReplyWithResult(
      WallpaperFunctionBase::GetNonBlockingTaskRunner(), FROM_HERE,
      base::BindOnce(&base::ReadFileToString,
                     base::FilePath(params->image_path), image_data_ptr),
      base::BindOnce(
          &WallpaperPrivateGetLocalImageDataFunction::OnReadImageDataComplete,
          this, std::move(image_data)));

  return RespondLater();
}

void WallpaperPrivateGetLocalImageDataFunction::OnReadImageDataComplete(
    std::unique_ptr<std::string> image_data,
    bool success) {
  if (!success) {
    Respond(Error("Reading image data failed."));
    return;
  }

  Respond(ArgumentList(get_local_image_data::Results::Create(
      std::vector<char>(image_data->begin(), image_data->end()))));
}

WallpaperPrivateConfirmPreviewWallpaperFunction::
    WallpaperPrivateConfirmPreviewWallpaperFunction() = default;

WallpaperPrivateConfirmPreviewWallpaperFunction::
    ~WallpaperPrivateConfirmPreviewWallpaperFunction() = default;

ExtensionFunction::ResponseAction
WallpaperPrivateConfirmPreviewWallpaperFunction::Run() {
  WallpaperControllerClient::Get()->ConfirmPreviewWallpaper();
  return RespondNow(NoArguments());
}

WallpaperPrivateCancelPreviewWallpaperFunction::
    WallpaperPrivateCancelPreviewWallpaperFunction() = default;

WallpaperPrivateCancelPreviewWallpaperFunction::
    ~WallpaperPrivateCancelPreviewWallpaperFunction() = default;

ExtensionFunction::ResponseAction
WallpaperPrivateCancelPreviewWallpaperFunction::Run() {
  WallpaperControllerClient::Get()->CancelPreviewWallpaper();
  return RespondNow(NoArguments());
}

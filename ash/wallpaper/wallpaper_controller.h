// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_WALLPAPER_WALLPAPER_CONTROLLER_H_
#define ASH_WALLPAPER_WALLPAPER_CONTROLLER_H_

#include <memory>

#include "ash/ash_export.h"
#include "ash/display/window_tree_host_manager.h"
#include "ash/public/cpp/wallpaper_types.h"
#include "ash/public/interfaces/wallpaper.mojom.h"
#include "ash/session/session_observer.h"
#include "ash/shell_observer.h"
#include "ash/wallpaper/wallpaper_info.h"
#include "ash/wallpaper/wallpaper_utils/wallpaper_color_calculator_observer.h"
#include "ash/wallpaper/wallpaper_utils/wallpaper_resizer_observer.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/observer_list.h"
#include "base/timer/timer.h"
#include "components/user_manager/user_type.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr_set.h"
#include "ui/compositor/compositor_lock.h"
#include "ui/gfx/image/image_skia.h"

class PrefRegistrySimple;

namespace base {
class SequencedTaskRunner;
}  // namespace base

namespace color_utils {
struct ColorProfile;
}  // namespace color_utils

namespace ash {

class WallpaperColorCalculator;
class WallpaperControllerObserver;
class WallpaperResizer;
class WallpaperWindowStateManager;

// The |CustomWallpaperElement| contains |first| the path of the image which
// is currently being loaded and or in progress of being loaded and |second|
// the image itself.
using CustomWallpaperElement = std::pair<base::FilePath, gfx::ImageSkia>;
using CustomWallpaperMap = std::map<AccountId, CustomWallpaperElement>;

using LoadedCallback = base::Callback<void(const gfx::ImageSkia& image)>;

// Controls the desktop background wallpaper:
//   - Sets a wallpaper image and layout;
//   - Handles display change (add/remove display, configuration change etc);
//   - Calculates prominent colors.
//   - Move wallpaper to locked container(s) when session state is not ACTIVE to
//     hide the user desktop and move it to unlocked container when session
//     state is ACTIVE;
class ASH_EXPORT WallpaperController : public mojom::WallpaperController,
                                       public WindowTreeHostManager::Observer,
                                       public ShellObserver,
                                       public WallpaperResizerObserver,
                                       public WallpaperColorCalculatorObserver,
                                       public SessionObserver,
                                       public ui::CompositorLockClient {
 public:
  enum WallpaperMode { WALLPAPER_NONE, WALLPAPER_IMAGE };

  enum WallpaperResolution {
    WALLPAPER_RESOLUTION_LARGE,
    WALLPAPER_RESOLUTION_SMALL
  };

  // Directory names of custom wallpapers.
  static const char kSmallWallpaperSubDir[];
  static const char kLargeWallpaperSubDir[];
  static const char kOriginalWallpaperSubDir[];
  static const char kThumbnailWallpaperSubDir[];

  // File path suffices of resized small or large wallpaper.
  static const char kSmallWallpaperSuffix[];
  static const char kLargeWallpaperSuffix[];

  // The width and height of small/large resolution wallpaper. When screen size
  // is smaller than |kSmallWallpaperMaxWidth| and |kSmallWallpaperMaxHeight|,
  // the small resolution wallpaper should be used. Otherwise, use the large
  // resolution wallpaper.
  static const int kSmallWallpaperMaxWidth;
  static const int kSmallWallpaperMaxHeight;
  static const int kLargeWallpaperMaxWidth;
  static const int kLargeWallpaperMaxHeight;

  // The color of the wallpaper if no other wallpaper images are available.
  static const SkColor kDefaultWallpaperColor;

  WallpaperController();
  ~WallpaperController() override;

  static void RegisterLocalStatePrefs(PrefRegistrySimple* registry);

  // Returns the maximum size of all displays combined in native
  // resolutions.  Note that this isn't the bounds of the display who
  // has maximum resolutions. Instead, this returns the size of the
  // maximum width of all displays, and the maximum height of all displays.
  static gfx::Size GetMaxDisplaySizeInNative();

  // Returns the appropriate wallpaper resolution for all root windows.
  static WallpaperResolution GetAppropriateResolution();

  // Returns the path of the online wallpaper corresponding to |url| and
  // |resolution|.
  static base::FilePath GetOnlineWallpaperPath(const GURL& url,
                                               WallpaperResolution resolution);

  // Returns wallpaper subdirectory name for current resolution.
  static std::string GetCustomWallpaperSubdirForCurrentResolution();

  // Returns custom wallpaper path. Appends |sub_dir|, |wallpaper_files_id| and
  // |file_name| to custom wallpaper directory.
  static base::FilePath GetCustomWallpaperPath(
      const std::string& sub_dir,
      const std::string& wallpaper_files_id,
      const std::string& file_name);

  // Returns custom wallpaper directory by appending corresponding |sub_dir|.
  static base::FilePath GetCustomWallpaperDir(const std::string& sub_dir);

  // Resizes |image| to a resolution which is nearest to |preferred_width| and
  // |preferred_height| while respecting the |layout| choice and saves the
  // resized wallpaper to |path|. |output_skia| is optional (may be
  // null). Returns true on success.
  static bool ResizeAndSaveWallpaper(const gfx::ImageSkia& image,
                                     const base::FilePath& path,
                                     WallpaperLayout layout,
                                     int preferred_width,
                                     int preferred_height,
                                     gfx::ImageSkia* output_skia);

  // Gets |account_id|'s custom wallpaper at |wallpaper_path|. Falls back to the
  // original custom wallpaper. When |show_wallpaper| is true, shows the
  // wallpaper immediately. Must run on wallpaper sequenced worker thread.
  static void SetWallpaperFromPath(
      const AccountId& account_id,
      const user_manager::UserType& user_type,
      const WallpaperInfo& info,
      const base::FilePath& wallpaper_path,
      bool show_wallpaper,
      const scoped_refptr<base::SingleThreadTaskRunner>& reply_task_runner,
      base::WeakPtr<WallpaperController> weak_ptr);

  // Creates a 1x1 solid color image to be used as the backup default wallpaper.
  static gfx::ImageSkia CreateSolidColorWallpaper();

  // TODO(crbug.com/776464): All the static |*ForTesting| functions should be
  // moved to the anonymous namespace of |WallpaperControllerTest|.
  //
  // Creates compressed JPEG image of solid color. Result bytes are written to
  // |output|. Returns true if gfx::JPEGCodec::Encode() succeeds.
  static bool CreateJPEGImageForTesting(int width,
                                        int height,
                                        SkColor color,
                                        std::vector<unsigned char>* output);

  // Writes a JPEG image of the specified size and color to |path|. Returns true
  // on success.
  static bool WriteJPEGFileForTesting(const base::FilePath& path,
                                      int width,
                                      int height,
                                      SkColor color);

  // Binds the mojom::WallpaperController interface request to this object.
  void BindRequest(mojom::WallpaperControllerRequest request);

  // Add/Remove observers.
  void AddObserver(WallpaperControllerObserver* observer);
  void RemoveObserver(WallpaperControllerObserver* observer);

  // Returns the prominent color based on |color_profile|.
  SkColor GetProminentColor(color_utils::ColorProfile color_profile) const;

  // Returns current image on the wallpaper, or an empty image if there's no
  // wallpaper.
  gfx::ImageSkia GetWallpaper() const;

  // Returns the original image id of the wallpaper before resizing, or 0 if
  // there's no wallpaper.
  uint32_t GetWallpaperOriginalImageId() const;

  // Returns the layout of the current wallpaper, or an invalid value if there's
  // no wallpaper.
  WallpaperLayout GetWallpaperLayout() const;

  // Returns the type of the current wallpaper, or an invalid value if there's
  // no wallpaper.
  WallpaperType GetWallpaperType() const;

  base::TimeDelta animation_duration() const { return animation_duration_; }

  // Returns true if the slower initial animation should be shown (as opposed to
  // the faster animation that's used e.g. when switching between different
  // wallpapers at login screen).
  bool ShouldShowInitialAnimation();

  // Notifies the controller that the wallpaper animation has finished.
  void OnWallpaperAnimationFinished();

  // Returns true if the active user is allowed to open the wallpaper picker.
  bool CanOpenWallpaperPicker();

  // Shows the wallpaper and alerts observers of changes. Does not show the
  // image if |preview_mode| is false and the current wallpaper is still being
  // previewed. See comments for |confirm_preview_wallpaper_callback_|.
  void ShowWallpaperImage(const gfx::ImageSkia& image,
                          WallpaperInfo info,
                          bool preview_mode);

  // Implementation of |SetDefaultWallpaper|. Sets wallpaper to default if
  // |show_wallpaper| is true. Otherwise just save the defaut wallpaper to
  // cache. |user_type| is the type of the user initiating the wallpaper
  // request; may be different from the active user.
  void SetDefaultWallpaperImpl(const AccountId& account_id,
                               const user_manager::UserType& user_type,
                               bool show_wallpaper);

  // Returns whether a wallpaper policy is enforced for |account_id| (not
  // including device policy).
  bool IsPolicyControlled(const AccountId& account_id, bool is_ephemeral) const;

  // When kiosk app is running or policy is enforced, setting a user wallpaper
  // is not allowed.
  bool CanSetUserWallpaper(const AccountId& account_id,
                           bool is_ephemeral) const;

  // Prepares wallpaper to lock screen transition. Will apply blur if
  // |locking| is true and remove it otherwise.
  void PrepareWallpaperForLockScreenChange(bool locking);

  // WindowTreeHostManager::Observer:
  void OnDisplayConfigurationChanged() override;

  // ShellObserver:
  void OnRootWindowAdded(aura::Window* root_window) override;
  void OnLocalStatePrefServiceInitialized(PrefService* pref_service) override;

  // SessionObserver:
  void OnSessionStateChanged(session_manager::SessionState state) override;

  // Returns true if the specified wallpaper is already stored in
  // |current_wallpaper_|. If |compare_layouts| is false, layout is ignored.
  bool WallpaperIsAlreadyLoaded(const gfx::ImageSkia& image,
                                bool compare_layouts,
                                WallpaperLayout layout) const;

  // Reads image from |file_path| on disk, and calls |OnWallpaperDataRead|
  // with the result of |ReadFileToString|.
  void ReadAndDecodeWallpaper(
      LoadedCallback callback,
      scoped_refptr<base::SequencedTaskRunner> task_runner,
      const base::FilePath& file_path);

  void set_wallpaper_reload_delay_for_test(int value) {
    wallpaper_reload_delay_ = value;
  }

  // Wallpaper should be dimmed for login, lock, OOBE and add user screens.
  bool ShouldApplyDimming() const;

  // Returns whether blur is enabled for login, lock, OOBE and add user screens.
  // See crbug.com/775591.
  bool IsBlurEnabled() const;

  // Returns whether the current wallpaper is blurred.
  bool IsWallpaperBlurred() const { return is_wallpaper_blurred_; }

  // Sets wallpaper info for |account_id| and saves it to local state if
  // |is_ephemeral| is false. Returns false if it fails (which happens if local
  // state is not available).
  bool SetUserWallpaperInfo(const AccountId& account_id,
                            const WallpaperInfo& info,
                            bool is_ephemeral);

  // Gets wallpaper info of |account_id| from local state, or memory if
  // |is_ephemeral| is true. Returns false if wallpaper info is not found.
  bool GetUserWallpaperInfo(const AccountId& account_id,
                            WallpaperInfo* info,
                            bool is_ephemeral) const;

  // Initializes wallpaper info for the user to default and saves it to local
  // state if |is_ephemeral| is false. Returns false if initialization fails.
  bool InitializeUserWallpaperInfo(const AccountId& account_id,
                                   bool is_ephemeral);

  // Gets encoded wallpaper from cache. Returns true if success.
  bool GetWallpaperFromCache(const AccountId& account_id,
                             gfx::ImageSkia* image);

  // Gets path of encoded wallpaper from cache. Returns true if success.
  bool GetPathFromCache(const AccountId& account_id, base::FilePath* path);

  // Returns true if device wallpaper policy is in effect and we are at the
  // login screen right now.
  bool ShouldSetDevicePolicyWallpaper() const;

  // mojom::WallpaperController:
  void Init(mojom::WallpaperControllerClientPtr client,
            const base::FilePath& user_data_path,
            const base::FilePath& chromeos_wallpapers_path,
            const base::FilePath& chromeos_custom_wallpapers_path,
            const base::FilePath& device_policy_wallpaper_path,
            bool is_device_wallpaper_policy_enforced) override;
  void SetCustomWallpaper(mojom::WallpaperUserInfoPtr user_info,
                          const std::string& wallpaper_files_id,
                          const std::string& file_name,
                          WallpaperLayout layout,
                          const gfx::ImageSkia& image,
                          bool preview_mode) override;
  void SetOnlineWallpaperIfExists(
      mojom::WallpaperUserInfoPtr user_info,
      const GURL& url,
      WallpaperLayout layout,
      bool preview_mode,
      SetOnlineWallpaperIfExistsCallback callback) override;
  void SetOnlineWallpaperFromData(mojom::WallpaperUserInfoPtr user_info,
                                  const std::string& image_data,
                                  const GURL& url,
                                  WallpaperLayout layout,
                                  bool preview_mode) override;
  void SetDefaultWallpaper(mojom::WallpaperUserInfoPtr user_info,
                           const std::string& wallpaper_files_id,
                           bool show_wallpaper) override;
  void SetCustomizedDefaultWallpaperPaths(
      const base::FilePath& customized_default_small_path,
      const base::FilePath& customized_default_large_path) override;
  void SetPolicyWallpaper(mojom::WallpaperUserInfoPtr user_info,
                          const std::string& wallpaper_files_id,
                          const std::string& data) override;
  void SetDeviceWallpaperPolicyEnforced(bool enforced) override;
  void SetThirdPartyWallpaper(mojom::WallpaperUserInfoPtr user_info,
                              const std::string& wallpaper_files_id,
                              const std::string& file_name,
                              WallpaperLayout layout,
                              const gfx::ImageSkia& image,
                              SetThirdPartyWallpaperCallback callback) override;
  void ConfirmPreviewWallpaper() override;
  void CancelPreviewWallpaper() override;
  void UpdateCustomWallpaperLayout(mojom::WallpaperUserInfoPtr user_info,
                                   WallpaperLayout layout) override;
  void ShowUserWallpaper(mojom::WallpaperUserInfoPtr user_info) override;
  void ShowSigninWallpaper() override;
  void RemoveUserWallpaper(mojom::WallpaperUserInfoPtr user_info,
                           const std::string& wallpaper_files_id) override;
  void RemovePolicyWallpaper(mojom::WallpaperUserInfoPtr user_info,
                             const std::string& wallpaper_files_id) override;
  void GetOfflineWallpaperList(
      GetOfflineWallpaperListCallback callback) override;
  void SetAnimationDuration(base::TimeDelta animation_duration) override;
  void OpenWallpaperPickerIfAllowed() override;
  void MinimizeInactiveWindows(const std::string& user_id_hash) override;
  void RestoreMinimizedWindows(const std::string& user_id_hash) override;
  void AddObserver(mojom::WallpaperObserverAssociatedPtrInfo observer) override;
  void GetWallpaperImage(GetWallpaperImageCallback callback) override;
  void GetWallpaperColors(GetWallpaperColorsCallback callback) override;
  void IsWallpaperBlurred(IsWallpaperBlurredCallback callback) override;
  void IsActiveUserWallpaperControlledByPolicy(
      IsActiveUserWallpaperControlledByPolicyCallback callback) override;
  void GetActiveUserWallpaperLocation(
      GetActiveUserWallpaperLocationCallback callback) override;
  void ShouldShowWallpaperSetting(
      ShouldShowWallpaperSettingCallback callback) override;

  // WallpaperResizerObserver:
  void OnWallpaperResized() override;

  // WallpaperColorCalculatorObserver:
  void OnColorCalculationComplete() override;

  // Sets dummy values for wallpaper directories.
  void InitializePathsForTesting(
      const base::FilePath& user_data_path,
      const base::FilePath& chromeos_wallpapers_path,
      const base::FilePath& chromeos_custom_wallpapers_path);

  // Shows a default wallpaper for testing, without changing users' wallpaper
  // info.
  void ShowDefaultWallpaperForTesting();

  // Creates an empty wallpaper. Some tests require a wallpaper widget is ready
  // when running. However, the wallpaper widgets are created asynchronously. If
  // loading a real wallpaper, there are cases that these tests crash because
  // the required widget is not ready. This function synchronously creates an
  // empty widget for those tests to prevent crashes.
  void CreateEmptyWallpaperForTesting();

  // Sets a test client interface with empty file paths.
  void SetClientForTesting(mojom::WallpaperControllerClientPtr client);

  // Flushes the mojo message pipe to chrome.
  void FlushForTesting();

 private:
  FRIEND_TEST_ALL_PREFIXES(WallpaperControllerTest, BasicReparenting);
  FRIEND_TEST_ALL_PREFIXES(WallpaperControllerTest,
                           WallpaperMovementDuringUnlock);
  friend class WallpaperControllerTest;

  // Cached default wallpaper image and file path. The file path can be used to
  // check if the image is outdated (i.e. when there's a new default wallpaper).
  struct CachedDefaultWallpaper {
    gfx::ImageSkia image;
    base::FilePath file_path;
  };

  struct OnlineWallpaperParams {
    AccountId account_id;
    bool is_ephemeral;
    GURL url;
    WallpaperLayout layout;
    bool preview_mode;
  };

  // Creates a WallpaperWidgetController for |root_window|.
  void InstallDesktopController(aura::Window* root_window);

  // Creates a WallpaperWidgetController for all root windows.
  void InstallDesktopControllerForAllWindows();

  // Moves the wallpaper to the specified container across all root windows.
  // Returns true if a wallpaper moved.
  bool ReparentWallpaper(int container);

  // Returns the wallpaper container id for unlocked and locked states.
  int GetWallpaperContainerId(bool locked);

  // Removes |account_id|'s wallpaper info and color cache if it exists.
  void RemoveUserWallpaperInfo(const AccountId& account_id, bool is_ephemeral);

  // Implementation of |RemoveUserWallpaper|, which deletes |account_id|'s
  // custom wallpapers and directories.
  void RemoveUserWallpaperImpl(const AccountId& account_id,
                               const std::string& wallpaper_files_id);

  // Used as the callback of checking ONLINE wallpaper existence in
  // |SetOnlineWallpaperIfExists|. Initiates reading and decoding the wallpaper
  // if |file_path| is not empty.
  void SetOnlineWallpaperFromPath(SetOnlineWallpaperIfExistsCallback callback,
                                  const OnlineWallpaperParams& params,
                                  const base::FilePath& file_path);

  // Used as the callback of decoding wallpapers of type ONLINE. Saves the image
  // to local file if |save_file| is true, and shows the wallpaper immediately
  // if |params.account_id| is the active user.
  void OnOnlineWallpaperDecoded(const OnlineWallpaperParams& params,
                                bool save_file,
                                const gfx::ImageSkia& image);

  // Implementation of |SetOnlineWallpaper|. Shows the wallpaper on screen if
  // |show_wallpaper| is true.
  void SetOnlineWallpaperImpl(const OnlineWallpaperParams& params,
                              const gfx::ImageSkia& image,
                              bool show_wallpaper);

  // Decodes |account_id|'s wallpaper. Shows the decoded wallpaper if
  // |show_wallpaper| is true.
  void SetWallpaperFromInfo(const AccountId& account_id,
                            const user_manager::UserType& user_type,
                            const WallpaperInfo& info,
                            bool show_wallpaper);

  // Used as the callback of default wallpaper decoding. Sets default wallpaper
  // to be the decoded image, and shows the wallpaper now if |show_wallpaper|
  // is true.
  void OnDefaultWallpaperDecoded(const base::FilePath& path,
                                 WallpaperLayout layout,
                                 bool show_wallpaper,
                                 const gfx::ImageSkia& image);

  // Saves |image| to disk if |user_info->is_ephemeral| is false, or if it is a
  // policy wallpaper for public accounts. Shows the wallpaper immediately if
  // |show_wallpaper| is true, otherwise only sets the wallpaper info and
  // updates the cache.
  void SaveAndSetWallpaper(mojom::WallpaperUserInfoPtr user_info,
                           const std::string& wallpaper_files_id,
                           const std::string& file_name,
                           WallpaperType type,
                           WallpaperLayout layout,
                           bool show_wallpaper,
                           const gfx::ImageSkia& image);

  // A wrapper of |ReadAndDecodeWallpaper| used in |SetWallpaperFromPath|.
  void StartDecodeFromPath(const AccountId& account_id,
                           const user_manager::UserType& user_type,
                           const base::FilePath& wallpaper_path,
                           const WallpaperInfo& info,
                           bool show_wallpaper);

  // Used as the callback of wallpaper decoding. (Wallpapers of type ONLINE,
  // DEFAULT and DEVICE should use their corresponding |*Decoded|, and all other
  // types should use this.) Shows the wallpaper immediately if |show_wallpaper|
  // is true. Otherwise, only updates the cache.
  void OnWallpaperDecoded(const AccountId& account_id,
                          const user_manager::UserType& user_type,
                          const base::FilePath& path,
                          const WallpaperInfo& info,
                          bool show_wallpaper,
                          const gfx::ImageSkia& image);

  // Reloads the current wallpaper. It may change the wallpaper size based on
  // the current display's resolution. If |clear_cache| is true, all wallpaper
  // cache should be cleared. This is required when the display's native
  // resolution changes to a larger resolution (e.g. when hooked up a large
  // external display) and we need to load a larger resolution wallpaper for the
  // display. All the previous small resolution wallpaper cache should be
  // cleared.
  void ReloadWallpaper(bool clear_cache);

  // Sets |prominent_colors_| and notifies the observers if there is a change.
  void SetProminentColors(const std::vector<SkColor>& prominent_colors);

  // Calculates prominent colors based on the wallpaper image and notifies
  // |observers_| of the value, either synchronously or asynchronously. In some
  // cases the wallpaper image will not actually be processed (e.g. user isn't
  // logged in, feature isn't enabled).
  // If an existing calculation is in progress it is destroyed.
  void CalculateWallpaperColors();

  // Returns false when the color extraction algorithm shouldn't be run based on
  // system state (e.g. wallpaper image, SessionState, etc.).
  bool ShouldCalculateColors() const;

  // Caches color calculation results in the local state pref service.
  void CacheProminentColors(const std::vector<SkColor>& colors,
                            const std::string& current_location);

  // Gets prominent color cache from the local state pref service. Returns an
  // empty value if the cache is not available.
  base::Optional<std::vector<SkColor>> GetCachedColors(
      const std::string& current_location);

  // Move all wallpaper widgets to the locked container.
  // Returns true if the wallpaper moved.
  bool MoveToLockedContainer();

  // Move all wallpaper widgets to unlocked container.
  // Returns true if the wallpaper moved.
  bool MoveToUnlockedContainer();

  // Returns whether the current wallpaper is set by device policy.
  bool IsDevicePolicyWallpaper() const;

  // Reads the device wallpaper file and sets it as the current wallpaper. Note
  // when it's called, it's guaranteed that ShouldSetDevicePolicyWallpaper()
  // should be true.
  void SetDevicePolicyWallpaper();

  // Called when the device policy controlled wallpaper has been decoded.
  void OnDevicePolicyWallpaperDecoded(const gfx::ImageSkia& image);

  // Implementation of |IsActiveUserWallpaperControlledByPolicy|.
  bool IsActiveUserWallpaperControlledByPolicyImpl() const;

  // Implementation of |GetActiveUserWallpaperLocation|.
  std::string GetActiveUserWallpaperLocationImpl() const;

  // Implementation of |ShouldShowWallpaperSetting|.
  bool ShouldShowWallpaperSettingImpl() const;

  // When wallpaper resizes, we can check which displays will be affected. For
  // simplicity, we only lock the compositor for the internal display.
  void GetInternalDisplayCompositorLock();

  // CompositorLockClient:
  void CompositorLockTimedOut() override;

  bool locked_;

  WallpaperMode wallpaper_mode_;

  // Client interface in chrome browser.
  mojom::WallpaperControllerClientPtr wallpaper_controller_client_;

  // Bindings for the WallpaperController interface.
  mojo::BindingSet<mojom::WallpaperController> bindings_;

  base::ObserverList<WallpaperControllerObserver> observers_;

  mojo::AssociatedInterfacePtrSet<mojom::WallpaperObserver> mojo_observers_;

  std::unique_ptr<WallpaperResizer> current_wallpaper_;

  // Asynchronous task to extract colors from the wallpaper.
  std::unique_ptr<WallpaperColorCalculator> color_calculator_;

  // Manages the states of the other windows when the wallpaper app window is
  // active.
  std::unique_ptr<WallpaperWindowStateManager> window_state_manager_;

  // The prominent colors extracted from the current wallpaper.
  // kInvalidWallpaperColor is used by default or if extracting colors fails.
  std::vector<SkColor> prominent_colors_;

  // Caches the color profiles that need to do wallpaper color extracting.
  const std::vector<color_utils::ColorProfile> color_profiles_;

  // The wallpaper info for ephemeral users, which is not stored to local state.
  // See |WallpaperUserInfo::is_ephemeral| for details.
  std::map<AccountId, WallpaperInfo> ephemeral_users_wallpaper_info_;

  // Cached user info of the current user.
  mojom::WallpaperUserInfoPtr current_user_;

  // Cached wallpapers of users.
  CustomWallpaperMap wallpaper_cache_map_;

  // Cached default wallpaper.
  CachedDefaultWallpaper cached_default_wallpaper_;

  // The paths of the customized default wallpapers, if they exist.
  base::FilePath customized_default_small_path_;
  base::FilePath customized_default_large_path_;

  gfx::Size current_max_display_size_;

  base::OneShotTimer timer_;

  int wallpaper_reload_delay_;

  bool is_wallpaper_blurred_ = false;

  // The wallpaper animation duration. An empty value disables the animation.
  base::TimeDelta animation_duration_;

  // Whether the device wallpaper policy is enforced on this device.
  bool is_device_wallpaper_policy_enforced_ = false;

  // Whether the current wallpaper (if any) is the first wallpaper since the
  // controller initialization. Empty wallpapers for testing don't count.
  bool is_first_wallpaper_ = false;

  scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner_;

  ScopedSessionObserver scoped_session_observer_;

  std::unique_ptr<ui::CompositorLock> compositor_lock_;

  // A non-empty value indicates the current wallpaper is in preview mode, which
  // expects either |ConfirmPreviewWallpaper| or |CancelPreviewWallpaper| to be
  // called to exit preview. In preview mode, other types of wallpaper requests
  // may still update wallpaper info for the user, but the preview wallpaper
  // cannot be replaced, except by another preview wallpaper.
  base::OnceClosure confirm_preview_wallpaper_callback_;

  // If true, use a solid color wallpaper as if it is the decoded image.
  bool bypass_decode_for_testing_ = false;

  // Tracks how many wallpapers have been set.
  int wallpaper_count_for_testing_ = 0;

  // The file paths of decoding requests that have been initiated. Must be a
  // list because more than one decoding requests may happen during a single
  // 'set wallpaper' request. (e.g. when a custom wallpaper decoding fails, a
  // default wallpaper decoding is initiated.)
  std::vector<base::FilePath> decode_requests_for_testing_;

  // PrefService provided by Shell::OnLocalStatePrefServiceInitialized.
  // Valid for the lifetime of ash::Shell which owns WallpaperController.
  // May be null during intialization or in tests.
  PrefService* local_state_ = nullptr;

  base::WeakPtrFactory<WallpaperController> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(WallpaperController);
};

}  // namespace ash

#endif  // ASH_WALLPAPER_WALLPAPER_CONTROLLER_H_

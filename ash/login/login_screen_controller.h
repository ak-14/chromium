// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_LOGIN_LOGIN_SCREEN_CONTROLLER_H_
#define ASH_LOGIN_LOGIN_SCREEN_CONTROLLER_H_

#include "ash/ash_export.h"
#include "ash/login/login_screen_controller_observer.h"
#include "ash/public/interfaces/login_screen.mojom.h"
#include "base/macros.h"
#include "base/observer_list.h"
#include "base/optional.h"
#include "mojo/public/cpp/bindings/binding_set.h"

class PrefRegistrySimple;

namespace ash {

class LoginDataDispatcher;

// LoginScreenController implements mojom::LoginScreen and wraps the
// mojom::LoginScreenClient interface. This lets a consumer of ash provide a
// LoginScreenClient, which we will dispatch to if one has been provided to us.
// This could send requests to LoginScreenClient and also handle requests from
// LoginScreenClient through mojo.
class ASH_EXPORT LoginScreenController : public mojom::LoginScreen {
 public:
  using OnShownCallback = base::OnceCallback<void(bool did_show)>;
  // Callback for authentication checks. |success| is nullopt if an
  // authentication check did not run, otherwise it is true/false if auth
  // succeeded/failed.
  using OnAuthenticateCallback =
      base::OnceCallback<void(base::Optional<bool> success)>;

  LoginScreenController();
  ~LoginScreenController() override;

  static void RegisterProfilePrefs(PrefRegistrySimple* registry, bool for_test);

  // Binds the mojom::LoginScreen interface to this object.
  void BindRequest(mojom::LoginScreenRequest request);

  // Hash the password and send AuthenticateUser request to LoginScreenClient.
  // LoginScreenClient (in the chrome process) will do the authentication and
  // request to show error messages in the screen if auth fails, or request to
  // clear errors if auth succeeds.
  void AuthenticateUser(const AccountId& account_id,
                        const std::string& password,
                        bool authenticated_by_pin,
                        OnAuthenticateCallback callback);
  void AttemptUnlock(const AccountId& account_id);
  void HardlockPod(const AccountId& account_id);
  void RecordClickOnLockIcon(const AccountId& account_id);
  void OnFocusPod(const AccountId& account_id);
  void OnNoPodFocused();
  void LoadWallpaper(const AccountId& account_id);
  void SignOutUser();
  void CancelAddUser();
  void LoginAsGuest();
  void OnMaxIncorrectPasswordAttempted(const AccountId& account_id);
  void FocusLockScreenApps(bool reverse);
  void ShowGaiaSignin();
  void OnRemoveUserWarningShown();
  void RemoveUser(const AccountId& account_id);
  void LaunchPublicSession(const AccountId& account_id,
                           const std::string& locale,
                           const std::string& input_method);

  // Add or remove an observer.
  void AddObserver(LoginScreenControllerObserver* observer);
  void RemoveObserver(LoginScreenControllerObserver* observer);

  // Enable or disable authentication for the debug overlay.
  enum class ForceFailAuth { kOff, kImmediate, kDelayed };
  void set_force_fail_auth_for_debug_overlay(ForceFailAuth force_fail) {
    force_fail_auth_for_debug_overlay_ = force_fail;
  }

  // mojom::LoginScreen:
  void SetClient(mojom::LoginScreenClientPtr client) override;
  void ShowLockScreen(ShowLockScreenCallback on_shown) override;
  void ShowLoginScreen(ShowLoginScreenCallback on_shown) override;
  void ShowErrorMessage(int32_t login_attempts,
                        const std::string& error_text,
                        const std::string& help_link_text,
                        int32_t help_topic_id) override;
  void ClearErrors() override;
  void ShowUserPodCustomIcon(const AccountId& account_id,
                             mojom::EasyUnlockIconOptionsPtr icon) override;
  void HideUserPodCustomIcon(const AccountId& account_id) override;
  void SetAuthType(const AccountId& account_id,
                   proximity_auth::mojom::AuthType auth_type,
                   const base::string16& initial_value) override;
  void LoadUsers(std::vector<mojom::LoginUserInfoPtr> users,
                 bool show_guest) override;
  void SetPinEnabledForUser(const AccountId& account_id,
                            bool is_enabled) override;
  void SetAvatarForUser(const AccountId& account_id,
                        mojom::UserAvatarPtr avatar) override;
  void HandleFocusLeavingLockScreenApps(bool reverse) override;
  void SetDevChannelInfo(const std::string& os_version_label_text,
                         const std::string& enterprise_info_text,
                         const std::string& bluetooth_name) override;
  void IsReadyForPassword(IsReadyForPasswordCallback callback) override;
  void SetPublicSessionDisplayName(const AccountId& account_id,
                                   const std::string& display_name) override;
  void SetPublicSessionLocales(const AccountId& account_id,
                               base::Value locales,
                               const std::string& default_locale,
                               bool show_advanced_view) override;

  // Flushes the mojo pipes - to be used in tests.
  void FlushForTesting();

 private:
  using PendingDoAuthenticateUser =
      base::OnceCallback<void(const std::string& system_salt)>;

  void DoAuthenticateUser(const AccountId& account_id,
                          const std::string& password,
                          bool authenticated_by_pin,
                          OnAuthenticateCallback callback,
                          const std::string& system_salt);
  void OnAuthenticateComplete(OnAuthenticateCallback callback, bool success);

  // Returns the active data dispatcher or nullptr if there is no lock screen.
  LoginDataDispatcher* DataDispatcher() const;

  // Common code that is called when the login/lock screen is shown.
  void OnShow();

  // Client interface in chrome browser. May be null in tests.
  mojom::LoginScreenClientPtr login_screen_client_;

  // Bindings for users of the LockScreen interface.
  mojo::BindingSet<mojom::LoginScreen> bindings_;

  // The current authentication stage. Used to get more verbose logging.
  enum class AuthenticationStage {
    kIdle,
    kGetSystemSalt,
    kDoAuthenticate,
    kUserCallback,
  };
  AuthenticationStage authentication_stage_ = AuthenticationStage::kIdle;

  base::ObserverList<LoginScreenControllerObserver> observers_;

  // If set to false, all auth requests will forcibly fail.
  ForceFailAuth force_fail_auth_for_debug_overlay_ = ForceFailAuth::kOff;

  base::WeakPtrFactory<LoginScreenController> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(LoginScreenController);
};

}  // namespace ash

#endif  // ASH_LOGIN_LOCK_SCREEN_CONTROLLER_H_

// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEBUI_SIGNIN_SIGNIN_CREATE_PROFILE_HANDLER_H_
#define CHROME_BROWSER_UI_WEBUI_SIGNIN_SIGNIN_CREATE_PROFILE_HANDLER_H_

#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/profiles/profile_attributes_storage.h"
#include "chrome/browser/profiles/profile_window.h"
#include "chrome/common/buildflags.h"
#include "content/public/browser/notification_observer.h"
#include "content/public/browser/notification_registrar.h"
#include "content/public/browser/web_ui_message_handler.h"
#include "google_apis/gaia/google_service_auth_error.h"

namespace base {
class DictionaryValue;
class ListValue;
}

// Handler for the 'create profile' page.
class SigninCreateProfileHandler : public content::WebUIMessageHandler,
                                   public content::NotificationObserver,
                                   public ProfileAttributesStorage::Observer {
 public:
  SigninCreateProfileHandler();
  ~SigninCreateProfileHandler() override;

  void GetLocalizedValues(base::DictionaryValue* localized_strings);

 protected:
  FRIEND_TEST_ALL_PREFIXES(SigninCreateProfileHandlerTest,
                           ReturnDefaultProfileNameAndIcons);
  FRIEND_TEST_ALL_PREFIXES(SigninCreateProfileHandlerTest,
                           ReturnSignedInProfiles);
  FRIEND_TEST_ALL_PREFIXES(SigninCreateProfileHandlerTest,
                           CreateProfile);
  FRIEND_TEST_ALL_PREFIXES(SigninCreateProfileHandlerTest,
                           CreateProfileWithForceSignin);

  // WebUIMessageHandler implementation.
  void RegisterMessages() override;

  // content::NotificationObserver implementation:
  void Observe(int type,
               const content::NotificationSource& source,
               const content::NotificationDetails& details) override;

  // ProfileAttributesStorage::Observer implementation:
  void OnProfileAuthInfoChanged(const base::FilePath& profile_path) override;

  // Represents the final profile creation status. It is used to map
  // the status to the javascript method to be called.
  enum ProfileCreationStatus {
    PROFILE_CREATION_SUCCESS,
    PROFILE_CREATION_ERROR,
  };

  // Represents the type of the in progress profile creation operation.
  // It is used to map the type of the profile creation operation to the
  // correct UMA metric name.
  enum ProfileCreationOperationType {
    NON_SUPERVISED_PROFILE_CREATION,
    NO_CREATION_IN_PROGRESS
  };

  // Callback for the "requestDefaultProfileIcons" message.
  // Sends the array of default profile icon URLs to WebUI.
  void RequestDefaultProfileIcons(const base::ListValue* args);

  // Sends an object to WebUI of the form: { "name": profileName } after
  // "requestDefaultProfileIcons" is fulfilled.
  void SendNewProfileDefaults();

  // Callback for the "requestSignedInProfiles" message.
  // Sends the email address of the signed-in user, or an empty string if the
  // user is not signed in.
  void RequestSignedInProfiles(const base::ListValue* args);

  // Asynchronously creates and initializes a new profile.
  // The arguments are as follows:
  //   0: name (string)
  //   1: icon (string)
  //   2: a flag stating whether we should create a profile desktop shortcut
  //      (optional, boolean)
  //   3: a flag stating whether the user should be supervised
  //      (optional, boolean)
  //   4: a string representing the supervised user ID.
  //   5: a string representing the custodian profile path.
  void CreateProfile(const base::ListValue* args);

  // If a local error occurs during profile creation, then show an appropriate
  // error message. However, if profile creation succeeded and the
  // profile being created/imported is a supervised user profile,
  // then proceed with the registration step. Otherwise, update the UI
  // as the final task after a new profile has been created.
  void OnProfileCreated(bool create_shortcut,
                        const std::string& supervised_user_id,
                        Profile* custodian_profile,
                        Profile* profile,
                        Profile::CreateStatus status);

  void HandleProfileCreationSuccess(bool create_shortcut,
                                    const std::string& supervised_user_id,
                                    Profile* custodian_profile,
                                    Profile* profile);

  // Creates desktop shortcut and updates the UI to indicate success
  // when creating a profile.
  void CreateShortcutAndShowSuccess(bool create_shortcut,
                                    Profile* custodian_profile,
                                    Profile* profile);

  // Opens a new window for |profile|.
  virtual void OpenNewWindowForProfile(Profile* profile,
                                       Profile::CreateStatus status);

  // Opens a new signin dialog for |profile|.
  virtual void OpenSigninDialogForProfile(Profile* profile);

  // This callback is run after a new browser (but not the window) has been
  // created for the new profile.
  void OnBrowserReadyCallback(Profile* profile, Profile::CreateStatus status);

  // Updates the UI to show an error when creating a profile.
  void ShowProfileCreationError(Profile* profile, const base::string16& error);

  // Records UMA histograms relevant to profile creation.
  void RecordProfileCreationMetrics(Profile::CreateStatus status);

  base::string16 GetProfileCreationErrorMessageLocal() const;

  base::Value GetWebUIListenerName(ProfileCreationStatus status) const;

  // Used to allow canceling a profile creation (particularly a supervised-user
  // registration) in progress. Set when profile creation is begun, and
  // cleared when all the callbacks have been run and creation is complete.
  base::FilePath profile_path_being_created_;

  // Used to track how long profile creation takes.
  base::TimeTicks profile_creation_start_time_;

  // Indicates the type of the in progress profile creation operation.
  // The value is only relevant while we are creating/importing a profile.
  ProfileCreationOperationType profile_creation_type_;

  // Asynchronously creates and initializes a new profile.
  virtual void DoCreateProfile(const base::string16& name,
                               const std::string& icon_url,
                               bool create_shortcut,
                               const std::string& supervised_user_id,
                               Profile* custodian_profile);

#if BUILDFLAG(ENABLE_SUPERVISED_USERS)
  // Cancels creation of a supervised-user profile currently in progress, as
  // indicated by profile_path_being_created_, removing the object and files
  // and canceling supervised-user registration. This is the handler for the
  // "cancelCreateProfile" message. |args| is not used.
  void HandleCancelProfileCreation(const base::ListValue* args);

  // Callback for the "switchToProfile" message. Opens a new window for the
  // profile. The profile file path is passed as a string argument.
  void SwitchToProfile(const base::ListValue* args);
#endif

  content::NotificationRegistrar registrar_;

  base::WeakPtrFactory<SigninCreateProfileHandler> weak_ptr_factory_;

 private:
  DISALLOW_COPY_AND_ASSIGN(SigninCreateProfileHandler);
};

#endif  // CHROME_BROWSER_UI_WEBUI_SIGNIN_SIGNIN_CREATE_PROFILE_HANDLER_H_

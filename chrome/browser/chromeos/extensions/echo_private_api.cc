// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/extensions/echo_private_api.h"

#include <string>
#include <utility>

#include "base/bind.h"
#include "base/files/file_util.h"
#include "base/location.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/time/time.h"
#include "base/values.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/chromeos/settings/cros_settings.h"
#include "chrome/browser/chromeos/ui/echo_dialog_view.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_navigator_params.h"
#include "chrome/common/extensions/api/echo_private.h"
#include "chrome/common/pref_names.h"
#include "chromeos/system/statistics_provider.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/pref_service.h"
#include "components/prefs/scoped_user_pref_update.h"
#include "content/public/browser/web_contents.h"
#include "extensions/browser/extension_file_task_runner.h"
#include "extensions/common/extension.h"

namespace echo_api = extensions::api::echo_private;

namespace {

// URL of "More info" link shown in echo dialog in GetUserConsent function.
const char kMoreInfoLink[] =
    "chrome-extension://honijodknafkokifofgiaalefdiedpko/main.html?"
    "answer=2677280";

}  // namespace

namespace chromeos {

namespace echo_offer {

void RegisterPrefs(PrefRegistrySimple* registry) {
  registry->RegisterDictionaryPref(prefs::kEchoCheckedOffers);
}

}  // namespace echo_offer

}  // namespace chromeos

EchoPrivateGetRegistrationCodeFunction::
    EchoPrivateGetRegistrationCodeFunction() {}

EchoPrivateGetRegistrationCodeFunction::
    ~EchoPrivateGetRegistrationCodeFunction() {}

ExtensionFunction::ResponseValue
EchoPrivateGetRegistrationCodeFunction::GetRegistrationCode(
    const std::string& type) {
  // Possible ECHO code type and corresponding key name in StatisticsProvider.
  const std::string kCouponType = "COUPON_CODE";
  const std::string kGroupType = "GROUP_CODE";

  chromeos::system::StatisticsProvider* provider =
      chromeos::system::StatisticsProvider::GetInstance();
  std::string result;
  if (type == kCouponType) {
    provider->GetMachineStatistic(chromeos::system::kOffersCouponCodeKey,
                                  &result);
  } else if (type == kGroupType) {
    provider->GetMachineStatistic(chromeos::system::kOffersGroupCodeKey,
                                  &result);
  }

  return ArgumentList(echo_api::GetRegistrationCode::Results::Create(result));
}

ExtensionFunction::ResponseAction
EchoPrivateGetRegistrationCodeFunction::Run() {
  std::unique_ptr<echo_api::GetRegistrationCode::Params> params =
      echo_api::GetRegistrationCode::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(params);
  return RespondNow(GetRegistrationCode(params->type));
}

EchoPrivateSetOfferInfoFunction::EchoPrivateSetOfferInfoFunction() {}

EchoPrivateSetOfferInfoFunction::~EchoPrivateSetOfferInfoFunction() {}

ExtensionFunction::ResponseAction EchoPrivateSetOfferInfoFunction::Run() {
  std::unique_ptr<echo_api::SetOfferInfo::Params> params =
      echo_api::SetOfferInfo::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(params);

  const std::string& service_id = params->id;
  std::unique_ptr<base::DictionaryValue> dict =
      params->offer_info.additional_properties.DeepCopyWithoutEmptyChildren();

  PrefService* local_state = g_browser_process->local_state();
  DictionaryPrefUpdate offer_update(local_state, prefs::kEchoCheckedOffers);
  offer_update->SetWithoutPathExpansion("echo." + service_id, std::move(dict));
  return RespondNow(NoArguments());
}

EchoPrivateGetOfferInfoFunction::EchoPrivateGetOfferInfoFunction() {}

EchoPrivateGetOfferInfoFunction::~EchoPrivateGetOfferInfoFunction() {}

ExtensionFunction::ResponseAction EchoPrivateGetOfferInfoFunction::Run() {
  std::unique_ptr<echo_api::GetOfferInfo::Params> params =
      echo_api::GetOfferInfo::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(params);

  const std::string& service_id = params->id;
  PrefService* local_state = g_browser_process->local_state();
  const base::DictionaryValue* offer_infos = local_state->
      GetDictionary(prefs::kEchoCheckedOffers);

  const base::DictionaryValue* offer_info = NULL;
  if (!offer_infos->GetDictionaryWithoutPathExpansion(
         "echo." + service_id, &offer_info)) {
    return RespondNow(Error("Not found"));
  }

  echo_api::GetOfferInfo::Results::Result result;
  result.additional_properties.MergeDictionary(offer_info);
  return RespondNow(
      ArgumentList(echo_api::GetOfferInfo::Results::Create(result)));
}

EchoPrivateGetOobeTimestampFunction::EchoPrivateGetOobeTimestampFunction() {
}

EchoPrivateGetOobeTimestampFunction::~EchoPrivateGetOobeTimestampFunction() {
}

bool EchoPrivateGetOobeTimestampFunction::RunAsync() {
  base::PostTaskAndReplyWithResult(
      extensions::GetExtensionFileTaskRunner().get(), FROM_HERE,
      base::Bind(
          &EchoPrivateGetOobeTimestampFunction::GetOobeTimestampOnFileSequence,
          this),
      base::Bind(&EchoPrivateGetOobeTimestampFunction::SendResponse, this));
  return true;
}

// Get the OOBE timestamp from file /home/chronos/.oobe_completed.
// The timestamp is used to determine when the user first activates the device.
// If we can get the timestamp info, return it as yyyy-mm-dd, otherwise, return
// an empty string.
bool EchoPrivateGetOobeTimestampFunction::GetOobeTimestampOnFileSequence() {
  DCHECK(
      extensions::GetExtensionFileTaskRunner()->RunsTasksInCurrentSequence());

  const char kOobeTimestampFile[] = "/home/chronos/.oobe_completed";
  std::string timestamp = "";
  base::File::Info fileInfo;
  if (base::GetFileInfo(base::FilePath(kOobeTimestampFile), &fileInfo)) {
    base::Time::Exploded ctime;
    fileInfo.creation_time.UTCExplode(&ctime);
    timestamp += base::StringPrintf("%u-%u-%u",
                                    ctime.year,
                                    ctime.month,
                                    ctime.day_of_month);
  }
  results_ = echo_api::GetOobeTimestamp::Results::Create(timestamp);
  return true;
}

EchoPrivateGetUserConsentFunction::EchoPrivateGetUserConsentFunction()
    : redeem_offers_allowed_(false) {
}

// static
scoped_refptr<EchoPrivateGetUserConsentFunction>
EchoPrivateGetUserConsentFunction::CreateForTest(
      const DialogShownTestCallback& dialog_shown_callback) {
  scoped_refptr<EchoPrivateGetUserConsentFunction> function(
      new EchoPrivateGetUserConsentFunction());
  function->dialog_shown_callback_ = dialog_shown_callback;
  return function;
}

EchoPrivateGetUserConsentFunction::~EchoPrivateGetUserConsentFunction() {}

bool EchoPrivateGetUserConsentFunction::RunAsync() {
  CheckRedeemOffersAllowed();
  return true;
}

void EchoPrivateGetUserConsentFunction::OnAccept() {
  Finalize(true);
}

void EchoPrivateGetUserConsentFunction::OnCancel() {
  Finalize(false);
}

void EchoPrivateGetUserConsentFunction::OnMoreInfoLinkClicked() {
  NavigateParams params(GetProfile(), GURL(kMoreInfoLink),
                        ui::PAGE_TRANSITION_LINK);
  // Open the link in a new window. The echo dialog is modal, so the current
  // window is useless until the dialog is closed.
  params.disposition = WindowOpenDisposition::NEW_WINDOW;
  Navigate(&params);
}

void EchoPrivateGetUserConsentFunction::CheckRedeemOffersAllowed() {
  chromeos::CrosSettingsProvider::TrustedStatus status =
      chromeos::CrosSettings::Get()->PrepareTrustedValues(base::Bind(
          &EchoPrivateGetUserConsentFunction::CheckRedeemOffersAllowed,
          this));
  if (status == chromeos::CrosSettingsProvider::TEMPORARILY_UNTRUSTED)
    return;

  bool allow = true;
  chromeos::CrosSettings::Get()->GetBoolean(
      chromeos::kAllowRedeemChromeOsRegistrationOffers, &allow);

  OnRedeemOffersAllowedChecked(allow);
}

void EchoPrivateGetUserConsentFunction::OnRedeemOffersAllowedChecked(
    bool is_allowed) {
  redeem_offers_allowed_ = is_allowed;

  std::unique_ptr<echo_api::GetUserConsent::Params> params =
      echo_api::GetUserConsent::Params::Create(*args_);

  // Verify that the passed origin URL is valid.
  GURL service_origin = GURL(params->consent_requester.origin);
  if (!service_origin.is_valid()) {
    error_ = "Invalid origin.";
    SendResponse(false);
    return;
  }

  content::WebContents* web_contents = GetAssociatedWebContentsDeprecated();
  if (!web_contents) {
    error_ = "No web contents.";
    SendResponse(false);
    return;
  }

  // Add ref to ensure the function stays around until the dialog listener is
  // called. The reference is release in |Finalize|.
  AddRef();

  // Create and show the dialog.
  chromeos::EchoDialogView* dialog = new chromeos::EchoDialogView(this);
  if (redeem_offers_allowed_) {
    dialog->InitForEnabledEcho(
        base::UTF8ToUTF16(params->consent_requester.service_name),
        base::UTF8ToUTF16(params->consent_requester.origin));
  } else {
    dialog->InitForDisabledEcho();
  }
  dialog->Show(web_contents->GetTopLevelNativeWindow());

  // If there is a dialog_shown_callback_, invoke it with the created dialog.
  if (!dialog_shown_callback_.is_null())
    dialog_shown_callback_.Run(dialog);
}

void EchoPrivateGetUserConsentFunction::Finalize(bool consent) {
  // Consent should not be true if offers redeeming is disabled.
  CHECK(redeem_offers_allowed_ || !consent);
  results_ = echo_api::GetUserConsent::Results::Create(consent);
  SendResponse(true);

  // Release the reference added in |OnRedeemOffersAllowedChecked|, before
  // showing the dialog.
  Release();
}

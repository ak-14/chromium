// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/autofill/core/browser/personal_data_manager.h"

#include <stddef.h>

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include "base/feature_list.h"
#include "base/i18n/case_conversion.h"
#include "base/i18n/timezone.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "components/autofill/core/browser/address_i18n.h"
#include "components/autofill/core/browser/autofill-inl.h"
#include "components/autofill/core/browser/autofill_country.h"
#include "components/autofill/core/browser/autofill_experiments.h"
#include "components/autofill/core/browser/autofill_field.h"
#include "components/autofill/core/browser/autofill_metrics.h"
#include "components/autofill/core/browser/autofill_profile_comparator.h"
#include "components/autofill/core/browser/country_data.h"
#include "components/autofill/core/browser/country_names.h"
#include "components/autofill/core/browser/form_structure.h"
#include "components/autofill/core/browser/personal_data_manager_observer.h"
#include "components/autofill/core/browser/phone_number.h"
#include "components/autofill/core/browser/phone_number_i18n.h"
#include "components/autofill/core/browser/validation.h"
#include "components/autofill/core/common/autofill_clock.h"
#include "components/autofill/core/common/autofill_pref_names.h"
#include "components/autofill/core/common/autofill_switches.h"
#include "components/autofill/core/common/autofill_util.h"
#include "components/prefs/pref_service.h"
#include "components/sync/driver/sync_service.h"
#include "components/sync/driver/sync_service_utils.h"
#include "components/variations/variations_associated_data.h"
#include "components/version_info/version_info.h"
#include "services/identity/public/cpp/identity_manager.h"
#include "third_party/libaddressinput/src/cpp/include/libaddressinput/address_data.h"
#include "third_party/libaddressinput/src/cpp/include/libaddressinput/address_formatter.h"

namespace autofill {

namespace {

using ::i18n::addressinput::AddressField;
using ::i18n::addressinput::GetStreetAddressLinesAsSingleLine;
using ::i18n::addressinput::STREET_ADDRESS;

// The length of a local profile GUID.
const int LOCAL_GUID_LENGTH = 36;

constexpr base::TimeDelta kDisusedProfileTimeDelta =
    base::TimeDelta::FromDays(180);
constexpr base::TimeDelta kDisusedCreditCardTimeDelta =
    base::TimeDelta::FromDays(180);
constexpr base::TimeDelta kDisusedCreditCardDeletionTimeDelta =
    base::TimeDelta::FromDays(395);
constexpr base::TimeDelta kDisusedAddressDeletionTimeDelta =
    base::TimeDelta::FromDays(395);

// Time delta to create test data.
base::TimeDelta DeletableUseDateDelta() {
  static base::TimeDelta delta =
      kDisusedCreditCardDeletionTimeDelta + base::TimeDelta::FromDays(5);
  return delta;
}
base::TimeDelta DeletableExpiryDateDelta() {
  static base::TimeDelta delta =
      kDisusedCreditCardDeletionTimeDelta + base::TimeDelta::FromDays(45);
  return delta;
}

template <typename T>
class FormGroupMatchesByGUIDFunctor {
 public:
  explicit FormGroupMatchesByGUIDFunctor(const std::string& guid)
      : guid_(guid) {}

  bool operator()(const T& form_group) { return form_group.guid() == guid_; }

  bool operator()(const T* form_group) { return form_group->guid() == guid_; }

  bool operator()(const std::unique_ptr<T>& form_group) {
    return form_group->guid() == guid_;
  }

 private:
  const std::string guid_;
};

template <typename T, typename C>
typename C::const_iterator FindElementByGUID(const C& container,
                                             const std::string& guid) {
  return std::find_if(container.begin(), container.end(),
                      FormGroupMatchesByGUIDFunctor<T>(guid));
}

template <typename T, typename C>
bool FindByGUID(const C& container, const std::string& guid) {
  return FindElementByGUID<T>(container, guid) != container.end();
}

template <typename T>
class IsEmptyFunctor {
 public:
  explicit IsEmptyFunctor(const std::string& app_locale)
      : app_locale_(app_locale) {}

  bool operator()(const T& form_group) {
    return form_group.IsEmpty(app_locale_);
  }

 private:
  const std::string app_locale_;
};

bool IsSyncEnabledFor(const syncer::SyncService* sync_service,
                      syncer::ModelType model_type) {
  return sync_service != nullptr && sync_service->CanSyncStart() &&
         sync_service->GetPreferredDataTypes().Has(model_type);
}

// In addition to just getting the values out of the autocomplete profile, this
// function handles formatting of the street address into a single string.
base::string16 GetInfoInOneLine(const AutofillProfile* profile,
                                const AutofillType& type,
                                const std::string app_locale) {
  std::vector<base::string16> results;

  AddressField address_field;
  if (i18n::FieldForType(type.GetStorableType(), &address_field) &&
      address_field == STREET_ADDRESS) {
    std::string street_address_line;
    GetStreetAddressLinesAsSingleLine(
        *i18n::CreateAddressDataFromAutofillProfile(*profile, app_locale),
        &street_address_line);
    return base::UTF8ToUTF16(street_address_line);
  }

  return profile->GetInfo(type, app_locale);
}

// Receives the loaded profiles from the web data service and stores them in
// |*dest|. The pending handle is the address of the pending handle
// corresponding to this request type. This function is used to save both
// server and local profiles and credit cards.
template <typename ValueType>
void ReceiveLoadedDbValues(WebDataServiceBase::Handle h,
                           WDTypedResult* result,
                           WebDataServiceBase::Handle* pending_handle,
                           std::vector<std::unique_ptr<ValueType>>* dest) {
  DCHECK_EQ(*pending_handle, h);
  *pending_handle = 0;

  *dest = std::move(
      static_cast<WDResult<std::vector<std::unique_ptr<ValueType>>>*>(result)
          ->GetValue());
}

// A helper function for finding the maximum value in a string->int map.
static bool CompareVotes(const std::pair<std::string, int>& a,
                         const std::pair<std::string, int>& b) {
  return a.second < b.second;
}

// Returns whether the |suggestion| is valid considering the
// |field_contents_canon|, the |type| and |is_masked_server_card|. Assigns true
// to |is_prefix_matched| if the |field_contents_canon| is a prefix to
// |suggestion|, assigns false otherwise.
bool IsValidSuggestionForFieldContents(base::string16 suggestion_canon,
                                       base::string16 field_contents_canon,
                                       const AutofillType& type,
                                       bool is_masked_server_card,
                                       bool* is_prefix_matched) {
  *is_prefix_matched = true;

  // Phones should do a substring match because they can be trimmed to remove
  // the first parts (e.g. country code or prefix). It is still considered a
  // prefix match in order to put it at the top of the suggestions.
  if ((type.group() == PHONE_HOME || type.group() == PHONE_BILLING) &&
      suggestion_canon.find(field_contents_canon) != base::string16::npos) {
    return true;
  }

  // For card number fields, suggest the card if:
  // - the number matches any part of the card, or
  // - it's a masked card and there are 6 or fewer typed so far.
  if (type.GetStorableType() == CREDIT_CARD_NUMBER) {
    if (suggestion_canon.find(field_contents_canon) == base::string16::npos &&
        (!is_masked_server_card || field_contents_canon.size() >= 6)) {
      return false;
    }
    return true;
  }

  if (base::StartsWith(suggestion_canon, field_contents_canon,
                       base::CompareCase::SENSITIVE)) {
    return true;
  }

  if (IsFeatureSubstringMatchEnabled() &&
      suggestion_canon.length() >= field_contents_canon.length() &&
      GetTextSelectionStart(suggestion_canon, field_contents_canon, false) !=
          base::string16::npos) {
    *is_prefix_matched = false;
    return true;
  }

  return false;
}

AutofillProfile CreateBasicTestAddress(const std::string& locale) {
  const base::Time use_date =
      AutofillClock::Now() - base::TimeDelta::FromDays(20);
  AutofillProfile profile;
  profile.SetInfo(NAME_FULL, base::UTF8ToUTF16("John McTester"), locale);
  profile.SetInfo(COMPANY_NAME, base::UTF8ToUTF16("Test Inc."), locale);
  profile.SetInfo(EMAIL_ADDRESS,
                  base::UTF8ToUTF16("jmctester@fake.chromium.org"), locale);
  profile.SetInfo(ADDRESS_HOME_LINE1, base::UTF8ToUTF16("123 Invented Street"),
                  locale);
  profile.SetInfo(ADDRESS_HOME_LINE2, base::UTF8ToUTF16("Suite A"), locale);
  profile.SetInfo(ADDRESS_HOME_CITY, base::UTF8ToUTF16("Mountain View"),
                  locale);
  profile.SetInfo(ADDRESS_HOME_STATE, base::UTF8ToUTF16("California"), locale);
  profile.SetInfo(ADDRESS_HOME_ZIP, base::UTF8ToUTF16("94043"), locale);
  profile.SetInfo(ADDRESS_HOME_COUNTRY, base::UTF8ToUTF16("US"), locale);
  profile.SetInfo(PHONE_HOME_WHOLE_NUMBER, base::UTF8ToUTF16("844-555-0173"),
                  locale);
  profile.set_use_date(use_date);
  return profile;
}

AutofillProfile CreateDisusedTestAddress(const std::string& locale) {
  const base::Time use_date =
      AutofillClock::Now() - base::TimeDelta::FromDays(185);
  AutofillProfile profile;
  profile.SetInfo(NAME_FULL, base::UTF8ToUTF16("Polly Disused"), locale);
  profile.SetInfo(COMPANY_NAME,
                  base::UTF8ToUTF16(base::StringPrintf(
                      "%lld Inc.", static_cast<long long>(use_date.ToTimeT()))),
                  locale);
  profile.SetInfo(EMAIL_ADDRESS,
                  base::UTF8ToUTF16("polly.disused@fake.chromium.org"), locale);
  profile.SetInfo(ADDRESS_HOME_LINE1, base::UTF8ToUTF16("456 Disused Lane"),
                  locale);
  profile.SetInfo(ADDRESS_HOME_LINE2, base::UTF8ToUTF16("Apt. B"), locale);
  profile.SetInfo(ADDRESS_HOME_CITY, base::UTF8ToUTF16("Austin"), locale);
  profile.SetInfo(ADDRESS_HOME_STATE, base::UTF8ToUTF16("Texas"), locale);
  profile.SetInfo(ADDRESS_HOME_ZIP, base::UTF8ToUTF16("73301"), locale);
  profile.SetInfo(ADDRESS_HOME_COUNTRY, base::UTF8ToUTF16("US"), locale);
  profile.SetInfo(PHONE_HOME_WHOLE_NUMBER, base::UTF8ToUTF16("844-555-0174"),
                  locale);
  profile.set_use_date(use_date);
  return profile;
}

AutofillProfile CreateDisusedDeletableTestAddress(const std::string& locale) {
  const base::Time use_date =
      AutofillClock::Now() - base::TimeDelta::FromDays(400);
  AutofillProfile profile;
  profile.SetInfo(NAME_FULL, base::UTF8ToUTF16("Polly Deletable"), locale);
  profile.SetInfo(COMPANY_NAME,
                  base::UTF8ToUTF16(base::StringPrintf(
                      "%lld Inc.", static_cast<long long>(use_date.ToTimeT()))),
                  locale);
  profile.SetInfo(EMAIL_ADDRESS,
                  base::UTF8ToUTF16("polly.deletable@fake.chromium.org"),
                  locale);
  profile.SetInfo(ADDRESS_HOME_LINE1, base::UTF8ToUTF16("459 Deletable Lane"),
                  locale);
  profile.SetInfo(ADDRESS_HOME_LINE2, base::UTF8ToUTF16("Apt. B"), locale);
  profile.SetInfo(ADDRESS_HOME_CITY, base::UTF8ToUTF16("Austin"), locale);
  profile.SetInfo(ADDRESS_HOME_STATE, base::UTF8ToUTF16("Texas"), locale);
  profile.SetInfo(ADDRESS_HOME_ZIP, base::UTF8ToUTF16("73301"), locale);
  profile.SetInfo(ADDRESS_HOME_COUNTRY, base::UTF8ToUTF16("US"), locale);
  profile.SetInfo(PHONE_HOME_WHOLE_NUMBER, base::UTF8ToUTF16("844-555-0274"),
                  locale);
  profile.set_use_date(use_date);
  return profile;
}

// Create a card expiring 500 days from now which was last used 10 days ago.
CreditCard CreateBasicTestCreditCard(const std::string& locale) {
  const base::Time now = AutofillClock::Now();
  const base::Time use_date = now - base::TimeDelta::FromDays(10);
  base::Time::Exploded expiry_date;
  (now + base::TimeDelta::FromDays(500)).LocalExplode(&expiry_date);

  CreditCard credit_card;
  credit_card.SetInfo(CREDIT_CARD_NAME_FULL,
                      base::UTF8ToUTF16("Alice Testerson"), locale);
  credit_card.SetInfo(CREDIT_CARD_NUMBER, base::UTF8ToUTF16("4545454545454545"),
                      locale);
  credit_card.SetExpirationMonth(expiry_date.month);
  credit_card.SetExpirationYear(expiry_date.year);
  credit_card.set_use_date(use_date);
  return credit_card;
}

CreditCard CreateDisusedTestCreditCard(const std::string& locale) {
  const base::Time now = AutofillClock::Now();
  const base::Time use_date = now - base::TimeDelta::FromDays(185);
  base::Time::Exploded expiry_date;
  (now - base::TimeDelta::FromDays(200)).LocalExplode(&expiry_date);

  CreditCard credit_card;
  credit_card.SetInfo(CREDIT_CARD_NAME_FULL, base::UTF8ToUTF16("Bob Disused"),
                      locale);
  credit_card.SetInfo(CREDIT_CARD_NUMBER, base::UTF8ToUTF16("4111111111111111"),
                      locale);
  credit_card.SetExpirationMonth(expiry_date.month);
  credit_card.SetExpirationYear(expiry_date.year);
  credit_card.set_use_date(use_date);
  return credit_card;
}

CreditCard CreateDisusedDeletableTestCreditCard(const std::string& locale) {
  const base::Time now = AutofillClock::Now();
  const base::Time use_date = now - DeletableUseDateDelta();
  base::Time::Exploded expiry_date;
  (now - DeletableExpiryDateDelta()).LocalExplode(&expiry_date);

  CreditCard credit_card;
  credit_card.SetInfo(CREDIT_CARD_NAME_FULL,
                      base::UTF8ToUTF16("Charlie Deletable"), locale);
  credit_card.SetInfo(CREDIT_CARD_NUMBER, base::UTF8ToUTF16("378282246310005"),
                      locale);
  credit_card.SetExpirationMonth(expiry_date.month);
  credit_card.SetExpirationYear(expiry_date.year);
  credit_card.set_use_date(use_date);
  return credit_card;
}

}  // namespace

const char kFrecencyFieldTrialName[] = "AutofillProfileOrderByFrecency";
const char kFrecencyFieldTrialLimitParam[] = "limit";

PersonalDataManager::PersonalDataManager(const std::string& app_locale)
    : database_(nullptr),
      is_data_loaded_(false),
      pending_profiles_query_(0),
      pending_server_profiles_query_(0),
      pending_creditcards_query_(0),
      pending_server_creditcards_query_(0),
      app_locale_(app_locale),
      pref_service_(nullptr),
      identity_manager_(nullptr),
      sync_service_(nullptr),
      is_off_the_record_(false),
      has_logged_stored_profile_metrics_(false),
      has_logged_stored_credit_card_metrics_(false) {}

void PersonalDataManager::Init(scoped_refptr<AutofillWebDataService> database,
                               PrefService* pref_service,
                               identity::IdentityManager* identity_manager,
                               bool is_off_the_record) {
  CountryNames::SetLocaleString(app_locale_);

  database_ = database;
  SetPrefService(pref_service);
  identity_manager_ = identity_manager;
  is_off_the_record_ = is_off_the_record;

  if (!is_off_the_record_)
    AutofillMetrics::LogIsAutofillEnabledAtStartup(IsAutofillEnabled());

  // WebDataService may not be available in tests.
  if (!database_.get())
    return;

  LoadProfiles();
  LoadCreditCards();

  database_->AddObserver(this);

  // Check if profile cleanup has already been performed this major version.
  is_autofill_profile_cleanup_pending_ =
      pref_service_->GetInteger(prefs::kAutofillLastVersionDeduped) >=
      atoi(version_info::GetVersionNumber().c_str());
  DVLOG(1) << "Autofill profile cleanup "
           << (is_autofill_profile_cleanup_pending_ ? "needs to be"
                                                    : "has already been")
           << " performed for this version";
}

PersonalDataManager::~PersonalDataManager() {
  CancelPendingQuery(&pending_profiles_query_);
  CancelPendingQuery(&pending_server_profiles_query_);
  CancelPendingQuery(&pending_creditcards_query_);
  CancelPendingQuery(&pending_server_creditcards_query_);

  if (database_.get())
    database_->RemoveObserver(this);
}

void PersonalDataManager::Shutdown() {
  if (sync_service_)
    sync_service_->RemoveObserver(this);

  sync_service_ = nullptr;
}

void PersonalDataManager::OnSyncServiceInitialized(
    syncer::SyncService* sync_service) {
  // If the sync service is not enabled for autofill address profiles then run
  // address cleanup/startup code here. Otherwise, defer until after sync has
  // started.
  if (!IsSyncEnabledFor(sync_service, syncer::AUTOFILL_PROFILE)) {
    ApplyProfileUseDatesFix();  // One-time fix, otherwise NOP.
    ApplyDedupingRoutine();     // Once per major version, otherwise NOP.
    DeleteDisusedAddresses();   // Once per major version, otherwise NOP.
    CreateTestAddresses();      // Once per user profile startup.
  }

  // Similarly, if the sync service is not enabled for autofill credit cards
  // then run credit card address cleanup/startup code here. Otherwise, defer
  // until after sync has started.
  if (!IsSyncEnabledFor(sync_service, syncer::AUTOFILL_WALLET_DATA)) {
    DeleteDisusedCreditCards();  // Once per major version, otherwise NOP.
    CreateTestCreditCards();     // Once per user profile startup.
  }

  if (sync_service_ != sync_service) {
    // Before the sync service pointer gets changed, remove the observer.
    if (sync_service_)
      sync_service_->RemoveObserver(this);

    sync_service_ = sync_service;

    if (!sync_service_) {
      ResetFullServerCards();
      return;
    }

    sync_service_->AddObserver(this);
    // Re-mask all server cards if the upload state is not active.
    if (syncer::GetUploadToGoogleState(
            sync_service_, syncer::ModelType::AUTOFILL_WALLET_DATA) ==
        syncer::UploadState::NOT_ACTIVE) {
      ResetFullServerCards();
    }
  }
}

void PersonalDataManager::OnWebDataServiceRequestDone(
    WebDataServiceBase::Handle h,
    std::unique_ptr<WDTypedResult> result) {
  DCHECK(pending_profiles_query_ || pending_server_profiles_query_ ||
         pending_creditcards_query_ || pending_server_creditcards_query_);

  if (!result) {
    // Error from the web database.
    if (h == pending_creditcards_query_)
      pending_creditcards_query_ = 0;
    else if (h == pending_profiles_query_)
      pending_profiles_query_ = 0;
    else if (h == pending_server_creditcards_query_)
      pending_server_creditcards_query_ = 0;
    else if (h == pending_server_profiles_query_)
      pending_server_profiles_query_ = 0;
  } else {
    switch (result->GetType()) {
      case AUTOFILL_PROFILES_RESULT:
        if (h == pending_profiles_query_) {
          ReceiveLoadedDbValues(h, result.get(), &pending_profiles_query_,
                                &web_profiles_);
        } else {
          ReceiveLoadedDbValues(h, result.get(),
                                &pending_server_profiles_query_,
                                &server_profiles_);
        }
        break;
      case AUTOFILL_CREDITCARDS_RESULT:
        if (h == pending_creditcards_query_) {
          ReceiveLoadedDbValues(h, result.get(), &pending_creditcards_query_,
                                &local_credit_cards_);
        } else {
          ReceiveLoadedDbValues(h, result.get(),
                                &pending_server_creditcards_query_,
                                &server_credit_cards_);

          // If the user has a saved unmasked server card and the experiment is
          // disabled, force mask all cards back to the unsaved state.
          if (!OfferStoreUnmaskedCards())
            ResetFullServerCards();
        }
        break;
      default:
        NOTREACHED();
    }
  }

  // If all requests have responded, then all personal data is loaded.
  if (pending_profiles_query_ == 0 && pending_creditcards_query_ == 0 &&
      pending_server_profiles_query_ == 0 &&
      pending_server_creditcards_query_ == 0) {
    is_data_loaded_ = true;
    LogStoredProfileMetrics();
    LogStoredCreditCardMetrics();
    NotifyPersonalDataChanged();
  }
}

void PersonalDataManager::AutofillMultipleChanged() {
  has_synced_new_data_ = true;
  Refresh();
}

void PersonalDataManager::SyncStarted(syncer::ModelType model_type) {
  // Run deferred autofill address profile startup code.
  // See: OnSyncServiceInitialized
  if (model_type == syncer::AUTOFILL_PROFILE) {
    ApplyProfileUseDatesFix();  // One-time fix, otherwise NOP.
    ApplyDedupingRoutine();     // Once per major version, otherwise NOP.
    DeleteDisusedAddresses();   // Once per major version, otherwise NOP.
    CreateTestAddresses();      // Once per user profile startup.
  }

  // Run deferred credit card startup code.
  // See: OnSyncServiceInitialized
  if (model_type == syncer::AUTOFILL_WALLET_DATA) {
    DeleteDisusedCreditCards();  // Once per major version, otherwise NOP.
    CreateTestCreditCards();     // Once per user profile startup.
  }
}

void PersonalDataManager::OnStateChanged(syncer::SyncService* sync_service) {
  if (syncer::GetUploadToGoogleState(sync_service_,
                                     syncer::ModelType::AUTOFILL_WALLET_DATA) !=
      syncer::UploadState::ACTIVE) {
    ResetFullServerCards();
  }
}

void PersonalDataManager::AddObserver(PersonalDataManagerObserver* observer) {
  observers_.AddObserver(observer);
}

void PersonalDataManager::RemoveObserver(
    PersonalDataManagerObserver* observer) {
  observers_.RemoveObserver(observer);
}

void PersonalDataManager::MarkObserversInsufficientFormDataForImport() {
  for (PersonalDataManagerObserver& observer : observers_)
    observer.OnInsufficientFormData();
}

void PersonalDataManager::RecordUseOf(const AutofillDataModel& data_model) {
  if (is_off_the_record_ || !database_.get())
    return;

  CreditCard* credit_card = GetCreditCardByGUID(data_model.guid());
  if (credit_card) {
    credit_card->RecordAndLogUse();

    if (credit_card->record_type() == CreditCard::LOCAL_CARD)
      database_->UpdateCreditCard(*credit_card);
    else
      database_->UpdateServerCardMetadata(*credit_card);

    Refresh();
    return;
  }

  AutofillProfile* profile = GetProfileByGUID(data_model.guid());
  if (profile) {
    profile->RecordAndLogUse();

    if (profile->record_type() == AutofillProfile::LOCAL_PROFILE)
      database_->UpdateAutofillProfile(*profile);
    else if (profile->record_type() == AutofillProfile::SERVER_PROFILE)
      database_->UpdateServerAddressMetadata(*profile);

    Refresh();
  }
}

void PersonalDataManager::AddProfile(const AutofillProfile& profile) {
  if (is_off_the_record_)
    return;

  if (profile.IsEmpty(app_locale_))
    return;

  // Don't add an existing profile.
  if (FindByGUID<AutofillProfile>(web_profiles_, profile.guid()))
    return;

  if (!database_.get())
    return;

  // Don't add a duplicate.
  if (FindByContents(web_profiles_, profile))
    return;

  // Add the new profile to the web database.
  database_->AddAutofillProfile(profile);

  // Refresh our local cache and send notifications to observers.
  Refresh();
}

void PersonalDataManager::UpdateProfile(const AutofillProfile& profile) {
  if (is_off_the_record_)
    return;

  AutofillProfile* existing_profile = GetProfileByGUID(profile.guid());
  if (!existing_profile)
    return;

  // Don't overwrite the origin for a profile that is already stored.
  if (existing_profile->EqualsSansOrigin(profile))
    return;

  if (profile.IsEmpty(app_locale_)) {
    RemoveByGUID(profile.guid());
    return;
  }

  if (!database_.get())
    return;

  // Make the update.
  database_->UpdateAutofillProfile(profile);

  // Refresh our local cache and send notifications to observers.
  Refresh();
}

AutofillProfile* PersonalDataManager::GetProfileByGUID(
    const std::string& guid) {
  return GetProfileFromProfilesByGUID(guid, GetProfiles());
}

// static
AutofillProfile* PersonalDataManager::GetProfileFromProfilesByGUID(
    const std::string& guid,
    const std::vector<AutofillProfile*>& profiles) {
  std::vector<AutofillProfile*>::const_iterator iter =
      FindElementByGUID<AutofillProfile>(profiles, guid);
  return iter != profiles.end() ? *iter : nullptr;
}

void PersonalDataManager::AddCreditCard(const CreditCard& credit_card) {
  if (is_off_the_record_)
    return;

  if (credit_card.IsEmpty(app_locale_))
    return;

  if (FindByGUID<CreditCard>(local_credit_cards_, credit_card.guid()))
    return;

  if (!database_.get())
    return;

  // Don't add a duplicate.
  if (FindByContents(local_credit_cards_, credit_card))
    return;

  // Add the new credit card to the web database.
  database_->AddCreditCard(credit_card);

  // Refresh our local cache and send notifications to observers.
  Refresh();
}

void PersonalDataManager::UpdateCreditCard(const CreditCard& credit_card) {
  DCHECK_EQ(CreditCard::LOCAL_CARD, credit_card.record_type());
  if (is_off_the_record_)
    return;

  CreditCard* existing_credit_card = GetCreditCardByGUID(credit_card.guid());
  if (!existing_credit_card)
    return;

  // Don't overwrite the origin for a credit card that is already stored.
  if (existing_credit_card->Compare(credit_card) == 0)
    return;

  if (credit_card.IsEmpty(app_locale_)) {
    RemoveByGUID(credit_card.guid());
    return;
  }

  // Update the cached version.
  *existing_credit_card = credit_card;

  if (!database_.get())
    return;

  // Make the update.
  database_->UpdateCreditCard(credit_card);

  // Refresh our local cache and send notifications to observers.
  Refresh();
}

void PersonalDataManager::AddFullServerCreditCard(
    const CreditCard& credit_card) {
  DCHECK_EQ(CreditCard::FULL_SERVER_CARD, credit_card.record_type());
  DCHECK(!credit_card.IsEmpty(app_locale_));
  DCHECK(!credit_card.server_id().empty());

  if (is_off_the_record_ || !database_.get())
    return;

  // Don't add a duplicate.
  if (FindByGUID<CreditCard>(server_credit_cards_, credit_card.guid()) ||
      FindByContents(server_credit_cards_, credit_card))
    return;

  // Add the new credit card to the web database.
  database_->AddFullServerCreditCard(credit_card);

  // Refresh our local cache and send notifications to observers.
  Refresh();
}

void PersonalDataManager::UpdateServerCreditCard(
    const CreditCard& credit_card) {
  DCHECK_NE(CreditCard::LOCAL_CARD, credit_card.record_type());

  if (is_off_the_record_ || !database_.get())
    return;

  // Look up by server id, not GUID.
  const CreditCard* existing_credit_card = nullptr;
  for (const auto& server_card : server_credit_cards_) {
    if (credit_card.server_id() == server_card->server_id()) {
      existing_credit_card = server_card.get();
      break;
    }
  }
  if (!existing_credit_card)
    return;

  DCHECK_NE(existing_credit_card->record_type(), credit_card.record_type());
  DCHECK_EQ(existing_credit_card->Label(), credit_card.Label());
  if (existing_credit_card->record_type() == CreditCard::MASKED_SERVER_CARD) {
    database_->UnmaskServerCreditCard(credit_card, credit_card.number());
  } else {
    database_->MaskServerCreditCard(credit_card.server_id());
  }

  Refresh();
}

void PersonalDataManager::UpdateServerCardMetadata(
    const CreditCard& credit_card) {
  DCHECK_NE(CreditCard::LOCAL_CARD, credit_card.record_type());

  if (is_off_the_record_ || !database_.get())
    return;

  database_->UpdateServerCardMetadata(credit_card);

  Refresh();
}

void PersonalDataManager::ResetFullServerCard(const std::string& guid) {
  for (const auto& card : server_credit_cards_) {
    if (card->guid() == guid) {
      DCHECK_EQ(card->record_type(), CreditCard::FULL_SERVER_CARD);
      CreditCard card_copy = *card;
      card_copy.set_record_type(CreditCard::MASKED_SERVER_CARD);
      card_copy.SetNumber(card->LastFourDigits());
      UpdateServerCreditCard(card_copy);
      break;
    }
  }
}

void PersonalDataManager::ResetFullServerCards() {
  for (const auto& card : server_credit_cards_) {
    if (card->record_type() == CreditCard::FULL_SERVER_CARD) {
      CreditCard card_copy = *card;
      card_copy.set_record_type(CreditCard::MASKED_SERVER_CARD);
      card_copy.SetNumber(card->LastFourDigits());
      UpdateServerCreditCard(card_copy);
    }
  }
}

void PersonalDataManager::ClearAllServerData() {
  // This could theoretically be called before we get the data back from the
  // database on startup, and it could get called when the wallet pref is
  // off (meaning this class won't even query for the server data) so don't
  // check the server_credit_cards_/profiles_ before posting to the DB.
  database_->ClearAllServerData();

  // The above call will eventually clear our server data by notifying us
  // that the data changed and then this class will re-fetch. Preemptively
  // clear so that tests can synchronously verify that this data was cleared.
  server_credit_cards_.clear();
  server_profiles_.clear();
}

void PersonalDataManager::AddServerCreditCardForTest(
    std::unique_ptr<CreditCard> credit_card) {
  server_credit_cards_.push_back(std::move(credit_card));
}

void PersonalDataManager::SetSyncServiceForTest(
    syncer::SyncService* sync_service) {
  if (sync_service_)
    sync_service_->RemoveObserver(this);

  sync_service_ = sync_service;

  if (sync_service_)
    sync_service_->AddObserver(this);
}

void PersonalDataManager::
    RemoveAutofillProfileByGUIDAndBlankCreditCardReferecne(
        const std::string& guid) {
  database_->RemoveAutofillProfile(guid);

  // Reset the billing_address_id of any card that refered to this profile.
  for (CreditCard* credit_card : GetCreditCards()) {
    if (credit_card->billing_address_id() == guid) {
      credit_card->set_billing_address_id("");

      if (credit_card->record_type() == CreditCard::LOCAL_CARD)
        database_->UpdateCreditCard(*credit_card);
      else
        database_->UpdateServerCardMetadata(*credit_card);
    }
  }
}

void PersonalDataManager::RemoveByGUID(const std::string& guid) {
  if (is_off_the_record_)
    return;

  bool is_credit_card = FindByGUID<CreditCard>(local_credit_cards_, guid);
  bool is_profile =
      !is_credit_card && FindByGUID<AutofillProfile>(web_profiles_, guid);
  if (!is_credit_card && !is_profile)
    return;

  if (!database_.get())
    return;

  if (is_credit_card) {
    database_->RemoveCreditCard(guid);
  } else {
    RemoveAutofillProfileByGUIDAndBlankCreditCardReferecne(guid);
  }

  // Refresh our local cache and send notifications to observers.
  Refresh();
}

CreditCard* PersonalDataManager::GetCreditCardByGUID(const std::string& guid) {
  const std::vector<CreditCard*>& credit_cards = GetCreditCards();
  std::vector<CreditCard*>::const_iterator iter =
      FindElementByGUID<CreditCard>(credit_cards, guid);
  return iter != credit_cards.end() ? *iter : nullptr;
}

CreditCard* PersonalDataManager::GetCreditCardByNumber(
    const std::string& number) {
  CreditCard numbered_card;
  numbered_card.SetNumber(base::ASCIIToUTF16(number));
  for (CreditCard* credit_card : GetCreditCards()) {
    DCHECK(credit_card);
    if (credit_card->HasSameNumberAs(numbered_card))
      return credit_card;
  }
  return nullptr;
}

void PersonalDataManager::GetNonEmptyTypes(
    ServerFieldTypeSet* non_empty_types) {
  for (AutofillProfile* profile : GetProfiles())
    profile->GetNonEmptyTypes(app_locale_, non_empty_types);
  for (CreditCard* card : GetCreditCards())
    card->GetNonEmptyTypes(app_locale_, non_empty_types);
}

bool PersonalDataManager::IsDataLoaded() const {
  return is_data_loaded_;
}

std::vector<AutofillProfile*> PersonalDataManager::GetProfiles() const {
  std::vector<AutofillProfile*> result;
  result.reserve(web_profiles_.size());
  for (const auto& profile : web_profiles_)
    result.push_back(profile.get());
  return result;
}

std::vector<AutofillProfile*> PersonalDataManager::GetServerProfiles() const {
  std::vector<AutofillProfile*> result;
  result.reserve(server_profiles_.size());
  for (const auto& profile : server_profiles_)
    result.push_back(profile.get());
  return result;
}

std::vector<CreditCard*> PersonalDataManager::GetLocalCreditCards() const {
  std::vector<CreditCard*> result;
  if (!IsAutofillCreditCardEnabled())
    return result;

  result.reserve(local_credit_cards_.size());
  for (const auto& card : local_credit_cards_)
    result.push_back(card.get());
  return result;
}

std::vector<CreditCard*> PersonalDataManager::GetServerCreditCards() const {
  std::vector<CreditCard*> result;
  if (!IsAutofillCreditCardEnabled() || !IsAutofillWalletImportEnabled())
    return result;

  result.reserve(server_credit_cards_.size());
  for (const auto& card : server_credit_cards_)
    result.push_back(card.get());
  return result;
}

std::vector<CreditCard*> PersonalDataManager::GetCreditCards() const {
  std::vector<CreditCard*> result;
  if (!IsAutofillCreditCardEnabled())
    return result;

  result.reserve(local_credit_cards_.size() + server_credit_cards_.size());
  for (const auto& card : local_credit_cards_)
    result.push_back(card.get());
  if (IsAutofillWalletImportEnabled()) {
    for (const auto& card : server_credit_cards_)
      result.push_back(card.get());
  }
  return result;
}

void PersonalDataManager::Refresh() {
  LoadProfiles();
  LoadCreditCards();
}

std::vector<AutofillProfile*> PersonalDataManager::GetProfilesToSuggest()
    const {
  std::vector<AutofillProfile*> profiles = GetProfiles();

  // Rank the suggestions by frecency (see AutofillDataModel for details).
  const base::Time comparison_time = AutofillClock::Now();
  std::sort(profiles.begin(), profiles.end(),
            [comparison_time](const AutofillDataModel* a,
                              const AutofillDataModel* b) {
              return a->CompareFrecency(b, comparison_time);
            });

  return profiles;
}

// static
void PersonalDataManager::RemoveProfilesNotUsedSinceTimestamp(
    base::Time min_last_used,
    std::vector<AutofillProfile*>* profiles) {
  const size_t original_size = profiles->size();
  profiles->erase(
      std::stable_partition(profiles->begin(), profiles->end(),
                            [min_last_used](const AutofillDataModel* m) {
                              return m->use_date() > min_last_used;
                            }),
      profiles->end());
  const size_t num_profiles_supressed = original_size - profiles->size();
  AutofillMetrics::LogNumberOfAddressesSuppressedForDisuse(
      num_profiles_supressed);
}

std::vector<Suggestion> PersonalDataManager::GetProfileSuggestions(
    const AutofillType& type,
    const base::string16& field_contents,
    bool field_is_autofilled,
    const std::vector<ServerFieldType>& other_field_types) {
  if (IsInAutofillSuggestionsDisabledExperiment())
    return std::vector<Suggestion>();

  AutofillProfileComparator comparator(app_locale_);
  base::string16 field_contents_canon =
      comparator.NormalizeForComparison(field_contents);

  // Get the profiles to suggest, which are already sorted.
  std::vector<AutofillProfile*> profiles = GetProfilesToSuggest();

  // If enabled, suppress disused address profiles when triggered from an empty
  // field.
  if (field_contents_canon.empty() &&
      base::FeatureList::IsEnabled(kAutofillSuppressDisusedAddresses)) {
    const base::Time min_last_used =
        AutofillClock::Now() - kDisusedProfileTimeDelta;
    RemoveProfilesNotUsedSinceTimestamp(min_last_used, &profiles);
  }

  std::vector<Suggestion> suggestions;
  // Match based on a prefix search.
  std::vector<AutofillProfile*> matched_profiles;
  for (AutofillProfile* profile : profiles) {
    base::string16 value = GetInfoInOneLine(profile, type, app_locale_);
    if (value.empty())
      continue;

    bool prefix_matched_suggestion;
    base::string16 suggestion_canon = comparator.NormalizeForComparison(value);
    if (IsValidSuggestionForFieldContents(
            suggestion_canon, field_contents_canon, type,
            /* is_masked_server_card= */ false, &prefix_matched_suggestion)) {
      matched_profiles.push_back(profile);
      suggestions.push_back(Suggestion(value));
      suggestions.back().backend_id = profile->guid();
      suggestions.back().match = prefix_matched_suggestion
                                     ? Suggestion::PREFIX_MATCH
                                     : Suggestion::SUBSTRING_MATCH;
    }
  }

  // Prefix matches should precede other token matches.
  if (IsFeatureSubstringMatchEnabled()) {
    std::stable_sort(suggestions.begin(), suggestions.end(),
                     [](const Suggestion& a, const Suggestion& b) {
                       return a.match < b.match;
                     });
  }

  // Don't show two suggestions if one is a subset of the other.
  std::vector<AutofillProfile*> unique_matched_profiles;
  std::vector<Suggestion> unique_suggestions;
  // If there are many profiles, subset checking will take a long time(easily
  // seconds). We will only do this if the profiles count is reasonable.
  if (matched_profiles.size() <= 15) {
    ServerFieldTypeSet types(other_field_types.begin(),
                             other_field_types.end());
    for (size_t i = 0; i < matched_profiles.size(); ++i) {
      bool include = true;
      AutofillProfile* profile_a = matched_profiles[i];
      for (size_t j = 0; j < matched_profiles.size(); ++j) {
        AutofillProfile* profile_b = matched_profiles[j];
        // Check if profile A is a subset of profile B. If not, continue.
        if (i == j || suggestions[i].value != suggestions[j].value ||
            !profile_a->IsSubsetOfForFieldSet(*profile_b, app_locale_, types)) {
          continue;
        }

        // Check if profile B is also a subset of profile A. If so, the
        // profiles are identical. Include the first one but not the second.
        if (i < j &&
            profile_b->IsSubsetOfForFieldSet(*profile_a, app_locale_, types)) {
          continue;
        }

        // One-way subset. Don't include profile A.
        include = false;
        break;
      }
      if (include) {
        unique_matched_profiles.push_back(matched_profiles[i]);
        unique_suggestions.push_back(suggestions[i]);
      }
    }
  } else {
    unique_matched_profiles = matched_profiles;
    unique_suggestions = suggestions;
  }

  // Generate disambiguating labels based on the list of matches.
  std::vector<base::string16> labels;
  AutofillProfile::CreateInferredLabels(
      unique_matched_profiles, &other_field_types, type.GetStorableType(), 1,
      app_locale_, &labels);
  DCHECK_EQ(unique_suggestions.size(), labels.size());
  for (size_t i = 0; i < labels.size(); i++)
    unique_suggestions[i].label = labels[i];

  // Get the profile suggestions limit value set for the current frecency field
  // trial group or SIZE_MAX if no limit is defined.
  std::string limit_str = variations::GetVariationParamValue(
      kFrecencyFieldTrialName, kFrecencyFieldTrialLimitParam);
  size_t limit = SIZE_MAX;
  // Reassign SIZE_MAX to |limit| is needed after calling base::StringToSizeT,
  // as this method can modify |limit| even if it returns false.
  if (!base::StringToSizeT(limit_str, &limit))
    limit = SIZE_MAX;

  unique_suggestions.resize(std::min(unique_suggestions.size(), limit));

  return unique_suggestions;
}

// TODO(crbug.com/613187): Investigate if it would be more efficient to dedupe
// with a vector instead of a list.
const std::vector<CreditCard*> PersonalDataManager::GetCreditCardsToSuggest()
    const {
  std::vector<CreditCard*> credit_cards;
  if (ShouldSuggestServerCards()) {
    credit_cards = GetCreditCards();
  } else {
    credit_cards = GetLocalCreditCards();
  }

  std::list<CreditCard*> cards_to_dedupe(credit_cards.begin(),
                                         credit_cards.end());

  DedupeCreditCardToSuggest(&cards_to_dedupe);

  std::vector<CreditCard*> cards_to_suggest(
      std::make_move_iterator(std::begin(cards_to_dedupe)),
      std::make_move_iterator(std::end(cards_to_dedupe)));

  // Rank the cards by frecency (see AutofillDataModel for details). All expired
  // cards should be suggested last, also by frecency.
  base::Time comparison_time = AutofillClock::Now();
  std::stable_sort(cards_to_suggest.begin(), cards_to_suggest.end(),
                   [comparison_time](const CreditCard* a, const CreditCard* b) {
                     bool a_is_expired = a->IsExpired(comparison_time);
                     if (a_is_expired != b->IsExpired(comparison_time))
                       return !a_is_expired;

                     return a->CompareFrecency(b, comparison_time);
                   });

  return cards_to_suggest;
}

// static
void PersonalDataManager::RemoveExpiredCreditCardsNotUsedSinceTimestamp(
    base::Time comparison_time,
    base::Time min_last_used,
    std::vector<CreditCard*>* cards) {
  const size_t original_size = cards->size();
  // Split the vector into [unexpired-or-expired-but-after-timestamp,
  // expired-and-before-timestamp], then delete the latter.
  cards->erase(std::stable_partition(
                   cards->begin(), cards->end(),
                   [comparison_time, min_last_used](const CreditCard* c) {
                     return !c->IsExpired(comparison_time) ||
                            c->use_date() > min_last_used;
                   }),
               cards->end());
  const size_t num_cards_supressed = original_size - cards->size();
  AutofillMetrics::LogNumberOfCreditCardsSuppressedForDisuse(
      num_cards_supressed);
}

std::vector<Suggestion> PersonalDataManager::GetCreditCardSuggestions(
    const AutofillType& type,
    const base::string16& field_contents) {
  if (IsInAutofillSuggestionsDisabledExperiment())
    return std::vector<Suggestion>();
  std::vector<CreditCard*> cards = GetCreditCardsToSuggest();
  // If enabled, suppress disused address profiles when triggered from an empty
  // field.
  if (field_contents.empty() &&
      base::FeatureList::IsEnabled(kAutofillSuppressDisusedCreditCards)) {
    const base::Time min_last_used =
        AutofillClock::Now() - kDisusedCreditCardTimeDelta;
    RemoveExpiredCreditCardsNotUsedSinceTimestamp(AutofillClock::Now(),
                                                  min_last_used, &cards);
  }

  return GetSuggestionsForCards(type, field_contents, cards);
}

bool PersonalDataManager::IsAutofillEnabled() const {
  return ::autofill::IsAutofillEnabled(pref_service_);
}

bool PersonalDataManager::IsAutofillCreditCardEnabled() const {
  return pref_service_->GetBoolean(prefs::kAutofillCreditCardEnabled);
}

bool PersonalDataManager::IsAutofillWalletImportEnabled() const {
  return pref_service_->GetBoolean(prefs::kAutofillWalletImportEnabled);
}

std::string PersonalDataManager::CountryCodeForCurrentTimezone() const {
  return base::CountryCodeForCurrentTimezone();
}

void PersonalDataManager::SetPrefService(PrefService* pref_service) {
  enabled_pref_ = std::make_unique<BooleanPrefMember>();
  wallet_enabled_pref_ = std::make_unique<BooleanPrefMember>();
  credit_card_enabled_pref_ = std::make_unique<BooleanPrefMember>();
  pref_service_ = pref_service;
  // |pref_service_| can be nullptr in tests.
  if (pref_service_) {
    credit_card_enabled_pref_->Init(
        prefs::kAutofillCreditCardEnabled, pref_service_,
        base::Bind(&PersonalDataManager::Refresh, base::Unretained(this)));
    enabled_pref_->Init(prefs::kAutofillEnabled, pref_service_,
                        base::Bind(&PersonalDataManager::EnabledPrefChanged,
                                   base::Unretained(this)));
    wallet_enabled_pref_->Init(
        prefs::kAutofillWalletImportEnabled, pref_service_,
        base::Bind(&PersonalDataManager::EnabledPrefChanged,
                   base::Unretained(this)));
  }
}

// TODO(crbug.com/618448): Refactor MergeProfile to not depend on class
// variables.
std::string PersonalDataManager::MergeProfile(
    const AutofillProfile& new_profile,
    std::vector<std::unique_ptr<AutofillProfile>>* existing_profiles,
    const std::string& app_locale,
    std::vector<AutofillProfile>* merged_profiles) {
  merged_profiles->clear();

  // Sort the existing profiles in decreasing order of frecency, so the "best"
  // profiles are checked first. Put the verified profiles last so the non
  // verified profiles get deduped among themselves before reaching the verified
  // profiles.
  // TODO(crbug.com/620521): Remove the check for verified from the sort.
  base::Time comparison_time = AutofillClock::Now();
  std::sort(existing_profiles->begin(), existing_profiles->end(),
            [comparison_time](const std::unique_ptr<AutofillProfile>& a,
                              const std::unique_ptr<AutofillProfile>& b) {
              if (a->IsVerified() != b->IsVerified())
                return !a->IsVerified();
              return a->CompareFrecency(b.get(), comparison_time);
            });

  // Set to true if |existing_profiles| already contains an equivalent profile.
  bool matching_profile_found = false;
  std::string guid = new_profile.guid();

  // If we have already saved this address, merge in any missing values.
  // Only merge with the first match. Merging the new profile into the existing
  // one preserves the validity of credit card's billing address reference.
  AutofillProfileComparator comparator(app_locale);
  for (const auto& existing_profile : *existing_profiles) {
    if (!matching_profile_found &&
        comparator.AreMergeable(new_profile, *existing_profile) &&
        existing_profile->SaveAdditionalInfo(new_profile, app_locale)) {
      // Unverified profiles should always be updated with the newer data,
      // whereas verified profiles should only ever be overwritten by verified
      // data.  If an automatically aggregated profile would overwrite a
      // verified profile, just drop it.
      matching_profile_found = true;
      guid = existing_profile->guid();

      // We set the modification date so that immediate requests for profiles
      // will properly reflect the fact that this profile has been modified
      // recently. After writing to the database and refreshing the local copies
      // the profile will have a very slightly newer time reflecting what's
      // actually stored in the database.
      existing_profile->set_modification_date(AutofillClock::Now());
    }
    merged_profiles->push_back(*existing_profile);
  }

  // If the new profile was not merged with an existing one, add it to the list.
  if (!matching_profile_found) {
    merged_profiles->push_back(new_profile);
    // Similar to updating merged profiles above, set the modification date on
    // new profiles.
    merged_profiles->back().set_modification_date(AutofillClock::Now());
    AutofillMetrics::LogProfileActionOnFormSubmitted(
        AutofillMetrics::NEW_PROFILE_CREATED);
  }

  return guid;
}

bool PersonalDataManager::IsCountryOfInterest(
    const std::string& country_code) const {
  DCHECK_EQ(2U, country_code.size());

  const std::vector<AutofillProfile*>& profiles = GetProfiles();
  std::list<std::string> country_codes;
  for (size_t i = 0; i < profiles.size(); ++i) {
    country_codes.push_back(base::ToLowerASCII(
        base::UTF16ToASCII(profiles[i]->GetRawInfo(ADDRESS_HOME_COUNTRY))));
  }

  std::string timezone_country = CountryCodeForCurrentTimezone();
  if (!timezone_country.empty())
    country_codes.push_back(base::ToLowerASCII(timezone_country));

  // Only take the locale into consideration if all else fails.
  if (country_codes.empty()) {
    country_codes.push_back(base::ToLowerASCII(
        AutofillCountry::CountryCodeForLocale(app_locale())));
  }

  return base::ContainsValue(country_codes, base::ToLowerASCII(country_code));
}

const std::string& PersonalDataManager::GetDefaultCountryCodeForNewAddress()
    const {
  if (default_country_code_.empty())
    default_country_code_ = MostCommonCountryCodeFromProfiles();

  // Failing that, guess based on system timezone.
  if (default_country_code_.empty())
    default_country_code_ = CountryCodeForCurrentTimezone();

  // Failing that, guess based on locale.
  if (default_country_code_.empty())
    default_country_code_ = AutofillCountry::CountryCodeForLocale(app_locale());

  return default_country_code_;
}

// static
void PersonalDataManager::DedupeCreditCardToSuggest(
    std::list<CreditCard*>* cards_to_suggest) {
  for (auto outer_it = cards_to_suggest->begin();
       outer_it != cards_to_suggest->end(); ++outer_it) {
    // If considering a full server card, look for local cards that are
    // duplicates of it and remove them.
    if ((*outer_it)->record_type() == CreditCard::FULL_SERVER_CARD) {
      for (auto inner_it = cards_to_suggest->begin();
           inner_it != cards_to_suggest->end();) {
        auto inner_it_copy = inner_it++;
        if ((*inner_it_copy)->IsLocalDuplicateOfServerCard(**outer_it))
          cards_to_suggest->erase(inner_it_copy);
      }
      // If considering a local card, look for masked server cards that are
      // duplicates of it and remove them.
    } else if ((*outer_it)->record_type() == CreditCard::LOCAL_CARD) {
      for (auto inner_it = cards_to_suggest->begin();
           inner_it != cards_to_suggest->end();) {
        auto inner_it_copy = inner_it++;
        if ((*inner_it_copy)->record_type() == CreditCard::MASKED_SERVER_CARD &&
            (*outer_it)->IsLocalDuplicateOfServerCard(**inner_it_copy)) {
          cards_to_suggest->erase(inner_it_copy);
        }
      }
    }
  }
}

void PersonalDataManager::SetProfiles(std::vector<AutofillProfile>* profiles) {
  if (is_off_the_record_)
    return;

  // Remove empty profiles from input.
  profiles->erase(std::remove_if(profiles->begin(), profiles->end(),
                                 IsEmptyFunctor<AutofillProfile>(app_locale_)),
                  profiles->end());

  if (!database_.get())
    return;

  // Any profiles that are not in the new profile list should be removed from
  // the web database.
  for (const auto& it : web_profiles_) {
    if (!FindByGUID<AutofillProfile>(*profiles, it->guid()))
      database_->RemoveAutofillProfile(it->guid());
  }

  // Update the web database with the existing profiles.
  for (const AutofillProfile& it : *profiles) {
    if (FindByGUID<AutofillProfile>(web_profiles_, it.guid()))
      database_->UpdateAutofillProfile(it);
  }

  // Add the new profiles to the web database.  Don't add a duplicate.
  for (const AutofillProfile& it : *profiles) {
    if (!FindByGUID<AutofillProfile>(web_profiles_, it.guid()) &&
        !FindByContents(web_profiles_, it))
      database_->AddAutofillProfile(it);
  }

  // Copy in the new profiles.
  web_profiles_.clear();
  for (const AutofillProfile& it : *profiles) {
    web_profiles_.push_back(std::make_unique<AutofillProfile>(it));
  }

  // Refresh our local cache and send notifications to observers.
  Refresh();
}

void PersonalDataManager::SetCreditCards(
    std::vector<CreditCard>* credit_cards) {
  if (is_off_the_record_)
    return;

  // Remove empty credit cards from input.
  credit_cards->erase(std::remove_if(credit_cards->begin(), credit_cards->end(),
                                     IsEmptyFunctor<CreditCard>(app_locale_)),
                      credit_cards->end());

  if (!database_.get())
    return;

  // Any credit cards that are not in the new credit card list should be
  // removed.
  for (const auto& card : local_credit_cards_) {
    if (!FindByGUID<CreditCard>(*credit_cards, card->guid()))
      database_->RemoveCreditCard(card->guid());
  }

  // Update the web database with the existing credit cards.
  for (const CreditCard& card : *credit_cards) {
    if (FindByGUID<CreditCard>(local_credit_cards_, card.guid()))
      database_->UpdateCreditCard(card);
  }

  // Add the new credit cards to the web database.  Don't add a duplicate.
  for (const CreditCard& card : *credit_cards) {
    if (!FindByGUID<CreditCard>(local_credit_cards_, card.guid()) &&
        !FindByContents(local_credit_cards_, card))
      database_->AddCreditCard(card);
  }

  // Copy in the new credit cards.
  local_credit_cards_.clear();
  for (const CreditCard& card : *credit_cards)
    local_credit_cards_.push_back(std::make_unique<CreditCard>(card));

  // Refresh our local cache and send notifications to observers.
  Refresh();
}

void PersonalDataManager::LoadProfiles() {
  if (!database_.get()) {
    NOTREACHED();
    return;
  }

  CancelPendingQuery(&pending_profiles_query_);
  CancelPendingQuery(&pending_server_profiles_query_);

  pending_profiles_query_ = database_->GetAutofillProfiles(this);
  pending_server_profiles_query_ = database_->GetServerProfiles(this);
}

void PersonalDataManager::LoadCreditCards() {
  if (!database_.get()) {
    NOTREACHED();
    return;
  }

  CancelPendingQuery(&pending_creditcards_query_);
  CancelPendingQuery(&pending_server_creditcards_query_);

  pending_creditcards_query_ = database_->GetCreditCards(this);
  pending_server_creditcards_query_ = database_->GetServerCreditCards(this);
}

void PersonalDataManager::CancelPendingQuery(
    WebDataServiceBase::Handle* handle) {
  if (*handle) {
    if (!database_.get()) {
      NOTREACHED();
      return;
    }
    database_->CancelRequest(*handle);
  }
  *handle = 0;
}

std::string PersonalDataManager::SaveImportedProfile(
    const AutofillProfile& imported_profile) {
  if (is_off_the_record_)
    return std::string();

  std::vector<AutofillProfile> profiles;
  std::string guid =
      MergeProfile(imported_profile, &web_profiles_, app_locale_, &profiles);
  SetProfiles(&profiles);
  return guid;
}

void PersonalDataManager::NotifyPersonalDataChanged() {
  for (PersonalDataManagerObserver& observer : observers_)
    observer.OnPersonalDataChanged();

  // If new data was synced, try to convert new server profiles and update
  // server cards.
  if (has_synced_new_data_) {
    has_synced_new_data_ = false;
    ConvertWalletAddressesAndUpdateWalletCards();
  }
}

std::string PersonalDataManager::SaveImportedCreditCard(
    const CreditCard& imported_card) {
  DCHECK(!imported_card.number().empty());
  if (is_off_the_record_)
    return std::string();

  // Set to true if |imported_card| is merged into the credit card list.
  bool merged = false;

  std::string guid = imported_card.guid();
  std::vector<CreditCard> credit_cards;
  for (auto& card : local_credit_cards_) {
    // If |imported_card| has not yet been merged, check whether it should be
    // with the current |card|.
    if (!merged && card->UpdateFromImportedCard(imported_card, app_locale_)) {
      guid = card->guid();
      merged = true;
    }

    credit_cards.push_back(*card);
  }

  if (!merged)
    credit_cards.push_back(imported_card);

  SetCreditCards(&credit_cards);
  return guid;
}

void PersonalDataManager::LogStoredProfileMetrics() const {
  if (!has_logged_stored_profile_metrics_) {
    // Update the histogram of how many addresses the user has stored.
    AutofillMetrics::LogStoredProfileCount(web_profiles_.size());

    // If the user has stored addresses, log the distribution of days since
    // their last use and how many would be considered disused.
    if (!web_profiles_.empty()) {
      size_t num_disused_profiles = 0;
      const base::Time now = AutofillClock::Now();
      for (const std::unique_ptr<AutofillProfile>& profile : web_profiles_) {
        const base::TimeDelta time_since_last_use = now - profile->use_date();
        AutofillMetrics::LogStoredProfileDaysSinceLastUse(
            time_since_last_use.InDays());
        if (time_since_last_use > kDisusedProfileTimeDelta)
          ++num_disused_profiles;
      }
      AutofillMetrics::LogStoredProfileDisusedCount(num_disused_profiles);
    }

    // Only log this info once per chrome user profile load.
    has_logged_stored_profile_metrics_ = true;
  }
}

void PersonalDataManager::LogStoredCreditCardMetrics() const {
  if (!has_logged_stored_credit_card_metrics_) {
    AutofillMetrics::LogStoredCreditCardMetrics(
        local_credit_cards_, server_credit_cards_, kDisusedProfileTimeDelta);

    // Only log this info once per chrome user profile load.
    has_logged_stored_credit_card_metrics_ = true;
  }
}

std::string PersonalDataManager::MostCommonCountryCodeFromProfiles() const {
  if (!IsAutofillEnabled())
    return std::string();

  // Count up country codes from existing profiles.
  std::map<std::string, int> votes;
  // TODO(estade): can we make this GetProfiles() instead? It seems to cause
  // errors in tests on mac trybots. See http://crbug.com/57221
  const std::vector<AutofillProfile*>& profiles = GetProfiles();
  const std::vector<std::string>& country_codes =
      CountryDataMap::GetInstance()->country_codes();
  for (size_t i = 0; i < profiles.size(); ++i) {
    std::string country_code = base::ToUpperASCII(
        base::UTF16ToASCII(profiles[i]->GetRawInfo(ADDRESS_HOME_COUNTRY)));

    if (base::ContainsValue(country_codes, country_code)) {
      // Verified profiles count 100x more than unverified ones.
      votes[country_code] += profiles[i]->IsVerified() ? 100 : 1;
    }
  }

  // Take the most common country code.
  if (!votes.empty()) {
    std::map<std::string, int>::iterator iter =
        std::max_element(votes.begin(), votes.end(), CompareVotes);
    return iter->first;
  }

  return std::string();
}

void PersonalDataManager::EnabledPrefChanged() {
  default_country_code_.clear();
  if (!pref_service_->GetBoolean(prefs::kAutofillWalletImportEnabled)) {
    // Re-mask all server cards when the user turns off wallet card
    // integration.
    ResetFullServerCards();
  }
  NotifyPersonalDataChanged();
}

bool PersonalDataManager::IsKnownCard(const CreditCard& credit_card) {
  const auto stripped_pan = CreditCard::StripSeparators(credit_card.number());
  for (const auto& card : local_credit_cards_) {
    if (stripped_pan == CreditCard::StripSeparators(card->number()))
      return true;
  }

  const auto masked_info = credit_card.NetworkAndLastFourDigits();
  for (const auto& card : server_credit_cards_) {
    switch (card->record_type()) {
      case CreditCard::FULL_SERVER_CARD:
        if (stripped_pan == CreditCard::StripSeparators(card->number()))
          return true;
        break;
      case CreditCard::MASKED_SERVER_CARD:
        if (masked_info == card->NetworkAndLastFourDigits())
          return true;
        break;
      default:
        NOTREACHED();
    }
  }

  return false;
}

std::vector<Suggestion> PersonalDataManager::GetSuggestionsForCards(
    const AutofillType& type,
    const base::string16& field_contents,
    const std::vector<CreditCard*>& cards_to_suggest) const {
  std::vector<Suggestion> suggestions;
  base::string16 field_contents_lower = base::i18n::ToLower(field_contents);
  for (const CreditCard* credit_card : cards_to_suggest) {
    // The value of the stored data for this field type in the |credit_card|.
    base::string16 creditcard_field_value =
        credit_card->GetInfo(type, app_locale_);
    if (creditcard_field_value.empty())
      continue;
    base::string16 creditcard_field_lower =
        base::i18n::ToLower(creditcard_field_value);

    bool prefix_matched_suggestion;
    if (IsValidSuggestionForFieldContents(
            creditcard_field_lower, field_contents_lower, type,
            credit_card->record_type() == CreditCard::MASKED_SERVER_CARD,
            &prefix_matched_suggestion)) {
      // Make a new suggestion.
      suggestions.push_back(Suggestion());
      Suggestion* suggestion = &suggestions.back();

      suggestion->value = credit_card->GetInfo(type, app_locale_);
      suggestion->icon = base::UTF8ToUTF16(credit_card->network());
      suggestion->backend_id = credit_card->guid();
      suggestion->match = prefix_matched_suggestion
                              ? Suggestion::PREFIX_MATCH
                              : Suggestion::SUBSTRING_MATCH;

      // If the value is the card number, the label is the expiration date.
      // Otherwise the label is the card number, or if that is empty the
      // cardholder name. The label should never repeat the value.
      if (type.GetStorableType() == CREDIT_CARD_NUMBER) {
        suggestion->value = credit_card->NetworkOrBankNameAndLastFourDigits();
        if (IsAutofillCreditCardLastUsedDateDisplayExperimentEnabled()) {
          suggestion->label =
              credit_card->GetLastUsedDateForDisplay(app_locale_);
        } else {
          suggestion->label = credit_card->GetInfo(
              AutofillType(CREDIT_CARD_EXP_DATE_2_DIGIT_YEAR), app_locale_);
        }
        if (IsAutofillCreditCardPopupLayoutExperimentEnabled())
          ModifyAutofillCreditCardSuggestion(suggestion);
      } else if (credit_card->number().empty()) {
        if (type.GetStorableType() != CREDIT_CARD_NAME_FULL) {
          suggestion->label = credit_card->GetInfo(
              AutofillType(CREDIT_CARD_NAME_FULL), app_locale_);
        }
      } else {
#if defined(OS_ANDROID)
        // Since Android places the label on its own row, there's more
        // horizontal
        // space to work with. Show "Amex - 1234" rather than desktop's "*1234".
        suggestion->label = credit_card->NetworkOrBankNameAndLastFourDigits();
#else
        suggestion->label = base::ASCIIToUTF16("*");
        suggestion->label.append(credit_card->LastFourDigits());
#endif
      }
    }
  }

  // Prefix matches should precede other token matches.
  if (IsFeatureSubstringMatchEnabled()) {
    std::stable_sort(suggestions.begin(), suggestions.end(),
                     [](const Suggestion& a, const Suggestion& b) {
                       return a.match < b.match;
                     });
  }

  return suggestions;
}

void PersonalDataManager::ApplyProfileUseDatesFix() {
  // Don't run if the fix has already been applied.
  if (pref_service_->GetBoolean(prefs::kAutofillProfileUseDatesFixed))
    return;

  std::vector<AutofillProfile> profiles;
  bool has_changed_data = false;
  for (AutofillProfile* profile : GetProfiles()) {
    if (profile->use_date() == base::Time()) {
      profile->set_use_date(AutofillClock::Now() -
                            base::TimeDelta::FromDays(14));
      has_changed_data = true;
    }
    profiles.push_back(*profile);
  }

  // Set the pref so that this fix is never run again.
  pref_service_->SetBoolean(prefs::kAutofillProfileUseDatesFixed, true);

  if (has_changed_data)
    SetProfiles(&profiles);
}

bool PersonalDataManager::ApplyDedupingRoutine() {
  if (!is_autofill_profile_cleanup_pending_)
    return false;

  is_autofill_profile_cleanup_pending_ = false;

  // No need to de-duplicate if there are less than two profiles.
  if (web_profiles_.size() < 2) {
    DVLOG(1) << "Autofill profile de-duplication not needed.";
    return false;
  }

  // Check if de-duplication has already been performed this major version.
  int current_major_version = atoi(version_info::GetVersionNumber().c_str());
  if (pref_service_->GetInteger(prefs::kAutofillLastVersionDeduped) >=
      current_major_version) {
    DVLOG(1)
        << "Autofill profile de-duplication already performed for this version";
    return false;
  }

  DVLOG(1) << "Starting autofill profile de-duplication.";
  std::unordered_set<AutofillProfile*> profiles_to_delete;
  profiles_to_delete.reserve(web_profiles_.size());

  // Create the map used to update credit card's billing addresses after the
  // dedupe.
  std::unordered_map<std::string, std::string> guids_merge_map;

  DedupeProfiles(&web_profiles_, &profiles_to_delete, &guids_merge_map);

  // Apply the profile changes to the database.
  for (const auto& profile : web_profiles_) {
    // If the profile was set to be deleted, remove it from the database.
    if (profiles_to_delete.count(profile.get())) {
      database_->RemoveAutofillProfile(profile->guid());
    } else {
      // Otherwise, update the profile in the database.
      database_->UpdateAutofillProfile(*profile);
    }
  }

  UpdateCardsBillingAddressReference(guids_merge_map);

  // Set the pref to the current major version.
  pref_service_->SetInteger(prefs::kAutofillLastVersionDeduped,
                            current_major_version);

  // Refresh the local cache and send notifications to observers.
  Refresh();

  return true;
}

void PersonalDataManager::DedupeProfiles(
    std::vector<std::unique_ptr<AutofillProfile>>* existing_profiles,
    std::unordered_set<AutofillProfile*>* profiles_to_delete,
    std::unordered_map<std::string, std::string>* guids_merge_map) {
  AutofillMetrics::LogNumberOfProfilesConsideredForDedupe(
      existing_profiles->size());

  // Sort the profiles by frecency with all the verified profiles at the end.
  // That way the most relevant profiles will get merged into the less relevant
  // profiles, which keeps the syntax of the most relevant profiles data.
  // Verified profiles are put at the end because they do not merge into other
  // profiles, so the loop can be stopped when we reach those. However they need
  // to be in the vector because an unverified profile trying to merge into a
  // similar verified profile will be discarded.
  base::Time comparison_time = AutofillClock::Now();
  std::sort(existing_profiles->begin(), existing_profiles->end(),
            [comparison_time](const std::unique_ptr<AutofillProfile>& a,
                              const std::unique_ptr<AutofillProfile>& b) {
              if (a->IsVerified() != b->IsVerified())
                return !a->IsVerified();
              return a->CompareFrecency(b.get(), comparison_time);
            });

  AutofillProfileComparator comparator(app_locale_);

  for (size_t i = 0; i < existing_profiles->size(); ++i) {
    AutofillProfile* profile_to_merge = (*existing_profiles)[i].get();

    // If the profile was set to be deleted, skip it. It has already been
    // merged into another profile.
    if (profiles_to_delete->count(profile_to_merge))
      continue;

    // If we have reached the verified profiles, stop trying to merge. Verified
    // profiles do not get merged.
    if (profile_to_merge->IsVerified())
      break;

    // If we have not reached the last profile, try to merge |profile_to_merge|
    // with all the less relevant |existing_profiles|.
    for (size_t j = i + 1; j < existing_profiles->size(); ++j) {
      AutofillProfile* existing_profile = (*existing_profiles)[j].get();

      // Don't try to merge a profile that was already set for deletion.
      if (profiles_to_delete->count(existing_profile))
        continue;

      // Move on if the profiles are not mergeable.
      if (!comparator.AreMergeable(*existing_profile, *profile_to_merge))
        continue;

      // The profiles are found to be mergeable. Attempt to update the existing
      // profile. This returns true if the merge was successful, or if the
      // merge would have been successful but the existing profile IsVerified()
      // and will not accept updates from profile_to_merge.
      if (existing_profile->SaveAdditionalInfo(*profile_to_merge,
                                               app_locale_)) {
        // Keep track that a credit card using |profile_to_merge|'s GUID as its
        // billing address id should replace it by |existing_profile|'s GUID.
        guids_merge_map->insert(std::pair<std::string, std::string>(
            profile_to_merge->guid(), existing_profile->guid()));

        // Since |profile_to_merge| was a duplicate of |existing_profile|
        // and was merged successfully, it can now be deleted.
        profiles_to_delete->insert(profile_to_merge);

        // Now try to merge the new resulting profile with the rest of the
        // existing profiles.
        profile_to_merge = existing_profile;

        // Verified profiles do not get merged. Save some time by not
        // trying.
        if (profile_to_merge->IsVerified())
          break;
      }
    }
  }
  AutofillMetrics::LogNumberOfProfilesRemovedDuringDedupe(
      profiles_to_delete->size());
}

void PersonalDataManager::UpdateCardsBillingAddressReference(
    const std::unordered_map<std::string, std::string>& guids_merge_map) {
  /*  Here is an example of what the graph might look like.

      A -> B
             \
               -> E
             /
      C -> D
  */

  for (auto* credit_card : GetCreditCards()) {
    // If the credit card is not associated with a billing address, skip it.
    if (credit_card->billing_address_id().empty())
      break;

    // If the billing address profile associated with the card has been merged,
    // replace it by the id of the profile in which it was merged. Repeat the
    // process until the billing address has not been merged into another one.
    std::unordered_map<std::string, std::string>::size_type nb_guid_changes = 0;
    bool was_modified = false;
    auto it = guids_merge_map.find(credit_card->billing_address_id());
    while (it != guids_merge_map.end()) {
      was_modified = true;
      credit_card->set_billing_address_id(it->second);
      it = guids_merge_map.find(credit_card->billing_address_id());

      // Out of abundance of caution.
      if (nb_guid_changes > guids_merge_map.size()) {
        NOTREACHED();
        // Cancel the changes for that card.
        was_modified = false;
        break;
      }
    }

    // If the card was modified, apply the changes to the database.
    if (was_modified) {
      if (credit_card->record_type() == CreditCard::LOCAL_CARD)
        database_->UpdateCreditCard(*credit_card);
      else
        database_->UpdateServerCardMetadata(*credit_card);
    }
  }
}

void PersonalDataManager::ConvertWalletAddressesAndUpdateWalletCards() {
  // Copy the local profiles into a vector<AutofillProfile>. Theses are the
  // existing profiles. Get them sorted in decreasing order of frecency, so the
  // "best" profiles are checked first. Put the verified profiles last so the
  // server addresses have a chance to merge into the non-verified local
  // profiles.
  std::vector<AutofillProfile> local_profiles;
  for (AutofillProfile* existing_profile : GetProfilesToSuggest()) {
    local_profiles.push_back(*existing_profile);
  }

  // Since we are already iterating on all the server profiles to convert Wallet
  // addresses and we will need to access them by guid later to update the
  // Wallet cards, create a map here.
  std::unordered_map<std::string, AutofillProfile*> server_id_profiles_map;

  // Create the map used to update credit card's billing addresses after the
  // convertion/merge.
  std::unordered_map<std::string, std::string> guids_merge_map;

  bool has_converted_addresses = ConvertWalletAddressesToLocalProfiles(
      &local_profiles, &server_id_profiles_map, &guids_merge_map);
  bool should_update_cards = UpdateWalletCardsAlreadyConvertedBillingAddresses(
      &local_profiles, &server_id_profiles_map, &guids_merge_map);

  if (has_converted_addresses) {
    // Save the local profiles to the DB.
    SetProfiles(&local_profiles);
  }

  if (should_update_cards || has_converted_addresses) {
    // Update the credit cards billing address relationship.
    UpdateCardsBillingAddressReference(guids_merge_map);

    // Force a reload of the profiles and cards.
    Refresh();
  }
}

bool PersonalDataManager::ConvertWalletAddressesToLocalProfiles(
    std::vector<AutofillProfile>* local_profiles,
    std::unordered_map<std::string, AutofillProfile*>* server_id_profiles_map,
    std::unordered_map<std::string, std::string>* guids_merge_map) {
  bool has_converted_addresses = false;
  for (std::unique_ptr<AutofillProfile>& wallet_address : server_profiles_) {
    // Add the profile to the map.
    server_id_profiles_map->insert(
        std::make_pair(wallet_address->server_id(), wallet_address.get()));

    // If the address has not been converted yet, convert it.
    if (!wallet_address->has_converted()) {
      // Try to merge the server address into a similar local profile, or create
      // a new local profile if no similar profile is found.
      std::string address_guid =
          MergeServerAddressesIntoProfiles(*wallet_address, local_profiles);

      // Update the map to transfer the billing address relationship from the
      // server address to the converted/merged local profile.
      guids_merge_map->insert(std::pair<std::string, std::string>(
          wallet_address->server_id(), address_guid));

      // Update the wallet addresses metadata to record the conversion.
      wallet_address->set_has_converted(true);
      database_->UpdateServerAddressMetadata(*wallet_address);

      has_converted_addresses = true;
    }
  }

  return has_converted_addresses;
}

bool PersonalDataManager::UpdateWalletCardsAlreadyConvertedBillingAddresses(
    std::vector<AutofillProfile>* local_profiles,
    std::unordered_map<std::string, AutofillProfile*>* server_id_profiles_map,
    std::unordered_map<std::string, std::string>* guids_merge_map) {
  // Look for server cards that still refer to server addresses but for which
  // there is no mapping. This can happen if it's a new card for which the
  // billing address has already been converted. This should be a no-op for most
  // situations. Otherwise, it should affect only one Wallet card, sinces users
  // do not add a lot of credit cards.
  AutofillProfileComparator comparator(app_locale_);
  bool should_update_cards = false;
  for (std::unique_ptr<CreditCard>& wallet_card : server_credit_cards_) {
    std::string billing_address_id = wallet_card->billing_address_id();

    // If billing address refers to a server id and that id is not a key in the
    // guids_merge_map, it means that the card is new but the address was
    // already converted. Look for the matching converted profile.
    if (!billing_address_id.empty() &&
        billing_address_id.length() != LOCAL_GUID_LENGTH &&
        guids_merge_map->find(billing_address_id) == guids_merge_map->end()) {
      // Get the profile.
      auto it = server_id_profiles_map->find(billing_address_id);
      if (it != server_id_profiles_map->end()) {
        AutofillProfile* billing_address = it->second;

        // Look for a matching local profile (DO NOT MERGE).
        bool matching_profile_found = false;
        for (auto& local_profile : *local_profiles) {
          if (!matching_profile_found &&
              comparator.AreMergeable(*billing_address, local_profile)) {
            matching_profile_found = true;

            // The Wallet address matches this local profile. Add this to the
            // merge mapping.
            guids_merge_map->insert(std::pair<std::string, std::string>(
                billing_address_id, local_profile.guid()));
            should_update_cards = true;
          }
        }
      }
    }
  }

  return should_update_cards;
}

// TODO(crbug.com/687975): Reuse MergeProfiles in this function.
std::string PersonalDataManager::MergeServerAddressesIntoProfiles(
    const AutofillProfile& server_address,
    std::vector<AutofillProfile>* existing_profiles) {
  // Set to true if |existing_profiles| already contains an equivalent profile.
  bool matching_profile_found = false;
  std::string guid = server_address.guid();

  // If there is already a local profile that is very similar, merge in any
  // missing values. Only merge with the first match.
  AutofillProfileComparator comparator(app_locale_);
  for (auto& local_profile : *existing_profiles) {
    if (!matching_profile_found &&
        comparator.AreMergeable(server_address, local_profile) &&
        local_profile.SaveAdditionalInfo(server_address, app_locale_)) {
      matching_profile_found = true;
      local_profile.set_modification_date(AutofillClock::Now());
      guid = local_profile.guid();
      AutofillMetrics::LogWalletAddressConversionType(
          AutofillMetrics::CONVERTED_ADDRESS_MERGED);
    }
  }

  // If the server address was not merged with a local profile, add it to the
  // list.
  if (!matching_profile_found) {
    existing_profiles->push_back(server_address);
    // Set the profile as being local.
    existing_profiles->back().set_record_type(AutofillProfile::LOCAL_PROFILE);
    existing_profiles->back().set_modification_date(AutofillClock::Now());

    // Wallet addresses don't have an email address, use the one from the
    // currently signed-in account.
    base::string16 email =
        base::UTF8ToUTF16(identity_manager_->GetPrimaryAccountInfo().email);
    if (!email.empty())
      existing_profiles->back().SetRawInfo(EMAIL_ADDRESS, email);

    AutofillMetrics::LogWalletAddressConversionType(
        AutofillMetrics::CONVERTED_ADDRESS_ADDED);
  }

  return guid;
}

void PersonalDataManager::CreateTestAddresses() {
  if (has_created_test_addresses_)
    return;

  has_created_test_addresses_ = true;
  if (!base::FeatureList::IsEnabled(kAutofillCreateDataForTest))
    return;

  AddProfile(CreateBasicTestAddress(app_locale_));
  AddProfile(CreateDisusedTestAddress(app_locale_));
  AddProfile(CreateDisusedDeletableTestAddress(app_locale_));
}

void PersonalDataManager::CreateTestCreditCards() {
  if (has_created_test_credit_cards_)
    return;

  has_created_test_credit_cards_ = true;
  if (!base::FeatureList::IsEnabled(kAutofillCreateDataForTest))
    return;

  AddCreditCard(CreateBasicTestCreditCard(app_locale_));
  AddCreditCard(CreateDisusedTestCreditCard(app_locale_));
  AddCreditCard(CreateDisusedDeletableTestCreditCard(app_locale_));
}

bool PersonalDataManager::IsCreditCardDeletable(CreditCard* card) {
  const base::Time deletion_threshold =
      AutofillClock::Now() - kDisusedCreditCardDeletionTimeDelta;

  return card->use_date() < deletion_threshold &&
         card->IsExpired(deletion_threshold);
}

bool PersonalDataManager::DeleteDisusedCreditCards() {
  if (!base::FeatureList::IsEnabled(kAutofillDeleteDisusedCreditCards)) {
    return false;
  }

  // Check if credit cards deletion has already been performed this major
  // version.
  int current_major_version = atoi(version_info::GetVersionNumber().c_str());
  if (pref_service_->GetInteger(
          prefs::kAutofillLastVersionDisusedCreditCardsDeleted) >=
      current_major_version) {
    DVLOG(1)
        << "Autofill credit cards deletion already performed for this version";
    return false;
  }

  // Set the pref to the current major version.
  pref_service_->SetInteger(
      prefs::kAutofillLastVersionDisusedCreditCardsDeleted,
      current_major_version);

  // Only delete local cards, as server cards are managed by Payments.
  auto cards = GetLocalCreditCards();

  // Early exit when there is no local cards.
  if (cards.empty()) {
    return true;
  }

  std::vector<std::string> guid_to_delete;
  for (CreditCard* card : cards) {
    if (IsCreditCardDeletable(card)) {
      guid_to_delete.push_back(card->guid());
    }
  }

  size_t num_deleted_cards = guid_to_delete.size();

  for (auto const guid : guid_to_delete) {
    database_->RemoveCreditCard(guid);
  }

  if (num_deleted_cards > 0) {
    Refresh();
  }

  AutofillMetrics::LogNumberOfCreditCardsDeletedForDisuse(num_deleted_cards);

  return true;
}

bool PersonalDataManager::IsAddressDeletable(
    AutofillProfile* profile,
    std::unordered_set<std::string> const& used_billing_address_guids) {
  const base::Time deletion_threshold =
      AutofillClock::Now() - kDisusedAddressDeletionTimeDelta;

  return profile->use_date() < deletion_threshold && !profile->IsVerified() &&
         used_billing_address_guids.find(profile->guid()) ==
             used_billing_address_guids.end();
}

bool PersonalDataManager::DeleteDisusedAddresses() {
  if (!base::FeatureList::IsEnabled(kAutofillDeleteDisusedAddresses)) {
    return false;
  }

  // Check if address deletion has already been performed this major version.
  int current_major_version = atoi(version_info::GetVersionNumber().c_str());
  if (pref_service_->GetInteger(
          prefs::kAutofillLastVersionDisusedAddressesDeleted) >=
      current_major_version) {
    DVLOG(1)
        << "Autofill addresses deletion already performed for this version";
    return false;
  }

  // Set the pref to the current major version.
  pref_service_->SetInteger(prefs::kAutofillLastVersionDisusedAddressesDeleted,
                            current_major_version);

  const std::vector<AutofillProfile*>& profiles = GetProfiles();

  // Early exit when there are no profiles.
  if (profiles.empty()) {
    return true;
  }

  std::unordered_set<std::string> used_billing_address_guids;
  for (CreditCard* card : GetCreditCards()) {
    if (!IsCreditCardDeletable(card)) {
      used_billing_address_guids.insert(card->billing_address_id());
    }
  }

  std::vector<std::string> guids_to_delete;
  for (AutofillProfile* profile : profiles) {
    if (IsAddressDeletable(profile, used_billing_address_guids)) {
      guids_to_delete.push_back(profile->guid());
    }
  }

  size_t num_deleted_addresses = guids_to_delete.size();

  for (auto const guid : guids_to_delete) {
    RemoveAutofillProfileByGUIDAndBlankCreditCardReferecne(guid);
  }

  if (num_deleted_addresses > 0) {
    Refresh();
  }

  AutofillMetrics::LogNumberOfAddressesDeletedForDisuse(num_deleted_addresses);

  return true;
}

bool PersonalDataManager::ShouldSuggestServerCards() const {
  if (!IsAutofillWalletImportEnabled())
    return false;

  if (is_syncing_for_test_)
    return true;

  // Server cards should be suggested if the sync service active.
  return syncer::GetUploadToGoogleState(
             sync_service_, syncer::ModelType::AUTOFILL_WALLET_DATA) ==
         syncer::UploadState::ACTIVE;
}

}  // namespace autofill

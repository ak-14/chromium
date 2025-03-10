// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_AUTOFILL_CORE_BROWSER_AUTOFILL_MANAGER_H_
#define COMPONENTS_AUTOFILL_CORE_BROWSER_AUTOFILL_MANAGER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/callback_forward.h"
#include "base/compiler_specific.h"
#include "base/containers/circular_deque.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/string16.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "build/build_config.h"
#include "components/autofill/core/browser/autocomplete_history_manager.h"
#include "components/autofill/core/browser/autofill_client.h"
#include "components/autofill/core/browser/autofill_download_manager.h"
#include "components/autofill/core/browser/autofill_driver.h"
#include "components/autofill/core/browser/autofill_handler.h"
#include "components/autofill/core/browser/autofill_metrics.h"
#include "components/autofill/core/browser/card_unmask_delegate.h"
#include "components/autofill/core/browser/field_filler.h"
#include "components/autofill/core/browser/form_data_importer.h"
#include "components/autofill/core/browser/form_structure.h"
#include "components/autofill/core/browser/form_types.h"
#include "components/autofill/core/browser/payments/full_card_request.h"
#include "components/autofill/core/browser/payments/payments_client.h"
#include "components/autofill/core/browser/personal_data_manager.h"
#include "components/autofill/core/common/form_data.h"

#if defined(OS_ANDROID) || defined(OS_IOS)
#include "components/autofill/core/browser/autofill_assistant.h"
#endif

namespace gfx {
class RectF;
}

namespace user_prefs {
class PrefRegistrySyncable;
}

namespace autofill {

class AutofillDataModel;
class AutofillDownloadManager;
class AutofillExternalDelegate;
class AutofillField;
class AutofillClient;
class AutofillManagerTestDelegate;
class AutofillProfile;
class AutofillType;
class CreditCard;
class FormStructureBrowserTest;

struct FormData;
struct FormFieldData;

// We show the credit card signin promo only a certain number of times.
extern const int kCreditCardSigninPromoImpressionLimit;

// Manages saving and restoring the user's personal information entered into web
// forms. One per frame; owned by the AutofillDriver.
class AutofillManager : public AutofillHandler,
                        public AutofillDownloadManager::Observer,
                        public payments::PaymentsClientUnmaskDelegate,
                        public payments::FullCardRequest::ResultDelegate,
                        public payments::FullCardRequest::UIDelegate {
 public:
  // Registers our Enable/Disable Autofill pref.
  static void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry);

  AutofillManager(AutofillDriver* driver,
                  AutofillClient* client,
                  const std::string& app_locale,
                  AutofillDownloadManagerState enable_download_manager);
  ~AutofillManager() override;

  // Sets an external delegate.
  void SetExternalDelegate(AutofillExternalDelegate* delegate);

  void ShowAutofillSettings();

  // Whether the |field| should show an entry to scan a credit card.
  virtual bool ShouldShowScanCreditCard(const FormData& form,
                                        const FormFieldData& field);

  // Whether the |field| belongs to CREDIT_CARD |FieldTypeGroup|.
  virtual bool IsCreditCardPopup(const FormData& form,
                                 const FormFieldData& field);

  // Whether we should show the signin promo, based on the triggered |field|
  // inside the |form|.
  virtual bool ShouldShowCreditCardSigninPromo(const FormData& form,
                                               const FormFieldData& field);

  // Called from our external delegate so they cannot be private.
  virtual void FillOrPreviewForm(AutofillDriver::RendererFormDataAction action,
                                 int query_id,
                                 const FormData& form,
                                 const FormFieldData& field,
                                 int unique_id);
  virtual void FillCreditCardForm(int query_id,
                                  const FormData& form,
                                  const FormFieldData& field,
                                  const CreditCard& credit_card,
                                  const base::string16& cvc);
  void DidShowSuggestions(bool is_new_popup,
                          const FormData& form,
                          const FormFieldData& field);

  // Returns true if the value/identifier is deletable. Fills out
  // |title| and |body| with relevant user-facing text.
  bool GetDeletionConfirmationText(const base::string16& value,
                                   int identifier,
                                   base::string16* title,
                                   base::string16* body);

  // Remove the credit card or Autofill profile that matches |unique_id|
  // from the database. Returns true if deletion is allowed.
  bool RemoveAutofillProfileOrCreditCard(int unique_id);

  // Remove the specified Autocomplete entry.
  void RemoveAutocompleteEntry(const base::string16& name,
                               const base::string16& value);

  // Returns true when the Payments card unmask prompt is being displayed.
  bool IsShowingUnmaskPrompt();

  // Returns the present form structures seen by Autofill manager.
  const std::vector<std::unique_ptr<FormStructure>>& GetFormStructures();

  AutofillClient* client() { return client_; }

  AutofillDownloadManager* download_manager() {
    return download_manager_.get();
  }

  payments::FullCardRequest* GetOrCreateFullCardRequest();

  payments::FullCardRequest* CreateFullCardRequest(
      const base::TimeTicks& form_parsed_timestamp);

  base::WeakPtr<payments::FullCardRequest::UIDelegate>
  GetAsFullCardRequestUIDelegate() {
    return weak_ptr_factory_.GetWeakPtr();
  }

  const std::string& app_locale() const { return app_locale_; }

  // Only for testing.
  void SetTestDelegate(AutofillManagerTestDelegate* delegate);

  // Will send an upload based on the |form_structure| data and the local
  // Autofill profile data. |observed_submission| is specified if the upload
  // follows an observed submission event.
  // return false if the upload couldn't start.
  virtual bool StartUploadProcess(std::unique_ptr<FormStructure> form_structure,
                                  const base::TimeTicks& timestamp,
                                  bool observed_submission);

  // Update the pending form with |form|, possibly processing the current
  // pending form for upload.
  void UpdatePendingForm(const FormData& form);

  // Upload the current pending form.
  void ProcessPendingFormForUpload();

  // AutofillHandler:
  void OnFocusNoLongerOnForm() override;
  void OnDidFillAutofillFormData(const FormData& form,
                                 const base::TimeTicks timestamp) override;
  void OnDidPreviewAutofillFormData() override;
  void OnFormsSeen(const std::vector<FormData>& forms,
                   const base::TimeTicks timestamp) override;
  void OnDidEndTextFieldEditing() override;
  void OnHidePopup() override;
  void OnSetDataList(const std::vector<base::string16>& values,
                     const std::vector<base::string16>& labels) override;
  void SelectFieldOptionsDidChange(const FormData& form) override;
  void Reset() override;

  // Returns true if the value of the AutofillEnabled pref is true and the
  // client supports Autofill.
  virtual bool IsAutofillEnabled() const;

  // Returns true if the value of the AutofillCreditCardEnabled pref is true and
  // the client supports Autofill.
  virtual bool IsCreditCardAutofillEnabled();

  // Shared code to determine if |form| should be uploaded to the Autofill
  // server. It verifies that uploading is allowed and |form| meets conditions
  // to be uploadable. Exposed for testing.
  bool ShouldUploadForm(const FormStructure& form);

 protected:
  // Test code should prefer to use this constructor.
  AutofillManager(AutofillDriver* driver,
                  AutofillClient* client,
                  PersonalDataManager* personal_data,
                  const std::string app_locale = "en-US",
                  AutofillDownloadManagerState enable_download_manager =
                      DISABLE_AUTOFILL_DOWNLOAD_MANAGER);

  // Uploads the form data to the Autofill server. |observed_submission|
  // indicates that upload is the result of a submission event.
  virtual void UploadFormData(const FormStructure& submitted_form,
                              bool observed_submission);

  // Logs quality metrics for the |submitted_form| and uploads the form data
  // to the crowdsourcing server, if appropriate. |observed_submission|
  // indicates whether the upload is a result of an observed submission event.
  virtual void UploadFormDataAsyncCallback(
      const FormStructure* submitted_form,
      const base::TimeTicks& load_time,
      const base::TimeTicks& interaction_time,
      const base::TimeTicks& submission_time,
      bool observed_submission);

  // Maps suggestion backend ID to and from an integer identifying it. Two of
  // these intermediate integers are packed by MakeFrontendID to make the IDs
  // that this class generates for the UI and for IPC.
  virtual int BackendIDToInt(const std::string& backend_id) const;
  virtual std::string IntToBackendID(int int_id) const;

  // Methods for packing and unpacking credit card and profile IDs for sending
  // and receiving to and from the renderer process.
  int MakeFrontendID(const std::string& cc_backend_id,
                     const std::string& profile_backend_id) const;
  void SplitFrontendID(int frontend_id,
                       std::string* cc_backend_id,
                       std::string* profile_backend_id) const;

  // AutofillHandler:
  bool OnFormSubmittedImpl(const FormData& form,
                           bool known_success,
                           SubmissionSource source,
                           base::TimeTicks timestamp) override;
  void OnTextFieldDidChangeImpl(const FormData& form,
                                const FormFieldData& field,
                                const gfx::RectF& bounding_box,
                                const base::TimeTicks timestamp) override;
  void OnTextFieldDidScrollImpl(const FormData& form,
                                const FormFieldData& field,
                                const gfx::RectF& bounding_box) override {}
  void OnQueryFormFieldAutofillImpl(int query_id,
                                    const FormData& form,
                                    const FormFieldData& field,
                                    const gfx::RectF& transformed_box) override;
  void OnFocusOnFormFieldImpl(const FormData& form,
                              const FormFieldData& field,
                              const gfx::RectF& bounding_box) override;
  void OnSelectControlDidChangeImpl(const FormData& form,
                                    const FormFieldData& field,
                                    const gfx::RectF& bounding_box) override;

  std::vector<std::unique_ptr<FormStructure>>* form_structures() {
    return &form_structures_;
  }

  AutofillMetrics::FormInteractionsUkmLogger* form_interactions_ukm_logger() {
    return form_interactions_ukm_logger_.get();
  }

  // Exposed for testing.
  AutofillExternalDelegate* external_delegate() { return external_delegate_; }

  // Exposed for testing.
  void set_download_manager(AutofillDownloadManager* manager) {
    download_manager_.reset(manager);
  }

  // Exposed for testing.
  void set_payments_client(payments::PaymentsClient* payments_client) {
    payments_client_.reset(payments_client);
  }

  // Exposed for testing.
  void set_form_data_importer(FormDataImporter* form_data_importer) {
    form_data_importer_.reset(form_data_importer);
  }

 private:
  // Keeps track of the filling context for a form, used to make refill attemps.
  struct FillingContext {
    FillingContext();
    ~FillingContext();

    // Whether a refill attempt was made.
    bool attempted_refill = false;
    // The profile that was used for the initial fill.
    AutofillProfile temp_data_model;
    // The name of the field that was initially filled.
    base::string16 filled_field_name;
    // The time at which the initial fill occured.
    base::TimeTicks original_fill_time;
    // The timer used to trigger a refill.
    base::OneShotTimer on_refill_timer;
    // The field type groups that were initially filled.
    std::set<FieldTypeGroup> type_groups_originally_filled;
  };

  // AutofillDownloadManager::Observer:
  void OnLoadedServerPredictions(
      std::string response,
      const std::vector<std::string>& form_signatures) override;

  // payments::PaymentsClientUnmaskDelegate:
  void OnDidGetRealPan(AutofillClient::PaymentsRpcResult result,
                       const std::string& real_pan) override;

  // payments::FullCardRequest::ResultDelegate:
  void OnFullCardRequestSucceeded(
      const payments::FullCardRequest& full_card_request,
      const CreditCard& card,
      const base::string16& cvc) override;
  void OnFullCardRequestFailed() override;

  // payments::FullCardRequest::UIDelegate:
  void ShowUnmaskPrompt(const CreditCard& card,
                        AutofillClient::UnmaskCardReason reason,
                        base::WeakPtr<CardUnmaskDelegate> delegate) override;
  void OnUnmaskVerificationResult(
      AutofillClient::PaymentsRpcResult result) override;

  // Returns false if Autofill is disabled or if no Autofill data is available.
  bool RefreshDataModels();

  // Gets the profile referred by |unique_id|. Returns true if the profile
  // exists.
  bool GetProfile(int unique_id, const AutofillProfile** profile);

  // Gets the credit card referred by |unique_id|. Returns true if the credit
  // card exists.
  bool GetCreditCard(int unique_id, const CreditCard** credit_card);

  // Determines whether a fill on |form| initiated from |field| will wind up
  // filling a credit card number. This is useful to determine if we will need
  // to unmask a card.
  bool WillFillCreditCardNumber(const FormData& form,
                                const FormFieldData& field);

  // Fills or previews the credit card form.
  // Assumes the form and field are valid.
  void FillOrPreviewCreditCardForm(
      AutofillDriver::RendererFormDataAction action,
      int query_id,
      const FormData& form,
      const FormFieldData& field,
      const CreditCard& credit_card);

  // Fills or previews the profile form.
  // Assumes the form and field are valid.
  void FillOrPreviewProfileForm(AutofillDriver::RendererFormDataAction action,
                                int query_id,
                                const FormData& form,
                                const FormFieldData& field,
                                const AutofillProfile& profile);

  // Fills or previews |data_model| in the |form|.
  void FillOrPreviewDataModelForm(AutofillDriver::RendererFormDataAction action,
                                  int query_id,
                                  const FormData& form,
                                  const FormFieldData& field,
                                  const AutofillDataModel& data_model,
                                  bool is_credit_card,
                                  const base::string16& cvc,
                                  FormStructure* form_structure,
                                  AutofillField* autofill_field,
                                  bool is_refill = false);

  // Creates a FormStructure using the FormData received from the renderer. Will
  // return an empty scoped_ptr if the data should not be processed for upload
  // or personal data.
  std::unique_ptr<FormStructure> ValidateSubmittedForm(const FormData& form);

  // Fills |form_structure| cached element corresponding to |form|.
  // Returns false if the cached element was not found.
  bool FindCachedForm(const FormData& form,
                      FormStructure** form_structure) const WARN_UNUSED_RESULT;

  // Fills |form_structure| and |autofill_field| with the cached elements
  // corresponding to |form| and |field|.  This might have the side-effect of
  // updating the cache.  Returns false if the |form| is not autofillable, or if
  // it is not already present in the cache and the cache is full.
  bool GetCachedFormAndField(const FormData& form,
                             const FormFieldData& field,
                             FormStructure** form_structure,
                             AutofillField** autofill_field) WARN_UNUSED_RESULT;

  // Returns the field corresponding to |form| and |field| that can be
  // autofilled. Returns NULL if the field cannot be autofilled.
  AutofillField* GetAutofillField(const FormData& form,
                                  const FormFieldData& field)
      WARN_UNUSED_RESULT;

  // Re-parses |live_form| and adds the result to |form_structures_|.
  // |cached_form| should be a pointer to the existing version of the form, or
  // NULL if no cached version exists.  The updated form is then written into
  // |updated_form|.  Returns false if the cache could not be updated.
  bool UpdateCachedForm(const FormData& live_form,
                        const FormStructure* cached_form,
                        FormStructure** updated_form) WARN_UNUSED_RESULT;

  // Returns a list of values from the stored profiles that match |type| and the
  // value of |field| and returns the labels of the matching profiles. |labels|
  // is filled with the Profile label.
  std::vector<Suggestion> GetProfileSuggestions(
      const FormStructure& form,
      const FormFieldData& field,
      const AutofillField& autofill_field) const;

  // Returns a list of values from the stored credit cards that match |type| and
  // the value of |field| and returns the labels of the matching credit cards.
  // |is_all_server_suggestions| will be set to true if there is no credit card
  // suggestions or all suggestions come from Payments server.
  std::vector<Suggestion> GetCreditCardSuggestions(
      const FormFieldData& field,
      const AutofillType& type,
      bool* is_all_server_suggestions) const;

  // Parses the forms using heuristic matching and querying the Autofill server.
  void ParseForms(const std::vector<FormData>& forms);

  // Parses the |form| with the server data retrieved from the |cached_form|
  // (if any), and writes it to the |parse_form_structure|. Adds the
  // |parse_form_structure| to the |form_structures_|. Returns true if the form
  // is parsed.
  bool ParseForm(const FormData& form,
                 const FormStructure* cached_form,
                 FormStructure** parsed_form_structure);

  // If |initial_interaction_timestamp_| is unset or is set to a later time than
  // |interaction_timestamp|, updates the cached timestamp.  The latter check is
  // needed because IPC messages can arrive out of order.
  void UpdateInitialInteractionTimestamp(
      const base::TimeTicks& interaction_timestamp);

  // Examines |form| and returns true if it is in a non-secure context or
  // its action attribute targets a HTTP url.
  bool IsFormNonSecure(const FormData& form) const;

  // Uses the existing personal data in |profiles| and |credit_cards| to
  // determine possible field types for the |submitted_form|.  This is
  // potentially expensive -- on the order of 50ms even for a small set of
  // |stored_data|. Hence, it should not run on the UI thread -- to avoid
  // locking up the UI -- nor on the IO thread -- to avoid blocking IPC calls.
  static void DeterminePossibleFieldTypesForUpload(
      const std::vector<AutofillProfile>& profiles,
      const std::vector<CreditCard>& credit_cards,
      const std::string& app_locale,
      FormStructure* submitted_form);

  // Uses context about previous and next fields to select the appropriate type
  // for fields with ambiguous upload types.
  static void DisambiguateUploadTypes(FormStructure* form);

  // Disambiguates address field upload types.
  static void DisambiguateAddressUploadTypes(FormStructure* form,
                                             size_t current_index);

  // Disambiguates phone field upload types.
  static void DisambiguatePhoneUploadTypes(FormStructure* form,
                                           size_t current_index);

  // Disambiguates name field upload types.
  static void DisambiguateNameUploadTypes(
      FormStructure* form,
      size_t current_index,
      const ServerFieldTypeSet& upload_types);

  void FillFieldWithValue(AutofillField* autofill_field,
                          const AutofillDataModel& data_model,
                          FormFieldData* field_data,
                          bool should_notify,
                          const base::string16& cvc);

  AutofillMetrics::CardNumberStatus GetCardNumberStatus(
      CreditCard& credit_card);

  // Whether there should be an attemps to refill the form. Returns true if all
  // the following are satisfied:
  //  There have been no refill on that page yet.
  //  A non empty form name was recorded in a previous fill
  //  That form name matched the currently parsed form name
  //  It's been less than kLimitBeforeRefillMs since the original fill.
  bool ShouldTriggerRefill(const FormStructure& form_structure);

  // Attempts to refill the form that was changed dynamically. Should only be
  // called if ShouldTriggerRefill returns true.
  void TriggerRefill(const FormData& form, FormStructure* form_structure);

  AutofillClient* const client_;

  // Handles Payments service requests.
  std::unique_ptr<payments::PaymentsClient> payments_client_;

  std::string app_locale_;

  // The personal data manager, used to save and load personal data to/from the
  // web database.  This is overridden by the AutofillManagerTest.
  // Weak reference.
  // May be NULL.  NULL indicates OTR.
  PersonalDataManager* personal_data_;

  // Handles importing of address and credit card data from forms.
  // Must be initialized (and thus listed) after payments_client_.
  std::unique_ptr<FormDataImporter> form_data_importer_;

  // Used to help fill data into fields.
  FieldFiller field_filler_;

  base::circular_deque<std::string> autofilled_form_signatures_;

  // Handles queries and uploads to Autofill servers. Will be NULL if
  // the download manager functionality is disabled.
  std::unique_ptr<AutofillDownloadManager> download_manager_;

  // Handles single-field autocomplete form data.
  std::unique_ptr<AutocompleteHistoryManager> autocomplete_history_manager_;

  // Utility for logging URL keyed metrics.
  std::unique_ptr<AutofillMetrics::FormInteractionsUkmLogger>
      form_interactions_ukm_logger_;

  // Utilities for logging form events.
  std::unique_ptr<AutofillMetrics::FormEventLogger> address_form_event_logger_;
  std::unique_ptr<AutofillMetrics::FormEventLogger>
      credit_card_form_event_logger_;

  // Have we logged whether Autofill is enabled for this page load?
  bool has_logged_autofill_enabled_ = false;
  // Have we logged an address suggestions count metric for this page?
  bool has_logged_address_suggestions_count_ = false;
  // Have we shown Autofill suggestions at least once?
  bool did_show_suggestions_ = false;
  // Has the user manually edited at least one form field among the autofillable
  // ones?
  bool user_did_type_ = false;
  // Has the user autofilled a form on this page?
  bool user_did_autofill_ = false;
  // Has the user edited a field that was previously autofilled?
  bool user_did_edit_autofilled_field_ = false;

  // When the form finished loading.
  std::map<FormData, base::TimeTicks> forms_loaded_timestamps_;
  // When the user first interacted with a potentially fillable form on this
  // page.
  base::TimeTicks initial_interaction_timestamp_;

  // Our copy of the form data.
  std::vector<std::unique_ptr<FormStructure>> form_structures_;

  // A copy of the currently interacted form data.
  std::unique_ptr<FormData> pending_form_data_;

  // Responsible for getting the full card details, including the PAN and the
  // CVC.
  std::unique_ptr<payments::FullCardRequest> full_card_request_;

  // Collected information about the autofill form where unmasked card will be
  // filled.
  int unmasking_query_id_ = -1;
  FormData unmasking_form_;
  FormFieldData unmasking_field_;
  CreditCard masked_card_;

  // Ablation experiment turns off autofill, but logging still has to be kept
  // for metrics analysis.
  bool enable_ablation_logging_ = false;

  // Suggestion backend ID to ID mapping. We keep two maps to convert back and
  // forth. These should be used only by BackendIDToInt and IntToBackendID.
  // Note that the integers are not frontend IDs.
  mutable std::map<std::string, int> backend_to_int_map_;
  mutable std::map<int, std::string> int_to_backend_map_;

  // Delegate to perform external processing (display, selection) on
  // our behalf.  Weak.
  AutofillExternalDelegate* external_delegate_ = nullptr;

  // Delegate used in test to get notifications on certain events.
  AutofillManagerTestDelegate* test_delegate_ = nullptr;

#if defined(OS_ANDROID) || defined(OS_IOS)
  AutofillAssistant autofill_assistant_;
#endif

  // A map of form names to FillingContext instances used to make refill
  // attempts for dynamic forms.
  std::map<base::string16, std::unique_ptr<FillingContext>>
      filling_contexts_map_;

  base::WeakPtrFactory<AutofillManager> weak_ptr_factory_;

  friend class AutofillManagerTest;
  friend class FormStructureBrowserTest;
  friend class SaveCardBubbleViewsBrowserTestBase;
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest,
                           DeterminePossibleFieldTypesForUpload);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest,
                           DeterminePossibleFieldTypesForUploadStressTest);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest, DisambiguateUploadTypes);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest,
                           DisabledAutofillDispatchesError);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest,
                           DetermineHeuristicsWithOverallPrediction);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, AddressFilledFormEvents);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, AddressSubmittedFormEvents);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, AddressWillSubmitFormEvents);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, AddressSuggestionsCount);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, AutofillFormSubmittedState);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, AutofillIsEnabledAtPageLoad);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, CreditCardSelectedFormEvents);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, CreditCardFilledFormEvents);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, CreditCardGetRealPanDuration);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, CreditCardWillSubmitFormEvents);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, CreditCardSubmittedFormEvents);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest,
                           CreditCardCheckoutFlowUserActions);
  FRIEND_TEST_ALL_PREFIXES(
      AutofillMetricsTest,
      CreditCardSubmittedWithoutSelectingSuggestionsNoCard);
  FRIEND_TEST_ALL_PREFIXES(
      AutofillMetricsTest,
      CreditCardSubmittedWithoutSelectingSuggestionsUnknownCard);
  FRIEND_TEST_ALL_PREFIXES(
      AutofillMetricsTest,
      CreditCardSubmittedWithoutSelectingSuggestionsKnownCard);
  FRIEND_TEST_ALL_PREFIXES(
      AutofillMetricsTest,
      ShouldNotLogSubmitWithoutSelectingSuggestionsIfSuggestionFilled);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, ProfileCheckoutFlowUserActions);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, DeveloperEngagement);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, FormFillDuration);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest,
                           NoQualityMetricsForNonAutofillableForms);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, QualityMetrics);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest,
                           QualityMetrics_BasedOnAutocomplete);
  FRIEND_TEST_ALL_PREFIXES(
      AutofillMetricsTest,
      QualityMetrics_LoggedCorrecltyForOnlyFillWhenFocusedField);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest,
                           QualityMetrics_LoggedCorrecltyForRationalizationOk);
  FRIEND_TEST_ALL_PREFIXES(
      AutofillMetricsTest,
      QualityMetrics_LoggedCorrecltyForRationalizationGood);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest,
                           QualityMetrics_LoggedCorrecltyForRationalizationBad);

  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest, SaneMetricsWithCacheMismatch);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest, TestExternalDelegate);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest,
                           TestTabContentsWithExternalDelegate);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest,
                           UserHappinessFormLoadAndSubmission);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest,
                           UserHappinessFormInteraction_AddressForm);
  FRIEND_TEST_ALL_PREFIXES(AutofillMetricsTest,
                           UserHappinessFormInteraction_CreditCardForm);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest, OnLoadedServerPredictions);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest,
                           OnLoadedServerPredictions_ResetManager);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest, DontOfferToSavePaymentsCard);
  FRIEND_TEST_ALL_PREFIXES(AutofillManagerTest, FillInUpdatedExpirationDate);
  DISALLOW_COPY_AND_ASSIGN(AutofillManager);
};

}  // namespace autofill

#endif  // COMPONENTS_AUTOFILL_CORE_BROWSER_AUTOFILL_MANAGER_H_

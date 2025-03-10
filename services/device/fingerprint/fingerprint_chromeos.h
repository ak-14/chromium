// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_DEVICE_FINGERPRINT_FINGERPRINT_CHROMEOS_H_
#define SERVICES_DEVICE_FINGERPRINT_FINGERPRINT_CHROMEOS_H_

#include <stdint.h>

#include "base/containers/queue.h"
#include "base/macros.h"
#include "chromeos/dbus/biod/biod_client.h"
#include "dbus/object_path.h"
#include "services/device/fingerprint/fingerprint_export.h"
#include "services/device/public/mojom/fingerprint.mojom.h"

namespace device {

// Implementation of Fingerprint interface for ChromeOS platform.
// This is used to connect to biod(through dbus) and perform fingerprint related
// operations. It observes signals from biod.
class SERVICES_DEVICE_FINGERPRINT_EXPORT FingerprintChromeOS
    : public mojom::Fingerprint,
      public chromeos::BiodClient::Observer {
 public:
  enum class FingerprintSession {
    NONE,
    AUTH,
    ENROLL,
  };

  explicit FingerprintChromeOS();
  ~FingerprintChromeOS() override;

  // mojom::Fingerprint:
  void GetRecordsForUser(const std::string& user_id,
                         GetRecordsForUserCallback callback) override;
  void StartEnrollSession(const std::string& user_id,
                          const std::string& label) override;
  void CancelCurrentEnrollSession(
      CancelCurrentEnrollSessionCallback callback) override;
  void RequestRecordLabel(const std::string& record_path,
                          RequestRecordLabelCallback callback) override;
  void SetRecordLabel(const std::string& record_path,
                      const std::string& new_label,
                      SetRecordLabelCallback callback) override;
  void RemoveRecord(const std::string& record_path,
                    RemoveRecordCallback callback) override;
  void StartAuthSession() override;
  void EndCurrentAuthSession(EndCurrentAuthSessionCallback callback) override;
  void DestroyAllRecords(DestroyAllRecordsCallback callback) override;
  void RequestType(RequestTypeCallback callback) override;
  void AddFingerprintObserver(mojom::FingerprintObserverPtr observer) override;

 private:
  friend class FingerprintChromeOSTest;

  // chromeos::BiodClient::Observer:
  void BiodServiceRestarted() override;
  void BiodEnrollScanDoneReceived(biod::ScanResult scan_result,
                                  bool enroll_session_complete,
                                  int percent_complete) override;
  void BiodAuthScanDoneReceived(
      biod::ScanResult scan_result,
      const chromeos::AuthScanMatches& matches) override;
  void BiodSessionFailedReceived() override;

  void OnFingerprintObserverDisconnected(mojom::FingerprintObserver* observer);
  void OnStartEnrollSession(const dbus::ObjectPath& enroll_path);
  void OnStartAuthSession(const dbus::ObjectPath& auth_path);
  void OnGetRecordsForUser(GetRecordsForUserCallback callback,
                           const std::vector<dbus::ObjectPath>& record_paths);
  void OnGetLabelFromRecordPath(size_t num_records,
                                const dbus::ObjectPath& record_path,
                                const std::string& label);

  void OnCloseEnrollSessionForAuth(bool result);
  void OnCloseAuthSessionForEnroll(const std::string& user_id,
                                   const std::string& label,
                                   bool result);
  void ScheduleStartEnroll(const std::string& user_id,
                           const std::string& label);
  void ScheduleStartAuth();

  void RunGetRecordsForUser(const std::string& user_id,
                            GetRecordsForUserCallback callback);

  // Start next request of GetRecordsForUser.
  void StartNextRequest();

  std::vector<mojom::FingerprintObserverPtr> observers_;

  // Saves record object path to label mapping for current GetRecordsForUser
  // request, and reset after the request is done.
  std::unordered_map<std::string, std::string> records_path_to_label_;

  // Callback for current GetRecordsForUser request.
  GetRecordsForUserCallback on_get_records_;

  // Pending requests of GetRecordsForUser.
  base::queue<base::OnceClosure> get_records_pending_requests_;

  // Whether a GetRecordsForUser request is in process.
  bool is_request_running_ = false;

  // Session opened by current service.
  FingerprintSession opened_session_ = FingerprintSession::NONE;

  base::WeakPtrFactory<FingerprintChromeOS> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(FingerprintChromeOS);
};

}  // namespace device

#endif  // SERVICES_DEVICE_FINGERPRINT_FINGERPRINT_CHROMEOS_H_

// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "base/memory/scoped_refptr.h"
#include "base/no_destructor.h"
#include "base/run_loop.h"
#include "base/test/null_task_runner.h"
#include "base/test/scoped_task_environment.h"
#include "base/test/simple_test_clock.h"
#include "chromeos/dbus/dbus_thread_manager.h"
#include "chromeos/services/device_sync/device_sync_impl.h"
#include "chromeos/services/device_sync/device_sync_service.h"
#include "chromeos/services/device_sync/fake_device_sync_observer.h"
#include "chromeos/services/device_sync/public/mojom/constants.mojom.h"
#include "chromeos/services/device_sync/public/mojom/device_sync.mojom.h"
#include "components/cryptauth/cryptauth_device_manager_impl.h"
#include "components/cryptauth/cryptauth_enrollment_manager_impl.h"
#include "components/cryptauth/cryptauth_gcm_manager_impl.h"
#include "components/cryptauth/fake_cryptauth_device_manager.h"
#include "components/cryptauth/fake_cryptauth_enrollment_manager.h"
#include "components/cryptauth/fake_cryptauth_gcm_manager.h"
#include "components/cryptauth/fake_gcm_device_info_provider.h"
#include "components/cryptauth/fake_remote_device_provider.h"
#include "components/cryptauth/remote_device_provider_impl.h"
#include "components/cryptauth/remote_device_test_util.h"
#include "components/gcm_driver/fake_gcm_driver.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/testing_pref_service.h"
#include "net/url_request/url_request_context_getter.h"
#include "services/identity/public/cpp/identity_test_environment.h"
#include "services/service_manager/public/cpp/test/test_connector_factory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace chromeos {

namespace device_sync {

namespace {

const char kTestEmail[] = "example@gmail.com";
const char kTestGcmDeviceInfoLongDeviceId[] = "longDeviceId";
const char kTestCryptAuthGCMRegistrationId[] = "cryptAuthRegistrationId";
const size_t kNumTestDevices = 5u;

const cryptauth::GcmDeviceInfo& GetTestGcmDeviceInfo() {
  static const base::NoDestructor<cryptauth::GcmDeviceInfo> gcm_device_info([] {
    cryptauth::GcmDeviceInfo gcm_device_info;
    gcm_device_info.set_long_device_id(kTestGcmDeviceInfoLongDeviceId);
    return gcm_device_info;
  }());

  return *gcm_device_info;
}

cryptauth::RemoteDeviceList GenerateTestRemoteDevices() {
  cryptauth::RemoteDeviceList devices =
      cryptauth::GenerateTestRemoteDevices(kNumTestDevices);

  // Load an empty set of BeaconSeeds for each device.
  // TODO(khorimoto): Adjust device_sync_mojom_traits.h/cc to allow passing
  // devices without BeaconSeeds to be sent across Mojo.
  for (auto& device : devices)
    device.LoadBeaconSeeds(std::vector<cryptauth::BeaconSeed>());

  return devices;
}

class FakeCryptAuthGCMManagerFactory
    : public cryptauth::CryptAuthGCMManagerImpl::Factory {
 public:
  FakeCryptAuthGCMManagerFactory(gcm::FakeGCMDriver* fake_gcm_driver,
                                 TestingPrefServiceSimple* test_pref_service)
      : fake_gcm_driver_(fake_gcm_driver),
        test_pref_service_(test_pref_service) {}

  ~FakeCryptAuthGCMManagerFactory() override = default;

  cryptauth::FakeCryptAuthGCMManager* instance() { return instance_; }

  // cryptauth::CryptAuthGCMManagerImpl::Factory:
  std::unique_ptr<cryptauth::CryptAuthGCMManager> BuildInstance(
      gcm::GCMDriver* gcm_driver,
      PrefService* pref_service) override {
    EXPECT_EQ(fake_gcm_driver_, gcm_driver);
    EXPECT_EQ(test_pref_service_, pref_service);

    // Only one instance is expected to be created per test.
    EXPECT_FALSE(instance_);

    auto instance = std::make_unique<cryptauth::FakeCryptAuthGCMManager>(
        kTestCryptAuthGCMRegistrationId);
    instance_ = instance.get();

    return std::move(instance);
  }

 private:
  gcm::FakeGCMDriver* fake_gcm_driver_;
  TestingPrefServiceSimple* test_pref_service_;

  cryptauth::FakeCryptAuthGCMManager* instance_ = nullptr;
};

class FakeCryptAuthDeviceManagerFactory
    : public cryptauth::CryptAuthDeviceManagerImpl::Factory {
 public:
  FakeCryptAuthDeviceManagerFactory(
      base::SimpleTestClock* simple_test_clock,
      FakeCryptAuthGCMManagerFactory* fake_cryptauth_gcm_manager_factory,
      TestingPrefServiceSimple* test_pref_service)
      : simple_test_clock_(simple_test_clock),
        fake_cryptauth_gcm_manager_factory_(fake_cryptauth_gcm_manager_factory),
        test_pref_service_(test_pref_service) {}

  ~FakeCryptAuthDeviceManagerFactory() override = default;

  cryptauth::FakeCryptAuthDeviceManager* instance() { return instance_; }

  // cryptauth::CryptAuthDeviceManagerImpl::Factory:
  std::unique_ptr<cryptauth::CryptAuthDeviceManager> BuildInstance(
      base::Clock* clock,
      cryptauth::CryptAuthClientFactory* client_factory,
      cryptauth::CryptAuthGCMManager* gcm_manager,
      PrefService* pref_service) override {
    EXPECT_EQ(simple_test_clock_, clock);
    EXPECT_EQ(fake_cryptauth_gcm_manager_factory_->instance(), gcm_manager);
    EXPECT_EQ(test_pref_service_, pref_service);

    // Only one instance is expected to be created per test.
    EXPECT_FALSE(instance_);

    auto instance = std::make_unique<cryptauth::FakeCryptAuthDeviceManager>();
    instance_ = instance.get();

    return std::move(instance);
  }

 private:
  base::SimpleTestClock* simple_test_clock_;
  FakeCryptAuthGCMManagerFactory* fake_cryptauth_gcm_manager_factory_;
  TestingPrefServiceSimple* test_pref_service_;

  cryptauth::FakeCryptAuthDeviceManager* instance_ = nullptr;
};

class FakeCryptAuthEnrollmentManagerFactory
    : public cryptauth::CryptAuthEnrollmentManagerImpl::Factory {
 public:
  FakeCryptAuthEnrollmentManagerFactory(
      base::SimpleTestClock* simple_test_clock,
      FakeCryptAuthGCMManagerFactory* fake_cryptauth_gcm_manager_factory,
      TestingPrefServiceSimple* test_pref_service)
      : simple_test_clock_(simple_test_clock),
        fake_cryptauth_gcm_manager_factory_(fake_cryptauth_gcm_manager_factory),
        test_pref_service_(test_pref_service) {}

  ~FakeCryptAuthEnrollmentManagerFactory() override = default;

  void set_device_already_enrolled_in_cryptauth(
      bool device_already_enrolled_in_cryptauth) {
    device_already_enrolled_in_cryptauth_ =
        device_already_enrolled_in_cryptauth;
  }

  cryptauth::FakeCryptAuthEnrollmentManager* instance() { return instance_; }

  // cryptauth::CryptAuthEnrollmentManagerImpl::Factory:
  std::unique_ptr<cryptauth::CryptAuthEnrollmentManager> BuildInstance(
      base::Clock* clock,
      std::unique_ptr<cryptauth::CryptAuthEnrollerFactory> enroller_factory,
      std::unique_ptr<cryptauth::SecureMessageDelegate> secure_message_delegate,
      const cryptauth::GcmDeviceInfo& device_info,
      cryptauth::CryptAuthGCMManager* gcm_manager,
      PrefService* pref_service) override {
    EXPECT_EQ(simple_test_clock_, clock);
    EXPECT_EQ(kTestGcmDeviceInfoLongDeviceId, device_info.long_device_id());
    EXPECT_EQ(fake_cryptauth_gcm_manager_factory_->instance(), gcm_manager);
    EXPECT_EQ(test_pref_service_, pref_service);

    // Only one instance is expected to be created per test.
    EXPECT_FALSE(instance_);

    auto instance =
        std::make_unique<cryptauth::FakeCryptAuthEnrollmentManager>();
    instance->set_is_enrollment_valid(device_already_enrolled_in_cryptauth_);
    instance_ = instance.get();

    return std::move(instance);
  }

 private:
  base::SimpleTestClock* simple_test_clock_;
  FakeCryptAuthGCMManagerFactory* fake_cryptauth_gcm_manager_factory_;
  TestingPrefServiceSimple* test_pref_service_;

  bool device_already_enrolled_in_cryptauth_ = false;
  cryptauth::FakeCryptAuthEnrollmentManager* instance_ = nullptr;
};

class FakeRemoteDeviceProviderFactory
    : public cryptauth::RemoteDeviceProviderImpl::Factory {
 public:
  FakeRemoteDeviceProviderFactory(
      const cryptauth::RemoteDeviceList& initial_devices,
      identity::IdentityManager* identity_manager,
      FakeCryptAuthDeviceManagerFactory* fake_cryptauth_device_manager_factory,
      FakeCryptAuthEnrollmentManagerFactory*
          fake_cryptauth_enrollment_manager_factory)
      : initial_devices_(initial_devices),
        identity_manager_(identity_manager),
        fake_cryptauth_device_manager_factory_(
            fake_cryptauth_device_manager_factory),
        fake_cryptauth_enrollment_manager_factory_(
            fake_cryptauth_enrollment_manager_factory) {}

  ~FakeRemoteDeviceProviderFactory() override = default;

  cryptauth::FakeRemoteDeviceProvider* instance() { return instance_; }

  // cryptauth::RemoteDeviceProviderImpl::Factory:
  std::unique_ptr<cryptauth::RemoteDeviceProvider> BuildInstance(
      cryptauth::CryptAuthDeviceManager* device_manager,
      const std::string& user_id,
      const std::string& user_private_key) override {
    EXPECT_EQ(fake_cryptauth_device_manager_factory_->instance(),
              device_manager);
    EXPECT_EQ(identity_manager_->GetPrimaryAccountInfo().account_id, user_id);
    EXPECT_EQ(fake_cryptauth_enrollment_manager_factory_->instance()
                  ->GetUserPrivateKey(),
              user_private_key);

    // Only one instance is expected to be created per test.
    EXPECT_FALSE(instance_);

    auto instance = std::make_unique<cryptauth::FakeRemoteDeviceProvider>();
    instance->set_synced_remote_devices(initial_devices_);
    instance_ = instance.get();

    return std::move(instance);
  }

 private:
  const cryptauth::RemoteDeviceList& initial_devices_;

  identity::IdentityManager* identity_manager_;
  FakeCryptAuthDeviceManagerFactory* fake_cryptauth_device_manager_factory_;
  FakeCryptAuthEnrollmentManagerFactory*
      fake_cryptauth_enrollment_manager_factory_;

  cryptauth::FakeRemoteDeviceProvider* instance_ = nullptr;
};

class FakeURLRequestContextGetter : public net::URLRequestContextGetter {
 public:
  FakeURLRequestContextGetter() : null_task_runner_(new base::NullTaskRunner) {}

  net::URLRequestContext* GetURLRequestContext() override { return nullptr; }

  scoped_refptr<base::SingleThreadTaskRunner> GetNetworkTaskRunner()
      const override {
    return null_task_runner_;
  }

 private:
  ~FakeURLRequestContextGetter() override {}

  scoped_refptr<base::SingleThreadTaskRunner> null_task_runner_;
};

}  // namespace

class DeviceSyncServiceTest : public testing::Test {
 public:
  class FakePrefConnectionDelegate
      : public DeviceSyncImpl::PrefConnectionDelegate {
   public:
    FakePrefConnectionDelegate(
        std::unique_ptr<TestingPrefServiceSimple> test_pref_service)
        : test_pref_service_(std::move(test_pref_service)),
          test_pref_registry_(
              base::WrapRefCounted(test_pref_service_->registry())) {}

    ~FakePrefConnectionDelegate() override = default;

    void InvokePendingCallback() {
      EXPECT_FALSE(pending_callback_.is_null());
      std::move(pending_callback_).Run(std::move(test_pref_service_));

      // Note: |pending_callback_| was passed from within the service, so it is
      // necessary to let the rest of the current RunLoop run to ensure that
      // the callback is executed before returning from this function.
      base::RunLoop().RunUntilIdle();
    }

    bool HasStartedPrefConnection() {
      return HasFinishedPrefConnection() || !pending_callback_.is_null();
    }

    bool HasFinishedPrefConnection() { return !test_pref_service_.get(); }

    // DeviceSyncImpl::PrefConnectionDelegate:
    scoped_refptr<PrefRegistrySimple> CreatePrefRegistry() override {
      return test_pref_registry_;
    }

    void ConnectToPrefService(service_manager::Connector* connector,
                              scoped_refptr<PrefRegistrySimple> pref_registry,
                              prefs::ConnectCallback callback) override {
      EXPECT_EQ(test_pref_service_->registry(), pref_registry.get());
      pending_callback_ = std::move(callback);
    }

   private:
    std::unique_ptr<TestingPrefServiceSimple> test_pref_service_;
    scoped_refptr<PrefRegistrySimple> test_pref_registry_;

    prefs::ConnectCallback pending_callback_;
  };

  class FakeDeviceSyncImplFactory : public DeviceSyncImpl::Factory {
   public:
    FakeDeviceSyncImplFactory(std::unique_ptr<FakePrefConnectionDelegate>
                                  fake_pref_connection_delegate,
                              base::SimpleTestClock* simple_test_clock)
        : fake_pref_connection_delegate_(
              std::move(fake_pref_connection_delegate)),
          simple_test_clock_(simple_test_clock) {}

    ~FakeDeviceSyncImplFactory() override = default;

    // DeviceSyncImpl::Factory:
    std::unique_ptr<DeviceSyncImpl> BuildInstance(
        identity::IdentityManager* identity_manager,
        gcm::GCMDriver* gcm_driver,
        service_manager::Connector* connector,
        cryptauth::GcmDeviceInfoProvider* gcm_device_info_provider,
        scoped_refptr<net::URLRequestContextGetter> url_request_context)
        override {
      return base::WrapUnique(new DeviceSyncImpl(
          identity_manager, gcm_driver, connector, gcm_device_info_provider,
          std::move(url_request_context), simple_test_clock_,
          std::move(fake_pref_connection_delegate_)));
    }

   private:
    std::unique_ptr<FakePrefConnectionDelegate> fake_pref_connection_delegate_;
    base::SimpleTestClock* simple_test_clock_;
  };

  DeviceSyncServiceTest() : test_devices_(GenerateTestRemoteDevices()) {}
  ~DeviceSyncServiceTest() override = default;

  void SetUp() override {
    DBusThreadManager::Initialize();

    fake_gcm_driver_ = std::make_unique<gcm::FakeGCMDriver>();

    auto test_pref_service = std::make_unique<TestingPrefServiceSimple>();
    test_pref_service_ = test_pref_service.get();

    simple_test_clock_ = std::make_unique<base::SimpleTestClock>();

    // Note: The primary account is guaranteed to be available when the service
    //       starts up since this is a CrOS-only service, and CrOS requires that
    //       the user logs in.
    identity_test_environment_ =
        std::make_unique<identity::IdentityTestEnvironment>();
    identity_test_environment_->MakePrimaryAccountAvailable(kTestEmail);

    fake_cryptauth_gcm_manager_factory_ =
        std::make_unique<FakeCryptAuthGCMManagerFactory>(fake_gcm_driver_.get(),
                                                         test_pref_service_);
    cryptauth::CryptAuthGCMManagerImpl::Factory::SetInstanceForTesting(
        fake_cryptauth_gcm_manager_factory_.get());

    fake_cryptauth_device_manager_factory_ =
        std::make_unique<FakeCryptAuthDeviceManagerFactory>(
            simple_test_clock_.get(), fake_cryptauth_gcm_manager_factory_.get(),
            test_pref_service_);
    cryptauth::CryptAuthDeviceManagerImpl::Factory::SetInstanceForTesting(
        fake_cryptauth_device_manager_factory_.get());

    fake_cryptauth_enrollment_manager_factory_ =
        std::make_unique<FakeCryptAuthEnrollmentManagerFactory>(
            simple_test_clock_.get(), fake_cryptauth_gcm_manager_factory_.get(),
            test_pref_service_);
    cryptauth::CryptAuthEnrollmentManagerImpl::Factory::SetInstanceForTesting(
        fake_cryptauth_enrollment_manager_factory_.get());

    fake_remote_device_provider_factory_ =
        std::make_unique<FakeRemoteDeviceProviderFactory>(
            test_devices_, identity_test_environment_->identity_manager(),
            fake_cryptauth_device_manager_factory_.get(),
            fake_cryptauth_enrollment_manager_factory_.get());
    cryptauth::RemoteDeviceProviderImpl::Factory::SetInstanceForTesting(
        fake_remote_device_provider_factory_.get());

    auto fake_pref_connection_delegate =
        std::make_unique<FakePrefConnectionDelegate>(
            std::move(test_pref_service));
    fake_pref_connection_delegate_ = fake_pref_connection_delegate.get();

    fake_device_sync_impl_factory_ =
        std::make_unique<FakeDeviceSyncImplFactory>(
            std::move(fake_pref_connection_delegate), simple_test_clock_.get());
    DeviceSyncImpl::Factory::SetInstanceForTesting(
        fake_device_sync_impl_factory_.get());

    fake_gcm_device_info_provider_ =
        std::make_unique<cryptauth::FakeGcmDeviceInfoProvider>(
            GetTestGcmDeviceInfo());

    fake_url_request_context_getter_ =
        base::MakeRefCounted<FakeURLRequestContextGetter>();

    fake_device_sync_observer_ = std::make_unique<FakeDeviceSyncObserver>();
    connector_factory_ =
        service_manager::TestConnectorFactory::CreateForUniqueService(
            std::make_unique<DeviceSyncService>(
                identity_test_environment_->identity_manager(),
                fake_gcm_driver_.get(), fake_gcm_device_info_provider_.get(),
                fake_url_request_context_getter_.get()));
  }

  void TearDown() override { DBusThreadManager::Shutdown(); }

  void ConnectToDeviceSyncService(bool device_already_enrolled_in_cryptauth) {
    // Used in CompleteConnectionToPrefService().
    device_already_enrolled_in_cryptauth_ =
        device_already_enrolled_in_cryptauth;

    fake_cryptauth_enrollment_manager_factory_
        ->set_device_already_enrolled_in_cryptauth(
            device_already_enrolled_in_cryptauth);

    // Must not have already connected.
    EXPECT_FALSE(connector_);

    // Create the Connector and bind it to |device_sync_|.
    connector_ = connector_factory_->CreateConnector();
    connector_->BindInterface(mojom::kServiceName, &device_sync_);

    // Set |fake_device_sync_observer_|.
    CallAddObserver();
  }

  void CompleteConnectionToPrefService() {
    EXPECT_TRUE(fake_pref_connection_delegate()->HasStartedPrefConnection());
    EXPECT_FALSE(fake_pref_connection_delegate()->HasFinishedPrefConnection());

    fake_pref_connection_delegate_->InvokePendingCallback();
    EXPECT_TRUE(fake_pref_connection_delegate()->HasFinishedPrefConnection());

    // When connection to preferences is complete, CryptAuth classes are
    // expected to be created and initialized.
    EXPECT_TRUE(fake_cryptauth_gcm_manager_factory_->instance()
                    ->has_started_listening());
    EXPECT_TRUE(
        fake_cryptauth_enrollment_manager_factory_->instance()->has_started());

    // If the device was already enrolled in CryptAuth, initialization should
    // now be complete; otherwise, enrollment needs to finish before
    // the flow has finished up.
    VerifyInitializationStatus(
        device_already_enrolled_in_cryptauth_ /* expected_to_be_initialized */);

    if (!device_already_enrolled_in_cryptauth_)
      return;

    // Now that the service is initialized, RemoteDeviceProvider is expected to
    // load all relevant RemoteDevice objects.
    fake_remote_device_provider_factory_->instance()
        ->NotifyObserversDeviceListChanged();
  }

  void VerifyInitializationStatus(bool expected_to_be_initialized) {
    // CryptAuthDeviceManager::Start() is called as the last step of the
    // initialization flow.
    EXPECT_EQ(
        expected_to_be_initialized,
        fake_cryptauth_device_manager_factory_->instance()->has_started());
  }

  // Simulates an enrollment with success == |success|. If enrollment was not
  // yet in progress before this call, it is started before it is completed.
  void SimulateEnrollment(bool success) {
    cryptauth::FakeCryptAuthEnrollmentManager* enrollment_manager =
        fake_cryptauth_enrollment_manager_factory_->instance();

    bool had_valid_enrollment_before_call =
        enrollment_manager->IsEnrollmentValid();

    if (!enrollment_manager->IsEnrollmentInProgress()) {
      enrollment_manager->ForceEnrollmentNow(
          cryptauth::InvocationReason::INVOCATION_REASON_MANUAL);
    }

    enrollment_manager->FinishActiveEnrollment(success);

    // If this was the first successful enrollment for this device,
    // RemoteDeviceProvider is expected to load all relevant RemoteDevice
    // objects.
    if (success && !had_valid_enrollment_before_call) {
      fake_remote_device_provider_factory_->instance()
          ->NotifyObserversDeviceListChanged();
    }
  }

  // Simulates a device sync with success == |success|. Optionally, if
  // |updated_devices| is provided, these devices will set on the
  // FakeRemoteDeviceProvider.
  void SimulateSync(bool success,
                    const cryptauth::RemoteDeviceList& updated_devices =
                        cryptauth::RemoteDeviceList()) {
    cryptauth::FakeCryptAuthDeviceManager* device_manager =
        fake_cryptauth_device_manager_factory_->instance();
    cryptauth::FakeRemoteDeviceProvider* remote_device_provider =
        fake_remote_device_provider_factory_->instance();

    EXPECT_TRUE(device_manager->IsSyncInProgress());
    device_manager->FinishActiveSync(
        success ? cryptauth::CryptAuthDeviceManager::SyncResult::SUCCESS
                : cryptauth::CryptAuthDeviceManager::SyncResult::FAILURE,
        updated_devices.empty()
            ? cryptauth::CryptAuthDeviceManager::DeviceChangeResult::UNCHANGED
            : cryptauth::CryptAuthDeviceManager::DeviceChangeResult::CHANGED);

    if (!updated_devices.empty()) {
      remote_device_provider->set_synced_remote_devices(updated_devices);
      remote_device_provider->NotifyObserversDeviceListChanged();
    }
  }

  void InitializeServiceSuccessfully() {
    ConnectToDeviceSyncService(true /* device_already_enrolled_in_cryptauth */);
    CompleteConnectionToPrefService();
    VerifyInitializationStatus(true /* expected_to_be_initialized */);

    base::RunLoop().RunUntilIdle();

    // Enrollment did not occur since the device was already in a valid state.
    EXPECT_EQ(0u, fake_device_sync_observer()->num_enrollment_events());

    // The initial set of synced devices was set.
    EXPECT_EQ(1u, fake_device_sync_observer()->num_sync_events());
  }

  const cryptauth::RemoteDeviceList& test_devices() { return test_devices_; }

  FakeDeviceSyncObserver* fake_device_sync_observer() {
    return fake_device_sync_observer_.get();
  }

  FakePrefConnectionDelegate* fake_pref_connection_delegate() {
    return fake_pref_connection_delegate_;
  }

  void CallAddObserver() {
    base::RunLoop run_loop;
    device_sync_->AddObserver(
        fake_device_sync_observer_->GenerateInterfacePtr(),
        base::BindOnce(&DeviceSyncServiceTest::OnAddObserverCompleted,
                       base::Unretained(this), run_loop.QuitClosure()));
    run_loop.Run();
  }

  bool CallForceEnrollmentNow() {
    base::RunLoop run_loop;
    device_sync_->ForceEnrollmentNow(
        base::BindOnce(&DeviceSyncServiceTest::OnForceEnrollmentNowCompleted,
                       base::Unretained(this), run_loop.QuitClosure()));
    run_loop.Run();

    if (fake_cryptauth_enrollment_manager_factory_->instance()) {
      EXPECT_EQ(last_force_enrollment_now_result_,
                fake_cryptauth_enrollment_manager_factory_->instance()
                    ->IsEnrollmentInProgress());
    }

    return last_force_enrollment_now_result_;
  }

  bool CallForceSyncNow() {
    base::RunLoop run_loop;
    device_sync_->ForceSyncNow(
        base::BindOnce(&DeviceSyncServiceTest::OnForceSyncNowCompleted,
                       base::Unretained(this), run_loop.QuitClosure()));
    run_loop.Run();

    if (fake_cryptauth_device_manager_factory_->instance()) {
      EXPECT_EQ(last_force_sync_now_result_,
                fake_cryptauth_device_manager_factory_->instance()
                    ->IsSyncInProgress());
    }

    return last_force_sync_now_result_;
  }

  const cryptauth::RemoteDeviceList& CallGetSyncedDevices() {
    base::RunLoop run_loop;
    device_sync_->GetSyncedDevices(
        base::BindOnce(&DeviceSyncServiceTest::OnGetSyncedDevicesCompleted,
                       base::Unretained(this), run_loop.QuitClosure()));
    run_loop.Run();
    return last_synced_devices_result_;
  }

 private:
  void OnAddObserverCompleted(base::OnceClosure quit_closure) {
    std::move(quit_closure).Run();
  }

  void OnForceEnrollmentNowCompleted(base::OnceClosure quit_closure,
                                     bool success) {
    last_force_enrollment_now_result_ = success;
    std::move(quit_closure).Run();
  }

  void OnForceSyncNowCompleted(base::OnceClosure quit_closure, bool success) {
    last_force_sync_now_result_ = success;
    std::move(quit_closure).Run();
  }

  void OnGetSyncedDevicesCompleted(
      base::OnceClosure quit_closure,
      const cryptauth::RemoteDeviceList& synced_devices) {
    last_synced_devices_result_ = synced_devices;
    std::move(quit_closure).Run();
  }

  const base::test::ScopedTaskEnvironment scoped_task_environment_;
  const cryptauth::RemoteDeviceList test_devices_;

  TestingPrefServiceSimple* test_pref_service_;
  FakePrefConnectionDelegate* fake_pref_connection_delegate_;
  std::unique_ptr<base::SimpleTestClock> simple_test_clock_;
  std::unique_ptr<FakeDeviceSyncImplFactory> fake_device_sync_impl_factory_;
  std::unique_ptr<FakeCryptAuthGCMManagerFactory>
      fake_cryptauth_gcm_manager_factory_;
  std::unique_ptr<FakeCryptAuthDeviceManagerFactory>
      fake_cryptauth_device_manager_factory_;
  std::unique_ptr<FakeCryptAuthEnrollmentManagerFactory>
      fake_cryptauth_enrollment_manager_factory_;
  std::unique_ptr<FakeRemoteDeviceProviderFactory>
      fake_remote_device_provider_factory_;

  std::unique_ptr<identity::IdentityTestEnvironment> identity_test_environment_;
  std::unique_ptr<gcm::FakeGCMDriver> fake_gcm_driver_;
  std::unique_ptr<cryptauth::FakeGcmDeviceInfoProvider>
      fake_gcm_device_info_provider_;
  scoped_refptr<FakeURLRequestContextGetter> fake_url_request_context_getter_;

  std::unique_ptr<service_manager::TestConnectorFactory> connector_factory_;
  std::unique_ptr<service_manager::Connector> connector_;

  bool device_already_enrolled_in_cryptauth_;
  bool last_force_enrollment_now_result_;
  bool last_force_sync_now_result_;
  cryptauth::RemoteDeviceList last_synced_devices_result_;

  std::unique_ptr<FakeDeviceSyncObserver> fake_device_sync_observer_;
  mojom::DeviceSyncPtr device_sync_;

  DISALLOW_COPY_AND_ASSIGN(DeviceSyncServiceTest);
};

TEST_F(DeviceSyncServiceTest, PreferencesNeverConnect) {
  ConnectToDeviceSyncService(false /* device_already_enrolled_in_cryptauth */);

  // A connection to the Preferences service should have started.
  EXPECT_TRUE(fake_pref_connection_delegate()->HasStartedPrefConnection());
  EXPECT_FALSE(fake_pref_connection_delegate()->HasFinishedPrefConnection());

  // Do not complete the connection; without this step, the other API functions
  // should fail.
  EXPECT_FALSE(CallForceEnrollmentNow());
  EXPECT_FALSE(CallForceSyncNow());
  EXPECT_TRUE(CallGetSyncedDevices().empty());

  // No observer callbacks should have been invoked.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, fake_device_sync_observer()->num_enrollment_events());
  EXPECT_EQ(0u, fake_device_sync_observer()->num_sync_events());
}

TEST_F(DeviceSyncServiceTest,
       DeviceNotAlreadyEnrolledInCryptAuth_FailsEnrollment) {
  ConnectToDeviceSyncService(false /* device_already_enrolled_in_cryptauth */);
  CompleteConnectionToPrefService();

  // Simulate enrollment failing.
  SimulateEnrollment(false /* success */);
  VerifyInitializationStatus(false /* success */);

  // Fail again; initialization still should not complete.
  SimulateEnrollment(false /* success */);
  VerifyInitializationStatus(false /* expected_to_be_initialized */);

  // Other API functions should still fail since initialization never completed.
  EXPECT_FALSE(CallForceEnrollmentNow());
  EXPECT_FALSE(CallForceSyncNow());
  EXPECT_TRUE(CallGetSyncedDevices().empty());

  // No observer callbacks should have been invoked.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, fake_device_sync_observer()->num_enrollment_events());
  EXPECT_EQ(0u, fake_device_sync_observer()->num_sync_events());
}

TEST_F(DeviceSyncServiceTest,
       DeviceNotAlreadyEnrolledInCryptAuth_FailsEnrollment_ThenSucceeds) {
  ConnectToDeviceSyncService(false /* device_already_enrolled_in_cryptauth */);
  CompleteConnectionToPrefService();

  // Initialization has not yet completed, so no devices should be available.
  EXPECT_TRUE(CallGetSyncedDevices().empty());

  // Simulate enrollment failing.
  SimulateEnrollment(false /* success */);
  VerifyInitializationStatus(false /* success */);

  // Simulate enrollment succeeding; this should result in a fully-initialized
  // service.
  SimulateEnrollment(true /* success */);
  VerifyInitializationStatus(true /* expected_to_be_initialized */);

  // Enrollment occurred successfully, and the initial set of synced devices was
  // set.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, fake_device_sync_observer()->num_enrollment_events());
  EXPECT_EQ(1u, fake_device_sync_observer()->num_sync_events());

  // Now that the service is initialized, API functions should be operation and
  // synced devices should be available.
  EXPECT_TRUE(CallForceEnrollmentNow());
  EXPECT_TRUE(CallForceSyncNow());
  EXPECT_EQ(test_devices(), CallGetSyncedDevices());
}

TEST_F(DeviceSyncServiceTest,
       DeviceAlreadyEnrolledInCryptAuth_InitializationFlow) {
  InitializeServiceSuccessfully();

  // Now that the service is initialized, API functions should be operation and
  // synced devices should be available.
  EXPECT_TRUE(CallForceEnrollmentNow());
  EXPECT_TRUE(CallForceSyncNow());
  EXPECT_EQ(test_devices(), CallGetSyncedDevices());
}

TEST_F(DeviceSyncServiceTest, EnrollAgainAfterInitialization) {
  InitializeServiceSuccessfully();

  // Force an enrollment.
  EXPECT_TRUE(CallForceEnrollmentNow());

  // Simulate that enrollment failing.
  SimulateEnrollment(false /* success */);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, fake_device_sync_observer()->num_enrollment_events());

  // Force an enrollment again.
  EXPECT_TRUE(CallForceEnrollmentNow());

  // This time, simulate the enrollment succeeding.
  SimulateEnrollment(true /* success */);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, fake_device_sync_observer()->num_enrollment_events());
}

TEST_F(DeviceSyncServiceTest, SyncedDeviceUpdates) {
  InitializeServiceSuccessfully();
  EXPECT_EQ(1u, fake_device_sync_observer()->num_sync_events());

  // Force a device sync.
  EXPECT_TRUE(CallForceSyncNow());

  // Simulate failed sync.
  SimulateSync(false /* success */);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, fake_device_sync_observer()->num_sync_events());

  // Force a sync again.
  EXPECT_TRUE(CallForceSyncNow());

  // Simulate successful sync which does not change the synced device list.
  SimulateSync(true /* success */);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, fake_device_sync_observer()->num_sync_events());

  // Force a sync again.
  EXPECT_TRUE(CallForceSyncNow());

  // Create a new list which is the same as the initial test devices except that
  // the first device is removed.
  cryptauth::RemoteDeviceList updated_device_list(test_devices().begin() + 1,
                                                  test_devices().end());
  EXPECT_EQ(kNumTestDevices - 1, updated_device_list.size());

  // Simulate successful sync which does change the synced device list.
  SimulateSync(true /* success */, updated_device_list);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, fake_device_sync_observer()->num_sync_events());

  // The updated list should be available via GetSyncedDevices().
  EXPECT_EQ(updated_device_list, CallGetSyncedDevices());
}

}  // namespace device_sync

}  // namespace chromeos

// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/components/proximity_auth/remote_device_life_cycle_impl.h"

#include <stddef.h>

#include <memory>
#include <utility>

#include "base/callback.h"
#include "base/macros.h"
#include "base/test/test_simple_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "chromeos/components/proximity_auth/messenger.h"
#include "components/cryptauth/authenticator.h"
#include "components/cryptauth/connection_finder.h"
#include "components/cryptauth/cryptauth_test_util.h"
#include "components/cryptauth/fake_connection.h"
#include "components/cryptauth/secure_context.h"
#include "components/cryptauth/wire_message.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::_;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

namespace proximity_auth {

namespace {

class StubSecureContext : public cryptauth::SecureContext {
 public:
  StubSecureContext() {}
  ~StubSecureContext() override {}

  void Decode(const std::string& encoded_message,
              const MessageCallback& callback) override {
    NOTREACHED();
  }

  void Encode(const std::string& message,
              const MessageCallback& callback) override {
    NOTREACHED();
  }

  ProtocolVersion GetProtocolVersion() const override {
    NOTREACHED();
    return SecureContext::PROTOCOL_VERSION_THREE_ONE;
  }

  std::string GetChannelBindingData() const override { return std::string(); }

 private:
  DISALLOW_COPY_AND_ASSIGN(StubSecureContext);
};

class FakeConnectionFinder : public cryptauth::ConnectionFinder {
 public:
  explicit FakeConnectionFinder(const cryptauth::RemoteDevice& remote_device)
      : remote_device_(remote_device), connection_(nullptr) {}
  ~FakeConnectionFinder() override {}

  void OnConnectionFound() {
    ASSERT_FALSE(connection_callback_.is_null());
    std::unique_ptr<cryptauth::FakeConnection> scoped_connection_(
        new cryptauth::FakeConnection(remote_device_));
    connection_ = scoped_connection_.get();
    connection_callback_.Run(std::move(scoped_connection_));
  }

  cryptauth::FakeConnection* connection() { return connection_; }

 private:
  // cryptauth::ConnectionFinder:
  void Find(const cryptauth::ConnectionFinder::ConnectionCallback&
                connection_callback) override {
    ASSERT_TRUE(connection_callback_.is_null());
    connection_callback_ = connection_callback;
  }

  const cryptauth::RemoteDevice remote_device_;

  cryptauth::FakeConnection* connection_;

  cryptauth::ConnectionFinder::ConnectionCallback connection_callback_;

  DISALLOW_COPY_AND_ASSIGN(FakeConnectionFinder);
};

class FakeAuthenticator : public cryptauth::Authenticator {
 public:
  explicit FakeAuthenticator(cryptauth::Connection* connection)
      : connection_(connection) {}
  ~FakeAuthenticator() override {
    // This object should be destroyed immediately after authentication is
    // complete in order not to outlive the underlying connection.
    EXPECT_FALSE(callback_.is_null());
    EXPECT_EQ(cryptauth::kTestRemoteDevicePublicKey,
              connection_->remote_device().public_key);
  }

  void OnAuthenticationResult(cryptauth::Authenticator::Result result) {
    ASSERT_FALSE(callback_.is_null());
    std::unique_ptr<cryptauth::SecureContext> secure_context;
    if (result == Authenticator::Result::SUCCESS)
      secure_context.reset(new StubSecureContext());
    callback_.Run(result, std::move(secure_context));
  }

 private:
  // cryptauth::Authenticator:
  void Authenticate(const AuthenticationCallback& callback) override {
    ASSERT_TRUE(callback_.is_null());
    callback_ = callback;
  }

  cryptauth::Connection* connection_;

  AuthenticationCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(FakeAuthenticator);
};

// Subclass of RemoteDeviceLifeCycleImpl to make it testable.
class TestableRemoteDeviceLifeCycleImpl : public RemoteDeviceLifeCycleImpl {
 public:
  TestableRemoteDeviceLifeCycleImpl(
      const cryptauth::RemoteDevice& remote_device)
      : RemoteDeviceLifeCycleImpl(remote_device),
        remote_device_(remote_device) {}

  ~TestableRemoteDeviceLifeCycleImpl() override {}

  FakeConnectionFinder* connection_finder() { return connection_finder_; }
  FakeAuthenticator* authenticator() { return authenticator_; }

 private:
  std::unique_ptr<cryptauth::ConnectionFinder> CreateConnectionFinder()
      override {
    std::unique_ptr<FakeConnectionFinder> scoped_connection_finder(
        new FakeConnectionFinder(remote_device_));
    connection_finder_ = scoped_connection_finder.get();
    return std::move(scoped_connection_finder);
  }

  std::unique_ptr<cryptauth::Authenticator> CreateAuthenticator() override {
    EXPECT_TRUE(connection_finder_);
    std::unique_ptr<FakeAuthenticator> scoped_authenticator(
        new FakeAuthenticator(connection_finder_->connection()));
    authenticator_ = scoped_authenticator.get();
    return std::move(scoped_authenticator);
  }

  const cryptauth::RemoteDevice remote_device_;
  FakeConnectionFinder* connection_finder_;
  FakeAuthenticator* authenticator_;

  DISALLOW_COPY_AND_ASSIGN(TestableRemoteDeviceLifeCycleImpl);
};

}  // namespace

class ProximityAuthRemoteDeviceLifeCycleImplTest
    : public testing::Test,
      public RemoteDeviceLifeCycle::Observer {
 protected:
  ProximityAuthRemoteDeviceLifeCycleImplTest()
      : life_cycle_(cryptauth::CreateClassicRemoteDeviceForTest()),
        task_runner_(new base::TestSimpleTaskRunner()),
        thread_task_runner_handle_(task_runner_) {}

  ~ProximityAuthRemoteDeviceLifeCycleImplTest() override {
    life_cycle_.RemoveObserver(this);
  }

  void StartLifeCycle() {
    EXPECT_EQ(RemoteDeviceLifeCycle::State::STOPPED, life_cycle_.GetState());
    life_cycle_.AddObserver(this);

    EXPECT_CALL(*this, OnLifeCycleStateChanged(
                           RemoteDeviceLifeCycle::State::STOPPED,
                           RemoteDeviceLifeCycle::State::FINDING_CONNECTION));
    life_cycle_.Start();
    task_runner_->RunUntilIdle();
    Mock::VerifyAndClearExpectations(this);

    EXPECT_EQ(RemoteDeviceLifeCycle::State::FINDING_CONNECTION,
              life_cycle_.GetState());
  }

  cryptauth::FakeConnection* OnConnectionFound() {
    EXPECT_EQ(RemoteDeviceLifeCycle::State::FINDING_CONNECTION,
              life_cycle_.GetState());

    EXPECT_CALL(*this, OnLifeCycleStateChanged(
                           RemoteDeviceLifeCycle::State::FINDING_CONNECTION,
                           RemoteDeviceLifeCycle::State::AUTHENTICATING));
    life_cycle_.connection_finder()->OnConnectionFound();
    task_runner_->RunUntilIdle();
    Mock::VerifyAndClearExpectations(this);

    EXPECT_EQ(RemoteDeviceLifeCycle::State::AUTHENTICATING,
              life_cycle_.GetState());
    return life_cycle_.connection_finder()->connection();
  }

  void Authenticate(cryptauth::Authenticator::Result result) {
    EXPECT_EQ(RemoteDeviceLifeCycle::State::AUTHENTICATING,
              life_cycle_.GetState());

    RemoteDeviceLifeCycle::State expected_state =
        (result == cryptauth::Authenticator::Result::SUCCESS)
            ? RemoteDeviceLifeCycle::State::SECURE_CHANNEL_ESTABLISHED
            : RemoteDeviceLifeCycle::State::AUTHENTICATION_FAILED;

    EXPECT_CALL(*this, OnLifeCycleStateChanged(
                           RemoteDeviceLifeCycle::State::AUTHENTICATING,
                           expected_state));
    life_cycle_.authenticator()->OnAuthenticationResult(result);

    if (result == cryptauth::Authenticator::Result::SUCCESS)
      task_runner_->RunUntilIdle();

    EXPECT_EQ(expected_state, life_cycle_.GetState());
    Mock::VerifyAndClearExpectations(this);
  }

  MOCK_METHOD2(OnLifeCycleStateChanged,
               void(RemoteDeviceLifeCycle::State old_state,
                    RemoteDeviceLifeCycle::State new_state));

  TestableRemoteDeviceLifeCycleImpl life_cycle_;
  scoped_refptr<base::TestSimpleTaskRunner> task_runner_;
  base::ThreadTaskRunnerHandle thread_task_runner_handle_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ProximityAuthRemoteDeviceLifeCycleImplTest);
};

TEST_F(ProximityAuthRemoteDeviceLifeCycleImplTest, GetRemoteDevice) {
  cryptauth::RemoteDevice expected_remote_device =
      cryptauth::CreateClassicRemoteDeviceForTest();
  cryptauth::RemoteDevice remote_device = life_cycle_.GetRemoteDevice();
  EXPECT_EQ(expected_remote_device.user_id, remote_device.user_id);
  EXPECT_EQ(expected_remote_device.name, remote_device.name);
  EXPECT_EQ(expected_remote_device.public_key, remote_device.public_key);
  EXPECT_EQ(expected_remote_device.persistent_symmetric_key,
            remote_device.persistent_symmetric_key);
}

TEST_F(ProximityAuthRemoteDeviceLifeCycleImplTest, AuthenticateAndDisconnect) {
  StartLifeCycle();
  for (size_t i = 0; i < 3; ++i) {
    cryptauth::Connection* connection = OnConnectionFound();
    Authenticate(cryptauth::Authenticator::Result::SUCCESS);
    EXPECT_TRUE(life_cycle_.GetMessenger());

    EXPECT_CALL(*this,
                OnLifeCycleStateChanged(
                    RemoteDeviceLifeCycle::State::SECURE_CHANNEL_ESTABLISHED,
                    RemoteDeviceLifeCycle::State::FINDING_CONNECTION));
    connection->Disconnect();
    Mock::VerifyAndClearExpectations(this);
  }
}

TEST_F(ProximityAuthRemoteDeviceLifeCycleImplTest, AuthenticationFails) {
  // Simulate an authentication failure after connecting to the device.
  StartLifeCycle();
  OnConnectionFound();
  Authenticate(cryptauth::Authenticator::Result::FAILURE);
  EXPECT_FALSE(life_cycle_.GetMessenger());

  // After a delay, the life cycle should return to FINDING_CONNECTION.
  EXPECT_CALL(*this, OnLifeCycleStateChanged(
                         RemoteDeviceLifeCycle::State::AUTHENTICATION_FAILED,
                         RemoteDeviceLifeCycle::State::FINDING_CONNECTION));
  task_runner_->RunUntilIdle();
  EXPECT_EQ(RemoteDeviceLifeCycle::State::FINDING_CONNECTION,
            life_cycle_.GetState());

  // Try failing with the DISCONNECTED state instead.
  OnConnectionFound();
  Authenticate(cryptauth::Authenticator::Result::DISCONNECTED);
  EXPECT_FALSE(life_cycle_.GetMessenger());

  // Check we're back in FINDING_CONNECTION state again.
  EXPECT_CALL(*this, OnLifeCycleStateChanged(
                         RemoteDeviceLifeCycle::State::AUTHENTICATION_FAILED,
                         RemoteDeviceLifeCycle::State::FINDING_CONNECTION));
  task_runner_->RunUntilIdle();
  EXPECT_EQ(RemoteDeviceLifeCycle::State::FINDING_CONNECTION,
            life_cycle_.GetState());
}

TEST_F(ProximityAuthRemoteDeviceLifeCycleImplTest,
       AuthenticationFailsThenSucceeds) {
  // Authentication fails on first pass.
  StartLifeCycle();
  OnConnectionFound();
  Authenticate(cryptauth::Authenticator::Result::FAILURE);
  EXPECT_FALSE(life_cycle_.GetMessenger());
  EXPECT_CALL(*this, OnLifeCycleStateChanged(_, _));
  task_runner_->RunUntilIdle();

  // Authentication succeeds on second pass.
  cryptauth::Connection* connection = OnConnectionFound();
  Authenticate(cryptauth::Authenticator::Result::SUCCESS);
  EXPECT_TRUE(life_cycle_.GetMessenger());
  EXPECT_CALL(*this, OnLifeCycleStateChanged(_, _));
  connection->Disconnect();
}

}  // namespace proximity_auth

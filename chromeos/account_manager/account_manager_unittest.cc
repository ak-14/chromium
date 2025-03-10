// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/account_manager/account_manager.h"

#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/files/scoped_temp_dir.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/test/scoped_task_environment.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace chromeos {

class AccountManagerTest : public testing::Test {
 public:
  AccountManagerTest() = default;
  ~AccountManagerTest() override {}

 protected:
  void SetUp() override {
    ASSERT_TRUE(tmp_dir_.CreateUniqueTempDir());
    account_manager_ = std::make_unique<AccountManager>();
    account_manager_->Initialize(tmp_dir_.GetPath(),
                                 base::SequencedTaskRunnerHandle::Get());
  }

  // Check base/test/scoped_task_environment.h. This must be the first member /
  // declared before any member that cares about tasks.
  base::test::ScopedTaskEnvironment scoped_task_environment_;
  base::ScopedTempDir tmp_dir_;
  std::unique_ptr<AccountManager> account_manager_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AccountManagerTest);
};

class AccountManagerObserver : public AccountManager::Observer {
 public:
  AccountManagerObserver() = default;
  ~AccountManagerObserver() override = default;

  void OnAccountListUpdated(const std::vector<std::string>& accounts) override {
    is_callback_called_ = true;
    accounts_ = accounts;
  }

  bool is_callback_called_ = false;
  std::vector<std::string> accounts_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AccountManagerObserver);
};

TEST_F(AccountManagerTest, TestInitialization) {
  AccountManager account_manager;

  EXPECT_EQ(account_manager.init_state_,
            AccountManager::InitializationState::kNotStarted);
  account_manager.Initialize(tmp_dir_.GetPath(),
                             base::SequencedTaskRunnerHandle::Get());
  scoped_task_environment_.RunUntilIdle();
  EXPECT_EQ(account_manager.init_state_,
            AccountManager::InitializationState::kInitialized);
}

TEST_F(AccountManagerTest, TestUpsert) {
  account_manager_->UpsertToken("abc", "123");

  std::vector<std::string> accounts;
  base::RunLoop run_loop;
  account_manager_->GetAccounts(base::BindOnce(
      [](std::vector<std::string>* accounts, base::OnceClosure quit_closure,
         std::vector<std::string> stored_accounts) -> void {
        *accounts = stored_accounts;
        std::move(quit_closure).Run();
      },
      base::Unretained(&accounts), run_loop.QuitClosure()));
  run_loop.Run();

  EXPECT_EQ(1UL, accounts.size());
  EXPECT_EQ("abc", accounts[0]);
}

TEST_F(AccountManagerTest, TestPersistence) {
  account_manager_->UpsertToken("abc", "123");
  scoped_task_environment_.RunUntilIdle();

  account_manager_ = std::make_unique<AccountManager>();
  account_manager_->Initialize(tmp_dir_.GetPath(),
                               base::SequencedTaskRunnerHandle::Get());

  std::vector<std::string> accounts;
  base::RunLoop run_loop;
  account_manager_->GetAccounts(base::BindOnce(
      [](std::vector<std::string>* accounts, base::OnceClosure quit_closure,
         std::vector<std::string> stored_accounts) -> void {
        *accounts = stored_accounts;
        std::move(quit_closure).Run();
      },
      base::Unretained(&accounts), run_loop.QuitClosure()));
  run_loop.Run();

  EXPECT_EQ(1UL, accounts.size());
  EXPECT_EQ("abc", accounts[0]);
}

TEST_F(AccountManagerTest, TestObserverAddAccount) {
  auto observer = std::make_unique<AccountManagerObserver>();
  EXPECT_FALSE(observer->is_callback_called_);

  account_manager_->AddObserver(observer.get());
  account_manager_->UpsertToken("abc", "123");
  scoped_task_environment_.RunUntilIdle();

  EXPECT_TRUE(observer->is_callback_called_);
  EXPECT_EQ(1UL, observer->accounts_.size());
  EXPECT_EQ("abc", observer->accounts_[0]);

  // Observers should not be called if account list does not change.
  observer->is_callback_called_ = false;
  account_manager_->UpsertToken("abc", "456");
  scoped_task_environment_.RunUntilIdle();
  EXPECT_FALSE(observer->is_callback_called_);

  // Don't leak
  account_manager_->RemoveObserver(observer.get());
}

}  // namespace chromeos

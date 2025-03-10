// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "base/command_line.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "chrome/browser/chromeos/login/login_manager_test.h"
#include "chrome/browser/chromeos/login/screens/error_screen.h"
#include "chrome/browser/chromeos/login/screens/network_error_view.h"
#include "chrome/browser/chromeos/login/startup_utils.h"
#include "chrome/browser/chromeos/login/test/oobe_screen_waiter.h"
#include "chrome/browser/chromeos/login/ui/captive_portal_window_proxy.h"
#include "chrome/browser/chromeos/login/ui/login_display_host.h"
#include "chrome/browser/chromeos/login/ui/webui_login_view.h"
#include "chrome/browser/chromeos/net/network_portal_detector_test_impl.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chromeos/chromeos_switches.h"
#include "chromeos/dbus/fake_shill_manager_client.h"
#include "chromeos/network/portal_detector/network_portal_detector.h"

namespace chromeos {

namespace {

// Stub implementation of CaptivePortalWindowProxyDelegate, does
// nothing and used to instantiate CaptivePortalWindowProxy.
class CaptivePortalWindowProxyStubDelegate
    : public CaptivePortalWindowProxyDelegate {
 public:
  CaptivePortalWindowProxyStubDelegate() : num_portal_notifications_(0) {}

  ~CaptivePortalWindowProxyStubDelegate() override {}

  void OnPortalDetected() override { ++num_portal_notifications_; }

  int num_portal_notifications() const { return num_portal_notifications_; }

 private:
  int num_portal_notifications_;
};

}  // namespace

class CaptivePortalWindowTest : public InProcessBrowserTest {
 protected:
  void ShowIfRedirected() { captive_portal_window_proxy_->ShowIfRedirected(); }

  void Show() { captive_portal_window_proxy_->Show(); }

  void Close() { captive_portal_window_proxy_->Close(); }

  void OnRedirected() { captive_portal_window_proxy_->OnRedirected(); }

  void OnOriginalURLLoaded() {
    captive_portal_window_proxy_->OnOriginalURLLoaded();
  }

  void CheckState(bool is_shown, int num_portal_notifications) {
    bool actual_is_shown = (CaptivePortalWindowProxy::STATE_DISPLAYED ==
                            captive_portal_window_proxy_->GetState());
    ASSERT_EQ(is_shown, actual_is_shown);
    ASSERT_EQ(num_portal_notifications, delegate_.num_portal_notifications());
  }

  void SetUpCommandLine(base::CommandLine* command_line) override {
    command_line->AppendSwitch(chromeos::switches::kForceLoginManagerInTests);
    command_line->AppendSwitch(chromeos::switches::kLoginManager);
    command_line->AppendSwitch(chromeos::switches::kDisableHIDDetectionOnOOBE);
  }

  void SetUpOnMainThread() override {
    content::WebContents* web_contents =
        LoginDisplayHost::default_host()->GetWebUILoginView()->GetWebContents();
    captive_portal_window_proxy_.reset(
        new CaptivePortalWindowProxy(&delegate_, web_contents));
  }

  void TearDownOnMainThread() override {
    captive_portal_window_proxy_.reset();
  }

 private:
  std::unique_ptr<CaptivePortalWindowProxy> captive_portal_window_proxy_;
  CaptivePortalWindowProxyStubDelegate delegate_;
};

IN_PROC_BROWSER_TEST_F(CaptivePortalWindowTest, Show) {
  Show();
}

IN_PROC_BROWSER_TEST_F(CaptivePortalWindowTest, ShowClose) {
  CheckState(false, 0);

  Show();
  CheckState(true, 0);

  Close();
  CheckState(false, 0);
}

IN_PROC_BROWSER_TEST_F(CaptivePortalWindowTest, OnRedirected) {
  CheckState(false, 0);

  ShowIfRedirected();
  CheckState(false, 0);

  OnRedirected();
  CheckState(true, 1);

  Close();
  CheckState(false, 1);
}

IN_PROC_BROWSER_TEST_F(CaptivePortalWindowTest, OnOriginalURLLoaded) {
  CheckState(false, 0);

  ShowIfRedirected();
  CheckState(false, 0);

  OnRedirected();
  CheckState(true, 1);

  OnOriginalURLLoaded();
  CheckState(false, 1);
}

IN_PROC_BROWSER_TEST_F(CaptivePortalWindowTest, MultipleCalls) {
  CheckState(false, 0);

  ShowIfRedirected();
  CheckState(false, 0);

  Show();
  CheckState(true, 0);

  Close();
  CheckState(false, 0);

  OnRedirected();
  CheckState(false, 1);

  OnOriginalURLLoaded();
  CheckState(false, 1);

  Show();
  CheckState(true, 1);

  OnRedirected();
  CheckState(true, 2);

  Close();
  CheckState(false, 2);

  OnOriginalURLLoaded();
  CheckState(false, 2);
}

class CaptivePortalWindowCtorDtorTest : public LoginManagerTest {
 public:
  CaptivePortalWindowCtorDtorTest() : LoginManagerTest(false) {}
  ~CaptivePortalWindowCtorDtorTest() override {}

  void SetUpInProcessBrowserTestFixture() override {
    LoginManagerTest::SetUpInProcessBrowserTestFixture();

    network_portal_detector_ = new NetworkPortalDetectorTestImpl();
    network_portal_detector::InitializeForTesting(network_portal_detector_);
    NetworkPortalDetector::CaptivePortalState portal_state;
    portal_state.status = NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_PORTAL;
    portal_state.response_code = 200;
    network_portal_detector_->SetDefaultNetworkForTesting(
        FakeShillManagerClient::kFakeEthernetNetworkGuid);
    network_portal_detector_->SetDetectionResultsForTesting(
        FakeShillManagerClient::kFakeEthernetNetworkGuid, portal_state);
  }

 protected:
  NetworkPortalDetectorTestImpl* network_portal_detector() {
    return network_portal_detector_;
  }

  PortalDetectorStrategy::StrategyId strategy_id() {
    return network_portal_detector_->strategy_id();
  }

 private:
  NetworkPortalDetectorTestImpl* network_portal_detector_;

  DISALLOW_COPY_AND_ASSIGN(CaptivePortalWindowCtorDtorTest);
};

IN_PROC_BROWSER_TEST_F(CaptivePortalWindowCtorDtorTest, PRE_OpenPortalDialog) {
  StartupUtils::MarkOobeCompleted();
}

IN_PROC_BROWSER_TEST_F(CaptivePortalWindowCtorDtorTest, OpenPortalDialog) {
  LoginDisplayHost* host = LoginDisplayHost::default_host();
  ASSERT_TRUE(host);
  OobeUI* oobe = host->GetOobeUI();
  ASSERT_TRUE(oobe);

  // Error screen asks portal detector to change detection strategy.
  ErrorScreen* error_screen = oobe->GetErrorScreen();
  ASSERT_TRUE(error_screen);

  ASSERT_EQ(PortalDetectorStrategy::STRATEGY_ID_LOGIN_SCREEN, strategy_id());
  network_portal_detector()->NotifyObserversForTesting();
  OobeScreenWaiter(OobeScreen::SCREEN_ERROR_MESSAGE).Wait();
  ASSERT_EQ(PortalDetectorStrategy::STRATEGY_ID_ERROR_SCREEN, strategy_id());

  error_screen->ShowCaptivePortal();
}

}  // namespace chromeos

// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/app_list/crostini/crostini_installer_view.h"

#include "base/run_loop.h"
#include "base/test/scoped_feature_list.h"
#include "chrome/browser/chromeos/crostini/crostini_util.h"
#include "chrome/browser/ui/app_list/app_list_client_impl.h"
#include "chrome/browser/ui/app_list/app_list_service_impl.h"
#include "chrome/browser/ui/app_list/crostini/crostini_app_model_builder.h"
#include "chrome/browser/ui/app_list/test/chrome_app_list_test_support.h"
#include "chrome/browser/ui/test/test_browser_dialog.h"
#include "chrome/common/chrome_features.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "components/crx_file/id_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/views/window/dialog_client_view.h"

namespace {
constexpr char kCrostiniTerminalAppName[] = "Terminal";
}  // namespace

class CrostiniInstallerViewBrowserTest : public DialogBrowserTest {
 public:
  CrostiniInstallerViewBrowserTest() {}

  // DialogBrowserTest:
  void ShowUi(const std::string& name) override {
    AppListServiceImpl* service = test::GetAppListServiceImpl();
    AppListClientImpl* client = service->GetAppListClient();
    const std::string kCrostiniTerminalId =
        crx_file::id_util::GenerateId(kCrostiniTerminalAppName);
    client->ActivateItem(kCrostiniTerminalId, 0);
  }

  void SetUp() override {
    scoped_feature_list_.InitAndEnableFeature(
        features::kExperimentalCrostiniUI);
    DialogBrowserTest::SetUp();
  }

  CrostiniInstallerView* ActiveView() {
    return CrostiniInstallerView::GetActiveViewForTesting();
  }

  bool HasAcceptButton() {
    return ActiveView()->GetDialogClientView()->ok_button() != nullptr;
  }

  bool HasCancelButton() {
    return ActiveView()->GetDialogClientView()->cancel_button() != nullptr;
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;

  DISALLOW_COPY_AND_ASSIGN(CrostiniInstallerViewBrowserTest);
};

// Test the dialog is actually launched from the app launcher.
IN_PROC_BROWSER_TEST_F(CrostiniInstallerViewBrowserTest, InvokeUi_default) {
  ShowAndVerifyUi();
}

IN_PROC_BROWSER_TEST_F(CrostiniInstallerViewBrowserTest, InstallFlow) {
  ShowUi("default");
  EXPECT_NE(nullptr, ActiveView());
  EXPECT_EQ(ui::DIALOG_BUTTON_OK | ui::DIALOG_BUTTON_CANCEL,
            ActiveView()->GetDialogButtons());

  EXPECT_TRUE(HasAcceptButton());
  EXPECT_TRUE(HasCancelButton());

  ActiveView()->GetDialogClientView()->AcceptWindow();
  EXPECT_FALSE(ActiveView()->GetWidget()->IsClosed());
  EXPECT_FALSE(HasAcceptButton());
  EXPECT_TRUE(HasCancelButton());
}

IN_PROC_BROWSER_TEST_F(CrostiniInstallerViewBrowserTest, Cancel) {
  ShowUi("default");
  EXPECT_NE(nullptr, ActiveView());
  ActiveView()->GetDialogClientView()->CancelWindow();
  EXPECT_TRUE(ActiveView()->GetWidget()->IsClosed());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(nullptr, ActiveView());
}

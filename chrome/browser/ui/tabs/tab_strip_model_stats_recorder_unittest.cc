// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/tabs/tab_strip_model_stats_recorder.h"

#include "base/macros.h"
#include "base/test/histogram_tester.h"
#include "chrome/browser/ui/tabs/tab_strip_model.h"
#include "chrome/browser/ui/tabs/test_tab_strip_model_delegate.h"
#include "chrome/test/base/chrome_render_view_host_test_harness.h"
#include "chrome/test/base/testing_profile.h"
#include "content/public/browser/web_contents.h"
#include "content/public/test/test_web_contents_factory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::HistogramTester;
using content::WebContents;

class TabStripModelStatsRecorderTest : public ChromeRenderViewHostTestHarness {
};

class NoUnloadListenerTabStripModelDelegate : public TestTabStripModelDelegate {
 public:
  NoUnloadListenerTabStripModelDelegate() {}
  ~NoUnloadListenerTabStripModelDelegate() override {}

  bool RunUnloadListenerBeforeClosing(WebContents* contents) override {
    return false;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(NoUnloadListenerTabStripModelDelegate);
};

TEST_F(TabStripModelStatsRecorderTest, BasicTabLifecycle) {
  NoUnloadListenerTabStripModelDelegate delegate;
  TabStripModel tabstrip(&delegate, profile());

  TabStripModelStatsRecorder recorder;
  tabstrip.AddObserver(&recorder);

  HistogramTester tester;

  // Insert the first tab.
  WebContents* contents1 = CreateTestWebContents();
  tabstrip.InsertWebContentsAt(0, contents1, TabStripModel::ADD_ACTIVE);

  // Deactivate the first tab by inserting new tab.
  WebContents* contents2 = CreateTestWebContents();
  tabstrip.InsertWebContentsAt(1, contents2, TabStripModel::ADD_ACTIVE);

  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.Target_Active",
      static_cast<int>(TabStripModelStatsRecorder::TabState::INACTIVE), 1);

  // Reactivate the first tab.
  tabstrip.ActivateTabAt(tabstrip.GetIndexOfWebContents(contents1), true);

  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.Target_Active",
      static_cast<int>(TabStripModelStatsRecorder::TabState::INACTIVE), 2);
  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.Target_Inactive",
      static_cast<int>(TabStripModelStatsRecorder::TabState::ACTIVE), 1);
  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.NumberOfOtherTabsActivatedBeforeMadeActive", 1, 1);

  // Replace the contents of the first tab.
  // TabStripModeStatsRecorder should follow WebContents change.
  WebContents* contents3 = CreateTestWebContents();
  tabstrip.ReplaceWebContentsAt(0, contents3);

  // Close the inactive second tab.
  tabstrip.CloseWebContentsAt(tabstrip.GetIndexOfWebContents(contents2),
                              TabStripModel::CLOSE_USER_GESTURE |
                                  TabStripModel::CLOSE_CREATE_HISTORICAL_TAB);

  tester.ExpectBucketCount(
      "Tabs.StateTransfer.Target_Inactive",
      static_cast<int>(TabStripModelStatsRecorder::TabState::CLOSED), 1);

  // Close the active first tab.
  tabstrip.CloseSelectedTabs();
  tester.ExpectBucketCount(
      "Tabs.StateTransfer.Target_Active",
      static_cast<int>(TabStripModelStatsRecorder::TabState::CLOSED), 1);

  tabstrip.RemoveObserver(&recorder);

  tabstrip.CloseAllTabs();
}

TEST_F(TabStripModelStatsRecorderTest, ObserveMultipleTabStrips) {
  NoUnloadListenerTabStripModelDelegate delegate;
  TabStripModel tabstrip1(&delegate, profile());
  TabStripModel tabstrip2(&delegate, profile());

  TabStripModelStatsRecorder recorder;
  tabstrip1.AddObserver(&recorder);
  tabstrip2.AddObserver(&recorder);

  HistogramTester tester;

  // Create a tab in strip 1.
  WebContents* contents1 = CreateTestWebContents();
  tabstrip1.InsertWebContentsAt(0, contents1, TabStripModel::ADD_ACTIVE);

  // Create a tab in strip 2.
  WebContents* contents2 = CreateTestWebContents();
  tabstrip2.InsertWebContentsAt(0, contents2, TabStripModel::ADD_ACTIVE);

  // Create another tab in strip 1.
  WebContents* contents3 = CreateTestWebContents();
  tabstrip1.InsertWebContentsAt(1, contents3, TabStripModel::ADD_ACTIVE);

  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.Target_Active",
      static_cast<int>(TabStripModelStatsRecorder::TabState::INACTIVE), 1);

  // Create another tab in strip 2.
  WebContents* contents4 = CreateTestWebContents();
  tabstrip2.InsertWebContentsAt(1, contents4, TabStripModel::ADD_ACTIVE);

  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.Target_Active",
      static_cast<int>(TabStripModelStatsRecorder::TabState::INACTIVE), 2);

  // Move the first tab in strip 1 to strip 2
  tabstrip1.DetachWebContentsAt(0).release();
  tabstrip2.InsertWebContentsAt(2, contents1, TabStripModel::ADD_ACTIVE);

  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.Target_Active",
      static_cast<int>(TabStripModelStatsRecorder::TabState::INACTIVE), 3);
  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.Target_Inactive",
      static_cast<int>(TabStripModelStatsRecorder::TabState::ACTIVE), 1);

  // Switch to the first tab in strip 2.
  tabstrip2.ActivateTabAt(0, true);
  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.Target_Active",
      static_cast<int>(TabStripModelStatsRecorder::TabState::INACTIVE), 4);
  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.Target_Inactive",
      static_cast<int>(TabStripModelStatsRecorder::TabState::ACTIVE), 2);

  // Close the first tab in strip 2.
  tabstrip2.CloseSelectedTabs();
  tester.ExpectBucketCount(
      "Tabs.StateTransfer.Target_Active",
      static_cast<int>(TabStripModelStatsRecorder::TabState::CLOSED), 1);

  tabstrip1.RemoveObserver(&recorder);
  tabstrip2.RemoveObserver(&recorder);

  tabstrip1.CloseAllTabs();
  tabstrip2.CloseAllTabs();
}

TEST_F(TabStripModelStatsRecorderTest,
       NumberOfOtherTabsActivatedBeforeMadeActive) {
  NoUnloadListenerTabStripModelDelegate delegate;
  TabStripModel tabstrip(&delegate, profile());

  TabStripModelStatsRecorder recorder;
  tabstrip.AddObserver(&recorder);

  HistogramTester tester;

  // Create first tab
  WebContents* contents0 = CreateTestWebContents();
  tabstrip.InsertWebContentsAt(0, contents0, TabStripModel::ADD_ACTIVE);

  // Add 9 more tabs and activate them
  for (int i = 1; i < 10; ++i) {
    WebContents* contents = CreateTestWebContents();
    tabstrip.InsertWebContentsAt(1, contents, TabStripModel::ADD_ACTIVE);
  }

  // Reactivate the first tab
  tabstrip.ActivateTabAt(tabstrip.GetIndexOfWebContents(contents0), true);

  tester.ExpectUniqueSample(
      "Tabs.StateTransfer.NumberOfOtherTabsActivatedBeforeMadeActive", 9, 1);

  tabstrip.RemoveObserver(&recorder);
  tabstrip.CloseAllTabs();
}

TEST_F(TabStripModelStatsRecorderTest,
       NumberOfOtherTabsActivatedBeforeMadeActive_CycleTabs) {
  NoUnloadListenerTabStripModelDelegate delegate;
  TabStripModel tabstrip(&delegate, profile());

  TabStripModelStatsRecorder recorder;
  tabstrip.AddObserver(&recorder);

  HistogramTester tester;

  // Create tab 0, 1, 2
  WebContents* contents0 = CreateTestWebContents();
  WebContents* contents1 = CreateTestWebContents();
  WebContents* contents2 = CreateTestWebContents();
  tabstrip.InsertWebContentsAt(0, contents0, TabStripModel::ADD_ACTIVE);
  tabstrip.InsertWebContentsAt(1, contents1, TabStripModel::ADD_ACTIVE);
  tabstrip.InsertWebContentsAt(2, contents2, TabStripModel::ADD_ACTIVE);

  // Switch between tabs {0,1} for 5 times, then switch to tab 2
  for (int i = 0; i < 5; ++i) {
    tabstrip.ActivateTabAt(tabstrip.GetIndexOfWebContents(contents0), true);
    tabstrip.ActivateTabAt(tabstrip.GetIndexOfWebContents(contents1), true);
  }
  tabstrip.ActivateTabAt(tabstrip.GetIndexOfWebContents(contents2), true);

  EXPECT_THAT(
      tester.GetAllSamples(
          "Tabs.StateTransfer.NumberOfOtherTabsActivatedBeforeMadeActive"),
      testing::ElementsAre(base::Bucket(1, 8), base::Bucket(2, 2),
                           base::Bucket(10, 1)));

  tabstrip.RemoveObserver(&recorder);
  tabstrip.CloseAllTabs();
}

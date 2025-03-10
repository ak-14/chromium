// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/display/manager/display_manager.h"

#include "ash/accelerators/accelerator_commands.h"
#include "ash/display/cursor_window_controller.h"
#include "ash/display/display_configuration_controller.h"
#include "ash/display/display_util.h"
#include "ash/display/mirror_window_controller.h"
#include "ash/display/mirror_window_test_api.h"
#include "ash/display/screen_orientation_controller.h"
#include "ash/display/screen_orientation_controller_test_api.h"
#include "ash/display/window_tree_host_manager.h"
#include "ash/public/cpp/app_types.h"
#include "ash/public/cpp/ash_switches.h"
#include "ash/screen_util.h"
#include "ash/shell.h"
#include "ash/strings/grit/ash_strings.h"
#include "ash/test/ash_test_base.h"
#include "ash/wm/tablet_mode/tablet_mode_controller.h"
#include "ash/wm/window_state.h"
#include "ash/wm/window_util.h"
#include "base/command_line.h"
#include "base/format_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "build/build_config.h"
#include "chromeos/accelerometer/accelerometer_reader.h"
#include "chromeos/accelerometer/accelerometer_types.h"
#include "ui/aura/client/aura_constants.h"
#include "ui/aura/env.h"
#include "ui/aura/window_observer.h"
#include "ui/aura/window_tree_host.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/display/display.h"
#include "ui/display/display_layout.h"
#include "ui/display/display_layout_builder.h"
#include "ui/display/display_observer.h"
#include "ui/display/display_switches.h"
#include "ui/display/manager/display_change_observer.h"
#include "ui/display/manager/display_layout_store.h"
#include "ui/display/manager/display_manager_utilities.h"
#include "ui/display/manager/display_util.h"
#include "ui/display/manager/fake_display_snapshot.h"
#include "ui/display/manager/managed_display_info.h"
#include "ui/display/manager/test/touch_device_manager_test_api.h"
#include "ui/display/screen.h"
#include "ui/display/test/display_manager_test_api.h"
#include "ui/events/devices/touchscreen_device.h"
#include "ui/events/test/event_generator.h"
#include "ui/gfx/font_render_params.h"

namespace ash {

using std::vector;
using std::string;

using base::StringPrintf;

namespace {

std::string ToDisplayName(int64_t id) {
  return "x-" + base::Int64ToString(id);
}

}  // namespace

class DisplayManagerTest : public AshTestBase,
                           public display::DisplayObserver,
                           public aura::WindowObserver {
 public:
  DisplayManagerTest() = default;
  ~DisplayManagerTest() override = default;

  void SetUp() override {
    AshTestBase::SetUp();
    display::Screen::GetScreen()->AddObserver(this);
    Shell::GetPrimaryRootWindow()->AddObserver(this);
  }
  void TearDown() override {
    Shell::GetPrimaryRootWindow()->RemoveObserver(this);
    display::Screen::GetScreen()->RemoveObserver(this);
    AshTestBase::TearDown();
  }

  const vector<display::Display>& changed() const { return changed_; }
  const vector<display::Display>& added() const { return added_; }
  uint32_t changed_metrics() const { return changed_metrics_; }

  string GetCountSummary() const {
    return StringPrintf("%" PRIuS " %" PRIuS " %" PRIuS " %" PRIuS " %" PRIuS,
                        changed_.size(), added_.size(), removed_count_,
                        will_process_count_, did_process_count_);
  }

  void reset() {
    changed_.clear();
    added_.clear();
    removed_count_ = will_process_count_ = did_process_count_ = 0U;
    changed_metrics_ = 0U;
    root_window_destroyed_ = false;
  }

  bool root_window_destroyed() const { return root_window_destroyed_; }

  const display::ManagedDisplayInfo& GetDisplayInfo(
      const display::Display& display) {
    return display_manager()->GetDisplayInfo(display.id());
  }

  const display::ManagedDisplayInfo& GetDisplayInfoAt(int index) {
    return GetDisplayInfo(display_manager()->GetDisplayAt(index));
  }

  const display::Display& GetDisplayForId(int64_t id) {
    return display_manager()->GetDisplayForId(id);
  }

  const display::ManagedDisplayInfo& GetDisplayInfoForId(int64_t id) {
    return GetDisplayInfo(display_manager()->GetDisplayForId(id));
  }

  // aura::DisplayObserver overrides:
  void OnWillProcessDisplayChanges() override { ++will_process_count_; }
  void OnDidProcessDisplayChanges() override { ++did_process_count_; }
  void OnDisplayMetricsChanged(const display::Display& display,
                               uint32_t changed_metrics) override {
    changed_.push_back(display);
    changed_metrics_ |= changed_metrics;
  }
  void OnDisplayAdded(const display::Display& new_display) override {
    added_.push_back(new_display);
  }
  void OnDisplayRemoved(const display::Display& old_display) override {
    ++removed_count_;
  }

  // aura::WindowObserver overrides:
  void OnWindowDestroying(aura::Window* window) override {
    ASSERT_EQ(Shell::GetPrimaryRootWindow(), window);
    root_window_destroyed_ = true;
  }

  // Returns true if there exists any overlapping mirroring displays.
  bool OverlappingMirroringDisplaysExist() {
    const auto& mirroring_displays =
        display_manager()->software_mirroring_display_list();
    for (size_t i = 0; i < mirroring_displays.size() - 1; ++i) {
      for (size_t j = i + 1; j < mirroring_displays.size(); ++j) {
        const gfx::Rect& bounds_1 = mirroring_displays[i].bounds();
        const gfx::Rect& bounds_2 = mirroring_displays[j].bounds();
        if (bounds_1.Intersects(bounds_2))
          return true;
      }
    }

    return false;
  }

  void SetSoftwareMirrorMode(bool active) {
    display_manager()->SetMirrorMode(
        active ? display::MirrorMode::kNormal : display::MirrorMode::kOff,
        base::nullopt);
    RunAllPendingInMessageLoop();
  }

 private:
  vector<display::Display> changed_;
  vector<display::Display> added_;
  size_t removed_count_ = 0u;
  size_t will_process_count_ = 0u;
  size_t did_process_count_ = 0u;
  bool root_window_destroyed_ = false;
  uint32_t changed_metrics_ = 0u;

  DISALLOW_COPY_AND_ASSIGN(DisplayManagerTest);
};

class DisplayManagerTestDisableMultiMirroring : public DisplayManagerTest {
 public:
  DisplayManagerTestDisableMultiMirroring() = default;
  ~DisplayManagerTestDisableMultiMirroring() override = default;

  // DisplayManagerTest:
  void SetUp() override {
    base::CommandLine::ForCurrentProcess()->AppendSwitch(
        ::switches::kDisableMultiMirroring);
    DisplayManagerTest::SetUp();
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(DisplayManagerTestDisableMultiMirroring);
};

TEST_F(DisplayManagerTest, UpdateDisplayTest) {
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());

  // Update primary and add seconary.
  UpdateDisplay("100+0-500x500,0+501-400x400");
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ("0,0 500x500",
            display_manager()->GetDisplayAt(0).bounds().ToString());

  EXPECT_EQ("2 1 0 1 1", GetCountSummary());
  EXPECT_EQ(display_manager()->GetDisplayAt(0).id(), changed()[0].id());
  EXPECT_EQ(display_manager()->GetDisplayAt(1).id(), changed()[1].id());
  EXPECT_EQ(display_manager()->GetDisplayAt(1).id(), added()[0].id());
  EXPECT_EQ("0,0 500x500", changed()[0].bounds().ToString());
  EXPECT_EQ("500,0 400x400", changed()[1].bounds().ToString());
  // Secondary display is on right.
  EXPECT_EQ("500,0 400x400", added()[0].bounds().ToString());
  EXPECT_EQ("0,501 400x400",
            GetDisplayInfo(added()[0]).bounds_in_native().ToString());
  reset();

  // Delete secondary.
  UpdateDisplay("100+0-500x500");
  EXPECT_EQ("0 0 1 1 1", GetCountSummary());
  reset();

  // Change primary.
  UpdateDisplay("1+1-1000x600");
  EXPECT_EQ("1 0 0 1 1", GetCountSummary());
  EXPECT_EQ(display_manager()->GetDisplayAt(0).id(), changed()[0].id());
  EXPECT_EQ("0,0 1000x600", changed()[0].bounds().ToString());
  reset();

  // Add secondary.
  UpdateDisplay("1+1-1000x600,1002+0-600x400");
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ("1 1 0 1 1", GetCountSummary());
  EXPECT_EQ(display_manager()->GetDisplayAt(1).id(), changed()[0].id());
  EXPECT_EQ(display_manager()->GetDisplayAt(1).id(), added()[0].id());
  // Secondary display is on right.
  EXPECT_EQ("1000,0 600x400", added()[0].bounds().ToString());
  EXPECT_EQ("1002,0 600x400",
            GetDisplayInfo(added()[0]).bounds_in_native().ToString());
  reset();

  // Secondary removed, primary changed.
  UpdateDisplay("1+1-800x300");
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ("1 0 1 1 1", GetCountSummary());
  EXPECT_EQ(display_manager()->GetDisplayAt(0).id(), changed()[0].id());
  EXPECT_EQ("0,0 800x300", changed()[0].bounds().ToString());
  reset();

  // # of display can go to zero when screen is off.
  const vector<display::ManagedDisplayInfo> empty;
  display_manager()->OnNativeDisplaysChanged(empty);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  // Going to 0 displays doesn't actually change the list and is effectively
  // ignored.
  EXPECT_EQ("0 0 0 0 0", GetCountSummary());
  EXPECT_FALSE(root_window_destroyed());
  // Display configuration stays the same
  EXPECT_EQ("0,0 800x300",
            display_manager()->GetDisplayAt(0).bounds().ToString());
  reset();

  // Connect to display again
  UpdateDisplay("100+100-500x400");
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ("1 0 0 1 1", GetCountSummary());
  EXPECT_FALSE(root_window_destroyed());
  EXPECT_EQ("0,0 500x400", changed()[0].bounds().ToString());
  EXPECT_EQ("100,100 500x400",
            GetDisplayInfo(changed()[0]).bounds_in_native().ToString());
  reset();

  // Go back to zero and wake up with multiple displays.
  display_manager()->OnNativeDisplaysChanged(empty);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_FALSE(root_window_destroyed());
  reset();

  // Add secondary.
  UpdateDisplay("0+0-1000x600,1000+1000-600x400");
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ("0,0 1000x600",
            display_manager()->GetDisplayAt(0).bounds().ToString());
  // Secondary display is on right.
  EXPECT_EQ("1000,0 600x400",
            display_manager()->GetDisplayAt(1).bounds().ToString());
  EXPECT_EQ("1000,1000 600x400",
            GetDisplayInfoAt(1).bounds_in_native().ToString());
  reset();

  // Changing primary will update secondary as well.
  UpdateDisplay("0+0-800x600,1000+1000-600x400");
  EXPECT_EQ("2 0 0 1 1", GetCountSummary());
  reset();
  EXPECT_EQ("0,0 800x600",
            display_manager()->GetDisplayAt(0).bounds().ToString());
  EXPECT_EQ("800,0 600x400",
            display_manager()->GetDisplayAt(1).bounds().ToString());
}

TEST_F(DisplayManagerTest, ScaleOnlyChange) {
  display_manager()->ToggleDisplayScaleFactor();
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_BOUNDS);
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_WORK_AREA);
}

// Test in emulation mode (use_fullscreen_host_window=false)
TEST_F(DisplayManagerTest, EmulatorTest) {
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());

  display_manager()->AddRemoveDisplay();
  // Update primary and add seconary.
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ("1 1 0 1 1", GetCountSummary());
  reset();

  display_manager()->AddRemoveDisplay();
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ("0 0 1 1 1", GetCountSummary());
  reset();

  display_manager()->AddRemoveDisplay();
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ("1 1 0 1 1", GetCountSummary());
}

// Tests support for 3 displays.
TEST_F(DisplayManagerTest, UpdateThreeDisplaysWithDefaultLayout) {
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());

  // Test with three displays. Native origin will not affect ash
  // display layout.
  UpdateDisplay("0+0-640x480,1000+0-320x200,2000+0-400x300");

  EXPECT_EQ(3U, display_manager()->GetNumDisplays());
  EXPECT_EQ("0,0 640x480",
            display_manager()->GetDisplayAt(0).bounds().ToString());
  EXPECT_EQ("640,0 320x200",
            display_manager()->GetDisplayAt(1).bounds().ToString());
  EXPECT_EQ("960,0 400x300",
            display_manager()->GetDisplayAt(2).bounds().ToString());

  EXPECT_EQ("3 2 0 1 1", GetCountSummary());
  EXPECT_EQ(display_manager()->GetDisplayAt(0).id(), changed()[0].id());
  EXPECT_EQ(display_manager()->GetDisplayAt(1).id(), changed()[1].id());
  EXPECT_EQ(display_manager()->GetDisplayAt(2).id(), changed()[2].id());
  EXPECT_EQ(display_manager()->GetDisplayAt(1).id(), added()[0].id());
  EXPECT_EQ(display_manager()->GetDisplayAt(2).id(), added()[1].id());
  EXPECT_EQ("0,0 640x480", changed()[0].bounds().ToString());
  EXPECT_EQ("640,0 320x200", changed()[1].bounds().ToString());
  EXPECT_EQ("960,0 400x300", changed()[2].bounds().ToString());
  // Secondary and terniary displays are on right.
  EXPECT_EQ("640,0 320x200", added()[0].bounds().ToString());
  EXPECT_EQ("1000,0 320x200",
            GetDisplayInfo(added()[0]).bounds_in_native().ToString());
  EXPECT_EQ("960,0 400x300", added()[1].bounds().ToString());
  EXPECT_EQ("2000,0 400x300",
            GetDisplayInfo(added()[1]).bounds_in_native().ToString());

  // Verify calling ReconfigureDisplays doesn't change anything.
  display_manager()->ReconfigureDisplays();
  EXPECT_EQ(3U, display_manager()->GetNumDisplays());
  EXPECT_EQ("0,0 640x480",
            display_manager()->GetDisplayAt(0).bounds().ToString());
  EXPECT_EQ("640,0 320x200",
            display_manager()->GetDisplayAt(1).bounds().ToString());
  EXPECT_EQ("960,0 400x300",
            display_manager()->GetDisplayAt(2).bounds().ToString());

  display::DisplayPlacement default_placement(display::DisplayPlacement::BOTTOM,
                                              10);
  display_manager()->layout_store()->SetDefaultDisplayPlacement(
      default_placement);

  // Test with new displays.
  UpdateDisplay("640x480");
  UpdateDisplay("640x480,320x200,400x300");

  EXPECT_EQ("0,0 640x480",
            display_manager()->GetDisplayAt(0).bounds().ToString());
  EXPECT_EQ("10,480 320x200",
            display_manager()->GetDisplayAt(1).bounds().ToString());
  EXPECT_EQ("20,680 400x300",
            display_manager()->GetDisplayAt(2).bounds().ToString());
}

TEST_F(DisplayManagerTest, LayoutMorethanThreeDisplaysTest) {
  int64_t primary_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();
  display::DisplayIdList list = display::test::CreateDisplayIdListN(
      3, primary_id, primary_id + 1, primary_id + 2);
  {
    // Layout: [2]
    //         [1][P]
    display::DisplayLayoutBuilder builder(primary_id);
    builder.AddDisplayPlacement(list[1], primary_id,
                                display::DisplayPlacement::LEFT, 10);
    builder.AddDisplayPlacement(list[2], list[1],
                                display::DisplayPlacement::TOP, 10);
    display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
        list, builder.Build());

    UpdateDisplay("640x480,320x200,400x300");

    EXPECT_EQ(3U, display_manager()->GetNumDisplays());

    EXPECT_EQ("0,0 640x480",
              display_manager()->GetDisplayAt(0).bounds().ToString());
    EXPECT_EQ("-320,10 320x200",
              display_manager()->GetDisplayAt(1).bounds().ToString());

    // The above layout causes an overlap between [P] and [2], making [2]'s
    // bounds be "-310,-290 400x300" if the overlap is not fixed. The overlap
    // must be detected and fixed and [2] is shifted up to remove the overlap.
    EXPECT_EQ("-310,-300 400x300",
              display_manager()->GetDisplayAt(2).bounds().ToString());
  }
  {
    // Layout: [1]
    //         [P][2]
    display::DisplayLayoutBuilder builder(primary_id);
    builder.AddDisplayPlacement(list[1], primary_id,
                                display::DisplayPlacement::TOP, 10);
    builder.AddDisplayPlacement(list[2], primary_id,
                                display::DisplayPlacement::RIGHT, 10);
    display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
        list, builder.Build());

    UpdateDisplay("640x480,320x200,400x300");

    EXPECT_EQ(3U, display_manager()->GetNumDisplays());

    EXPECT_EQ("0,0 640x480",
              display_manager()->GetDisplayAt(0).bounds().ToString());
    EXPECT_EQ("10,-200 320x200",
              display_manager()->GetDisplayAt(1).bounds().ToString());
    EXPECT_EQ("640,10 400x300",
              display_manager()->GetDisplayAt(2).bounds().ToString());
  }
  {
    // Layout: [P]
    //         [2]
    //         [1]
    display::DisplayLayoutBuilder builder(primary_id);
    builder.AddDisplayPlacement(list[1], list[2],
                                display::DisplayPlacement::BOTTOM, 10);
    builder.AddDisplayPlacement(list[2], primary_id,
                                display::DisplayPlacement::BOTTOM, 10);
    display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
        list, builder.Build());

    UpdateDisplay("640x480,320x200,400x300");

    EXPECT_EQ(3U, display_manager()->GetNumDisplays());

    EXPECT_EQ("0,0 640x480",
              display_manager()->GetDisplayAt(0).bounds().ToString());
    EXPECT_EQ("20,780 320x200",
              display_manager()->GetDisplayAt(1).bounds().ToString());
    EXPECT_EQ("10,480 400x300",
              display_manager()->GetDisplayAt(2).bounds().ToString());
  }

  {
    list = display::test::CreateDisplayIdListN(5, primary_id, primary_id + 1,
                                               primary_id + 2, primary_id + 3,
                                               primary_id + 4);
    // Layout: [P][2]
    //      [3][4]
    //      [1]
    display::DisplayLayoutBuilder builder(primary_id);
    builder.AddDisplayPlacement(list[2], primary_id,
                                display::DisplayPlacement::RIGHT, 10);
    builder.AddDisplayPlacement(list[1], list[3],
                                display::DisplayPlacement::BOTTOM, 10);
    builder.AddDisplayPlacement(list[3], list[4],
                                display::DisplayPlacement::LEFT, 10);
    builder.AddDisplayPlacement(list[4], primary_id,
                                display::DisplayPlacement::BOTTOM, 10);
    display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
        list, builder.Build());

    UpdateDisplay("640x480,320x200,400x300,300x200,200x100");

    EXPECT_EQ(5U, display_manager()->GetNumDisplays());

    EXPECT_EQ("0,0 640x480",
              display_manager()->GetDisplayAt(0).bounds().ToString());
    // 2nd is right of the primary.
    EXPECT_EQ("640,10 400x300",
              display_manager()->GetDisplayAt(2).bounds().ToString());
    // 4th is bottom of the primary.
    EXPECT_EQ("10,480 200x100",
              display_manager()->GetDisplayAt(4).bounds().ToString());
    // 3rd is the left of 4th.
    EXPECT_EQ("-290,480 300x200",
              display_manager()->GetDisplayAt(3).bounds().ToString());
    // 1st is the bottom of 3rd.
    EXPECT_EQ("-280,680 320x200",
              display_manager()->GetDisplayAt(1).bounds().ToString());
  }
}

// Makes sure that layouts with overlapped displays are detected and fixed when
// applied.
TEST_F(DisplayManagerTest, NoOverlappedDisplays) {
  int64_t primary_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();
  {
    // Layout with multiple overlaps and special cases:
    //
    //            +-----+
    //       +----+-+6  |
    //       |  5 | |   |
    //  +----+----+ |   |
    //  | 7  |    | |   |
    //  +----+----+-+---+---+-+---------+
    //       |      |   P   | |   2     |
    //       +------+       | |         +----------+
    //              |       | |         |     3    |
    //              |       | |         |          |
    //              +--+----+-+-+-+-----+--+       |
    //                 |    1   | |   4 |  |       |
    //                 |        | |     +--+-------+
    //                 |        | |        |
    //                 +--------+ +--------+

    display::DisplayIdList list = display::test::CreateDisplayIdListN(
        8, primary_id, primary_id + 1, primary_id + 2, primary_id + 3,
        primary_id + 4, primary_id + 5, primary_id + 6, primary_id + 7);
    display::DisplayLayoutBuilder builder(primary_id);
    builder.AddDisplayPlacement(list[1], primary_id,
                                display::DisplayPlacement::BOTTOM, 50);
    builder.AddDisplayPlacement(list[2], list[1],
                                display::DisplayPlacement::TOP, 300);
    builder.AddDisplayPlacement(list[3], list[2],
                                display::DisplayPlacement::RIGHT, 30);
    builder.AddDisplayPlacement(list[4], list[2],
                                display::DisplayPlacement::BOTTOM, 400);
    builder.AddDisplayPlacement(list[5], primary_id,
                                display::DisplayPlacement::LEFT, -300);
    builder.AddDisplayPlacement(list[6], primary_id,
                                display::DisplayPlacement::TOP, -250);
    builder.AddDisplayPlacement(list[7], list[6],
                                display::DisplayPlacement::LEFT, 250);
    display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
        list, builder.Build());

    UpdateDisplay(
        "480x400,480x400,480x400,480x400,480x400,480x400,480x400,530x150");

    // The resulting layout after overlaps had been removed:
    //
    //
    //  +---------+
    //  | 7       +-----+
    //  +-+-------+  6  |
    //    |   5   |     |
    //    |       |     |
    //    |       |     |
    //    |       |-+---+----+---------+
    //    |       | |   P    |   2     |
    //    +-------+ |        |         +----------+
    //              |        |         |     3    |
    //              |        |         |          |
    //              +--+-----+-+-------+          |
    //                 |   1   |       |          |
    //                 |       |  +----+---+------+
    //                 |       |  |   4    |
    //                 +-------+  |        |
    //                            |        |
    //                            +--------+

    EXPECT_EQ(8U, display_manager()->GetNumDisplays());

    EXPECT_EQ(gfx::Rect(0, 0, 480, 400),
              display_manager()->GetDisplayAt(0).bounds());
    EXPECT_EQ(gfx::Rect(50, 400, 480, 400),
              display_manager()->GetDisplayAt(1).bounds());
    EXPECT_EQ(gfx::Rect(480, 0, 480, 400),
              display_manager()->GetDisplayAt(2).bounds());
    EXPECT_EQ(gfx::Rect(960, 30, 480, 400),
              display_manager()->GetDisplayAt(3).bounds());
    EXPECT_EQ(gfx::Rect(730, 430, 480, 400),
              display_manager()->GetDisplayAt(4).bounds());
    EXPECT_EQ(gfx::Rect(-730, -300, 480, 400),
              display_manager()->GetDisplayAt(5).bounds());
    EXPECT_EQ(gfx::Rect(-250, -400, 480, 400),
              display_manager()->GetDisplayAt(6).bounds());
    EXPECT_EQ(gfx::Rect(-780, -450, 530, 150),
              display_manager()->GetDisplayAt(7).bounds());

    // Expect that the displays have been reparented correctly, such that a
    // child is always touching its parent.
    display::DisplayLayoutBuilder expected_layout_builder(primary_id);
    expected_layout_builder.AddDisplayPlacement(
        list[1], primary_id, display::DisplayPlacement::BOTTOM, 50);
    expected_layout_builder.AddDisplayPlacement(
        list[2], list[1], display::DisplayPlacement::TOP, 430);
    expected_layout_builder.AddDisplayPlacement(
        list[3], list[2], display::DisplayPlacement::RIGHT, 30);
    // [4] became a child of [3] instead of [2] as they no longer touch.
    expected_layout_builder.AddDisplayPlacement(
        list[4], list[3], display::DisplayPlacement::BOTTOM, -230);
    // [5] became a child of [6] instead of [P] as they no longer touch.
    expected_layout_builder.AddDisplayPlacement(
        list[5], list[6], display::DisplayPlacement::LEFT, 100);
    expected_layout_builder.AddDisplayPlacement(
        list[6], primary_id, display::DisplayPlacement::TOP, -250);
    expected_layout_builder.AddDisplayPlacement(
        list[7], list[6], display::DisplayPlacement::LEFT, -50);

    const display::DisplayLayout& layout =
        display_manager()->GetCurrentResolvedDisplayLayout();

    EXPECT_TRUE(
        layout.HasSamePlacementList(*(expected_layout_builder.Build())));
  }

  {
    // The following is a special case where a child display is closer to the
    // origin than its parent. Test that we can handle it successfully without
    // introducing a circular dependency.
    //
    // +---------+
    // |    P    |    +---------+
    // |         |    |    3    |
    // |         |    |         |
    // |         |    |         |
    // +------+--+----+         |
    // |    1 |  | 2  +---------+
    // |      |  |    |
    // |      |  |    |
    // |      |  |    |
    // +------+--+----+
    //

    display::DisplayIdList list = display::test::CreateDisplayIdListN(
        4, primary_id, primary_id + 1, primary_id + 2, primary_id + 3);
    display::DisplayLayoutBuilder builder(primary_id);
    builder.AddDisplayPlacement(list[1], primary_id,
                                display::DisplayPlacement::BOTTOM, 0);
    builder.AddDisplayPlacement(list[2], primary_id,
                                display::DisplayPlacement::BOTTOM, 464);
    builder.AddDisplayPlacement(list[3], list[2],
                                display::DisplayPlacement::RIGHT, -700);
    display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
        list, builder.Build());
    UpdateDisplay("696x800,696x800,300x800,696x800");

    // The expected layout should be:
    //
    // +---------+
    // |    P    |       +---------+
    // |         |       |    3    |
    // |         |       |         |
    // |         |       |         |
    // +---------+-------+         |
    // |    1    |   2   +---------+
    // |         |       |
    // |         |       |
    // |         |       |
    // +---------+-------+
    //
    //

    EXPECT_EQ(4U, display_manager()->GetNumDisplays());
    EXPECT_EQ(gfx::Rect(0, 0, 696, 800),
              display_manager()->GetDisplayAt(0).bounds());
    EXPECT_EQ(gfx::Rect(0, 800, 696, 800),
              display_manager()->GetDisplayAt(1).bounds());
    EXPECT_EQ(gfx::Rect(696, 800, 300, 800),
              display_manager()->GetDisplayAt(2).bounds());
    EXPECT_EQ(gfx::Rect(996, 100, 696, 800),
              display_manager()->GetDisplayAt(3).bounds());

    // This case if not handled correctly might lead to a cyclic dependency.
    // Make sure this doesn't happen.
    display::DisplayLayoutBuilder expected_layout_builder(primary_id);
    expected_layout_builder.AddDisplayPlacement(
        list[1], primary_id, display::DisplayPlacement::BOTTOM, 0);
    expected_layout_builder.AddDisplayPlacement(
        list[2], primary_id, display::DisplayPlacement::BOTTOM, 696);
    expected_layout_builder.AddDisplayPlacement(
        list[3], list[2], display::DisplayPlacement::RIGHT, -700);

    const display::DisplayLayout& layout =
        display_manager()->GetCurrentResolvedDisplayLayout();
    EXPECT_TRUE(
        layout.HasSamePlacementList(*(expected_layout_builder.Build())));
  }

  {
    // The following is a layout with an overlap to the left of the primary
    // display.
    //
    // +---------+---------+
    // |    1    |    P    |
    // |         |         |
    // +---------+         |
    // |         |         |
    // +---------+---------+
    // |    2    |
    // |         |
    // +---------+

    display::DisplayIdList list = display::test::CreateDisplayIdListN(
        3, primary_id, primary_id + 1, primary_id + 2);
    display::DisplayLayoutBuilder builder(primary_id);
    builder.AddDisplayPlacement(list[1], primary_id,
                                display::DisplayPlacement::LEFT, 0);
    builder.AddDisplayPlacement(list[2], primary_id,
                                display::DisplayPlacement::LEFT, 250);
    display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
        list, builder.Build());
    UpdateDisplay("696x500,696x500,696x500");

    // The expected layout should be:
    //
    // +---------+---------+
    // |    1    |    P    |
    // |         |         |
    // |         |         |
    // |         |         |
    // +---------+---------+
    // |    2    |
    // |         |
    // |         |
    // |         |
    // +---------+

    EXPECT_EQ(3U, display_manager()->GetNumDisplays());
    EXPECT_EQ(gfx::Rect(0, 0, 696, 500),
              display_manager()->GetDisplayAt(0).bounds());
    EXPECT_EQ(gfx::Rect(-696, 0, 696, 500),
              display_manager()->GetDisplayAt(1).bounds());
    EXPECT_EQ(gfx::Rect(-696, 500, 696, 500),
              display_manager()->GetDisplayAt(2).bounds());
  }

  {
    // The following is a layout with an overlap occurring above the primary
    // display.
    //
    //    +------+--+------+
    //    |  2   |  | 1    |
    //    |      |  |      |
    //    |      |  |      |
    //    |      |  |      |
    //    +------+--+------+
    //           |    P    |
    //           |         |
    //           |         |
    //           |         |
    //           +---------+
    //

    display::DisplayIdList list = display::test::CreateDisplayIdListN(
        3, primary_id, primary_id + 1, primary_id + 2);
    display::DisplayLayoutBuilder builder(primary_id);
    builder.AddDisplayPlacement(list[1], primary_id,
                                display::DisplayPlacement::TOP, 0);
    builder.AddDisplayPlacement(list[2], primary_id,
                                display::DisplayPlacement::TOP, -348);
    display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
        list, builder.Build());
    UpdateDisplay("696x500,696x500,696x500");

    // The expected layout should be:
    //
    // +---------+---------+
    // |    2    |    1    |
    // |         |         |
    // |         |         |
    // |         |         |
    // +---------+---------+
    //           |    P    |
    //           |         |
    //           |         |
    //           |         |
    //           +---------+
    //

    EXPECT_EQ(3U, display_manager()->GetNumDisplays());
    EXPECT_EQ(gfx::Rect(0, 0, 696, 500),
              display_manager()->GetDisplayAt(0).bounds());
    EXPECT_EQ(gfx::Rect(0, -500, 696, 500),
              display_manager()->GetDisplayAt(1).bounds());
    EXPECT_EQ(gfx::Rect(-696, -500, 696, 500),
              display_manager()->GetDisplayAt(2).bounds());
  }
}

TEST_F(DisplayManagerTest, NoOverlappedDisplaysNotFitBetweenTwo) {
  //    +------+--+----+--+------+
  //    |  1   |  |  2 |  |  3   |
  //    |      |  |    |  |      |
  //    |      |  |    |  |      |
  //    |      |  |    |  |      |
  //    +-+----+--+----+--+---+--+
  //      |         P         |
  //      |                   |
  //      |                   |
  //      |                   |
  //      +-------------------+
  //

  int64_t primary_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();
  display::DisplayIdList list = display::test::CreateDisplayIdListN(
      4, primary_id, primary_id + 1, primary_id + 2, primary_id + 3);
  display::DisplayLayoutBuilder builder(primary_id);
  builder.AddDisplayPlacement(list[1], primary_id,
                              display::DisplayPlacement::TOP, -110);
  builder.AddDisplayPlacement(list[2], primary_id,
                              display::DisplayPlacement::TOP, 300);
  builder.AddDisplayPlacement(list[3], primary_id,
                              display::DisplayPlacement::TOP, 600);
  display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
      list, builder.Build());
  UpdateDisplay("1200x500,600x500,600x500,600x500");

  // The expected layout should be:
  //
  //    +---------+---------+---------+
  //    |    1    |    2    |    3    |
  //    |         |         |         |
  //    |         |         |         |
  //    |         |         |         |
  //    +-+-------+---------+-+-------+
  //      |         P         |
  //      |                   |
  //      |                   |
  //      |                   |
  //      +-------------------+
  //

  EXPECT_EQ(4U, display_manager()->GetNumDisplays());
  EXPECT_EQ(gfx::Rect(0, 0, 1200, 500),
            display_manager()->GetDisplayAt(0).bounds());
  EXPECT_EQ(gfx::Rect(-110, -500, 600, 500),
            display_manager()->GetDisplayAt(1).bounds());
  EXPECT_EQ(gfx::Rect(490, -500, 600, 500),
            display_manager()->GetDisplayAt(2).bounds());
  EXPECT_EQ(gfx::Rect(1090, -500, 600, 500),
            display_manager()->GetDisplayAt(3).bounds());
}

TEST_F(DisplayManagerTest, NoOverlappedDisplaysAfterResolutionChange) {
  // Starting with a good layout with no overlaps, test that if the resolution
  // of one of the displays is changed, it won't result in any overlaps.
  //
  //         +-------------------+
  //         |         4         |
  //         |                   |
  //         |                   |
  //         |                   |
  //    +----+----+---------+----+----+
  //    |    1    |    2    |    3    |
  //    |         |         |         |
  //    |         |         |         |
  //    |         |         |         |
  //    +----+----+---------+----+----+
  //         |         p         |
  //         |                   |
  //         |                   |
  //         |                   |
  //         +-------------------+
  //

  int64_t primary_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();
  display::DisplayIdList list = display::test::CreateDisplayIdListN(
      5, primary_id, primary_id + 1, primary_id + 2, primary_id + 3,
      primary_id + 4);
  display::DisplayLayoutBuilder builder(primary_id);
  builder.AddDisplayPlacement(list[1], primary_id,
                              display::DisplayPlacement::TOP, -250);
  builder.AddDisplayPlacement(list[2], primary_id,
                              display::DisplayPlacement::TOP, 250);
  builder.AddDisplayPlacement(list[3], primary_id,
                              display::DisplayPlacement::TOP, 750);
  builder.AddDisplayPlacement(list[4], list[1], display::DisplayPlacement::TOP,
                              250);
  display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
      list, builder.Build());
  UpdateDisplay("1000x500,500x500,500x500,500x500,1000x500");

  // There should be no overlap at all.
  EXPECT_EQ(5U, display_manager()->GetNumDisplays());
  EXPECT_EQ(gfx::Rect(0, 0, 1000, 500),
            display_manager()->GetDisplayAt(0).bounds());
  EXPECT_EQ(gfx::Rect(-250, -500, 500, 500),
            display_manager()->GetDisplayAt(1).bounds());
  EXPECT_EQ(gfx::Rect(250, -500, 500, 500),
            display_manager()->GetDisplayAt(2).bounds());
  EXPECT_EQ(gfx::Rect(750, -500, 500, 500),
            display_manager()->GetDisplayAt(3).bounds());
  EXPECT_EQ(gfx::Rect(0, -1000, 1000, 500),
            display_manager()->GetDisplayAt(4).bounds());

  // Change the resolution of display (2) and expect the following layout.
  //
  //         +-------------------+
  //         |         4         |
  //         |                   |
  //         |                   |
  //         |                   |
  //         +----+-------------++
  //              |      2      |
  //    +---------+             +---------+
  //    |    1    |             |    3    |
  //    |         |             |         |
  //    |         |             |         |
  //    |         |             |         |
  //    +----+----+-------------++--------+
  //         |         p         |
  //         |                   |
  //         |                   |
  //         |                   |
  //         +-------------------+
  //

  UpdateDisplay("1000x500,500x500,600x600,500x500,1000x500");

  EXPECT_EQ(5U, display_manager()->GetNumDisplays());
  EXPECT_EQ(gfx::Rect(0, 0, 1000, 500),
            display_manager()->GetDisplayAt(0).bounds());
  EXPECT_EQ(gfx::Rect(-250, -500, 500, 500),
            display_manager()->GetDisplayAt(1).bounds());
  EXPECT_EQ(gfx::Rect(250, -600, 600, 600),
            display_manager()->GetDisplayAt(2).bounds());
  EXPECT_EQ(gfx::Rect(850, -500, 500, 500),
            display_manager()->GetDisplayAt(3).bounds());
  EXPECT_EQ(gfx::Rect(0, -1100, 1000, 500),
            display_manager()->GetDisplayAt(4).bounds());
}

TEST_F(DisplayManagerTest, NoOverlappedDisplaysWithDetachedDisplays) {
  // Detached displays that intersect other non-detached displays.
  //
  //    +---------+---------+---------+
  //    |    1    |    2    |    3    |
  //    |         |         |         |
  //    |         |         |         |
  //    |         |         |         |
  //    +----+----+-----+---+----+----+
  //         |  4, 5    | P      |
  //         | detached |        |
  //         |          |        |
  //         +----------+        |
  //         +-------------------+
  //

  int64_t primary_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();
  display::DisplayIdList list = display::test::CreateDisplayIdListN(
      6, primary_id, primary_id + 1, primary_id + 2, primary_id + 3,
      primary_id + 4, primary_id + 5);
  display::DisplayLayoutBuilder builder(primary_id);
  builder.AddDisplayPlacement(list[1], primary_id,
                              display::DisplayPlacement::TOP, -250);
  builder.AddDisplayPlacement(list[2], primary_id,
                              display::DisplayPlacement::TOP, 250);
  builder.AddDisplayPlacement(list[3], primary_id,
                              display::DisplayPlacement::TOP, 750);
  display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
      list, builder.Build());
  UpdateDisplay("1000x500,500x500,500x500,500x500,500x400,500x400");

  // Detached displays will be de-intersected and reparented appropriately.
  //
  //    +---------+---------+---------+
  //    |    1    |    2    |    3    |
  //    |         |         |         |
  //    |         |         |         |
  //    |         |         |         |
  //    +----+----+---------+----+----+
  //         |         P         |
  //         |                   |
  //         |                   |
  //         |                   |
  //         +----------+--------+
  //         |     4    |
  //         |          |
  //         |          |
  //         +----------+
  //         |     5    |
  //         |          |
  //         |          |
  //         +----------+
  //

  EXPECT_EQ(6U, display_manager()->GetNumDisplays());
  EXPECT_EQ(gfx::Rect(0, 0, 1000, 500),
            display_manager()->GetDisplayAt(0).bounds());
  EXPECT_EQ(gfx::Rect(-250, -500, 500, 500),
            display_manager()->GetDisplayAt(1).bounds());
  EXPECT_EQ(gfx::Rect(250, -500, 500, 500),
            display_manager()->GetDisplayAt(2).bounds());
  EXPECT_EQ(gfx::Rect(750, -500, 500, 500),
            display_manager()->GetDisplayAt(3).bounds());
  EXPECT_EQ(gfx::Rect(0, 500, 500, 400),
            display_manager()->GetDisplayAt(4).bounds());
  EXPECT_EQ(gfx::Rect(0, 900, 500, 400),
            display_manager()->GetDisplayAt(5).bounds());

  // This case if not handled correctly might lead to a cyclic dependency.
  // Make sure this doesn't happen.
  display::DisplayLayoutBuilder expected_layout_builder(primary_id);
  expected_layout_builder.AddDisplayPlacement(
      list[1], primary_id, display::DisplayPlacement::TOP, -250);
  expected_layout_builder.AddDisplayPlacement(
      list[2], primary_id, display::DisplayPlacement::TOP, 250);
  expected_layout_builder.AddDisplayPlacement(
      list[3], primary_id, display::DisplayPlacement::TOP, 750);
  expected_layout_builder.AddDisplayPlacement(
      list[4], primary_id, display::DisplayPlacement::BOTTOM, 0);
  expected_layout_builder.AddDisplayPlacement(
      list[5], list[4], display::DisplayPlacement::BOTTOM, 0);

  const display::DisplayLayout& layout =
      display_manager()->GetCurrentResolvedDisplayLayout();
  EXPECT_TRUE(layout.HasSamePlacementList(*(expected_layout_builder.Build())));
}

// TODO(weidongg/774795) Remove test when multi mirroring is enabled by default.
TEST_F(DisplayManagerTestDisableMultiMirroring, NoMirrorInThreeDisplays) {
  UpdateDisplay("640x480,320x200,400x300");
  ash::Shell::Get()->display_configuration_controller()->SetMirrorMode(true);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(3u, display_manager()->GetNumDisplays());
  EXPECT_EQ(l10n_util::GetStringUTF16(IDS_ASH_DISPLAY_MIRRORING_NOT_SUPPORTED),
            GetDisplayErrorNotificationMessageForTest());
}

TEST_F(DisplayManagerTest, OverscanInsetsTest) {
  UpdateDisplay("0+0-500x500,0+501-400x400");
  reset();
  ASSERT_EQ(2u, display_manager()->GetNumDisplays());
  const display::ManagedDisplayInfo display_info1 = GetDisplayInfoAt(0);
  const display::ManagedDisplayInfo display_info2 = GetDisplayInfoAt(1);

  display_manager()->SetOverscanInsets(display_info2.id(),
                                       gfx::Insets(13, 12, 11, 10));

  std::vector<display::Display> changed_displays = changed();
  ASSERT_EQ(1u, changed_displays.size());
  EXPECT_EQ(display_info2.id(), changed_displays[0].id());
  EXPECT_EQ("0,0 500x500", GetDisplayInfoAt(0).bounds_in_native().ToString());
  display::ManagedDisplayInfo updated_display_info2 = GetDisplayInfoAt(1);
  EXPECT_EQ("0,501 400x400",
            updated_display_info2.bounds_in_native().ToString());
  EXPECT_EQ("378x376", updated_display_info2.size_in_pixel().ToString());
  EXPECT_EQ("13,12,11,10",
            updated_display_info2.overscan_insets_in_dip().ToString());
  EXPECT_EQ("500,0 378x376",
            display_manager()->GetSecondaryDisplay().bounds().ToString());

  // Make sure that SetOverscanInsets() is idempotent.
  display_manager()->SetOverscanInsets(display_info1.id(), gfx::Insets());
  display_manager()->SetOverscanInsets(display_info2.id(),
                                       gfx::Insets(13, 12, 11, 10));
  EXPECT_EQ("0,0 500x500", GetDisplayInfoAt(0).bounds_in_native().ToString());
  updated_display_info2 = GetDisplayInfoAt(1);
  EXPECT_EQ("0,501 400x400",
            updated_display_info2.bounds_in_native().ToString());
  EXPECT_EQ("378x376", updated_display_info2.size_in_pixel().ToString());
  EXPECT_EQ("13,12,11,10",
            updated_display_info2.overscan_insets_in_dip().ToString());

  display_manager()->SetOverscanInsets(display_info2.id(),
                                       gfx::Insets(10, 11, 12, 13));
  EXPECT_EQ("0,0 500x500", GetDisplayInfoAt(0).bounds_in_native().ToString());
  EXPECT_EQ("376x378", GetDisplayInfoAt(1).size_in_pixel().ToString());
  EXPECT_EQ("10,11,12,13",
            GetDisplayInfoAt(1).overscan_insets_in_dip().ToString());

  // Recreate a new 2nd display. It won't apply the overscan inset because the
  // new display has a different ID.
  UpdateDisplay("0+0-500x500");
  UpdateDisplay("0+0-500x500,0+501-400x400");
  EXPECT_EQ("0,0 500x500", GetDisplayInfoAt(0).bounds_in_native().ToString());
  EXPECT_EQ("0,501 400x400", GetDisplayInfoAt(1).bounds_in_native().ToString());

  // Recreate the displays with the same ID.  It should apply the overscan
  // inset.
  UpdateDisplay("0+0-500x500");

  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(display_info1);
  display_info_list.push_back(display_info2);

  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ("0,0 500x500", GetDisplayInfoAt(0).bounds_in_native().ToString());
  updated_display_info2 = GetDisplayInfoAt(1);
  EXPECT_EQ("376x378", updated_display_info2.size_in_pixel().ToString());
  EXPECT_EQ("10,11,12,13",
            updated_display_info2.overscan_insets_in_dip().ToString());

  // HiDPI but overscan display. The specified insets size should be doubled.
  UpdateDisplay("0+0-500x500,0+501-400x400*2");
  display_manager()->SetOverscanInsets(display_manager()->GetDisplayAt(1).id(),
                                       gfx::Insets(4, 5, 6, 7));
  EXPECT_EQ("0,0 500x500", GetDisplayInfoAt(0).bounds_in_native().ToString());
  updated_display_info2 = GetDisplayInfoAt(1);
  EXPECT_EQ("0,501 400x400",
            updated_display_info2.bounds_in_native().ToString());
  EXPECT_EQ("376x380", updated_display_info2.size_in_pixel().ToString());
  EXPECT_EQ("4,5,6,7",
            updated_display_info2.overscan_insets_in_dip().ToString());
  EXPECT_EQ("8,10,12,14",
            updated_display_info2.GetOverscanInsetsInPixel().ToString());

  // Make sure switching primary display applies the overscan offset only once.
  ash::Shell::Get()->window_tree_host_manager()->SetPrimaryDisplayId(
      display_manager()->GetSecondaryDisplay().id());
  EXPECT_EQ("-500,0 500x500",
            display_manager()->GetSecondaryDisplay().bounds().ToString());
  EXPECT_EQ("0,0 500x500",
            GetDisplayInfo(display_manager()->GetSecondaryDisplay())
                .bounds_in_native()
                .ToString());
  EXPECT_EQ("0,501 400x400",
            GetDisplayInfo(display::Screen::GetScreen()->GetPrimaryDisplay())
                .bounds_in_native()
                .ToString());
  EXPECT_EQ(
      "0,0 188x190",
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds().ToString());

  // Make sure just moving the overscan area should property notify observers.
  UpdateDisplay("0+0-500x500");
  int64_t primary_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();
  display_manager()->SetOverscanInsets(primary_id, gfx::Insets(0, 0, 20, 20));
  EXPECT_EQ(
      "0,0 480x480",
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds().ToString());
  reset();
  display_manager()->SetOverscanInsets(primary_id, gfx::Insets(10, 10, 10, 10));
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_BOUNDS);
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_WORK_AREA);
  EXPECT_EQ(
      "0,0 480x480",
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds().ToString());
  reset();
  display_manager()->SetOverscanInsets(primary_id, gfx::Insets(0, 0, 0, 0));
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_BOUNDS);
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_WORK_AREA);
  EXPECT_EQ(
      "0,0 500x500",
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds().ToString());
}

TEST_F(DisplayManagerTest, ZeroOverscanInsets) {
  // Make sure the display change events is emitted for overscan inset changes.
  UpdateDisplay("0+0-500x500,0+501-400x400");
  ASSERT_EQ(2u, display_manager()->GetNumDisplays());
  int64_t display2_id = display_manager()->GetDisplayAt(1).id();

  reset();
  display_manager()->SetOverscanInsets(display2_id, gfx::Insets(0, 0, 0, 0));
  EXPECT_EQ(0u, changed().size());

  reset();
  display_manager()->SetOverscanInsets(display2_id, gfx::Insets(1, 0, 0, 0));
  ASSERT_EQ(1u, changed().size());
  EXPECT_EQ(display2_id, changed()[0].id());

  reset();
  display_manager()->SetOverscanInsets(display2_id, gfx::Insets(0, 0, 0, 0));
  ASSERT_EQ(1u, changed().size());
  EXPECT_EQ(display2_id, changed()[0].id());
}

TEST_F(DisplayManagerTest, TouchCalibrationTest) {
  UpdateDisplay("0+0-500x500,0+501-1024x600");
  reset();
  display::TouchDeviceManager* touch_device_manager =
      display_manager()->touch_device_manager();
  display::test::TouchDeviceManagerTestApi tdm_test_api(touch_device_manager);

  const ui::TouchscreenDevice touchdevice(
      11, ui::InputDeviceType::INPUT_DEVICE_EXTERNAL,
      std::string("test touch device"), gfx::Size(123, 456), 1);
  const display::TouchDeviceIdentifier touch_device_identifier_2 =
      display::TouchDeviceIdentifier::FromDevice(touchdevice);

  ASSERT_EQ(2u, display_manager()->GetNumDisplays());
  const display::ManagedDisplayInfo display_info1 = GetDisplayInfoAt(0);
  const display::ManagedDisplayInfo display_info2 = GetDisplayInfoAt(1);

  EXPECT_FALSE(tdm_test_api.GetTouchDeviceCount(display_info2));

  const display::TouchCalibrationData::CalibrationPointPairQuad
      point_pair_quad = {
          {std::make_pair(gfx::Point(50, 50), gfx::Point(43, 51)),
           std::make_pair(gfx::Point(950, 50), gfx::Point(975, 45)),
           std::make_pair(gfx::Point(50, 550), gfx::Point(48, 534)),
           std::make_pair(gfx::Point(950, 550), gfx::Point(967, 574))}};
  const gfx::Size bounds_at_calibration(display_info2.size_in_pixel());
  const display::TouchCalibrationData touch_data(point_pair_quad,
                                                 bounds_at_calibration);

  // Set the touch calibration data for the secondary display.
  display_manager()->SetTouchCalibrationData(
      display_info2.id(), point_pair_quad, bounds_at_calibration,
      touch_device_identifier_2);

  EXPECT_TRUE(tdm_test_api.GetTouchDeviceCount(display_info2));
  EXPECT_EQ(touch_data, touch_device_manager->GetCalibrationData(
                            touchdevice, display_info2.id()));

  // Clearing touch calibration data from the secondary display.
  touch_device_manager->ClearTouchCalibrationData(touch_device_identifier_2,
                                                  GetDisplayInfoAt(1).id());

  EXPECT_TRUE(touch_device_manager
                  ->GetCalibrationData(touchdevice, GetDisplayInfoAt(1).id())
                  .IsEmpty());

  // Make sure that SetTouchCalibrationData() is idempotent.
  display::TouchCalibrationData::CalibrationPointPairQuad point_pair_quad_2 =
      point_pair_quad;
  point_pair_quad_2[1] =
      std::make_pair(gfx::Point(950, 50), gfx::Point(975, 53));
  display::TouchCalibrationData touch_data_2(point_pair_quad_2,
                                             bounds_at_calibration);
  display_manager()->SetTouchCalibrationData(
      display_info2.id(), point_pair_quad_2, bounds_at_calibration,
      touch_device_identifier_2);

  EXPECT_EQ(touch_data_2, touch_device_manager->GetCalibrationData(
                              touchdevice, GetDisplayInfoAt(1).id()));

  // Recreate a new 2nd display. It won't apply the touhc calibration data
  // because the new display has a different ID.
  UpdateDisplay("0+0-500x500");
  UpdateDisplay("0+0-500x500,0+501-400x400");
  tdm_test_api.ResetTouchDeviceManager();

  // Recreate the displays with the same ID.  It should apply the touch
  // calibration associated data.
  UpdateDisplay("0+0-500x500");
  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(display_info1);
  display_info_list.push_back(display_info2);
  display_manager()->OnNativeDisplaysChanged(display_info_list);

  // Make sure multiple touch devices works.
  display_manager()->SetTouchCalibrationData(
      display_info2.id(), point_pair_quad, bounds_at_calibration,
      touch_device_identifier_2);

  EXPECT_EQ(touch_data, touch_device_manager->GetCalibrationData(
                            touchdevice, GetDisplayInfoAt(1).id()));

  const ui::TouchscreenDevice touchdevice_2(
      12, ui::InputDeviceType::INPUT_DEVICE_EXTERNAL,
      std::string("test touch device 2"), gfx::Size(234, 567), 1);
  display::TouchDeviceIdentifier touch_device_identifier_2_2 =
      display::TouchDeviceIdentifier::FromDevice(touchdevice_2);

  display_manager()->SetTouchCalibrationData(
      display_info2.id(), point_pair_quad_2, bounds_at_calibration,
      touch_device_identifier_2_2);
  EXPECT_EQ(touch_data_2, touch_device_manager->GetCalibrationData(
                              touchdevice_2, GetDisplayInfoAt(1).id()));
  EXPECT_EQ(touch_data, touch_device_manager->GetCalibrationData(
                            touchdevice, GetDisplayInfoAt(1).id()));
}

TEST_F(DisplayManagerTest, UpdateDisplayZoomTest) {
  // Initialize a display pair.
  UpdateDisplay("1920x1080#1280x720|640x480%60, 600x400*2#600x400");
  reset();

  // The second display has a device scale factor of 2 set.
  constexpr float display_2_dsf = 2.0f;

  ASSERT_EQ(2u, display_manager()->GetNumDisplays());
  const display::ManagedDisplayInfo& info_1 = GetDisplayInfoAt(0);

  // The display should have 2 display modes based on the initialization spec.
  ASSERT_EQ(2u, info_1.display_modes().size());

  const display::ManagedDisplayInfo::ManagedDisplayModeList& modes =
      info_1.display_modes();

  // Set the display mode.
  display::test::SetDisplayResolution(display_manager(), info_1.id(),
                                      modes[0].size());
  display_manager()->UpdateDisplays();

  // Since no zoom factor or device scale factor has been set on the display,
  // the total/effective device scale factor on the display is 1.
  EXPECT_EQ(
      display_manager()->GetDisplayForId(info_1.id()).device_scale_factor(),
      1.f);

  float zoom_factor_1 = 2.0f;
  display_manager()->UpdateZoomFactor(info_1.id(), zoom_factor_1);
  EXPECT_EQ(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
            zoom_factor_1);

  // With the zoom factor set for the display. The effective zoom factor
  // returned should have the display zoom taken into consideration.
  EXPECT_EQ(
      display_manager()->GetDisplayForId(info_1.id()).device_scale_factor(),
      zoom_factor_1);

  // Update the zoom factor for a different display mode.
  float zoom_factor_2 = 1.5f;
  display_manager()->UpdateZoomFactor(info_1.id(), zoom_factor_2);

  EXPECT_EQ(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
            zoom_factor_2);

  // Change the display mode of the device.
  display::test::SetDisplayResolution(display_manager(), info_1.id(),
                                      modes[1].size());
  display_manager()->UpdateDisplays();

  // Since the display mode was changed, the zoom factor for the display is
  // reset to the default of 1.
  EXPECT_EQ(
      display_manager()->GetDisplayForId(info_1.id()).device_scale_factor(),
      1.f);

  // When setting the display mode back to the old one, the final effective
  // device scale factor should be using the correct zoom factor.
  display::test::SetDisplayResolution(display_manager(), info_1.id(),
                                      modes[0].size());
  display_manager()->UpdateDisplays();

  // Set the zoom factor back to |zoom_factor_2| for first display.
  display_manager()->UpdateZoomFactor(info_1.id(), zoom_factor_2);
  EXPECT_EQ(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
            zoom_factor_2);
  EXPECT_EQ(
      display_manager()->GetDisplayForId(info_1.id()).device_scale_factor(),
      zoom_factor_2);

  // Update the zoom factor for the second display.
  float zoom_factor_3 = 1.5f;
  const display::ManagedDisplayInfo& info_2 = GetDisplayInfoAt(1);
  display_manager()->UpdateZoomFactor(info_2.id(), zoom_factor_3);
  EXPECT_EQ(display_manager()->GetDisplayInfo(info_2.id()).zoom_factor(),
            zoom_factor_3);
  EXPECT_EQ(
      display_manager()->GetDisplayForId(info_2.id()).device_scale_factor(),
      zoom_factor_3 * display_2_dsf);

  // Modifying zoom factor for a display should not effect zoom factors of
  // other displays.
  EXPECT_EQ(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
            zoom_factor_2);

  // Update the zoom factor for display to see if it gets reflected.
  display_manager()->UpdateZoomFactor(info_1.id(), zoom_factor_3);

  EXPECT_EQ(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
            zoom_factor_3);
  display::test::SetDisplayResolution(display_manager(), info_1.id(),
                                      modes[0].size());
  display_manager()->UpdateDisplays();

  EXPECT_EQ(
      display_manager()->GetDisplayForId(info_1.id()).device_scale_factor(),
      1.f);
  EXPECT_EQ(
      display_manager()->GetDisplayForId(info_2.id()).device_scale_factor(),
      zoom_factor_3 * display_2_dsf);
}

TEST_F(DisplayManagerTest, ZoomDisplay) {
  // Initialize a display pair.
  UpdateDisplay("1920x1080#1920x1080|1280x720%60, 2560x1440*2#2560x1440");
  reset();

  ASSERT_EQ(2u, display_manager()->GetNumDisplays());

  const display::ManagedDisplayInfo& info_1 = GetDisplayInfoAt(0);
  const display::ManagedDisplayInfo::ManagedDisplayModeList& modes_1 =
      info_1.display_modes();

  const display::ManagedDisplayInfo& info_2 = GetDisplayInfoAt(1);
  const display::ManagedDisplayInfo::ManagedDisplayModeList& modes_2 =
      info_2.display_modes();

  // Set the display mode for each display.
  display::test::SetDisplayResolution(display_manager(), info_1.id(),
                                      modes_1[0].size());
  display::test::SetDisplayResolution(display_manager(), info_2.id(),
                                      modes_2[0].size());
  display_manager()->UpdateDisplays();

  // Enumerate the zoom factors for display.
  const std::vector<double> zoom_factors_1 =
      display::GetDisplayZoomFactors(modes_1[0]);

  // Set the zoom factor to one of the enumerated zoom factors for the said
  // display.
  const std::size_t zoom_factor_idx_1 = 0;
  display_manager()->UpdateZoomFactor(info_1.id(),
                                      zoom_factors_1[zoom_factor_idx_1]);

  // Make sure the chage was successful.
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
              zoom_factors_1[zoom_factor_idx_1], 0.001f);

  // Zoom out the display. This should have no effect, since the display is
  // already at the minimum zoom level.
  display_manager()->ZoomDisplay(info_1.id(), true /* up */);
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
              zoom_factors_1[zoom_factor_idx_1], 0.001f);

  // Ensure that this call did not modify the zoom value for the other display.
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_2.id()).zoom_factor(), 1.f,
              0.001f);

  // Zoom in the display.
  display_manager()->ZoomDisplay(info_1.id(), false /* up */);

  // The zoom factor for the display should be set to the next zoom factor in
  // list.
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
              zoom_factors_1[zoom_factor_idx_1 + 1], 0.001f);

  // Zoom out the display.
  display_manager()->ZoomDisplay(info_1.id(), true /* up */);

  // The zoom level should decrease from the previous level.
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
              zoom_factors_1[zoom_factor_idx_1], 0.001f);

  // Enumerate the zoom factors for display.
  const std::vector<double> zoom_factors_2 =
      display::GetDisplayZoomFactors(modes_2[0]);

  // Set the zoom factor to one of the enumerated zoom factors for the said
  // display.
  const std::size_t zoom_factor_idx_2 = zoom_factors_2.size() - 1;
  display_manager()->UpdateZoomFactor(info_2.id(),
                                      zoom_factors_2[zoom_factor_idx_2]);

  // Make sure the chage was successful.
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_2.id()).zoom_factor(),
              zoom_factors_2[zoom_factor_idx_2], 0.001f);

  // Zoom in the display. This should have no effect since we are already at
  // maximum zoom.
  display_manager()->ZoomDisplay(info_2.id(), false /* up */);
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_2.id()).zoom_factor(),
              zoom_factors_2[zoom_factor_idx_2], 0.001f);

  // Zoom out the display
  display_manager()->ZoomDisplay(info_2.id(), true /* up */);
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_2.id()).zoom_factor(),
              zoom_factors_2[zoom_factor_idx_2 - 1], 0.001f);

  // Ensure that this call did not modify the zoom value for the other display.
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(),
              zoom_factors_1[zoom_factor_idx_1], 0.001f);

  // Reset the zoom value for displays.
  display_manager()->ResetDisplayZoom(info_1.id());
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(), 1.f,
              0.001f);
  // Resetting the zoom level of one display should not effect the other display
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_2.id()).zoom_factor(),
              zoom_factors_2[zoom_factor_idx_2 - 1], 0.001f);

  // Now reset the zoom value for other display.
  display_manager()->ResetDisplayZoom(info_2.id());
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_2.id()).zoom_factor(), 1.f,
              0.001f);
  EXPECT_NEAR(display_manager()->GetDisplayInfo(info_1.id()).zoom_factor(), 1.f,
              0.001f);
}

TEST_F(DisplayManagerTest, TestDeviceScaleOnlyChange) {
  UpdateDisplay("1000x600");
  aura::WindowTreeHost* host = Shell::GetPrimaryRootWindow()->GetHost();
  EXPECT_EQ(1, host->compositor()->device_scale_factor());
  EXPECT_EQ("1000x600",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());
  EXPECT_EQ("1 0 0 1 1", GetCountSummary());

  UpdateDisplay("1000x600*2");
  EXPECT_EQ(2, host->compositor()->device_scale_factor());
  EXPECT_EQ("2 0 0 2 2", GetCountSummary());
  EXPECT_EQ("500x300",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());
}

TEST_F(DisplayManagerTest, TestNativeDisplaysChanged) {
  // Disable restoring mirror mode to prevent interference from previous
  // display configuration.
  display_manager()->set_disable_restoring_mirror_mode_for_test(true);

  const int64_t internal_display_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  const int external_id = 10;
  const int mirror_id = 11;
  const int64_t invalid_id = display::kInvalidDisplayId;
  const display::ManagedDisplayInfo internal_display_info =
      display::CreateDisplayInfo(internal_display_id,
                                 gfx::Rect(0, 0, 500, 500));
  const display::ManagedDisplayInfo external_display_info =
      display::CreateDisplayInfo(external_id, gfx::Rect(1, 1, 100, 100));
  const display::ManagedDisplayInfo mirroring_display_info =
      display::CreateDisplayInfo(mirror_id, gfx::Rect(0, 0, 500, 500));

  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ(1U, display_manager()->num_connected_displays());
  std::string default_bounds =
      display_manager()->GetDisplayAt(0).bounds().ToString();

  std::vector<display::ManagedDisplayInfo> display_info_list;
  // Primary disconnected.
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ(default_bounds,
            display_manager()->GetDisplayAt(0).bounds().ToString());
  EXPECT_EQ(1U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  // External connected while primary was disconnected.
  display_info_list.push_back(external_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());

  EXPECT_EQ(invalid_id, GetDisplayForId(internal_display_id).id());
  EXPECT_EQ("1,1 100x100",
            GetDisplayInfoForId(external_id).bounds_in_native().ToString());
  EXPECT_EQ(1U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(external_id,
            display::Screen::GetScreen()->GetPrimaryDisplay().id());

  EXPECT_EQ(internal_display_id, display::Display::InternalDisplayId());

  // Primary connected, with different bounds.
  display_info_list.clear();
  display_info_list.push_back(internal_display_info);
  display_info_list.push_back(external_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ(internal_display_id,
            display::Screen::GetScreen()->GetPrimaryDisplay().id());

  // This combinatino is new, so internal display becomes primary.
  EXPECT_EQ("0,0 500x500",
            GetDisplayForId(internal_display_id).bounds().ToString());
  EXPECT_EQ("1,1 100x100",
            GetDisplayInfoForId(10).bounds_in_native().ToString());
  EXPECT_EQ(2U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(ToDisplayName(internal_display_id),
            display_manager()->GetDisplayNameForId(internal_display_id));

  // Emulate suspend.
  display_info_list.clear();
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ("0,0 500x500",
            GetDisplayForId(internal_display_id).bounds().ToString());
  EXPECT_EQ("1,1 100x100",
            GetDisplayInfoForId(10).bounds_in_native().ToString());
  EXPECT_EQ(2U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(ToDisplayName(internal_display_id),
            display_manager()->GetDisplayNameForId(internal_display_id));

  // External display has disconnected then resumed.
  display_info_list.push_back(internal_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ("0,0 500x500",
            GetDisplayForId(internal_display_id).bounds().ToString());
  EXPECT_EQ(1U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  // External display was changed during suspend.
  display_info_list.push_back(external_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ(2U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  // suspend...
  display_info_list.clear();
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ(2U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  // and resume with different external display.
  display_info_list.push_back(internal_display_info);
  display_info_list.push_back(
      display::CreateDisplayInfo(12, gfx::Rect(1, 1, 100, 100)));
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ(2U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  // mirrored...
  display_info_list.clear();
  display_info_list.push_back(internal_display_info);
  display_info_list.push_back(mirroring_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ("0,0 500x500",
            GetDisplayForId(internal_display_id).bounds().ToString());
  EXPECT_EQ(2U, display_manager()->num_connected_displays());
  EXPECT_EQ(11U, display_manager()->GetMirroringDestinationDisplayIdList()[0]);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());

  // Test display name.
  EXPECT_EQ(ToDisplayName(internal_display_id),
            display_manager()->GetDisplayNameForId(internal_display_id));
  EXPECT_EQ("x-10", display_manager()->GetDisplayNameForId(10));
  EXPECT_EQ("x-11", display_manager()->GetDisplayNameForId(11));
  EXPECT_EQ("x-12", display_manager()->GetDisplayNameForId(12));
  // Default name for the id that doesn't exist.
  EXPECT_EQ("Display 100", display_manager()->GetDisplayNameForId(100));

  // and exit mirroring.
  display_info_list.clear();
  display_info_list.push_back(internal_display_info);
  display_info_list.push_back(external_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ(2U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ("0,0 500x500",
            GetDisplayForId(internal_display_id).bounds().ToString());
  EXPECT_EQ("500,0 100x100", GetDisplayForId(10).bounds().ToString());

  // Turn off internal
  display_info_list.clear();
  display_info_list.push_back(external_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ(invalid_id, GetDisplayForId(internal_display_id).id());
  EXPECT_EQ("1,1 100x100",
            GetDisplayInfoForId(external_id).bounds_in_native().ToString());
  EXPECT_EQ(1U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  // Switched to another display
  display_info_list.clear();
  display_info_list.push_back(internal_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ(
      "0,0 500x500",
      GetDisplayInfoForId(internal_display_id).bounds_in_native().ToString());
  EXPECT_EQ(1U, display_manager()->num_connected_displays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  display_manager()->set_disable_restoring_mirror_mode_for_test(false);
}

// Make sure crash does not happen if add and remove happens at the same time.
// See: crbug.com/414394
TEST_F(DisplayManagerTest, DisplayAddRemoveAtTheSameTime) {
  UpdateDisplay("100+0-500x500,0+501-400x400");

  const int64_t primary_id = WindowTreeHostManager::GetPrimaryDisplayId();
  const int64_t secondary_id = display_manager()->GetSecondaryDisplay().id();

  display::ManagedDisplayInfo primary_info =
      display_manager()->GetDisplayInfo(primary_id);
  display::ManagedDisplayInfo secondary_info =
      display_manager()->GetDisplayInfo(secondary_id);

  // An id which is different from primary and secondary.
  const int64_t third_id = secondary_id + 1;

  display::ManagedDisplayInfo third_info =
      display::CreateDisplayInfo(third_id, gfx::Rect(0, 0, 600, 600));

  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(third_info);
  display_info_list.push_back(secondary_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);

  // Secondary seconary_id becomes the primary as it has smaller output index.
  EXPECT_EQ(secondary_id, WindowTreeHostManager::GetPrimaryDisplayId());
  EXPECT_EQ(third_id, display_manager()->GetSecondaryDisplay().id());
  EXPECT_EQ("600x600", GetDisplayForId(third_id).size().ToString());
}

TEST_F(DisplayManagerTest, TestNativeDisplaysChangedNoInternal) {
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());

  // Don't change the display info if all displays are disconnected.
  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());

  // Connect another display which will become primary.
  const display::ManagedDisplayInfo external_display_info =
      display::CreateDisplayInfo(10, gfx::Rect(1, 1, 100, 100));
  display_info_list.push_back(external_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ("1,1 100x100",
            GetDisplayInfoForId(10).bounds_in_native().ToString());
  EXPECT_EQ("100x100", ash::Shell::GetPrimaryRootWindow()
                           ->GetHost()
                           ->GetBoundsInPixels()
                           .size()
                           .ToString());
}

TEST_F(DisplayManagerTest, NativeDisplaysChangedAfterPrimaryChange) {
  const int64_t internal_display_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  const display::ManagedDisplayInfo native_display_info =
      display::CreateDisplayInfo(internal_display_id,
                                 gfx::Rect(0, 0, 500, 500));
  const display::ManagedDisplayInfo secondary_display_info =
      display::CreateDisplayInfo(10, gfx::Rect(1, 1, 100, 100));

  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(native_display_info);
  display_info_list.push_back(secondary_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_EQ("0,0 500x500",
            GetDisplayForId(internal_display_id).bounds().ToString());
  EXPECT_EQ("500,0 100x100", GetDisplayForId(10).bounds().ToString());

  ash::Shell::Get()->window_tree_host_manager()->SetPrimaryDisplayId(
      secondary_display_info.id());
  EXPECT_EQ("-500,0 500x500",
            GetDisplayForId(internal_display_id).bounds().ToString());
  EXPECT_EQ("0,0 100x100", GetDisplayForId(10).bounds().ToString());

  // OnNativeDisplaysChanged may change the display bounds.  Here makes sure
  // nothing changed if the exactly same displays are specified.
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ("-500,0 500x500",
            GetDisplayForId(internal_display_id).bounds().ToString());
  EXPECT_EQ("0,0 100x100", GetDisplayForId(10).bounds().ToString());
}

TEST_F(DisplayManagerTest, DontRememberBestResolution) {
  int display_id = 1000;
  display::ManagedDisplayInfo native_display_info =
      display::CreateDisplayInfo(display_id, gfx::Rect(0, 0, 1000, 500));
  display::ManagedDisplayInfo::ManagedDisplayModeList display_modes;
  display_modes.push_back(
      display::ManagedDisplayMode(gfx::Size(1000, 500), 58.0f, false, true));
  display_modes.push_back(
      display::ManagedDisplayMode(gfx::Size(800, 300), 59.0f, false, false));
  display_modes.push_back(
      display::ManagedDisplayMode(gfx::Size(400, 500), 60.0f, false, false));

  native_display_info.SetManagedDisplayModes(display_modes);

  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(native_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);

  display::ManagedDisplayMode expected_mode(gfx::Size(1000, 500), 0.0f, false,
                                            false);

  display::ManagedDisplayMode mode;
  EXPECT_FALSE(
      display_manager()->GetSelectedModeForDisplayId(display_id, &mode));
  display::ManagedDisplayMode active_mode;
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));

  // Unsupported resolution.
  display::test::SetDisplayResolution(display_manager(), display_id,
                                      gfx::Size(800, 4000));
  EXPECT_FALSE(
      display_manager()->GetSelectedModeForDisplayId(display_id, &mode));
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));

  // Supported resolution.
  display::test::SetDisplayResolution(display_manager(), display_id,
                                      gfx::Size(800, 300));
  EXPECT_TRUE(
      display_manager()->GetSelectedModeForDisplayId(display_id, &mode));
  EXPECT_EQ("800x300", mode.size().ToString());
  EXPECT_EQ(59.0f, mode.refresh_rate());
  EXPECT_FALSE(mode.native());

  expected_mode =
      display::ManagedDisplayMode(gfx::Size(800, 300), 0.0f, false, false);

  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));

  // Best resolution.
  display::test::SetDisplayResolution(display_manager(), display_id,
                                      gfx::Size(1000, 500));
  EXPECT_TRUE(
      display_manager()->GetSelectedModeForDisplayId(display_id, &mode));
  EXPECT_EQ("1000x500", mode.size().ToString());
  EXPECT_EQ(58.0f, mode.refresh_rate());
  EXPECT_TRUE(mode.native());

  expected_mode =
      display::ManagedDisplayMode(gfx::Size(1000, 500), 0.0f, false, false);

  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));
}

TEST_F(DisplayManagerTest, ResolutionFallback) {
  int display_id = 1000;
  display::ManagedDisplayInfo native_display_info =
      display::CreateDisplayInfo(display_id, gfx::Rect(0, 0, 1000, 500));
  display::ManagedDisplayInfo::ManagedDisplayModeList display_modes;
  display_modes.push_back(
      display::ManagedDisplayMode(gfx::Size(1000, 500), 58.0f, false, true));
  display_modes.push_back(
      display::ManagedDisplayMode(gfx::Size(800, 300), 59.0f, false, false));
  display_modes.push_back(
      display::ManagedDisplayMode(gfx::Size(400, 500), 60.0f, false, false));

  display::ManagedDisplayInfo::ManagedDisplayModeList copy = display_modes;
  native_display_info.SetManagedDisplayModes(copy);

  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(native_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  {
    display::test::SetDisplayResolution(display_manager(), display_id,
                                        gfx::Size(800, 300));
    display::ManagedDisplayInfo new_native_display_info =
        display::CreateDisplayInfo(display_id, gfx::Rect(0, 0, 400, 500));
    copy = display_modes;
    new_native_display_info.SetManagedDisplayModes(copy);
    std::vector<display::ManagedDisplayInfo> new_display_info_list;
    new_display_info_list.push_back(new_native_display_info);
    display_manager()->OnNativeDisplaysChanged(new_display_info_list);

    display::ManagedDisplayMode mode;
    EXPECT_TRUE(
        display_manager()->GetSelectedModeForDisplayId(display_id, &mode));
    EXPECT_EQ("400x500", mode.size().ToString());
    EXPECT_EQ(60.0f, mode.refresh_rate());
    EXPECT_FALSE(mode.native());
  }
  {
    // Best resolution should find itself on the resolutions list.
    display::test::SetDisplayResolution(display_manager(), display_id,
                                        gfx::Size(800, 300));
    display::ManagedDisplayInfo new_native_display_info =
        display::CreateDisplayInfo(display_id, gfx::Rect(0, 0, 1000, 500));
    display::ManagedDisplayInfo::ManagedDisplayModeList copy = display_modes;
    new_native_display_info.SetManagedDisplayModes(copy);
    std::vector<display::ManagedDisplayInfo> new_display_info_list;
    new_display_info_list.push_back(new_native_display_info);
    display_manager()->OnNativeDisplaysChanged(new_display_info_list);

    display::ManagedDisplayMode mode;
    EXPECT_TRUE(
        display_manager()->GetSelectedModeForDisplayId(display_id, &mode));
    EXPECT_EQ("1000x500", mode.size().ToString());
    EXPECT_EQ(58.0f, mode.refresh_rate());
    EXPECT_TRUE(mode.native());
  }
}

TEST_F(DisplayManagerTest, Rotate) {
  UpdateDisplay("100x200/r,300x400/l");
  EXPECT_EQ("1,1 100x200", GetDisplayInfoAt(0).bounds_in_native().ToString());
  EXPECT_EQ("200x100", GetDisplayInfoAt(0).size_in_pixel().ToString());

  EXPECT_EQ("1,201 300x400", GetDisplayInfoAt(1).bounds_in_native().ToString());
  EXPECT_EQ("400x300", GetDisplayInfoAt(1).size_in_pixel().ToString());
  reset();
  UpdateDisplay("100x200/b,300x400");
  EXPECT_EQ("2 0 0 1 1", GetCountSummary());
  reset();

  EXPECT_EQ("1,1 100x200", GetDisplayInfoAt(0).bounds_in_native().ToString());
  EXPECT_EQ("100x200", GetDisplayInfoAt(0).size_in_pixel().ToString());

  EXPECT_EQ("1,201 300x400", GetDisplayInfoAt(1).bounds_in_native().ToString());
  EXPECT_EQ("300x400", GetDisplayInfoAt(1).size_in_pixel().ToString());

  // Just Rotating display will change the bounds on both display.
  UpdateDisplay("100x200/l,300x400");
  EXPECT_EQ("2 0 0 1 1", GetCountSummary());
  reset();

  // Updating to the same configuration should report no changes. A will/did
  // change is still sent.
  UpdateDisplay("100x200/l,300x400");
  EXPECT_EQ("0 0 0 1 1", GetCountSummary());
  reset();

  // Rotating 180 degrees should report one change.
  UpdateDisplay("100x200/r,300x400");
  EXPECT_EQ("1 0 0 1 1", GetCountSummary());
  reset();

  UpdateDisplay("200x200");
  EXPECT_EQ("1 0 1 1 1", GetCountSummary());
  reset();

  // Rotating 180 degrees should report one change.
  UpdateDisplay("200x200/u");
  EXPECT_EQ("1 0 0 1 1", GetCountSummary());
  reset();

  UpdateDisplay("200x200/l");
  EXPECT_EQ("1 0 0 1 1", GetCountSummary());

  // Having the internal display deactivated should restore user rotation. Newly
  // set rotations should be applied.
  UpdateDisplay("200x200, 200x200");
  const int64_t internal_display_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();

  display_manager()->SetDisplayRotation(internal_display_id,
                                        display::Display::ROTATE_90,
                                        display::Display::RotationSource::USER);
  display_manager()->SetDisplayRotation(
      internal_display_id, display::Display::ROTATE_0,
      display::Display::RotationSource::ACTIVE);

  const display::ManagedDisplayInfo info =
      GetDisplayInfoForId(internal_display_id);
  EXPECT_EQ(display::Display::ROTATE_0, info.GetActiveRotation());

  // Deactivate internal display to simulate Docked Mode.
  vector<display::ManagedDisplayInfo> secondary_only;
  secondary_only.push_back(GetDisplayInfoAt(1));
  display_manager()->OnNativeDisplaysChanged(secondary_only);

  const display::ManagedDisplayInfo& post_removal_info =
      display::test::DisplayManagerTestApi(display_manager())
          .GetInternalManagedDisplayInfo(internal_display_id);
  EXPECT_NE(info.GetActiveRotation(), post_removal_info.GetActiveRotation());
  EXPECT_EQ(display::Display::ROTATE_90, post_removal_info.GetActiveRotation());

  display_manager()->SetDisplayRotation(
      internal_display_id, display::Display::ROTATE_180,
      display::Display::RotationSource::ACTIVE);
  const display::ManagedDisplayInfo& post_rotation_info =
      display::test::DisplayManagerTestApi(display_manager())
          .GetInternalManagedDisplayInfo(internal_display_id);
  EXPECT_NE(info.GetActiveRotation(), post_rotation_info.GetActiveRotation());
  EXPECT_EQ(display::Display::ROTATE_180,
            post_rotation_info.GetActiveRotation());
}

TEST_F(DisplayManagerTest, UIScale) {
  UpdateDisplay("1280x800");
  int64_t display_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.125f);
  EXPECT_EQ(1.0, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.8f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.75f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.625f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());

  display::test::ScopedSetInternalDisplayId set_internal(display_manager(),
                                                         display_id);

  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.5f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.25f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.125f);
  EXPECT_EQ(1.125f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.8f);
  EXPECT_EQ(0.8f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.75f);
  EXPECT_EQ(0.8f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.625f);
  EXPECT_EQ(0.625f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.6f);
  EXPECT_EQ(0.625f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.5f);
  EXPECT_EQ(0.5f, GetDisplayInfoAt(0).configured_ui_scale());

  UpdateDisplay("1366x768");
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.5f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.25f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.125f);
  EXPECT_EQ(1.125f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.8f);
  EXPECT_EQ(1.125f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.75f);
  EXPECT_EQ(0.75f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.6f);
  EXPECT_EQ(0.6f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.625f);
  EXPECT_EQ(0.6f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.5f);
  EXPECT_EQ(0.5f, GetDisplayInfoAt(0).configured_ui_scale());

  UpdateDisplay("1280x850*2");
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.5f);
  EXPECT_EQ(1.5f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.25f);
  EXPECT_EQ(1.25f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.125f);
  EXPECT_EQ(1.125f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.0f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  display::Display display = display::Screen::GetScreen()->GetPrimaryDisplay();
  EXPECT_EQ(2.0f, display.device_scale_factor());
  EXPECT_EQ("640x425", display.bounds().size().ToString());

  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.8f);
  EXPECT_EQ(0.8f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.75f);
  EXPECT_EQ(0.8f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.625f);
  EXPECT_EQ(0.625f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.6f);
  EXPECT_EQ(0.625f, GetDisplayInfoAt(0).configured_ui_scale());
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.5f);
  EXPECT_EQ(0.5f, GetDisplayInfoAt(0).configured_ui_scale());

  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 2.0f);
  EXPECT_EQ(2.0f, GetDisplayInfoAt(0).configured_ui_scale());
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveUIScale());
  display = display::Screen::GetScreen()->GetPrimaryDisplay();
  EXPECT_EQ(1.0f, display.device_scale_factor());
  EXPECT_EQ("1280x850", display.bounds().size().ToString());
}

TEST_F(DisplayManagerTest, UIScaleWithDisplayMode) {
  int display_id = 1000;

  // Setup the display modes with UI-scale.
  display::ManagedDisplayInfo native_display_info =
      display::CreateDisplayInfo(display_id, gfx::Rect(0, 0, 1280, 800));
  const display::ManagedDisplayMode base_mode(gfx::Size(1280, 800), 60.0f,
                                              false, false);
  display::ManagedDisplayInfo::ManagedDisplayModeList mode_list =
      CreateInternalManagedDisplayModeList(base_mode);
  native_display_info.SetManagedDisplayModes(mode_list);

  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(native_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);

  display::ManagedDisplayMode expected_mode = base_mode;
  display::ManagedDisplayMode active_mode;
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));

  display::test::ScopedSetInternalDisplayId set_internal(display_manager(),
                                                         display_id);

  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.5f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.25f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).configured_ui_scale());
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.125f);
  EXPECT_EQ(1.125f, GetDisplayInfoAt(0).configured_ui_scale());

  expected_mode = display::ManagedDisplayMode(
      expected_mode.size(), expected_mode.refresh_rate(),
      expected_mode.is_interlaced(), expected_mode.native(),
      1.125f /* ui_scale */, expected_mode.device_scale_factor());

  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.8f);
  EXPECT_EQ(0.8f, GetDisplayInfoAt(0).configured_ui_scale());

  expected_mode = display::ManagedDisplayMode(
      expected_mode.size(), expected_mode.refresh_rate(),
      expected_mode.is_interlaced(), expected_mode.native(),
      0.8f /* ui_scale */, expected_mode.device_scale_factor());

  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.75f);
  EXPECT_EQ(0.8f, GetDisplayInfoAt(0).configured_ui_scale());
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.625f);
  EXPECT_EQ(0.625f, GetDisplayInfoAt(0).configured_ui_scale());

  expected_mode = display::ManagedDisplayMode(
      expected_mode.size(), expected_mode.refresh_rate(),
      expected_mode.is_interlaced(), expected_mode.native(),
      0.625f /* ui_scale */, expected_mode.device_scale_factor());

  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.6f);
  EXPECT_EQ(0.625f, GetDisplayInfoAt(0).configured_ui_scale());
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));
  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.5f);
  EXPECT_EQ(0.5f, GetDisplayInfoAt(0).configured_ui_scale());

  expected_mode = display::ManagedDisplayMode(
      expected_mode.size(), expected_mode.refresh_rate(),
      expected_mode.is_interlaced(), expected_mode.native(),
      0.5f /* ui_scale */, expected_mode.device_scale_factor());

  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));
}

// Tests that ResetInternalDisplayZoom() resets to the default 0.8f UI scale
// defined for the 1.25x displays.
TEST_F(DisplayManagerTest, ResetInternalDisplayZoomFor1_25x) {
  // Setup the display modes with UI-scale.
  display::ManagedDisplayMode base_mode(
      gfx::Size(1920, 1080), 60.0f, false /* is_interlaced */,
      true /* native */, 1.0f /* ui_scale */, 1.25f /* device_scale_factor */);
  display::ManagedDisplayInfo::ManagedDisplayModeList mode_list =
      CreateInternalManagedDisplayModeList(base_mode);

  const int display_id = 1000;
  display::ManagedDisplayInfo native_display_info =
      display::CreateDisplayInfo(display_id, gfx::Rect(0, 0, 1920, 1080));
  native_display_info.set_device_scale_factor(1.25f);
  native_display_info.SetManagedDisplayModes(mode_list);

  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(native_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);

  display::ManagedDisplayMode expected_mode = base_mode;
  display::ManagedDisplayMode active_mode;
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(display_id, &active_mode));
  EXPECT_TRUE(expected_mode.IsEquivalent(active_mode));

  display::test::ScopedSetInternalDisplayId set_internal(display_manager(),
                                                         display_id);

  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.5f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveDeviceScaleFactor());
  EXPECT_EQ(0.5f, GetDisplayInfoAt(0).GetEffectiveUIScale());
  EXPECT_EQ(0.5f, GetDisplayInfoAt(0).configured_ui_scale());
  EXPECT_EQ("960x540", GetDisplayForId(display_id).size().ToString());

  // Reset the internal display zoom and expect the UI scale to go to the
  // default 0.8f.
  display_manager()->ResetInternalDisplayZoom();
  EXPECT_EQ(1.25f, GetDisplayInfoAt(0).GetEffectiveDeviceScaleFactor());
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveUIScale());
  EXPECT_EQ(0.8f, GetDisplayInfoAt(0).configured_ui_scale());
  EXPECT_EQ("1536x864", GetDisplayForId(display_id).size().ToString());
}

TEST_F(DisplayManagerTest, Use125DSFForUIScaling) {
  int64_t display_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();

  display::test::ScopedSetInternalDisplayId set_internal(display_manager(),
                                                         display_id);
  UpdateDisplay("1920x1080*1.25");
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveDeviceScaleFactor());
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveUIScale());

  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.8f);
  EXPECT_EQ(1.25f, GetDisplayInfoAt(0).GetEffectiveDeviceScaleFactor());
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveUIScale());
  EXPECT_EQ("1536x864", GetDisplayForId(display_id).size().ToString());

  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 0.5f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveDeviceScaleFactor());
  EXPECT_EQ(0.5f, GetDisplayInfoAt(0).GetEffectiveUIScale());
  EXPECT_EQ("960x540", GetDisplayForId(display_id).size().ToString());

  display::test::DisplayManagerTestApi(display_manager())
      .SetDisplayUIScale(display_id, 1.25f);
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveDeviceScaleFactor());
  EXPECT_EQ(1.25f, GetDisplayInfoAt(0).GetEffectiveUIScale());
  EXPECT_EQ("2400x1350", GetDisplayForId(display_id).size().ToString());
}

TEST_F(DisplayManagerTest, FHD125DefaultsTo08UIScaling) {
  int64_t display_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();

  display_id++;
  display::test::ScopedSetInternalDisplayId set_internal(display_manager(),
                                                         display_id);

  // Setup the display modes with UI-scale.
  display::ManagedDisplayInfo native_display_info =
      display::CreateDisplayInfo(display_id, gfx::Rect(0, 0, 1920, 1080));
  native_display_info.set_device_scale_factor(1.25);

  const display::ManagedDisplayMode base_mode(gfx::Size(1920, 1080), 60.0f,
                                              false, false);
  display::ManagedDisplayInfo::ManagedDisplayModeList mode_list =
      CreateInternalManagedDisplayModeList(base_mode);
  native_display_info.SetManagedDisplayModes(mode_list);

  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(native_display_info);

  display_manager()->OnNativeDisplaysChanged(display_info_list);

  EXPECT_EQ(1.25f, GetDisplayInfoAt(0).GetEffectiveDeviceScaleFactor());
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveUIScale());
}

// Don't default to 1.25 DSF if the user already has a prefrence stored for
// the internal display.
TEST_F(DisplayManagerTest, FHD125DefaultsTo08UIScalingNoOverride) {
  int64_t display_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();

  display_id++;
  display::test::ScopedSetInternalDisplayId set_internal(display_manager(),
                                                         display_id);
  const gfx::Insets dummy_overscan_insets;
  display_manager()->RegisterDisplayProperty(
      display_id, display::Display::ROTATE_0, 1.0f, &dummy_overscan_insets,
      gfx::Size(), 1.0f, 1.0f);

  // Setup the display modes with UI-scale.
  display::ManagedDisplayInfo native_display_info =
      display::CreateDisplayInfo(display_id, gfx::Rect(0, 0, 1920, 1080));
  native_display_info.set_device_scale_factor(1.25);

  const display::ManagedDisplayMode base_mode(gfx::Size(1920, 1080), 60.0f,
                                              false, false);
  display::ManagedDisplayInfo::ManagedDisplayModeList mode_list =
      CreateInternalManagedDisplayModeList(base_mode);
  native_display_info.SetManagedDisplayModes(mode_list);

  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(native_display_info);

  display_manager()->OnNativeDisplaysChanged(display_info_list);

  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveDeviceScaleFactor());
  EXPECT_EQ(1.0f, GetDisplayInfoAt(0).GetEffectiveUIScale());
}

TEST_F(DisplayManagerTest, ResolutionChangeInUnifiedMode) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  display_manager()->SetUnifiedDesktopEnabled(true);

  UpdateDisplay("200x200, 400x400");

  int64_t unified_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();
  display::ManagedDisplayInfo info =
      display_manager()->GetDisplayInfo(unified_id);
  ASSERT_EQ(2u, info.display_modes().size());
  EXPECT_EQ("400x200", info.display_modes()[0].size().ToString());
  EXPECT_TRUE(info.display_modes()[0].native());
  EXPECT_EQ("800x400", info.display_modes()[1].size().ToString());
  EXPECT_FALSE(info.display_modes()[1].native());
  EXPECT_EQ(
      "400x200",
      display::Screen::GetScreen()->GetPrimaryDisplay().size().ToString());
  display::ManagedDisplayMode active_mode;
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(unified_id, &active_mode));
  EXPECT_EQ(1.0f, active_mode.ui_scale());
  EXPECT_EQ("400x200", active_mode.size().ToString());

  EXPECT_TRUE(display::test::SetDisplayResolution(display_manager(), unified_id,
                                                  gfx::Size(800, 400)));
  EXPECT_EQ(
      "800x400",
      display::Screen::GetScreen()->GetPrimaryDisplay().size().ToString());

  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(unified_id, &active_mode));
  EXPECT_EQ(1.0f, active_mode.ui_scale());
  EXPECT_EQ("800x400", active_mode.size().ToString());

  // resolution change will not persist in unified desktop mode.
  UpdateDisplay("600x600, 200x200");
  EXPECT_EQ(
      "1200x600",
      display::Screen::GetScreen()->GetPrimaryDisplay().size().ToString());
  EXPECT_TRUE(
      display_manager()->GetActiveModeForDisplayId(unified_id, &active_mode));
  EXPECT_EQ(1.0f, active_mode.ui_scale());
  EXPECT_TRUE(active_mode.native());
  EXPECT_EQ("1200x600", active_mode.size().ToString());
}

TEST_F(DisplayManagerTest, UpdateMouseCursorAfterRotateZoom) {
  // Make sure just rotating will not change native location.
  UpdateDisplay("300x200,200x150");
  aura::Window::Windows root_windows = Shell::GetAllRootWindows();
  aura::Env* env = aura::Env::GetInstance();

  ui::test::EventGenerator generator1(root_windows[0]);
  ui::test::EventGenerator generator2(root_windows[1]);

  // Test on 1st display.
  generator1.MoveMouseToInHost(150, 50);
  EXPECT_EQ("150,50", env->last_mouse_location().ToString());
  UpdateDisplay("300x200/r,200x150");
  EXPECT_EQ("50,150", env->last_mouse_location().ToString());

  // Test on 2nd display.
  generator2.MoveMouseToInHost(50, 100);
  EXPECT_EQ("250,100", env->last_mouse_location().ToString());
  UpdateDisplay("300x200/r,200x150/l");
  EXPECT_EQ("250,50", env->last_mouse_location().ToString());

  // The native location is now outside, so move to the center
  // of closest display.
  UpdateDisplay("300x200/r,100x50/l");
  EXPECT_EQ("225,50", env->last_mouse_location().ToString());

  // Make sure just zooming will not change native location.
  UpdateDisplay("600x400*2,400x300");

  // Test on 1st display.
  generator1.MoveMouseToInHost(200, 300);
  EXPECT_EQ("100,150", env->last_mouse_location().ToString());
  UpdateDisplay("600x400*2@1.5,400x300");
  EXPECT_EQ("150,225", env->last_mouse_location().ToString());

  // Test on 2nd display.
  UpdateDisplay("600x400,400x300*2");
  generator2.MoveMouseToInHost(200, 250);
  EXPECT_EQ("700,125", env->last_mouse_location().ToString());
  UpdateDisplay("600x400,400x300*2@1.5");
  EXPECT_EQ("750,187", env->last_mouse_location().ToString());

  // The native location is now outside, so move to the
  // center of closest display.
  UpdateDisplay("600x400,400x200*2@1.5");
  EXPECT_EQ("750,75", env->last_mouse_location().ToString());
}

class TestDisplayObserver : public display::DisplayObserver {
 public:
  TestDisplayObserver() : changed_(false) {}
  ~TestDisplayObserver() override = default;

  // display::DisplayObserver overrides:
  void OnDisplayMetricsChanged(const display::Display&, uint32_t) override {}
  void OnDisplayAdded(const display::Display& new_display) override {
    // Mirror window should already be delete before restoring
    // the external display.
    EXPECT_TRUE(test_api.GetHosts().empty());
    changed_ = true;
  }
  void OnDisplayRemoved(const display::Display& old_display) override {
    // Mirror window should not be created until the external display
    // is removed.
    EXPECT_TRUE(test_api.GetHosts().empty());
    changed_ = true;
  }

  bool changed_and_reset() {
    bool changed = changed_;
    changed_ = false;
    return changed;
  }

 private:
  MirrorWindowTestApi test_api;
  bool changed_;

  DISALLOW_COPY_AND_ASSIGN(TestDisplayObserver);
};

TEST_F(DisplayManagerTest, SoftwareMirroring) {
  UpdateDisplay("300x400,400x500");

  MirrorWindowTestApi test_api;
  EXPECT_TRUE(test_api.GetHosts().empty());

  TestDisplayObserver display_observer;
  display::Screen::GetScreen()->AddObserver(&display_observer);

  display_manager()->SetMultiDisplayMode(display::DisplayManager::MIRRORING);
  display_manager()->UpdateDisplays();
  RunAllPendingInMessageLoop();
  EXPECT_TRUE(display_observer.changed_and_reset());
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ(
      "0,0 300x400",
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds().ToString());
  std::vector<aura::WindowTreeHost*> hosts = test_api.GetHosts();
  ASSERT_EQ(1U, hosts.size());
  EXPECT_EQ("400x500", hosts[0]->GetBoundsInPixels().size().ToString());
  EXPECT_EQ("300x400", hosts[0]->window()->bounds().size().ToString());
  EXPECT_TRUE(display_manager()->IsInMirrorMode());

  SetSoftwareMirrorMode(false);
  EXPECT_TRUE(display_observer.changed_and_reset());
  EXPECT_TRUE(test_api.GetHosts().empty());
  EXPECT_EQ(2U, display_manager()->GetNumDisplays());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  // Make sure the mirror window has the pixel size of the
  // source display.
  SetSoftwareMirrorMode(true);
  EXPECT_TRUE(display_observer.changed_and_reset());

  UpdateDisplay("300x400@0.5,400x500");
  EXPECT_FALSE(display_observer.changed_and_reset());
  EXPECT_EQ("300x400",
            test_api.GetHosts()[0]->window()->bounds().size().ToString());

  UpdateDisplay("310x410*2,400x500");
  EXPECT_FALSE(display_observer.changed_and_reset());
  EXPECT_EQ("310x410",
            test_api.GetHosts()[0]->window()->bounds().size().ToString());

  UpdateDisplay("320x420/r,400x500");
  EXPECT_FALSE(display_observer.changed_and_reset());
  EXPECT_EQ("320x420",
            test_api.GetHosts()[0]->window()->bounds().size().ToString());

  UpdateDisplay("330x440/r,400x500");
  EXPECT_FALSE(display_observer.changed_and_reset());
  EXPECT_EQ("330x440",
            test_api.GetHosts()[0]->window()->bounds().size().ToString());

  // Overscan insets are ignored.
  UpdateDisplay("400x600/o,600x800/o");
  EXPECT_FALSE(display_observer.changed_and_reset());
  EXPECT_EQ("400x600",
            test_api.GetHosts()[0]->window()->bounds().size().ToString());

  display::Screen::GetScreen()->RemoveObserver(&display_observer);
}

TEST_F(DisplayManagerTest, RotateInSoftwareMirroring) {
  UpdateDisplay("600x400,500x300");
  SetSoftwareMirrorMode(true);

  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  int64_t primary_id = display::Screen::GetScreen()->GetPrimaryDisplay().id();
  display_manager()->SetDisplayRotation(
      primary_id, display::Display::ROTATE_180,
      display::Display::RotationSource::ACTIVE);
  SetSoftwareMirrorMode(false);
}

// TODO(weidongg/774795) Remove test when multi mirroring is enabled by default.
// Make sure this does not cause any crashes. See http://crbug.com/412910
TEST_F(DisplayManagerTestDisableMultiMirroring,
       SoftwareMirroringWithCompositingCursor) {
  UpdateDisplay("300x400,400x500");

  MirrorWindowTestApi test_api;
  EXPECT_TRUE(test_api.GetHosts().empty());

  display::ManagedDisplayInfo secondary_info =
      display_manager()->GetDisplayInfo(
          display_manager()->GetSecondaryDisplay().id());

  display_manager()->SetSoftwareMirroring(true);
  display_manager()->UpdateDisplays();

  aura::Window::Windows root_windows = Shell::GetAllRootWindows();
  EXPECT_FALSE(root_windows[0]->Contains(test_api.GetCursorWindow()));

  Shell::Get()->SetCursorCompositingEnabled(true);

  EXPECT_TRUE(root_windows[0]->Contains(test_api.GetCursorWindow()));

  // Removes the first display and keeps the second one.
  display_manager()->SetSoftwareMirroring(false);
  std::vector<display::ManagedDisplayInfo> new_info_list;
  new_info_list.push_back(secondary_info);
  display_manager()->OnNativeDisplaysChanged(new_info_list);

  root_windows = Shell::GetAllRootWindows();
  EXPECT_TRUE(root_windows[0]->Contains(test_api.GetCursorWindow()));

  Shell::Get()->SetCursorCompositingEnabled(false);
}

TEST_F(DisplayManagerTest, InvertLayout) {
  EXPECT_EQ("left, 0",
            display::DisplayPlacement(display::DisplayPlacement::RIGHT, 0)
                .Swap()
                .ToString());
  EXPECT_EQ("left, -100",
            display::DisplayPlacement(display::DisplayPlacement::RIGHT, 100)
                .Swap()
                .ToString());
  EXPECT_EQ("left, 50",
            display::DisplayPlacement(display::DisplayPlacement::RIGHT, -50)
                .Swap()
                .ToString());

  EXPECT_EQ("right, 0",
            display::DisplayPlacement(display::DisplayPlacement::LEFT, 0)
                .Swap()
                .ToString());
  EXPECT_EQ("right, -90",
            display::DisplayPlacement(display::DisplayPlacement::LEFT, 90)
                .Swap()
                .ToString());
  EXPECT_EQ("right, 60",
            display::DisplayPlacement(display::DisplayPlacement::LEFT, -60)
                .Swap()
                .ToString());

  EXPECT_EQ("bottom, 0",
            display::DisplayPlacement(display::DisplayPlacement::TOP, 0)
                .Swap()
                .ToString());
  EXPECT_EQ("bottom, -80",
            display::DisplayPlacement(display::DisplayPlacement::TOP, 80)
                .Swap()
                .ToString());
  EXPECT_EQ("bottom, 70",
            display::DisplayPlacement(display::DisplayPlacement::TOP, -70)
                .Swap()
                .ToString());

  EXPECT_EQ("top, 0",
            display::DisplayPlacement(display::DisplayPlacement::BOTTOM, 0)
                .Swap()
                .ToString());
  EXPECT_EQ("top, -70",
            display::DisplayPlacement(display::DisplayPlacement::BOTTOM, 70)
                .Swap()
                .ToString());
  EXPECT_EQ("top, 80",
            display::DisplayPlacement(display::DisplayPlacement::BOTTOM, -80)
                .Swap()
                .ToString());
}

TEST_F(DisplayManagerTest, NotifyPrimaryChange) {
  UpdateDisplay("500x500,500x500");
  SwapPrimaryDisplay();
  reset();
  UpdateDisplay("500x500");
  EXPECT_FALSE(changed_metrics() &
               display::DisplayObserver::DISPLAY_METRIC_BOUNDS);
  EXPECT_FALSE(changed_metrics() &
               display::DisplayObserver::DISPLAY_METRIC_WORK_AREA);
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_PRIMARY);

  UpdateDisplay("500x500,500x500");
  SwapPrimaryDisplay();
  UpdateDisplay("500x400");
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_BOUNDS);
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_WORK_AREA);
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_PRIMARY);
}

TEST_F(DisplayManagerTest, NotifyPrimaryChangeUndock) {
  // Assume the default display is an external display, and
  // emulates undocking by switching to another display.
  display::ManagedDisplayInfo another_display_info =
      display::CreateDisplayInfo(1, gfx::Rect(0, 0, 1280, 800));
  std::vector<display::ManagedDisplayInfo> info_list;
  info_list.push_back(another_display_info);
  reset();
  display_manager()->OnNativeDisplaysChanged(info_list);
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_BOUNDS);
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_WORK_AREA);
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_PRIMARY);
}

TEST_F(DisplayManagerTest, UpdateDisplayWithHostOrigin) {
  UpdateDisplay("100x200,300x400");
  ASSERT_EQ(2, display::Screen::GetScreen()->GetNumDisplays());
  aura::Window::Windows root_windows = Shell::Get()->GetAllRootWindows();
  ASSERT_EQ(2U, root_windows.size());
  aura::WindowTreeHost* host0 = root_windows[0]->GetHost();
  aura::WindowTreeHost* host1 = root_windows[1]->GetHost();

  EXPECT_EQ("1,1", host0->GetBoundsInPixels().origin().ToString());
  EXPECT_EQ("100x200", host0->GetBoundsInPixels().size().ToString());
  // UpdateDisplay set the origin if it's not set.
  EXPECT_NE("1,1", host1->GetBoundsInPixels().origin().ToString());
  EXPECT_EQ("300x400", host1->GetBoundsInPixels().size().ToString());

  UpdateDisplay("100x200,200+300-300x400");
  ASSERT_EQ(2, display::Screen::GetScreen()->GetNumDisplays());
  EXPECT_EQ("0,0", host0->GetBoundsInPixels().origin().ToString());
  EXPECT_EQ("100x200", host0->GetBoundsInPixels().size().ToString());
  EXPECT_EQ("200,300", host1->GetBoundsInPixels().origin().ToString());
  EXPECT_EQ("300x400", host1->GetBoundsInPixels().size().ToString());

  UpdateDisplay("400+500-200x300,300x400");
  ASSERT_EQ(2, display::Screen::GetScreen()->GetNumDisplays());
  EXPECT_EQ("400,500", host0->GetBoundsInPixels().origin().ToString());
  EXPECT_EQ("200x300", host0->GetBoundsInPixels().size().ToString());
  EXPECT_EQ("0,0", host1->GetBoundsInPixels().origin().ToString());
  EXPECT_EQ("300x400", host1->GetBoundsInPixels().size().ToString());

  UpdateDisplay("100+200-100x200,300+500-200x300");
  ASSERT_EQ(2, display::Screen::GetScreen()->GetNumDisplays());
  EXPECT_EQ("100,200", host0->GetBoundsInPixels().origin().ToString());
  EXPECT_EQ("100x200", host0->GetBoundsInPixels().size().ToString());
  EXPECT_EQ("300,500", host1->GetBoundsInPixels().origin().ToString());
  EXPECT_EQ("200x300", host1->GetBoundsInPixels().size().ToString());
}

TEST_F(DisplayManagerTest, UnifiedDesktopBasic) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("400x500,300x200");

  // Enable after extended mode.
  display_manager()->SetUnifiedDesktopEnabled(true);

  // Defaults to the unified desktop.
  display::Screen* screen = display::Screen::GetScreen();
  // The 2nd display is scaled so that it has the same height as 1st display.
  // 300 * 500 / 200  + 400 = 1150.
  EXPECT_EQ(gfx::Size(1150, 500), screen->GetPrimaryDisplay().size());

  SetSoftwareMirrorMode(true);
  EXPECT_EQ(gfx::Size(400, 500), screen->GetPrimaryDisplay().size());

  SetSoftwareMirrorMode(false);
  EXPECT_EQ(gfx::Size(1150, 500), screen->GetPrimaryDisplay().size());

  // Switch to single desktop.
  UpdateDisplay("500x300");
  EXPECT_EQ(gfx::Size(500, 300), screen->GetPrimaryDisplay().size());

  // Switch to unified desktop.
  UpdateDisplay("500x300,400x500");
  // 400 * 300 / 500 + 500 ~= 739.
  EXPECT_EQ(gfx::Size(739, 300), screen->GetPrimaryDisplay().size());

  // The default should fit to the internal display.
  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(
      display::CreateDisplayInfo(10, gfx::Rect(0, 0, 500, 300)));
  display_info_list.push_back(
      display::CreateDisplayInfo(11, gfx::Rect(500, 0, 400, 500)));
  {
    display::test::ScopedSetInternalDisplayId set_internal(display_manager(),
                                                           11);
    display_manager()->OnNativeDisplaysChanged(display_info_list);
    // 500 * 500 / 300 + 400 ~= 1233.
    EXPECT_EQ(gfx::Size(1233, 500), screen->GetPrimaryDisplay().size());
  }

  // Switch to 3 displays.
  UpdateDisplay("500x300,400x500,500x300");
  EXPECT_EQ(gfx::Size(1239, 300), screen->GetPrimaryDisplay().size());

  // Switch back to extended desktop.
  display_manager()->SetUnifiedDesktopEnabled(false);
  EXPECT_EQ(gfx::Size(500, 300), screen->GetPrimaryDisplay().size());
  EXPECT_EQ(gfx::Size(400, 500),
            display_manager()->GetSecondaryDisplay().size());
  EXPECT_EQ(
      gfx::Size(500, 300),
      display_manager()
          ->GetDisplayForId(display_manager()->GetSecondaryDisplay().id() + 1)
          .size());
}

TEST_F(DisplayManagerTest, UnifiedDesktopWithHardwareMirroring) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  // Enter to hardware mirroring.
  display::ManagedDisplayInfo d1(1, "", false);
  d1.SetBounds(gfx::Rect(0, 0, 500, 500));
  display::ManagedDisplayInfo d2(2, "", false);
  d2.SetBounds(gfx::Rect(0, 0, 500, 500));
  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(d1);
  display_info_list.push_back(d2);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  ASSERT_TRUE(display_manager()->IsInHardwareMirrorMode());
  display_manager()->SetUnifiedDesktopEnabled(true);
  EXPECT_TRUE(display_manager()->IsInHardwareMirrorMode());

  // The display manager automatically switches to software mirroring if
  // hardware mirroring is no longer available, because previous mirror mode
  // enforces current display mode to be mirror mode.
  display::DisplayIdList list = display::test::CreateDisplayIdList2(1, 2);
  display::DisplayLayoutBuilder builder(
      display_manager()->layout_store()->GetRegisteredDisplayLayout(list));
  display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
      list, builder.Build());
  d2.SetBounds(gfx::Rect(0, 500, 500, 500));
  display_info_list.clear();
  display_info_list.push_back(d1);
  display_info_list.push_back(d2);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_FALSE(display_manager()->IsInUnifiedMode());

  // Exit software mirroring and enter unified desktop mode after mirror mode is
  // turned off.
  SetSoftwareMirrorMode(false);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_TRUE(display_manager()->IsInUnifiedMode());
}

TEST_F(DisplayManagerTest, UnifiedDesktopEnabledWithExtended) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("400x500,300x200");
  display::DisplayIdList list = display_manager()->GetCurrentDisplayIdList();
  display::DisplayLayoutBuilder builder(
      display_manager()->layout_store()->GetRegisteredDisplayLayout(list));
  builder.SetDefaultUnified(false);
  display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
      list, builder.Build());
  display_manager()->SetUnifiedDesktopEnabled(true);
  EXPECT_FALSE(display_manager()->IsInUnifiedMode());
}

TEST_F(DisplayManagerTest, UnifiedDesktopWith2xDSF) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  display_manager()->SetUnifiedDesktopEnabled(true);
  display::Screen* screen = display::Screen::GetScreen();

  // 2nd display is 2x.
  UpdateDisplay("400x500,1000x800*2");
  display::ManagedDisplayInfo info =
      display_manager()->GetDisplayInfo(screen->GetPrimaryDisplay().id());
  ASSERT_EQ(2u, info.display_modes().size());
  EXPECT_EQ("1640x800", info.display_modes()[0].size().ToString());
  EXPECT_EQ(2.0f, info.display_modes()[0].device_scale_factor());
  EXPECT_EQ("1025x500", info.display_modes()[1].size().ToString());
  EXPECT_EQ(1.0f, info.display_modes()[1].device_scale_factor());

  // For 1x, 400 + 500 / 800 * 100 = 1025.
  EXPECT_EQ("1025x500", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("1025x500",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());
  accelerators::ZoomDisplay(false);
  // (800 / 500 * 400 + 500) /2 = 820
  EXPECT_EQ("820x400", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("820x400",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());

  // 1st display is 2x.
  UpdateDisplay("1200x800*2,1000x1000");
  info = display_manager()->GetDisplayInfo(screen->GetPrimaryDisplay().id());
  ASSERT_EQ(2u, info.display_modes().size());
  EXPECT_EQ("2000x800", info.display_modes()[0].size().ToString());
  EXPECT_EQ(2.0f, info.display_modes()[0].device_scale_factor());
  EXPECT_EQ("2500x1000", info.display_modes()[1].size().ToString());
  EXPECT_EQ(1.0f, info.display_modes()[1].device_scale_factor());

  // For 2x, (800 / 1000 * 1000 + 1200) / 2 = 1000
  EXPECT_EQ("1000x400", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("1000x400",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());
  accelerators::ZoomDisplay(true);
  // 1000 / 800 * 1200 + 1000 = 2500
  EXPECT_EQ("2500x1000", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("2500x1000",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());

  // Both displays are 2x.
  // 1st display is 2x.
  UpdateDisplay("1200x800*2,1000x1000*2");
  info = display_manager()->GetDisplayInfo(screen->GetPrimaryDisplay().id());
  ASSERT_EQ(2u, info.display_modes().size());
  EXPECT_EQ("2000x800", info.display_modes()[0].size().ToString());
  EXPECT_EQ(2.0f, info.display_modes()[0].device_scale_factor());
  EXPECT_EQ("2500x1000", info.display_modes()[1].size().ToString());
  EXPECT_EQ(2.0f, info.display_modes()[1].device_scale_factor());

  EXPECT_EQ("1000x400", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("1000x400",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());
  accelerators::ZoomDisplay(true);
  EXPECT_EQ("1250x500", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("1250x500",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());

  // Both displays have the same physical height, with the first display
  // being 2x.
  UpdateDisplay("1000x800*2,300x800");
  info = display_manager()->GetDisplayInfo(screen->GetPrimaryDisplay().id());
  ASSERT_EQ(2u, info.display_modes().size());
  EXPECT_EQ("1300x800", info.display_modes()[0].size().ToString());
  EXPECT_EQ(2.0f, info.display_modes()[0].device_scale_factor());
  EXPECT_EQ("1300x800", info.display_modes()[1].size().ToString());
  EXPECT_EQ(1.0f, info.display_modes()[1].device_scale_factor());

  EXPECT_EQ("650x400", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("650x400",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());
  accelerators::ZoomDisplay(true);
  EXPECT_EQ("1300x800", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("1300x800",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());

  // Both displays have the same physical height, with the second display
  // being 2x.
  UpdateDisplay("1000x800,300x800*2");
  ASSERT_EQ(2u, info.display_modes().size());
  EXPECT_EQ("1300x800", info.display_modes()[0].size().ToString());
  EXPECT_EQ(2.0f, info.display_modes()[0].device_scale_factor());
  EXPECT_EQ("1300x800", info.display_modes()[1].size().ToString());
  EXPECT_EQ(1.0f, info.display_modes()[1].device_scale_factor());

  EXPECT_EQ("1300x800", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("1300x800",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());
  accelerators::ZoomDisplay(false);
  EXPECT_EQ("650x400", screen->GetPrimaryDisplay().size().ToString());
  EXPECT_EQ("650x400",
            Shell::GetPrimaryRootWindow()->bounds().size().ToString());
}

// Updating displays again in unified desktop mode should not crash.
// crbug.com/491094.
TEST_F(DisplayManagerTest, ConfigureUnifiedTwice) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("300x200,400x500");
  // Mirror windows are created in a posted task.
  RunAllPendingInMessageLoop();

  UpdateDisplay("300x250,400x550");
  RunAllPendingInMessageLoop();
}

TEST_F(DisplayManagerTest, NoRotateUnifiedDesktop) {
  display_manager()->SetUnifiedDesktopEnabled(true);

  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("400x500,300x200");

  display::Screen* screen = display::Screen::GetScreen();
  const display::Display& display = screen->GetPrimaryDisplay();
  EXPECT_EQ("1150x500", display.size().ToString());
  display_manager()->SetDisplayRotation(
      display.id(), display::Display::ROTATE_90,
      display::Display::RotationSource::ACTIVE);
  EXPECT_EQ("1150x500", screen->GetPrimaryDisplay().size().ToString());
  display_manager()->SetDisplayRotation(
      display.id(), display::Display::ROTATE_0,
      display::Display::RotationSource::ACTIVE);
  EXPECT_EQ("1150x500", screen->GetPrimaryDisplay().size().ToString());

  UpdateDisplay("400x500");
  EXPECT_EQ("400x500", screen->GetPrimaryDisplay().size().ToString());
}

// Validate that setting an invalid matrix will fall back to the default
// horizontal unified desktop layout.
TEST_F(DisplayManagerTest, UnifiedDesktopInvalidMatrices) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("400x500,300x200");
  display_manager()->SetUnifiedDesktopEnabled(true);
  display::Screen* screen = display::Screen::GetScreen();

  display::DisplayIdList list = display_manager()->GetCurrentDisplayIdList();
  ASSERT_EQ(2u, list.size());
  {
    // Create an empty matrix.
    display::UnifiedDesktopLayoutMatrix matrix;
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    // The result is still a valid default horizontal layout.
    EXPECT_EQ(gfx::Size(1150, 500), screen->GetPrimaryDisplay().size());

    // 2 x 1 empty matrix.
    matrix.resize(2u);
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    // The result is still a valid default horizontal layout.
    EXPECT_EQ(gfx::Size(1150, 500), screen->GetPrimaryDisplay().size());
  }

  {
    // 2 x 1 vertical matrix with invalid IDs.
    display::UnifiedDesktopLayoutMatrix matrix;
    matrix.resize(2u);
    matrix[0].emplace_back(list[0]);
    matrix[1].emplace_back(-100);
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    // The result is still a valid default horizontal layout.
    EXPECT_EQ(gfx::Size(1150, 500), screen->GetPrimaryDisplay().size());
  }

  {
    // Matrix with a missing ID.
    display::UnifiedDesktopLayoutMatrix matrix;
    matrix.resize(2u);
    matrix[0].emplace_back(list[0]);
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    // The result is still a valid default horizontal layout.
    EXPECT_EQ(gfx::Size(1150, 500), screen->GetPrimaryDisplay().size());
  }

  // Switch to 3 displays.
  UpdateDisplay("500x300,400x500,500x300");
  list = display_manager()->GetCurrentDisplayIdList();
  ASSERT_EQ(3u, list.size());
  {
    // Create a matrix with unequal rows
    display::UnifiedDesktopLayoutMatrix matrix;
    matrix.resize(3u);
    matrix[0].emplace_back(list[0]);
    matrix[1].emplace_back(list[1]);
    matrix[1].emplace_back(list[2]);  // Typo; meant to say matrix[2].
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    // The result is still a valid default horizontal layout.
    EXPECT_EQ(gfx::Size(1239, 300), screen->GetPrimaryDisplay().size());
  }

  {
    // Create a matrix with repeated IDs.
    display::UnifiedDesktopLayoutMatrix matrix;
    matrix.resize(3u);
    matrix[0].emplace_back(list[0]);
    matrix[1].emplace_back(list[1]);
    matrix[2].emplace_back(list[1]);  // Typo; meant to say list[2].
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    // The result is still a valid default horizontal layout.
    EXPECT_EQ(gfx::Size(1239, 300), screen->GetPrimaryDisplay().size());
  }
}

TEST_F(DisplayManagerTest, UnifiedDesktopVerticalLayout2x1) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("400x500,300x200");
  display_manager()->SetUnifiedDesktopEnabled(true);
  display::Screen* screen = display::Screen::GetScreen();
  // This is still a horizontal layout.
  EXPECT_EQ(gfx::Size(1150, 500), screen->GetPrimaryDisplay().size());

  display::DisplayIdList list = display_manager()->GetCurrentDisplayIdList();
  ASSERT_EQ(2u, list.size());
  {
    // Create a 2 x 1 vertical layout matrix and set it.
    // [400 x 500]
    // [300 x 200]
    display::UnifiedDesktopLayoutMatrix matrix;
    matrix.resize(2u);
    matrix[0].emplace_back(list[0]);
    matrix[1].emplace_back(list[1]);
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    // 500 + 400 * 200 / 300 ~= 766.
    EXPECT_EQ(gfx::Size(400, 766), screen->GetPrimaryDisplay().size());
    // Display in top-left cell is considered primary.
    EXPECT_EQ(
        list[0],
        display_manager()->GetPrimaryMirroringDisplayForUnifiedDesktop()->id());

    // Validate display rows and max heights.
    EXPECT_EQ(0, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[0]));
    EXPECT_EQ(1, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[1]));
    EXPECT_EQ(500, display_manager()->GetUnifiedDesktopRowMaxHeight(0));
    EXPECT_EQ(400 * 200 / 300,
              display_manager()->GetUnifiedDesktopRowMaxHeight(1));
    EXPECT_FALSE(OverlappingMirroringDisplaysExist());
  }

  {
    // Change the order of the displays such that the [300 x 200] is on top,
    // which should make its bounds used for the default mode.
    // [300 x 200]
    // [400 x 500]
    display::UnifiedDesktopLayoutMatrix matrix;
    matrix.resize(2u);
    matrix[0].emplace_back(list[1]);
    matrix[1].emplace_back(list[0]);
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    // 200 + 300 * 500 / 400 ~= 574 (Note that we actually scale the max unified
    // bounds).
    EXPECT_EQ(gfx::Size(300, 574), screen->GetPrimaryDisplay().size());
    // Display in top-left cell is considered primary.
    EXPECT_EQ(
        list[1],
        display_manager()->GetPrimaryMirroringDisplayForUnifiedDesktop()->id());

    // Validate display rows and max heights.
    EXPECT_EQ(1, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[0]));
    EXPECT_EQ(0, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[1]));
    EXPECT_EQ(199, display_manager()->GetUnifiedDesktopRowMaxHeight(0));
    // 300 * 500 / 400.
    EXPECT_EQ(375, display_manager()->GetUnifiedDesktopRowMaxHeight(1));
    EXPECT_FALSE(OverlappingMirroringDisplaysExist());
  }

  {
    // Revert to the first matrix, but mark the [300 x 200] display as internal.
    // [400 x 500]
    // [300 x 200] : Internal
    display::UnifiedDesktopLayoutMatrix matrix;
    matrix.resize(2u);
    matrix[0].emplace_back(list[0]);
    matrix[1].emplace_back(list[1]);
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    std::vector<display::ManagedDisplayInfo> display_info_list;
    display_info_list.emplace_back(
        display::CreateDisplayInfo(list[0], gfx::Rect(0, 0, 400, 500)));
    display_info_list.emplace_back(
        display::CreateDisplayInfo(list[1], gfx::Rect(400, 0, 300, 200)));
    display::test::ScopedSetInternalDisplayId set_internal(display_manager(),
                                                           list[1]);
    display_manager()->OnNativeDisplaysChanged(display_info_list);
    EXPECT_EQ(gfx::Size(300, 574), screen->GetPrimaryDisplay().size());
    // Display in top-left cell is considered primary.
    EXPECT_EQ(
        list[0],
        display_manager()->GetPrimaryMirroringDisplayForUnifiedDesktop()->id());

    // Validate display rows and max heights.
    EXPECT_EQ(0, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[0]));
    EXPECT_EQ(1, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[1]));
    // 300 * 500 / 400.
    EXPECT_EQ(375, display_manager()->GetUnifiedDesktopRowMaxHeight(0));
    EXPECT_EQ(199, display_manager()->GetUnifiedDesktopRowMaxHeight(1));
    EXPECT_FALSE(OverlappingMirroringDisplaysExist());
  }
}

TEST_F(DisplayManagerTest, UnifiedDesktopVerticalLayout3x1) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("500x300,400x500,500x300");
  display_manager()->SetUnifiedDesktopEnabled(true);
  display::Screen* screen = display::Screen::GetScreen();

  display::DisplayIdList list = display_manager()->GetCurrentDisplayIdList();
  ASSERT_EQ(3u, list.size());
  {
    // Create a 3 x 1 vertical layout matrix and set it.
    // [500 x 300]
    // [400 x 500]
    // [500 x 300]
    display::UnifiedDesktopLayoutMatrix matrix;
    matrix.resize(3u);
    matrix[0].emplace_back(list[0]);
    matrix[1].emplace_back(list[1]);
    matrix[2].emplace_back(list[2]);
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    EXPECT_EQ(gfx::Size(500, 1225), screen->GetPrimaryDisplay().size());
    // Display in top-left cell is considered primary.
    EXPECT_EQ(
        list[0],
        display_manager()->GetPrimaryMirroringDisplayForUnifiedDesktop()->id());

    // Validate display rows and max heights.
    EXPECT_EQ(0, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[0]));
    EXPECT_EQ(1, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[1]));
    EXPECT_EQ(2, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[2]));
    EXPECT_EQ(300, display_manager()->GetUnifiedDesktopRowMaxHeight(0));
    // 500 * 500 / 400 = 625.
    EXPECT_EQ(625, display_manager()->GetUnifiedDesktopRowMaxHeight(1));
    EXPECT_EQ(300, display_manager()->GetUnifiedDesktopRowMaxHeight(2));
    EXPECT_FALSE(OverlappingMirroringDisplaysExist());
  }

  {
    // We can change the order however we want.
    // [400 x 500]
    // [500 x 300]
    // [500 x 300]
    display::UnifiedDesktopLayoutMatrix matrix;
    matrix.resize(3u);
    matrix[0].emplace_back(list[1]);
    matrix[1].emplace_back(list[0]);
    matrix[2].emplace_back(list[2]);
    display_manager()->SetUnifiedDesktopMatrix(matrix);
    EXPECT_EQ(gfx::Size(400, 980), screen->GetPrimaryDisplay().size());
    // Display in top-left cell is considered primary.
    EXPECT_EQ(
        list[1],
        display_manager()->GetPrimaryMirroringDisplayForUnifiedDesktop()->id());

    // Validate display rows and max heights.
    EXPECT_EQ(1, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[0]));
    EXPECT_EQ(0, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[1]));
    EXPECT_EQ(2, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                     list[2]));
    EXPECT_EQ(500, display_manager()->GetUnifiedDesktopRowMaxHeight(0));
    // 400 * 300 / 500 = 240.
    EXPECT_EQ(240, display_manager()->GetUnifiedDesktopRowMaxHeight(1));
    EXPECT_EQ(240, display_manager()->GetUnifiedDesktopRowMaxHeight(2));
    EXPECT_FALSE(OverlappingMirroringDisplaysExist());
  }
}

TEST_F(DisplayManagerTest, UnifiedDesktopGridLayout2x2) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("500x300,400x500,300x600,200x300");
  display_manager()->SetUnifiedDesktopEnabled(true);
  display::Screen* screen = display::Screen::GetScreen();

  display::DisplayIdList list = display_manager()->GetCurrentDisplayIdList();
  ASSERT_EQ(4u, list.size());
  // Create a 2 x 2 vertical layout matrix and set it.
  // [500 x 300] [400 x 500]
  // [300 x 600] [200 x 300]
  display::UnifiedDesktopLayoutMatrix matrix;
  matrix.resize(2u);
  matrix[0].emplace_back(list[0]);
  matrix[0].emplace_back(list[1]);
  matrix[1].emplace_back(list[2]);
  matrix[1].emplace_back(list[3]);
  display_manager()->SetUnifiedDesktopMatrix(matrix);
  EXPECT_EQ(gfx::Size(739, 933), screen->GetPrimaryDisplay().size());
  // Display in top-left cell is considered primary.
  EXPECT_EQ(
      list[0],
      display_manager()->GetPrimaryMirroringDisplayForUnifiedDesktop()->id());

  // Validate display rows and max heights.
  EXPECT_EQ(0, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[0]));
  EXPECT_EQ(0, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[1]));
  EXPECT_EQ(1, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[2]));
  EXPECT_EQ(1, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[3]));
  EXPECT_EQ(300, display_manager()->GetUnifiedDesktopRowMaxHeight(0));
  EXPECT_EQ(633, display_manager()->GetUnifiedDesktopRowMaxHeight(1));
  EXPECT_FALSE(OverlappingMirroringDisplaysExist());
}

TEST_F(DisplayManagerTest, UnifiedDesktopGridLayout3x2) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("500x300,400x500,300x600,200x300,700x200,350x480");
  display_manager()->SetUnifiedDesktopEnabled(true);
  display::Screen* screen = display::Screen::GetScreen();

  display::DisplayIdList list = display_manager()->GetCurrentDisplayIdList();
  ASSERT_EQ(6u, list.size());
  // Create a 3 x 2 vertical layout matrix and set it.
  // [500 x 300] [400 x 500]
  // [300 x 600] [200 x 300]
  // [700 x 200] [350 x 480]
  display::UnifiedDesktopLayoutMatrix matrix;
  matrix.resize(3u);
  matrix[0].emplace_back(list[0]);
  matrix[0].emplace_back(list[1]);
  matrix[1].emplace_back(list[2]);
  matrix[1].emplace_back(list[3]);
  matrix[2].emplace_back(list[4]);
  matrix[2].emplace_back(list[5]);
  display_manager()->SetUnifiedDesktopMatrix(matrix);
  EXPECT_EQ(gfx::Size(739, 1108), screen->GetPrimaryDisplay().size());
  // Display in top-left cell is considered primary.
  EXPECT_EQ(
      list[0],
      display_manager()->GetPrimaryMirroringDisplayForUnifiedDesktop()->id());

  // Validate display rows and max heights.
  EXPECT_EQ(0, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[0]));
  EXPECT_EQ(0, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[1]));
  EXPECT_EQ(1, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[2]));
  EXPECT_EQ(1, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[3]));
  EXPECT_EQ(2, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[4]));
  EXPECT_EQ(2, display_manager()->GetMirroringDisplayRowIndexInUnifiedMatrix(
                   list[5]));
  EXPECT_EQ(300, display_manager()->GetUnifiedDesktopRowMaxHeight(0));
  EXPECT_EQ(633, display_manager()->GetUnifiedDesktopRowMaxHeight(1));
  EXPECT_EQ(175, display_manager()->GetUnifiedDesktopRowMaxHeight(2));
  EXPECT_FALSE(OverlappingMirroringDisplaysExist());
}

TEST_F(DisplayManagerTest, DockMode) {
  const int64_t internal_id = 1;
  const int64_t external_id = 2;

  const display::ManagedDisplayInfo internal_display_info =
      display::CreateDisplayInfo(internal_id, gfx::Rect(0, 0, 500, 500));
  const display::ManagedDisplayInfo external_display_info =
      display::CreateDisplayInfo(external_id, gfx::Rect(1, 1, 100, 100));
  std::vector<display::ManagedDisplayInfo> display_info_list;

  // software mirroring.
  display_info_list.push_back(internal_display_info);
  display_info_list.push_back(external_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  const int64_t internal_display_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  EXPECT_EQ(internal_id, internal_display_id);

  display_info_list.clear();
  display_info_list.push_back(external_display_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(1U, display_manager()->active_display_list().size());

  EXPECT_TRUE(display_manager()->IsActiveDisplayId(external_id));
  EXPECT_FALSE(display_manager()->IsActiveDisplayId(internal_id));

  EXPECT_FALSE(display_manager()->ZoomInternalDisplay(true));
  EXPECT_FALSE(display_manager()->ZoomInternalDisplay(false));
  EXPECT_FALSE(display::test::DisplayManagerTestApi(display_manager())
                   .SetDisplayUIScale(internal_id, 1.0f));
}

// Make sure that bad layout information is ignored and does not crash.
TEST_F(DisplayManagerTest, DontRegisterBadConfig) {
  display::DisplayIdList list = display::test::CreateDisplayIdList2(1, 2);
  display::DisplayLayoutBuilder builder(1);
  builder.AddDisplayPlacement(2, 1, display::DisplayPlacement::LEFT, 0);
  builder.AddDisplayPlacement(3, 1, display::DisplayPlacement::BOTTOM, 0);

  display_manager()->layout_store()->RegisterLayoutForDisplayIdList(
      list, builder.Build());
}

class ScreenShutdownTest : public AshTestBase {
 public:
  ScreenShutdownTest() = default;
  ~ScreenShutdownTest() override = default;

  void TearDown() override {
    display::Screen* orig_screen = display::Screen::GetScreen();
    AshTestBase::TearDown();
    display::Screen* screen = display::Screen::GetScreen();
    EXPECT_NE(orig_screen, screen);
    EXPECT_EQ(2, screen->GetNumDisplays());
    EXPECT_EQ("500x300", screen->GetPrimaryDisplay().size().ToString());
    std::vector<display::Display> all = screen->GetAllDisplays();
    EXPECT_EQ("500x300", all[0].size().ToString());
    EXPECT_EQ("800x400", all[1].size().ToString());
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ScreenShutdownTest);
};

TEST_F(ScreenShutdownTest, ScreenAfterShutdown) {
  UpdateDisplay("500x300,800x400");
}

namespace {

// A helper class that sets the display configuration and starts ash.
// This is to make sure the font configuration happens during ash
// initialization process.
class FontTestHelper : public AshTestBase {
 public:
  enum DisplayType { INTERNAL, EXTERNAL };

  FontTestHelper(float scale, DisplayType display_type) {
    gfx::ClearFontRenderParamsCacheForTest();
    base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
    if (display_type == INTERNAL)
      command_line->AppendSwitch(::switches::kUseFirstDisplayAsInternal);
    command_line->AppendSwitchASCII(::switches::kHostWindowBounds,
                                    StringPrintf("1000x800*%f", scale));
    SetUp();
  }

  ~FontTestHelper() override { TearDown(); }

  // AshTestBase:
  void TestBody() override { NOTREACHED(); }

 private:
  DISALLOW_COPY_AND_ASSIGN(FontTestHelper);
};

bool IsTextSubpixelPositioningEnabled() {
  gfx::FontRenderParams params =
      gfx::GetFontRenderParams(gfx::FontRenderParamsQuery(), nullptr);
  return params.subpixel_positioning;
}

gfx::FontRenderParams::Hinting GetFontHintingParams() {
  gfx::FontRenderParams params =
      gfx::GetFontRenderParams(gfx::FontRenderParamsQuery(), nullptr);
  return params.hinting;
}

}  // namespace

using DisplayManagerFontTest = testing::Test;

TEST_F(DisplayManagerFontTest, TextSubpixelPositioningWithDsf100Internal) {
  FontTestHelper helper(1.0f, FontTestHelper::INTERNAL);
  ASSERT_DOUBLE_EQ(
      1.0f,
      display::Screen::GetScreen()->GetPrimaryDisplay().device_scale_factor());
  EXPECT_FALSE(IsTextSubpixelPositioningEnabled());
  EXPECT_NE(gfx::FontRenderParams::HINTING_NONE, GetFontHintingParams());
}

TEST_F(DisplayManagerFontTest, TextSubpixelPositioningWithDsf200Internal) {
  FontTestHelper helper(2.0f, FontTestHelper::INTERNAL);
  ASSERT_DOUBLE_EQ(
      2.0f,
      display::Screen::GetScreen()->GetPrimaryDisplay().device_scale_factor());
  EXPECT_TRUE(IsTextSubpixelPositioningEnabled());
  EXPECT_EQ(gfx::FontRenderParams::HINTING_NONE, GetFontHintingParams());

  display::test::DisplayManagerTestApi(helper.display_manager())
      .SetDisplayUIScale(display::Screen::GetScreen()->GetPrimaryDisplay().id(),
                         2.0f);

  ASSERT_DOUBLE_EQ(
      1.0f,
      display::Screen::GetScreen()->GetPrimaryDisplay().device_scale_factor());
  EXPECT_FALSE(IsTextSubpixelPositioningEnabled());
  EXPECT_NE(gfx::FontRenderParams::HINTING_NONE, GetFontHintingParams());
}

TEST_F(DisplayManagerFontTest, TextSubpixelPositioningWithDsf100External) {
  FontTestHelper helper(1.0f, FontTestHelper::EXTERNAL);
  ASSERT_DOUBLE_EQ(
      1.0f,
      display::Screen::GetScreen()->GetPrimaryDisplay().device_scale_factor());
  EXPECT_FALSE(IsTextSubpixelPositioningEnabled());
  EXPECT_NE(gfx::FontRenderParams::HINTING_NONE, GetFontHintingParams());
}

TEST_F(DisplayManagerFontTest, TextSubpixelPositioningWithDsf125External) {
  FontTestHelper helper(1.25f, FontTestHelper::EXTERNAL);
  ASSERT_DOUBLE_EQ(
      1.25f,
      display::Screen::GetScreen()->GetPrimaryDisplay().device_scale_factor());
  EXPECT_TRUE(IsTextSubpixelPositioningEnabled());
  EXPECT_EQ(gfx::FontRenderParams::HINTING_NONE, GetFontHintingParams());
}

TEST_F(DisplayManagerFontTest, TextSubpixelPositioningWithDsf200External) {
  FontTestHelper helper(2.0f, FontTestHelper::EXTERNAL);
  ASSERT_DOUBLE_EQ(
      2.0f,
      display::Screen::GetScreen()->GetPrimaryDisplay().device_scale_factor());
  EXPECT_TRUE(IsTextSubpixelPositioningEnabled());
  EXPECT_EQ(gfx::FontRenderParams::HINTING_NONE, GetFontHintingParams());
}

TEST_F(DisplayManagerFontTest,
       TextSubpixelPositioningWithDsf125InternalWithScaling) {
  FontTestHelper helper(1.25f, FontTestHelper::INTERNAL);
  ASSERT_DOUBLE_EQ(
      1.0f,
      display::Screen::GetScreen()->GetPrimaryDisplay().device_scale_factor());
  EXPECT_FALSE(IsTextSubpixelPositioningEnabled());
  EXPECT_NE(gfx::FontRenderParams::HINTING_NONE, GetFontHintingParams());

  display::test::DisplayManagerTestApi(helper.display_manager())
      .SetDisplayUIScale(display::Screen::GetScreen()->GetPrimaryDisplay().id(),
                         0.8f);

  ASSERT_DOUBLE_EQ(
      1.25f,
      display::Screen::GetScreen()->GetPrimaryDisplay().device_scale_factor());
  EXPECT_TRUE(IsTextSubpixelPositioningEnabled());
  EXPECT_EQ(gfx::FontRenderParams::HINTING_NONE, GetFontHintingParams());
}

TEST_F(DisplayManagerTest, CheckInitializationOfRotationProperty) {
  int64_t id = display_manager()->GetDisplayAt(0).id();
  display_manager()->RegisterDisplayProperty(
      id, display::Display::ROTATE_90, 1.0f, nullptr, gfx::Size(), 1.0f, 1.0f);

  const display::ManagedDisplayInfo& info =
      display_manager()->GetDisplayInfo(id);

  EXPECT_EQ(display::Display::ROTATE_90,
            info.GetRotation(display::Display::RotationSource::USER));
  EXPECT_EQ(display::Display::ROTATE_90,
            info.GetRotation(display::Display::RotationSource::ACTIVE));
}

TEST_F(DisplayManagerTest, RejectInvalidLayoutData) {
  display::DisplayLayoutStore* layout_store = display_manager()->layout_store();
  int64_t id1 = 10001;
  int64_t id2 = 10002;
  ASSERT_TRUE(display::CompareDisplayIds(id1, id2));
  display::DisplayLayoutBuilder good_builder(id1);
  good_builder.SetSecondaryPlacement(id2, display::DisplayPlacement::LEFT, 0);
  std::unique_ptr<display::DisplayLayout> good(good_builder.Build());

  display::DisplayIdList good_list =
      display::test::CreateDisplayIdList2(id1, id2);
  layout_store->RegisterLayoutForDisplayIdList(good_list, good->Copy());

  display::DisplayLayoutBuilder bad(id1);
  bad.SetSecondaryPlacement(id2, display::DisplayPlacement::BOTTOM, 0);

  display::DisplayIdList bad_list(2);
  bad_list[0] = id2;
  bad_list[1] = id1;
  layout_store->RegisterLayoutForDisplayIdList(bad_list, bad.Build());

  EXPECT_EQ(good->ToString(),
            layout_store->GetRegisteredDisplayLayout(good_list).ToString());
}

TEST_F(DisplayManagerTest, GuessDisplayIdFieldsInDisplayLayout) {
  int64_t id1 = 10001;
  int64_t id2 = 10002;

  std::unique_ptr<display::DisplayLayout> old_layout(
      new display::DisplayLayout);
  old_layout->placement_list.emplace_back(display::DisplayPlacement::BOTTOM, 0);
  old_layout->primary_id = id1;

  display::DisplayLayoutStore* layout_store = display_manager()->layout_store();
  display::DisplayIdList list = display::test::CreateDisplayIdList2(id1, id2);
  layout_store->RegisterLayoutForDisplayIdList(list, std::move(old_layout));
  const display::DisplayLayout& stored =
      layout_store->GetRegisteredDisplayLayout(list);

  EXPECT_EQ(id1, stored.placement_list[0].parent_display_id);
  EXPECT_EQ(id2, stored.placement_list[0].display_id);
}

TEST_F(DisplayManagerTest, AccelerometerSupport) {
  display::test::DisplayManagerTestApi(display_manager())
      .SetFirstDisplayAsInternalDisplay();
  display::Screen* screen = display::Screen::GetScreen();
  EXPECT_EQ(display::Display::AccelerometerSupport::UNAVAILABLE,
            screen->GetPrimaryDisplay().accelerometer_support());

  display_manager()->set_internal_display_has_accelerometer(true);
  display_manager()->UpdateDisplays();
  EXPECT_EQ(display::Display::AccelerometerSupport::AVAILABLE,
            screen->GetPrimaryDisplay().accelerometer_support());

  UpdateDisplay("1000x1000,800x800");
  EXPECT_EQ(display::Display::AccelerometerSupport::AVAILABLE,
            screen->GetPrimaryDisplay().accelerometer_support());
  EXPECT_EQ(display::Display::AccelerometerSupport::UNAVAILABLE,
            display_manager()->GetSecondaryDisplay().accelerometer_support());

  // Secondary is now primary and should not have accelerometer support.
  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(
      display::CreateDisplayInfo(display_manager()->GetSecondaryDisplay().id(),
                                 gfx::Rect(1, 1, 100, 100)));
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(display::Display::AccelerometerSupport::UNAVAILABLE,
            screen->GetPrimaryDisplay().accelerometer_support());

  // Re-enable internal display.
  display_info_list.clear();
  display_info_list.push_back(display::CreateDisplayInfo(
      display::Display::InternalDisplayId(), gfx::Rect(1, 1, 100, 100)));
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_EQ(display::Display::AccelerometerSupport::AVAILABLE,
            screen->GetPrimaryDisplay().accelerometer_support());
}

namespace {

std::unique_ptr<display::DisplayMode> MakeDisplayMode() {
  return std::make_unique<display::DisplayMode>(gfx::Size(1366, 768), false,
                                                60);
}

}  // namespace

TEST_F(DisplayManagerTest, DisconnectedInternalDisplayShouldUpdateDisplayInfo) {
  constexpr int64_t external_id = 123;
  const int64_t internal_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  display::Screen* screen = display::Screen::GetScreen();
  DCHECK(screen);
  Shell* shell = Shell::Get();
  display::DisplayChangeObserver observer(shell->display_configurator(),
                                          display_manager());
  display::DisplayConfigurator::DisplayStateList outputs;
  std::unique_ptr<display::DisplaySnapshot> internal_snapshot =
      display::FakeDisplaySnapshot::Builder()
          .SetId(internal_id)
          .SetType(display::DISPLAY_CONNECTION_TYPE_INTERNAL)
          .SetDPI(210)  // 1.6f
          .SetNativeMode(MakeDisplayMode())
          .Build();
  EXPECT_FALSE(internal_snapshot->current_mode());

  outputs.push_back(internal_snapshot.get());
  std::unique_ptr<display::DisplaySnapshot> external_snapshot =
      display::FakeDisplaySnapshot::Builder()
          .SetId(external_id)
          .SetNativeMode(MakeDisplayMode())
          .AddMode(MakeDisplayMode())
          .SetOrigin({0, 1000})
          .Build();
  // "Connectd display" has the current mode.
  external_snapshot->set_current_mode(external_snapshot->native_mode());

  outputs.push_back(external_snapshot.get());

  // Update the display manager through DisplayChangeObserver.
  observer.GetStateForDisplayIds(outputs);
  observer.OnDisplayModeChanged(outputs);

  EXPECT_EQ(1u, display_manager()->GetNumDisplays());
  EXPECT_TRUE(display_manager()->IsActiveDisplayId(external_id));
  EXPECT_FALSE(display_manager()->IsActiveDisplayId(internal_id));

  const display::ManagedDisplayInfo& display_info =
      display_manager()->GetDisplayInfo(internal_id);
  EXPECT_EQ(1.6f, display_info.device_scale_factor());

  bool has_default = false;
  for (auto& mode : display_info.display_modes()) {
    if (mode.is_default()) {
      has_default = true;
      EXPECT_EQ(1.6f, mode.device_scale_factor());
    }
  }
  EXPECT_TRUE(has_default);
}

TEST_F(DisplayManagerTest, UpdateInternalDisplayNativeBounds) {
  constexpr int64_t external_id = 123;
  const int64_t internal_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  display::Screen* screen = display::Screen::GetScreen();
  DCHECK(screen);
  Shell* shell = Shell::Get();
  display::DisplayChangeObserver observer(shell->display_configurator(),
                                          display_manager());
  display::DisplayConfigurator::DisplayStateList outputs;
  std::unique_ptr<display::DisplaySnapshot> internal_snapshot =
      display::FakeDisplaySnapshot::Builder()
          .SetId(internal_id)
          .SetType(display::DISPLAY_CONNECTION_TYPE_INTERNAL)
          .SetDPI(210)  // 1.6f
          .SetNativeMode(MakeDisplayMode())
          .Build();
  internal_snapshot->set_current_mode(internal_snapshot->native_mode());
  outputs.push_back(internal_snapshot.get());

  observer.GetStateForDisplayIds(outputs);
  observer.OnDisplayModeChanged(outputs);
  EXPECT_EQ(1u, display_manager()->GetNumDisplays());

  internal_snapshot->set_origin({0, 1000});

  std::unique_ptr<display::DisplaySnapshot> external_snapshot =
      display::FakeDisplaySnapshot::Builder()
          .SetId(external_id)
          .SetNativeMode(MakeDisplayMode())
          .AddMode(MakeDisplayMode())
          .Build();
  // "Connectd display" has the current mode.
  external_snapshot->set_current_mode(external_snapshot->native_mode());
  outputs.push_back(external_snapshot.get());

  reset();
  observer.GetStateForDisplayIds(outputs);
  observer.OnDisplayModeChanged(outputs);

  EXPECT_EQ(2u, display_manager()->GetNumDisplays());
  EXPECT_TRUE(changed_metrics() &
              display::DisplayObserver::DISPLAY_METRIC_BOUNDS);
}

// It's difficult to test with full stack due to crbug.com/771178.
// Improve the coverage once it is fixed.
TEST_F(DisplayManagerTest, ForcedMirrorMode) {
  // Disable restoring mirror mode to prevent interference from previous
  // display configuration.
  display_manager()->set_disable_restoring_mirror_mode_for_test(true);

  constexpr int64_t id1 = 1;
  constexpr int64_t id2 = 2;
  display::Screen* screen = display::Screen::GetScreen();
  DCHECK(screen);
  Shell* shell = Shell::Get();
  display::DisplayChangeObserver observer(shell->display_configurator(),
                                          display_manager());
  display::DisplayConfigurator::DisplayStateList outputs;
  std::unique_ptr<display::DisplaySnapshot> snapshot1 =
      display::FakeDisplaySnapshot::Builder()
          .SetId(id1)
          .SetNativeMode(MakeDisplayMode())
          .Build();
  std::unique_ptr<display::DisplaySnapshot> snapshot2 =
      display::FakeDisplaySnapshot::Builder()
          .SetId(id2)
          .SetNativeMode(MakeDisplayMode())
          .SetOrigin({0, 1000})
          .Build();
  snapshot1->set_current_mode(snapshot1->native_mode());
  snapshot2->set_current_mode(snapshot2->native_mode());

  outputs.push_back(snapshot1.get());
  outputs.push_back(snapshot2.get());

  EXPECT_EQ(display::MULTIPLE_DISPLAY_STATE_MULTI_EXTENDED,
            observer.GetStateForDisplayIds(outputs));

  display_manager()->layout_store()->set_forced_mirror_mode_for_tablet(true);

  observer.OnDisplayModeChanged(outputs);

  const display::DisplayIdList current_list =
      display_manager()->GetCurrentDisplayIdList();
  display_manager()->layout_store()->UpdateDefaultUnified(current_list,
                                                          false /* unified */);
  EXPECT_EQ(display::MULTIPLE_DISPLAY_STATE_DUAL_MIRROR,
            observer.GetStateForDisplayIds(outputs));

  display_manager()->layout_store()->set_forced_mirror_mode_for_tablet(false);

  EXPECT_EQ(display::MULTIPLE_DISPLAY_STATE_MULTI_EXTENDED,
            observer.GetStateForDisplayIds(outputs));

  display_manager()->set_disable_restoring_mirror_mode_for_test(false);
}

namespace {

class DisplayManagerOrientationTest : public DisplayManagerTest {
 public:
  DisplayManagerOrientationTest() = default;
  ~DisplayManagerOrientationTest() override = default;

  void SetUp() override {
    DisplayManagerTest::SetUp();
    const float kMeanGravity = 9.8066f;
    portrait_primary->Set(chromeos::ACCELEROMETER_SOURCE_SCREEN, -kMeanGravity,
                          0.f, 0.f);
    portrait_secondary->Set(chromeos::ACCELEROMETER_SOURCE_SCREEN, kMeanGravity,
                            0.f, 0.f);
    landscape_primary->Set(chromeos::ACCELEROMETER_SOURCE_SCREEN, 0,
                           -kMeanGravity, 0.f);
  }

 protected:
  scoped_refptr<chromeos::AccelerometerUpdate> portrait_primary =
      new chromeos::AccelerometerUpdate();
  scoped_refptr<chromeos::AccelerometerUpdate> portrait_secondary =
      new chromeos::AccelerometerUpdate();
  scoped_refptr<chromeos::AccelerometerUpdate> landscape_primary =
      new chromeos::AccelerometerUpdate();

 private:
  DISALLOW_COPY_AND_ASSIGN(DisplayManagerOrientationTest);
};

class TestObserver : public ScreenOrientationController::Observer {
 public:
  TestObserver() = default;
  ~TestObserver() override = default;

  void OnUserRotationLockChanged() override { count_++; }

  int countAndReset() {
    int tmp = count_;
    count_ = 0;
    return tmp;
  }

 private:
  int count_ = 0;
};

}  // namespace

TEST_F(DisplayManagerOrientationTest, SaveRestoreUserRotationLock) {
  Shell* shell = Shell::Get();
  display::DisplayManager* display_manager = shell->display_manager();
  display::test::DisplayManagerTestApi(display_manager)
      .SetFirstDisplayAsInternalDisplay();
  ScreenOrientationController* orientation_controller =
      shell->screen_orientation_controller();
  ScreenOrientationControllerTestApi test_api(orientation_controller);
  TestObserver test_observer;
  orientation_controller->AddObserver(&test_observer);

  // Set up windows with portrait,lanscape and any.
  aura::Window* window_a = CreateTestWindowInShellWithId(0);
  {
    window_a->SetProperty(aura::client::kAppType,
                          static_cast<int>(AppType::CHROME_APP));
    orientation_controller->LockOrientationForWindow(window_a,
                                                     OrientationLockType::kAny);
  }
  aura::Window* window_p = CreateTestWindowInShellWithId(0);
  {
    window_p->SetProperty(aura::client::kAppType,
                          static_cast<int>(AppType::CHROME_APP));
    orientation_controller->LockOrientationForWindow(
        window_p, OrientationLockType::kPortrait);
  }
  aura::Window* window_l = CreateTestWindowInShellWithId(0);
  {
    window_l->SetProperty(aura::client::kAppType,
                          static_cast<int>(AppType::CHROME_APP));
    orientation_controller->LockOrientationForWindow(
        window_l, OrientationLockType::kLandscape);
  }

  DisplayConfigurationController* configuration_controller =
      shell->display_configuration_controller();
  display::Screen* screen = display::Screen::GetScreen();

  // Rotate to portrait in clamshell.
  configuration_controller->SetDisplayRotation(
      screen->GetPrimaryDisplay().id(), display::Display::ROTATE_270,
      display::Display::RotationSource::USER);
  EXPECT_EQ(display::Display::ROTATE_270,
            screen->GetPrimaryDisplay().rotation());
  EXPECT_FALSE(display_manager->registered_internal_display_rotation_lock());

  EXPECT_EQ(0, test_observer.countAndReset());
  // Just enabling will not save the lock.
  Shell::Get()->tablet_mode_controller()->EnableTabletModeWindowManager(true);
  EXPECT_EQ(1, test_observer.countAndReset());

  EXPECT_EQ(display::Display::ROTATE_0, screen->GetPrimaryDisplay().rotation());
  EXPECT_FALSE(display_manager->registered_internal_display_rotation_lock());
  EXPECT_EQ(OrientationLockType::kLandscapePrimary,
            test_api.GetCurrentOrientation());

  // Enable lock at 0.
  orientation_controller->ToggleUserRotationLock();
  EXPECT_EQ(1, test_observer.countAndReset());

  EXPECT_TRUE(display_manager->registered_internal_display_rotation_lock());
  EXPECT_EQ(display::Display::ROTATE_0,
            display_manager->registered_internal_display_rotation());

  // Application can overwwrite the locked orientation.
  wm::ActivateWindow(window_p);
  EXPECT_EQ(display::Display::ROTATE_270,
            screen->GetPrimaryDisplay().rotation());
  EXPECT_EQ(display::Display::ROTATE_0,
            display_manager->registered_internal_display_rotation());
  EXPECT_EQ(0, test_observer.countAndReset());
  EXPECT_EQ(OrientationLockType::kPortraitPrimary,
            test_api.GetCurrentOrientation());

  // Any will rotate to the locked rotation.
  wm::ActivateWindow(window_a);
  EXPECT_EQ(display::Display::ROTATE_0, screen->GetPrimaryDisplay().rotation());
  EXPECT_TRUE(display_manager->registered_internal_display_rotation_lock());
  EXPECT_EQ(display::Display::ROTATE_0,
            display_manager->registered_internal_display_rotation());
  EXPECT_EQ(0, test_observer.countAndReset());

  wm::ActivateWindow(window_l);
  EXPECT_EQ(display::Display::ROTATE_0, screen->GetPrimaryDisplay().rotation());
  EXPECT_TRUE(display_manager->registered_internal_display_rotation_lock());
  EXPECT_EQ(display::Display::ROTATE_0,
            display_manager->registered_internal_display_rotation());
  EXPECT_EQ(0, test_observer.countAndReset());

  // Exit tablet mode reset to clamshell's rotation, which is 90.
  Shell::Get()->tablet_mode_controller()->EnableTabletModeWindowManager(false);
  EXPECT_EQ(1, test_observer.countAndReset());
  EXPECT_EQ(display::Display::ROTATE_270,
            screen->GetPrimaryDisplay().rotation());
  // Activate Any.
  wm::ActivateWindow(window_a);
  Shell::Get()->tablet_mode_controller()->EnableTabletModeWindowManager(true);
  EXPECT_EQ(1, test_observer.countAndReset());
  // Entering with active ANY will lock again to landscape.
  EXPECT_EQ(display::Display::ROTATE_0, screen->GetPrimaryDisplay().rotation());

  wm::ActivateWindow(window_p);
  EXPECT_EQ(display::Display::ROTATE_270,
            screen->GetPrimaryDisplay().rotation());
  EXPECT_EQ(0, test_observer.countAndReset());
  orientation_controller->ToggleUserRotationLock();
  orientation_controller->ToggleUserRotationLock();
  EXPECT_EQ(2, test_observer.countAndReset());

  EXPECT_TRUE(display_manager->registered_internal_display_rotation_lock());
  EXPECT_EQ(display::Display::ROTATE_270,
            display_manager->registered_internal_display_rotation());

  wm::ActivateWindow(window_l);
  EXPECT_EQ(display::Display::ROTATE_0, screen->GetPrimaryDisplay().rotation());
  EXPECT_EQ(display::Display::ROTATE_270,
            display_manager->registered_internal_display_rotation());

  // ANY will rotate to locked ortation.
  wm::ActivateWindow(window_a);
  EXPECT_EQ(display::Display::ROTATE_270,
            screen->GetPrimaryDisplay().rotation());

  orientation_controller->RemoveObserver(&test_observer);
}

TEST_F(DisplayManagerOrientationTest, UserRotationLockReverse) {
  Shell* shell = Shell::Get();
  display::DisplayManager* display_manager = shell->display_manager();
  display::test::DisplayManagerTestApi test_api(display_manager);
  test_api.SetFirstDisplayAsInternalDisplay();
  ScreenOrientationController* orientation_controller =
      shell->screen_orientation_controller();

  // Set up windows with portrait,lanscape and any.
  aura::Window* window = CreateTestWindowInShellWithId(0);
  window->SetProperty(aura::client::kAppType,
                      static_cast<int>(AppType::CHROME_APP));
  display::Screen* screen = display::Screen::GetScreen();

  // Just enabling will not save the lock.
  Shell::Get()->tablet_mode_controller()->EnableTabletModeWindowManager(true);

  orientation_controller->LockOrientationForWindow(
      window, OrientationLockType::kPortrait);
  EXPECT_EQ(display::Display::ROTATE_270,
            screen->GetPrimaryDisplay().rotation());

  orientation_controller->OnAccelerometerUpdated(portrait_secondary);

  EXPECT_EQ(display::Display::ROTATE_90,
            screen->GetPrimaryDisplay().rotation());

  orientation_controller->OnAccelerometerUpdated(portrait_primary);
  EXPECT_EQ(display::Display::ROTATE_270,
            screen->GetPrimaryDisplay().rotation());

  // Enable lock at 270.
  orientation_controller->ToggleUserRotationLock();
  EXPECT_TRUE(display_manager->registered_internal_display_rotation_lock());
  EXPECT_EQ(display::Display::ROTATE_270,
            display_manager->registered_internal_display_rotation());

  orientation_controller->OnAccelerometerUpdated(portrait_secondary);

  EXPECT_EQ(display::Display::ROTATE_270,
            screen->GetPrimaryDisplay().rotation());
}

TEST_F(DisplayManagerOrientationTest, LockToSpecificOrientation) {
  Shell* shell = Shell::Get();
  display::DisplayManager* display_manager = shell->display_manager();
  display::test::DisplayManagerTestApi(display_manager)
      .SetFirstDisplayAsInternalDisplay();
  ScreenOrientationController* orientation_controller =
      shell->screen_orientation_controller();
  ScreenOrientationControllerTestApi test_api(orientation_controller);

  aura::Window* window_a = CreateTestWindowInShellWithId(0);
  {
    window_a->SetProperty(aura::client::kAppType,
                          static_cast<int>(AppType::CHROME_APP));
    orientation_controller->LockOrientationForWindow(window_a,
                                                     OrientationLockType::kAny);
  }
  wm::ActivateWindow(window_a);
  Shell::Get()->tablet_mode_controller()->EnableTabletModeWindowManager(true);

  orientation_controller->OnAccelerometerUpdated(portrait_primary);

  EXPECT_EQ(OrientationLockType::kPortraitPrimary,
            test_api.GetCurrentOrientation());

  orientation_controller->OnAccelerometerUpdated(portrait_secondary);

  aura::Window* window_lsc = CreateTestWindowInShellWithId(1);
  window_lsc->SetProperty(aura::client::kAppType,
                          static_cast<int>(AppType::CHROME_APP));

  aura::Window* window_psc = CreateTestWindowInShellWithId(1);
  window_psc->SetProperty(aura::client::kAppType,
                          static_cast<int>(AppType::CHROME_APP));

  orientation_controller->LockOrientationForWindow(
      window_psc, OrientationLockType::kPortraitSecondary);
  orientation_controller->LockOrientationForWindow(
      window_psc, OrientationLockType::kCurrent);
  wm::ActivateWindow(window_psc);

  orientation_controller->LockOrientationForWindow(
      window_lsc, OrientationLockType::kLandscapeSecondary);
  orientation_controller->LockOrientationForWindow(
      window_lsc, OrientationLockType::kCurrent);

  EXPECT_EQ(OrientationLockType::kPortraitSecondary,
            test_api.GetCurrentOrientation());

  // The orientation should stay portrait secondary.
  orientation_controller->OnAccelerometerUpdated(portrait_primary);
  EXPECT_EQ(OrientationLockType::kPortraitSecondary,
            test_api.GetCurrentOrientation());
  wm::ActivateWindow(window_lsc);

  EXPECT_EQ(OrientationLockType::kLandscapeSecondary,
            test_api.GetCurrentOrientation());

  // The orientation should stay landscape secondary.
  orientation_controller->OnAccelerometerUpdated(landscape_primary);
  EXPECT_EQ(OrientationLockType::kLandscapeSecondary,
            test_api.GetCurrentOrientation());

  wm::ActivateWindow(window_a);
  orientation_controller->OnAccelerometerUpdated(portrait_primary);

  // Swtching to |window_a| enables rotation.
  EXPECT_EQ(OrientationLockType::kPortraitPrimary,
            test_api.GetCurrentOrientation());

  // The orientation has alraedy been locked to secondary once, so
  // it should swtich back to the portrait secondary.
  wm::ActivateWindow(window_psc);
  EXPECT_EQ(OrientationLockType::kPortraitSecondary,
            test_api.GetCurrentOrientation());
}

// crbug.com/734107
TEST_F(DisplayManagerOrientationTest, DisplayChangeShouldNotSaveUserRotation) {
  Shell* shell = Shell::Get();
  display::DisplayManager* display_manager = shell->display_manager();
  display::test::DisplayManagerTestApi test_api(display_manager);
  test_api.SetFirstDisplayAsInternalDisplay();
  display::Screen* screen = display::Screen::GetScreen();

  Shell::Get()->tablet_mode_controller()->EnableTabletModeWindowManager(true);
  // Emulate that Animator is calling this async when animation is completed.
  display_manager->SetDisplayRotation(
      screen->GetPrimaryDisplay().id(), display::Display::ROTATE_90,
      display::Display::RotationSource::ACCELEROMETER);
  EXPECT_EQ(display::Display::ROTATE_90,
            screen->GetPrimaryDisplay().rotation());

  Shell::Get()->tablet_mode_controller()->EnableTabletModeWindowManager(false);
  EXPECT_EQ(display::Display::ROTATE_0, screen->GetPrimaryDisplay().rotation());
}

TEST_F(DisplayManagerTest, HardwareMirrorMode) {
  // Create three displays with the same origin in frame buffer.
  const int64_t internal_display_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  constexpr int64_t first_mirror_id = 11;
  constexpr int64_t second_mirror_id = 12;
  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(display::CreateDisplayInfo(
      internal_display_id, gfx::Rect(0, 0, 500, 500)));
  display_info_list.push_back(
      display::CreateDisplayInfo(first_mirror_id, gfx::Rect(0, 0, 500, 500)));
  display_info_list.push_back(
      display::CreateDisplayInfo(second_mirror_id, gfx::Rect(0, 0, 500, 500)));

  // mirrored across 3 displays...
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  RunAllPendingInMessageLoop();

  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ(3U, display_manager()->num_connected_displays());

  EXPECT_EQ(internal_display_id, display_manager()->mirroring_source_id());
  EXPECT_EQ(gfx::Rect(0, 0, 500, 500),
            GetDisplayForId(internal_display_id).bounds());

  const display::DisplayIdList id_list =
      display_manager()->GetMirroringDestinationDisplayIdList();
  ASSERT_EQ(2U, id_list.size());
  EXPECT_EQ(11U, id_list[0]);
  EXPECT_EQ(12U, id_list[1]);

  EXPECT_FALSE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_TRUE(display_manager()->IsInHardwareMirrorMode());
}

TEST_F(DisplayManagerTest, SoftwareMirrorModeBasics) {
  UpdateDisplay("300x400,400x500,500x600");

  // There's not mirror window by default.
  MirrorWindowTestApi test_api;
  EXPECT_TRUE(test_api.GetHosts().empty());

  TestDisplayObserver display_observer;
  display::Screen::GetScreen()->AddObserver(&display_observer);

  // Turn on mirror mode.
  SetSoftwareMirrorMode(true);
  EXPECT_TRUE(display_observer.changed_and_reset());
  EXPECT_EQ(1U, display_manager()->GetNumDisplays());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 400),
            display::Screen::GetScreen()->GetPrimaryDisplay().bounds());

  std::vector<aura::WindowTreeHost*> host_list = test_api.GetHosts();
  ASSERT_EQ(2U, host_list.size());
  EXPECT_EQ(gfx::Size(400, 500), host_list[0]->GetBoundsInPixels().size());
  EXPECT_EQ(gfx::Size(300, 400), host_list[0]->window()->bounds().size());
  EXPECT_EQ(gfx::Size(500, 600), host_list[1]->GetBoundsInPixels().size());
  EXPECT_EQ(gfx::Size(300, 400), host_list[1]->window()->bounds().size());

  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_FALSE(display_manager()->IsInHardwareMirrorMode());

  // Turn off mirror mode.
  SetSoftwareMirrorMode(false);
  EXPECT_TRUE(display_observer.changed_and_reset());
  EXPECT_EQ(3U, display_manager()->GetNumDisplays());

  host_list = test_api.GetHosts();
  EXPECT_TRUE(host_list.empty());

  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  // Make sure the mirror window has the pixel size of the
  // source display.
  SetSoftwareMirrorMode(true);
  EXPECT_TRUE(display_observer.changed_and_reset());

  UpdateDisplay("300x400@0.5,400x500,500x600");
  EXPECT_FALSE(display_observer.changed_and_reset());
  host_list = test_api.GetHosts();
  EXPECT_EQ(gfx::Size(300, 400), host_list[0]->window()->bounds().size());
  EXPECT_EQ(gfx::Size(300, 400), host_list[1]->window()->bounds().size());

  UpdateDisplay("310x410*2,400x500,500x600");
  EXPECT_FALSE(display_observer.changed_and_reset());
  host_list = test_api.GetHosts();
  EXPECT_EQ(gfx::Size(310, 410), host_list[0]->window()->bounds().size());
  EXPECT_EQ(gfx::Size(310, 410), host_list[1]->window()->bounds().size());

  UpdateDisplay("320x420/r,400x500,500x600");
  EXPECT_FALSE(display_observer.changed_and_reset());
  host_list = test_api.GetHosts();
  EXPECT_EQ(gfx::Size(320, 420), host_list[0]->window()->bounds().size());
  EXPECT_EQ(gfx::Size(320, 420), host_list[1]->window()->bounds().size());

  UpdateDisplay("330x440/r,400x500,500x600");
  EXPECT_FALSE(display_observer.changed_and_reset());
  host_list = test_api.GetHosts();
  EXPECT_EQ(gfx::Size(330, 440), host_list[0]->window()->bounds().size());
  EXPECT_EQ(gfx::Size(330, 440), host_list[1]->window()->bounds().size());

  // Overscan insets are ignored.
  UpdateDisplay("400x600/o,600x800/o,500x600/o");
  EXPECT_FALSE(display_observer.changed_and_reset());
  host_list = test_api.GetHosts();
  EXPECT_EQ(gfx::Size(400, 600), host_list[0]->window()->bounds().size());
  EXPECT_EQ(gfx::Size(400, 600), host_list[1]->window()->bounds().size());

  display::Screen::GetScreen()->RemoveObserver(&display_observer);
}

TEST_F(DisplayManagerTest, SwitchToAndFromSoftwareMirrorMode) {
  // Don't check root window destruction in unified mode.
  Shell::GetPrimaryRootWindow()->RemoveObserver(this);

  UpdateDisplay("300x400,400x500,500x600");

  // Switch from extended to mirroring.
  SetSoftwareMirrorMode(true);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_FALSE(display_manager()->IsInUnifiedMode());

  // Switch from mirroring to extended.
  SetSoftwareMirrorMode(false);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_FALSE(display_manager()->IsInUnifiedMode());

  // Switch from mirroring to unified, but it fails.
  SetSoftwareMirrorMode(true);
  display_manager()->SetUnifiedDesktopEnabled(true);
  RunAllPendingInMessageLoop();
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_FALSE(display_manager()->IsInUnifiedMode());

  // Turn off mirroring, it switches to unified.
  SetSoftwareMirrorMode(false);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_TRUE(display_manager()->IsInUnifiedMode());

  // Switch from unified to mirroring.
  SetSoftwareMirrorMode(true);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_FALSE(display_manager()->IsInUnifiedMode());
}

TEST_F(DisplayManagerTest, SourceAndDestinationInSoftwareMirrorMode) {
  constexpr int64_t first_display_id = 10;
  constexpr int64_t second_display_id = 11;
  constexpr int64_t third_display_id = 12;
  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.emplace_back(
      display::CreateDisplayInfo(first_display_id, gfx::Rect(0, 0, 100, 100)));
  display_info_list.emplace_back(
      display::CreateDisplayInfo(second_display_id, gfx::Rect(1, 1, 500, 500)));
  display_info_list.emplace_back(
      display::CreateDisplayInfo(third_display_id, gfx::Rect(2, 2, 500, 500)));

  // Connect all displays.
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  RunAllPendingInMessageLoop();
  EXPECT_EQ(display::kInvalidDisplayId,
            display_manager()->mirroring_source_id());
  EXPECT_TRUE(
      display_manager()->GetMirroringDestinationDisplayIdList().empty());

  // Activate software mirror mode.
  SetSoftwareMirrorMode(true);
  EXPECT_EQ(first_display_id, display_manager()->mirroring_source_id());
  display::DisplayIdList id_list =
      display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(2U, id_list.size());
  EXPECT_EQ(second_display_id, id_list[0]);
  EXPECT_EQ(third_display_id, id_list[1]);

  // Set the second display as internal display.
  SetSoftwareMirrorMode(false);

  display::test::ScopedSetInternalDisplayId set_internal(display_manager(),
                                                         second_display_id);
  SetSoftwareMirrorMode(true);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(second_display_id, display_manager()->mirroring_source_id());
  id_list = display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(2U, id_list.size());
  EXPECT_EQ(first_display_id, id_list[0]);
  EXPECT_EQ(third_display_id, id_list[1]);
}

TEST_F(DisplayManagerTest, CompositingCursorInMultiSoftwareMirroring) {
  const int64_t internal_display_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  constexpr int64_t first_mirror_id = 11;
  constexpr int64_t second_mirror_id = 12;
  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.push_back(display::CreateDisplayInfo(
      internal_display_id, gfx::Rect(0, 0, 100, 100)));
  display_info_list.push_back(
      display::CreateDisplayInfo(first_mirror_id, gfx::Rect(1, 1, 500, 500)));
  display_info_list.push_back(
      display::CreateDisplayInfo(second_mirror_id, gfx::Rect(2, 2, 500, 500)));

  // Connect all displays, cursor compositing is disabled by default.
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  RunAllPendingInMessageLoop();
  CursorWindowController* cursor_window_controller =
      Shell::Get()->window_tree_host_manager()->cursor_window_controller();
  EXPECT_FALSE(cursor_window_controller->is_cursor_compositing_enabled());
  MirrorWindowTestApi test_api;
  EXPECT_EQ(nullptr, test_api.GetCursorWindow());

  // Turn on mirror mode, cursor compositing is enabled and cursor window is
  // composited in internal display's root window.
  SetSoftwareMirrorMode(true);
  EXPECT_TRUE(cursor_window_controller->is_cursor_compositing_enabled());
  EXPECT_TRUE(Shell::GetRootWindowForDisplayId(internal_display_id)
                  ->Contains(test_api.GetCursorWindow()));

  // Turn off mirror mode, cursor compositing is disabled and cursor window does
  // not exist.
  SetSoftwareMirrorMode(false);
  EXPECT_FALSE(cursor_window_controller->is_cursor_compositing_enabled());
  EXPECT_EQ(nullptr, test_api.GetCursorWindow());
}

TEST_F(DisplayManagerTest, MirrorModeRestore) {
  const int64_t internal_display_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  constexpr int64_t first_display_id = 210000001;
  constexpr int64_t second_display_id = 220000002;
  const int64_t first_display_masked_id =
      display::GetDisplayIdWithoutOutputIndex(first_display_id);
  const int64_t second_display_masked_id =
      display::GetDisplayIdWithoutOutputIndex(second_display_id);
  display::ManagedDisplayInfo first_mirror_info =
      display::CreateDisplayInfo(first_display_id, gfx::Rect(1, 1, 500, 500));
  display::ManagedDisplayInfo second_mirror_info =
      display::CreateDisplayInfo(second_display_id, gfx::Rect(2, 2, 500, 500));
  std::vector<display::ManagedDisplayInfo> display_info_list;

  // There's no external display now.
  display_info_list.push_back(display::CreateDisplayInfo(
      internal_display_id, gfx::Rect(0, 0, 100, 100)));
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().empty());

  // Connect the first external display.
  display_info_list.push_back(first_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().empty());

  // Turn on mirror mode.
  SetSoftwareMirrorMode(true);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(1U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));

  // Remove the first external display.
  display_info_list.erase(display_info_list.end() - 1);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(1U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));

  // Reconnect the first external display.
  display_info_list.push_back(first_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(1U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));

  // Remove the first external display.
  display_info_list.erase(display_info_list.end() - 1);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(1U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));

  // Connect the second external display.
  display_info_list.push_back(second_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(1U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));

  // Remove the second external display.
  display_info_list.erase(display_info_list.end() - 1);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(1U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));

  // Add the first and then add the second external display (not mirrored
  // before).
  display_info_list.push_back(first_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  display_info_list.push_back(second_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(2U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      second_display_masked_id));

  // Remove the second display.
  display_info_list.erase(display_info_list.end() - 1);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(2U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      second_display_masked_id));

  // Remove the first display and then add the second display.
  display_info_list.erase(display_info_list.end() - 1);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  display_info_list.push_back(second_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(2U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      second_display_masked_id));

  // Turn off mirror mode.
  SetSoftwareMirrorMode(false);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(1U, display_manager()->external_display_mirror_info().size());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().count(
      first_display_masked_id));

  // Add the first display (mirrored before).
  display_info_list.push_back(first_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_TRUE(display_manager()->external_display_mirror_info().empty());
}

TEST_F(DisplayManagerTest, MixedMirrorModeBasics) {
  UpdateDisplay("300x400,400x500,500x600");
  display::DisplayIdList id_list = display_manager()->GetCurrentDisplayIdList();

  // Turn on mixed mirror mode. (Mirror from the first display to the second
  // display)
  display::DisplayIdList dst_ids;
  dst_ids.emplace_back(id_list[1]);
  base::Optional<display::MixedMirrorModeParams> mixed_params(
      base::in_place, id_list[0], dst_ids);
  display_manager()->SetMirrorMode(display::MirrorMode::kMixed, mixed_params);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(id_list[0], display_manager()->mirroring_source_id());
  display::DisplayIdList destination_ids =
      display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(1U, destination_ids.size());
  EXPECT_EQ(id_list[1], destination_ids[0]);
  EXPECT_TRUE(display_manager()->mixed_mirror_mode_params());

  // Turn off mirror mode.
  display_manager()->SetMirrorMode(display::MirrorMode::kOff, base::nullopt);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());
  EXPECT_FALSE(display_manager()->mixed_mirror_mode_params());
}

TEST_F(DisplayManagerTest, MixedMirrorModeToMirrorMode) {
  UpdateDisplay("300x400,400x500,500x600");
  display::DisplayIdList id_list = display_manager()->GetCurrentDisplayIdList();

  // Turn on mixed mirror mode. (Mirror from the first display to the second
  // display)
  display::DisplayIdList dst_ids;
  dst_ids.emplace_back(id_list[1]);
  base::Optional<display::MixedMirrorModeParams> mixed_params(
      base::in_place, id_list[0], dst_ids);
  display_manager()->SetMirrorMode(display::MirrorMode::kMixed, mixed_params);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(id_list[0], display_manager()->mirroring_source_id());
  display::DisplayIdList destination_ids =
      display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(1U, destination_ids.size());
  EXPECT_EQ(id_list[1], destination_ids[0]);
  EXPECT_TRUE(display_manager()->mixed_mirror_mode_params());

  // Overwrite mixed mirror mode with default mirror mode (Mirror all
  // displays).
  display_manager()->SetMirrorMode(display::MirrorMode::kNormal, base::nullopt);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(id_list[0], display_manager()->mirroring_source_id());
  destination_ids = display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(2U, destination_ids.size());
  EXPECT_EQ(id_list[1], destination_ids[0]);
  EXPECT_EQ(id_list[2], destination_ids[1]);
  EXPECT_FALSE(display_manager()->mixed_mirror_mode_params());
}

TEST_F(DisplayManagerTest, MirrorModeToMixedMirrorMode) {
  UpdateDisplay("300x400,400x500,500x600");
  display::DisplayIdList id_list = display_manager()->GetCurrentDisplayIdList();

  // Turn on mirror mode.
  display_manager()->SetMirrorMode(display::MirrorMode::kNormal, base::nullopt);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());
  EXPECT_EQ(id_list[0], display_manager()->mirroring_source_id());
  display::DisplayIdList destination_ids =
      display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(2U, destination_ids.size());
  EXPECT_EQ(id_list[1], destination_ids[0]);
  EXPECT_EQ(id_list[2], destination_ids[1]);
  EXPECT_FALSE(display_manager()->mixed_mirror_mode_params());

  // Overwrite default mirror mode with mixed mirror mode. (Mirror from the
  // first display to the second display)
  display::DisplayIdList dst_ids;
  dst_ids.emplace_back(id_list[1]);
  base::Optional<display::MixedMirrorModeParams> mixed_params(
      base::in_place, id_list[0], dst_ids);
  display_manager()->SetMirrorMode(display::MirrorMode::kMixed, mixed_params);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(id_list[0], display_manager()->mirroring_source_id());
  destination_ids = display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(1U, destination_ids.size());
  EXPECT_EQ(id_list[1], destination_ids[0]);
  EXPECT_TRUE(display_manager()->mixed_mirror_mode_params());
}

TEST_F(DisplayManagerTest, MixedMirrorModeRestore) {
  const int64_t internal_display_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  constexpr int64_t first_display_id = 210000001;
  constexpr int64_t second_display_id = 220000002;
  display::ManagedDisplayInfo first_mirror_info =
      display::CreateDisplayInfo(first_display_id, gfx::Rect(1, 1, 500, 500));
  display::ManagedDisplayInfo second_mirror_info =
      display::CreateDisplayInfo(second_display_id, gfx::Rect(2, 2, 500, 500));
  std::vector<display::ManagedDisplayInfo> display_info_list;

  // Connect the first and second displays.
  display_info_list.push_back(display::CreateDisplayInfo(
      internal_display_id, gfx::Rect(0, 0, 100, 100)));
  display_info_list.push_back(first_mirror_info);
  display_info_list.push_back(second_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);

  // Turn on mixed mirror mode. (Mirror from the internal display to the
  // first display)
  display::DisplayIdList dst_ids;
  dst_ids.emplace_back(first_display_id);
  base::Optional<display::MixedMirrorModeParams> mixed_params(
      base::in_place, internal_display_id, dst_ids);
  display_manager()->SetMirrorMode(display::MirrorMode::kMixed, mixed_params);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(internal_display_id, display_manager()->mirroring_source_id());
  display::DisplayIdList destination_ids =
      display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(1U, destination_ids.size());
  EXPECT_EQ(first_display_id, destination_ids[0]);

  // Remove the second display. Mirroring is not changed.
  display_info_list.erase(display_info_list.end() - 1);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(internal_display_id, display_manager()->mirroring_source_id());
  destination_ids = display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(1U, destination_ids.size());
  EXPECT_EQ(first_display_id, destination_ids[0]);

  // Add the second display. Mirroring is not changed.
  display_info_list.push_back(second_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(internal_display_id, display_manager()->mirroring_source_id());
  destination_ids = display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(1U, destination_ids.size());
  EXPECT_EQ(first_display_id, destination_ids[0]);

  // Remove the first display. Mirroring ends.
  display_info_list.erase(display_info_list.end() - 2);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_FALSE(display_manager()->IsInMirrorMode());

  // Add the first display. Mirroring is restored.
  display_info_list.push_back(first_mirror_info);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(internal_display_id, display_manager()->mirroring_source_id());
  destination_ids = display_manager()->GetMirroringDestinationDisplayIdList();
  EXPECT_EQ(1U, destination_ids.size());
  EXPECT_EQ(first_display_id, destination_ids[0]);
}

TEST_F(DisplayManagerTest, MirrorModeRestoreAfterResume) {
  const int64_t internal_display_id =
      display::test::DisplayManagerTestApi(display_manager())
          .SetFirstDisplayAsInternalDisplay();
  constexpr int64_t external_display_id = 210000001;
  std::vector<display::ManagedDisplayInfo> display_info_list;
  display_info_list.emplace_back(display::CreateDisplayInfo(
      internal_display_id, gfx::Rect(0, 0, 100, 100)));
  display_info_list.emplace_back(display::CreateDisplayInfo(
      external_display_id, gfx::Rect(1, 1, 500, 500)));

  // Turn on mirror mode.
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  display_manager()->SetMirrorMode(display::MirrorMode::kNormal, base::nullopt);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());

  // Suspend.
  display_manager()->SetMultiDisplayMode(display::DisplayManager::MIRRORING);
  display_manager()->OnNativeDisplaysChanged(
      std::vector<display::ManagedDisplayInfo>());
  EXPECT_TRUE(display_manager()->IsInMirrorMode());

  // Resume.
  display_manager()->SetMultiDisplayMode(display::DisplayManager::MIRRORING);
  display_manager()->OnNativeDisplaysChanged(display_info_list);
  EXPECT_TRUE(display_manager()->IsInMirrorMode());
}

TEST_F(DisplayManagerTest, SoftwareMirrorRotationForTablet) {
  UpdateDisplay("400x300,800x800");
  RunAllPendingInMessageLoop();

  // Set the first display as internal display so that the tablet mode can be
  // enabled.
  display::test::DisplayManagerTestApi(display_manager())
      .SetFirstDisplayAsInternalDisplay();

  // Simulate turning on mirror mode triggered by tablet mode on.
  Shell::Get()->tablet_mode_controller()->EnableTabletModeWindowManager(true);
  RunAllPendingInMessageLoop();
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(gfx::Rect(0, 0, 400, 300),
            display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  MirrorWindowTestApi test_api;
  std::vector<aura::WindowTreeHost*> host_list = test_api.GetHosts();
  ASSERT_EQ(1U, host_list.size());
  EXPECT_EQ(gfx::Size(800, 800), host_list[0]->GetBoundsInPixels().size());
  EXPECT_EQ(gfx::Size(400, 300), host_list[0]->window()->bounds().size());

  // Test the target display's bounds after the transforms are applied.
  gfx::RectF transformed_rect1(
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  Shell::Get()->GetPrimaryRootWindow()->transform().TransformRect(
      &transformed_rect1);
  host_list[0]->window()->transform().TransformRect(&transformed_rect1);
  EXPECT_EQ(gfx::RectF(0.0f, 100.0f, 800.0f, 600.0f), transformed_rect1);

  // Rotate the source display by 90 degrees.
  UpdateDisplay("400x300/r,800x800");
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 400),
            display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  host_list = test_api.GetHosts();
  ASSERT_EQ(1U, host_list.size());
  EXPECT_EQ(gfx::Size(800, 800), host_list[0]->GetBoundsInPixels().size());
  EXPECT_EQ(gfx::Size(300, 400), host_list[0]->window()->bounds().size());

  // Test the target display's bounds after the transforms are applied.
  gfx::RectF transformed_rect2(
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  Shell::Get()->GetPrimaryRootWindow()->transform().TransformRect(
      &transformed_rect2);
  host_list[0]->window()->transform().TransformRect(&transformed_rect2);
  EXPECT_EQ(gfx::RectF(100.0f, 0.0f, 600.0f, 800.0f), transformed_rect2);

  // Change the bounds of the source display and rotate the source display by 90
  // degrees.
  UpdateDisplay("300x400/r,800x800");
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(gfx::Rect(0, 0, 400, 300),
            display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  host_list = test_api.GetHosts();
  ASSERT_EQ(1U, host_list.size());
  EXPECT_EQ(gfx::Size(800, 800), host_list[0]->GetBoundsInPixels().size());
  EXPECT_EQ(gfx::Size(400, 300), host_list[0]->window()->bounds().size());

  // Test the target display's bounds after the transforms are applied.
  gfx::RectF transformed_rect3(
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  Shell::Get()->GetPrimaryRootWindow()->transform().TransformRect(
      &transformed_rect3);
  host_list[0]->window()->transform().TransformRect(&transformed_rect3);
  EXPECT_EQ(gfx::RectF(0.0f, 100.0f, 800.0f, 600.0f), transformed_rect3);
}

TEST_F(DisplayManagerTest, SoftwareMirrorRotationForNonTablet) {
  MirrorWindowTestApi test_api;
  UpdateDisplay("400x300,800x800");

  // Simulate turning on mirror mode not triggered by tablet mode.
  SetSoftwareMirrorMode(true);
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(gfx::Rect(0, 0, 400, 300),
            display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  std::vector<aura::WindowTreeHost*> host_list = test_api.GetHosts();
  ASSERT_EQ(1U, host_list.size());
  EXPECT_EQ(gfx::Size(800, 800), host_list[0]->GetBoundsInPixels().size());
  EXPECT_EQ(gfx::Size(400, 300), host_list[0]->window()->bounds().size());

  // Test the target display's bounds after the transforms are applied.
  gfx::RectF transformed_rect1(
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  Shell::Get()->GetPrimaryRootWindow()->transform().TransformRect(
      &transformed_rect1);
  host_list[0]->window()->transform().TransformRect(&transformed_rect1);
  EXPECT_EQ(gfx::RectF(0.0f, 100.0f, 800.0f, 600.0f), transformed_rect1);

  // Rotate the source display by 90 degrees.
  UpdateDisplay("400x300/r,800x800");
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(gfx::Rect(0, 0, 300, 400),
            display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  host_list = test_api.GetHosts();
  ASSERT_EQ(1U, host_list.size());
  EXPECT_EQ(gfx::Size(800, 800), host_list[0]->GetBoundsInPixels().size());
  EXPECT_EQ(gfx::Size(400, 300), host_list[0]->window()->bounds().size());

  // Test the target display's bounds after the transforms are applied.
  gfx::RectF transformed_rect2(
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  Shell::Get()->GetPrimaryRootWindow()->transform().TransformRect(
      &transformed_rect2);
  host_list[0]->window()->transform().TransformRect(&transformed_rect2);
  EXPECT_EQ(gfx::RectF(0.0f, 100.0f, 800.0f, 600.0f), transformed_rect2);

  // Change the bounds of the source display and rotate the source display by 90
  // degrees.
  UpdateDisplay("300x400/r,800x800");
  EXPECT_TRUE(display_manager()->IsInSoftwareMirrorMode());
  EXPECT_EQ(gfx::Rect(0, 0, 400, 300),
            display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  host_list = test_api.GetHosts();
  ASSERT_EQ(1U, host_list.size());
  EXPECT_EQ(gfx::Size(800, 800), host_list[0]->GetBoundsInPixels().size());
  EXPECT_EQ(gfx::Size(300, 400), host_list[0]->window()->bounds().size());

  // Test the target display's bounds after the transforms are applied.
  gfx::RectF transformed_rect3(
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds());
  Shell::Get()->GetPrimaryRootWindow()->transform().TransformRect(
      &transformed_rect3);
  host_list[0]->window()->transform().TransformRect(&transformed_rect3);
  EXPECT_EQ(gfx::RectF(100.0f, 0.0f, 600.0f, 800.0f), transformed_rect3);
}

}  // namespace ash

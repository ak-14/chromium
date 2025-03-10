// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/components/shortcut_viewer/views/keyboard_shortcut_view.h"

#include <set>

#include "ash/components/shortcut_viewer/keyboard_shortcut_viewer_metadata.h"
#include "ash/components/shortcut_viewer/views/keyboard_shortcut_item_view.h"
#include "ash/components/shortcut_viewer/views/ksv_search_box_view.h"
#include "ash/test/ash_test_base.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/aura/window.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/events/test/event_generator.h"
#include "ui/views/controls/textfield/textfield.h"
#include "ui/views/widget/widget.h"

namespace keyboard_shortcut_viewer {

class KeyboardShortcutViewTest : public ash::AshTestBase {
 public:
  KeyboardShortcutViewTest() = default;
  ~KeyboardShortcutViewTest() override = default;

 protected:
  int GetTabCount() const {
    DCHECK(GetView());
    return GetView()->GetTabCountForTesting();
  }

  const std::vector<std::unique_ptr<KeyboardShortcutItemView>>&
  GetShortcutViews() {
    DCHECK(GetView());
    return GetView()->GetShortcutViewsForTesting();
  }

  KSVSearchBoxView* GetSearchBoxView() {
    DCHECK(GetView());
    return GetView()->GetSearchBoxViewForTesting();
  }

  void KeyPress(ui::KeyboardCode key_code, bool should_insert) {
    ui::KeyEvent event(ui::ET_KEY_PRESSED, key_code, ui::EF_NONE);
    GetSearchBoxView()->OnKeyEvent(&event);
    if (!should_insert)
      return;

    // Emulates the input method.
    if (::isalnum(static_cast<int>(key_code))) {
      base::char16 character = ::tolower(static_cast<int>(key_code));
      GetSearchBoxView()->search_box()->InsertText(
          base::string16(1, character));
    }
  }

 private:
  KeyboardShortcutView* GetView() const {
    return KeyboardShortcutView::GetInstanceForTesting();
  }

  DISALLOW_COPY_AND_ASSIGN(KeyboardShortcutViewTest);
};

// Shows and closes the widget for KeyboardShortcutViewer.
TEST_F(KeyboardShortcutViewTest, ShowAndClose) {
  // Showing the widget.
  views::Widget* widget = KeyboardShortcutView::Show(CurrentContext());
  EXPECT_TRUE(widget);

  // Cleaning up.
  widget->CloseNow();
}

// KeyboardShortcutViewer window should be centered in screen.
TEST_F(KeyboardShortcutViewTest, CenterWindowInScreen) {
  // Showing the widget.
  views::Widget* widget = KeyboardShortcutView::Show(CurrentContext());
  EXPECT_TRUE(widget);

  gfx::Rect root_window_bounds =
      display::Screen::GetScreen()
          ->GetDisplayNearestWindow(widget->GetNativeWindow()->GetRootWindow())
          .work_area();
  gfx::Rect shortcuts_window_bounds =
      widget->GetNativeWindow()->GetBoundsInScreen();
  EXPECT_EQ(root_window_bounds.CenterPoint().x(),
            shortcuts_window_bounds.CenterPoint().x());
  EXPECT_EQ(root_window_bounds.CenterPoint().y(),
            shortcuts_window_bounds.CenterPoint().y());

  // Cleaning up.
  widget->CloseNow();
}

// Test that the number of side tabs equals to the number of categories.
TEST_F(KeyboardShortcutViewTest, SideTabsCount) {
  // Showing the widget.
  views::Widget* widget = KeyboardShortcutView::Show(CurrentContext());

  int category_number = 0;
  ShortcutCategory current_category = ShortcutCategory::kUnknown;
  for (const auto& item_view : GetShortcutViews()) {
    const ShortcutCategory category = item_view->category();
    if (current_category != category) {
      DCHECK(current_category < category);
      ++category_number;
      current_category = category;
    }
  }
  EXPECT_EQ(GetTabCount(), category_number);

  // Cleaning up.
  widget->CloseNow();
}

// Test that the top line in two views should be center aligned.
TEST_F(KeyboardShortcutViewTest, TopLineCenterAlignedInItemView) {
  // Showing the widget.
  views::Widget* widget = KeyboardShortcutView::Show(CurrentContext());

  for (const auto& item_view : GetShortcutViews()) {
    DCHECK(item_view->child_count() == 2);

    // The top lines in both |description_label_view_| and
    // |shortcut_label_view_| should be center aligned. Only need to check one
    // view in the top line, because StyledLabel always center align all the
    // views in a line.
    const views::View* description_view = item_view->child_at(0);
    const views::View* shortcut_view = item_view->child_at(1);
    const views::View* description_top_line_view =
        description_view->child_at(0);
    const views::View* shortcut_top_line_view = shortcut_view->child_at(0);
    EXPECT_EQ(description_top_line_view->GetBoundsInScreen().CenterPoint().y(),
              shortcut_top_line_view->GetBoundsInScreen().CenterPoint().y());
  }

  // Cleaning up.
  widget->CloseNow();
}

// Test that the focus is on search box when window inits and exits search mode.
TEST_F(KeyboardShortcutViewTest, FocusOnSearchBox) {
  // Showing the widget.
  views::Widget* widget = KeyboardShortcutView::Show(CurrentContext());

  // Case 1: when window creates. The focus should be on search box.
  EXPECT_TRUE(GetSearchBoxView()->search_box()->HasFocus());

  // Press a key should enter search mode.
  KeyPress(ui::VKEY_A, /*should_insert=*/true);
  EXPECT_TRUE(GetSearchBoxView()->back_button()->visible());
  EXPECT_FALSE(GetSearchBoxView()->search_box()->text().empty());

  // Case 2: Exit search mode by clicking |back_button|. The focus should be on
  // search box.
  GetSearchBoxView()->ButtonPressed(
      GetSearchBoxView()->back_button(),
      ui::MouseEvent(ui::ET_MOUSE_PRESSED, gfx::Point(), gfx::Point(),
                     base::TimeTicks(), ui::EF_LEFT_MOUSE_BUTTON,
                     ui::EF_LEFT_MOUSE_BUTTON));
  EXPECT_TRUE(GetSearchBoxView()->search_box()->text().empty());
  EXPECT_TRUE(GetSearchBoxView()->search_box()->HasFocus());

  // Enter search mode again.
  KeyPress(ui::VKEY_A, /*should_insert=*/true);
  EXPECT_FALSE(GetSearchBoxView()->search_box()->text().empty());

  // Case 3: Exit search mode by pressing |VKEY_ESCAPE|. The focus should be on
  // search box.
  KeyPress(ui::VKEY_ESCAPE, /*should_insert=*/false);
  EXPECT_TRUE(GetSearchBoxView()->search_box()->text().empty());
  EXPECT_TRUE(GetSearchBoxView()->search_box()->HasFocus());

  // Cleaning up.
  widget->CloseNow();
}

// Test that the window can be closed by accelerator.
TEST_F(KeyboardShortcutViewTest, CloseWindowByAccelerator) {
  // Showing the widget.
  views::Widget* widget = KeyboardShortcutView::Show(CurrentContext());
  EXPECT_FALSE(widget->IsClosed());

  ui::test::EventGenerator& event_generator = GetEventGenerator();
  event_generator.PressKey(ui::VKEY_W, ui::EF_CONTROL_DOWN);
  EXPECT_TRUE(widget->IsClosed());
}

}  // namespace keyboard_shortcut_viewer

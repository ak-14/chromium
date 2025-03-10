// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/app_list/search/settings_shortcut/settings_shortcut_result.h"

#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/app_list/search/settings_shortcut/settings_shortcut_metadata.h"
#include "chrome/browser/ui/chrome_pages.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/gfx/image/image_skia_operations.h"
#include "ui/gfx/paint_vector_icon.h"

namespace app_list {

namespace {

// TODO(wutao): Need UX specs on these values.
constexpr int kSettingsIconSize = 48;

// Icon color.
constexpr SkColor kSettingsColor = SkColorSetARGBMacro(0x8A, 0x00, 0x00, 0x00);

}  // namespace

SettingsShortcutResult::SettingsShortcutResult(
    Profile* profile,
    const SettingsShortcut& settings_shortcut)
    : profile_(profile), settings_shortcut_(settings_shortcut) {
  set_id(settings_shortcut.shortcut_id);
  set_title(
      l10n_util::GetStringUTF16(settings_shortcut.name_string_resource_id));
  // TODO(wutao): create a new display type kSettingsShortcut.
  set_display_type(DisplayType::kTile);
  SetIcon(gfx::ImageSkiaOperations::CreateResizedImage(
      gfx::CreateVectorIcon(settings_shortcut.vector_icon, kSettingsColor),
      skia::ImageOperations::RESIZE_BEST,
      gfx::Size(kSettingsIconSize, kSettingsIconSize)));
}

void SettingsShortcutResult::Open(int event_flags) {
  chrome::ShowSettingsSubPageForProfile(profile_, settings_shortcut_.subpage);
}

std::unique_ptr<ChromeSearchResult> SettingsShortcutResult::Duplicate() const {
  auto result =
      std::make_unique<SettingsShortcutResult>(profile_, settings_shortcut_);
  result->set_title_tags(title_tags());
  result->set_relevance(relevance());
  return result;
}

ui::MenuModel* SettingsShortcutResult::GetContextMenuModel() {
  return nullptr;
}

}  // namespace app_list

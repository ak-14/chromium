// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_SYSTEM_POWER_TRAY_POWER_H_
#define ASH_SYSTEM_POWER_TRAY_POWER_H_

#include <memory>

#include "ash/system/power/power_status.h"
#include "ash/system/tray/system_tray_item.h"
#include "base/macros.h"

namespace ash {

namespace tray {
class PowerTrayView;
}

class ASH_EXPORT TrayPower : public SystemTrayItem,
                             public PowerStatus::Observer {
 public:
  explicit TrayPower(SystemTray* system_tray);
  ~TrayPower() override;

 private:
  // This enum is used for histogram. The existing values should not be removed,
  // and the new values should be added just before CHARGER_TYPE_COUNT.
  enum ChargerType {
    UNKNOWN_CHARGER,
    MAINS_CHARGER,
    USB_CHARGER,
    UNCONFIRMED_SPRING_CHARGER,
    SAFE_SPRING_CHARGER,
    CHARGER_TYPE_COUNT,
  };

  // Overridden from SystemTrayItem.
  views::View* CreateTrayView(LoginStatus status) override;
  views::View* CreateDefaultView(LoginStatus status) override;
  void OnTrayViewDestroyed() override;

  // Overridden from PowerStatus::Observer.
  void OnPowerStatusChanged() override;

  tray::PowerTrayView* power_tray_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(TrayPower);
};

}  // namespace ash

#endif  // ASH_SYSTEM_POWER_TRAY_POWER_H_

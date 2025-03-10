// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UI_DISPLAY_MANAGER_TEST_TEST_NATIVE_DISPLAY_DELEGATE_H_
#define UI_DISPLAY_MANAGER_TEST_TEST_NATIVE_DISPLAY_DELEGATE_H_

#include <stdint.h>

#include <vector>

#include "base/macros.h"
#include "base/observer_list.h"
#include "ui/display/manager/test/action_logger.h"
#include "ui/display/manager/test/action_logger_util.h"
#include "ui/display/types/native_display_delegate.h"

namespace display {

class ActionLogger;
class DisplaySnapshot;
class NativeDisplayObserver;

namespace test {

class TestNativeDisplayDelegate : public NativeDisplayDelegate {
 public:
  // Ownership of |log| remains with the caller.
  explicit TestNativeDisplayDelegate(ActionLogger* log);
  ~TestNativeDisplayDelegate() override;

  const std::vector<DisplaySnapshot*>& outputs() const { return outputs_; }

  void set_outputs(const std::vector<DisplaySnapshot*>& outputs) {
    outputs_ = outputs;
  }

  void set_max_configurable_pixels(int pixels) {
    max_configurable_pixels_ = pixels;
  }

  void set_get_hdcp_state_expectation(bool success) {
    get_hdcp_expectation_ = success;
  }

  void set_set_hdcp_state_expectation(bool success) {
    set_hdcp_expectation_ = success;
  }

  void set_hdcp_state(HDCPState state) { hdcp_state_ = state; }

  void set_run_async(bool run_async) { run_async_ = run_async; }

  // NativeDisplayDelegate overrides:
  void Initialize() override;
  void TakeDisplayControl(const DisplayControlCallback& callback) override;
  void RelinquishDisplayControl(
      const DisplayControlCallback& callback) override;
  void GetDisplays(const GetDisplaysCallback& callback) override;
  void Configure(const DisplaySnapshot& output,
                 const DisplayMode* mode,
                 const gfx::Point& origin,
                 const ConfigureCallback& callback) override;
  void GetHDCPState(const DisplaySnapshot& output,
                    const GetHDCPStateCallback& callback) override;
  void SetHDCPState(const DisplaySnapshot& output,
                    HDCPState state,
                    const SetHDCPStateCallback& callback) override;
  bool SetColorCorrection(const DisplaySnapshot& output,
                          const std::vector<GammaRampRGBEntry>& degamma_lut,
                          const std::vector<GammaRampRGBEntry>& gamma_lut,
                          const std::vector<float>& correction_matrix) override;
  void AddObserver(NativeDisplayObserver* observer) override;
  void RemoveObserver(NativeDisplayObserver* observer) override;
  FakeDisplayController* GetFakeDisplayController() override;

 private:
  bool Configure(const DisplaySnapshot& output,
                 const DisplayMode* mode,
                 const gfx::Point& origin);

  // Outputs to be returned by GetDisplays().
  std::vector<DisplaySnapshot*> outputs_;

  // |max_configurable_pixels_| represents the maximum number of pixels that
  // Configure will support.  Tests can use this to force Configure
  // to fail if attempting to set a resolution that is higher than what
  // a device might support under a given circumstance.
  // A value of 0 means that no limit is enforced and Configure will
  // return success regardless of the resolution.
  int max_configurable_pixels_;

  bool get_hdcp_expectation_;
  bool set_hdcp_expectation_;

  // Result value of GetHDCPState().
  HDCPState hdcp_state_;

  // If true, the callbacks are posted on the message loop.
  bool run_async_;

  ActionLogger* log_;  // Not owned.

  base::ObserverList<NativeDisplayObserver> observers_;

  DISALLOW_COPY_AND_ASSIGN(TestNativeDisplayDelegate);
};

}  // namespace test
}  // namespace display

#endif  // UI_DISPLAY_MANAGER_TEST_TEST_NATIVE_DISPLAY_DELEGATE_H_

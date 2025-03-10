// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IOS_CHROME_BROWSER_UI_HISTORY_HISTORY_LOCAL_COMMANDS_H_
#define IOS_CHROME_BROWSER_UI_HISTORY_HISTORY_LOCAL_COMMANDS_H_

#include "base/ios/block_types.h"

// Protocol to communicate HistoryTableViewController actions to its
// coordinator.
@protocol HistoryLocalCommands
// Notifies the coordinator that history should be dismissed.
- (void)dismissHistoryWithCompletion:(ProceduralBlock)completionHandler;
@end

#endif  // IOS_CHROME_BROWSER_UI_HISTORY_HISTORY_LOCAL_COMMANDS_H_

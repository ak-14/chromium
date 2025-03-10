// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef STORAGE_BROWSER_FILEAPI_SANDBOX_QUOTA_OBSERVER_H_
#define STORAGE_BROWSER_FILEAPI_SANDBOX_QUOTA_OBSERVER_H_

#include <stdint.h>

#include <map>

#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/timer/timer.h"
#include "storage/browser/fileapi/file_observers.h"
#include "storage/browser/fileapi/file_system_url.h"

namespace base {
class SequencedTaskRunner;
}

namespace storage {
class QuotaManagerProxy;
}

namespace storage {

class FileSystemUsageCache;
class FileSystemURL;
class ObfuscatedFileUtil;

class SandboxQuotaObserver
    : public FileUpdateObserver,
      public FileAccessObserver {
 public:
  typedef std::map<base::FilePath, int64_t> PendingUpdateNotificationMap;

  SandboxQuotaObserver(storage::QuotaManagerProxy* quota_manager_proxy,
                       base::SequencedTaskRunner* update_notify_runner,
                       ObfuscatedFileUtil* sandbox_file_util,
                       FileSystemUsageCache* file_system_usage_cache_);
  ~SandboxQuotaObserver() override;

  // FileUpdateObserver overrides.
  void OnStartUpdate(const FileSystemURL& url) override;
  void OnUpdate(const FileSystemURL& url, int64_t delta) override;
  void OnEndUpdate(const FileSystemURL& url) override;

  // FileAccessObserver overrides.
  void OnAccess(const FileSystemURL& url) override;

  void SetUsageCacheEnabled(const GURL& origin,
                            FileSystemType type,
                            bool enabled);

 private:
  void ApplyPendingUsageUpdate();
  void UpdateUsageCacheFile(const base::FilePath& usage_file_path,
                            int64_t delta);

  base::FilePath GetUsageCachePath(const FileSystemURL& url);

  scoped_refptr<storage::QuotaManagerProxy> quota_manager_proxy_;
  scoped_refptr<base::SequencedTaskRunner> update_notify_runner_;

  // Not owned; sandbox_file_util_ should have identical lifetime with this.
  ObfuscatedFileUtil* sandbox_file_util_;

  // Not owned; file_system_usage_cache_ should have longer lifetime than this.
  FileSystemUsageCache* file_system_usage_cache_;

  PendingUpdateNotificationMap pending_update_notification_;
  base::OneShotTimer delayed_cache_update_helper_;

  DISALLOW_COPY_AND_ASSIGN(SandboxQuotaObserver);
};

}  // namespace storage

#endif  // STORAGE_BROWSER_FILEAPI_SANDBOX_QUOTA_OBSERVER_H_

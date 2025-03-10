// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import "ios/chrome/browser/ui/settings/password_exporter.h"

#include "base/logging.h"
#include "base/mac/bind_objc_block.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/sys_string_conversions.h"
#include "base/task_runner_util.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_restrictions.h"
#include "components/autofill/core/common/password_form.h"
#include "components/password_manager/core/browser/export/password_csv_writer.h"
#include "components/password_manager/core/browser/password_manager_metrics_util.h"
#include "components/strings/grit/components_strings.h"
#import "ios/chrome/browser/passwords/passwords_directory_util.h"
#import "ios/chrome/browser/ui/settings/reauthentication_module.h"
#include "ios/chrome/grit/ios_strings.h"
#include "ui/base/l10n/l10n_util_mac.h"

#if !defined(__has_feature) || !__has_feature(objc_arc)
#error "This file requires ARC support."
#endif

namespace {

enum class ReauthenticationStatus {
  PENDING,
  SUCCESSFUL,
  FAILED,
};

}  // namespace

@interface PasswordSerializerBridge : NSObject<PasswordSerializerBridge>
@end

@implementation PasswordSerializerBridge

- (void)serializePasswords:
            (std::vector<std::unique_ptr<autofill::PasswordForm>>)passwords
                   handler:(void (^)(std::string))serializedPasswordsHandler {
  base::PostTaskWithTraitsAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_BLOCKING},
      base::BindOnce(&password_manager::PasswordCSVWriter::SerializePasswords,
                     std::move(passwords)),
      base::OnceCallback<void(std::string)>(
          base::BindBlockArc(serializedPasswordsHandler)));
}

@end

@interface PasswordFileWriter : NSObject<FileWriterProtocol>
@end

@implementation PasswordFileWriter

- (void)writeData:(NSData*)data
            toURL:(NSURL*)fileURL
          handler:(void (^)(WriteToURLStatus))handler {
  WriteToURLStatus (^writeToFile)() = ^{
    base::AssertBlockingAllowed();
    NSError* error = nil;

    NSURL* directoryURL = [fileURL URLByDeletingLastPathComponent];
    NSFileManager* fileManager = [NSFileManager defaultManager];

    if (![fileManager createDirectoryAtURL:directoryURL
               withIntermediateDirectories:YES
                                attributes:nil
                                     error:nil]) {
      return WriteToURLStatus::UNKNOWN_ERROR;
    }

    BOOL success = [data
        writeToURL:fileURL
           options:(NSDataWritingAtomic | NSDataWritingFileProtectionComplete)
             error:&error];

    if (!success) {
      if (error.code == NSFileWriteOutOfSpaceError) {
        return WriteToURLStatus::OUT_OF_DISK_SPACE_ERROR;
      } else {
        return WriteToURLStatus::UNKNOWN_ERROR;
      }
    }
    return WriteToURLStatus::SUCCESS;
  };
  base::PostTaskWithTraitsAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_BLOCKING},
      base::BindBlockArc(writeToFile), base::BindBlockArc(handler));
}

@end

@interface PasswordExporter () {
  // Module containing the reauthentication mechanism used for exporting
  // passwords.
  __weak id<ReauthenticationProtocol> _weakReauthenticationModule;
  // Instance of the view controller initiating the export. Used
  // for displaying alerts.
  __weak id<PasswordExporterDelegate> _weakDelegate;
  // Name of the temporary passwords file. It can be used by the receiving app,
  // so it needs to be a localized string.
  NSString* _tempPasswordsFileName;
  // Bridge object that triggers password serialization and executes a
  // handler on the serialized passwords.
  id<PasswordSerializerBridge> _passwordSerializerBridge;
  // Object that writes data to a file asyncronously and executes a handler
  // block when finished.
  id<FileWriterProtocol> _passwordFileWriter;
}

// Contains the status of the reauthentication flow.
@property(nonatomic, assign) ReauthenticationStatus reauthenticationStatus;
// Whether the password serializing has finished.
@property(nonatomic, assign) BOOL serializingFinished;
// String containing serialized password forms.
@property(nonatomic, copy) NSString* serializedPasswords;
// The exporter state.
@property(nonatomic, assign) ExportState exportState;
// The number of passwords that are exported. Used for metrics.
@property(nonatomic, assign) int passwordCount;

@end

@implementation PasswordExporter

// Public synthesized properties
@synthesize exportState = _exportState;

// Private synthesized properties
@synthesize reauthenticationStatus = _reauthenticationStatus;
@synthesize serializingFinished = _serializingFinished;
@synthesize serializedPasswords = _serializedPasswords;
@synthesize passwordCount = _passwordCount;

- (instancetype)initWithReauthenticationModule:
                    (id<ReauthenticationProtocol>)reauthenticationModule
                                      delegate:(id<PasswordExporterDelegate>)
                                                   delegate {
  DCHECK(delegate);
  DCHECK(reauthenticationModule);
  self = [super init];
  if (self) {
    _tempPasswordsFileName =
        [l10n_util::GetNSString(IDS_PASSWORD_MANAGER_DEFAULT_EXPORT_FILENAME)
            stringByAppendingString:@".csv"];
    _passwordSerializerBridge = [[PasswordSerializerBridge alloc] init];
    _passwordFileWriter = [[PasswordFileWriter alloc] init];
    _weakReauthenticationModule = reauthenticationModule;
    _weakDelegate = delegate;
    [self resetExportState];
  }
  return self;
}

- (void)startExportFlow:
    (std::vector<std::unique_ptr<autofill::PasswordForm>>)passwords {
  DCHECK(!passwords.empty());
  DCHECK(self.exportState == ExportState::IDLE);
  if ([_weakReauthenticationModule canAttemptReauth]) {
    self.exportState = ExportState::ONGOING;
    [_weakDelegate updateExportPasswordsButton];
    [self serializePasswords:std::move(passwords)];
    [self startReauthentication];
  } else {
    [_weakDelegate showSetPasscodeDialog];
  }
}

- (void)cancelExport {
  self.exportState = ExportState::CANCELLING;
  UMA_HISTOGRAM_ENUMERATION(
      "PasswordManager.ExportPasswordsToCSVResult",
      password_manager::metrics_util::ExportPasswordsResult::USER_ABORTED,
      password_manager::metrics_util::ExportPasswordsResult::COUNT);
}

#pragma mark -  Private methods

- (void)showExportErrorAlertWithLocalizedReason:(NSString*)errorReason {
  [_weakDelegate showExportErrorAlertWithLocalizedReason:errorReason];
}

- (void)serializePasswords:
    (std::vector<std::unique_ptr<autofill::PasswordForm>>)passwords {
  self.passwordCount = passwords.size();

  base::Time exportPreparationStart = base::Time::Now();
  __weak PasswordExporter* weakSelf = self;
  void (^onPasswordsSerialized)(std::string) =
      ^(std::string serializedPasswords) {
        PasswordExporter* strongSelf = weakSelf;
        if (!strongSelf)
          return;
        strongSelf.serializedPasswords =
            base::SysUTF8ToNSString(serializedPasswords);
        strongSelf.serializingFinished = YES;
        UMA_HISTOGRAM_MEDIUM_TIMES(
            "PasswordManager.TimeReadingExportedPasswords",
            base::Time::Now() - exportPreparationStart);
        [strongSelf tryExporting];
      };

  [_passwordSerializerBridge serializePasswords:std::move(passwords)
                                        handler:onPasswordsSerialized];
}

- (void)startReauthentication {
  __weak PasswordExporter* weakSelf = self;

  void (^onReauthenticationFinished)(BOOL) = ^(BOOL success) {
    PasswordExporter* strongSelf = weakSelf;
    if (!strongSelf)
      return;
    if (success) {
      strongSelf.reauthenticationStatus = ReauthenticationStatus::SUCCESSFUL;
      [strongSelf showPreparingPasswordsAlert];
    } else {
      strongSelf.reauthenticationStatus = ReauthenticationStatus::FAILED;
    }
    [strongSelf tryExporting];
  };

  [_weakReauthenticationModule
      attemptReauthWithLocalizedReason:l10n_util::GetNSString(
                                           IDS_IOS_EXPORT_PASSWORDS)
                  canReusePreviousAuth:NO
                               handler:onReauthenticationFinished];
}

- (void)showPreparingPasswordsAlert {
  [_weakDelegate showPreparingPasswordsAlert];
}

- (void)tryExporting {
  if (!self.serializingFinished)
    return;
  switch (self.reauthenticationStatus) {
    case ReauthenticationStatus::PENDING:
      return;
    case ReauthenticationStatus::SUCCESSFUL:
      [self writePasswordsToFile];
      break;
    case ReauthenticationStatus::FAILED:
      UMA_HISTOGRAM_ENUMERATION(
          "PasswordManager.ExportPasswordsToCSVResult",
          password_manager::metrics_util::ExportPasswordsResult::USER_ABORTED,
          password_manager::metrics_util::ExportPasswordsResult::COUNT);
      [self resetExportState];
      break;
    default:
      NOTREACHED();
  }
}

- (void)resetExportState {
  self.serializingFinished = NO;
  self.serializedPasswords = nil;
  self.passwordCount = 0;
  self.reauthenticationStatus = ReauthenticationStatus::PENDING;
  self.exportState = ExportState::IDLE;
  [_weakDelegate updateExportPasswordsButton];
}

- (void)writePasswordsToFile {
  if (self.exportState == ExportState::CANCELLING) {
    [self resetExportState];
    return;
  }

  NSURL* uniqueDirectoryURL = [GetPasswordsDirectoryURL()
      URLByAppendingPathComponent:[[NSUUID UUID] UUIDString]
                      isDirectory:YES];
  NSURL* passwordsTempFileURL =
      [uniqueDirectoryURL URLByAppendingPathComponent:_tempPasswordsFileName
                                          isDirectory:NO];

  __weak PasswordExporter* weakSelf = self;
  void (^onFileWritten)(WriteToURLStatus) = ^(WriteToURLStatus status) {
    PasswordExporter* strongSelf = weakSelf;
    if (!strongSelf) {
      return;
    }
    if (strongSelf.exportState == ExportState::CANCELLING) {
      [strongSelf resetExportState];
      return;
    }
    switch (status) {
      case WriteToURLStatus::SUCCESS:
        [strongSelf showActivityView:passwordsTempFileURL];
        break;
      case WriteToURLStatus::OUT_OF_DISK_SPACE_ERROR:
        [strongSelf
            showExportErrorAlertWithLocalizedReason:
                l10n_util::GetNSString(
                    IDS_IOS_EXPORT_PASSWORDS_OUT_OF_SPACE_ALERT_MESSAGE)];
        UMA_HISTOGRAM_ENUMERATION(
            "PasswordManager.ExportPasswordsToCSVResult",
            password_manager::metrics_util::ExportPasswordsResult::WRITE_FAILED,
            password_manager::metrics_util::ExportPasswordsResult::COUNT);
        [strongSelf resetExportState];
        break;
      case WriteToURLStatus::UNKNOWN_ERROR:
        [strongSelf
            showExportErrorAlertWithLocalizedReason:
                l10n_util::GetNSString(
                    IDS_IOS_EXPORT_PASSWORDS_UNKNOWN_ERROR_ALERT_MESSAGE)];
        UMA_HISTOGRAM_ENUMERATION(
            "PasswordManager.ExportPasswordsToCSVResult",
            password_manager::metrics_util::ExportPasswordsResult::WRITE_FAILED,
            password_manager::metrics_util::ExportPasswordsResult::COUNT);
        [strongSelf resetExportState];
        break;
      default:
        NOTREACHED();
    }
  };

  NSData* serializedPasswordsData =
      [self.serializedPasswords dataUsingEncoding:NSUTF8StringEncoding];

  // Drop |serializedPasswords| as it is no longer needed.
  self.serializedPasswords = nil;

  [_passwordFileWriter writeData:serializedPasswordsData
                           toURL:passwordsTempFileURL
                         handler:onFileWritten];
}

- (void)deleteTemporaryFile:(NSURL*)passwordsTempFileURL {
  NSURL* uniqueDirectoryURL =
      [passwordsTempFileURL URLByDeletingLastPathComponent];
  base::PostTaskWithTraits(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::BACKGROUND},
      base::BindBlockArc(^{
        base::AssertBlockingAllowed();
        NSFileManager* fileManager = [NSFileManager defaultManager];
        [fileManager removeItemAtURL:uniqueDirectoryURL error:nil];
      }));
}

- (void)showActivityView:(NSURL*)passwordsTempFileURL {
  if (self.exportState == ExportState::CANCELLING) {
    [self deleteTemporaryFile:passwordsTempFileURL];
    [self resetExportState];
    return;
  }
  __weak PasswordExporter* weakSelf = self;
  [_weakDelegate
      showActivityViewWithActivityItems:@[ passwordsTempFileURL ]
                      completionHandler:^(
                          NSString* activityType, BOOL completed,
                          NSArray* returnedItems, NSError* activityError) {
                        [weakSelf deleteTemporaryFile:passwordsTempFileURL];
                      }];
  UMA_HISTOGRAM_ENUMERATION(
      "PasswordManager.ExportPasswordsToCSVResult",
      password_manager::metrics_util::ExportPasswordsResult::SUCCESS,
      password_manager::metrics_util::ExportPasswordsResult::COUNT);
  UMA_HISTOGRAM_COUNTS("PasswordManager.ExportedPasswordsPerUserInCSV",
                       self.passwordCount);
}

#pragma mark - ForTesting

- (void)setPasswordSerializerBridge:
    (id<PasswordSerializerBridge>)passwordSerializerBridge {
  _passwordSerializerBridge = passwordSerializerBridge;
}

- (void)setPasswordFileWriter:(id<FileWriterProtocol>)passwordFileWriter {
  _passwordFileWriter = passwordFileWriter;
}

@end

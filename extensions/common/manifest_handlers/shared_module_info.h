// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef EXTENSIONS_COMMON_MANIFEST_HANDLERS_SHARED_MODULE_INFO_H_
#define EXTENSIONS_COMMON_MANIFEST_HANDLERS_SHARED_MODULE_INFO_H_

#include <string>
#include <vector>

#include "base/values.h"
#include "extensions/common/extension.h"
#include "extensions/common/manifest_handler.h"

namespace extensions {

class SharedModuleInfo : public Extension::ManifestData {
 public:
  SharedModuleInfo();
  ~SharedModuleInfo() override;

  bool Parse(const Extension* extension, base::string16* error);

  struct ImportInfo {
    std::string extension_id;
    std::string minimum_version;
  };

  // Utility functions.
  static void ParseImportedPath(const std::string& path,
                                std::string* import_id,
                                std::string* import_relative_path);
  static bool IsImportedPath(const std::string& path);

  // Functions relating to exporting resources.
  static bool IsSharedModule(const Extension* extension);
  // Check against the shared module's whitelist to see if |other_id| can import
  // its resources. If no whitelist is specified, all extensions can import this
  // extension.
  static bool IsExportAllowedByWhitelist(const Extension* extension,
                                         const std::string& other_id);

  // Functions relating to importing resources.
  static bool ImportsExtensionById(const Extension* extension,
                                   const std::string& other_id);
  static bool ImportsModules(const Extension* extension);
  static const std::vector<ImportInfo>& GetImports(const Extension* extension);

 private:
  // Optional list of extensions from which importing is allowed.
  std::set<std::string> export_whitelist_;

  // Optional list of module imports of other extensions.
  std::vector<ImportInfo> imports_;
};

// Parses all import/export keys in the manifest.
class SharedModuleHandler : public ManifestHandler {
 public:
  SharedModuleHandler();
  ~SharedModuleHandler() override;

  bool Parse(Extension* extension, base::string16* error) override;
  bool Validate(const Extension* extension,
                std::string* error,
                std::vector<InstallWarning>* warnings) const override;

 private:
  base::span<const char* const> Keys() const override;
};

}  // namespace extensions

#endif  // EXTENSIONS_COMMON_MANIFEST_HANDLERS_SHARED_MODULE_INFO_H_

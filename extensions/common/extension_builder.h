// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef EXTENSIONS_COMMON_EXTENSION_BUILDER_H_
#define EXTENSIONS_COMMON_EXTENSION_BUILDER_H_

#include <memory>
#include <string>

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "extensions/common/manifest.h"
#include "extensions/common/value_builder.h"

namespace extensions {
class Extension;

// An easier way to create extensions than Extension::Create. The
// constructor sets up some defaults which are customized using the
// methods.
// This class can be used in two ways:
// Aided Manifest Construction
//   The easy way. Use the constructor that takes a name and use helper methods
//   like AddPermission() to customize the extension without needing to
//   construct the manifest dictionary by hand. For more customization, you can
//   use MergeManifest() to add additional keys (which will take precedence over
//   others).
// Custom Manifest Construction
//   The hard way. Use the default constructor. SetManifest() *must* be called
//   with a valid manifest dictionary.
//   TODO(devlin): My suspicion is that this is almost always less readable and
//   useful, but it came first and is used in many places. It'd be nice to maybe
//   get rid of it.
// These are not interchangable - calling SetManifest() with aided manifest
// construction or e.g. AddPermissions() with custom manifest construction will
// crash.
class ExtensionBuilder {
 public:
  enum class Type {
    EXTENSION,
    PLATFORM_APP,
  };

  enum class ActionType {
    PAGE_ACTION,
    BROWSER_ACTION,
  };

  enum class BackgroundPage {
    PERSISTENT,
    EVENT,
  };

  // Initializes an ExtensionBuilder that can be used with SetManifest() for
  // complete customization.
  ExtensionBuilder();

  // Initializes an ExtensionBuilder that can be used with various utility
  // methods to automatically construct a manifest. |name| will be the name of
  // the extension and used to generate a stable ID.
  ExtensionBuilder(const std::string& name, Type type = Type::EXTENSION);

  ~ExtensionBuilder();

  // Move constructor and operator=.
  ExtensionBuilder(ExtensionBuilder&& other);
  ExtensionBuilder& operator=(ExtensionBuilder&& other);

  // Can only be called once, after which it's invalid to use the builder.
  // CHECKs that the extension was created successfully.
  scoped_refptr<Extension> Build();

  //////////////////////////////////////////////////////////////////////////////
  // Utility methods for use with aided manifest construction.

  // Add one or more permissions to the extension.
  ExtensionBuilder& AddPermission(const std::string& permission);
  ExtensionBuilder& AddPermissions(const std::vector<std::string>& permissions);

  // Sets an action type for the extension to have. By default, no action will
  // be set (though note that we synthesize a page action for most extensions).
  ExtensionBuilder& SetAction(ActionType action);

  // Sets a background page for the extension to have. By default, no background
  // page will be set.
  ExtensionBuilder& SetBackgroundPage(BackgroundPage background_page);

  //////////////////////////////////////////////////////////////////////////////
  // Utility methods for use with custom manifest construction.

  // Assigns the extension's manifest to |manifest|.
  ExtensionBuilder& SetManifest(
      std::unique_ptr<base::DictionaryValue> manifest);

  //////////////////////////////////////////////////////////////////////////////
  // Common utility methods (usable with both aided and custom manifest
  // creation).

  // Defaults to FilePath().
  ExtensionBuilder& SetPath(const base::FilePath& path);

  // Defaults to Manifest::UNPACKED.
  ExtensionBuilder& SetLocation(Manifest::Location location);

  // Merge another manifest into the current manifest, with new keys taking
  // precedence.
  ExtensionBuilder& MergeManifest(
      std::unique_ptr<base::DictionaryValue> manifest);

  // Add flags to the extension. Default is no flags.
  ExtensionBuilder& AddFlags(int init_from_value_flags);

  // Defaults to the default extension ID created in Extension::Create or to an
  // ID generated from the extension's name, if aided manifest construction is
  // used.
  ExtensionBuilder& SetID(const std::string& id);

 private:
  struct ManifestData;

  // Information for constructing the manifest; either metadata about the
  // manifest which will be used to construct it, or the dictionary itself. Only
  // one will be present.
  std::unique_ptr<ManifestData> manifest_data_;
  std::unique_ptr<base::DictionaryValue> manifest_value_;

  base::FilePath path_;
  Manifest::Location location_;
  int flags_;
  std::string id_;

  DISALLOW_COPY_AND_ASSIGN(ExtensionBuilder);
};

}  // namespace extensions

#endif  // EXTENSIONS_COMMON_EXTENSION_BUILDER_H_

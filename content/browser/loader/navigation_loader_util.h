// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_LOADER_NAVIGATION_LOADER_UTIL_H_
#define CONTENT_BROWSER_LOADER_NAVIGATION_LOADER_UTIL_H_

#include "base/optional.h"

#include <string>

class GURL;
namespace net {
class HttpResponseHeaders;
}
namespace url {
class Origin;
}

namespace content {
namespace navigation_loader_util {

// Determines whether given response would result in a download.
// Called on IO thread.
bool IsDownload(const GURL& url,
                net::HttpResponseHeaders* headers,
                const std::string& mime_type,
                bool have_suggested_filename,
                bool is_cross_origin);

bool IsCrossOriginRequest(const GURL& request_url,
                          const base::Optional<url::Origin>& initiator);

}  // namespace navigation_loader_util
}  // namespace content

#endif  // CONTENT_BROWSER_LOADER_NAVIGATION_LOADER_UTIL_H_
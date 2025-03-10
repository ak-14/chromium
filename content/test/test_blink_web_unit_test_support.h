// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_TEST_TEST_BLINK_WEB_UNIT_TEST_SUPPORT_H_
#define CONTENT_TEST_TEST_BLINK_WEB_UNIT_TEST_SUPPORT_H_

#include <memory>

#include "base/compiler_specific.h"
#include "base/files/scoped_temp_dir.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "build/build_config.h"
#include "cc/blink/web_compositor_support_impl.h"
#include "content/child/blink_platform_impl.h"
#include "content/renderer/webfileutilities_impl.h"
#include "content/test/mock_webblob_registry_impl.h"
#include "content/test/mock_webclipboard_impl.h"
#include "third_party/blink/public/platform/web_url_loader_mock_factory.h"

namespace blink {
namespace scheduler {
class WebMainThreadScheduler;
}
}

namespace content {

// An implementation of BlinkPlatformImpl for tests.
class TestBlinkWebUnitTestSupport : public BlinkPlatformImpl {
 public:
  TestBlinkWebUnitTestSupport();
  ~TestBlinkWebUnitTestSupport() override;

  blink::WebBlobRegistry* GetBlobRegistry() override;
  blink::WebClipboard* Clipboard() override;
  blink::WebFileUtilities* GetFileUtilities() override;
  blink::WebIDBFactory* IdbFactory() override;

  std::unique_ptr<blink::WebURLLoaderFactory> CreateDefaultURLLoaderFactory()
      override;
  std::unique_ptr<blink::WebDataConsumerHandle> CreateDataConsumerHandle(
      mojo::ScopedDataPipeConsumerHandle handle) override;
  blink::WebString UserAgent() override;
  blink::WebString QueryLocalizedString(
      blink::WebLocalizedString::Name name) override;
  blink::WebString QueryLocalizedString(blink::WebLocalizedString::Name name,
                                        const blink::WebString& value) override;
  blink::WebString QueryLocalizedString(
      blink::WebLocalizedString::Name name,
      const blink::WebString& value1,
      const blink::WebString& value2) override;
  blink::WebString DefaultLocale() override;

  blink::WebCompositorSupport* CompositorSupport() override;

  std::unique_ptr<blink::WebGestureCurve> CreateFlingAnimationCurve(
      blink::WebGestureDevice device_source,
      const blink::WebFloatPoint& velocity,
      const blink::WebSize& cumulative_scroll) override;

  blink::WebURLLoaderMockFactory* GetURLLoaderMockFactory() override;

  blink::WebThread* CurrentThread() override;

  void GetPluginList(bool refresh,
                     const blink::WebSecurityOrigin& mainFrameOrigin,
                     blink::WebPluginListBuilder* builder) override;

  std::unique_ptr<blink::WebRTCCertificateGenerator>
  CreateRTCCertificateGenerator() override;

 private:
  MockWebBlobRegistryImpl blob_registry_;
  std::unique_ptr<MockWebClipboardImpl> mock_clipboard_;
  WebFileUtilitiesImpl file_utilities_;
  base::ScopedTempDir file_system_root_;
  std::unique_ptr<blink::WebURLLoaderMockFactory> url_loader_factory_;
  cc_blink::WebCompositorSupportImpl compositor_support_;
  std::unique_ptr<blink::scheduler::WebMainThreadScheduler>
      main_thread_scheduler_;
  std::unique_ptr<blink::WebThread> web_thread_;

  base::WeakPtrFactory<TestBlinkWebUnitTestSupport> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(TestBlinkWebUnitTestSupport);
};

}  // namespace content

#endif  // CONTENT_TEST_TEST_BLINK_WEB_UNIT_TEST_SUPPORT_H_

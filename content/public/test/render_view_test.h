// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_TEST_RENDER_VIEW_TEST_H_
#define CONTENT_PUBLIC_TEST_RENDER_VIEW_TEST_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "base/command_line.h"
#include "base/strings/string16.h"
#include "base/test/scoped_task_environment.h"
#include "base/test/test_io_thread.h"
#include "build/build_config.h"
#include "content/public/browser/native_web_keyboard_event.h"
#include "content/public/common/main_function_params.h"
#include "content/public/common/page_state.h"
#include "content/public/test/mock_render_thread.h"
#include "mojo/edk/embedder/scoped_ipc_support.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_frame.h"

namespace base {
class FieldTrialList;
}

namespace blink {
namespace scheduler {
class WebMainThreadScheduler;
}
class WebGestureEvent;
class WebInputElement;
class WebMouseEvent;
class WebWidget;
}

namespace gfx {
class Rect;
}

namespace content {
class ContentBrowserClient;
class ContentClient;
class ContentRendererClient;
class FakeCompositorDependencies;
class MockRenderProcess;
class PageState;
class RendererMainPlatformDelegate;
class RendererBlinkPlatformImpl;
class RendererBlinkPlatformImplTestOverrideImpl;
class RenderView;
struct ResizeParams;

class RenderViewTest : public testing::Test {
 public:
  // A special BlinkPlatformImpl class with overrides that are useful for
  // RenderViewTest.
  class RendererBlinkPlatformImplTestOverride {
   public:
    RendererBlinkPlatformImplTestOverride();
    ~RendererBlinkPlatformImplTestOverride();
    RendererBlinkPlatformImpl* Get() const;
    void Initialize();
    void Shutdown();

   private:
    std::unique_ptr<blink::scheduler::WebMainThreadScheduler>
        main_thread_scheduler_;
    std::unique_ptr<RendererBlinkPlatformImplTestOverrideImpl>
        blink_platform_impl_;
  };

  RenderViewTest();
  ~RenderViewTest() override;

 protected:
  // Returns a pointer to the main frame.
  blink::WebLocalFrame* GetMainFrame();

  // Executes the given JavaScript in the context of the main frame. The input
  // is a NULL-terminated UTF-8 string.
  void ExecuteJavaScriptForTests(const char* js);

  // Executes the given JavaScript and sets the int value it evaluates to in
  // |result|.
  // Returns true if the JavaScript was evaluated correctly to an int value,
  // false otherwise.
  bool ExecuteJavaScriptAndReturnIntValue(const base::string16& script,
                                          int* result);

  // Loads |html| into the main frame as a data: URL and blocks until the
  // navigation is committed.
  void LoadHTML(const char* html);

  // Pretends to load |url| into the main frame, but substitutes |html| for the
  // response body (and does not include any response headers). This can be used
  // instead of LoadHTML for tests that cannot use a data: url (for example if
  // document.location needs to be set to something specific.)
  void LoadHTMLWithUrlOverride(const char* html, const char* url);

  // Returns the current PageState.
  // In OOPIF enabled modes, this returns a PageState object for the main frame.
  PageState GetCurrentPageState();

  // Navigates the main frame back or forward in session history and commits.
  // The caller must capture a PageState for the target page.
  void GoBack(const GURL& url, const PageState& state);
  void GoForward(const GURL& url, const PageState& state);

  // Sends one native key event over IPC.
  void SendNativeKeyEvent(const NativeWebKeyboardEvent& key_event);

  // Send a raw keyboard event to the renderer.
  void SendWebKeyboardEvent(const blink::WebKeyboardEvent& key_event);

  // Send a raw mouse event to the renderer.
  void SendWebMouseEvent(const blink::WebMouseEvent& mouse_event);

  // Send a raw gesture event to the renderer.
  void SendWebGestureEvent(const blink::WebGestureEvent& gesture_event);

  // Returns the bounds (coordinates and size) of the element with id
  // |element_id|.  Returns an empty rect if such an element was not found.
  gfx::Rect GetElementBounds(const std::string& element_id);

  // Sends a left mouse click in the middle of the element with id |element_id|.
  // Returns true if the event was sent, false otherwise (typically because
  // the element was not found).
  bool SimulateElementClick(const std::string& element_id);

  // Sends a left mouse click at the |point|.
  void SimulatePointClick(const gfx::Point& point);

  // Sends a right mouse click in the middle of the element with id
  // |element_id|. Returns true if the event was sent, false otherwise
  // (typically because the element was not found).
  bool SimulateElementRightClick(const std::string& element_id);

  // Sends a right mouse click at the |point|.
  void SimulatePointRightClick(const gfx::Point& point);

  // Sends a tap at the |rect|.
  void SimulateRectTap(const gfx::Rect& rect);

  // Simulates |node| being focused.
  void SetFocused(const blink::WebNode& node);

  // Simulates a navigation with a type of reload to the given url.
  void Reload(const GURL& url);

  // Resize the view.
  void Resize(gfx::Size new_size, bool is_fullscreen);

  // Simulates typing the |ascii_character| into this render view. Also accepts
  // ui::VKEY_BACK for backspace. Will flush the message loop if
  // |flush_message_loop| is true.
  void SimulateUserTypingASCIICharacter(char ascii_character,
                                        bool flush_message_loop);

  // Simulates user focusing |input|, erasing all text, and typing the
  // |new_value| instead. Will process input events for autofill. This is a user
  // gesture.
  void SimulateUserInputChangeForElement(blink::WebInputElement* input,
                                         const std::string& new_value);

  // These are all methods from RenderViewImpl that we expose to testing code.
  bool OnMessageReceived(const IPC::Message& msg);
  void OnSameDocumentNavigation(blink::WebLocalFrame* frame,
                                bool is_new_navigation,
                                bool content_initiated);
  blink::WebWidget* GetWebWidget();

  // Allows a subclass to override the various content client implementations.
  virtual ContentClient* CreateContentClient();
  virtual ContentBrowserClient* CreateContentBrowserClient();
  virtual ContentRendererClient* CreateContentRendererClient();

  // Allows a subclass to customize the initial size of the RenderView.
  virtual std::unique_ptr<ResizeParams> InitialSizeParams();

  // testing::Test
  void SetUp() override;

  void TearDown() override;

  base::test::ScopedTaskEnvironment scoped_task_environment_;

  std::unique_ptr<FakeCompositorDependencies> compositor_deps_;
  std::unique_ptr<MockRenderProcess> mock_process_;
  // We use a naked pointer because we don't want to expose RenderViewImpl in
  // the embedder's namespace.
  RenderView* view_ = nullptr;
  RendererBlinkPlatformImplTestOverride blink_platform_impl_;
  std::unique_ptr<ContentClient> content_client_;
  std::unique_ptr<ContentBrowserClient> content_browser_client_;
  std::unique_ptr<ContentRendererClient> content_renderer_client_;
  std::unique_ptr<MockRenderThread> render_thread_;

  // Used to setup the process so renderers can run.
  std::unique_ptr<RendererMainPlatformDelegate> platform_;
  std::unique_ptr<MainFunctionParams> params_;
  std::unique_ptr<base::CommandLine> command_line_;
  std::unique_ptr<base::FieldTrialList> field_trial_list_;

  // For Mojo.
  std::unique_ptr<base::TestIOThread> test_io_thread_;
  std::unique_ptr<mojo::edk::ScopedIPCSupport> ipc_support_;
  service_manager::BinderRegistry binder_registry_;

#if defined(OS_MACOSX)
  std::unique_ptr<base::mac::ScopedNSAutoreleasePool> autorelease_pool_;
#endif

 private:
  void GoToOffset(int offset, const GURL& url, const PageState& state);
  void SendInputEvent(const blink::WebInputEvent& input_event);
};

}  // namespace content

#endif  // CONTENT_PUBLIC_TEST_RENDER_VIEW_TEST_H_

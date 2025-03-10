/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/public/web/web_frame.h"

#include <stdarg.h>

#include <limits>
#include <map>
#include <memory>
#include <set>

#include "SkBitmap.h"
#include "SkCanvas.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/page/launching_process_state.h"
#include "third_party/blink/public/platform/modules/fetch/fetch_api_request.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_cache.h"
#include "third_party/blink/public/platform/web_clipboard.h"
#include "third_party/blink/public/platform/web_coalesced_input_event.h"
#include "third_party/blink/public/platform/web_float_rect.h"
#include "third_party/blink/public/platform/web_keyboard_event.h"
#include "third_party/blink/public/platform/web_mock_clipboard.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_thread.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_loader_client.h"
#include "third_party/blink/public/platform/web_url_loader_mock_factory.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_context_menu_data.h"
#include "third_party/blink/public/web/web_device_emulation_params.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_document_loader.h"
#include "third_party/blink/public/web/web_find_options.h"
#include "third_party/blink/public/web/web_form_element.h"
#include "third_party/blink/public/web/web_frame_client.h"
#include "third_party/blink/public/web/web_frame_content_dumper.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/public/web/web_history_item.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/public/web/web_range.h"
#include "third_party/blink/public/web/web_remote_frame.h"
#include "third_party/blink/public/web/web_script_execution_callback.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_searchable_form_data.h"
#include "third_party/blink/public/web/web_security_policy.h"
#include "third_party/blink/public/web/web_selection.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_text_check_client.h"
#include "third_party/blink/public/web/web_text_checking_completion.h"
#include "third_party/blink/public/web/web_text_checking_result.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value_factory.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_node.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/viewport_style_resolver.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/user_gesture_indicator.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/text_finder.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/spellcheck/idle_spell_check_callback.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/exported/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_base.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/image_document.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_full_screen.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/document_threadable_loader.h"
#include "third_party/blink/renderer/core/loader/document_threadable_loader_client.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/threadable_loader.h"
#include "third_party/blink/renderer/core/loader/threadable_loading_context.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scoped_page_pauser.h"
#include "third_party/blink/renderer/core/paint/compositing/composited_layer_mapping.h"
#include "third_party/blink/renderer/core/paint/compositing/paint_layer_compositor.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/bindings/microtask.h"
#include "third_party/blink/renderer/platform/cursor.h"
#include "third_party/blink/renderer/platform/drag_image.h"
#include "third_party/blink/renderer/platform/geometry/float_rect.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/graphics_layer.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/scroll/scrollbar.h"
#include "third_party/blink/renderer/platform/scroll/scrollbar_test_suite.h"
#include "third_party/blink/renderer/platform/testing/histogram_tester.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl_hash.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/dtoa/utils.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "v8/include/v8.h"

using blink::URLTestHelpers::ToKURL;
using blink::mojom::SelectionMenuBehavior;
using blink::test::RunPendingTasks;
using testing::ElementsAre;
using testing::Mock;
using testing::_;

namespace blink {

::std::ostream& operator<<(::std::ostream& os, const WebFloatSize& size) {
  return os << "WebFloatSize: [" << size.width << ", " << size.height << "]";
}

::std::ostream& operator<<(::std::ostream& os, const WebFloatPoint& point) {
  return os << "WebFloatPoint: [" << point.x << ", " << point.y << "]";
}

const int kTouchPointPadding = 32;

class WebFrameTest : public testing::Test {
 protected:
  WebFrameTest()
      : base_url_("http://internal.test/"),
        not_base_url_("http://external.test/"),
        chrome_url_("chrome://") {}

  ~WebFrameTest() override {
    Platform::Current()
        ->GetURLLoaderMockFactory()
        ->UnregisterAllURLsAndClearMemoryCache();
  }

  void DisableRendererSchedulerThrottling() {
    // Make sure that the RendererScheduler is foregrounded to avoid getting
    // throttled.
    if (kLaunchingProcessIsBackgrounded) {
      Platform::Current()
          ->CurrentThread()
          ->Scheduler()
          ->GetWebMainThreadSchedulerForTest()
          ->SetRendererBackgrounded(false);
    }
  }

  void RegisterMockedHttpURLLoad(const std::string& file_name) {
    RegisterMockedURLLoadFromBase(base_url_, file_name);
  }

  void RegisterMockedChromeURLLoad(const std::string& file_name) {
    RegisterMockedURLLoadFromBase(chrome_url_, file_name);
  }

  void RegisterMockedURLLoadFromBase(const std::string& base_url,
                                     const std::string& file_name) {
    URLTestHelpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name));
  }

  void RegisterMockedHttpURLLoadWithCSP(const std::string& file_name,
                                        const std::string& csp,
                                        bool report_only = false) {
    WebURLResponse response;
    response.SetMIMEType("text/html");
    response.AddHTTPHeaderField(
        report_only ? WebString("Content-Security-Policy-Report-Only")
                    : WebString("Content-Security-Policy"),
        WebString::FromUTF8(csp));
    std::string full_string = base_url_ + file_name;
    URLTestHelpers::RegisterMockedURLLoadWithCustomResponse(
        ToKURL(full_string),
        test::CoreTestDataPath(WebString::FromUTF8(file_name)), response);
  }

  void RegisterMockedHttpURLLoadWithMimeType(const std::string& file_name,
                                             const std::string& mime_type) {
    URLTestHelpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url_), test::CoreTestDataPath(),
        WebString::FromUTF8(file_name), WebString::FromUTF8(mime_type));
  }

  static void ConfigureCompositingWebView(WebSettings* settings) {
    settings->SetAcceleratedCompositingEnabled(true);
    settings->SetPreferCompositingToLCDTextEnabled(true);
  }

  static void ConfigureAndroid(WebSettings* settings) {
    settings->SetViewportMetaEnabled(true);
    settings->SetViewportEnabled(true);
    settings->SetMainFrameResizesAreOrientationChanges(true);
    settings->SetShrinksViewportContentToFit(true);
    settings->SetViewportStyle(WebViewportStyle::kMobile);
  }

  static void ConfigureLoadsImagesAutomatically(WebSettings* settings) {
    settings->SetLoadsImagesAutomatically(true);
  }

  void InitializeTextSelectionWebView(
      const std::string& url,
      FrameTestHelpers::WebViewHelper* web_view_helper) {
    web_view_helper->InitializeAndLoad(url);
    web_view_helper->GetWebView()->GetSettings()->SetDefaultFontSize(12);
    web_view_helper->Resize(WebSize(640, 480));
  }

  std::unique_ptr<DragImage> NodeImageTestSetup(
      FrameTestHelpers::WebViewHelper* web_view_helper,
      const std::string& testcase) {
    RegisterMockedHttpURLLoad("nodeimage.html");
    web_view_helper->InitializeAndLoad(base_url_ + "nodeimage.html");
    web_view_helper->Resize(WebSize(640, 480));
    LocalFrame* frame =
        ToLocalFrame(web_view_helper->GetWebView()->GetPage()->MainFrame());
    DCHECK(frame);
    Element* element = frame->GetDocument()->getElementById(testcase.c_str());
    return DataTransfer::NodeImage(*frame, *element);
  }

  void RemoveElementById(WebLocalFrameImpl* frame, const AtomicString& id) {
    Element* element = frame->GetFrame()->GetDocument()->getElementById(id);
    DCHECK(element);
    element->remove();
  }

  // Both sets the inner html and runs the document lifecycle.
  void InitializeWithHTML(LocalFrame& frame, const String& html_content) {
    frame.GetDocument()->body()->SetInnerHTMLFromString(html_content);
    frame.GetDocument()->View()->UpdateAllLifecyclePhases();
  }

  WebFrame* LastChild(WebFrame* frame) { return frame->last_child_; }
  WebFrame* PreviousSibling(WebFrame* frame) {
    return frame->previous_sibling_;
  }
  void SwapAndVerifyFirstChildConsistency(const char* const message,
                                          WebFrame* parent,
                                          WebFrame* new_child);
  void SwapAndVerifyMiddleChildConsistency(const char* const message,
                                           WebFrame* parent,
                                           WebFrame* new_child);
  void SwapAndVerifyLastChildConsistency(const char* const message,
                                         WebFrame* parent,
                                         WebFrame* new_child);
  void SwapAndVerifySubframeConsistency(const char* const message,
                                        WebFrame* parent,
                                        WebFrame* new_child);

  int NumMarkersInRange(const Document* document,
                        const EphemeralRange& range,
                        DocumentMarker::MarkerTypes marker_types) {
    Node* start_container = range.StartPosition().ComputeContainerNode();
    unsigned start_offset = static_cast<unsigned>(
        range.StartPosition().ComputeOffsetInContainerNode());

    Node* end_container = range.EndPosition().ComputeContainerNode();
    unsigned end_offset = static_cast<unsigned>(
        range.EndPosition().ComputeOffsetInContainerNode());

    int node_count = 0;
    for (Node& node : range.Nodes()) {
      const DocumentMarkerVector& markers_in_node =
          document->Markers().MarkersFor(&node, marker_types);
      node_count += std::count_if(
          markers_in_node.begin(), markers_in_node.end(),
          [start_offset, end_offset, &node, &start_container,
           &end_container](const DocumentMarker* marker) {
            if (node == start_container && marker->EndOffset() <= start_offset)
              return false;
            if (node == end_container && marker->StartOffset() >= end_offset)
              return false;
            return true;
          });
    }

    return node_count;
  }

  static void GetElementAndCaretBonundsForFocusedEditableElement(
      FrameTestHelpers::WebViewHelper& helper,
      IntRect& element_bounds,
      IntRect& caret_bounds) {
    Element* element = helper.GetWebView()->FocusedElement();
    WebRect caret_in_viewport, unused;
    helper.GetWebView()->SelectionBounds(caret_in_viewport, unused);
    caret_bounds =
        helper.GetWebView()->GetPage()->GetVisualViewport().ViewportToRootFrame(
            caret_in_viewport);
    element_bounds = element->GetDocument().View()->AbsoluteToRootFrame(
        PixelSnappedIntRect(element->Node::BoundingBox()));
  }

  std::string base_url_;
  std::string not_base_url_;
  std::string chrome_url_;
};

typedef bool TestParamRootLayerScrolling;
class ParameterizedWebFrameTest
    : public testing::WithParamInterface<TestParamRootLayerScrolling>,
      private ScopedRootLayerScrollingForTest,
      public WebFrameTest {
 public:
  ParameterizedWebFrameTest() : ScopedRootLayerScrollingForTest(GetParam()) {}
};

INSTANTIATE_TEST_CASE_P(All, ParameterizedWebFrameTest, testing::Bool());

TEST_P(ParameterizedWebFrameTest, ContentText) {
  RegisterMockedHttpURLLoad("iframes_test.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");
  RegisterMockedHttpURLLoad("invisible_iframe.html");
  RegisterMockedHttpURLLoad("zero_sized_iframe.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "iframes_test.html");

  // Now retrieve the frames text and test it only includes visible elements.
  std::string content = WebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_NE(std::string::npos, content.find(" visible paragraph"));
  EXPECT_NE(std::string::npos, content.find(" visible iframe"));
  EXPECT_EQ(std::string::npos, content.find(" invisible pararaph"));
  EXPECT_EQ(std::string::npos, content.find(" invisible iframe"));
  EXPECT_EQ(std::string::npos, content.find("iframe with zero size"));
}

TEST_P(ParameterizedWebFrameTest, FrameForEnteredContext) {
  RegisterMockedHttpURLLoad("iframes_test.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");
  RegisterMockedHttpURLLoad("invisible_iframe.html");
  RegisterMockedHttpURLLoad("zero_sized_iframe.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "iframes_test.html");

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  EXPECT_EQ(web_view_helper.GetWebView()->MainFrame(),
            WebLocalFrame::FrameForContext(web_view_helper.GetWebView()
                                               ->MainFrameImpl()
                                               ->MainWorldScriptContext()));
  EXPECT_EQ(web_view_helper.GetWebView()->MainFrame()->FirstChild(),
            WebLocalFrame::FrameForContext(web_view_helper.GetWebView()
                                               ->MainFrame()
                                               ->FirstChild()
                                               ->ToWebLocalFrame()
                                               ->MainWorldScriptContext()));
}

class ScriptExecutionCallbackHelper : public WebScriptExecutionCallback {
 public:
  explicit ScriptExecutionCallbackHelper(v8::Local<v8::Context> context)
      : did_complete_(false), bool_value_(false), context_(context) {}
  ~ScriptExecutionCallbackHelper() override = default;

  bool DidComplete() const { return did_complete_; }
  const String& StringValue() const { return string_value_; }
  bool BoolValue() { return bool_value_; }

 private:
  // WebScriptExecutionCallback:
  void Completed(const WebVector<v8::Local<v8::Value>>& values) override {
    did_complete_ = true;
    if (!values.IsEmpty()) {
      if (values[0]->IsString()) {
        string_value_ =
            ToCoreString(values[0]->ToString(context_).ToLocalChecked());
      } else if (values[0]->IsBoolean()) {
        bool_value_ = values[0].As<v8::Boolean>()->Value();
      }
    }
  }

  bool did_complete_;
  String string_value_;
  bool bool_value_;
  v8::Local<v8::Context> context_;
};

TEST_P(ParameterizedWebFrameTest, RequestExecuteScript) {
  RegisterMockedHttpURLLoad("foo.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  ScriptExecutionCallbackHelper callback_helper(
      web_view_helper.LocalMainFrame()->MainWorldScriptContext());
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->RequestExecuteScriptAndReturnValue(
          WebScriptSource(WebString("'hello';")), false, &callback_helper);
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("hello", callback_helper.StringValue());
}

TEST_P(ParameterizedWebFrameTest, SuspendedRequestExecuteScript) {
  RegisterMockedHttpURLLoad("foo.html");
  RegisterMockedHttpURLLoad("bar.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  ScriptExecutionCallbackHelper callback_helper(
      web_view_helper.LocalMainFrame()->MainWorldScriptContext());

  // Suspend scheduled tasks so the script doesn't run.
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->GetFrame()
      ->GetDocument()
      ->PauseScheduledTasks();
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->RequestExecuteScriptAndReturnValue(
          WebScriptSource(WebString("'hello';")), false, &callback_helper);
  RunPendingTasks();
  EXPECT_FALSE(callback_helper.DidComplete());

  // If the frame navigates, pending scripts should be removed, but the callback
  // should always be ran.
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "bar.html");
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ(String(), callback_helper.StringValue());
}

TEST_P(ParameterizedWebFrameTest, RequestExecuteV8Function) {
  RegisterMockedHttpURLLoad("foo.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  auto callback = [](const v8::FunctionCallbackInfo<v8::Value>& info) {
    info.GetReturnValue().Set(V8String(info.GetIsolate(), "hello"));
  };

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  v8::Local<v8::Context> context =
      web_view_helper.LocalMainFrame()->MainWorldScriptContext();
  ScriptExecutionCallbackHelper callback_helper(context);
  v8::Local<v8::Function> function =
      v8::Function::New(context, callback).ToLocalChecked();
  web_view_helper.GetWebView()
      ->MainFrame()
      ->ToWebLocalFrame()
      ->RequestExecuteV8Function(context, function,
                                 v8::Undefined(context->GetIsolate()), 0,
                                 nullptr, &callback_helper);
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("hello", callback_helper.StringValue());
}

TEST_P(ParameterizedWebFrameTest, RequestExecuteV8FunctionWhileSuspended) {
  DisableRendererSchedulerThrottling();
  RegisterMockedHttpURLLoad("foo.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  auto callback = [](const v8::FunctionCallbackInfo<v8::Value>& info) {
    info.GetReturnValue().Set(V8String(info.GetIsolate(), "hello"));
  };

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  v8::Local<v8::Context> context =
      web_view_helper.LocalMainFrame()->MainWorldScriptContext();

  // Suspend scheduled tasks so the script doesn't run.
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  main_frame->GetFrame()->GetDocument()->PauseScheduledTasks();

  ScriptExecutionCallbackHelper callback_helper(context);
  v8::Local<v8::Function> function =
      v8::Function::New(context, callback).ToLocalChecked();
  main_frame->RequestExecuteV8Function(context, function,
                                       v8::Undefined(context->GetIsolate()), 0,
                                       nullptr, &callback_helper);
  RunPendingTasks();
  EXPECT_FALSE(callback_helper.DidComplete());

  main_frame->GetFrame()->GetDocument()->UnpauseScheduledTasks();
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ("hello", callback_helper.StringValue());
}

TEST_P(ParameterizedWebFrameTest,
       RequestExecuteV8FunctionWhileSuspendedWithUserGesture) {
  DisableRendererSchedulerThrottling();
  RegisterMockedHttpURLLoad("foo.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");

  auto callback = [](const v8::FunctionCallbackInfo<v8::Value>& info) {
    info.GetReturnValue().Set(v8::Boolean::New(
        info.GetIsolate(), UserGestureIndicator::ProcessingUserGesture()));
  };

  // Suspend scheduled tasks so the script doesn't run.
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  main_frame->GetFrame()->GetDocument()->PauseScheduledTasks();

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  v8::Local<v8::Context> context =
      web_view_helper.LocalMainFrame()->MainWorldScriptContext();

  std::unique_ptr<UserGestureIndicator> indicator = Frame::NotifyUserActivation(
      main_frame->GetFrame(), UserGestureToken::kNewGesture);
  ScriptExecutionCallbackHelper callback_helper(context);
  v8::Local<v8::Function> function =
      v8::Function::New(context, callback).ToLocalChecked();
  main_frame->RequestExecuteV8Function(
      main_frame->MainWorldScriptContext(), function,
      v8::Undefined(context->GetIsolate()), 0, nullptr, &callback_helper);

  RunPendingTasks();
  EXPECT_FALSE(callback_helper.DidComplete());

  main_frame->GetFrame()->GetDocument()->UnpauseScheduledTasks();
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ(true, callback_helper.BoolValue());
}

class ScriptNotPausedCallbackHelper {
 public:
  ScriptNotPausedCallbackHelper() = default;
  ~ScriptNotPausedCallbackHelper() = default;

  WebLocalFrame::PausableTaskCallback GetCallback() {
    return WTF::Bind(&ScriptNotPausedCallbackHelper::Run,
                     WTF::Unretained(this));
  }

  void set_closure(base::OnceClosure closure) { closure_ = std::move(closure); }
  const base::Optional<WebLocalFrame::PausableTaskResult>& result() const {
    return result_;
  }

 private:
  void Run(WebLocalFrame::PausableTaskResult result) {
    ASSERT_FALSE(result_) << "Callback invoked multiple times!";
    result_ = result;
    if (closure_)
      std::move(*closure_).Run();
  }

  base::Optional<WebLocalFrame::PausableTaskResult> result_;
  base::Optional<base::OnceClosure> closure_;
};

TEST_P(ParameterizedWebFrameTest, CallingPostPausableTaskWhileNotPaused) {
  RegisterMockedHttpURLLoad("foo.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();

  ScriptState::Scope scope(ToScriptStateForMainWorld(main_frame->GetFrame()));

  ScriptNotPausedCallbackHelper callback_helper;
  main_frame->PostPausableTask(callback_helper.GetCallback());
  RunPendingTasks();

  ASSERT_TRUE(callback_helper.result());
  EXPECT_EQ(WebLocalFrame::PausableTaskResult::kReady,
            *callback_helper.result());
}

// Flaky on Android: crbug.com/804892.
#if defined(OS_ANDROID)
TEST_P(ParameterizedWebFrameTest, DISABLED_CallingPostPausableTaskWhilePaused)
#else
TEST_P(ParameterizedWebFrameTest, CallingPostPausableTaskWhilePaused)
#endif
{
  RegisterMockedHttpURLLoad("foo.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();

  ScriptState::Scope scope(ToScriptStateForMainWorld(main_frame->GetFrame()));

  // Suspend scheduled tasks so the script doesn't run.
  main_frame->GetFrame()->GetDocument()->PauseScheduledTasks();

  ScriptNotPausedCallbackHelper callback_helper;
  main_frame->PostPausableTask(callback_helper.GetCallback());
  RunPendingTasks();
  EXPECT_FALSE(callback_helper.result());

  main_frame->GetFrame()->GetDocument()->UnpauseScheduledTasks();
  RunPendingTasks();
  ASSERT_TRUE(callback_helper.result());
  EXPECT_EQ(WebLocalFrame::PausableTaskResult::kReady,
            *callback_helper.result());
}

TEST_P(ParameterizedWebFrameTest, CallingPostPausableTaskAndNavigating) {
  RegisterMockedHttpURLLoad("foo.html");
  RegisterMockedHttpURLLoad("bar.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();

  ScriptState::Scope scope(ToScriptStateForMainWorld(main_frame->GetFrame()));

  // Suspend scheduled tasks so the script doesn't run.
  main_frame->GetFrame()->GetDocument()->PauseScheduledTasks();

  ScriptNotPausedCallbackHelper callback_helper;
  main_frame->PostPausableTask(callback_helper.GetCallback());
  RunPendingTasks();
  EXPECT_FALSE(callback_helper.result());

  // If the frame navigates, pending scripts should be removed, but the callback
  // should always be ran.
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "bar.html");
  ASSERT_TRUE(callback_helper.result());
  EXPECT_EQ(WebLocalFrame::PausableTaskResult::kContextInvalidOrDestroyed,
            *callback_helper.result());
}

TEST_P(ParameterizedWebFrameTest,
       CallingPostPausableTaskAndDestroyingTheContext) {
  RegisterMockedHttpURLLoad("foo.html");
  RegisterMockedHttpURLLoad("bar.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();

  auto navigate_frame = [](FrameTestHelpers::WebViewHelper* web_view_helper,
                           const std::string& url) {
    FrameTestHelpers::LoadFrame(web_view_helper->GetWebView()->MainFrameImpl(),
                                url);
  };

  ScriptNotPausedCallbackHelper callback_helper;
  // Navigate the frame when the helper is notified that script can run. This
  // will invalidate the context immediately.
  callback_helper.set_closure(WTF::Bind(navigate_frame,
                                        WTF::Unretained(&web_view_helper),
                                        base_url_ + "bar.html"));

  ScriptState::Scope scope(ToScriptStateForMainWorld(main_frame->GetFrame()));

  main_frame->PostPausableTask(callback_helper.GetCallback());
  RunPendingTasks();

  ASSERT_TRUE(callback_helper.result());
  EXPECT_EQ(WebLocalFrame::PausableTaskResult::kReady,
            *callback_helper.result());
}

TEST_P(ParameterizedWebFrameTest, IframeScriptRemovesSelf) {
  RegisterMockedHttpURLLoad("single_iframe.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "single_iframe.html");

  v8::HandleScope scope(v8::Isolate::GetCurrent());
  ScriptExecutionCallbackHelper callback_helper(
      web_view_helper.LocalMainFrame()->MainWorldScriptContext());
  web_view_helper.GetWebView()
      ->MainFrame()
      ->FirstChild()
      ->ToWebLocalFrame()
      ->RequestExecuteScriptAndReturnValue(
          WebScriptSource(WebString(
              "var iframe = "
              "window.top.document.getElementsByTagName('iframe')[0]; "
              "window.top.document.body.removeChild(iframe); 'hello';")),
          false, &callback_helper);
  RunPendingTasks();
  EXPECT_TRUE(callback_helper.DidComplete());
  EXPECT_EQ(String(), callback_helper.StringValue());
}

TEST_P(ParameterizedWebFrameTest, FormWithNullFrame) {
  RegisterMockedHttpURLLoad("form.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "form.html");

  WebVector<WebFormElement> forms;
  web_view_helper.LocalMainFrame()->GetDocument().Forms(forms);
  web_view_helper.Reset();

  EXPECT_EQ(forms.size(), 1U);

  // This test passes if this doesn't crash.
  WebSearchableFormData searchable_data_form(forms[0]);
}

TEST_P(ParameterizedWebFrameTest, ChromePageJavascript) {
  RegisterMockedChromeURLLoad("history.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(chrome_url_ + "history.html");

  // Try to run JS against the chrome-style URL.
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              "javascript:document.body.appendChild(document."
                              "createTextNode('Clobbered'))");

  // Now retrieve the frame's text and ensure it was modified by running
  // javascript.
  std::string content = WebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_NE(std::string::npos, content.find("Clobbered"));
}

TEST_P(ParameterizedWebFrameTest, ChromePageNoJavascript) {
  RegisterMockedChromeURLLoad("history.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(chrome_url_ + "history.html");

  // Try to run JS against the chrome-style URL after prohibiting it.
  WebSecurityPolicy::RegisterURLSchemeAsNotAllowingJavascriptURLs("chrome");
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              "javascript:document.body.appendChild(document."
                              "createTextNode('Clobbered'))");

  // Now retrieve the frame's text and ensure it wasn't modified by running
  // javascript.
  std::string content = WebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_EQ(std::string::npos, content.find("Clobbered"));
}

TEST_P(ParameterizedWebFrameTest, LocationSetHostWithMissingPort) {
  std::string file_name = "print-location-href.html";
  RegisterMockedHttpURLLoad(file_name);
  RegisterMockedURLLoadFromBase("http://internal.test:0/", file_name);

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + file_name);

  // Setting host to "hostname:" should be treated as "hostname:0".
  FrameTestHelpers::LoadFrame(
      web_view_helper.GetWebView()->MainFrameImpl(),
      "javascript:location.host = 'internal.test:'; void 0;");

  FrameTestHelpers::LoadFrame(
      web_view_helper.GetWebView()->MainFrameImpl(),
      "javascript:document.body.textContent = location.href; void 0;");

  std::string content = WebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_EQ("http://internal.test:0/" + file_name, content);
}

TEST_P(ParameterizedWebFrameTest, LocationSetEmptyPort) {
  std::string file_name = "print-location-href.html";
  RegisterMockedHttpURLLoad(file_name);
  RegisterMockedURLLoadFromBase("http://internal.test:0/", file_name);

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + file_name);

  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              "javascript:location.port = ''; void 0;");

  FrameTestHelpers::LoadFrame(
      web_view_helper.GetWebView()->MainFrameImpl(),
      "javascript:document.body.textContent = location.href; void 0;");

  std::string content = WebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_EQ("http://internal.test:0/" + file_name, content);
}

class EvaluateOnLoadWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  EvaluateOnLoadWebFrameClient() : executing_(false), was_executed_(false) {}
  ~EvaluateOnLoadWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidClearWindowObject() override {
    EXPECT_FALSE(executing_);
    was_executed_ = true;
    executing_ = true;
    v8::HandleScope handle_scope(v8::Isolate::GetCurrent());
    Frame()->ExecuteScriptAndReturnValue(
        WebScriptSource(WebString("window.someProperty = 42;")));
    executing_ = false;
  }

  bool executing_;
  bool was_executed_;
};

TEST_P(ParameterizedWebFrameTest, DidClearWindowObjectIsNotRecursive) {
  EvaluateOnLoadWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", &web_frame_client);
  EXPECT_TRUE(web_frame_client.was_executed_);
}

class CSSCallbackWebFrameClient : public FrameTestHelpers::TestWebFrameClient {
 public:
  CSSCallbackWebFrameClient() : update_count_(0) {}
  ~CSSCallbackWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidMatchCSS(
      const WebVector<WebString>& newly_matching_selectors,
      const WebVector<WebString>& stopped_matching_selectors) override;

  std::map<WebLocalFrame*, std::set<std::string>> matched_selectors_;
  int update_count_;
};

void CSSCallbackWebFrameClient::DidMatchCSS(
    const WebVector<WebString>& newly_matching_selectors,
    const WebVector<WebString>& stopped_matching_selectors) {
  ++update_count_;
  std::set<std::string>& frame_selectors = matched_selectors_[Frame()];
  for (size_t i = 0; i < newly_matching_selectors.size(); ++i) {
    std::string selector = newly_matching_selectors[i].Utf8();
    EXPECT_EQ(0U, frame_selectors.count(selector)) << selector;
    frame_selectors.insert(selector);
  }
  for (size_t i = 0; i < stopped_matching_selectors.size(); ++i) {
    std::string selector = stopped_matching_selectors[i].Utf8();
    EXPECT_EQ(1U, frame_selectors.count(selector)) << selector;
    frame_selectors.erase(selector);
  }
}

class WebFrameCSSCallbackTest : public testing::Test {
 protected:
  WebFrameCSSCallbackTest() {
    frame_ = helper_.InitializeAndLoad("about:blank", &client_)
                 ->MainFrame()
                 ->ToWebLocalFrame();
  }

  ~WebFrameCSSCallbackTest() {
    EXPECT_EQ(1U, client_.matched_selectors_.size());
  }

  WebDocument Doc() const { return frame_->GetDocument(); }

  int UpdateCount() const { return client_.update_count_; }

  const std::set<std::string>& MatchedSelectors() {
    return client_.matched_selectors_[frame_];
  }

  void LoadHTML(const std::string& html) {
    FrameTestHelpers::LoadHTMLString(frame_, html, ToKURL("about:blank"));
  }

  void ExecuteScript(const WebString& code) {
    frame_->ExecuteScript(WebScriptSource(code));
    frame_->View()->UpdateAllLifecyclePhases();
    RunPendingTasks();
  }

  CSSCallbackWebFrameClient client_;
  FrameTestHelpers::WebViewHelper helper_;
  WebLocalFrame* frame_;
};

TEST_F(WebFrameCSSCallbackTest, AuthorStyleSheet) {
  LoadHTML(
      "<style>"
      // This stylesheet checks that the internal property and value can't be
      // set by a stylesheet, only WebDocument::watchCSSSelectors().
      "div.initial_on { -internal-callback: none; }"
      "div.initial_off { -internal-callback: -internal-presence; }"
      "</style>"
      "<div class=\"initial_on\"></div>"
      "<div class=\"initial_off\"></div>");

  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("div.initial_on"));
  frame_->GetDocument().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->UpdateAllLifecyclePhases();
  RunPendingTasks();
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("div.initial_on"));

  // Check that adding a watched selector calls back for already-present nodes.
  selectors.push_back(WebString::FromUTF8("div.initial_off"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->UpdateAllLifecyclePhases();
  RunPendingTasks();
  EXPECT_EQ(2, UpdateCount());
  EXPECT_THAT(MatchedSelectors(),
              ElementsAre("div.initial_off", "div.initial_on"));

  // Check that we can turn off callbacks for certain selectors.
  Doc().WatchCSSSelectors(WebVector<WebString>());
  frame_->View()->UpdateAllLifecyclePhases();
  RunPendingTasks();
  EXPECT_EQ(3, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre());
}

TEST_F(WebFrameCSSCallbackTest, SharedComputedStyle) {
  // Check that adding an element calls back when it matches an existing rule.
  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));

  ExecuteScript(
      "i1 = document.createElement('span');"
      "i1.id = 'first_span';"
      "document.body.appendChild(i1)");
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  // Adding a second element that shares a ComputedStyle shouldn't call back.
  // We use <span>s to avoid default style rules that can set
  // ComputedStyle::unique().
  ExecuteScript(
      "i2 = document.createElement('span');"
      "i2.id = 'second_span';"
      "i1 = document.getElementById('first_span');"
      "i1.parentNode.insertBefore(i2, i1.nextSibling);");
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  // Removing the first element shouldn't call back.
  ExecuteScript(
      "i1 = document.getElementById('first_span');"
      "i1.parentNode.removeChild(i1);");
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  // But removing the second element *should* call back.
  ExecuteScript(
      "i2 = document.getElementById('second_span');"
      "i2.parentNode.removeChild(i2);");
  EXPECT_EQ(2, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre());
}

TEST_F(WebFrameCSSCallbackTest, CatchesAttributeChange) {
  LoadHTML("<span></span>");

  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span[attr=\"value\"]"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  RunPendingTasks();

  EXPECT_EQ(0, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre());

  ExecuteScript(
      "document.querySelector('span').setAttribute('attr', 'value');");
  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span[attr=\"value\"]"));
}

TEST_F(WebFrameCSSCallbackTest, DisplayNone) {
  LoadHTML("<div style='display:none'><span></span></div>");

  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  RunPendingTasks();

  EXPECT_EQ(0, UpdateCount()) << "Don't match elements in display:none trees.";

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'block';");
  EXPECT_EQ(1, UpdateCount()) << "Match elements when they become displayed.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'none';");
  EXPECT_EQ(2, UpdateCount())
      << "Unmatch elements when they become undisplayed.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre());

  ExecuteScript(
      "s = document.querySelector('span');"
      "s.style.display = 'none';");
  EXPECT_EQ(2, UpdateCount())
      << "No effect from no-display'ing a span that's already undisplayed.";

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'block';");
  EXPECT_EQ(2, UpdateCount())
      << "No effect from displaying a div whose span is display:none.";

  ExecuteScript(
      "s = document.querySelector('span');"
      "s.style.display = 'inline';");
  EXPECT_EQ(3, UpdateCount())
      << "Now the span is visible and produces a callback.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "s = document.querySelector('span');"
      "s.style.display = 'none';");
  EXPECT_EQ(4, UpdateCount())
      << "Undisplaying the span directly should produce another callback.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre());
}

TEST_F(WebFrameCSSCallbackTest, DisplayContents) {
  LoadHTML("<div style='display:contents'><span></span></div>");

  Vector<WebString> selectors(1u, WebString::FromUTF8("span"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->UpdateAllLifecyclePhases();
  RunPendingTasks();

  EXPECT_EQ(1, UpdateCount()) << "Match elements in display:contents trees.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "s = document.querySelector('span');"
      "s.style.display = 'contents';");
  EXPECT_EQ(1, UpdateCount()) << "Match elements which are display:contents.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'block';");
  EXPECT_EQ(1, UpdateCount())
      << "Still match display:contents after parent becomes display:block.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "d = document.querySelector('div');"
      "d.style.display = 'none';");
  EXPECT_EQ(2, UpdateCount())
      << "No longer matched when parent becomes display:none.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre());
}

TEST_F(WebFrameCSSCallbackTest, Reparenting) {
  LoadHTML(
      "<div id='d1'><span></span></div>"
      "<div id='d2'></div>");

  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->UpdateAllLifecyclePhases();
  RunPendingTasks();

  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));

  ExecuteScript(
      "s = document.querySelector('span');"
      "d2 = document.getElementById('d2');"
      "d2.appendChild(s);");
  EXPECT_EQ(1, UpdateCount()) << "Just moving an element that continues to "
                                 "match shouldn't send a spurious callback.";
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"));
}

TEST_F(WebFrameCSSCallbackTest, MultiSelector) {
  LoadHTML("<span></span>");

  // Check that selector lists match as the whole list, not as each element
  // independently.
  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  selectors.push_back(WebString::FromUTF8("span,p"));
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->UpdateAllLifecyclePhases();
  RunPendingTasks();

  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span", "span, p"));
}

TEST_F(WebFrameCSSCallbackTest, InvalidSelector) {
  LoadHTML("<p><span></span></p>");

  // Build a list with one valid selector and one invalid.
  Vector<WebString> selectors;
  selectors.push_back(WebString::FromUTF8("span"));
  selectors.push_back(WebString::FromUTF8("["));       // Invalid.
  selectors.push_back(WebString::FromUTF8("p span"));  // Not compound.
  Doc().WatchCSSSelectors(WebVector<WebString>(selectors));
  frame_->View()->UpdateAllLifecyclePhases();
  RunPendingTasks();

  EXPECT_EQ(1, UpdateCount());
  EXPECT_THAT(MatchedSelectors(), ElementsAre("span"))
      << "An invalid selector shouldn't prevent other selectors from matching.";
}

TEST_P(ParameterizedWebFrameTest, DispatchMessageEventWithOriginCheck) {
  RegisterMockedHttpURLLoad("postmessage_test.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "postmessage_test.html");

  // Send a message with the correct origin.
  WebSecurityOrigin correct_origin(
      WebSecurityOrigin::Create(ToKURL(base_url_)));
  WebDocument document = web_view_helper.LocalMainFrame()->GetDocument();
  WebSerializedScriptValue data(WebSerializedScriptValue::CreateInvalid());
  WebDOMMessageEvent message(data, "http://origin.com");
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->DispatchMessageEventWithOriginCheck(correct_origin, message,
                                            false /* has_user_gesture */);

  // Send another message with incorrect origin.
  WebSecurityOrigin incorrect_origin(
      WebSecurityOrigin::Create(ToKURL(chrome_url_)));
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->DispatchMessageEventWithOriginCheck(incorrect_origin, message,
                                            false /* has_user_gesture */);

  // Verify that only the first addition is in the body of the page.
  std::string content = WebFrameContentDumper::DumpWebViewAsText(
                            web_view_helper.GetWebView(), 1024)
                            .Utf8();
  EXPECT_NE(std::string::npos, content.find("Message 1."));
  EXPECT_EQ(std::string::npos, content.find("Message 2."));
}

namespace {

scoped_refptr<SerializedScriptValue> SerializeString(
    const StringView& message,
    ScriptState* script_state) {
  // This is inefficient, but avoids duplicating serialization logic for the
  // sake of this test.
  NonThrowableExceptionState exception_state;
  ScriptState::Scope scope(script_state);
  V8ScriptValueSerializer serializer(script_state);
  return serializer.Serialize(V8String(script_state->GetIsolate(), message),
                              exception_state);
}

}  // namespace

TEST_P(ParameterizedWebFrameTest, PostMessageThenDetach) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");

  LocalFrame* frame =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame());
  NonThrowableExceptionState exception_state;
  scoped_refptr<SerializedScriptValue> message =
      SerializeString("message", ToScriptStateForMainWorld(frame));
  MessagePortArray message_ports;
  frame->DomWindow()->postMessage(message, message_ports, "*",
                                  frame->DomWindow(), exception_state);
  web_view_helper.Reset();
  EXPECT_FALSE(exception_state.HadException());

  // Success is not crashing.
  RunPendingTasks();
}

namespace {

class FixedLayoutTestWebViewClient
    : public FrameTestHelpers::TestWebViewClient {
 public:
  FixedLayoutTestWebViewClient() = default;
  ~FixedLayoutTestWebViewClient() override = default;

  // FrameTestHelpers::TestWebViewClient:
  WebScreenInfo GetScreenInfo() override { return screen_info_; }

  WebScreenInfo screen_info_;
};

class FakeCompositingWebViewClient : public FixedLayoutTestWebViewClient {};

// Helper function to set autosizing multipliers on a document.
bool SetTextAutosizingMultiplier(Document* document, float multiplier) {
  bool multiplier_set = false;
  for (LayoutObject* layout_object = document->GetLayoutView(); layout_object;
       layout_object = layout_object->NextInPreOrder()) {
    if (layout_object->Style()) {
      scoped_refptr<ComputedStyle> modified_style =
          ComputedStyle::Clone(layout_object->StyleRef());
      modified_style->SetTextAutosizingMultiplier(multiplier);
      EXPECT_EQ(multiplier, modified_style->TextAutosizingMultiplier());
      layout_object->SetStyleInternal(std::move(modified_style));
      multiplier_set = true;
    }
  }
  return multiplier_set;
}

// Helper function to check autosizing multipliers on a document.
bool CheckTextAutosizingMultiplier(Document* document, float multiplier) {
  bool multiplier_checked = false;
  for (LayoutObject* layout_object = document->GetLayoutView(); layout_object;
       layout_object = layout_object->NextInPreOrder()) {
    if (layout_object->Style() && layout_object->IsText()) {
      EXPECT_EQ(multiplier, layout_object->Style()->TextAutosizingMultiplier());
      multiplier_checked = true;
    }
  }
  return multiplier_checked;
}

}  // namespace

TEST_P(ParameterizedWebFrameTest,
       ChangeInFixedLayoutResetsTextAutosizingMultipliers) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FixedLayoutTestWebViewClient client;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);

  Document* document =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();
  document->GetSettings()->SetTextAutosizingEnabled(true);
  EXPECT_TRUE(document->GetSettings()->TextAutosizingEnabled());
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_TRUE(SetTextAutosizingMultiplier(document, 2));

  ViewportDescription description = document->GetViewportDescription();
  // Choose a width that's not going match the viewport width of the loaded
  // document.
  description.min_width = Length(100, blink::kFixed);
  description.max_width = Length(100, blink::kFixed);
  web_view_helper.GetWebView()->UpdatePageDefinedViewportConstraints(
      description);

  EXPECT_TRUE(CheckTextAutosizingMultiplier(document, 1));
}

TEST_P(ParameterizedWebFrameTest,
       WorkingTextAutosizingMultipliers_VirtualViewport) {
  const std::string html_file = "fixed_layout.html";
  RegisterMockedHttpURLLoad(html_file);

  FixedLayoutTestWebViewClient client;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + html_file, nullptr, &client,
                                    nullptr, ConfigureAndroid);

  Document* document =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();
  document->GetSettings()->SetTextAutosizingEnabled(true);
  EXPECT_TRUE(document->GetSettings()->TextAutosizingEnabled());

  web_view_helper.Resize(WebSize(490, 800));

  // Multiplier: 980 / 490 = 2.0
  EXPECT_TRUE(CheckTextAutosizingMultiplier(document, 2.0));
}

TEST_P(ParameterizedWebFrameTest,
       VisualViewportSetSizeInvalidatesTextAutosizingMultipliers) {
  RegisterMockedHttpURLLoad("iframe_reload.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");

  FixedLayoutTestWebViewClient client;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "iframe_reload.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);

  LocalFrame* main_frame =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame());
  Document* document = main_frame->GetDocument();
  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();
  document->GetSettings()->SetTextAutosizingEnabled(true);
  EXPECT_TRUE(document->GetSettings()->TextAutosizingEnabled());
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  for (Frame* frame = main_frame; frame; frame = frame->Tree().TraverseNext()) {
    if (!frame->IsLocalFrame())
      continue;
    EXPECT_TRUE(
        SetTextAutosizingMultiplier(ToLocalFrame(frame)->GetDocument(), 2));
    for (LayoutObject* layout_object =
             ToLocalFrame(frame)->GetDocument()->GetLayoutView();
         layout_object; layout_object = layout_object->NextInPreOrder()) {
      if (layout_object->IsText())
        EXPECT_FALSE(layout_object->NeedsLayout());
    }
  }

  frame_view->GetPage()->GetVisualViewport().SetSize(IntSize(200, 200));

  for (Frame* frame = main_frame; frame; frame = frame->Tree().TraverseNext()) {
    if (!frame->IsLocalFrame())
      continue;
    for (LayoutObject* layout_object =
             ToLocalFrame(frame)->GetDocument()->GetLayoutView();
         !layout_object; layout_object = layout_object->NextInPreOrder()) {
      if (layout_object->IsText())
        EXPECT_TRUE(layout_object->NeedsLayout());
    }
  }
}

TEST_P(ParameterizedWebFrameTest, ZeroHeightPositiveWidthNotIgnored) {
  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 1280;
  int viewport_height = 0;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->GetLayoutSize()
                                .Width());
  EXPECT_EQ(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->GetLayoutSize()
                                 .Height());
}

TEST_P(ParameterizedWebFrameTest,
       DeviceScaleFactorUsesDefaultWithoutViewportTag) {
  RegisterMockedHttpURLLoad("no_viewport_tag.html");

  int viewport_width = 640;
  int viewport_height = 480;

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 2;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "no_viewport_tag.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);

  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(
      2,
      web_view_helper.GetWebView()->GetPage()->DeviceScaleFactorDeprecated());

  // Device scale factor should be independent of page scale.
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(1, 2);
  web_view_helper.GetWebView()->SetPageScaleFactor(0.5);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(1, web_view_helper.GetWebView()->PageScaleFactor());

  // Force the layout to happen before leaving the test.
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
}

TEST_P(ParameterizedWebFrameTest, FixedLayoutInitializeAtMinimumScale) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "fixed_layout.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  int default_fixed_layout_width = 980;
  float minimum_page_scale_factor =
      viewport_width / (float)default_fixed_layout_width;
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->MinimumPageScaleFactor());

  // Assume the user has pinch zoomed to page scale factor 2.
  float user_pinch_page_scale_factor = 2;
  web_view_helper.GetWebView()->SetPageScaleFactor(
      user_pinch_page_scale_factor);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  // Make sure we don't reset to initial scale if the page continues to load.
  web_view_helper.GetWebView()->DidCommitLoad(false, false);
  web_view_helper.GetWebView()->DidChangeContentsSize();
  EXPECT_EQ(user_pinch_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  // Make sure we don't reset to initial scale if the viewport size changes.
  web_view_helper.Resize(WebSize(viewport_width, viewport_height + 100));
  EXPECT_EQ(user_pinch_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, WideDocumentInitializeAtMinimumScale) {
  RegisterMockedHttpURLLoad("wide_document.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "wide_document.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  int wide_document_width = 1500;
  float minimum_page_scale_factor = viewport_width / (float)wide_document_width;
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->MinimumPageScaleFactor());

  // Assume the user has pinch zoomed to page scale factor 2.
  float user_pinch_page_scale_factor = 2;
  web_view_helper.GetWebView()->SetPageScaleFactor(
      user_pinch_page_scale_factor);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  // Make sure we don't reset to initial scale if the page continues to load.
  web_view_helper.GetWebView()->DidCommitLoad(false, false);
  web_view_helper.GetWebView()->DidChangeContentsSize();
  EXPECT_EQ(user_pinch_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  // Make sure we don't reset to initial scale if the viewport size changes.
  web_view_helper.Resize(WebSize(viewport_width, viewport_height + 100));
  EXPECT_EQ(user_pinch_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, DelayedViewportInitialScale) {
  RegisterMockedHttpURLLoad("viewport-auto-initial-scale.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-auto-initial-scale.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(0.25f, web_view_helper.GetWebView()->PageScaleFactor());

  Document* document =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();
  ViewportDescription description = document->GetViewportDescription();
  description.zoom = 2;
  document->SetViewportDescription(description);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(2, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, setLoadWithOverviewModeToFalse) {
  RegisterMockedHttpURLLoad("viewport-auto-initial-scale.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-auto-initial-scale.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  // The page must be displayed at 100% zoom.
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest,
       SetLoadWithOverviewModeToFalseAndNoWideViewport) {
  RegisterMockedHttpURLLoad("large-div.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "large-div.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  // The page must be displayed at 100% zoom, despite that it hosts a wide div
  // element.
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, NoWideViewportIgnoresPageViewportWidth) {
  RegisterMockedHttpURLLoad("viewport-auto-initial-scale.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-auto-initial-scale.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  // The page sets viewport width to 3000, but with UseWideViewport == false is
  // must be ignored.
  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->ContentsSize()
                                .Width());
  EXPECT_EQ(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->ContentsSize()
                                 .Height());
}

TEST_P(ParameterizedWebFrameTest,
       NoWideViewportIgnoresPageViewportWidthButAccountsScale) {
  RegisterMockedHttpURLLoad("viewport-wide-2x-initial-scale.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-wide-2x-initial-scale.html", nullptr, &client,
      nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  // The page sets viewport width to 3000, but with UseWideViewport == false it
  // must be ignored while the initial scale specified by the page must be
  // accounted.
  EXPECT_EQ(viewport_width / 2, web_view_helper.GetWebView()
                                    ->MainFrameImpl()
                                    ->GetFrameView()
                                    ->ContentsSize()
                                    .Width());
  EXPECT_EQ(viewport_height / 2, web_view_helper.GetWebView()
                                     ->MainFrameImpl()
                                     ->GetFrameView()
                                     ->ContentsSize()
                                     .Height());
}

TEST_P(ParameterizedWebFrameTest, WideViewportSetsTo980WithoutViewportTag) {
  RegisterMockedHttpURLLoad("no_viewport_tag.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "no_viewport_tag.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(980, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->LayoutViewportScrollableArea()
                     ->ContentsSize()
                     .Width());
  EXPECT_EQ(980.0 / viewport_width * viewport_height,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->LayoutViewportScrollableArea()
                ->ContentsSize()
                .Height());
}

TEST_P(ParameterizedWebFrameTest, WideViewportSetsTo980WithXhtmlMp) {
  RegisterMockedHttpURLLoad("viewport/viewport-legacy-xhtmlmp.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  FrameTestHelpers::LoadFrame(
      web_view_helper.GetWebView()->MainFrameImpl(),
      base_url_ + "viewport/viewport-legacy-xhtmlmp.html");

  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->ContentsSize()
                                .Width());
  EXPECT_EQ(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->ContentsSize()
                                 .Height());
}

TEST_P(ParameterizedWebFrameTest, NoWideViewportAndHeightInMeta) {
  RegisterMockedHttpURLLoad("viewport-height-1000.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport-height-1000.html",
                                    nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->ContentsSize()
                                .Width());
}

TEST_P(ParameterizedWebFrameTest, WideViewportSetsTo980WithAutoWidth) {
  RegisterMockedHttpURLLoad("viewport-2x-initial-scale.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-2x-initial-scale.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(980, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->ContentsSize()
                     .Width());
  EXPECT_EQ(980.0 / viewport_width * viewport_height,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->ContentsSize()
                .Height());
}

TEST_P(ParameterizedWebFrameTest,
       PageViewportInitialScaleOverridesLoadWithOverviewMode) {
  RegisterMockedHttpURLLoad("viewport-wide-2x-initial-scale.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-wide-2x-initial-scale.html", nullptr, &client,
      nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  // The page must be displayed at 200% zoom, as specified in its viewport meta
  // tag.
  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, setInitialPageScaleFactorPermanently) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  float enforced_page_scale_factor = 2.0f;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  int viewport_width = 640;
  int viewport_height = 480;
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  web_view_helper.GetWebView()->SetInitialPageScaleOverride(-1);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(1.0, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest,
       PermanentInitialPageScaleFactorOverridesLoadWithOverviewMode) {
  RegisterMockedHttpURLLoad("viewport-auto-initial-scale.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;
  float enforced_page_scale_factor = 0.5f;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-auto-initial-scale.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest,
       PermanentInitialPageScaleFactorOverridesPageViewportInitialScale) {
  RegisterMockedHttpURLLoad("viewport-wide-2x-initial-scale.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;
  float enforced_page_scale_factor = 0.5f;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-wide-2x-initial-scale.html", nullptr, &client,
      nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest,
       SmallPermanentInitialPageScaleFactorIsClobbered) {
  const char* pages[] = {
      // These pages trigger the clobbering condition. There must be a matching
      // item in "pageScaleFactors" array.
      "viewport-device-0.5x-initial-scale.html",
      "viewport-initial-scale-1.html",
      // These ones do not.
      "viewport-auto-initial-scale.html",
      "viewport-target-densitydpi-device-and-fixed-width.html"};
  float page_scale_factors[] = {0.5f, 1.0f};
  for (size_t i = 0; i < arraysize(pages); ++i)
    RegisterMockedHttpURLLoad(pages[i]);

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 400;
  int viewport_height = 300;
  float enforced_page_scale_factor = 0.75f;

  for (size_t i = 0; i < arraysize(pages); ++i) {
    for (int quirk_enabled = 0; quirk_enabled <= 1; ++quirk_enabled) {
      FrameTestHelpers::WebViewHelper web_view_helper;
      web_view_helper.InitializeAndLoad(base_url_ + pages[i], nullptr, &client,
                                        nullptr, ConfigureAndroid);
      web_view_helper.GetWebView()
          ->GetSettings()
          ->SetClobberUserAgentInitialScaleQuirk(quirk_enabled);
      web_view_helper.GetWebView()->SetInitialPageScaleOverride(
          enforced_page_scale_factor);
      web_view_helper.Resize(WebSize(viewport_width, viewport_height));

      float expected_page_scale_factor =
          quirk_enabled && i < arraysize(page_scale_factors)
              ? page_scale_factors[i]
              : enforced_page_scale_factor;
      EXPECT_EQ(expected_page_scale_factor,
                web_view_helper.GetWebView()->PageScaleFactor());
    }
  }
}

TEST_P(ParameterizedWebFrameTest,
       PermanentInitialPageScaleFactorAffectsLayoutWidth) {
  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;
  float enforced_page_scale_factor = 0.5;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(viewport_width / enforced_page_scale_factor,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->ContentsSize()
                .Width());
  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest,
       DocumentElementClientHeightWorksWithWrapContentMode) {
  RegisterMockedHttpURLLoad("0-by-0.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "0-by-0.html", nullptr, &client,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  LocalFrame* frame = web_view_helper.LocalMainFrame()->GetFrame();
  Document* document = frame->GetDocument();
  EXPECT_EQ(viewport_height, document->documentElement()->clientHeight());
  EXPECT_EQ(viewport_width, document->documentElement()->clientWidth());
}

TEST_P(ParameterizedWebFrameTest,
       SetForceZeroLayoutHeightWorksWithWrapContentMode) {
  RegisterMockedHttpURLLoad("0-by-0.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "0-by-0.html", nullptr, &client,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  PaintLayerCompositor* compositor = web_view_helper.GetWebView()->Compositor();
  GraphicsLayer* scroll_container = compositor->ContainerLayer();
  if (!scroll_container)
    scroll_container = compositor->RootGraphicsLayer();

  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .Width());
  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .Height());
  EXPECT_EQ(0.0, scroll_container->Size().Width());
  EXPECT_EQ(0.0, scroll_container->Size().Height());

  web_view_helper.Resize(WebSize(viewport_width, 0));
  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->GetLayoutSize()
                                .Width());
  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .Height());
  EXPECT_EQ(viewport_width, scroll_container->Size().Width());
  EXPECT_EQ(0.0, scroll_container->Size().Height());

  // The flag ForceZeroLayoutHeight will cause the following resize of viewport
  // height to be ignored by the outer viewport (the container layer of
  // LayerCompositor). The height of the visualViewport, however, is not
  // affected.
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  EXPECT_FALSE(web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->NeedsLayout());
  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->GetLayoutSize()
                                .Width());
  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .Height());
  EXPECT_EQ(viewport_width, scroll_container->Size().Width());
  EXPECT_EQ(viewport_height, scroll_container->Size().Height());

  LocalFrame* frame = web_view_helper.LocalMainFrame()->GetFrame();
  VisualViewport& visual_viewport = frame->GetPage()->GetVisualViewport();
  EXPECT_EQ(viewport_height, visual_viewport.ContainerLayer()->Size().Height());
  EXPECT_TRUE(
      visual_viewport.ContainerLayer()->PlatformLayer()->MasksToBounds());
  EXPECT_FALSE(scroll_container->PlatformLayer()->MasksToBounds());
}

TEST_P(ParameterizedWebFrameTest, SetForceZeroLayoutHeight) {
  RegisterMockedHttpURLLoad("200-by-300.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "200-by-300.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_LE(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->GetLayoutSize()
                                 .Height());
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  EXPECT_TRUE(web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->NeedsLayout());

  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .Height());

  web_view_helper.Resize(WebSize(viewport_width, viewport_height * 2));
  EXPECT_FALSE(web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->NeedsLayout());
  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .Height());

  web_view_helper.Resize(WebSize(viewport_width * 2, viewport_height));
  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .Height());

  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(false);
  EXPECT_LE(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->GetLayoutSize()
                                 .Height());
}

TEST_P(ParameterizedWebFrameTest, ToggleViewportMetaOnOff) {
  RegisterMockedHttpURLLoad("viewport-device-width.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport-device-width.html",
                                    nullptr, &client);
  WebSettings* settings = web_view_helper.GetWebView()->GetSettings();
  settings->SetViewportMetaEnabled(false);
  settings->SetViewportEnabled(true);
  settings->SetMainFrameResizesAreOrientationChanges(true);
  settings->SetShrinksViewportContentToFit(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  Document* document =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();
  EXPECT_FALSE(document->GetViewportDescription().IsLegacyViewportType());

  settings->SetViewportMetaEnabled(true);
  EXPECT_TRUE(document->GetViewportDescription().IsLegacyViewportType());

  settings->SetViewportMetaEnabled(false);
  EXPECT_FALSE(document->GetViewportDescription().IsLegacyViewportType());
}

TEST_P(ParameterizedWebFrameTest,
       SetForceZeroLayoutHeightWorksWithRelayoutsWhenHeightChanged) {
  // this unit test is an attempt to target a real world case where an app could
  // 1. call resize(width, 0) and setForceZeroLayoutHeight(true)
  // 2. load content (hoping that the viewport height would increase
  // as more content is added)
  // 3. fail to register touch events aimed at the loaded content
  // because the layout is only updated if either width or height is changed
  RegisterMockedHttpURLLoad("button.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "button.html", nullptr, &client,
                                    nullptr, ConfigureAndroid);
  // set view height to zero so that if the height of the view is not
  // successfully updated during later resizes touch events will fail
  // (as in not hit content included in the view)
  web_view_helper.Resize(WebSize(viewport_width, 0));

  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  FloatPoint hit_point = FloatPoint(30, 30);  // button size is 100x100

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById("tap_button");

  ASSERT_NE(nullptr, element);
  EXPECT_EQ(String("oldValue"), element->innerText());

  WebGestureEvent gesture_event(WebInputEvent::kGestureTap,
                                WebInputEvent::kNoModifiers,
                                WebInputEvent::GetStaticTimeStampForTests(),
                                kWebGestureDeviceTouchscreen);
  gesture_event.SetFrameScale(1);
  gesture_event.SetPositionInWidget(hit_point);
  gesture_event.SetPositionInScreen(hit_point);
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->GetFrame()
      ->GetEventHandler()
      .HandleGestureEvent(gesture_event);
  // when pressed, the button changes its own text to "updatedValue"
  EXPECT_EQ(String("updatedValue"), element->innerText());
}

TEST_P(ParameterizedWebFrameTest, FrameOwnerPropertiesMargin) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebFrameOwnerProperties properties;
  properties.margin_width = 11;
  properties.margin_height = 22;
  WebLocalFrameImpl* local_frame = FrameTestHelpers::CreateLocalChild(
      *helper.RemoteMainFrame(), "frameName", properties);

  RegisterMockedHttpURLLoad("frame_owner_properties.html");
  FrameTestHelpers::LoadFrame(local_frame,
                              base_url_ + "frame_owner_properties.html");

  // Check if the LocalFrame has seen the marginwidth and marginheight
  // properties.
  Document* child_document = local_frame->GetFrame()->GetDocument();
  EXPECT_EQ(11, child_document->FirstBodyElement()->GetIntegralAttribute(
                    HTMLNames::marginwidthAttr));
  EXPECT_EQ(22, child_document->FirstBodyElement()->GetIntegralAttribute(
                    HTMLNames::marginheightAttr));

  LocalFrameView* frame_view = local_frame->GetFrameView();
  frame_view->Resize(800, 600);
  frame_view->SetNeedsLayout();
  frame_view->UpdateAllLifecyclePhases();
  // Expect scrollbars to be enabled by default.
  EXPECT_NE(nullptr,
            frame_view->LayoutViewportScrollableArea()->HorizontalScrollbar());
  EXPECT_NE(nullptr,
            frame_view->LayoutViewportScrollableArea()->VerticalScrollbar());
}

TEST_P(ParameterizedWebFrameTest, FrameOwnerPropertiesScrolling) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebFrameOwnerProperties properties;
  // Turn off scrolling in the subframe.
  properties.scrolling_mode =
      WebFrameOwnerProperties::ScrollingMode::kAlwaysOff;
  WebLocalFrameImpl* local_frame = FrameTestHelpers::CreateLocalChild(
      *helper.RemoteMainFrame(), "frameName", properties);

  RegisterMockedHttpURLLoad("frame_owner_properties.html");
  FrameTestHelpers::LoadFrame(local_frame,
                              base_url_ + "frame_owner_properties.html");

  Document* child_document = local_frame->GetFrame()->GetDocument();
  EXPECT_EQ(0, child_document->FirstBodyElement()->GetIntegralAttribute(
                   HTMLNames::marginwidthAttr));
  EXPECT_EQ(0, child_document->FirstBodyElement()->GetIntegralAttribute(
                   HTMLNames::marginheightAttr));

  LocalFrameView* frame_view =
      static_cast<WebLocalFrameImpl*>(local_frame)->GetFrameView();
  EXPECT_EQ(nullptr, frame_view->HorizontalScrollbar());
  EXPECT_EQ(nullptr, frame_view->VerticalScrollbar());
}

TEST_P(ParameterizedWebFrameTest,
       SetForceZeroLayoutHeightWorksAcrossNavigations) {
  RegisterMockedHttpURLLoad("200-by-300.html");
  RegisterMockedHttpURLLoad("large-div.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "200-by-300.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "large-div.html");
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .Height());
}

TEST_P(ParameterizedWebFrameTest,
       SetForceZeroLayoutHeightWithWideViewportQuirk) {
  RegisterMockedHttpURLLoad("200-by-300.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "200-by-300.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .Height());
}

TEST_P(ParameterizedWebFrameTest, WideViewportAndWideContentWithInitialScale) {
  RegisterMockedHttpURLLoad("wide_document_width_viewport.html");
  RegisterMockedHttpURLLoad("white-1x1.png");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 600;
  int viewport_height = 800;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.GetWebView()->GetSettings()->SetViewportMetaLayoutSizeQuirk(
      true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "wide_document_width_viewport.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  int wide_document_width = 800;
  float minimum_page_scale_factor = viewport_width / (float)wide_document_width;
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
  EXPECT_EQ(minimum_page_scale_factor,
            web_view_helper.GetWebView()->MinimumPageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, WideViewportQuirkClobbersHeight) {
  RegisterMockedHttpURLLoad("viewport-height-1000.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 600;
  int viewport_height = 800;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.GetWebView()->GetSettings()->SetViewportMetaLayoutSizeQuirk(
      true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "viewport-height-1000.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(800, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->GetLayoutSize()
                     .Height());
  EXPECT_EQ(1, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, LayoutSize320Quirk) {
  RegisterMockedHttpURLLoad("viewport/viewport-30.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 600;
  int viewport_height = 800;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.GetWebView()->GetSettings()->SetViewportMetaLayoutSizeQuirk(
      true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "viewport/viewport-30.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(600, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->GetLayoutSize()
                     .Width());
  EXPECT_EQ(800, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->GetLayoutSize()
                     .Height());
  EXPECT_EQ(1, web_view_helper.GetWebView()->PageScaleFactor());

  // The magic number to snap to device-width is 320, so test that 321 is
  // respected.
  Document* document =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();
  ViewportDescription description = document->GetViewportDescription();
  description.min_width = Length(321, blink::kFixed);
  description.max_width = Length(321, blink::kFixed);
  document->SetViewportDescription(description);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(321, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->GetLayoutSize()
                     .Width());

  description.min_width = Length(320, blink::kFixed);
  description.max_width = Length(320, blink::kFixed);
  document->SetViewportDescription(description);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(600, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->GetLayoutSize()
                     .Width());

  description = document->GetViewportDescription();
  description.max_height = Length(1000, blink::kFixed);
  document->SetViewportDescription(description);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(1000, web_view_helper.GetWebView()
                      ->MainFrameImpl()
                      ->GetFrameView()
                      ->GetLayoutSize()
                      .Height());

  description.max_height = Length(320, blink::kFixed);
  document->SetViewportDescription(description);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(800, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->GetLayoutSize()
                     .Height());
}

TEST_P(ParameterizedWebFrameTest, ZeroValuesQuirk) {
  RegisterMockedHttpURLLoad("viewport-zero-values.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetViewportMetaZeroValuesQuirk(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetViewportMetaLayoutSizeQuirk(
      true);
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "viewport-zero-values.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->GetLayoutSize()
                                .Width());
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());

  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(viewport_width, web_view_helper.GetWebView()
                                ->MainFrameImpl()
                                ->GetFrameView()
                                ->GetLayoutSize()
                                .Width());
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, OverflowHiddenDisablesScrolling) {
  RegisterMockedHttpURLLoad("body-overflow-hidden.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client);
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "body-overflow-hidden.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_FALSE(view->UserInputScrollable(kVerticalScrollbar));
  EXPECT_FALSE(view->UserInputScrollable(kHorizontalScrollbar));
}

TEST_P(ParameterizedWebFrameTest,
       OverflowHiddenDisablesScrollingWithSetCanHaveScrollbars) {
  RegisterMockedHttpURLLoad("body-overflow-hidden-short.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client);
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "body-overflow-hidden-short.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_FALSE(view->UserInputScrollable(kVerticalScrollbar));
  EXPECT_FALSE(view->UserInputScrollable(kHorizontalScrollbar));

  web_view_helper.LocalMainFrame()->SetCanHaveScrollbars(true);
  EXPECT_FALSE(view->UserInputScrollable(kVerticalScrollbar));
  EXPECT_FALSE(view->UserInputScrollable(kHorizontalScrollbar));
}

TEST_P(ParameterizedWebFrameTest, IgnoreOverflowHiddenQuirk) {
  RegisterMockedHttpURLLoad("body-overflow-hidden.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetIgnoreMainFrameOverflowHiddenQuirk(true);
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "body-overflow-hidden.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_TRUE(view->LayoutViewportScrollableArea()->UserInputScrollable(
      kVerticalScrollbar));
}

TEST_P(ParameterizedWebFrameTest, NonZeroValuesNoQuirk) {
  RegisterMockedHttpURLLoad("viewport-nonzero-values.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;
  float expected_page_scale_factor = 0.5f;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetViewportMetaZeroValuesQuirk(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "viewport-nonzero-values.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(viewport_width / expected_page_scale_factor,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->GetLayoutSize()
                .Width());
  EXPECT_EQ(expected_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(viewport_width / expected_page_scale_factor,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->GetLayoutSize()
                .Width());
  EXPECT_EQ(expected_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, setPageScaleFactorDoesNotLayout) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  // Small viewport to ensure there are always scrollbars.
  int viewport_width = 64;
  int viewport_height = 48;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  int prev_layout_count =
      web_view_helper.LocalMainFrame()->GetFrameView()->LayoutCount();
  web_view_helper.GetWebView()->SetPageScaleFactor(3);
  EXPECT_FALSE(web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->NeedsLayout());
  EXPECT_EQ(prev_layout_count, web_view_helper.GetWebView()
                                   ->MainFrameImpl()
                                   ->GetFrameView()
                                   ->LayoutCount());
}

TEST_P(ParameterizedWebFrameTest,
       setPageScaleFactorWithOverlayScrollbarsDoesNotLayout) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  int prev_layout_count =
      web_view_helper.LocalMainFrame()->GetFrameView()->LayoutCount();
  web_view_helper.GetWebView()->SetPageScaleFactor(30);
  EXPECT_FALSE(web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->NeedsLayout());
  EXPECT_EQ(prev_layout_count, web_view_helper.GetWebView()
                                   ->MainFrameImpl()
                                   ->GetFrameView()
                                   ->LayoutCount());
}

TEST_P(ParameterizedWebFrameTest, pageScaleFactorWrittenToHistoryItem) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  web_view_helper.GetWebView()->SetPageScaleFactor(3);
  EXPECT_EQ(3,
            ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
                ->Loader()
                .GetDocumentLoader()
                ->GetHistoryItem()
                ->GetViewState()
                ->page_scale_factor_);
}

TEST_P(ParameterizedWebFrameTest, initialScaleWrittenToHistoryItem) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "fixed_layout.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  int default_fixed_layout_width = 980;
  float minimum_page_scale_factor =
      viewport_width / (float)default_fixed_layout_width;
  EXPECT_EQ(minimum_page_scale_factor,
            ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
                ->Loader()
                .GetDocumentLoader()
                ->GetHistoryItem()
                ->GetViewState()
                ->page_scale_factor_);
}

TEST_P(ParameterizedWebFrameTest, pageScaleFactorDoesntShrinkFrameView) {
  RegisterMockedHttpURLLoad("large-div.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  // Small viewport to ensure there are always scrollbars.
  int viewport_width = 64;
  int viewport_height = 48;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "large-div.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  int viewport_width_minus_scrollbar = viewport_width;
  int viewport_height_minus_scrollbar = viewport_height;

  if (view->VerticalScrollbar() &&
      !view->VerticalScrollbar()->IsOverlayScrollbar())
    viewport_width_minus_scrollbar -= 15;

  if (view->HorizontalScrollbar() &&
      !view->HorizontalScrollbar()->IsOverlayScrollbar())
    viewport_height_minus_scrollbar -= 15;

  web_view_helper.GetWebView()->SetPageScaleFactor(2);

  IntSize unscaled_size = view->VisibleContentSize(kIncludeScrollbars);
  EXPECT_EQ(viewport_width, unscaled_size.Width());
  EXPECT_EQ(viewport_height, unscaled_size.Height());

  IntSize unscaled_size_minus_scrollbar =
      view->VisibleContentSize(kExcludeScrollbars);
  EXPECT_EQ(viewport_width_minus_scrollbar,
            unscaled_size_minus_scrollbar.Width());
  EXPECT_EQ(viewport_height_minus_scrollbar,
            unscaled_size_minus_scrollbar.Height());

  IntSize frame_view_size = view->VisibleContentRect().Size();
  EXPECT_EQ(viewport_width_minus_scrollbar, frame_view_size.Width());
  EXPECT_EQ(viewport_height_minus_scrollbar, frame_view_size.Height());
}

TEST_P(ParameterizedWebFrameTest, pageScaleFactorDoesNotApplyCssTransform) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  web_view_helper.GetWebView()->SetPageScaleFactor(2);

  EXPECT_EQ(980,
            ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
                ->ContentLayoutObject()
                ->DocumentRect()
                .Width());
  EXPECT_EQ(980, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->LayoutViewportScrollableArea()
                     ->ContentsSize()
                     .Width());
}

TEST_P(ParameterizedWebFrameTest, targetDensityDpiHigh) {
  RegisterMockedHttpURLLoad("viewport-target-densitydpi-high.html");

  FixedLayoutTestWebViewClient client;
  // high-dpi = 240
  float target_dpi = 240.0f;
  float device_scale_factors[] = {1.0f, 4.0f / 3.0f, 2.0f};
  int viewport_width = 640;
  int viewport_height = 480;

  for (size_t i = 0; i < arraysize(device_scale_factors); ++i) {
    float device_scale_factor = device_scale_factors[i];
    float device_dpi = device_scale_factor * 160.0f;
    client.screen_info_.device_scale_factor = device_scale_factor;

    FrameTestHelpers::WebViewHelper web_view_helper;
    web_view_helper.InitializeAndLoad(
        base_url_ + "viewport-target-densitydpi-high.html", nullptr, &client,
        nullptr, ConfigureAndroid);
    web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
        true);
    web_view_helper.GetWebView()
        ->GetSettings()
        ->SetSupportDeprecatedTargetDensityDPI(true);
    web_view_helper.Resize(WebSize(viewport_width, viewport_height));

    // We need to account for the fact that logical pixels are unconditionally
    // multiplied by deviceScaleFactor to produce physical pixels.
    float density_dpi_scale_ratio =
        device_scale_factor * target_dpi / device_dpi;
    EXPECT_NEAR(viewport_width * density_dpi_scale_ratio,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .Width(),
                1.0f);
    EXPECT_NEAR(viewport_height * density_dpi_scale_ratio,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .Height(),
                1.0f);
    EXPECT_NEAR(1.0f / density_dpi_scale_ratio,
                web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
  }
}

TEST_P(ParameterizedWebFrameTest, targetDensityDpiDevice) {
  RegisterMockedHttpURLLoad("viewport-target-densitydpi-device.html");

  float device_scale_factors[] = {1.0f, 4.0f / 3.0f, 2.0f};

  FixedLayoutTestWebViewClient client;
  int viewport_width = 640;
  int viewport_height = 480;

  for (size_t i = 0; i < arraysize(device_scale_factors); ++i) {
    client.screen_info_.device_scale_factor = device_scale_factors[i];

    FrameTestHelpers::WebViewHelper web_view_helper;
    web_view_helper.InitializeAndLoad(
        base_url_ + "viewport-target-densitydpi-device.html", nullptr, &client,
        nullptr, ConfigureAndroid);
    web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
        true);
    web_view_helper.GetWebView()
        ->GetSettings()
        ->SetSupportDeprecatedTargetDensityDPI(true);
    web_view_helper.Resize(WebSize(viewport_width, viewport_height));

    EXPECT_NEAR(viewport_width * client.screen_info_.device_scale_factor,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .Width(),
                1.0f);
    EXPECT_NEAR(viewport_height * client.screen_info_.device_scale_factor,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .Height(),
                1.0f);
    EXPECT_NEAR(1.0f / client.screen_info_.device_scale_factor,
                web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
  }
}

TEST_P(ParameterizedWebFrameTest, targetDensityDpiDeviceAndFixedWidth) {
  RegisterMockedHttpURLLoad(
      "viewport-target-densitydpi-device-and-fixed-width.html");

  float device_scale_factors[] = {1.0f, 4.0f / 3.0f, 2.0f};

  FixedLayoutTestWebViewClient client;
  int viewport_width = 640;
  int viewport_height = 480;

  for (size_t i = 0; i < arraysize(device_scale_factors); ++i) {
    client.screen_info_.device_scale_factor = device_scale_factors[i];

    FrameTestHelpers::WebViewHelper web_view_helper;
    web_view_helper.InitializeAndLoad(
        base_url_ + "viewport-target-densitydpi-device-and-fixed-width.html",
        nullptr, &client, nullptr, ConfigureAndroid);
    web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
        true);
    web_view_helper.GetWebView()
        ->GetSettings()
        ->SetSupportDeprecatedTargetDensityDPI(true);
    web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
    web_view_helper.Resize(WebSize(viewport_width, viewport_height));

    EXPECT_NEAR(viewport_width,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .Width(),
                1.0f);
    EXPECT_NEAR(viewport_height,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .Height(),
                1.0f);
    EXPECT_NEAR(1.0f, web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
  }
}

TEST_P(ParameterizedWebFrameTest, NoWideViewportAndScaleLessThanOne) {
  RegisterMockedHttpURLLoad("viewport-initial-scale-less-than-1.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1.33f;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-initial-scale-less-than-1.html", nullptr, &client,
      nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetSupportDeprecatedTargetDensityDPI(true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_NEAR(viewport_width * client.screen_info_.device_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Width(),
              1.0f);
  EXPECT_NEAR(viewport_height * client.screen_info_.device_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Height(),
              1.0f);
  EXPECT_NEAR(1.0f / client.screen_info_.device_scale_factor,
              web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
}

TEST_P(ParameterizedWebFrameTest,
       NoWideViewportAndScaleLessThanOneWithDeviceWidth) {
  RegisterMockedHttpURLLoad(
      "viewport-initial-scale-less-than-1-device-width.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1.33f;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-initial-scale-less-than-1-device-width.html",
      nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetSupportDeprecatedTargetDensityDPI(true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  const float kPageZoom = 0.25f;
  EXPECT_NEAR(
      viewport_width * client.screen_info_.device_scale_factor / kPageZoom,
      web_view_helper.GetWebView()
          ->MainFrameImpl()
          ->GetFrameView()
          ->GetLayoutSize()
          .Width(),
      1.0f);
  EXPECT_NEAR(
      viewport_height * client.screen_info_.device_scale_factor / kPageZoom,
      web_view_helper.GetWebView()
          ->MainFrameImpl()
          ->GetFrameView()
          ->GetLayoutSize()
          .Height(),
      1.0f);
  EXPECT_NEAR(1.0f / client.screen_info_.device_scale_factor,
              web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
}

TEST_P(ParameterizedWebFrameTest,
       NoWideViewportAndNoViewportWithInitialPageScaleOverride) {
  RegisterMockedHttpURLLoad("large-div.html");

  FixedLayoutTestWebViewClient client;
  int viewport_width = 640;
  int viewport_height = 480;
  float enforced_page_scale_factor = 5.0f;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "large-div.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_NEAR(viewport_width / enforced_page_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Width(),
              1.0f);
  EXPECT_NEAR(viewport_height / enforced_page_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Height(),
              1.0f);
  EXPECT_NEAR(enforced_page_scale_factor,
              web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
}

TEST_P(ParameterizedWebFrameTest, NoUserScalableQuirkIgnoresViewportScale) {
  RegisterMockedHttpURLLoad("viewport-initial-scale-and-user-scalable-no.html");

  FixedLayoutTestWebViewClient client;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-initial-scale-and-user-scalable-no.html", nullptr,
      &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetViewportMetaNonUserScalableQuirk(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_NEAR(viewport_width,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Width(),
              1.0f);
  EXPECT_NEAR(viewport_height,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Height(),
              1.0f);
  EXPECT_NEAR(1.0f, web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
}

TEST_P(ParameterizedWebFrameTest,
       NoUserScalableQuirkIgnoresViewportScaleForNonWideViewport) {
  RegisterMockedHttpURLLoad("viewport-initial-scale-and-user-scalable-no.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1.33f;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-initial-scale-and-user-scalable-no.html", nullptr,
      &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetSupportDeprecatedTargetDensityDPI(true);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetViewportMetaNonUserScalableQuirk(true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_NEAR(viewport_width * client.screen_info_.device_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Width(),
              1.0f);
  EXPECT_NEAR(viewport_height * client.screen_info_.device_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Height(),
              1.0f);
  EXPECT_NEAR(1.0f / client.screen_info_.device_scale_factor,
              web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
}

TEST_P(ParameterizedWebFrameTest,
       NoUserScalableQuirkIgnoresViewportScaleForWideViewport) {
  RegisterMockedHttpURLLoad("viewport-2x-initial-scale-non-user-scalable.html");

  FixedLayoutTestWebViewClient client;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-2x-initial-scale-non-user-scalable.html", nullptr,
      &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetViewportMetaNonUserScalableQuirk(true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_NEAR(viewport_width,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Width(),
              1.0f);
  EXPECT_NEAR(viewport_height,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .Height(),
              1.0f);
  EXPECT_NEAR(1.0f, web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
}

TEST_P(ParameterizedWebFrameTest,
       DesktopPageCanBeZoomedInWhenWideViewportIsTurnedOff) {
  RegisterMockedHttpURLLoad("no_viewport_tag.html");

  FixedLayoutTestWebViewClient client;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "no_viewport_tag.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_NEAR(1.0f, web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
  EXPECT_NEAR(1.0f, web_view_helper.GetWebView()->MinimumPageScaleFactor(),
              0.01f);
  EXPECT_NEAR(5.0f, web_view_helper.GetWebView()->MaximumPageScaleFactor(),
              0.01f);
}

TEST_P(ParameterizedWebFrameTest, AtViewportInsideAtMediaInitialViewport) {
  RegisterMockedHttpURLLoad("viewport-inside-media.html");

  FixedLayoutTestWebViewClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport-inside-media.html",
                                    nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.Resize(WebSize(640, 480));

  EXPECT_EQ(2000, web_view_helper.GetWebView()
                      ->MainFrameImpl()
                      ->GetFrameView()
                      ->GetLayoutSize()
                      .Width());

  web_view_helper.Resize(WebSize(1200, 480));

  EXPECT_EQ(1200, web_view_helper.GetWebView()
                      ->MainFrameImpl()
                      ->GetFrameView()
                      ->GetLayoutSize()
                      .Width());
}

TEST_P(ParameterizedWebFrameTest, AtViewportAffectingAtMediaRecalcCount) {
  RegisterMockedHttpURLLoad("viewport-and-media.html");

  FixedLayoutTestWebViewClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(640, 480));
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "viewport-and-media.html");

  Document* document =
      web_view_helper.LocalMainFrame()->GetFrame()->GetDocument();
  EXPECT_EQ(2000, web_view_helper.GetWebView()
                      ->MainFrameImpl()
                      ->GetFrameView()
                      ->GetLayoutSize()
                      .Width());

  // The styleForElementCount() should match the number of elements for a single
  // pass of computed styles construction for the document.
  EXPECT_EQ(8u, document->GetStyleEngine().StyleForElementCount());
  EXPECT_EQ(Color(0, 128, 0),
            document->body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_P(ParameterizedWebFrameTest, AtViewportWithViewportLengths) {
  RegisterMockedHttpURLLoad("viewport-lengths.html");

  FixedLayoutTestWebViewClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(800, 600));
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "viewport-lengths.html");

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_EQ(400, view->GetLayoutSize().Width());
  EXPECT_EQ(300, view->GetLayoutSize().Height());

  web_view_helper.Resize(WebSize(1000, 400));

  EXPECT_EQ(500, view->GetLayoutSize().Width());
  EXPECT_EQ(200, view->GetLayoutSize().Height());
}

class WebFrameResizeTest : public ParameterizedWebFrameTest {
 protected:
  static FloatSize ComputeRelativeOffset(const IntPoint& absolute_offset,
                                         const LayoutRect& rect) {
    FloatSize relative_offset =
        FloatPoint(absolute_offset) - FloatPoint(rect.Location());
    relative_offset.Scale(1.f / rect.Width(), 1.f / rect.Height());
    return relative_offset;
  }

  void TestResizeYieldsCorrectScrollAndScale(
      const char* url,
      const float initial_page_scale_factor,
      const WebSize scroll_offset,
      const WebSize viewport_size,
      const bool should_scale_relative_to_viewport_width) {
    RegisterMockedHttpURLLoad(url);

    const float aspect_ratio =
        static_cast<float>(viewport_size.width) / viewport_size.height;

    FrameTestHelpers::WebViewHelper web_view_helper;
    web_view_helper.InitializeAndLoad(base_url_ + url, nullptr, nullptr,
                                      nullptr, ConfigureAndroid);
    web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);

    // Origin scrollOffsets preserved under resize.
    {
      web_view_helper.Resize(
          WebSize(viewport_size.width, viewport_size.height));
      web_view_helper.GetWebView()->SetPageScaleFactor(
          initial_page_scale_factor);
      ASSERT_EQ(viewport_size, web_view_helper.GetWebView()->Size());
      ASSERT_EQ(initial_page_scale_factor,
                web_view_helper.GetWebView()->PageScaleFactor());
      web_view_helper.Resize(
          WebSize(viewport_size.height, viewport_size.width));
      float expected_page_scale_factor =
          initial_page_scale_factor *
          (should_scale_relative_to_viewport_width ? 1 / aspect_ratio : 1);
      EXPECT_NEAR(expected_page_scale_factor,
                  web_view_helper.GetWebView()->PageScaleFactor(), 0.05f);
      EXPECT_EQ(WebSize(), web_view_helper.LocalMainFrame()->GetScrollOffset());
    }

    // Resizing just the height should not affect pageScaleFactor or
    // scrollOffset.
    {
      web_view_helper.Resize(
          WebSize(viewport_size.width, viewport_size.height));
      web_view_helper.GetWebView()->SetPageScaleFactor(
          initial_page_scale_factor);
      web_view_helper.LocalMainFrame()->SetScrollOffset(scroll_offset);
      web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
      const WebSize expected_scroll_offset =
          web_view_helper.LocalMainFrame()->GetScrollOffset();
      web_view_helper.Resize(
          WebSize(viewport_size.width, viewport_size.height * 0.8f));
      EXPECT_EQ(initial_page_scale_factor,
                web_view_helper.GetWebView()->PageScaleFactor());
      EXPECT_EQ(expected_scroll_offset,
                web_view_helper.LocalMainFrame()->GetScrollOffset());
      web_view_helper.Resize(
          WebSize(viewport_size.width, viewport_size.height * 0.8f));
      EXPECT_EQ(initial_page_scale_factor,
                web_view_helper.GetWebView()->PageScaleFactor());
      EXPECT_EQ(expected_scroll_offset,
                web_view_helper.LocalMainFrame()->GetScrollOffset());
    }
  }
};

INSTANTIATE_TEST_CASE_P(All, WebFrameResizeTest, testing::Bool());

TEST_P(WebFrameResizeTest,
       ResizeYieldsCorrectScrollAndScaleForWidthEqualsDeviceWidth) {
  // With width=device-width, pageScaleFactor is preserved across resizes as
  // long as the content adjusts according to the device-width.
  const char* url = "resize_scroll_mobile.html";
  const float kInitialPageScaleFactor = 1;
  const WebSize scroll_offset(0, 50);
  const WebSize viewport_size(120, 160);
  const bool kShouldScaleRelativeToViewportWidth = true;

  TestResizeYieldsCorrectScrollAndScale(url, kInitialPageScaleFactor,
                                        scroll_offset, viewport_size,
                                        kShouldScaleRelativeToViewportWidth);
}

TEST_P(WebFrameResizeTest, ResizeYieldsCorrectScrollAndScaleForMinimumScale) {
  // This tests a scenario where minimum-scale is set to 1.0, but some element
  // on the page is slightly larger than the portrait width, so our "natural"
  // minimum-scale would be lower. In that case, we should stick to 1.0 scale
  // on rotation and not do anything strange.
  const char* url = "resize_scroll_minimum_scale.html";
  const float kInitialPageScaleFactor = 1;
  const WebSize scroll_offset(0, 0);
  const WebSize viewport_size(240, 320);
  const bool kShouldScaleRelativeToViewportWidth = false;

  TestResizeYieldsCorrectScrollAndScale(url, kInitialPageScaleFactor,
                                        scroll_offset, viewport_size,
                                        kShouldScaleRelativeToViewportWidth);
}

TEST_P(WebFrameResizeTest, ResizeYieldsCorrectScrollAndScaleForFixedWidth) {
  // With a fixed width, pageScaleFactor scales by the relative change in
  // viewport width.
  const char* url = "resize_scroll_fixed_width.html";
  const float kInitialPageScaleFactor = 2;
  const WebSize scroll_offset(0, 200);
  const WebSize viewport_size(240, 320);
  const bool kShouldScaleRelativeToViewportWidth = true;

  TestResizeYieldsCorrectScrollAndScale(url, kInitialPageScaleFactor,
                                        scroll_offset, viewport_size,
                                        kShouldScaleRelativeToViewportWidth);
}

TEST_P(WebFrameResizeTest, ResizeYieldsCorrectScrollAndScaleForFixedLayout) {
  // With a fixed layout, pageScaleFactor scales by the relative change in
  // viewport width.
  const char* url = "resize_scroll_fixed_layout.html";
  const float kInitialPageScaleFactor = 2;
  const WebSize scroll_offset(200, 400);
  const WebSize viewport_size(320, 240);
  const bool kShouldScaleRelativeToViewportWidth = true;

  TestResizeYieldsCorrectScrollAndScale(url, kInitialPageScaleFactor,
                                        scroll_offset, viewport_size,
                                        kShouldScaleRelativeToViewportWidth);
}

TEST_P(ParameterizedWebFrameTest, pageScaleFactorUpdatesScrollbars) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  ScrollableArea* scrollable_area = view->LayoutViewportScrollableArea();
  EXPECT_EQ(scrollable_area->ScrollSize(kHorizontalScrollbar),
            scrollable_area->ContentsSize().Width() -
                view->VisibleContentRect().Width());
  EXPECT_EQ(scrollable_area->ScrollSize(kVerticalScrollbar),
            scrollable_area->ContentsSize().Height() -
                view->VisibleContentRect().Height());

  web_view_helper.GetWebView()->SetPageScaleFactor(10);

  EXPECT_EQ(scrollable_area->ScrollSize(kHorizontalScrollbar),
            scrollable_area->ContentsSize().Width() -
                view->VisibleContentRect().Width());
  EXPECT_EQ(scrollable_area->ScrollSize(kVerticalScrollbar),
            scrollable_area->ContentsSize().Height() -
                view->VisibleContentRect().Height());
}

TEST_P(ParameterizedWebFrameTest, CanOverrideScaleLimits) {
  RegisterMockedHttpURLLoad("no_scale_for_you.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "no_scale_for_you.html",
                                    nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->MinimumPageScaleFactor());
  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->MaximumPageScaleFactor());

  web_view_helper.GetWebView()->SetIgnoreViewportTagScaleLimits(true);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->MinimumPageScaleFactor());
  EXPECT_EQ(5.0f, web_view_helper.GetWebView()->MaximumPageScaleFactor());

  web_view_helper.GetWebView()->SetIgnoreViewportTagScaleLimits(false);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->MinimumPageScaleFactor());
  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->MaximumPageScaleFactor());
}

// Android doesn't have scrollbars on the main LocalFrameView
#if defined(OS_ANDROID)
TEST_P(ParameterizedWebFrameTest, DISABLED_updateOverlayScrollbarLayers)
#else
TEST_P(ParameterizedWebFrameTest, updateOverlayScrollbarLayers)
#endif
{
  RegisterMockedHttpURLLoad("large-div.html");

  int view_width = 500;
  int view_height = 500;

  std::unique_ptr<FakeCompositingWebViewClient>
      fake_compositing_web_view_client =
          std::make_unique<FakeCompositingWebViewClient>();
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, fake_compositing_web_view_client.get(),
                             nullptr, &ConfigureCompositingWebView);

  web_view_helper.Resize(WebSize(view_width, view_height));
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "large-div.html");

  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_TRUE(
      view->LayoutViewportScrollableArea()->LayerForHorizontalScrollbar());
  EXPECT_TRUE(
      view->LayoutViewportScrollableArea()->LayerForVerticalScrollbar());

  web_view_helper.Resize(WebSize(view_width * 10, view_height * 10));
  EXPECT_FALSE(
      view->LayoutViewportScrollableArea()->LayerForHorizontalScrollbar());
  EXPECT_FALSE(
      view->LayoutViewportScrollableArea()->LayerForVerticalScrollbar());
}

void SetScaleAndScrollAndLayout(WebViewImpl* web_view,
                                WebPoint scroll,
                                float scale) {
  web_view->SetPageScaleFactor(scale);
  web_view->MainFrameImpl()->SetScrollOffset(WebSize(scroll.x, scroll.y));
  web_view->UpdateAllLifecyclePhases();
}

void SimulatePageScale(WebViewImpl* web_view_impl, float& scale) {
  ScrollOffset scroll_delta =
      ToScrollOffset(
          web_view_impl->FakePageScaleAnimationTargetPositionForTesting()) -
      web_view_impl->MainFrameImpl()->GetFrameView()->GetScrollOffset();
  float scale_delta =
      web_view_impl->FakePageScaleAnimationPageScaleForTesting() /
      web_view_impl->PageScaleFactor();
  web_view_impl->ApplyViewportDeltas(WebFloatSize(), FloatSize(scroll_delta),
                                     WebFloatSize(), scale_delta, 0);
  scale = web_view_impl->PageScaleFactor();
}

void SimulateMultiTargetZoom(WebViewImpl* web_view_impl,
                             const WebRect& rect,
                             float& scale) {
  if (web_view_impl->ZoomToMultipleTargetsRect(rect))
    SimulatePageScale(web_view_impl, scale);
}

void SimulateDoubleTap(WebViewImpl* web_view_impl,
                       WebPoint& point,
                       float& scale) {
  web_view_impl->AnimateDoubleTapZoom(point);
  EXPECT_TRUE(web_view_impl->FakeDoubleTapAnimationPendingForTesting());
  SimulatePageScale(web_view_impl, scale);
}

TEST_P(ParameterizedWebFrameTest, DivAutoZoomParamsTest) {
  RegisterMockedHttpURLLoad("get_scale_for_auto_zoom_into_div_test.html");

  const float kDeviceScaleFactor = 2.0f;
  int viewport_width = 640 / kDeviceScaleFactor;
  int viewport_height = 1280 / kDeviceScaleFactor;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_for_auto_zoom_into_div_test.html", nullptr,
      nullptr, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDeviceScaleFactor(kDeviceScaleFactor);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.01f, 4);
  web_view_helper.GetWebView()->SetPageScaleFactor(0.5f);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  WebRect wide_div(200, 100, 400, 150);
  WebRect tall_div(200, 300, 400, 800);
  WebPoint double_tap_point_wide(wide_div.x + 50, wide_div.y + 50);
  WebPoint double_tap_point_tall(tall_div.x + 50, tall_div.y + 50);
  float scale;
  WebPoint scroll;

  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;

  // Test double-tap zooming into wide div.
  WebRect wide_block_bound = web_view_helper.GetWebView()->ComputeBlockBound(
      double_tap_point_wide, false);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForBlockRect(
      WebPoint(double_tap_point_wide.x, double_tap_point_wide.y),
      wide_block_bound, kTouchPointPadding,
      double_tap_zoom_already_legible_scale, scale, scroll);
  // The div should horizontally fill the screen (modulo margins), and
  // vertically centered (modulo integer rounding).
  EXPECT_NEAR(viewport_width / (float)wide_div.width, scale, 0.1);
  EXPECT_NEAR(wide_div.x, scroll.x, 20);
  EXPECT_EQ(0, scroll.y);

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), scroll, scale);

  // Test zoom out back to minimum scale.
  wide_block_bound = web_view_helper.GetWebView()->ComputeBlockBound(
      double_tap_point_wide, false);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForBlockRect(
      WebPoint(double_tap_point_wide.x, double_tap_point_wide.y),
      wide_block_bound, kTouchPointPadding,
      double_tap_zoom_already_legible_scale, scale, scroll);
  // FIXME: Looks like we are missing EXPECTs here.

  scale = web_view_helper.GetWebView()->MinimumPageScaleFactor();
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0),
                             scale);

  // Test double-tap zooming into tall div.
  WebRect tall_block_bound = web_view_helper.GetWebView()->ComputeBlockBound(
      double_tap_point_tall, false);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForBlockRect(
      WebPoint(double_tap_point_tall.x, double_tap_point_tall.y),
      tall_block_bound, kTouchPointPadding,
      double_tap_zoom_already_legible_scale, scale, scroll);
  // The div should start at the top left of the viewport.
  EXPECT_NEAR(viewport_width / (float)tall_div.width, scale, 0.1);
  EXPECT_NEAR(tall_div.x, scroll.x, 20);
  EXPECT_NEAR(tall_div.y, scroll.y, 20);
}

TEST_P(ParameterizedWebFrameTest, DivAutoZoomWideDivTest) {
  RegisterMockedHttpURLLoad("get_wide_div_for_auto_zoom_test.html");

  const float kDeviceScaleFactor = 2.0f;
  int viewport_width = 640 / kDeviceScaleFactor;
  int viewport_height = 1280 / kDeviceScaleFactor;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_wide_div_for_auto_zoom_test.html", nullptr, nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDeviceScaleFactor(kDeviceScaleFactor);
  web_view_helper.GetWebView()->SetPageScaleFactor(1.0f);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;

  WebRect div(0, 100, viewport_width, 150);
  WebPoint point(div.x + 50, div.y + 50);
  float scale;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);

  SimulateDoubleTap(web_view_helper.GetWebView(), point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
}

TEST_P(ParameterizedWebFrameTest, DivAutoZoomVeryTallTest) {
  // When a block is taller than the viewport and a zoom targets a lower part
  // of it, then we should keep the target point onscreen instead of snapping
  // back up the top of the block.
  RegisterMockedHttpURLLoad("very_tall_div.html");

  const float kDeviceScaleFactor = 2.0f;
  int viewport_width = 640 / kDeviceScaleFactor;
  int viewport_height = 1280 / kDeviceScaleFactor;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "very_tall_div.html", nullptr,
                                    nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDeviceScaleFactor(kDeviceScaleFactor);
  web_view_helper.GetWebView()->SetPageScaleFactor(1.0f);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  WebRect div(200, 300, 400, 5000);
  WebPoint point(div.x + 50, div.y + 3000);
  float scale;
  WebPoint scroll;

  WebRect block_bound =
      web_view_helper.GetWebView()->ComputeBlockBound(point, true);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForBlockRect(
      point, block_bound, 0, 1.0f, scale, scroll);
  EXPECT_EQ(scale, 1.0f);
  EXPECT_EQ(scroll.y, 2660);
}

TEST_P(ParameterizedWebFrameTest, DivAutoZoomMultipleDivsTest) {
  RegisterMockedHttpURLLoad("get_multiple_divs_for_auto_zoom_test.html");

  const float kDeviceScaleFactor = 2.0f;
  int viewport_width = 640 / kDeviceScaleFactor;
  int viewport_height = 1280 / kDeviceScaleFactor;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_multiple_divs_for_auto_zoom_test.html", nullptr, nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.5f, 4);
  web_view_helper.GetWebView()->SetDeviceScaleFactor(kDeviceScaleFactor);
  web_view_helper.GetWebView()->SetPageScaleFactor(0.5f);
  web_view_helper.GetWebView()->SetMaximumLegibleScale(1.f);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  WebRect top_div(200, 100, 200, 150);
  WebRect bottom_div(200, 300, 200, 150);
  WebPoint top_point(top_div.x + 50, top_div.y + 50);
  WebPoint bottom_point(bottom_div.x + 50, bottom_div.y + 50);
  float scale;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);

  // Test double tap on two different divs.  After first zoom, we should go back
  // to minimum page scale with a second double tap.
  SimulateDoubleTap(web_view_helper.GetWebView(), top_point, scale);
  EXPECT_FLOAT_EQ(1, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), bottom_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);

  // If the user pinch zooms after double tap, a second double tap should zoom
  // back to the div.
  SimulateDoubleTap(web_view_helper.GetWebView(), top_point, scale);
  EXPECT_FLOAT_EQ(1, scale);
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 0.6f, 0);
  SimulateDoubleTap(web_view_helper.GetWebView(), bottom_point, scale);
  EXPECT_FLOAT_EQ(1, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), bottom_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);

  // If we didn't yet get an auto-zoom update and a second double-tap arrives,
  // should go back to minimum scale.
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.1f, 0);
  web_view_helper.GetWebView()->AnimateDoubleTapZoom(top_point);
  EXPECT_TRUE(
      web_view_helper.GetWebView()->FakeDoubleTapAnimationPendingForTesting());
  SimulateDoubleTap(web_view_helper.GetWebView(), bottom_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
}

TEST_P(ParameterizedWebFrameTest, DivAutoZoomScaleBoundsTest) {
  RegisterMockedHttpURLLoad("get_scale_bounds_check_for_auto_zoom_test.html");

  int viewport_width = 320;
  int viewport_height = 480;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_bounds_check_for_auto_zoom_test.html", nullptr,
      nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDeviceScaleFactor(1.5f);
  web_view_helper.GetWebView()->SetMaximumLegibleScale(1.f);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  WebRect div(200, 100, 200, 150);
  WebPoint double_tap_point(div.x + 50, div.y + 50);
  float scale;

  // Test double tap scale bounds.
  // minimumPageScale < doubleTapZoomAlreadyLegibleScale < 1
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.5f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(1, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(1, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.1f, 0);
  // 1 < minimumPageScale < doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(1.1f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.1f, 0);
  // minimumPageScale < 1 < doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.95f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
}

TEST_P(ParameterizedWebFrameTest, DivAutoZoomScaleLegibleScaleTest) {
  RegisterMockedHttpURLLoad("get_scale_bounds_check_for_auto_zoom_test.html");

  int viewport_width = 320;
  int viewport_height = 480;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  float maximum_legible_scale_factor = 1.13f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_bounds_check_for_auto_zoom_test.html", nullptr,
      nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetMaximumLegibleScale(
      maximum_legible_scale_factor);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(true);

  WebRect div(200, 100, 200, 150);
  WebPoint double_tap_point(div.x + 50, div.y + 50);
  float scale;

  // Test double tap scale bounds.
  // minimumPageScale < doubleTapZoomAlreadyLegibleScale < 1 <
  //     maximumLegibleScaleFactor
  float legible_scale = maximum_legible_scale_factor;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.5f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.1f, 0);
  // 1 < maximumLegibleScaleFactor < minimumPageScale <
  //     doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(1.0f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.1f, 0);
  // minimumPageScale < 1 < maximumLegibleScaleFactor <
  //     doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.95f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.1f, 0);
  // minimumPageScale < 1 < doubleTapZoomAlreadyLegibleScale <
  //     maximumLegibleScaleFactor
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.9f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
}

TEST_P(ParameterizedWebFrameTest, DivAutoZoomScaleFontScaleFactorTest) {
  RegisterMockedHttpURLLoad("get_scale_bounds_check_for_auto_zoom_test.html");

  int viewport_width = 320;
  int viewport_height = 480;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  float accessibility_font_scale_factor = 1.13f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_bounds_check_for_auto_zoom_test.html", nullptr,
      nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetMaximumLegibleScale(1.f);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(true);
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetAccessibilityFontScaleFactor(accessibility_font_scale_factor);

  WebRect div(200, 100, 200, 150);
  WebPoint double_tap_point(div.x + 50, div.y + 50);
  float scale;

  // Test double tap scale bounds.
  // minimumPageScale < doubleTapZoomAlreadyLegibleScale < 1 <
  //     accessibilityFontScaleFactor
  float legible_scale = accessibility_font_scale_factor;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.5f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.1f, 0);
  // 1 < accessibilityFontScaleFactor < minimumPageScale <
  //     doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(1.0f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.1f, 0);
  // minimumPageScale < 1 < accessibilityFontScaleFactor <
  //     doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.95f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.1f, 0);
  // minimumPageScale < 1 < doubleTapZoomAlreadyLegibleScale <
  //     accessibilityFontScaleFactor
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.9f, 4);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
}

TEST_P(ParameterizedWebFrameTest, BlockBoundTest) {
  RegisterMockedHttpURLLoad("block_bound.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "block_bound.html", nullptr,
                                    nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(300, 300));

  IntRect rect_back = IntRect(0, 0, 200, 200);
  IntRect rect_left_top = IntRect(10, 10, 80, 80);
  IntRect rect_right_bottom = IntRect(110, 110, 80, 80);
  IntRect block_bound;

  block_bound = IntRect(
      web_view_helper.GetWebView()->ComputeBlockBound(WebPoint(9, 9), true));
  EXPECT_EQ(rect_back, block_bound);

  block_bound = IntRect(
      web_view_helper.GetWebView()->ComputeBlockBound(WebPoint(10, 10), true));
  EXPECT_EQ(rect_left_top, block_bound);

  block_bound = IntRect(
      web_view_helper.GetWebView()->ComputeBlockBound(WebPoint(50, 50), true));
  EXPECT_EQ(rect_left_top, block_bound);

  block_bound = IntRect(
      web_view_helper.GetWebView()->ComputeBlockBound(WebPoint(89, 89), true));
  EXPECT_EQ(rect_left_top, block_bound);

  block_bound = IntRect(
      web_view_helper.GetWebView()->ComputeBlockBound(WebPoint(90, 90), true));
  EXPECT_EQ(rect_back, block_bound);

  block_bound = IntRect(web_view_helper.GetWebView()->ComputeBlockBound(
      WebPoint(109, 109), true));
  EXPECT_EQ(rect_back, block_bound);

  block_bound = IntRect(web_view_helper.GetWebView()->ComputeBlockBound(
      WebPoint(110, 110), true));
  EXPECT_EQ(rect_right_bottom, block_bound);
}

TEST_P(ParameterizedWebFrameTest, DivMultipleTargetZoomMultipleDivsTest) {
  RegisterMockedHttpURLLoad("get_multiple_divs_for_auto_zoom_test.html");

  const float kDeviceScaleFactor = 2.0f;
  int viewport_width = 640 / kDeviceScaleFactor;
  int viewport_height = 1280 / kDeviceScaleFactor;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_multiple_divs_for_auto_zoom_test.html");
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.5f, 4);
  web_view_helper.GetWebView()->SetDeviceScaleFactor(kDeviceScaleFactor);
  web_view_helper.GetWebView()->SetPageScaleFactor(0.5f);
  web_view_helper.GetWebView()->SetMaximumLegibleScale(1.f);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  WebRect viewport_rect(0, 0, viewport_width, viewport_height);
  WebRect top_div(200, 100, 200, 150);
  WebRect bottom_div(200, 300, 200, 150);
  float scale;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), WebPoint(0, 0),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);

  SimulateMultiTargetZoom(web_view_helper.GetWebView(), top_div, scale);
  EXPECT_FLOAT_EQ(1, scale);
  SimulateMultiTargetZoom(web_view_helper.GetWebView(), bottom_div, scale);
  EXPECT_FLOAT_EQ(1, scale);
  SimulateMultiTargetZoom(web_view_helper.GetWebView(), viewport_rect, scale);
  EXPECT_FLOAT_EQ(1, scale);
  web_view_helper.GetWebView()->SetPageScaleFactor(
      web_view_helper.GetWebView()->MinimumPageScaleFactor());
  SimulateMultiTargetZoom(web_view_helper.GetWebView(), top_div, scale);
  EXPECT_FLOAT_EQ(1, scale);
}

TEST_P(ParameterizedWebFrameTest, DontZoomInOnFocusedInTouchAction) {
  RegisterMockedHttpURLLoad("textbox_in_touch_action.html");

  int viewport_width = 600;
  int viewport_height = 1000;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "textbox_in_touch_action.html");
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 4);
  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(false);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetAutoZoomFocusedNodeToLegibleScale(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));

  float initial_scale = web_view_helper.GetWebView()->PageScaleFactor();

  // Focus the first textbox that's in a touch-action: pan-x ancestor, this
  // shouldn't cause an autozoom since pan-x disables pinch-zoom.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();
  EXPECT_EQ(
      web_view_helper.GetWebView()->FakePageScaleAnimationPageScaleForTesting(),
      0);

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0),
                             initial_scale);
  ASSERT_EQ(initial_scale, web_view_helper.GetWebView()->PageScaleFactor());

  // Focus the second textbox that's in a touch-action: manipulation ancestor,
  // this should cause an autozoom since it allows pinch-zoom.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();
  EXPECT_GT(
      web_view_helper.GetWebView()->FakePageScaleAnimationPageScaleForTesting(),
      initial_scale);

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0),
                             initial_scale);
  ASSERT_EQ(initial_scale, web_view_helper.GetWebView()->PageScaleFactor());

  // Focus the third textbox that has a touch-action: pan-x ancestor, this
  // should cause an autozoom since it's seperated from the node with the
  // touch-action by an overflow:scroll element.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();
  EXPECT_GT(
      web_view_helper.GetWebView()->FakePageScaleAnimationPageScaleForTesting(),
      initial_scale);
}

TEST_P(ParameterizedWebFrameTest, DivScrollIntoEditableTest) {
  RegisterMockedHttpURLLoad("get_scale_for_zoom_into_editable_test.html");

  const bool kAutoZoomToLegibleScale = true;
  int viewport_width = 450;
  int viewport_height = 300;
  float left_box_ratio = 0.3f;
  int caret_padding = 10;
  float min_readable_caret_height = 16.0f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_for_zoom_into_editable_test.html");
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 4);

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  WebRect edit_box_with_text(200, 200, 250, 20);
  WebRect edit_box_with_no_text(200, 250, 250, 20);

  // Test scrolling the focused node
  // The edit box is shorter and narrower than the viewport when legible.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  // Set the caret to the end of the input box.
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->GetDocument()
      .GetElementById("EditBoxWithText")
      .To<WebInputElement>()
      .SetSelectionRange(1000, 1000);
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0), 1);
  WebRect rect, caret;
  web_view_helper.GetWebView()->SelectionBounds(caret, rect);

  // Set the page scale to be smaller than the minimal readable scale.
  float initial_scale = min_readable_caret_height / caret.height * 0.5f;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0),
                             initial_scale);

  float scale;
  IntPoint scroll;
  bool need_animation;
  IntRect element_bounds, caret_bounds;
  GetElementAndCaretBonundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // The edit box should be left aligned with a margin for possible label.
  int h_scroll = edit_box_with_text.x - left_box_ratio * viewport_width / scale;
  EXPECT_NEAR(h_scroll, scroll.X(), 2);
  int v_scroll = edit_box_with_text.y -
                 (viewport_height / scale - edit_box_with_text.height) / 2;
  EXPECT_NEAR(v_scroll, scroll.Y(), 2);
  EXPECT_NEAR(min_readable_caret_height / caret.height, scale, 0.1);

  // The edit box is wider than the viewport when legible.
  viewport_width = 200;
  viewport_height = 150;
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0),
                             initial_scale);
  GetElementAndCaretBonundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // The caret should be right aligned since the caret would be offscreen when
  // the edit box is left aligned.
  h_scroll = caret.x + caret.width + caret_padding - viewport_width / scale;
  EXPECT_NEAR(h_scroll, scroll.X(), 2);
  EXPECT_NEAR(min_readable_caret_height / caret.height, scale, 0.1);

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0),
                             initial_scale);
  // Move focus to edit box with text.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  GetElementAndCaretBonundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // The edit box should be left aligned.
  h_scroll = edit_box_with_no_text.x;
  EXPECT_NEAR(h_scroll, scroll.X(), 2);
  v_scroll = edit_box_with_no_text.y -
             (viewport_height / scale - edit_box_with_no_text.height) / 2;
  EXPECT_NEAR(v_scroll, scroll.Y(), 2);
  EXPECT_NEAR(min_readable_caret_height / caret.height, scale, 0.1);

  // Move focus back to the first edit box.
  web_view_helper.GetWebView()->AdvanceFocus(true);
  // Zoom out slightly.
  const float within_tolerance_scale = scale * 0.9f;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), scroll,
                             within_tolerance_scale);
  // Move focus back to the second edit box.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  GetElementAndCaretBonundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  // The scale should not be adjusted as the zoomed out scale was sufficiently
  // close to the previously focused scale.
  EXPECT_FALSE(need_animation);
}

TEST_P(ParameterizedWebFrameTest, DivScrollIntoEditablePreservePageScaleTest) {
  RegisterMockedHttpURLLoad("get_scale_for_zoom_into_editable_test.html");

  const bool kAutoZoomToLegibleScale = true;
  const int kViewportWidth = 450;
  const int kViewportHeight = 300;
  const float kMinReadableCaretHeight = 16.0f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_for_zoom_into_editable_test.html");
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(false);
  web_view_helper.Resize(WebSize(kViewportWidth, kViewportHeight));
  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  const WebRect edit_box_with_text(200, 200, 250, 20);

  web_view_helper.GetWebView()->AdvanceFocus(false);
  // Set the caret to the begining of the input box.
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->GetDocument()
      .GetElementById("EditBoxWithText")
      .To<WebInputElement>()
      .SetSelectionRange(0, 0);
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0), 1);
  WebRect rect, caret;
  web_view_helper.GetWebView()->SelectionBounds(caret, rect);

  // Set the page scale to be twice as large as the minimal readable scale.
  float new_scale = kMinReadableCaretHeight / caret.height * 2.0;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0),
                             new_scale);

  float scale;
  IntPoint scroll;
  bool need_animation;
  IntRect element_bounds, caret_bounds;
  GetElementAndCaretBonundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // Edit box and caret should be left alinged
  int h_scroll = edit_box_with_text.x;
  EXPECT_NEAR(h_scroll, scroll.X(), 1);
  int v_scroll = edit_box_with_text.y -
                 (kViewportHeight / scale - edit_box_with_text.height) / 2;
  EXPECT_NEAR(v_scroll, scroll.Y(), 1);
  // Page scale have to be unchanged
  EXPECT_EQ(new_scale, scale);

  // Set page scale and scroll such that edit box will be under the screen
  new_scale = 3.0;
  h_scroll = 200;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(),
                             WebPoint(h_scroll, 0), new_scale);
  GetElementAndCaretBonundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // Horizontal scroll have to be the same
  EXPECT_NEAR(h_scroll, scroll.X(), 1);
  v_scroll = edit_box_with_text.y -
             (kViewportHeight / scale - edit_box_with_text.height) / 2;
  EXPECT_NEAR(v_scroll, scroll.Y(), 1);
  // Page scale have to be unchanged
  EXPECT_EQ(new_scale, scale);
}

// Tests the scroll into view functionality when
// autoZoomeFocusedNodeToLegibleScale set to false. i.e. The path non-Android
// platforms take.
TEST_P(ParameterizedWebFrameTest,
       DivScrollIntoEditableTestZoomToLegibleScaleDisabled) {
  RegisterMockedHttpURLLoad("get_scale_for_zoom_into_editable_test.html");

  const bool kAutoZoomToLegibleScale = false;
  int viewport_width = 100;
  int viewport_height = 100;
  float left_box_ratio = 0.3f;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_for_zoom_into_editable_test.html");
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(false);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 4);

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  WebRect edit_box_with_text(200, 200, 250, 20);
  WebRect edit_box_with_no_text(200, 250, 250, 20);

  // Test scrolling the focused node
  // Since we're zoomed out, the caret is considered too small to be legible and
  // so we'd normally zoom in. Make sure we don't change scale since the
  // auto-zoom setting is off.

  // Focus the second empty textbox.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  web_view_helper.GetWebView()->AdvanceFocus(false);

  // Set the page scale to be smaller than the minimal readable scale.
  float initial_scale = 0.25f;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), WebPoint(0, 0),
                             initial_scale);

  float scale;
  IntPoint scroll;
  bool need_animation;
  IntRect element_bounds, caret_bounds;
  GetElementAndCaretBonundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);

  // There should be no change in page scale.
  EXPECT_EQ(initial_scale, scale);
  // The edit box should be left aligned with a margin for possible label.
  EXPECT_TRUE(need_animation);
  int h_scroll =
      edit_box_with_no_text.x - left_box_ratio * viewport_width / scale;
  EXPECT_NEAR(h_scroll, scroll.X(), 2);
  int v_scroll = edit_box_with_no_text.y -
                 (viewport_height / scale - edit_box_with_no_text.height) / 2;
  EXPECT_NEAR(v_scroll, scroll.Y(), 2);

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), scroll, scale);

  // Select the first textbox.
  web_view_helper.GetWebView()->AdvanceFocus(true);
  WebRect rect, caret;
  web_view_helper.GetWebView()->SelectionBounds(caret, rect);
  GetElementAndCaretBonundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);

  // There should be no change at all since the textbox is fully visible
  // already.
  EXPECT_EQ(initial_scale, scale);
  EXPECT_FALSE(need_animation);
}

TEST_P(ParameterizedWebFrameTest, CharacterIndexAtPointWithPinchZoom) {
  RegisterMockedHttpURLLoad("sometext.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "sometext.html");
  web_view_helper.LoadAhem();
  web_view_helper.Resize(WebSize(640, 480));

  // Move the visual viewport to the start of the target div containing the
  // text.
  web_view_helper.GetWebView()->SetPageScaleFactor(2);
  web_view_helper.GetWebView()->SetVisualViewportOffset(WebFloatPoint(100, 50));

  WebRect base_rect;
  WebRect extent_rect;

  WebLocalFrame* main_frame =
      web_view_helper.GetWebView()->MainFrame()->ToWebLocalFrame();

  // Since we're zoomed in to 2X, each char of Ahem is 20px wide/tall in
  // viewport space. We expect to hit the fifth char on the first line.
  size_t ix = main_frame->CharacterIndexForPoint(WebPoint(100, 15));

  EXPECT_EQ(5ul, ix);
}

TEST_P(ParameterizedWebFrameTest, FirstRectForCharacterRangeWithPinchZoom) {
  RegisterMockedHttpURLLoad("textbox.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "textbox.html");
  web_view_helper.Resize(WebSize(640, 480));

  WebLocalFrame* main_frame = web_view_helper.LocalMainFrame();
  main_frame->ExecuteScript(WebScriptSource("selectRange();"));

  WebRect old_rect;
  main_frame->FirstRectForCharacterRange(0, 5, old_rect);

  WebFloatPoint visual_offset(100, 130);
  float scale = 2;
  web_view_helper.GetWebView()->SetPageScaleFactor(scale);
  web_view_helper.GetWebView()->SetVisualViewportOffset(visual_offset);

  WebRect base_rect;
  WebRect extent_rect;

  WebRect rect;
  main_frame->FirstRectForCharacterRange(0, 5, rect);

  EXPECT_EQ((old_rect.x - visual_offset.x) * scale, rect.x);
  EXPECT_EQ((old_rect.y - visual_offset.y) * scale, rect.y);
  EXPECT_EQ(old_rect.width * scale, rect.width);
  EXPECT_EQ(old_rect.height * scale, rect.height);
}
class TestReloadDoesntRedirectWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestReloadDoesntRedirectWebFrameClient() = default;
  ~TestReloadDoesntRedirectWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  WebNavigationPolicy DecidePolicyForNavigation(
      const NavigationPolicyInfo& info) override {
    EXPECT_FALSE(info.extra_data);
    return kWebNavigationPolicyCurrentTab;
  }
};

TEST_P(ParameterizedWebFrameTest, ReloadDoesntSetRedirect) {
  // Test for case in http://crbug.com/73104. Reloading a frame very quickly
  // would sometimes call decidePolicyForNavigation with isRedirect=true
  RegisterMockedHttpURLLoad("form.html");

  TestReloadDoesntRedirectWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "form.html", &web_frame_client);

  web_view_helper.GetWebView()->MainFrameImpl()->Reload(
      WebFrameLoadType::kReloadBypassingCache);
  // start another reload before request is delivered.
  FrameTestHelpers::ReloadFrameBypassingCache(
      web_view_helper.GetWebView()->MainFrameImpl());
}

class ClearScrollStateOnCommitWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  ClearScrollStateOnCommitWebFrameClient() = default;
  ~ClearScrollStateOnCommitWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidCommitProvisionalLoad(const WebHistoryItem&,
                                WebHistoryCommitType,
                                WebGlobalObjectReusePolicy) override {
    Frame()->View()->ResetScrollAndScaleState();
  }
};

TEST_P(ParameterizedWebFrameTest, ReloadWithOverrideURLPreservesState) {
  const std::string first_url = "200-by-300.html";
  const std::string second_url = "content-width-1000.html";
  const std::string third_url = "very_tall_div.html";
  const float kPageScaleFactor = 1.1684f;
  const int kPageWidth = 120;
  const int kPageHeight = 100;

  RegisterMockedHttpURLLoad(first_url);
  RegisterMockedHttpURLLoad(second_url);
  RegisterMockedHttpURLLoad(third_url);

  ClearScrollStateOnCommitWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + first_url, &client);
  web_view_helper.Resize(WebSize(kPageWidth, kPageHeight));
  web_view_helper.LocalMainFrame()->SetScrollOffset(
      WebSize(kPageWidth / 4, kPageHeight / 4));
  web_view_helper.GetWebView()->SetPageScaleFactor(kPageScaleFactor);

  // Reload the page and end up at the same url. State should not be propagated.
  web_view_helper.GetWebView()->MainFrameImpl()->ReloadWithOverrideURL(
      ToKURL(base_url_ + first_url), WebFrameLoadType::kReload);
  FrameTestHelpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.GetWebView()->MainFrame());
  EXPECT_EQ(0, web_view_helper.LocalMainFrame()->GetScrollOffset().width);
  EXPECT_EQ(0, web_view_helper.LocalMainFrame()->GetScrollOffset().height);
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());

  // Reload the page using the cache. State should not be propagated.
  web_view_helper.GetWebView()->MainFrameImpl()->ReloadWithOverrideURL(
      ToKURL(base_url_ + second_url), WebFrameLoadType::kReload);
  FrameTestHelpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.GetWebView()->MainFrame());
  EXPECT_EQ(0, web_view_helper.LocalMainFrame()->GetScrollOffset().width);
  EXPECT_EQ(0, web_view_helper.LocalMainFrame()->GetScrollOffset().height);
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());

  // Reload the page while bypassing the cache. State should not be propagated.
  web_view_helper.GetWebView()->MainFrameImpl()->ReloadWithOverrideURL(
      ToKURL(base_url_ + third_url), WebFrameLoadType::kReloadBypassingCache);
  FrameTestHelpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.GetWebView()->MainFrame());
  EXPECT_EQ(0, web_view_helper.LocalMainFrame()->GetScrollOffset().width);
  EXPECT_EQ(0, web_view_helper.LocalMainFrame()->GetScrollOffset().height);
  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, ReloadWhileProvisional) {
  // Test that reloading while the previous load is still pending does not cause
  // the initial request to get lost.
  RegisterMockedHttpURLLoad("fixed_layout.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  WebURLRequest request(ToKURL(base_url_ + "fixed_layout.html"));
  web_view_helper.GetWebView()->MainFrameImpl()->LoadRequest(request);
  // start reload before first request is delivered.
  FrameTestHelpers::ReloadFrameBypassingCache(
      web_view_helper.GetWebView()->MainFrameImpl());

  WebDocumentLoader* document_loader =
      web_view_helper.LocalMainFrame()->GetDocumentLoader();
  ASSERT_TRUE(document_loader);
  EXPECT_EQ(ToKURL(base_url_ + "fixed_layout.html"),
            KURL(document_loader->GetRequest().Url()));
}

TEST_P(ParameterizedWebFrameTest, AppendRedirects) {
  const std::string first_url = "about:blank";
  const std::string second_url = "http://internal.test";

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(first_url);

  WebDocumentLoader* document_loader =
      web_view_helper.LocalMainFrame()->GetDocumentLoader();
  ASSERT_TRUE(document_loader);
  document_loader->AppendRedirect(ToKURL(second_url));

  WebVector<WebURL> redirects;
  document_loader->RedirectChain(redirects);
  ASSERT_EQ(2U, redirects.size());
  EXPECT_EQ(ToKURL(first_url), KURL(redirects[0]));
  EXPECT_EQ(ToKURL(second_url), KURL(redirects[1]));
}

TEST_P(ParameterizedWebFrameTest, IframeRedirect) {
  RegisterMockedHttpURLLoad("iframe_redirect.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "iframe_redirect.html");
  // Pump pending requests one more time. The test page loads script that
  // navigates.
  FrameTestHelpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.GetWebView()->MainFrame());

  WebFrame* iframe = web_view_helper.LocalMainFrame()->FindFrameByName(
      WebString::FromUTF8("ifr"));
  ASSERT_TRUE(iframe && iframe->IsWebLocalFrame());
  WebDocumentLoader* iframe_document_loader =
      iframe->ToWebLocalFrame()->GetDocumentLoader();
  ASSERT_TRUE(iframe_document_loader);
  WebVector<WebURL> redirects;
  iframe_document_loader->RedirectChain(redirects);
  ASSERT_EQ(2U, redirects.size());
  EXPECT_EQ(ToKURL("about:blank"), KURL(redirects[0]));
  EXPECT_EQ(ToKURL("http://internal.test/visible_iframe.html"),
            KURL(redirects[1]));
}

TEST_P(ParameterizedWebFrameTest, ClearFocusedNodeTest) {
  RegisterMockedHttpURLLoad("iframe_clear_focused_node_test.html");
  RegisterMockedHttpURLLoad("autofocus_input_field_iframe.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ +
                                    "iframe_clear_focused_node_test.html");

  // Clear the focused node.
  web_view_helper.GetWebView()->ClearFocusedElement();

  // Now retrieve the FocusedNode and test it should be null.
  EXPECT_EQ(nullptr, web_view_helper.GetWebView()->FocusedElement());
}

class ChangedSelectionCounter : public FrameTestHelpers::TestWebFrameClient {
 public:
  ChangedSelectionCounter() : call_count_(0) {}
  void DidChangeSelection(bool isSelectionEmpty) { ++call_count_; }
  int Count() const { return call_count_; }
  void Reset() { call_count_ = 0; }

 private:
  int call_count_;
};

TEST_P(ParameterizedWebFrameTest, TabKeyCursorMoveTriggersOneSelectionChange) {
  ChangedSelectionCounter counter;
  FrameTestHelpers::WebViewHelper web_view_helper;
  RegisterMockedHttpURLLoad("editable_elements.html");
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "editable_elements.html", &counter);

  WebKeyboardEvent tab_down(WebInputEvent::kKeyDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());
  WebKeyboardEvent tab_up(WebInputEvent::kKeyUp, WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests());
  tab_down.dom_key = Platform::Current()->DomKeyEnumFromString("\t");
  tab_up.dom_key = Platform::Current()->DomKeyEnumFromString("\t");
  tab_down.windows_key_code = VKEY_TAB;
  tab_up.windows_key_code = VKEY_TAB;

  // Move to the next text-field: 1 cursor change.
  counter.Reset();
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_down));
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_up));
  EXPECT_EQ(1, counter.Count());

  // Move to another text-field: 1 cursor change.
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_down));
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_up));
  EXPECT_EQ(2, counter.Count());

  // Move to a number-field: 1 cursor change.
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_down));
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_up));
  EXPECT_EQ(3, counter.Count());

  // Move to an editable element: 1 cursor change.
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_down));
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_up));
  EXPECT_EQ(4, counter.Count());

  // Move to a non-editable element: 0 cursor changes.
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_down));
  web_view->HandleInputEvent(WebCoalescedInputEvent(tab_up));
  EXPECT_EQ(4, counter.Count());
}

// Implementation of WebFrameClient that tracks the v8 contexts that are created
// and destroyed for verification.
class ContextLifetimeTestWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  struct Notification {
   public:
    Notification(WebLocalFrame* frame,
                 v8::Local<v8::Context> context,
                 int world_id)
        : frame(frame),
          context(context->GetIsolate(), context),
          world_id(world_id) {}

    ~Notification() { context.Reset(); }

    bool Equals(Notification* other) {
      return other && frame == other->frame && context == other->context &&
             world_id == other->world_id;
    }

    WebLocalFrame* frame;
    v8::Persistent<v8::Context> context;
    int world_id;
  };

  ContextLifetimeTestWebFrameClient(
      Vector<std::unique_ptr<Notification>>& create_notifications,
      Vector<std::unique_ptr<Notification>>& release_notifications)
      : create_notifications_(create_notifications),
        release_notifications_(release_notifications) {}
  ~ContextLifetimeTestWebFrameClient() override = default;

  void Reset() {
    create_notifications_.clear();
    release_notifications_.clear();
  }

  // WebFrameClient:
  WebLocalFrame* CreateChildFrame(WebLocalFrame* parent,
                                  WebTreeScopeType scope,
                                  const WebString& name,
                                  const WebString& fallback_name,
                                  WebSandboxFlags sandbox_flags,
                                  const ParsedFeaturePolicy& container_policy,
                                  const WebFrameOwnerProperties&) override {
    return CreateLocalChild(*parent, scope,
                            std::make_unique<ContextLifetimeTestWebFrameClient>(
                                create_notifications_, release_notifications_));
  }

  void DidCreateScriptContext(v8::Local<v8::Context> context,
                              int world_id) override {
    create_notifications_.push_back(
        std::make_unique<Notification>(Frame(), context, world_id));
  }

  void WillReleaseScriptContext(v8::Local<v8::Context> context,
                                int world_id) override {
    release_notifications_.push_back(
        std::make_unique<Notification>(Frame(), context, world_id));
  }

 private:
  Vector<std::unique_ptr<Notification>>& create_notifications_;
  Vector<std::unique_ptr<Notification>>& release_notifications_;
};

TEST_P(ParameterizedWebFrameTest, ContextNotificationsLoadUnload) {
  v8::HandleScope handle_scope(v8::Isolate::GetCurrent());

  RegisterMockedHttpURLLoad("context_notifications_test.html");
  RegisterMockedHttpURLLoad("context_notifications_test_frame.html");

  // Load a frame with an iframe, make sure we get the right create
  // notifications.
  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      create_notifications;
  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      release_notifications;
  ContextLifetimeTestWebFrameClient web_frame_client(create_notifications,
                                                     release_notifications);
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "context_notifications_test.html", &web_frame_client);

  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  WebFrame* child_frame = main_frame->FirstChild();

  ASSERT_EQ(2u, create_notifications.size());
  EXPECT_EQ(0u, release_notifications.size());

  auto& first_create_notification = create_notifications[0];
  auto& second_create_notification = create_notifications[1];

  EXPECT_EQ(main_frame, first_create_notification->frame);
  EXPECT_EQ(main_frame->MainWorldScriptContext(),
            first_create_notification->context);
  EXPECT_EQ(0, first_create_notification->world_id);

  EXPECT_EQ(child_frame, second_create_notification->frame);
  EXPECT_EQ(child_frame->ToWebLocalFrame()->MainWorldScriptContext(),
            second_create_notification->context);
  EXPECT_EQ(0, second_create_notification->world_id);

  // Close the view. We should get two release notifications that are exactly
  // the same as the create ones, in reverse order.
  web_view_helper.Reset();

  ASSERT_EQ(2u, release_notifications.size());
  auto& first_release_notification = release_notifications[0];
  auto& second_release_notification = release_notifications[1];

  ASSERT_TRUE(
      first_create_notification->Equals(second_release_notification.get()));
  ASSERT_TRUE(
      second_create_notification->Equals(first_release_notification.get()));
}

TEST_P(ParameterizedWebFrameTest, ContextNotificationsReload) {
  v8::HandleScope handle_scope(v8::Isolate::GetCurrent());

  RegisterMockedHttpURLLoad("context_notifications_test.html");
  RegisterMockedHttpURLLoad("context_notifications_test_frame.html");

  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      create_notifications;
  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      release_notifications;
  ContextLifetimeTestWebFrameClient web_frame_client(create_notifications,
                                                     release_notifications);
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "context_notifications_test.html", &web_frame_client);

  // Refresh, we should get two release notifications and two more create
  // notifications.
  FrameTestHelpers::ReloadFrame(web_view_helper.GetWebView()->MainFrameImpl());
  ASSERT_EQ(4u, create_notifications.size());
  ASSERT_EQ(2u, release_notifications.size());

  // The two release notifications we got should be exactly the same as the
  // first two create notifications.
  for (size_t i = 0; i < release_notifications.size(); ++i) {
    EXPECT_TRUE(release_notifications[i]->Equals(
        create_notifications[create_notifications.size() - 3 - i].get()));
  }

  // The last two create notifications should be for the current frames and
  // context.
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  WebFrame* child_frame = main_frame->FirstChild();
  auto& first_refresh_notification = create_notifications[2];
  auto& second_refresh_notification = create_notifications[3];

  EXPECT_EQ(main_frame, first_refresh_notification->frame);
  EXPECT_EQ(main_frame->MainWorldScriptContext(),
            first_refresh_notification->context);
  EXPECT_EQ(0, first_refresh_notification->world_id);

  EXPECT_EQ(child_frame, second_refresh_notification->frame);
  EXPECT_EQ(child_frame->ToWebLocalFrame()->MainWorldScriptContext(),
            second_refresh_notification->context);
  EXPECT_EQ(0, second_refresh_notification->world_id);
}

TEST_P(ParameterizedWebFrameTest, ContextNotificationsIsolatedWorlds) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::HandleScope handle_scope(isolate);

  RegisterMockedHttpURLLoad("context_notifications_test.html");
  RegisterMockedHttpURLLoad("context_notifications_test_frame.html");

  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      create_notifications;
  Vector<std::unique_ptr<ContextLifetimeTestWebFrameClient::Notification>>
      release_notifications;
  ContextLifetimeTestWebFrameClient web_frame_client(create_notifications,
                                                     release_notifications);
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "context_notifications_test.html", &web_frame_client);

  // Add an isolated world.
  web_frame_client.Reset();

  int isolated_world_id = 42;
  WebScriptSource script_source("hi!");
  int num_sources = 1;
  web_view_helper.LocalMainFrame()->ExecuteScriptInIsolatedWorld(
      isolated_world_id, &script_source, num_sources);

  // We should now have a new create notification.
  ASSERT_EQ(1u, create_notifications.size());
  auto& notification = create_notifications[0];
  ASSERT_EQ(isolated_world_id, notification->world_id);
  ASSERT_EQ(web_view_helper.GetWebView()->MainFrame(), notification->frame);

  // We don't have an API to enumarate isolated worlds for a frame, but we can
  // at least assert that the context we got is *not* the main world's context.
  ASSERT_NE(web_view_helper.LocalMainFrame()->MainWorldScriptContext(),
            v8::Local<v8::Context>::New(isolate, notification->context));

  web_view_helper.Reset();

  // We should have gotten three release notifications (one for each of the
  // frames, plus one for the isolated context).
  ASSERT_EQ(3u, release_notifications.size());

  // And one of them should be exactly the same as the create notification for
  // the isolated context.
  int match_count = 0;
  for (size_t i = 0; i < release_notifications.size(); ++i) {
    if (release_notifications[i]->Equals(create_notifications[0].get()))
      ++match_count;
  }
  EXPECT_EQ(1, match_count);
}

TEST_P(ParameterizedWebFrameTest, FindInPage) {
  RegisterMockedHttpURLLoad("find.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find.html");
  ASSERT_TRUE(web_view_helper.LocalMainFrame());
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();
  const int kFindIdentifier = 12345;
  WebFindOptions options;

  // Find in a <div> element.
  EXPECT_TRUE(frame->Find(kFindIdentifier, WebString::FromUTF8("bar1"), options,
                          false));
  frame->StopFinding(WebLocalFrame::kStopFindActionKeepSelection);
  WebRange range = frame->SelectionRange();
  EXPECT_EQ(5, range.StartOffset());
  EXPECT_EQ(9, range.EndOffset());
  EXPECT_TRUE(frame->GetDocument().FocusedElement().IsNull());

  // Find in an <input> value.
  EXPECT_TRUE(frame->Find(kFindIdentifier, WebString::FromUTF8("bar2"), options,
                          false));
  // Confirm stopFinding(WebLocalFrame::StopFindActionKeepSelection) sets the
  // selection on the found text.
  frame->StopFinding(WebLocalFrame::kStopFindActionKeepSelection);
  range = frame->SelectionRange();
  ASSERT_FALSE(range.IsNull());
  EXPECT_EQ(5, range.StartOffset());
  EXPECT_EQ(9, range.EndOffset());
  EXPECT_TRUE(frame->GetDocument().FocusedElement().HasHTMLTagName("input"));

  // Find in a <textarea> content.
  EXPECT_TRUE(frame->Find(kFindIdentifier, WebString::FromUTF8("bar3"), options,
                          false));
  // Confirm stopFinding(WebLocalFrame::StopFindActionKeepSelection) sets the
  // selection on the found text.
  frame->StopFinding(WebLocalFrame::kStopFindActionKeepSelection);
  range = frame->SelectionRange();
  ASSERT_FALSE(range.IsNull());
  EXPECT_EQ(5, range.StartOffset());
  EXPECT_EQ(9, range.EndOffset());
  EXPECT_TRUE(frame->GetDocument().FocusedElement().HasHTMLTagName("textarea"));

  // Find in a contentEditable element.
  EXPECT_TRUE(frame->Find(kFindIdentifier, WebString::FromUTF8("bar4"), options,
                          false));
  // Confirm stopFinding(WebLocalFrame::StopFindActionKeepSelection) sets the
  // selection on the found text.
  frame->StopFinding(WebLocalFrame::kStopFindActionKeepSelection);
  range = frame->SelectionRange();
  ASSERT_FALSE(range.IsNull());
  EXPECT_EQ(0, range.StartOffset());
  EXPECT_EQ(4, range.EndOffset());
  // "bar4" is surrounded by <span>, but the focusable node should be the parent
  // <div>.
  EXPECT_TRUE(frame->GetDocument().FocusedElement().HasHTMLTagName("div"));

  // Find in <select> content.
  EXPECT_FALSE(frame->Find(kFindIdentifier, WebString::FromUTF8("bar5"),
                           options, false));
  // If there are any matches, stopFinding will set the selection on the found
  // text.  However, we do not expect any matches, so check that the selection
  // is null.
  frame->StopFinding(WebLocalFrame::kStopFindActionKeepSelection);
  range = frame->SelectionRange();
  ASSERT_TRUE(range.IsNull());
}

TEST_P(ParameterizedWebFrameTest, GetContentAsPlainText) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  // We set the size because it impacts line wrapping, which changes the
  // resulting text value.
  web_view_helper.Resize(WebSize(640, 480));
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // Generate a simple test case.
  const char kSimpleSource[] = "<div>Foo bar</div><div></div>baz";
  KURL test_url = ToKURL("about:blank");
  FrameTestHelpers::LoadHTMLString(frame, kSimpleSource, test_url);

  // Make sure it comes out OK.
  const std::string expected("Foo bar\nbaz");
  WebString text = WebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), std::numeric_limits<size_t>::max());
  EXPECT_EQ(expected, text.Utf8());

  // Try reading the same one with clipping of the text.
  const int kLength = 5;
  text = WebFrameContentDumper::DumpWebViewAsText(web_view_helper.GetWebView(),
                                                  kLength);
  EXPECT_EQ(expected.substr(0, kLength), text.Utf8());

  // Now do a new test with a subframe.
  const char kOuterFrameSource[] = "Hello<iframe></iframe> world";
  FrameTestHelpers::LoadHTMLString(frame, kOuterFrameSource, test_url);

  // Load something into the subframe.
  WebLocalFrame* subframe = frame->FirstChild()->ToWebLocalFrame();
  ASSERT_TRUE(subframe);
  FrameTestHelpers::LoadHTMLString(subframe, "sub<p>text", test_url);

  text = WebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), std::numeric_limits<size_t>::max());
  EXPECT_EQ("Hello world\n\nsub\n\ntext", text.Utf8());

  // Get the frame text where the subframe separator falls on the boundary of
  // what we'll take. There used to be a crash in this case.
  text = WebFrameContentDumper::DumpWebViewAsText(web_view_helper.GetWebView(),
                                                  12);
  EXPECT_EQ("Hello world", text.Utf8());
}

TEST_P(ParameterizedWebFrameTest, GetFullHtmlOfPage) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // Generate a simple test case.
  const char kSimpleSource[] = "<p>Hello</p><p>World</p>";
  KURL test_url = ToKURL("about:blank");
  FrameTestHelpers::LoadHTMLString(frame, kSimpleSource, test_url);

  WebString text = WebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), std::numeric_limits<size_t>::max());
  EXPECT_EQ("Hello\n\nWorld", text.Utf8());

  const std::string html = WebFrameContentDumper::DumpAsMarkup(frame).Utf8();

  // Load again with the output html.
  FrameTestHelpers::LoadHTMLString(frame, html, test_url);

  EXPECT_EQ(html, WebFrameContentDumper::DumpAsMarkup(frame).Utf8());

  text = WebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), std::numeric_limits<size_t>::max());
  EXPECT_EQ("Hello\n\nWorld", text.Utf8());

  // Test selection check
  EXPECT_FALSE(frame->HasSelection());
  frame->ExecuteCommand(WebString::FromUTF8("SelectAll"));
  EXPECT_TRUE(frame->HasSelection());
  frame->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_FALSE(frame->HasSelection());
  WebString selection_html = frame->SelectionAsMarkup();
  EXPECT_TRUE(selection_html.IsEmpty());
}

class TestExecuteScriptDuringDidCreateScriptContext
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestExecuteScriptDuringDidCreateScriptContext() = default;
  ~TestExecuteScriptDuringDidCreateScriptContext() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidCreateScriptContext(v8::Local<v8::Context> context,
                              int world_id) override {
    Frame()->ExecuteScript(WebScriptSource("window.history = 'replaced';"));
  }
};

TEST_P(ParameterizedWebFrameTest, ExecuteScriptDuringDidCreateScriptContext) {
  RegisterMockedHttpURLLoad("hello_world.html");

  TestExecuteScriptDuringDidCreateScriptContext web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "hello_world.html",
                                    &web_frame_client);

  FrameTestHelpers::ReloadFrame(web_view_helper.GetWebView()->MainFrameImpl());
}

class FindUpdateWebFrameClient : public FrameTestHelpers::TestWebFrameClient {
 public:
  FindUpdateWebFrameClient()
      : find_results_are_ready_(false), count_(-1), active_index_(-1) {}
  ~FindUpdateWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void ReportFindInPageMatchCount(int, int count, bool final_update) override {
    count_ = count;
    if (final_update)
      find_results_are_ready_ = true;
  }

  void ReportFindInPageSelection(int,
                                 int active_match_ordinal,
                                 const WebRect&) override {
    active_index_ = active_match_ordinal;
  }

  bool FindResultsAreReady() const { return find_results_are_ready_; }
  int Count() const { return count_; }
  int ActiveIndex() const { return active_index_; }

 private:
  bool find_results_are_ready_;
  int count_;
  int active_index_;
};

TEST_P(ParameterizedWebFrameTest, FindInPageMatchRects) {
  RegisterMockedHttpURLLoad("find_in_page_frame.html");

  FindUpdateWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_page_frame.html",
                                    &client);
  web_view_helper.Resize(WebSize(640, 480));
  web_view_helper.GetWebView()->SetMaximumLegibleScale(1.f);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  RunPendingTasks();

  // Note that the 'result 19' in the <select> element is not expected to
  // produce a match. Also, results 00 and 01 are in a different frame that is
  // not included in this test.
  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;
  const int kNumResults = 17;

  WebFindOptions options;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  EXPECT_TRUE(main_frame->Find(kFindIdentifier, search_text, options, false));

  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = static_cast<WebLocalFrameImpl*>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, options);
  }

  RunPendingTasks();
  EXPECT_TRUE(client.FindResultsAreReady());

  WebVector<WebFloatRect> web_match_rects;
  main_frame->FindMatchRects(web_match_rects);
  ASSERT_EQ(static_cast<size_t>(kNumResults), web_match_rects.size());
  int rects_version = main_frame->FindMatchMarkersVersion();

  for (int result_index = 0; result_index < kNumResults; ++result_index) {
    FloatRect result_rect =
        static_cast<FloatRect>(web_match_rects[result_index]);

    // Select the match by the center of its rect.
    EXPECT_EQ(main_frame->SelectNearestFindMatch(result_rect.Center(), nullptr),
              result_index + 1);

    // Check that the find result ordering matches with our expectations.
    Range* result = main_frame->GetTextFinder()->ActiveMatch();
    ASSERT_TRUE(result);
    result->setEnd(result->endContainer(), result->endOffset() + 3);
    EXPECT_EQ(result->GetText(),
              String::Format("%s %02d", kFindString, result_index + 2));

    // Verify that the expected match rect also matches the currently active
    // match.  Compare the enclosing rects to prevent precision issues caused by
    // CSS transforms.
    FloatRect active_match = main_frame->ActiveFindMatchRect();
    EXPECT_EQ(EnclosingIntRect(active_match), EnclosingIntRect(result_rect));

    // The rects version should not have changed.
    EXPECT_EQ(main_frame->FindMatchMarkersVersion(), rects_version);
  }

  // Resizing should update the rects version.
  web_view_helper.Resize(WebSize(800, 600));
  RunPendingTasks();
  EXPECT_TRUE(main_frame->FindMatchMarkersVersion() != rects_version);
}

TEST_P(ParameterizedWebFrameTest, FindInPageActiveIndex) {
  RegisterMockedHttpURLLoad("find_match_count.html");

  FindUpdateWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_match_count.html",
                                    &client);
  web_view_helper.GetWebView()->Resize(WebSize(640, 480));
  RunPendingTasks();

  const char* kFindString = "a";
  const int kFindIdentifier = 7777;
  const int kActiveIndex = 1;

  WebFindOptions options;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  EXPECT_TRUE(main_frame->Find(kFindIdentifier, search_text, options, false));
  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = static_cast<WebLocalFrameImpl*>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, options);
  }

  RunPendingTasks();
  EXPECT_TRUE(main_frame->Find(kFindIdentifier, search_text, options, false));
  main_frame->StopFinding(WebLocalFrame::kStopFindActionClearSelection);

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = static_cast<WebLocalFrameImpl*>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, options);
  }

  RunPendingTasks();
  EXPECT_TRUE(client.FindResultsAreReady());
  EXPECT_EQ(kActiveIndex, client.ActiveIndex());

  const char* kFindStringNew = "e";
  WebString search_text_new = WebString::FromUTF8(kFindStringNew);

  EXPECT_TRUE(
      main_frame->Find(kFindIdentifier, search_text_new, options, false));
  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = static_cast<WebLocalFrameImpl*>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(
        kFindIdentifier, search_text_new, options);
  }

  RunPendingTasks();
  EXPECT_TRUE(client.FindResultsAreReady());
  EXPECT_EQ(kActiveIndex, client.ActiveIndex());
}

TEST_P(ParameterizedWebFrameTest, FindOnDetachedFrame) {
  RegisterMockedHttpURLLoad("find_in_page.html");
  RegisterMockedHttpURLLoad("find_in_page_frame.html");

  FindUpdateWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_page.html", &client);
  web_view_helper.Resize(WebSize(640, 480));
  RunPendingTasks();

  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;

  WebFindOptions options;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  WebLocalFrameImpl* second_frame =
      ToWebLocalFrameImpl(main_frame->TraverseNext());

  // Detach the frame before finding.
  RemoveElementById(main_frame, "frame");

  EXPECT_TRUE(main_frame->Find(kFindIdentifier, search_text, options, false));
  EXPECT_FALSE(
      second_frame->Find(kFindIdentifier, search_text, options, false));

  RunPendingTasks();
  EXPECT_FALSE(client.FindResultsAreReady());

  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = static_cast<WebLocalFrameImpl*>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, options);
  }

  RunPendingTasks();
  EXPECT_TRUE(client.FindResultsAreReady());
}

TEST_P(ParameterizedWebFrameTest, FindDetachFrameBeforeScopeStrings) {
  RegisterMockedHttpURLLoad("find_in_page.html");
  RegisterMockedHttpURLLoad("find_in_page_frame.html");

  FindUpdateWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_page.html", &client);
  web_view_helper.Resize(WebSize(640, 480));
  RunPendingTasks();

  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;

  WebFindOptions options;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();

  for (WebFrame* frame = main_frame; frame; frame = frame->TraverseNext()) {
    EXPECT_TRUE(frame->ToWebLocalFrame()->Find(kFindIdentifier, search_text,
                                               options, false));
  }

  RunPendingTasks();
  EXPECT_FALSE(client.FindResultsAreReady());

  // Detach the frame between finding and scoping.
  RemoveElementById(main_frame, "frame");

  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = static_cast<WebLocalFrameImpl*>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, options);
  }

  RunPendingTasks();
  EXPECT_TRUE(client.FindResultsAreReady());
}

TEST_P(ParameterizedWebFrameTest, FindDetachFrameWhileScopingStrings) {
  RegisterMockedHttpURLLoad("find_in_page.html");
  RegisterMockedHttpURLLoad("find_in_page_frame.html");

  FindUpdateWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_page.html", &client);
  web_view_helper.Resize(WebSize(640, 480));
  RunPendingTasks();

  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;

  WebFindOptions options;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();

  for (WebFrame* frame = main_frame; frame; frame = frame->TraverseNext()) {
    EXPECT_TRUE(frame->ToWebLocalFrame()->Find(kFindIdentifier, search_text,
                                               options, false));
  }

  RunPendingTasks();
  EXPECT_FALSE(client.FindResultsAreReady());

  main_frame->EnsureTextFinder().ResetMatchCount();

  for (WebLocalFrameImpl* frame = main_frame; frame;
       frame = static_cast<WebLocalFrameImpl*>(frame->TraverseNext())) {
    frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                        search_text, options);
  }

  // The first startScopingStringMatches will have reset the state. Detach
  // before it actually scopes.
  RemoveElementById(main_frame, "frame");

  RunPendingTasks();
  EXPECT_TRUE(client.FindResultsAreReady());
}

TEST_P(ParameterizedWebFrameTest, ResetMatchCount) {
  RegisterMockedHttpURLLoad("find_in_generated_frame.html");

  FindUpdateWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find_in_generated_frame.html",
                                    &client);
  web_view_helper.Resize(WebSize(640, 480));
  RunPendingTasks();

  const char kFindString[] = "result";
  const int kFindIdentifier = 12345;

  WebFindOptions options;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();

  // Check that child frame exists.
  EXPECT_TRUE(!!main_frame->TraverseNext());

  for (WebFrame* frame = main_frame; frame; frame = frame->TraverseNext()) {
    EXPECT_FALSE(frame->ToWebLocalFrame()->Find(kFindIdentifier, search_text,
                                                options, false));
  }

  RunPendingTasks();
  EXPECT_FALSE(client.FindResultsAreReady());

  main_frame->EnsureTextFinder().ResetMatchCount();
}

TEST_P(ParameterizedWebFrameTest, SetTickmarks) {
  RegisterMockedHttpURLLoad("find.html");

  FindUpdateWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find.html", &client);
  web_view_helper.Resize(WebSize(640, 480));
  RunPendingTasks();

  const char kFindString[] = "foo";
  const int kFindIdentifier = 12345;

  WebFindOptions options;
  WebString search_text = WebString::FromUTF8(kFindString);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  EXPECT_TRUE(main_frame->Find(kFindIdentifier, search_text, options, false));

  main_frame->EnsureTextFinder().ResetMatchCount();
  main_frame->EnsureTextFinder().StartScopingStringMatches(
      kFindIdentifier, search_text, options);

  RunPendingTasks();
  EXPECT_TRUE(client.FindResultsAreReady());

  // Get the tickmarks for the original find request.
  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();
  Scrollbar* scrollbar = frame_view->CreateScrollbar(kHorizontalScrollbar);
  Vector<IntRect> original_tickmarks;
  scrollbar->GetTickmarks(original_tickmarks);
  EXPECT_EQ(4u, original_tickmarks.size());

  // Override the tickmarks.
  Vector<IntRect> overriding_tickmarks_expected;
  overriding_tickmarks_expected.push_back(IntRect(0, 0, 100, 100));
  overriding_tickmarks_expected.push_back(IntRect(0, 20, 100, 100));
  overriding_tickmarks_expected.push_back(IntRect(0, 30, 100, 100));
  main_frame->SetTickmarks(overriding_tickmarks_expected);

  // Check the tickmarks are overriden correctly.
  Vector<IntRect> overriding_tickmarks_actual;
  scrollbar->GetTickmarks(overriding_tickmarks_actual);
  EXPECT_EQ(overriding_tickmarks_expected, overriding_tickmarks_actual);

  // Reset the tickmark behavior.
  Vector<IntRect> reset_tickmarks;
  main_frame->SetTickmarks(reset_tickmarks);

  // Check that the original tickmarks are returned
  Vector<IntRect> original_tickmarks_after_reset;
  scrollbar->GetTickmarks(original_tickmarks_after_reset);
  EXPECT_EQ(original_tickmarks, original_tickmarks_after_reset);
}

TEST_P(ParameterizedWebFrameTest, FindInPageJavaScriptUpdatesDOM) {
  RegisterMockedHttpURLLoad("find.html");

  FindUpdateWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find.html", &client);
  web_view_helper.Resize(WebSize(640, 480));
  RunPendingTasks();

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  const int kFindIdentifier = 12345;
  static const char* kFindString = "foo";
  WebString search_text = WebString::FromUTF8(kFindString);
  WebFindOptions options;
  bool active_now;

  frame->EnsureTextFinder().ResetMatchCount();
  frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                      search_text, options);
  RunPendingTasks();
  EXPECT_TRUE(client.FindResultsAreReady());

  // Find in a <div> element.
  options.find_next = true;
  EXPECT_TRUE(
      frame->Find(kFindIdentifier, search_text, options, false, &active_now));
  EXPECT_TRUE(active_now);

  // Insert new text, which contains occurence of |searchText|.
  frame->ExecuteScript(WebScriptSource(
      "var newTextNode = document.createTextNode('bar5 foo5');"
      "var textArea = document.getElementsByTagName('textarea')[0];"
      "document.body.insertBefore(newTextNode, textArea);"));

  // Find in a <input> element.
  EXPECT_TRUE(
      frame->Find(kFindIdentifier, search_text, options, false, &active_now));
  EXPECT_TRUE(active_now);

  // Find in the inserted text node.
  EXPECT_TRUE(
      frame->Find(kFindIdentifier, search_text, options, false, &active_now));
  frame->StopFinding(WebLocalFrame::kStopFindActionKeepSelection);
  WebRange range = frame->SelectionRange();
  EXPECT_EQ(5, range.StartOffset());
  EXPECT_EQ(8, range.EndOffset());
  EXPECT_TRUE(frame->GetDocument().FocusedElement().IsNull());
  EXPECT_FALSE(active_now);
}

struct FakeTimerSetter {
  FakeTimerSetter() {
    time_elapsed_ = 0.0;
    original_time_function_ = SetTimeFunctionsForTesting(ReturnMockTime);
  }

  ~FakeTimerSetter() { SetTimeFunctionsForTesting(original_time_function_); }
  static double ReturnMockTime() {
    time_elapsed_ += 1.0;
    return time_elapsed_;
  }

 private:
  TimeFunction original_time_function_;
  static double time_elapsed_;
};
double FakeTimerSetter::time_elapsed_ = 0.;

TEST_P(ParameterizedWebFrameTest, FindInPageJavaScriptUpdatesDOMProperOrdinal) {
  FakeTimerSetter fake_timer;

  const WebString search_pattern = WebString::FromUTF8("abc");
  // We have 2 occurrences of the pattern in our text.
  const char* html =
      "foo bar foo bar foo abc bar foo bar foo bar foo bar foo bar foo bar foo "
      "bar foo bar foo bar foo bar foo bar foo bar foo bar foo bar foo bar foo "
      "bar foo bar foo abc bar <div id='new_text'></div>";

  FindUpdateWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&client);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  FrameTestHelpers::LoadHTMLString(frame, html,
                                   URLTestHelpers::ToKURL(base_url_));
  web_view_helper.Resize(WebSize(640, 480));
  web_view_helper.GetWebView()->SetFocus(true);
  RunPendingTasks();

  const int kFindIdentifier = 12345;
  WebFindOptions options;

  // The first search that will start the scoping process.
  frame->RequestFind(kFindIdentifier, search_pattern, options);
  EXPECT_FALSE(client.FindResultsAreReady());
  EXPECT_EQ(1, client.Count());
  EXPECT_TRUE(frame->EnsureTextFinder().ScopingInProgress());

  // The scoping won't find all the entries on the first run due to the fake
  // timer.
  while (frame->EnsureTextFinder().ScopingInProgress())
    RunPendingTasks();

  EXPECT_EQ(2, client.Count());
  EXPECT_EQ(1, client.ActiveIndex());

  options.find_next = true;

  // The second search will jump to the next match without any scoping.
  frame->RequestFind(kFindIdentifier, search_pattern, options);

  EXPECT_EQ(2, client.Count());
  EXPECT_EQ(2, client.ActiveIndex());
  EXPECT_FALSE(frame->EnsureTextFinder().ScopingInProgress());

  // Insert new text, which contains occurence of |searchText|.
  frame->ExecuteScript(
      WebScriptSource("var textDiv = document.getElementById('new_text');"
                      "textDiv.innerHTML = 'foo abc';"));

  // The third search will find a new match and initiate a new scoping.
  frame->RequestFind(kFindIdentifier, search_pattern, options);

  EXPECT_TRUE(frame->EnsureTextFinder().ScopingInProgress());

  while (frame->EnsureTextFinder().ScopingInProgress())
    RunPendingTasks();

  EXPECT_EQ(3, client.Count());
  EXPECT_EQ(3, client.ActiveIndex());
}

TEST_P(ParameterizedWebFrameTest,
       FindInPageStopFindActionKeepSelectionInAnotherDocument) {
  RegisterMockedHttpURLLoad("find.html");
  RegisterMockedHttpURLLoad("hello_world.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "find.html");
  ASSERT_TRUE(web_view_helper.LocalMainFrame());
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();
  const int kFindIdentifier = 12345;
  WebFindOptions options;

  // Set active match
  ASSERT_TRUE(
      frame->Find(kFindIdentifier, WebString::FromUTF8("foo"), options, false));
  // Move to another page.
  FrameTestHelpers::LoadFrame(frame, base_url_ + "hello_world.html");

  // Stop Find-In-Page. |TextFinder::active_match_| still hold a |Range| in
  // "find.html".
  frame->StopFinding(WebLocalFrame::kStopFindActionKeepSelection);

  // Pass if not crash. See http://crbug.com/719880 for details.
}

static WebPoint TopLeft(const WebRect& rect) {
  return WebPoint(rect.x, rect.y);
}

static WebPoint BottomRightMinusOne(const WebRect& rect) {
  // FIXME: If we don't subtract 1 from the x- and y-coordinates of the
  // selection bounds, selectRange() will select the *next* element. That's
  // strictly correct, as hit-testing checks the pixel to the lower-right of
  // the input coordinate, but it's a wart on the API.
  return WebPoint(rect.x + rect.width - 1, rect.y + rect.height - 1);
}

static WebRect ElementBounds(WebLocalFrame* frame, const WebString& id) {
  return frame->GetDocument().GetElementById(id).BoundsInViewport();
}

static std::string SelectionAsString(WebFrame* frame) {
  return frame->ToWebLocalFrame()->SelectionAsText().Utf8();
}

TEST_P(ParameterizedWebFrameTest, SelectRange) {
  WebLocalFrame* frame;
  WebRect start_web_rect;
  WebRect end_web_rect;

  RegisterMockedHttpURLLoad("select_range_basic.html");
  RegisterMockedHttpURLLoad("select_range_scroll.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("Some test text for testing.", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);
  frame->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_EQ("", SelectionAsString(frame));
  frame->SelectRange(TopLeft(start_web_rect),
                     BottomRightMinusOne(end_web_rect));
  // On some devices, the above bottomRightMinusOne() causes the ending '.' not
  // selected.
  std::string selection_string = SelectionAsString(frame);
  EXPECT_TRUE(selection_string == "Some test text for testing." ||
              selection_string == "Some test text for testing");

  InitializeTextSelectionWebView(base_url_ + "select_range_scroll.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("Some offscreen test text for testing.", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);
  frame->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_EQ("", SelectionAsString(frame));
  frame->SelectRange(TopLeft(start_web_rect),
                     BottomRightMinusOne(end_web_rect));
  // On some devices, the above bottomRightMinusOne() causes the ending '.' not
  // selected.
  selection_string = SelectionAsString(frame);
  EXPECT_TRUE(selection_string == "Some offscreen test text for testing." ||
              selection_string == "Some offscreen test text for testing");
}

TEST_P(ParameterizedWebFrameTest, SelectRangeDefaultHandleVisibility) {
  RegisterMockedHttpURLLoad("select_range_basic.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide);
  EXPECT_FALSE(frame->SelectionRange().IsNull());

  EXPECT_FALSE(frame->GetFrame()->Selection().IsHandleVisible())
      << "By default selection handles should not be visible";
}

TEST_P(ParameterizedWebFrameTest, SelectRangeHideHandle) {
  RegisterMockedHttpURLLoad("select_range_basic.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide);

  EXPECT_FALSE(frame->GetFrame()->Selection().IsHandleVisible())
      << "Selection handle should not be visible with kHideSelectionHandle";
}

TEST_P(ParameterizedWebFrameTest, SelectRangeShowHandle) {
  RegisterMockedHttpURLLoad("select_range_basic.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kShowSelectionHandle,
                     SelectionMenuBehavior::kHide);

  EXPECT_TRUE(frame->GetFrame()->Selection().IsHandleVisible())
      << "Selection handle should be visible with kShowSelectionHandle";
}

TEST_P(ParameterizedWebFrameTest, SelectRangePreserveHandleVisibility) {
  RegisterMockedHttpURLLoad("select_range_basic.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_basic.html",
                                 &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide);
  frame->SelectRange(WebRange(0, 6), WebLocalFrame::kPreserveHandleVisibility,
                     SelectionMenuBehavior::kHide);

  EXPECT_FALSE(frame->GetFrame()->Selection().IsHandleVisible())
      << "kPreserveHandleVisibility should keep handles invisible";

  frame->SelectRange(WebRange(0, 5), WebLocalFrame::kShowSelectionHandle,
                     SelectionMenuBehavior::kHide);
  frame->SelectRange(WebRange(0, 6), WebLocalFrame::kPreserveHandleVisibility,
                     SelectionMenuBehavior::kHide);

  EXPECT_TRUE(frame->GetFrame()->Selection().IsHandleVisible())
      << "kPreserveHandleVisibility should keep handles visible";
}

TEST_P(ParameterizedWebFrameTest, SelectRangeInIframe) {
  WebFrame* frame;
  WebRect start_web_rect;
  WebRect end_web_rect;

  RegisterMockedHttpURLLoad("select_range_iframe.html");
  RegisterMockedHttpURLLoad("select_range_basic.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_iframe.html",
                                 &web_view_helper);
  frame = web_view_helper.GetWebView()->MainFrame();
  WebLocalFrame* subframe = frame->FirstChild()->ToWebLocalFrame();
  EXPECT_EQ("Some test text for testing.", SelectionAsString(subframe));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);
  subframe->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_EQ("", SelectionAsString(subframe));
  subframe->SelectRange(TopLeft(start_web_rect),
                        BottomRightMinusOne(end_web_rect));
  // On some devices, the above bottomRightMinusOne() causes the ending '.' not
  // selected.
  std::string selection_string = SelectionAsString(subframe);
  EXPECT_TRUE(selection_string == "Some test text for testing." ||
              selection_string == "Some test text for testing");
}

TEST_P(ParameterizedWebFrameTest, SelectRangeDivContentEditable) {
  WebLocalFrame* frame;
  WebRect start_web_rect;
  WebRect end_web_rect;

  RegisterMockedHttpURLLoad("select_range_div_editable.html");

  // Select the middle of an editable element, then try to extend the selection
  // to the top of the document.  The selection range should be clipped to the
  // bounds of the editable element.
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_div_editable.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);

  frame->SelectRange(BottomRightMinusOne(end_web_rect), WebPoint(0, 0));
  EXPECT_EQ("16-char header. This text is initially selected.",
            SelectionAsString(frame));

  // As above, but extending the selection to the bottom of the document.
  InitializeTextSelectionWebView(base_url_ + "select_range_div_editable.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();

  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);
  frame->SelectRange(TopLeft(start_web_rect),
                     BottomRightMinusOne(end_web_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);

  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);
  frame->SelectRange(TopLeft(start_web_rect), WebPoint(640, 480));
  EXPECT_EQ("This text is initially selected. 16-char footer.",
            SelectionAsString(frame));
}

// positionForPoint returns the wrong values for contenteditable spans. See
// http://crbug.com/238334.
TEST_P(ParameterizedWebFrameTest, DISABLED_SelectRangeSpanContentEditable) {
  WebLocalFrame* frame;
  WebRect start_web_rect;
  WebRect end_web_rect;

  RegisterMockedHttpURLLoad("select_range_span_editable.html");

  // Select the middle of an editable element, then try to extend the selection
  // to the top of the document.
  // The selection range should be clipped to the bounds of the editable
  // element.
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_span_editable.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);

  frame->SelectRange(BottomRightMinusOne(end_web_rect), WebPoint(0, 0));
  EXPECT_EQ("16-char header. This text is initially selected.",
            SelectionAsString(frame));

  // As above, but extending the selection to the bottom of the document.
  InitializeTextSelectionWebView(base_url_ + "select_range_span_editable.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();

  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);
  frame->SelectRange(TopLeft(start_web_rect),
                     BottomRightMinusOne(end_web_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);

  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);
  frame->SelectRange(TopLeft(start_web_rect), WebPoint(640, 480));
  EXPECT_EQ("This text is initially selected. 16-char footer.",
            SelectionAsString(frame));
}

TEST_P(ParameterizedWebFrameTest, SelectRangeCanMoveSelectionStart) {
  RegisterMockedHttpURLLoad("text_selection.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "text_selection.html",
                                 &web_view_helper);
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // Select second span. We can move the start to include the first span.
  frame->ExecuteScript(WebScriptSource("selectElement('header_2');"));
  EXPECT_EQ("Header 2.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "header_2")),
                     TopLeft(ElementBounds(frame, "header_1")));
  EXPECT_EQ("Header 1. Header 2.", SelectionAsString(frame));

  // We can move the start and end together.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "header_1")),
                     BottomRightMinusOne(ElementBounds(frame, "header_1")));
  EXPECT_EQ("", SelectionAsString(frame));
  // Selection is a caret, not empty.
  EXPECT_FALSE(frame->SelectionRange().IsNull());

  // We can move the start across the end.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "header_1")),
                     BottomRightMinusOne(ElementBounds(frame, "header_2")));
  EXPECT_EQ(" Header 2.", SelectionAsString(frame));

  // Can't extend the selection part-way into an editable element.
  frame->ExecuteScript(WebScriptSource("selectElement('footer_2');"));
  EXPECT_EQ("Footer 2.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "footer_2")),
                     TopLeft(ElementBounds(frame, "editable_2")));
  EXPECT_EQ(" [ Footer 1. Footer 2.", SelectionAsString(frame));

  // Can extend the selection completely across editable elements.
  frame->ExecuteScript(WebScriptSource("selectElement('footer_2');"));
  EXPECT_EQ("Footer 2.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "footer_2")),
                     TopLeft(ElementBounds(frame, "header_2")));
  EXPECT_EQ("Header 2. ] [ Editable 1. Editable 2. ] [ Footer 1. Footer 2.",
            SelectionAsString(frame));

  // If the selection is editable text, we can't extend it into non-editable
  // text.
  frame->ExecuteScript(WebScriptSource("selectElement('editable_2');"));
  EXPECT_EQ("Editable 2.", SelectionAsString(frame));
  frame->SelectRange(BottomRightMinusOne(ElementBounds(frame, "editable_2")),
                     TopLeft(ElementBounds(frame, "header_2")));
  // positionForPoint returns the wrong values for contenteditable spans. See
  // http://crbug.com/238334.
  // EXPECT_EQ("[ Editable 1. Editable 2.", selectionAsString(frame));
}

TEST_P(ParameterizedWebFrameTest, SelectRangeCanMoveSelectionEnd) {
  RegisterMockedHttpURLLoad("text_selection.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "text_selection.html",
                                 &web_view_helper);
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // Select first span. We can move the end to include the second span.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(TopLeft(ElementBounds(frame, "header_1")),
                     BottomRightMinusOne(ElementBounds(frame, "header_2")));
  EXPECT_EQ("Header 1. Header 2.", SelectionAsString(frame));

  // We can move the start and end together.
  frame->ExecuteScript(WebScriptSource("selectElement('header_2');"));
  EXPECT_EQ("Header 2.", SelectionAsString(frame));
  frame->SelectRange(TopLeft(ElementBounds(frame, "header_2")),
                     TopLeft(ElementBounds(frame, "header_2")));
  EXPECT_EQ("", SelectionAsString(frame));
  // Selection is a caret, not empty.
  EXPECT_FALSE(frame->SelectionRange().IsNull());

  // We can move the end across the start.
  frame->ExecuteScript(WebScriptSource("selectElement('header_2');"));
  EXPECT_EQ("Header 2.", SelectionAsString(frame));
  frame->SelectRange(TopLeft(ElementBounds(frame, "header_2")),
                     TopLeft(ElementBounds(frame, "header_1")));
  EXPECT_EQ("Header 1. ", SelectionAsString(frame));

  // Can't extend the selection part-way into an editable element.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(TopLeft(ElementBounds(frame, "header_1")),
                     BottomRightMinusOne(ElementBounds(frame, "editable_1")));
  EXPECT_EQ("Header 1. Header 2. ] ", SelectionAsString(frame));

  // Can extend the selection completely across editable elements.
  frame->ExecuteScript(WebScriptSource("selectElement('header_1');"));
  EXPECT_EQ("Header 1.", SelectionAsString(frame));
  frame->SelectRange(TopLeft(ElementBounds(frame, "header_1")),
                     BottomRightMinusOne(ElementBounds(frame, "footer_1")));
  EXPECT_EQ("Header 1. Header 2. ] [ Editable 1. Editable 2. ] [ Footer 1.",
            SelectionAsString(frame));

  // If the selection is editable text, we can't extend it into non-editable
  // text.
  frame->ExecuteScript(WebScriptSource("selectElement('editable_1');"));
  EXPECT_EQ("Editable 1.", SelectionAsString(frame));
  frame->SelectRange(TopLeft(ElementBounds(frame, "editable_1")),
                     BottomRightMinusOne(ElementBounds(frame, "footer_1")));
  // positionForPoint returns the wrong values for contenteditable spans. See
  // http://crbug.com/238334.
  // EXPECT_EQ("Editable 1. Editable 2. ]", selectionAsString(frame));
}

TEST_P(ParameterizedWebFrameTest, MoveRangeSelectionExtent) {
  WebLocalFrameImpl* frame;
  WebRect start_web_rect;
  WebRect end_web_rect;

  RegisterMockedHttpURLLoad("move_range_selection_extent.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "move_range_selection_extent.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);

  frame->MoveRangeSelectionExtent(WebPoint(640, 480));
  EXPECT_EQ("This text is initially selected. 16-char footer.",
            SelectionAsString(frame));

  frame->MoveRangeSelectionExtent(WebPoint(0, 0));
  EXPECT_EQ("16-char header. ", SelectionAsString(frame));

  // Reset with swapped base and extent.
  frame->SelectRange(TopLeft(end_web_rect),
                     BottomRightMinusOne(start_web_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));

  frame->MoveRangeSelectionExtent(WebPoint(640, 480));
  EXPECT_EQ(" 16-char footer.", SelectionAsString(frame));

  frame->MoveRangeSelectionExtent(WebPoint(0, 0));
  EXPECT_EQ("16-char header. This text is initially selected.",
            SelectionAsString(frame));

  frame->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_EQ("", SelectionAsString(frame));
}

TEST_P(ParameterizedWebFrameTest, MoveRangeSelectionExtentCannotCollapse) {
  WebLocalFrameImpl* frame;
  WebRect start_web_rect;
  WebRect end_web_rect;

  RegisterMockedHttpURLLoad("move_range_selection_extent.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "move_range_selection_extent.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);

  frame->MoveRangeSelectionExtent(BottomRightMinusOne(start_web_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));

  // Reset with swapped base and extent.
  frame->SelectRange(TopLeft(end_web_rect),
                     BottomRightMinusOne(start_web_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));

  frame->MoveRangeSelectionExtent(BottomRightMinusOne(end_web_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
}

TEST_P(ParameterizedWebFrameTest, MoveRangeSelectionExtentScollsInputField) {
  WebLocalFrameImpl* frame;
  WebRect start_web_rect;
  WebRect end_web_rect;

  RegisterMockedHttpURLLoad("move_range_selection_extent_input_field.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(
      base_url_ + "move_range_selection_extent_input_field.html",
      &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("Length", SelectionAsString(frame));
  web_view_helper.GetWebView()->SelectionBounds(start_web_rect, end_web_rect);

  EXPECT_EQ(0, frame->GetFrame()
                   ->Selection()
                   .ComputeVisibleSelectionInDOMTree()
                   .RootEditableElement()
                   ->scrollLeft());
  frame->MoveRangeSelectionExtent(
      WebPoint(end_web_rect.x + 500, end_web_rect.y));
  EXPECT_GE(frame->GetFrame()
                ->Selection()
                .ComputeVisibleSelectionInDOMTree()
                .RootEditableElement()
                ->scrollLeft(),
            1);
  EXPECT_EQ("Lengthy text goes here.", SelectionAsString(frame));
}

static int ComputeOffset(LayoutObject* layout_object, int x, int y) {
  return layout_object->PositionForPoint(LayoutPoint(x, y))
      .GetPosition()
      .ComputeOffsetInContainerNode();
}

// positionForPoint returns the wrong values for contenteditable spans. See
// http://crbug.com/238334.
TEST_P(ParameterizedWebFrameTest, DISABLED_PositionForPointTest) {
  RegisterMockedHttpURLLoad("select_range_span_editable.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_span_editable.html",
                                 &web_view_helper);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  LayoutObject* layout_object = main_frame->GetFrame()
                                    ->Selection()
                                    .ComputeVisibleSelectionInDOMTree()
                                    .RootEditableElement()
                                    ->GetLayoutObject();
  EXPECT_EQ(0, ComputeOffset(layout_object, -1, -1));
  EXPECT_EQ(64, ComputeOffset(layout_object, 1000, 1000));

  RegisterMockedHttpURLLoad("select_range_div_editable.html");
  InitializeTextSelectionWebView(base_url_ + "select_range_div_editable.html",
                                 &web_view_helper);
  main_frame = web_view_helper.LocalMainFrame();
  layout_object = main_frame->GetFrame()
                      ->Selection()
                      .ComputeVisibleSelectionInDOMTree()
                      .RootEditableElement()
                      ->GetLayoutObject();
  EXPECT_EQ(0, ComputeOffset(layout_object, -1, -1));
  EXPECT_EQ(64, ComputeOffset(layout_object, 1000, 1000));
}

#if !defined(OS_MACOSX) && !defined(OS_LINUX)
TEST_P(ParameterizedWebFrameTest,
       SelectRangeStaysHorizontallyAlignedWhenMoved) {
  RegisterMockedHttpURLLoad("move_caret.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "move_caret.html",
                                 &web_view_helper);
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();

  WebRect initial_start_rect;
  WebRect initial_end_rect;
  WebRect start_rect;
  WebRect end_rect;

  frame->ExecuteScript(WebScriptSource("selectRange();"));
  web_view_helper.GetWebView()->SelectionBounds(initial_start_rect,
                                                initial_end_rect);
  WebPoint moved_start(TopLeft(initial_start_rect));

  moved_start.y += 40;
  frame->SelectRange(moved_start, BottomRightMinusOne(initial_end_rect));
  web_view_helper.GetWebView()->SelectionBounds(start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);

  moved_start.y -= 80;
  frame->SelectRange(moved_start, BottomRightMinusOne(initial_end_rect));
  web_view_helper.GetWebView()->SelectionBounds(start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);

  WebPoint moved_end(BottomRightMinusOne(initial_end_rect));

  moved_end.y += 40;
  frame->SelectRange(TopLeft(initial_start_rect), moved_end);
  web_view_helper.GetWebView()->SelectionBounds(start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);

  moved_end.y -= 80;
  frame->SelectRange(TopLeft(initial_start_rect), moved_end);
  web_view_helper.GetWebView()->SelectionBounds(start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);
}

TEST_P(ParameterizedWebFrameTest, MoveCaretStaysHorizontallyAlignedWhenMoved) {
  WebLocalFrameImpl* frame;
  RegisterMockedHttpURLLoad("move_caret.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "move_caret.html",
                                 &web_view_helper);
  frame = (WebLocalFrameImpl*)web_view_helper.GetWebView()->MainFrame();

  WebRect initial_start_rect;
  WebRect initial_end_rect;
  WebRect start_rect;
  WebRect end_rect;

  frame->ExecuteScript(WebScriptSource("selectCaret();"));
  web_view_helper.GetWebView()->SelectionBounds(initial_start_rect,
                                                initial_end_rect);
  WebPoint move_to(TopLeft(initial_start_rect));

  move_to.y += 40;
  frame->MoveCaretSelection(move_to);
  web_view_helper.GetWebView()->SelectionBounds(start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);

  move_to.y -= 80;
  frame->MoveCaretSelection(move_to);
  web_view_helper.GetWebView()->SelectionBounds(start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);
}
#endif

class CompositedSelectionBoundsTestLayerTreeView : public WebLayerTreeView {
 public:
  CompositedSelectionBoundsTestLayerTreeView() : selection_cleared_(false) {}
  ~CompositedSelectionBoundsTestLayerTreeView() override = default;

  // WebLayerTreeView:
  void RegisterSelection(const WebSelection& selection) override {
    selection_ = std::make_unique<WebSelection>(selection);
  }
  void ClearSelection() override {
    selection_cleared_ = true;
    selection_.reset();
  }

  bool GetAndResetSelectionCleared() {
    bool selection_cleared = selection_cleared_;
    selection_cleared_ = false;
    return selection_cleared;
  }

  const WebSelection* Selection() const { return selection_.get(); }
  const WebSelectionBound* Start() const {
    return selection_ ? &selection_->Start() : nullptr;
  }
  const WebSelectionBound* end() const {
    return selection_ ? &selection_->end() : nullptr;
  }

 private:
  bool selection_cleared_;
  std::unique_ptr<WebSelection> selection_;
};

class CompositedSelectionBoundsTestWebViewClient
    : public FrameTestHelpers::TestWebViewClient {
 public:
  ~CompositedSelectionBoundsTestWebViewClient() override = default;
  WebLayerTreeView* InitializeLayerTreeView() override {
    return &test_layer_tree_view_;
  }

  CompositedSelectionBoundsTestLayerTreeView& SelectionLayerTreeView() {
    return test_layer_tree_view_;
  }

 private:
  CompositedSelectionBoundsTestLayerTreeView test_layer_tree_view_;
};

class CompositedSelectionBoundsTest
    : public ParameterizedWebFrameTest,
      private ScopedCompositedSelectionUpdateForTest {
 protected:
  CompositedSelectionBoundsTest()
      : ScopedCompositedSelectionUpdateForTest(true),
        fake_selection_layer_tree_view_(
            fake_selection_web_view_client_.SelectionLayerTreeView()) {
    RegisterMockedHttpURLLoad("Ahem.ttf");

    web_view_helper_.Initialize(nullptr, &fake_selection_web_view_client_);
    web_view_helper_.GetWebView()->GetSettings()->SetDefaultFontSize(12);
    web_view_helper_.GetWebView()->SetDefaultPageScaleLimits(1, 1);
    web_view_helper_.Resize(WebSize(640, 480));
  }

  void RunTestWithNoSelection(const char* test_file) {
    RegisterMockedHttpURLLoad(test_file);
    web_view_helper_.GetWebView()->SetFocus(true);
    FrameTestHelpers::LoadFrame(web_view_helper_.GetWebView()->MainFrameImpl(),
                                base_url_ + test_file);
    web_view_helper_.GetWebView()->UpdateAllLifecyclePhases();

    const WebSelection* selection = fake_selection_layer_tree_view_.Selection();
    const WebSelectionBound* select_start =
        fake_selection_layer_tree_view_.Start();
    const WebSelectionBound* select_end = fake_selection_layer_tree_view_.end();

    EXPECT_FALSE(selection);
    EXPECT_FALSE(select_start);
    EXPECT_FALSE(select_end);
  }

  void RunTest(const char* test_file) {
    RegisterMockedHttpURLLoad(test_file);
    web_view_helper_.GetWebView()->SetFocus(true);
    FrameTestHelpers::LoadFrame(web_view_helper_.GetWebView()->MainFrameImpl(),
                                base_url_ + test_file);
    web_view_helper_.GetWebView()->UpdateAllLifecyclePhases();

    v8::HandleScope handle_scope(v8::Isolate::GetCurrent());
    v8::Local<v8::Value> result =
        web_view_helper_.GetWebView()
            ->MainFrameImpl()
            ->ExecuteScriptAndReturnValue(WebScriptSource("expectedResult"));
    ASSERT_FALSE(result.IsEmpty() || (*result)->IsUndefined());

    ASSERT_TRUE((*result)->IsArray());
    v8::Array& expected_result = *v8::Array::Cast(*result);
    ASSERT_GE(expected_result.Length(), 10u);

    v8::Local<v8::Context> context =
        v8::Isolate::GetCurrent()->GetCurrentContext();

    const int start_edge_top_in_layer_x = expected_result.Get(context, 1)
                                              .ToLocalChecked()
                                              .As<v8::Int32>()
                                              ->Value();
    const int start_edge_top_in_layer_y = expected_result.Get(context, 2)
                                              .ToLocalChecked()
                                              .As<v8::Int32>()
                                              ->Value();
    const int start_edge_bottom_in_layer_x = expected_result.Get(context, 3)
                                                 .ToLocalChecked()
                                                 .As<v8::Int32>()
                                                 ->Value();
    const int start_edge_bottom_in_layer_y = expected_result.Get(context, 4)
                                                 .ToLocalChecked()
                                                 .As<v8::Int32>()
                                                 ->Value();

    const int end_edge_top_in_layer_x = expected_result.Get(context, 6)
                                            .ToLocalChecked()
                                            .As<v8::Int32>()
                                            ->Value();
    const int end_edge_top_in_layer_y = expected_result.Get(context, 7)
                                            .ToLocalChecked()
                                            .As<v8::Int32>()
                                            ->Value();
    const int end_edge_bottom_in_layer_x = expected_result.Get(context, 8)
                                               .ToLocalChecked()
                                               .As<v8::Int32>()
                                               ->Value();
    const int end_edge_bottom_in_layer_y = expected_result.Get(context, 9)
                                               .ToLocalChecked()
                                               .As<v8::Int32>()
                                               ->Value();

    FloatPoint hit_point;

    if (expected_result.Length() >= 17) {
      hit_point = FloatPoint(expected_result.Get(context, 15)
                                 .ToLocalChecked()
                                 .As<v8::Int32>()
                                 ->Value(),
                             expected_result.Get(context, 16)
                                 .ToLocalChecked()
                                 .As<v8::Int32>()
                                 ->Value());
    } else {
      hit_point =
          FloatPoint((start_edge_top_in_layer_x + start_edge_bottom_in_layer_x +
                      end_edge_top_in_layer_x + end_edge_bottom_in_layer_x) /
                         4,
                     (start_edge_top_in_layer_y + start_edge_bottom_in_layer_y +
                      end_edge_top_in_layer_y + end_edge_bottom_in_layer_y) /
                             4 +
                         3);
    }

    WebGestureEvent gesture_event(WebInputEvent::kGestureTap,
                                  WebInputEvent::kNoModifiers,
                                  WebInputEvent::GetStaticTimeStampForTests(),
                                  kWebGestureDeviceTouchscreen);
    gesture_event.SetFrameScale(1);
    gesture_event.SetPositionInWidget(hit_point);
    gesture_event.SetPositionInScreen(hit_point);

    web_view_helper_.GetWebView()
        ->MainFrameImpl()
        ->GetFrame()
        ->GetEventHandler()
        .HandleGestureEvent(gesture_event);

    const WebSelection* selection = fake_selection_layer_tree_view_.Selection();
    const WebSelectionBound* select_start =
        fake_selection_layer_tree_view_.Start();
    const WebSelectionBound* select_end = fake_selection_layer_tree_view_.end();

    ASSERT_TRUE(selection);
    ASSERT_TRUE(select_start);
    ASSERT_TRUE(select_end);

    EXPECT_FALSE(selection->IsNone());

    blink::Node* layer_owner_node_for_start = V8Node::ToImplWithTypeCheck(
        v8::Isolate::GetCurrent(), expected_result.Get(0));
    ASSERT_TRUE(layer_owner_node_for_start);
    EXPECT_EQ(GetExpectedLayerForSelection(layer_owner_node_for_start)
                  ->PlatformLayer()
                  ->Id(),
              select_start->layer_id);

    EXPECT_EQ(start_edge_top_in_layer_x, select_start->edge_top_in_layer.x);
    EXPECT_EQ(start_edge_top_in_layer_y, select_start->edge_top_in_layer.y);
    EXPECT_EQ(start_edge_bottom_in_layer_x,
              select_start->edge_bottom_in_layer.x);

    blink::Node* layer_owner_node_for_end = V8Node::ToImplWithTypeCheck(
        v8::Isolate::GetCurrent(),
        expected_result.Get(context, 5).ToLocalChecked());

    ASSERT_TRUE(layer_owner_node_for_end);
    EXPECT_EQ(GetExpectedLayerForSelection(layer_owner_node_for_end)
                  ->PlatformLayer()
                  ->Id(),
              select_end->layer_id);

    EXPECT_EQ(end_edge_top_in_layer_x, select_end->edge_top_in_layer.x);
    EXPECT_EQ(end_edge_top_in_layer_y, select_end->edge_top_in_layer.y);
    EXPECT_EQ(end_edge_bottom_in_layer_x, select_end->edge_bottom_in_layer.x);

    // Platform differences can introduce small stylistic deviations in
    // y-axis positioning, the details of which aren't relevant to
    // selection behavior. However, such deviations from the expected value
    // should be consistent for the corresponding y coordinates.
    int y_bottom_epsilon = 0;
    if (expected_result.Length() == 13) {
      y_bottom_epsilon = expected_result.Get(context, 12)
                             .ToLocalChecked()
                             .As<v8::Int32>()
                             ->Value();
    }

    int y_bottom_deviation =
        start_edge_bottom_in_layer_y - select_start->edge_bottom_in_layer.y;
    EXPECT_GE(y_bottom_epsilon, std::abs(y_bottom_deviation));
    EXPECT_EQ(y_bottom_deviation,
              end_edge_bottom_in_layer_y - select_end->edge_bottom_in_layer.y);

    if (expected_result.Length() >= 15) {
      bool start_hidden = expected_result.Get(context, 13)
                              .ToLocalChecked()
                              .As<v8::Boolean>()
                              ->Value();
      bool end_hidden = expected_result.Get(context, 14)
                            .ToLocalChecked()
                            .As<v8::Boolean>()
                            ->Value();

      EXPECT_EQ(start_hidden, select_start->hidden);
      EXPECT_EQ(end_hidden, select_end->hidden);
    }
  }

  void RunTestWithMultipleFiles(const char* test_file, ...) {
    va_list aux_files;
    va_start(aux_files, test_file);
    while (const char* aux_file = va_arg(aux_files, const char*))
      RegisterMockedHttpURLLoad(aux_file);
    va_end(aux_files);

    RunTest(test_file);
  }

  GraphicsLayer* GetExpectedLayerForSelection(blink::Node* node) const {
    CompositedLayerMapping* clm = node->GetLayoutObject()
                                      ->EnclosingLayer()
                                      ->EnclosingLayerForPaintInvalidation()
                                      ->GetCompositedLayerMapping();

    // If the Node is a scroller, the selection will be relative to its
    // scrolling contents layer.
    return clm->ScrollingContentsLayer() ? clm->ScrollingContentsLayer()
                                         : clm->MainGraphicsLayer();
  }

  CompositedSelectionBoundsTestWebViewClient fake_selection_web_view_client_;
  CompositedSelectionBoundsTestLayerTreeView& fake_selection_layer_tree_view_;
  FrameTestHelpers::WebViewHelper web_view_helper_;
};

INSTANTIATE_TEST_CASE_P(All, CompositedSelectionBoundsTest, testing::Bool());

TEST_P(CompositedSelectionBoundsTest, None) {
  RunTestWithNoSelection("composited_selection_bounds_none.html");
}
TEST_P(CompositedSelectionBoundsTest, NoneReadonlyCaret) {
  RunTestWithNoSelection(
      "composited_selection_bounds_none_readonly_caret.html");
}
TEST_P(CompositedSelectionBoundsTest, DetachedFrame) {
  RunTestWithNoSelection("composited_selection_bounds_detached_frame.html");
}

TEST_P(CompositedSelectionBoundsTest, Basic) {
  RunTest("composited_selection_bounds_basic.html");
}
TEST_P(CompositedSelectionBoundsTest, Transformed) {
  RunTest("composited_selection_bounds_transformed.html");
}
TEST_P(CompositedSelectionBoundsTest, VerticalRightToLeft) {
  RunTest("composited_selection_bounds_vertical_rl.html");
}
TEST_P(CompositedSelectionBoundsTest, VerticalLeftToRight) {
  RunTest("composited_selection_bounds_vertical_lr.html");
}
TEST_P(CompositedSelectionBoundsTest, SplitLayer) {
  RunTest("composited_selection_bounds_split_layer.html");
}
TEST_P(CompositedSelectionBoundsTest, Iframe) {
  RunTestWithMultipleFiles("composited_selection_bounds_iframe.html",
                           "composited_selection_bounds_basic.html", nullptr);
}
TEST_P(CompositedSelectionBoundsTest, Editable) {
  RunTest("composited_selection_bounds_editable.html");
}
TEST_P(CompositedSelectionBoundsTest, EditableDiv) {
  RunTest("composited_selection_bounds_editable_div.html");
}
#if defined(OS_LINUX)
#if !defined(OS_ANDROID)
TEST_P(CompositedSelectionBoundsTest, Input) {
  RunTest("composited_selection_bounds_input.html");
}
TEST_P(CompositedSelectionBoundsTest, InputScrolled) {
  RunTest("composited_selection_bounds_input_scrolled.html");
}
#endif
#endif

class DisambiguationPopupTestWebViewClient
    : public FrameTestHelpers::TestWebViewClient {
 public:
  DisambiguationPopupTestWebViewClient() = default;
  ~DisambiguationPopupTestWebViewClient() override = default;

  // FrameTestHelpers::TestWebViewClient:
  bool DidTapMultipleTargets(const WebSize&,
                             const WebRect&,
                             const WebVector<WebRect>& target_rects) override {
    EXPECT_GE(target_rects.size(), 2u);
    triggered_ = true;
    return true;
  }

  bool Triggered() const { return triggered_; }
  void ResetTriggered() { triggered_ = false; }
  bool triggered_;
};

static WebCoalescedInputEvent FatTap(int x, int y, int diameter) {
  WebGestureEvent event(WebInputEvent::kGestureTap, WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        kWebGestureDeviceTouchscreen);
  event.SetPositionInWidget(WebFloatPoint(x, y));
  event.data.tap.width = diameter;
  event.data.tap.height = diameter;
  return WebCoalescedInputEvent(event);
}

TEST_P(ParameterizedWebFrameTest, DisambiguationPopup) {
  const std::string html_file = "disambiguation_popup.html";
  RegisterMockedHttpURLLoad(html_file);

  DisambiguationPopupTestWebViewClient client;
  const int kTapDiameter = 100;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + html_file, nullptr, &client);
  web_view_helper.Resize(WebSize(1000, 1000));

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(FatTap(0, 0, kTapDiameter));
  EXPECT_FALSE(client.Triggered());

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(
      FatTap(200, 115, kTapDiameter));
  EXPECT_FALSE(client.Triggered());

  for (int i = 0; i <= 46; i++) {
    client.ResetTriggered();
    web_view_helper.GetWebView()->HandleInputEvent(
        FatTap(120, 230 + i * 5, kTapDiameter));

    int j = i % 10;
    if (j >= 7 && j <= 9)
      EXPECT_TRUE(client.Triggered());
    else
      EXPECT_FALSE(client.Triggered());
  }

  for (int i = 0; i <= 46; i++) {
    client.ResetTriggered();
    web_view_helper.GetWebView()->HandleInputEvent(
        FatTap(10 + i * 5, 590, kTapDiameter));

    int j = i % 10;
    if (j >= 7 && j <= 9)
      EXPECT_TRUE(client.Triggered());
    else
      EXPECT_FALSE(client.Triggered());
  }

  // The same taps shouldn't trigger didTapMultipleTargets() after disabling the
  // notification for multi-target-tap.
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetMultiTargetTapNotificationEnabled(false);

  for (int i = 0; i <= 46; i++) {
    client.ResetTriggered();
    web_view_helper.GetWebView()->HandleInputEvent(
        FatTap(10 + i * 5, 590, kTapDiameter));
    EXPECT_FALSE(client.Triggered());
  }
}

TEST_P(ParameterizedWebFrameTest, DisambiguationPopupNoContainer) {
  RegisterMockedHttpURLLoad("disambiguation_popup_no_container.html");

  DisambiguationPopupTestWebViewClient client;
  const int kTapDiameter = 100;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "disambiguation_popup_no_container.html", nullptr, &client);
  web_view_helper.Resize(WebSize(1000, 1000));

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(FatTap(50, 50, kTapDiameter));
  EXPECT_FALSE(client.Triggered());
}

TEST_P(ParameterizedWebFrameTest, DisambiguationPopupMobileSite) {
  const std::string html_file = "disambiguation_popup_mobile_site.html";
  RegisterMockedHttpURLLoad(html_file);

  DisambiguationPopupTestWebViewClient client;
  const int kTapDiameter = 100;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + html_file, nullptr, &client,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(1000, 1000));

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(FatTap(0, 0, kTapDiameter));
  EXPECT_FALSE(client.Triggered());

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(
      FatTap(200, 115, kTapDiameter));
  EXPECT_FALSE(client.Triggered());

  for (int i = 0; i <= 46; i++) {
    client.ResetTriggered();
    web_view_helper.GetWebView()->HandleInputEvent(
        FatTap(120, 230 + i * 5, kTapDiameter));
    EXPECT_FALSE(client.Triggered());
  }

  for (int i = 0; i <= 46; i++) {
    client.ResetTriggered();
    web_view_helper.GetWebView()->HandleInputEvent(
        FatTap(10 + i * 5, 590, kTapDiameter));
    EXPECT_FALSE(client.Triggered());
  }
}

TEST_P(ParameterizedWebFrameTest, DisambiguationPopupViewportSite) {
  const std::string html_file = "disambiguation_popup_viewport_site.html";
  RegisterMockedHttpURLLoad(html_file);

  DisambiguationPopupTestWebViewClient client;
  const int kTapDiameter = 100;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + html_file, nullptr, &client,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(1000, 1000));

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(FatTap(0, 0, kTapDiameter));
  EXPECT_FALSE(client.Triggered());

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(
      FatTap(200, 115, kTapDiameter));
  EXPECT_FALSE(client.Triggered());

  for (int i = 0; i <= 46; i++) {
    client.ResetTriggered();
    web_view_helper.GetWebView()->HandleInputEvent(
        FatTap(120, 230 + i * 5, kTapDiameter));
    EXPECT_FALSE(client.Triggered());
  }

  for (int i = 0; i <= 46; i++) {
    client.ResetTriggered();
    web_view_helper.GetWebView()->HandleInputEvent(
        FatTap(10 + i * 5, 590, kTapDiameter));
    EXPECT_FALSE(client.Triggered());
  }
}

TEST_P(ParameterizedWebFrameTest, DisambiguationPopupVisualViewport) {
  const std::string html_file = "disambiguation_popup_200_by_800.html";
  RegisterMockedHttpURLLoad(html_file);

  DisambiguationPopupTestWebViewClient client;
  const int kTapDiameter = 100;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + html_file, nullptr, &client,
                                    nullptr, ConfigureAndroid);

  WebViewImpl* web_view_impl = web_view_helper.GetWebView();
  ASSERT_TRUE(web_view_impl);
  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  ASSERT_TRUE(frame);

  web_view_helper.Resize(WebSize(100, 200));

  // Scroll main frame to the bottom of the document
  web_view_impl->MainFrameImpl()->SetScrollOffset(WebSize(0, 400));
  EXPECT_EQ(ScrollOffset(0, 400),
            frame->View()->LayoutViewportScrollableArea()->GetScrollOffset());

  web_view_impl->SetPageScaleFactor(2.0);

  // Scroll visual viewport to the top of the main frame.
  VisualViewport& visual_viewport = frame->GetPage()->GetVisualViewport();
  visual_viewport.SetLocation(FloatPoint(0, 0));
  EXPECT_EQ(ScrollOffset(0, 0), visual_viewport.GetScrollOffset());

  // Tap at the top: there is nothing there.
  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(FatTap(10, 60, kTapDiameter));
  EXPECT_FALSE(client.Triggered());

  // Scroll visual viewport to the bottom of the main frame.
  visual_viewport.SetLocation(FloatPoint(0, 200));
  EXPECT_EQ(ScrollOffset(0, 200), visual_viewport.GetScrollOffset());

  // Now the tap with the same coordinates should hit two elements.
  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(FatTap(10, 60, kTapDiameter));
  EXPECT_TRUE(client.Triggered());

  // The same tap shouldn't trigger didTapMultipleTargets() after disabling the
  // notification for multi-target-tap.
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetMultiTargetTapNotificationEnabled(false);
  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(FatTap(10, 60, kTapDiameter));
  EXPECT_FALSE(client.Triggered());
}

TEST_P(ParameterizedWebFrameTest, DisambiguationPopupBlacklist) {
  const unsigned kViewportWidth = 500;
  const unsigned kViewportHeight = 1000;
  const unsigned kDivHeight = 100;
  const std::string html_file = "disambiguation_popup_blacklist.html";
  RegisterMockedHttpURLLoad(html_file);

  DisambiguationPopupTestWebViewClient client;
  const int kTapDiameter = 100;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + html_file, nullptr, &client);
  web_view_helper.Resize(WebSize(kViewportWidth, kViewportHeight));

  // Click somewhere where the popup shouldn't appear.
  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(
      FatTap(kViewportWidth / 2, 0, kTapDiameter));
  EXPECT_FALSE(client.Triggered());

  // Click directly in between two container divs with click handlers, with
  // children that don't handle clicks.
  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(
      FatTap(kViewportWidth / 2, kDivHeight, kTapDiameter));
  EXPECT_TRUE(client.Triggered());

  // The third div container should be blacklisted if you click on the link it
  // contains.
  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(
      FatTap(kViewportWidth / 2, kDivHeight * 3.25, kTapDiameter));
  EXPECT_FALSE(client.Triggered());
}

TEST_P(ParameterizedWebFrameTest, DisambiguationPopupPageScale) {
  RegisterMockedHttpURLLoad("disambiguation_popup_page_scale.html");

  DisambiguationPopupTestWebViewClient client;
  const int kTapDiameter = 50;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "disambiguation_popup_page_scale.html", nullptr, &client);
  web_view_helper.Resize(WebSize(1000, 1000));

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(FatTap(80, 80, kTapDiameter));
  EXPECT_TRUE(client.Triggered());

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(
      FatTap(230, 190, kTapDiameter));
  EXPECT_TRUE(client.Triggered());

  web_view_helper.GetWebView()->SetPageScaleFactor(3.0f);
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(
      FatTap(240, 240, kTapDiameter));
  EXPECT_TRUE(client.Triggered());

  client.ResetTriggered();
  web_view_helper.GetWebView()->HandleInputEvent(
      FatTap(690, 570, kTapDiameter));
  EXPECT_FALSE(client.Triggered());
}

class TestSubstituteDataWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestSubstituteDataWebFrameClient() : commit_called_(false) {}
  ~TestSubstituteDataWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidFailProvisionalLoad(const WebURLError& error,
                              WebHistoryCommitType) override {
    Frame()->LoadHTMLString("This should appear",
                            ToKURL("chrome-error://chromewebdata/"),
                            error.url(), true);
  }
  void DidCommitProvisionalLoad(const WebHistoryItem&,
                                WebHistoryCommitType,
                                WebGlobalObjectReusePolicy) override {
    if (Frame()->GetDocumentLoader()->GetResponse().Url() !=
        WebURL(URLTestHelpers::ToKURL("about:blank")))
      commit_called_ = true;
  }

  bool CommitCalled() const { return commit_called_; }

 private:
  bool commit_called_;
};

TEST_P(ParameterizedWebFrameTest, ReplaceNavigationAfterHistoryNavigation) {
  TestSubstituteDataWebFrameClient web_frame_client;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", &web_frame_client);
  WebLocalFrame* frame = web_view_helper.GetWebView()->MainFrameImpl();

  // Load a url as a history navigation that will return an error.
  // TestSubstituteDataWebFrameClient will start a SubstituteData load in
  // response to the load failure, which should get fully committed.  Due to
  // https://bugs.webkit.org/show_bug.cgi?id=91685,
  // FrameLoader::didReceiveData() wasn't getting called in this case, which
  // resulted in the SubstituteData document not getting displayed.
  std::string error_url = "http://0.0.0.0";
  ResourceError error = ResourceError::Failure(ToKURL(error_url));
  WebURLResponse response;
  response.SetURL(URLTestHelpers::ToKURL(error_url));
  response.SetMIMEType("text/html");
  response.SetHTTPStatusCode(500);
  WebHistoryItem error_history_item;
  error_history_item.Initialize();
  error_history_item.SetURLString(
      WebString::FromUTF8(error_url.c_str(), error_url.length()));
  Platform::Current()->GetURLLoaderMockFactory()->RegisterErrorURL(
      URLTestHelpers::ToKURL(error_url), response, error);
  FrameTestHelpers::LoadHistoryItem(frame, error_history_item,
                                    kWebHistoryDifferentDocumentLoad,
                                    mojom::FetchCacheMode::kDefault);
  WebString text = WebFrameContentDumper::DumpWebViewAsText(
      web_view_helper.GetWebView(), std::numeric_limits<size_t>::max());
  EXPECT_EQ("This should appear", text.Utf8());
  EXPECT_TRUE(web_frame_client.CommitCalled());
}

class TestWillInsertBodyWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestWillInsertBodyWebFrameClient() : num_bodies_(0), did_load_(false) {}
  ~TestWillInsertBodyWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidCommitProvisionalLoad(const WebHistoryItem&,
                                WebHistoryCommitType,
                                WebGlobalObjectReusePolicy) override {
    num_bodies_ = 0;
    did_load_ = true;
  }
  void DidCreateDocumentElement() override { EXPECT_EQ(0, num_bodies_); }
  void WillInsertBody() override { num_bodies_++; }

  int num_bodies_;
  bool did_load_;
};

TEST_P(ParameterizedWebFrameTest, HTMLDocument) {
  RegisterMockedHttpURLLoad("clipped-body.html");

  TestWillInsertBodyWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "clipped-body.html",
                                    &web_frame_client);

  EXPECT_TRUE(web_frame_client.did_load_);
  EXPECT_EQ(1, web_frame_client.num_bodies_);
}

TEST_P(ParameterizedWebFrameTest, EmptyDocument) {
  RegisterMockedHttpURLLoad("frameserializer/svg/green_rectangle.svg");

  TestWillInsertBodyWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);

  EXPECT_FALSE(web_frame_client.did_load_);
  // The empty document that a new frame starts with triggers this.
  EXPECT_EQ(1, web_frame_client.num_bodies_);
}

TEST_P(ParameterizedWebFrameTest,
       MoveCaretSelectionTowardsWindowPointWithNoSelection) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebFrame* frame = web_view_helper.GetWebView()->MainFrame();

  // This test passes if this doesn't crash.
  frame->ToWebLocalFrame()->MoveCaretSelection(WebPoint(0, 0));
}

class TextCheckClient : public WebTextCheckClient {
 public:
  TextCheckClient() : number_of_times_checked_(0) {}
  ~TextCheckClient() override = default;

  // WebTextCheckClient:
  bool IsSpellCheckingEnabled() const override { return true; }
  void RequestCheckingOfText(const WebString&,
                             WebTextCheckingCompletion* completion) override {
    ++number_of_times_checked_;
    Vector<WebTextCheckingResult> results;
    const int kMisspellingStartOffset = 1;
    const int kMisspellingLength = 8;
    results.push_back(WebTextCheckingResult(
        kWebTextDecorationTypeSpelling, kMisspellingStartOffset,
        kMisspellingLength, WebVector<WebString>()));
    completion->DidFinishCheckingText(results);
  }

  int NumberOfTimesChecked() const { return number_of_times_checked_; }

 private:
  int number_of_times_checked_;
};

TEST_P(ParameterizedWebFrameTest, ReplaceMisspelledRange) {
  RegisterMockedHttpURLLoad("spell.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  TextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById("data");

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      WebSettings::kEditingBehaviorWin);

  element->focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "_wellcome_.", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckCallback()
      .ForceInvocationForTesting();

  const int kAllTextBeginOffset = 0;
  const int kAllTextLength = 11;
  frame->SelectRange(WebRange(kAllTextBeginOffset, kAllTextLength),
                     WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide);
  EphemeralRange selection_range = frame->GetFrame()
                                       ->Selection()
                                       .ComputeVisibleSelectionInDOMTree()
                                       .ToNormalizedEphemeralRange();

  EXPECT_EQ(1, textcheck.NumberOfTimesChecked());
  EXPECT_EQ(1, NumMarkersInRange(document, selection_range,
                                 DocumentMarker::kSpelling));

  frame->ReplaceMisspelledRange("welcome");
  EXPECT_EQ("_welcome_.", WebFrameContentDumper::DumpWebViewAsText(
                              web_view_helper.GetWebView(),
                              std::numeric_limits<size_t>::max())
                              .Utf8());
}

TEST_P(ParameterizedWebFrameTest, RemoveSpellingMarkers) {
  RegisterMockedHttpURLLoad("spell.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  TextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById("data");

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      WebSettings::kEditingBehaviorWin);

  element->focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "_wellcome_.", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckCallback()
      .ForceInvocationForTesting();

  frame->RemoveSpellingMarkers();

  const int kAllTextBeginOffset = 0;
  const int kAllTextLength = 11;
  frame->SelectRange(WebRange(kAllTextBeginOffset, kAllTextLength),
                     WebLocalFrame::kHideSelectionHandle,
                     SelectionMenuBehavior::kHide);
  EphemeralRange selection_range = frame->GetFrame()
                                       ->Selection()
                                       .ComputeVisibleSelectionInDOMTree()
                                       .ToNormalizedEphemeralRange();

  EXPECT_EQ(0, NumMarkersInRange(document, selection_range,
                                 DocumentMarker::kSpelling));
}

static void GetSpellingMarkerOffsets(WebVector<unsigned>* offsets,
                                     const Document& document) {
  Vector<unsigned> result;
  const DocumentMarkerVector& document_markers = document.Markers().Markers();
  for (size_t i = 0; i < document_markers.size(); ++i)
    result.push_back(document_markers[i]->StartOffset());
  offsets->Assign(result);
}

TEST_P(ParameterizedWebFrameTest, RemoveSpellingMarkersUnderWords) {
  RegisterMockedHttpURLLoad("spell.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* web_frame = web_view_helper.LocalMainFrame();
  TextCheckClient textcheck;
  web_frame->SetTextCheckClient(&textcheck);

  LocalFrame* frame = web_frame->GetFrame();
  Document* document = frame->GetDocument();
  Element* element = document->getElementById("data");

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      WebSettings::kEditingBehaviorWin);

  element->focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, " wellcome ", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  frame->GetSpellChecker()
      .GetIdleSpellCheckCallback()
      .ForceInvocationForTesting();

  WebVector<unsigned> offsets1;
  GetSpellingMarkerOffsets(&offsets1, *frame->GetDocument());
  EXPECT_EQ(1U, offsets1.size());

  Vector<String> words;
  words.push_back("wellcome");
  frame->RemoveSpellingMarkersUnderWords(words);

  WebVector<unsigned> offsets2;
  GetSpellingMarkerOffsets(&offsets2, *frame->GetDocument());
  EXPECT_EQ(0U, offsets2.size());
}

class StubbornTextCheckClient : public WebTextCheckClient {
 public:
  StubbornTextCheckClient() : completion_(nullptr) {}
  ~StubbornTextCheckClient() override = default;

  // WebTextCheckClient:
  bool IsSpellCheckingEnabled() const override { return true; }
  void RequestCheckingOfText(const WebString&,
                             WebTextCheckingCompletion* completion) override {
    completion_ = completion;
  }
  void CancelAllPendingRequests() override {
    if (!completion_)
      return;
    completion_->DidCancelCheckingText();
    completion_ = nullptr;
  }

  void KickNoResults() { Kick(-1, -1, kWebTextDecorationTypeSpelling); }

  void Kick() { Kick(1, 8, kWebTextDecorationTypeSpelling); }

  void KickGrammar() { Kick(1, 8, kWebTextDecorationTypeGrammar); }

 private:
  void Kick(int misspelling_start_offset,
            int misspelling_length,
            WebTextDecorationType type) {
    if (!completion_)
      return;
    Vector<WebTextCheckingResult> results;
    if (misspelling_start_offset >= 0 && misspelling_length > 0) {
      results.push_back(WebTextCheckingResult(type, misspelling_start_offset,
                                              misspelling_length));
    }
    completion_->DidFinishCheckingText(results);
    completion_ = nullptr;
  }

  WebTextCheckingCompletion* completion_;
};

TEST_P(ParameterizedWebFrameTest, SlowSpellcheckMarkerPosition) {
  RegisterMockedHttpURLLoad("spell.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  StubbornTextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById("data");

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      WebSettings::kEditingBehaviorWin);

  element->focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "wellcome ", exception_state);
  EXPECT_FALSE(exception_state.HadException());
  document->execCommand("InsertText", false, "he", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckCallback()
      .ForceInvocationForTesting();

  textcheck.Kick();

  WebVector<unsigned> offsets;
  GetSpellingMarkerOffsets(&offsets, *frame->GetFrame()->GetDocument());
  EXPECT_EQ(0U, offsets.size());
}

TEST_P(ParameterizedWebFrameTest, SpellcheckResultErasesMarkers) {
  RegisterMockedHttpURLLoad("spell.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  StubbornTextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById("data");

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      WebSettings::kEditingBehaviorWin);

  element->focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "welcome ", exception_state);

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckCallback()
      .ForceInvocationForTesting();

  document->UpdateStyleAndLayout();

  EXPECT_FALSE(exception_state.HadException());
  auto range = EphemeralRange::RangeOfContents(*element);
  document->Markers().AddSpellingMarker(range);
  document->Markers().AddGrammarMarker(range);
  EXPECT_EQ(2U, document->Markers().Markers().size());

  textcheck.KickNoResults();
  EXPECT_EQ(0U, document->Markers().Markers().size());
}

TEST_P(ParameterizedWebFrameTest, SpellcheckResultsSavedInDocument) {
  RegisterMockedHttpURLLoad("spell.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  StubbornTextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById("data");

  web_view_helper.GetWebView()->GetSettings()->SetEditingBehavior(
      WebSettings::kEditingBehaviorWin);

  element->focus();
  NonThrowableExceptionState exception_state;
  document->execCommand("InsertText", false, "wellcome ", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckCallback()
      .ForceInvocationForTesting();

  textcheck.Kick();
  ASSERT_EQ(1U, document->Markers().Markers().size());
  ASSERT_NE(static_cast<DocumentMarker*>(nullptr),
            document->Markers().Markers()[0]);
  EXPECT_EQ(DocumentMarker::kSpelling,
            document->Markers().Markers()[0]->GetType());

  document->execCommand("InsertText", false, "wellcome ", exception_state);
  EXPECT_FALSE(exception_state.HadException());

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckCallback()
      .ForceInvocationForTesting();

  textcheck.KickGrammar();
  ASSERT_EQ(1U, document->Markers().Markers().size());
  ASSERT_NE(static_cast<DocumentMarker*>(nullptr),
            document->Markers().Markers()[0]);
  EXPECT_EQ(DocumentMarker::kGrammar,
            document->Markers().Markers()[0]->GetType());
}

class TestAccessInitialDocumentWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestAccessInitialDocumentWebFrameClient() = default;
  ~TestAccessInitialDocumentWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidAccessInitialDocument() override { ++did_access_initial_document_; }

  // !!!!!!!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!!!!!!
  // If the actual counts in the tests below increase, this could be an
  // indicator of a bug that causes DidAccessInitialDocument() to always be
  // invoked, regardless of whether or not the initial document is accessed.
  // Please do not simply increment the expected counts in the below tests
  // without understanding what's causing the increased count.
  int did_access_initial_document_ = 0;
};

TEST_P(ParameterizedWebFrameTest, DidAccessInitialDocumentBody) {
  TestAccessInitialDocumentWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Create another window that will try to access it.
  FrameTestHelpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Access the initial document by modifying the body.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.document.body.innerHTML += 'Modified';"));
  RunPendingTasks();
  EXPECT_EQ(1, web_frame_client.did_access_initial_document_);

  web_view_helper.Reset();
}

TEST_P(ParameterizedWebFrameTest, DidAccessInitialDocumentOpen) {
  TestAccessInitialDocumentWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Create another window that will try to access it.
  FrameTestHelpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Access the initial document by calling document.open(), which allows
  // arbitrary modification of the initial document.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.document.open();"));
  RunPendingTasks();
  EXPECT_EQ(1, web_frame_client.did_access_initial_document_);

  web_view_helper.Reset();
}

TEST_P(ParameterizedWebFrameTest, DidAccessInitialDocumentNavigator) {
  TestAccessInitialDocumentWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Create another window that will try to access it.
  FrameTestHelpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Access the initial document to get to the navigator object.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("console.log(window.opener.navigator);"));
  RunPendingTasks();
  EXPECT_EQ(1, web_frame_client.did_access_initial_document_);

  web_view_helper.Reset();
}

TEST_P(ParameterizedWebFrameTest, DidAccessInitialDocumentViaJavascriptUrl) {
  TestAccessInitialDocumentWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Access the initial document from a javascript: URL.
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              "javascript:document.body.appendChild(document."
                              "createTextNode('Modified'))");
  EXPECT_EQ(1, web_frame_client.did_access_initial_document_);

  web_view_helper.Reset();
}

TEST_P(ParameterizedWebFrameTest,
       DidAccessInitialDocumentBodyBeforeModalDialog) {
  TestAccessInitialDocumentWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Create another window that will try to access it.
  FrameTestHelpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Access the initial document by modifying the body.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.document.body.innerHTML += 'Modified';"));
  EXPECT_EQ(1, web_frame_client.did_access_initial_document_);

  // Run a modal dialog, which used to run a nested run loop and require
  // a special case for notifying about the access.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.confirm('Modal');"));
  EXPECT_EQ(2, web_frame_client.did_access_initial_document_);

  // Ensure that we don't notify again later.
  RunPendingTasks();
  EXPECT_EQ(2, web_frame_client.did_access_initial_document_);

  web_view_helper.Reset();
}

TEST_P(ParameterizedWebFrameTest, DidWriteToInitialDocumentBeforeModalDialog) {
  TestAccessInitialDocumentWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Create another window that will try to access it.
  FrameTestHelpers::WebViewHelper new_web_view_helper;
  WebViewImpl* new_view = new_web_view_helper.InitializeWithOpener(
      web_view_helper.GetWebView()->MainFrame());
  RunPendingTasks();
  EXPECT_EQ(0, web_frame_client.did_access_initial_document_);

  // Access the initial document with document.write, which moves us past the
  // initial empty document state of the state machine.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.document.write('Modified'); "
                      "window.opener.document.close();"));
  EXPECT_EQ(1, web_frame_client.did_access_initial_document_);

  // Run a modal dialog, which used to run a nested run loop and require
  // a special case for notifying about the access.
  new_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("window.opener.confirm('Modal');"));
  EXPECT_EQ(1, web_frame_client.did_access_initial_document_);

  // Ensure that we don't notify again later.
  RunPendingTasks();
  EXPECT_EQ(1, web_frame_client.did_access_initial_document_);

  web_view_helper.Reset();
}

class TestScrolledFrameClient : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestScrolledFrameClient() { Reset(); }
  ~TestScrolledFrameClient() override = default;

  void Reset() { did_scroll_frame_ = false; }
  bool WasFrameScrolled() const { return did_scroll_frame_; }

  // WebFrameClient:
  void DidChangeScrollOffset() override {
    if (Frame()->Parent())
      return;
    EXPECT_FALSE(did_scroll_frame_);
    LocalFrameView* view = ToWebLocalFrameImpl(Frame())->GetFrameView();
    // LocalFrameView can be scrolled in
    // LocalFrameView::SetFixedVisibleContentRect which is called from
    // LocalFrame::CreateView (before the frame is associated with the the
    // view).
    if (view)
      did_scroll_frame_ = true;
  }

 private:
  bool did_scroll_frame_;
};

TEST_P(ParameterizedWebFrameTest, CompositorScrollIsUserScrollLongPage) {
  RegisterMockedHttpURLLoad("long_scroll.html");
  TestScrolledFrameClient client;

  // Make sure we initialize to minimum scale, even if the window size
  // only becomes available after the load begins.
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "long_scroll.html", &client);
  web_view_helper.Resize(WebSize(1000, 1000));

  WebLocalFrameImpl* frame_impl = web_view_helper.LocalMainFrame();
  DocumentLoader::InitialScrollState& initial_scroll_state =
      frame_impl->GetFrame()
          ->Loader()
          .GetDocumentLoader()
          ->GetInitialScrollState();

  EXPECT_FALSE(client.WasFrameScrolled());
  EXPECT_FALSE(initial_scroll_state.was_scrolled_by_user);

  auto* scrollable_area =
      frame_impl->GetFrameView()->LayoutViewportScrollableArea();

  // Do a compositor scroll, verify that this is counted as a user scroll.
  scrollable_area->DidScroll(gfx::ScrollOffset(0, 1));
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.7f, 0);
  EXPECT_TRUE(client.WasFrameScrolled());
  EXPECT_TRUE(initial_scroll_state.was_scrolled_by_user);

  client.Reset();
  initial_scroll_state.was_scrolled_by_user = false;

  // The page scale 1.0f and scroll.
  scrollable_area->DidScroll(gfx::ScrollOffset(0, 2));
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.0f, 0);
  EXPECT_TRUE(client.WasFrameScrolled());
  EXPECT_TRUE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();
  initial_scroll_state.was_scrolled_by_user = false;

  // No scroll event if there is no scroll delta.
  scrollable_area->DidScroll(gfx::ScrollOffset(0, 2));
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 1.0f, 0);
  EXPECT_FALSE(client.WasFrameScrolled());
  EXPECT_FALSE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();

  // Non zero page scale and scroll.
  scrollable_area->DidScroll(gfx::ScrollOffset(9, 15));
  web_view_helper.GetWebView()->ApplyViewportDeltas(
      WebFloatSize(), WebFloatSize(), WebFloatSize(), 0.6f, 0);
  EXPECT_TRUE(client.WasFrameScrolled());
  EXPECT_TRUE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();
  initial_scroll_state.was_scrolled_by_user = false;

  // Programmatic scroll.
  frame_impl->ExecuteScript(WebScriptSource("window.scrollTo(0, 20);"));
  EXPECT_TRUE(client.WasFrameScrolled());
  EXPECT_FALSE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();

  // Programmatic scroll to same offset. No scroll event should be generated.
  frame_impl->ExecuteScript(WebScriptSource("window.scrollTo(0, 20);"));
  EXPECT_FALSE(client.WasFrameScrolled());
  EXPECT_FALSE(initial_scroll_state.was_scrolled_by_user);
  client.Reset();
}

TEST_P(ParameterizedWebFrameTest, SiteForCookiesForRedirect) {
  String file_path = test::CoreTestDataPath("first_party.html");

  WebURL test_url(ToKURL("http://internal.test/first_party_redirect.html"));
  char redirect[] = "http://internal.test/first_party.html";
  WebURL redirect_url(ToKURL(redirect));
  WebURLResponse redirect_response;
  redirect_response.SetMIMEType("text/html");
  redirect_response.SetHTTPStatusCode(302);
  redirect_response.SetHTTPHeaderField("Location", redirect);
  Platform::Current()->GetURLLoaderMockFactory()->RegisterURL(
      test_url, redirect_response, file_path);

  WebURLResponse final_response;
  final_response.SetMIMEType("text/html");
  Platform::Current()->GetURLLoaderMockFactory()->RegisterURL(
      redirect_url, final_response, file_path);

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "first_party_redirect.html");
  EXPECT_TRUE(web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetDocument()
                  .SiteForCookies() == redirect_url);
}

class TestNavigationPolicyWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestNavigationPolicyWebFrameClient() = default;
  ~TestNavigationPolicyWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidNavigateWithinPage(const WebHistoryItem&,
                             WebHistoryCommitType,
                             bool) override {
    EXPECT_TRUE(false);
  }

  WebNavigationPolicy DecidePolicyForNavigation(
      const NavigationPolicyInfo& info) override {
    return kWebNavigationPolicyIgnore;
  }
};

TEST_P(ParameterizedWebFrameTest, SimulateFragmentAnchorMiddleClick) {
  RegisterMockedHttpURLLoad("fragment_middle_click.html");
  TestNavigationPolicyWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fragment_middle_click.html",
                                    &client);

  Document* document =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument();
  KURL destination = document->Url();
  destination.SetFragmentIdentifier("test");

  MouseEventInit mouse_initializer;
  mouse_initializer.setView(document->domWindow());
  mouse_initializer.setButton(1);

  Event* event =
      MouseEvent::Create(nullptr, EventTypeNames::click, mouse_initializer);
  FrameLoadRequest frame_request(document, ResourceRequest(destination));
  frame_request.SetTriggeringEvent(event);
  ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
      ->Loader()
      .Load(frame_request);
}

class TestNewWindowWebViewClient : public FrameTestHelpers::TestWebViewClient {
 public:
  TestNewWindowWebViewClient() = default;
  ~TestNewWindowWebViewClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  WebView* CreateView(WebLocalFrame*,
                      const WebURLRequest&,
                      const WebWindowFeatures&,
                      const WebString&,
                      WebNavigationPolicy,
                      bool,
                      WebSandboxFlags) override {
    EXPECT_TRUE(false);
    return nullptr;
  }
};

class TestNewWindowWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestNewWindowWebFrameClient() : decide_policy_call_count_(0) {}
  ~TestNewWindowWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  WebNavigationPolicy DecidePolicyForNavigation(
      const NavigationPolicyInfo& info) override {
    decide_policy_call_count_++;
    return kWebNavigationPolicyIgnore;
  }

  int DecidePolicyCallCount() const { return decide_policy_call_count_; }

 private:
  int decide_policy_call_count_;
};

TEST_P(ParameterizedWebFrameTest, ModifiedClickNewWindow) {
  RegisterMockedHttpURLLoad("ctrl_click.html");
  RegisterMockedHttpURLLoad("hello_world.html");
  TestNewWindowWebViewClient web_view_client;
  TestNewWindowWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "ctrl_click.html",
                                    &web_frame_client, &web_view_client);

  LocalFrame* frame =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame());
  Document* document = frame->GetDocument();
  KURL destination = ToKURL(base_url_ + "hello_world.html");

  // ctrl+click event
  MouseEventInit mouse_initializer;
  mouse_initializer.setView(document->domWindow());
  mouse_initializer.setButton(1);
  mouse_initializer.setCtrlKey(true);

  Event* event =
      MouseEvent::Create(nullptr, EventTypeNames::click, mouse_initializer);
  FrameLoadRequest frame_request(document, ResourceRequest(destination));
  frame_request.SetTriggeringEvent(event);
  std::unique_ptr<UserGestureIndicator> gesture =
      Frame::NotifyUserActivation(frame);
  ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
      ->Loader()
      .Load(frame_request);
  FrameTestHelpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.GetWebView()->MainFrame());

  // decidePolicyForNavigation should be called both for the original request
  // and the ctrl+click.
  EXPECT_EQ(2, web_frame_client.DecidePolicyCallCount());
}

TEST_P(ParameterizedWebFrameTest, BackToReload) {
  RegisterMockedHttpURLLoad("fragment_middle_click.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fragment_middle_click.html");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();
  const FrameLoader& main_frame_loader =
      web_view_helper.LocalMainFrame()->GetFrame()->Loader();
  Persistent<HistoryItem> first_item =
      main_frame_loader.GetDocumentLoader()->GetHistoryItem();
  EXPECT_TRUE(first_item);

  RegisterMockedHttpURLLoad("white-1x1.png");
  FrameTestHelpers::LoadFrame(frame, base_url_ + "white-1x1.png");
  EXPECT_NE(first_item.Get(),
            main_frame_loader.GetDocumentLoader()->GetHistoryItem());

  FrameTestHelpers::LoadHistoryItem(frame, WebHistoryItem(first_item.Get()),
                                    kWebHistoryDifferentDocumentLoad,
                                    mojom::FetchCacheMode::kDefault);
  EXPECT_EQ(first_item.Get(),
            main_frame_loader.GetDocumentLoader()->GetHistoryItem());

  FrameTestHelpers::ReloadFrame(frame);
  EXPECT_EQ(mojom::FetchCacheMode::kValidateCache,
            frame->GetDocumentLoader()->GetRequest().GetCacheMode());
}

TEST_P(ParameterizedWebFrameTest, BackDuringChildFrameReload) {
  RegisterMockedHttpURLLoad("page_with_blank_iframe.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "page_with_blank_iframe.html");
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  const FrameLoader& main_frame_loader = main_frame->GetFrame()->Loader();
  WebLocalFrame* child_frame = main_frame->FirstChild()->ToWebLocalFrame();
  ASSERT_TRUE(child_frame);

  // Start a history navigation, then have a different frame commit a
  // navigation.  In this case, reload an about:blank frame, which will commit
  // synchronously.  After the history navigation completes, both the
  // appropriate document url and the current history item should reflect the
  // history navigation.
  RegisterMockedHttpURLLoad("white-1x1.png");
  WebHistoryItem item;
  item.Initialize();
  WebURL history_url(ToKURL(base_url_ + "white-1x1.png"));
  item.SetURLString(history_url.GetString());
  WebURLRequest request =
      main_frame->RequestFromHistoryItem(item, mojom::FetchCacheMode::kDefault);
  main_frame->Load(request, WebFrameLoadType::kBackForward, item,
                   kWebHistoryDifferentDocumentLoad, false,
                   base::UnguessableToken::Create());

  FrameTestHelpers::ReloadFrame(child_frame);
  EXPECT_EQ(item.UrlString(), main_frame->GetDocument().Url().GetString());
  EXPECT_EQ(item.UrlString(), WebString(main_frame_loader.GetDocumentLoader()
                                            ->GetHistoryItem()
                                            ->UrlString()));
}

TEST_P(ParameterizedWebFrameTest, ReloadPost) {
  RegisterMockedHttpURLLoad("reload_post.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "reload_post.html");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              "javascript:document.forms[0].submit()");
  // Pump requests one more time after the javascript URL has executed to
  // trigger the actual POST load request.
  FrameTestHelpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.GetWebView()->MainFrame());
  EXPECT_EQ(WebString::FromUTF8("POST"),
            frame->GetDocumentLoader()->GetRequest().HttpMethod());

  FrameTestHelpers::ReloadFrame(frame);
  EXPECT_EQ(mojom::FetchCacheMode::kValidateCache,
            frame->GetDocumentLoader()->GetRequest().GetCacheMode());
  EXPECT_EQ(kWebNavigationTypeFormResubmitted,
            frame->GetDocumentLoader()->GetNavigationType());
}

TEST_P(ParameterizedWebFrameTest, LoadHistoryItemReload) {
  RegisterMockedHttpURLLoad("fragment_middle_click.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fragment_middle_click.html");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();
  const FrameLoader& main_frame_loader =
      web_view_helper.LocalMainFrame()->GetFrame()->Loader();
  Persistent<HistoryItem> first_item =
      main_frame_loader.GetDocumentLoader()->GetHistoryItem();
  EXPECT_TRUE(first_item);

  RegisterMockedHttpURLLoad("white-1x1.png");
  FrameTestHelpers::LoadFrame(frame, base_url_ + "white-1x1.png");
  EXPECT_NE(first_item.Get(),
            main_frame_loader.GetDocumentLoader()->GetHistoryItem());

  // Cache policy overrides should take.
  FrameTestHelpers::LoadHistoryItem(frame, WebHistoryItem(first_item),
                                    kWebHistoryDifferentDocumentLoad,
                                    mojom::FetchCacheMode::kValidateCache);
  EXPECT_EQ(first_item.Get(),
            main_frame_loader.GetDocumentLoader()->GetHistoryItem());
  EXPECT_EQ(mojom::FetchCacheMode::kValidateCache,
            frame->GetDocumentLoader()->GetRequest().GetCacheMode());
}

class TestCachePolicyWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestCachePolicyWebFrameClient()
      : cache_mode_(mojom::FetchCacheMode::kDefault),
        will_send_request_call_count_(0) {}
  ~TestCachePolicyWebFrameClient() override = default;

  mojom::FetchCacheMode GetCacheMode() const { return cache_mode_; }
  int WillSendRequestCallCount() const { return will_send_request_call_count_; }
  TestCachePolicyWebFrameClient& ChildClient(size_t i) {
    return *child_clients_[i].get();
  }
  size_t ChildFrameCreationCount() const { return child_clients_.size(); }

  // FrameTestHelpers::TestWebFrameClient:
  WebLocalFrame* CreateChildFrame(
      WebLocalFrame* parent,
      WebTreeScopeType scope,
      const WebString&,
      const WebString&,
      WebSandboxFlags,
      const ParsedFeaturePolicy&,
      const WebFrameOwnerProperties& frame_owner_properties) override {
    auto child = std::make_unique<TestCachePolicyWebFrameClient>();
    auto* child_ptr = child.get();
    child_clients_.push_back(std::move(child));
    return CreateLocalChild(*parent, scope, child_ptr);
  }
  void WillSendRequest(WebURLRequest& request) override {
    cache_mode_ = request.GetCacheMode();
    will_send_request_call_count_++;
  }

 private:
  mojom::FetchCacheMode cache_mode_;
  Vector<std::unique_ptr<TestCachePolicyWebFrameClient>> child_clients_;
  int will_send_request_call_count_;
};

TEST_P(ParameterizedWebFrameTest, ReloadIframe) {
  RegisterMockedHttpURLLoad("iframe_reload.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");

  TestCachePolicyWebFrameClient main_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "iframe_reload.html",
                                    &main_frame_client);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();

  ASSERT_EQ(1U, main_frame_client.ChildFrameCreationCount());
  TestCachePolicyWebFrameClient* child_client =
      &main_frame_client.ChildClient(0);
  WebLocalFrameImpl* child_frame =
      ToWebLocalFrameImpl(main_frame->FirstChild());
  EXPECT_EQ(child_client, child_frame->Client());
  EXPECT_EQ(1u, main_frame->GetFrame()->Tree().ScopedChildCount());
  EXPECT_EQ(1, child_client->WillSendRequestCallCount());
  EXPECT_EQ(mojom::FetchCacheMode::kDefault, child_client->GetCacheMode());

  FrameTestHelpers::ReloadFrame(main_frame);

  // A new child WebLocalFrame should have been created with a new client.
  ASSERT_EQ(2U, main_frame_client.ChildFrameCreationCount());
  TestCachePolicyWebFrameClient* new_child_client =
      &main_frame_client.ChildClient(1);
  WebLocalFrameImpl* new_child_frame =
      ToWebLocalFrameImpl(main_frame->FirstChild());
  EXPECT_EQ(new_child_client, new_child_frame->Client());
  ASSERT_NE(child_client, new_child_client);
  ASSERT_NE(child_frame, new_child_frame);
  // But there should still only be one subframe.
  EXPECT_EQ(1u, main_frame->GetFrame()->Tree().ScopedChildCount());

  EXPECT_EQ(1, new_child_client->WillSendRequestCallCount());
  // Sub-frames should not be forcibly revalidated.
  // TODO(toyoshim): Will consider to revalidate main resources in sub-frames
  // on reloads. Or will do only for bypassingCache.
  EXPECT_EQ(mojom::FetchCacheMode::kDefault, new_child_client->GetCacheMode());
}

class TestSameDocumentWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestSameDocumentWebFrameClient() : frame_load_type_reload_seen_(false) {}
  ~TestSameDocumentWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void WillSendRequest(WebURLRequest&) override {
    FrameLoader& frame_loader =
        ToWebLocalFrameImpl(Frame())->GetFrame()->Loader();
    if (frame_loader.GetProvisionalDocumentLoader()->LoadType() ==
        kFrameLoadTypeReload)
      frame_load_type_reload_seen_ = true;
  }

  bool FrameLoadTypeReloadSeen() const { return frame_load_type_reload_seen_; }

 private:
  bool frame_load_type_reload_seen_;
};

TEST_P(ParameterizedWebFrameTest, NavigateToSame) {
  RegisterMockedHttpURLLoad("navigate_to_same.html");
  TestSameDocumentWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "navigate_to_same.html",
                                    &client);
  EXPECT_FALSE(client.FrameLoadTypeReloadSeen());

  FrameLoadRequest frame_request(
      nullptr,
      ResourceRequest(
          ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
              ->GetDocument()
              ->Url()));
  ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame())
      ->Loader()
      .Load(frame_request);
  FrameTestHelpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.GetWebView()->MainFrame());

  EXPECT_TRUE(client.FrameLoadTypeReloadSeen());
}

class TestSameDocumentWithImageWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestSameDocumentWithImageWebFrameClient() : num_of_image_requests_(0) {}
  ~TestSameDocumentWithImageWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void WillSendRequest(WebURLRequest& request) override {
    if (request.GetRequestContext() == WebURLRequest::kRequestContextImage) {
      num_of_image_requests_++;
      EXPECT_EQ(mojom::FetchCacheMode::kDefault, request.GetCacheMode());
    }
  }

  int NumOfImageRequests() const { return num_of_image_requests_; }

 private:
  int num_of_image_requests_;
};

TEST_P(ParameterizedWebFrameTest,
       NavigateToSameNoConditionalRequestForSubresource) {
  RegisterMockedHttpURLLoad("foo_with_image.html");
  RegisterMockedHttpURLLoad("white-1x1.png");
  TestSameDocumentWithImageWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo_with_image.html", &client,
                                    nullptr, nullptr,
                                    &ConfigureLoadsImagesAutomatically);

  WebCache::Clear();
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "foo_with_image.html");

  // 2 images are requested, and each triggers 2 willSendRequest() calls,
  // once for preloading and once for the real request.
  EXPECT_EQ(client.NumOfImageRequests(), 4);
}

TEST_P(ParameterizedWebFrameTest, WebNodeImageContents) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  static const char kBluePNG[] =
      "<img "
      "src=\"data:image/"
      "png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+"
      "9AAAAGElEQVQYV2NkYPj/n4EIwDiqEF8oUT94AFIQE/cCn90IAAAAAElFTkSuQmCC\">";

  // Load up the image and test that we can extract the contents.
  KURL test_url = ToKURL("about:blank");
  FrameTestHelpers::LoadHTMLString(frame, kBluePNG, test_url);

  WebNode node = frame->GetDocument().Body().FirstChild();
  EXPECT_TRUE(node.IsElementNode());
  WebElement element = node.To<WebElement>();
  WebImage image = element.ImageContents();
  ASSERT_FALSE(image.IsNull());
  EXPECT_EQ(image.Size().width, 10);
  EXPECT_EQ(image.Size().height, 10);
  SkBitmap bitmap = image.GetSkBitmap();
  EXPECT_EQ(bitmap.getColor(0, 0), SK_ColorBLUE);
}

TEST_P(ParameterizedWebFrameTest, WebNodeImageContentsWithOrientation) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // 4x8 jpg with orientation = 6 ( 90 degree CW rotation ).
  // w - white, b - blue.
  //   raw      =>       oriented
  // w w w w          b b b b w w w w
  // w w w w          b b b b w w w w
  // w w w w          b b b b w w w w
  // w w w w          b b b b w w w w
  // b b b b
  // b b b b
  // b b b b
  // b b b b
  static const char kBlueJPGWithOrientation[] =
      "<img "
      "src=\"data:image/"
      "jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/4QBiRXhpZgAATU0AKgAAAAgABQESAAM"
      "AAAABAAYAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAIAAAITAAMAAAABAA"
      "EAAAAAAAAAAABgAAAAAQAAAGAAAAAB/9sAQwACAQECAQECAgICAgICAgMFAwMDAwMGBAQDB"
      "QcGBwcHBgcHCAkLCQgICggHBwoNCgoLDAwMDAcJDg8NDA4LDAwM/9sAQwECAgIDAwMGAwMG"
      "DAgHCAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw"
      "M/8AAEQgACAAEAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC/"
      "/EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJ"
      "DNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3"
      "eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tf"
      "Y2drh4uPk5ebn6Onq8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCA"
      "kKC//EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM"
      "1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpz"
      "dHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytL"
      "T1NXW19jZ2uLj5OXm5+jp6vLz9PX29/j5+v/aAAwDAQACEQMRAD8A7j/iMz/6tv8A/Mgf/e"
    "2iiiv9ff8AiVzwx/6Fn/lbEf8Ay0+A/tvG/wA/4L/I/9k=\">";

  // Load up the image and test that we can extract the contents.
  KURL test_url = ToKURL("about:blank");
  FrameTestHelpers::LoadHTMLString(frame, kBlueJPGWithOrientation, test_url);

  WebNode node = frame->GetDocument().Body().FirstChild();
  EXPECT_TRUE(node.IsElementNode());
  WebElement element = node.To<WebElement>();

  WebImage image_with_orientation = element.ImageContents();
  ASSERT_FALSE(image_with_orientation.IsNull());
  EXPECT_EQ(image_with_orientation.Size().width, 8);
  EXPECT_EQ(image_with_orientation.Size().height, 4);
  SkBitmap oriented_bitmap = image_with_orientation.GetSkBitmap();
  // Should be almost blue.
  SkColor oriented_color = oriented_bitmap.getColor(0, 0);
  EXPECT_NEAR(SkColorGetR(oriented_color), SkColorGetR(SK_ColorBLUE), 5);
  EXPECT_NEAR(SkColorGetG(oriented_color), SkColorGetG(SK_ColorBLUE), 5);
  EXPECT_NEAR(SkColorGetB(oriented_color), SkColorGetB(SK_ColorBLUE), 5);
  EXPECT_NEAR(SkColorGetA(oriented_color), SkColorGetA(SK_ColorBLUE), 5);
}

class TestStartStopCallbackWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestStartStopCallbackWebFrameClient()
      : start_loading_count_(0),
        stop_loading_count_(0),
        different_document_start_count_(0) {}
  ~TestStartStopCallbackWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidStartLoading(bool to_different_document) override {
    TestWebFrameClient::DidStartLoading(to_different_document);
    start_loading_count_++;
    if (to_different_document)
      different_document_start_count_++;
  }
  void DidStopLoading() override {
    TestWebFrameClient::DidStopLoading();
    stop_loading_count_++;
  }

  int StartLoadingCount() const { return start_loading_count_; }
  int StopLoadingCount() const { return stop_loading_count_; }
  int DifferentDocumentStartCount() const {
    return different_document_start_count_;
  }

 private:
  int start_loading_count_;
  int stop_loading_count_;
  int different_document_start_count_;
};

TEST_P(ParameterizedWebFrameTest, PushStateStartsAndStops) {
  RegisterMockedHttpURLLoad("push_state.html");
  TestStartStopCallbackWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "push_state.html", &client);

  EXPECT_EQ(client.StartLoadingCount(), 2);
  EXPECT_EQ(client.StopLoadingCount(), 2);
  EXPECT_EQ(client.DifferentDocumentStartCount(), 1);
}

class TestDidNavigateCommitTypeWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestDidNavigateCommitTypeWebFrameClient()
      : last_commit_type_(kWebHistoryInertCommit) {}
  ~TestDidNavigateCommitTypeWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidNavigateWithinPage(const WebHistoryItem&,
                             WebHistoryCommitType type,
                             bool) override {
    last_commit_type_ = type;
  }

  WebHistoryCommitType LastCommitType() const { return last_commit_type_; }

 private:
  WebHistoryCommitType last_commit_type_;
};

TEST_P(ParameterizedWebFrameTest, SameDocumentHistoryNavigationCommitType) {
  RegisterMockedHttpURLLoad("push_state.html");
  TestDidNavigateCommitTypeWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url_ + "push_state.html", &client);
  Persistent<HistoryItem> item =
      ToLocalFrame(web_view_impl->GetPage()->MainFrame())
          ->Loader()
          .GetDocumentLoader()
          ->GetHistoryItem();
  RunPendingTasks();

  ToLocalFrame(web_view_impl->GetPage()->MainFrame())
      ->Loader()
      .Load(FrameLoadRequest(nullptr, item->GenerateResourceRequest(
                                          mojom::FetchCacheMode::kDefault)),
            kFrameLoadTypeBackForward, item.Get(), kHistorySameDocumentLoad);
  EXPECT_EQ(kWebBackForwardCommit, client.LastCommitType());
}

class TestHistoryChildWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestHistoryChildWebFrameClient() = default;
  ~TestHistoryChildWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidStartProvisionalLoad(WebDocumentLoader* document_loader,
                               WebURLRequest& request) override {
    replaces_current_history_item_ =
        document_loader->ReplacesCurrentHistoryItem();
  }

  bool ReplacesCurrentHistoryItem() { return replaces_current_history_item_; }

 private:
  bool replaces_current_history_item_ = false;
};

class TestHistoryWebFrameClient : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestHistoryWebFrameClient() = default;
  ~TestHistoryWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  WebLocalFrame* CreateChildFrame(WebLocalFrame* parent,
                                  WebTreeScopeType scope,
                                  const WebString& name,
                                  const WebString& fallback_name,
                                  WebSandboxFlags,
                                  const ParsedFeaturePolicy&,
                                  const WebFrameOwnerProperties&) override {
    return CreateLocalChild(*parent, scope, &child_client_);
  }

  TestHistoryChildWebFrameClient& ChildClient() { return child_client_; }

 private:
  TestHistoryChildWebFrameClient child_client_;
};

// Tests that the first navigation in an initially blank subframe will result in
// a history entry being replaced and not a new one being added.
TEST_P(ParameterizedWebFrameTest, FirstBlankSubframeNavigation) {
  RegisterMockedHttpURLLoad("history.html");
  RegisterMockedHttpURLLoad("find.html");

  TestHistoryWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", &client);

  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  frame->ExecuteScript(WebScriptSource(WebString::FromUTF8(
      "document.body.appendChild(document.createElement('iframe'))")));

  WebLocalFrameImpl* iframe = ToWebLocalFrameImpl(frame->FirstChild());
  ASSERT_EQ(&client.ChildClient(), iframe->Client());

  std::string url1 = base_url_ + "history.html";
  FrameTestHelpers::LoadFrame(iframe, url1);
  EXPECT_EQ(url1, iframe->GetDocument().Url().GetString().Utf8());
  EXPECT_TRUE(client.ChildClient().ReplacesCurrentHistoryItem());

  std::string url2 = base_url_ + "find.html";
  FrameTestHelpers::LoadFrame(iframe, url2);
  EXPECT_EQ(url2, iframe->GetDocument().Url().GetString().Utf8());
  EXPECT_FALSE(client.ChildClient().ReplacesCurrentHistoryItem());
}

// Tests that a navigation in a frame with a non-blank initial URL will create
// a new history item, unlike the case above.
TEST_P(ParameterizedWebFrameTest, FirstNonBlankSubframeNavigation) {
  RegisterMockedHttpURLLoad("history.html");
  RegisterMockedHttpURLLoad("find.html");

  TestHistoryWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", &client);

  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  std::string url1 = base_url_ + "history.html";
  std::string load_frame_js =
      "javascript:var f = document.createElement('iframe'); "
      "f.src = '";
  load_frame_js += url1 + "';" + "document.body.appendChild(f)";
  FrameTestHelpers::LoadFrame(frame, load_frame_js);

  WebLocalFrame* iframe = frame->FirstChild()->ToWebLocalFrame();
  EXPECT_EQ(url1, iframe->GetDocument().Url().GetString().Utf8());

  std::string url2 = base_url_ + "find.html";
  FrameTestHelpers::LoadFrame(iframe, url2);
  EXPECT_EQ(url2, iframe->GetDocument().Url().GetString().Utf8());
  EXPECT_FALSE(client.ChildClient().ReplacesCurrentHistoryItem());
}

// Test verifies that layout will change a layer's scrollable attibutes
TEST_P(ParameterizedWebFrameTest, overflowHiddenRewrite) {
  RegisterMockedHttpURLLoad("non-scrollable.html");
  std::unique_ptr<FakeCompositingWebViewClient>
      fake_compositing_web_view_client =
          std::make_unique<FakeCompositingWebViewClient>();
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, fake_compositing_web_view_client.get(),
                             nullptr, &ConfigureCompositingWebView);

  web_view_helper.Resize(WebSize(100, 100));
  FrameTestHelpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                              base_url_ + "non-scrollable.html");

  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  PaintLayerCompositor* compositor = web_view_helper.GetWebView()->Compositor();
  GraphicsLayer* scroll_layer = compositor->ScrollLayer();
  ASSERT_TRUE(scroll_layer);
  WebLayer* web_scroll_layer = scroll_layer->PlatformLayer();

  // Verify that the WebLayer is not scrollable initially.
  ASSERT_FALSE(web_scroll_layer->UserScrollableHorizontal());
  ASSERT_FALSE(web_scroll_layer->UserScrollableVertical());

  // Call javascript to make the layer scrollable, and verify it.
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->ExecuteScript(WebScriptSource("allowScroll();"));
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  scroll_layer = compositor->ScrollLayer();
  web_scroll_layer = scroll_layer->PlatformLayer();
  ASSERT_TRUE(web_scroll_layer->UserScrollableHorizontal());
  ASSERT_TRUE(web_scroll_layer->UserScrollableVertical());
}

// Test that currentHistoryItem reflects the current page, not the provisional
// load.
TEST_P(ParameterizedWebFrameTest, CurrentHistoryItem) {
  RegisterMockedHttpURLLoad("fixed_layout.html");
  std::string url = base_url_ + "fixed_layout.html";

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  WebLocalFrame* frame = web_view_helper.GetWebView()->MainFrameImpl();
  const FrameLoader& main_frame_loader =
      web_view_helper.LocalMainFrame()->GetFrame()->Loader();
  WebURLRequest request(ToKURL(url));
  frame->LoadRequest(request);

  // Before commit, there is no history item.
  EXPECT_FALSE(main_frame_loader.GetDocumentLoader()->GetHistoryItem());

  FrameTestHelpers::PumpPendingRequestsForFrameToLoad(frame);

  // After commit, there is.
  HistoryItem* item = main_frame_loader.GetDocumentLoader()->GetHistoryItem();
  ASSERT_TRUE(item);
  EXPECT_EQ(WTF::String(url.data()), item->UrlString());
}

class FailCreateChildFrame : public FrameTestHelpers::TestWebFrameClient {
 public:
  FailCreateChildFrame() : call_count_(0) {}
  ~FailCreateChildFrame() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  WebLocalFrame* CreateChildFrame(
      WebLocalFrame* parent,
      WebTreeScopeType scope,
      const WebString& name,
      const WebString& fallback_name,
      WebSandboxFlags sandbox_flags,
      const ParsedFeaturePolicy& container_policy,
      const WebFrameOwnerProperties& frame_owner_properties) override {
    ++call_count_;
    return nullptr;
  }

  int CallCount() const { return call_count_; }

 private:
  int call_count_;
};

// Test that we don't crash if WebFrameClient::createChildFrame() fails.
TEST_P(ParameterizedWebFrameTest, CreateChildFrameFailure) {
  RegisterMockedHttpURLLoad("create_child_frame_fail.html");
  FailCreateChildFrame client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "create_child_frame_fail.html",
                                    &client);

  EXPECT_EQ(1, client.CallCount());
}

TEST_P(ParameterizedWebFrameTest, fixedPositionInFixedViewport) {
  RegisterMockedHttpURLLoad("fixed-position-in-fixed-viewport.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "fixed-position-in-fixed-viewport.html", nullptr, nullptr,
      nullptr, ConfigureAndroid);

  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view_helper.Resize(WebSize(100, 100));

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  Element* bottom_fixed = document->getElementById("bottom-fixed");
  Element* top_bottom_fixed = document->getElementById("top-bottom-fixed");
  Element* right_fixed = document->getElementById("right-fixed");
  Element* left_right_fixed = document->getElementById("left-right-fixed");

  // The layout viewport will hit the min-scale limit of 0.25, so it'll be
  // 400x800.
  web_view_helper.Resize(WebSize(100, 200));
  EXPECT_EQ(800, bottom_fixed->OffsetTop() + bottom_fixed->OffsetHeight());
  EXPECT_EQ(800, top_bottom_fixed->OffsetHeight());

  // Now the layout viewport hits the content width limit of 500px so it'll be
  // 500x500.
  web_view_helper.Resize(WebSize(200, 200));
  EXPECT_EQ(500, right_fixed->OffsetLeft() + right_fixed->OffsetWidth());
  EXPECT_EQ(500, left_right_fixed->OffsetWidth());
}

TEST_P(ParameterizedWebFrameTest, FrameViewMoveWithSetFrameRect) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  web_view_helper.Resize(WebSize(200, 200));
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_EQ(IntRect(0, 0, 200, 200), frame_view->FrameRect());
  frame_view->SetFrameRect(IntRect(100, 100, 200, 200));
  EXPECT_EQ(IntRect(100, 100, 200, 200), frame_view->FrameRect());
}

TEST_P(ParameterizedWebFrameTest, FrameViewScrollAccountsForBrowserControls) {
  FakeCompositingWebViewClient client;
  RegisterMockedHttpURLLoad("long_scroll.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "long_scroll.html", nullptr,
                                    &client, nullptr, ConfigureAndroid);

  WebViewImpl* web_view = web_view_helper.GetWebView();
  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();

  float browser_controls_height = 40;
  web_view->ResizeWithBrowserControls(WebSize(100, 100),
                                      browser_controls_height, 0, false);
  web_view->SetPageScaleFactor(2.0f);
  web_view->UpdateAllLifecyclePhases();

  web_view->MainFrameImpl()->SetScrollOffset(WebSize(0, 2000));
  EXPECT_EQ(ScrollOffset(0, 1900),
            frame_view->LayoutViewportScrollableArea()->GetScrollOffset());

  // Simulate the browser controls showing by 20px, thus shrinking the viewport
  // and allowing it to scroll an additional 20px.
  web_view->ApplyViewportDeltas(WebFloatSize(), WebFloatSize(), WebFloatSize(),
                                1.0f, 20.0f / browser_controls_height);
  EXPECT_EQ(ScrollOffset(0, 1920),
            frame_view->LayoutViewportScrollableArea()->MaximumScrollOffset());

  // Show more, make sure the scroll actually gets clamped.
  web_view->ApplyViewportDeltas(WebFloatSize(), WebFloatSize(), WebFloatSize(),
                                1.0f, 20.0f / browser_controls_height);
  web_view->MainFrameImpl()->SetScrollOffset(WebSize(0, 2000));
  EXPECT_EQ(ScrollOffset(0, 1940),
            frame_view->LayoutViewportScrollableArea()->GetScrollOffset());

  // Hide until there's 10px showing.
  web_view->ApplyViewportDeltas(WebFloatSize(), WebFloatSize(), WebFloatSize(),
                                1.0f, -30.0f / browser_controls_height);
  EXPECT_EQ(ScrollOffset(0, 1910),
            frame_view->LayoutViewportScrollableArea()->MaximumScrollOffset());

  // Simulate a LayoutEmbeddedContent::resize. The frame is resized to
  // accomodate the browser controls and Blink's view of the browser controls
  // matches that of the CC
  web_view->ApplyViewportDeltas(WebFloatSize(), WebFloatSize(), WebFloatSize(),
                                1.0f, 30.0f / browser_controls_height);
  web_view->ResizeWithBrowserControls(WebSize(100, 60), 40.0f, 0, true);
  web_view->UpdateAllLifecyclePhases();
  EXPECT_EQ(ScrollOffset(0, 1940),
            frame_view->LayoutViewportScrollableArea()->MaximumScrollOffset());

  // Now simulate hiding.
  web_view->ApplyViewportDeltas(WebFloatSize(), WebFloatSize(), WebFloatSize(),
                                1.0f, -10.0f / browser_controls_height);
  EXPECT_EQ(ScrollOffset(0, 1930),
            frame_view->LayoutViewportScrollableArea()->MaximumScrollOffset());

  // Reset to original state: 100px widget height, browser controls fully
  // hidden.
  web_view->ApplyViewportDeltas(WebFloatSize(), WebFloatSize(), WebFloatSize(),
                                1.0f, -30.0f / browser_controls_height);
  web_view->ResizeWithBrowserControls(WebSize(100, 100),
                                      browser_controls_height, 0, false);
  web_view->UpdateAllLifecyclePhases();
  EXPECT_EQ(ScrollOffset(0, 1900),
            frame_view->LayoutViewportScrollableArea()->MaximumScrollOffset());

  // Show the browser controls by just 1px, since we're zoomed in to 2X, that
  // should allow an extra 0.5px of scrolling in the visual viewport. Make
  // sure we're not losing any pixels when applying the adjustment on the
  // main frame.
  web_view->ApplyViewportDeltas(WebFloatSize(), WebFloatSize(), WebFloatSize(),
                                1.0f, 1.0f / browser_controls_height);
  EXPECT_EQ(ScrollOffset(0, 1901),
            frame_view->LayoutViewportScrollableArea()->MaximumScrollOffset());

  web_view->ApplyViewportDeltas(WebFloatSize(), WebFloatSize(), WebFloatSize(),
                                1.0f, 2.0f / browser_controls_height);
  EXPECT_EQ(ScrollOffset(0, 1903),
            frame_view->LayoutViewportScrollableArea()->MaximumScrollOffset());
}

TEST_P(ParameterizedWebFrameTest, MaximumScrollPositionCanBeNegative) {
  RegisterMockedHttpURLLoad("rtl-overview-mode.html");

  FixedLayoutTestWebViewClient client;
  client.screen_info_.device_scale_factor = 1;
  int viewport_width = 640;
  int viewport_height = 480;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "rtl-overview-mode.html",
                                    nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(-1);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();

  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();
  ScrollableArea* layout_viewport = frame_view->LayoutViewportScrollableArea();
  EXPECT_LT(layout_viewport->MaximumScrollOffset().Width(), 0);
}

TEST_P(ParameterizedWebFrameTest, FullscreenLayerSize) {
  FakeCompositingWebViewClient client;
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  int viewport_width = 640;
  int viewport_height = 480;
  client.screen_info_.rect.width = viewport_width;
  client.screen_info_.rect.height = viewport_height;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_div.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_impl->UpdateAllLifecyclePhases();

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();
  std::unique_ptr<UserGestureIndicator> gesture =
      Frame::NotifyUserActivation(frame);
  Element* div_fullscreen = document->getElementById("div1");
  Fullscreen::RequestFullscreen(*div_fullscreen);
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->DidEnterFullscreen();
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));

  // Verify that the element is sized to the viewport.
  LayoutFullScreen* fullscreen_layout_object =
      Fullscreen::From(*document).FullScreenLayoutObject();
  EXPECT_EQ(viewport_width, fullscreen_layout_object->LogicalWidth().ToInt());
  EXPECT_EQ(viewport_height, fullscreen_layout_object->LogicalHeight().ToInt());

  // Verify it's updated after a device rotation.
  client.screen_info_.rect.width = viewport_height;
  client.screen_info_.rect.height = viewport_width;
  web_view_helper.Resize(WebSize(viewport_height, viewport_width));
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(viewport_height, fullscreen_layout_object->LogicalWidth().ToInt());
  EXPECT_EQ(viewport_width, fullscreen_layout_object->LogicalHeight().ToInt());
}

TEST_P(ParameterizedWebFrameTest, FullscreenLayerNonScrollable) {
  FakeCompositingWebViewClient client;
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  int viewport_width = 640;
  int viewport_height = 480;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_div.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_impl->UpdateAllLifecyclePhases();

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();
  std::unique_ptr<UserGestureIndicator> gesture =
      Frame::NotifyUserActivation(frame);
  Element* div_fullscreen = document->getElementById("div1");
  Fullscreen::RequestFullscreen(*div_fullscreen);
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->DidEnterFullscreen();
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));

  // Verify that the viewports are nonscrollable.
  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();
  GraphicsLayer* layout_viewport_scroll_layer =
      web_view_impl->Compositor()->ScrollLayer();
  GraphicsLayer* visual_viewport_scroll_layer =
      frame_view->GetPage()->GetVisualViewport().ScrollLayer();

  ASSERT_FALSE(layout_viewport_scroll_layer->PlatformLayer()
                   ->UserScrollableHorizontal());
  ASSERT_FALSE(
      layout_viewport_scroll_layer->PlatformLayer()->UserScrollableVertical());
  ASSERT_FALSE(visual_viewport_scroll_layer->PlatformLayer()
                   ->UserScrollableHorizontal());
  ASSERT_FALSE(
      visual_viewport_scroll_layer->PlatformLayer()->UserScrollableVertical());

  // Verify that the viewports are scrollable upon exiting fullscreen.
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->DidExitFullscreen();
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  layout_viewport_scroll_layer = web_view_impl->Compositor()->ScrollLayer();
  visual_viewport_scroll_layer =
      frame_view->GetPage()->GetVisualViewport().ScrollLayer();
  ASSERT_TRUE(layout_viewport_scroll_layer->PlatformLayer()
                  ->UserScrollableHorizontal());
  ASSERT_TRUE(
      layout_viewport_scroll_layer->PlatformLayer()->UserScrollableVertical());
  ASSERT_TRUE(visual_viewport_scroll_layer->PlatformLayer()
                  ->UserScrollableHorizontal());
  ASSERT_TRUE(
      visual_viewport_scroll_layer->PlatformLayer()->UserScrollableVertical());
}

TEST_P(ParameterizedWebFrameTest, FullscreenMainFrame) {
  FakeCompositingWebViewClient client;
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  int viewport_width = 640;
  int viewport_height = 480;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_div.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_impl->UpdateAllLifecyclePhases();

  WebLayer* web_scroll_layer = web_view_impl->MainFrameImpl()
                                   ->GetFrame()
                                   ->View()
                                   ->LayoutViewportScrollableArea()
                                   ->LayerForScrolling()
                                   ->PlatformLayer();
  ASSERT_TRUE(web_scroll_layer->Scrollable());
  ASSERT_TRUE(web_scroll_layer->UserScrollableHorizontal());
  ASSERT_TRUE(web_scroll_layer->UserScrollableVertical());

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();
  std::unique_ptr<UserGestureIndicator> gesture =
      Frame::NotifyUserActivation(frame);
  Fullscreen::RequestFullscreen(*document->documentElement());
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->DidEnterFullscreen();
  EXPECT_EQ(document->documentElement(),
            Fullscreen::FullscreenElementFrom(*document));

  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(document->documentElement(),
            Fullscreen::FullscreenElementFrom(*document));

  // Verify that the main frame is still scrollable.
  web_scroll_layer = web_view_impl->MainFrameImpl()
                         ->GetFrame()
                         ->View()
                         ->LayoutViewportScrollableArea()
                         ->LayerForScrolling()
                         ->PlatformLayer();
  ASSERT_TRUE(web_scroll_layer->Scrollable());
  ASSERT_TRUE(web_scroll_layer->UserScrollableHorizontal());
  ASSERT_TRUE(web_scroll_layer->UserScrollableVertical());

  // Verify the main frame still behaves correctly after a resize.
  web_view_helper.Resize(WebSize(viewport_height, viewport_width));
  ASSERT_TRUE(web_scroll_layer->Scrollable());
  ASSERT_TRUE(web_scroll_layer->UserScrollableHorizontal());
  ASSERT_TRUE(web_scroll_layer->UserScrollableVertical());
}

TEST_P(ParameterizedWebFrameTest, FullscreenSubframe) {
  FakeCompositingWebViewClient client;
  RegisterMockedHttpURLLoad("fullscreen_iframe.html");
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_iframe.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  int viewport_width = 640;
  int viewport_height = 480;
  client.screen_info_.rect.width = viewport_width;
  client.screen_info_.rect.height = viewport_height;
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_impl->UpdateAllLifecyclePhases();

  LocalFrame* frame =
      ToWebLocalFrameImpl(
          web_view_helper.GetWebView()->MainFrame()->FirstChild())
          ->GetFrame();
  Document* document = frame->GetDocument();
  std::unique_ptr<UserGestureIndicator> gesture =
      Frame::NotifyUserActivation(frame);
  Element* div_fullscreen = document->getElementById("div1");
  Fullscreen::RequestFullscreen(*div_fullscreen);
  web_view_impl->DidEnterFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();

  // Verify that the element is sized to the viewport.
  LayoutFullScreen* fullscreen_layout_object =
      Fullscreen::From(*document).FullScreenLayoutObject();
  EXPECT_EQ(viewport_width, fullscreen_layout_object->LogicalWidth().ToInt());
  EXPECT_EQ(viewport_height, fullscreen_layout_object->LogicalHeight().ToInt());

  // Verify it's updated after a device rotation.
  client.screen_info_.rect.width = viewport_height;
  client.screen_info_.rect.height = viewport_width;
  web_view_helper.Resize(WebSize(viewport_height, viewport_width));
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(viewport_height, fullscreen_layout_object->LogicalWidth().ToInt());
  EXPECT_EQ(viewport_width, fullscreen_layout_object->LogicalHeight().ToInt());
}

// Tests entering nested fullscreen and then exiting via the same code path
// that's used when the browser process exits fullscreen.
TEST_P(ParameterizedWebFrameTest, FullscreenNestedExit) {
  RegisterMockedHttpURLLoad("fullscreen_iframe.html");
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url_ + "fullscreen_iframe.html");

  web_view_impl->UpdateAllLifecyclePhases();

  Document* top_doc = web_view_impl->MainFrameImpl()->GetFrame()->GetDocument();
  Element* top_body = top_doc->body();

  HTMLIFrameElement* iframe =
      ToHTMLIFrameElement(top_doc->QuerySelector("iframe"));
  Document* iframe_doc = iframe->contentDocument();
  Element* iframe_body = iframe_doc->body();

  {
    std::unique_ptr<UserGestureIndicator> gesture =
        Frame::NotifyUserActivation(top_doc->GetFrame());
    Fullscreen::RequestFullscreen(*top_body);
  }
  web_view_impl->DidEnterFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();

  {
    std::unique_ptr<UserGestureIndicator> gesture =
        Frame::NotifyUserActivation(iframe_doc->GetFrame());
    Fullscreen::RequestFullscreen(*iframe_body);
  }
  web_view_impl->DidEnterFullscreen();
  Microtask::PerformCheckpoint(V8PerIsolateData::MainThreadIsolate());
  web_view_impl->UpdateAllLifecyclePhases();

  // We are now in nested fullscreen, with both documents having a non-empty
  // fullscreen element stack.
  EXPECT_EQ(iframe, Fullscreen::FullscreenElementFrom(*top_doc));
  EXPECT_EQ(iframe_body, Fullscreen::FullscreenElementFrom(*iframe_doc));

  web_view_impl->DidExitFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();

  // We should now have fully exited fullscreen.
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*top_doc));
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*iframe_doc));
}

TEST_P(ParameterizedWebFrameTest, FullscreenWithTinyViewport) {
  FakeCompositingWebViewClient client;
  RegisterMockedHttpURLLoad("viewport-tiny.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-tiny.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  int viewport_width = 384;
  int viewport_height = 640;
  client.screen_info_.rect.width = viewport_width;
  client.screen_info_.rect.height = viewport_height;
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_impl->UpdateAllLifecyclePhases();

  auto* layout_view = web_view_helper.GetWebView()
                          ->MainFrameImpl()
                          ->GetFrameView()
                          ->GetLayoutView();
  EXPECT_EQ(320, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(533, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.2, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.2, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  std::unique_ptr<UserGestureIndicator> gesture =
      Frame::NotifyUserActivation(frame);
  Fullscreen::RequestFullscreen(*frame->GetDocument()->documentElement());
  web_view_impl->DidEnterFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(384, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(640, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  web_view_impl->DidExitFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(320, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(533, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.2, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.2, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, FullscreenResizeWithTinyViewport) {
  FakeCompositingWebViewClient client;
  RegisterMockedHttpURLLoad("viewport-tiny.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-tiny.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  int viewport_width = 384;
  int viewport_height = 640;
  client.screen_info_.rect.width = viewport_width;
  client.screen_info_.rect.height = viewport_height;
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_impl->UpdateAllLifecyclePhases();

  auto* layout_view = web_view_helper.GetWebView()
                          ->MainFrameImpl()
                          ->GetFrameView()
                          ->GetLayoutView();
  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  std::unique_ptr<UserGestureIndicator> gesture =
      Frame::NotifyUserActivation(frame);
  Fullscreen::RequestFullscreen(*frame->GetDocument()->documentElement());
  web_view_impl->DidEnterFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(384, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(640, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  viewport_width = 640;
  viewport_height = 384;
  client.screen_info_.rect.width = viewport_width;
  client.screen_info_.rect.height = viewport_height;
  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(640, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(384, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  web_view_impl->DidExitFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_EQ(320, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(192, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(2, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(2, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());
}

TEST_P(ParameterizedWebFrameTest, FullscreenRestoreScaleFactorUponExiting) {
  // The purpose of this test is to more precisely simulate the sequence of
  // resize and switching fullscreen state operations on WebView, with the
  // interference from Android status bars like a real device does.
  // This verifies we handle the transition and restore states correctly.
  WebSize screen_size_minus_status_bars_minus_url_bar(598, 303);
  WebSize screen_size_minus_status_bars(598, 359);
  WebSize screen_size(640, 384);

  FakeCompositingWebViewClient client;
  RegisterMockedHttpURLLoad("fullscreen_restore_scale_factor.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_restore_scale_factor.html", nullptr, &client,
      nullptr, &ConfigureAndroid);
  client.screen_info_.rect.width =
      screen_size_minus_status_bars_minus_url_bar.width;
  client.screen_info_.rect.height =
      screen_size_minus_status_bars_minus_url_bar.height;
  web_view_helper.Resize(screen_size_minus_status_bars_minus_url_bar);
  auto* layout_view = web_view_helper.GetWebView()
                          ->MainFrameImpl()
                          ->GetFrameView()
                          ->GetLayoutView();
  EXPECT_EQ(screen_size_minus_status_bars_minus_url_bar.width,
            layout_view->LogicalWidth().Floor());
  EXPECT_EQ(screen_size_minus_status_bars_minus_url_bar.height,
            layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());

  {
    LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
    std::unique_ptr<UserGestureIndicator> gesture =
        Frame::NotifyUserActivation(frame);
    Fullscreen::RequestFullscreen(*frame->GetDocument()->body());
  }

  web_view_impl->DidEnterFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();
  client.screen_info_.rect.width = screen_size_minus_status_bars.width;
  client.screen_info_.rect.height = screen_size_minus_status_bars.height;
  web_view_helper.Resize(screen_size_minus_status_bars);
  client.screen_info_.rect.width = screen_size.width;
  client.screen_info_.rect.height = screen_size.height;
  web_view_helper.Resize(screen_size);
  EXPECT_EQ(screen_size.width, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(screen_size.height, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  web_view_impl->DidExitFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();
  client.screen_info_.rect.width = screen_size_minus_status_bars.width;
  client.screen_info_.rect.height = screen_size_minus_status_bars.height;
  web_view_helper.Resize(screen_size_minus_status_bars);
  client.screen_info_.rect.width =
      screen_size_minus_status_bars_minus_url_bar.width;
  client.screen_info_.rect.height =
      screen_size_minus_status_bars_minus_url_bar.height;
  web_view_helper.Resize(screen_size_minus_status_bars_minus_url_bar);
  EXPECT_EQ(screen_size_minus_status_bars_minus_url_bar.width,
            layout_view->LogicalWidth().Floor());
  EXPECT_EQ(screen_size_minus_status_bars_minus_url_bar.height,
            layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());
}

// Tests that leaving fullscreen by navigating to a new page resets the
// fullscreen page scale constraints.
TEST_P(ParameterizedWebFrameTest, ClearFullscreenConstraintsOnNavigation) {
  RegisterMockedHttpURLLoad("viewport-tiny.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  int viewport_width = 100;
  int viewport_height = 200;

  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-tiny.html", nullptr, nullptr, nullptr,
      ConfigureAndroid);

  web_view_helper.Resize(WebSize(viewport_width, viewport_height));
  web_view_impl->UpdateAllLifecyclePhases();

  // viewport-tiny.html specifies a 320px layout width.
  auto* layout_view =
      web_view_impl->MainFrameImpl()->GetFrameView()->GetLayoutView();
  EXPECT_EQ(320, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(640, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(0.3125, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(0.3125, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  std::unique_ptr<UserGestureIndicator> gesture =
      Frame::NotifyUserActivation(frame, UserGestureToken::kNewGesture);
  Fullscreen::RequestFullscreen(*frame->GetDocument()->documentElement());
  web_view_impl->DidEnterFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();

  // Entering fullscreen causes layout size and page scale limits to be
  // overridden.
  EXPECT_EQ(100, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(200, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  const char kSource[] = "<meta name=\"viewport\" content=\"width=200\">";

  // Load a new page before exiting fullscreen.
  KURL test_url = ToKURL("about:blank");
  WebLocalFrame* web_frame = web_view_helper.LocalMainFrame();
  FrameTestHelpers::LoadHTMLString(web_frame, kSource, test_url);
  web_view_impl->DidExitFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();

  // Make sure the new page's layout size and scale factor limits aren't
  // overridden.
  layout_view = web_view_impl->MainFrameImpl()->GetFrameView()->GetLayoutView();
  EXPECT_EQ(200, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(400, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(0.5, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());
}

namespace {

class TestFullscreenWebLayerTreeView : public WebLayerTreeView {
 public:
  TestFullscreenWebLayerTreeView() = default;
  ~TestFullscreenWebLayerTreeView() override = default;

  // WebLayerTreeView:
  void SetBackgroundColor(blink::WebColor color) override {
    has_transparent_background = SkColorGetA(color) < SK_AlphaOPAQUE;
  }
  bool has_transparent_background = false;
};

class TestFullscreenWebViewClient : public FrameTestHelpers::TestWebViewClient {
 public:
  TestFullscreenWebViewClient() = default;
  ~TestFullscreenWebViewClient() override = default;

  // FrameTestHelpers::TestWebViewClient:
  WebLayerTreeView* InitializeLayerTreeView() override {
    return &test_fullscreen_layer_tree_view;
  }
  TestFullscreenWebLayerTreeView test_fullscreen_layer_tree_view;
};

}  // namespace

TEST_P(ParameterizedWebFrameTest, OverlayFullscreenVideo) {
  ScopedForceOverlayFullscreenVideoForTest force_overlay_fullscreen_video(true);
  RegisterMockedHttpURLLoad("fullscreen_video.html");
  TestFullscreenWebViewClient web_view_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_video.html", nullptr, &web_view_client);

  const TestFullscreenWebLayerTreeView& layer_tree_view =
      web_view_client.test_fullscreen_layer_tree_view;

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  std::unique_ptr<UserGestureIndicator> gesture =
      Frame::NotifyUserActivation(frame);
  HTMLVideoElement* video =
      ToHTMLVideoElement(frame->GetDocument()->getElementById("video"));
  EXPECT_TRUE(video->UsesOverlayFullscreenVideo());
  EXPECT_FALSE(video->IsFullscreen());
  EXPECT_FALSE(layer_tree_view.has_transparent_background);

  video->webkitEnterFullscreen();
  web_view_impl->DidEnterFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_TRUE(video->IsFullscreen());
  EXPECT_TRUE(layer_tree_view.has_transparent_background);

  web_view_impl->DidExitFullscreen();
  web_view_impl->UpdateAllLifecyclePhases();
  EXPECT_FALSE(video->IsFullscreen());
  EXPECT_FALSE(layer_tree_view.has_transparent_background);
}

TEST_P(ParameterizedWebFrameTest, LayoutBlockPercentHeightDescendants) {
  RegisterMockedHttpURLLoad("percent-height-descendants.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ +
                                    "percent-height-descendants.html");

  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view_helper.Resize(WebSize(800, 800));
  web_view->UpdateAllLifecyclePhases();

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  LayoutBlock* container =
      ToLayoutBlock(document->getElementById("container")->GetLayoutObject());
  LayoutBox* percent_height_in_anonymous =
      ToLayoutBox(document->getElementById("percent-height-in-anonymous")
                      ->GetLayoutObject());
  LayoutBox* percent_height_direct_child =
      ToLayoutBox(document->getElementById("percent-height-direct-child")
                      ->GetLayoutObject());

  EXPECT_TRUE(
      container->HasPercentHeightDescendant(percent_height_in_anonymous));
  EXPECT_TRUE(
      container->HasPercentHeightDescendant(percent_height_direct_child));

  ASSERT_TRUE(container->PercentHeightDescendants());
  ASSERT_TRUE(container->HasPercentHeightDescendants());
  EXPECT_EQ(2U, container->PercentHeightDescendants()->size());
  EXPECT_TRUE(container->PercentHeightDescendants()->Contains(
      percent_height_in_anonymous));
  EXPECT_TRUE(container->PercentHeightDescendants()->Contains(
      percent_height_direct_child));

  LayoutBlock* anonymous_block = percent_height_in_anonymous->ContainingBlock();
  EXPECT_TRUE(anonymous_block->IsAnonymous());
  EXPECT_FALSE(anonymous_block->HasPercentHeightDescendants());
}

TEST_P(ParameterizedWebFrameTest, HasVisibleContentOnVisibleFrames) {
  RegisterMockedHttpURLLoad("visible_frames.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url_ + "visible_frames.html");
  for (WebFrame* frame = web_view_impl->MainFrameImpl()->TraverseNext(); frame;
       frame = frame->TraverseNext()) {
    EXPECT_TRUE(frame->ToWebLocalFrame()->HasVisibleContent());
  }
}

TEST_P(ParameterizedWebFrameTest, HasVisibleContentOnHiddenFrames) {
  RegisterMockedHttpURLLoad("hidden_frames.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url_ + "hidden_frames.html");
  for (WebFrame* frame = web_view_impl->MainFrameImpl()->TraverseNext(); frame;
       frame = frame->TraverseNext()) {
    EXPECT_FALSE(frame->ToWebLocalFrame()->HasVisibleContent());
  }
}

class ManifestChangeWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  ManifestChangeWebFrameClient() : manifest_change_count_(0) {}
  ~ManifestChangeWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidChangeManifest() override { ++manifest_change_count_; }

  int ManifestChangeCount() { return manifest_change_count_; }

 private:
  int manifest_change_count_;
};

TEST_P(ParameterizedWebFrameTest, NotifyManifestChange) {
  RegisterMockedHttpURLLoad("link-manifest-change.html");

  ManifestChangeWebFrameClient web_frame_client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "link-manifest-change.html",
                                    &web_frame_client);

  EXPECT_EQ(14, web_frame_client.ManifestChangeCount());
}

static Resource* FetchManifest(Document* document, const KURL& url) {
  FetchParameters fetch_parameters{ResourceRequest(url)};
  fetch_parameters.SetRequestContext(WebURLRequest::kRequestContextManifest);

  return RawResource::FetchSynchronously(fetch_parameters, document->Fetcher());
}

TEST_P(ParameterizedWebFrameTest, ManifestFetch) {
  RegisterMockedHttpURLLoad("foo.html");
  RegisterMockedHttpURLLoad("link-manifest-fetch.json");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  Document* document =
      web_view_helper.LocalMainFrame()->GetFrame()->GetDocument();

  Resource* resource =
      FetchManifest(document, ToKURL(base_url_ + "link-manifest-fetch.json"));

  EXPECT_TRUE(resource->IsLoaded());
}

TEST_P(ParameterizedWebFrameTest, ManifestCSPFetchAllow) {
  RegisterMockedURLLoadFromBase(not_base_url_, "link-manifest-fetch.json");
  RegisterMockedHttpURLLoadWithCSP("foo.html", "manifest-src *");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  Document* document =
      web_view_helper.LocalMainFrame()->GetFrame()->GetDocument();

  Resource* resource = FetchManifest(
      document, ToKURL(not_base_url_ + "link-manifest-fetch.json"));

  EXPECT_TRUE(resource->IsLoaded());
}

TEST_P(ParameterizedWebFrameTest, ManifestCSPFetchSelf) {
  RegisterMockedURLLoadFromBase(not_base_url_, "link-manifest-fetch.json");
  RegisterMockedHttpURLLoadWithCSP("foo.html", "manifest-src 'self'");

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  Document* document =
      web_view_helper.LocalMainFrame()->GetFrame()->GetDocument();

  Resource* resource = FetchManifest(
      document, ToKURL(not_base_url_ + "link-manifest-fetch.json"));

  // Fetching resource wasn't allowed.
  ASSERT_TRUE(resource);
  EXPECT_TRUE(resource->ErrorOccurred());
  EXPECT_TRUE(resource->GetResourceError().IsAccessCheck());
}

TEST_P(ParameterizedWebFrameTest, ManifestCSPFetchSelfReportOnly) {
  RegisterMockedURLLoadFromBase(not_base_url_, "link-manifest-fetch.json");
  RegisterMockedHttpURLLoadWithCSP("foo.html", "manifest-src 'self'",
                                   /* report only */ true);

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  Document* document =
      web_view_helper.LocalMainFrame()->GetFrame()->GetDocument();

  Resource* resource = FetchManifest(
      document, ToKURL(not_base_url_ + "link-manifest-fetch.json"));

  EXPECT_TRUE(resource->IsLoaded());
}

TEST_P(ParameterizedWebFrameTest, ReloadBypassingCache) {
  // Check that a reload bypassing cache on a frame will result in the cache
  // policy of the request being set to ReloadBypassingCache.
  RegisterMockedHttpURLLoad("foo.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();
  FrameTestHelpers::ReloadFrameBypassingCache(frame);
  EXPECT_EQ(mojom::FetchCacheMode::kBypassCache,
            frame->GetDocumentLoader()->GetRequest().GetCacheMode());
}

static void NodeImageTestValidation(const IntSize& reference_bitmap_size,
                                    DragImage* drag_image) {
  // Prepare the reference bitmap.
  SkBitmap bitmap;
  bitmap.allocN32Pixels(reference_bitmap_size.Width(),
                        reference_bitmap_size.Height());
  SkCanvas canvas(bitmap);
  canvas.drawColor(SK_ColorGREEN);

  EXPECT_EQ(reference_bitmap_size.Width(), drag_image->Size().Width());
  EXPECT_EQ(reference_bitmap_size.Height(), drag_image->Size().Height());
  const SkBitmap& drag_bitmap = drag_image->Bitmap();
  EXPECT_EQ(0, memcmp(bitmap.getPixels(), drag_bitmap.getPixels(),
                      bitmap.computeByteSize()));
}

TEST_P(ParameterizedWebFrameTest, NodeImageTestCSSTransformDescendant) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image = NodeImageTestSetup(
      &web_view_helper, std::string("case-css-3dtransform-descendant"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(IntSize(40, 40), drag_image.get());
}

TEST_P(ParameterizedWebFrameTest, NodeImageTestCSSTransform) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image =
      NodeImageTestSetup(&web_view_helper, std::string("case-css-transform"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(IntSize(40, 40), drag_image.get());
}

TEST_P(ParameterizedWebFrameTest, NodeImageTestCSS3DTransform) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image =
      NodeImageTestSetup(&web_view_helper, std::string("case-css-3dtransform"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(IntSize(40, 40), drag_image.get());
}

TEST_P(ParameterizedWebFrameTest, NodeImageTestInlineBlock) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image =
      NodeImageTestSetup(&web_view_helper, std::string("case-inlineblock"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(IntSize(40, 40), drag_image.get());
}

TEST_P(ParameterizedWebFrameTest, NodeImageTestFloatLeft) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image = NodeImageTestSetup(
      &web_view_helper, std::string("case-float-left-overflow-hidden"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(IntSize(40, 40), drag_image.get());
}

// Crashes on Android: http://crbug.com/403804
#if defined(OS_ANDROID)
TEST_P(ParameterizedWebFrameTest, DISABLED_PrintingBasic)
#else
TEST_P(ParameterizedWebFrameTest, PrintingBasic)
#endif
{
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("data:text/html,Hello, world.");

  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  WebPrintParams print_params;
  print_params.print_content_area.width = 500;
  print_params.print_content_area.height = 500;

  int page_count = frame->PrintBegin(print_params);
  EXPECT_EQ(1, page_count);
  frame->PrintEnd();
}

class ThemeColorTestWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  ThemeColorTestWebFrameClient() : did_notify_(false) {}
  ~ThemeColorTestWebFrameClient() override = default;

  void Reset() { did_notify_ = false; }

  bool DidNotify() const { return did_notify_; }

 private:
  // FrameTestHelpers::TestWebFrameClient:
  void DidChangeThemeColor() override { did_notify_ = true; }

  bool did_notify_;
};

TEST_P(ParameterizedWebFrameTest, ThemeColor) {
  RegisterMockedHttpURLLoad("theme_color_test.html");
  ThemeColorTestWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "theme_color_test.html",
                                    &client);
  EXPECT_TRUE(client.DidNotify());
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ(0xff0000ff, frame->GetDocument().ThemeColor());
  // Change color by rgb.
  client.Reset();
  frame->ExecuteScript(
      WebScriptSource("document.getElementById('tc1').setAttribute('content', "
                      "'rgb(0, 0, 0)');"));
  EXPECT_TRUE(client.DidNotify());
  EXPECT_EQ(0xff000000, frame->GetDocument().ThemeColor());
  // Change color by hsl.
  client.Reset();
  frame->ExecuteScript(
      WebScriptSource("document.getElementById('tc1').setAttribute('content', "
                      "'hsl(240,100%, 50%)');"));
  EXPECT_TRUE(client.DidNotify());
  EXPECT_EQ(0xff0000ff, frame->GetDocument().ThemeColor());
  // Change of second theme-color meta tag will not change frame's theme
  // color.
  client.Reset();
  frame->ExecuteScript(WebScriptSource(
      "document.getElementById('tc2').setAttribute('content', '#00FF00');"));
  EXPECT_TRUE(client.DidNotify());
  EXPECT_EQ(0xff0000ff, frame->GetDocument().ThemeColor());
}

// Make sure that an embedder-triggered detach with a remote frame parent
// doesn't leave behind dangling pointers.
TEST_P(ParameterizedWebFrameTest, EmbedderTriggeredDetachWithRemoteMainFrame) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebLocalFrame* child_frame =
      FrameTestHelpers::CreateLocalChild(*helper.RemoteMainFrame());

  // Purposely keep the LocalFrame alive so it's the last thing to be destroyed.
  Persistent<Frame> child_core_frame = WebFrame::ToCoreFrame(*child_frame);
  helper.Reset();
  child_core_frame.Clear();
}

class WebFrameSwapTest : public ParameterizedWebFrameTest {
 protected:
  WebFrameSwapTest() {
    RegisterMockedHttpURLLoad("frame-a-b-c.html");
    RegisterMockedHttpURLLoad("subframe-a.html");
    RegisterMockedHttpURLLoad("subframe-b.html");
    RegisterMockedHttpURLLoad("subframe-c.html");
    RegisterMockedHttpURLLoad("subframe-hello.html");

    web_view_helper_.InitializeAndLoad(base_url_ + "frame-a-b-c.html");
  }

  void Reset() { web_view_helper_.Reset(); }
  WebLocalFrame* MainFrame() const { return web_view_helper_.LocalMainFrame(); }
  WebViewImpl* WebView() const { return web_view_helper_.GetWebView(); }

 private:
  FrameTestHelpers::WebViewHelper web_view_helper_;
};

INSTANTIATE_TEST_CASE_P(All, WebFrameSwapTest, testing::Bool());

TEST_P(WebFrameSwapTest, SwapMainFrame) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  MainFrame()->Swap(remote_frame);

  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);
  remote_frame->Swap(local_frame);

  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  FrameTestHelpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");

  std::string content =
      WebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("hello", content);
}

TEST_P(WebFrameSwapTest, ValidateSizeOnRemoteToLocalMainFrameSwap) {
  WebSize size(111, 222);

  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  MainFrame()->Swap(remote_frame);

  remote_frame->View()->Resize(size);

  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);
  remote_frame->Swap(local_frame);

  // Verify that the size that was set with a remote main frame is correct
  // after swapping to a local frame.
  Page* page = static_cast<WebViewImpl*>(local_frame->View())
                   ->GetPage()
                   ->MainFrame()
                   ->GetPage();
  EXPECT_EQ(size.width, page->GetVisualViewport().Size().Width());
  EXPECT_EQ(size.height, page->GetVisualViewport().Size().Height());
}

// Verify that size changes to browser controls while the main frame is remote
// are preserved when the main frame swaps to a local frame.  See
// https://crbug.com/769321.
TEST_P(WebFrameSwapTest,
       ValidateBrowserControlsSizeOnRemoteToLocalMainFrameSwap) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  MainFrame()->Swap(remote_frame);

  // Create a provisional main frame frame but don't swap it in yet.
  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);

  WebViewImpl* web_view = static_cast<WebViewImpl*>(local_frame->View());
  EXPECT_TRUE(web_view->MainFrame() &&
              web_view->MainFrame()->IsWebRemoteFrame());

  // Resize the browser controls.
  float top_browser_controls_height = 40;
  float bottom_browser_controls_height = 60;
  web_view->ResizeWithBrowserControls(WebSize(100, 100),
                                      top_browser_controls_height,
                                      bottom_browser_controls_height, false);

  // Swap the provisional frame in and verify that the browser controls size is
  // correct.
  remote_frame->Swap(local_frame);
  Page* page = static_cast<WebViewImpl*>(local_frame->View())
                   ->GetPage()
                   ->MainFrame()
                   ->GetPage();
  EXPECT_EQ(top_browser_controls_height,
            page->GetBrowserControls().TopHeight());
  EXPECT_EQ(bottom_browser_controls_height,
            page->GetBrowserControls().BottomHeight());
}

namespace {

class SwapMainFrameWhenTitleChangesWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  SwapMainFrameWhenTitleChangesWebFrameClient() = default;
  ~SwapMainFrameWhenTitleChangesWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidReceiveTitle(const WebString& title, WebTextDirection) override {
    if (title.IsEmpty())
      return;

    if (!Frame()->Parent())
      Frame()->Swap(FrameTestHelpers::CreateRemote());
  }
};

}  // namespace

TEST_P(ParameterizedWebFrameTest, SwapMainFrameWhileLoading) {
  SwapMainFrameWhenTitleChangesWebFrameClient frame_client;

  FrameTestHelpers::WebViewHelper web_view_helper;
  RegisterMockedHttpURLLoad("frame-a-b-c.html");
  RegisterMockedHttpURLLoad("subframe-a.html");
  RegisterMockedHttpURLLoad("subframe-b.html");
  RegisterMockedHttpURLLoad("subframe-c.html");
  RegisterMockedHttpURLLoad("subframe-hello.html");

  web_view_helper.InitializeAndLoad(base_url_ + "frame-a-b-c.html",
                                    &frame_client);
}

void WebFrameTest::SwapAndVerifyFirstChildConsistency(const char* const message,
                                                      WebFrame* parent,
                                                      WebFrame* new_child) {
  SCOPED_TRACE(message);
  parent->FirstChild()->Swap(new_child);

  EXPECT_EQ(new_child, parent->FirstChild());
  EXPECT_EQ(new_child->Parent(), parent);
  EXPECT_EQ(new_child,
            parent->last_child_->previous_sibling_->previous_sibling_);
  EXPECT_EQ(new_child->NextSibling(), parent->last_child_->previous_sibling_);
}

TEST_P(WebFrameSwapTest, SwapFirstChild) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  SwapAndVerifyFirstChildConsistency("local->remote", MainFrame(),
                                     remote_frame);

  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);
  SwapAndVerifyFirstChildConsistency("remote->local", MainFrame(), local_frame);

  // FIXME: This almost certainly fires more load events on the iframe element
  // than it should.
  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  FrameTestHelpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  std::string content =
      WebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("\n\nhello\n\nb\n\n\na\n\nc", content);
}

void WebFrameTest::SwapAndVerifyMiddleChildConsistency(
    const char* const message,
    WebFrame* parent,
    WebFrame* new_child) {
  SCOPED_TRACE(message);
  parent->FirstChild()->NextSibling()->Swap(new_child);

  EXPECT_EQ(new_child, parent->FirstChild()->NextSibling());
  EXPECT_EQ(new_child, parent->last_child_->previous_sibling_);
  EXPECT_EQ(new_child->Parent(), parent);
  EXPECT_EQ(new_child, parent->FirstChild()->NextSibling());
  EXPECT_EQ(new_child->previous_sibling_, parent->FirstChild());
  EXPECT_EQ(new_child, parent->last_child_->previous_sibling_);
  EXPECT_EQ(new_child->NextSibling(), parent->last_child_);
}

TEST_P(WebFrameSwapTest, SwapMiddleChild) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  SwapAndVerifyMiddleChildConsistency("local->remote", MainFrame(),
                                      remote_frame);

  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);
  SwapAndVerifyMiddleChildConsistency("remote->local", MainFrame(),
                                      local_frame);

  // FIXME: This almost certainly fires more load events on the iframe element
  // than it should.
  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  FrameTestHelpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  std::string content =
      WebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("\n\na\n\nhello\n\nc", content);
}

void WebFrameTest::SwapAndVerifyLastChildConsistency(const char* const message,
                                                     WebFrame* parent,
                                                     WebFrame* new_child) {
  SCOPED_TRACE(message);
  LastChild(parent)->Swap(new_child);

  EXPECT_EQ(new_child, LastChild(parent));
  EXPECT_EQ(new_child->Parent(), parent);
  EXPECT_EQ(new_child, parent->FirstChild()->NextSibling()->NextSibling());
  EXPECT_EQ(new_child->previous_sibling_, parent->FirstChild()->NextSibling());
}

TEST_P(WebFrameSwapTest, SwapLastChild) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  SwapAndVerifyLastChildConsistency("local->remote", MainFrame(), remote_frame);

  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);
  SwapAndVerifyLastChildConsistency("remote->local", MainFrame(), local_frame);

  // FIXME: This almost certainly fires more load events on the iframe element
  // than it should.
  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  FrameTestHelpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  std::string content =
      WebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("\n\na\n\nb\n\n\na\n\nhello", content);
}

TEST_P(WebFrameSwapTest, DetachProvisionalFrame) {
  WebRemoteFrameImpl* remote_frame = FrameTestHelpers::CreateRemote();
  SwapAndVerifyMiddleChildConsistency("local->remote", MainFrame(),
                                      remote_frame);

  WebLocalFrameImpl* provisional_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);

  // The provisional frame should have a local frame owner.
  FrameOwner* owner = provisional_frame->GetFrame()->Owner();
  ASSERT_TRUE(owner->IsLocal());

  // But the owner should point to |remoteFrame|, since the new frame is still
  // provisional.
  EXPECT_EQ(remote_frame->GetFrame(), owner->ContentFrame());

  // After detaching the provisional frame, the frame owner should still point
  // at |remoteFrame|.
  provisional_frame->Detach();

  // The owner should not be affected by detaching the provisional frame, so it
  // should still point to |remoteFrame|.
  EXPECT_EQ(remote_frame->GetFrame(), owner->ContentFrame());
}

void WebFrameTest::SwapAndVerifySubframeConsistency(const char* const message,
                                                    WebFrame* old_frame,
                                                    WebFrame* new_frame) {
  SCOPED_TRACE(message);

  EXPECT_TRUE(old_frame->FirstChild());
  old_frame->Swap(new_frame);

  EXPECT_FALSE(new_frame->FirstChild());
  EXPECT_FALSE(new_frame->last_child_);
}

TEST_P(WebFrameSwapTest, EventsOnDisconnectedSubDocumentSkipped) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild()->NextSibling();
  EXPECT_TRUE(target_frame);
  SwapAndVerifySubframeConsistency("local->remote", target_frame, remote_frame);

  WebLocalFrameImpl* local_child =
      FrameTestHelpers::CreateLocalChild(*remote_frame, "local-inside-remote");

  Document* main_document =
      WebView()->MainFrameImpl()->GetFrame()->GetDocument();
  Document* child_document = local_child->GetFrame()->GetDocument();
  EventHandlerRegistry& event_registry =
      main_document->GetPage()->GetEventHandlerRegistry();

  // Add the non-connected, but local, child document as having an event.
  event_registry.DidAddEventHandler(
      *child_document, EventHandlerRegistry::kTouchStartOrMoveEventBlocking);
  // Passes if this does not crash or DCHECK.
  main_document->View()->UpdateAllLifecyclePhases();
}

TEST_P(WebFrameSwapTest, EventsOnDisconnectedElementSkipped) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild()->NextSibling();
  EXPECT_TRUE(target_frame);
  SwapAndVerifySubframeConsistency("local->remote", target_frame, remote_frame);

  WebLocalFrameImpl* local_child =
      FrameTestHelpers::CreateLocalChild(*remote_frame, "local-inside-remote");

  Document* main_document =
      WebView()->MainFrameImpl()->GetFrame()->GetDocument();

  // Layout ensures that elements in the local_child frame get LayoutObjects
  // attached, but doesn't paint, because the child frame needs to not have
  // been composited for the purpose of this test.
  local_child->GetFrameView()->UpdateLayout();
  Document* child_document = local_child->GetFrame()->GetDocument();
  EventHandlerRegistry& event_registry =
      main_document->GetPage()->GetEventHandlerRegistry();

  // Add the non-connected body element as having an event.
  event_registry.DidAddEventHandler(
      *child_document->body(),
      EventHandlerRegistry::kTouchStartOrMoveEventBlocking);
  // Passes if this does not crash or DCHECK.
  main_document->View()->UpdateAllLifecyclePhases();
}

TEST_P(WebFrameSwapTest, SwapParentShouldDetachChildren) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild()->NextSibling();
  EXPECT_TRUE(target_frame);
  SwapAndVerifySubframeConsistency("local->remote", target_frame, remote_frame);

  target_frame = MainFrame()->FirstChild()->NextSibling();
  EXPECT_TRUE(target_frame);

  // Create child frames in the target frame before testing the swap.
  FrameTestHelpers::CreateRemoteChild(*remote_frame);

  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);
  SwapAndVerifySubframeConsistency("remote->local", target_frame, local_frame);

  // FIXME: This almost certainly fires more load events on the iframe element
  // than it should.
  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  FrameTestHelpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  std::string content =
      WebFrameContentDumper::DumpWebViewAsText(WebView(), 1024).Utf8();
  EXPECT_EQ("\n\na\n\nhello\n\nc", content);
}

TEST_P(WebFrameSwapTest, SwapPreservesGlobalContext) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());
  v8::Local<v8::Value> window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("window"));
  ASSERT_TRUE(window_top->IsObject());
  v8::Local<v8::Value> original_window =
      MainFrame()->ExecuteScriptAndReturnValue(
          WebScriptSource("document.querySelector('#frame2').contentWindow;"));
  ASSERT_TRUE(original_window->IsObject());

  // Make sure window reference stays the same when swapping to a remote frame.
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild()->NextSibling();
  target_frame->Swap(remote_frame);
  v8::Local<v8::Value> remote_window = MainFrame()->ExecuteScriptAndReturnValue(
      WebScriptSource("document.querySelector('#frame2').contentWindow;"));
  EXPECT_TRUE(original_window->StrictEquals(remote_window));
  // Check that its view is consistent with the world.
  v8::Local<v8::Value> remote_window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource(
          "document.querySelector('#frame2').contentWindow.top;"));
  EXPECT_TRUE(window_top->StrictEquals(remote_window_top));

  // Now check that remote -> local works too, since it goes through a different
  // code path.
  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);
  remote_frame->Swap(local_frame);
  v8::Local<v8::Value> local_window = MainFrame()->ExecuteScriptAndReturnValue(
      WebScriptSource("document.querySelector('#frame2').contentWindow;"));
  EXPECT_TRUE(original_window->StrictEquals(local_window));
  v8::Local<v8::Value> local_window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource(
          "document.querySelector('#frame2').contentWindow.top;"));
  EXPECT_TRUE(window_top->StrictEquals(local_window_top));
}

TEST_P(WebFrameSwapTest, SetTimeoutAfterSwap) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::HandleScope scope(isolate);
  MainFrame()->ExecuteScript(
      WebScriptSource("savedSetTimeout = window[0].setTimeout"));

  // Swap the frame to a remote frame.
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild();
  target_frame->Swap(remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUnique()), false);

  // Invoking setTimeout should throw a security error.
  {
    v8::Local<v8::Value> exception = MainFrame()->ExecuteScriptAndReturnValue(
        WebScriptSource("try {\n"
                        "  savedSetTimeout.call(window[0], () => {}, 0);\n"
                        "} catch (e) { e; }"));
    ASSERT_TRUE(!exception.IsEmpty());
    EXPECT_EQ(
        "SecurityError: Blocked a frame with origin \"http://internal.test\" "
        "from accessing a cross-origin frame.",
        ToCoreString(exception
                         ->ToString(ToScriptStateForMainWorld(
                                        WebView()->MainFrameImpl()->GetFrame())
                                        ->GetContext())
                         .ToLocalChecked()));
  }
}

TEST_P(WebFrameSwapTest, SwapInitializesGlobal) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());

  v8::Local<v8::Value> window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("window"));
  ASSERT_TRUE(window_top->IsObject());

  v8::Local<v8::Value> last_child = MainFrame()->ExecuteScriptAndReturnValue(
      WebScriptSource("saved = window[2]"));
  ASSERT_TRUE(last_child->IsObject());

  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  WebFrameTest::LastChild(MainFrame())->Swap(remote_frame);
  v8::Local<v8::Value> remote_window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("saved.top"));
  EXPECT_TRUE(remote_window_top->IsObject());
  EXPECT_TRUE(window_top->StrictEquals(remote_window_top));

  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);
  remote_frame->Swap(local_frame);
  v8::Local<v8::Value> local_window_top =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("saved.top"));
  EXPECT_TRUE(local_window_top->IsObject());
  EXPECT_TRUE(window_top->StrictEquals(local_window_top));
}

TEST_P(WebFrameSwapTest, RemoteFramesAreIndexable) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());

  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  LastChild(MainFrame())->Swap(remote_frame);
  v8::Local<v8::Value> remote_window =
      MainFrame()->ExecuteScriptAndReturnValue(WebScriptSource("window[2]"));
  EXPECT_TRUE(remote_window->IsObject());
  v8::Local<v8::Value> window_length = MainFrame()->ExecuteScriptAndReturnValue(
      WebScriptSource("window.length"));
  ASSERT_TRUE(window_length->IsInt32());
  EXPECT_EQ(3, window_length.As<v8::Int32>()->Value());
}

TEST_P(WebFrameSwapTest, RemoteFrameLengthAccess) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());

  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  LastChild(MainFrame())->Swap(remote_frame);
  v8::Local<v8::Value> remote_window_length =
      MainFrame()->ExecuteScriptAndReturnValue(
          WebScriptSource("window[2].length"));
  ASSERT_TRUE(remote_window_length->IsInt32());
  EXPECT_EQ(0, remote_window_length.As<v8::Int32>()->Value());
}

TEST_P(WebFrameSwapTest, RemoteWindowNamedAccess) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());

  // TODO(dcheng): Once OOPIF unit test infrastructure is in place, test that
  // named window access on a remote window works. For now, just test that
  // accessing a named property doesn't crash.
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  LastChild(MainFrame())->Swap(remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUnique()), false);
  v8::Local<v8::Value> remote_window_property =
      MainFrame()->ExecuteScriptAndReturnValue(
          WebScriptSource("window[2].foo"));
  EXPECT_TRUE(remote_window_property.IsEmpty());
}

TEST_P(WebFrameSwapTest, RemoteWindowToString) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::HandleScope scope(isolate);

  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  LastChild(MainFrame())->Swap(remote_frame);
  v8::Local<v8::Value> to_string_result =
      MainFrame()->ExecuteScriptAndReturnValue(
          WebScriptSource("Object.prototype.toString.call(window[2])"));
  ASSERT_FALSE(to_string_result.IsEmpty());
  EXPECT_STREQ("[object Object]",
               *v8::String::Utf8Value(isolate, to_string_result));
}

// TODO(alexmos, dcheng): This test and some other OOPIF tests use
// very little of the test fixture support in WebFrameSwapTest.  We should
// clean these tests up.
TEST_P(WebFrameSwapTest, FramesOfRemoteParentAreIndexable) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());

  WebRemoteFrame* remote_parent_frame = FrameTestHelpers::CreateRemote();
  MainFrame()->Swap(remote_parent_frame);
  remote_parent_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUnique()), false);

  WebLocalFrame* child_frame =
      FrameTestHelpers::CreateLocalChild(*remote_parent_frame);
  FrameTestHelpers::LoadFrame(child_frame, base_url_ + "subframe-hello.html");

  v8::Local<v8::Value> window =
      child_frame->ExecuteScriptAndReturnValue(WebScriptSource("window"));
  v8::Local<v8::Value> child_of_remote_parent =
      child_frame->ExecuteScriptAndReturnValue(
          WebScriptSource("parent.frames[0]"));
  EXPECT_TRUE(child_of_remote_parent->IsObject());
  EXPECT_TRUE(window->StrictEquals(child_of_remote_parent));

  v8::Local<v8::Value> window_length = child_frame->ExecuteScriptAndReturnValue(
      WebScriptSource("parent.frames.length"));
  ASSERT_TRUE(window_length->IsInt32());
  EXPECT_EQ(1, window_length.As<v8::Int32>()->Value());
}

// Check that frames with a remote parent don't crash while accessing
// window.frameElement.
TEST_P(WebFrameSwapTest, FrameElementInFramesWithRemoteParent) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());

  WebRemoteFrame* remote_parent_frame = FrameTestHelpers::CreateRemote();
  MainFrame()->Swap(remote_parent_frame);
  remote_parent_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUnique()), false);

  WebLocalFrame* child_frame =
      FrameTestHelpers::CreateLocalChild(*remote_parent_frame);
  FrameTestHelpers::LoadFrame(child_frame, base_url_ + "subframe-hello.html");

  v8::Local<v8::Value> frame_element = child_frame->ExecuteScriptAndReturnValue(
      WebScriptSource("window.frameElement"));
  // frameElement should be null if cross-origin.
  ASSERT_FALSE(frame_element.IsEmpty());
  EXPECT_TRUE(frame_element->IsNull());
}

class RemoteToLocalSwapWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  explicit RemoteToLocalSwapWebFrameClient(WebRemoteFrame* remote_frame)
      : history_commit_type_(kWebHistoryInertCommit),
        remote_frame_(remote_frame) {}
  ~RemoteToLocalSwapWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidCommitProvisionalLoad(const WebHistoryItem&,
                                WebHistoryCommitType history_commit_type,
                                WebGlobalObjectReusePolicy) override {
    history_commit_type_ = history_commit_type;
    remote_frame_->Swap(Frame());
  }

  WebHistoryCommitType HistoryCommitType() const {
    return history_commit_type_;
  }

  WebHistoryCommitType history_commit_type_;
  WebRemoteFrame* remote_frame_;
};

// The commit type should be Initial if we are swapping a RemoteFrame to a
// LocalFrame as it is first being created.  This happens when another frame
// exists in the same process, such that we create the RemoteFrame before the
// first navigation occurs.
TEST_P(WebFrameSwapTest, HistoryCommitTypeAfterNewRemoteToLocalSwap) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild();
  ASSERT_TRUE(target_frame);
  target_frame->Swap(remote_frame);
  ASSERT_TRUE(MainFrame()->FirstChild());
  ASSERT_EQ(MainFrame()->FirstChild(), remote_frame);

  RemoteToLocalSwapWebFrameClient client(remote_frame);
  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame, &client);
  FrameTestHelpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  EXPECT_EQ(kWebInitialCommitInChildFrame, client.HistoryCommitType());

  // Manually reset to break WebViewHelper's dependency on the stack allocated
  // TestWebFrameClient.
  Reset();
}

// The commit type should be Standard if we are swapping a RemoteFrame to a
// LocalFrame after commits have already happened in the frame.  The browser
// process will inform us via setCommittedFirstRealLoad.
TEST_P(WebFrameSwapTest, HistoryCommitTypeAfterExistingRemoteToLocalSwap) {
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote();
  WebFrame* target_frame = MainFrame()->FirstChild();
  ASSERT_TRUE(target_frame);
  target_frame->Swap(remote_frame);
  ASSERT_TRUE(MainFrame()->FirstChild());
  ASSERT_EQ(MainFrame()->FirstChild(), remote_frame);

  RemoteToLocalSwapWebFrameClient client(remote_frame);
  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame, &client);
  local_frame->SetCommittedFirstRealLoad();
  FrameTestHelpers::LoadFrame(local_frame, base_url_ + "subframe-hello.html");
  EXPECT_EQ(kWebStandardCommit, client.HistoryCommitType());

  // Manually reset to break WebViewHelper's dependency on the stack allocated
  // TestWebFrameClient.
  Reset();
}

class RemoteNavigationClient
    : public FrameTestHelpers::TestWebRemoteFrameClient {
 public:
  RemoteNavigationClient() = default;
  ~RemoteNavigationClient() override = default;

  // FrameTestHelpers::TestWebRemoteFrameClient:
  void Navigate(const WebURLRequest& request,
                bool should_replace_current_entry) override {
    last_request_ = request;
  }

  const WebURLRequest& LastRequest() const { return last_request_; }

 private:
  WebURLRequest last_request_;
};

TEST_P(WebFrameSwapTest, NavigateRemoteFrameViaLocation) {
  RemoteNavigationClient client;
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote(&client);
  WebFrame* target_frame = MainFrame()->FirstChild();
  ASSERT_TRUE(target_frame);
  target_frame->Swap(remote_frame);
  ASSERT_TRUE(MainFrame()->FirstChild());
  ASSERT_EQ(MainFrame()->FirstChild(), remote_frame);

  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin::CreateFromString("http://127.0.0.1"), false);
  MainFrame()->ExecuteScript(
      WebScriptSource("document.getElementsByTagName('iframe')[0]."
                      "contentWindow.location = 'data:text/html,hi'"));
  ASSERT_FALSE(client.LastRequest().IsNull());
  EXPECT_EQ(WebURL(ToKURL("data:text/html,hi")), client.LastRequest().Url());

  // Manually reset to break WebViewHelper's dependency on the stack allocated
  // TestWebFrameClient.
  Reset();
}

TEST_P(WebFrameSwapTest, WindowOpenOnRemoteFrame) {
  RemoteNavigationClient remote_client;
  WebRemoteFrame* remote_frame = FrameTestHelpers::CreateRemote(&remote_client);
  MainFrame()->FirstChild()->Swap(remote_frame);
  remote_frame->SetReplicatedOrigin(
      WebSecurityOrigin(SecurityOrigin::CreateUnique()), false);

  ASSERT_TRUE(MainFrame()->FirstChild()->IsWebRemoteFrame());
  LocalDOMWindow* main_window =
      ToWebLocalFrameImpl(MainFrame())->GetFrame()->DomWindow();

  KURL destination = ToKURL("data:text/html:destination");
  NonThrowableExceptionState exception_state;
  main_window->open(destination.GetString(), "frame1", "", main_window,
                    main_window, exception_state);
  ASSERT_FALSE(remote_client.LastRequest().IsNull());
  EXPECT_EQ(remote_client.LastRequest().Url(), WebURL(destination));

  // Pointing a named frame to an empty URL should just return a reference to
  // the frame's window without navigating it.
  DOMWindow* result = main_window->open("", "frame1", "", main_window,
                                        main_window, exception_state);
  EXPECT_EQ(remote_client.LastRequest().Url(), WebURL(destination));
  EXPECT_EQ(result, WebFrame::ToCoreFrame(*remote_frame)->DomWindow());

  Reset();
}

class RemoteWindowCloseClient : public FrameTestHelpers::TestWebViewClient {
 public:
  RemoteWindowCloseClient() : closed_(false) {}
  ~RemoteWindowCloseClient() override = default;

  // FrameTestHelpers::TestWebViewClient:
  void CloseWidgetSoon() override { closed_ = true; }

  bool Closed() const { return closed_; }

 private:
  bool closed_;
};

TEST_P(ParameterizedWebFrameTest, WindowOpenRemoteClose) {
  FrameTestHelpers::WebViewHelper main_web_view;
  main_web_view.Initialize();

  // Create a remote window that will be closed later in the test.
  RemoteWindowCloseClient view_client;
  FrameTestHelpers::WebViewHelper popup;
  popup.InitializeRemote(nullptr, nullptr, &view_client);
  popup.RemoteMainFrame()->SetOpener(main_web_view.LocalMainFrame());

  LocalFrame* local_frame = main_web_view.LocalMainFrame()->GetFrame();
  RemoteFrame* remote_frame = popup.RemoteMainFrame()->GetFrame();

  // Attempt to close the window, which should fail as it isn't opened
  // by a script.
  remote_frame->DomWindow()->close(local_frame->DomWindow());
  EXPECT_FALSE(view_client.Closed());

  // Marking it as opened by a script should now allow it to be closed.
  remote_frame->GetPage()->SetOpenedByDOM();
  remote_frame->DomWindow()->close(local_frame->DomWindow());
  EXPECT_TRUE(view_client.Closed());
}

TEST_P(ParameterizedWebFrameTest, NavigateRemoteToLocalWithOpener) {
  FrameTestHelpers::WebViewHelper main_web_view;
  main_web_view.Initialize();
  WebLocalFrame* main_frame = main_web_view.LocalMainFrame();

  // Create a popup with a remote frame and set its opener to the main frame.
  FrameTestHelpers::WebViewHelper popup_helper;
  popup_helper.InitializeRemote(
      nullptr, SecurityOrigin::CreateFromString("http://foo.com"));
  WebRemoteFrame* popup_remote_frame = popup_helper.RemoteMainFrame();
  popup_remote_frame->SetOpener(main_frame);
  EXPECT_FALSE(main_frame->GetSecurityOrigin().CanAccess(
      popup_remote_frame->GetSecurityOrigin()));

  // Do a remote-to-local swap in the popup.
  WebLocalFrame* popup_local_frame =
      FrameTestHelpers::CreateProvisional(*popup_remote_frame);
  popup_remote_frame->Swap(popup_local_frame);

  // The initial document created during the remote-to-local swap should have
  // inherited its opener's SecurityOrigin.
  EXPECT_TRUE(main_frame->GetSecurityOrigin().CanAccess(
      popup_helper.LocalMainFrame()->GetSecurityOrigin()));
}

TEST_P(ParameterizedWebFrameTest, SwapWithOpenerCycle) {
  // First, create a remote main frame with itself as the opener.
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebRemoteFrame* remote_frame = helper.RemoteMainFrame();
  helper.RemoteMainFrame()->SetOpener(remote_frame);

  // Now swap in a local frame. It shouldn't crash.
  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateProvisional(*remote_frame);
  remote_frame->Swap(local_frame);

  // And the opener cycle should still be preserved.
  EXPECT_EQ(local_frame, local_frame->Opener());
}

class CommitTypeWebFrameClient : public FrameTestHelpers::TestWebFrameClient {
 public:
  CommitTypeWebFrameClient() : history_commit_type_(kWebHistoryInertCommit) {}
  ~CommitTypeWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidCommitProvisionalLoad(const WebHistoryItem&,
                                WebHistoryCommitType history_commit_type,
                                WebGlobalObjectReusePolicy) override {
    history_commit_type_ = history_commit_type;
  }

  WebHistoryCommitType HistoryCommitType() const {
    return history_commit_type_;
  }

 private:
  WebHistoryCommitType history_commit_type_;
};

TEST_P(ParameterizedWebFrameTest, RemoteFrameInitialCommitType) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote(nullptr, SecurityOrigin::CreateFromString(
                                       WebString::FromUTF8(base_url_)));

  // If an iframe has a remote main frame, ensure the inital commit is correctly
  // identified as WebInitialCommitInChildFrame.
  CommitTypeWebFrameClient child_frame_client;
  WebLocalFrame* child_frame = FrameTestHelpers::CreateLocalChild(
      *helper.RemoteMainFrame(), "frameName", WebFrameOwnerProperties(),
      nullptr, &child_frame_client);
  RegisterMockedHttpURLLoad("foo.html");
  FrameTestHelpers::LoadFrame(child_frame, base_url_ + "foo.html");
  EXPECT_EQ(kWebInitialCommitInChildFrame,
            child_frame_client.HistoryCommitType());

  helper.Reset();
}

class GestureEventTestWebWidgetClient
    : public FrameTestHelpers::TestWebWidgetClient {
 public:
  GestureEventTestWebWidgetClient() : did_handle_gesture_event_(false) {}
  ~GestureEventTestWebWidgetClient() override = default;

  // FrameTestHelpers::TestWebWidgetClient:
  void DidHandleGestureEvent(const WebGestureEvent& event,
                             bool event_cancelled) override {
    did_handle_gesture_event_ = true;
  }
  bool DidHandleGestureEvent() const { return did_handle_gesture_event_; }

 private:
  bool did_handle_gesture_event_;
};

TEST_P(ParameterizedWebFrameTest, FrameWidgetTest) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();

  GestureEventTestWebWidgetClient child_widget_client;
  WebLocalFrame* child_frame = FrameTestHelpers::CreateLocalChild(
      *helper.RemoteMainFrame(), WebString(), WebFrameOwnerProperties(),
      nullptr, nullptr, &child_widget_client);

  helper.GetWebView()->Resize(WebSize(1000, 1000));

  WebGestureEvent event(WebInputEvent::kGestureTap, WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        kWebGestureDeviceTouchscreen);
  event.SetPositionInWidget(WebFloatPoint(20, 20));
  child_frame->FrameWidget()->HandleInputEvent(WebCoalescedInputEvent(event));
  EXPECT_TRUE(child_widget_client.DidHandleGestureEvent());

  helper.Reset();
}

class MockDocumentThreadableLoaderClient
    : public DocumentThreadableLoaderClient {
 public:
  MockDocumentThreadableLoaderClient() : failed_(false) {}
  ~MockDocumentThreadableLoaderClient() override = default;

  // DocumentThreadableLoaderClient:
  void DidFail(const ResourceError&) override { failed_ = true; }

  void Reset() { failed_ = false; }
  bool Failed() { return failed_; }

  bool failed_;
};

// FIXME: This would be better as a unittest on DocumentThreadableLoader but it
// requires spin-up of a frame. It may be possible to remove that requirement
// and convert it to a unittest.
TEST_P(ParameterizedWebFrameTest, LoaderOriginAccess) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");

  SchemeRegistry::RegisterURLSchemeAsDisplayIsolated("chrome");

  // Cross-origin request.
  KURL resource_url("chrome://test.pdf");
  ResourceRequest request(resource_url);
  request.SetRequestContext(WebURLRequest::kRequestContextObject);
  request.SetFetchCredentialsMode(network::mojom::FetchCredentialsMode::kOmit);
  RegisterMockedChromeURLLoad("test.pdf");

  LocalFrame* frame(
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame()));

  MockDocumentThreadableLoaderClient client;
  ThreadableLoaderOptions options;

  // First try to load the request with regular access. Should fail.
  request.SetFetchRequestMode(network::mojom::FetchRequestMode::kCORS);
  ResourceLoaderOptions resource_loader_options;
  DocumentThreadableLoader::LoadResourceSynchronously(
      *ThreadableLoadingContext::Create(*frame->GetDocument()), request, client,
      options, resource_loader_options);
  EXPECT_TRUE(client.Failed());

  client.Reset();
  // Try to load the request with cross origin access. Should succeed.
  request.SetFetchRequestMode(network::mojom::FetchRequestMode::kNoCORS);
  DocumentThreadableLoader::LoadResourceSynchronously(
      *ThreadableLoadingContext::Create(*frame->GetDocument()), request, client,
      options, resource_loader_options);
  EXPECT_FALSE(client.Failed());
}

TEST_P(ParameterizedWebFrameTest, DetachRemoteFrame) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebRemoteFrame* child_frame =
      FrameTestHelpers::CreateRemoteChild(*helper.RemoteMainFrame());
  child_frame->Detach();
}

class TestConsoleMessageWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestConsoleMessageWebFrameClient() = default;
  ~TestConsoleMessageWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidAddMessageToConsole(const WebConsoleMessage& message,
                              const WebString& source_name,
                              unsigned source_line,
                              const WebString& stack_trace) override {
    messages.push_back(message);
  }

  Vector<WebConsoleMessage> messages;
};

TEST_P(ParameterizedWebFrameTest, CrossDomainAccessErrorsUseCallingWindow) {
  RegisterMockedHttpURLLoad("hidden_frames.html");
  RegisterMockedChromeURLLoad("hello_world.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  TestConsoleMessageWebFrameClient web_frame_client;
  web_view_helper.InitializeAndLoad(base_url_ + "hidden_frames.html",
                                    &web_frame_client);

  // Create another window with a cross-origin page, and point its opener to
  // first window.
  FrameTestHelpers::WebViewHelper popup_web_view_helper;
  TestConsoleMessageWebFrameClient popup_web_frame_client;
  WebViewImpl* popup_view = popup_web_view_helper.InitializeAndLoad(
      chrome_url_ + "hello_world.html", &popup_web_frame_client);
  popup_view->MainFrame()->SetOpener(web_view_helper.GetWebView()->MainFrame());

  // Attempt a blocked navigation of an opener's subframe, and ensure that
  // the error shows up on the popup (calling) window's console, rather than
  // the target window.
  popup_view->MainFrameImpl()->ExecuteScript(WebScriptSource(
      "try { opener.frames[1].location.href='data:text/html,foo'; } catch (e) "
      "{}"));
  EXPECT_TRUE(web_frame_client.messages.IsEmpty());
  ASSERT_EQ(1u, popup_web_frame_client.messages.size());
  EXPECT_TRUE(std::string::npos !=
              popup_web_frame_client.messages[0].text.Utf8().find(
                  "Unsafe JavaScript attempt to initiate navigation"));

  // Try setting a cross-origin iframe element's source to a javascript: URL,
  // and check that this error is also printed on the calling window.
  popup_view->MainFrameImpl()->ExecuteScript(
      WebScriptSource("opener.document.querySelectorAll('iframe')[1].src='"
                      "javascript:alert()'"));
  EXPECT_TRUE(web_frame_client.messages.IsEmpty());
  ASSERT_EQ(2u, popup_web_frame_client.messages.size());
  EXPECT_TRUE(
      std::string::npos !=
      popup_web_frame_client.messages[1].text.Utf8().find("Blocked a frame"));

  // Manually reset to break WebViewHelpers' dependencies on the stack
  // allocated WebFrameClients.
  web_view_helper.Reset();
  popup_web_view_helper.Reset();
}

TEST_P(ParameterizedWebFrameTest, ResizeInvalidatesDeviceMediaQueries) {
  RegisterMockedHttpURLLoad("device_media_queries.html");
  FixedLayoutTestWebViewClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "device_media_queries.html",
                                    nullptr, &client, nullptr,
                                    ConfigureAndroid);
  LocalFrame* frame =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame());
  Element* element = frame->GetDocument()->getElementById("test");
  ASSERT_TRUE(element);

  client.screen_info_.rect = WebRect(0, 0, 700, 500);
  client.screen_info_.available_rect = client.screen_info_.rect;
  web_view_helper.Resize(WebSize(700, 500));
  EXPECT_EQ(300, element->OffsetWidth());
  EXPECT_EQ(300, element->OffsetHeight());

  client.screen_info_.rect = WebRect(0, 0, 710, 500);
  client.screen_info_.available_rect = client.screen_info_.rect;
  web_view_helper.Resize(WebSize(710, 500));
  EXPECT_EQ(400, element->OffsetWidth());
  EXPECT_EQ(300, element->OffsetHeight());

  client.screen_info_.rect = WebRect(0, 0, 690, 500);
  client.screen_info_.available_rect = client.screen_info_.rect;
  web_view_helper.Resize(WebSize(690, 500));
  EXPECT_EQ(200, element->OffsetWidth());
  EXPECT_EQ(300, element->OffsetHeight());

  client.screen_info_.rect = WebRect(0, 0, 700, 510);
  client.screen_info_.available_rect = client.screen_info_.rect;
  web_view_helper.Resize(WebSize(700, 510));
  EXPECT_EQ(300, element->OffsetWidth());
  EXPECT_EQ(400, element->OffsetHeight());

  client.screen_info_.rect = WebRect(0, 0, 700, 490);
  client.screen_info_.available_rect = client.screen_info_.rect;
  web_view_helper.Resize(WebSize(700, 490));
  EXPECT_EQ(300, element->OffsetWidth());
  EXPECT_EQ(200, element->OffsetHeight());

  client.screen_info_.rect = WebRect(0, 0, 690, 510);
  client.screen_info_.available_rect = client.screen_info_.rect;
  web_view_helper.Resize(WebSize(690, 510));
  EXPECT_EQ(200, element->OffsetWidth());
  EXPECT_EQ(400, element->OffsetHeight());
}

class DeviceEmulationTest : public ParameterizedWebFrameTest {
 protected:
  DeviceEmulationTest() {
    RegisterMockedHttpURLLoad("device_emulation.html");
    client_.screen_info_.device_scale_factor = 1;
    web_view_helper_.InitializeAndLoad(base_url_ + "device_emulation.html",
                                       nullptr, &client_);
  }

  void TestResize(const WebSize size, const String& expected_size) {
    client_.screen_info_.rect = WebRect(0, 0, size.width, size.height);
    client_.screen_info_.available_rect = client_.screen_info_.rect;
    web_view_helper_.Resize(size);
    EXPECT_EQ(expected_size, DumpSize("test"));
  }

  String DumpSize(const String& id) {
    String code = "dumpSize('" + id + "')";
    v8::HandleScope scope(v8::Isolate::GetCurrent());
    ScriptExecutionCallbackHelper callback_helper(
        web_view_helper_.LocalMainFrame()->MainWorldScriptContext());
    web_view_helper_.GetWebView()
        ->MainFrameImpl()
        ->RequestExecuteScriptAndReturnValue(WebScriptSource(WebString(code)),
                                             false, &callback_helper);
    RunPendingTasks();
    EXPECT_TRUE(callback_helper.DidComplete());
    return callback_helper.StringValue();
  }

  FixedLayoutTestWebViewClient client_;
  FrameTestHelpers::WebViewHelper web_view_helper_;
};

INSTANTIATE_TEST_CASE_P(All, DeviceEmulationTest, testing::Bool());

TEST_P(DeviceEmulationTest, DeviceSizeInvalidatedOnResize) {
  WebDeviceEmulationParams params;
  params.screen_position = WebDeviceEmulationParams::kMobile;
  web_view_helper_.GetWebView()->EnableDeviceEmulation(params);

  TestResize(WebSize(700, 500), "300x300");
  TestResize(WebSize(710, 500), "400x300");
  TestResize(WebSize(690, 500), "200x300");
  TestResize(WebSize(700, 510), "300x400");
  TestResize(WebSize(700, 490), "300x200");
  TestResize(WebSize(710, 510), "400x400");
  TestResize(WebSize(690, 490), "200x200");
  TestResize(WebSize(800, 600), "400x400");

  web_view_helper_.GetWebView()->DisableDeviceEmulation();
}

TEST_P(DeviceEmulationTest, PointerAndHoverTypes) {
  web_view_helper_.GetWebView()
      ->GetDevToolsEmulator()
      ->SetTouchEventEmulationEnabled(true, 1);
  EXPECT_EQ("20x20", DumpSize("pointer"));
  web_view_helper_.GetWebView()
      ->GetDevToolsEmulator()
      ->SetTouchEventEmulationEnabled(false, 1);
}

TEST_P(ParameterizedWebFrameTest, CreateLocalChildWithPreviousSibling) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebRemoteFrame* parent = helper.RemoteMainFrame();

  WebLocalFrame* second_frame(
      FrameTestHelpers::CreateLocalChild(*parent, "name2"));
  WebLocalFrame* fourth_frame(FrameTestHelpers::CreateLocalChild(
      *parent, "name4", WebFrameOwnerProperties(), second_frame));
  WebLocalFrame* third_frame(FrameTestHelpers::CreateLocalChild(
      *parent, "name3", WebFrameOwnerProperties(), second_frame));
  WebLocalFrame* first_frame(
      FrameTestHelpers::CreateLocalChild(*parent, "name1"));

  EXPECT_EQ(first_frame, parent->FirstChild());
  EXPECT_EQ(nullptr, PreviousSibling(first_frame));
  EXPECT_EQ(second_frame, first_frame->NextSibling());

  EXPECT_EQ(first_frame, PreviousSibling(second_frame));
  EXPECT_EQ(third_frame, second_frame->NextSibling());

  EXPECT_EQ(second_frame, PreviousSibling(third_frame));
  EXPECT_EQ(fourth_frame, third_frame->NextSibling());

  EXPECT_EQ(third_frame, PreviousSibling(fourth_frame));
  EXPECT_EQ(nullptr, fourth_frame->NextSibling());
  EXPECT_EQ(fourth_frame, LastChild(parent));

  EXPECT_EQ(parent, first_frame->Parent());
  EXPECT_EQ(parent, second_frame->Parent());
  EXPECT_EQ(parent, third_frame->Parent());
  EXPECT_EQ(parent, fourth_frame->Parent());
}

TEST_P(ParameterizedWebFrameTest, SendBeaconFromChildWithRemoteMainFrame) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateLocalChild(*helper.RemoteMainFrame());

  // Finally, make sure an embedder triggered load in the local frame swapped
  // back in works.
  RegisterMockedHttpURLLoad("send_beacon.html");
  RegisterMockedHttpURLLoad("reload_post.html");  // url param to sendBeacon()
  FrameTestHelpers::LoadFrame(local_frame, base_url_ + "send_beacon.html");
}

TEST_P(ParameterizedWebFrameTest, SiteForCookiesFromChildWithRemoteMainFrame) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote(nullptr,
                          SecurityOrigin::Create(ToKURL(not_base_url_)));

  WebLocalFrame* local_frame =
      FrameTestHelpers::CreateLocalChild(*helper.RemoteMainFrame());

  RegisterMockedHttpURLLoad("foo.html");
  FrameTestHelpers::LoadFrame(local_frame, base_url_ + "foo.html");
  EXPECT_EQ(WebURL(SecurityOrigin::UrlWithUniqueSecurityOrigin()),
            local_frame->GetDocument().SiteForCookies());

  SchemeRegistry::RegisterURLSchemeAsFirstPartyWhenTopLevel("http");
  EXPECT_EQ(WebURL(ToKURL(not_base_url_)),
            local_frame->GetDocument().SiteForCookies());
  SchemeRegistry::RemoveURLSchemeAsFirstPartyWhenTopLevel("http");
}

// See https://crbug.com/525285.
TEST_P(ParameterizedWebFrameTest,
       RemoteToLocalSwapOnMainFrameInitializesCoreFrame) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();

  FrameTestHelpers::CreateLocalChild(*helper.RemoteMainFrame());

  // Do a remote-to-local swap of the top frame.
  WebLocalFrame* local_root =
      FrameTestHelpers::CreateProvisional(*helper.RemoteMainFrame());
  helper.RemoteMainFrame()->Swap(local_root);

  // Load a page with a child frame in the new root to make sure this doesn't
  // crash when the child frame invokes setCoreFrame.
  RegisterMockedHttpURLLoad("single_iframe.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");
  FrameTestHelpers::LoadFrame(local_root, base_url_ + "single_iframe.html");
}

// See https://crbug.com/628942.
TEST_P(ParameterizedWebFrameTest, PausedPageLoadWithRemoteMainFrame) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebRemoteFrameImpl* remote_root = helper.RemoteMainFrame();

  // Check that ScopedPagePauser properly triggers deferred loading for
  // the current Page.
  Page* page = remote_root->GetFrame()->GetPage();
  EXPECT_FALSE(page->Paused());
  {
    ScopedPagePauser pauser;
    EXPECT_TRUE(page->Paused());
  }
  EXPECT_FALSE(page->Paused());

  // Repeat this for a page with a local child frame, and ensure that the
  // child frame's loads are also suspended.
  WebLocalFrameImpl* web_local_child =
      FrameTestHelpers::CreateLocalChild(*remote_root);
  RegisterMockedHttpURLLoad("foo.html");
  FrameTestHelpers::LoadFrame(web_local_child, base_url_ + "foo.html");
  LocalFrame* local_child = web_local_child->GetFrame();
  EXPECT_FALSE(page->Paused());
  EXPECT_FALSE(
      local_child->GetDocument()->Fetcher()->Context().DefersLoading());
  {
    ScopedPagePauser pauser;
    EXPECT_TRUE(page->Paused());
    EXPECT_TRUE(
        local_child->GetDocument()->Fetcher()->Context().DefersLoading());
  }
  EXPECT_FALSE(page->Paused());
  EXPECT_FALSE(
      local_child->GetDocument()->Fetcher()->Context().DefersLoading());
}

class OverscrollWebViewClient : public FrameTestHelpers::TestWebViewClient {
 public:
  MOCK_METHOD5(DidOverscroll,
               void(const WebFloatSize&,
                    const WebFloatSize&,
                    const WebFloatPoint&,
                    const WebFloatSize&,
                    const WebOverscrollBehavior&));
};

typedef std::pair<bool, blink::WebGestureDevice> WebFrameOverscrollTestParam;
class WebFrameOverscrollTest
    : public WebFrameTest,
      public testing::WithParamInterface<WebFrameOverscrollTestParam>,
      private ScopedRootLayerScrollingForTest {
 public:
  WebFrameOverscrollTest()
      : ScopedRootLayerScrollingForTest(GetParam().first) {}

 protected:
  WebCoalescedInputEvent GenerateEvent(WebInputEvent::Type type,
                                       float delta_x = 0.0,
                                       float delta_y = 0.0) {
    WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests(),
                          GetParam().second);
    // TODO(wjmaclean): Make sure that touchpad device is only ever used for
    // gesture scrolling event types.
    event.SetPositionInWidget(WebFloatPoint(100, 100));
    if (type == WebInputEvent::kGestureScrollUpdate) {
      event.data.scroll_update.delta_x = delta_x;
      event.data.scroll_update.delta_y = delta_y;
    } else if (type == WebInputEvent::kGestureScrollBegin) {
      event.data.scroll_begin.delta_x_hint = delta_x;
      event.data.scroll_begin.delta_y_hint = delta_y;
    }
    return WebCoalescedInputEvent(event);
  }

  void ScrollBegin(FrameTestHelpers::WebViewHelper* web_view_helper,
                   float delta_x_hint,
                   float delta_y_hint) {
    web_view_helper->GetWebView()->HandleInputEvent(GenerateEvent(
        WebInputEvent::kGestureScrollBegin, delta_x_hint, delta_y_hint));
  }

  void ScrollUpdate(FrameTestHelpers::WebViewHelper* web_view_helper,
                    float delta_x,
                    float delta_y) {
    web_view_helper->GetWebView()->HandleInputEvent(
        GenerateEvent(WebInputEvent::kGestureScrollUpdate, delta_x, delta_y));
  }

  void ScrollEnd(FrameTestHelpers::WebViewHelper* web_view_helper) {
    web_view_helper->GetWebView()->HandleInputEvent(
        GenerateEvent(WebInputEvent::kGestureScrollEnd));
  }
};

// First parameter in each value pair controls RootLayerScrolling.
INSTANTIATE_TEST_CASE_P(
    All,
    WebFrameOverscrollTest,
    testing::Values(
        WebFrameOverscrollTestParam(false, kWebGestureDeviceTouchpad),
        WebFrameOverscrollTestParam(false, kWebGestureDeviceTouchscreen),
        WebFrameOverscrollTestParam(true, kWebGestureDeviceTouchpad),
        WebFrameOverscrollTestParam(true, kWebGestureDeviceTouchscreen)));

TEST_P(WebFrameOverscrollTest,
       AccumulatedRootOverscrollAndUnsedDeltaValuesOnOverscroll) {
  OverscrollWebViewClient client;
  RegisterMockedHttpURLLoad("overscroll/overscroll.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "overscroll/overscroll.html",
                                    nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.Resize(WebSize(200, 200));

  // Calculation of accumulatedRootOverscroll and unusedDelta on multiple
  // scrollUpdate.
  ScrollBegin(&web_view_helper, -300, -316);
  EXPECT_CALL(client, DidOverscroll(WebFloatSize(8, 16), WebFloatSize(8, 16),
                                    WebFloatPoint(100, 100), WebFloatSize(),
                                    WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, -308, -316);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(WebFloatSize(0, 13), WebFloatSize(8, 29),
                                    WebFloatPoint(100, 100), WebFloatSize(),
                                    WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 0, -13);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(WebFloatSize(20, 13), WebFloatSize(28, 42),
                                    WebFloatPoint(100, 100), WebFloatSize(),
                                    WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, -20, -13);
  Mock::VerifyAndClearExpectations(&client);

  // Overscroll is not reported.
  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, 0, 1);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, 1, 0);
  Mock::VerifyAndClearExpectations(&client);

  // Overscroll is reported.
  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(0, -701), WebFloatSize(0, -701),
                            WebFloatPoint(100, 100), WebFloatSize(),
                            WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 0, 1000);
  Mock::VerifyAndClearExpectations(&client);

  // Overscroll is not reported.
  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollEnd(&web_view_helper);
  Mock::VerifyAndClearExpectations(&client);
}

TEST_P(WebFrameOverscrollTest,
       AccumulatedOverscrollAndUnusedDeltaValuesOnDifferentAxesOverscroll) {
  OverscrollWebViewClient client;
  RegisterMockedHttpURLLoad("overscroll/div-overscroll.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/div-overscroll.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(WebSize(200, 200));

  ScrollBegin(&web_view_helper, 0, -316);

  // Scroll the Div to the end.
  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, 0, -316);
  Mock::VerifyAndClearExpectations(&client);

  ScrollEnd(&web_view_helper);
  ScrollBegin(&web_view_helper, 0, -100);

  // Now On Scrolling DIV, scroll is bubbled and root layer is over-scrolled.
  EXPECT_CALL(client, DidOverscroll(WebFloatSize(0, 100), WebFloatSize(0, 100),
                                    WebFloatPoint(100, 100), WebFloatSize(),
                                    WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 0, -100);
  ScrollUpdate(&web_view_helper, 0, -100);
  Mock::VerifyAndClearExpectations(&client);

  // TODO(bokan): This has never worked but by the accident that this test was
  // being run in a WebView without a size. This test should be fixed along with
  // the bug, crbug.com/589320.
  // Page scrolls vertically, but over-scrolls horizontally.
  // EXPECT_CALL(client, didOverscroll(WebFloatSize(-100, 0), WebFloatSize(-100,
  // 0), WebFloatPoint(100, 100), WebFloatSize(), WebOverscrollBehavior()));
  // ScrollUpdate(&webViewHelper, 100, 50);
  // Mock::VerifyAndClearExpectations(&client);

  // Scrolling up, Overscroll is not reported.
  // EXPECT_CALL(client, didOverscroll(_, _, _, _, _)).Times(0);
  // ScrollUpdate(&webViewHelper, 0, -50);
  // Mock::VerifyAndClearExpectations(&client);

  // Page scrolls horizontally, but over-scrolls vertically.
  // EXPECT_CALL(client, didOverscroll(WebFloatSize(0, 100), WebFloatSize(0,
  // 100), WebFloatPoint(100, 100), WebFloatSize(),
  // WebOverscrollBehavior()));
  // ScrollUpdate(&webViewHelper, -100, -100);
  // Mock::VerifyAndClearExpectations(&client);
}

TEST_P(WebFrameOverscrollTest, RootLayerOverscrolledOnInnerDivOverScroll) {
  OverscrollWebViewClient client;
  RegisterMockedHttpURLLoad("overscroll/div-overscroll.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/div-overscroll.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(WebSize(200, 200));

  ScrollBegin(&web_view_helper, 0, -316);

  // Scroll the Div to the end.
  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, 0, -316);
  Mock::VerifyAndClearExpectations(&client);

  ScrollEnd(&web_view_helper);
  ScrollBegin(&web_view_helper, 0, -150);

  // Now On Scrolling DIV, scroll is bubbled and root layer is over-scrolled.
  EXPECT_CALL(client, DidOverscroll(WebFloatSize(0, 50), WebFloatSize(0, 50),
                                    WebFloatPoint(100, 100), WebFloatSize(),
                                    WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 0, -150);
  Mock::VerifyAndClearExpectations(&client);
}

TEST_P(WebFrameOverscrollTest, RootLayerOverscrolledOnInnerIFrameOverScroll) {
  OverscrollWebViewClient client;
  RegisterMockedHttpURLLoad("overscroll/iframe-overscroll.html");
  RegisterMockedHttpURLLoad("overscroll/scrollable-iframe.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/iframe-overscroll.html", nullptr, &client,
      nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(200, 200));

  ScrollBegin(&web_view_helper, 0, -320);
  // Scroll the IFrame to the end.
  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);

  // This scroll will fully scroll the iframe but will be consumed before being
  // counted as overscroll.
  ScrollUpdate(&web_view_helper, 0, -320);

  // This scroll will again target the iframe but wont bubble further up. Make
  // sure that the unused scroll isn't handled as overscroll.
  ScrollUpdate(&web_view_helper, 0, -50);
  Mock::VerifyAndClearExpectations(&client);

  ScrollEnd(&web_view_helper);
  ScrollBegin(&web_view_helper, 0, -150);

  // Now On Scrolling IFrame, scroll is bubbled and root layer is over-scrolled.
  EXPECT_CALL(client, DidOverscroll(WebFloatSize(0, 50), WebFloatSize(0, 50),
                                    WebFloatPoint(100, 100), WebFloatSize(),
                                    WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 0, -150);
  Mock::VerifyAndClearExpectations(&client);

  ScrollEnd(&web_view_helper);
}

TEST_P(WebFrameOverscrollTest, ScaledPageRootLayerOverscrolled) {
  OverscrollWebViewClient client;
  RegisterMockedHttpURLLoad("overscroll/overscroll.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/overscroll.html", nullptr, &client, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(WebSize(200, 200));
  web_view_impl->SetPageScaleFactor(3.0);

  // Calculation of accumulatedRootOverscroll and unusedDelta on scaled page.
  // The point is (99, 99) because we clamp in the division by 3 to 33 so when
  // we go back to viewport coordinates it becomes (99, 99).
  ScrollBegin(&web_view_helper, 0, 30);
  EXPECT_CALL(client, DidOverscroll(WebFloatSize(0, -30), WebFloatSize(0, -30),
                                    WebFloatPoint(99, 99), WebFloatSize(),
                                    WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 0, 30);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(WebFloatSize(0, -30), WebFloatSize(0, -60),
                                    WebFloatPoint(99, 99), WebFloatSize(),
                                    WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 0, 30);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(-30, -30), WebFloatSize(-30, -90),
                            WebFloatPoint(99, 99), WebFloatSize(),
                            WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 30, 30);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(-30, 0), WebFloatSize(-60, -90),
                            WebFloatPoint(99, 99), WebFloatSize(),
                            WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 30, 0);
  Mock::VerifyAndClearExpectations(&client);

  // Overscroll is not reported.
  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollEnd(&web_view_helper);
  Mock::VerifyAndClearExpectations(&client);
}

TEST_P(WebFrameOverscrollTest, NoOverscrollForSmallvalues) {
  OverscrollWebViewClient client;
  RegisterMockedHttpURLLoad("overscroll/overscroll.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "overscroll/overscroll.html",
                                    nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.Resize(WebSize(200, 200));

  ScrollBegin(&web_view_helper, 10, 10);
  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(-10, -10), WebFloatSize(-10, -10),
                            WebFloatPoint(100, 100), WebFloatSize(),
                            WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 10, 10);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(0, -0.10), WebFloatSize(-10, -10.10),
                            WebFloatPoint(100, 100), WebFloatSize(),
                            WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 0, 0.10);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(WebFloatSize(-0.10, 0),
                                    WebFloatSize(-10.10, -10.10),
                                    WebFloatPoint(100, 100), WebFloatSize(),
                                    WebOverscrollBehavior()));
  ScrollUpdate(&web_view_helper, 0.10, 0);
  Mock::VerifyAndClearExpectations(&client);

  // For residual values overscrollDelta should be reset and didOverscroll
  // shouldn't be called.
  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, 0, 0.09);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, 0.09, 0.09);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, 0.09, 0);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, 0, -0.09);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, -0.09, -0.09);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollUpdate(&web_view_helper, -0.09, 0);
  Mock::VerifyAndClearExpectations(&client);

  EXPECT_CALL(client, DidOverscroll(_, _, _, _, _)).Times(0);
  ScrollEnd(&web_view_helper);
  Mock::VerifyAndClearExpectations(&client);
}

TEST_P(WebFrameOverscrollTest, OverscrollBehaviorAffectsDidOverscroll) {
  OverscrollWebViewClient client;
  RegisterMockedHttpURLLoad("overscroll/overscroll.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "overscroll/overscroll.html",
                                    nullptr, &client, nullptr,
                                    ConfigureAndroid);
  web_view_helper.Resize(WebSize(200, 200));

  WebLocalFrame* mainFrame =
      web_view_helper.GetWebView()->MainFrame()->ToWebLocalFrame();
  mainFrame->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: auto;'")));

  ScrollBegin(&web_view_helper, 100, 116);
  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(-100, -100), WebFloatSize(-100, -100),
                            WebFloatPoint(100, 100), WebFloatSize(),
                            WebOverscrollBehavior(
                                WebOverscrollBehavior::OverscrollBehaviorType::
                                    kOverscrollBehaviorTypeAuto)));
  ScrollUpdate(&web_view_helper, 100, 100);
  Mock::VerifyAndClearExpectations(&client);

  mainFrame->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: contain;'")));

  ScrollBegin(&web_view_helper, 100, 116);
  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(-100, -100), WebFloatSize(-200, -200),
                            WebFloatPoint(100, 100), WebFloatSize(),
                            WebOverscrollBehavior(
                                WebOverscrollBehavior::OverscrollBehaviorType::
                                    kOverscrollBehaviorTypeContain)));
  ScrollUpdate(&web_view_helper, 100, 100);
  Mock::VerifyAndClearExpectations(&client);

  mainFrame->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: none;'")));

  ScrollBegin(&web_view_helper, 100, 116);
  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(-100, -100), WebFloatSize(-300, -300),
                            WebFloatPoint(100, 100), WebFloatSize(),
                            WebOverscrollBehavior(
                                WebOverscrollBehavior::OverscrollBehaviorType::
                                    kOverscrollBehaviorTypeNone)));
  ScrollUpdate(&web_view_helper, 100, 100);
  Mock::VerifyAndClearExpectations(&client);
}

TEST_P(WebFrameOverscrollTest, OnlyMainFrameOverscrollBehaviorHasEffect) {
  OverscrollWebViewClient client;
  RegisterMockedHttpURLLoad("overscroll/iframe-overscroll.html");
  RegisterMockedHttpURLLoad("overscroll/scrollable-iframe.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/iframe-overscroll.html", nullptr, &client,
      nullptr, ConfigureAndroid);
  web_view_helper.Resize(WebSize(200, 200));

  WebLocalFrame* mainFrame =
      web_view_helper.GetWebView()->MainFrame()->ToWebLocalFrame();
  mainFrame->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: auto;'")));
  WebLocalFrame* subframe = web_view_helper.GetWebView()
                                ->MainFrame()
                                ->FirstChild()
                                ->ToWebLocalFrame();
  subframe->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: none;'")));

  ScrollBegin(&web_view_helper, 100, 116);
  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(-100, -100), WebFloatSize(-100, -100),
                            WebFloatPoint(100, 100), WebFloatSize(),
                            WebOverscrollBehavior(
                                WebOverscrollBehavior::OverscrollBehaviorType::
                                    kOverscrollBehaviorTypeAuto)));
  ScrollUpdate(&web_view_helper, 100, 100);
  Mock::VerifyAndClearExpectations(&client);

  mainFrame->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: contain;'")));

  EXPECT_CALL(client,
              DidOverscroll(WebFloatSize(-100, -100), WebFloatSize(-200, -200),
                            WebFloatPoint(100, 100), WebFloatSize(),
                            WebOverscrollBehavior(
                                WebOverscrollBehavior::OverscrollBehaviorType::
                                    kOverscrollBehaviorTypeContain)));
  ScrollUpdate(&web_view_helper, 100, 100);
  Mock::VerifyAndClearExpectations(&client);
}

TEST_P(ParameterizedWebFrameTest, OrientationFrameDetach) {
  ScopedOrientationEventForTest orientation_event(true);
  RegisterMockedHttpURLLoad("orientation-frame-detach.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "orientation-frame-detach.html");
  web_view_impl->MainFrameImpl()->SendOrientationChangeEvent();
}

// Macro is not correctly expanded in TEST_P (We cannot use
// TEST_P(ParameterizedWebFrameTest, MAYBE_MaxFramesDetach for example).
#if defined(THREAD_SANITIZER)
TEST_P(ParameterizedWebFrameTest, DISABLED_MaxFramesDetach) {
#else
TEST_P(ParameterizedWebFrameTest, MaxFramesDetach) {
#endif  // defined(THREAD_SANITIZER)
  RegisterMockedHttpURLLoad("max-frames-detach.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url_ + "max-frames-detach.html");
  web_view_impl->MainFrameImpl()->CollectGarbage();
}

TEST_P(ParameterizedWebFrameTest, ImageDocumentLoadFinishTime) {
  // Loading an image resource directly generates an ImageDocument with
  // the document loader feeding image data into the resource of a generated
  // img tag. We expect the load finish time to be the same for the document
  // and the image resource.

  RegisterMockedHttpURLLoadWithMimeType("white-1x1.png", "image/png");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "white-1x1.png");
  WebViewImpl* web_view = web_view_helper.GetWebView();
  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();

  EXPECT_TRUE(document);
  EXPECT_TRUE(document->IsImageDocument());

  ImageDocument* img_document = ToImageDocument(document);
  ImageResource* resource = img_document->CachedImageResourceDeprecated();

  EXPECT_TRUE(resource);
  EXPECT_NE(0, resource->LoadFinishTime());

  DocumentLoader* loader = document->Loader();

  EXPECT_TRUE(loader);
  EXPECT_EQ(TimeTicksInSeconds(loader->GetTiming().ResponseEnd()),
            resource->LoadFinishTime());
}

class CallbackOrderingWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  CallbackOrderingWebFrameClient() : callback_count_(0) {}
  ~CallbackOrderingWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void DidStartLoading(bool to_different_document) override {
    EXPECT_EQ(0, callback_count_++);
    FrameTestHelpers::TestWebFrameClient::DidStartLoading(
        to_different_document);
  }
  void DidStartProvisionalLoad(WebDocumentLoader*, WebURLRequest&) override {
    EXPECT_EQ(1, callback_count_++);
  }
  void DidCommitProvisionalLoad(const WebHistoryItem&,
                                WebHistoryCommitType,
                                WebGlobalObjectReusePolicy) override {
    EXPECT_EQ(2, callback_count_++);
  }
  void DidFinishDocumentLoad() override { EXPECT_EQ(3, callback_count_++); }
  void DidHandleOnloadEvents() override { EXPECT_EQ(4, callback_count_++); }
  void DidFinishLoad() override { EXPECT_EQ(5, callback_count_++); }
  void DidStopLoading() override {
    EXPECT_EQ(6, callback_count_++);
    FrameTestHelpers::TestWebFrameClient::DidStopLoading();
  }

 private:
  int callback_count_;
};

TEST_P(ParameterizedWebFrameTest, CallbackOrdering) {
  RegisterMockedHttpURLLoad("foo.html");
  CallbackOrderingWebFrameClient client;
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html", &client);
}

class TestWebRemoteFrameClientForVisibility
    : public FrameTestHelpers::TestWebRemoteFrameClient {
 public:
  TestWebRemoteFrameClientForVisibility() : visible_(true) {}
  ~TestWebRemoteFrameClientForVisibility() override = default;

  // FrameTestHelpers::TestWebRemoteFrameClient:
  void VisibilityChanged(bool visible) override { visible_ = visible; }

  bool IsVisible() const { return visible_; }

 private:
  bool visible_;
};

class WebFrameVisibilityChangeTest : public ParameterizedWebFrameTest {
 public:
  WebFrameVisibilityChangeTest() {
    RegisterMockedHttpURLLoad("visible_iframe.html");
    RegisterMockedHttpURLLoad("single_iframe.html");
    frame_ =
        web_view_helper_.InitializeAndLoad(base_url_ + "single_iframe.html")
            ->MainFrameImpl();
    web_remote_frame_ = FrameTestHelpers::CreateRemote(&remote_frame_client_);
  }

  ~WebFrameVisibilityChangeTest() = default;

  void ExecuteScriptOnMainFrame(const WebScriptSource& script) {
    MainFrame()->ExecuteScript(script);
    MainFrame()->View()->UpdateAllLifecyclePhases();
    RunPendingTasks();
  }

  void SwapLocalFrameToRemoteFrame() {
    LastChild(MainFrame())->Swap(RemoteFrame());
  }

  WebLocalFrame* MainFrame() { return frame_; }
  WebRemoteFrameImpl* RemoteFrame() { return web_remote_frame_; }
  TestWebRemoteFrameClientForVisibility* RemoteFrameClient() {
    return &remote_frame_client_;
  }

 private:
  TestWebRemoteFrameClientForVisibility remote_frame_client_;
  FrameTestHelpers::WebViewHelper web_view_helper_;
  WebLocalFrame* frame_;
  Persistent<WebRemoteFrameImpl> web_remote_frame_;
};

INSTANTIATE_TEST_CASE_P(All, WebFrameVisibilityChangeTest, testing::Bool());

TEST_P(WebFrameVisibilityChangeTest, RemoteFrameVisibilityChange) {
  SwapLocalFrameToRemoteFrame();
  ExecuteScriptOnMainFrame(WebScriptSource(
      "document.querySelector('iframe').style.display = 'none';"));
  EXPECT_FALSE(RemoteFrameClient()->IsVisible());

  ExecuteScriptOnMainFrame(WebScriptSource(
      "document.querySelector('iframe').style.display = 'block';"));
  EXPECT_TRUE(RemoteFrameClient()->IsVisible());
}

TEST_P(WebFrameVisibilityChangeTest, RemoteFrameParentVisibilityChange) {
  SwapLocalFrameToRemoteFrame();
  ExecuteScriptOnMainFrame(
      WebScriptSource("document.querySelector('iframe').parentElement.style."
                      "display = 'none';"));
  EXPECT_FALSE(RemoteFrameClient()->IsVisible());
}

static void EnableGlobalReuseForUnownedMainFrames(WebSettings* settings) {
  settings->SetShouldReuseGlobalForUnownedMainFrame(true);
}

// A main frame with no opener should have a unique security origin. Thus, the
// global should never be reused on the initial navigation.
TEST(WebFrameGlobalReuseTest, MainFrameWithNoOpener) {
  FrameTestHelpers::WebViewHelper helper;
  helper.Initialize();

  WebLocalFrame* main_frame = helper.LocalMainFrame();
  v8::HandleScope scope(v8::Isolate::GetCurrent());
  main_frame->ExecuteScript(WebScriptSource("hello = 'world';"));
  FrameTestHelpers::LoadFrame(main_frame, "data:text/html,new page");
  v8::Local<v8::Value> result =
      main_frame->ExecuteScriptAndReturnValue(WebScriptSource("hello"));
  EXPECT_TRUE(result.IsEmpty());
}

// Child frames should never reuse the global on a cross-origin navigation, even
// if the setting is enabled. It's not safe to since the parent could have
// injected script before the initial navigation.
TEST(WebFrameGlobalReuseTest, ChildFrame) {
  FrameTestHelpers::WebViewHelper helper;
  helper.Initialize(nullptr, nullptr, nullptr,
                    EnableGlobalReuseForUnownedMainFrames);

  WebLocalFrame* main_frame = helper.LocalMainFrame();
  FrameTestHelpers::LoadFrame(main_frame, "data:text/html,<iframe></iframe>");

  WebLocalFrame* child_frame = main_frame->FirstChild()->ToWebLocalFrame();
  v8::HandleScope scope(v8::Isolate::GetCurrent());
  child_frame->ExecuteScript(WebScriptSource("hello = 'world';"));
  FrameTestHelpers::LoadFrame(child_frame, "data:text/html,new page");
  v8::Local<v8::Value> result =
      child_frame->ExecuteScriptAndReturnValue(WebScriptSource("hello"));
  EXPECT_TRUE(result.IsEmpty());
}

// A main frame with an opener should never reuse the global on a cross-origin
// navigation, even if the setting is enabled. It's not safe to since the opener
// could have injected script.
TEST(WebFrameGlobalReuseTest, MainFrameWithOpener) {
  FrameTestHelpers::WebViewHelper opener_helper;
  opener_helper.Initialize();
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeWithOpener(opener_helper.GetWebView()->MainFrame(), nullptr,
                              nullptr, nullptr,
                              EnableGlobalReuseForUnownedMainFrames);

  WebLocalFrame* main_frame = helper.LocalMainFrame();
  v8::HandleScope scope(v8::Isolate::GetCurrent());
  main_frame->ExecuteScript(WebScriptSource("hello = 'world';"));
  FrameTestHelpers::LoadFrame(main_frame, "data:text/html,new page");
  v8::Local<v8::Value> result =
      main_frame->ExecuteScriptAndReturnValue(WebScriptSource("hello"));
  EXPECT_TRUE(result.IsEmpty());
}

// A main frame that is unrelated to any other frame /can/ reuse the global if
// the setting is enabled. In this case, it's impossible for any other frames to
// have touched the global. Only the embedder could have injected script, and
// the embedder enabling this setting is a signal that the injected script needs
// to persist on the first navigation away from the initial empty document.
TEST(WebFrameGlobalReuseTest, ReuseForMainFrameIfEnabled) {
  FrameTestHelpers::WebViewHelper helper;
  helper.Initialize(nullptr, nullptr, nullptr,
                    EnableGlobalReuseForUnownedMainFrames);

  WebLocalFrame* main_frame = helper.LocalMainFrame();
  v8::HandleScope scope(v8::Isolate::GetCurrent());
  main_frame->ExecuteScript(WebScriptSource("hello = 'world';"));
  FrameTestHelpers::LoadFrame(main_frame, "data:text/html,new page");
  v8::Local<v8::Value> result =
      main_frame->ExecuteScriptAndReturnValue(WebScriptSource("hello"));
  ASSERT_TRUE(result->IsString());
  EXPECT_EQ("world",
            ToCoreString(result->ToString(main_frame->MainWorldScriptContext())
                             .ToLocalChecked()));
}

class SaveImageFromDataURLWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  SaveImageFromDataURLWebFrameClient() = default;
  ~SaveImageFromDataURLWebFrameClient() override = default;

  // WebFrameClient:
  void SaveImageFromDataURL(const WebString& data_url) override {
    data_url_ = data_url;
  }

  // Local methods
  const WebString& Result() const { return data_url_; }
  void Reset() { data_url_ = WebString(); }

 private:
  WebString data_url_;
};

TEST_P(ParameterizedWebFrameTest, SaveImageAt) {
  std::string url = base_url_ + "image-with-data-url.html";
  RegisterMockedURLLoadFromBase(base_url_, "image-with-data-url.html");
  URLTestHelpers::RegisterMockedURLLoad(
      ToKURL("http://test"), test::CoreTestDataPath("white-1x1.png"));

  FrameTestHelpers::WebViewHelper helper;
  SaveImageFromDataURLWebFrameClient client;
  WebViewImpl* web_view = helper.InitializeAndLoad(url, &client);
  web_view->Resize(WebSize(400, 400));
  web_view->UpdateAllLifecyclePhases();

  WebLocalFrame* local_frame = web_view->MainFrameImpl();

  client.Reset();
  local_frame->SaveImageAt(WebPoint(1, 1));
  EXPECT_EQ(
      WebString::FromUTF8("data:image/gif;base64"
                          ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      client.Result());

  client.Reset();
  local_frame->SaveImageAt(WebPoint(1, 2));
  EXPECT_EQ(WebString(), client.Result());

  web_view->SetPageScaleFactor(4);
  web_view->SetVisualViewportOffset(WebFloatPoint(1, 1));

  client.Reset();
  local_frame->SaveImageAt(WebPoint(3, 3));
  EXPECT_EQ(
      WebString::FromUTF8("data:image/gif;base64"
                          ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      client.Result());

  // Explicitly reset to break dependency on locally scoped client.
  helper.Reset();
}

TEST_P(ParameterizedWebFrameTest, SaveImageWithImageMap) {
  std::string url = base_url_ + "image-map.html";
  RegisterMockedURLLoadFromBase(base_url_, "image-map.html");

  FrameTestHelpers::WebViewHelper helper;
  SaveImageFromDataURLWebFrameClient client;
  WebViewImpl* web_view = helper.InitializeAndLoad(url, &client);
  web_view->Resize(WebSize(400, 400));

  WebLocalFrame* local_frame = web_view->MainFrameImpl();

  client.Reset();
  local_frame->SaveImageAt(WebPoint(25, 25));
  EXPECT_EQ(
      WebString::FromUTF8("data:image/gif;base64"
                          ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      client.Result());

  client.Reset();
  local_frame->SaveImageAt(WebPoint(75, 25));
  EXPECT_EQ(
      WebString::FromUTF8("data:image/gif;base64"
                          ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      client.Result());

  client.Reset();
  local_frame->SaveImageAt(WebPoint(125, 25));
  EXPECT_EQ(WebString(), client.Result());

  // Explicitly reset to break dependency on locally scoped client.
  helper.Reset();
}

TEST_P(ParameterizedWebFrameTest, CopyImageAt) {
  std::string url = base_url_ + "canvas-copy-image.html";
  RegisterMockedURLLoadFromBase(base_url_, "canvas-copy-image.html");

  FrameTestHelpers::WebViewHelper helper;
  WebViewImpl* web_view = helper.InitializeAndLoad(url);
  web_view->Resize(WebSize(400, 400));

  uint64_t sequence = Platform::Current()->Clipboard()->SequenceNumber(
      mojom::ClipboardBuffer::kStandard);

  WebLocalFrame* local_frame = web_view->MainFrameImpl();
  local_frame->CopyImageAt(WebPoint(50, 50));

  EXPECT_NE(sequence, Platform::Current()->Clipboard()->SequenceNumber(
                          mojom::ClipboardBuffer::kStandard));

  WebImage image =
      static_cast<WebMockClipboard*>(Platform::Current()->Clipboard())
          ->ReadRawImage(mojom::ClipboardBuffer::kStandard);

  EXPECT_EQ(SkColorSetARGB(255, 255, 0, 0), image.GetSkBitmap().getColor(0, 0));
}

TEST_P(ParameterizedWebFrameTest, CopyImageAtWithPinchZoom) {
  std::string url = base_url_ + "canvas-copy-image.html";
  RegisterMockedURLLoadFromBase(base_url_, "canvas-copy-image.html");

  FrameTestHelpers::WebViewHelper helper;
  WebViewImpl* web_view = helper.InitializeAndLoad(url);
  web_view->Resize(WebSize(400, 400));
  web_view->UpdateAllLifecyclePhases();
  web_view->SetPageScaleFactor(2);
  web_view->SetVisualViewportOffset(WebFloatPoint(200, 200));

  uint64_t sequence = Platform::Current()->Clipboard()->SequenceNumber(
      mojom::ClipboardBuffer::kStandard);

  WebLocalFrame* local_frame = web_view->MainFrameImpl();
  local_frame->CopyImageAt(WebPoint(0, 0));

  EXPECT_NE(sequence, Platform::Current()->Clipboard()->SequenceNumber(
                          mojom::ClipboardBuffer::kStandard));

  WebImage image =
      static_cast<WebMockClipboard*>(Platform::Current()->Clipboard())
          ->ReadRawImage(mojom::ClipboardBuffer::kStandard);

  EXPECT_EQ(SkColorSetARGB(255, 255, 0, 0), image.GetSkBitmap().getColor(0, 0));
}

TEST_P(ParameterizedWebFrameTest, CopyImageWithImageMap) {
  SaveImageFromDataURLWebFrameClient client;

  std::string url = base_url_ + "image-map.html";
  RegisterMockedURLLoadFromBase(base_url_, "image-map.html");

  FrameTestHelpers::WebViewHelper helper;
  WebViewImpl* web_view = helper.InitializeAndLoad(url, &client);
  web_view->Resize(WebSize(400, 400));

  client.Reset();
  WebLocalFrame* local_frame = web_view->MainFrameImpl();
  local_frame->SaveImageAt(WebPoint(25, 25));
  EXPECT_EQ(
      WebString::FromUTF8("data:image/gif;base64"
                          ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      client.Result());

  client.Reset();
  local_frame->SaveImageAt(WebPoint(75, 25));
  EXPECT_EQ(
      WebString::FromUTF8("data:image/gif;base64"
                          ",R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs="),
      client.Result());

  client.Reset();
  local_frame->SaveImageAt(WebPoint(125, 25));
  EXPECT_EQ(WebString(), client.Result());
  // Explicitly reset to break dependency on locally scoped client.
  helper.Reset();
}

TEST_P(ParameterizedWebFrameTest, LoadJavascriptURLInNewFrame) {
  FrameTestHelpers::WebViewHelper helper;
  helper.Initialize();

  std::string redirect_url = base_url_ + "foo.html";
  KURL javascript_url = ToKURL("javascript:location='" + redirect_url + "'");
  URLTestHelpers::RegisterMockedURLLoad(ToKURL(redirect_url),
                                        test::CoreTestDataPath("foo.html"));
  helper.LocalMainFrame()->LoadJavaScriptURL(javascript_url);

  // Normally, the result of the JS url replaces the existing contents on the
  // Document. However, if the JS triggers a navigation, the contents should
  // not be replaced.
  EXPECT_EQ("", ToLocalFrame(helper.GetWebView()->GetPage()->MainFrame())
                    ->GetDocument()
                    ->documentElement()
                    ->innerText());
}

class TestResourcePriorityWebFrameClient
    : public FrameTestHelpers::TestWebFrameClient {
 public:
  class ExpectedRequest {
   public:
    ExpectedRequest(const KURL& url, WebURLRequest::Priority priority)
        : url(url), priority(priority), seen(false) {}

    KURL url;
    WebURLRequest::Priority priority;
    bool seen;
  };

  TestResourcePriorityWebFrameClient() = default;
  ~TestResourcePriorityWebFrameClient() override = default;

  // FrameTestHelpers::TestWebFrameClient:
  void WillSendRequest(WebURLRequest& request) override {
    ExpectedRequest* expected_request = expected_requests_.at(request.Url());
    DCHECK(expected_request);
    EXPECT_EQ(expected_request->priority, request.GetPriority());
    expected_request->seen = true;
  }

  void AddExpectedRequest(const KURL& url, WebURLRequest::Priority priority) {
    expected_requests_.insert(url,
                              std::make_unique<ExpectedRequest>(url, priority));
  }

  void VerifyAllRequests() {
    for (const auto& request : expected_requests_)
      EXPECT_TRUE(request.value->seen);
  }

 private:
  HashMap<KURL, std::unique_ptr<ExpectedRequest>> expected_requests_;
};

TEST_P(ParameterizedWebFrameTest, ChangeResourcePriority) {
  TestResourcePriorityWebFrameClient client;
  RegisterMockedHttpURLLoad("promote_img_in_viewport_priority.html");
  RegisterMockedHttpURLLoad("image_slow.pl");
  RegisterMockedHttpURLLoad("image_slow_out_of_viewport.pl");
  client.AddExpectedRequest(
      ToKURL("http://internal.test/promote_img_in_viewport_priority.html"),
      WebURLRequest::Priority::kVeryHigh);
  client.AddExpectedRequest(ToKURL("http://internal.test/image_slow.pl"),
                            WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(
      ToKURL("http://internal.test/image_slow_out_of_viewport.pl"),
      WebURLRequest::Priority::kLow);

  FrameTestHelpers::WebViewHelper helper;
  helper.Initialize(&client);
  helper.Resize(WebSize(640, 480));
  FrameTestHelpers::LoadFrame(
      helper.GetWebView()->MainFrameImpl(),
      base_url_ + "promote_img_in_viewport_priority.html");

  // Ensure the image in the viewport got promoted after the request was sent.
  Resource* image = ToWebLocalFrameImpl(helper.GetWebView()->MainFrame())
                        ->GetFrame()
                        ->GetDocument()
                        ->Fetcher()
                        ->AllResources()
                        .at(ToKURL("http://internal.test/image_slow.pl"));
  DCHECK(image);
  EXPECT_EQ(ResourceLoadPriority::kHigh,
            image->GetResourceRequest().Priority());

  client.VerifyAllRequests();
}

TEST_P(ParameterizedWebFrameTest, ScriptPriority) {
  TestResourcePriorityWebFrameClient client;
  RegisterMockedHttpURLLoad("script_priority.html");
  RegisterMockedHttpURLLoad("priorities/defer.js");
  RegisterMockedHttpURLLoad("priorities/async.js");
  RegisterMockedHttpURLLoad("priorities/head.js");
  RegisterMockedHttpURLLoad("priorities/document-write.js");
  RegisterMockedHttpURLLoad("priorities/injected.js");
  RegisterMockedHttpURLLoad("priorities/injected-async.js");
  RegisterMockedHttpURLLoad("priorities/body.js");
  client.AddExpectedRequest(ToKURL("http://internal.test/script_priority.html"),
                            WebURLRequest::Priority::kVeryHigh);
  client.AddExpectedRequest(ToKURL("http://internal.test/priorities/defer.js"),
                            WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(ToKURL("http://internal.test/priorities/async.js"),
                            WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(ToKURL("http://internal.test/priorities/head.js"),
                            WebURLRequest::Priority::kHigh);
  client.AddExpectedRequest(
      ToKURL("http://internal.test/priorities/document-write.js"),
      WebURLRequest::Priority::kHigh);
  client.AddExpectedRequest(
      ToKURL("http://internal.test/priorities/injected.js"),
      WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(
      ToKURL("http://internal.test/priorities/injected-async.js"),
      WebURLRequest::Priority::kLow);
  client.AddExpectedRequest(ToKURL("http://internal.test/priorities/body.js"),
                            WebURLRequest::Priority::kHigh);

  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeAndLoad(base_url_ + "script_priority.html", &client);
  client.VerifyAllRequests();
}

class MultipleDataChunkDelegate : public WebURLLoaderTestDelegate {
 public:
  MultipleDataChunkDelegate() = default;
  ~MultipleDataChunkDelegate() override = default;

  // WebURLLoaderTestDelegate:
  void DidReceiveData(WebURLLoaderClient* original_client,
                      const char* data,
                      int data_length) override {
    EXPECT_GT(data_length, 16);
    original_client->DidReceiveData(data, 16);
    // This didReceiveData call shouldn't crash due to a failed assertion.
    original_client->DidReceiveData(data + 16, data_length - 16);
  }
};

TEST_P(ParameterizedWebFrameTest, ImageDocumentDecodeError) {
  std::string url = base_url_ + "not_an_image.ico";
  URLTestHelpers::RegisterMockedURLLoad(
      ToKURL(url), test::CoreTestDataPath("not_an_image.ico"), "image/x-icon");
  MultipleDataChunkDelegate delegate;
  Platform::Current()->GetURLLoaderMockFactory()->SetLoaderDelegate(&delegate);
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeAndLoad(url);
  Platform::Current()->GetURLLoaderMockFactory()->SetLoaderDelegate(nullptr);

  Document* document =
      ToLocalFrame(helper.GetWebView()->GetPage()->MainFrame())->GetDocument();
  EXPECT_TRUE(document->IsImageDocument());
  EXPECT_EQ(ResourceStatus::kDecodeError,
            ToImageDocument(document)->CachedImage()->GetContentStatus());
}

// Ensure that the root layer -- whose size is ordinarily derived from the
// content size -- maintains a minimum height matching the viewport in cases
// where the content is smaller.
TEST_P(ParameterizedWebFrameTest, RootLayerMinimumHeight) {
  constexpr int kViewportWidth = 320;
  constexpr int kViewportHeight = 640;
  constexpr int kBrowserControlsHeight = 100;

  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr, nullptr, ConfigureAndroid);
  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view->ResizeWithBrowserControls(
      WebSize(kViewportWidth, kViewportHeight - kBrowserControlsHeight),
      kBrowserControlsHeight, 0, true);

  InitializeWithHTML(
      *web_view->MainFrameImpl()->GetFrame(),
      "<!DOCTYPE html>"
      "<meta name='viewport' content='width=device-width, initial-scale=1'>"
      "<style>"
      "  html, body {width:100%;height:540px;margin:0px}"
      "  #elem {"
      "    overflow: scroll;"
      "    width: 100px;"
      "    height: 10px;"
      "    position: fixed;"
      "    left: 0px;"
      "    bottom: 0px;"
      "  }"
      "</style>"
      "<div id='elem'></div>");
  web_view->UpdateAllLifecyclePhases();

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  LocalFrameView* frame_view = web_view->MainFrameImpl()->GetFrameView();
  PaintLayerCompositor* compositor = frame_view->GetLayoutView()->Compositor();

  EXPECT_EQ(kViewportHeight - kBrowserControlsHeight,
            compositor->RootLayer()->BoundingBoxForCompositing().Height());

  document->View()->SetTracksPaintInvalidations(true);

  web_view->ResizeWithBrowserControls(WebSize(kViewportWidth, kViewportHeight),
                                      kBrowserControlsHeight, 0, false);

  EXPECT_EQ(kViewportHeight,
            compositor->RootLayer()->BoundingBoxForCompositing().Height());
  EXPECT_EQ(kViewportHeight, compositor->RootGraphicsLayer()->Size().Height());
  EXPECT_EQ(kViewportHeight, compositor->RootGraphicsLayer()->Size().Height());

  const RasterInvalidationTracking* invalidation_tracking =
      document->GetLayoutView()
          ->Layer()
          ->GetCompositedLayerMapping()
          ->MainGraphicsLayer()
          ->GetRasterInvalidationTracking();
  ASSERT_TRUE(invalidation_tracking);
  const auto& raster_invalidations = invalidation_tracking->Invalidations();

  if (RuntimeEnabledFeatures::RootLayerScrollingEnabled()) {
    // With RLS we don't issue raster invalidation, because the content paints
    // into the scrolling contents layer whose size hasn't changed.
    EXPECT_TRUE(raster_invalidations.IsEmpty());
  } else {
    // The newly revealed content at the bottom of the screen should have been
    // invalidated. There are additional invalidations for the position: fixed
    // element.
    EXPECT_GT(raster_invalidations.size(), 0u);
    EXPECT_TRUE(raster_invalidations[0].rect.Contains(
        IntRect(0, kViewportHeight - kBrowserControlsHeight, kViewportWidth,
                kBrowserControlsHeight)));
  }

  document->View()->SetTracksPaintInvalidations(false);
}

// Load a page with display:none set and try to scroll it. It shouldn't crash
// due to lack of layoutObject. crbug.com/653327.
TEST_P(ParameterizedWebFrameTest, ScrollBeforeLayoutDoesntCrash) {
  RegisterMockedHttpURLLoad("display-none.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "display-none.html");
  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view_helper.Resize(WebSize(640, 480));

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  document->documentElement()->SetLayoutObject(nullptr);

  WebGestureEvent begin_event(
      WebInputEvent::kGestureScrollBegin, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), kWebGestureDeviceTouchpad);
  WebGestureEvent update_event(
      WebInputEvent::kGestureScrollUpdate, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), kWebGestureDeviceTouchpad);
  WebGestureEvent end_event(
      WebInputEvent::kGestureScrollEnd, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests(), kWebGestureDeviceTouchpad);

  // Try GestureScrollEnd and GestureScrollUpdate first to make sure that not
  // seeing a Begin first doesn't break anything. (This currently happens).
  web_view_helper.GetWebView()->HandleInputEvent(
      WebCoalescedInputEvent(end_event));
  web_view_helper.GetWebView()->HandleInputEvent(
      WebCoalescedInputEvent(update_event));

  // Try a full Begin/Update/End cycle.
  web_view_helper.GetWebView()->HandleInputEvent(
      WebCoalescedInputEvent(begin_event));
  web_view_helper.GetWebView()->HandleInputEvent(
      WebCoalescedInputEvent(update_event));
  web_view_helper.GetWebView()->HandleInputEvent(
      WebCoalescedInputEvent(end_event));
}

TEST_P(ParameterizedWebFrameTest, MouseOverDifferntNodeClearsTooltip) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr, nullptr,
                             [](WebSettings* settings) {});
  web_view_helper.Resize(WebSize(200, 200));
  WebViewImpl* web_view = web_view_helper.GetWebView();

  InitializeWithHTML(
      *web_view->MainFrameImpl()->GetFrame(),
      "<head>"
      "  <style type='text/css'>"
      "   div"
      "    {"
      "      width: 200px;"
      "      height: 100px;"
      "      background-color: #eeeeff;"
      "    }"
      "    div:hover"
      "    {"
      "      background-color: #ddddff;"
      "    }"
      "  </style>"
      "</head>"
      "<body>"
      "  <div id='div1' title='Title Attribute Value'>Hover HERE</div>"
      "  <div id='div2' title='Title Attribute Value'>Then HERE</div>"
      "  <br><br><br>"
      "</body>");

  web_view->UpdateAllLifecyclePhases();

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  Element* div1_tag = document->getElementById("div1");

  HitTestResult hit_test_result = web_view->CoreHitTestResultAt(
      WebPoint(div1_tag->OffsetLeft() + 5, div1_tag->OffsetTop() + 5));

  EXPECT_TRUE(hit_test_result.InnerElement());

  // Mouse over link. Mouse cursor should be hand.
  WebMouseEvent mouse_move_over_link_event(
      WebInputEvent::kMouseMove,
      WebFloatPoint(div1_tag->OffsetLeft() + 5, div1_tag->OffsetTop() + 5),
      WebFloatPoint(div1_tag->OffsetLeft() + 5, div1_tag->OffsetTop() + 5),
      WebPointerProperties::Button::kNoButton, 0, WebInputEvent::kNoModifiers,
      CurrentTimeTicksInSeconds());
  mouse_move_over_link_event.SetFrameScale(1);
  document->GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_over_link_event, Vector<WebMouseEvent>());

  EXPECT_EQ(
      document->HoverElement(),
      document->GetFrame()->GetChromeClient().LastSetTooltipNodeForTesting());
  EXPECT_EQ(
      div1_tag,
      document->GetFrame()->GetChromeClient().LastSetTooltipNodeForTesting());

  Element* div2_tag = document->getElementById("div2");

  WebMouseEvent mouse_move_event(
      WebInputEvent::kMouseMove,
      WebFloatPoint(div2_tag->OffsetLeft() + 5, div2_tag->OffsetTop() + 5),
      WebFloatPoint(div2_tag->OffsetLeft() + 5, div2_tag->OffsetTop() + 5),
      WebPointerProperties::Button::kNoButton, 0, WebInputEvent::kNoModifiers,
      CurrentTimeTicksInSeconds());
  mouse_move_event.SetFrameScale(1);
  document->GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, Vector<WebMouseEvent>());

  EXPECT_EQ(
      document->HoverElement(),
      document->GetFrame()->GetChromeClient().LastSetTooltipNodeForTesting());
  EXPECT_EQ(
      div2_tag,
      document->GetFrame()->GetChromeClient().LastSetTooltipNodeForTesting());
}

class WebFrameSimTest : public testing::WithParamInterface<bool>,
                        private ScopedRootLayerScrollingForTest,
                        public SimTest {
 public:
  WebFrameSimTest() : ScopedRootLayerScrollingForTest(GetParam()) {}
};

INSTANTIATE_TEST_CASE_P(All, WebFrameSimTest, testing::Bool());

TEST_P(WebFrameSimTest, HitTestWithIgnoreClippingAtNegativeOffset) {
  WebView().Resize(WebSize(500, 300));
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest r("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  r.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body, html {
          width: 100%;
          height: 1000px;
          margin: 0;
        }
        #top {
          position: absolute;
          top: 500px;
          height: 100px;
          width: 100%;

        }
        #bottom {
          position: absolute;
          top: 600px;
          width: 100%;
          height: 500px;
        }
      </style>
      <div id="top"></div>
      <div id="bottom"></div>
  )HTML");

  Compositor().BeginFrame();

  LocalFrameView* frame_view =
      ToLocalFrame(WebView().GetPage()->MainFrame())->View();

  frame_view->GetScrollableArea()->SetScrollOffset(ScrollOffset(0, 600),
                                                   kProgrammaticScroll);
  Compositor().BeginFrame();

  HitTestRequest request = HitTestRequest::kMove | HitTestRequest::kReadOnly |
                           HitTestRequest::kActive |
                           HitTestRequest::kIgnoreClipping;
  HitTestResult result(request,
                       frame_view->RootFrameToAbsolute(LayoutPoint(100, -50)));
  frame_view->GetLayoutView()->HitTest(result);

  EXPECT_EQ(GetDocument().getElementById("top"), result.InnerNode());
}

TEST_P(WebFrameSimTest, TickmarksDocumentRelative) {
  WebView().Resize(WebSize(500, 300));
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body, html {
          width: 4000px;
          height: 4000px;
          margin: 0;
        }
        div {
          position: absolute;
          left: 800px;
          top: 2000px;
        }
      </style>
      <div>test</div>
  )HTML");

  Compositor().BeginFrame();

  WebLocalFrameImpl* frame = ToWebLocalFrameImpl(WebView().MainFrame());
  LocalFrameView* frame_view =
      ToLocalFrame(WebView().GetPage()->MainFrame())->View();

  frame_view->GetScrollableArea()->SetScrollOffset(ScrollOffset(3000, 1000),
                                                   kProgrammaticScroll);
  WebFindOptions options;
  WebString search_text = WebString::FromUTF8("test");
  const int kFindIdentifier = 12345;
  EXPECT_TRUE(frame->Find(kFindIdentifier, search_text, options, false));

  frame->EnsureTextFinder().ResetMatchCount();
  frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                      search_text, options);

  RunPendingTasks();

  // Get the tickmarks for the original find request.
  Scrollbar* scrollbar = frame_view->CreateScrollbar(kVerticalScrollbar);
  Vector<IntRect> original_tickmarks;
  scrollbar->GetTickmarks(original_tickmarks);
  EXPECT_EQ(1u, original_tickmarks.size());

  EXPECT_EQ(IntPoint(800, 2000), original_tickmarks[0].Location());
}

TEST_P(WebFrameSimTest, FindInPageSelectNextMatch) {
  WebView().Resize(WebSize(500, 300));
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body, html {
          width: 4000px;
          height: 4000px;
          margin: 0;
        }
        #box1 {
          position: absolute;
          left: 800px;
          top: 2000px;
        }

        #box2 {
          position: absolute;
          left: 1000px;
          top: 3000px;
        }
      </style>
      <div id="box1">test</div>
      <div id="box2">test</div>
  )HTML");

  Compositor().BeginFrame();

  WebLocalFrameImpl* frame = ToWebLocalFrameImpl(WebView().MainFrame());
  LocalFrameView* frame_view =
      ToLocalFrame(WebView().GetPage()->MainFrame())->View();

  Element* box1 = GetDocument().getElementById("box1");
  Element* box2 = GetDocument().getElementById("box2");

  IntRect box1_rect = box1->GetLayoutObject()->AbsoluteBoundingBoxRect();
  IntRect box2_rect = box2->GetLayoutObject()->AbsoluteBoundingBoxRect();

  frame_view->GetScrollableArea()->SetScrollOffset(ScrollOffset(3000, 1000),
                                                   kProgrammaticScroll);
  WebFindOptions options;
  WebString search_text = WebString::FromUTF8("test");
  const int kFindIdentifier = 12345;
  EXPECT_TRUE(frame->Find(kFindIdentifier, search_text, options, false));

  frame->EnsureTextFinder().ResetMatchCount();
  frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                      search_text, options);

  RunPendingTasks();

  WebVector<WebFloatRect> web_match_rects;
  frame->FindMatchRects(web_match_rects);
  ASSERT_EQ(2ul, web_match_rects.size());

  FloatRect result_rect = static_cast<FloatRect>(web_match_rects[0]);
  frame->SelectNearestFindMatch(result_rect.Center(), nullptr);

  LocalFrame* local_frame = ToLocalFrame(WebView().GetPage()->MainFrame());
  VisualViewport& visual_viewport = local_frame->GetPage()->GetVisualViewport();
  EXPECT_TRUE(visual_viewport.VisibleRectInDocument().Contains(box1_rect));

  result_rect = static_cast<FloatRect>(web_match_rects[1]);
  frame->SelectNearestFindMatch(result_rect.Center(), nullptr);

  EXPECT_TRUE(visual_viewport.VisibleRectInDocument().Contains(box2_rect))
      << "Box [" << box2_rect.ToString() << "] is not visible in viewport ["
      << visual_viewport.VisibleRectInDocument().ToString() << "]";
}

TEST_P(WebFrameSimTest, TestScrollFocusedEditableElementIntoView) {
  WebView().Resize(WebSize(500, 300));
  WebView().SetDefaultPageScaleLimits(1.f, 4);
  WebView().EnableFakePageScaleAnimationForTesting(true);
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);
  WebView().GetPage()->GetSettings().SetViewportEnabled(false);
  WebView().GetSettings()->SetAutoZoomFocusedNodeToLegibleScale(true);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        ::-webkit-scrollbar {
          width: 0px;
          height: 0px;
        }
        body {
          margin: 0px;
        }
        input {
          border: 0;
          padding: 0;
          position: absolute;
          left: 200px;
          top: 600px;
          width: 100px;
          height: 20px;
        }
        #content {
          background: silver;
          width: 500px;
          height: 600px;
        }
      </style>
      <div id="content">a</div>
      <input type="text">
  )HTML");

  Compositor().BeginFrame();

  WebView().AdvanceFocus(false);

  LocalFrame* frame = ToLocalFrame(WebView().GetPage()->MainFrame());
  LocalFrameView* frame_view = frame->View();
  VisualViewport& visual_viewport = frame->GetPage()->GetVisualViewport();
  FloatRect inputRect(200, 600, 100, 20);

  frame_view->GetScrollableArea()->SetScrollOffset(ScrollOffset(0, 0),
                                                   kProgrammaticScroll);

  ASSERT_EQ(FloatPoint(), visual_viewport.VisibleRectInDocument().Location());

  WebView()
      .MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();

  EXPECT_EQ(1, WebView().FakePageScaleAnimationPageScaleForTesting());

  frame_view->LayoutViewportScrollableArea()->SetScrollOffset(
      ToFloatSize(WebView().FakePageScaleAnimationTargetPositionForTesting()),
      kProgrammaticScroll);

  EXPECT_TRUE(visual_viewport.VisibleRectInDocument().Contains(inputRect));

  // Reset the testing getters.
  WebView().EnableFakePageScaleAnimationForTesting(true);

  // This input is already in view, this shouldn't cause a scroll.
  WebView()
      .MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();

  EXPECT_EQ(0, WebView().FakePageScaleAnimationPageScaleForTesting());
  EXPECT_EQ(IntPoint(),
            WebView().FakePageScaleAnimationTargetPositionForTesting());

  // Now resize the visual viewport so that the input box is no longer in view
  // (e.g. a keyboard is overlayed).
  WebView().ResizeVisualViewport(IntSize(200, 100));
  ASSERT_FALSE(visual_viewport.VisibleRectInDocument().Contains(inputRect));

  WebView()
      .MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();
  frame_view->GetScrollableArea()->SetScrollOffset(
      ToFloatSize(WebView().FakePageScaleAnimationTargetPositionForTesting()),
      kProgrammaticScroll);

  EXPECT_TRUE(visual_viewport.VisibleRectInDocument().Contains(inputRect));
  EXPECT_EQ(1, WebView().FakePageScaleAnimationPageScaleForTesting());
}

TEST_P(WebFrameSimTest, ScrollFocusedIntoViewClipped) {
  // The Android On-Screen Keyboard (OSK) resizes the Widget Blink is hosted
  // in. When the keyboard is shown, we scroll and zoom in on the currently
  // focused editable element. However, the scroll and zoom is a smoothly
  // animated "PageScaleAnimation" that's performed in CC only on the viewport
  // layers. There are some situations in which the widget resize causes the
  // focued input to be hidden by clipping parents that aren't the main frame.
  // In these cases, there's no way to scroll just the viewport to make the
  // input visible, we need to also scroll those clip/scroller elements  This
  // test ensures we do so. https://crbug.com/270018.
  WebView().Resize(WebSize(400, 600));
  WebView().SetDefaultPageScaleLimits(0.25f, 5);
  WebView().EnableFakePageScaleAnimationForTesting(true);
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);
  WebView().GetSettings()->SetViewportMetaEnabled(true);
  WebView().GetSettings()->SetViewportEnabled(true);
  WebView().GetSettings()->SetMainFrameResizesAreOrientationChanges(true);
  WebView().GetSettings()->SetShrinksViewportContentToFit(true);
  WebView().GetSettings()->SetViewportStyle(WebViewportStyle::kMobile);
  WebView().GetSettings()->SetAutoZoomFocusedNodeToLegibleScale(true);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        ::-webkit-scrollbar {
          width: 0px;
          height: 0px;
        }
        body, html {
          margin: 0px;
          width: 100%;
          height: 100%;
        }
        input {
          padding: 0;
          position: relative;
          top: 1400px;
          width: 100px;
          height: 20px;
        }
        #clip {
          width: 100%;
          height: 100%;
          overflow: hidden;
        }
        #container {
          width: 980px;
          height: 1470px;
        }
      </style>
      <div id="clip">
        <div id="container">
          <input type="text" id="target">
        </div>
      </div>
  )HTML");

  Compositor().BeginFrame();
  WebView().AdvanceFocus(false);

  LocalFrame* frame = ToLocalFrame(WebView().GetPage()->MainFrame());
  LocalFrameView* frame_view = frame->View();
  VisualViewport& visual_viewport = frame->GetPage()->GetVisualViewport();

  ASSERT_EQ(FloatPoint(), visual_viewport.VisibleRectInDocument().Location());

  // Simulate the keyboard being shown and resizing the widget. Cause a scroll
  // into view after.
  WebView().Resize(WebSize(400, 300));

  float scale_before = visual_viewport.Scale();
  WebView()
      .MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();

  Element* input = GetDocument().getElementById("target");
  IntRect input_rect(input->getBoundingClientRect()->top(),
                     input->getBoundingClientRect()->left(),
                     input->getBoundingClientRect()->width(),
                     input->getBoundingClientRect()->height());

  EXPECT_TRUE(frame_view->VisibleContentRect().Contains(input_rect))
      << "Layout viewport [" << frame_view->VisibleContentRect().ToString()
      << "] does not contain input rect [" << input_rect.ToString()
      << "] after scroll into view.";

  EXPECT_TRUE(visual_viewport.VisibleRect().Contains(input_rect))
      << "Visual viewport [" << visual_viewport.VisibleRect().ToString()
      << "] does not contain input rect [" << input_rect.ToString()
      << "] after scroll into view.";

  // Make sure we also zoomed in on the input.
  EXPECT_GT(WebView().FakePageScaleAnimationPageScaleForTesting(),
            scale_before);

  // Additional gut-check that we actually scrolled the non-user-scrollable
  // clip element to make sure the input is in view.
  Element* clip = GetDocument().getElementById("clip");
  EXPECT_GT(clip->scrollTop(), 0);
}

TEST_P(WebFrameSimTest, DoubleTapZoomWhileScrolled) {
  WebView().Resize(WebSize(490, 500));
  WebView().SetDefaultPageScaleLimits(0.5f, 4);
  WebView().EnableFakePageScaleAnimationForTesting(true);

  WebView().GetSettings()->SetTextAutosizingEnabled(false);
  WebView().GetSettings()->SetViewportMetaEnabled(true);
  WebView().GetSettings()->SetViewportEnabled(true);
  WebView().GetSettings()->SetMainFrameResizesAreOrientationChanges(true);
  WebView().GetSettings()->SetShrinksViewportContentToFit(true);
  WebView().GetSettings()->SetViewportStyle(WebViewportStyle::kMobile);
  WebView().GetSettings()->SetAutoZoomFocusedNodeToLegibleScale(true);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        ::-webkit-scrollbar {
          width: 0px;
          height: 0px;
        }
        body {
          margin: 0px;
          width: 10000px;
          height: 10000px;
        }
        #target {
          position: absolute;
          left: 2000px;
          top: 3000px;
          width: 100px;
          height: 100px;
          background-color: blue;
        }
      </style>
      <div id="target"></div>
  )HTML");

  Compositor().BeginFrame();

  LocalFrame* frame = ToLocalFrame(WebView().GetPage()->MainFrame());
  LocalFrameView* frame_view = frame->View();
  VisualViewport& visual_viewport = frame->GetPage()->GetVisualViewport();
  FloatRect target_rect_in_document(2000, 3000, 100, 100);

  ASSERT_EQ(0.5f, visual_viewport.Scale());

  // Center the target in the screen.
  frame_view->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(2000 - 440, 3000 - 450), kProgrammaticScroll);
  Element* target = GetDocument().QuerySelector("#target");
  DOMRect* rect = target->getBoundingClientRect();
  ASSERT_EQ(440, rect->left());
  ASSERT_EQ(450, rect->top());

  // Double-tap on the target. Expect that we zoom in and the target is
  // contained in the visual viewport.
  {
    WebView().AnimateDoubleTapZoom(WebPoint(445, 455));
    EXPECT_TRUE(WebView().FakeDoubleTapAnimationPendingForTesting());
    ScrollOffset new_offset = ToScrollOffset(
        WebView().FakePageScaleAnimationTargetPositionForTesting());
    float new_scale = WebView().FakePageScaleAnimationPageScaleForTesting();
    visual_viewport.SetScale(new_scale);
    frame_view->GetScrollableArea()->SetScrollOffset(new_offset,
                                                     kProgrammaticScroll);

    EXPECT_FLOAT_EQ(1, visual_viewport.Scale());
    EXPECT_TRUE(visual_viewport.VisibleRectInDocument().Contains(
        target_rect_in_document));
  }

  // Reset the testing getters.
  WebView().EnableFakePageScaleAnimationForTesting(true);

  // Double-tap on the target again. We should zoom out and the target should
  // remain on screen.
  {
    WebView().AnimateDoubleTapZoom(WebPoint(445, 455));
    EXPECT_TRUE(WebView().FakeDoubleTapAnimationPendingForTesting());
    IntPoint target_offset =
        WebView().FakePageScaleAnimationTargetPositionForTesting();
    float new_scale = WebView().FakePageScaleAnimationPageScaleForTesting();

    EXPECT_FLOAT_EQ(0.5f, new_scale);
    EXPECT_TRUE(target_rect_in_document.Contains(target_offset));
  }
}

TEST_P(WebFrameSimTest, ChangeBackgroundColor) {
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete("<!DOCTYPE html><body></body>");

  Element* body = GetDocument().QuerySelector("body");
  EXPECT_TRUE(!!body);

  Compositor().BeginFrame();
  // White is the default background of a web page.
  EXPECT_EQ(SK_ColorWHITE, Compositor().background_color());

  // Setting the background of the body to red will cause the background
  // color of the WebView to switch to red.
  body->SetInlineStyleProperty(CSSPropertyBackgroundColor, "red");
  Compositor().BeginFrame();
  EXPECT_EQ(SK_ColorRED, Compositor().background_color());
}

// Ensure we don't crash if we try to scroll into view the focused editable
// element which doesn't have a LayoutObject.
TEST_P(WebFrameSimTest, ScrollFocusedEditableIntoViewNoLayoutObject) {
  WebView().Resize(WebSize(500, 600));
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest r("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  r.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        input {
          position: absolute;
          top: 1000px;
          left: 800px;
        }

        @media (max-height: 500px) {
          input {
            display: none;
          }
        }
      </style>
      <input id="target" type="text"></input>
  )HTML");

  Compositor().BeginFrame();

  Element* input = GetDocument().getElementById("target");
  input->focus();

  ScrollableArea* area = GetDocument().View()->LayoutViewportScrollableArea();
  area->SetScrollOffset(ScrollOffset(0, 0), kProgrammaticScroll);

  ASSERT_TRUE(input->GetLayoutObject());
  ASSERT_EQ(input, WebView().FocusedElement());
  ASSERT_EQ(ScrollOffset(0, 0), area->GetScrollOffset());

  // The resize should cause the focused element to lose its LayoutObject. If
  // this resize came from the Android on-screen keyboard, this would be
  // followed by a ScrollFocusedEditableElementIntoView. Ensure we don't crash.
  WebView().Resize(WebSize(500, 300));

  ASSERT_FALSE(input->GetLayoutObject());
  ASSERT_EQ(input, WebView().FocusedElement());

  WebFrameWidget* widget = WebView().MainFrameImpl()->FrameWidgetImpl();
  widget->ScrollFocusedEditableElementIntoView();
  Compositor().BeginFrame();

  // Shouldn't cause any scrolling either.
  EXPECT_EQ(ScrollOffset(0, 0), area->GetScrollOffset());
}

TEST_P(WebFrameSimTest, DisplayNoneIFrameHasNoLayoutObjects) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      "<!DOCTYPE html>"
      "<iframe src=frame.html style='display: none'></iframe>");
  frame_resource.Complete(
      "<!DOCTYPE html>"
      "<html><body>This is a visible iframe.</body></html>");

  Element* element = GetDocument().QuerySelector("iframe");
  HTMLFrameOwnerElement* frame_owner_element = ToHTMLFrameOwnerElement(element);
  Document* iframe_doc = frame_owner_element->contentDocument();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());

  // Changing the display from 'none' -> 'block' should cause layout objects to
  // appear.
  element->SetInlineStyleProperty(CSSPropertyDisplay, CSSValueBlock);
  Compositor().BeginFrame();
  EXPECT_TRUE(iframe_doc->documentElement()->GetLayoutObject());

  // Changing the display from 'block' -> 'none' should cause layout objects to
  // disappear.
  element->SetInlineStyleProperty(CSSPropertyDisplay, CSSValueNone);

  Compositor().BeginFrame();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());
}

// Although it is not spec compliant, many websites intentionally call
// Window.print() on display:none iframes. https://crbug.com/819327.
TEST_P(WebFrameSimTest, DisplayNoneIFramePrints) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      "<!DOCTYPE html>"
      "<iframe src=frame.html style='display: none'></iframe>");
  frame_resource.Complete(
      "<!DOCTYPE html>"
      "<html><body>This is a visible iframe.</body></html>");

  Element* element = GetDocument().QuerySelector("iframe");
  HTMLFrameOwnerElement* frame_owner_element = ToHTMLFrameOwnerElement(element);
  Document* iframe_doc = frame_owner_element->contentDocument();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());

  FloatSize page_size(400, 400);
  float maximum_shrink_ratio = 1.0;
  iframe_doc->GetFrame()->StartPrinting(page_size, page_size,
                                        maximum_shrink_ratio);
  EXPECT_TRUE(iframe_doc->documentElement()->GetLayoutObject());

  iframe_doc->GetFrame()->EndPrinting();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());
}

TEST_P(WebFrameSimTest, NormalIFrameHasLayoutObjects) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      "<!DOCTYPE html>"
      "<iframe src=frame.html style='display: block'></iframe>");
  frame_resource.Complete(
      "<!DOCTYPE html>"
      "<html><body>This is a visible iframe.</body></html>");

  Element* element = GetDocument().QuerySelector("iframe");
  HTMLFrameOwnerElement* frame_owner_element = ToHTMLFrameOwnerElement(element);
  Document* iframe_doc = frame_owner_element->contentDocument();
  EXPECT_TRUE(iframe_doc->documentElement()->GetLayoutObject());

  // Changing the display from 'block' -> 'none' should cause layout objects to
  // disappear.
  element->SetInlineStyleProperty(CSSPropertyDisplay, CSSValueNone);
  Compositor().BeginFrame();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());
}

TEST_P(WebFrameSimTest, ScrollOriginChangeUpdatesLayerPositions) {
  // With RLS, scroll origin changes do not update layer positions.
  // It's unclear why it was ever desirable to update layer positions,
  // even without RLS, because the position adjustment in the PLC scroll
  // layer was negated by the position adjustment in the content root layer.
  if (RuntimeEnabledFeatures::RootLayerScrollingEnabled())
    return;

  WebView().Resize(WebSize(800, 600));
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <body dir='rtl'>
      <div style='width:1px; height:1px; position:absolute; left:-10000px'>
      </div>
    </body>
  )HTML");

  Compositor().BeginFrame();
  ScrollableArea* area = GetDocument().View()->LayoutViewportScrollableArea();
  ASSERT_EQ(10000, area->ScrollOrigin().X());
  ASSERT_EQ(10000, area->LayerForScrolling()->GetPosition().X());

  // Removing the overflowing element removes all overflow so the scroll origin
  // implicitly is reset to (0, 0).
  GetDocument().QuerySelector("div")->remove();
  Compositor().BeginFrame();

  EXPECT_EQ(0, area->ScrollOrigin().X());
  EXPECT_EQ(0, area->LayerForScrolling()->GetPosition().X());
}

TEST_P(WebFrameSimTest, RtlInitialScrollOffsetWithViewport) {
  WebView().GetSettings()->SetViewportEnabled(true);
  WebView().GetSettings()->SetViewportMetaEnabled(true);

  WebView().Resize(WebSize(400, 400));
  WebView().SetDefaultPageScaleLimits(0.25f, 2);

  SimRequest main_resource("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <meta name='viewport' content='width=device-width, minimum-scale=1'>
    <body dir='rtl'>
    <div style='width: 3000px; height: 20px'></div>
  )HTML");

  Compositor().BeginFrame();
  ScrollableArea* area = GetDocument().View()->LayoutViewportScrollableArea();
  ASSERT_EQ(ScrollOffset(0, 0), area->GetScrollOffset());
}

TEST_P(WebFrameSimTest, LayoutViewportExceedsLayoutOverflow) {
  // This test fails without RLS (but doesn't cause visible paint clipping due
  // to differences in composited layer geometry logic).
  if (!RuntimeEnabledFeatures::RootLayerScrollingEnabled())
    return;

  WebView().GetSettings()->SetViewportEnabled(true);
  WebView().GetSettings()->SetViewportMetaEnabled(true);

  WebView().ResizeWithBrowserControls(WebSize(400, 540), 60, 0, true);
  WebView().SetDefaultPageScaleLimits(0.25f, 2);

  SimRequest main_resource("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <meta name='viewport' content='width=device-width, minimum-scale=1'>
    <body style='margin: 0; height: 95vh'>
  )HTML");

  Compositor().BeginFrame();
  ScrollableArea* area = GetDocument().View()->LayoutViewportScrollableArea();
  ASSERT_EQ(540, area->VisibleHeight());
  ASSERT_EQ(IntSize(400, 570), area->ContentsSize());

  // Hide browser controls, growing layout viewport without affecting ICB.
  WebView().ResizeWithBrowserControls(WebSize(400, 600), 60, 0, false);
  Compositor().BeginFrame();

  // ContentsSize() should grow to accomodate new visible size.
  ASSERT_EQ(600, area->VisibleHeight());
  ASSERT_EQ(IntSize(400, 600), area->ContentsSize());
}

TEST_P(WebFrameSimTest, NamedLookupIgnoresEmptyNames) {
  SimRequest main_resource("https://example.com/main.html", "text/html");
  LoadURL("https://example.com/main.html");
  main_resource.Complete(R"HTML(
    <body>
    <iframe name="" src="data:text/html,"></iframe>
    </body>)HTML");

  EXPECT_EQ(nullptr, MainFrame().GetFrame()->Tree().ScopedChild(""));
  EXPECT_EQ(nullptr,
            MainFrame().GetFrame()->Tree().ScopedChild(AtomicString()));
  EXPECT_EQ(nullptr, MainFrame().GetFrame()->Tree().ScopedChild(g_empty_atom));
}

TEST_P(ParameterizedWebFrameTest, NoLoadingCompletionCallbacksInDetach) {
  class LoadingObserverFrameClient
      : public FrameTestHelpers::TestWebFrameClient {
   public:
    LoadingObserverFrameClient() = default;
    ~LoadingObserverFrameClient() override = default;

    // FrameTestHelpers::TestWebFrameClient:
    void FrameDetached(DetachType type) override {
      did_call_frame_detached_ = true;
      TestWebFrameClient::FrameDetached(type);
    }

    void DidStopLoading() override {
      // TODO(dcheng): Investigate not calling this as well during frame detach.
      did_call_did_stop_loading_ = true;
      TestWebFrameClient::DidStopLoading();
    }

    void DidFailProvisionalLoad(const WebURLError&,
                                WebHistoryCommitType) override {
      EXPECT_TRUE(false) << "The load should not have failed.";
    }

    void DidFinishDocumentLoad() override {
      // TODO(dcheng): Investigate not calling this as well during frame detach.
      did_call_did_finish_document_load_ = true;
    }

    void DidHandleOnloadEvents() override {
      // TODO(dcheng): Investigate not calling this as well during frame detach.
      did_call_did_handle_onload_events_ = true;
    }

    void DidFinishLoad() override {
      EXPECT_TRUE(false) << "didFinishLoad() should not have been called.";
    }

    void DispatchLoad() override {
      EXPECT_TRUE(false) << "dispatchLoad() should not have been called.";
    }

    bool DidCallFrameDetached() const { return did_call_frame_detached_; }
    bool DidCallDidStopLoading() const { return did_call_did_stop_loading_; }
    bool DidCallDidFinishDocumentLoad() const {
      return did_call_did_finish_document_load_;
    }
    bool DidCallDidHandleOnloadEvents() const {
      return did_call_did_handle_onload_events_;
    }

   private:
    bool did_call_frame_detached_ = false;
    bool did_call_did_stop_loading_ = false;
    bool did_call_did_finish_document_load_ = false;
    bool did_call_did_handle_onload_events_ = false;
  };

  class MainFrameClient : public FrameTestHelpers::TestWebFrameClient {
   public:
    MainFrameClient() = default;
    ~MainFrameClient() override = default;

    // FrameTestHelpers::TestWebFrameClient:
    WebLocalFrame* CreateChildFrame(WebLocalFrame* parent,
                                    WebTreeScopeType scope,
                                    const WebString& name,
                                    const WebString& fallback_name,
                                    WebSandboxFlags sandbox_flags,
                                    const ParsedFeaturePolicy& container_policy,
                                    const WebFrameOwnerProperties&) override {
      return CreateLocalChild(*parent, scope, &child_client_);
    }

    LoadingObserverFrameClient& ChildClient() { return child_client_; }

   private:
    LoadingObserverFrameClient child_client_;
  };

  RegisterMockedHttpURLLoad("single_iframe.html");
  URLTestHelpers::RegisterMockedURLLoad(
      ToKURL(base_url_ + "visible_iframe.html"),
      test::CoreTestDataPath("frame_with_frame.html"));
  RegisterMockedHttpURLLoad("parent_detaching_frame.html");

  FrameTestHelpers::WebViewHelper web_view_helper;
  MainFrameClient main_frame_client;
  web_view_helper.InitializeAndLoad(base_url_ + "single_iframe.html",
                                    &main_frame_client);

  EXPECT_TRUE(main_frame_client.ChildClient().DidCallFrameDetached());
  EXPECT_TRUE(main_frame_client.ChildClient().DidCallDidStopLoading());
  EXPECT_TRUE(main_frame_client.ChildClient().DidCallDidFinishDocumentLoad());
  EXPECT_TRUE(main_frame_client.ChildClient().DidCallDidHandleOnloadEvents());

  web_view_helper.Reset();
}

TEST_P(ParameterizedWebFrameTest, ClearClosedOpener) {
  FrameTestHelpers::WebViewHelper opener_helper;
  opener_helper.Initialize();
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeWithOpener(opener_helper.GetWebView()->MainFrame());

  opener_helper.Reset();
  EXPECT_EQ(nullptr, helper.LocalMainFrame()->Opener());
}

class ShowVirtualKeyboardObserverWidgetClient
    : public FrameTestHelpers::TestWebWidgetClient {
 public:
  ShowVirtualKeyboardObserverWidgetClient()
      : did_show_virtual_keyboard_(false) {}
  ~ShowVirtualKeyboardObserverWidgetClient() override = default;

  // FrameTestHelpers::TestWebWidgetClient:
  void ShowVirtualKeyboardOnElementFocus() override {
    did_show_virtual_keyboard_ = true;
  }

  bool DidShowVirtualKeyboard() const { return did_show_virtual_keyboard_; }

 private:
  bool did_show_virtual_keyboard_;
};

TEST_P(ParameterizedWebFrameTest, ShowVirtualKeyboardOnElementFocus) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeRemote();

  ShowVirtualKeyboardObserverWidgetClient web_widget_client;
  WebLocalFrameImpl* local_frame = FrameTestHelpers::CreateLocalChild(
      *web_view_helper.RemoteMainFrame(), "child", WebFrameOwnerProperties(),
      nullptr, nullptr, &web_widget_client);

  RegisterMockedHttpURLLoad("input_field_default.html");
  FrameTestHelpers::LoadFrame(local_frame,
                              base_url_ + "input_field_default.html");

  // Simulate an input element focus leading to Element::focus() call with a
  // user gesture.
  Frame::NotifyUserActivation(local_frame->GetFrame(),
                              UserGestureToken::kNewGesture);
  local_frame->ExecuteScript(
      WebScriptSource("window.focus();"
                      "document.querySelector('input').focus();"));

  // Verify that the right WebWidgetClient has been notified.
  EXPECT_TRUE(web_widget_client.DidShowVirtualKeyboard());

  web_view_helper.Reset();
}

class ContextMenuWebFrameClient : public FrameTestHelpers::TestWebFrameClient {
 public:
  ContextMenuWebFrameClient() = default;
  ~ContextMenuWebFrameClient() override = default;

  // WebFrameClient:
  void ShowContextMenu(const WebContextMenuData& data) override {
    menu_data_ = data;
  }

  WebContextMenuData GetMenuData() { return menu_data_; }

 private:
  WebContextMenuData menu_data_;
  DISALLOW_COPY_AND_ASSIGN(ContextMenuWebFrameClient);
};

bool TestSelectAll(const std::string& html) {
  ContextMenuWebFrameClient frame;
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.Initialize(&frame);
  FrameTestHelpers::LoadHTMLString(web_view->MainFrameImpl(), html,
                                   ToKURL("about:blank"));
  web_view->Resize(WebSize(500, 300));
  web_view->UpdateAllLifecyclePhases();
  RunPendingTasks();
  web_view->SetInitialFocus(false);
  RunPendingTasks();

  WebMouseEvent mouse_event(WebInputEvent::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());

  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.SetPositionInWidget(8, 8);
  mouse_event.click_count = 1;
  web_view->HandleInputEvent(WebCoalescedInputEvent(mouse_event));
  RunPendingTasks();
  web_view_helper.Reset();
  return frame.GetMenuData().edit_flags & WebContextMenuData::kCanSelectAll;
}

TEST_P(ParameterizedWebFrameTest, ContextMenuDataSelectAll) {
  EXPECT_FALSE(TestSelectAll("<textarea></textarea>"));
  EXPECT_TRUE(TestSelectAll("<textarea>nonempty</textarea>"));
  EXPECT_FALSE(TestSelectAll("<input>"));
  EXPECT_TRUE(TestSelectAll("<input value='nonempty'>"));
  EXPECT_FALSE(TestSelectAll("<div contenteditable></div>"));
  EXPECT_TRUE(TestSelectAll("<div contenteditable>nonempty</div>"));
  EXPECT_TRUE(TestSelectAll("<div contenteditable>\n</div>"));
}

TEST_P(ParameterizedWebFrameTest, ContextMenuDataSelectedText) {
  ContextMenuWebFrameClient frame;
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.Initialize(&frame);
  const std::string& html = "<input value=' '>";
  FrameTestHelpers::LoadHTMLString(web_view->MainFrameImpl(), html,
                                   ToKURL("about:blank"));
  web_view->Resize(WebSize(500, 300));
  web_view->UpdateAllLifecyclePhases();
  RunPendingTasks();
  web_view->SetInitialFocus(false);
  RunPendingTasks();

  web_view->MainFrameImpl()->ExecuteCommand(WebString::FromUTF8("SelectAll"));

  WebMouseEvent mouse_event(WebInputEvent::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());

  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.SetPositionInWidget(8, 8);
  mouse_event.click_count = 1;
  web_view->HandleInputEvent(WebCoalescedInputEvent(mouse_event));
  RunPendingTasks();
  web_view_helper.Reset();
  EXPECT_EQ(frame.GetMenuData().selected_text, " ");
}

TEST_P(ParameterizedWebFrameTest, ContextMenuDataPasswordSelectedText) {
  ContextMenuWebFrameClient frame;
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.Initialize(&frame);
  const std::string& html = "<input type='password' value='password'>";
  FrameTestHelpers::LoadHTMLString(web_view->MainFrameImpl(), html,
                                   ToKURL("about:blank"));
  web_view->Resize(WebSize(500, 300));
  web_view->UpdateAllLifecyclePhases();
  RunPendingTasks();
  web_view->SetInitialFocus(false);
  RunPendingTasks();

  web_view->MainFrameImpl()->ExecuteCommand(WebString::FromUTF8("SelectAll"));

  WebMouseEvent mouse_event(WebInputEvent::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());

  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.SetPositionInWidget(8, 8);
  mouse_event.click_count = 1;
  web_view->HandleInputEvent(WebCoalescedInputEvent(mouse_event));

  RunPendingTasks();
  web_view_helper.Reset();
  EXPECT_EQ(frame.GetMenuData().input_field_type,
            blink::WebContextMenuData::kInputFieldTypePassword);
  EXPECT_FALSE(frame.GetMenuData().selected_text.IsEmpty());
}

TEST_P(ParameterizedWebFrameTest, ContextMenuDataNonLocatedMenu) {
  ContextMenuWebFrameClient frame;
  FrameTestHelpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.Initialize(&frame);
  const std::string& html =
      "<div style='font-size: 1000%; line-height: 0.7em'>Select me<br/>"
      "Next line</div>";
  FrameTestHelpers::LoadHTMLString(web_view->MainFrameImpl(), html,
                                   ToKURL("about:blank"));
  web_view->Resize(WebSize(500, 300));
  web_view->UpdateAllLifecyclePhases();
  RunPendingTasks();
  web_view->SetInitialFocus(false);
  RunPendingTasks();

  WebMouseEvent mouse_event(WebInputEvent::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());

  mouse_event.button = WebMouseEvent::Button::kLeft;
  mouse_event.SetPositionInWidget(0, 0);
  mouse_event.click_count = 2;
  web_view->HandleInputEvent(WebCoalescedInputEvent(mouse_event));

  web_view->ShowContextMenu(kMenuSourceTouch);

  RunPendingTasks();
  web_view_helper.Reset();
  EXPECT_EQ(frame.GetMenuData().source_type, kMenuSourceTouch);
  EXPECT_FALSE(frame.GetMenuData().selected_text.IsEmpty());
}

TEST_P(ParameterizedWebFrameTest, LocalFrameWithRemoteParentIsTransparent) {
  FrameTestHelpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebLocalFrameImpl* local_frame =
      FrameTestHelpers::CreateLocalChild(*helper.RemoteMainFrame());
  FrameTestHelpers::LoadFrame(local_frame, "data:text/html,some page");

  // Local frame with remote parent should have transparent baseBackgroundColor.
  Color color = local_frame->GetFrameView()->BaseBackgroundColor();
  EXPECT_EQ(Color::kTransparent, color);
}

class TestFallbackWebFrameClient : public FrameTestHelpers::TestWebFrameClient {
 public:
  TestFallbackWebFrameClient() : child_client_(nullptr) {}
  ~TestFallbackWebFrameClient() override = default;

  void SetChildWebFrameClient(TestFallbackWebFrameClient* client) {
    child_client_ = client;
  }

  // FrameTestHelpers::TestWebFrameClient:
  WebLocalFrame* CreateChildFrame(
      WebLocalFrame* parent,
      WebTreeScopeType scope,
      const WebString&,
      const WebString&,
      WebSandboxFlags,
      const ParsedFeaturePolicy& container_policy,
      const WebFrameOwnerProperties& frameOwnerProperties) override {
    DCHECK(child_client_);
    return CreateLocalChild(*parent, scope, child_client_);
  }
  WebNavigationPolicy DecidePolicyForNavigation(
      const NavigationPolicyInfo& info) override {
    if (child_client_ || KURL(info.url_request.Url()) == BlankURL())
      return kWebNavigationPolicyCurrentTab;
    return kWebNavigationPolicyHandledByClient;
  }

 private:
  TestFallbackWebFrameClient* child_client_;
};

TEST_P(ParameterizedWebFrameTest, FallbackForNonexistentProvisionalNavigation) {
  RegisterMockedHttpURLLoad("fallback.html");
  TestFallbackWebFrameClient main_client;
  TestFallbackWebFrameClient child_client;
  main_client.SetChildWebFrameClient(&child_client);

  FrameTestHelpers::WebViewHelper web_view_helper_;
  web_view_helper_.Initialize(&main_client);

  WebLocalFrameImpl* main_frame = web_view_helper_.LocalMainFrame();
  WebURLRequest request(ToKURL(base_url_ + "fallback.html"));
  main_frame->LoadRequest(request);

  // Because the child frame will be HandledByClient, the main frame will not
  // finish loading, so FrameTestHelpers::PumpPendingRequestsForFrameToLoad
  // doesn't work here.
  Platform::Current()->GetURLLoaderMockFactory()->ServeAsynchronousRequests();

  // Overwrite the client-handled child frame navigation with about:blank.
  WebLocalFrame* child = main_frame->FirstChild()->ToWebLocalFrame();
  child->LoadRequest(WebURLRequest(BlankURL()));

  // Failing the original child frame navigation and trying to render fallback
  // content shouldn't crash. It should return NoLoadInProgress. This is so the
  // caller won't attempt to replace the correctly empty frame with an error
  // page.
  EXPECT_EQ(
      WebLocalFrame::NoLoadInProgress,
      child->MaybeRenderFallbackContent(ResourceError::Failure(request.Url())));
}

TEST_P(ParameterizedWebFrameTest, AltTextOnAboutBlankPage) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  web_view_helper.Resize(WebSize(640, 480));
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();

  const char kSource[] =
      "<img id='foo' src='foo' alt='foo alt' width='200' height='200'>";
  FrameTestHelpers::LoadHTMLString(frame, kSource, ToKURL("about:blank"));
  web_view_helper.GetWebView()->UpdateAllLifecyclePhases();
  RunPendingTasks();

  // Check LayoutText with alt text "foo alt"
  LayoutObject* layout_object = frame->GetFrame()
                                    ->GetDocument()
                                    ->getElementById("foo")
                                    ->GetLayoutObject()
                                    ->SlowFirstChild();
  String text = "";
  for (LayoutObject* obj = layout_object; obj; obj = obj->NextInPreOrder()) {
    if (obj->IsText()) {
      LayoutText* layout_text = ToLayoutText(obj);
      text = layout_text->GetText();
      break;
    }
  }
  EXPECT_EQ("foo alt", text.Utf8());
}

TEST_F(WebFrameTest, NavigatorPluginsClearedWhenPluginsDisabled) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  v8::HandleScope scope(v8::Isolate::GetCurrent());
  v8::Local<v8::Value> result =
      web_view_helper.LocalMainFrame()->ExecuteScriptAndReturnValue(
          WebScriptSource("navigator.plugins.length"));
  EXPECT_NE(0, result->Int32Value());
  web_view_helper.GetWebView()->GetPage()->GetSettings().SetPluginsEnabled(
      false);
  result = web_view_helper.LocalMainFrame()->ExecuteScriptAndReturnValue(
      WebScriptSource("navigator.plugins.length"));
  EXPECT_EQ(0, result->Int32Value());
}

TEST_F(WebFrameTest, RecordSameDocumentNavigationToHistogram) {
  const char* histogramName =
      "RendererScheduler.UpdateForSameDocumentNavigationCount";
  FrameTestHelpers::WebViewHelper web_view_helper;
  HistogramTester tester;
  web_view_helper.InitializeAndLoad("about:blank");
  LocalFrame* frame =
      ToLocalFrame(web_view_helper.GetWebView()->GetPage()->MainFrame());

  FrameLoader& main_frame_loader =
      web_view_helper.GetWebView()->MainFrameImpl()->GetFrame()->Loader();
  scoped_refptr<SerializedScriptValue> message =
      SerializeString("message", ToScriptStateForMainWorld(frame));
  tester.ExpectTotalCount(histogramName, 0);
  main_frame_loader.UpdateForSameDocumentNavigation(
      ToKURL("about:blank"), kSameDocumentNavigationHistoryApi, message,
      kScrollRestorationAuto, kFrameLoadTypeInitialHistoryLoad,
      frame->GetDocument());
  // The bucket index corresponds to the definition of
  // |SinglePageAppNavigationType|.
  tester.ExpectBucketCount(histogramName,
                           kSPANavTypeHistoryPushStateOrReplaceState, 1);
  main_frame_loader.UpdateForSameDocumentNavigation(
      ToKURL("about:blank"), kSameDocumentNavigationDefault, message,
      kScrollRestorationManual, kFrameLoadTypeBackForward,
      frame->GetDocument());
  tester.ExpectBucketCount(histogramName,
                           kSPANavTypeSameDocumentBackwardOrForward, 1);
  main_frame_loader.UpdateForSameDocumentNavigation(
      ToKURL("about:blank"), kSameDocumentNavigationDefault, message,
      kScrollRestorationManual, kFrameLoadTypeInitialHistoryLoad,
      frame->GetDocument());
  tester.ExpectBucketCount(histogramName, kSPANavTypeOtherFragmentNavigation,
                           1);
  // kSameDocumentNavigationHistoryApi and kFrameLoadTypeBackForward is an
  // illegal combination, which has been caught by DCHECK in
  // UpdateForSameDocumentNavigation().

  tester.ExpectTotalCount(histogramName, 3);
}

TEST_P(ParameterizedWebFrameTest, DidScrollCallbackAfterScrollableAreaChanges) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  web_view_helper.Resize(WebSize(200, 200));
  WebViewImpl* web_view = web_view_helper.GetWebView();

  InitializeWithHTML(*web_view->MainFrameImpl()->GetFrame(),
                     "<style>"
                     "  #scrollable {"
                     "    height: 100px;"
                     "    width: 100px;"
                     "    overflow: scroll;"
                     "    will-change: transform;"
                     "  }"
                     "  #forceScroll { height: 120px; width: 50px; }"
                     "</style>"
                     "<div id='scrollable'>"
                     "  <div id='forceScroll'></div>"
                     "</div>");

  web_view->UpdateAllLifecyclePhases();

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  Element* scrollable = document->getElementById("scrollable");

  auto* scrollable_area =
      ToLayoutBox(scrollable->GetLayoutObject())->GetScrollableArea();
  EXPECT_NE(nullptr, scrollable_area);

  // We should have a composited layer for scrolling due to will-change.
  WebLayer* web_scroll_layer =
      scrollable_area->LayerForScrolling()->PlatformLayer();
  EXPECT_NE(nullptr, web_scroll_layer);

  // Ensure a synthetic impl-side scroll offset propagates to the scrollable
  // area using the DidScroll callback.
  EXPECT_EQ(ScrollOffset(), scrollable_area->GetScrollOffset());
  web_scroll_layer->SetScrollOffsetFromImplSideForTesting(
      gfx::ScrollOffset(0, 1));
  web_view->UpdateAllLifecyclePhases();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());

  // Make the scrollable area non-scrollable.
  scrollable->setAttribute(HTMLNames::styleAttr, "overflow: visible");

  // Update layout without updating compositing state.
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();
  frame->ExecuteScript(
      WebScriptSource("var forceLayoutFromScript = scrollable.offsetTop;"));
  EXPECT_EQ(document->Lifecycle().GetState(), DocumentLifecycle::kLayoutClean);

  EXPECT_EQ(nullptr,
            ToLayoutBox(scrollable->GetLayoutObject())->GetScrollableArea());

  // The web scroll layer has not been deleted yet and we should be able to
  // apply impl-side offsets without crashing.
  web_scroll_layer->SetScrollOffsetFromImplSideForTesting(
      gfx::ScrollOffset(0, 3));
}

class SlimmingPaintWebFrameTest : public PaintTestConfigurations,
                                  public WebFrameTest {
 public:
  void SetUp() override {
    web_view_helper_ = std::make_unique<FrameTestHelpers::WebViewHelper>();
    web_view_helper_->Initialize(nullptr, &web_view_client_, nullptr,
                                 &ConfigureCompositingWebView);
    web_view_helper_->Resize(WebSize(200, 200));

    // The paint artifact compositor should have been created as part of the
    // web view helper setup.
    DCHECK(paint_artifact_compositor());
    paint_artifact_compositor()->EnableExtraDataForTesting();
  }

  WebLocalFrame* LocalMainFrame() { return web_view_helper_->LocalMainFrame(); }

  LocalFrameView* GetLocalFrameView() {
    return web_view_helper_->LocalMainFrame()->GetFrameView();
  }

  WebViewImpl* WebView() { return web_view_helper_->GetWebView(); }

  size_t ContentLayerCount() {
    return paint_artifact_compositor()
        ->GetExtraDataForTesting()
        ->content_layers.size();
  }

  size_t ScrollHitTestLayerCount() {
    return paint_artifact_compositor()
        ->GetExtraDataForTesting()
        ->scroll_hit_test_layers.size();
  }

  std::unique_ptr<WebLayer> ContentLayerAt(unsigned index) {
    return paint_artifact_compositor()
        ->GetExtraDataForTesting()
        ->ContentWebLayerAt(index);
  }

  std::unique_ptr<WebLayer> ScrollHitTestLayerAt(unsigned index) {
    return paint_artifact_compositor()
        ->GetExtraDataForTesting()
        ->ScrollHitTestWebLayerAt(index);
  }

 private:
  PaintArtifactCompositor* paint_artifact_compositor() {
    return GetLocalFrameView()->GetPaintArtifactCompositorForTesting();
  }
  FrameTestHelpers::TestWebViewClient web_view_client_;
  std::unique_ptr<FrameTestHelpers::WebViewHelper> web_view_helper_;
};

INSTANTIATE_TEST_CASE_P(All,
                        SlimmingPaintWebFrameTest,
                        testing::ValuesIn(kSlimmingPaintV2TestConfigurations));

TEST_P(SlimmingPaintWebFrameTest, DidScrollCallbackAfterScrollableAreaChanges) {
  DCHECK(RuntimeEnabledFeatures::SlimmingPaintV2Enabled());

  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(),
                     "<style>"
                     "  #scrollable {"
                     "    height: 100px;"
                     "    width: 100px;"
                     "    overflow: scroll;"
                     "    will-change: transform;"
                     "  }"
                     "  #forceScroll { height: 120px; width: 50px; }"
                     "</style>"
                     "<div id='scrollable'>"
                     "  <div id='forceScroll'></div>"
                     "</div>");

  WebView()->UpdateAllLifecyclePhases();

  Document* document = WebView()->MainFrameImpl()->GetFrame()->GetDocument();
  Element* scrollable = document->getElementById("scrollable");

  auto* scrollable_area =
      ToLayoutBox(scrollable->GetLayoutObject())->GetScrollableArea();
  EXPECT_NE(nullptr, scrollable_area);

  EXPECT_EQ(ContentLayerCount(), 2u);
  EXPECT_EQ(ScrollHitTestLayerCount(), 1u);

  // Ensure a synthetic impl-side scroll offset propagates to the scrollable
  // area using the DidScroll callback.
  EXPECT_EQ(ScrollOffset(), scrollable_area->GetScrollOffset());
  ScrollHitTestLayerAt(0)->SetScrollOffsetFromImplSideForTesting(
      gfx::ScrollOffset(0, 1));
  WebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());

  // Make the scrollable area non-scrollable.
  scrollable->setAttribute(HTMLNames::styleAttr, "overflow: visible");

  // Update layout without updating compositing state.
  LocalMainFrame()->ExecuteScript(
      WebScriptSource("var forceLayoutFromScript = scrollable.offsetTop;"));
  EXPECT_EQ(document->Lifecycle().GetState(), DocumentLifecycle::kLayoutClean);

  EXPECT_EQ(nullptr,
            ToLayoutBox(scrollable->GetLayoutObject())->GetScrollableArea());

  // The web scroll layer has not been deleted yet and we should be able to
  // apply impl-side offsets without crashing.
  EXPECT_EQ(ScrollHitTestLayerCount(), 1u);
  ScrollHitTestLayerAt(0)->SetScrollOffsetFromImplSideForTesting(
      gfx::ScrollOffset(0, 3));

  WebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(ContentLayerCount(), 1u);
  EXPECT_EQ(ScrollHitTestLayerCount(), 0u);
}

TEST_P(SlimmingPaintWebFrameTest, FrameViewScroll) {
  DCHECK(RuntimeEnabledFeatures::SlimmingPaintV2Enabled());

  InitializeWithHTML(*WebView()->MainFrameImpl()->GetFrame(),
                     "<style>"
                     "  #forceScroll {"
                     "    height: 2000px;"
                     "    width: 100px;"
                     "  }"
                     "</style>"
                     "<div id='forceScroll'></div>");

  WebView()->UpdateAllLifecyclePhases();

  auto* scrollable_area = GetLocalFrameView()->LayoutViewportScrollableArea();
  EXPECT_NE(nullptr, scrollable_area);

  EXPECT_EQ(ScrollHitTestLayerCount(), 1u);

  // Ensure a synthetic impl-side scroll offset propagates to the scrollable
  // area using the DidScroll callback.
  EXPECT_EQ(ScrollOffset(), scrollable_area->GetScrollOffset());
  ScrollHitTestLayerAt(0)->SetScrollOffsetFromImplSideForTesting(
      gfx::ScrollOffset(0, 1));
  WebView()->UpdateAllLifecyclePhases();
  EXPECT_EQ(ScrollOffset(0, 1), scrollable_area->GetScrollOffset());
}

static void TestFramePrinting(WebLocalFrameImpl* frame) {
  WebPrintParams print_params;
  WebSize page_size(500, 500);
  print_params.print_content_area.width = page_size.width;
  print_params.print_content_area.height = page_size.height;
  EXPECT_EQ(1, frame->PrintBegin(print_params, WebNode()));
  PaintRecorder recorder;
  frame->PrintPagesForTesting(recorder.beginRecording(IntRect()), page_size);
  frame->PrintEnd();
}

TEST_P(ParameterizedWebFrameTest, PrintDetachedIframe) {
  RegisterMockedHttpURLLoad("print-detached-iframe.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "print-detached-iframe.html");
  TestFramePrinting(
      ToWebLocalFrameImpl(web_view_helper.LocalMainFrame()->FirstChild()));
}

TEST_P(ParameterizedWebFrameTest, PrintIframeUnderDetached) {
  RegisterMockedHttpURLLoad("print-detached-iframe.html");
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "print-detached-iframe.html");
  TestFramePrinting(ToWebLocalFrameImpl(
      web_view_helper.LocalMainFrame()->FirstChild()->FirstChild()));
}

TEST_F(WebFrameTest, ExecuteCommandProducesUserGesture) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();

  EXPECT_FALSE(frame->GetFrame()->HasBeenActivated());
  frame->ExecuteScript(WebScriptSource(WebString("document.execCommand('copy');")));
  EXPECT_FALSE(frame->GetFrame()->HasBeenActivated());
  frame->ExecuteCommand(WebString::FromUTF8("Paste"));
  EXPECT_TRUE(frame->GetFrame()->HasBeenActivated());
}

TEST_F(WebFrameTest, GetCanonicalUrlForSharingNone) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  EXPECT_TRUE(frame->GetDocument().CanonicalUrlForSharing().IsNull());
}

TEST_F(WebFrameTest, GetCanonicalUrlForSharingNotInHead) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  FrameTestHelpers::LoadHTMLString(
      frame, R"(
    <body>
      <link rel="canonical" href="https://example.com/canonical.html">
    </body>)", ToKURL("https://example.com/test_page.html"));
  EXPECT_TRUE(frame->GetDocument().CanonicalUrlForSharing().IsNull());
}

TEST_F(WebFrameTest, GetCanonicalUrlForSharing) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  FrameTestHelpers::LoadHTMLString(
      frame, R"(
    <head>
      <link rel="canonical" href="https://example.com/canonical.html">
    </head>)", ToKURL("https://example.com/test_page.html"));
  EXPECT_EQ(WebURL(ToKURL("https://example.com/canonical.html")),
            frame->GetDocument().CanonicalUrlForSharing());
}

TEST_F(WebFrameTest, GetCanonicalUrlForSharingMultiple) {
  FrameTestHelpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  FrameTestHelpers::LoadHTMLString(
      frame, R"(
    <head>
      <link rel="canonical" href="https://example.com/canonical1.html">
      <link rel="canonical" href="https://example.com/canonical2.html">
    </head>)", ToKURL("https://example.com/test_page.html"));
  EXPECT_EQ(WebURL(ToKURL("https://example.com/canonical1.html")),
            frame->GetDocument().CanonicalUrlForSharing());
}

}  // namespace blink

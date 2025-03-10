// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/renderer_host/render_widget_host_view_child_frame.h"

#include "base/macros.h"
#include "base/run_loop.h"
#include "components/viz/common/surfaces/surface_id.h"
#include "content/browser/frame_host/frame_tree_node.h"
#include "content/browser/web_contents/web_contents_impl.h"
#include "content/common/frame_messages.h"
#include "content/common/view_messages.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/content_browser_test.h"
#include "content/public/test/content_browser_test_utils.h"
#include "content/public/test/test_utils.h"
#include "content/shell/browser/shell.h"
#include "content/test/content_browser_test_utils_internal.h"
#include "content/test/test_content_browser_client.h"
#include "net/dns/mock_host_resolver.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/geometry/size.h"

namespace content {

class RenderWidgetHostViewChildFrameTest : public ContentBrowserTest {
 public:
  RenderWidgetHostViewChildFrameTest() {}

  void SetUpCommandLine(base::CommandLine* command_line) override {
    IsolateAllSitesForTesting(command_line);
  }

  void SetUpOnMainThread() override {
    host_resolver()->AddRule("*", "127.0.0.1");
    SetupCrossSiteRedirector(embedded_test_server());
    ASSERT_TRUE(embedded_test_server()->Start());
  }

  void CheckScreenWidth(RenderFrameHost* render_frame_host) {
    int width;
    ExecuteScriptAndGetValue(render_frame_host, "window.screen.width")
        ->GetAsInteger(&width);
    EXPECT_EQ(expected_screen_width_, width);
  }

  // Tests that the FrameSinkId of each child frame has been updated by the
  // RenderFrameProxy.
  void CheckFrameSinkId(RenderFrameHost* render_frame_host) {
    RenderWidgetHostViewBase* child_view =
        static_cast<RenderFrameHostImpl*>(render_frame_host)
            ->GetRenderWidgetHost()
            ->GetView();
    // Only interested in updated FrameSinkIds on child frames.
    if (!child_view || !child_view->IsRenderWidgetHostViewChildFrame())
      return;

    // Ensure that the received viz::FrameSinkId was correctly set on the child
    // frame.
    viz::FrameSinkId actual_frame_sink_id_ = child_view->GetFrameSinkId();
    EXPECT_EQ(expected_frame_sink_id_, actual_frame_sink_id_);

    // The viz::FrameSinkID will be replaced while the test blocks for
    // navigation. It should differ from the information stored in the child's
    // RenderWidgetHost.
    EXPECT_NE(base::checked_cast<uint32_t>(
                  child_view->GetRenderWidgetHost()->GetProcess()->GetID()),
              actual_frame_sink_id_.client_id());
    EXPECT_NE(base::checked_cast<uint32_t>(
                  child_view->GetRenderWidgetHost()->GetRoutingID()),
              actual_frame_sink_id_.sink_id());
  }

  void set_expected_frame_sink_id(viz::FrameSinkId frame_sink_id) {
    expected_frame_sink_id_ = frame_sink_id;
  }

  void set_expected_screen_width(int width) { expected_screen_width_ = width; }

 private:
  viz::FrameSinkId expected_frame_sink_id_;
  int expected_screen_width_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetHostViewChildFrameTest);
};

// Tests that the screen is properly reflected for RWHVChildFrame.
IN_PROC_BROWSER_TEST_F(RenderWidgetHostViewChildFrameTest, Screen) {
  GURL main_url(embedded_test_server()->GetURL("/site_per_process_main.html"));
  NavigateToURL(shell(), main_url);

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  // Load cross-site page into iframe.
  GURL cross_site_url(
      embedded_test_server()->GetURL("foo.com", "/title2.html"));
  NavigateFrameToURL(root->child_at(0), cross_site_url);

  int main_frame_screen_width = 0;
  ExecuteScriptAndGetValue(shell()->web_contents()->GetMainFrame(),
                           "window.screen.width")
      ->GetAsInteger(&main_frame_screen_width);
  set_expected_screen_width(main_frame_screen_width);
  EXPECT_NE(main_frame_screen_width, 0);

  shell()->web_contents()->ForEachFrame(
      base::BindRepeating(&RenderWidgetHostViewChildFrameTest::CheckScreenWidth,
                          base::Unretained(this)));
}

// Test that auto-resize sizes in the top frame are propagated to OOPIF
// RenderWidgetHostViews. See https://crbug.com/726743.
IN_PROC_BROWSER_TEST_F(RenderWidgetHostViewChildFrameTest,
                       ChildFrameAutoResizeUpdate) {
  EXPECT_TRUE(NavigateToURL(
      shell(), embedded_test_server()->GetURL(
                   "a.com", "/cross_site_iframe_factory.html?a(b)")));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  root->current_frame_host()
      ->GetRenderWidgetHost()
      ->GetView()
      ->EnableAutoResize(gfx::Size(0, 0), gfx::Size(100, 100));

  RenderWidgetHostView* rwhv =
      root->child_at(0)->current_frame_host()->GetRenderWidgetHost()->GetView();

  // Fake an auto-resize update from the parent renderer.
  int routing_id =
      root->current_frame_host()->GetRenderWidgetHost()->GetRoutingID();
  ViewHostMsg_ResizeOrRepaint_ACK_Params params;
  params.view_size = gfx::Size(75, 75);
  params.flags = 0;
  params.child_allocated_local_surface_id =
      viz::LocalSurfaceId(10, 10, base::UnguessableToken::Create());
  root->current_frame_host()->GetRenderWidgetHost()->OnMessageReceived(
      ViewHostMsg_ResizeOrRepaint_ACK(routing_id, params));

  // RenderWidgetHostImpl has delayed auto-resize processing. Yield here to
  // let it complete.
  base::RunLoop run_loop;
  base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                                run_loop.QuitClosure());
  run_loop.Run();

  // The child frame's RenderWidgetHostView should now use the auto-resize value
  // for its visible viewport.
  EXPECT_EQ(gfx::Size(75, 75), rwhv->GetVisibleViewportSize());
}

// Tests that while in mus, the child frame receives an updated FrameSinkId
// representing the frame sink used by the RenderFrameProxy.
IN_PROC_BROWSER_TEST_F(RenderWidgetHostViewChildFrameTest, ChildFrameSinkId) {
  // Only when mus hosts viz do we expect a RenderFrameProxy to provide the
  // FrameSinkId.
  if (!base::FeatureList::IsEnabled(features::kMash))
    return;

  GURL main_url(embedded_test_server()->GetURL("/site_per_process_main.html"));
  NavigateToURL(shell(), main_url);

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  scoped_refptr<UpdateResizeParamsMessageFilter> message_filter(
      new UpdateResizeParamsMessageFilter());
  root->current_frame_host()->GetProcess()->AddFilter(message_filter.get());

  // Load cross-site page into iframe.
  GURL cross_site_url(
      embedded_test_server()->GetURL("foo.com", "/title2.html"));
  // The child frame is created during this blocking call, on the UI thread.
  // This is racing the IPC we are testing for, which arrives on the IO thread.
  // Due to this we cannot get the pre-IPC value of the viz::FrameSinkId.
  NavigateFrameToURL(root->child_at(0), cross_site_url);

  // Ensure that the IPC providing the new viz::FrameSinkId. If it does not then
  // this test will timeout.
  set_expected_frame_sink_id(message_filter->GetOrWaitForId());

  shell()->web_contents()->ForEachFrame(
      base::BindRepeating(&RenderWidgetHostViewChildFrameTest::CheckFrameSinkId,
                          base::Unretained(this)));
}

// Test that auto-resize messages only trigger a single allocation/response
// from the child.
IN_PROC_BROWSER_TEST_F(RenderWidgetHostViewChildFrameTest,
                       ChildFrameAutoResizeMessages) {
  EXPECT_TRUE(NavigateToURL(
      shell(), embedded_test_server()->GetURL(
                   "a.com", "/cross_site_iframe_factory.html?a(b)")));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  // Create our message filter to intercept messages.
  scoped_refptr<UpdateResizeParamsMessageFilter> message_filter =
      new UpdateResizeParamsMessageFilter();
  root->current_frame_host()->GetProcess()->AddFilter(message_filter.get());

  // Load cross-site page into iframe.
  GURL cross_site_url(
      embedded_test_server()->GetURL("foo.com", "/title2.html"));
  // The child frame is created during this blocking call, on the UI thread.
  // This is racing the IPC we are testing for, which arrives on the IO thread.
  // Due to this we cannot get the pre-IPC value of the viz::FrameSinkId.
  NavigateFrameToURL(root->child_at(0), cross_site_url);

  RenderWidgetHostImpl* child_frame_impl =
      root->child_at(0)->current_frame_host()->GetRenderWidgetHost();
  child_frame_impl->SetAutoResize(true, gfx::Size(10, 10), gfx::Size(100, 100));

  // Fake an auto-resize update from the parent renderer.
  int routing_id = root->child_at(0)
                       ->current_frame_host()
                       ->GetRenderWidgetHost()
                       ->GetRoutingID();
  ViewHostMsg_ResizeOrRepaint_ACK_Params params;
  params.view_size = gfx::Size(75, 75);
  params.flags = 0;
  params.sequence_number = 7;
  viz::LocalSurfaceId current_id =
      child_frame_impl->GetView()->GetLocalSurfaceId();
  params.child_allocated_local_surface_id = viz::LocalSurfaceId(
      current_id.parent_sequence_number(),
      current_id.child_sequence_number() + 1, current_id.embed_token());
  child_frame_impl->OnMessageReceived(
      ViewHostMsg_ResizeOrRepaint_ACK(routing_id, params));

  // The first UpdateResizeParams message received should have our new sequence
  // number.
  EXPECT_EQ(params.sequence_number, message_filter->WaitForSequenceNumber());
}

}  // namespace content

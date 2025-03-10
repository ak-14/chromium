// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/devtools/protocol/page_handler.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/base64.h"
#include "base/bind.h"
#include "base/location.h"
#include "base/memory/ref_counted.h"
#include "base/memory/ref_counted_memory.h"
#include "base/process/process_handle.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "components/viz/common/features.h"
#include "content/browser/devtools/devtools_session.h"
#include "content/browser/devtools/protocol/devtools_download_manager_delegate.h"
#include "content/browser/devtools/protocol/devtools_download_manager_helper.h"
#include "content/browser/devtools/protocol/emulation_handler.h"
#include "content/browser/frame_host/navigation_request.h"
#include "content/browser/frame_host/navigator.h"
#include "content/browser/manifest/manifest_manager_host.h"
#include "content/browser/renderer_host/render_widget_host_impl.h"
#include "content/browser/renderer_host/render_widget_host_view_base.h"
#include "content/browser/web_contents/web_contents_impl.h"
#include "content/browser/web_contents/web_contents_view.h"
#include "content/common/view_messages.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/download_manager.h"
#include "content/public/browser/javascript_dialog_manager.h"
#include "content/public/browser/navigation_controller.h"
#include "content/public/browser/navigation_entry.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/render_widget_host.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/browser/web_contents_delegate.h"
#include "content/public/common/browser_side_navigation_policy.h"
#include "content/public/common/referrer.h"
#include "content/public/common/result_codes.h"
#include "content/public/common/use_zoom_for_dsf_policy.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "ui/base/page_transition_types.h"
#include "ui/gfx/codec/jpeg_codec.h"
#include "ui/gfx/codec/png_codec.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/image/image.h"
#include "ui/gfx/image/image_util.h"
#include "ui/gfx/skbitmap_operations.h"
#include "ui/snapshot/snapshot.h"

namespace content {
namespace protocol {

namespace {

constexpr const char* kPng = "png";
constexpr const char* kJpeg = "jpeg";
constexpr int kDefaultScreenshotQuality = 80;
constexpr int kFrameRetryDelayMs = 100;
constexpr int kCaptureRetryLimit = 2;
constexpr int kMaxScreencastFramesInFlight = 2;

std::string EncodeImage(const gfx::Image& image,
                        const std::string& format,
                        int quality) {
  DCHECK(!image.IsEmpty());

  scoped_refptr<base::RefCountedMemory> data;
  if (format == kPng) {
    data = image.As1xPNGBytes();
  } else if (format == kJpeg) {
    scoped_refptr<base::RefCountedBytes> bytes(new base::RefCountedBytes());
    if (gfx::JPEG1xEncodedDataFromImage(image, quality, &bytes->data()))
      data = bytes;
  }

  if (!data || !data->front())
    return std::string();

  std::string base_64_data;
  base::Base64Encode(
      base::StringPiece(reinterpret_cast<const char*>(data->front()),
                        data->size()),
      &base_64_data);

  return base_64_data;
}

std::string EncodeSkBitmap(const SkBitmap& image,
                           const std::string& format,
                           int quality) {
  return EncodeImage(gfx::Image::CreateFrom1xBitmap(image), format, quality);
}

std::unique_ptr<Page::ScreencastFrameMetadata> BuildScreencastFrameMetadata(
    const gfx::Size& surface_size,
    float device_scale_factor,
    float page_scale_factor,
    const gfx::Vector2dF& root_scroll_offset,
    float top_controls_height,
    float top_controls_shown_ratio) {
  if (surface_size.IsEmpty() || device_scale_factor == 0)
    return nullptr;

  const gfx::SizeF content_size_dip =
      gfx::ScaleSize(gfx::SizeF(surface_size), 1 / device_scale_factor);
  float top_offset_dip = top_controls_height * top_controls_shown_ratio;
  if (IsUseZoomForDSFEnabled())
    top_offset_dip /= device_scale_factor;
  std::unique_ptr<Page::ScreencastFrameMetadata> page_metadata =
      Page::ScreencastFrameMetadata::Create()
          .SetPageScaleFactor(page_scale_factor)
          .SetOffsetTop(top_offset_dip)
          .SetDeviceWidth(content_size_dip.width())
          .SetDeviceHeight(content_size_dip.height())
          .SetScrollOffsetX(root_scroll_offset.x())
          .SetScrollOffsetY(root_scroll_offset.y())
          .SetTimestamp(base::Time::Now().ToDoubleT())
          .Build();
  return page_metadata;
}

// Determines the snapshot size that best-fits the Surface's content to the
// remote's requested image size.
gfx::Size DetermineSnapshotSize(const gfx::Size& surface_size,
                                int screencast_max_width,
                                int screencast_max_height) {
  if (surface_size.IsEmpty())
    return gfx::Size();  // Nothing to copy (and avoid divide-by-zero below).

  double scale = 1;
  if (screencast_max_width > 0) {
    scale = std::min(scale, static_cast<double>(screencast_max_width) /
                                surface_size.width());
  }
  if (screencast_max_height > 0) {
    scale = std::min(scale, static_cast<double>(screencast_max_height) /
                                surface_size.height());
  }
  return gfx::ToRoundedSize(gfx::ScaleSize(gfx::SizeF(surface_size), scale));
}

#if !defined(OS_ANDROID)
void GetMetadataFromFrame(const media::VideoFrame& frame,
                          double* device_scale_factor,
                          double* page_scale_factor,
                          gfx::Vector2dF* root_scroll_offset) {
  // Get metadata from |frame| and ensure that no metadata is missing.
  bool success = true;
  double root_scroll_offset_x, root_scroll_offset_y;
  success &= frame.metadata()->GetDouble(
      media::VideoFrameMetadata::DEVICE_SCALE_FACTOR, device_scale_factor);
  success &= frame.metadata()->GetDouble(
      media::VideoFrameMetadata::PAGE_SCALE_FACTOR, page_scale_factor);
  success &= frame.metadata()->GetDouble(
      media::VideoFrameMetadata::ROOT_SCROLL_OFFSET_X, &root_scroll_offset_x);
  success &= frame.metadata()->GetDouble(
      media::VideoFrameMetadata::ROOT_SCROLL_OFFSET_Y, &root_scroll_offset_y);
  DCHECK(success);

  root_scroll_offset->set_x(root_scroll_offset_x);
  root_scroll_offset->set_y(root_scroll_offset_y);
}
#endif  // !defined(OS_ANDROID)

}  // namespace

PageHandler::PageHandler(EmulationHandler* emulation_handler)
    : DevToolsDomainHandler(Page::Metainfo::domainName),
      enabled_(false),
      screencast_enabled_(false),
      screencast_quality_(kDefaultScreenshotQuality),
      screencast_max_width_(-1),
      screencast_max_height_(-1),
      capture_every_nth_frame_(1),
      capture_retry_count_(0),
      has_compositor_frame_metadata_(false),
      session_id_(0),
      frame_counter_(0),
      frames_in_flight_(0),
#if !defined(OS_ANDROID)
      video_consumer_(nullptr),
      last_surface_size_(gfx::Size()),
#endif  // !defined(OS_ANDROID)
      host_(nullptr),
      emulation_handler_(emulation_handler),
      observer_(this),
      weak_factory_(this) {
#if !defined(OS_ANDROID)
  if (base::FeatureList::IsEnabled(features::kVizDisplayCompositor)) {
    video_consumer_ = std::make_unique<DevToolsVideoConsumer>(
        base::BindRepeating(&PageHandler::OnFrameFromVideoConsumer,
                            weak_factory_.GetWeakPtr()));
  }
#endif  // !defined(OS_ANDROID)
  DCHECK(emulation_handler_);
}

PageHandler::~PageHandler() {
}

// static
std::vector<PageHandler*> PageHandler::EnabledForWebContents(
    WebContentsImpl* contents) {
  if (!DevToolsAgentHost::HasFor(contents))
    return std::vector<PageHandler*>();
  std::vector<PageHandler*> result;
  for (auto* handler :
       PageHandler::ForAgentHost(static_cast<DevToolsAgentHostImpl*>(
           DevToolsAgentHost::GetOrCreateFor(contents).get()))) {
    if (handler->enabled_)
      result.push_back(handler);
  }
  return result;
}

// static
std::vector<PageHandler*> PageHandler::ForAgentHost(
    DevToolsAgentHostImpl* host) {
  return DevToolsSession::HandlersForAgentHost<PageHandler>(
      host, Page::Metainfo::domainName);
}

void PageHandler::SetRenderer(int process_host_id,
                              RenderFrameHostImpl* frame_host) {
  if (host_ == frame_host)
    return;

  RenderWidgetHostImpl* widget_host =
      host_ ? host_->GetRenderWidgetHost() : nullptr;
  if (widget_host && observer_.IsObserving(widget_host))
    observer_.Remove(widget_host);

  host_ = frame_host;
  widget_host = host_ ? host_->GetRenderWidgetHost() : nullptr;

  if (widget_host)
    observer_.Add(widget_host);

#if !defined(OS_ANDROID)
  if (video_consumer_ && frame_host) {
    video_consumer_->SetFrameSinkId(
        frame_host->GetRenderWidgetHost()->GetFrameSinkId());
  }
#endif  // !defined(OS_ANDROID)
}

void PageHandler::Wire(UberDispatcher* dispatcher) {
  frontend_.reset(new Page::Frontend(dispatcher->channel()));
  Page::Dispatcher::wire(dispatcher, this);
}

void PageHandler::OnSwapCompositorFrame(
    viz::CompositorFrameMetadata frame_metadata) {
  last_compositor_frame_metadata_ = std::move(frame_metadata);
  has_compositor_frame_metadata_ = true;

  if (screencast_enabled_)
    InnerSwapCompositorFrame();
}

void PageHandler::OnSynchronousSwapCompositorFrame(
    viz::CompositorFrameMetadata frame_metadata) {
  if (has_compositor_frame_metadata_) {
    last_compositor_frame_metadata_ =
        std::move(next_compositor_frame_metadata_);
  } else {
    last_compositor_frame_metadata_ = frame_metadata.Clone();
  }
  next_compositor_frame_metadata_ = std::move(frame_metadata);

  has_compositor_frame_metadata_ = true;

  if (screencast_enabled_)
    InnerSwapCompositorFrame();
}

void PageHandler::RenderWidgetHostVisibilityChanged(
    RenderWidgetHost* widget_host,
    bool became_visible) {
  if (!screencast_enabled_)
    return;
  NotifyScreencastVisibility(became_visible);
}

void PageHandler::RenderWidgetHostDestroyed(RenderWidgetHost* widget_host) {
  observer_.Remove(widget_host);
}

void PageHandler::DidAttachInterstitialPage() {
  if (!enabled_)
    return;
  frontend_->InterstitialShown();
}

void PageHandler::DidDetachInterstitialPage() {
  if (!enabled_)
    return;
  frontend_->InterstitialHidden();
}

void PageHandler::DidRunJavaScriptDialog(const GURL& url,
                                         const base::string16& message,
                                         const base::string16& default_prompt,
                                         JavaScriptDialogType dialog_type,
                                         bool has_non_devtools_handlers,
                                         JavaScriptDialogCallback callback) {
  if (!enabled_)
    return;
  DCHECK(pending_dialog_.is_null());
  pending_dialog_ = std::move(callback);
  std::string type = Page::DialogTypeEnum::Alert;
  if (dialog_type == JAVASCRIPT_DIALOG_TYPE_CONFIRM)
    type = Page::DialogTypeEnum::Confirm;
  if (dialog_type == JAVASCRIPT_DIALOG_TYPE_PROMPT)
    type = Page::DialogTypeEnum::Prompt;
  frontend_->JavascriptDialogOpening(url.spec(), base::UTF16ToUTF8(message),
                                     type, has_non_devtools_handlers,
                                     base::UTF16ToUTF8(default_prompt));
}

void PageHandler::DidRunBeforeUnloadConfirm(const GURL& url,
                                            bool has_non_devtools_handlers,
                                            JavaScriptDialogCallback callback) {
  if (!enabled_)
    return;
  DCHECK(pending_dialog_.is_null());
  pending_dialog_ = std::move(callback);
  frontend_->JavascriptDialogOpening(url.spec(), std::string(),
                                     Page::DialogTypeEnum::Beforeunload,
                                     has_non_devtools_handlers, std::string());
}

void PageHandler::DidCloseJavaScriptDialog(bool success,
                                           const base::string16& user_input) {
  if (!enabled_)
    return;
  pending_dialog_.Reset();
  frontend_->JavascriptDialogClosed(success, base::UTF16ToUTF8(user_input));
}

Response PageHandler::Enable() {
  enabled_ = true;
  if (GetWebContents() && GetWebContents()->ShowingInterstitialPage())
    frontend_->InterstitialShown();
  return Response::FallThrough();
}

Response PageHandler::Disable() {
  enabled_ = false;
  screencast_enabled_ = false;

#if !defined(OS_ANDROID)
  if (video_consumer_)
    video_consumer_->StopCapture();
#endif  // !defined(OS_ANDROID)

  if (!pending_dialog_.is_null()) {
    WebContentsImpl* web_contents = GetWebContents();
    // Leave dialog hanging if there is a manager that can take care of it,
    // cancel and send ack otherwise.
    bool has_dialog_manager =
        web_contents && web_contents->GetDelegate() &&
        web_contents->GetDelegate()->GetJavaScriptDialogManager(web_contents);
    if (!has_dialog_manager)
      std::move(pending_dialog_).Run(false, base::string16());
    pending_dialog_.Reset();
  }

  download_manager_delegate_ = nullptr;
  navigate_callbacks_.clear();
  return Response::FallThrough();
}

Response PageHandler::Crash() {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents)
    return Response::Error("Not attached to a page");
  if (web_contents->IsCrashed())
    return Response::Error("The target has already crashed");
  if (web_contents->GetMainFrame()->frame_tree_node()->navigation_request())
    return Response::Error("Page has pending navigations, not killing");
  return Response::FallThrough();
}

Response PageHandler::Close() {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents)
    return Response::Error("Not attached to a page");
  web_contents->DispatchBeforeUnload();
  return Response::OK();
}

Response PageHandler::Reload(Maybe<bool> bypassCache,
                             Maybe<std::string> script_to_evaluate_on_load) {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents)
    return Response::InternalError();
  if (web_contents->IsCrashed() ||
      web_contents->GetURL().scheme() == url::kDataScheme ||
      (web_contents->GetController().GetVisibleEntry() &&
       web_contents->GetController().GetVisibleEntry()->IsViewSourceMode())) {
    web_contents->GetController().Reload(bypassCache.fromMaybe(false)
                                             ? ReloadType::BYPASSING_CACHE
                                             : ReloadType::NORMAL,
                                         false);
    return Response::OK();
  } else {
    // Handle reload in renderer except for crashed and view source mode.
    return Response::FallThrough();
  }
}

void PageHandler::Navigate(const std::string& url,
                           Maybe<std::string> referrer,
                           Maybe<std::string> maybe_transition_type,
                           Maybe<std::string> frame_id,
                           std::unique_ptr<NavigateCallback> callback) {
  GURL gurl(url);
  if (!gurl.is_valid()) {
    callback->sendFailure(Response::Error("Cannot navigate to invalid URL"));
    return;
  }

  if (!host_) {
    callback->sendFailure(Response::InternalError());
    return;
  }

  ui::PageTransition type;
  std::string transition_type =
      maybe_transition_type.fromMaybe(Page::TransitionTypeEnum::Typed);
  if (transition_type == Page::TransitionTypeEnum::Link)
    type = ui::PAGE_TRANSITION_LINK;
  else if (transition_type == Page::TransitionTypeEnum::Typed)
    type = ui::PAGE_TRANSITION_TYPED;
  else if (transition_type == Page::TransitionTypeEnum::Auto_bookmark)
    type = ui::PAGE_TRANSITION_AUTO_BOOKMARK;
  else if (transition_type == Page::TransitionTypeEnum::Auto_subframe)
    type = ui::PAGE_TRANSITION_AUTO_SUBFRAME;
  else if (transition_type == Page::TransitionTypeEnum::Manual_subframe)
    type = ui::PAGE_TRANSITION_MANUAL_SUBFRAME;
  else if (transition_type == Page::TransitionTypeEnum::Generated)
    type = ui::PAGE_TRANSITION_GENERATED;
  else if (transition_type == Page::TransitionTypeEnum::Auto_toplevel)
    type = ui::PAGE_TRANSITION_AUTO_TOPLEVEL;
  else if (transition_type == Page::TransitionTypeEnum::Form_submit)
    type = ui::PAGE_TRANSITION_FORM_SUBMIT;
  else if (transition_type == Page::TransitionTypeEnum::Reload)
    type = ui::PAGE_TRANSITION_RELOAD;
  else if (transition_type == Page::TransitionTypeEnum::Keyword)
    type = ui::PAGE_TRANSITION_KEYWORD;
  else if (transition_type == Page::TransitionTypeEnum::Keyword_generated)
    type = ui::PAGE_TRANSITION_KEYWORD_GENERATED;
  else
    type = ui::PAGE_TRANSITION_TYPED;

  FrameTreeNode* frame_tree_node = nullptr;
  std::string out_frame_id = frame_id.fromMaybe(
      host_->frame_tree_node()->devtools_frame_token().ToString());
  FrameTreeNode* root = host_->frame_tree_node();
  if (root->devtools_frame_token().ToString() == out_frame_id) {
    frame_tree_node = root;
  } else {
    for (FrameTreeNode* node : root->frame_tree()->SubtreeNodes(root)) {
      if (node->devtools_frame_token().ToString() == out_frame_id) {
        frame_tree_node = node;
        break;
      }
    }
  }

  if (!frame_tree_node) {
    callback->sendFailure(Response::Error("No frame with given id found"));
    return;
  }

  NavigationController::LoadURLParams params(gurl);
  params.referrer =
      Referrer(GURL(referrer.fromMaybe("")), blink::kWebReferrerPolicyDefault);
  params.transition_type = type;
  params.frame_tree_node_id = frame_tree_node->frame_tree_node_id();
  frame_tree_node->navigator()->GetController()->LoadURLWithParams(params);

  base::UnguessableToken frame_token = frame_tree_node->devtools_frame_token();
  auto navigate_callback = navigate_callbacks_.find(frame_token);
  if (navigate_callback != navigate_callbacks_.end()) {
    std::string error_string = net::ErrorToString(net::ERR_ABORTED);
    navigate_callback->second->sendSuccess(out_frame_id, Maybe<std::string>(),
                                           Maybe<std::string>(error_string));
  }
  if (frame_tree_node->navigation_request()) {
    navigate_callbacks_[frame_token] = std::move(callback);
  } else {
    callback->sendSuccess(out_frame_id, Maybe<std::string>(),
                          Maybe<std::string>());
  }
}

void PageHandler::NavigationReset(NavigationRequest* navigation_request) {
  auto navigate_callback = navigate_callbacks_.find(
      navigation_request->frame_tree_node()->devtools_frame_token());
  if (navigate_callback == navigate_callbacks_.end())
    return;
  std::string frame_id =
      navigation_request->frame_tree_node()->devtools_frame_token().ToString();
  bool success = navigation_request->net_error() == net::OK;
  std::string error_string =
      net::ErrorToString(navigation_request->net_error());
  navigate_callback->second->sendSuccess(
      frame_id,
      Maybe<std::string>(
          navigation_request->devtools_navigation_token().ToString()),
      success ? Maybe<std::string>() : Maybe<std::string>(error_string));
  navigate_callbacks_.erase(navigate_callback);
}

static const char* TransitionTypeName(ui::PageTransition type) {
  int32_t t = type & ~ui::PAGE_TRANSITION_QUALIFIER_MASK;
  switch (t) {
    case ui::PAGE_TRANSITION_LINK:
      return Page::TransitionTypeEnum::Link;
    case ui::PAGE_TRANSITION_TYPED:
      return Page::TransitionTypeEnum::Typed;
    case ui::PAGE_TRANSITION_AUTO_BOOKMARK:
      return Page::TransitionTypeEnum::Auto_bookmark;
    case ui::PAGE_TRANSITION_AUTO_SUBFRAME:
      return Page::TransitionTypeEnum::Auto_subframe;
    case ui::PAGE_TRANSITION_MANUAL_SUBFRAME:
      return Page::TransitionTypeEnum::Manual_subframe;
    case ui::PAGE_TRANSITION_GENERATED:
      return Page::TransitionTypeEnum::Generated;
    case ui::PAGE_TRANSITION_AUTO_TOPLEVEL:
      return Page::TransitionTypeEnum::Auto_toplevel;
    case ui::PAGE_TRANSITION_FORM_SUBMIT:
      return Page::TransitionTypeEnum::Form_submit;
    case ui::PAGE_TRANSITION_RELOAD:
      return Page::TransitionTypeEnum::Reload;
    case ui::PAGE_TRANSITION_KEYWORD:
      return Page::TransitionTypeEnum::Keyword;
    case ui::PAGE_TRANSITION_KEYWORD_GENERATED:
      return Page::TransitionTypeEnum::Keyword_generated;
    default:
      return Page::TransitionTypeEnum::Other;
  }
}

Response PageHandler::GetNavigationHistory(
    int* current_index,
    std::unique_ptr<NavigationEntries>* entries) {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents)
    return Response::InternalError();

  NavigationController& controller = web_contents->GetController();
  *current_index = controller.GetCurrentEntryIndex();
  *entries = NavigationEntries::create();
  for (int i = 0; i != controller.GetEntryCount(); ++i) {
    auto* entry = controller.GetEntryAtIndex(i);
    (*entries)->addItem(
        Page::NavigationEntry::Create()
            .SetId(entry->GetUniqueID())
            .SetUrl(entry->GetURL().spec())
            .SetUserTypedURL(entry->GetUserTypedURL().spec())
            .SetTitle(base::UTF16ToUTF8(entry->GetTitle()))
            .SetTransitionType(TransitionTypeName(entry->GetTransitionType()))
            .Build());
  }
  return Response::OK();
}

Response PageHandler::NavigateToHistoryEntry(int entry_id) {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents)
    return Response::InternalError();

  NavigationController& controller = web_contents->GetController();
  for (int i = 0; i != controller.GetEntryCount(); ++i) {
    if (controller.GetEntryAtIndex(i)->GetUniqueID() == entry_id) {
      controller.GoToIndex(i);
      return Response::OK();
    }
  }

  return Response::InvalidParams("No entry with passed id");
}

void PageHandler::CaptureScreenshot(
    Maybe<std::string> format,
    Maybe<int> quality,
    Maybe<Page::Viewport> clip,
    Maybe<bool> from_surface,
    std::unique_ptr<CaptureScreenshotCallback> callback) {
  if (!host_ || !host_->GetRenderWidgetHost()) {
    callback->sendFailure(Response::InternalError());
    return;
  }

  RenderWidgetHostImpl* widget_host = host_->GetRenderWidgetHost();
  std::string screenshot_format = format.fromMaybe(kPng);
  int screenshot_quality = quality.fromMaybe(kDefaultScreenshotQuality);

  // We don't support clip/emulation when capturing from window, bail out.
  if (!from_surface.fromMaybe(true)) {
    widget_host->GetSnapshotFromBrowser(
        base::Bind(&PageHandler::ScreenshotCaptured, weak_factory_.GetWeakPtr(),
                   base::Passed(std::move(callback)), screenshot_format,
                   screenshot_quality, gfx::Size(), gfx::Size(),
                   blink::WebDeviceEmulationParams()),
        false);
    return;
  }

  // Welcome to the neural net of capturing screenshot while emulating device
  // metrics!
  bool emulation_enabled = emulation_handler_->device_emulation_enabled();
  blink::WebDeviceEmulationParams original_params =
      emulation_handler_->GetDeviceEmulationParams();
  blink::WebDeviceEmulationParams modified_params = original_params;

  // Capture original view size if we know we are going to destroy it. We use
  // it in ScreenshotCaptured to restore.
  gfx::Size original_view_size =
      emulation_enabled || clip.isJust()
          ? widget_host->GetView()->GetViewBounds().size()
          : gfx::Size();
  gfx::Size emulated_view_size = modified_params.view_size;

  double dpfactor = 1;
  ScreenInfo screen_info;
  widget_host->GetScreenInfo(&screen_info);
  if (emulation_enabled) {
    // When emulating, emulate again and scale to make resulting image match
    // physical DP resolution. If view_size is not overriden, use actual view
    // size.
    float original_scale =
        original_params.scale > 0 ? original_params.scale : 1;
    if (!modified_params.view_size.width) {
      emulated_view_size.set_width(
          ceil(original_view_size.width() / original_scale));
    }
    if (!modified_params.view_size.height) {
      emulated_view_size.set_height(
          ceil(original_view_size.height() / original_scale));
    }

    dpfactor = modified_params.device_scale_factor
                   ? modified_params.device_scale_factor /
                         screen_info.device_scale_factor
                   : 1;
    // When clip is specified, we scale viewport via clip, otherwise we use
    // scale.
    modified_params.scale = clip.isJust() ? 1 : dpfactor;
    modified_params.view_size.width = emulated_view_size.width();
    modified_params.view_size.height = emulated_view_size.height();
  } else if (clip.isJust()) {
    // When not emulating, still need to emulate the page size.
    modified_params.view_size.width = original_view_size.width();
    modified_params.view_size.height = original_view_size.height();
    modified_params.screen_size.width = 0;
    modified_params.screen_size.height = 0;
    modified_params.device_scale_factor = 0;
    modified_params.scale = 1;
  }

  // Set up viewport in renderer.
  if (clip.isJust()) {
    modified_params.viewport_offset.x = clip.fromJust()->GetX();
    modified_params.viewport_offset.y = clip.fromJust()->GetY();
    modified_params.viewport_scale = clip.fromJust()->GetScale() * dpfactor;
  }

  // We use WebDeviceEmulationParams to either emulate, set viewport or both.
  emulation_handler_->SetDeviceEmulationParams(modified_params);

  // Set view size for the screenshot right after emulating.
  if (clip.isJust()) {
    double scale = dpfactor * clip.fromJust()->GetScale();
    widget_host->GetView()->SetSize(
        gfx::Size(gfx::ToRoundedInt(clip.fromJust()->GetWidth() * scale),
                  gfx::ToRoundedInt(clip.fromJust()->GetHeight() * scale)));
  } else if (emulation_enabled) {
    widget_host->GetView()->SetSize(
        gfx::ScaleToFlooredSize(emulated_view_size, dpfactor));
  }
  gfx::Size requested_image_size = gfx::Size();
  if (emulation_enabled || clip.isJust()) {
    if (clip.isJust()) {
      requested_image_size =
          gfx::Size(clip.fromJust()->GetWidth(), clip.fromJust()->GetHeight());
    } else {
      requested_image_size = emulated_view_size;
    }
    double scale = emulation_enabled ? original_params.device_scale_factor
                                     : screen_info.device_scale_factor;
    if (clip.isJust())
      scale *= clip.fromJust()->GetScale();
    requested_image_size = gfx::ScaleToRoundedSize(requested_image_size, scale);
  }

  widget_host->GetSnapshotFromBrowser(
      base::Bind(&PageHandler::ScreenshotCaptured, weak_factory_.GetWeakPtr(),
                 base::Passed(std::move(callback)), screenshot_format,
                 screenshot_quality, original_view_size, requested_image_size,
                 original_params),
      true);
}

void PageHandler::PrintToPDF(Maybe<bool> landscape,
                             Maybe<bool> display_header_footer,
                             Maybe<bool> print_background,
                             Maybe<double> scale,
                             Maybe<double> paper_width,
                             Maybe<double> paper_height,
                             Maybe<double> margin_top,
                             Maybe<double> margin_bottom,
                             Maybe<double> margin_left,
                             Maybe<double> margin_right,
                             Maybe<String> page_ranges,
                             Maybe<bool> ignore_invalid_page_ranges,
                             Maybe<String> header_template,
                             Maybe<String> footer_template,
                             Maybe<bool> prefer_css_page_size,
                             std::unique_ptr<PrintToPDFCallback> callback) {
  callback->sendFailure(Response::Error("PrintToPDF is not implemented"));
  return;
}

Response PageHandler::StartScreencast(Maybe<std::string> format,
                                      Maybe<int> quality,
                                      Maybe<int> max_width,
                                      Maybe<int> max_height,
                                      Maybe<int> every_nth_frame) {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents)
    return Response::InternalError();
  RenderWidgetHostImpl* widget_host =
      host_ ? host_->GetRenderWidgetHost() : nullptr;
  if (!widget_host)
    return Response::InternalError();

  screencast_enabled_ = true;
  screencast_format_ = format.fromMaybe(kPng);
  screencast_quality_ = quality.fromMaybe(kDefaultScreenshotQuality);
  if (screencast_quality_ < 0 || screencast_quality_ > 100)
    screencast_quality_ = kDefaultScreenshotQuality;
  screencast_max_width_ = max_width.fromMaybe(-1);
  screencast_max_height_ = max_height.fromMaybe(-1);
  ++session_id_;
  frame_counter_ = 0;
  frames_in_flight_ = 0;
  capture_every_nth_frame_ = every_nth_frame.fromMaybe(1);
  bool visible = !widget_host->is_hidden();
  NotifyScreencastVisibility(visible);

#if !defined(OS_ANDROID)
  if (video_consumer_) {
    gfx::Size surface_size = gfx::Size();
    RenderWidgetHostViewBase* const view =
        static_cast<RenderWidgetHostViewBase*>(host_->GetView());
    if (view) {
      surface_size = view->GetCompositorViewportPixelSize();
      last_surface_size_ = surface_size;
    }

    gfx::Size snapshot_size = DetermineSnapshotSize(
        surface_size, screencast_max_width_, screencast_max_height_);
    if (!snapshot_size.IsEmpty())
      video_consumer_->SetMinAndMaxFrameSize(snapshot_size, snapshot_size);

    video_consumer_->StartCapture();
    return Response::FallThrough();
  }
#endif  // !defined(OS_ANDROID)

  if (!visible)
    return Response::FallThrough();

  if (has_compositor_frame_metadata_) {
    InnerSwapCompositorFrame();
  } else {
    widget_host->Send(new ViewMsg_ForceRedraw(widget_host->GetRoutingID(),
                                              ui::LatencyInfo()));
  }
  return Response::FallThrough();
}

Response PageHandler::StopScreencast() {
  screencast_enabled_ = false;
#if !defined(OS_ANDROID)
  if (video_consumer_)
    video_consumer_->StopCapture();
#endif  // !defined(OS_ANDROID)
  return Response::FallThrough();
}

Response PageHandler::ScreencastFrameAck(int session_id) {
  if (session_id == session_id_)
    --frames_in_flight_;
  return Response::OK();
}

Response PageHandler::HandleJavaScriptDialog(bool accept,
                                             Maybe<std::string> prompt_text) {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents)
    return Response::InternalError();

  if (pending_dialog_.is_null())
    return Response::InvalidParams("No dialog is showing");

  base::string16 prompt_override;
  if (prompt_text.isJust())
    prompt_override = base::UTF8ToUTF16(prompt_text.fromJust());
  std::move(pending_dialog_).Run(accept, prompt_override);

  // Clean up the dialog UI if any.
  if (web_contents->GetDelegate()) {
    JavaScriptDialogManager* manager =
        web_contents->GetDelegate()->GetJavaScriptDialogManager(web_contents);
    if (manager) {
      manager->HandleJavaScriptDialog(
          web_contents, accept,
          prompt_text.isJust() ? &prompt_override : nullptr);
    }
  }

  return Response::OK();
}

Response PageHandler::RequestAppBanner() {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents || !web_contents->GetDelegate())
    return Response::InternalError();
  web_contents->GetDelegate()->RequestAppBannerFromDevTools(web_contents);
  return Response::OK();
}

Response PageHandler::BringToFront() {
  WebContentsImpl* wc = GetWebContents();
  if (wc) {
    wc->Activate();
    wc->Focus();
    return Response::OK();
  }
  return Response::InternalError();
}

Response PageHandler::SetDownloadBehavior(const std::string& behavior,
                                          Maybe<std::string> download_path) {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents)
    return Response::InternalError();

  if (behavior == Page::SetDownloadBehavior::BehaviorEnum::Allow &&
      !download_path.isJust())
    return Response::Error("downloadPath not provided");

  if (behavior == Page::SetDownloadBehavior::BehaviorEnum::Default) {
    DevToolsDownloadManagerHelper::RemoveFromWebContents(web_contents);
    download_manager_delegate_ = nullptr;
    return Response::OK();
  }

  // Override download manager delegate.
  content::BrowserContext* browser_context = web_contents->GetBrowserContext();
  DCHECK(browser_context);
  content::DownloadManager* download_manager =
      content::BrowserContext::GetDownloadManager(browser_context);
  download_manager_delegate_ =
      DevToolsDownloadManagerDelegate::TakeOver(download_manager);

  // Ensure that there is one helper attached. If there's already one, we reuse
  // it.
  DevToolsDownloadManagerHelper::CreateForWebContents(web_contents);
  DevToolsDownloadManagerHelper* download_helper =
      DevToolsDownloadManagerHelper::FromWebContents(web_contents);

  download_helper->SetDownloadBehavior(
      DevToolsDownloadManagerHelper::DownloadBehavior::DENY);
  if (behavior == Page::SetDownloadBehavior::BehaviorEnum::Allow) {
    download_helper->SetDownloadBehavior(
        DevToolsDownloadManagerHelper::DownloadBehavior::ALLOW);
    download_helper->SetDownloadPath(download_path.fromJust());
  }

  return Response::OK();
}

void PageHandler::GetAppManifest(
    std::unique_ptr<GetAppManifestCallback> callback) {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents || !web_contents->GetManifestManagerHost()) {
    callback->sendFailure(Response::Error("Cannot retrieve manifest"));
    return;
  }
  web_contents->GetManifestManagerHost()->RequestManifestDebugInfo(
      base::BindOnce(&PageHandler::GotManifest, weak_factory_.GetWeakPtr(),
                     std::move(callback)));
}

WebContentsImpl* PageHandler::GetWebContents() {
  return host_ && !host_->frame_tree_node()->parent()
             ? static_cast<WebContentsImpl*>(
                   WebContents::FromRenderFrameHost(host_))
             : nullptr;
}

void PageHandler::NotifyScreencastVisibility(bool visible) {
  if (visible)
    capture_retry_count_ = kCaptureRetryLimit;
  frontend_->ScreencastVisibilityChanged(visible);
}

void PageHandler::InnerSwapCompositorFrame() {
  if (!host_)
    return;

  if (frames_in_flight_ > kMaxScreencastFramesInFlight)
    return;

  if (++frame_counter_ % capture_every_nth_frame_)
    return;

  RenderWidgetHostViewBase* const view =
      static_cast<RenderWidgetHostViewBase*>(host_->GetView());
  if (!view || !view->IsSurfaceAvailableForCopy())
    return;

  const gfx::Size surface_size = view->GetCompositorViewportPixelSize();
  if (surface_size.IsEmpty())
    return;

  const gfx::Size snapshot_size = DetermineSnapshotSize(
      surface_size, screencast_max_width_, screencast_max_height_);
  if (snapshot_size.IsEmpty())
    return;

  std::unique_ptr<Page::ScreencastFrameMetadata> page_metadata =
      BuildScreencastFrameMetadata(
          surface_size, last_compositor_frame_metadata_.device_scale_factor,
          last_compositor_frame_metadata_.page_scale_factor,
          last_compositor_frame_metadata_.root_scroll_offset,
          last_compositor_frame_metadata_.top_controls_height,
          last_compositor_frame_metadata_.top_controls_shown_ratio);
  if (!page_metadata)
    return;

  // Request a copy of the surface as a scaled SkBitmap.
  view->CopyFromSurface(
      gfx::Rect(), snapshot_size,
      base::BindOnce(&PageHandler::ScreencastFrameCaptured,
                     weak_factory_.GetWeakPtr(), std::move(page_metadata)));
  frames_in_flight_++;
}

#if !defined(OS_ANDROID)
void PageHandler::OnFrameFromVideoConsumer(
    scoped_refptr<media::VideoFrame> frame) {
  if (!host_)
    return;

  RenderWidgetHostViewBase* const view =
      static_cast<RenderWidgetHostViewBase*>(host_->GetView());
  if (!view)
    return;

  const gfx::Size surface_size = view->GetCompositorViewportPixelSize();
  if (surface_size.IsEmpty())
    return;

  // If window has been resized, set the new dimensions.
  if (surface_size != last_surface_size_) {
    last_surface_size_ = surface_size;
    gfx::Size snapshot_size = DetermineSnapshotSize(
        surface_size, screencast_max_width_, screencast_max_height_);
    if (!snapshot_size.IsEmpty())
      video_consumer_->SetMinAndMaxFrameSize(snapshot_size, snapshot_size);
    return;
  }

  double device_scale_factor, page_scale_factor;
  gfx::Vector2dF root_scroll_offset;
  GetMetadataFromFrame(*frame, &device_scale_factor, &page_scale_factor,
                       &root_scroll_offset);
  // Top controls are only present on Android. Hence use default values of 0.f.
  // TODO(dgozman): fix this when viz capture is available on Android.
  const float kTopControlsHeight = 0.f;
  const float kTopControlsShownRatio = 0.f;
  std::unique_ptr<Page::ScreencastFrameMetadata> page_metadata =
      BuildScreencastFrameMetadata(surface_size, device_scale_factor,
                                   page_scale_factor, root_scroll_offset,
                                   kTopControlsHeight, kTopControlsShownRatio);
  if (!page_metadata)
    return;

  ScreencastFrameCaptured(std::move(page_metadata),
                          DevToolsVideoConsumer::GetSkBitmapFromFrame(frame));
}
#endif  // !defined(OS_ANDROID)

void PageHandler::ScreencastFrameCaptured(
    std::unique_ptr<Page::ScreencastFrameMetadata> page_metadata,
    const SkBitmap& bitmap) {
  if (bitmap.drawsNothing()) {
    if (capture_retry_count_) {
      --capture_retry_count_;
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE,
          base::BindOnce(&PageHandler::InnerSwapCompositorFrame,
                         weak_factory_.GetWeakPtr()),
          base::TimeDelta::FromMilliseconds(kFrameRetryDelayMs));
    }
    --frames_in_flight_;
    return;
  }
  base::PostTaskWithTraitsAndReplyWithResult(
      FROM_HERE, {base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
      base::BindOnce(&EncodeSkBitmap, bitmap, screencast_format_,
                     screencast_quality_),
      base::BindOnce(&PageHandler::ScreencastFrameEncoded,
                     weak_factory_.GetWeakPtr(), std::move(page_metadata)));
}

void PageHandler::ScreencastFrameEncoded(
    std::unique_ptr<Page::ScreencastFrameMetadata> page_metadata,
    const std::string& data) {
  if (data.empty()) {
    --frames_in_flight_;
    return;  // Encode failed.
  }

  frontend_->ScreencastFrame(data, std::move(page_metadata), session_id_);
}

void PageHandler::ScreenshotCaptured(
    std::unique_ptr<CaptureScreenshotCallback> callback,
    const std::string& format,
    int quality,
    const gfx::Size& original_view_size,
    const gfx::Size& requested_image_size,
    const blink::WebDeviceEmulationParams& original_emulation_params,
    const gfx::Image& image) {
  if (original_view_size.width()) {
    RenderWidgetHostImpl* widget_host = host_->GetRenderWidgetHost();
    widget_host->GetView()->SetSize(original_view_size);
    emulation_handler_->SetDeviceEmulationParams(original_emulation_params);
  }

  if (image.IsEmpty()) {
    callback->sendFailure(Response::Error("Unable to capture screenshot"));
    return;
  }

  if (!requested_image_size.IsEmpty() &&
      (image.Width() != requested_image_size.width() ||
       image.Height() != requested_image_size.height())) {
    const SkBitmap* bitmap = image.ToSkBitmap();
    SkBitmap cropped = SkBitmapOperations::CreateTiledBitmap(
        *bitmap, 0, 0, requested_image_size.width(),
        requested_image_size.height());
    gfx::Image croppedImage = gfx::Image::CreateFrom1xBitmap(cropped);
    callback->sendSuccess(EncodeImage(croppedImage, format, quality));
  } else {
    callback->sendSuccess(EncodeImage(image, format, quality));
  }
}

void PageHandler::GotManifest(std::unique_ptr<GetAppManifestCallback> callback,
                              const GURL& manifest_url,
                              blink::mojom::ManifestDebugInfoPtr debug_info) {
  std::unique_ptr<Array<Page::AppManifestError>> errors =
      Array<Page::AppManifestError>::create();
  bool failed = true;
  if (debug_info) {
    failed = false;
    for (const auto& error : debug_info->errors) {
      errors->addItem(Page::AppManifestError::Create()
                          .SetMessage(error->message)
                          .SetCritical(error->critical)
                          .SetLine(error->line)
                          .SetColumn(error->column)
                          .Build());
      if (error->critical)
        failed = true;
    }
  }
  callback->sendSuccess(
      manifest_url.possibly_invalid_spec(), std::move(errors),
      failed ? Maybe<std::string>() : debug_info->raw_manifest);
}

Response PageHandler::StopLoading() {
  WebContentsImpl* web_contents = GetWebContents();
  if (!web_contents)
    return Response::InternalError();
  web_contents->Stop();
  return Response::OK();
}

}  // namespace protocol
}  // namespace content

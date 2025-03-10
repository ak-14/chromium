// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_FRAME_MESSAGES_H_
#define CONTENT_COMMON_FRAME_MESSAGES_H_

// IPC messages for interacting with frames.

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/optional.h"
#include "build/build_config.h"
#include "components/viz/common/surfaces/surface_id.h"
#include "components/viz/common/surfaces/surface_info.h"
#include "content/common/buildflags.h"
#include "content/common/content_export.h"
#include "content/common/content_param_traits.h"
#include "content/common/content_security_policy/csp_context.h"
#include "content/common/content_security_policy_header.h"
#include "content/common/download/mhtml_save_status.h"
#include "content/common/frame_message_enums.h"
#include "content/common/frame_message_structs.h"
#include "content/common/frame_owner_properties.h"
#include "content/common/frame_replication_state.h"
#include "content/common/frame_resize_params.h"
#include "content/common/navigation_gesture.h"
#include "content/common/navigation_params.h"
#include "content/common/resource_timing_info.h"
#include "content/common/savable_subframe.h"
#include "content/public/common/common_param_traits.h"
#include "content/public/common/console_message_level.h"
#include "content/public/common/context_menu_params.h"
#include "content/public/common/favicon_url.h"
#include "content/public/common/file_chooser_file_info.h"
#include "content/public/common/file_chooser_params.h"
#include "content/public/common/frame_navigate_params.h"
#include "content/public/common/javascript_dialog_type.h"
#include "content/public/common/page_importance_signals.h"
#include "content/public/common/page_state.h"
#include "content/public/common/previews_state.h"
#include "content/public/common/referrer.h"
#include "content/public/common/request_context_type.h"
#include "content/public/common/screen_info.h"
#include "content/public/common/stop_find_action.h"
#include "content/public/common/three_d_api_types.h"
#include "ipc/ipc_message_macros.h"
#include "ipc/ipc_platform_file.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "ppapi/buildflags/buildflags.h"
#include "third_party/blink/public/common/feature_policy/feature_policy.h"
#include "third_party/blink/public/common/frame/frame_policy.h"
#include "third_party/blink/public/common/message_port/message_port_channel.h"
#include "third_party/blink/public/common/message_port/transferable_message.h"
#include "third_party/blink/public/platform/web_focus_type.h"
#include "third_party/blink/public/platform/web_insecure_request_policy.h"
#include "third_party/blink/public/platform/web_intrinsic_sizing_info.h"
#include "third_party/blink/public/platform/web_scroll_into_view_params.h"
#include "third_party/blink/public/platform/web_sudden_termination_disabler_type.h"
#include "third_party/blink/public/web/web_find_options.h"
#include "third_party/blink/public/web/web_frame_owner_properties.h"
#include "third_party/blink/public/web/web_frame_serializer_cache_control_policy.h"
#include "third_party/blink/public/web/web_fullscreen_options.h"
#include "third_party/blink/public/web/web_tree_scope_type.h"
#include "third_party/blink/public/web/web_triggering_event_info.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/ipc/gfx_param_traits.h"
#include "ui/gfx/ipc/skia/gfx_skia_param_traits.h"
#include "ui/gfx/range/range.h"
#include "url/gurl.h"
#include "url/origin.h"

#if BUILDFLAG(ENABLE_PLUGINS)
#include "content/common/pepper_renderer_instance_data.h"
#endif

// Singly-included section for type definitions.
#ifndef INTERNAL_CONTENT_COMMON_FRAME_MESSAGES_H_
#define INTERNAL_CONTENT_COMMON_FRAME_MESSAGES_H_

using FrameMsg_GetSerializedHtmlWithLocalLinks_UrlMap =
    std::map<GURL, base::FilePath>;
using FrameMsg_GetSerializedHtmlWithLocalLinks_FrameRoutingIdMap =
    std::map<int, base::FilePath>;

#endif  // INTERNAL_CONTENT_COMMON_FRAME_MESSAGES_H_

#undef IPC_MESSAGE_EXPORT
#define IPC_MESSAGE_EXPORT CONTENT_EXPORT

#define IPC_MESSAGE_START FrameMsgStart
IPC_ENUM_TRAITS_MAX_VALUE(
    blink::WebScrollIntoViewParams::AlignmentBehavior,
    blink::WebScrollIntoViewParams::kLastAlignmentBehavior)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebScrollIntoViewParams::Type,
                          blink::WebScrollIntoViewParams::kLastType)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebScrollIntoViewParams::Behavior,
                          blink::WebScrollIntoViewParams::kLastBehavior)
IPC_ENUM_TRAITS_MIN_MAX_VALUE(content::JavaScriptDialogType,
                              content::JAVASCRIPT_DIALOG_TYPE_ALERT,
                              content::JAVASCRIPT_DIALOG_TYPE_PROMPT)
IPC_ENUM_TRAITS_MAX_VALUE(FrameMsg_Navigate_Type::Value,
                          FrameMsg_Navigate_Type::NAVIGATE_TYPE_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(FrameMsg_UILoadMetricsReportType::Value,
                          FrameMsg_UILoadMetricsReportType::REPORT_TYPE_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebContextMenuData::MediaType,
                          blink::WebContextMenuData::kMediaTypeLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebContextMenuData::InputFieldType,
                          blink::WebContextMenuData::kInputFieldTypeLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebFocusType, blink::kWebFocusTypeLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebFrameOwnerProperties::ScrollingMode,
                          blink::WebFrameOwnerProperties::ScrollingMode::kLast)
IPC_ENUM_TRAITS_MAX_VALUE(content::StopFindAction,
                          content::STOP_FIND_ACTION_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(content::FaviconURL::IconType,
                          content::FaviconURL::IconType::kMax)
IPC_ENUM_TRAITS(blink::WebSandboxFlags)  // Bitmask.
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebTreeScopeType,
                          blink::WebTreeScopeType::kLast)
IPC_ENUM_TRAITS_MAX_VALUE(ui::MenuSourceType, ui::MENU_SOURCE_TYPE_LAST)
IPC_ENUM_TRAITS_MAX_VALUE(content::FileChooserParams::Mode,
                          content::FileChooserParams::Save)
IPC_ENUM_TRAITS_MAX_VALUE(content::CSPDirective::Name,
                          content::CSPDirective::NameLast)
IPC_ENUM_TRAITS_MAX_VALUE(blink::mojom::FeaturePolicyFeature,
                          blink::mojom::FeaturePolicyFeature::kMaxValue)
IPC_ENUM_TRAITS_MAX_VALUE(content::CSPDisposition,
                          content::CSPDisposition::LAST)
IPC_ENUM_TRAITS_MAX_VALUE(blink::WebTriggeringEventInfo,
                          blink::WebTriggeringEventInfo::kLast)

IPC_STRUCT_TRAITS_BEGIN(blink::WebFloatSize)
  IPC_STRUCT_TRAITS_MEMBER(width)
  IPC_STRUCT_TRAITS_MEMBER(height)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebIntrinsicSizingInfo)
  IPC_STRUCT_TRAITS_MEMBER(size)
  IPC_STRUCT_TRAITS_MEMBER(aspect_ratio)
  IPC_STRUCT_TRAITS_MEMBER(has_width)
  IPC_STRUCT_TRAITS_MEMBER(has_height)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebFindOptions)
  IPC_STRUCT_TRAITS_MEMBER(forward)
  IPC_STRUCT_TRAITS_MEMBER(match_case)
  IPC_STRUCT_TRAITS_MEMBER(find_next)
  IPC_STRUCT_TRAITS_MEMBER(force)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebFullscreenOptions)
  IPC_STRUCT_TRAITS_MEMBER(prefers_navigation_bar)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebScrollIntoViewParams::Alignment)
  IPC_STRUCT_TRAITS_MEMBER(rect_visible)
  IPC_STRUCT_TRAITS_MEMBER(rect_hidden)
  IPC_STRUCT_TRAITS_MEMBER(rect_partial)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::WebScrollIntoViewParams)
  IPC_STRUCT_TRAITS_MEMBER(align_x)
  IPC_STRUCT_TRAITS_MEMBER(align_y)
  IPC_STRUCT_TRAITS_MEMBER(type)
  IPC_STRUCT_TRAITS_MEMBER(make_visible_in_visual_viewport)
  IPC_STRUCT_TRAITS_MEMBER(behavior)
  IPC_STRUCT_TRAITS_MEMBER(is_for_scroll_sequence)
  IPC_STRUCT_TRAITS_MEMBER(zoom_into_rect)
  IPC_STRUCT_TRAITS_MEMBER(relative_element_bounds)
  IPC_STRUCT_TRAITS_MEMBER(relative_caret_bounds)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::ContextMenuParams)
  IPC_STRUCT_TRAITS_MEMBER(media_type)
  IPC_STRUCT_TRAITS_MEMBER(x)
  IPC_STRUCT_TRAITS_MEMBER(y)
  IPC_STRUCT_TRAITS_MEMBER(link_url)
  IPC_STRUCT_TRAITS_MEMBER(link_text)
  IPC_STRUCT_TRAITS_MEMBER(unfiltered_link_url)
  IPC_STRUCT_TRAITS_MEMBER(src_url)
  IPC_STRUCT_TRAITS_MEMBER(has_image_contents)
  IPC_STRUCT_TRAITS_MEMBER(properties)
  IPC_STRUCT_TRAITS_MEMBER(page_url)
  IPC_STRUCT_TRAITS_MEMBER(frame_url)
  IPC_STRUCT_TRAITS_MEMBER(media_flags)
  IPC_STRUCT_TRAITS_MEMBER(selection_text)
  IPC_STRUCT_TRAITS_MEMBER(title_text)
  IPC_STRUCT_TRAITS_MEMBER(suggested_filename)
  IPC_STRUCT_TRAITS_MEMBER(misspelled_word)
  IPC_STRUCT_TRAITS_MEMBER(dictionary_suggestions)
  IPC_STRUCT_TRAITS_MEMBER(spellcheck_enabled)
  IPC_STRUCT_TRAITS_MEMBER(is_editable)
  IPC_STRUCT_TRAITS_MEMBER(writing_direction_default)
  IPC_STRUCT_TRAITS_MEMBER(writing_direction_left_to_right)
  IPC_STRUCT_TRAITS_MEMBER(writing_direction_right_to_left)
  IPC_STRUCT_TRAITS_MEMBER(edit_flags)
  IPC_STRUCT_TRAITS_MEMBER(frame_charset)
  IPC_STRUCT_TRAITS_MEMBER(referrer_policy)
  IPC_STRUCT_TRAITS_MEMBER(custom_context)
  IPC_STRUCT_TRAITS_MEMBER(custom_items)
  IPC_STRUCT_TRAITS_MEMBER(source_type)
  IPC_STRUCT_TRAITS_MEMBER(input_field_type)
  IPC_STRUCT_TRAITS_MEMBER(selection_rect)
  IPC_STRUCT_TRAITS_MEMBER(selection_start_offset)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::CustomContextMenuContext)
  IPC_STRUCT_TRAITS_MEMBER(is_pepper_menu)
  IPC_STRUCT_TRAITS_MEMBER(request_id)
  IPC_STRUCT_TRAITS_MEMBER(render_widget_id)
  IPC_STRUCT_TRAITS_MEMBER(link_followed)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::FaviconURL)
  IPC_STRUCT_TRAITS_MEMBER(icon_url)
  IPC_STRUCT_TRAITS_MEMBER(icon_type)
  IPC_STRUCT_TRAITS_MEMBER(icon_sizes)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::FrameOwnerProperties)
  IPC_STRUCT_TRAITS_MEMBER(name)
  IPC_STRUCT_TRAITS_MEMBER(scrolling_mode)
  IPC_STRUCT_TRAITS_MEMBER(margin_width)
  IPC_STRUCT_TRAITS_MEMBER(margin_height)
  IPC_STRUCT_TRAITS_MEMBER(allow_fullscreen)
  IPC_STRUCT_TRAITS_MEMBER(allow_payment_request)
  IPC_STRUCT_TRAITS_MEMBER(is_display_none)
  IPC_STRUCT_TRAITS_MEMBER(required_csp)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::FrameResizeParams)
  IPC_STRUCT_TRAITS_MEMBER(screen_info)
  IPC_STRUCT_TRAITS_MEMBER(auto_resize_enabled)
  IPC_STRUCT_TRAITS_MEMBER(min_size_for_auto_resize)
  IPC_STRUCT_TRAITS_MEMBER(max_size_for_auto_resize)
  IPC_STRUCT_TRAITS_MEMBER(auto_resize_sequence_number)
  IPC_STRUCT_TRAITS_MEMBER(screen_space_rect)
  IPC_STRUCT_TRAITS_MEMBER(local_frame_size)
  IPC_STRUCT_TRAITS_MEMBER(capture_sequence_number)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::FramePolicy)
  IPC_STRUCT_TRAITS_MEMBER(sandbox_flags)
  IPC_STRUCT_TRAITS_MEMBER(container_policy)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::PageImportanceSignals)
  IPC_STRUCT_TRAITS_MEMBER(had_form_interaction)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::ResourceLoadTiming)
  IPC_STRUCT_TRAITS_MEMBER(request_time)
  IPC_STRUCT_TRAITS_MEMBER(proxy_start)
  IPC_STRUCT_TRAITS_MEMBER(proxy_end)
  IPC_STRUCT_TRAITS_MEMBER(dns_start)
  IPC_STRUCT_TRAITS_MEMBER(dns_end)
  IPC_STRUCT_TRAITS_MEMBER(connect_start)
  IPC_STRUCT_TRAITS_MEMBER(connect_end)
  IPC_STRUCT_TRAITS_MEMBER(worker_start)
  IPC_STRUCT_TRAITS_MEMBER(worker_ready)
  IPC_STRUCT_TRAITS_MEMBER(send_start)
  IPC_STRUCT_TRAITS_MEMBER(send_end)
  IPC_STRUCT_TRAITS_MEMBER(receive_headers_end)
  IPC_STRUCT_TRAITS_MEMBER(ssl_start)
  IPC_STRUCT_TRAITS_MEMBER(ssl_end)
  IPC_STRUCT_TRAITS_MEMBER(push_start)
  IPC_STRUCT_TRAITS_MEMBER(push_end)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::ResourceTimingInfo)
  IPC_STRUCT_TRAITS_MEMBER(name)
  IPC_STRUCT_TRAITS_MEMBER(start_time)
  IPC_STRUCT_TRAITS_MEMBER(initiator_type)
  IPC_STRUCT_TRAITS_MEMBER(alpn_negotiated_protocol)
  IPC_STRUCT_TRAITS_MEMBER(connection_info)
  IPC_STRUCT_TRAITS_MEMBER(timing)
  IPC_STRUCT_TRAITS_MEMBER(last_redirect_end_time)
  IPC_STRUCT_TRAITS_MEMBER(finish_time)
  IPC_STRUCT_TRAITS_MEMBER(transfer_size)
  IPC_STRUCT_TRAITS_MEMBER(encoded_body_size)
  IPC_STRUCT_TRAITS_MEMBER(decoded_body_size)
  IPC_STRUCT_TRAITS_MEMBER(did_reuse_connection)
  IPC_STRUCT_TRAITS_MEMBER(allow_timing_details)
  IPC_STRUCT_TRAITS_MEMBER(allow_redirect_details)
  IPC_STRUCT_TRAITS_MEMBER(allow_negative_values)
  IPC_STRUCT_TRAITS_MEMBER(server_timing)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::ServerTimingInfo)
  IPC_STRUCT_TRAITS_MEMBER(name)
  IPC_STRUCT_TRAITS_MEMBER(duration)
  IPC_STRUCT_TRAITS_MEMBER(description)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_BEGIN(FrameHostMsg_DidFailProvisionalLoadWithError_Params)
  // Error code as reported in the DidFailProvisionalLoad callback.
  IPC_STRUCT_MEMBER(int, error_code)
  // An error message generated from the error_code. This can be an empty
  // string if we were unable to find a meaningful description.
  IPC_STRUCT_MEMBER(base::string16, error_description)
  // The URL that the error is reported for.
  IPC_STRUCT_MEMBER(GURL, url)
  // True if the failure is the result of navigating to a POST again
  // and we're going to show the POST interstitial.
  IPC_STRUCT_MEMBER(bool, showing_repost_interstitial)
IPC_STRUCT_END()

IPC_STRUCT_TRAITS_BEGIN(content::FrameNavigateParams)
  IPC_STRUCT_TRAITS_MEMBER(nav_entry_id)
  IPC_STRUCT_TRAITS_MEMBER(item_sequence_number)
  IPC_STRUCT_TRAITS_MEMBER(document_sequence_number)
  IPC_STRUCT_TRAITS_MEMBER(url)
  IPC_STRUCT_TRAITS_MEMBER(base_url)
  IPC_STRUCT_TRAITS_MEMBER(referrer)
  IPC_STRUCT_TRAITS_MEMBER(transition)
  IPC_STRUCT_TRAITS_MEMBER(redirects)
  IPC_STRUCT_TRAITS_MEMBER(should_update_history)
  IPC_STRUCT_TRAITS_MEMBER(contents_mime_type)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::ScreenInfo)
  IPC_STRUCT_TRAITS_MEMBER(device_scale_factor)
  IPC_STRUCT_TRAITS_MEMBER(color_space)
#if defined(OS_MACOSX)
  IPC_STRUCT_TRAITS_MEMBER(icc_profile)
#endif
  IPC_STRUCT_TRAITS_MEMBER(depth)
  IPC_STRUCT_TRAITS_MEMBER(depth_per_component)
  IPC_STRUCT_TRAITS_MEMBER(is_monochrome)
  IPC_STRUCT_TRAITS_MEMBER(rect)
  IPC_STRUCT_TRAITS_MEMBER(available_rect)
  IPC_STRUCT_TRAITS_MEMBER(orientation_type)
  IPC_STRUCT_TRAITS_MEMBER(orientation_angle)
IPC_STRUCT_TRAITS_END()

// Parameters structure for mojom::FrameHost::DidCommitProvisionalLoad.
// TODO(https://crbug.com/729021): Convert this to a Mojo struct.
IPC_STRUCT_BEGIN_WITH_PARENT(FrameHostMsg_DidCommitProvisionalLoad_Params,
                             content::FrameNavigateParams)
  IPC_STRUCT_TRAITS_PARENT(content::FrameNavigateParams)

  // This is the value from the browser (copied from the navigation request)
  // indicating whether it intended to make a new entry. TODO(avi): Remove this
  // when the pending entry situation is made sane and the browser keeps them
  // around long enough to match them via nav_entry_id.
  IPC_STRUCT_MEMBER(bool, intended_as_new_entry)

  // Whether this commit created a new entry.
  IPC_STRUCT_MEMBER(bool, did_create_new_entry)

  // Whether this commit should replace the current entry.
  IPC_STRUCT_MEMBER(bool, should_replace_current_entry)

  // The gesture that initiated this navigation.
  IPC_STRUCT_MEMBER(content::NavigationGesture, gesture)

  // The HTTP method used by the navigation.
  IPC_STRUCT_MEMBER(std::string, method)

  // The POST body identifier. -1 if it doesn't exist.
  IPC_STRUCT_MEMBER(int64_t, post_id)

  // The status code of the HTTP request.
  IPC_STRUCT_MEMBER(int, http_status_code)

  // This flag is used to warn if the renderer is displaying an error page,
  // so that we can set the appropriate page type.
  IPC_STRUCT_MEMBER(bool, url_is_unreachable)

  // Serialized history item state to store in the navigation entry.
  IPC_STRUCT_MEMBER(content::PageState, page_state)

  // Original request's URL.
  IPC_STRUCT_MEMBER(GURL, original_request_url)

  // User agent override used to navigate.
  IPC_STRUCT_MEMBER(bool, is_overriding_user_agent)

  // Notifies the browser that for this navigation, the session history was
  // successfully cleared.
  IPC_STRUCT_MEMBER(bool, history_list_was_cleared)

  // The routing_id of the render view associated with the navigation. We need
  // to track the RenderViewHost routing_id because of downstream dependencies
  // (https://crbug.com/392171 DownloadRequestHandle, SaveFileManager,
  // ResourceDispatcherHostImpl, MediaStreamUIProxy and possibly others). They
  // look up the view based on the ID stored in the resource requests. Once
  // those dependencies are unwound or moved to RenderFrameHost
  // (https://crbug.com/304341) we can move the client to be based on the
  // routing_id of the RenderFrameHost.
  IPC_STRUCT_MEMBER(int, render_view_routing_id)

  // Origin of the frame.  This will be replicated to any associated
  // RenderFrameProxies.
  IPC_STRUCT_MEMBER(url::Origin, origin)

  // How navigation metrics starting on UI action for this load should be
  // reported.
  IPC_STRUCT_MEMBER(FrameMsg_UILoadMetricsReportType::Value, report_type)

  // Timestamp at which the UI action that triggered the navigation originated.
  IPC_STRUCT_MEMBER(base::TimeTicks, ui_timestamp)

  // The insecure request policy the document for the load is enforcing.
  IPC_STRUCT_MEMBER(blink::WebInsecureRequestPolicy, insecure_request_policy)

  // The upgrade insecure navigations set the document for the load is
  // enforcing.
  IPC_STRUCT_MEMBER(std::vector<uint32_t>, insecure_navigations_set)

  // True if the document for the load is a unique origin that should be
  // considered potentially trustworthy.
  IPC_STRUCT_MEMBER(bool, has_potentially_trustworthy_unique_origin)

  // See WebSearchableFormData for a description of these.
  // Not used by PlzNavigate: in that case these fields are sent to the browser
  // in mojom::BeginNavigationParams.
  IPC_STRUCT_MEMBER(GURL, searchable_form_url)
  IPC_STRUCT_MEMBER(std::string, searchable_form_encoding)

  // This is a non-decreasing value that the browser process can use to
  // identify and discard compositor frames that correspond to now-unloaded
  // web content.
  IPC_STRUCT_MEMBER(uint32_t, content_source_id)
IPC_STRUCT_END()

IPC_STRUCT_BEGIN(FrameMsg_PostMessage_Params)
  // Whether the data format is supplied as serialized script value, or as
  // a simple string. If it is a raw string, must be converted from string to a
  // WebSerializedScriptValue in the renderer process.
  IPC_STRUCT_MEMBER(bool, is_data_raw_string)

  // When sent to the browser, this is the routing ID of the source frame in
  // the source process.  The browser replaces it with the routing ID of the
  // equivalent frame proxy in the destination process.
  IPC_STRUCT_MEMBER(int, source_routing_id)

  // The origin of the source frame.
  IPC_STRUCT_MEMBER(base::string16, source_origin)

  // The origin for the message's target.
  IPC_STRUCT_MEMBER(base::string16, target_origin)

  // The encoded data, and any extra properties such as transfered ports or
  // blobs.
  IPC_STRUCT_MEMBER(
      scoped_refptr<base::RefCountedData<blink::TransferableMessage>>, message)
IPC_STRUCT_END()

IPC_STRUCT_TRAITS_BEGIN(content::SourceLocation)
  IPC_STRUCT_TRAITS_MEMBER(url)
  IPC_STRUCT_TRAITS_MEMBER(line_number)
  IPC_STRUCT_TRAITS_MEMBER(column_number)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::CommonNavigationParams)
  IPC_STRUCT_TRAITS_MEMBER(url)
  IPC_STRUCT_TRAITS_MEMBER(referrer)
  IPC_STRUCT_TRAITS_MEMBER(transition)
  IPC_STRUCT_TRAITS_MEMBER(navigation_type)
  IPC_STRUCT_TRAITS_MEMBER(allow_download)
  IPC_STRUCT_TRAITS_MEMBER(should_replace_current_entry)
  IPC_STRUCT_TRAITS_MEMBER(ui_timestamp)
  IPC_STRUCT_TRAITS_MEMBER(report_type)
  IPC_STRUCT_TRAITS_MEMBER(base_url_for_data_url)
  IPC_STRUCT_TRAITS_MEMBER(history_url_for_data_url)
  IPC_STRUCT_TRAITS_MEMBER(previews_state)
  IPC_STRUCT_TRAITS_MEMBER(navigation_start)
  IPC_STRUCT_TRAITS_MEMBER(method)
  IPC_STRUCT_TRAITS_MEMBER(post_data)
  IPC_STRUCT_TRAITS_MEMBER(source_location)
  IPC_STRUCT_TRAITS_MEMBER(should_check_main_world_csp)
  IPC_STRUCT_TRAITS_MEMBER(has_user_gesture)
  IPC_STRUCT_TRAITS_MEMBER(started_from_context_menu)
  IPC_STRUCT_TRAITS_MEMBER(suggested_filename)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::NavigationTiming)
  IPC_STRUCT_TRAITS_MEMBER(redirect_start)
  IPC_STRUCT_TRAITS_MEMBER(redirect_end)
  IPC_STRUCT_TRAITS_MEMBER(fetch_start)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::RequestNavigationParams)
  IPC_STRUCT_TRAITS_MEMBER(is_overriding_user_agent)
  IPC_STRUCT_TRAITS_MEMBER(redirects)
  IPC_STRUCT_TRAITS_MEMBER(redirect_response)
  IPC_STRUCT_TRAITS_MEMBER(redirect_infos)
  IPC_STRUCT_TRAITS_MEMBER(post_content_type)
  IPC_STRUCT_TRAITS_MEMBER(original_url)
  IPC_STRUCT_TRAITS_MEMBER(original_method)
  IPC_STRUCT_TRAITS_MEMBER(can_load_local_resources)
  IPC_STRUCT_TRAITS_MEMBER(page_state)
  IPC_STRUCT_TRAITS_MEMBER(nav_entry_id)
  IPC_STRUCT_TRAITS_MEMBER(is_history_navigation_in_new_child)
  IPC_STRUCT_TRAITS_MEMBER(subframe_unique_names)
  IPC_STRUCT_TRAITS_MEMBER(intended_as_new_entry)
  IPC_STRUCT_TRAITS_MEMBER(pending_history_list_offset)
  IPC_STRUCT_TRAITS_MEMBER(current_history_list_offset)
  IPC_STRUCT_TRAITS_MEMBER(current_history_list_length)
  IPC_STRUCT_TRAITS_MEMBER(was_discarded)
  IPC_STRUCT_TRAITS_MEMBER(is_view_source)
  IPC_STRUCT_TRAITS_MEMBER(should_clear_history_list)
  IPC_STRUCT_TRAITS_MEMBER(should_create_service_worker)
  IPC_STRUCT_TRAITS_MEMBER(navigation_timing)
  IPC_STRUCT_TRAITS_MEMBER(service_worker_provider_id)
  IPC_STRUCT_TRAITS_MEMBER(appcache_host_id)
  IPC_STRUCT_TRAITS_MEMBER(was_activated)
#if defined(OS_ANDROID)
  IPC_STRUCT_TRAITS_MEMBER(data_url_as_string)
#endif
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(blink::ParsedFeaturePolicyDeclaration)
  IPC_STRUCT_TRAITS_MEMBER(feature)
  IPC_STRUCT_TRAITS_MEMBER(matches_all_origins)
  IPC_STRUCT_TRAITS_MEMBER(matches_opaque_src)
  IPC_STRUCT_TRAITS_MEMBER(origins)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::FrameReplicationState)
  IPC_STRUCT_TRAITS_MEMBER(origin)
  IPC_STRUCT_TRAITS_MEMBER(name)
  IPC_STRUCT_TRAITS_MEMBER(unique_name)
  IPC_STRUCT_TRAITS_MEMBER(feature_policy_header)
  IPC_STRUCT_TRAITS_MEMBER(active_sandbox_flags)
  IPC_STRUCT_TRAITS_MEMBER(frame_policy)
  IPC_STRUCT_TRAITS_MEMBER(accumulated_csp_headers)
  IPC_STRUCT_TRAITS_MEMBER(scope)
  IPC_STRUCT_TRAITS_MEMBER(insecure_request_policy)
  IPC_STRUCT_TRAITS_MEMBER(insecure_navigations_set)
  IPC_STRUCT_TRAITS_MEMBER(has_potentially_trustworthy_unique_origin)
  IPC_STRUCT_TRAITS_MEMBER(has_received_user_gesture)
  IPC_STRUCT_TRAITS_MEMBER(has_received_user_gesture_before_nav)
IPC_STRUCT_TRAITS_END()

// Parameters included with an OpenURL request.
// |is_history_navigation_in_new_child| is true in the case that the browser
// process should look for an existing history item for the frame.
IPC_STRUCT_BEGIN(FrameHostMsg_OpenURL_Params)
  IPC_STRUCT_MEMBER(GURL, url)
  IPC_STRUCT_MEMBER(bool, uses_post)
  IPC_STRUCT_MEMBER(scoped_refptr<network::ResourceRequestBody>,
                    resource_request_body)
  IPC_STRUCT_MEMBER(std::string, extra_headers)
  IPC_STRUCT_MEMBER(content::Referrer, referrer)
  IPC_STRUCT_MEMBER(WindowOpenDisposition, disposition)
  IPC_STRUCT_MEMBER(bool, should_replace_current_entry)
  IPC_STRUCT_MEMBER(bool, user_gesture)
  IPC_STRUCT_MEMBER(bool, is_history_navigation_in_new_child)
  IPC_STRUCT_MEMBER(blink::WebTriggeringEventInfo, triggering_event_info)
  IPC_STRUCT_MEMBER(base::Optional<std::string>, suggested_filename)
IPC_STRUCT_END()

IPC_STRUCT_BEGIN(FrameHostMsg_DownloadUrl_Params)
  IPC_STRUCT_MEMBER(int, render_view_id)
  IPC_STRUCT_MEMBER(int, render_frame_id)
  IPC_STRUCT_MEMBER(GURL, url)
  IPC_STRUCT_MEMBER(content::Referrer, referrer)
  IPC_STRUCT_MEMBER(url::Origin, initiator_origin)
  IPC_STRUCT_MEMBER(base::string16, suggested_name)
IPC_STRUCT_END()

IPC_STRUCT_BEGIN(FrameMsg_TextTrackSettings_Params)
  // Text tracks on/off state
  IPC_STRUCT_MEMBER(bool, text_tracks_enabled)

  // Background color of the text track.
  IPC_STRUCT_MEMBER(std::string, text_track_background_color)

  // Font family of the text track text.
  IPC_STRUCT_MEMBER(std::string, text_track_font_family)

  // Font style of the text track text.
  IPC_STRUCT_MEMBER(std::string, text_track_font_style)

  // Font variant of the text track text.
  IPC_STRUCT_MEMBER(std::string, text_track_font_variant)

  // Color of the text track text.
  IPC_STRUCT_MEMBER(std::string, text_track_text_color)

  // Text shadow (edge style) of the text track text.
  IPC_STRUCT_MEMBER(std::string, text_track_text_shadow)

  // Size of the text track text.
  IPC_STRUCT_MEMBER(std::string, text_track_text_size)
IPC_STRUCT_END()

IPC_STRUCT_TRAITS_BEGIN(content::SavableSubframe)
  IPC_STRUCT_TRAITS_MEMBER(original_url)
  IPC_STRUCT_TRAITS_MEMBER(routing_id)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_BEGIN(FrameMsg_SerializeAsMHTML_Params)
  // Job id - used to match responses to requests.
  IPC_STRUCT_MEMBER(int, job_id)

  // Destination file handle.
  IPC_STRUCT_MEMBER(IPC::PlatformFileForTransit, destination_file)

  // MHTML boundary marker / MIME multipart boundary maker.  The same
  // |mhtml_boundary_marker| should be used for serialization of each frame.
  IPC_STRUCT_MEMBER(std::string, mhtml_boundary_marker)

  // Whether to use binary encoding while serializing.  Binary encoding is not
  // supported outside of Chrome, so this should not be used if the MHTML is
  // intended for sharing.
  IPC_STRUCT_MEMBER(bool, mhtml_binary_encoding)

  IPC_STRUCT_MEMBER(blink::WebFrameSerializerCacheControlPolicy,
                    mhtml_cache_control_policy)

  // Whether to remove popup overlay while serializing.
  IPC_STRUCT_MEMBER(bool, mhtml_popup_overlay_removal)

  // Whether to detect problems while serializing.
  IPC_STRUCT_MEMBER(bool, mhtml_problem_detection)

  // |digests_of_uris_to_skip| contains digests of uris of MHTML parts that
  // should be skipped.  This helps deduplicate mhtml parts across frames.
  // SECURITY NOTE: Sha256 digests (rather than uris) are used to prevent
  // disclosing uris to other renderer processes;  the digests should be
  // generated using SHA256HashString function from crypto/sha2.h and hashing
  // |salt + url.spec()|.
  IPC_STRUCT_MEMBER(std::set<std::string>, digests_of_uris_to_skip)

  // Salt used for |digests_of_uris_to_skip|.
  IPC_STRUCT_MEMBER(std::string, salt)
IPC_STRUCT_END()

// This message is used to send hittesting data from the renderer in order
// to perform hittesting on the browser process.
IPC_STRUCT_BEGIN(FrameHostMsg_HittestData_Params)
  // |surface_id| represents the surface used by this remote frame.
  IPC_STRUCT_MEMBER(viz::SurfaceId, surface_id)

  // If |ignored_for_hittest| then this surface should be ignored during
  // hittesting.
  IPC_STRUCT_MEMBER(bool, ignored_for_hittest)
IPC_STRUCT_END()

IPC_STRUCT_BEGIN(FrameHostMsg_CreateChildFrame_Params)
  IPC_STRUCT_MEMBER(int32_t, parent_routing_id)
  IPC_STRUCT_MEMBER(blink::WebTreeScopeType, scope)
  IPC_STRUCT_MEMBER(std::string, frame_name)
  IPC_STRUCT_MEMBER(std::string, frame_unique_name)
  IPC_STRUCT_MEMBER(bool, is_created_by_script)
  IPC_STRUCT_MEMBER(blink::FramePolicy, frame_policy)
  IPC_STRUCT_MEMBER(content::FrameOwnerProperties, frame_owner_properties)
IPC_STRUCT_END()

IPC_STRUCT_TRAITS_BEGIN(content::CSPSource)
  IPC_STRUCT_TRAITS_MEMBER(scheme)
  IPC_STRUCT_TRAITS_MEMBER(host)
  IPC_STRUCT_TRAITS_MEMBER(is_host_wildcard)
  IPC_STRUCT_TRAITS_MEMBER(port)
  IPC_STRUCT_TRAITS_MEMBER(is_port_wildcard)
  IPC_STRUCT_TRAITS_MEMBER(path)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::CSPSourceList)
  IPC_STRUCT_TRAITS_MEMBER(allow_self)
  IPC_STRUCT_TRAITS_MEMBER(allow_star)
  IPC_STRUCT_TRAITS_MEMBER(sources)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::CSPDirective)
  IPC_STRUCT_TRAITS_MEMBER(name)
  IPC_STRUCT_TRAITS_MEMBER(source_list)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::ContentSecurityPolicy)
  IPC_STRUCT_TRAITS_MEMBER(header)
  IPC_STRUCT_TRAITS_MEMBER(directives)
  IPC_STRUCT_TRAITS_MEMBER(report_endpoints)
  IPC_STRUCT_TRAITS_MEMBER(use_reporting_api)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::ContentSecurityPolicyHeader)
  IPC_STRUCT_TRAITS_MEMBER(header_value)
  IPC_STRUCT_TRAITS_MEMBER(type)
  IPC_STRUCT_TRAITS_MEMBER(source)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::CSPViolationParams)
  IPC_STRUCT_TRAITS_MEMBER(directive)
  IPC_STRUCT_TRAITS_MEMBER(effective_directive)
  IPC_STRUCT_TRAITS_MEMBER(console_message)
  IPC_STRUCT_TRAITS_MEMBER(blocked_url)
  IPC_STRUCT_TRAITS_MEMBER(report_endpoints)
  IPC_STRUCT_TRAITS_MEMBER(use_reporting_api)
  IPC_STRUCT_TRAITS_MEMBER(header)
  IPC_STRUCT_TRAITS_MEMBER(disposition)
  IPC_STRUCT_TRAITS_MEMBER(after_redirect)
  IPC_STRUCT_TRAITS_MEMBER(source_location)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::FileChooserFileInfo)
  IPC_STRUCT_TRAITS_MEMBER(file_path)
  IPC_STRUCT_TRAITS_MEMBER(display_name)
  IPC_STRUCT_TRAITS_MEMBER(file_system_url)
  IPC_STRUCT_TRAITS_MEMBER(modification_time)
  IPC_STRUCT_TRAITS_MEMBER(length)
  IPC_STRUCT_TRAITS_MEMBER(is_directory)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_TRAITS_BEGIN(content::FileChooserParams)
  IPC_STRUCT_TRAITS_MEMBER(mode)
  IPC_STRUCT_TRAITS_MEMBER(title)
  IPC_STRUCT_TRAITS_MEMBER(default_file_name)
  IPC_STRUCT_TRAITS_MEMBER(accept_types)
  IPC_STRUCT_TRAITS_MEMBER(need_local_path)
#if defined(OS_ANDROID)
  IPC_STRUCT_TRAITS_MEMBER(capture)
#endif
  IPC_STRUCT_TRAITS_MEMBER(requestor)
IPC_STRUCT_TRAITS_END()

IPC_STRUCT_BEGIN(FrameMsg_MixedContentFound_Params)
  IPC_STRUCT_MEMBER(GURL, main_resource_url)
  IPC_STRUCT_MEMBER(GURL, mixed_content_url)
  IPC_STRUCT_MEMBER(content::RequestContextType, request_context_type)
  IPC_STRUCT_MEMBER(bool, was_allowed)
  IPC_STRUCT_MEMBER(bool, had_redirect)
  IPC_STRUCT_MEMBER(content::SourceLocation, source_location)
IPC_STRUCT_END()

#if BUILDFLAG(USE_EXTERNAL_POPUP_MENU)
// This message is used for supporting popup menus on Mac OS X and Android using
// native controls. See the FrameHostMsg_ShowPopup message.
IPC_STRUCT_BEGIN(FrameHostMsg_ShowPopup_Params)
  // Position on the screen.
  IPC_STRUCT_MEMBER(gfx::Rect, bounds)

  // The height of each item in the menu.
  IPC_STRUCT_MEMBER(int, item_height)

  // The size of the font to use for those items.
  IPC_STRUCT_MEMBER(double, item_font_size)

  // The currently selected (displayed) item in the menu.
  IPC_STRUCT_MEMBER(int, selected_item)

  // The entire list of items in the popup menu.
  IPC_STRUCT_MEMBER(std::vector<content::MenuItem>, popup_items)

  // Whether items should be right-aligned.
  IPC_STRUCT_MEMBER(bool, right_aligned)

  // Whether this is a multi-select popup.
  IPC_STRUCT_MEMBER(bool, allow_multiple_selection)
IPC_STRUCT_END()
#endif

// Causes a window previously opened via RenderMessageFilter::CreateNewWindow to
// be shown on the screen. This message is routed to the preexisting frame that
// opened the window, and |pending_widget_routing_id| corresponds to the
// widget routing id from the CreateNewWindow reply.
IPC_MESSAGE_ROUTED4(FrameHostMsg_ShowCreatedWindow,
                    int /* pending_widget_routing_id */,
                    WindowOpenDisposition /* disposition */,
                    gfx::Rect /* initial_rect */,
                    bool /* opened_by_user_gesture */)

// Let the browser know a StreamHandle has been consumed and can be released.
IPC_MESSAGE_ROUTED1(FrameHostMsg_StreamHandleConsumed, GURL /* stream_url */)

#if BUILDFLAG(ENABLE_PLUGINS)
IPC_STRUCT_TRAITS_BEGIN(content::PepperRendererInstanceData)
  IPC_STRUCT_TRAITS_MEMBER(render_process_id)
  IPC_STRUCT_TRAITS_MEMBER(render_frame_id)
  IPC_STRUCT_TRAITS_MEMBER(document_url)
  IPC_STRUCT_TRAITS_MEMBER(plugin_url)
  IPC_STRUCT_TRAITS_MEMBER(is_potentially_secure_plugin_context)
IPC_STRUCT_TRAITS_END()
#endif

// -----------------------------------------------------------------------------
// Messages sent from the browser to the renderer.

// Notifies the embedding frame that the intrinsic sizing info parameters
// of a child frame have changed.
IPC_MESSAGE_ROUTED1(FrameMsg_IntrinsicSizingInfoOfChildChanged,
                    blink::WebIntrinsicSizingInfo)

IPC_MESSAGE_ROUTED1(FrameMsg_SetChildFrameSurface,
                    viz::SurfaceInfo /* surface_info */)

// Notifies the embedding frame that the process rendering the child frame's
// contents has terminated.
IPC_MESSAGE_ROUTED0(FrameMsg_ChildFrameProcessGone)

// Sent in response to a FrameHostMsg_ContextMenu to let the renderer know that
// the menu has been closed.
IPC_MESSAGE_ROUTED1(FrameMsg_ContextMenuClosed,
                    content::CustomContextMenuContext /* custom_context */)

// Reloads all the Lo-Fi images in the RenderFrame. Ignores the cache and
// reloads from the network.
IPC_MESSAGE_ROUTED0(FrameMsg_ReloadLoFiImages)

// Executes custom context menu action that was provided from Blink.
IPC_MESSAGE_ROUTED2(FrameMsg_CustomContextMenuAction,
                    content::CustomContextMenuContext /* custom_context */,
                    unsigned /* action */)

// Requests that the RenderFrame or RenderFrameProxy updates its opener to the
// specified frame.  The routing ID may be MSG_ROUTING_NONE if the opener was
// disowned.
IPC_MESSAGE_ROUTED1(FrameMsg_UpdateOpener, int /* opener_routing_id */)

// Requests that the RenderFrame send back a response after waiting for the
// commit, activation and frame swap of the current DOM tree in blink.
IPC_MESSAGE_ROUTED1(FrameMsg_VisualStateRequest, uint64_t /* id */)

// Instructs the renderer to delete the RenderFrame.
IPC_MESSAGE_ROUTED0(FrameMsg_Delete)

// Instructs the renderer to invoke the frame's beforeunload event handler.
// Expects the result to be returned via FrameHostMsg_BeforeUnload_ACK.
IPC_MESSAGE_ROUTED1(FrameMsg_BeforeUnload, bool /* is_reload */)

// Instructs the frame to swap out for a cross-site transition, including
// running the unload event handler and creating a RenderFrameProxy with the
// given |proxy_routing_id|. Expects a SwapOut_ACK message when finished.
IPC_MESSAGE_ROUTED3(FrameMsg_SwapOut,
                    int /* proxy_routing_id */,
                    bool /* is_loading */,
                    content::FrameReplicationState /* replication_state */)

// Requests that a provisional RenderFrame swap itself into the frame tree,
// replacing the RenderFrameProxy that it is associated with.  This is used
// with remote-to-local frame navigations when the RenderFrameProxy corresponds
// to a non-live (crashed) frame.  In that case, the browser process will send
// this message as part of an early commit to stop showing the sad iframe
// without waiting for the provisional RenderFrame's navigation to commit.
IPC_MESSAGE_ROUTED0(FrameMsg_SwapIn)

// Instructs the frame to stop the load in progress, if any.
IPC_MESSAGE_ROUTED0(FrameMsg_Stop)

// PlzNavigate
// Informs the renderer that the browser stopped processing a renderer-initiated
// navigation. It does not stop ongoing loads in the current page.
IPC_MESSAGE_ROUTED0(FrameMsg_DroppedNavigation)

// A message sent to RenderFrameProxy to indicate that its corresponding
// RenderFrame has started loading a document.
IPC_MESSAGE_ROUTED0(FrameMsg_DidStartLoading)

// A message sent to RenderFrameProxy to indicate that its corresponding
// RenderFrame has completed loading.
IPC_MESSAGE_ROUTED0(FrameMsg_DidStopLoading)

// Add message to the frame console.
IPC_MESSAGE_ROUTED2(FrameMsg_AddMessageToConsole,
                    content::ConsoleMessageLevel /* level */,
                    std::string /* message */)

// Request for the renderer to execute JavaScript in the frame's context.
//
// javascript is the string containing the JavaScript to be executed in the
// target frame's context.
//
// If the third parameter is true the result is sent back to the browser using
// the message FrameHostMsg_JavaScriptExecuteResponse.
// FrameHostMsg_JavaScriptExecuteResponse is passed the ID parameter so that the
// host can uniquely identify the request.
IPC_MESSAGE_ROUTED3(FrameMsg_JavaScriptExecuteRequest,
                    base::string16,  /* javascript */
                    int,  /* ID */
                    bool  /* if true, a reply is requested */)

// ONLY FOR TESTS: Same as above but adds a fake UserGestureindicator around
// execution. (crbug.com/408426)
IPC_MESSAGE_ROUTED4(FrameMsg_JavaScriptExecuteRequestForTests,
                    base::string16,  /* javascript */
                    int,  /* ID */
                    bool, /* if true, a reply is requested */
                    bool  /* if true, a user gesture indicator is created */)

// Same as FrameMsg_JavaScriptExecuteRequest above except the script is
// run in the isolated world specified by the fourth parameter.
IPC_MESSAGE_ROUTED4(FrameMsg_JavaScriptExecuteRequestInIsolatedWorld,
                    base::string16, /* javascript */
                    int, /* ID */
                    bool, /* if true, a reply is requested */
                    int /* world_id */)

// Tells the renderer to reload the frame, optionally bypassing the cache while
// doing so.
IPC_MESSAGE_ROUTED1(FrameMsg_Reload,
                    bool /* bypass_cache */)

// Requests the corresponding RenderFrameProxy to be deleted and removed from
// the frame tree.
IPC_MESSAGE_ROUTED0(FrameMsg_DeleteProxy)

// Request the text surrounding the selection with a |max_length|. The response
// will be sent via FrameHostMsg_TextSurroundingSelectionResponse.
IPC_MESSAGE_ROUTED1(FrameMsg_TextSurroundingSelectionRequest,
                    uint32_t /* max_length */)

// Change the accessibility mode in the renderer process.
IPC_MESSAGE_ROUTED1(FrameMsg_SetAccessibilityMode, ui::AXMode)

// Sent to a proxy to record the resource timing info for this frame in the
// parent frame.
IPC_MESSAGE_ROUTED1(FrameMsg_ForwardResourceTimingToParent,
                    content::ResourceTimingInfo)

// Sent to a proxy to dispatch a load event in the iframe element containing
// this frame.
IPC_MESSAGE_ROUTED0(FrameMsg_DispatchLoad)

// Sent to a subframe to control whether to collapse its the frame owner element
// in the embedder document, that is, to remove it from the layout as if it did
// not exist.
IPC_MESSAGE_ROUTED1(FrameMsg_Collapse, bool /* collapsed */)

// Notifies the frame that its parent has changed the frame's sandbox flags or
// container policy.
IPC_MESSAGE_ROUTED1(FrameMsg_DidUpdateFramePolicy, blink::FramePolicy)

// Sent to a frame proxy after navigation, when the active sandbox flags on its
// real frame have been updated by a CSP header which sets sandbox flags, or
// when the feature policy header has been set.
IPC_MESSAGE_ROUTED2(FrameMsg_DidSetFramePolicyHeaders,
                    blink::WebSandboxFlags,
                    blink::ParsedFeaturePolicy)

// Update a proxy's window.name property.  Used when the frame's name is
// changed in another process.
IPC_MESSAGE_ROUTED2(FrameMsg_DidUpdateName,
                    std::string /* name */,
                    std::string /* unique_name */)

// Updates replicated ContentSecurityPolicy in a frame proxy.
IPC_MESSAGE_ROUTED1(FrameMsg_AddContentSecurityPolicies,
                    std::vector<content::ContentSecurityPolicyHeader>)

// Resets ContentSecurityPolicy in a frame proxy / in RemoteSecurityContext.
IPC_MESSAGE_ROUTED0(FrameMsg_ResetContentSecurityPolicy)

// Update a proxy's replicated enforcement of insecure request policy.
// Used when the frame's policy is changed in another process.
IPC_MESSAGE_ROUTED1(FrameMsg_EnforceInsecureRequestPolicy,
                    blink::WebInsecureRequestPolicy)

// Update a proxy's replicated set for enforcement of insecure navigations.
// Used when the frame's set is changed in another process.
IPC_MESSAGE_ROUTED1(FrameMsg_EnforceInsecureNavigationsSet,
                    std::vector<uint32_t> /* set */)

// Update a proxy's replicated origin.  Used when the frame is navigated to a
// new origin.
IPC_MESSAGE_ROUTED2(FrameMsg_DidUpdateOrigin,
                    url::Origin /* origin */,
                    bool /* is potentially trustworthy unique origin */)

// Notifies RenderFrameProxy that its associated RenderWidgetHostView has
// changed.
IPC_MESSAGE_ROUTED1(FrameMsg_ViewChanged,
                    content::FrameMsg_ViewChanged_Params /* params */)

// Notifies this frame or proxy that it is now focused.  This is used to
// support cross-process focused frame changes.
IPC_MESSAGE_ROUTED0(FrameMsg_SetFocusedFrame)

// Sent to a frame proxy when its real frame is preparing to enter fullscreen
// in another process.  Actually entering fullscreen will be done separately as
// part of ViewMsg_Resize, once the browser process has resized the tab for
// fullscreen.
IPC_MESSAGE_ROUTED0(FrameMsg_WillEnterFullscreen)

// Send to the RenderFrame to set text tracks state and style settings.
// Sent for top-level frames.
IPC_MESSAGE_ROUTED1(FrameMsg_SetTextTrackSettings,
                    FrameMsg_TextTrackSettings_Params /* params */)

// Sent to a frame when one of its remote children finishes loading, so that the
// frame can update its loading state.
IPC_MESSAGE_ROUTED0(FrameMsg_CheckCompleted)

// Posts a message from a frame in another process to the current renderer.
IPC_MESSAGE_ROUTED1(FrameMsg_PostMessageEvent, FrameMsg_PostMessage_Params)

// Tells the RenderFrame to clear the focused element (if any).
IPC_MESSAGE_ROUTED0(FrameMsg_ClearFocusedElement)

// Informs the parent renderer that the child is beginning an autoresize
// transaction.
IPC_MESSAGE_ROUTED(FrameMsg_BeginResizeDueToAutoResize)

// Informs the parent renderer that the child has completed an autoresize
// transaction and that the child can now allocate a new viz::LocalSurfaceId
// for its new size.
IPC_MESSAGE_ROUTED1(FrameMsg_EndResizeDueToAutoResize,
                    uint64_t /* sequence_number */)

// Requests a viz::LocalSurfaceId to enable auto-resize mode from the parent
// renderer.
IPC_MESSAGE_ROUTED2(FrameMsg_EnableAutoResize,
                    gfx::Size /* min_size */,
                    gfx::Size /* max_size */)

// Requests a viz::LocalSurfaceId to disable auto-resize-mode from the parent
// renderer.
IPC_MESSAGE_ROUTED0(FrameMsg_DisableAutoResize)

#if defined(OS_ANDROID)
// Request the distance to the nearest find result in a frame from the point at
// (x, y), defined in fractions of the content document's width and height. The
// distance will be returned via FrameHostMsg_GetNearestFindResult_Reply.  Note
// that |nfr_request_id| is a completely seperate ID from the |request_id| used
// in other find-related IPCs. It is specifically used to uniquely identify a
// nearest find result request, rather than a find request.
IPC_MESSAGE_ROUTED3(FrameMsg_GetNearestFindResult,
                    int /* nfr_request_id */,
                    float /* x */,
                    float /* y */)

// Activates a find result. The point (x,y) is in fractions of the content
// document's width and height.
IPC_MESSAGE_ROUTED3(FrameMsg_ActivateNearestFindResult,
                    int /* request_id */,
                    float /* x */,
                    float /* y */)

// Sent when the browser wants the bounding boxes of the current find matches.
//
// If match rects are already cached on the browser side, |current_version|
// should be the version number from the FrameHostMsg_FindMatchRects_Reply
// they came in, so the renderer can tell if it needs to send updated rects.
// Otherwise just pass -1 to always receive the list of rects.
//
// There must be an active search string (it is probably most useful to call
// this immediately after a FrameHostMsg_Find_Reply message arrives with
// final_update set to true).
IPC_MESSAGE_ROUTED1(FrameMsg_FindMatchRects, int /* current_version */)
#endif

#if BUILDFLAG(USE_EXTERNAL_POPUP_MENU)
#if defined(OS_MACOSX)
IPC_MESSAGE_ROUTED1(FrameMsg_SelectPopupMenuItem,
                    int /* selected index, -1 means no selection */)
#else
IPC_MESSAGE_ROUTED2(FrameMsg_SelectPopupMenuItems,
                    bool /* user canceled the popup */,
                    std::vector<int> /* selected indices */)
#endif
#endif

// PlzNavigate
// Tells the renderer that a navigation was blocked because a content security
// policy was violated.
IPC_MESSAGE_ROUTED1(FrameMsg_ReportContentSecurityPolicyViolation,
                    content::CSPViolationParams /* violation_params */)

// Request to enumerate and return links to all savable resources in the frame
// Note: this covers only the immediate frame / doesn't cover subframes.
IPC_MESSAGE_ROUTED0(FrameMsg_GetSavableResourceLinks)

// Get html data by serializing the target frame and replacing all resource
// links with a path to the local copy passed in the message payload.
IPC_MESSAGE_ROUTED2(FrameMsg_GetSerializedHtmlWithLocalLinks,
                    FrameMsg_GetSerializedHtmlWithLocalLinks_UrlMap,
                    FrameMsg_GetSerializedHtmlWithLocalLinks_FrameRoutingIdMap)

// Serialize target frame and its resources into MHTML and write it into the
// provided destination file handle.  Note that when serializing multiple
// frames, one needs to serialize the *main* frame first (the main frame
// needs to go first according to RFC2557 + the main frame will trigger
// generation of the MHTML header).
IPC_MESSAGE_ROUTED1(FrameMsg_SerializeAsMHTML, FrameMsg_SerializeAsMHTML_Params)

IPC_MESSAGE_ROUTED1(FrameMsg_SetFrameOwnerProperties,
                    content::FrameOwnerProperties /* frame_owner_properties */)

// Request to continue running the sequential focus navigation algorithm in
// this frame.  |source_routing_id| identifies the frame that issued this
// request.  This message is sent when pressing <tab> or <shift-tab> needs to
// find the next focusable element in a cross-process frame.
IPC_MESSAGE_ROUTED2(FrameMsg_AdvanceFocus,
                    blink::WebFocusType /* type */,
                    int32_t /* source_routing_id */)

// Tells the RenderFrame to advance the focus to next input node in the form by
// moving in specified direction if the currently focused node is a Text node
// (textfield, text area or content editable nodes).
IPC_MESSAGE_ROUTED1(FrameMsg_AdvanceFocusInForm,
                    blink::WebFocusType /* direction for advancing focus */)

// Sent when the user wants to search for a word on the page (find-in-page).
IPC_MESSAGE_ROUTED3(FrameMsg_Find,
                    int /* request_id */,
                    base::string16 /* search_text */,
                    blink::WebFindOptions)

// This message notifies the frame that it is no longer the active frame in the
// current find session, and so it should clear its active find match (and no
// longer highlight it with special coloring).
IPC_MESSAGE_ROUTED0(FrameMsg_ClearActiveFindMatch)

// This message notifies the frame that the user has closed the find-in-page
// window (and what action to take regarding the selection).
IPC_MESSAGE_ROUTED1(FrameMsg_StopFinding, content::StopFindAction /* action */)

// Copies the image at location x, y to the clipboard (if there indeed is an
// image at that location).
IPC_MESSAGE_ROUTED2(FrameMsg_CopyImageAt,
                    int /* x */,
                    int /* y */)

// Saves the image at location x, y to the disk (if there indeed is an
// image at that location).
IPC_MESSAGE_ROUTED2(FrameMsg_SaveImageAt,
                    int /* x */,
                    int /* y */)

// Notify the renderer of our overlay routing token.
IPC_MESSAGE_ROUTED1(FrameMsg_SetOverlayRoutingToken,
                    base::UnguessableToken /* routing_token */)

#if BUILDFLAG(ENABLE_PLUGINS)
// Notifies the renderer of updates to the Plugin Power Saver origin whitelist.
IPC_MESSAGE_ROUTED1(FrameMsg_UpdatePluginContentOriginWhitelist,
                    std::set<url::Origin> /* origin_whitelist */)

// This message notifies that the frame that the volume of the Pepper instance
// for |pp_instance| should be changed to |volume|.
IPC_MESSAGE_ROUTED2(FrameMsg_SetPepperVolume,
                    int32_t /* pp_instance */,
                    double /* volume */)
#endif  // BUILDFLAG(ENABLE_PLUGINS)

// Used to instruct the RenderFrame to go into "view source" mode. This should
// only be sent to the main frame.
IPC_MESSAGE_ROUTED0(FrameMsg_EnableViewSourceMode)

// Tells the frame to suppress any further modal dialogs. This ensures that no
// ScopedPageLoadDeferrer is on the stack for SwapOut.
IPC_MESSAGE_ROUTED0(FrameMsg_SuppressFurtherDialogs)

// Notifies the RenderFrame about a user activation from the browser side.
IPC_MESSAGE_ROUTED0(FrameMsg_NotifyUserActivation)

// Tells the frame to consider itself to have received a user gesture (based
// on a user gesture processed in a different renderer process).
IPC_MESSAGE_ROUTED0(FrameMsg_SetHasReceivedUserGesture)

// Tells the frame to mark that the previous document on that frame had received
// a user gesture on the same eTLD+1.
IPC_MESSAGE_ROUTED1(FrameMsg_SetHasReceivedUserGestureBeforeNavigation,
                    bool /* value */)

IPC_MESSAGE_ROUTED1(FrameMsg_RunFileChooserResponse,
                    std::vector<content::FileChooserFileInfo>)

// Updates the renderer with a list of unique blink::UseCounter::Feature values
// representing Blink features used, performed or encountered by the browser
// during the current page load happening on the frame.
IPC_MESSAGE_ROUTED1(FrameMsg_BlinkFeatureUsageReport,
                    std::set<int>) /* features */

// Informs the renderer that mixed content was found by the browser. The
// included data is used for instance to report to the CSP policy and to log to
// the frame console.
IPC_MESSAGE_ROUTED1(FrameMsg_MixedContentFound,
                    FrameMsg_MixedContentFound_Params)

// Sent to the parent process of a cross-process frame to request scrolling.
IPC_MESSAGE_ROUTED2(FrameMsg_ScrollRectToVisible,
                    gfx::Rect /* rect_to_scroll */,
                    blink::WebScrollIntoViewParams /* properties */)

// -----------------------------------------------------------------------------
// Messages sent from the renderer to the browser.

// Blink and JavaScript error messages to log to the console
// or debugger UI.
IPC_MESSAGE_ROUTED4(FrameHostMsg_DidAddMessageToConsole,
                    int32_t,        /* log level */
                    base::string16, /* msg */
                    int32_t,        /* line number */
                    base::string16 /* source id */)

// Sent by the renderer when a child frame is created in the renderer.
//
// Each of these messages will have a corresponding FrameHostMsg_Detach message
// sent when the frame is detached from the DOM.
// Note that |new_render_frame_id|, |new_interface_provider|, and
// |devtools_frame_token| are out parameters. Browser process defines them for
// the renderer process.
IPC_SYNC_MESSAGE_CONTROL1_3(
    FrameHostMsg_CreateChildFrame,
    FrameHostMsg_CreateChildFrame_Params,
    int32_t,                 /* new_routing_id */
    mojo::MessagePipeHandle, /* new_interface_provider */
    base::UnguessableToken /* devtools_frame_token */)

// Sent by the renderer to the parent RenderFrameHost when a child frame is
// detached from the DOM.
IPC_MESSAGE_ROUTED0(FrameHostMsg_Detach)

// Indicates the renderer process is gone.  This actually is sent by the
// browser process to itself, but keeps the interface cleaner.
IPC_MESSAGE_ROUTED2(FrameHostMsg_RenderProcessGone,
                    int, /* this really is base::TerminationStatus */
                    int /* exit_code */)

// Sent by the renderer when the frame becomes focused.
IPC_MESSAGE_ROUTED0(FrameHostMsg_FrameFocused)

// Sent when the renderer starts a provisional load for a frame.
IPC_MESSAGE_ROUTED3(FrameHostMsg_DidStartProvisionalLoad,
                    GURL /* url */,
                    std::vector<GURL> /* redirect_chain */,
                    base::TimeTicks /* navigation_start */)

// Sent when the renderer fails a provisional load with an error.
IPC_MESSAGE_ROUTED1(FrameHostMsg_DidFailProvisionalLoadWithError,
                    FrameHostMsg_DidFailProvisionalLoadWithError_Params)

// Notifies the browser that a document has been loaded.
IPC_MESSAGE_ROUTED0(FrameHostMsg_DidFinishDocumentLoad)

IPC_MESSAGE_ROUTED3(FrameHostMsg_DidFailLoadWithError,
                    GURL /* validated_url */,
                    int /* error_code */,
                    base::string16 /* error_description */)

// Sent when the renderer starts loading the page. |to_different_document| will
// be true unless the load is a fragment navigation, or triggered by
// history.pushState/replaceState.
IPC_MESSAGE_ROUTED1(FrameHostMsg_DidStartLoading,
                    bool /* to_different_document */)

// Sent when the renderer is done loading a page.
IPC_MESSAGE_ROUTED0(FrameHostMsg_DidStopLoading)

// Notifies the browser that this frame has new session history information.
IPC_MESSAGE_ROUTED1(FrameHostMsg_UpdateState, content::PageState /* state */)

// Notifies the browser process about a new Content Security Policy that needs
// to be applies to the frame.  This message is sent when a frame commits
// navigation to a new location (reporting accumulated policies from HTTP
// headers and/or policies that might have been inherited from the parent frame)
// or when a new policy has been discovered afterwards (i.e. found in a
// dynamically added or a static <meta> element).
IPC_MESSAGE_ROUTED1(FrameHostMsg_DidAddContentSecurityPolicies,
                    std::vector<content::ContentSecurityPolicy> /* policies */)

// Sent when the renderer changed the progress of a load.
IPC_MESSAGE_ROUTED1(FrameHostMsg_DidChangeLoadProgress,
                    double /* load_progress */)

// Requests that the given URL be opened in the specified manner.
IPC_MESSAGE_ROUTED1(FrameHostMsg_OpenURL, FrameHostMsg_OpenURL_Params)

// Notifies the browser that a frame finished loading.
IPC_MESSAGE_ROUTED1(FrameHostMsg_DidFinishLoad,
                    GURL /* validated_url */)

// Initiates a download based on user actions like 'ALT+click'.
IPC_MESSAGE_CONTROL(FrameHostMsg_DownloadUrl, FrameHostMsg_DownloadUrl_Params)

// Asks the browser to save a image (for <canvas> or <img>) from a data URL.
// Note: |data_url| is the contents of a data:URL, and that it's represented as
// a string only to work around size limitations for GURLs in IPC messages.
IPC_MESSAGE_CONTROL3(FrameHostMsg_SaveImageFromDataURL,
                     int /* render_view_id */,
                     int /* render_frame_id */,
                     std::string /* data_url */)

// Sent when after the onload handler has been invoked for the document
// in this frame. Sent for top-level frames. |report_type| and |ui_timestamp|
// are used to report navigation metrics starting on the ui input event that
// triggered the navigation timestamp.
IPC_MESSAGE_ROUTED2(FrameHostMsg_DocumentOnLoadCompleted,
                    FrameMsg_UILoadMetricsReportType::Value /* report_type */,
                    base::TimeTicks /* ui_timestamp */)

// Notifies that the initial empty document of a view has been accessed.
// After this, it is no longer safe to show a pending navigation's URL without
// making a URL spoof possible.
IPC_MESSAGE_ROUTED0(FrameHostMsg_DidAccessInitialDocument)

// Sent when the RenderFrame or RenderFrameProxy either updates its opener to
// another frame identified by |opener_routing_id|, or, if |opener_routing_id|
// is MSG_ROUTING_NONE, the frame disowns its opener for the lifetime of the
// window.
IPC_MESSAGE_ROUTED1(FrameHostMsg_DidChangeOpener, int /* opener_routing_id */)

// Notifies the browser that sandbox flags or container policy have changed for
// a subframe of this frame.
IPC_MESSAGE_ROUTED2(
    FrameHostMsg_DidChangeFramePolicy,
    int32_t /* subframe_routing_id */,
    blink::FramePolicy /* updated sandbox flags and container policy */)

// Notifies the browser that frame owner properties have changed for a subframe
// of this frame.
IPC_MESSAGE_ROUTED2(FrameHostMsg_DidChangeFrameOwnerProperties,
                    int32_t /* subframe_routing_id */,
                    content::FrameOwnerProperties /* frame_owner_properties */)

// Notifies the browser that document has parsed the body. This is used by the
// ResourceScheduler as an indication that bandwidth contention won't block
// first paint.
IPC_MESSAGE_ROUTED1(FrameHostMsg_WillInsertBody,
                    int /* render_view_routing_id */)

// Changes the title for the page in the UI when the page is navigated or the
// title changes. Sent for top-level frames.
IPC_MESSAGE_ROUTED2(FrameHostMsg_UpdateTitle,
                    base::string16 /* title */,
                    blink::WebTextDirection /* title direction */)

// Following message is used to communicate the values received by the
// callback binding the JS to Cpp.
// An instance of browser that has an automation host listening to it can
// have a javascript send a native value (string, number, boolean) to the
// listener in Cpp. (DomAutomationController)
IPC_MESSAGE_ROUTED1(FrameHostMsg_DomOperationResponse,
                    std::string  /* json_string */)

// Used to check if cookies are enabled for the given URL. This may block
// waiting for a previous SetCookie message to be processed.
IPC_SYNC_MESSAGE_CONTROL3_1(FrameHostMsg_CookiesEnabled,
                            int /* render_frame_id */,
                            GURL /* url */,
                            GURL /* site_for_cookies */,
                            bool /* cookies_enabled */)

// Sent by the renderer process to check whether client 3D APIs
// (Pepper 3D, WebGL) are explicitly blocked.
IPC_SYNC_MESSAGE_CONTROL3_1(FrameHostMsg_Are3DAPIsBlocked,
                            int /* render_frame_id */,
                            GURL /* top_origin_url */,
                            content::ThreeDAPIType /* requester */,
                            bool /* blocked */)

// Message sent from renderer to the browser when focus changes inside the
// frame. The first parameter says whether the newly focused element needs
// keyboard input (true for textfields, text areas and content editable divs).
// The second parameter is the node bounds relative to local root's
// RenderWidgetHostView.
IPC_MESSAGE_ROUTED2(FrameHostMsg_FocusedNodeChanged,
                    bool /* is_editable_node */,
                    gfx::Rect /* node_bounds */)

#if BUILDFLAG(ENABLE_PLUGINS)
// Notification sent from a renderer to the browser that a Pepper plugin
// instance is created in the DOM.
IPC_MESSAGE_ROUTED1(FrameHostMsg_PepperInstanceCreated,
                    int32_t /* pp_instance */)

// Notification sent from a renderer to the browser that a Pepper plugin
// instance is deleted from the DOM.
IPC_MESSAGE_ROUTED1(FrameHostMsg_PepperInstanceDeleted,
                    int32_t /* pp_instance */)

// Sent to the browser when the renderer detects it is blocked on a pepper
// plugin message for too long. This is also sent when it becomes unhung
// (according to the value of is_hung). The browser can give the user the
// option of killing the plugin.
IPC_MESSAGE_ROUTED3(FrameHostMsg_PepperPluginHung,
                    int /* plugin_child_id */,
                    base::FilePath /* path */,
                    bool /* is_hung */)

// Sent by the renderer process to indicate that a plugin instance has crashed.
// Note: |plugin_pid| should not be trusted. The corresponding process has
// probably died. Moreover, the ID may have been reused by a new process. Any
// usage other than displaying it in a prompt to the user is very likely to be
// wrong.
IPC_MESSAGE_ROUTED2(FrameHostMsg_PluginCrashed,
                    base::FilePath /* plugin_path */,
                    base::ProcessId /* plugin_pid */)

// Notification sent from a renderer to the browser that a Pepper plugin
// instance has started playback.
IPC_MESSAGE_ROUTED1(FrameHostMsg_PepperStartsPlayback,
                    int32_t /* pp_instance */)

// Notification sent from a renderer to the browser that a Pepper plugin
// instance has stopped playback.
IPC_MESSAGE_ROUTED1(FrameHostMsg_PepperStopsPlayback,
                    int32_t /* pp_instance */)

// Used to get the list of plugins. |main_frame_origin| is used to handle
// exceptions for plugin content settings.
IPC_SYNC_MESSAGE_CONTROL2_1(FrameHostMsg_GetPlugins,
                            bool /* refresh*/,
                            url::Origin /* main_frame_origin */,
                            std::vector<content::WebPluginInfo> /* plugins */)

// Return information about a plugin for the given URL and MIME
// type. If there is no matching plugin, |found| is false.
// |actual_mime_type| is the actual mime type supported by the
// found plugin.
IPC_SYNC_MESSAGE_CONTROL4_3(FrameHostMsg_GetPluginInfo,
                            int /* render_frame_id */,
                            GURL /* url */,
                            url::Origin /* main_frame_origin */,
                            std::string /* mime_type */,
                            bool /* found */,
                            content::WebPluginInfo /* plugin info */,
                            std::string /* actual_mime_type */)

// A renderer sends this to the browser process when it wants to temporarily
// whitelist an origin's plugin content as essential. This temporary whitelist
// is specific to a top level frame, and is cleared when the whitelisting
// RenderFrame is destroyed.
IPC_MESSAGE_ROUTED1(FrameHostMsg_PluginContentOriginAllowed,
                    url::Origin /* content_origin */)

// A renderer sends this to the browser process when it wants to create a ppapi
// plugin.  The browser will create the plugin process if necessary, and will
// return a handle to the channel on success.
//
// The plugin_child_id is the ChildProcessHost ID assigned in the browser
// process. This ID is valid only in the context of the browser process and is
// used to identify the proper process when the renderer notifies it that the
// plugin is hung.
//
// On error an empty string and null handles are returned.
IPC_SYNC_MESSAGE_CONTROL2_3(FrameHostMsg_OpenChannelToPepperPlugin,
                            base::FilePath /* path */,
                            base::Optional<url::Origin>, /* origin_lock */
                            IPC::ChannelHandle /* handle to channel */,
                            base::ProcessId /* plugin_pid */,
                            int /* plugin_child_id */)

// Message from the renderer to the browser indicating the in-process instance
// has been created.
IPC_MESSAGE_CONTROL2(FrameHostMsg_DidCreateInProcessInstance,
                     int32_t /* instance */,
                     content::PepperRendererInstanceData /* instance_data */)

// Message from the renderer to the browser indicating the in-process instance
// has been destroyed.
IPC_MESSAGE_CONTROL1(FrameHostMsg_DidDeleteInProcessInstance,
                     int32_t /* instance */)

// Notification that a plugin has created a new plugin instance. The parameters
// indicate:
//  - The plugin process ID that we're creating the instance for.
//  - The instance ID of the instance being created.
//  - A PepperRendererInstanceData struct which contains properties from the
//    renderer which are associated with the plugin instance. This includes the
//    routing ID of the associated RenderFrame and the URL of plugin.
//  - Whether the plugin we're creating an instance for is external or internal.
//
// This message must be sync even though it returns no parameters to avoid
// a race condition with the plugin process. The plugin process sends messages
// to the browser that assume the browser knows about the instance. We need to
// make sure that the browser actually knows about the instance before we tell
// the plugin to run.
IPC_SYNC_MESSAGE_CONTROL4_0(
    FrameHostMsg_DidCreateOutOfProcessPepperInstance,
    int /* plugin_child_id */,
    int32_t /* pp_instance */,
    content::PepperRendererInstanceData /* creation_data */,
    bool /* is_external */)

// Notification that a plugin has destroyed an instance. This is the opposite of
// the "DidCreate" message above.
IPC_MESSAGE_CONTROL3(FrameHostMsg_DidDeleteOutOfProcessPepperInstance,
                     int /* plugin_child_id */,
                     int32_t /* pp_instance */,
                     bool /* is_external */)

// A renderer sends this to the browser process when it wants to
// create a ppapi broker.  The browser will create the broker process
// if necessary, and will return a handle to the channel on success.
// On error an empty string is returned.
// The browser will respond with ViewMsg_PpapiBrokerChannelCreated.
IPC_MESSAGE_CONTROL2(FrameHostMsg_OpenChannelToPpapiBroker,
                     int /* routing_id */,
                     base::FilePath /* path */)

// A renderer sends this to the browser process when it throttles or unthrottles
// a plugin instance for the Plugin Power Saver feature.
IPC_MESSAGE_CONTROL3(FrameHostMsg_PluginInstanceThrottleStateChange,
                     int /* plugin_child_id */,
                     int32_t /* pp_instance */,
                     bool /* is_throttled */)
#endif  // BUILDFLAG(ENABLE_PLUGINS)

// Provides the result from handling BeforeUnload.  |proceed| matches the return
// value of the frame's beforeunload handler: true if the user decided to
// proceed with leaving the page.
IPC_MESSAGE_ROUTED3(FrameHostMsg_BeforeUnload_ACK,
                    bool /* proceed */,
                    base::TimeTicks /* before_unload_start_time */,
                    base::TimeTicks /* before_unload_end_time */)

// Indicates that the current frame has swapped out, after a SwapOut message.
IPC_MESSAGE_ROUTED0(FrameHostMsg_SwapOut_ACK)

// Tells the browser that a child's resize parameters have changed.
IPC_MESSAGE_ROUTED2(FrameHostMsg_UpdateResizeParams,
                    viz::SurfaceId /* surface_id */,
                    content::FrameResizeParams)

// Sent by a parent frame to update its child's viewport intersection rect for
// use by the IntersectionObserver API.
// compositor_rect is dependent on the intersection rect and indicates the
// area of the child frame that needs to be rastered. It is in physical pixels.
IPC_MESSAGE_ROUTED2(FrameHostMsg_UpdateViewportIntersection,
                    gfx::Rect /* viewport_intersection */,
                    gfx::Rect /* compositor_visible_rect */)

// Informs the child that the frame has changed visibility.
IPC_MESSAGE_ROUTED1(FrameHostMsg_VisibilityChanged, bool /* visible */)

// Sets or unsets the inert bit on a remote frame.
IPC_MESSAGE_ROUTED1(FrameHostMsg_SetIsInert, bool /* inert */)

// Toggles render throttling on a remote frame. |is_throttled| indicates
// whether the current frame should be throttled based on its viewport
// visibility, and |subtree_throttled| indicates that an ancestor frame has
// been throttled, so all descendant frames also should be throttled.
IPC_MESSAGE_ROUTED2(FrameHostMsg_UpdateRenderThrottlingStatus,
                    bool /* is_throttled */,
                    bool /* subtree_throttled */)

// Indicates that this frame recieved a user gesture, so that the state can be
// propagated to any remote frames.
IPC_MESSAGE_ROUTED0(FrameHostMsg_SetHasReceivedUserGesture)

// Indicates that this frame received a user gesture on a previous navigation on
// the same eTLD+1. This ensures the state is propagated to any remote frames.
IPC_MESSAGE_ROUTED1(FrameHostMsg_SetHasReceivedUserGestureBeforeNavigation,
                    bool /* value */)

// Used to tell the parent that the user right clicked on an area of the
// content area, and a context menu should be shown for it. The params
// object contains information about the node(s) that were selected when the
// user right clicked.
IPC_MESSAGE_ROUTED1(FrameHostMsg_ContextMenu, content::ContextMenuParams)

// Notification that the text selection has changed.
// Note: The second parameter is the character based offset of the
// base::string16 text in the document.
IPC_MESSAGE_ROUTED3(FrameHostMsg_SelectionChanged,
                    base::string16 /* text covers the selection range */,
                    uint32_t /* the offset of the text in the document */,
                    gfx::Range /* selection range in the document */)

// Response for FrameMsg_JavaScriptExecuteRequest, sent when a reply was
// requested. The ID is the parameter supplied to
// FrameMsg_JavaScriptExecuteRequest. The result has the value returned by the
// script as its only element, one of Null, Boolean, Integer, Real, Date, or
// String.
IPC_MESSAGE_ROUTED2(FrameHostMsg_JavaScriptExecuteResponse,
                    int  /* id */,
                    base::ListValue  /* result */)

// A request to run a JavaScript dialog.
IPC_SYNC_MESSAGE_ROUTED3_2(FrameHostMsg_RunJavaScriptDialog,
                           base::string16 /* in - alert message */,
                           base::string16 /* in - default prompt */,
                           content::JavaScriptDialogType /* in - type */,
                           bool /* out - success */,
                           base::string16 /* out - user_input field */)

// Displays a dialog to confirm that the user wants to navigate away from the
// page. Replies true if yes, and false otherwise. The reply string is ignored,
// but is included so that we can use
// RenderFrameHostImpl::SendJavaScriptDialogReply.
IPC_SYNC_MESSAGE_ROUTED1_2(FrameHostMsg_RunBeforeUnloadConfirm,
                           bool /* in - is a reload */,
                           bool /* out - success */,
                           base::string16 /* out - This is ignored.*/)

// Notify browser the theme color has been changed.
IPC_MESSAGE_ROUTED1(FrameHostMsg_DidChangeThemeColor,
                    SkColor /* theme_color */)

// Response for FrameMsg_TextSurroundingSelectionRequest, |startOffset| and
// |endOffset| are the offsets of the selection in the returned |content|.
IPC_MESSAGE_ROUTED3(FrameHostMsg_TextSurroundingSelectionResponse,
                    base::string16,  /* content */
                    uint32_t, /* startOffset */
                    uint32_t/* endOffset */)

// Register a new handler for URL requests with the given scheme.
IPC_MESSAGE_ROUTED4(FrameHostMsg_RegisterProtocolHandler,
                    std::string /* scheme */,
                    GURL /* url */,
                    base::string16 /* title */,
                    bool /* user_gesture */)

// Unregister the registered handler for URL requests with the given scheme.
IPC_MESSAGE_ROUTED3(FrameHostMsg_UnregisterProtocolHandler,
                    std::string /* scheme */,
                    GURL /* url */,
                    bool /* user_gesture */)

// Sent when the renderer loads a resource from its memory cache.
// The security info is non empty if the resource was originally loaded over
// a secure connection.
// Note: May only be sent once per URL per frame per committed load.
IPC_MESSAGE_ROUTED4(FrameHostMsg_DidLoadResourceFromMemoryCache,
                    GURL /* url */,
                    std::string /* http method */,
                    std::string /* mime type */,
                    content::ResourceType /* resource type */)

// This frame attempted to navigate the main frame to the given url, even
// though this frame has never received a user gesture.
IPC_MESSAGE_ROUTED1(FrameHostMsg_DidBlockFramebust, GURL /* url */)

// PlzNavigate
// Tells the browser to abort an ongoing renderer-initiated navigation. This is
// used when the page calls document.open.
IPC_MESSAGE_ROUTED0(FrameHostMsg_AbortNavigation)

// Sent as a response to FrameMsg_VisualStateRequest.
// The message is delivered using RenderWidget::QueueMessage.
IPC_MESSAGE_ROUTED1(FrameHostMsg_VisualStateResponse, uint64_t /* id */)

// Puts the browser into "tab fullscreen" mode for the sending renderer.
// See the comment in chrome/browser/ui/browser.h for more details.
IPC_MESSAGE_ROUTED1(FrameHostMsg_EnterFullscreen, blink::WebFullscreenOptions)

// Exits the browser from "tab fullscreen" mode for the sending renderer.
// See the comment in chrome/browser/ui/browser.h for more details.
IPC_MESSAGE_ROUTED0(FrameHostMsg_ExitFullscreen)

// Sent when a new sudden termination disabler condition is either introduced or
// removed.
IPC_MESSAGE_ROUTED2(FrameHostMsg_SuddenTerminationDisablerChanged,
                    bool /* present */,
                    blink::WebSuddenTerminationDisablerType /* disabler_type */)

// Requests that the resource timing info be added to the performance entries of
// a remote parent frame.
IPC_MESSAGE_ROUTED1(FrameHostMsg_ForwardResourceTimingToParent,
                    content::ResourceTimingInfo)

// Dispatch a load event for this frame in the iframe element of an
// out-of-process parent frame.
IPC_MESSAGE_ROUTED0(FrameHostMsg_DispatchLoad)

// Sent by a frame proxy to the browser when a child frame finishes loading, so
// that the corresponding RenderFrame can check whether its load has completed.
IPC_MESSAGE_ROUTED0(FrameHostMsg_CheckCompleted)

// Sent to the browser from a frame proxy to post a message to the frame's
// active renderer.
IPC_MESSAGE_ROUTED1(FrameHostMsg_RouteMessageEvent,
                    FrameMsg_PostMessage_Params)

// Sent when the renderer displays insecure content in a secure origin.
IPC_MESSAGE_ROUTED0(FrameHostMsg_DidDisplayInsecureContent)

// Sent when the renderer displays a form containing a non-secure action target
// url on a page in a secure origin.
IPC_MESSAGE_ROUTED0(FrameHostMsg_DidContainInsecureFormAction)

// Sent when the renderer runs insecure content in a secure origin.
IPC_MESSAGE_ROUTED2(FrameHostMsg_DidRunInsecureContent,
                    GURL /* security_origin */,
                    GURL /* target URL */)

// Sent when the renderer displays content that was loaded with
// certificate errors.
IPC_MESSAGE_ROUTED0(FrameHostMsg_DidDisplayContentWithCertificateErrors)

// Sent when the renderer runs content that was loaded with certificate
// errors.
IPC_MESSAGE_ROUTED0(FrameHostMsg_DidRunContentWithCertificateErrors)

// Response to FrameMsg_GetSavableResourceLinks.
IPC_MESSAGE_ROUTED3(FrameHostMsg_SavableResourceLinksResponse,
                    std::vector<GURL> /* savable resource links */,
                    content::Referrer /* referrer for all the links above */,
                    std::vector<content::SavableSubframe> /* subframes */)

// Response to FrameMsg_GetSavableResourceLinks in case the frame contains
// non-savable content (i.e. from a non-savable scheme) or if there were
// errors gathering the links.
IPC_MESSAGE_ROUTED0(FrameHostMsg_SavableResourceLinksError)

// Response to FrameMsg_GetSerializedHtmlWithLocalLinks.
IPC_MESSAGE_ROUTED2(FrameHostMsg_SerializedHtmlWithLocalLinksResponse,
                    std::string /* data buffer */,
                    bool /* end of data? */)

// Response to FrameMsg_SerializeAsMHTML.
IPC_MESSAGE_ROUTED4(
    FrameHostMsg_SerializeAsMHTMLResponse,
    int /* job_id (used to match responses to requests) */,
    content::MhtmlSaveStatus /* final success/failure status */,
    std::set<std::string> /* digests of uris of serialized resources */,
    base::TimeDelta /* how much time of the main render thread was used */)

// Sent when the renderer updates hint for importance of a tab.
IPC_MESSAGE_ROUTED1(FrameHostMsg_UpdatePageImportanceSignals,
                    content::PageImportanceSignals)

// This message is sent from a RenderFrameProxy when sequential focus
// navigation needs to advance into its actual frame.  |source_routing_id|
// identifies the frame that issued this request.  This is used when pressing
// <tab> or <shift-tab> hits an out-of-process iframe when searching for the
// next focusable element.
IPC_MESSAGE_ROUTED2(FrameHostMsg_AdvanceFocus,
                    blink::WebFocusType /* type */,
                    int32_t /* source_routing_id */)

// Result of string search in the document.
// Response to FrameMsg_Find with the results of the requested find-in-page
// search, the number of matches found and the selection rect (in screen
// coordinates) for the string found. If |final_update| is false, it signals
// that this is not the last Find_Reply message - more will be sent as the
// scoping effort continues.
IPC_MESSAGE_ROUTED5(FrameHostMsg_Find_Reply,
                    int /* request_id */,
                    int /* number of matches */,
                    gfx::Rect /* selection_rect */,
                    int /* active_match_ordinal */,
                    bool /* final_update */)

// Sends hittesting data needed to perform hittesting on the browser process.
IPC_MESSAGE_ROUTED1(FrameHostMsg_HittestData, FrameHostMsg_HittestData_Params)

// Request that the host send its overlay routing token for this render frame
// via SetOverlayRoutingToken.
IPC_MESSAGE_ROUTED0(FrameHostMsg_RequestOverlayRoutingToken)

// Asks the browser to display the file chooser.  The result is returned in a
// FrameMsg_RunFileChooserResponse message.
IPC_MESSAGE_ROUTED1(FrameHostMsg_RunFileChooser, content::FileChooserParams)

// Notification that the urls for the favicon of a site has been determined.
IPC_MESSAGE_ROUTED1(FrameHostMsg_UpdateFaviconURL,
                    std::vector<content::FaviconURL> /* candidates */)

// A message from HTML-based UI.  When (trusted) Javascript calls
// send(message, args), this message is sent to the browser.
IPC_MESSAGE_ROUTED3(FrameHostMsg_WebUISend,
                    GURL /* source_url */,
                    std::string /* message */,
                    base::ListValue /* args */)

// Sent by a local root to request scrolling in its parent process.
IPC_MESSAGE_ROUTED2(FrameHostMsg_ScrollRectToVisibleInParentFrame,
                    gfx::Rect /* rect_to_scroll */,
                    blink::WebScrollIntoViewParams /* properties */)

// Sent to notify that a frame called |window.focus()|.
IPC_MESSAGE_ROUTED0(FrameHostMsg_FrameDidCallFocus)

// Ask the frame host to print a cross-process subframe.
// The printed content of this subframe belongs to the document specified by
// its document cookie. Document cookie is a unique id for a printed document
// associated with a print job.
// The content will be rendered in the specified rectangular area in its parent
// frame.
IPC_MESSAGE_ROUTED2(FrameHostMsg_PrintCrossProcessSubframe,
                    gfx::Rect /* rect area of the frame content */,
                    int /* rendered document cookie */)

#if BUILDFLAG(USE_EXTERNAL_POPUP_MENU)

// Message to show/hide a popup menu using native controls.
IPC_MESSAGE_ROUTED1(FrameHostMsg_ShowPopup,
                    FrameHostMsg_ShowPopup_Params)
IPC_MESSAGE_ROUTED0(FrameHostMsg_HidePopup)

#endif

#if defined(OS_ANDROID)
// Response to FrameMsg_FindMatchRects.
//
// |version| will contain the current version number of the renderer's find
// match list (incremented whenever they change), which should be passed in the
// next call to FrameMsg_FindMatchRects.
//
// |rects| will either contain a list of the enclosing rects of all matches
// found by the most recent Find operation, or will be empty if |version| is not
// greater than the |current_version| passed to FrameMsg_FindMatchRects (hence
// your locally cached rects should still be valid). The rect coords will be
// custom normalized fractions of the document size. The rects will be sorted by
// frame traversal order starting in the main frame, then by dom order.
//
// |active_rect| will contain the bounding box of the active find-in-page match
// marker, in similarly normalized coords (or an empty rect if there isn't one).
IPC_MESSAGE_ROUTED3(FrameHostMsg_FindMatchRects_Reply,
                    int /* version */,
                    std::vector<gfx::RectF> /* rects */,
                    gfx::RectF /* active_rect */)

// Response to FrameMsg_GetNearestFindResult. |distance| is the distance to the
// nearest find result in the sending frame.
IPC_MESSAGE_ROUTED2(FrameHostMsg_GetNearestFindResult_Reply,
                    int /* nfr_request_id */,
                    float /* distance */)
#endif

// Adding a new message? Stick to the sort order above: first platform
// independent FrameMsg, then ifdefs for platform specific FrameMsg, then
// platform independent FrameHostMsg, then ifdefs for platform specific
// FrameHostMsg.

#endif  // CONTENT_COMMON_FRAME_MESSAGES_H_

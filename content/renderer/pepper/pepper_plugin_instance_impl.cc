// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/pepper/pepper_plugin_instance_impl.h"

#include <utility>

#include "base/bind.h"
#include "base/bit_cast.h"
#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_offset_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "cc/blink/web_layer_impl.h"
#include "cc/layers/texture_layer.h"
#include "content/common/content_constants_internal.h"
#include "content/common/frame_messages.h"
#include "content/public/common/content_constants.h"
#include "content/public/renderer/content_renderer_client.h"
#include "content/renderer/media/audio_device_factory.h"
#include "content/renderer/pepper/event_conversion.h"
#include "content/renderer/pepper/fullscreen_container.h"
#include "content/renderer/pepper/gfx_conversion.h"
#include "content/renderer/pepper/host_dispatcher_wrapper.h"
#include "content/renderer/pepper/host_globals.h"
#include "content/renderer/pepper/message_channel.h"
#include "content/renderer/pepper/pepper_audio_controller.h"
#include "content/renderer/pepper/pepper_browser_connection.h"
#include "content/renderer/pepper/pepper_compositor_host.h"
#include "content/renderer/pepper/pepper_file_ref_renderer_host.h"
#include "content/renderer/pepper/pepper_graphics_2d_host.h"
#include "content/renderer/pepper/pepper_in_process_router.h"
#include "content/renderer/pepper/pepper_plugin_instance_metrics.h"
#include "content/renderer/pepper/pepper_try_catch.h"
#include "content/renderer/pepper/pepper_url_loader_host.h"
#include "content/renderer/pepper/plugin_instance_throttler_impl.h"
#include "content/renderer/pepper/plugin_module.h"
#include "content/renderer/pepper/plugin_object.h"
#include "content/renderer/pepper/ppapi_preferences_builder.h"
#include "content/renderer/pepper/ppb_buffer_impl.h"
#include "content/renderer/pepper/ppb_graphics_3d_impl.h"
#include "content/renderer/pepper/ppb_image_data_impl.h"
#include "content/renderer/pepper/renderer_ppapi_host_impl.h"
#include "content/renderer/pepper/url_request_info_util.h"
#include "content/renderer/pepper/url_response_info_util.h"
#include "content/renderer/render_frame_impl.h"
#include "content/renderer/render_thread_impl.h"
#include "content/renderer/render_view_impl.h"
#include "content/renderer/render_widget.h"
#include "content/renderer/render_widget_fullscreen_pepper.h"
#include "content/renderer/sad_plugin.h"
#include "device/gamepad/public/cpp/gamepads.h"
#include "ppapi/c/dev/ppp_text_input_dev.h"
#include "ppapi/c/pp_rect.h"
#include "ppapi/c/ppb_audio_config.h"
#include "ppapi/c/ppb_core.h"
#include "ppapi/c/ppb_gamepad.h"
#include "ppapi/c/ppp_input_event.h"
#include "ppapi/c/ppp_instance.h"
#include "ppapi/c/ppp_messaging.h"
#include "ppapi/c/ppp_mouse_lock.h"
#include "ppapi/c/private/ppb_find_private.h"
#include "ppapi/c/private/ppp_find_private.h"
#include "ppapi/c/private/ppp_instance_private.h"
#include "ppapi/c/private/ppp_pdf.h"
#include "ppapi/host/ppapi_host.h"
#include "ppapi/proxy/ppapi_messages.h"
#include "ppapi/proxy/serialized_var.h"
#include "ppapi/proxy/uma_private_resource.h"
#include "ppapi/proxy/url_loader_resource.h"
#include "ppapi/shared_impl/ppapi_permissions.h"
#include "ppapi/shared_impl/ppb_gamepad_shared.h"
#include "ppapi/shared_impl/ppb_input_event_shared.h"
#include "ppapi/shared_impl/ppb_url_util_shared.h"
#include "ppapi/shared_impl/ppb_view_shared.h"
#include "ppapi/shared_impl/ppp_instance_combined.h"
#include "ppapi/shared_impl/resource.h"
#include "ppapi/shared_impl/scoped_pp_resource.h"
#include "ppapi/shared_impl/scoped_pp_var.h"
#include "ppapi/shared_impl/time_conversion.h"
#include "ppapi/shared_impl/url_request_info_data.h"
#include "ppapi/shared_impl/var.h"
#include "ppapi/thunk/enter.h"
#include "ppapi/thunk/ppb_buffer_api.h"
#include "printing/buildflags/buildflags.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/blink/public/platform/url_conversion.h"
#include "third_party/blink/public/platform/web_coalesced_input_event.h"
#include "third_party/blink/public/platform/web_cursor_info.h"
#include "third_party/blink/public/platform/web_float_rect.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "third_party/blink/public/platform/web_keyboard_event.h"
#include "third_party/blink/public/platform/web_mouse_event.h"
#include "third_party/blink/public/platform/web_pointer_event.h"
#include "third_party/blink/public/platform/web_rect.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_touch_event.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_document_loader.h"
#include "third_party/blink/public/web/web_ime_text_span.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_plugin_container.h"
#include "third_party/blink/public/web/web_plugin_script_forbidden_scope.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/public/web/web_print_preset_options.h"
#include "third_party/blink/public/web/web_print_scaling_option.h"
#include "third_party/blink/public/web/web_scoped_user_gesture.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_user_gesture_indicator.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/khronos/GLES2/gl2.h"
#include "ui/events/blink/blink_event_util.h"
#include "ui/events/blink/web_input_event.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/gfx/image/image_skia_rep.h"
#include "ui/gfx/range/range.h"
#include "url/origin.h"
#include "v8/include/v8.h"

#if BUILDFLAG(ENABLE_PRINTING)
// nogncheck because dependency on //printing is conditional upon
// enable_basic_printing flags.
#include "printing/metafile_skia_wrapper.h"  // nogncheck
#include "printing/pdf_metafile_skia.h"  // nogncheck
#endif

#if defined(OS_CHROMEOS)
#include "ui/events/keycodes/keyboard_codes_posix.h"
#endif

// Windows defines 'PostMessage', so we have to undef it.
#ifdef PostMessage
#undef PostMessage
#endif

using base::StringPrintf;
using ppapi::InputEventData;
using ppapi::PpapiGlobals;
using ppapi::PPB_InputEvent_Shared;
using ppapi::PPB_View_Shared;
using ppapi::PPP_Instance_Combined;
using ppapi::Resource;
using ppapi::ScopedPPResource;
using ppapi::ScopedPPVar;
using ppapi::StringVar;
using ppapi::TrackedCallback;
using ppapi::thunk::EnterResourceNoLock;
using ppapi::thunk::PPB_Buffer_API;
using ppapi::thunk::PPB_Gamepad_API;
using ppapi::thunk::PPB_Graphics2D_API;
using ppapi::thunk::PPB_Graphics3D_API;
using ppapi::thunk::PPB_ImageData_API;
using ppapi::Var;
using ppapi::ArrayBufferVar;
using ppapi::ViewData;
using blink::WebCanvas;
using blink::WebCursorInfo;
using blink::WebDocument;
using blink::WebElement;
using blink::WebFrame;
using blink::WebInputEvent;
using blink::WebLocalFrame;
using blink::WebPlugin;
using blink::WebPluginContainer;
using blink::WebPrintParams;
using blink::WebPrintScalingOption;
using blink::WebScopedUserGesture;
using blink::WebString;
using blink::WebURLError;
using blink::WebAssociatedURLLoaderClient;
using blink::WebURLRequest;
using blink::WebURLResponse;
using blink::WebUserGestureIndicator;
using blink::WebUserGestureToken;
using blink::WebView;
using blink::WebWidget;

namespace content {

namespace {

#define STATIC_ASSERT_ENUM(a, b)                            \
  static_assert(static_cast<int>(a) == static_cast<int>(b), \
                "mismatching enums: " #a)

// Check PP_TextInput_Type and ui::TextInputType are kept in sync.
STATIC_ASSERT_ENUM(ui::TEXT_INPUT_TYPE_NONE, PP_TEXTINPUT_TYPE_NONE);
STATIC_ASSERT_ENUM(ui::TEXT_INPUT_TYPE_TEXT, PP_TEXTINPUT_TYPE_TEXT);
STATIC_ASSERT_ENUM(ui::TEXT_INPUT_TYPE_PASSWORD, PP_TEXTINPUT_TYPE_PASSWORD);
STATIC_ASSERT_ENUM(ui::TEXT_INPUT_TYPE_SEARCH, PP_TEXTINPUT_TYPE_SEARCH);
STATIC_ASSERT_ENUM(ui::TEXT_INPUT_TYPE_EMAIL, PP_TEXTINPUT_TYPE_EMAIL);
STATIC_ASSERT_ENUM(ui::TEXT_INPUT_TYPE_NUMBER, PP_TEXTINPUT_TYPE_NUMBER);
STATIC_ASSERT_ENUM(ui::TEXT_INPUT_TYPE_TELEPHONE, PP_TEXTINPUT_TYPE_TELEPHONE);
STATIC_ASSERT_ENUM(ui::TEXT_INPUT_TYPE_URL, PP_TEXTINPUT_TYPE_URL);

// The default text input type is to regard the plugin always accept text input.
// This is for allowing users to use input methods even on completely-IME-
// unaware plugins (e.g., PPAPI Flash or PDF plugin for M16).
// Plugins need to explicitly opt out the text input mode if they know
// that they don't accept texts.
const ui::TextInputType kPluginDefaultTextInputType = ui::TEXT_INPUT_TYPE_TEXT;

// <embed>/<object> attributes.
const char kWidth[] = "width";
const char kHeight[] = "height";
const char kBorder[] = "border";  // According to w3c, deprecated.
const char kStyle[] = "style";

#define STATIC_ASSERT_MATCHING_ENUM(webkit_name, np_name)       \
  static_assert(static_cast<int>(WebCursorInfo::webkit_name) == \
                static_cast<int>(np_name),                      \
                "mismatching enums: " #webkit_name)

STATIC_ASSERT_MATCHING_ENUM(kTypePointer, PP_MOUSECURSOR_TYPE_POINTER);
STATIC_ASSERT_MATCHING_ENUM(kTypeCross, PP_MOUSECURSOR_TYPE_CROSS);
STATIC_ASSERT_MATCHING_ENUM(kTypeHand, PP_MOUSECURSOR_TYPE_HAND);
STATIC_ASSERT_MATCHING_ENUM(kTypeIBeam, PP_MOUSECURSOR_TYPE_IBEAM);
STATIC_ASSERT_MATCHING_ENUM(kTypeWait, PP_MOUSECURSOR_TYPE_WAIT);
STATIC_ASSERT_MATCHING_ENUM(kTypeHelp, PP_MOUSECURSOR_TYPE_HELP);
STATIC_ASSERT_MATCHING_ENUM(kTypeEastResize, PP_MOUSECURSOR_TYPE_EASTRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeNorthResize, PP_MOUSECURSOR_TYPE_NORTHRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeNorthEastResize,
                            PP_MOUSECURSOR_TYPE_NORTHEASTRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeNorthWestResize,
                            PP_MOUSECURSOR_TYPE_NORTHWESTRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeSouthResize, PP_MOUSECURSOR_TYPE_SOUTHRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeSouthEastResize,
                            PP_MOUSECURSOR_TYPE_SOUTHEASTRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeSouthWestResize,
                            PP_MOUSECURSOR_TYPE_SOUTHWESTRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeWestResize, PP_MOUSECURSOR_TYPE_WESTRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeNorthSouthResize,
                            PP_MOUSECURSOR_TYPE_NORTHSOUTHRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeEastWestResize,
                            PP_MOUSECURSOR_TYPE_EASTWESTRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeNorthEastSouthWestResize,
                            PP_MOUSECURSOR_TYPE_NORTHEASTSOUTHWESTRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeNorthWestSouthEastResize,
                            PP_MOUSECURSOR_TYPE_NORTHWESTSOUTHEASTRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeColumnResize,
                            PP_MOUSECURSOR_TYPE_COLUMNRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeRowResize, PP_MOUSECURSOR_TYPE_ROWRESIZE);
STATIC_ASSERT_MATCHING_ENUM(kTypeMiddlePanning,
                            PP_MOUSECURSOR_TYPE_MIDDLEPANNING);
STATIC_ASSERT_MATCHING_ENUM(kTypeEastPanning, PP_MOUSECURSOR_TYPE_EASTPANNING);
STATIC_ASSERT_MATCHING_ENUM(kTypeNorthPanning,
                            PP_MOUSECURSOR_TYPE_NORTHPANNING);
STATIC_ASSERT_MATCHING_ENUM(kTypeNorthEastPanning,
                            PP_MOUSECURSOR_TYPE_NORTHEASTPANNING);
STATIC_ASSERT_MATCHING_ENUM(kTypeNorthWestPanning,
                            PP_MOUSECURSOR_TYPE_NORTHWESTPANNING);
STATIC_ASSERT_MATCHING_ENUM(kTypeSouthPanning,
                            PP_MOUSECURSOR_TYPE_SOUTHPANNING);
STATIC_ASSERT_MATCHING_ENUM(kTypeSouthEastPanning,
                            PP_MOUSECURSOR_TYPE_SOUTHEASTPANNING);
STATIC_ASSERT_MATCHING_ENUM(kTypeSouthWestPanning,
                            PP_MOUSECURSOR_TYPE_SOUTHWESTPANNING);
STATIC_ASSERT_MATCHING_ENUM(kTypeWestPanning, PP_MOUSECURSOR_TYPE_WESTPANNING);
STATIC_ASSERT_MATCHING_ENUM(kTypeMove, PP_MOUSECURSOR_TYPE_MOVE);
STATIC_ASSERT_MATCHING_ENUM(kTypeVerticalText,
                            PP_MOUSECURSOR_TYPE_VERTICALTEXT);
STATIC_ASSERT_MATCHING_ENUM(kTypeCell, PP_MOUSECURSOR_TYPE_CELL);
STATIC_ASSERT_MATCHING_ENUM(kTypeContextMenu, PP_MOUSECURSOR_TYPE_CONTEXTMENU);
STATIC_ASSERT_MATCHING_ENUM(kTypeAlias, PP_MOUSECURSOR_TYPE_ALIAS);
STATIC_ASSERT_MATCHING_ENUM(kTypeProgress, PP_MOUSECURSOR_TYPE_PROGRESS);
STATIC_ASSERT_MATCHING_ENUM(kTypeNoDrop, PP_MOUSECURSOR_TYPE_NODROP);
STATIC_ASSERT_MATCHING_ENUM(kTypeCopy, PP_MOUSECURSOR_TYPE_COPY);
STATIC_ASSERT_MATCHING_ENUM(kTypeNone, PP_MOUSECURSOR_TYPE_NONE);
STATIC_ASSERT_MATCHING_ENUM(kTypeNotAllowed, PP_MOUSECURSOR_TYPE_NOTALLOWED);
STATIC_ASSERT_MATCHING_ENUM(kTypeZoomIn, PP_MOUSECURSOR_TYPE_ZOOMIN);
STATIC_ASSERT_MATCHING_ENUM(kTypeZoomOut, PP_MOUSECURSOR_TYPE_ZOOMOUT);
STATIC_ASSERT_MATCHING_ENUM(kTypeGrab, PP_MOUSECURSOR_TYPE_GRAB);
STATIC_ASSERT_MATCHING_ENUM(kTypeGrabbing, PP_MOUSECURSOR_TYPE_GRABBING);
// Do not assert WebCursorInfo::TypeCustom == PP_CURSORTYPE_CUSTOM;
// PP_CURSORTYPE_CUSTOM is pinned to allow new cursor types.

#undef STATIC_ASSERT_MATCHING_ENUM

STATIC_ASSERT_ENUM(blink::kWebPrintScalingOptionNone,
                   PP_PRINTSCALINGOPTION_NONE);
STATIC_ASSERT_ENUM(blink::kWebPrintScalingOptionFitToPrintableArea,
                   PP_PRINTSCALINGOPTION_FIT_TO_PRINTABLE_AREA);
STATIC_ASSERT_ENUM(blink::kWebPrintScalingOptionSourceSize,
                   PP_PRINTSCALINGOPTION_SOURCE_SIZE);

#undef STATIC_ASSERT_ENUM

// Sets |*security_origin| to be the WebKit security origin associated with the
// document containing the given plugin instance. On success, returns true. If
// the instance is invalid, returns false and |*security_origin| will be
// unchanged.
bool SecurityOriginForInstance(PP_Instance instance_id,
                               blink::WebSecurityOrigin* security_origin) {
  PepperPluginInstanceImpl* instance =
      HostGlobals::Get()->GetInstance(instance_id);
  if (!instance)
    return false;

  *security_origin = instance->container()->GetDocument().GetSecurityOrigin();
  return true;
}

// Convert the given vector to an array of C-strings. The strings in the
// returned vector are only guaranteed valid so long as the vector of strings
// is not modified.
std::unique_ptr<const char* []> StringVectorToArgArray(
    const std::vector<std::string>& vector) {
  auto array = std::make_unique<const char* []>(vector.size());
  for (size_t i = 0; i < vector.size(); ++i)
    array[i] = vector[i].c_str();
  return array;
}

// Returns true if this is a "system reserved" key which should not be sent to
// a plugin. Some poorly behaving plugins (like Flash) incorrectly report that
// they handle all keys sent to them. This can prevent keystrokes from working
// for things like screen brightness and volume control.
bool IsReservedSystemInputEvent(const blink::WebInputEvent& event) {
#if defined(OS_CHROMEOS)
  if (event.GetType() != WebInputEvent::kKeyDown &&
      event.GetType() != WebInputEvent::kKeyUp)
    return false;
  const blink::WebKeyboardEvent& key_event =
      static_cast<const blink::WebKeyboardEvent&>(event);
  switch (key_event.windows_key_code) {
    case ui::VKEY_BRIGHTNESS_DOWN:
    case ui::VKEY_BRIGHTNESS_UP:
    case ui::VKEY_KBD_BRIGHTNESS_DOWN:
    case ui::VKEY_KBD_BRIGHTNESS_UP:
    case ui::VKEY_VOLUME_MUTE:
    case ui::VKEY_VOLUME_DOWN:
    case ui::VKEY_VOLUME_UP:
      return true;
    default:
      return false;
  }
#endif  // defined(OS_CHROMEOS)
  return false;
}

class PluginInstanceLockTarget : public MouseLockDispatcher::LockTarget {
 public:
  explicit PluginInstanceLockTarget(PepperPluginInstanceImpl* plugin)
      : plugin_(plugin) {}

  void OnLockMouseACK(bool succeeded) override {
    plugin_->OnLockMouseACK(succeeded);
  }

  void OnMouseLockLost() override { plugin_->OnMouseLockLost(); }

  bool HandleMouseLockedInputEvent(const blink::WebMouseEvent& event) override {
    plugin_->HandleMouseLockedInputEvent(event);
    return true;
  }

 private:
  PepperPluginInstanceImpl* plugin_;
};

void PrintPDFOutput(PP_Resource print_output,
                    printing::PdfMetafileSkia* metafile) {
#if BUILDFLAG(ENABLE_PRINTING)
  DCHECK(metafile);

  ppapi::thunk::EnterResourceNoLock<PPB_Buffer_API> enter(print_output, true);
  if (enter.failed())
    return;

  BufferAutoMapper mapper(enter.object());
  if (!mapper.data() || !mapper.size()) {
    NOTREACHED();
    return;
  }

  metafile->InitFromData(mapper.data(), mapper.size());
#endif  // BUILDFLAG(ENABLE_PRINTING)
}

}  // namespace

// static
PepperPluginInstanceImpl* PepperPluginInstanceImpl::Create(
    RenderFrameImpl* render_frame,
    PluginModule* module,
    WebPluginContainer* container,
    const GURL& plugin_url) {
  base::Callback<const void*(const char*)> get_plugin_interface_func =
      base::Bind(&PluginModule::GetPluginInterface, module);
  PPP_Instance_Combined* ppp_instance_combined =
      PPP_Instance_Combined::Create(std::move(get_plugin_interface_func));
  if (!ppp_instance_combined)
    return nullptr;

  return new PepperPluginInstanceImpl(render_frame,
                                      module,
                                      ppp_instance_combined,
                                      container,
                                      plugin_url);
}

// static
PepperPluginInstance* PepperPluginInstance::Get(PP_Instance instance_id) {
  PepperPluginInstanceImpl* instance =
      PepperPluginInstanceImpl::GetForTesting(instance_id);
  if (instance && !instance->is_deleted())
    return instance;
  return nullptr;
}

// static
PepperPluginInstanceImpl* PepperPluginInstanceImpl::GetForTesting(
    PP_Instance instance_id) {
  PepperPluginInstanceImpl* instance =
      HostGlobals::Get()->GetInstance(instance_id);
  return instance;
}

PepperPluginInstanceImpl::ExternalDocumentLoader::ExternalDocumentLoader()
    : finished_loading_(false) {}

PepperPluginInstanceImpl::ExternalDocumentLoader::~ExternalDocumentLoader() {}

void PepperPluginInstanceImpl::ExternalDocumentLoader::ReplayReceivedData(
    WebAssociatedURLLoaderClient* document_loader) {
  for (std::list<std::string>::iterator it = data_.begin(); it != data_.end();
       ++it) {
    document_loader->DidReceiveData(it->c_str(), it->length());
  }
  if (finished_loading_) {
    document_loader->DidFinishLoading(0 /* finish_time */);
  } else if (error_.get()) {
    DCHECK(!finished_loading_);
    document_loader->DidFail(*error_);
  }
}

void PepperPluginInstanceImpl::ExternalDocumentLoader::DidReceiveData(
    const char* data,
    int data_length) {
  data_.push_back(std::string(data, data_length));
}

void PepperPluginInstanceImpl::ExternalDocumentLoader::DidFinishLoading(
    double finish_time) {
  DCHECK(!finished_loading_);

  if (error_.get())
    return;

  finished_loading_ = true;
}

void PepperPluginInstanceImpl::ExternalDocumentLoader::DidFail(
    const WebURLError& error) {
  DCHECK(!error_.get());

  if (finished_loading_)
    return;

  error_ = std::make_unique<WebURLError>(error);
}

PepperPluginInstanceImpl::GamepadImpl::GamepadImpl()
    : Resource(ppapi::Resource::Untracked()) {}

PepperPluginInstanceImpl::GamepadImpl::~GamepadImpl() {}

PPB_Gamepad_API* PepperPluginInstanceImpl::GamepadImpl::AsPPB_Gamepad_API() {
  return this;
}

void PepperPluginInstanceImpl::GamepadImpl::Sample(
    PP_Instance instance,
    PP_GamepadsSampleData* data) {
  device::Gamepads gamepads_data;
  RenderThreadImpl::current()->SampleGamepads(&gamepads_data);
  ppapi::ConvertDeviceGamepadData(gamepads_data, data);
}

PepperPluginInstanceImpl::PepperPluginInstanceImpl(
    RenderFrameImpl* render_frame,
    PluginModule* module,
    ppapi::PPP_Instance_Combined* instance_interface,
    WebPluginContainer* container,
    const GURL& plugin_url)
    : RenderFrameObserver(render_frame),
      render_frame_(render_frame),
      module_(module),
      instance_interface_(instance_interface),
      pp_instance_(0),
      graphics2d_translation_(0, 0),
      graphics2d_scale_(1.f),
      container_(container),
      layer_bound_to_fullscreen_(false),
      layer_is_hardware_(false),
      plugin_url_(plugin_url),
      document_url_(container ? GURL(container->GetDocument().Url()) : GURL()),
      is_flash_plugin_(module->name() == kFlashPluginName),
      has_been_clicked_(false),
      full_frame_(false),
      viewport_to_dip_scale_(1.0f),
      sent_initial_did_change_view_(false),
      bound_graphics_2d_platform_(nullptr),
      bound_compositor_(nullptr),
      has_webkit_focus_(false),
      has_content_area_focus_(false),
      find_identifier_(-1),
      plugin_find_interface_(nullptr),
      plugin_input_event_interface_(nullptr),
      plugin_mouse_lock_interface_(nullptr),
      plugin_pdf_interface_(nullptr),
      plugin_private_interface_(nullptr),
      plugin_textinput_interface_(nullptr),
      checked_for_plugin_input_event_interface_(false),
      checked_for_plugin_pdf_interface_(false),
      metafile_(nullptr),
      gamepad_impl_(new GamepadImpl()),
      uma_private_impl_(nullptr),
      plugin_print_interface_(nullptr),
      always_on_top_(false),
      fullscreen_container_(nullptr),
      flash_fullscreen_(false),
      desired_fullscreen_state_(false),
      message_channel_(nullptr),
      sad_plugin_(nullptr),
      input_event_mask_(0),
      filtered_input_event_mask_(0),
      text_input_type_(kPluginDefaultTextInputType),
      selection_caret_(0),
      selection_anchor_(0),
      pending_user_gesture_(0.0),
      document_loader_(nullptr),
      external_document_load_(false),
      isolate_(v8::Isolate::GetCurrent()),
      is_deleted_(false),
      initialized_(false),
      audio_controller_(std::make_unique<PepperAudioController>(this)),
      view_change_weak_ptr_factory_(this),
      weak_factory_(this) {
  pp_instance_ = HostGlobals::Get()->AddInstance(this);

  memset(&current_print_settings_, 0, sizeof(current_print_settings_));
  module_->InstanceCreated(this);

  if (render_frame_) {  // NULL in tests or if the frame has been destroyed.
    render_frame_->PepperInstanceCreated(this);
    view_data_.is_page_visible = !render_frame_->GetRenderWidget()->is_hidden();

    // Set the initial focus.
    SetContentAreaFocus(render_frame_->GetRenderWidget()->has_focus());

    if (!module_->IsProxied()) {
      PepperBrowserConnection* browser_connection =
          PepperBrowserConnection::Get(render_frame_);
      browser_connection->DidCreateInProcessInstance(
          pp_instance(),
          render_frame_->GetRoutingID(),
          document_url_,
          GetPluginURL());
    }
  }

  RendererPpapiHostImpl* host_impl = module_->renderer_ppapi_host();
  resource_creation_ = host_impl->CreateInProcessResourceCreationAPI(this);

  if (GetContentClient()->renderer() &&  // NULL in unit tests.
      GetContentClient()->renderer()->IsExternalPepperPlugin(module->name()))
    external_document_load_ = true;
}

PepperPluginInstanceImpl::~PepperPluginInstanceImpl() {
  DCHECK(!fullscreen_container_);

  // Notify all the plugin objects of deletion. This will prevent blink from
  // calling into the plugin any more.
  //
  // Swap out the set so we can delete from it (the objects will try to
  // unregister themselves inside the delete call).
  PluginObjectSet plugin_object_copy;
  live_plugin_objects_.swap(plugin_object_copy);
  for (PluginObjectSet::iterator i = plugin_object_copy.begin();
       i != plugin_object_copy.end();
       ++i) {
    (*i)->InstanceDeleted();
  }

  if (message_channel_)
    message_channel_->InstanceDeleted();
  message_channel_object_.Reset();

  if (TrackedCallback::IsPending(lock_mouse_callback_))
    lock_mouse_callback_->Abort();

  audio_controller_->OnPepperInstanceDeleted();

  if (render_frame_)
    render_frame_->PepperInstanceDeleted(this);

  if (!module_->IsProxied() && render_frame_) {
    PepperBrowserConnection* browser_connection =
        PepperBrowserConnection::Get(render_frame_);
    browser_connection->DidDeleteInProcessInstance(pp_instance());
  }

  UnSetAndDeleteLockTargetAdapter();
  module_->InstanceDeleted(this);
  // If we switched from the NaCl plugin module, notify it too.
  if (original_module_.get())
    original_module_->InstanceDeleted(this);

  // This should be last since some of the above "instance deleted" calls will
  // want to look up in the global map to get info off of our object.
  HostGlobals::Get()->InstanceDeleted(pp_instance_);

  if (throttler_)
    throttler_->RemoveObserver(this);
}

// NOTE: Any of these methods that calls into the plugin needs to take into
// account that the plugin may use Var to remove the <embed> from the DOM, which
// will make the PepperWebPluginImpl drop its reference, usually the last one.
// If a method needs to access a member of the instance after the call has
// returned, then it needs to keep its own reference on the stack.

v8::Local<v8::Object> PepperPluginInstanceImpl::GetMessageChannelObject() {
  return v8::Local<v8::Object>::New(isolate_, message_channel_object_);
}

void PepperPluginInstanceImpl::MessageChannelDestroyed() {
  message_channel_ = nullptr;
  message_channel_object_.Reset();
}

v8::Local<v8::Context> PepperPluginInstanceImpl::GetMainWorldContext() {
  if (!container_)
    return v8::Local<v8::Context>();

  WebLocalFrame* frame = container_->GetDocument().GetFrame();

  if (!frame)
    return v8::Local<v8::Context>();

  v8::Local<v8::Context> context = frame->MainWorldScriptContext();
  DCHECK(context->GetIsolate() == isolate_);
  return context;
}

void PepperPluginInstanceImpl::Delete() {
  is_deleted_ = true;

  if (render_frame_ && render_frame_->plugin_find_handler() == this) {
    render_frame_->set_plugin_find_handler(nullptr);
  }

  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);

  // It is important to destroy the throttler before anything else.
  // The plugin instance may flush its graphics pipeline during its postmortem
  // spasm, causing the throttler to engage and obtain new dangling reference
  // to the plugin container being destroyed.
  throttler_.reset();

  // Force the MessageChannel to release its "passthrough object" which should
  // release our last reference to the "InstanceObject" and will probably
  // destroy it. We want to do this prior to calling DidDestroy in case the
  // destructor of the instance object tries to use the instance.
  if (message_channel_)
    message_channel_->SetPassthroughObject(v8::Local<v8::Object>());
  // If this is a NaCl plugin instance, shut down the NaCl plugin by calling
  // its DidDestroy. Don't call DidDestroy on the untrusted plugin instance,
  // since there is little that it can do at this point.
  if (original_instance_interface_) {
    base::TimeTicks start = base::TimeTicks::Now();
    original_instance_interface_->DidDestroy(pp_instance());
    UMA_HISTOGRAM_CUSTOM_TIMES("NaCl.Perf.ShutdownTime.Total",
                               base::TimeTicks::Now() - start,
                               base::TimeDelta::FromMilliseconds(1),
                               base::TimeDelta::FromSeconds(20),
                               100);
  } else {
    instance_interface_->DidDestroy(pp_instance());
  }
  // Ensure we don't attempt to call functions on the destroyed instance.
  original_instance_interface_.reset();
  instance_interface_.reset();

  if (fullscreen_container_) {
    fullscreen_container_->Destroy();
    fullscreen_container_ = nullptr;
  }

  // Force-unbind any Graphics. In the case of Graphics2D, if the plugin
  // leaks the graphics 2D, it may actually get cleaned up after our
  // destruction, so we need its pointers to be up to date.
  BindGraphics(pp_instance(), 0);
  container_ = nullptr;
}

bool PepperPluginInstanceImpl::is_deleted() const { return is_deleted_; }

void PepperPluginInstanceImpl::Paint(WebCanvas* canvas,
                                     const gfx::Rect& plugin_rect,
                                     const gfx::Rect& paint_rect) {
  TRACE_EVENT0("ppapi", "PluginInstance::Paint");
  if (module()->is_crashed()) {
    // Crashed plugin painting.
    if (!sad_plugin_)  // Lazily initialize bitmap.
      sad_plugin_ = GetContentClient()->renderer()->GetSadPluginBitmap();
    if (sad_plugin_)
      PaintSadPlugin(canvas, plugin_rect, *sad_plugin_);
    return;
  }

  if (bound_graphics_2d_platform_)
    bound_graphics_2d_platform_->Paint(canvas, plugin_rect, paint_rect);
}

void PepperPluginInstanceImpl::InvalidateRect(const gfx::Rect& rect) {
  if (fullscreen_container_) {
    if (rect.IsEmpty())
      fullscreen_container_->Invalidate();
    else
      fullscreen_container_->InvalidateRect(rect);
  } else {
    if (!container_ || view_data_.rect.size.width == 0 ||
        view_data_.rect.size.height == 0)
      return;  // Nothing to do.
    if (rect.IsEmpty())
      container_->Invalidate();
    else
      container_->InvalidateRect(rect);
  }

  cc::Layer* layer =
      texture_layer_ ? texture_layer_.get() : compositor_layer_.get();
  if (layer) {
    if (rect.IsEmpty()) {
      layer->SetNeedsDisplay();
    } else {
      layer->SetNeedsDisplayRect(rect);
    }
  }
}

void PepperPluginInstanceImpl::ScrollRect(int dx,
                                          int dy,
                                          const gfx::Rect& rect) {
  cc::Layer* layer =
      texture_layer_ ? texture_layer_.get() : compositor_layer_.get();
  if (layer) {
    InvalidateRect(rect);
  } else if (fullscreen_container_) {
    fullscreen_container_->ScrollRect(dx, dy, rect);
  } else {
    if (full_frame_ && !IsViewAccelerated()) {
      container_->ScrollRect(rect);
    } else {
      // Can't do optimized scrolling since there could be other elements on top
      // of us or the view renders via the accelerated compositor which is
      // incompatible with the move and backfill scrolling model.
      InvalidateRect(rect);
    }
  }
}

void PepperPluginInstanceImpl::CommitTransferableResource(
    const viz::TransferableResource& resource) {
  if (!committed_texture_.mailbox_holder.mailbox.IsZero() &&
      !IsTextureInUse(committed_texture_)) {
    committed_texture_graphics_3d_->ReturnFrontBuffer(
        committed_texture_.mailbox_holder.mailbox,
        committed_texture_consumed_sync_token_, false);
  }

  committed_texture_ = resource;
  committed_texture_graphics_3d_ = bound_graphics_3d_;
  committed_texture_consumed_sync_token_ = gpu::SyncToken();

  if (!texture_layer_) {
    UpdateLayer(true);
    return;
  }

  PassCommittedTextureToTextureLayer();
  texture_layer_->SetNeedsDisplay();
}

void PepperPluginInstanceImpl::PassCommittedTextureToTextureLayer() {
  DCHECK(bound_graphics_3d_);

  if (committed_texture_.mailbox_holder.mailbox.IsZero())
    return;

  std::unique_ptr<viz::SingleReleaseCallback> callback(
      viz::SingleReleaseCallback::Create(base::BindOnce(
          &PepperPluginInstanceImpl::FinishedConsumingCommittedTexture,
          weak_factory_.GetWeakPtr(), committed_texture_,
          committed_texture_graphics_3d_)));

  IncrementTextureReferenceCount(committed_texture_);
  texture_layer_->SetTransferableResource(committed_texture_,
                                          std::move(callback));
}

void PepperPluginInstanceImpl::FinishedConsumingCommittedTexture(
    const viz::TransferableResource& resource,
    scoped_refptr<PPB_Graphics3D_Impl> graphics_3d,
    const gpu::SyncToken& sync_token,
    bool is_lost) {
  bool removed = DecrementTextureReferenceCount(resource);
  bool is_committed_texture = committed_texture_.mailbox_holder.mailbox ==
                              resource.mailbox_holder.mailbox;

  if (is_committed_texture && !is_lost) {
    committed_texture_consumed_sync_token_ = sync_token;
    return;
  }

  if (removed && !is_committed_texture) {
    graphics_3d->ReturnFrontBuffer(resource.mailbox_holder.mailbox, sync_token,
                                   is_lost);
  }
}

void PepperPluginInstanceImpl::InstanceCrashed() {
  // Force free all resources and vars.
  HostGlobals::Get()->InstanceCrashed(pp_instance());

  // Free any associated graphics.
  SetFullscreen(false);
  FlashSetFullscreen(false, false);
  // Unbind current 2D or 3D graphics context.
  BindGraphics(pp_instance(), 0);
  InvalidateRect(gfx::Rect());

  if (render_frame_)
    render_frame_->PluginCrashed(module_->path(), module_->GetPeerProcessId());
  UnSetAndDeleteLockTargetAdapter();
}

bool PepperPluginInstanceImpl::Initialize(
    const std::vector<std::string>& arg_names,
    const std::vector<std::string>& arg_values,
    bool full_frame,
    std::unique_ptr<PluginInstanceThrottlerImpl> throttler) {
  DCHECK(!throttler_);

  if (!render_frame_)
    return false;

  if (throttler) {
    throttler_ = std::move(throttler);
    throttler_->AddObserver(this);
  }

  message_channel_ = MessageChannel::Create(this, &message_channel_object_);
  DCHECK(message_channel_);

  full_frame_ = full_frame;

  UpdateTouchEventRequest();
  UpdateWheelEventRequest();

  argn_ = arg_names;
  argv_ = arg_values;
  std::unique_ptr<const char* []> argn_array(StringVectorToArgArray(argn_));
  std::unique_ptr<const char* []> argv_array(StringVectorToArgArray(argv_));
  auto weak_this = weak_factory_.GetWeakPtr();
  bool success = PP_ToBool(instance_interface_->DidCreate(
      pp_instance(), argn_.size(), argn_array.get(), argv_array.get()));
  if (!weak_this) {
    // The plugin may do synchronous scripting during "DidCreate", so |this|
    // may be deleted. In that case, return failure and don't touch any
    // member variables.
    return false;
  }
  // If this is a plugin that hosts external plugins, we should delay messages
  // so that the child plugin that's created later will receive all the
  // messages. (E.g., NaCl trusted plugin starting a child NaCl app.)
  //
  // A host for external plugins will call ResetAsProxied later, at which point
  // we can Start() the MessageChannel.
  if (success && !module_->renderer_ppapi_host()->IsExternalPluginHost())
    message_channel_->Start();

  if (success)
    AccessibilityModeChanged();

  initialized_ = success;
  return success;
}

bool PepperPluginInstanceImpl::HandleDocumentLoad(
    const blink::WebURLResponse& response) {
  DCHECK(!document_loader_);
  if (external_document_load_) {
    // The external proxy isn't available, so save the response and record
    // document load notifications for later replay.
    external_document_response_ = response;
    external_document_loader_ = std::make_unique<ExternalDocumentLoader>();
    document_loader_ = external_document_loader_.get();
    return true;
  }

  if (module()->is_crashed()) {
    // Don't create a resource for a crashed plugin.
    container()->GetDocument().GetFrame()->StopLoading();
    return false;
  }

  DCHECK(!document_loader_);

  // Create a loader resource host for this load. Note that we have to set
  // the document_loader before issuing the in-process
  // PPP_Instance.HandleDocumentLoad call below, since this may reentrantly
  // call into the instance and expect it to be valid.
  RendererPpapiHostImpl* host_impl = module_->renderer_ppapi_host();
  auto loader_host =
      std::make_unique<PepperURLLoaderHost>(host_impl, true, pp_instance(), 0);
  // TODO(teravest): Remove set_document_loader() from instance and clean up
  // this relationship.
  set_document_loader(loader_host.get());
  loader_host->DidReceiveResponse(response);

  // This host will be pending until the resource object attaches to it.
  int pending_host_id = host_impl->GetPpapiHost()->AddPendingResourceHost(
      std::unique_ptr<ppapi::host::ResourceHost>(std::move(loader_host)));
  DCHECK(pending_host_id);

  DataFromWebURLResponse(
      host_impl,
      pp_instance(),
      response,
      base::Bind(&PepperPluginInstanceImpl::DidDataFromWebURLResponse,
                 weak_factory_.GetWeakPtr(),
                 response,
                 pending_host_id));

  // If the load was not abandoned, document_loader_ will now be set. It's
  // possible that the load was canceled by now and document_loader_ was
  // already nulled out.
  return true;
}

bool PepperPluginInstanceImpl::SendCompositionEventToPlugin(
    PP_InputEvent_Type type,
    const base::string16& text) {
  std::vector<blink::WebImeTextSpan> empty;
  return SendCompositionEventWithImeTextSpanInformationToPlugin(
      type, text, empty, static_cast<int>(text.size()),
      static_cast<int>(text.size()));
}

bool PepperPluginInstanceImpl::
    SendCompositionEventWithImeTextSpanInformationToPlugin(
        PP_InputEvent_Type type,
        const base::string16& text,
        const std::vector<blink::WebImeTextSpan>& ime_text_spans,
        int selection_start,
        int selection_end) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);

  if (!LoadInputEventInterface())
    return false;

  PP_InputEvent_Class event_class = PP_INPUTEVENT_CLASS_IME;
  if (!(filtered_input_event_mask_ & event_class) &&
      !(input_event_mask_ & event_class))
    return false;

  ppapi::InputEventData event;
  event.event_type = type;
  event.event_time_stamp =
      ppapi::TimeTicksToPPTimeTicks(base::TimeTicks::Now());

  // Convert UTF16 text to UTF8 with offset conversion.
  std::vector<size_t> utf16_offsets;
  utf16_offsets.push_back(selection_start);
  utf16_offsets.push_back(selection_end);
  for (size_t i = 0; i < ime_text_spans.size(); ++i) {
    utf16_offsets.push_back(ime_text_spans[i].start_offset);
    utf16_offsets.push_back(ime_text_spans[i].end_offset);
  }
  std::vector<size_t> utf8_offsets(utf16_offsets);
  event.character_text = base::UTF16ToUTF8AndAdjustOffsets(text, &utf8_offsets);

  // Set the converted selection range.
  event.composition_selection_start =
      (utf8_offsets[0] == std::string::npos ? event.character_text.size()
                                            : utf8_offsets[0]);
  event.composition_selection_end =
      (utf8_offsets[1] == std::string::npos ? event.character_text.size()
                                            : utf8_offsets[1]);

  // Set the converted segmentation points.
  // Be sure to add 0 and size(), and remove duplication or errors.
  std::set<size_t> offset_set(utf8_offsets.begin() + 2, utf8_offsets.end());
  offset_set.insert(0);
  offset_set.insert(event.character_text.size());
  offset_set.erase(std::string::npos);
  event.composition_segment_offsets.assign(offset_set.begin(),
                                           offset_set.end());

  // Set the composition target.
  for (size_t i = 0; i < ime_text_spans.size(); ++i) {
    if (ime_text_spans[i].thickness ==
        ui::mojom::ImeTextSpanThickness::kThick) {
      std::vector<uint32_t>::iterator it =
          std::find(event.composition_segment_offsets.begin(),
                    event.composition_segment_offsets.end(),
                    utf8_offsets[2 * i + 2]);
      if (it != event.composition_segment_offsets.end()) {
        event.composition_target_segment =
            it - event.composition_segment_offsets.begin();
        break;
      }
    }
  }

  // Send the event.
  bool handled = false;
  if (filtered_input_event_mask_ & event_class)
    event.is_filtered = true;
  else
    handled = true;  // Unfiltered events are assumed to be handled.
  scoped_refptr<PPB_InputEvent_Shared> event_resource(
      new PPB_InputEvent_Shared(ppapi::OBJECT_IS_IMPL, pp_instance(), event));
  handled |= PP_ToBool(plugin_input_event_interface_->HandleInputEvent(
      pp_instance(), event_resource->pp_resource()));
  return handled;
}

void PepperPluginInstanceImpl::RequestInputEventsHelper(
    uint32_t event_classes) {
  if (event_classes & PP_INPUTEVENT_CLASS_TOUCH)
    UpdateTouchEventRequest();
  if (event_classes & PP_INPUTEVENT_CLASS_WHEEL)
    UpdateWheelEventRequest();
}

bool PepperPluginInstanceImpl::HandleCompositionStart(
    const base::string16& text) {
  return SendCompositionEventToPlugin(PP_INPUTEVENT_TYPE_IME_COMPOSITION_START,
                                      text);
}

bool PepperPluginInstanceImpl::HandleCompositionUpdate(
    const base::string16& text,
    const std::vector<blink::WebImeTextSpan>& ime_text_spans,
    int selection_start,
    int selection_end) {
  return SendCompositionEventWithImeTextSpanInformationToPlugin(
      PP_INPUTEVENT_TYPE_IME_COMPOSITION_UPDATE, text, ime_text_spans,
      selection_start, selection_end);
}

bool PepperPluginInstanceImpl::HandleCompositionEnd(
    const base::string16& text) {
  return SendCompositionEventToPlugin(PP_INPUTEVENT_TYPE_IME_COMPOSITION_END,
                                      text);
}

bool PepperPluginInstanceImpl::HandleTextInput(const base::string16& text) {
  return SendCompositionEventToPlugin(PP_INPUTEVENT_TYPE_IME_TEXT, text);
}

void PepperPluginInstanceImpl::GetSurroundingText(base::string16* text,
                                                  gfx::Range* range) const {
  std::vector<size_t> offsets;
  offsets.push_back(selection_anchor_);
  offsets.push_back(selection_caret_);
  *text = base::UTF8ToUTF16AndAdjustOffsets(surrounding_text_, &offsets);
  range->set_start(offsets[0] == base::string16::npos ? text->size()
                                                      : offsets[0]);
  range->set_end(offsets[1] == base::string16::npos ? text->size()
                                                    : offsets[1]);
}

bool PepperPluginInstanceImpl::IsPluginAcceptingCompositionEvents() const {
  return (filtered_input_event_mask_ & PP_INPUTEVENT_CLASS_IME) ||
         (input_event_mask_ & PP_INPUTEVENT_CLASS_IME);
}

gfx::Rect PepperPluginInstanceImpl::GetCaretBounds() const {
  if (!text_input_caret_info_) {
    // If it is never set by the plugin, use the bottom left corner.
    gfx::Rect rect(view_data_.rect.point.x,
                   view_data_.rect.point.y + view_data_.rect.size.height,
                   0, 0);
    ConvertDIPToViewport(&rect);
    return rect;
  }

  // TODO(kinaba) Take CSS transformation into account.
  // TODO(kinaba) Take |text_input_caret_info_->caret_bounds| into account. On
  // some platforms, an "exclude rectangle" where candidate window must avoid
  // the region can be passed to IME. Currently, we pass only the caret
  // rectangle because it is the only information supported uniformly in
  // Chromium.
  gfx::Rect caret = text_input_caret_info_->caret;
  caret.Offset(view_data_.rect.point.x, view_data_.rect.point.y);
  ConvertDIPToViewport(&caret);
  return caret;
}

bool PepperPluginInstanceImpl::HandleCoalescedInputEvent(
    const blink::WebCoalescedInputEvent& event,
    WebCursorInfo* cursor_info) {
  if (blink::WebInputEvent::IsTouchEventType(event.Event().GetType()) &&
      ((filtered_input_event_mask_ & PP_INPUTEVENT_CLASS_COALESCED_TOUCH) ||
       (input_event_mask_ & PP_INPUTEVENT_CLASS_COALESCED_TOUCH))) {
    bool result = false;
    for (size_t i = 0; i < event.CoalescedEventSize(); ++i) {
      result |= HandleInputEvent(event.CoalescedEvent(i), cursor_info);
    }
    return result;
  }
  return HandleInputEvent(event.Event(), cursor_info);
}

bool PepperPluginInstanceImpl::HandleInputEvent(
    const blink::WebInputEvent& event,
    WebCursorInfo* cursor_info) {
  TRACE_EVENT0("ppapi", "PepperPluginInstanceImpl::HandleInputEvent");

  if (!render_frame_)
    return false;

  if (!has_been_clicked_ && is_flash_plugin_ &&
      event.GetType() == blink::WebInputEvent::kMouseDown &&
      (event.GetModifiers() & blink::WebInputEvent::kLeftButtonDown)) {
    has_been_clicked_ = true;
    blink::WebRect bounds = container()->GetElement().BoundsInViewport();
    render_frame()->GetRenderWidget()->ConvertViewportToWindow(&bounds);
    RecordFlashClickSizeMetric(bounds.width, bounds.height);
  }

  if (throttler_ && throttler_->ConsumeInputEvent(event))
    return true;

  if (WebInputEvent::IsMouseEventType(event.GetType())) {
    render_frame_->PepperDidReceiveMouseEvent(this);
  }

  // Don't dispatch input events to crashed plugins.
  if (module()->is_crashed())
    return false;

  // Don't send reserved system key events to plugins.
  if (IsReservedSystemInputEvent(event))
    return false;

  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);

  bool rv = false;
  if (LoadInputEventInterface()) {
    PP_InputEvent_Class event_class = ClassifyInputEvent(event);
    if (!event_class)
      return false;

    if ((filtered_input_event_mask_ & event_class) ||
        (input_event_mask_ & event_class)) {
      // Actually send the event.
      std::vector<ppapi::InputEventData> events;
      std::unique_ptr<const WebInputEvent> event_in_dip(
          ui::ScaleWebInputEvent(event, viewport_to_dip_scale_));
      if (event_in_dip)
        CreateInputEventData(*event_in_dip.get(), &events);
      else
        CreateInputEventData(event, &events);

      // Allow the user gesture to be pending after the plugin handles the
      // event. This allows out-of-process plugins to respond to the user
      // gesture after processing has finished here.
      if (WebUserGestureIndicator::IsProcessingUserGesture(
              render_frame_->GetWebFrame())) {
        pending_user_gesture_ =
            ppapi::TimeTicksToPPTimeTicks(base::TimeTicks::Now());
        pending_user_gesture_token_ =
            WebUserGestureIndicator::CurrentUserGestureToken();
        WebUserGestureIndicator::ExtendTimeout();
      }

      // Each input event may generate more than one PP_InputEvent.
      for (size_t i = 0; i < events.size(); i++) {
        if (filtered_input_event_mask_ & event_class)
          events[i].is_filtered = true;
        else
          rv = true;  // Unfiltered events are assumed to be handled.
        scoped_refptr<PPB_InputEvent_Shared> event_resource(
            new PPB_InputEvent_Shared(
                ppapi::OBJECT_IS_IMPL, pp_instance(), events[i]));

        rv |= PP_ToBool(plugin_input_event_interface_->HandleInputEvent(
            pp_instance(), event_resource->pp_resource()));
      }
    }
  }

  if (cursor_)
    *cursor_info = *cursor_;
  return rv;
}

void PepperPluginInstanceImpl::HandleMessage(ScopedPPVar message) {
  TRACE_EVENT0("ppapi", "PepperPluginInstanceImpl::HandleMessage");
  if (is_deleted_)
    return;
  ppapi::proxy::HostDispatcher* dispatcher =
      ppapi::proxy::HostDispatcher::GetForInstance(pp_instance());
  if (!dispatcher || (message.get().type == PP_VARTYPE_OBJECT)) {
    // The dispatcher should always be valid, and MessageChannel should never
    // send an 'object' var over PPP_Messaging.
    NOTREACHED();
    return;
  }
  dispatcher->Send(new PpapiMsg_PPPMessaging_HandleMessage(
      ppapi::API_ID_PPP_MESSAGING,
      pp_instance(),
      ppapi::proxy::SerializedVarSendInputShmem(dispatcher, message.get(),
                                                pp_instance())));
}

bool PepperPluginInstanceImpl::HandleBlockingMessage(ScopedPPVar message,
                                                     ScopedPPVar* result) {
  TRACE_EVENT0("ppapi", "PepperPluginInstanceImpl::HandleBlockingMessage");
  if (is_deleted_)
    return false;
  ppapi::proxy::HostDispatcher* dispatcher =
      ppapi::proxy::HostDispatcher::GetForInstance(pp_instance());
  if (!dispatcher || (message.get().type == PP_VARTYPE_OBJECT)) {
    // The dispatcher should always be valid, and MessageChannel should never
    // send an 'object' var over PPP_Messaging.
    NOTREACHED();
    return false;
  }
  ppapi::proxy::ReceiveSerializedVarReturnValue msg_reply;
  bool was_handled = false;
  dispatcher->Send(new PpapiMsg_PPPMessageHandler_HandleBlockingMessage(
      ppapi::API_ID_PPP_MESSAGING,
      pp_instance(),
      ppapi::proxy::SerializedVarSendInputShmem(dispatcher, message.get(),
                                                pp_instance()),
      &msg_reply,
      &was_handled));
  *result = ScopedPPVar(ScopedPPVar::PassRef(), msg_reply.Return(dispatcher));
  TRACE_EVENT0("ppapi",
               "PepperPluginInstanceImpl::HandleBlockingMessage return.");
  return was_handled;
}

PP_Var PepperPluginInstanceImpl::GetInstanceObject(v8::Isolate* isolate) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);

  DCHECK_EQ(isolate, isolate_);

  // If the plugin supports the private instance interface, try to retrieve its
  // instance object.
  if (LoadPrivateInterface())
    return plugin_private_interface_->GetInstanceObject(pp_instance());
  return PP_MakeUndefined();
}

void PepperPluginInstanceImpl::ViewChanged(
    const gfx::Rect& window,
    const gfx::Rect& clip,
    const gfx::Rect& unobscured) {
  if (!render_frame_)
    return;

  // WebKit can give weird (x,y) positions for empty clip rects (since the
  // position technically doesn't matter). But we want to make these
  // consistent since this is given to the plugin, so force everything to 0
  // in the "everything is clipped" case.
  gfx::Rect new_clip;
  if (!clip.IsEmpty())
    new_clip = clip;

  unobscured_rect_ = unobscured;

  view_data_.rect = PP_FromGfxRect(window);
  view_data_.clip_rect = PP_FromGfxRect(clip);
  view_data_.device_scale = container_->DeviceScaleFactor();
  view_data_.css_scale =
      container_->PageZoomFactor() * container_->PageScaleFactor();
  blink::WebFloatRect windowToViewportScale(0, 0, 1.0f, 0);
  render_frame()->GetRenderWidget()->ConvertWindowToViewport(
      &windowToViewportScale);
  viewport_to_dip_scale_ = 1.0f / windowToViewportScale.width;
  ConvertRectToDIP(&view_data_.rect);
  ConvertRectToDIP(&view_data_.clip_rect);
  view_data_.css_scale *= viewport_to_dip_scale_;
  view_data_.device_scale /= viewport_to_dip_scale_;

  gfx::Size scroll_offset = gfx::ScaleToRoundedSize(
      container_->GetDocument().GetFrame()->GetScrollOffset(),
      viewport_to_dip_scale_);

  view_data_.scroll_offset = PP_MakePoint(scroll_offset.width(),
                                          scroll_offset.height());

  // The view size may have changed and we might need to update
  // our registration of event listeners.
  UpdateTouchEventRequest();
  UpdateWheelEventRequest();

  if (desired_fullscreen_state_ || view_data_.is_fullscreen) {
    bool is_fullscreen_element = container_->IsFullscreenElement();
    if (!view_data_.is_fullscreen && desired_fullscreen_state_ &&
        render_frame()->GetRenderWidget()->is_fullscreen_granted() &&
        is_fullscreen_element) {
      // Entered fullscreen. Only possible via SetFullscreen().
      view_data_.is_fullscreen = true;
    } else if (view_data_.is_fullscreen && !is_fullscreen_element) {
      // Exited fullscreen. Possible via SetFullscreen() or F11/link,
      // so desired_fullscreen_state might be out-of-date.
      desired_fullscreen_state_ = false;
      view_data_.is_fullscreen = false;

      // This operation will cause the plugin to re-layout which will send more
      // DidChangeView updates. Schedule an asynchronous update and suppress
      // notifications until that completes to avoid sending intermediate sizes
      // to the plugins.
      ScheduleAsyncDidChangeView();

      // Reset the size attributes that we hacked to fill in the screen and
      // retrigger ViewChanged. Make sure we don't forward duplicates of
      // this view to the plugin.
      ResetSizeAttributesAfterFullscreen();
      return;
    }
  }

  UpdateFlashFullscreenState(fullscreen_container_ != nullptr);

  // During plugin initialization, there are often re-layouts. Avoid sending
  // intermediate sizes the plugin and throttler.
  if (sent_initial_did_change_view_)
    SendDidChangeView();
  else
    ScheduleAsyncDidChangeView();
}

void PepperPluginInstanceImpl::SetWebKitFocus(bool has_focus) {
  if (has_webkit_focus_ == has_focus)
    return;

  bool old_plugin_focus = PluginHasFocus();
  has_webkit_focus_ = has_focus;
  if (PluginHasFocus() != old_plugin_focus)
    SendFocusChangeNotification();
}

void PepperPluginInstanceImpl::SetContentAreaFocus(bool has_focus) {
  if (has_content_area_focus_ == has_focus)
    return;

  bool old_plugin_focus = PluginHasFocus();
  has_content_area_focus_ = has_focus;
  if (PluginHasFocus() != old_plugin_focus)
    SendFocusChangeNotification();
}

void PepperPluginInstanceImpl::PageVisibilityChanged(bool is_visible) {
  if (is_visible == view_data_.is_page_visible)
    return;  // Nothing to do.
  view_data_.is_page_visible = is_visible;

  // If the initial DidChangeView notification hasn't been sent to the plugin,
  // let it pass the visibility state for us, instead of sending a notification
  // immediately. It is possible that PepperPluginInstanceImpl::ViewChanged()
  // hasn't been called for the first time. In that case, most of the fields in
  // |view_data_| haven't been properly initialized.
  if (sent_initial_did_change_view_)
    SendDidChangeView();
}

void PepperPluginInstanceImpl::ViewInitiatedPaint() {
  if (bound_graphics_2d_platform_)
    bound_graphics_2d_platform_->ViewInitiatedPaint();
  else if (bound_graphics_3d_.get())
    bound_graphics_3d_->ViewInitiatedPaint();
  else if (bound_compositor_)
    bound_compositor_->ViewInitiatedPaint();
}

void PepperPluginInstanceImpl::SetSelectedText(
    const base::string16& selected_text) {
  if (!render_frame_)
    return;

  selected_text_ = selected_text;
  gfx::Range range(0, selected_text.length());
  render_frame_->SetSelectedText(selected_text, 0, range);
}

void PepperPluginInstanceImpl::SetLinkUnderCursor(const std::string& url) {
  link_under_cursor_ = base::UTF8ToUTF16(url);
}

void PepperPluginInstanceImpl::SetTextInputType(ui::TextInputType type) {
  if (!render_frame_)
    return;

  text_input_type_ = type;
  render_frame_->PepperTextInputTypeChanged(this);
}

void PepperPluginInstanceImpl::PostMessageToJavaScript(PP_Var message) {
  if (message_channel_)
    message_channel_->PostMessageToJavaScript(message);
}

int32_t PepperPluginInstanceImpl::RegisterMessageHandler(
    PP_Instance instance,
    void* user_data,
    const PPP_MessageHandler_0_2* handler,
    PP_Resource message_loop) {
  // Not supported in-process.
  NOTIMPLEMENTED();
  return PP_ERROR_FAILED;
}

void PepperPluginInstanceImpl::UnregisterMessageHandler(PP_Instance instance) {
  // Not supported in-process.
  NOTIMPLEMENTED();
}

base::string16 PepperPluginInstanceImpl::GetSelectedText(bool html) {
  return selected_text_;
}

base::string16 PepperPluginInstanceImpl::GetLinkAtPosition(
    const gfx::Point& point) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  if (!LoadPdfInterface()) {
    // TODO(koz): Change the containing function to GetLinkUnderCursor(). We can
    // return |link_under_cursor_| here because this is only ever called with
    // the current mouse coordinates.
    return link_under_cursor_;
  }

  PP_Point p;
  p.x = point.x();
  p.y = point.y();
  PP_Var rv = plugin_pdf_interface_->GetLinkAtPosition(pp_instance(), p);
  // If the plugin returns undefined for this function it has switched to
  // providing us with the link under the cursor eagerly.
  if (rv.type == PP_VARTYPE_UNDEFINED)
    return link_under_cursor_;
  StringVar* string = StringVar::FromPPVar(rv);
  base::string16 link;
  if (string)
    link = base::UTF8ToUTF16(string->value());
  // Release the ref the plugin transfered to us.
  PpapiGlobals::Get()->GetVarTracker()->ReleaseVar(rv);
  return link;
}

void PepperPluginInstanceImpl::SetCaretPosition(const gfx::PointF& position) {
  if (!LoadPdfInterface())
    return;

  PP_FloatPoint p;
  p.x = position.x();
  p.y = position.y();
  plugin_pdf_interface_->SetCaretPosition(pp_instance(), &p);
}

void PepperPluginInstanceImpl::MoveRangeSelectionExtent(
    const gfx::PointF& extent) {
  if (!LoadPdfInterface())
    return;

  PP_FloatPoint p;
  p.x = extent.x();
  p.y = extent.y();
  plugin_pdf_interface_->MoveRangeSelectionExtent(pp_instance(), &p);
}

void PepperPluginInstanceImpl::SetSelectionBounds(const gfx::PointF& base,
                                                  const gfx::PointF& extent) {
  if (!LoadPdfInterface())
    return;

  PP_FloatPoint p_base;
  p_base.x = base.x();
  p_base.y = base.y();

  PP_FloatPoint p_extent;
  p_extent.x = extent.x();
  p_extent.y = extent.y();
  plugin_pdf_interface_->SetSelectionBounds(pp_instance(), &p_base, &p_extent);
}

bool PepperPluginInstanceImpl::CanEditText() {
  if (!LoadPdfInterface())
    return false;
  // No reference to |this| on the stack. Do not do any more work after this.
  // See NOTE above.
  return PP_ToBool(plugin_pdf_interface_->CanEditText(pp_instance()));
}

bool PepperPluginInstanceImpl::HasEditableText() {
  if (!LoadPdfInterface())
    return false;

  // No reference to |this| on the stack. Do not do any more work after this.
  // See NOTE above.
  return PP_ToBool(plugin_pdf_interface_->HasEditableText(pp_instance()));
}

void PepperPluginInstanceImpl::ReplaceSelection(const std::string& text) {
  if (!LoadPdfInterface())
    return;

  // No reference to |this| on the stack. Do not do any more work after this.
  // See NOTE above.
  plugin_pdf_interface_->ReplaceSelection(pp_instance(), text.c_str());
}

void PepperPluginInstanceImpl::SelectAll() {
  if (!LoadPdfInterface())
    return;

#if defined(OS_MACOSX)
  static const ui::EventFlags kPlatformModifier = ui::EF_COMMAND_DOWN;
#else
  static const ui::EventFlags kPlatformModifier = ui::EF_CONTROL_DOWN;
#endif
  // Synthesize a ctrl + a key event to send to the plugin and let it sort out
  // the event. See also https://crbug.com/739529.
  ui::KeyEvent event(L'A', ui::VKEY_A, kPlatformModifier);
  WebCursorInfo dummy_cursor_info;

  // No reference to |this| on the stack. Do not do any more work after this.
  // See NOTE above.
  HandleInputEvent(MakeWebKeyboardEvent(event), &dummy_cursor_info);
}

bool PepperPluginInstanceImpl::CanUndo() {
  if (!LoadPdfInterface())
    return false;

  // No reference to |this| on the stack. Do not do any more work after this.
  // See NOTE above.
  return PP_ToBool(plugin_pdf_interface_->CanUndo(pp_instance()));
}

bool PepperPluginInstanceImpl::CanRedo() {
  if (!LoadPdfInterface())
    return false;

  // No reference to |this| on the stack. Do not do any more work after this.
  // See NOTE above.
  return PP_ToBool(plugin_pdf_interface_->CanRedo(pp_instance()));
}

void PepperPluginInstanceImpl::Undo() {
  if (!LoadPdfInterface())
    return;

  // No reference to |this| on the stack. Do not do any more work after this.
  // See NOTE above.
  plugin_pdf_interface_->Undo(pp_instance());
}

void PepperPluginInstanceImpl::Redo() {
  if (!LoadPdfInterface())
    return;

  plugin_pdf_interface_->Redo(pp_instance());
}

void PepperPluginInstanceImpl::RequestSurroundingText(
    size_t desired_number_of_characters) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  if (!LoadTextInputInterface())
    return;
  plugin_textinput_interface_->RequestSurroundingText(
      pp_instance(), desired_number_of_characters);
}

bool PepperPluginInstanceImpl::StartFind(const std::string& search_text,
                                         bool case_sensitive,
                                         int identifier) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  if (!LoadFindInterface())
    return false;
  find_identifier_ = identifier;
  return PP_ToBool(plugin_find_interface_->StartFind(
      pp_instance(), search_text.c_str(), PP_FromBool(case_sensitive)));
}

void PepperPluginInstanceImpl::SelectFindResult(bool forward, int identifier) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  if (!LoadFindInterface())
    return;
  find_identifier_ = identifier;
  plugin_find_interface_->SelectFindResult(pp_instance(), PP_FromBool(forward));
}

void PepperPluginInstanceImpl::StopFind() {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  if (!LoadFindInterface())
    return;
  find_identifier_ = -1;
  plugin_find_interface_->StopFind(pp_instance());
}

bool PepperPluginInstanceImpl::LoadFindInterface() {
  if (!module_->permissions().HasPermission(ppapi::PERMISSION_PDF))
    return false;
  if (!plugin_find_interface_) {
    plugin_find_interface_ = static_cast<const PPP_Find_Private*>(
        module_->GetPluginInterface(PPP_FIND_PRIVATE_INTERFACE));
  }

  return !!plugin_find_interface_;
}

bool PepperPluginInstanceImpl::LoadInputEventInterface() {
  if (!checked_for_plugin_input_event_interface_) {
    checked_for_plugin_input_event_interface_ = true;
    plugin_input_event_interface_ = static_cast<const PPP_InputEvent*>(
        module_->GetPluginInterface(PPP_INPUT_EVENT_INTERFACE));
  }
  return !!plugin_input_event_interface_;
}

bool PepperPluginInstanceImpl::LoadMouseLockInterface() {
  if (!plugin_mouse_lock_interface_) {
    plugin_mouse_lock_interface_ = static_cast<const PPP_MouseLock*>(
        module_->GetPluginInterface(PPP_MOUSELOCK_INTERFACE));
  }

  return !!plugin_mouse_lock_interface_;
}

bool PepperPluginInstanceImpl::LoadPdfInterface() {
  if (!checked_for_plugin_pdf_interface_) {
    checked_for_plugin_pdf_interface_ = true;
    plugin_pdf_interface_ = static_cast<const PPP_Pdf*>(
        module_->GetPluginInterface(PPP_PDF_INTERFACE_1));
  }

  return !!plugin_pdf_interface_;
}

bool PepperPluginInstanceImpl::LoadPrintInterface() {
  // Only check for the interface if the plugin has dev permission.
  if (!module_->permissions().HasPermission(ppapi::PERMISSION_DEV))
    return false;
  if (!plugin_print_interface_) {
    plugin_print_interface_ = static_cast<const PPP_Printing_Dev*>(
        module_->GetPluginInterface(PPP_PRINTING_DEV_INTERFACE));
  }
  return !!plugin_print_interface_;
}

bool PepperPluginInstanceImpl::LoadPrivateInterface() {
  // If this is a NaCl app, we want to talk to the trusted NaCl plugin to
  // call GetInstanceObject. This is necessary to ensure that the properties
  // the trusted plugin exposes (readyState and lastError) work properly. Note
  // that untrusted NaCl apps are not allowed to provide PPP_InstancePrivate,
  // so it's correct to never look up PPP_InstancePrivate for them.
  //
  // If this is *not* a NaCl plugin, original_module_ will never be set; we talk
  // to the "real" module.
  scoped_refptr<PluginModule> module =
      original_module_.get() ? original_module_ : module_;
  // Only check for the interface if the plugin has private permission.
  if (!module->permissions().HasPermission(ppapi::PERMISSION_PRIVATE))
    return false;
  if (!plugin_private_interface_) {
    plugin_private_interface_ = static_cast<const PPP_Instance_Private*>(
        module->GetPluginInterface(PPP_INSTANCE_PRIVATE_INTERFACE));
  }

  return !!plugin_private_interface_;
}

bool PepperPluginInstanceImpl::LoadTextInputInterface() {
  if (!plugin_textinput_interface_) {
    plugin_textinput_interface_ = static_cast<const PPP_TextInput_Dev*>(
        module_->GetPluginInterface(PPP_TEXTINPUT_DEV_INTERFACE));
  }

  return !!plugin_textinput_interface_;
}

void PepperPluginInstanceImpl::SetGraphics2DTransform(
    const float& scale,
    const gfx::PointF& translation) {
  graphics2d_scale_ = scale;
  graphics2d_translation_ = translation;

  UpdateLayerTransform();
}

void PepperPluginInstanceImpl::UpdateLayerTransform() {
  if (!bound_graphics_2d_platform_ || !texture_layer_) {
    // Currently the transform is only applied for Graphics2D.
    return;
  }
  // Set the UV coordinates of the texture based on the size of the Graphics2D
  // context. By default a texture gets scaled to the size of the layer. But
  // if the size of the Graphics2D context doesn't match the size of the plugin
  // then it will be incorrectly stretched. This also affects how the plugin
  // is painted when it is being resized. If the Graphics2D contents are
  // stretched when a plugin is resized while waiting for a new frame from the
  // plugin to be rendered, then flickering behavior occurs as in
  // crbug.com/353453.
  gfx::SizeF graphics_2d_size_in_dip =
      gfx::ScaleSize(gfx::SizeF(bound_graphics_2d_platform_->Size()),
                     bound_graphics_2d_platform_->GetScale());
  gfx::Size plugin_size_in_dip(view_data_.rect.size.width,
                               view_data_.rect.size.height);

  // Adding the SetLayerTransform from Graphics2D to the UV.
  // If graphics2d_scale_ is 1.f and graphics2d_translation_ is 0 then UV will
  // be top_left (0,0) and lower_right (plugin_size_in_dip.width() /
  // graphics_2d_size_in_dip.width(), plugin_size_in_dip.height() /
  // graphics_2d_size_in_dip.height())
  gfx::PointF top_left =
      gfx::PointF(-graphics2d_translation_.x() / graphics2d_scale_,
                  -graphics2d_translation_.y() / graphics2d_scale_);
  gfx::PointF lower_right =
      gfx::PointF((1 / graphics2d_scale_) * plugin_size_in_dip.width() -
                      graphics2d_translation_.x() / graphics2d_scale_,
                  (1 / graphics2d_scale_) * plugin_size_in_dip.height() -
                      graphics2d_translation_.y() / graphics2d_scale_);
  texture_layer_->SetUV(
      gfx::PointF(top_left.x() / graphics_2d_size_in_dip.width(),
                  top_left.y() / graphics_2d_size_in_dip.height()),
      gfx::PointF(lower_right.x() / graphics_2d_size_in_dip.width(),
                  lower_right.y() / graphics_2d_size_in_dip.height()));
}

bool PepperPluginInstanceImpl::PluginHasFocus() const {
  return flash_fullscreen_ || (has_webkit_focus_ && has_content_area_focus_);
}

void PepperPluginInstanceImpl::SendFocusChangeNotification() {
  // Keep a reference on the stack. RenderFrameImpl::PepperFocusChanged may
  // remove the <embed> from the DOM, which will make the PepperWebPluginImpl
  // drop its reference, usually the last one. This is similar to possible
  // plugin behavior described at the NOTE above Delete().
  scoped_refptr<PepperPluginInstanceImpl> ref(this);

  if (!render_frame_)
    return;

  bool has_focus = PluginHasFocus();
  render_frame_->PepperFocusChanged(this, has_focus);

  // instance_interface_ may have been cleared in Delete() if the
  // PepperWebPluginImpl is destroyed.
  if (instance_interface_)
    instance_interface_->DidChangeFocus(pp_instance(), PP_FromBool(has_focus));
}

void PepperPluginInstanceImpl::UpdateTouchEventRequest() {
  // If the view has 0 area don't request touch events.
  if (view_data_.rect.size.width == 0 || view_data_.rect.size.height == 0) {
    container_->RequestTouchEventType(
        blink::WebPluginContainer::kTouchEventRequestTypeNone);
    return;
  }
  blink::WebPluginContainer::TouchEventRequestType request_type =
      blink::WebPluginContainer::kTouchEventRequestTypeSynthesizedMouse;
  if ((filtered_input_event_mask_ & PP_INPUTEVENT_CLASS_COALESCED_TOUCH) ||
      (input_event_mask_ & PP_INPUTEVENT_CLASS_COALESCED_TOUCH)) {
    request_type =
        blink::WebPluginContainer::kTouchEventRequestTypeRawLowLatency;
  } else if ((filtered_input_event_mask_ & PP_INPUTEVENT_CLASS_TOUCH) ||
             (input_event_mask_ & PP_INPUTEVENT_CLASS_TOUCH)) {
    request_type = blink::WebPluginContainer::kTouchEventRequestTypeRaw;
  }

  container_->RequestTouchEventType(request_type);
}

void PepperPluginInstanceImpl::UpdateWheelEventRequest() {
  // If the view has 0 area don't request wheel events.
  if (view_data_.rect.size.width == 0 || view_data_.rect.size.height == 0) {
    container_->SetWantsWheelEvents(false);
    return;
  }

  bool hasWheelMask =
      (filtered_input_event_mask_ & PP_INPUTEVENT_CLASS_WHEEL) ||
      (input_event_mask_ & PP_INPUTEVENT_CLASS_WHEEL);
  container_->SetWantsWheelEvents(hasWheelMask);
}

void PepperPluginInstanceImpl::ScheduleAsyncDidChangeView() {
  if (view_change_weak_ptr_factory_.HasWeakPtrs())
    return;  // Already scheduled.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(&PepperPluginInstanceImpl::SendAsyncDidChangeView,
                     view_change_weak_ptr_factory_.GetWeakPtr()));
}

void PepperPluginInstanceImpl::SendAsyncDidChangeView() {
  // The bound callback that owns the weak pointer is still valid until after
  // this function returns. SendDidChangeView checks HasWeakPtrs, so we need to
  // invalidate them here.
  // NOTE: If we ever want to have more than one pending callback, it should
  // use a different factory, or we should have a different strategy here.
  view_change_weak_ptr_factory_.InvalidateWeakPtrs();
  SendDidChangeView();
}

void PepperPluginInstanceImpl::SendDidChangeView() {
  if (!render_frame_)
    return;

  // An asynchronous view update is scheduled. Skip sending this update.
  if (view_change_weak_ptr_factory_.HasWeakPtrs())
    return;

  // Don't send DidChangeView to crashed plugins.
  if (module()->is_crashed())
    return;

  if (bound_compositor_)
    bound_compositor_->set_viewport_to_dip_scale(viewport_to_dip_scale_);

  if (bound_graphics_2d_platform_)
    bound_graphics_2d_platform_->set_viewport_to_dip_scale(
        viewport_to_dip_scale_);

  module_->renderer_ppapi_host()->set_viewport_to_dip_scale(
      viewport_to_dip_scale_);

  // During the first view update, initialize the throttler.
  if (!sent_initial_did_change_view_) {
    if (is_flash_plugin_ && RenderThread::Get()) {
      RecordFlashSizeMetric(unobscured_rect_.width(),
                            unobscured_rect_.height());
    }

    if (throttler_) {
      throttler_->Initialize(render_frame_, url::Origin::Create(plugin_url_),
                             module()->name(), unobscured_rect_.size());
    }
  }

  ppapi::ViewData view_data = view_data_;

  // When plugin content is throttled, fake the page being offscreen. We cannot
  // send empty view data here, as some plugins rely on accurate view data.
  if (throttler_ && throttler_->IsThrottled()) {
    view_data.is_page_visible = false;
    view_data.clip_rect.point.x = 0;
    view_data.clip_rect.point.y = 0;
    view_data.clip_rect.size.width = 0;
    view_data.clip_rect.size.height = 0;
  }

  if (sent_initial_did_change_view_ && last_sent_view_data_.Equals(view_data))
    return;  // Nothing to update.

  sent_initial_did_change_view_ = true;
  last_sent_view_data_ = view_data;
  ScopedPPResource resource(
      ScopedPPResource::PassRef(),
      (new PPB_View_Shared(ppapi::OBJECT_IS_IMPL, pp_instance(), view_data))
          ->GetReference());

  UpdateLayerTransform();

  if (bound_graphics_2d_platform_ &&
      (!view_data.is_page_visible ||
       PP_ToGfxRect(view_data.clip_rect).IsEmpty())) {
    bound_graphics_2d_platform_->ClearCache();
  }

  // It's possible that Delete() has been called but the renderer hasn't
  // released its reference to this object yet.
  if (instance_interface_) {
    instance_interface_->DidChangeView(
        pp_instance(), resource, &view_data.rect, &view_data.clip_rect);
  }
}

void PepperPluginInstanceImpl::ReportGeometry() {
  // If this call was delayed, we may have transitioned back to fullscreen in
  // the mean time, so only report the geometry if we are actually in normal
  // mode.
  if (container_ && !fullscreen_container_ && !flash_fullscreen_)
    container_->ReportGeometry();
}

bool PepperPluginInstanceImpl::GetPreferredPrintOutputFormat(
    PP_PrintOutputFormat_Dev* format,
    const WebPrintParams& print_params) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  if (!LoadPrintInterface())
    return false;
  uint32_t supported_formats =
      plugin_print_interface_->QuerySupportedFormats(pp_instance());
  if ((supported_formats & PP_PRINTOUTPUTFORMAT_PDF) &&
      !print_params.rasterize_pdf) {
    *format = PP_PRINTOUTPUTFORMAT_PDF;
    return true;
  }
  if (supported_formats & PP_PRINTOUTPUTFORMAT_RASTER) {
    *format = PP_PRINTOUTPUTFORMAT_RASTER;
    return true;
  }
  return false;
}

bool PepperPluginInstanceImpl::SupportsPrintInterface() {
  PP_PrintOutputFormat_Dev format;
  WebPrintParams params;
  params.rasterize_pdf = false;
  return GetPreferredPrintOutputFormat(&format, params);
}

bool PepperPluginInstanceImpl::IsPrintScalingDisabled() {
  DCHECK(plugin_print_interface_);
  if (!plugin_print_interface_)
    return false;
  return plugin_print_interface_->IsScalingDisabled(pp_instance()) == PP_TRUE;
}

int PepperPluginInstanceImpl::PrintBegin(const WebPrintParams& print_params) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  PP_PrintOutputFormat_Dev format;
  if (!GetPreferredPrintOutputFormat(&format, print_params)) {
    // PrintBegin should not have been called since SupportsPrintInterface
    // would have returned false;
    NOTREACHED();
    return 0;
  }
  int num_pages = 0;
  PP_PrintSettings_Dev print_settings;
  print_settings.printable_area = PP_FromGfxRect(print_params.printable_area);
  print_settings.content_area = PP_FromGfxRect(print_params.print_content_area);
  print_settings.paper_size = PP_FromGfxSize(print_params.paper_size);
  print_settings.dpi = print_params.printer_dpi;
  print_settings.orientation = PP_PRINTORIENTATION_NORMAL;
  print_settings.grayscale = PP_FALSE;
  print_settings.print_scaling_option =
      static_cast<PP_PrintScalingOption_Dev>(print_params.print_scaling_option);
  print_settings.format = format;
  num_pages = plugin_print_interface_->Begin(pp_instance(), &print_settings);
  if (!num_pages)
    return 0;
  current_print_settings_ = print_settings;
  metafile_ = nullptr;
  ranges_.clear();
  ranges_.reserve(num_pages);
  return num_pages;
}

void PepperPluginInstanceImpl::PrintPage(int page_number,
                                         blink::WebCanvas* canvas) {
#if BUILDFLAG(ENABLE_PRINTING)
  DCHECK(plugin_print_interface_);

  // |canvas| should always have an associated metafile.
  printing::PdfMetafileSkia* metafile =
      printing::MetafileSkiaWrapper::GetMetafileFromCanvas(canvas);
  DCHECK(metafile);

  // |ranges_| should be empty IFF |metafile_| is not set.
  DCHECK_EQ(ranges_.empty(), !metafile_);
  if (metafile_) {
    // The metafile should be the same across all calls for a given print job.
    DCHECK_EQ(metafile_, metafile);
  } else {
    // Store |metafile| on the first call.
    metafile_ = metafile;
  }

  PP_PrintPageNumberRange_Dev page_range = {page_number, page_number};
  ranges_.push_back(page_range);
#endif
}

void PepperPluginInstanceImpl::PrintEnd() {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  DCHECK(plugin_print_interface_);

  if (!ranges_.empty()) {
    PP_Resource print_output = plugin_print_interface_->PrintPages(
        pp_instance(), ranges_.data(), ranges_.size());
    if (print_output) {
      if (current_print_settings_.format == PP_PRINTOUTPUTFORMAT_PDF ||
          current_print_settings_.format == PP_PRINTOUTPUTFORMAT_RASTER) {
        PrintPDFOutput(print_output, metafile_);
      }

      // Now release the print output resource.
      PluginModule::GetCore()->ReleaseResource(print_output);
    }

    ranges_.clear();
    metafile_ = nullptr;
  }

  plugin_print_interface_->End(pp_instance());
  memset(&current_print_settings_, 0, sizeof(current_print_settings_));
}

bool PepperPluginInstanceImpl::GetPrintPresetOptionsFromDocument(
    blink::WebPrintPresetOptions* preset_options) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  if (!LoadPdfInterface())
    return false;

  PP_PdfPrintPresetOptions_Dev options;
  if (!plugin_pdf_interface_->GetPrintPresetOptionsFromDocument(pp_instance(),
                                                                &options)) {
    return false;
  }

  preset_options->is_scaling_disabled = PP_ToBool(options.is_scaling_disabled);
  switch (options.duplex) {
    case PP_PRIVATEDUPLEXMODE_SIMPLEX:
      preset_options->duplex_mode = blink::kWebSimplex;
      break;
    case PP_PRIVATEDUPLEXMODE_SHORT_EDGE:
      preset_options->duplex_mode = blink::kWebShortEdge;
      break;
    case PP_PRIVATEDUPLEXMODE_LONG_EDGE:
      preset_options->duplex_mode = blink::kWebLongEdge;
      break;
    default:
      preset_options->duplex_mode = blink::kWebUnknownDuplexMode;
      break;
  }
  preset_options->copies = options.copies;
  preset_options->is_page_size_uniform =
      PP_ToBool(options.is_page_size_uniform);
  preset_options->uniform_page_size = blink::WebSize(
      options.uniform_page_size.width, options.uniform_page_size.height);

  return true;
}

bool PepperPluginInstanceImpl::CanRotateView() {
  if (!LoadPdfInterface() || module()->is_crashed())
    return false;

  return true;
}

void PepperPluginInstanceImpl::RotateView(WebPlugin::RotationType type) {
  if (!LoadPdfInterface())
    return;
  PP_PrivatePageTransformType transform_type =
      type == WebPlugin::kRotationType90Clockwise
          ? PP_PRIVATEPAGETRANSFORMTYPE_ROTATE_90_CW
          : PP_PRIVATEPAGETRANSFORMTYPE_ROTATE_90_CCW;
  plugin_pdf_interface_->Transform(pp_instance(), transform_type);
  // NOTE: plugin instance may have been deleted.
}

bool PepperPluginInstanceImpl::FlashIsFullscreenOrPending() {
  return fullscreen_container_ != nullptr;
}

bool PepperPluginInstanceImpl::IsFullscreenOrPending() {
  return desired_fullscreen_state_;
}

bool PepperPluginInstanceImpl::SetFullscreen(bool fullscreen) {
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);

  // Check whether we are trying to switch to the state we're already going
  // to (i.e. if we're already switching to fullscreen but the fullscreen
  // container isn't ready yet, don't do anything more).
  if (fullscreen == IsFullscreenOrPending())
    return false;

  if (!SetFullscreenCommon(fullscreen))
    return false;

  // Check whether we are trying to switch while the state is in transition.
  // The 2nd request gets dropped while messing up the internal state, so
  // disallow this.
  if (view_data_.is_fullscreen != desired_fullscreen_state_)
    return false;

  DVLOG(1) << "Setting fullscreen to " << (fullscreen ? "on" : "off");
  desired_fullscreen_state_ = fullscreen;

  if (fullscreen) {
    // Create the user gesture in case we're processing one that's pending.
    WebScopedUserGesture user_gesture(CurrentUserGestureToken());
    // WebKit does not resize the plugin to fill the screen in fullscreen mode,
    // so we will tweak plugin's attributes to support the expected behavior.
    KeepSizeAttributesBeforeFullscreen();
    SetSizeAttributesForFullscreen();
    container_->RequestFullscreen();
  } else {
    container_->CancelFullscreen();
  }
  return true;
}

void PepperPluginInstanceImpl::UpdateFlashFullscreenState(
    bool flash_fullscreen) {
  bool is_mouselock_pending = TrackedCallback::IsPending(lock_mouse_callback_);

  if (flash_fullscreen == flash_fullscreen_) {
    // Manually clear callback when fullscreen fails with mouselock pending.
    if (!flash_fullscreen && is_mouselock_pending)
      lock_mouse_callback_->Run(PP_ERROR_FAILED);
    return;
  }

  UpdateLayer(false);

  bool old_plugin_focus = PluginHasFocus();
  flash_fullscreen_ = flash_fullscreen;
  if (is_mouselock_pending && !IsMouseLocked()) {
    if (!IsProcessingUserGesture() &&
        !module_->permissions().HasPermission(
            ppapi::PERMISSION_BYPASS_USER_GESTURE)) {
      lock_mouse_callback_->Run(PP_ERROR_NO_USER_GESTURE);
    } else {
      // Open a user gesture here so the Webkit user gesture checks will succeed
      // for out-of-process plugins.
      WebScopedUserGesture user_gesture(CurrentUserGestureToken());
      if (!LockMouse())
        lock_mouse_callback_->Run(PP_ERROR_FAILED);
    }
  }

  if (PluginHasFocus() != old_plugin_focus)
    SendFocusChangeNotification();
}

bool PepperPluginInstanceImpl::IsViewAccelerated() {
  if (!container_)
    return false;

  WebDocument document = container_->GetDocument();
  WebLocalFrame* frame = document.GetFrame();
  if (!frame)
    return false;

  WebView* view = frame->View();
  return view && view->IsAcceleratedCompositingActive();
}

void PepperPluginInstanceImpl::UpdateLayer(bool force_creation) {
  if (!container_)
    return;

  bool want_3d_layer = !!bound_graphics_3d_.get();
  bool want_2d_layer = !!bound_graphics_2d_platform_;
  bool want_texture_layer = want_3d_layer || want_2d_layer;
  bool want_compositor_layer = !!bound_compositor_;

  if (throttler_ && throttler_->IsHiddenForPlaceholder()) {
    want_3d_layer = false;
    want_2d_layer = false;
    want_texture_layer = false;
    want_compositor_layer = false;
  }

  if (!force_creation && (want_texture_layer == !!texture_layer_) &&
      (want_3d_layer == layer_is_hardware_) &&
      (want_compositor_layer == !!compositor_layer_.get()) &&
      layer_bound_to_fullscreen_ == !!fullscreen_container_) {
    UpdateLayerTransform();
    return;
  }

  if (texture_layer_ || compositor_layer_) {
    if (!layer_bound_to_fullscreen_)
      container_->SetWebLayer(nullptr);
    else if (fullscreen_container_)
      fullscreen_container_->SetLayer(nullptr);
    web_layer_.reset();
    if (texture_layer_) {
      texture_layer_->ClearClient();
      texture_layer_ = nullptr;
    }
    compositor_layer_ = nullptr;
  }

  if (want_texture_layer) {
    bool opaque = false;
    if (want_3d_layer) {
      DCHECK(bound_graphics_3d_.get());
      texture_layer_ = cc::TextureLayer::CreateForMailbox(nullptr);
      opaque = bound_graphics_3d_->IsOpaque();

      PassCommittedTextureToTextureLayer();
    } else {
      DCHECK(bound_graphics_2d_platform_);
      texture_layer_ = cc::TextureLayer::CreateForMailbox(this);
      bound_graphics_2d_platform_->AttachedToNewLayer();
      opaque = bound_graphics_2d_platform_->IsAlwaysOpaque();
      texture_layer_->SetFlipped(false);
    }

    auto layer = std::make_unique<cc_blink::WebLayerImpl>(texture_layer_);
    // Ignore transparency in fullscreen, since that's what Flash always
    // wants to do, and that lets it not recreate a context if
    // wmode=transparent was specified.
    opaque = opaque || fullscreen_container_;
    layer->layer()->SetContentsOpaque(opaque);
    layer->SetContentsOpaqueIsFixed(true);
    web_layer_ = std::move(layer);
  } else if (want_compositor_layer) {
    compositor_layer_ = bound_compositor_->layer();
    web_layer_ = std::make_unique<cc_blink::WebLayerImpl>(compositor_layer_);
  }

  if (web_layer_) {
    if (fullscreen_container_) {
      fullscreen_container_->SetLayer(web_layer_.get());
    } else {
      container_->SetWebLayer(web_layer_.get());
    }
    if (is_flash_plugin_) {
      web_layer_->CcLayer()->SetMayContainVideo(true);
    }
  }

  layer_bound_to_fullscreen_ = !!fullscreen_container_;
  layer_is_hardware_ = want_3d_layer;
  UpdateLayerTransform();
}

bool PepperPluginInstanceImpl::PrepareTransferableResource(
    cc::SharedBitmapIdRegistrar* bitmap_registrar,
    viz::TransferableResource* transferable_resource,
    std::unique_ptr<viz::SingleReleaseCallback>* release_callback) {
  if (!bound_graphics_2d_platform_)
    return false;
  return bound_graphics_2d_platform_->PrepareTransferableResource(
      bitmap_registrar, transferable_resource, release_callback);
}

void PepperPluginInstanceImpl::AccessibilityModeChanged() {
  if (render_frame_ && render_frame_->render_accessibility() &&
      LoadPdfInterface()) {
    plugin_pdf_interface_->EnableAccessibility(pp_instance());
  }
}

void PepperPluginInstanceImpl::OnDestruct() {
  render_frame_ = nullptr;
}

void PepperPluginInstanceImpl::OnThrottleStateChange() {
  if (!render_frame_)
    return;

  SendDidChangeView();

  bool is_throttled = throttler_->IsThrottled();
  render_frame()->Send(new FrameHostMsg_PluginInstanceThrottleStateChange(
      module_->GetPluginChildId(), pp_instance_, is_throttled));
}

void PepperPluginInstanceImpl::OnHiddenForPlaceholder(bool hidden) {
  UpdateLayer(false /* device_changed */);
}

void PepperPluginInstanceImpl::AddPluginObject(PluginObject* plugin_object) {
  DCHECK(live_plugin_objects_.find(plugin_object) ==
         live_plugin_objects_.end());
  live_plugin_objects_.insert(plugin_object);
}

void PepperPluginInstanceImpl::RemovePluginObject(PluginObject* plugin_object) {
  // Don't actually verify that the object is in the set since during module
  // deletion we'll be in the process of freeing them.
  live_plugin_objects_.erase(plugin_object);
}

bool PepperPluginInstanceImpl::IsProcessingUserGesture() const {
  PP_TimeTicks now = ppapi::TimeTicksToPPTimeTicks(base::TimeTicks::Now());
  // Give a lot of slack so tests won't be flaky.
  const PP_TimeTicks kUserGestureDurationInSeconds = 10.0;
  return pending_user_gesture_token_.HasGestures() &&
         (now - pending_user_gesture_ < kUserGestureDurationInSeconds);
}

WebUserGestureToken PepperPluginInstanceImpl::CurrentUserGestureToken() {
  if (!IsProcessingUserGesture())
    pending_user_gesture_token_ = WebUserGestureToken();
  return pending_user_gesture_token_;
}

void PepperPluginInstanceImpl::OnLockMouseACK(bool succeeded) {
  if (TrackedCallback::IsPending(lock_mouse_callback_))
    lock_mouse_callback_->Run(succeeded ? PP_OK : PP_ERROR_FAILED);
}

void PepperPluginInstanceImpl::OnMouseLockLost() {
  if (LoadMouseLockInterface())
    plugin_mouse_lock_interface_->MouseLockLost(pp_instance());
}

void PepperPluginInstanceImpl::HandleMouseLockedInputEvent(
    const blink::WebMouseEvent& event) {
  // |cursor_info| is ignored since it is hidden when the mouse is locked.
  blink::WebCursorInfo cursor_info;
  HandleInputEvent(event, &cursor_info);
}

void PepperPluginInstanceImpl::SimulateInputEvent(
    const InputEventData& input_event) {
  WebWidget* widget =
      container()->GetDocument().GetFrame()->LocalRoot()->FrameWidget();
  if (!widget) {
    NOTREACHED();
    return;
  }

  bool handled = SimulateIMEEvent(input_event);
  if (handled)
    return;

  std::vector<std::unique_ptr<WebInputEvent>> events =
      CreateSimulatedWebInputEvents(
          input_event, view_data_.rect.point.x + view_data_.rect.size.width / 2,
          view_data_.rect.point.y + view_data_.rect.size.height / 2);
  for (std::vector<std::unique_ptr<WebInputEvent>>::iterator it =
           events.begin();
       it != events.end(); ++it) {
    widget->HandleInputEvent(blink::WebCoalescedInputEvent(*it->get()));
  }
  if (input_event.event_type == PP_INPUTEVENT_TYPE_TOUCHSTART ||
      input_event.event_type == PP_INPUTEVENT_TYPE_TOUCHMOVE ||
      input_event.event_type == PP_INPUTEVENT_TYPE_TOUCHEND ||
      input_event.event_type == PP_INPUTEVENT_TYPE_TOUCHCANCEL)
    widget->DispatchBufferedTouchEvents();
}

bool PepperPluginInstanceImpl::SimulateIMEEvent(
    const InputEventData& input_event) {
  switch (input_event.event_type) {
    case PP_INPUTEVENT_TYPE_IME_COMPOSITION_START:
    case PP_INPUTEVENT_TYPE_IME_COMPOSITION_UPDATE:
      SimulateImeSetCompositionEvent(input_event);
      break;
    case PP_INPUTEVENT_TYPE_IME_COMPOSITION_END:
      DCHECK(input_event.character_text.empty());
      SimulateImeSetCompositionEvent(input_event);
      break;
    case PP_INPUTEVENT_TYPE_IME_TEXT:
      if (!render_frame_)
        return false;
      render_frame_->SimulateImeCommitText(
          base::UTF8ToUTF16(input_event.character_text),
          std::vector<blink::WebImeTextSpan>(), gfx::Range());
      break;
    default:
      return false;
  }
  return true;
}

void PepperPluginInstanceImpl::SimulateImeSetCompositionEvent(
    const InputEventData& input_event) {
  if (!render_frame_)
    return;

  std::vector<size_t> offsets;
  offsets.push_back(input_event.composition_selection_start);
  offsets.push_back(input_event.composition_selection_end);
  offsets.insert(offsets.end(),
                 input_event.composition_segment_offsets.begin(),
                 input_event.composition_segment_offsets.end());

  base::string16 utf16_text =
      base::UTF8ToUTF16AndAdjustOffsets(input_event.character_text, &offsets);

  std::vector<blink::WebImeTextSpan> ime_text_spans;
  for (size_t i = 2; i + 1 < offsets.size(); ++i) {
    blink::WebImeTextSpan ime_text_span;
    ime_text_span.start_offset = offsets[i];
    ime_text_span.end_offset = offsets[i + 1];
    if (input_event.composition_target_segment == static_cast<int32_t>(i - 2))
      ime_text_span.thickness = ui::mojom::ImeTextSpanThickness::kThick;
    ime_text_spans.push_back(ime_text_span);
  }

  render_frame_->SimulateImeSetComposition(utf16_text, ime_text_spans,
                                           offsets[0], offsets[1]);
}

PP_Bool PepperPluginInstanceImpl::BindGraphics(PP_Instance instance,
                                               PP_Resource device) {
  TRACE_EVENT0("ppapi", "PepperPluginInstanceImpl::BindGraphics");
  // The Graphics3D instance can't be destroyed until we call
  // UpdateLayer().
  scoped_refptr<ppapi::Resource> old_graphics = bound_graphics_3d_.get();
  if (bound_graphics_3d_.get()) {
    bound_graphics_3d_->BindToInstance(false);
    bound_graphics_3d_ = nullptr;
  }
  if (bound_graphics_2d_platform_) {
    bound_graphics_2d_platform_->BindToInstance(nullptr);
    bound_graphics_2d_platform_ = nullptr;
  }
  if (bound_compositor_) {
    bound_compositor_->BindToInstance(nullptr);
    bound_compositor_ = nullptr;
  }

  // Special-case clearing the current device.
  if (!device) {
    UpdateLayer(true);
    InvalidateRect(gfx::Rect());
    return PP_TRUE;
  }

  // Refuse to bind if in transition to fullscreen with PPB_FlashFullscreen or
  // to/from fullscreen with PPB_Fullscreen.
  if ((fullscreen_container_ && !flash_fullscreen_) ||
      desired_fullscreen_state_ != view_data_.is_fullscreen)
    return PP_FALSE;

  const ppapi::host::PpapiHost* ppapi_host =
      RendererPpapiHost::GetForPPInstance(instance)->GetPpapiHost();
  ppapi::host::ResourceHost* host = ppapi_host->GetResourceHost(device);
  PepperGraphics2DHost* graphics_2d = nullptr;
  PepperCompositorHost* compositor = nullptr;
  if (host) {
    if (host->IsGraphics2DHost()) {
      graphics_2d = static_cast<PepperGraphics2DHost*>(host);
    } else if (host->IsCompositorHost()) {
      compositor = static_cast<PepperCompositorHost*>(host);
    } else {
      DLOG(ERROR) <<
          "Resource is not PepperCompositorHost or PepperGraphics2DHost.";
    }
  }

  EnterResourceNoLock<PPB_Graphics3D_API> enter_3d(device, false);
  PPB_Graphics3D_Impl* graphics_3d =
      enter_3d.succeeded()
          ? static_cast<PPB_Graphics3D_Impl*>(enter_3d.object())
          : nullptr;

  if (compositor) {
    if (compositor->BindToInstance(this)) {
      bound_compositor_ = compositor;
      bound_compositor_->set_viewport_to_dip_scale(viewport_to_dip_scale_);
      UpdateLayer(true);
      return PP_TRUE;
    }
  } else if (graphics_2d) {
    if (graphics_2d->BindToInstance(this)) {
      bound_graphics_2d_platform_ = graphics_2d;
      bound_graphics_2d_platform_->set_viewport_to_dip_scale(
          viewport_to_dip_scale_);
      UpdateLayer(true);
      return PP_TRUE;
    }
  } else if (graphics_3d) {
    // Make sure graphics can only be bound to the instance it is
    // associated with.
    if (graphics_3d->pp_instance() == pp_instance() &&
        graphics_3d->BindToInstance(true)) {
      bound_graphics_3d_ = graphics_3d;
      UpdateLayer(true);
      return PP_TRUE;
    }
  }

  // The instance cannot be bound or the device is not a valid resource type.
  return PP_FALSE;
}

PP_Bool PepperPluginInstanceImpl::IsFullFrame(PP_Instance instance) {
  return PP_FromBool(full_frame());
}

const ViewData* PepperPluginInstanceImpl::GetViewData(PP_Instance instance) {
  return &view_data_;
}

PP_Bool PepperPluginInstanceImpl::FlashIsFullscreen(PP_Instance instance) {
  return PP_FromBool(flash_fullscreen_);
}

PP_Var PepperPluginInstanceImpl::GetWindowObject(PP_Instance instance) {
  if (!container_)
    return PP_MakeUndefined();
  V8VarConverter converter(pp_instance_, V8VarConverter::kAllowObjectVars);
  PepperTryCatchVar try_catch(this, &converter, nullptr);
  WebLocalFrame* frame = container_->GetDocument().GetFrame();
  if (!frame) {
    try_catch.SetException("No frame exists for window object.");
    return PP_MakeUndefined();
  }

  ScopedPPVar result =
      try_catch.FromV8(frame->MainWorldScriptContext()->Global());
  DCHECK(!try_catch.HasException());
  return result.Release();
}

PP_Var PepperPluginInstanceImpl::GetOwnerElementObject(PP_Instance instance) {
  if (!container_)
    return PP_MakeUndefined();
  V8VarConverter converter(pp_instance_, V8VarConverter::kAllowObjectVars);
  PepperTryCatchVar try_catch(this, &converter, nullptr);
  ScopedPPVar result = try_catch.FromV8(container_->V8ObjectForElement());
  DCHECK(!try_catch.HasException());
  return result.Release();
}

PP_Var PepperPluginInstanceImpl::ExecuteScript(PP_Instance instance,
                                               PP_Var script_var,
                                               PP_Var* exception) {
  if (!container_)
    return PP_MakeUndefined();
  if (is_deleted_ && blink::WebPluginScriptForbiddenScope::IsForbidden())
    return PP_MakeUndefined();

  // Executing the script may remove the plugin from the DOM, so we need to keep
  // a reference to ourselves so that we can still process the result after
  // running the script below.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);
  V8VarConverter converter(pp_instance_, V8VarConverter::kAllowObjectVars);
  PepperTryCatchVar try_catch(this, &converter, exception);

  // Check for an exception due to the context being destroyed.
  if (try_catch.HasException())
    return PP_MakeUndefined();

  WebLocalFrame* frame = container_->GetDocument().GetFrame();
  if (!frame) {
    try_catch.SetException("No frame to execute script in.");
    return PP_MakeUndefined();
  }

  StringVar* script_string_var = StringVar::FromPPVar(script_var);
  if (!script_string_var) {
    try_catch.SetException("Script param to ExecuteScript must be a string.");
    return PP_MakeUndefined();
  }

  std::string script_string = script_string_var->value();
  blink::WebScriptSource script(
      blink::WebString::FromUTF8(script_string.c_str()));
  v8::Local<v8::Value> result;
  if (IsProcessingUserGesture()) {
    blink::WebScopedUserGesture user_gesture(CurrentUserGestureToken());
    result = frame->ExecuteScriptAndReturnValue(script);
  } else {
    result = frame->ExecuteScriptAndReturnValue(script);
  }

  ScopedPPVar var_result = try_catch.FromV8(result);
  if (try_catch.HasException())
    return PP_MakeUndefined();

  return var_result.Release();
}

uint32_t PepperPluginInstanceImpl::GetAudioHardwareOutputSampleRate(
    PP_Instance instance) {
  return render_frame() ? AudioDeviceFactory::GetOutputDeviceInfo(
                              render_frame()->GetRoutingID(),
                              0 /* session_id */, std::string() /* device_id */)
                              .output_params()
                              .sample_rate()
                        : 0;
}

uint32_t PepperPluginInstanceImpl::GetAudioHardwareOutputBufferSize(
    PP_Instance instance) {
  return render_frame() ? AudioDeviceFactory::GetOutputDeviceInfo(
                              render_frame()->GetRoutingID(),
                              0 /* session_id */, std::string() /* device_id */
                              )
                              .output_params()
                              .frames_per_buffer()
                        : 0;
}

PP_Var PepperPluginInstanceImpl::GetDefaultCharSet(PP_Instance instance) {
  if (!render_frame_)
    return PP_MakeUndefined();
  return StringVar::StringToPPVar(
      render_frame_->render_view()->webkit_preferences().default_encoding);
}

void PepperPluginInstanceImpl::SetPluginToHandleFindRequests(
    PP_Instance instance) {
  if (!LoadFindInterface())
    return;
  bool is_main_frame =
      render_frame_ &&
      render_frame_->GetRenderView()->GetMainRenderFrame() == render_frame_;
  if (!is_main_frame)
    return;
  render_frame_->set_plugin_find_handler(this);
}

void PepperPluginInstanceImpl::NumberOfFindResultsChanged(
    PP_Instance instance,
    int32_t total,
    PP_Bool final_result) {
  // After stopping search and setting find_identifier_ to -1 there still may be
  // a NumberOfFindResultsChanged notification pending from plug-in. Just ignore
  // them.
  if (find_identifier_ == -1)
    return;
  if (render_frame_) {
    render_frame_->ReportFindInPageMatchCount(find_identifier_, total,
                                              PP_ToBool(final_result));
  }
}

void PepperPluginInstanceImpl::SelectedFindResultChanged(PP_Instance instance,
                                                         int32_t index) {
  if (find_identifier_ == -1)
    return;
  if (render_frame_) {
    render_frame_->ReportFindInPageSelection(find_identifier_, index + 1,
                                             blink::WebRect());
  }
}

void PepperPluginInstanceImpl::SetTickmarks(PP_Instance instance,
                                            const PP_Rect* tickmarks,
                                            uint32_t count) {
  if (!render_frame_ || !render_frame_->GetWebFrame())
    return;

  blink::WebVector<blink::WebRect> tickmarks_converted(
      static_cast<size_t>(count));
  for (uint32_t i = 0; i < count; ++i) {
    gfx::RectF tickmark(tickmarks[i].point.x,
                        tickmarks[i].point.y,
                        tickmarks[i].size.width,
                        tickmarks[i].size.height);
    tickmark.Scale(1 / viewport_to_dip_scale_);
    tickmarks_converted[i] = blink::WebRect(gfx::ToEnclosedRect(tickmark));
  }
  WebLocalFrame* frame = render_frame_->GetWebFrame();
  frame->SetTickmarks(tickmarks_converted);
}

PP_Bool PepperPluginInstanceImpl::IsFullscreen(PP_Instance instance) {
  return PP_FromBool(view_data_.is_fullscreen);
}

PP_Bool PepperPluginInstanceImpl::SetFullscreen(PP_Instance instance,
                                                PP_Bool fullscreen) {
  return PP_FromBool(SetFullscreen(PP_ToBool(fullscreen)));
}

PP_Bool PepperPluginInstanceImpl::GetScreenSize(PP_Instance instance,
                                                PP_Size* size) {
  if (flash_fullscreen_) {
    // Workaround for Flash rendering bug: Flash is assuming the fullscreen view
    // size will be equal to the physical screen size.  However, the fullscreen
    // view is sized by the browser UI, and may not be the same size as the
    // screen or the desktop.  Therefore, report the view size as the screen
    // size when in fullscreen mode.  http://crbug.com/506016
    // TODO(miu): Remove this workaround once Flash has been fixed.
    *size = view_data_.rect.size;
  } else {
    // All other cases: Report the screen size.
    if (!render_frame_ || !render_frame_->GetRenderWidget())
      return PP_FALSE;
    blink::WebScreenInfo info =
        render_frame_->GetRenderWidget()->GetScreenInfo();
    *size = PP_MakeSize(info.rect.width, info.rect.height);
  }
  return PP_TRUE;
}

ppapi::Resource* PepperPluginInstanceImpl::GetSingletonResource(
    PP_Instance instance,
    ppapi::SingletonResourceID id) {
  // Flash APIs and some others aren't implemented in-process.
  switch (id) {
    case ppapi::BROKER_SINGLETON_ID:
    case ppapi::BROWSER_FONT_SINGLETON_ID:
    case ppapi::FLASH_CLIPBOARD_SINGLETON_ID:
    case ppapi::FLASH_FILE_SINGLETON_ID:
    case ppapi::FLASH_FULLSCREEN_SINGLETON_ID:
    case ppapi::FLASH_SINGLETON_ID:
    case ppapi::ISOLATED_FILESYSTEM_SINGLETON_ID:
    case ppapi::NETWORK_PROXY_SINGLETON_ID:
    case ppapi::PDF_SINGLETON_ID:
    case ppapi::TRUETYPE_FONT_SINGLETON_ID:
      NOTIMPLEMENTED();
      return nullptr;
    case ppapi::GAMEPAD_SINGLETON_ID:
      return gamepad_impl_.get();
    case ppapi::UMA_SINGLETON_ID: {
      if (!uma_private_impl_.get()) {
        RendererPpapiHostImpl* host_impl = module_->renderer_ppapi_host();
        if (host_impl->in_process_router()) {
          uma_private_impl_ = new ppapi::proxy::UMAPrivateResource(
              host_impl->in_process_router()->GetPluginConnection(instance),
              instance);
        }
      }
      return uma_private_impl_.get();
    }
  }

  NOTREACHED();
  return nullptr;
}

int32_t PepperPluginInstanceImpl::RequestInputEvents(PP_Instance instance,
                                                     uint32_t event_classes) {
  input_event_mask_ |= event_classes;
  filtered_input_event_mask_ &= ~(event_classes);
  RequestInputEventsHelper(event_classes);
  return ValidateRequestInputEvents(false, event_classes);
}

int32_t PepperPluginInstanceImpl::RequestFilteringInputEvents(
    PP_Instance instance,
    uint32_t event_classes) {
  filtered_input_event_mask_ |= event_classes;
  input_event_mask_ &= ~(event_classes);
  RequestInputEventsHelper(event_classes);
  return ValidateRequestInputEvents(true, event_classes);
}

void PepperPluginInstanceImpl::ClearInputEventRequest(PP_Instance instance,
                                                      uint32_t event_classes) {
  input_event_mask_ &= ~(event_classes);
  filtered_input_event_mask_ &= ~(event_classes);
  RequestInputEventsHelper(event_classes);
}

void PepperPluginInstanceImpl::PostMessage(PP_Instance instance,
                                           PP_Var message) {
  PostMessageToJavaScript(message);
}

PP_Bool PepperPluginInstanceImpl::SetCursor(PP_Instance instance,
                                            PP_MouseCursor_Type type,
                                            PP_Resource image,
                                            const PP_Point* hot_spot) {
  if (!ValidateSetCursorParams(type, image, hot_spot))
    return PP_FALSE;

  if (type != PP_MOUSECURSOR_TYPE_CUSTOM) {
    DoSetCursor(std::make_unique<WebCursorInfo>(
        static_cast<WebCursorInfo::Type>(type)));
    return PP_TRUE;
  }

  EnterResourceNoLock<PPB_ImageData_API> enter(image, true);
  if (enter.failed())
    return PP_FALSE;
  PPB_ImageData_Impl* image_data =
      static_cast<PPB_ImageData_Impl*>(enter.object());

  ImageDataAutoMapper auto_mapper(image_data);
  if (!auto_mapper.is_valid())
    return PP_FALSE;

  auto custom_cursor =
      std::make_unique<WebCursorInfo>(WebCursorInfo::kTypeCustom);
  custom_cursor->hot_spot.x = hot_spot->x;
  custom_cursor->hot_spot.y = hot_spot->y;

  SkBitmap bitmap(image_data->GetMappedBitmap());
  // Make a deep copy, so that the cursor remains valid even after the original
  // image data gets freed.
  SkBitmap& dst = custom_cursor->custom_image.GetSkBitmap();
  if (!dst.tryAllocPixels(bitmap.info()) ||
      !bitmap.readPixels(dst.info(), dst.getPixels(), dst.rowBytes(), 0, 0)) {
    return PP_FALSE;
  }

  DoSetCursor(std::move(custom_cursor));
  return PP_TRUE;
}

int32_t PepperPluginInstanceImpl::LockMouse(
    PP_Instance instance,
    scoped_refptr<TrackedCallback> callback) {
  if (TrackedCallback::IsPending(lock_mouse_callback_))
    return PP_ERROR_INPROGRESS;

  if (IsMouseLocked())
    return PP_OK;

  if (!CanAccessMainFrame())
    return PP_ERROR_NOACCESS;

  if (!IsProcessingUserGesture())
    return PP_ERROR_NO_USER_GESTURE;

  // Attempt mouselock only if Flash isn't waiting on fullscreen, otherwise
  // we wait and call LockMouse() in UpdateFlashFullscreenState().
  if (!FlashIsFullscreenOrPending() || flash_fullscreen_) {
    // Open a user gesture here so the Webkit user gesture checks will succeed
    // for out-of-process plugins.
    WebScopedUserGesture user_gesture(CurrentUserGestureToken());
    if (!LockMouse())
      return PP_ERROR_FAILED;
  }

  // Either mouselock succeeded or a Flash fullscreen is pending.
  lock_mouse_callback_ = callback;
  return PP_OK_COMPLETIONPENDING;
}

void PepperPluginInstanceImpl::UnlockMouse(PP_Instance instance) {
  GetMouseLockDispatcher()->UnlockMouse(GetOrCreateLockTargetAdapter());
}

void PepperPluginInstanceImpl::SetTextInputType(PP_Instance instance,
                                                PP_TextInput_Type type) {
  if (!render_frame_)
    return;
  int itype = type;
  if (itype < 0 || itype > ui::TEXT_INPUT_TYPE_URL)
    itype = ui::TEXT_INPUT_TYPE_NONE;
  SetTextInputType(static_cast<ui::TextInputType>(itype));
}

void PepperPluginInstanceImpl::UpdateCaretPosition(
    PP_Instance instance,
    const PP_Rect& caret,
    const PP_Rect& bounding_box) {
  if (!render_frame_)
    return;
  TextInputCaretInfo info = {PP_ToGfxRect(caret), PP_ToGfxRect(bounding_box)};
  text_input_caret_info_ = std::move(info);
  render_frame_->PepperCaretPositionChanged(this);
}

void PepperPluginInstanceImpl::CancelCompositionText(PP_Instance instance) {
  if (render_frame_)
    render_frame_->PepperCancelComposition(this);
}

void PepperPluginInstanceImpl::SelectionChanged(PP_Instance instance) {
  // TODO(kinaba): currently the browser always calls RequestSurroundingText.
  // It can be optimized so that it won't call it back until the information
  // is really needed.

  // Avoid calling in nested context or else this will reenter the plugin. This
  // uses a weak pointer rather than exploiting the fact that this class is
  // refcounted because we don't actually want this operation to affect the
  // lifetime of the instance.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(&PepperPluginInstanceImpl::RequestSurroundingText,
                     weak_factory_.GetWeakPtr(),
                     static_cast<size_t>(kExtraCharsForTextInput)));
}

void PepperPluginInstanceImpl::UpdateSurroundingText(PP_Instance instance,
                                                     const char* text,
                                                     uint32_t caret,
                                                     uint32_t anchor) {
  if (!render_frame_)
    return;
  surrounding_text_ = text;
  selection_caret_ = caret;
  selection_anchor_ = anchor;
  render_frame_->PepperSelectionChanged(this);
}

PP_Var PepperPluginInstanceImpl::ResolveRelativeToDocument(
    PP_Instance instance,
    PP_Var relative,
    PP_URLComponents_Dev* components) {
  StringVar* relative_string = StringVar::FromPPVar(relative);
  if (!relative_string)
    return PP_MakeNull();

  GURL document_url = container()->GetDocument().BaseURL();
  return ppapi::PPB_URLUtil_Shared::GenerateURLReturn(
      document_url.Resolve(relative_string->value()), components);
}

PP_Bool PepperPluginInstanceImpl::DocumentCanRequest(PP_Instance instance,
                                                     PP_Var url) {
  StringVar* url_string = StringVar::FromPPVar(url);
  if (!url_string)
    return PP_FALSE;

  blink::WebSecurityOrigin security_origin;
  if (!SecurityOriginForInstance(instance, &security_origin))
    return PP_FALSE;

  GURL gurl(url_string->value());
  if (!gurl.is_valid())
    return PP_FALSE;

  return PP_FromBool(security_origin.CanRequest(gurl));
}

PP_Bool PepperPluginInstanceImpl::DocumentCanAccessDocument(
    PP_Instance instance,
    PP_Instance target) {
  blink::WebSecurityOrigin our_origin;
  if (!SecurityOriginForInstance(instance, &our_origin))
    return PP_FALSE;

  blink::WebSecurityOrigin target_origin;
  if (!SecurityOriginForInstance(instance, &target_origin))
    return PP_FALSE;

  return PP_FromBool(our_origin.CanAccess(target_origin));
}

PP_Var PepperPluginInstanceImpl::GetDocumentURL(
    PP_Instance instance,
    PP_URLComponents_Dev* components) {
  blink::WebDocument document = container()->GetDocument();
  return ppapi::PPB_URLUtil_Shared::GenerateURLReturn(document.Url(),
                                                      components);
}

PP_Var PepperPluginInstanceImpl::GetPluginInstanceURL(
    PP_Instance instance,
    PP_URLComponents_Dev* components) {
  return ppapi::PPB_URLUtil_Shared::GenerateURLReturn(plugin_url_, components);
}

PP_Var PepperPluginInstanceImpl::GetPluginReferrerURL(
    PP_Instance instance,
    PP_URLComponents_Dev* components) {
  blink::WebDocument document = container()->GetDocument();
  if (!full_frame_)
    return ppapi::PPB_URLUtil_Shared::GenerateURLReturn(document.Url(),
                                                        components);
  WebLocalFrame* frame = document.GetFrame();
  if (!frame)
    return PP_MakeUndefined();
  const WebURLRequest& request = frame->GetDocumentLoader()->OriginalRequest();
  WebString referer = request.HttpHeaderField("Referer");
  if (referer.IsEmpty())
    return PP_MakeUndefined();
  return ppapi::PPB_URLUtil_Shared::GenerateURLReturn(
      blink::WebStringToGURL(referer), components);
}

PP_ExternalPluginResult PepperPluginInstanceImpl::ResetAsProxied(
    scoped_refptr<PluginModule> module) {
  // Save the original module and switch over to the new one now that this
  // plugin is using the IPC-based proxy.
  original_module_ = module_;
  module_ = module;

  // For NaCl instances, remember the NaCl plugin instance interface, so we
  // can shut it down by calling its DidDestroy in our Delete() method.
  original_instance_interface_ = std::move(instance_interface_);

  base::Callback<const void*(const char*)> get_plugin_interface_func =
      base::Bind(&PluginModule::GetPluginInterface, module_);
  PPP_Instance_Combined* ppp_instance_combined =
      PPP_Instance_Combined::Create(std::move(get_plugin_interface_func));
  if (!ppp_instance_combined) {
    // The proxy must support at least one usable PPP_Instance interface.
    // While this could be a failure to implement the interface in the NaCl
    // module, it is more likely that the NaCl process has crashed. Either
    // way, report that module initialization failed.
    return PP_EXTERNAL_PLUGIN_ERROR_MODULE;
  }

  instance_interface_.reset(ppp_instance_combined);
  // Clear all PPP interfaces we may have cached.
  plugin_find_interface_ = nullptr;
  plugin_input_event_interface_ = nullptr;
  checked_for_plugin_input_event_interface_ = false;
  plugin_mouse_lock_interface_ = nullptr;
  plugin_pdf_interface_ = nullptr;
  checked_for_plugin_pdf_interface_ = false;
  plugin_private_interface_ = nullptr;
  plugin_textinput_interface_ = nullptr;

  // Re-send the DidCreate event via the proxy.
  std::unique_ptr<const char* []> argn_array(StringVectorToArgArray(argn_));
  std::unique_ptr<const char* []> argv_array(StringVectorToArgArray(argv_));
  if (!instance_interface_->DidCreate(
          pp_instance(), argn_.size(), argn_array.get(), argv_array.get()))
    return PP_EXTERNAL_PLUGIN_ERROR_INSTANCE;
  if (message_channel_)
    message_channel_->Start();

  // Clear sent_initial_did_change_view_ and cancel any pending DidChangeView
  // event. This way, SendDidChangeView will send the "current" view
  // immediately (before other events like HandleDocumentLoad).
  sent_initial_did_change_view_ = false;
  view_change_weak_ptr_factory_.InvalidateWeakPtrs();
  SendDidChangeView();

  DCHECK(external_document_load_);
  external_document_load_ = false;
  if (!external_document_response_.IsNull()) {
    document_loader_ = nullptr;
    // Pass the response to the new proxy.
    HandleDocumentLoad(external_document_response_);
    external_document_response_ = blink::WebURLResponse();
    // Replay any document load events we've received to the real loader.
    external_document_loader_->ReplayReceivedData(document_loader_);
    external_document_loader_.reset();
  }

  return PP_EXTERNAL_PLUGIN_OK;
}

bool PepperPluginInstanceImpl::IsValidInstanceOf(PluginModule* module) {
  DCHECK(module);
  return module == module_.get() || module == original_module_.get();
}

RenderFrame* PepperPluginInstanceImpl::GetRenderFrame() {
  return render_frame_;
}

blink::WebPluginContainer* PepperPluginInstanceImpl::GetContainer() {
  return container_;
}

v8::Isolate* PepperPluginInstanceImpl::GetIsolate() const { return isolate_; }

ppapi::VarTracker* PepperPluginInstanceImpl::GetVarTracker() {
  return HostGlobals::Get()->GetVarTracker();
}

const GURL& PepperPluginInstanceImpl::GetPluginURL() { return plugin_url_; }

base::FilePath PepperPluginInstanceImpl::GetModulePath() {
  return module_->path();
}

PP_Resource PepperPluginInstanceImpl::CreateImage(gfx::ImageSkia* source_image,
                                                  float scale) {
  gfx::ImageSkiaRep image_skia_rep = source_image->GetRepresentation(scale);

  if (image_skia_rep.is_null() || image_skia_rep.scale() != scale)
    return 0;

  scoped_refptr<PPB_ImageData_Impl> image_data(
      new PPB_ImageData_Impl(pp_instance(), PPB_ImageData_Impl::PLATFORM));
  if (!image_data->Init(PPB_ImageData_Impl::GetNativeImageDataFormat(),
                        image_skia_rep.pixel_width(),
                        image_skia_rep.pixel_height(),
                        false)) {
    return 0;
  }

  ImageDataAutoMapper mapper(image_data.get());
  if (!mapper.is_valid())
    return 0;

  SkCanvas* canvas = image_data->GetCanvas();
  // Note: Do not SkBitmap::copyTo the canvas bitmap directly because it will
  // ignore the allocated pixels in shared memory and re-allocate a new buffer.
  canvas->writePixels(image_skia_rep.sk_bitmap(), 0, 0);

  return image_data->GetReference();
}

PP_ExternalPluginResult PepperPluginInstanceImpl::SwitchToOutOfProcessProxy(
    const base::FilePath& file_path,
    ppapi::PpapiPermissions permissions,
    const IPC::ChannelHandle& channel_handle,
    base::ProcessId plugin_pid,
    int plugin_child_id) {
  // Create a new module for each instance of the external plugin that is using
  // the IPC based out-of-process proxy. We can't use the existing module,
  // because it is configured for the in-process plugin, and we must keep it
  // that way to allow the page to create other instances.
  scoped_refptr<PluginModule> external_plugin_module(
      module_->CreateModuleForExternalPluginInstance());

  RendererPpapiHostImpl* renderer_ppapi_host =
      external_plugin_module->CreateOutOfProcessModule(render_frame_,
                                                       file_path,
                                                       permissions,
                                                       channel_handle,
                                                       plugin_pid,
                                                       plugin_child_id,
                                                       true);
  if (!renderer_ppapi_host) {
    DLOG(ERROR) << "CreateExternalPluginModule() failed";
    return PP_EXTERNAL_PLUGIN_ERROR_MODULE;
  }

  // Finally, switch the instance to the proxy.
  return external_plugin_module->InitAsProxiedExternalPlugin(this);
}

void PepperPluginInstanceImpl::SetAlwaysOnTop(bool on_top) {
  always_on_top_ = on_top;
}

void PepperPluginInstanceImpl::DoSetCursor(
    std::unique_ptr<WebCursorInfo> cursor) {
  cursor_ = std::move(cursor);
  if (fullscreen_container_)
    fullscreen_container_->PepperDidChangeCursor(*cursor_);
  else if (render_frame_)
    render_frame_->PepperDidChangeCursor(this, *cursor_);
}

bool PepperPluginInstanceImpl::IsFullPagePlugin() {
  WebLocalFrame* frame = container()->GetDocument().GetFrame();
  return frame->View()->MainFrame()->IsWebLocalFrame() &&
         frame->View()
             ->MainFrame()
             ->ToWebLocalFrame()
             ->GetDocument()
             .IsPluginDocument();
}

bool PepperPluginInstanceImpl::FlashSetFullscreen(bool fullscreen,
                                                  bool delay_report) {
  TRACE_EVENT0("ppapi", "PepperPluginInstanceImpl::FlashSetFullscreen");
  // Keep a reference on the stack. See NOTE above.
  scoped_refptr<PepperPluginInstanceImpl> ref(this);

  // We check whether we are trying to switch to the state we're already going
  // to (i.e. if we're already switching to fullscreen but the fullscreen
  // container isn't ready yet, don't do anything more).
  if (fullscreen == FlashIsFullscreenOrPending())
    return true;

  if (!SetFullscreenCommon(fullscreen))
    return false;

  // Unbind current 2D or 3D graphics context.
  DVLOG(1) << "Setting fullscreen to " << (fullscreen ? "on" : "off");
  if (fullscreen) {
    DCHECK(!fullscreen_container_);
    fullscreen_container_ =
        render_frame_->CreatePepperFullscreenContainer(this);
    UpdateLayer(false);
  } else {
    DCHECK(fullscreen_container_);
    fullscreen_container_->Destroy();
    fullscreen_container_ = nullptr;
    UpdateFlashFullscreenState(false);
    if (!delay_report) {
      ReportGeometry();
    } else {
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE,
          base::BindOnce(&PepperPluginInstanceImpl::ReportGeometry, this));
    }
  }

  return true;
}

bool PepperPluginInstanceImpl::IsRectTopmost(const gfx::Rect& rect) {
  if (flash_fullscreen_)
    return true;

  return container_->IsRectTopmost(rect);
}

int32_t PepperPluginInstanceImpl::Navigate(
    const ppapi::URLRequestInfoData& request,
    const char* target,
    bool from_user_action) {
  if (!container_)
    return PP_ERROR_FAILED;

  WebDocument document = container_->GetDocument();
  WebLocalFrame* frame = document.GetFrame();
  if (!frame)
    return PP_ERROR_FAILED;

  ppapi::URLRequestInfoData completed_request = request;

  WebURLRequest web_request;
  if (!CreateWebURLRequest(
          pp_instance_, &completed_request, frame, &web_request)) {
    return PP_ERROR_FAILED;
  }
  web_request.SetSiteForCookies(document.SiteForCookies());
  if (IsProcessingUserGesture())
    web_request.SetHasUserGesture(true);

  GURL gurl(web_request.Url());
  if (gurl.SchemeIs(url::kJavaScriptScheme)) {
    // In imitation of the NPAPI implementation, only |target_frame == frame| is
    // allowed for security reasons.
    WebFrame* target_frame =
        frame->FindFrameByName(WebString::FromUTF8(target));
    if (target_frame != frame)
      return PP_ERROR_NOACCESS;

    // TODO(viettrungluu): NPAPI sends the result back to the plugin -- do we
    // need that?
    blink::WebScopedUserGesture user_gesture(CurrentUserGestureToken());
    WebString result = container_->ExecuteScriptURL(gurl, false);
    return result.IsNull() ? PP_ERROR_FAILED : PP_OK;
  }

  // Only GETs and POSTs are supported.
  if (web_request.HttpMethod() != "GET" && web_request.HttpMethod() != "POST")
    return PP_ERROR_BADARGUMENT;

  WebString target_str = WebString::FromUTF8(target);
  blink::WebScopedUserGesture user_gesture(CurrentUserGestureToken());
  container_->LoadFrameRequest(web_request, target_str);
  return PP_OK;
}

int PepperPluginInstanceImpl::MakePendingFileRefRendererHost(
    const base::FilePath& path) {
  RendererPpapiHostImpl* host_impl = module_->renderer_ppapi_host();
  PepperFileRefRendererHost* file_ref_host(
      new PepperFileRefRendererHost(host_impl, pp_instance(), 0, path));
  return host_impl->GetPpapiHost()->AddPendingResourceHost(
      std::unique_ptr<ppapi::host::ResourceHost>(file_ref_host));
}

void PepperPluginInstanceImpl::SetEmbedProperty(PP_Var key, PP_Var value) {
  if (message_channel_)
    message_channel_->SetReadOnlyProperty(key, value);
}

bool PepperPluginInstanceImpl::CanAccessMainFrame() const {
  if (!container_)
    return false;
  blink::WebDocument containing_document = container_->GetDocument();

  if (!containing_document.GetFrame() ||
      !containing_document.GetFrame()->View() ||
      !containing_document.GetFrame()->View()->MainFrame()) {
    return false;
  }
  blink::WebFrame* main_frame =
      containing_document.GetFrame()->View()->MainFrame();

  return containing_document.GetSecurityOrigin().CanAccess(
      main_frame->GetSecurityOrigin());
}

void PepperPluginInstanceImpl::KeepSizeAttributesBeforeFullscreen() {
  WebElement element = container_->GetElement();
  width_before_fullscreen_ = element.GetAttribute(WebString::FromUTF8(kWidth));
  height_before_fullscreen_ =
      element.GetAttribute(WebString::FromUTF8(kHeight));
  border_before_fullscreen_ =
      element.GetAttribute(WebString::FromUTF8(kBorder));
  style_before_fullscreen_ = element.GetAttribute(WebString::FromUTF8(kStyle));
}

void PepperPluginInstanceImpl::SetSizeAttributesForFullscreen() {
  if (!render_frame_)
    return;

  // TODO(miu): Revisit this logic.  If the style must be modified for correct
  // behavior, the width and height should probably be set to 100%, rather than
  // a fixed screen size.

  blink::WebScreenInfo info = render_frame_->GetRenderWidget()->GetScreenInfo();
  screen_size_for_fullscreen_ = gfx::Size(info.rect.width, info.rect.height);
  std::string width = base::IntToString(screen_size_for_fullscreen_.width());
  std::string height = base::IntToString(screen_size_for_fullscreen_.height());

  WebElement element = container_->GetElement();
  element.SetAttribute(WebString::FromUTF8(kWidth), WebString::FromUTF8(width));
  element.SetAttribute(WebString::FromUTF8(kHeight),
                       WebString::FromUTF8(height));
  element.SetAttribute(WebString::FromUTF8(kBorder), WebString::FromUTF8("0"));

  // There should be no style settings that matter in fullscreen mode,
  // so just replace them instead of appending.
  // NOTE: "position: fixed" and "display: block" reset the plugin and
  // using %% settings might not work without them (e.g. if the plugin is a
  // child of a container element).
  std::string style;
  style += StringPrintf("width: %s !important; ", width.c_str());
  style += StringPrintf("height: %s !important; ", height.c_str());
  style += "margin: 0 !important; padding: 0 !important; border: 0 !important";
  container_->GetElement().SetAttribute(kStyle, WebString::FromUTF8(style));
}

void PepperPluginInstanceImpl::ResetSizeAttributesAfterFullscreen() {
  screen_size_for_fullscreen_ = gfx::Size();
  WebElement element = container_->GetElement();
  element.SetAttribute(WebString::FromUTF8(kWidth), width_before_fullscreen_);
  element.SetAttribute(WebString::FromUTF8(kHeight), height_before_fullscreen_);
  element.SetAttribute(WebString::FromUTF8(kBorder), border_before_fullscreen_);
  element.SetAttribute(WebString::FromUTF8(kStyle), style_before_fullscreen_);
}

bool PepperPluginInstanceImpl::SetFullscreenCommon(bool fullscreen) const {
  if (!render_frame_)
    return false;

  if (fullscreen) {
    if (!render_frame_->render_view()
             ->renderer_preferences()
             .plugin_fullscreen_allowed) {
      return false;
    }

    if (!IsProcessingUserGesture())
      return false;
  }
  return true;
}

bool PepperPluginInstanceImpl::IsMouseLocked() {
  return GetMouseLockDispatcher()->IsMouseLockedTo(
      GetOrCreateLockTargetAdapter());
}

bool PepperPluginInstanceImpl::LockMouse() {
  return GetMouseLockDispatcher()->LockMouse(GetOrCreateLockTargetAdapter());
}

MouseLockDispatcher::LockTarget*
PepperPluginInstanceImpl::GetOrCreateLockTargetAdapter() {
  if (!lock_target_)
    lock_target_ = std::make_unique<PluginInstanceLockTarget>(this);
  return lock_target_.get();
}

MouseLockDispatcher* PepperPluginInstanceImpl::GetMouseLockDispatcher() {
  if (flash_fullscreen_) {
    RenderWidgetFullscreenPepper* container =
        static_cast<RenderWidgetFullscreenPepper*>(fullscreen_container_);
    return container->mouse_lock_dispatcher();
  }
  if (render_frame_)
    return render_frame_->render_view()->mouse_lock_dispatcher();
  return nullptr;
}

void PepperPluginInstanceImpl::UnSetAndDeleteLockTargetAdapter() {
  if (lock_target_) {
    GetMouseLockDispatcher()->OnLockTargetDestroyed(lock_target_.get());
    lock_target_.reset();
  }
}

void PepperPluginInstanceImpl::DidDataFromWebURLResponse(
    const blink::WebURLResponse& response,
    int pending_host_id,
    const ppapi::URLResponseInfoData& data) {
  if (is_deleted_)
    return;

  RendererPpapiHostImpl* host_impl = module_->renderer_ppapi_host();

  if (host_impl->in_process_router()) {
    // Running in-process, we can just create the resource and call the
    // PPP_Instance function directly.
    scoped_refptr<ppapi::proxy::URLLoaderResource> loader_resource(
        new ppapi::proxy::URLLoaderResource(
            host_impl->in_process_router()->GetPluginConnection(pp_instance()),
            pp_instance(),
            pending_host_id,
            data));

    PP_Resource loader_pp_resource = loader_resource->GetReference();
    if (!instance_interface_->HandleDocumentLoad(pp_instance(),
                                                 loader_pp_resource))
      loader_resource->Close();
    // We don't pass a ref into the plugin, if it wants one, it will have taken
    // an additional one.
    ppapi::PpapiGlobals::Get()->GetResourceTracker()->ReleaseResource(
        loader_pp_resource);
  } else {
    // Running out-of-process. Initiate an IPC call to notify the plugin
    // process.
    ppapi::proxy::HostDispatcher* dispatcher =
        ppapi::proxy::HostDispatcher::GetForInstance(pp_instance());
    dispatcher->Send(new PpapiMsg_PPPInstance_HandleDocumentLoad(
        ppapi::API_ID_PPP_INSTANCE, pp_instance(), pending_host_id, data));
  }
}

void PepperPluginInstanceImpl::ConvertRectToDIP(PP_Rect* rect) const {
  rect->point.x *= viewport_to_dip_scale_;
  rect->point.y *= viewport_to_dip_scale_;
  rect->size.width *= viewport_to_dip_scale_;
  rect->size.height *= viewport_to_dip_scale_;
}

void PepperPluginInstanceImpl::ConvertDIPToViewport(gfx::Rect* rect) const {
  rect->set_x(rect->x() / viewport_to_dip_scale_);
  rect->set_y(rect->y() / viewport_to_dip_scale_);
  rect->set_width(rect->width() / viewport_to_dip_scale_);
  rect->set_height(rect->height() / viewport_to_dip_scale_);
}

void PepperPluginInstanceImpl::IncrementTextureReferenceCount(
    const viz::TransferableResource& resource) {
  auto it =
      std::find_if(texture_ref_counts_.begin(), texture_ref_counts_.end(),
                   [&resource](const MailboxRefCount& ref_count) {
                     return ref_count.first == resource.mailbox_holder.mailbox;
                   });
  if (it == texture_ref_counts_.end()) {
    texture_ref_counts_.emplace_back(resource.mailbox_holder.mailbox, 1);
    return;
  }

  it->second++;
}

bool PepperPluginInstanceImpl::DecrementTextureReferenceCount(
    const viz::TransferableResource& resource) {
  auto it =
      std::find_if(texture_ref_counts_.begin(), texture_ref_counts_.end(),
                   [&resource](const MailboxRefCount& ref_count) {
                     return ref_count.first == resource.mailbox_holder.mailbox;
                   });
  DCHECK(it != texture_ref_counts_.end());

  if (it->second == 1) {
    texture_ref_counts_.erase(it);
    return true;
  }

  it->second--;
  return false;
}

bool PepperPluginInstanceImpl::IsTextureInUse(
    const viz::TransferableResource& resource) const {
  auto it =
      std::find_if(texture_ref_counts_.begin(), texture_ref_counts_.end(),
                   [&resource](const MailboxRefCount& ref_count) {
                     return ref_count.first == resource.mailbox_holder.mailbox;
                   });
  return it != texture_ref_counts_.end();
}

}  // namespace content

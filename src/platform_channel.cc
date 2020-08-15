#include "platform_channel.h"

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>

#include <sys/socket.h>
#include <sys/un.h>

#include "macros.h"

namespace flutter {

PlatformChannel::PlatformChannel() {
  static constexpr char kAccessibilityChannel[] = "flutter/accessibility";
  static constexpr char kFlutterPlatformChannel[] = "flutter/platform";
  static constexpr char kTextInputChannel[] = "flutter/textinput";
  static constexpr char kKeyEventChannel[] = "flutter/keyevent";
  static constexpr char kFlutterPlatformViewsChannel[] =
      "flutter/platform_views";

  static constexpr char kPluginFlutterIoConnectivity[] =
      "plugins.flutter.io/connectivity";
  static constexpr char kPluginFlutterIoConnectivityStatus[] =
      "plugins.flutter.io/connectivity_status";
  static constexpr char kPluginFlutterIoUrlLauncher[] =
      "plugins.flutter.io/url_launcher";
  static constexpr char kPluginFlutterIoVideoPlayer[] =
      "flutter.io/videoPlayer";
  static constexpr char kPluginFlutterIoVideoPlayerEvents[] =
      "flutter.io/videoPlayer/videoEventsnull";

  static constexpr char kPluginFlutterQtMapboxGLEvents[] =
      "com.mapbox/mapboxgl.qt";

  platform_message_handlers_[kAccessibilityChannel] =
      std::bind(&PlatformChannel::OnAccessibilityChannelPlatformMessage, this,
                std::placeholders::_1);
  platform_message_handlers_[kFlutterPlatformChannel] =
      std::bind(&PlatformChannel::OnFlutterPlatformChannelPlatformMessage, this,
                std::placeholders::_1);
  platform_message_handlers_[kTextInputChannel] =
      std::bind(&PlatformChannel::OnFlutterTextInputChannelPlatformMessage,
                this, std::placeholders::_1);
  platform_message_handlers_[kFlutterPlatformViewsChannel] =
      std::bind(&PlatformChannel::OnFlutterPlatformViewsChannelPlatformMessage,
                this, std::placeholders::_1);
  platform_message_handlers_[kPluginFlutterIoConnectivity] =
      std::bind(&PlatformChannel::OnFlutterPluginConnectivity, this,
                std::placeholders::_1);
  platform_message_handlers_[kPluginFlutterIoConnectivityStatus] =
      std::bind(&PlatformChannel::OnFlutterPluginConnectivityStatus, this,
                std::placeholders::_1);
  platform_message_handlers_[kPluginFlutterIoUrlLauncher] =
      std::bind(&PlatformChannel::OnFlutterPluginIoUrlLauncher, this,
                std::placeholders::_1);
  platform_message_handlers_[kPluginFlutterIoVideoPlayer] =
      std::bind(&PlatformChannel::OnFlutterPluginIoVideoPlayer, this,
                std::placeholders::_1);
  platform_message_handlers_[kPluginFlutterIoVideoPlayerEvents] =
      std::bind(&PlatformChannel::OnFlutterPluginIoVideoPlayerEvents, this,
                std::placeholders::_1);

  platform_message_handlers_[kPluginFlutterQtMapboxGLEvents] =
      std::bind(&PlatformChannel::OnFlutterQtMapboxGLEvents, this,
                std::placeholders::_1);
  
  server_thread_ = std::make_unique<std::thread>(&PlatformChannel::ServerThread, this);

}

PlatformChannel::~PlatformChannel() {
  server_thread_->join();
}

void PlatformChannel::ServerThread(void) {

  static constexpr char kUnixSocketPath[] = "/tmp/flutter_mapbox_demo.unixsocket";

  int ret_code = 0;

  int fd_accept = -1;
  ssize_t size = 0;
  int flags = 0;

  int response = -1;

  FLWAY_LOG << "ServerThread Start..." << std::endl;

  remove(kUnixSocketPath);

  struct sockaddr_un sun, sun_client;
  memset(&sun, 0, sizeof(sun));
  memset(&sun_client, 0, sizeof(sun_client));

  socklen_t socklen = sizeof(sun_client);

  fd_accept = socket(AF_LOCAL, SOCK_STREAM, 0);
  if (fd_accept == -1) {
    FLWAY_ERROR << "socket create faild." << std::endl;
    return;
  }

  sun.sun_family = AF_LOCAL;
  strcpy(sun.sun_path, kUnixSocketPath);

  ret_code = bind(fd_accept, (const struct sockaddr *)&sun, sizeof(sun));
  if (ret_code == -1) {
    FLWAY_ERROR << "socket bind faild." << std::endl;
    close(fd_accept);
    return;
  }

  ret_code = listen(fd_accept, 10);
  if (ret_code == -1) {
    FLWAY_ERROR << "socket listen faild." << std::endl;
    close(fd_accept);
    return;
  }
  
  FLWAY_LOG << "accecpt waiting..." << std::endl;
  socket_fd_ = accept(fd_accept, (struct sockaddr *)&sun_client, &socklen);
  if (socket_fd_ == -1) {
      FLWAY_ERROR << "socket accept faild." << std::endl;
      return;
  }
  FLWAY_LOG << "connect done." << std::endl;

  while(1) {
    uint32_t buf_len = 0;
    size = read(socket_fd_, &buf_len, sizeof(buf_len));
    if(size < sizeof(buf_len)) {
      FLWAY_ERROR << "socket header read error." << std::endl;
      break;
    }

    uint8_t* buf = reinterpret_cast<uint8_t*>(malloc(buf_len));
    if(buf == NULL) {
      FLWAY_ERROR << "socket body allocate error." << std::endl;
      break;
    }
    size = read(socket_fd_, buf, buf_len);
    if(size < buf_len) {
      FLWAY_ERROR << "socket body read error." << std::endl;
      free(buf);
      break;
    }

    free(buf);

    FLWAY_LOG << "recv data:" << buf << std::endl;
  }

  close(socket_fd_);
  socket_fd_ = -1;

  return;
}

void PlatformChannel::SetEngine(FlutterEngine engine) {
  engine_ = engine;
}

void PlatformChannel::PlatformMessageCallback(
    const FlutterPlatformMessage* message) {
  // Find the handler for the channel; if there isn't one, report the failure.
  if (platform_message_handlers_.find(message->channel) ==
      platform_message_handlers_.end()) {
    FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                             nullptr, 0);
    return;
  }

  auto& message_handler = platform_message_handlers_[message->channel];

  message_handler(message);
}

void PlatformChannel::OnAccessibilityChannelPlatformMessage(
    const FlutterPlatformMessage* message) {
  std::string msg;
  msg.assign(reinterpret_cast<const char*>(message->message),
             message->message_size);
  FLWAY_LOG << "AccessibilityChannel: " << msg << std::endl;
}

void PlatformChannel::OnFlutterPlatformChannelPlatformMessage(
    const FlutterPlatformMessage* message) {
  rapidjson::Document document;
  document.Parse(reinterpret_cast<const char*>(message->message),
                 message->message_size);
  if (document.HasParseError() || !document.IsObject()) {
    return;
  }

  auto root = document.GetObject();
  auto method = root.FindMember("method");
  if (method == root.MemberEnd() || !method->value.IsString()) {
    return;
  }

  std::string msg;
  msg.assign(reinterpret_cast<const char*>(message->message),
             message->message_size);
  FLWAY_LOG << "PlatformChannel: " << method->value.GetString() << std::endl;

#if 0
  static constexpr char kSetApplicationSwitcherDescription[] = "SystemChrome.setApplicationSwitcherDescription";
  static constexpr char kSetSystemUiOverlayStyle[] = "SystemChrome.setSystemUIOverlayStyle";
  static constexpr char kSystemNavigatorPopMethod[] = "SystemNavigator.pop";
  static constexpr char kGetClipboardDataMethod[] = "Clipboard.getData";
  static constexpr char kSetClipboardDataMethod[] = "Clipboard.setData";
  static constexpr char kSystemSoundPlay[] = "SystemSound.play";
  static constexpr char kTextPlainFormat[] = "text/plain";
  static constexpr char kTextKey[] = "text";
#endif

  FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                           nullptr, 0);
}

void PlatformChannel::OnFlutterTextInputChannelPlatformMessage(
    const FlutterPlatformMessage* message) {
  rapidjson::Document document;
  document.Parse(reinterpret_cast<const char*>(message->message),
                 message->message_size);
  if (document.HasParseError() || !document.IsObject()) {
    return;
  }
  auto root = document.GetObject();
  auto method = root.FindMember("method");
  if (method == root.MemberEnd() || !method->value.IsString()) {
    return;
  }

  std::string msg;
  msg.assign(reinterpret_cast<const char*>(message->message),
             message->message_size);
  FLWAY_LOG << "TextInput: " << method->value.GetString() << std::endl;

#if 0
  if (method->value == "TextInput.show") {
    if (ime_) {
      text_sync_service_->ShowKeyboard();
    }
  } else if (method->value == "TextInput.hide") {
    if (ime_) {
      text_sync_service_->HideKeyboard();
    }
  } else 

  if (method->value == "TextInput.setClient") {
    current_text_input_client_ = 0;
    DeactivateIme();
    auto args = root.FindMember("args");
    if (args == root.MemberEnd() || !args->value.IsArray() ||
        args->value.Size() != 2)
      return;
    const auto& configuration = args->value[1];
    if (!configuration.IsObject()) {
      return;
    }
    // TODO(abarth): Read the keyboard type from the configuration.
    current_text_input_client_ = args->value[0].GetInt();

    auto initial_text_input_state = fuchsia::ui::input::TextInputState{};
    initial_text_input_state.text = "";
    last_text_state_ = std::make_unique<fuchsia::ui::input::TextInputState>(
        initial_text_input_state);
    ActivateIme();
  } else if (method->value == "TextInput.setEditingState") {
    if (ime_) {
      auto args_it = root.FindMember("args");
      if (args_it == root.MemberEnd() || !args_it->value.IsObject()) {
        return;
      }
      const auto& args = args_it->value;
      fuchsia::ui::input::TextInputState state;
      state.text = "";
      // TODO(abarth): Deserialize state.
      auto text = args.FindMember("text");
      if (text != args.MemberEnd() && text->value.IsString())
        state.text = text->value.GetString();
      auto selection_base = args.FindMember("selectionBase");
      if (selection_base != args.MemberEnd() && selection_base->value.IsInt())
        state.selection.base = selection_base->value.GetInt();
      auto selection_extent = args.FindMember("selectionExtent");
      if (selection_extent != args.MemberEnd() &&
          selection_extent->value.IsInt())
        state.selection.extent = selection_extent->value.GetInt();
      auto selection_affinity = args.FindMember("selectionAffinity");
      if (selection_affinity != args.MemberEnd() &&
          selection_affinity->value.IsString() &&
          selection_affinity->value == "TextAffinity.upstream")
        state.selection.affinity = fuchsia::ui::input::TextAffinity::UPSTREAM;
      else
        state.selection.affinity = fuchsia::ui::input::TextAffinity::DOWNSTREAM;
      // We ignore selectionIsDirectional because that concept doesn't exist on
      // Fuchsia.
      auto composing_base = args.FindMember("composingBase");
      if (composing_base != args.MemberEnd() && composing_base->value.IsInt())
        state.composing.start = composing_base->value.GetInt();
      auto composing_extent = args.FindMember("composingExtent");
      if (composing_extent != args.MemberEnd() &&
          composing_extent->value.IsInt())
        state.composing.end = composing_extent->value.GetInt();
      ime_->SetState(std::move(state));
    }
  } else if (method->value == "TextInput.clearClient") {
    current_text_input_client_ = 0;
    last_text_state_ = nullptr;
    DeactivateIme();
  } else {
    FLWAY_ERROR << "Unknown " << message->channel << " method "
                    << method->value.GetString();
  }
#endif
}

void PlatformChannel::OnFlutterPlatformViewsChannelPlatformMessage(
    const FlutterPlatformMessage* message) {
  rapidjson::Document document;
  document.Parse(reinterpret_cast<const char*>(message->message),
                 message->message_size);
  if (document.HasParseError() || !document.IsObject()) {
    FLWAY_ERROR << "Could not parse document";
    return;
  }
  auto root = document.GetObject();
  auto method = root.FindMember("method");
  if (method == root.MemberEnd() || !method->value.IsString()) {
    return;
  }

  std::string msg;
  msg.assign(reinterpret_cast<const char*>(message->message),
             message->message_size);
  FLWAY_LOG << "PlatformViews: " << method->value.GetString() << std::endl;

  if (method->value == "View.enableWireframe") {
    auto args_it = root.FindMember("args");
    if (args_it == root.MemberEnd() || !args_it->value.IsObject()) {
      FLWAY_ERROR << "No arguments found.";
      return;
    }
    const auto& args = args_it->value;

    auto enable = args.FindMember("enable");
    if (!enable->value.IsBool()) {
      FLWAY_ERROR << "Argument 'enable' is not a bool";
      return;
    }

    FLWAY_LOG << "wireframe_enabled_callback goes here" << std::endl;
  } else {
    FLWAY_ERROR << "Unknown " << message->channel << " method "
                << method->value.GetString();
  }
}

void PlatformChannel::OnFlutterPluginIoUrlLauncher(
    const FlutterPlatformMessage* message) {
  std::unique_ptr<std::vector<std::uint8_t>> result;
  auto codec = &flutter::StandardMethodCodec::GetInstance();
  auto method_call =
      codec->DecodeMethodCall(message->message, message->message_size);

  if (method_call->method_name().compare("launch") == 0) {
    std::string url;
    if (method_call->arguments() && method_call->arguments()->IsMap()) {
      const EncodableMap& arguments = method_call->arguments()->MapValue();
      auto url_it = arguments.find(EncodableValue("url"));
      if (url_it != arguments.end()) {
        url = url_it->second.StringValue();
      }
    }
    if (url.empty()) {
      auto result =
          codec->EncodeErrorEnvelope("argument_error", "No URL provided");
      goto done;
    }

    pid_t pid = fork();
    if (pid == 0) {
      execl("/usr/bin/xdg-open", "xdg-open", url.c_str(), nullptr);
      exit(1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (status != 0) {
      std::ostringstream error_message;
      error_message << "Failed to open " << url << ": error " << status;
      result = codec->EncodeErrorEnvelope("open_error", error_message.str());
      goto done;
    }
    auto val = EncodableValue(true);
    result = codec->EncodeSuccessEnvelope(&val);

  } else if (method_call->method_name().compare("canLaunch") == 0) {
    std::string url;
    if (method_call->arguments() && method_call->arguments()->IsMap()) {
      const EncodableMap& arguments = method_call->arguments()->MapValue();
      auto url_it = arguments.find(EncodableValue("url"));
      if (url_it != arguments.end()) {
        url = url_it->second.StringValue();
      }
    }
    if (url.empty()) {
      result = codec->EncodeErrorEnvelope("argument_error", "No URL provided");
      goto done;
    }
    flutter::EncodableValue response(
        (url.rfind("https:", 0) == 0) || (url.rfind("http:", 0) == 0) ||
        (url.rfind("ftp:", 0) == 0) || (url.rfind("file:", 0) == 0));
    result = codec->EncodeSuccessEnvelope(&response);
  }
done:
  FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                           result->data(), result->size());
}

void PlatformChannel::OnFlutterPluginIoVideoPlayerEvents(
    const FlutterPlatformMessage* message) {
  std::unique_ptr<std::vector<std::uint8_t>> result;
  auto codec = &flutter::StandardMethodCodec::GetInstance();
  auto method_call =
      codec->DecodeMethodCall(message->message, message->message_size);
  FLWAY_LOG << "VideoPlayerEvents: " << method_call->method_name() << std::endl;

  if (method_call->method_name().compare("listen") == 0) {
  } else if (method_call->method_name().compare("cancel") == 0) {
  }

  flutter::EncodableValue val(true);
  result = codec->EncodeSuccessEnvelope(&val);
  FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                           result->data(), result->size());
}

void PlatformChannel::OnFlutterPluginIoVideoPlayer(
    const FlutterPlatformMessage* message) {
  std::unique_ptr<std::vector<std::uint8_t>> result;
  auto codec = &flutter::StandardMethodCodec::GetInstance();
  auto method_call =
      codec->DecodeMethodCall(message->message, message->message_size);
  FLWAY_LOG << "VideoPlayer: " << method_call->method_name() << std::endl;

  if (method_call->method_name().compare("init") == 0) {
    FLWAY_LOG << "Initialize Video Player here..." << std::endl;
    flutter::EncodableValue val(true);
    result = codec->EncodeSuccessEnvelope(&val);
    FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                             result->data(), result->size());
    return;
  } else if (method_call->method_name().compare("create") == 0) {
    EncodableMap args = method_call->arguments()->MapValue();
    std::stringstream ss;
    ss << "\n";
    for (auto it = args.cbegin(); it != args.cend(); ++it) {
      ss << "\t" << it->first.StringValue() << " : ["
         << (it->second.IsNull() ? "" : it->second.StringValue()) << "]\n";
    }
    FLWAY_LOG << ss.str() << std::endl;
    EncodableValue val(args);
    result = codec->EncodeSuccessEnvelope(&val);
    FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                             result->data(), result->size());
    return;
  } else if (method_call->method_name().compare("dispose") == 0) {
    FLWAY_LOG << "Terminate Video Player here..." << std::endl;
    flutter::EncodableValue val(true);
    result = codec->EncodeSuccessEnvelope(&val);
    FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                             result->data(), result->size());
    return;
  }

  flutter::EncodableValue val(false);
  result = codec->EncodeSuccessEnvelope(&val);
  FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                           result->data(), result->size());
}

void PlatformChannel::OnFlutterPluginConnectivityStatus(
    const FlutterPlatformMessage* message) {
  std::unique_ptr<std::vector<std::uint8_t>> result;
  auto codec = &flutter::StandardMethodCodec::GetInstance();
  auto method_call =
      codec->DecodeMethodCall(message->message, message->message_size);
  FLWAY_LOG << "ConnectivityStatus: " << method_call->method_name()
            << std::endl;

  flutter::EncodableValue val(true);
  result = codec->EncodeSuccessEnvelope(&val);
  FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                           result->data(), result->size());
}

void PlatformChannel::OnFlutterPluginConnectivity(
    const FlutterPlatformMessage* message) {
  std::unique_ptr<std::vector<std::uint8_t>> result;
  auto codec = &flutter::StandardMethodCodec::GetInstance();
  auto method_call =
      codec->DecodeMethodCall(message->message, message->message_size);

  if (method_call->method_name().compare("check") == 0) {
    flutter::EncodableValue val("wifi");
    result = codec->EncodeSuccessEnvelope(&val);
    FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                             result->data(), result->size());
    return;
#if 0
  wifi
  mobile
  none
#endif
  } else if (method_call->method_name().compare("wifiName") == 0) {
  } else if (method_call->method_name().compare("wifiBSSID") == 0) {
  } else if (method_call->method_name().compare("wifiIPAddress") == 0) {
  } else if (method_call->method_name().compare(
                 "requestLocationServiceAuthorization") == 0) {
  } else if (method_call->method_name().compare(
                 "getLocationServiceAuthorization") == 0) {
#if 0
  notDetermined
  restricted
  denied
  authorizedAlways
  authorizedWhenInUse
#endif
  }
}

void PlatformChannel::OnFlutterQtMapboxGLEvents(
    const FlutterPlatformMessage* message) {
  std::unique_ptr<std::vector<std::uint8_t>> result;
  auto codec = &flutter::StandardMethodCodec::GetInstance();
  auto method_call =
      codec->DecodeMethodCall(message->message, message->message_size);
  FLWAY_LOG << "QtMapboxGLEvents: " << method_call->method_name() << std::endl;

  if (method_call->method_name().compare("SetCurrentLocation") == 0) {
    if (method_call->arguments() && method_call->arguments()->IsMap()) {
      const EncodableMap& arguments = method_call->arguments()->MapValue();
      double lat, lon;
      auto lat_it = arguments.find(EncodableValue("lat"));
      if (lat_it != arguments.end()) {
        lat = lat_it->second.DoubleValue();
      }
      auto lon_it = arguments.find(EncodableValue("lon"));
      if (lon_it != arguments.end()) {
        lon = lon_it->second.DoubleValue();
      }
      
      rapidjson::Document document;
      auto& allocator = document.GetAllocator();
      document.SetObject();
       
      document.AddMember("method", "SetCurrentLocation", allocator);
      document.AddMember("lat", lat, allocator);
      document.AddMember("lon", lon, allocator);

      rapidjson::StringBuffer buffer;
      rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
      document.Accept(writer);
      FLWAY_LOG << buffer.GetString() << std::endl;

      uint32_t buf_len = buffer.GetSize();
      
      if( socket_fd_ != -1 ) {
        write(socket_fd_, reinterpret_cast<const void*>(&buf_len), sizeof(buf_len));
        write(socket_fd_, reinterpret_cast<const void*>(buffer.GetString()), buf_len);
      }
      else {
        FLWAY_ERROR << "can not write buffer." << std::endl;
      }
    }
  } 
 
  flutter::EncodableValue val(true);
  result = codec->EncodeSuccessEnvelope(&val);
  FlutterEngineSendPlatformMessageResponse(engine_, message->response_handle,
                                           result->data(), result->size());
}

}  // namespace flutter
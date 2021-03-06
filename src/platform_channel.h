#pragma once

#include <flutter/standard_method_codec.h>
#include <flutter_embedder.h>

#include <functional>
#include <map>

#include <thread>

namespace flutter {

class PlatformChannel {
 public:
  PlatformChannel();
  ~PlatformChannel();
  void PlatformMessageCallback(const FlutterPlatformMessage* message);
  void SetEngine(FlutterEngine engine);

 private:
  FlutterEngine engine_;
  std::map<std::string, std::function<void(const FlutterPlatformMessage*)>>
      platform_message_handlers_;

  void OnAccessibilityChannelPlatformMessage(const FlutterPlatformMessage*);
  void OnFlutterPlatformChannelPlatformMessage(const FlutterPlatformMessage*);
  void OnFlutterTextInputChannelPlatformMessage(const FlutterPlatformMessage*);
  void OnFlutterPlatformViewsChannelPlatformMessage(
      const FlutterPlatformMessage*);

  void OnFlutterPluginIoUrlLauncher(const FlutterPlatformMessage*);
  void OnFlutterPluginConnectivity(const FlutterPlatformMessage*);
  void OnFlutterPluginConnectivityStatus(const FlutterPlatformMessage*);
  void OnFlutterPluginIoVideoPlayer(const FlutterPlatformMessage*);
  void OnFlutterPluginIoVideoPlayerEvents(const FlutterPlatformMessage*);
  void OnFlutterQtMapboxGLEvents(const FlutterPlatformMessage*);

  std::unique_ptr<std::thread> server_thread_;
  void ServerThread(void);

  int socket_fd_ = -1;
};

}  // namespace flutter
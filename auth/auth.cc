#include "auth/auth.h"
#include <ctime>
#include <string>
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "extensions/common/wasm/base64.h"
#include "extensions/common/wasm/json_util.h"

using ::nlohmann::json;
using ::Wasm::Common::JsonArrayIterate;
using ::Wasm::Common::JsonGetField;
using ::Wasm::Common::JsonObjectIterate;
using ::Wasm::Common::JsonValueAs;

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace basic_auth {

PROXY_WASM_NULL_PLUGIN_REGISTRY

#endif

static RegisterContextFactory register_BasicAuth(
    CONTEXT_FACTORY(PluginContext), ROOT_FACTORY(PluginRootContext));

namespace {

//基本验证失败没有找到请求头
void deniedNoBasicAuthData(const std::string& realm) {
  sendLocalResponse(
      401,
      "Request denied by Basic Auth check. No Basic "
      "Authentication information found.",
      "", {{"WWW-Authenticate", absl::StrCat("Basic realm=", realm)}});
}

//响应大小
void responseSizeToLarge(const std::string& realm) {
  sendLocalResponse(
      431,
      "Response content-length to large.",
      "", {{"WWW-Authenticate", absl::StrCat("Basic realm=", realm)}});
}

//用户名校验失败
void deniedInvalidCredentials(const std::string& realm) {
  sendLocalResponse(
      401,
      "Request denied by Basic Auth check. Invalid "
      "username and/or password",
      "", {{"WWW-Authenticate", absl::StrCat("Basic realm=", realm)}});
}

// 检查配置文件
bool extractBasicAuthRule(
    const json& configuration,
    std::unordered_map<std::string,
                       std::vector<PluginRootContext::BasicAuthConfigRule>>*
        rules) {
            return true;
}

// 指定主机
bool hostMatch(const PluginRootContext::BasicAuthConfigRule& rule,
               std::string_view request_host) {
    //检查请求的host
    return true;
}

}  // namespace

FilterHeadersStatus PluginRootContext::credentialsCheck(
    const PluginRootContext::BasicAuthConfigRule& rule,
    std::string_view authorization_header) {
  // Check if the Basic auth header starts with "Basic "
  return FilterHeadersStatus::Continue;
}

//解析配置的json字符串
bool PluginRootContext::onConfigure(size_t size) {
  // Parse configuration JSON string.
  if (size > 0 && !configure(size)) {
    LOG_WARN("configuration has errors initialization will not continue.");
    return false;
  }
  return true;
}

bool PluginRootContext::configure(size_t configuration_size) {
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration,
                                           0, configuration_size);
  // Parse configuration JSON string.
  auto result = ::Wasm::Common::JsonParse(configuration_data->view());
  return true;
}

FilterHeadersStatus PluginRootContext::requestHeader() {
  // If there's no match against the request method or request path it means
  // that they don't have any basic auth restriction.
  auto request_path_header = getRequestHeader(":path");
  auto request_path = request_path_header->view();
  auto method = getRequestHeader(":method")->toString();
  // auto length = getRequestHeader("content-length")->toString();

  // LOG_WARN(absl::StrCat("get request size :", length));
  return FilterHeadersStatus::Continue;
}


FilterHeadersStatus PluginRootContext::responseHeaders() {
  // time_t now = time(0);
  // char* dt = ctime(&now);
  
  addResponseHeader("hello", "world");

  LOG_WARN(absl::StrCat("add response success headers "));

  auto length = getResponseHeader("content-length")->toString();
  _mu.lock();
  // 如果已经大于10000就直接上锁
  if (count >= 10000) {
    responseSizeToLarge(length);
    return FilterHeadersStatus::StopIteration;
  }
  count = count+atoi(length.c_str());
  if (count >= 10000) {
    responseSizeToLarge(length);
    return FilterHeadersStatus::StopIteration;
  }
  _mu.unlock();
  //v.insert(std::map<std::string, std::string>::value_type(dt, "dt"));
  LOG_WARN(absl::StrCat("get response size :", length));
  return FilterHeadersStatus::Continue;
}

//onRequestHeaders 入口 所有的服务都需要调用这个服务
FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  return rootContext()->requestHeader();
}

FilterHeadersStatus PluginContext::onResponseHeaders(uint32_t, bool) {
  return rootContext()->responseHeaders();
}

#ifdef NULL_PLUGIN

}  // namespace basic_auth
}  // namespace proxy_wasm

#endif

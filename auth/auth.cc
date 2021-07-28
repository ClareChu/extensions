#include "auth/auth.h"

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
  if (!absl::StartsWith(authorization_header, "Basic ")) {
    deniedNoBasicAuthData(realm_);
    return FilterHeadersStatus::StopIteration;
  }
  std::string_view authorization_header_strip =
      absl::StripPrefix(authorization_header, "Basic ");

  auto auth_credential_iter =
      rule.encoded_credentials.find(std::string(authorization_header_strip));
  // Check if encoded credential is part of the encoded_credentials
  // set from our container to grant or deny access.
  if (auth_credential_iter == rule.encoded_credentials.end()) {
    deniedInvalidCredentials(realm_);
    return FilterHeadersStatus::StopIteration;
  }

  return FilterHeadersStatus::Continue;
}

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
  if (!result.has_value()) {
    LOG_WARN(absl::StrCat("cannot parse plugin configuration JSON string: ",
                          configuration_data->view()));
    return false;
  }
  // j is a JsonObject holds configuration data
  auto j = result.value();
  if (!JsonArrayIterate(j, "basic_auth_rules",
                        [&](const json& configuration) -> bool {
                          return extractBasicAuthRule(
                              configuration, &basic_auth_configuration_);
                        })) {
    LOG_WARN(absl::StrCat("cannot parse plugin configuration JSON string: ",
                          configuration_data->view()));
    return false;
  }
  auto it = j.find("realm");
  if (it != j.end()) {
    auto realm_string = JsonValueAs<std::string>(it.value());
    if (realm_string.second != Wasm::Common::JsonParserResultDetail::OK) {
      LOG_WARN(absl::StrCat(
          "cannot parse realm in plugin configuration JSON string: ",
          configuration_data->view()));
      return false;
    }
    realm_ = realm_string.first.value();
  }
  return true;
}

FilterHeadersStatus PluginRootContext::check() {
  auto request_path_header = getRequestHeader(":path");
  auto request_path = request_path_header->view();
  auto method = getRequestHeader(":method")->toString();
  auto method_iter = basic_auth_configuration_.find(method);
  // First we check if the request method is present in our container
  if (method_iter != basic_auth_configuration_.end()) {
    auto request_host_header = getRequestHeader(":authority");
    auto request_host = request_host_header->view();
    // We iterate through our vector of struct in order to find if the
    // request_path according to given match pattern, is part of the plugin's
    // configuration data. If that's the case we check the credentials
    FilterHeadersStatus header_status = FilterHeadersStatus::Continue;
    auto authorization_header = getRequestHeader("authorization");
    auto authorization = authorization_header->view();
    for (auto& rule : basic_auth_configuration_[method]) {
      if (!hostMatch(rule, request_host)) {
        continue;
      }
      if (rule.path_pattern == MATCH_TYPE::Prefix) {
        if (absl::StartsWith(request_path, rule.request_path)) {
          header_status = credentialsCheck(rule, authorization);
        }
      } else if (rule.path_pattern == MATCH_TYPE::Exact) {
        if (rule.request_path == request_path) {
          header_status = credentialsCheck(rule, authorization);
        }
      } else if (rule.path_pattern == MATCH_TYPE::Suffix) {
        if (absl::EndsWith(request_path, rule.request_path)) {
          header_status = credentialsCheck(rule, authorization);
        }
      }
      if (header_status == FilterHeadersStatus::StopIteration) {
        return FilterHeadersStatus::StopIteration;
      }
    }
  }
  // If there's no match against the request method or request path it means
  // that they don't have any basic auth restriction.
  return FilterHeadersStatus::Continue;
}

FilterHeadersStatus PluginContext::onRequestHeaders(uint32_t, bool) {
  return rootContext()->check();
}

#ifdef NULL_PLUGIN

}  // namespace basic_auth
}  // namespace proxy_wasm

#endif

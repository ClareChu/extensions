load("@proxy_wasm_cpp_sdk//bazel/wasm:wasm.bzl", "wasm_cc_binary")

wasm_cc_binary(
    name = "auth.wasm",
    srcs = [
        "auth.cc",
        "auth.h",
        "@io_istio_proxy//extensions/common/wasm:base64.h",
    ],
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@io_istio_proxy//extensions/common/wasm:json_util",
        "@proxy_wasm_cpp_sdk//:proxy_wasm_intrinsics",
    ],
)

cc_library(
    name = "auth",
    srcs = [
        "auth.cc",
        "@io_istio_proxy//extensions/common/wasm:base64.h",
    ],
    hdrs = [
        "auth.h",
    ],
    copts = ["-DNULL_PLUGIN"],
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@io_istio_proxy//extensions/common/wasm:json_util",
        "@proxy_wasm_cpp_host//:lib",
    ],
)

licenses(["notice"])  # Apache 2.0

cc_binary(
    name = "hybrid_encrypt_cli_cc",
    srcs = ["hybrid_encrypt_cli.cc"],
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        "//cc",
        "//cc:cleartext_keyset_handle",
        "//cc/hybrid:hybrid_encrypt_config",
        "//cc/hybrid:hybrid_encrypt_factory",
        "//cc/util:status",
    ],
)

cc_binary(
    name = "hybrid_decrypt_cli_cc",
    srcs = ["hybrid_decrypt_cli.cc"],
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        "//cc",
        "//cc:cleartext_keyset_handle",
        "//cc/hybrid:hybrid_decrypt_config",
        "//cc/hybrid:hybrid_decrypt_factory",
        "//cc/util:status",
    ],
)

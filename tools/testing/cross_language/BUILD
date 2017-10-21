package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

sh_test(
    name = "hybrid_encryption_test",
    size = "small",
    srcs = [
        "hybrid_encryption_test.sh",
    ],
    data = [
        "//examples/keytemplates:hybrid",
        "//tools/testing:hybrid_decrypt_cli_java",
        "//tools/testing:hybrid_encrypt_cli_java",
        "//tools/testing/cc:hybrid_decrypt_cli_cc",
        "//tools/testing/cc:hybrid_encrypt_cli_cc",
        "//tools/tinkey",
    ],
)

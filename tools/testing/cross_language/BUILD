package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

filegroup(
    name = "test_lib",
    srcs = [
        "test_util.sh",
    ],
)

sh_test(
    name = "aead_test",
    size = "small",
    srcs = [
        "aead_test.sh",
    ],
    data = [
        ":test_lib",
        "//examples/keytemplates:aead",
        "//tools/testing:aead_cli_java",
        "//tools/testing/cc:aead_cli_cc",
        "//tools/tinkey",
    ],
)

sh_test(
    name = "hybrid_encryption_test",
    size = "small",
    srcs = [
        "hybrid_encryption_test.sh",
    ],
    data = [
        ":test_lib",
        "//examples/keytemplates:hybrid",
        "//tools/testing:hybrid_decrypt_cli_java",
        "//tools/testing:hybrid_encrypt_cli_java",
        "//tools/testing/cc:hybrid_decrypt_cli_cc",
        "//tools/testing/cc:hybrid_encrypt_cli_cc",
        "//tools/tinkey",
    ],
)

sh_test(
    name = "signature_test",
    size = "small",
    srcs = [
        "signature_test.sh",
    ],
    data = [
        ":test_lib",
        "//examples/keytemplates:signature",
        "//tools/testing:public_key_sign_cli_java",
        "//tools/testing:public_key_verify_cli_java",
        "//tools/testing/cc:public_key_sign_cli_cc",
        "//tools/testing/cc:public_key_verify_cli_cc",
        "//tools/tinkey",
    ],
)

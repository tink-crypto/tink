package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

java_library(
    name = "cli_util",
    testonly = 1,
    srcs = [
        "java/com/google/crypto/tink/testing/CliUtil.java",
    ],
    javacopts = JAVACOPTS,
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        "//java:testonly",
    ],
)

java_binary(
    name = "aead_cli_java",
    testonly = 1,
    srcs = [
        "java/com/google/crypto/tink/testing/AeadCli.java",
    ],
    javacopts = JAVACOPTS,
    main_class = "com.google.crypto.tink.testing.AeadCli",
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        ":cli_util",
        "//java:testonly",
    ],
)

java_binary(
    name = "hybrid_encrypt_cli_java",
    testonly = 1,
    srcs = [
        "java/com/google/crypto/tink/testing/HybridEncryptCli.java",
    ],
    javacopts = JAVACOPTS,
    main_class = "com.google.crypto.tink.testing.HybridEncryptCli",
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        ":cli_util",
        "//java:testonly",
    ],
)

java_binary(
    name = "hybrid_decrypt_cli_java",
    testonly = 1,
    srcs = [
        "java/com/google/crypto/tink/testing/HybridDecryptCli.java",
    ],
    javacopts = JAVACOPTS,
    main_class = "com.google.crypto.tink.testing.HybridDecryptCli",
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        ":cli_util",
        "//java:testonly",
    ],
)

java_binary(
    name = "public_key_sign_cli_java",
    testonly = 1,
    srcs = [
        "java/com/google/crypto/tink/testing/PublicKeySignCli.java",
    ],
    javacopts = JAVACOPTS,
    main_class = "com.google.crypto.tink.testing.PublicKeySignCli",
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        ":cli_util",
        "//java:testonly",
    ],
)

java_binary(
    name = "public_key_verify_cli_java",
    testonly = 1,
    srcs = [
        "java/com/google/crypto/tink/testing/PublicKeyVerifyCli.java",
    ],
    javacopts = JAVACOPTS,
    main_class = "com.google.crypto.tink.testing.PublicKeyVerifyCli",
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        ":cli_util",
        "//java:testonly",
    ],
)

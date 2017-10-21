package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

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
        "//java:testonly",
    ],
)

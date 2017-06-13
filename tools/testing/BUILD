licenses(["notice"])  # Apache 2.0

load("//java/build_defs:javac.bzl", "JAVACOPTS")

java_binary(
    name = "hybrid_encrypt_cli_java",
    srcs = [
        "java/com/google/crypto/tink/testing/HybridEncryptCli.java",
    ],
    javacopts = JAVACOPTS,
    main_class = "com.google.crypto.tink.testing.HybridEncryptCli",
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        "//java",
        "//java:keyset_handle",
    ],
)

java_binary(
    name = "hybrid_decrypt_cli_java",
    srcs = [
        "java/com/google/crypto/tink/testing/HybridDecryptCli.java",
    ],
    javacopts = JAVACOPTS,
    main_class = "com.google.crypto.tink.testing.HybridDecryptCli",
    visibility = ["//tools/testing:__subpackages__"],
    deps = [
        "//java",
        "//java:keyset_handle",
    ],
)

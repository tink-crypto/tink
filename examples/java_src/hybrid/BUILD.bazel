package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files([
    "hybrid_test_public_keyset.json",
    "hybrid_test_private_keyset.json",
])

java_binary(
    name = "hybrid_example",
    srcs = ["HybridExample.java"],
    main_class = "hybrid.HybridExample",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:hybrid_decrypt",
        "@tink_java//src/main/java/com/google/crypto/tink:hybrid_encrypt",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/hybrid:hybrid_config",
    ],
)

sh_test(
    name = "hybrid_example_test",
    size = "small",
    srcs = ["hybrid_example_test.sh"],
    args = [
        "$(rootpath :hybrid_example)",
        "$(rootpath :hybrid_test_public_keyset.json)",
        "$(rootpath :hybrid_test_private_keyset.json)",
    ],
    data = [
        ":hybrid_example",
        ":hybrid_test_private_keyset.json",
        ":hybrid_test_public_keyset.json",
    ],
)

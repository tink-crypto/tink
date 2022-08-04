package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files(["aead_test_keyset.json"])

java_binary(
    name = "aead_example",
    srcs = ["AeadExample.java"],
    main_class = "aead.AeadExample",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:aead",
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/aead:aead_config",
    ],
)

sh_test(
    name = "aead_example_test",
    size = "small",
    srcs = ["aead_example_test.sh"],
    args = [
        "$(rootpath :aead_example)",
        "$(rootpath :aead_test_keyset.json)",
    ],
    data = [
        ":aead_example",
        ":aead_test_keyset.json",
    ],
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files([
    "streaming_aead_test_keyset.json",
])

java_binary(
    name = "streaming_aead_example",
    srcs = ["StreamingAeadExample.java"],
    main_class = "streamingaead.StreamingAeadExample",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink:streaming_aead",
        "@tink_java//src/main/java/com/google/crypto/tink/streamingaead:streaming_aead_config",
    ],
)

sh_test(
    name = "streaming_aead_example_test",
    size = "small",
    srcs = ["streaming_aead_example_test.sh"],
    args = [
        "$(rootpath :streaming_aead_example)",
        "$(rootpath :streaming_aead_test_keyset.json)",
    ],
    data = [
        ":streaming_aead_example",
        ":streaming_aead_test_keyset.json",
    ],
)

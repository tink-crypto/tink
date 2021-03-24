package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files(["mac_test_keyset.json"])

java_binary(
    name = "mac_example",
    srcs = ["MacExample.java"],
    main_class = "mac.MacExample",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:mac",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/mac:mac_config",
        "@tink_java//src/main/java/com/google/crypto/tink/subtle:hex",
    ],
)

sh_test(
    name = "mac_example_test",
    size = "small",
    srcs = ["mac_example_test.sh"],
    args = [
        "$(rootpath :mac_example)",
        "$(rootpath :mac_test_keyset.json)",
    ],
    data = [
        ":mac_example",
        ":mac_test_keyset.json",
    ],
)

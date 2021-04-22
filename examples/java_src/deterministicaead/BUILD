package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files(["deterministic_aead_test_keyset.json"])

java_binary(
    name = "deterministic_aead_example",
    srcs = ["DeterministicAeadExample.java"],
    main_class = "deterministicaead.DeterministicAeadExample",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:deterministic_aead",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/daead:deterministic_aead_config",
    ],
)

sh_test(
    name = "deterministic_aead_test",
    size = "small",
    srcs = ["deterministic_aead_test.sh"],
    args = [
        "$(rootpath :deterministic_aead_example)",
        "$(rootpath :deterministic_aead_test_keyset.json)",
    ],
    data = [
        ":deterministic_aead_example",
        ":deterministic_aead_test_keyset.json",
    ],
)

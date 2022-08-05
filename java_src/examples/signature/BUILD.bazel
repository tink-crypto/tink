package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files([
    "signature_test_private_keyset.json",
    "signature_test_public_keyset.json",
])

java_binary(
    name = "signature_example",
    srcs = ["SignatureExample.java"],
    main_class = "signature.SignatureExample",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:public_key_sign",
        "@tink_java//src/main/java/com/google/crypto/tink:public_key_verify",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/signature:signature_config",
        "@tink_java//src/main/java/com/google/crypto/tink/subtle:hex",
    ],
)

sh_test(
    name = "signature_example_test",
    size = "small",
    srcs = ["signature_example_test.sh"],
    args = [
        "$(rootpath :signature_example)",
        "$(rootpath :signature_test_private_keyset.json)",
        "$(rootpath :signature_test_public_keyset.json)",
    ],
    data = [
        ":signature_example",
        ":signature_test_private_keyset.json",
        ":signature_test_public_keyset.json",
    ],
)

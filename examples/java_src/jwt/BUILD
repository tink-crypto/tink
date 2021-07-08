package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files([
    "jwt_signature_test_private_keyset.json",
    "jwt_signature_test_public_keyset.json",
])

java_binary(
    name = "jwt_signature_example",
    srcs = ["JwtSignatureExample.java"],
    main_class = "jwt.JwtSignatureExample",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_public_key_sign",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_public_key_verify",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_signature_config",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_validator",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:raw_jwt",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:verified_jwt",
    ],
)

sh_test(
    name = "jwt_signature_example_test",
    size = "small",
    srcs = ["jwt_signature_example_test.sh"],
    args = [
        "$(rootpath :jwt_signature_example)",
        "$(rootpath :jwt_signature_test_private_keyset.json)",
        "$(rootpath :jwt_signature_test_public_keyset.json)",
    ],
    data = [
        ":jwt_signature_example",
        ":jwt_signature_test_private_keyset.json",
        ":jwt_signature_test_public_keyset.json",
    ],
)

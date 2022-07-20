package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files([
    "jwt_signature_test_private_keyset.json",
])

java_binary(
    name = "jwt_sign",
    srcs = ["JwtSign.java"],
    main_class = "jwt.JwtSign",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_public_key_sign",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_signature_config",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:raw_jwt",
    ],
)

java_binary(
    name = "jwt_generate_public_jwk_set",
    srcs = ["JwtGeneratePublicJwkSet.java"],
    main_class = "jwt.JwtGeneratePublicJwkSet",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwk_set_converter",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_signature_config",
    ],
)

java_binary(
    name = "jwt_verify",
    srcs = ["JwtVerify.java"],
    main_class = "jwt.JwtVerify",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwk_set_converter",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_public_key_verify",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_signature_config",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:jwt_validator",
        "@tink_java//src/main/java/com/google/crypto/tink/jwt:verified_jwt",
        "@tink_java//src/main/java/com/google/crypto/tink/tinkkey:key_access",
    ],
)

sh_test(
    name = "jwt_signature_example_test",
    size = "small",
    srcs = ["jwt_signature_example_test.sh"],
    args = [
        "$(rootpath :jwt_sign)",
        "$(rootpath :jwt_generate_public_jwk_set)",
        "$(rootpath :jwt_verify)",
        "$(rootpath :jwt_signature_test_private_keyset.json)",
    ],
    data = [
        ":jwt_generate_public_jwk_set",
        ":jwt_sign",
        ":jwt_signature_test_private_keyset.json",
        ":jwt_verify",
    ],
)

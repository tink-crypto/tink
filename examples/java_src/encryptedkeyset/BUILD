package(default_visibility = ["//visibility:public"])

licenses(["notice"])

java_binary(
    name = "encrypted_keyset_example",
    srcs = ["EncryptedKeysetExample.java"],
    main_class = "encryptedkeyset.EncryptedKeysetExample",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:aead",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_reader",
        "@tink_java//src/main/java/com/google/crypto/tink:json_keyset_writer",
        "@tink_java//src/main/java/com/google/crypto/tink:key_templates",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/aead:aead_config",
        "@tink_java//src/main/java/com/google/crypto/tink/aead:kms_aead_key_manager",
        "@tink_java//src/main/java/com/google/crypto/tink/integration/gcpkms:gcp_kms_client",
    ],
)

# In order to run this test, use your own Cloud KMS key and credential.
sh_test(
    name = "encrypted_keyset_example_test",
    size = "small",
    srcs = ["encrypted_keyset_example_test.sh"],
    args = [
        "$(rootpath :encrypted_keyset_example)",
        # Change this to your key
        "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key",
        # Change this to your credential
        "$(rootpath @tink_base//testdata:credential.json)",
    ],
    data = [
        ":encrypted_keyset_example",
        # Change this to your credential
        "@tink_base//testdata:credential.json",
    ],
    tags = [
        "manual",
        "notap",
        # TODO(b/191644120): reintroduce this once the service account keys are updated.
        # "tink_guitar",
    ],
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

java_binary(
    name = "envelope_aead_example",
    srcs = ["EnvelopeAeadExample.java"],
    main_class = "envelopeaead.EnvelopeAeadExample",
    deps = [
        "@tink_java//src/main/java/com/google/crypto/tink:aead",
        "@tink_java//src/main/java/com/google/crypto/tink:key_templates",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/aead:aead_config",
        "@tink_java//src/main/java/com/google/crypto/tink/aead:kms_envelope_aead_key_manager",
        "@tink_java//src/main/java/com/google/crypto/tink/integration/gcpkms:gcp_kms_client",
    ],
)

# In order to run this test, use your own Cloud KMS key and credential
sh_test(
    name = "envelope_aead_example_test",
    size = "small",
    srcs = ["envelope_aead_example_test.sh"],
    args = [
        "$(rootpath :envelope_aead_example)",
        # Change this to your key
        "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key",
        # Change this to your credential
        "$(rootpath @tink_base//testdata:credential.json)",
    ],
    data = [
        ":envelope_aead_example",
        # Change this to your credential
        "@tink_base//testdata:credential.json",
    ],
    tags = [
        "manual",
        "requires-network",
    ],
)

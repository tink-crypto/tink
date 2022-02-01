package(default_visibility = ["//visibility:public"])

licenses(["notice"])

java_binary(
    name = "gcs_envelope_aead_example",
    srcs = ["GcsEnvelopeAeadExample.java"],
    main_class = "gcs.GcsEnvelopeAeadExample",
    deps = [
        "@examples_maven//:com_google_auth_google_auth_library_oauth2_http",
        "@examples_maven//:com_google_cloud_google_cloud_storage",
        "@tink_java//src/main/java/com/google/crypto/tink:aead",
        "@tink_java//src/main/java/com/google/crypto/tink:key_templates",
        "@tink_java//src/main/java/com/google/crypto/tink:registry_cluster",
        "@tink_java//src/main/java/com/google/crypto/tink/aead:aead_config",
        "@tink_java//src/main/java/com/google/crypto/tink/aead:kms_envelope_aead_key_manager",
        "@tink_java//src/main/java/com/google/crypto/tink/integration/gcpkms:gcp_kms_client",
    ],
)

# In order to run this test, you have to use your own GCP config.
sh_test(
    name = "gcs_envelope_aead_example_test",
    size = "small",
    srcs = ["gcs_envelope_aead_example_test.sh"],
    args = [
        "$(rootpath :gcs_envelope_aead_example)",
        # Change this to your key
        "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key",
        # Change this to your credential
        "$(rootpath @tink_base//testdata:credential.json)",
        # Change this to your project ID
        "tink-test-infrastructure",
        # Change this to your GCS bucket
        "gs://tink-gcs-examples",
    ],
    data = [
        ":gcs_envelope_aead_example",
        # Change this to your credential
        "@tink_base//testdata:credential.json",
    ],
    tags = [
        "manual",
        "notap",
        "requires-net:external",
        "tink_guitar",
    ],
)

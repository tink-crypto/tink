"""Dependencies of Java Tink."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

TINK_MAVEN_ARTIFACTS = [
    "com.google.protobuf:protobuf-java:3.19.6",
    "com.google.protobuf:protobuf-javalite:3.19.6",
    "com.amazonaws:aws-java-sdk-core:1.12.182",
    "com.amazonaws:aws-java-sdk-kms:1.12.182",
    "androidx.annotation:annotation:1.5.0",
    "com.google.auto:auto-common:1.2.1",
    "com.google.auto.service:auto-service:1.0.1",
    "com.google.auto.service:auto-service-annotations:1.0.1",
    "com.google.api-client:google-api-client:2.2.0",
    "com.google.apis:google-api-services-cloudkms:v1-rev20221107-2.0.0",
    "com.google.auth:google-auth-library-oauth2-http:1.20.0",
    "com.google.cloud:google-cloud-kms:2.31.0",
    "com.google.code.findbugs:jsr305:3.0.2",
    "com.google.code.gson:gson:2.10.1",
    "com.google.errorprone:error_prone_annotations:2.18.0",
    "com.google.http-client:google-http-client:1.43.1",
    "com.google.http-client:google-http-client-gson:1.43.1",
    "com.google.oauth-client:google-oauth-client:1.34.1",
    "com.google.truth:truth:0.44",
    "junit:junit:4.13.2",
    "org.conscrypt:conscrypt-openjdk-uber:2.5.2",
    "org.ow2.asm:asm:7.0",
    "org.ow2.asm:asm-commons:7.0",
    "org.pantsbuild:jarjar:1.7.2",
]

def tink_java_deps():
    """Loads dependencies of Java Tink."""

    # Google PKI certs for connecting to GCP KMS
    if not native.existing_rule("google_root_pem"):
        http_file(
            name = "google_root_pem",
            executable = 0,
            urls = ["https://pki.goog/roots.pem"],
            sha256 = "1acf0d4780541758be2c0f998e1e0275232626ed3f8793d8e2fe8e2753750613",
        )

    # Basic rules we need to add to bazel.
    if not native.existing_rule("bazel_skylib"):
        # Release from 2021-09-27.
        http_archive(
            name = "bazel_skylib",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.1.1/bazel-skylib-1.1.1.tar.gz",
                "https://github.com/bazelbuild/bazel-skylib/releases/download/1.1.1/bazel-skylib-1.1.1.tar.gz",
            ],
            sha256 = "c6966ec828da198c5d9adbaa94c05e3a1c7f21bd012a0b29ba8ddbccb2c93b0d",
        )

    # -------------------------------------------------------------------------
    # Protobuf.
    # -------------------------------------------------------------------------
    # proto_library, cc_proto_library and java_proto_library rules implicitly
    # depend respectively on:
    #   * @com_google_protobuf//:proto
    #   * @com_google_protobuf//:cc_toolchain
    #   * @com_google_protobuf//:java_toolchain
    # This statement defines the @com_google_protobuf repo.
    if not native.existing_rule("com_google_protobuf"):
        # Release X.21.9 from 2022-10-26.
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-21.9",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/refs/tags/v21.9.zip"],
            sha256 = "5babb8571f1cceafe0c18e13ddb3be556e87e12ceea3463d6b0d0064e6cc1ac3",
        )

    # -------------------------------------------------------------------------
    # Transitive Maven artifact resolution and publishing rules for Bazel.
    # -------------------------------------------------------------------------
    if not native.existing_rule("rules_jvm_external"):
        # Release from 2023-06-23
        http_archive(
            name = "rules_jvm_external",
            strip_prefix = "rules_jvm_external-5.3",
            url = "https://github.com/bazelbuild/rules_jvm_external/archive/5.3.zip",
            sha256 = "6cc8444b20307113a62b676846c29ff018402fd4c7097fcd6d0a0fd5f2e86429",
        )

    # -------------------------------------------------------------------------
    # Android rules for Bazel.
    # -------------------------------------------------------------------------
    if not native.existing_rule("build_bazel_rules_android"):
        # Last release from 2018-08-07.
        http_archive(
            name = "build_bazel_rules_android",
            urls = ["https://github.com/bazelbuild/rules_android/archive/refs/tags/v0.1.1.zip"],
            sha256 = "cd06d15dd8bb59926e4d65f9003bfc20f9da4b2519985c27e190cddc8b7a7806",
            strip_prefix = "rules_android-0.1.1",
        )

    # -------------------------------------------------------------------------
    # Wycheproof.
    # -------------------------------------------------------------------------
    if not native.existing_rule("wycheproof"):
        # Commit from 2019-12-17
        http_archive(
            name = "wycheproof",
            strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
            url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
            sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
        )

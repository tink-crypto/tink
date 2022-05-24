"""Dependencies of Java Tink."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

TINK_MAVEN_ARTIFACTS = [
    "com.amazonaws:aws-java-sdk-core:1.12.182",
    "com.amazonaws:aws-java-sdk-kms:1.12.182",
    "com.google.auto:auto-common:1.2.1",
    "com.google.auto.service:auto-service:1.0.1",
    "com.google.auto.service:auto-service-annotations:1.0.1",
    "com.google.api-client:google-api-client:1.33.2",
    "com.google.apis:google-api-services-cloudkms:v1-rev108-1.25.0",
    "com.google.auth:google-auth-library-oauth2-http:1.5.3",
    "com.google.code.findbugs:jsr305:3.0.1",
    "com.google.code.gson:gson:2.8.9",
    "com.google.errorprone:error_prone_annotations:2.10.0",
    "com.google.http-client:google-http-client:1.39.0",
    "com.google.http-client:google-http-client-gson:1.39.0",
    "com.google.oauth-client:google-oauth-client:1.30.1",
    "com.google.truth:truth:0.44",
    "joda-time:joda-time:2.10.3",
    "junit:junit:4.13",
    "org.conscrypt:conscrypt-openjdk-uber:2.4.0",
    "org.mockito:mockito-core:2.23.0",
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
            sha256 = "a9bebf3c3d65d4d421b7e2adbd8600ede614e9e2cc0a05fb2a652f147d7802f3",
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
        # Release from 2021-06-08.
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.19.3",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.19.3.zip"],
            sha256 = "6b6bf5cd8d0cca442745c4c3c9f527c83ad6ef35a405f64db5215889ac779b42",
        )

    # -------------------------------------------------------------------------
    # Remote Build Execution (RBE).
    # -------------------------------------------------------------------------
    if not native.existing_rule("bazel_toolchains"):
        # Latest bazel_toolchains package on 2021-10-13.
        http_archive(
            name = "bazel_toolchains",
            sha256 = "179ec02f809e86abf56356d8898c8bd74069f1bd7c56044050c2cd3d79d0e024",
            strip_prefix = "bazel-toolchains-4.1.0",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-toolchains/releases/download/4.1.0/bazel-toolchains-4.1.0.tar.gz",
                "https://github.com/bazelbuild/bazel-toolchains/releases/download/4.1.0/bazel-toolchains-4.1.0.tar.gz",
            ],
        )

    # -------------------------------------------------------------------------
    # Transitive Maven artifact resolution and publishing rules for Bazel.
    # -------------------------------------------------------------------------
    if not native.existing_rule("rules_jvm_external"):
        # Release from 2021-11-24
        http_archive(
            name = "rules_jvm_external",
            strip_prefix = "rules_jvm_external-4.2",
            sha256 = "cd1a77b7b02e8e008439ca76fd34f5b07aecb8c752961f9640dea15e9e5ba1ca",
            url = "https://github.com/bazelbuild/rules_jvm_external/archive/4.2.zip",
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

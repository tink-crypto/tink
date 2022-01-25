"""
Dependencies of Java Tink.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

TINK_MAVEN_ARTIFACTS = [
    "args4j:args4j:2.33",
    "com.amazonaws:aws-java-sdk-core:1.11.976",
    "com.amazonaws:aws-java-sdk-kms:1.11.976",
    "com.google.auto:auto-common:0.10",
    "com.google.auto.service:auto-service:1.0-rc7",
    "com.google.auto.service:auto-service-annotations:1.0-rc7",
    "com.google.api-client:google-api-client:1.31.4",
    "com.google.apis:google-api-services-cloudkms:v1-rev108-1.25.0",
    "com.google.code.findbugs:jsr305:3.0.1",
    "com.google.code.gson:gson:2.8.6",
    "com.google.errorprone:error_prone_annotations:2.10.0",
    "com.google.http-client:google-http-client:1.31.0",
    "com.google.http-client:google-http-client-jackson2:1.31.0",
    "com.google.oauth-client:google-oauth-client:1.30.1",
    "com.google.truth:truth:0.44",
    "com.fasterxml.jackson.core:jackson-core:2.12.3",
    "joda-time:joda-time:2.10.3",
    "junit:junit:4.13",
    "org.conscrypt:conscrypt-openjdk-uber:2.4.0",
    "org.mockito:mockito-core:2.23.0",
    "org.ow2.asm:asm:7.0",
    "org.ow2.asm:asm-commons:7.0",
    "org.pantsbuild:jarjar:1.7.2",
    "pl.pragmatists:JUnitParams:1.1.1",
]

def tink_java_deps():
    """ Loads dependencies of Java Tink.

    """
    if not native.existing_rule("rules_jvm_external"):
        # Release from 2021-11-24
        http_archive(
            name = "rules_jvm_external",
            strip_prefix = "rules_jvm_external-4.2",
            sha256 = "cd1a77b7b02e8e008439ca76fd34f5b07aecb8c752961f9640dea15e9e5ba1ca",
            url = "https://github.com/bazelbuild/rules_jvm_external/archive/4.2.zip",
        )

    if not native.existing_rule("build_bazel_rules_android"):
        # Last release from 2018-08-07.
        http_archive(
            name = "build_bazel_rules_android",
            urls = ["https://github.com/bazelbuild/rules_android/archive/v0.1.1.zip"],
            sha256 = "cd06d15dd8bb59926e4d65f9003bfc20f9da4b2519985c27e190cddc8b7a7806",
            strip_prefix = "rules_android-0.1.1",
        )

    if not native.existing_rule("rules_python"):
        # Needed by @com_google_protobuf_javalite.
        http_archive(
            name = "rules_python",
            sha256 = "e5470e92a18aa51830db99a4d9c492cc613761d5bdb7131c04bd92b9834380f6",
            strip_prefix = "rules_python-4b84ad270387a7c439ebdccfd530e2339601ef27",
            urls = ["https://github.com/bazelbuild/rules_python/archive/4b84ad270387a7c439ebdccfd530e2339601ef27.tar.gz"],
        )

"""
Initialization of dependencies of Java Tink.
"""

load("@com_google_protobuf//:protobuf_deps.bzl", javalite_protobuf_deps = "protobuf_deps")
load("@rules_jvm_external//:defs.bzl", "maven_install")
load("@build_bazel_rules_android//android:rules.bzl", "android_sdk_repository")

def tink_java_deps_init():
    """ Initializes dependencies of Java Tink.

    """
    javalite_protobuf_deps()
    maven_install(
        artifacts = [
            "args4j:args4j:2.33",
            "com.amazonaws:aws-java-sdk-core:1.11.976",
            "com.amazonaws:aws-java-sdk-kms:1.11.976",
            "com.google.auto:auto-common:0.10",
            "com.google.auto.service:auto-service:1.0-rc7",
            "com.google.auto.service:auto-service-annotations:1.0-rc7",
            "com.google.api-client:google-api-client:1.31.3",
            "com.google.apis:google-api-services-cloudkms:v1-rev108-1.25.0",
            "com.google.code.findbugs:jsr305:3.0.1",
            "com.google.code.gson:gson:2.8.6",
            "com.google.errorprone:error_prone_annotations:2.3.3",
            "com.google.http-client:google-http-client:1.31.0",
            "com.google.http-client:google-http-client-jackson2:1.31.0",
            "com.google.oauth-client:google-oauth-client:1.30.1",
            "com.google.truth:truth:0.44",
            "com.fasterxml.jackson.core:jackson-core:2.12.3",
            "joda-time:joda-time:2.10.3",
            "junit:junit:4.13",
            "org.conscrypt:conscrypt-openjdk-uber:2.4.0",
            "org.json:json:20170516",
            "org.mockito:mockito-core:2.23.0",
            "org.ow2.asm:asm:7.0",
            "org.ow2.asm:asm-commons:7.0",
            "org.pantsbuild:jarjar:1.7.2",
            "pl.pragmatists:JUnitParams:1.1.1",
        ],
        repositories = [
            "https://jcenter.bintray.com/",
            "https://maven.google.com",
            "https://repo1.maven.org/maven2",
        ],
    )
    android_sdk_repository(
        name = "androidsdk",
        # Tink uses some APIs that only supported at this level.
        api_level = 26,  # Oreo
    )

"""
Initialization of dependencies of Java Tink.
"""

load("@com_google_protobuf//:protobuf_deps.bzl", javalite_protobuf_deps = "protobuf_deps")
load("@rules_jvm_external//:defs.bzl", "maven_install")
load("@build_bazel_rules_android//android:rules.bzl", "android_sdk_repository")
load("@tink_java//:tink_java_deps.bzl", "TINK_MAVEN_ARTIFACTS")

def tink_java_deps_init():
    """ Initializes dependencies of Java Tink.

    """
    javalite_protobuf_deps()
    maven_install(
        artifacts = TINK_MAVEN_ARTIFACTS,
        repositories = [
            "https://maven.google.com",
            "https://repo1.maven.org/maven2",
        ],
    )
    android_sdk_repository(
        name = "androidsdk",
        # Tink uses some APIs that only supported at this level.
        api_level = 26,  # Oreo
    )

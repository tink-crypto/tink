workspace(name = "tink_java_gcpkms")

local_repository(
    name = "tink_java",
    path = "../tink_java",
)

load("@tink_java//:tink_java_deps.bzl", "tink_java_deps", "TINK_MAVEN_ARTIFACTS")
tink_java_deps()

load("@tink_java//:tink_java_deps_init.bzl", "tink_java_deps_init")
load("@tink_java_gcpkms//:tink_java_gcpkms_deps.bzl", "TINK_JAVA_GCPKMS_MAVEN_ARTIFACTS")
load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")
load("@rules_jvm_external//:defs.bzl", "maven_install")

tink_java_deps_init()

rbe_autoconfig(name = "rbe_default")

maven_install(
    artifacts = TINK_MAVEN_ARTIFACTS + TINK_JAVA_GCPKMS_MAVEN_ARTIFACTS,
    repositories = [
        "https://maven.google.com",
        "https://repo1.maven.org/maven2",
    ],
)

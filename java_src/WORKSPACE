workspace(name = "tink_java")

load("@tink_java//:tink_java_deps.bzl", "tink_java_deps", "TINK_MAVEN_ARTIFACTS")

tink_java_deps()

load("@tink_java//:tink_java_deps_init.bzl", "tink_java_deps_init")

tink_java_deps_init()

load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

rbe_autoconfig(name = "rbe_default")

load("@rules_jvm_external//:defs.bzl", "maven_install")

maven_install(
    artifacts = TINK_MAVEN_ARTIFACTS,
    repositories = [
        "https://maven.google.com",
        "https://repo1.maven.org/maven2",
    ],
)

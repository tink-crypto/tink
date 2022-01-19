"""
Dependencies of Java Tink.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_java_deps():
    """ Loads dependencies of Java Tink.

    """
    if not native.existing_rule("rules_jvm_external"):
        # Release from 2021-05-18
        http_archive(
            name = "rules_jvm_external",
            strip_prefix = "rules_jvm_external-4.1",
            sha256 = "f36441aa876c4f6427bfb2d1f2d723b48e9d930b62662bf723ddfb8fc80f0140",
            url = "https://github.com/bazelbuild/rules_jvm_external/archive/4.1.zip",
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

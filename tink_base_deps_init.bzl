"""
Initalization of dependencies of Tink base.
"""

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

# temporary: loads from other languages
load("//third_party/py:python_configure.bzl", "python_configure")
load("@rules_python//python:repositories.bzl", "py_repositories")
load("@rules_python//python:pip.bzl", "pip3_import", "pip_repositories")
load("@com_google_protobuf_javalite//:protobuf_deps.bzl", javalite_protobuf_deps = "protobuf_deps")
load("@rules_jvm_external//:defs.bzl", "maven_install")
load("@io_bazel_rules_closure//closure:repositories.bzl", "rules_closure_dependencies", "rules_closure_toolchains")

def tink_base_deps_init():
    """ Initializes dependencies of Tink base.

    """

    # --------
    # temporary: inits from other languages
    #
    # Python:
    python_configure(name = "local_config_python")
    py_repositories()
    pip_repositories()
    pip3_import(
        name = "tink_py_deps",
        requirements = "//python:requirements.txt",
    )

    # Java:
    javalite_protobuf_deps()
    maven_install(
        artifacts = [
            "args4j:args4j:2.33",
            "com.amazonaws:aws-java-sdk-core:1.11.625",
            "com.amazonaws:aws-java-sdk-kms:1.11.625",
            "com.google.auto:auto-common:0.10",
            "com.google.auto.service:auto-service:1.0-rc6",
            "com.google.auto.service:auto-service-annotations:1.0-rc6",
            "com.google.api-client:google-api-client:1.22.0",
            "com.google.apis:google-api-services-cloudkms:v1-rev89-1.25.0",
            "com.google.code.findbugs:jsr305:3.0.1",
            "com.google.errorprone:error_prone_annotations:2.3.3",
            "com.google.http-client:google-http-client:1.31.0",
            "com.google.http-client:google-http-client-jackson2:1.31.0",
            "com.google.oauth-client:google-oauth-client:1.30.1",
            "com.google.truth:truth:0.42",
            "org.json:json:20170516",
            "joda-time:joda-time:2.10.3",
            "junit:junit:4.13",
            "org.mockito:mockito-core:2.23.0",
        ],
        repositories = [
            "https://jcenter.bintray.com/",
            "https://maven.google.com",
            "https://repo1.maven.org/maven2",
        ],
    )

    # ----- Javascript
    rules_closure_dependencies()
    rules_closure_toolchains()

    # --------
    # Actual base inits.
    protobuf_deps()

    # Creates a default toolchain config for RBE.
    # Use this as is if you are using the rbe_ubuntu16_04 container,
    # otherwise refer to RBE docs.
    rbe_autoconfig(name = "rbe_default")

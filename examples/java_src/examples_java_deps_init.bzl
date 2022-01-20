"""
Initialization of dependencies of Java examples.
"""

load("@rules_jvm_external//:defs.bzl", "maven_install")

def examples_java_deps_init():
    """ Initializes dependencies of Java examples.

    """
    maven_install(
        name = "examples_maven",
        artifacts = [
            "com.google.cloud:google-cloud-storage:2.3.0",
            "com.google.auth:google-auth-library-oauth2-http:1.3.0",
        ],
        repositories = [
            # TODO(b/214259089): Disable during bintray outage.
            #"https://jcenter.bintray.com/",
            "https://maven.google.com",
            "https://repo1.maven.org/maven2",
        ],
    )

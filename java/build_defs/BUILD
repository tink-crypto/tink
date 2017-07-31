licenses(["notice"])  # Apache 2.0

# Blaze config for enabling Datalab functionality in the Colab build.
config_setting(
    name = "use_java_proto_full",
    values = {"define": "use_java_proto_full=true"},
    visibility = [
        "//java:__subpackages__",
        "//tools/tinkey:__subpackages__",
    ],
)

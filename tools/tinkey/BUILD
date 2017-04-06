licenses(["notice"])  # Apache 2.0

JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

java_binary(
    name = "tinkey",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/tinkey/*.java",
    ]),
    javacopts = JAVACOPTS,
    main_class = "com.google.cloud.crypto.tink.tinkey.Tinkey",
    deps = [
        "//java",
        "//java:key_management_restricted",
        "@args4j//jar",
        "@com_google_guava//jar",
    ],
)

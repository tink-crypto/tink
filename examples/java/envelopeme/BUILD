licenses(["notice"])  # Apache 2.0

JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

java_binary(
    name = "envelopeme",
    srcs = glob([
        "src/main/java/com/example/envelopeme/*.java",
    ]),
    javacopts = JAVACOPTS,
    main_class = "com.example.envelopeme.EnvelopeMe",
    deps = [
        "//java:key_management_restricted",
        "//java:keyset_handle_restricted",
        "//java:tink",
        "@args4j//jar",
        "@com_fasterxml_jackson_core//jar",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_google_oauth_client//jar",
    ],
)

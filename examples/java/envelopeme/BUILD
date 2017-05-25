licenses(["notice"])  # Apache 2.0

load("//java/build_defs:javac.bzl", "JAVACOPTS")

java_binary(
    name = "envelopeme",
    srcs = glob([
        "src/main/java/com/example/envelopeme/*.java",
    ]),
    javacopts = JAVACOPTS,
    main_class = "com.example.envelopeme.EnvelopeMe",
    deps = [
        "//java",
        "//java:aead_envelope",
        "//java:subtle",
        "@args4j//jar",
        "@com_google_guava//jar",
    ],
)

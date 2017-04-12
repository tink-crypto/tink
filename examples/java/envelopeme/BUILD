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
        "//java",
        "//java:subtle",
        "@args4j//jar",
        "@com_google_guava//jar",
    ],
)

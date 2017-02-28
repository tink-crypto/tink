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
        "//java:keyset_handle_restricted",
        "//java:tink",
    ],
)

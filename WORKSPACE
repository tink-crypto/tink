git_repository(
  name = "org_pubref_rules_protobuf",
  remote = "https://github.com/pubref/rules_protobuf",
  # need this to fix https://github.com/pubref/rules_protobuf/issues/50
  commit = "be63ed9cb3140ec23e4df5118fca9a3f98640cf6",
)

load("@org_pubref_rules_protobuf//java:rules.bzl", "java_proto_repositories")
java_proto_repositories()

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cpp_proto_repositories")
cpp_proto_repositories()

maven_jar(
    name = "args4j",
    artifact = "args4j:args4j:2.33",
)

maven_jar(
    name = "com_fasterxml_jackson_core",
    artifact = "com.fasterxml.jackson.core:jackson-core:2.8.6",
)

maven_jar(
    name = "com_google_api_client",
    artifact = "com.google.api-client:google-api-client:1.22.0",
)

maven_jar(
    name = "com_google_cloudkms",
    artifact = "com.google.apis:google-api-services-cloudkms:v1beta1-rev51-1.18.0-rc",
)

maven_jar(
    name = "com_google_guava",
    artifact = "com.google.guava:guava:21.0",
)

maven_jar(
    name = "com_google_inject_guice",
    artifact = "com.google.inject:guice:4.1.0",
)

maven_jar(
    name = "com_google_http_client",
    artifact = "com.google.http-client:google-http-client:1.22.0",
)

maven_jar(
    name = "com_google_http_client_jackson2",
    artifact = "com.google.http-client:google-http-client-jackson2:1.22.0",
)

maven_jar(
    name = "com_google_oauth_client",
    artifact = "com.google.oauth-client:google-oauth-client:1.22.0",
)

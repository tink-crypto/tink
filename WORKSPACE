git_repository(
  name = "org_pubref_rules_protobuf",
  # This is a fork of https://github.com/pubref/rules_protobuf
  # that removes gRPC and adds support for javalite.
  remote = "https://github.com/thaidn/rules_protobuf",
  commit = "812e9a0119712ffe0b125b806a1889797b4eaa02",
)

git_repository(
    name = "boringssl",
    commit = "e06766691547514e5bf756e4a0d926e8ca680e5a",
    remote = "https://boringssl.googlesource.com/boringssl",
)

new_git_repository(
    name = "gtest",
    remote = "https://github.com/google/googletest.git",
    commit = "ed9d1e1ff92ce199de5ca2667a667cd0a368482a",
    build_file = "//tools:gtest.BUILD",
)

load("@org_pubref_rules_protobuf//java:rules.bzl", "java_proto_repositories")
java_proto_repositories()

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cpp_proto_repositories")
cpp_proto_repositories()

maven_jar(
    name = "args4j",
    artifact = "args4j:args4j:2.33",
    sha1 = "bd87a75374a6d6523de82fef51fc3cfe9baf9fc9"
)

maven_jar(
    name = "com_google_api_client",
    artifact = "com.google.api-client:google-api-client:1.22.0",
    sha1 = "0244350c0c845c583717ade13f5666a452fd0cfa",
)

maven_jar(
    name = "com_google_cloudkms",
    artifact = "com.google.apis:google-api-services-cloudkms:v1-rev4-1.22.0",
    sha1 = "2b85135459e6ea03a834319d49a831e73f9451a9",
)

maven_jar(
    name = "com_google_code_gson_gson",
    artifact = "com.google.code.gson:gson:2.8.0",
    sha1 = "c4ba5371a29ac9b2ad6129b1d39ea38750043eff",
)

maven_jar(
    name = "com_google_guava",
    artifact = "com.google.guava:guava:21.0",
    sha1 = "3a3d111be1be1b745edfa7d91678a12d7ed38709",
)

maven_jar(
    name = "com_google_http_client",
    artifact = "com.google.http-client:google-http-client:1.22.0",
    sha1 = "d441fc58329c4a4c067acec04ac361627f66ecc8",
)

maven_jar(
    name = "com_google_http_client_jackson2",
    artifact = "com.google.http-client:google-http-client-jackson2:1.22.0",
    sha1 = "cc014d64ae11117e159d334c99d9c246d9b36f44",
)

maven_jar(
    name = "com_google_oauth_client",
    artifact = "com.google.oauth-client:google-oauth-client:1.22.0",
    sha1 = "1d63f369ac78e4838a3197147012026e791008cb",
)

maven_jar(
    name = "com_fasterxml_jackson_core",
    artifact = "com.fasterxml.jackson.core:jackson-core:2.8.8",
    sha1 = "d478fb6de45a7c3d2cad07c8ad70c7f0a797a020",
)

maven_jar(
    name = "junit_junit_4",
    artifact = "junit:junit:jar:4.12",
    sha1 = "2973d150c0dc1fefe998f834810d68f278ea58ec",
)

maven_jar(
    name = "com_google_truth",
    artifact = "com.google.truth:truth:jar:0.32",
    sha1 = "e996fb4b41dad04365112786796c945f909cfdf7",
)

# go packages
git_repository(
    name = "io_bazel_rules_go",
    remote = "https://github.com/bazelbuild/rules_go.git",
    tag = "0.4.4",
)

load("@io_bazel_rules_go//go:def.bzl", "go_repositories", "new_go_repository")

go_repositories()

git_repository(
    name = "org_pubref_rules_protobuf",
    remote = "https://github.com/pubref/rules_protobuf.git",
    tag = "v0.7.2",
)

# TODO(thaidn): move this rule to third_party/rules_protobuf.
load("@org_pubref_rules_protobuf//go:rules.bzl", "go_proto_repositories")

go_proto_repositories()

# cc
git_repository(
    name = "boringssl",
    commit = "e06766691547514e5bf756e4a0d926e8ca680e5a",
    remote = "https://boringssl.googlesource.com/boringssl",
)

new_git_repository(
    name = "gtest",
    build_file = "//tools:gtest.BUILD",
    commit = "ed9d1e1ff92ce199de5ca2667a667cd0a368482a",
    remote = "https://github.com/google/googletest.git",
)

load("//third_party/rules_protobuf/javalite:rules.bzl", "javalite_proto_repositories")

javalite_proto_repositories()

# proto_library rules implicitly depend on @com_google_protobuf//:protoc,
# which is the proto-compiler.
# This statement defines the @com_google_protobuf repo.
http_archive(
    name = "com_google_protobuf",
    sha256 = "ff771a662fb6bd4d3cc209bcccedef3e93980a49f71df1e987f6afa3bcdcba3a",
    strip_prefix = "protobuf-b4b0e304be5a68de3d0ee1af9b286f958750f5e4",
    urls = ["https://github.com/google/protobuf/archive/b4b0e304be5a68de3d0ee1af9b286f958750f5e4.zip"],
)

# cc_proto_library rules implicitly depend on @com_google_protobuf_cc//:cc_toolchain,
# which is the C++ proto runtime (base classes and common utilities).
http_archive(
    name = "com_google_protobuf_cc",
    sha256 = "ff771a662fb6bd4d3cc209bcccedef3e93980a49f71df1e987f6afa3bcdcba3a",
    strip_prefix = "protobuf-b4b0e304be5a68de3d0ee1af9b286f958750f5e4",
    urls = ["https://github.com/google/protobuf/archive/b4b0e304be5a68de3d0ee1af9b286f958750f5e4.zip"],
)

# java_proto_library rules implicitly depend on @com_google_protobuf_java//:java_toolchain,
# which is the Java proto runtime (base classes and common utilities).
http_archive(
    name = "com_google_protobuf_java",
    sha256 = "ff771a662fb6bd4d3cc209bcccedef3e93980a49f71df1e987f6afa3bcdcba3a",
    strip_prefix = "protobuf-b4b0e304be5a68de3d0ee1af9b286f958750f5e4",
    urls = ["https://github.com/google/protobuf/archive/b4b0e304be5a68de3d0ee1af9b286f958750f5e4.zip"],
)

# java_lite_proto_library rules implicitly depend on @com_google_protobuf_javalite//:javalite_toolchain,
# which is the JavaLite proto runtime (base classes and common utilities).
http_archive(
    name = "com_google_protobuf_javalite",
    sha256 = "75105f312cefd8aa5e0bdf29279dc8ef0a6f862362b321d35b1ed5c08ce2ecfb",
    strip_prefix = "protobuf-82809aaebf24fca3c2d5611149c78a3625bd3b70",
    urls = ["https://github.com/google/protobuf/archive/82809aaebf24fca3c2d5611149c78a3625bd3b70.zip"],
)

# objc_proto_library rules from @org_pubref_rules_protobuf require the objective
# runtime files to build correctly. Therefore, we add a newer version of
# google/protobuf that has the @com_google_protobuf_objc//:objectivec target.
http_archive(
    name = "com_google_protobuf_objc",
    sha256 = "6025a4bd2a1bce5414a6521f44c247a31a0bd19cb1271c8ef46880cc450a7b10",
    strip_prefix = "protobuf-286f0598422a70639e587b5329bd3037f5ee76b0",
    urls = ["https://github.com/google/protobuf/archive/286f0598422a70639e587b5329bd3037f5ee76b0.zip"],
)

maven_jar(
    name = "args4j",
    artifact = "args4j:args4j:2.33",
    sha1 = "bd87a75374a6d6523de82fef51fc3cfe9baf9fc9",
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

maven_jar(
    name = "com_google_errorprone_error_prone_annotations",
    artifact = "com.google.errorprone:error_prone_annotations:2.0.19",
    sha1 = "c3754a0bdd545b00ddc26884f9e7624f8b6a14de",
)

load("@org_pubref_rules_protobuf//objc:rules.bzl", "objc_proto_repositories")

objc_proto_repositories()

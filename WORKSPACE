# TODO(thaidn): remove this dependency by porting what needed to
# third_party/rules_protobuf.
git_repository(
    name = "org_pubref_rules_protobuf",
    commit = "61efe7c69a6bafffd9f1231f9d6ea97c2014aa64",
    remote = "https://github.com/pubref/rules_protobuf.git",
)

# go packages
git_repository(
    name = "io_bazel_rules_go",
    remote = "https://github.com/bazelbuild/rules_go.git",
    tag = "0.4.4",
)
load("@io_bazel_rules_go//go:def.bzl", "go_repositories", "new_go_repository")
load("@io_bazel_rules_go//proto:go_proto_library.bzl", "go_proto_repositories")

go_repositories()
go_proto_repositories()

# wycheproof
http_archive(
    name = "wycheproof",
    strip_prefix = "wycheproof-f755ff0279ddd5fa26640d959d5872764b45feb7",
    sha256 = "8b32637abcf0c775dac424894a6586a75df821a7ffeedc467ccffa29209683e5",
    url = "https://github.com/google/wycheproof/archive/f755ff0279ddd5fa26640d959d5872764b45feb7.zip",
)

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

# proto_library rules implicitly depend on @com_google_protobuf//:protoc,
# which is the proto-compiler.
# This statement defines the @com_google_protobuf repo.
http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-3.3.0",
    urls = ["https://github.com/google/protobuf/archive/v3.3.0.tar.gz"],
    sha256 = "94c414775f275d876e5e0e4a276527d155ab2d0da45eed6b7734301c330be36e",
)

# cc_proto_library rules implicitly depend on @com_google_protobuf_cc//:cc_toolchain,
# which is the C++ proto runtime (base classes and common utilities).
http_archive(
    name = "com_google_protobuf_cc",
    strip_prefix = "protobuf-3.3.0",
    urls = ["https://github.com/google/protobuf/archive/v3.3.0.tar.gz"],
    sha256 = "94c414775f275d876e5e0e4a276527d155ab2d0da45eed6b7734301c330be36e",
)

# java_proto_library rules implicitly depend on @com_google_protobuf_java//:java_toolchain,
# which is the Java proto runtime (base classes and common utilities).
http_archive(
    name = "com_google_protobuf_java",
    strip_prefix = "protobuf-3.3.0",
    urls = ["https://github.com/google/protobuf/archive/v3.3.0.tar.gz"],
    sha256 = "94c414775f275d876e5e0e4a276527d155ab2d0da45eed6b7734301c330be36e",
)

# java_lite_proto_library rules implicitly depend on @com_google_protobuf_javalite//:javalite_toolchain,
# which is the JavaLite proto runtime (base classes and common utilities).
http_archive(
    name = "com_google_protobuf_javalite",
    strip_prefix = "protobuf-javalite",
    urls = ["https://github.com/google/protobuf/archive/javalite.zip"],
    sha256 = "b9ca3f706c6a6a6a744a7ba85321abce9e7d49825a19aaba6f29278871d41926",
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
    name = "com_amazonaws_sdk_core",
    artifact = "com.amazonaws:aws-java-sdk-core:1.11.166",
    sha1 = "5f28def6d43d805cc1d795ad08187d5b463d6c9d",
)

maven_jar(
    name = "com_amazonaws_sdk_kms",
    artifact = "com.amazonaws:aws-java-sdk-kms:1.11.166",
    sha1 = "33a4c0d5c26c4ab6bb14c1d80cdec435f837d887",
)

maven_jar(
    name = "com_google_auto_common",
    artifact = "com.google.auto:auto-common:0.8",
    sha1 = "c6f7af0e57b9d69d81b05434ef9f3c5610d498c4",
)

maven_jar(
    name = "com_google_auto_service",
    artifact = "com.google.auto.service:auto-service:1.0-rc3",
    sha1 = "35c5d43b0332b8f94d473f9fee5fb1d74b5e0056",
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
    artifact = "com.fasterxml.jackson.core:jackson-core:2.9.0",
    sha1 = "88e7c6220be3b3497b3074d3fc7754213289b987",
)

maven_jar(
    name = "com_fasterxml_jackson_databind",
    artifact = "com.fasterxml.jackson.core:jackson-databind:2.9.0",
    sha1 = "14fb5f088cc0b0dc90a73ba745bcade4961a3ee3",
)

maven_jar(
    name = "com_fasterxml_jackson_annotations",
    artifact = "com.fasterxml.jackson.core:jackson-annotations:2.9.0",
    sha1 = "07c10d545325e3a6e72e06381afe469fd40eb701",
)

maven_jar(
    name = "junit_junit_4",
    artifact = "junit:junit:jar:4.12",
    sha1 = "2973d150c0dc1fefe998f834810d68f278ea58ec",
)

maven_jar(
    name = "org_mockito",
    artifact = "org.mockito:mockito-core:2.8.47",
    sha1 = "48840cfced22ec0c07203a0201c5ae7bc12557b5",
)

maven_jar(
    name = "net_bytebuddy",
    artifact = "net.bytebuddy:byte-buddy:1.6.14",
    sha1 = "871c3e49dc6183d0d361601c2f1d11abb1a6b48c",
)

maven_jar(
    name = "net_bytebuddy_agent",
    artifact = "net.bytebuddy:byte-buddy-agent:1.6.14",
    sha1 = "ba1e5ba3a84fb2fbf2f4de9138df19665eec4d59",
)

maven_jar(
    name = "org_objenesis",
    artifact = "org.objenesis:objenesis:2.5",
    sha1 = "612ecb799912ccf77cba9b3ed8c813da086076e9",
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

maven_jar(
    name = "org_apache_commons_logging",
    artifact = "commons-logging:commons-logging:1.2",
    sha1 = "4bfc12adfe4842bf07b657f0369c4cb522955686",
)

maven_jar(
    name = "org_apache_httpcomponents_httpclient",
    artifact = "org.apache.httpcomponents:httpclient:4.5.3",
    sha1 = "d1577ae15f01ef5438c5afc62162457c00a34713",
)

maven_jar(
    name = "org_apache_httpcomponents_httpcore",
    artifact = "org.apache.httpcomponents:httpcore:4.4.6",
    sha1 = "e3fd8ced1f52c7574af952e2e6da0df8df08eb82",
)

load("@org_pubref_rules_protobuf//objc:rules.bzl", "objc_proto_repositories")

objc_proto_repositories()

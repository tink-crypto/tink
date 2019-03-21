workspace(name="tink")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

#-----------------------------------------------------------------------------
# Google PKI certs for connecting to GCP KMS
#-----------------------------------------------------------------------------

http_file(
    name = "google_root_pem",
    executable = 0,
    urls = [
        "https://pki.goog/roots.pem"
    ],
    sha256 = "7f03c894282e3fc39105466a8ee5055ffd05e79dfd4010360117078afbfa68bd",
)

#-----------------------------------------------------------------------------
# wycheproof, for JSON test vectors
#-----------------------------------------------------------------------------
http_archive(
    name = "wycheproof",
    strip_prefix = "wycheproof-f89f4c53a8845fcefcdb9f14ee9191dbe167e3e3",
    url = "https://github.com/google/wycheproof/archive/f89f4c53a8845fcefcdb9f14ee9191dbe167e3e3.zip",
    sha256 = "b44bb0339ad149e6cdab1337445cf52440cbfc79684203a3db1c094d9ef8daea",
)

#-----------------------------------------------------------------------------
# cc
#-----------------------------------------------------------------------------
http_archive(
    name = "com_google_absl",
    strip_prefix = "abseil-cpp-c476da141ca9cffc2137baf85872f0cae9ffa9ad",
    url = "https://github.com/abseil/abseil-cpp/archive/c476da141ca9cffc2137baf85872f0cae9ffa9ad.zip",
    sha256 = "84b4277a9b56f9a192952beca535313497826c6ff2e38b2cac7351a3ed2ae780",
)

http_archive(
    name = "boringssl",
    strip_prefix = "boringssl-18637c5f37b87e57ebde0c40fe19c1560ec88813",
    url = "https://github.com/google/boringssl/archive/18637c5f37b87e57ebde0c40fe19c1560ec88813.zip",
    sha256 = "bd923e59fca0d2b50db09af441d11c844c5e882a54c68943b7fc39a8cb5dd211",
)

# GoogleTest/GoogleMock framework. Used by most C++ unit-tests.
http_archive(
    name = "com_google_googletest",
    strip_prefix = "googletest-eb9225ce361affe561592e0912320b9db84985d0",
    url = "https://github.com/google/googletest/archive/eb9225ce361affe561592e0912320b9db84985d0.zip",
    sha256 = "a7db7d1295ce46b93f3d1a90dbbc55a48409c00d19684fcd87823037add88118",
)

http_archive(
    name = "rapidjson",
    urls = [
        "https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz",
    ],
    sha256 = "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e",
    strip_prefix = "rapidjson-1.1.0",
    build_file = "//:third_party/rapidjson.BUILD.bazel",
)

http_archive(
    name = "aws_cpp_sdk",
    # Must be in sync with defines in third_party/aws_sdk_cpp.BUILD.bazel.
    urls = [
        "https://github.com/aws/aws-sdk-cpp/archive/1.4.80.tar.gz",
    ],
    strip_prefix = "aws-sdk-cpp-1.4.80/",
    build_file = "//:third_party/aws_sdk_cpp.BUILD.bazel",
)

http_archive(
    name = "curl",
    urls = [
        "https://mirror.bazel.build/curl.haxx.se/download/curl-7.49.1.tar.gz",
    ],
    sha256 = "ff3e80c1ca6a068428726cd7dd19037a47cc538ce58ef61c59587191039b2ca6",
    strip_prefix = "curl-7.49.1",
    build_file = "//:third_party/curl.BUILD.bazel",
)

http_archive(
    name = "zlib_archive",
    urls = [
        "https://mirror.bazel.build/zlib.net/zlib-1.2.11.tar.gz",
    ],
    sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",
    strip_prefix = "zlib-1.2.11",
    build_file = "//:third_party/zlib.BUILD.bazel",
)

#-----------------------------------------------------------------------------
# proto
#-----------------------------------------------------------------------------
# proto_library, cc_proto_library and java_proto_library rules implicitly depend
# on @com_google_protobuf//:proto, @com_google_protobuf//:cc_toolchain and
# @com_google_protobuf//:java_toolchain, respectively.
# This statement defines the @com_google_protobuf repo.
http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-3.6.1.2",
    urls = ["https://github.com/google/protobuf/archive/v3.6.1.2.zip"],
    sha256 = "d6618d117698132dadf0f830b762315807dc424ba36ab9183f1f436008a2fdb6",
)

# java_lite_proto_library rules implicitly depend on
# @com_google_protobuf_javalite//:javalite_toolchain, which is the JavaLite proto
# runtime (base classes and common utilities).
http_archive(
    name = "com_google_protobuf_javalite",
    strip_prefix = "protobuf-384989534b2246d413dbcd750744faab2607b516",
    urls = ["https://github.com/google/protobuf/archive/384989534b2246d413dbcd750744faab2607b516.zip"],
    sha256 = "79d102c61e2a479a0b7e5fc167bcfaa4832a0c6aad4a75fa7da0480564931bcc",
)

#-----------------------------------------------------------------------------
# java
#-----------------------------------------------------------------------------

# android sdk
android_sdk_repository(
    name = "androidsdk",
    # Tink uses features in Android Keystore that are only supported at this
    # level or newer.
    # See https://developer.android.com/training/articles/keystore.html.
    api_level = 23, # M
)

load("@bazel_tools//tools/build_defs/repo:java.bzl", "java_import_external")

################################################################################
# BEGIN BAZEL MAVEN CONFIG GENERATOR
# go/bazel-maven-config-generator
#   args4j:args4j:2.33
#   com.amazonaws:aws-java-sdk-core:1.11.166
#   com.amazonaws:aws-java-sdk-kms:1.11.166
#   com.google.auto:auto-common:0.8
#   com.google.auto.service:auto-service:1.0-rc3
#   com.google.api-client:google-api-client:1.22.0
#   com.google.apis:google-api-services-cloudkms:v1-rev4-1.22.0
#   com.google.code.findbugs:jsr305:3.0.1
#   com.google.errorprone:error_prone_annotations:2.0.19
#   com.google.oauth-client:google-oauth-client:1.22.0
#   org.json:json:20170516
#   junit:junit_4:4.12
#   org.mockito:mockito-core:2.8.47
#   com.google.truth:truth:0.32

java_import_external(
    name = "args4j",
    licenses = ["notice"],  # MIT License
    jar_sha256 = "91ddeaba0b24adce72291c618c00bbdce1c884755f6c4dba9c5c46e871c69ed6",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/args4j/args4j/2.33/args4j-2.33.jar",
        "https://repo1.maven.org/maven2/args4j/args4j/2.33/args4j-2.33.jar",
    ],
)

java_import_external(
    name = "com_amazonaws_aws_java_sdk_core",
    licenses = ["notice"],  # Apache License, Version 2.0
    jar_sha256 = "be81b204f0ddf069a4c1f44f7e06971351aab725cbf85f542bd8dc8fdf50d5c9",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/amazonaws/aws-java-sdk-core/1.11.166/aws-java-sdk-core-1.11.166.jar",
        "https://repo1.maven.org/maven2/com/amazonaws/aws-java-sdk-core/1.11.166/aws-java-sdk-core-1.11.166.jar",
    ],
    deps = [
        "@commons_logging",
        "@org_apache_httpcomponents_httpclient",
        "@software_amazon_ion_java",
        "@com_fasterxml_jackson_core_jackson_databind",
        "@com_fasterxml_jackson_dataformat_cbor",
        "@joda_time",
    ],
)

java_import_external(
    name = "com_amazonaws_aws_java_sdk_kms",
    licenses = ["notice"],  # Apache License, Version 2.0
    jar_sha256 = "e690e02028709196ace0eb3725f06c032242e40d187171fb4fe4cdc04cf0eec5",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/amazonaws/aws-java-sdk-kms/1.11.166/aws-java-sdk-kms-1.11.166.jar",
        "https://maven.ibiblio.org/maven2/com/amazonaws/aws-java-sdk-kms/1.11.166/aws-java-sdk-kms-1.11.166.jar",
    ],
    deps = [
        "@com_amazonaws_aws_java_sdk_core",
        "@com_amazonaws_jmespath_java",
    ],
)

java_import_external(
    name = "com_amazonaws_jmespath_java",
    licenses = ["notice"],  # Apache License, Version 2.0
    jar_sha256 = "75e44f769a29f9d92f3dc481f38fb5ee2066fbb0c2bdd94a75f12f193962d997",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/amazonaws/jmespath-java/1.11.166/jmespath-java-1.11.166.jar",
        "https://repo1.maven.org/maven2/com/amazonaws/jmespath-java/1.11.166/jmespath-java-1.11.166.jar",
    ],
    deps = ["@com_fasterxml_jackson_core_jackson_databind"],
)

java_import_external(
    name = "com_fasterxml_jackson_core",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "918c04b9f9043d51dead2192b5d94d9f065870c9f26c8defbe9c6dbc951f304f",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.6.7/jackson-core-2.6.7.jar",
        "https://maven.ibiblio.org/maven2/com/fasterxml/jackson/core/jackson-core/2.6.7/jackson-core-2.6.7.jar",
    ],
)

java_import_external(
    name = "com_fasterxml_jackson_core_jackson_annotations",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "03348c047d981376cc444fc466cd80bda8d7eb0698dc6a99dd52c5aa15eff5ad",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.6.0/jackson-annotations-2.6.0.jar",
        "https://maven.ibiblio.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.6.0/jackson-annotations-2.6.0.jar",
    ],
)

java_import_external(
    name = "com_fasterxml_jackson_core_jackson_databind",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "c6b6043c6880697536f4ae3b9fad09517081ea22b966f0a084fa2d0c515e0a4a",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.6.7.1/jackson-databind-2.6.7.1.jar",
        "https://maven.ibiblio.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.6.7.1/jackson-databind-2.6.7.1.jar",
    ],
    deps = [
        "@com_fasterxml_jackson_core_jackson_annotations",
        "@com_fasterxml_jackson_core",
    ],
)

java_import_external(
    name = "com_fasterxml_jackson_dataformat_cbor",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "956a0fb9186a796b8a6548909da1ee55004279647e261c7f540e5d49d4f199bf",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/fasterxml/jackson/dataformat/jackson-dataformat-cbor/2.6.7/jackson-dataformat-cbor-2.6.7.jar",
        "https://repo1.maven.org/maven2/com/fasterxml/jackson/dataformat/jackson-dataformat-cbor/2.6.7/jackson-dataformat-cbor-2.6.7.jar",
    ],
    deps = ["@com_fasterxml_jackson_core"],
)

java_import_external(
    name = "com_google_api_client",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "47c625c83a8cf97b8bbdff2acde923ff8fd3174e62aabcfc5d1b86692594ffba",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/google/api-client/google-api-client/1.22.0/google-api-client-1.22.0.jar",
        "https://maven.ibiblio.org/maven2/com/google/api-client/google-api-client/1.22.0/google-api-client-1.22.0.jar",
    ],
    deps = [
        "@com_google_oauth_client",
        "@com_google_http_client_jackson2",
        "@commons_codec",
    ],
)

java_import_external(
    name = "com_google_apis_google_api_services_cloudkms",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "0a991ab42838b2eb80b9880e34c25ab8076a1472a2b485dd3c8911509327f494",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/google/apis/google-api-services-cloudkms/v1-rev4-1.22.0/google-api-services-cloudkms-v1-rev4-1.22.0.jar",
        "https://maven.ibiblio.org/maven2/com/google/apis/google-api-services-cloudkms/v1-rev4-1.22.0/google-api-services-cloudkms-v1-rev4-1.22.0.jar",
    ],
    deps = ["@com_google_api_client"],
)

java_import_external(
    name = "com_google_auto_common",
    licenses = ["notice"],  # Apache 2.0
    jar_sha256 = "97db1709f57b91b32edacb596ef4641872f227b7d99ad90e467f0d77f5ba134a",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/google/auto/auto-common/0.8/auto-common-0.8.jar",
        "https://maven.ibiblio.org/maven2/com/google/auto/auto-common/0.8/auto-common-0.8.jar",
    ],
    deps = ["@com_google_guava"],
)

java_import_external(
    name = "com_google_auto_service",
    licenses = ["notice"],  # Apache 2.0
    jar_sha256 = "f68e20cc5aba8ad1759d2779c2b3725cc0bd9420c40e7b464a796b8ca1499e9e",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/google/auto/service/auto-service/1.0-rc3/auto-service-1.0-rc3.jar",
        "https://repo1.maven.org/maven2/com/google/auto/service/auto-service/1.0-rc3/auto-service-1.0-rc3.jar",
    ],
    deps = [
        "@com_google_auto_common",
        "@com_google_guava",
    ],
)

java_import_external(
    name = "com_google_auto_value",
    neverlink = 1,
    licenses = ["notice"],  # Apache 2.0
    jar_sha256 = "fd6fb139d97b427c321eb9370aeb29394e35d22d595166ca9071457448fa5660",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/google/auto/value/auto-value/1.0/auto-value-1.0.jar",
        "https://maven.ibiblio.org/maven2/com/google/auto/value/auto-value/1.0/auto-value-1.0.jar",
    ],
)

java_import_external(
    name = "com_google_code_findbugs_annotations",
    neverlink = 1,
    licenses = ["restricted"],  # GNU Lesser Public License
    jar_sha256 = "acc0d2c06be70e9094d70cd05dffa077735c8f9d1a870eafda130b0592528200",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/google/code/findbugs/annotations/3.0.1u2/annotations-3.0.1u2.jar",
        "https://repo1.maven.org/maven2/com/google/code/findbugs/annotations/3.0.1u2/annotations-3.0.1u2.jar",
    ],
    deps = [
        "@com_google_code_findbugs_jsr305",
    ],
)

java_import_external(
    name = "com_google_code_findbugs_jsr305",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "c885ce34249682bc0236b4a7d56efcc12048e6135a5baf7a9cde8ad8cda13fcd",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/google/code/findbugs/jsr305/3.0.1/jsr305-3.0.1.jar",
        "https://repo1.maven.org/maven2/com/google/code/findbugs/jsr305/3.0.1/jsr305-3.0.1.jar",
    ],
)

java_import_external(
    name = "com_google_errorprone_error_prone_annotations",
    licenses = ["notice"],  # Apache 2.0
    jar_sha256 = "cde78ace21e46398299d0d9c6be9f47b7f971c7f045d40c78f95be9a638cbf7e",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/google/errorprone/error_prone_annotations/2.0.19/error_prone_annotations-2.0.19.jar",
        "https://maven.ibiblio.org/maven2/com/google/errorprone/error_prone_annotations/2.0.19/error_prone_annotations-2.0.19.jar",
    ],
)

java_import_external(
    name = "com_google_guava",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "36a666e3b71ae7f0f0dca23654b67e086e6c93d192f60ba5dfd5519db6c288c8",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/google/guava/guava/20.0/guava-20.0.jar",
        "https://repo1.maven.org/maven2/com/google/guava/guava/20.0/guava-20.0.jar",
    ],
)

java_import_external(
    name = "com_google_http_client",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "f88ffa329ac52fb4f2ff0eb877ef7318423ac9b791a107f886ed5c7a00e77e11",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/google/http-client/google-http-client/1.22.0/google-http-client-1.22.0.jar",
        "https://maven.ibiblio.org/maven2/com/google/http-client/google-http-client/1.22.0/google-http-client-1.22.0.jar",
    ],
    deps = [
        "@com_google_code_findbugs_jsr305",
        "@org_apache_httpcomponents_httpclient",
        "@commons_codec",
    ],
)

java_import_external(
    name = "com_google_http_client_jackson2",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "45b1e34b2dcef5cb496ef25a1223d19cf102b8c2ea4abf96491631b2faf4611c",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/google/http-client/google-http-client-jackson2/1.22.0/google-http-client-jackson2-1.22.0.jar",
        "https://repo1.maven.org/maven2/com/google/http-client/google-http-client-jackson2/1.22.0/google-http-client-jackson2-1.22.0.jar",
    ],
    deps = [
        "@com_google_http_client",
        "@com_fasterxml_jackson_core",
    ],
)

java_import_external(
    name = "com_google_oauth_client",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "a4c56168b3e042105d68cf136e40e74f6e27f63ed0a948df966b332678e19022",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/google/oauth-client/google-oauth-client/1.22.0/google-oauth-client-1.22.0.jar",
        "https://repo1.maven.org/maven2/com/google/oauth-client/google-oauth-client/1.22.0/google-oauth-client-1.22.0.jar",
    ],
    deps = [
        "@com_google_http_client",
        "@com_google_code_findbugs_jsr305",
    ],
)

java_import_external(
    name = "com_google_truth",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "032eddc69652b0a1f8d458f999b4a9534965c646b8b5de0eba48ee69407051df",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/google/truth/truth/0.32/truth-0.32.jar",
        "https://maven.ibiblio.org/maven2/com/google/truth/truth/0.32/truth-0.32.jar",
    ],
    deps = [
        "@com_google_guava",
        "@junit",
        "@com_google_auto_value",
        "@com_google_errorprone_error_prone_annotations",
    ],
)

java_import_external(
    name = "commons_codec",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "ad19d2601c3abf0b946b5c3a4113e226a8c1e3305e395b90013b78dd94a723ce",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/commons-codec/commons-codec/1.9/commons-codec-1.9.jar",
        "https://repo1.maven.org/maven2/commons-codec/commons-codec/1.9/commons-codec-1.9.jar",
    ],
)

java_import_external(
    name = "commons_logging",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "daddea1ea0be0f56978ab3006b8ac92834afeefbd9b7e4e6316fca57df0fa636",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar",
        "https://repo1.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar",
    ],
)

java_import_external(
    name = "joda_time",
    licenses = ["notice"],  # Apache 2
    jar_sha256 = "b4670b95f75957c974284c5f3ada966040be2578f643c5c6083d262162061fa2",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/joda-time/joda-time/2.8.1/joda-time-2.8.1.jar",
        "https://repo1.maven.org/maven2/joda-time/joda-time/2.8.1/joda-time-2.8.1.jar",
    ],
)

java_import_external(
    name = "junit",
    licenses = ["reciprocal"],  # Eclipse Public License 1.0
    jar_sha256 = "59721f0805e223d84b90677887d9ff567dc534d7c502ca903c0c2b17f05c116a",
    jar_urls = [
        "https://repo1.maven.org/maven2/junit/junit/4.12/junit-4.12.jar",
        "https://maven.ibiblio.org/maven2/junit/junit/4.12/junit-4.12.jar",
    ],
    deps = ["@org_hamcrest_core"],
)

java_import_external(
    name = "net_bytebuddy_byte_buddy",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "917758b3c651e278a15a029ba1d42dbf802d8b0e1fe2aa4b81c5750c64f461c1",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/net/bytebuddy/byte-buddy/1.6.14/byte-buddy-1.6.14.jar",
        "https://repo1.maven.org/maven2/net/bytebuddy/byte-buddy/1.6.14/byte-buddy-1.6.14.jar",
    ],
    deps = [
        "@com_google_code_findbugs_annotations",
    ],
)

java_import_external(
    name = "net_bytebuddy_byte_buddy_agent",
    licenses = ["notice"],  # The Apache Software License, Version 2.0
    jar_sha256 = "c141a2d6809c3eeff4a43d25992826abccebdd4b793af3e7a5f346e88ae73a33",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/net/bytebuddy/byte-buddy-agent/1.6.14/byte-buddy-agent-1.6.14.jar",
        "https://repo1.maven.org/maven2/net/bytebuddy/byte-buddy-agent/1.6.14/byte-buddy-agent-1.6.14.jar",
    ],
)

java_import_external(
    name = "org_apache_httpcomponents_httpclient",
    licenses = ["notice"],  # Apache License, Version 2.0
    jar_sha256 = "0dffc621400d6c632f55787d996b8aeca36b30746a716e079a985f24d8074057",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5.2/httpclient-4.5.2.jar",
        "https://maven.ibiblio.org/maven2/org/apache/httpcomponents/httpclient/4.5.2/httpclient-4.5.2.jar",
    ],
    deps = [
        "@org_apache_httpcomponents_httpcore",
        "@commons_logging",
        "@commons_codec",
    ],
)

java_import_external(
    name = "org_apache_httpcomponents_httpcore",
    licenses = ["notice"],  # Apache License, Version 2.0
    jar_sha256 = "f7bc09dc8a7003822d109634ffd3845d579d12e725ae54673e323a7ce7f5e325",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/org/apache/httpcomponents/httpcore/4.4.4/httpcore-4.4.4.jar",
        "https://repo1.maven.org/maven2/org/apache/httpcomponents/httpcore/4.4.4/httpcore-4.4.4.jar",
    ],
)

java_import_external(
    name = "org_hamcrest_core",
    licenses = ["notice"],  # New BSD License
    jar_sha256 = "66fdef91e9739348df7a096aa384a5685f4e875584cce89386a7a47251c4d8e9",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar",
        "https://maven.ibiblio.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar",
    ],
)

java_import_external(
    name = "org_json",
    licenses = ["notice"],  # The JSON License
    jar_sha256 = "813f37e4820f1854e8a4eb4f80df94bf1b1f2ec6c3b72692f23ab9a556256af6",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/org/json/json/20170516/json-20170516.jar",
        "https://repo1.maven.org/maven2/org/json/json/20170516/json-20170516.jar",
    ],
)

java_import_external(
    name = "org_mockito_core",
    licenses = ["notice"],  # The MIT License
    jar_sha256 = "c496fe3790c55c07697cf37f5062f8758591ab035900bc108ce185b48df563a0",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/mockito/mockito-core/2.8.47/mockito-core-2.8.47.jar",
        "https://maven.ibiblio.org/maven2/org/mockito/mockito-core/2.8.47/mockito-core-2.8.47.jar",
    ],
    deps = [
        "@net_bytebuddy_byte_buddy",
        "@net_bytebuddy_byte_buddy_agent",
        "@org_objenesis",
    ],
)

java_import_external(
    name = "org_objenesis",
    licenses = ["notice"],  # Apache 2
    jar_sha256 = "293328e1b0d31ed30bb89fca542b6c52fac00989bb0e62eb9d98d630c4dd6b7c",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/org/objenesis/objenesis/2.5/objenesis-2.5.jar",
        "https://repo1.maven.org/maven2/org/objenesis/objenesis/2.5/objenesis-2.5.jar",
    ],
)

java_import_external(
    name = "software_amazon_ion_java",
    licenses = ["notice"],  # The Apache License, Version 2.0
    jar_sha256 = "0d127b205a1fce0abc2a3757a041748651bc66c15cf4c059bac5833b27d471a5",
    jar_urls = [
        "https://repo1.maven.org/maven2/software/amazon/ion/ion-java/1.0.2/ion-java-1.0.2.jar",
        "https://maven.ibiblio.org/maven2/software/amazon/ion/ion-java/1.0.2/ion-java-1.0.2.jar",
    ],
)

# END BAZEL MAVEN CONFIG GENERATOR
################################################################################

#-----------------------------------------------------------------------------
# objc
#-----------------------------------------------------------------------------

http_archive(
    name = "build_bazel_rules_apple",
    strip_prefix = "rules_apple-0.13.0",
    url = "https://github.com/bazelbuild/rules_apple/archive/0.13.0.zip",
    sha256 = "3723bb1ac58a0c9f3e908b03a6c26f5ec888ace2f1267412d7c6179e58210bbb",
)

load(
    "@build_bazel_rules_apple//apple:repositories.bzl",
    "apple_rules_dependencies",
)

apple_rules_dependencies()

load(
    "@build_bazel_rules_swift//swift:repositories.bzl",
    "swift_rules_dependencies",
)

swift_rules_dependencies()

load(
    "@build_bazel_apple_support//lib:repositories.bzl",
    "apple_support_dependencies",
)

apple_support_dependencies()

http_file(
    name = "xctestrunner",
    executable = 1,
    urls = ["https://github.com/google/xctestrunner/releases/download/0.2.6/ios_test_runner.par"],
    sha256 = "15fc7d09315a230f3d8ee2913eef8699456366e44b37a9266e36b28517003628",
)

#-----------------------------------------------------------------------------
# go
#-----------------------------------------------------------------------------
http_archive(
    name = "io_bazel_rules_go",
    urls = ["https://github.com/bazelbuild/rules_go/releases/download/0.17.1/rules_go-0.17.1.tar.gz"],
    sha256 = "6776d68ebb897625dead17ae510eac3d5f6342367327875210df44dbe2aeeb19",
)

http_archive(
    name = "bazel_gazelle",
    strip_prefix = "bazel-gazelle-395b3a1c2f22d8cd63e19c92d4e1556eb3d96dde",
    urls = ["https://github.com/bazelbuild/bazel-gazelle/archive/395b3a1c2f22d8cd63e19c92d4e1556eb3d96dde.zip"],
    sha256 = "a40deb9c0cfa2e424ad9b15fe68aa3d259ccb0ef6405dd4fe0506d86d75b8475",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")
go_rules_dependencies()
go_register_toolchains(nogo="@//go:tink_nogo")

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
gazelle_dependencies()

go_repository(
    name = "org_golang_x_crypto",
    commit = "0e37d006457bf46f9e6692014ba72ef82c33022c",
    importpath = "golang.org/x/crypto",
)

go_repository(
    name = "org_golang_x_sys",
    commit = "d0be0721c37eeb5299f245a996a483160fc36940",
    importpath = "golang.org/x/sys",
)

go_repository(
    name = "org_golang_google_api",
    commit = "3097bf831ede4a24e08a3316254e29ca726383e3",
    importpath = "google.golang.org/api",
)

go_repository(
    name = "org_golang_x_oauth2",
    commit = "ef147856a6ddbb60760db74283d2424e98c87bff",
    importpath = "golang.org/x/oauth2",
)

go_repository(
    name = "com_google_cloud_go",
    commit = "777200caa7fb8936aed0f12b1fd79af64cc83ec9",
    importpath = "cloud.google.com/go",
)

go_repository(
    name = "com_github_aws_sdk_go",
    commit = "182cda27d0921b14139ff6d352c09e0cb20e4578",
    importpath = "github.com/aws/aws-sdk-go",
)


#-----------------------------------------------------------------------------
# Javascript
#-----------------------------------------------------------------------------

http_archive(
    name = "io_bazel_rules_closure",
    sha256 = "319e5e0127a83436b55588877a9d81464c2780c0dffc809065cf299d772670f5",
    strip_prefix = "rules_closure-87d24b1df8b62405de8dd059cb604fd9d4b1e395",
    urls = [
        "https://github.com/bazelbuild/rules_closure/archive/87d24b1df8b62405de8dd059cb604fd9d4b1e395.zip",
    ],
)


load("@io_bazel_rules_closure//closure:defs.bzl", "closure_repositories")

closure_repositories()


workspace(name = "tink")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

#-----------------------------------------------------------------------------
# Basic rules we need to add to bazel.
#-----------------------------------------------------------------------------
# Release from 2019-10-09
http_archive(
    name = "bazel_skylib",
    url = "https://github.com/bazelbuild/bazel-skylib/releases/download/1.0.2/bazel-skylib-1.0.2.tar.gz",
    sha256 = "97e70364e9249702246c0e9444bccdc4b847bed1eb03c5a3ece4f83dfe6abc44",
)

#-----------------------------------------------------------------------------
# Google PKI certs for connecting to GCP KMS
#-----------------------------------------------------------------------------

http_file(
    name = "google_root_pem",
    executable = 0,
    urls = [
        "https://pki.goog/roots.pem",
    ],
    sha256 = "7f03c894282e3fc39105466a8ee5055ffd05e79dfd4010360117078afbfa68bd",
)

#-----------------------------------------------------------------------------
# wycheproof, for JSON test vectors
#-----------------------------------------------------------------------------
# Commit from 2018-07-31
http_archive(
    name = "wycheproof",
    strip_prefix = "wycheproof-f89f4c53a8845fcefcdb9f14ee9191dbe167e3e3",
    url = "https://github.com/google/wycheproof/archive/f89f4c53a8845fcefcdb9f14ee9191dbe167e3e3.zip",
    sha256 = "b44bb0339ad149e6cdab1337445cf52440cbfc79684203a3db1c094d9ef8daea",
)

#-----------------------------------------------------------------------------
# cc
#-----------------------------------------------------------------------------
# LTS release from 2019-08-08
http_archive(
    name = "com_google_absl",
    strip_prefix = "abseil-cpp-20190808",
    url = "https://github.com/abseil/abseil-cpp/archive/20190808.zip",
    sha256 = "0b62fc2d00c2b2bc3761a892a17ac3b8af3578bd28535d90b4c914b0a7460d4e",
)

# Commit from 2018-08-16
http_archive(
    name = "boringssl",
    strip_prefix = "boringssl-18637c5f37b87e57ebde0c40fe19c1560ec88813",
    url = "https://github.com/google/boringssl/archive/18637c5f37b87e57ebde0c40fe19c1560ec88813.zip",
    sha256 = "bd923e59fca0d2b50db09af441d11c844c5e882a54c68943b7fc39a8cb5dd211",
)

# GoogleTest/GoogleMock framework. Used by most C++ unit-tests.
# Release from 2019-10-03
http_archive(
    name = "com_google_googletest",
    strip_prefix = "googletest-1.10.x",
    url = "https://github.com/google/googletest/archive/v1.10.x.zip",
    sha256 = "54a139559cc46a68cf79e55d5c22dc9d48e647a66827342520ce0441402430fe",
)

# Release from 2016-08-25; still the latest release on 2019-10-18
http_archive(
    name = "rapidjson",
    urls = [
        "https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz",
    ],
    sha256 = "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e",
    strip_prefix = "rapidjson-1.1.0",
    build_file = "//:third_party/rapidjson.BUILD.bazel",
)

# Release from 2018-07-04
http_archive(
    name = "aws_cpp_sdk",
    # Must be in sync with defines in third_party/aws_sdk_cpp.BUILD.bazel.
    urls = [
        "https://github.com/aws/aws-sdk-cpp/archive/1.4.80.tar.gz",
    ],
    strip_prefix = "aws-sdk-cpp-1.4.80",
    build_file = "//:third_party/aws_sdk_cpp.BUILD.bazel",
)

# Needed for Cloud KMS API via gRPC.
# Commit from 2019-10-11
http_archive(
    name = "googleapis",
    urls = [
        "https://github.com/googleapis/googleapis/archive/192d3d8221175f7cc0aa8eeac1d820f47c53da7f.zip",
    ],
    sha256 = "6b5a017082eade41c7efcc4d2f441422e41c0a0c57dd88e19d3ebfb1b8ff4f12",
    strip_prefix = "googleapis-192d3d8221175f7cc0aa8eeac1d820f47c53da7f",
    patches = ["@//third_party:googleapis.patch"],
)

load("@googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,
    grpc = True,
)

# gRPC.
# Release from 2019-08-15
http_archive(
    name = "com_github_grpc_grpc",
    urls = [
        "https://github.com/grpc/grpc/archive/v1.22.1.tar.gz",
    ],
    sha256 = "cce1d4585dd017980d4a407d8c5e9f8fc8c1dbb03f249b99e88a387ebb45a035",
    strip_prefix = "grpc-1.22.1",
)

# Load grpc_deps.
# This is a workaround around the missing support for recursive WORKSPACE
# file loading (https://github.com/bazelbuild/bazel/issues/1943).
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()

# Release from 2016-05-30
http_archive(
    name = "curl",
    urls = [
        "https://mirror.bazel.build/curl.haxx.se/download/curl-7.49.1.tar.gz",
    ],
    sha256 = "ff3e80c1ca6a068428726cd7dd19037a47cc538ce58ef61c59587191039b2ca6",
    strip_prefix = "curl-7.49.1",
    build_file = "//:third_party/curl.BUILD.bazel",
)

# Releaes from 2017-01-15; still most recent release on 2019-10-18
http_archive(
    name = "zlib",
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
# Release from 2019-08-05
http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-3.9.1",
    urls = ["https://github.com/google/protobuf/archive/v3.9.1.zip"],
    sha256 = "c90d9e13564c0af85fd2912545ee47b57deded6e5a97de80395b6d2d9be64854",
)

# Load protobuf_deps.
# This is a workaround around the missing support for recursive WORKSPACE
# file loading (https://github.com/bazelbuild/bazel/issues/1943).
load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

# java_lite_proto_library rules implicitly depend on
# @com_google_protobuf_javalite//:javalite_toolchain, which is the JavaLite proto
# runtime (base classes and common utilities).
# Commit from 2019-08-23 on the javalite branch.
http_archive(
    name = "com_google_protobuf_javalite",
    strip_prefix = "protobuf-7b64714af67aa967dcf941df61fe5207975966be",
    urls = ["https://github.com/google/protobuf/archive/7b64714af67aa967dcf941df61fe5207975966be.zip"],
    sha256 = "311b29b8d0803ab4f89be22ff365266abb6c48fd3483d59b04772a144d7a24a1",
)

#-----------------------------------------------------------------------------
# java
#-----------------------------------------------------------------------------

# Not used by Java Tink, but apparently needed for C++ gRPC library.
# Commit from 2019-05-02
http_archive(
    name = "io_grpc_grpc_java",
    strip_prefix = "grpc-java-1.20.0",
    urls = [
        "https://github.com/grpc/grpc-java/archive/v1.20.0.tar.gz",
    ],
    sha256 = "553d1bdbde3ff4035747c184486bae2f084c75c3c4cdf5ef31a6aa48bdccaf9b",
)

# Release from 2019-08-14
http_archive(
    name = "rules_jvm_external",
    strip_prefix = "rules_jvm_external-2.7",
    sha256 = "f04b1466a00a2845106801e0c5cec96841f49ea4e7d1df88dc8e4bf31523df74",
    url = "https://github.com/bazelbuild/rules_jvm_external/archive/2.7.zip",
)

load("@rules_jvm_external//:defs.bzl", "maven_install")

maven_install(
    artifacts = [
        "args4j:args4j:2.33",
        "com.amazonaws:aws-java-sdk-core:1.11.625",
        "com.amazonaws:aws-java-sdk-kms:1.11.625",
        "com.google.auto:auto-common:0.10",
        "com.google.auto.service:auto-service:1.0-rc6",
        "com.google.auto.service:auto-service-annotations:1.0-rc6",
        "com.google.api-client:google-api-client:1.22.0",
        "com.google.apis:google-api-services-cloudkms:v1-rev89-1.25.0",
        "com.google.code.findbugs:jsr305:3.0.1",
        "com.google.errorprone:error_prone_annotations:2.3.3",
        "com.google.http-client:google-http-client:1.31.0",
        "com.google.http-client:google-http-client-jackson2:1.31.0",
        "com.google.oauth-client:google-oauth-client:1.30.1",
        "com.google.truth:truth:0.42",
        "org.json:json:20170516",
        "joda-time:joda-time:2.10.3",
        "junit:junit:4.12",
        "org.mockito:mockito-core:2.23.0",
    ],
    repositories = [
        "https://jcenter.bintray.com/",
        "https://maven.google.com",
        "https://repo1.maven.org/maven2",
    ],
)

#-----------------------------------------------------------------------------
# Android
#-----------------------------------------------------------------------------
# android sdk
android_sdk_repository(
    name = "androidsdk",
    # Tink uses features in Android Keystore that are only supported at this
    # level or newer.
    # See https://developer.android.com/training/articles/keystore.html.
    api_level = 23,  # M
)

# Last release from 2018-08-07.
http_archive(
    name = "build_bazel_rules_android",
    urls = ["https://github.com/bazelbuild/rules_android/archive/v0.1.1.zip"],
    sha256 = "cd06d15dd8bb59926e4d65f9003bfc20f9da4b2519985c27e190cddc8b7a7806",
    strip_prefix = "rules_android-0.1.1",
)

#-----------------------------------------------------------------------------
# objc
#-----------------------------------------------------------------------------

# Release from 2019-10-10
http_archive(
    name = "build_bazel_rules_apple",
    strip_prefix = "rules_apple-0.19.0",
    url = "https://github.com/bazelbuild/rules_apple/archive/0.19.0.zip",
    sha256 = "9f9eb6cdd25d7932cb939df24807c2d70772aad7a79f1357e25ced9d0d443cfd",
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

#-----------------------------------------------------------------------------
# go
#-----------------------------------------------------------------------------
# Release from 2019-10-14
http_archive(
    name = "io_bazel_rules_go",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/rules_go/releases/download/v0.20.0/rules_go-v0.20.0.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.20.0/rules_go-v0.20.0.tar.gz",
    ],
    sha256 = "078f2a9569fa9ed846e60805fb5fb167d6f6c4ece48e6d409bf5fb2154eaf0d8",
)

# Release from 2019-10-14
http_archive(
    name = "bazel_gazelle",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/bazel-gazelle/releases/download/v0.19.0/bazel-gazelle-v0.19.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.19.0/bazel-gazelle-v0.19.0.tar.gz",
    ],
    sha256 = "41bff2a0b32b02f20c227d234aa25ef3783998e5453f7eade929704dcff7cd4b",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains(nogo = "@//go:tink_nogo")

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

# How to update go dependencies:
# 1) Remove all go_repository rules in WORKSPACE.bazel
# 2) Update the files go.mod and go.sum. This can be done as follows:
#    2.1) Replacing all versions in go.mod with "latest".
#    2.2) Run "go mod tidy".
# 3) Update the WORKSPACE.bazel file by running
#    bazel run //:gazelle -- update-repos -from_file=go.mod
# Put the go repository rules in the right place.

go_repository(
    name = "co_honnef_go_tools",
    importpath = "honnef.co/go/tools",
    sum = "h1:LJwr7TCTghdatWv40WobzlKXc9c4s8oGa7QKJUtHhWA=",
    version = "v0.0.0-20190418001031-e561f6794a2a",
)

go_repository(
    name = "com_github_aws_aws_sdk_go",
    importpath = "github.com/aws/aws-sdk-go",
    sum = "h1:k7Fy6T/uNuLX6zuayU/TJoP7yMgGcJSkZpF7QVjwYpA=",
    version = "v1.25.16",
)

go_repository(
    name = "com_github_burntsushi_toml",
    importpath = "github.com/BurntSushi/toml",
    sum = "h1:WXkYYl6Yr3qBf1K79EBnL4mak0OimBfB0XUf9Vl28OQ=",
    version = "v0.3.1",
)

go_repository(
    name = "com_github_client9_misspell",
    importpath = "github.com/client9/misspell",
    sum = "h1:ta993UF76GwbvJcIo3Y68y/M3WxlpEHPWIGDkJYwzJI=",
    version = "v0.3.4",
)

go_repository(
    name = "com_github_davecgh_go_spew",
    importpath = "github.com/davecgh/go-spew",
    sum = "h1:ZDRjVQ15GmhC3fiQ8ni8+OwkZQO4DARzQgrnXU1Liz8=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_golang_glog",
    importpath = "github.com/golang/glog",
    sum = "h1:VKtxabqXZkF25pY9ekfRL6a582T4P37/31XEstQ5p58=",
    version = "v0.0.0-20160126235308-23def4e6c14b",
)

go_repository(
    name = "com_github_golang_mock",
    importpath = "github.com/golang/mock",
    sum = "h1:28o5sBqPkBsMGnC6b4MvE2TzSr5/AT4c/1fLqVGIwlk=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_golang_protobuf",
    importpath = "github.com/golang/protobuf",
    sum = "h1:6nsPYzhq5kReh6QImI3k5qWzO4PEbvbIW2cwSfR/6xs=",
    version = "v1.3.2",
)

go_repository(
    name = "com_github_google_btree",
    importpath = "github.com/google/btree",
    sum = "h1:964Od4U6p2jUkFxvCydnIczKteheJEzHRToSGK3Bnlw=",
    version = "v0.0.0-20180813153112-4030bb1f1f0c",
)

go_repository(
    name = "com_github_google_go_cmp",
    importpath = "github.com/google/go-cmp",
    sum = "h1:crn/baboCvb5fXaQ0IJ1SGTsTVrWpDsCWC8EGETZijY=",
    version = "v0.3.0",
)

go_repository(
    name = "com_github_google_martian",
    importpath = "github.com/google/martian",
    sum = "h1:/CP5g8u/VJHijgedC/Legn3BAbAaWPgecwXBIDzw5no=",
    version = "v2.1.0+incompatible",
)

go_repository(
    name = "com_github_google_pprof",
    importpath = "github.com/google/pprof",
    sum = "h1:eqyIo2HjKhKe/mJzTG8n4VqvLXIOEG+SLdDqX7xGtkY=",
    version = "v0.0.0-20181206194817-3ea8567a2e57",
)

go_repository(
    name = "com_github_googleapis_gax_go_v2",
    importpath = "github.com/googleapis/gax-go/v2",
    sum = "h1:sjZBwGj9Jlw33ImPtvFviGYvseOtDM7hkSKB7+Tv3SM=",
    version = "v2.0.5",
)

go_repository(
    name = "com_github_hashicorp_golang_lru",
    importpath = "github.com/hashicorp/golang-lru",
    sum = "h1:0hERBMJE1eitiLkihrMvRVBYAkpHzc/J3QdDN+dAcgU=",
    version = "v0.5.1",
)

go_repository(
    name = "com_github_jmespath_go_jmespath",
    importpath = "github.com/jmespath/go-jmespath",
    sum = "h1:pmfjZENx5imkbgOkpRUYLnmbU7UEFbjtDA2hxJ1ichM=",
    version = "v0.0.0-20180206201540-c2b33e8439af",
)

go_repository(
    name = "com_github_jstemmer_go_junit_report",
    importpath = "github.com/jstemmer/go-junit-report",
    sum = "h1:rBMNdlhTLzJjJSDIjNEXX1Pz3Hmwmz91v+zycvx9PJc=",
    version = "v0.0.0-20190106144839-af01ea7f8024",
)

go_repository(
    name = "com_github_pmezard_go_difflib",
    importpath = "github.com/pmezard/go-difflib",
    sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_stretchr_objx",
    importpath = "github.com/stretchr/objx",
    sum = "h1:4G4v2dO3VZwixGIRoQ5Lfboy6nUhCyYzaqnIAPPhYs4=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_stretchr_testify",
    importpath = "github.com/stretchr/testify",
    sum = "h1:2E4SXV/wtOkTonXsotYi4li6zVWxYlZuYNCXe9XRJyk=",
    version = "v1.4.0",
)

go_repository(
    name = "com_google_cloud_go",
    importpath = "cloud.google.com/go",
    sum = "h1:ROfEUZz+Gh5pa62DJWXSaonyu3StP6EA6lPEXPI6mCo=",
    version = "v0.38.0",
)

go_repository(
    name = "in_gopkg_check_v1",
    importpath = "gopkg.in/check.v1",
    sum = "h1:yhCVgyC4o1eVCa2tZl7eS0r+SDo693bJlVdllGtEeKM=",
    version = "v0.0.0-20161208181325-20d25e280405",
)

go_repository(
    name = "in_gopkg_yaml_v2",
    importpath = "gopkg.in/yaml.v2",
    sum = "h1:ZCJp+EgiOT7lHqUV2J862kp8Qj64Jo6az82+3Td9dZw=",
    version = "v2.2.2",
)

go_repository(
    name = "io_opencensus_go",
    importpath = "go.opencensus.io",
    sum = "h1:mU6zScU4U1YAFPHEHYk+3JC4SY7JxgkqS10ZOSyksNg=",
    version = "v0.21.0",
)

go_repository(
    name = "org_golang_google_api",
    importpath = "google.golang.org/api",
    sum = "h1:n/qM3q0/rV2F0pox7o0CvNhlPvZAo7pLbef122cbLJ0=",
    version = "v0.11.0",
)

go_repository(
    name = "org_golang_google_appengine",
    importpath = "google.golang.org/appengine",
    sum = "h1:KxkO13IPW4Lslp2bz+KHP2E3gtFlrIGNThxkZQ3g+4c=",
    version = "v1.5.0",
)

go_repository(
    name = "org_golang_google_genproto",
    importpath = "google.golang.org/genproto",
    sum = "h1:nfPFGzJkUDX6uBmpN/pSw7MbOAWegH5QDQuoXFHedLg=",
    version = "v0.0.0-20190502173448-54afdca5d873",
)

go_repository(
    name = "org_golang_google_grpc",
    importpath = "google.golang.org/grpc",
    sum = "h1:Hz2g2wirWK7H0qIIhGIqRGTuMwTE8HEKFnDZZ7lm9NU=",
    version = "v1.20.1",
)

go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto",
    sum = "h1:ObdrDkeb4kJdCP557AjRjq69pTHfNouLtWZG7j9rPN8=",
    version = "v0.0.0-20191011191535-87dc89f01550",
)

go_repository(
    name = "org_golang_x_exp",
    importpath = "golang.org/x/exp",
    sum = "h1:c2HOrn5iMezYjSlGPncknSEr/8x5LELb/ilJbXi9DEA=",
    version = "v0.0.0-20190121172915-509febef88a4",
)

go_repository(
    name = "org_golang_x_lint",
    importpath = "golang.org/x/lint",
    sum = "h1:QzoH/1pFpZguR8NrRHLcO6jKqfv2zpuSqZLgdm7ZmjI=",
    version = "v0.0.0-20190409202823-959b441ac422",
)

go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net",
    sum = "h1:uOCk1iQW6Vc18bnC13MfzScl+wdKBmM9Y9kU7Z83/lw=",
    version = "v0.0.0-20190503192946-f4e77d36d62c",
)

go_repository(
    name = "org_golang_x_oauth2",
    importpath = "golang.org/x/oauth2",
    sum = "h1:SVwTIAaPC2U/AvvLNZ2a7OVsmBpC8L5BlwK1whH3hm0=",
    version = "v0.0.0-20190604053449-0f29369cfe45",
)

go_repository(
    name = "org_golang_x_sync",
    importpath = "golang.org/x/sync",
    sum = "h1:8gQV6CLnAEikrhgkHFbMAEhagSSnXWGV915qUMm9mrU=",
    version = "v0.0.0-20190423024810-112230192c58",
)

go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    sum = "h1:ag/x1USPSsqHud38I9BAC88qdNLDHHtQ4mlgQIZPPNA=",
    version = "v0.0.0-20190507160741-ecd444e8653b",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    sum = "h1:tW2bmiBqwgJj/UpqtC8EpXEZVYOwU0yG4iWbprSVAcs=",
    version = "v0.3.2",
)

go_repository(
    name = "org_golang_x_time",
    importpath = "golang.org/x/time",
    sum = "h1:fqgJT0MGcGpPgpWU7VRdRjuArfcOvC4AoJmILihzhDg=",
    version = "v0.0.0-20181108054448-85acf8d2951c",
)

go_repository(
    name = "org_golang_x_tools",
    importpath = "golang.org/x/tools",
    sum = "h1:97SnQk1GYRXJgvwZ8fadnxDOWfKvkNQHH3CtZntPSrM=",
    version = "v0.0.0-20190506145303-2d16b83fe98c",
)

go_repository(
    name = "com_github_hashicorp_vault",
    importpath = "github.com/hashicorp/vault",
    tag = "v1.2.3",
)

#-----------------------------------------------------------------------------
# Javascript
#-----------------------------------------------------------------------------

# Last update: 2019-10-18, to latest release.
http_archive(
    name = "io_bazel_rules_closure",
    sha256 = "7d206c2383811f378a5ef03f4aacbcf5f47fd8650f6abbc3fa89f3a27dd8b176",
    strip_prefix = "rules_closure-0.10.0",
    urls = [
        "https://github.com/bazelbuild/rules_closure/archive/0.10.0.tar.gz",
    ],
)

load("@io_bazel_rules_closure//closure:repositories.bzl",
     "rules_closure_dependencies", "rules_closure_toolchains")
rules_closure_dependencies()
rules_closure_toolchains()

#-----------------------------------------------------------------------------
# Python
#-----------------------------------------------------------------------------
load("//third_party/py:python_configure.bzl", "python_configure")

python_configure(name = "local_config_python")

# Commit from 2019-10-09
http_archive(
    name = "rules_python",
    strip_prefix = "rules_python-5aa465d5d91f1d9d90cac10624e3d2faf2057bd5/",
    url = "https://github.com/bazelbuild/rules_python/archive/5aa465d5d91f1d9d90cac10624e3d2faf2057bd5.zip",
    sha256 = "84923d1907d4ab47e7276ab1d64564c52b01cb31d14d62c8a4e5699ec198cb37",
)

new_local_repository(
    name = "clif",
    build_file = "third_party/clif.BUILD.bazel",
    path = "/usr/local",
)

#-----------------------------------------------------------------------------
# Remote Build Execution
#-----------------------------------------------------------------------------
# Latest 0.29 package for bazel 0.29.1; updated on 2019-10-31.
http_archive(
    name = "bazel_toolchains",
    sha256 = "388da5cc148a43081c30c260ce1167747d8fb0968ee220e4ee1d1b1b8212eaa3",
    strip_prefix = "bazel-toolchains-0.29.9",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-toolchains/archive/0.29.9.tar.gz",
        "https://github.com/bazelbuild/bazel-toolchains/archive/0.29.9.tar.gz",
    ],
)

load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

# Creates a default toolchain config for RBE.
# Use this as is if you are using the rbe_ubuntu16_04 container,
# otherwise refer to RBE docs.
rbe_autoconfig(name = "rbe_default")

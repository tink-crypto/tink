workspace(name="tink")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

#-----------------------------------------------------------------------------
# Basic rules we need to add to bazel.
#-----------------------------------------------------------------------------
http_archive(
    name = "rules_python",
    strip_prefix = "rules_python-5aa465d5d91f1d9d90cac10624e3d2faf2057bd5/",
    url = "https://github.com/bazelbuild/rules_python/archive/5aa465d5d91f1d9d90cac10624e3d2faf2057bd5.zip",
    sha256 = "84923d1907d4ab47e7276ab1d64564c52b01cb31d14d62c8a4e5699ec198cb37",
)

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
    strip_prefix = "abseil-cpp-20190808",
    url = "https://github.com/abseil/abseil-cpp/archive/20190808.zip",
    sha256 = "0b62fc2d00c2b2bc3761a892a17ac3b8af3578bd28535d90b4c914b0a7460d4e",
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
    strip_prefix = "aws-sdk-cpp-1.4.80",
    build_file = "//:third_party/aws_sdk_cpp.BUILD.bazel",
)


# Needed for Cloud KMS API via gRPC.
http_archive(
    name = "googleapis",
    urls = [
        "https://github.com/googleapis/googleapis/archive/192d3d8221175f7cc0aa8eeac1d820f47c53da7f.zip",
    ],
    sha256 = "6b5a017082eade41c7efcc4d2f441422e41c0a0c57dd88e19d3ebfb1b8ff4f12",
    strip_prefix = "googleapis-192d3d8221175f7cc0aa8eeac1d820f47c53da7f",
)

load("@googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
)

# gRPC.
http_archive(
    name = "com_github_grpc_grpc",
    urls = [
        "https://github.com/grpc/grpc/archive/v1.22.1.tar.gz"
    ],
    sha256 = "cce1d4585dd017980d4a407d8c5e9f8fc8c1dbb03f249b99e88a387ebb45a035",
    strip_prefix = "grpc-1.22.1",
)

# Load grpc_deps.
# This is a workaround around the missing support for recursive WORKSPACE
# file loading (https://github.com/bazelbuild/bazel/issues/1943).
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
grpc_deps()

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
http_archive(
    name = "com_google_protobuf_javalite",
    strip_prefix = "protobuf-7b64714af67aa967dcf941df61fe5207975966be",
    urls = ["https://github.com/google/protobuf/archive/7b64714af67aa967dcf941df61fe5207975966be.zip"],
    sha256 = "311b29b8d0803ab4f89be22ff365266abb6c48fd3483d59b04772a144d7a24a1",
)

# Needed by gRPC, to build pb.h/pb.cc files from protos that contain services.
http_archive(
    name = "build_stack_rules_proto",
    strip_prefix = "rules_proto-f5d6eea6a4528bef3c1d3a44d486b51a214d61c2",
    urls = [
        "https://github.com/stackb/rules_proto/archive/f5d6eea6a4528bef3c1d3a44d486b51a214d61c2.tar.gz",
    ],
    sha256 = "128c4486b1707db917411c6e448849dd76ea3b8ba704f9e0627d9b01f2ee45fe",
)

load("@build_stack_rules_proto//cpp:deps.bzl", "cpp_grpc_library")
cpp_grpc_library()

#-----------------------------------------------------------------------------
# java
#-----------------------------------------------------------------------------

# Not used by Java Tink, but apparently needed for C++ gRPC library.
http_archive(
    name = "io_grpc_grpc_java",
    strip_prefix = "grpc-java-1.20.0",
    urls = [
        "https://github.com/grpc/grpc-java/archive/v1.20.0.tar.gz",
    ],
    sha256 = "553d1bdbde3ff4035747c184486bae2f084c75c3c4cdf5ef31a6aa48bdccaf9b",
)

# android sdk
android_sdk_repository(
    name = "androidsdk",
    # Tink uses features in Android Keystore that are only supported at this
    # level or newer.
    # See https://developer.android.com/training/articles/keystore.html.
    api_level = 23, # M
)

RULES_JVM_EXTERNAL_TAG = "2.7"
RULES_JVM_EXTERNAL_SHA = "f04b1466a00a2845106801e0c5cec96841f49ea4e7d1df88dc8e4bf31523df74"

http_archive(
    name = "rules_jvm_external",
    strip_prefix = "rules_jvm_external-%s" % RULES_JVM_EXTERNAL_TAG,
    sha256 = RULES_JVM_EXTERNAL_SHA,
    url = "https://github.com/bazelbuild/rules_jvm_external/archive/%s.zip" % RULES_JVM_EXTERNAL_TAG,
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
# objc
#-----------------------------------------------------------------------------

http_archive(
    name = "build_bazel_rules_apple",
    strip_prefix = "rules_apple-0.17.0",
    url = "https://github.com/bazelbuild/rules_apple/archive/0.17.0.zip",
    sha256 = "5ec8a6dd73ddeec3bf051ea82906dcd369c77f7f6030bc517c82e0e7a84c1cb9",
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
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/rules_go/releases/download/0.18.6/rules_go-0.18.6.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/0.18.6/rules_go-0.18.6.tar.gz",
    ],
    sha256 = "f04d2373bcaf8aa09bccb08a98a57e721306c8f6043a2a0ee610fd6853dcde3d",
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
    sha256 = "3eff8985b5c6df196ce3a1944468a2c553ec4063f142d0feefe544e0fcdb583c",
    strip_prefix = "rules_closure-0.9.0",
    urls = [
        "https://github.com/bazelbuild/rules_closure/archive/0.9.0.tar.gz",
    ],
)

load("@io_bazel_rules_closure//closure:defs.bzl", "closure_repositories")

closure_repositories(omit_zlib = True)

#-----------------------------------------------------------------------------
# Python
#-----------------------------------------------------------------------------

load("//third_party/py:python_configure.bzl", "python_configure")

python_configure(name = "local_config_python")

new_local_repository(
    name = "clif",
    build_file = "third_party/clif.BUILD.bazel",
    path = "/usr/local",
)

#-----------------------------------------------------------------------------
# Remote Build Execution
#-----------------------------------------------------------------------------
http_archive(
    name = "bazel_toolchains",
    sha256 = "4598bf5a8b4f5ced82c782899438a7ba695165d47b3bf783ce774e89a8c6e617",
    strip_prefix = "bazel-toolchains-0.27.0",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-toolchains/archive/0.27.0.tar.gz",
        "https://github.com/bazelbuild/bazel-toolchains/archive/0.27.0.tar.gz",
    ],
)

load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

# Creates a default toolchain config for RBE.
# Use this as is if you are using the rbe_ubuntu16_04 container,
# otherwise refer to RBE docs.
rbe_autoconfig(name = "rbe_default")

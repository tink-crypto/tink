# MAINTAINERS
#
# Every external rule must have a SHA checksum or tag.
#
# To update http_file(s) from maven servers, point your browser to
# https://repo1.maven.org/maven2/com/google/protobuf/protoc, find the
# file, copy it down to your workstation (with curl perhaps), and
# compute the sha256:
#
# $ curl -O -J -L https://repo1.maven.org/maven2/com/google/protobuf/protoc/3.0.0/protoc-3.0.0-linux-x86_64.exe
# $ sha256sum protoc-3.0.0-linux-x86_64.exe #linux
# $ shasum -a256 protoc-3.0.0-osx-x86_64.exe # macosx
#

DEPS = {
    "protoc_gen_javalite_linux_x86_64": {
        "rule": "http_file",
        "url" : "http://repo1.maven.org/maven2/com/google/protobuf/protoc-gen-javalite/3.0.0/protoc-gen-javalite-3.0.0-linux-x86_64.exe",
        "sha256": "83eb6ee8391cbd26ebf48f6636c089e530fd3fea454dc66e5a7e36a648795c7b",
    },

    "protoc_gen_javalite_macosx": {
        "rule": "http_file",
        "url" : "http://repo1.maven.org/maven2/com/google/protobuf/protoc-gen-javalite/3.0.0/protoc-gen-javalite-3.0.0-osx-x86_64.exe",
        "sha256": "fe6f2ba6c6550f20cfa4d07e481a19ce108981009fdd7e6819fed9caa70af074",
    },
}

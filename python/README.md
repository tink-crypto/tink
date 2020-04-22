# Tink for Python

Note that this is still under active development and the API might change until
the official release.

## Getting Started

In order to build Tink from source you can either use Bazel or build a Python
package using pip.

### Build with Bazel

```shell
bazel build "..."
```

### Build with pip from source

A setup script is provided which allows to install Tink as a Python package

```shell
pip3 install .
```

Note that this still requires Bazel to compile the binding to C++ and the
[protobuf compiler](https://github.com/protocolbuffers/protobuf).

### Running tests

You can run all tests with Bazel using

```shell
bazel test "..."
```

## Examples

As a starting point, it is best to look at the examples provided in
[../examples/python/](https://github.com/google/tink/examples/python/).

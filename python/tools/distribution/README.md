# Overview

This folder contains scripts to build binary and source wheels of the Tink
Python package.

## Building the release

In order to generate a release run `./tools/distribution/create_release.sh` from
the `python/` folder. Note that this requires [Docker](https://www.docker.com)
to be installed, as it makes use of the
[pypa images](https://github.com/pypa/manylinux) to build
[PEP 599](https://www.python.org/dev/peps/pep-0599/) conformant wheels.

This will carry out the following three steps:

*   Create binary wheels in a Docker container for Linux.
*   Create a source distribution of the Python package.
*   Run automatic tests against the packages created.

The resulting packages of this process will be stored in `python/release` and
can be distributed. The binary wheels can be installed on Linux without
Bazel/protoc being available. Currently this supports building binary wheels
for:

*   manylinux2014_x86_64: Python 3.7, 3.8, 3.9, 3.10

The binary wheels are tested inside a Docker container with the corresponding
Python versions.

The source distribution still needs to compile the C++ bindings, which requires
Bazel, protoc and the Tink repository to be available. The path to the Tink
repository can be set with `TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH`. The
source distribution is tested on the machine where the script is run.

## Publishing the release

The output generated in the previous step can directly be used for upload to
PyPI. It is recommended to first upload it to the
[test repository](https://test.pypi.org):

```
python3 -m twine upload --repository testpypi release/*
```

The package can then be installed using

```
pip3 install -i https://test.pypi.org/simple/ tink
```

In order to upload it to the PyPI repository run

```
python3 -m twine upload release/*
```


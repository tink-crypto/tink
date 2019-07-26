"""Macros to generate python 2 and 3 binaries."""

load("//devtools/python/blaze:pytype.bzl", "pytype_strict_binary")

def py23_binary(name, **kwargs):
    """Generates python 2 and 3 binaries. Accepts any py_binary arguments."""
    native.py_binary(
        name = name + "2",
        python_version = "PY2",
        **kwargs
    )

    native.py_binary(
        name = name + "3",
        python_version = "PY3",
        **kwargs
    )

def pytype_strict_23_binary(name, **kwargs):
    """Generates python 2 and 3 binaries.

    Accepts any pytype_strict_binary arguments."""
    pytype_strict_binary(
        name = name + "2",
        python_version = "PY2",
        **kwargs
    )

    pytype_strict_binary(
        name = name + "3",
        python_version = "PY3",
        **kwargs
    )

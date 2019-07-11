"""Macro to generate python 2 and 3 binaries."""

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

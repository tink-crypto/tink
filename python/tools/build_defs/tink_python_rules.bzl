"""Tink rules for python."""

def tink_pybind_extension(
        name,
        srcs = [],
        hdrs = [],
        copts = [],
        linkopts = [],
        features = ["-use_header_modules"],
        deps = []):
    """
    Pybind Extension for Tink.

    Creates Bazel targets for a pybind module:
    - A py_library with the taret name
    - A cc_binary with the target name.so

    Args:
      name: name of the target
      srcs: source files corresponding to the target
      hdrs: header files corresponding to the target
      copts: flags for the compiler
      linkopts: flags for the linker
      features: features enabled for Bazel
      deps: dependencies of the target

    Returns:
      A py_library target.
    """
    shared_lib_name = name + ".so"
    native.cc_binary(
        name = shared_lib_name,
        linkshared = 1,
        linkstatic = 1,
        srcs = srcs + hdrs,
        copts = copts + ["-fvisibility=hidden"],
        linkopts = linkopts + select({
            "@pybind11//:osx": [],
            "//conditions:default": ["-Wl,-Bsymbolic"],
        }),
        features = features,
        deps = deps,
    )

    # Extract Python targets from deps
    pybind_deps = [dep[:-3] for dep in deps if dep.endswith("_cc")]
    native.py_library(
        name = name,
        data = [shared_lib_name],
        deps = pybind_deps,
    )

def tink_pybind_library(
        name,
        copts = [],
        features = ["-use_header_modules"],
        tags = [],
        deps = [],
        **kwargs):
    native.cc_library(
        name = name,
        copts = copts,
        features = features,
        tags = tags,
        deps = deps,
        **kwargs
    )

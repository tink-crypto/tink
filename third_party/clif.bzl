"""Provide bazel rules for OSS CLIF."""

# Label for our OSS CLIF binary pyclif.
CLIF_PYCLIF = "@clif//:pyclif"

# Label for our OSS CLIF protobuf compiler.
CLIF_PROTO = "@clif//:proto"

# Label for our OSS CLIF C++ runtime headers and sources.
CLIF_CPP_RUNTIME = "@clif//:cpp_runtime"

# Additional CC compilation flags, if any.
EXTRA_CC_FLAGS = []

_PROTO_LIBRARY_SUFFIX = "_pyclif"

PYCLIF_PYEXT_SUFFIX = ".so"

PYCLIF_CC_LIB_SUFFIX = "_cclib"

PYCLIF_WRAP_SUFFIX = "_clif_wrap"

def _clif_wrap_cc_impl(ctx):
    """Executes CLIF cmdline tool to produce C++ python model from a CLIF spec."""
    if len(ctx.files.srcs) != 1:
        fail("Exactly one CLIF source file label must be specified.", "srcs")

    clif_spec_file = ctx.files.srcs[0]

    # Inputs is a set of all of the things we depend on, not inputs to the CLIF
    # program itself.
    inputs = depset([clif_spec_file])
    for dep in ctx.attr.deps:
        inputs += dep.cc.transitive_headers
    inputs += ctx.files._cliflib
    inputs += ctx.files.clif_deps
    inputs += ctx.files.toolchain_deps

    # Compute the set of include directories for CLIF so it can find header files
    # used in the CLIF specification. These are the repo roots for all of our
    # inputs (aka deps) plus all of the quote and system includes for our C++
    # deps.
    include_dirs = depset(_get_repository_roots(ctx, inputs))
    for dep in ctx.attr.deps:
        include_dirs += dep.cc.quote_include_directories
        include_dirs += dep.cc.system_include_directories

    # Construct our arguments for CLIF.
    args = [
        "--py3output",
        "--modname",
        ctx.attr.package_name + "." + ctx.attr.module_name,
        "-c",
        ctx.outputs.cc_out.path,
        "-g",
        ctx.outputs.h_out.path,
        "-i",
        ctx.outputs.ccinit_out.path,
        "--prepend",
        "clif/python/types.h",
    ]
    include_args = ["-I" + i for i in include_dirs.to_list()]

    # Add these includes to CLIF itself.
    args += include_args

    # Add these includes to those passed through by CLIF to its C++ matcher.
    args += ["-f" + " ".join(include_args + EXTRA_CC_FLAGS)]

    # The last argument is the actual CLIF specification file.
    args += [clif_spec_file.path]

    outputs = [ctx.outputs.cc_out, ctx.outputs.h_out, ctx.outputs.ccinit_out]
    ctx.actions.run(
        executable = ctx.executable._clif,
        arguments = args,
        inputs = inputs.to_list(),
        outputs = outputs,
        mnemonic = "CLIF",
        progress_message = "CLIF wrapping " + clif_spec_file.path,
    )

_clif_wrap_cc = rule(
    attrs = {
        "srcs": attr.label_list(
            mandatory = True,
            allow_files = True,
        ),
        "deps": attr.label_list(
            allow_files = True,
            providers = ["cc"],
        ),
        "toolchain_deps": attr.label_list(
            allow_files = True,
        ),
        # For rule "//foo/python:bar_clif" this should be "bar".
        "module_name": attr.string(mandatory = True),
        # For rule "//foo/python:bar_clif" this should be "foo/python".
        "package_name": attr.string(mandatory = True),
        "clif_deps": attr.label_list(allow_files = True),
        # Hidden attribute: the Label for our PYCLIF binary itself.
        "_clif": attr.label(
            default = Label(CLIF_PYCLIF),
            executable = True,
            cfg = "host",
        ),
        # Hidden attribute: The label to the C++ CLIF header files.
        "_cliflib": attr.label(
            default = Label(CLIF_CPP_RUNTIME),
            allow_files = True,
        ),
    },
    output_to_genfiles = True,
    outputs = {
        "cc_out": "%{module_name}.cc",
        "h_out": "%{module_name}.h",
        "ccinit_out": "%{module_name}_init.cc",
    },
    implementation = _clif_wrap_cc_impl,
)

def _get_repository_roots(ctx, files):
    """Returns abnormal root directories under which files reside.

    When running a ctx.action, source files within the main repository are all
    relative to the current directory; however, files that are generated or exist
    in remote repositories will have their root directory be a subdirectory,
    e.g. bazel-out/local-fastbuild/genfiles/external/jpeg_archive. This function
    returns the set of these devious directories, ranked and sorted by popularity
    in order to hopefully minimize the number of I/O system calls within the
    compiler, because includes have quadratic complexity.

    Args:
      ctx: context
      files: list of paths
    Returns:
      list of directories
    """
    ctx = ctx  # unused
    result = {}
    for f in files:
        root = f.root.path
        if root:
            if root not in result:
                result[root] = 0
            result[root] -= 1
        work = f.owner.workspace_root
        if work:
            if root:
                root += "/"
            root += work
        if root:
            if root not in result:
                result[root] = 0
            result[root] -= 1
    return [k for v, k in sorted([(v, k) for k, v in result.items()])]

def _clif_to_lib(label, extension):
    """Gets a C++/python/etc library corresponding to a CLIF library rule.

    Args:
      label: string. The name of a clif_rule. If the name is of the
        form <target>_pyclif we will stripe off the `_pyclif` ending.
      extension: string. The expected extension of our name library.

    Returns:
      <target>_extension.
    """
    if label.endswith(_PROTO_LIBRARY_SUFFIX):
        basename = label[:-len(_PROTO_LIBRARY_SUFFIX)]
    else:
        basename = label
    return basename + extension

def pyclifs_to_pyproto_libs(labels):
    """Gets the py protobuf label for each of pyclif label as a list."""
    return [_clif_to_lib(name, "_py_pb2") for name in labels]

def pyclifs_to_ccproto_libs(labels):
    """Gets the cc protobuf label for each of pyclif label as a list."""
    return [_clif_to_lib(name, "_cc_pb2") for name in labels]

def clif_deps_to_cclibs(labels):
    """Gets the cc_library name for each of label as a list."""
    return [_clif_to_lib(name, PYCLIF_CC_LIB_SUFFIX) for name in labels]

def _symlink_impl(ctx):
    """Creates a symbolic link between src and out."""
    out = ctx.outputs.out
    src = ctx.attr.src.files.to_list()[0]
    cmd = "ln -f -r -s %s %s" % (src.path, out.path)
    ctx.actions.run_shell(
        inputs = [src],
        outputs = [out],
        command = cmd,
    )

symlink = rule(
    implementation = _symlink_impl,
    attrs = {
        "src": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "out": attr.output(mandatory = True),
    },
)

def py_clif_cc(
        name,
        srcs,
        clif_deps = [],
        pyclif_deps = [],
        deps = [],
        copts = [],
        py_deps = [],
        **kwargs):
    """Defines a CLIF wrapper rule making C++ libraries accessible to Python.

    Here are two example working py_clif_cc rules:

    py_clif_cc(
        name = "proto_cpp",
        srcs = ["proto_cpp.clif"],
        pyclif_deps = ["//oss_clif:oss_pyclif"],
        deps = ["//oss_clif:proto_cpp_lib"],
    )

    py_clif_cc(
        name = "pyclif_dep",
        srcs = ["pyclif_dep.clif"],
        deps = ["//oss_clif:pyclif_dep_lib"],
    )

    Args:
      name: The name of the rule. This name becomes a suitable target for Python
        libraries to access the C++ code.
      srcs: A list that must contain a single file named <name>.clif containing
        our CLIF specification.
      clif_deps: A list of other CLIF rules included by this one.
      pyclif_deps: A potentially empty list of pyclif_proto_library rules
      deps: A list of C++ dependencies.
      copts: List of copts to provide to our native.cc_library when building our
        python extension module.
      py_deps: List of dependencies to provide to our the native.py_library
        created by this rule.
      **kwargs: kwargs passed to py_library rule created by this rule.
    """
    pyext_so = name + PYCLIF_PYEXT_SUFFIX
    cc_library_name = name + PYCLIF_CC_LIB_SUFFIX
    extended_cc_deps = deps + [CLIF_CPP_RUNTIME] + pyclif_deps

    # Here's a rough outline of how we build our pyclif library:
    #
    # Suppose we have a module named 'foo'.
    #
    # _clif_wrap_cc runs pyclif to produce foo.cc, foo.h, and foo_init.cc which
    # C++ python extension module.
    #
    # native.cc_library is a normal C++ library with those sources, effectively
    # our "python module" as a bazel C++ library allowing other rules to depend
    # on that C++ code.
    #
    # native.cc_binary depends on foo's cc_library to create a shared python
    # extension module (.so) which python will load via its dlopen mechanism.
    # This .so library is also used by the _clif_wrap_cc rule to get include paths
    # when building CLIF specs depending on other clif specs.
    #
    # native.py_library named `name` which provides a python bazel target that
    # loads the cc_binary, as data, producing a py extension module. This also
    # allows client python code to depend on this module.

    # This _clif_wrap_cc handles clif_deps differently than most clif.bzl's
    # do.  That is because we are doing something quite different than the
    # standard clif.bzl does -- we are replacing the generated extension module
    # with a symbolic link to protobuf's _message.so.  That file, in turn, is
    # a dependency of every single Python protocol buffer target.  And it needs
    # to depend on all of the _cclibs generated by the cc_library rule below.
    #
    # So because of all this, the normal strategy of having this rule depend
    # on clif_deps or clif_deps_to_pyexts(clif_deps) would create circular
    # dependencies.  Our strategy to avoid those circular dependencies is to
    # have anything the cc_library rule depends on be only C++ and not Python.
    # The raw clif_deps are a mixture of C++ and Python, so we have to very
    # carefully depend on only their C++ part (given by the
    # clif_deps_to_cclibs).
    _clif_wrap_cc(
        name = name + PYCLIF_WRAP_SUFFIX,
        srcs = srcs,
        deps = extended_cc_deps + clif_deps_to_cclibs(clif_deps),
        clif_deps = clif_deps_to_cclibs(clif_deps),
        toolchain_deps = ["@bazel_tools//tools/cpp:current_cc_toolchain"],
        module_name = name,
        # Turns //foo/bar:baz_pyclif into foo.bar to create our fully-qualified
        # python package name.
        package_name = native.package_name().replace("/", "."),
    )

    native.cc_library(
        name = cc_library_name,
        hdrs = [
            name + ".h",
        ],
        srcs = [
            name + ".cc",
            name + "_init.cc",
        ],
        copts = copts + EXTRA_CC_FLAGS,
        deps = extended_cc_deps + clif_deps_to_cclibs(clif_deps),
    )

    # To prevent ODR violations, all of the extensions must live in one
    # extension module.  And to be compatible with existing protobuf
    # generated code, that module must be _message.so.
    symlink(
        name = name + "_symlink",
        out = pyext_so,
        src = "@protobuf_archive//:python/google/protobuf/pyext/_message.so",
    )

    # We create our python module which is just a thin wrapper around our real
    # python module pyext_so (producing name.so for python to load). This
    # rule allows python code to depend on this module, even through its written
    # in C++.
    native.py_library(
        name = name,
        srcs = [],
        srcs_version = "PY2AND3",
        deps = pyclifs_to_pyproto_libs(pyclif_deps) + clif_deps + py_deps,
        data = [pyext_so],
        **kwargs
    )

# Copied from: devtools/clif/python/clif_build_rule.bzl with heavy
# modifications.

def _clif_proto_parser_rule_impl(ctx):
    """Implementation of _run_clif_proto_parser_rule."""
    proto_file = ctx.files.src[0]
    args = [
        "-c",
        ctx.outputs.cc.path,
        "-h",
        ctx.outputs.hdr.path,
        "--strip_dir=%s" % ctx.configuration.genfiles_dir.path,
        "--source_dir='.'",
        "%s" % proto_file.path,
    ]
    inputs = []
    for d in ctx.attr.deps:
        if "proto" in dir(d):
            inputs += list(d[ProtoInfo].transitive_sources)
    ctx.actions.run(
        mnemonic = "ClifProtoLibraryGeneration",
        arguments = args,
        executable = ctx.executable.parser,
        inputs = inputs,
        outputs = [ctx.outputs.hdr, ctx.outputs.cc],
    )

_run_clif_proto_parser_rule = rule(
    attrs = {
        "src": attr.label(allow_files = [".proto"]),
        "hdr": attr.output(),
        "cc": attr.output(),
        "deps": attr.label_list(),
        "parser": attr.label(
            executable = True,
            default = Label(CLIF_PROTO),
            cfg = "host",
        ),
    },
    output_to_genfiles = True,
    implementation = _clif_proto_parser_rule_impl,
)

def pyclif_proto_library(
        name,
        proto_lib,
        proto_srcfile = "",
        deps = [],
        visibility = None,
        compatible_with = None,
        testonly = None):
    """Generate C++ CLIF extension for using a proto and dependent py_proto_lib.

    Args:
      name: generated cc_library (name.h) to use in py_clif_cc clif_deps
      proto_lib: name of a proto_library rule
      proto_srcfile: the proto name if it does not match proto_lib rule name
      deps: passed to cc_library
      visibility: passed to all generated "files": name.h name.a name_pb2.py
      compatible_with: compatibility list
      testonly: available for test rules only flag (default from package)
    """
    if not name.endswith(_PROTO_LIBRARY_SUFFIX):
        fail("The name of the 'pyclif_proto_library' target should be of the " +
             "form '<PROTO_FILE>%s' where the proto " % _PROTO_LIBRARY_SUFFIX +
             "file being wrapped has the name '<PROTO_FILE>.proto'.")
    if proto_srcfile:
        required_name = proto_srcfile[:-len(".proto")] + _PROTO_LIBRARY_SUFFIX
        if name != required_name:
            fail("The name of the 'pyclif_proto_library' target should be " +
                 "'%s' as it is wrapping %s." % (required_name, proto_srcfile))

    hdr_file = name + ".h"
    cpp_file = name + ".cc"
    clifrule = name + "_clif_rule"
    src = name[:-len(_PROTO_LIBRARY_SUFFIX)] + ".proto"

    _run_clif_proto_parser_rule(
        name = clifrule,
        src = src,
        hdr = hdr_file,
        cc = cpp_file,
        deps = deps + [proto_lib],
        testonly = testonly,
    )

    # In OSS world, we cannot provide proto_lib as a direct dependency to our
    # cc_library as it doesn't provide a cc file:
    #   in deps attribute of cc_library rule //oss_clif:oss_pyclif: proto_library
    #   rule '//oss_clif:oss_proto' is misplaced here (expected cc_inc_library,
    #   cc_library, objc_library, experimental_objc_library or cc_proto_library).
    # So we need to synthesize our protobuf cc library name from our name as
    #   pyclif_name  = proto_pyclif
    #   cc_proto_lib = proto_cc_pb2
    native.cc_library(
        name = name,
        srcs = [cpp_file],
        hdrs = [hdr_file],
        deps = deps + [CLIF_CPP_RUNTIME] + pyclifs_to_ccproto_libs([name]),
        visibility = visibility,
        compatible_with = compatible_with,
        testonly = testonly,
        copts = EXTRA_CC_FLAGS,
    )

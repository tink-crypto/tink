# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Compiles protobuf for ObjC.

This tool uses https://github.com/pubref/rules_protobuf.
"""

# The actual rule which does the filtering.
def _do_filter_impl(ctx):
    return struct(
        files = depset([f for f in ctx.files.srcs if f.path.endswith(ctx.attr.suffix)]),
    )

_do_filter = rule(
    attrs = {
        "srcs": attr.label_list(
            mandatory = True,
            allow_files = True,
        ),
        "suffix": attr.string(
            mandatory = True,
        ),
    },
    implementation = _do_filter_impl,
)

# A convenient macro to wrap the custom rule and objc_library.
def tink_objc_proto_library(name, srcs, **kwargs):
    """
    Compiles ObjC proto libaries in srcs into a single library.

    Args:
      name: the name of the output library
      srcs: the list of ObjC proto libraries, which are generated using
            objc_proto_compile in rules_protobuf.
    """

    _do_filter(
        name = "%s_hdrs" % name,
        visibility = ["//visibility:private"],
        # srcs = hdrs,
        srcs = srcs,
        suffix = ".pbobjc.h",
    )
    _do_filter(
        name = "%s_srcs" % name,
        visibility = ["//visibility:private"],
        srcs = srcs,
        suffix = ".pbobjc.m",
    )
    native.objc_library(
        name = name,
        srcs = [":%s_srcs" % name],
        hdrs = [":%s_hdrs" % name],
        copts = ["-fno-objc-arc"],
        deps = ["@com_google_protobuf//:objectivec"],
        **kwargs
    )

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
      srcs = [ ":%s_srcs" % name ],
      hdrs = [ ":%s_hdrs" % name ],
      copts = [ "-fno-objc-arc" ],
      deps = [ "@com_google_protobuf_objc//:objectivec" ],
      **kwargs
  )

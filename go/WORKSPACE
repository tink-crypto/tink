workspace(name = "tink_go")

local_repository(
    name = "tink_base",
    path = "..",
)

load("@tink_base//:tink_base_deps.bzl", "tink_base_deps")
tink_base_deps()

load("@tink_base//:tink_base_deps_init.bzl", "tink_base_deps_init")
tink_base_deps_init()

load("@tink_go//:tink_go_deps.bzl", "tink_go_deps")
tink_go_deps()

load("@tink_go//:tink_go_deps_init.bzl", "tink_go_deps_init")
tink_go_deps_init()

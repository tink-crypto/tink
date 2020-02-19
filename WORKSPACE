workspace(name = "tink_base")

load("@tink_base//:tink_base_deps.bzl", "tink_base_deps")

tink_base_deps()

load("@tink_base//:tink_base_deps_init.bzl", "tink_base_deps_init")

tink_base_deps_init()

# ----- Python
load("@tink_py_deps//:requirements.bzl", "pip_install")

pip_install()


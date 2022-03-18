"""Tink rules for java."""

load("//devtools/build_cleaner/skylark:build_defs.bzl", "register_extension_info")
load("//tools/build_defs/android:rules.bzl", "android_binary", "android_instrumentation_test")

def tink_android_test(name, srcs, deps, shard_count = 1, data = [], min_version = 19):
    """Creates android_instrumentation_test targets, testing them on multiple devices.

    Args:
        name: The name of the test created.
        srcs: The test source of the test.
        deps: The dependencies.
        data: Data dependencies.
        min_version: The minimum version of android which should be tested.
    """
    TARGET_DEVICES = {
        19: "//tools/mobile/devices/android/generic_phone:android_19_x86",
        21: "//tools/mobile/devices/android/generic_phone:android_21_x86",
        22: "//tools/mobile/devices/android/generic_phone:android_22_x86",
        23: "//tools/mobile/devices/android/generic_phone:android_23_x86",
        24: "//tools/mobile/devices/android/generic_phone:android_24_x86",
        25: "//tools/mobile/devices/android/generic_phone:android_25_x86",
        26: "//tools/mobile/devices/android/generic_phone:android_26_x86",
        27: "//tools/mobile/devices/android/generic_phone:android_27_x86",
    }

    deps.append("//java/com/google/android/apps/common/testing/testrunner")

    # Some tests require --config=android_java8_libs  which in turn requires enabling multidex.
    # See go/java8-libs-for-android-faq for details.

    native_multidex_binary = name + "_native_binary"
    android_binary(
        srcs = srcs,
        name = native_multidex_binary,
        deps = deps,
        manifest = "//third_party/tink/java_src/src/androidtest:AndroidManifest.xml",
        testonly = 1,
        multidex = "native",
    )

    legacy_multidex_binary = name + "_legacy_binary"
    deps_copy = list(deps)
    deps_copy.append("//third_party/java/android/android_sdk_linux/extras/android/compatibility/multidex")
    android_binary(
        srcs = srcs,
        name = legacy_multidex_binary,
        deps = deps_copy,
        manifest = "//third_party/tink/java_src/src/androidtest:AndroidManifest.xml",
        testonly = 1,
        multidex = "legacy",
    )

    for version_num, device in TARGET_DEVICES.items():
        if version_num >= min_version:
            android_instrumentation_test(
                name = name + "_" + str(version_num) + "_test",
                target_device = device,
                test_app = legacy_multidex_binary if version_num < 21 else native_multidex_binary,
                data = data,
                tags = ["manual"],
                shard_count = shard_count,
            )

## Tell build_cleaner how to update dependencies in tink_android_test.
## For a target name foobar, it should use what as deps into foobar_native_binary.
register_extension_info(
    extension = tink_android_test,
    label_regex_for_dep = "{extension_name}_native_binary",
)

"""Tink rules for java."""

load("//devtools/build_cleaner/skylark:build_defs.bzl", "register_extension_info")
load("//tools/build_defs/android:rules.bzl", "android_binary", "android_instrumentation_test")

## TODO(b/185807287): Remove the remaining instances of collect_android_libraries_and_make_test_suite
## by replacing them with tink_android_test as in cl/423316322.
def collect_android_libraries_and_make_test_suite(name, shard_count = 1):
    """Creates an android test suite for android_library in the current package.

    Creates, for a bunch of devices, an android_instrumentation_test which
    runs all tests previously defined in android_library, but only for
    the versions specified there.

    If the android_library target has a tag "android_min_version:xx", the
    corresponding test is only added to android versions xx and above.

    Args:
        name: The prefix of the generated android test rules.
        shard_count: the number of shards under which the resulting binary runs.
    """

    TARGET_DEVICES = {
        19: "//tools/mobile/devices/android/nexus_5:google_19_x86_gms_stable",
        21: "//tools/mobile/devices/android/nexus_6:google_21_x86",
        22: "//tools/mobile/devices/android/nexus_6:google_22_x86",
        23: "//tools/mobile/devices/android/nexus_6:google_23_x86",
        24: "//tools/mobile/devices/android/nexus_6:google_24_x86",
        25: "//tools/mobile/devices/android/nexus_6p:google_25_x86",
        26: "//tools/mobile/devices/android/pixel_c:google_26_x86",
        27: "//tools/mobile/devices/android/pixel_xl:google_27_x86",
    }

    for version_num, device in TARGET_DEVICES.items():
        dependencies = {}
        data = {}
        for target_name, library_target in native.existing_rules().items():
            android_min_version = 0
            if "tags" in library_target:
                for tag in library_target["tags"]:
                    if tag.startswith("android_min_version"):
                        _, x = tag.split(":")
                        android_min_version = int(x)
                        break
            if library_target["kind"] == "android_library" and android_min_version <= version_num:
                dependencies[target_name] = True
                if "data" in library_target:
                    for entry in library_target["data"]:
                        data[entry] = True
        if len(dependencies) == 0:
            # Do not create a test target if there is nothing to test.
            continue
        dependencies["//java/com/google/android/apps/common/testing/testrunner"] = True

        binary_name = name + "_" + str(version_num) + "_collected_binary"

        # Some tests require --config=android_java8_libs which in turn requires enabling multidex.
        # See go/java8-libs-for-android-faq for details.
        multidex = "native"
        if version_num < 21:
            multidex = "legacy"
            dependencies["//third_party/java/android/android_sdk_linux/extras/android/compatibility/multidex"] = True
        android_binary(
            name = binary_name,
            deps = list(dependencies),
            manifest = "//third_party/tink/java_src/src/androidtest:AndroidManifest.xml",
            testonly = 1,
            multidex = multidex,
        )
        android_instrumentation_test(
            name = name + "_" + str(version_num) + "_test",
            shard_count = shard_count,
            target_device = device,
            test_app = binary_name,
            data = list(data),
            tags = ["manual"],
        )

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
        19: "//tools/mobile/devices/android/nexus_5:google_19_x86_gms_stable",
        21: "//tools/mobile/devices/android/nexus_6:google_21_x86",
        22: "//tools/mobile/devices/android/nexus_6:google_22_x86",
        23: "//tools/mobile/devices/android/nexus_6:google_23_x86",
        24: "//tools/mobile/devices/android/nexus_6:google_24_x86",
        25: "//tools/mobile/devices/android/nexus_6p:google_25_x86",
        26: "//tools/mobile/devices/android/pixel_c:google_26_x86",
        27: "//tools/mobile/devices/android/pixel_xl:google_27_x86",
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

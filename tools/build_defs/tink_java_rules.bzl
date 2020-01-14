"""Tink rules for java."""

load("//tools/build_defs/android:rules.bzl", "android_binary", "android_instrumentation_test", "android_library")
load("//devtools/build_cleaner/skylark:build_defs.bzl", "register_extension_info")

def tink_java_test(name, java_deps = [], android_deps = [], **kwargs):
    """Java Test for Tink.

    Creates a java_test for the sources as well as an android_library target, for which
    tests are generated when tink_create_android_test_suite() is called.

    This means that tink_create_android_test_suite must be called at some point *after*
    tink_java_test in the BUILD file. Failing to do so is a bug.
    """

    native.java_test(name = name, deps = java_deps, **kwargs)

    android_library(
        name = name + "_android_test_library",
        deps = android_deps,
        testonly = 1,
        **kwargs
    )

def _is_version_disabled(target, version_num):
    """Returns true if the target should be disabled for this android version.

    This is true if target["tags"] exists and contains a string android_min_version:xx"
    with xx > version_num."""

    if "tags" not in target:
        return False
    TAG_TO_STRIP = "android_min_version:"
    min_versions = [t[len(TAG_TO_STRIP):] for t in target["tags"] if t.startswith(TAG_TO_STRIP)]
    return any([int(v) > version_num for v in min_versions])

def tink_create_android_test_suite(shard_count = 1):
    """Creates an android test suite for previous tink_java_test.

    Creates, for a bunch of devices, an android_instrumentation_test which
    runs all tests previously defined in tink_java_test, but only for
    the versions specified there.

    If the tink_java_test target has a tag "android_min_version:xx", the
    corresponding test is only added to android versions xx and above.

    Args:
       shard_count: the number of shards under which the resulting binary runs.
    """

    TARGET_DEVICES = {
        19: "//tools/android/emulated_devices/nexus_5:google_19_x86_gms_stable",
        21: "//tools/android/emulated_devices/nexus_6:google_21_x86",
        22: "//tools/android/emulated_devices/nexus_6:google_22_x86",
        23: "//tools/android/emulated_devices/nexus_6:google_23_x86",
        24: "//tools/android/emulated_devices/nexus_6:google_24_x86",
        25: "//tools/android/emulated_devices/nexus_6p:google_25_x86",
        26: "//tools/android/emulated_devices/pixel_c:google_26_x86",
        27: "//tools/android/emulated_devices/pixel_xl:google_27_x86",
    }

    for version_num, device in TARGET_DEVICES.items():
        dependencies = {}
        for target_name, library_target in native.existing_rules().items():
            if library_target["kind"] == "android_library":
                if not _is_version_disabled(library_target, version_num):
                    dependencies[target_name] = True
        dependencies["//java/com/google/android/apps/common/testing/testrunner"] = True

        binary_name = "android_" + str(version_num) + "_collected_binary"
        android_binary(
            name = binary_name,
            deps = list(dependencies),
            manifest = "//third_party/tink/javatests:AndroidManifest.xml",
            testonly = 1,
        )
        android_instrumentation_test(
            name = "android_test_suite_" + str(version_num) + "_test",
            shard_count = shard_count,
            target_device = device,
            test_app = binary_name,
        )

# Tell build_cleaner that in tink_java_test, java_deps should be the dependencies needed
# by the created rule with the same name, android_deps should be the dependencies needed
# by the same name concatenated with _android_test_library.
# go/build-cleaner-build-extensions
register_extension_info(
    extension = tink_java_test,
    label_regex_map = {
        "java_deps": "deps:{extension_name}",
        "android_deps": "deps:{extension_name}_android_test_library",
    },
)

"""Tink rules for java."""

load("//tools/build_defs/android:rules.bzl", "android_binary", "android_instrumentation_test")

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
            android_min_version = 0
            if "tags" in library_target:
                for tag in library_target["tags"]:
                    if tag.startswith("android_min_version"):
                        _, x = tag.split(":")
                        android_min_version = int(x)
                        break
            if library_target["kind"] == "android_library" and android_min_version <= version_num:
                dependencies[target_name] = True
        dependencies["//java/com/google/android/apps/common/testing/testrunner"] = True

        binary_name = name + "_" + str(version_num) + "_collected_binary"
        android_binary(
            name = binary_name,
            deps = list(dependencies),
            manifest = "//third_party/tink/java_src/src/androidtest:AndroidManifest.xml",
            testonly = 1,
        )
        android_instrumentation_test(
            name = name + "_" + str(version_num) + "_test",
            shard_count = shard_count,
            target_device = device,
            test_app = binary_name,
            tags = ["manual"],
        )

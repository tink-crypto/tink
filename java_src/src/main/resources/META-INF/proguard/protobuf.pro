# Recently Protobuf Javalite introduced a change that relies on reflection,
# which doesn't work with Proguard. This rule keeps the reflection usages in
# (shaded) Protobuf classes in Tink as-is.
# The location of this file is determined by
# - https://developer.android.com/studio/build/shrink-code#configuration-files
# - https://docs.bazel.build/versions/master/be/java.html#java_library.resources
# See also:
# - https://github.com/google/tink/issues/361
# - https://github.com/protocolbuffers/protobuf/issues/6463
# WARNING: the shaded package name com.google.crypto.tink.shaded.protobuf must
# be kept in sync with jar_jar_rules.txt.
-keepclassmembers class * extends com.google.crypto.tink.shaded.protobuf.GeneratedMessageLite {
  <fields>;
}

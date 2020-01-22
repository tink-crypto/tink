"""Build definitions for javac related operations in tink."""

SOURCE_7_TARGET_7 = [
    "-source 1.7",
    "-target 1.7",
]

JAVACOPTS = []

# Compile Tink open source with java 7 and produce java 7 bytecode.
# This ensures that Tink doesn't use non-java 7 features.
JAVACOPTS_OSS = SOURCE_7_TARGET_7

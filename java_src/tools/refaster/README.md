# Refaster templates for Tink

In this directory, we store refaster templates for usage with Tink. These
help users modernize the code and move to preferred APIs.

We sometimes run these templates manually, but do not test them via continuous
integration.

```bash
tink_version="1.8.0"
errorprone_version="2.18.0"

## STEP 1: We get the 3 jar files:
## tink-{version}-jar, error_prone_refaster-{version}.jar, and error_prone_core-{version}.jar
## (For good measure, we verify the 3 sha256sums.)

maven_base="repo1.maven.org/maven2/com/google"

tink_jar="tink-${tink_version}.jar"
tink_sha256="92b8676c15b11a7faa15f3d1f05ed776a2897da3deba18c528ff32043339f248"

refaster_jar="error_prone_refaster-${errorprone_version}.jar"
refaster_sha256="0cde0a3db5c2f748fae4633ccd8c66a9ba9c5a0f7a380c9104b99372fd0c4959"
errorprone_jar="error_prone_core-${errorprone_version}-with-dependencies.jar"
errorprone_sha256="2b3f2d21e7754bece946cf8f7b0e2b2f805c46f58b4839eb302c3d2498a3a55e"

wget "https://${maven_base}/crypto/tink/tink/${tink_version}/${tink_jar}"
echo "${tink_sha256} ${tink_jar}" | sha256sum -c

wget "https://${maven_base}/errorprone/error_prone_refaster/${errorprone_version}/${refaster_jar}"
echo "${refaster_sha256} ${refaster_jar}" | sha256sum -c

wget "https://${maven_base}/errorprone/error_prone_core/${errorprone_version}/${errorprone_jar}"
echo "${errorprone_sha256} ${errorprone_jar}" | sha256sum -c

## STEP 2: Use the current file in tink1to2 to create a "tinkrule.refaster":
javac -cp "${tink_jar}:${refaster_jar}" \
    "-Xplugin:RefasterRuleCompiler --out ${PWD}/tinkrule.refaster" \
    java/com/google/tink1to2/KeysetHandleChanges.java

## STEP 3: Use error prone to create a patch:
javac -cp "${tink_jar}:${errorprone_jar}" \
           -XDcompilePolicy=byfile  \
           -processorpath "${errorprone_jar}" \
           "-Xplugin:ErrorProne -XepPatchChecks:refaster:${PWD}/tinkrule.refaster -XepPatchLocation:${PWD}" \
           java/com/google/tinkuser/TinkUser.java

cmp error-prone.patch expected-error-prone.patch
```

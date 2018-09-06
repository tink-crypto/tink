# Java Hello World

This is a command-line tool that can encrypt and decrypt small files with
AES128-GCM.

It demonstrates the basic steps of using Tink, namely generating or loading
key material, obtaining a primitive, and using the primitive to do crypto.

It also shows how to add a dependency on Tink using Maven. Please checkout
the pom.xml file.

Moreover, since this app shares the same Bazel's WORKSPACE with Tink, its
BUILD file can directly depend on Tink. Note that [a copy of this
app](https://github.com/thaidn/tink-examples/tree/master/helloworld/java) is
hosted in the tink-examples repo, which uses its own Bazel's WORKSAPCE,
and has to add Tink as a dependency using Bazel's maven\_jar rule.

## Build and Run

### Maven

```shell
git clone https://github.com/google/tink
cd tink/examples/helloworld/java
mvn package
echo foo > foo.txt
mvn exec:java -Dexec.args="encrypt --keyset test.cfg --in foo.txt --out bar.encrypted"
mvn exec:java -Dexec.args="decrypt --keyset test.cfg --in bar.encrypted --out foo2.txt"
cat foo2.txt
```

### Bazel

```shell
git clone https://github.com/google/tink
cd tink
bazel build //examples/helloworld/java/...
echo foo > foo.txt
./bazel-bin/examples/helloworld/java/helloworld encrypt --keyset test.cfg --in foo.txt --out bar.encrypted
./bazel-bin/examples/helloworld/java/helloworld decrypt --keyset test.cfg --in bar.encrypted --out foo2.txt
cat foo2.txt
```

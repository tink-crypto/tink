# Tink Java on Maven

Tink Java has 4 Maven artifacts, all are in the `com.google.crypto.tink` group.

### `tink`

The core of Tink built for server-side applications. It only depends on
[`com.google.code.gson:gson`](https://search.maven.org/artifact/com.google.code.gson/gson)
and
[`com.google.protobuf:protobuf-java`](https://search.maven.org/artifact/com.google.protobuf/protobuf-java).

### `tink-android`

Similar to `tink` but is built for Android applicationss.

This build includes an embeded copy
[`com.google.protobuf:protobuf-lite`](https://search.maven.org/artifact/com.google.protobuf/protobuf-javalite),
which is renamed to be `com.google.crypto.tink.shaded.protobuf`. This is done to
avoid dependency conflicts with other common dependencies that depend on a
conflicting version (e.g.  Firebase).

### `tink-awskms`

A plugin for the `tink` artifact that integrates Tink with AWS KMS.

### `tink-gcpkms`

A plugin for the `tink` artifact that integrates Tink with GCP KMS.

## Publishing snapshots

```shell
./maven/publish_snapshot.sh
```

This command publishes latest snapshots to Maven, and their Javadocs to
https://google.github.io/tink.

Snapshots are automatically published for every new commit to the master branch
of https://github.com/google/tink.

## Testing snapshots

```shell
./maven/test_snapshot.sh
```

New snapshots are also automatically tested for every new commit to the master
branch of https://github.com/google/tink.

## Adding a dependency

This should be considered only when there is no other option, 'cause adding
dependency makes Tink bloated and less secure. If a dependency got tampered
with, Tink would also be affected.

This process consists of 3 steps:

1.  To add a dependency for an artifact, you add it to the artifact's `pom.xml`.
    For example, the `com.google.crypto.tink:tink` artifact uses `tink.pom.xml`.
    You should always depend on the latest version of the dependency on Maven
    Central.

2.  Next, you want to publish a new snapshot of the artifact with the new
    dependency.

3.  Then you want to test the new snapshot.

You want to repeat these steps until there is no error.

If you encounter `Dependency convergence` error, it means that the artifact has
already, usually indirectly, depended on another version of the new dependency.
You want to exclude that version.

See the history of the POM files for examples.

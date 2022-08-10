# An implementation of Google AdMob Rewarded Ads

This app implements the verifier side of Server-Side Verification of Google
AdMob Rewarded Ads.

## Latest Release

The most recent release is
[1.7.0](https://github.com/google/tink/releases/tag/v1.7.0), released
2022-08-09. API docs can be found
[here](https://google.github.io/tink/javadoc/apps-rewardedads/1.7.0).

The Maven group ID is `com.google.crypto.tink`, and the artifact ID is
`apps-rewardedads`.

To add a dependency using Maven:

```xml
<dependency>
  <groupId>com.google.crypto.tink</groupId>
  <artifactId>apps-rewardedads</artifactId>
  <version>1.7.0</version>
</dependency>
```

## Snapshots

Snapshots of this app built from the master branch are available through Maven
using version `HEAD-SNAPSHOT`. API docs can be found
[here](https://google.github.io/tink/javadoc/apps-rewardedads/HEAD-SNAPSHOT).

To add a dependency using Maven:

```xml
<repositories>
<repository>
  <id>sonatype-snapshots</id>
  <name>sonatype-snapshots</name>
  <url>https://oss.sonatype.org/content/repositories/snapshots/</url>
  <snapshots>
    <enabled>true</enabled>
    <updatePolicy>always</updatePolicy>
  </snapshots>
  <releases>
    <updatePolicy>always</updatePolicy>
  </releases>
</repository>
</repositories>

<dependency>
  <groupId>com.google.crypto.tink</groupId>
  <artifactId>apps-rewardedads</artifactId>
  <version>HEAD-SNAPSHOT</version>
</dependency>
```

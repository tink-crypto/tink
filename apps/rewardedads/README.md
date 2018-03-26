# An implementation of Google AdMob Rewarded Ads

This app implements the verifier side of Server-Side Verification of Google
AdMob Rewarded Ads.

## Snapshots

This app has yet not been released, though you can still play with it using
snapshot versions.

Snapshots of this app built from the master branch are available through Maven
using version `HEAD-SNAPSHOT`. API docs can be found
[here](https://google.github.com/tink/javadoc/apps-rewardedads/HEAD-SNAPSHOT).

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

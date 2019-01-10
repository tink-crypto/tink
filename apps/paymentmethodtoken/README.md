# An implementation of [Google Payment Method Token](https://developers.google.com/pay/api/payment-data-cryptography).

## Latest release

The most recent release is
[1.2.1](https://github.com/google/tink/releases/tag/v1.2.1), released
2018-08-09. API docs can be found
[here](https://google.github.com/tink/javadoc/apps-paymentmethodtoken/1.2.1).

The Maven group ID is `com.google.crypto.tink`, and the artifact ID is
`apps-paymentmethodtoken`.

To add a dependency using Maven:

```xml
<dependency>
  <groupId>com.google.crypto.tink</groupId>
  <artifactId>apps-paymentmethodtoken</artifactId>
  <version>1.2.1</version>
</dependency>
```

## Snapshots

Snapshots of this app built from the master branch are available through Maven
using version `HEAD-SNAPSHOT`. API docs can be found
[here](https://google.github.com/tink/javadoc/apps-paymentmethodtoken/HEAD-SNAPSHOT).

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
  <artifactId>apps-paymentmethodtoken</artifactId>
  <version>HEAD-SNAPSHOT</version>
</dependency>
```

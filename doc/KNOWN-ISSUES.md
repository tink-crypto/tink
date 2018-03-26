# Known Issues

This doc lists known issues in Tink. Please report new issues by opening new
tickets or emailing the maintainers at `tink-dev@googlegroups.com`.

## All Android versions

*   The minimum API level that Tink supports is 19 (Android KitKat). This covers
    more than 90% of all Android phones. Tink hasn't been tested on older
    versions. It might or might not work. Drop us a line if you really need to
    support ancient Android phones.

*   On Android Marshmallow (API level 23) or older, the
    `newSeekableDecryptingChannel` method in implementations of `StreamingAead`
    doesn't work. It depends on
    [SeekableByteChannel](https://developer.android.com/reference/java/nio/channels/SeekableByteChannel.html),
    which is only available on API level 24 or newer. Users should use
    `newEncryptingStream` instead.

*   On Android Lollipop (API level 21) or older, `AndroidKeysetManager` does not
    support wrapping keysets with Android Keystore, but it'd store keysets in
    cleartext in private preference. This is secure enough for most
    applications.

*   On Android KitKat (API level 19) without [Google Play
    Services](https://developers.google.com/android/guides/overview), `AES-GCM`
    does not work properly because KitKat uses Bouncy Castle 1.48 which doesn't
    support updateAAD. If Google Play Services is present, `AES-GCM` should work
    well. If you want to support all Android versions, without depending on
    Google Play Services, please use `CHACHA20-POLY1305`, `AES-EAX`, or
    `AES-CTR-HMAC-AEAD`.

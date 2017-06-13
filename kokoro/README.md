# Presubmit test for Tink on GoB

This repo uses Kokoro for presubmit tests.

  * build config: https://ise-crypto-internal.git.corp.google.com/cloudcryptosdk/+/master/kokoro/.
  * job config: https://cs.corp.google.com/piper///depot/google3/devtools/kokoro/config/prod/tink/gob/.

There are two jobs: Ubuntu and MacOS. MacOS is failing and disabled because of
outdated JDK, see b/35928521.

See also https://goto.google.com/tink-presubmit for how presubmit is set up on
GitHub or Piper.


# Tink presubmit tests and continuous integration

![Kokoro Ubuntu](https://storage.googleapis.com/tink-kokoro-build-badges/tink-ubuntu.png)
![Kokoro macOS](https://storage.googleapis.com/tink-kokoro-build-badges/tink-macos.png)

Tink is testing continuously with
[Kokoro](https://www.cloudbees.com/sites/default/files/2016-jenkins-world-jenkins_inside_google.pdf)
an internal deployment of Jenkins at Google.

Continuous builds and presubmit tests are run on Ubuntu and macOS.

Presubmit tests are triggered for the pull request if one of the following
conditions is met:

 - The pull request is created by a Googler.
 - The pull request is attached with a kokoro:run label.

Continuous builds are triggered for every new commit, and upload to Maven snapshot
versions of Tink and apps.

# Tink presubmit tests and continuous integration

![Kokoro Ubuntu](https://storage.googleapis.com/tink-kokoro-build-badges/tink-ubuntu.png)
![Kokoro macOS](https://storage.googleapis.com/tink-kokoro-build-badges/tink-macos.png)

Tink is automatically tested using
[Kokoro](https://www.cloudbees.com/sites/default/files/2016-jenkins-world-jenkins_inside_google.pdf),
an internal deployment of Jenkins at Google.

Continuous builds and presubmit tests are run on Ubuntu and macOS.

## Continuous builds

Continuous builds are triggered for every new commit to the master branch and
the current release branch.

For the master branch, at the end of a successful
continious build, a snapshot of Tink and the example apps are created and
uploaded to Maven.

## Presubmit testing

Presubmit tests are triggered for a pull request if one of the following
conditions is met:

 - The pull request is created by a Googler.
 - The pull request is attached with a `kokoro:run` label.

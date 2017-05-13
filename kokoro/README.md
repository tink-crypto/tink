# Tink presubmit and continous test

![Kokoro Ubuntu](https://storage.googleapis.com/tink-kokoro-build-badges/tink.png)

Tink is testing continously with [Kokoro](https://www.cloudbees.com/sites/default/files/2016-jenkins-world-jenkins_inside_google.pdf)
an internal deployment of Jenkins at Google.

Kokoro will poll from this repo every 5 minutes and trigger a continuous build
if there are new commits.

A presubmit build will be triggered for the pull request if one of the
following conditions is met:

  * Pull request is created by a Googler.
  * Pull request is attached with a kokoro:run label.

Continuous and presubmit builds are done on Ubuntu.

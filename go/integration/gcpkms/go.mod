module github.com/google/tink/go/integration/gcpkms

go 1.12

replace github.com/google/tink/go v1.4.0 => ../..

require (
  github.com/google/tink/go v1.4.0
  golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
  google.golang.org/api v0.32.0
)

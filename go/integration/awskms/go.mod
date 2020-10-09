module github.com/google/tink/go/integration/awskms

go 1.12

replace github.com/google/tink/go v1.4.0 => ../..

require (
  github.com/aws/aws-sdk-go v1.35.6
  github.com/google/tink/go v1.4.0
)

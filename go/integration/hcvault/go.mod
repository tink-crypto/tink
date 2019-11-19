module github.com/google/tink/go/integration/hcvault

go 1.12

require (
  // TODO(oleksiys): Fix the core tink module dependency to v1.3.0 once it's released.
  github.com/google/tink v1.3.0-rc1.0.20190919192935-b4142f9ab6af
  github.com/hashicorp/vault/api v1.0.4
)

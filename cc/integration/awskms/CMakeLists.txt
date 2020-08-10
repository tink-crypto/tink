tink_module(awskms)

tink_cc_library(
  NAME aws_crypto
  SRCS
    aws_crypto.cc
    aws_crypto.h
  DEPS
    absl::base
    crypto
    aws-sdk::core
    aws-sdk::kms
)

tink_cc_library(
  NAME aws_kms_aead
  SRCS
    aws_kms_aead.cc
    aws_kms_aead.h
  DEPS
    absl::strings
    tink::core::aead
    tink::util::errors
    tink::util::status
    tink::util::statusor
    aws-sdk::core
    aws-sdk::kms
)

tink_cc_library(
  NAME aws_kms_client
  SRCS
    aws_kms_client.cc
    aws_kms_client.h
  DEPS
    absl::strings
    absl::synchronization
    tink::awskms::aws_crypto
    tink::awskms::aws_kms_aead
    tink::core::kms_client
    tink::util::errors
    tink::util::status
    tink::util::statusor
    aws-sdk::core
    aws-sdk::kms
)

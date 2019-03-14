tink_module(proto)

tink_cc_proto(
  NAME common
  SRCS common.proto
)

tink_cc_proto(
  NAME tink
  SRCS tink.proto
  DEPS tink::proto::common
)

tink_cc_proto(
  NAME config
  SRCS config.proto
)

tink_cc_proto(
  NAME aes_siv
  SRCS aes_siv.proto
)

tink_cc_proto(
  NAME rsa_ssa_pkcs1
  SRCS rsa_ssa_pkcs1.proto
  DEPS tink::proto::common
)

tink_cc_proto(
  NAME rsa_ssa_pss
  SRCS rsa_ssa_pss.proto
  DEPS tink::proto::common
)

tink_cc_proto(
  NAME ecdsa
  SRCS ecdsa.proto
  DEPS tink::proto::common
)

tink_cc_proto(
  NAME ed25519
  SRCS ed25519.proto
)

tink_cc_proto(
  NAME hmac
  SRCS hmac.proto
  DEPS tink::proto::common
)

tink_cc_proto(
  NAME aes_ctr
  SRCS aes_ctr.proto
)

tink_cc_proto(
  NAME aes_ctr_hmac_aead
  SRCS aes_ctr_hmac_aead.proto
  DEPS
    tink::proto::aes_ctr
    tink::proto::hmac
)

tink_cc_proto(
  NAME aes_gcm
  SRCS aes_gcm.proto
)

tink_cc_proto(
  NAME aes_ctr_hmac_streaming
  SRCS aes_ctr_hmac_streaming.proto
  DEPS
    tink::proto::common
    tink::proto::hmac
)

tink_cc_proto(
  NAME aes_gcm_hkdf_streaming
  SRCS aes_gcm_hkdf_streaming.proto
  DEPS tink::proto::common
)

tink_cc_proto(
  NAME aes_eax
  SRCS aes_eax.proto
)

tink_cc_proto(
  NAME chacha20_poly1305
  SRCS chacha20_poly1305.proto
)

tink_cc_proto(
  NAME kms_aead
  SRCS kms_aead.proto
)

tink_cc_proto(
  NAME kms_envelope
  SRCS kms_envelope.proto
  DEPS tink::proto::tink
)

tink_cc_proto(
  NAME ecies_aead_hkdf
  SRCS ecies_aead_hkdf.proto
  DEPS
    tink::proto::common
    tink::proto::tink
)

tink_cc_proto(
  NAME xchacha20_poly1305
  SRCS xchacha20_poly1305.proto
)

tink_cc_proto(
  NAME empty
  SRCS empty.proto
)

tink_target_group(
  NAME public_protos
  DEPS
    tink::proto::config
    tink::proto::tink
)

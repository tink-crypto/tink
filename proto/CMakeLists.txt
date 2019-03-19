tink_module(proto)

tink_cc_proto(
  NAME common_cc_proto
  SRCS common.proto
)

tink_cc_proto(
  NAME tink_cc_proto
  SRCS tink.proto
  DEPS tink::proto::common_cc_proto
)

tink_cc_proto(
  NAME config_cc_proto
  SRCS config.proto
)

tink_cc_proto(
  NAME aes_siv_cc_proto
  SRCS aes_siv.proto
)

tink_cc_proto(
  NAME rsa_ssa_pkcs1_cc_proto
  SRCS rsa_ssa_pkcs1.proto
  DEPS tink::proto::common_cc_proto
)

tink_cc_proto(
  NAME rsa_ssa_pss_cc_proto
  SRCS rsa_ssa_pss.proto
  DEPS tink::proto::common_cc_proto
)

tink_cc_proto(
  NAME ecdsa_cc_proto
  SRCS ecdsa.proto
  DEPS tink::proto::common_cc_proto
)

tink_cc_proto(
  NAME ed25519_cc_proto
  SRCS ed25519.proto
)

tink_cc_proto(
  NAME hmac_cc_proto
  SRCS hmac.proto
  DEPS tink::proto::common_cc_proto
)

tink_cc_proto(
  NAME aes_ctr_cc_proto
  SRCS aes_ctr.proto
)

tink_cc_proto(
  NAME aes_ctr_hmac_aead_cc_proto
  SRCS aes_ctr_hmac_aead.proto
  DEPS
    tink::proto::aes_ctr_cc_proto
    tink::proto::hmac_cc_proto
)

tink_cc_proto(
  NAME aes_gcm_cc_proto
  SRCS aes_gcm.proto
)

tink_cc_proto(
  NAME aes_ctr_hmac_streaming_cc_proto
  SRCS aes_ctr_hmac_streaming.proto
  DEPS
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
)

tink_cc_proto(
  NAME aes_gcm_hkdf_streaming_cc_proto
  SRCS aes_gcm_hkdf_streaming.proto
  DEPS tink::proto::common_cc_proto
)

tink_cc_proto(
  NAME aes_eax_cc_proto
  SRCS aes_eax.proto
)

tink_cc_proto(
  NAME chacha20_poly1305_cc_proto
  SRCS chacha20_poly1305.proto
)

tink_cc_proto(
  NAME kms_aead_cc_proto
  SRCS kms_aead.proto
)

tink_cc_proto(
  NAME kms_envelope_cc_proto
  SRCS kms_envelope.proto
  DEPS tink::proto::tink_cc_proto
)

tink_cc_proto(
  NAME ecies_aead_hkdf_cc_proto
  SRCS ecies_aead_hkdf.proto
  DEPS
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_proto(
  NAME xchacha20_poly1305_cc_proto
  SRCS xchacha20_poly1305.proto
)

tink_cc_proto(
  NAME empty_cc_proto
  SRCS empty.proto
)

tink_target_group(
  NAME public_protos_cc_proto
  DEPS
    tink::proto::config_cc_proto
    tink::proto::tink_cc_proto
)

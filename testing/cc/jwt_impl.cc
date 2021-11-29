// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

// Implementation of a JWT Service.
#include "jwt_impl.h"

#include <string>
#include <utility>

#include "absl/time/time.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/util/status.h"
#include "tink/jwt/jwk_set_converter.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::JwtMac;
using ::crypto::tink::JwtPublicKeySign;
using ::crypto::tink::JwtPublicKeyVerify;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::KeysetReader;
using ::crypto::tink::RawJwt;
using ::crypto::tink::VerifiedJwt;
using ::crypto::tink::util::StatusOr;

using ::crypto::tink::JwkSetToPublicKeysetHandle;
using ::grpc::ServerContext;

absl::Time TimestampToTime(tink_testing_api::Timestamp t) {
    return absl::FromUnixMillis(t.seconds() * 1000 + t.nanos() / 1000000);
}

Timestamp TimeToTimestamp(absl::Time time) {
  int64_t millis = absl::ToUnixMillis(time);
  int64_t seconds = millis / 1000;
  int32_t nanos = (millis - seconds * 1000) * 1000000;
  Timestamp timestamp;
  timestamp.set_seconds(seconds);
  timestamp.set_nanos(nanos);
  return timestamp;
}

crypto::tink::util::StatusOr<crypto::tink::RawJwt> RawJwtFromProto(
    const JwtToken& raw_jwt_proto) {
  auto builder = crypto::tink::RawJwtBuilder();
  if (raw_jwt_proto.has_type_header()) {
    builder.SetTypeHeader(raw_jwt_proto.type_header().value());
  }
  if (raw_jwt_proto.has_issuer()) {
    builder.SetIssuer(raw_jwt_proto.issuer().value());
  }
  if (raw_jwt_proto.has_subject()) {
    builder.SetSubject(raw_jwt_proto.subject().value());
  }
  for (const std::string& audience : raw_jwt_proto.audiences()) {
    builder.AddAudience(audience);
  }
  if (raw_jwt_proto.has_jwt_id()) {
    builder.SetJwtId(raw_jwt_proto.jwt_id().value());
  }
  if (raw_jwt_proto.has_expiration()) {
    builder.SetExpiration(TimestampToTime(raw_jwt_proto.expiration()));
  } else {
    builder.WithoutExpiration();
  }
  if (raw_jwt_proto.has_issued_at()) {
    builder.SetIssuedAt(TimestampToTime(raw_jwt_proto.issued_at()));
  }
  if (raw_jwt_proto.has_not_before()) {
    builder.SetNotBefore(TimestampToTime(raw_jwt_proto.not_before()));
  }
  auto claims = raw_jwt_proto.custom_claims();
  for (auto it = claims.begin(); it != claims.end(); it++) {
    const auto& name = it->first;
    const auto& value = it->second;
    if (value.kind_case() == JwtClaimValue::kNullValue) {
      builder.AddNullClaim(name);
    } else if (value.kind_case() == JwtClaimValue::kBoolValue) {
      builder.AddBooleanClaim(name, value.bool_value());
    } else if (value.kind_case() == JwtClaimValue::kNumberValue) {
      builder.AddNumberClaim(name, value.number_value());
    } else if (value.kind_case() == JwtClaimValue::kStringValue) {
      builder.AddStringClaim(name, value.string_value());
    } else if (value.kind_case() == JwtClaimValue::kJsonObjectValue) {
      builder.AddJsonObjectClaim(name, value.json_object_value());
    } else if (value.kind_case() == JwtClaimValue::kJsonArrayValue) {
      builder.AddJsonArrayClaim(name, value.json_array_value());
    }
  }
  return builder.Build();
}

JwtToken VerifiedJwtToProto(const crypto::tink::VerifiedJwt& verified_jwt) {
  JwtToken token;
  if (verified_jwt.HasTypeHeader()) {
    token.mutable_type_header()->set_value(
        verified_jwt.GetTypeHeader().ValueOrDie());
  }
  if (verified_jwt.HasIssuer()) {
    token.mutable_issuer()->set_value(verified_jwt.GetIssuer().ValueOrDie());
  }
  if (verified_jwt.HasSubject()) {
    token.mutable_subject()->set_value(verified_jwt.GetSubject().ValueOrDie());
  }
  if (verified_jwt.HasAudiences()) {
    std::vector<std::string> audiences =
        verified_jwt.GetAudiences().ValueOrDie();
    for (const std::string& audience : audiences) {
      token.add_audiences(audience);
    }
  }
  if (verified_jwt.HasJwtId()) {
    token.mutable_jwt_id()->set_value(verified_jwt.GetJwtId().ValueOrDie());
  }
  if (verified_jwt.HasExpiration()) {
    *token.mutable_expiration() =
        TimeToTimestamp(verified_jwt.GetExpiration().ValueOrDie());
  }
  if (verified_jwt.HasIssuedAt()) {
    *token.mutable_issued_at() =
        TimeToTimestamp(verified_jwt.GetIssuedAt().ValueOrDie());
  }
  if (verified_jwt.HasNotBefore()) {
    *token.mutable_not_before() =
        TimeToTimestamp(verified_jwt.GetNotBefore().ValueOrDie());
  }
  std::vector<std::string> names = verified_jwt.CustomClaimNames();
  for (const std::string& name : names) {
    if (verified_jwt.IsNullClaim(name)) {
      (*token.mutable_custom_claims())[name].set_null_value(
          NullValue::NULL_VALUE);
    } else if (verified_jwt.HasBooleanClaim(name)) {
      (*token.mutable_custom_claims())[name].set_bool_value(
          verified_jwt.GetBooleanClaim(name).ValueOrDie());
    } else if (verified_jwt.HasNumberClaim(name)) {
      (*token.mutable_custom_claims())[name].set_number_value(
          verified_jwt.GetNumberClaim(name).ValueOrDie());
    } else if (verified_jwt.HasStringClaim(name)) {
      (*token.mutable_custom_claims())[name].set_string_value(
          verified_jwt.GetStringClaim(name).ValueOrDie());
    } else if (verified_jwt.HasJsonObjectClaim(name)) {
      (*token.mutable_custom_claims())[name].set_json_object_value(
          verified_jwt.GetJsonObjectClaim(name).ValueOrDie());
    } else if (verified_jwt.HasJsonArrayClaim(name)) {
      (*token.mutable_custom_claims())[name].set_json_array_value(
          verified_jwt.GetJsonArrayClaim(name).ValueOrDie());
    }
  }
  return token;
}

crypto::tink::util::StatusOr<crypto::tink::JwtValidator> JwtValidatorFromProto(
    const JwtValidator& validator_proto) {
  auto builder = crypto::tink::JwtValidatorBuilder();
  if (validator_proto.has_expected_type_header()) {
    builder.ExpectTypeHeader(validator_proto.expected_type_header().value());
  }
  if (validator_proto.has_expected_issuer()) {
    builder.ExpectIssuer(validator_proto.expected_issuer().value());
  }
  if (validator_proto.has_expected_audience()) {
    builder.ExpectAudience(validator_proto.expected_audience().value());
  }
  if (validator_proto.ignore_type_header()) {
    builder.IgnoreTypeHeader();
  }
  if (validator_proto.ignore_issuer()) {
    builder.IgnoreIssuer();
  }
  if (validator_proto.ignore_audience()) {
    builder.IgnoreAudiences();
  }
  if (validator_proto.allow_missing_expiration()) {
    builder.AllowMissingExpiration();
  }
  if (validator_proto.expect_issued_in_the_past()) {
    builder.ExpectIssuedInThePast();
  }
  if (validator_proto.has_now()) {
    builder.SetFixedNow(TimestampToTime(validator_proto.now()));
  }
  if (validator_proto.has_clock_skew()) {
    builder.SetClockSkew(
        absl::Seconds(validator_proto.clock_skew().seconds()));
  }
  return builder.Build();
}

// Computes a MAC and generates a signed compact JWT
grpc::Status JwtImpl::ComputeMacAndEncode(grpc::ServerContext* context,
                                            const JwtSignRequest* request,
                                            JwtSignResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(request->keyset());
  if (!reader.ok()) {
    response->set_err(std::string(reader.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> handle =
      CleartextKeysetHandle::Read(*std::move(reader));
  if (!handle.ok()) {
    response->set_err(std::string(handle.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<JwtMac>> jwt_mac =
      (*handle)->GetPrimitive<JwtMac>();
  if (!jwt_mac.ok()) {
    response->set_err(std::string(jwt_mac.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<RawJwt> raw_jwt = RawJwtFromProto(request->raw_jwt());
  if (!raw_jwt.ok()) {
    response->set_err(std::string(raw_jwt.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncode(*raw_jwt);
  if (!compact.ok()) {
    response->set_err(std::string(compact.status().message()));
    return grpc::Status::OK;
  }
  response->set_signed_compact_jwt(*compact);
  return grpc::Status::OK;
}

// Verifies a signed compact JWT
grpc::Status JwtImpl::VerifyMacAndDecode(grpc::ServerContext* context,
                                           const JwtVerifyRequest* request,
                                           JwtVerifyResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(request->keyset());
  if (!reader.ok()) {
    response->set_err(std::string(reader.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> handle =
      CleartextKeysetHandle::Read(*std::move(reader));
  if (!handle.ok()) {
    response->set_err(std::string(handle.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<JwtMac>> jwt_mac = (*handle)->GetPrimitive<JwtMac>();
  if (!jwt_mac.ok()) {
    response->set_err(std::string(jwt_mac.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<crypto::tink::JwtValidator> validator =
      JwtValidatorFromProto(request->validator());
  StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecode(request->signed_compact_jwt(), *validator);
  if (!verified_jwt.ok()) {
    response->set_err(std::string(verified_jwt.status().message()));
    return grpc::Status::OK;
  }
  *response->mutable_verified_jwt() = VerifiedJwtToProto(*verified_jwt);
  return grpc::Status::OK;
}

grpc::Status JwtImpl::PublicKeySignAndEncode(grpc::ServerContext* context,
                                   const JwtSignRequest* request,
                                   JwtSignResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(request->keyset());
  if (!reader.ok()) {
    response->set_err(std::string(reader.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> handle =
      CleartextKeysetHandle::Read(*std::move(reader));
  if (!handle.ok()) {
    response->set_err(std::string(handle.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign =
      (*handle)->GetPrimitive<JwtPublicKeySign>();
  if (!jwt_sign.ok()) {
    response->set_err(std::string(jwt_sign.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<RawJwt> raw_jwt = RawJwtFromProto(request->raw_jwt());
  if (!raw_jwt.ok()) {
    response->set_err(std::string(raw_jwt.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::string> compact = (*jwt_sign)->SignAndEncode(*raw_jwt);
  if (!compact.ok()) {
    response->set_err(std::string(compact.status().message()));
    return grpc::Status::OK;
  }
  response->set_signed_compact_jwt(*compact);
  return grpc::Status::OK;
}

grpc::Status JwtImpl::PublicKeyVerifyAndDecode(grpc::ServerContext* context,
                                        const JwtVerifyRequest* request,
                                        JwtVerifyResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(request->keyset());
  if (!reader.ok()) {
    response->set_err(std::string(reader.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> handle =
      CleartextKeysetHandle::Read(*std::move(reader));
  if (!handle.ok()) {
    response->set_err(std::string(handle.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify =
      (*handle)->GetPrimitive<JwtPublicKeyVerify>();
  if (!jwt_verify.ok()) {
    response->set_err(std::string(jwt_verify.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<crypto::tink::JwtValidator> validator =
      JwtValidatorFromProto(request->validator());
  StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_verify)->VerifyAndDecode(request->signed_compact_jwt(), *validator);
  if (!verified_jwt.ok()) {
    response->set_err(std::string(verified_jwt.status().message()));
    return grpc::Status::OK;
  }
  *response->mutable_verified_jwt() = VerifiedJwtToProto(*verified_jwt);
  return grpc::Status::OK;
}

::grpc::Status JwtImpl::ToJwkSet(grpc::ServerContext* context,
                                 const JwtToJwkSetRequest* request,
                                 JwtToJwkSetResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(request->keyset());
  if (!reader.ok()) {
    response->set_err(std::string(reader.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> handle =
      CleartextKeysetHandle::Read(*std::move(reader));
  if (!handle.ok()) {
    response->set_err(std::string(handle.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::string> jwk_set = JwkSetFromPublicKeysetHandle(**handle);
  if (!jwk_set.ok()) {
    response->set_err(std::string(jwk_set.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_jwk_set(*jwk_set);
  return ::grpc::Status::OK;
}

::grpc::Status JwtImpl::FromJwkSet(grpc::ServerContext* context,
                                   const JwtFromJwkSetRequest* request,
                                   JwtFromJwkSetResponse* response) {
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      JwkSetToPublicKeysetHandle(request->jwk_set());
  if (!keyset_handle.ok()) {
    response->set_err(keyset_handle.status().error_message());
    return ::grpc::Status::OK;
  }
  std::stringbuf keyset;
  StatusOr<std::unique_ptr<crypto::tink::BinaryKeysetWriter>> writer =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!writer.ok()) {
    response->set_err(writer.status().error_message());
    return ::grpc::Status::OK;
  }
  crypto::tink::util::Status status =
      CleartextKeysetHandle::Write(writer->get(), **keyset_handle);
  if (!status.ok()) {
    response->set_err(status.error_message());
    return ::grpc::Status::OK;
  }
  response->set_keyset(keyset.str());
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api

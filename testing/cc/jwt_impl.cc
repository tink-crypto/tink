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

#include "absl/time/time.h"
#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "proto/testing/testing_api.grpc.pb.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/util/status.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::util::StatusOr;
using ::crypto::tink::JwtPublicKeySign;
using ::crypto::tink::JwtPublicKeyVerify;
using ::crypto::tink::JwtMac;
using ::crypto::tink::RawJwt;
using ::crypto::tink::VerifiedJwt;
using ::crypto::tink::KeysetReader;

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
::grpc::Status JwtImpl::ComputeMacAndEncode(grpc::ServerContext* context,
                                            const JwtSignRequest* request,
                                            JwtSignResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> reader_or =
      BinaryKeysetReader::New(request->keyset());
  if (!reader_or.ok()) {
    response->set_err(std::string(reader_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> handle_or =
      CleartextKeysetHandle::Read(std::move(reader_or.ValueOrDie()));
  if (!handle_or.ok()) {
    response->set_err(std::string(handle_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<JwtMac>> jwt_mac_or =
      handle_or.ValueOrDie()->GetPrimitive<JwtMac>();
  if (!jwt_mac_or.ok()) {
    response->set_err(std::string(jwt_mac_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<RawJwt> raw_jwt_or = RawJwtFromProto(request->raw_jwt());
  if (!raw_jwt_or.ok()) {
    response->set_err(std::string(raw_jwt_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::string> compact_or =
      jwt_mac_or.ValueOrDie()->ComputeMacAndEncode(raw_jwt_or.ValueOrDie());
  if (!compact_or.ok()) {
    response->set_err(std::string(compact_or.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_signed_compact_jwt(compact_or.ValueOrDie());
  return ::grpc::Status::OK;
}

// Verifies a signed compact JWT
::grpc::Status JwtImpl::VerifyMacAndDecode(grpc::ServerContext* context,
                                           const JwtVerifyRequest* request,
                                           JwtVerifyResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> reader_or =
      BinaryKeysetReader::New(request->keyset());
  if (!reader_or.ok()) {
    response->set_err(std::string(reader_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> handle_or =
      CleartextKeysetHandle::Read(std::move(reader_or.ValueOrDie()));
  if (!handle_or.ok()) {
    response->set_err(std::string(handle_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<JwtMac>> jwt_mac_or =
      handle_or.ValueOrDie()->GetPrimitive<JwtMac>();
  if (!jwt_mac_or.ok()) {
    response->set_err(std::string(jwt_mac_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<crypto::tink::JwtValidator> validator_or =
      JwtValidatorFromProto(request->validator());
  StatusOr<VerifiedJwt> verified_jwt_or =
      jwt_mac_or.ValueOrDie()->VerifyMacAndDecode(request->signed_compact_jwt(),
                                                  validator_or.ValueOrDie());
  if (!verified_jwt_or.ok()) {
    response->set_err(std::string(verified_jwt_or.status().message()));
    return ::grpc::Status::OK;
  }
  *response->mutable_verified_jwt() =
      VerifiedJwtToProto(verified_jwt_or.ValueOrDie());
  return ::grpc::Status::OK;
}

::grpc::Status JwtImpl::PublicKeySignAndEncode(grpc::ServerContext* context,
                                   const JwtSignRequest* request,
                                   JwtSignResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> reader_or =
      BinaryKeysetReader::New(request->keyset());
  if (!reader_or.ok()) {
    response->set_err(std::string(reader_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> handle_or =
      CleartextKeysetHandle::Read(std::move(reader_or.ValueOrDie()));
  if (!handle_or.ok()) {
    response->set_err(std::string(handle_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign_or =
      handle_or.ValueOrDie()->GetPrimitive<JwtPublicKeySign>();
  if (!jwt_sign_or.ok()) {
    response->set_err(std::string(jwt_sign_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<RawJwt> raw_jwt_or = RawJwtFromProto(request->raw_jwt());
  if (!raw_jwt_or.ok()) {
    response->set_err(std::string(raw_jwt_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::string> compact_or =
      jwt_sign_or.ValueOrDie()->SignAndEncode(raw_jwt_or.ValueOrDie());
  if (!compact_or.ok()) {
    response->set_err(std::string(compact_or.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_signed_compact_jwt(compact_or.ValueOrDie());
  return ::grpc::Status::OK;
}

::grpc::Status JwtImpl::PublicKeyVerifyAndDecode(grpc::ServerContext* context,
                                        const JwtVerifyRequest* request,
                                        JwtVerifyResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> reader_or =
      BinaryKeysetReader::New(request->keyset());
  if (!reader_or.ok()) {
    response->set_err(std::string(reader_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> handle_or =
      CleartextKeysetHandle::Read(std::move(reader_or.ValueOrDie()));
  if (!handle_or.ok()) {
    response->set_err(std::string(handle_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify_or =
      handle_or.ValueOrDie()->GetPrimitive<JwtPublicKeyVerify>();
  if (!jwt_verify_or.ok()) {
    response->set_err(std::string(jwt_verify_or.status().message()));
    return ::grpc::Status::OK;
  }
  StatusOr<crypto::tink::JwtValidator> validator_or =
      JwtValidatorFromProto(request->validator());
  StatusOr<VerifiedJwt> verified_jwt_or =
      jwt_verify_or.ValueOrDie()->VerifyAndDecode(request->signed_compact_jwt(),
                                                  validator_or.ValueOrDie());
  if (!verified_jwt_or.ok()) {
    response->set_err(std::string(verified_jwt_or.status().message()));
    return ::grpc::Status::OK;
  }
  *response->mutable_verified_jwt() =
      VerifiedJwtToProto(verified_jwt_or.ValueOrDie());
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api

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
#include "proto/testing/testing_api.grpc.pb.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/util/status.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::CleartextKeysetHandle;
using ::grpc::ServerContext;

crypto::tink::util::StatusOr<crypto::tink::RawJwt> RawJwtFromProto(
    const JwtToken& raw_jwt_proto) {
  auto builder = crypto::tink::RawJwtBuilder();
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
    builder.SetExpiration(
        absl::FromUnixSeconds(raw_jwt_proto.expiration().seconds()));
  }
  if (raw_jwt_proto.has_issued_at()) {
    builder.SetIssuedAt(
        absl::FromUnixSeconds(raw_jwt_proto.issued_at().seconds()));
  }
  if (raw_jwt_proto.has_not_before()) {
    builder.SetNotBefore(
        absl::FromUnixSeconds(raw_jwt_proto.not_before().seconds()));
  }
  auto claims = raw_jwt_proto.custom_claims();
  for (auto it = claims.begin(); it != claims.end(); it++) {
    const auto& name = it->first;
    const auto& value = it->second;
    if (value.kind_case() == JwtClaimValue::kNullValue) {
      auto status = builder.AddNullClaim(name);
      if (!status.ok()) {
        return status;
      }
    } else if (value.kind_case() == JwtClaimValue::kBoolValue) {
      auto status = builder.AddBooleanClaim(name, value.bool_value());
      if (!status.ok()) {
        return status;
      }
    } else if (value.kind_case() == JwtClaimValue::kNumberValue) {
      auto status = builder.AddNumberClaim(name, value.number_value());
      if (!status.ok()) {
        return status;
      }
    } else if (value.kind_case() == JwtClaimValue::kStringValue) {
      auto status = builder.AddStringClaim(name, value.string_value());
      if (!status.ok()) {
        return status;
      }
    } else if (value.kind_case() == JwtClaimValue::kJsonObjectValue) {
      auto status = builder.AddJsonObjectClaim(name, value.json_object_value());
      if (!status.ok()) {
        return status;
      }
    } else if (value.kind_case() == JwtClaimValue::kJsonArrayValue) {
      auto status = builder.AddJsonArrayClaim(name, value.json_array_value());
      if (!status.ok()) {
        return status;
      }
    }
  }
  return builder.Build();
}

JwtToken VerifiedJwtToProto(const crypto::tink::VerifiedJwt& verified_jwt) {
  JwtToken token;
  if (verified_jwt.HasIssuer()) {
    token.mutable_issuer()->set_value(verified_jwt.GetIssuer().ValueOrDie());
  }
  if (verified_jwt.HasSubject()) {
    token.mutable_subject()->set_value(verified_jwt.GetSubject().ValueOrDie());
  }
  if (verified_jwt.HasAudiences()) {
    auto audiences = verified_jwt.GetAudiences().ValueOrDie();
    for (const std::string& audience : audiences) {
      token.add_audiences(audience);
    }
  }
  if (verified_jwt.HasJwtId()) {
    token.mutable_jwt_id()->set_value(verified_jwt.GetJwtId().ValueOrDie());
  }
  if (verified_jwt.HasExpiration()) {
    token.mutable_expiration()
        ->set_seconds(
            absl::ToUnixSeconds(verified_jwt.GetExpiration().ValueOrDie()));
  }
  if (verified_jwt.HasIssuedAt()) {
    token.mutable_issued_at()
        ->set_seconds(
            absl::ToUnixSeconds(verified_jwt.GetIssuedAt().ValueOrDie()));
  }
  if (verified_jwt.HasNotBefore()) {
    token.mutable_not_before()
        ->set_seconds(
            absl::ToUnixSeconds(verified_jwt.GetNotBefore().ValueOrDie()));
  }
  for (const auto& name : verified_jwt.CustomClaimNames()) {
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
  if (validator_proto.has_issuer()) {
    builder.SetIssuer(validator_proto.issuer().value());
  }
  if (validator_proto.has_subject()) {
    builder.SetSubject(validator_proto.subject().value());
  }
  if (validator_proto.has_audience()) {
    builder.SetAudience(validator_proto.audience().value());
  }
  if (validator_proto.has_now()) {
    builder.SetFixedNow(absl::FromUnixSeconds(validator_proto.now().seconds()));
  }
  if (validator_proto.has_clock_skew()) {
    auto skew_status = builder.SetClockSkew(
        absl::Seconds(validator_proto.clock_skew().seconds()));
    if (!skew_status.ok()) {
      return skew_status;
    }
  }
  return builder.Build();
}

// Computes a MAC and generates a signed compact JWT
::grpc::Status JwtImpl::ComputeMacAndEncode(grpc::ServerContext* context,
                                            const JwtSignRequest* request,
                                            JwtSignResponse* response) {
  auto reader_or = BinaryKeysetReader::New(request->keyset());
  if (!reader_or.ok()) {
    response->set_err(reader_or.status().error_message());
    return ::grpc::Status::OK;
  }
  auto handle_or =
      CleartextKeysetHandle::Read(std::move(reader_or.ValueOrDie()));
  if (!handle_or.ok()) {
    response->set_err(handle_or.status().error_message());
    return ::grpc::Status::OK;
  }
  auto jwt_mac_or =
      handle_or.ValueOrDie()->GetPrimitive<crypto::tink::JwtMac>();
  if (!jwt_mac_or.ok()) {
    response->set_err(jwt_mac_or.status().error_message());
    return ::grpc::Status::OK;
  }
  auto raw_jwt_or = RawJwtFromProto(request->raw_jwt());
  if (!raw_jwt_or.ok()) {
    response->set_err(raw_jwt_or.status().error_message());
    return ::grpc::Status::OK;
  }
  auto compact_or =
      jwt_mac_or.ValueOrDie()->ComputeMacAndEncode(raw_jwt_or.ValueOrDie());
  if (!compact_or.ok()) {
    response->set_err(compact_or.status().error_message());
    return ::grpc::Status::OK;
  }
  response->set_signed_compact_jwt(compact_or.ValueOrDie());
  return ::grpc::Status::OK;
}

// Verifies a signed compact JWT
::grpc::Status JwtImpl::VerifyMacAndDecode(grpc::ServerContext* context,
                                           const JwtVerifyRequest* request,
                                           JwtVerifyResponse* response) {
  auto reader_or = BinaryKeysetReader::New(request->keyset());
  if (!reader_or.ok()) {
    response->set_err(reader_or.status().error_message());
    return ::grpc::Status::OK;
  }
  auto handle_or =
      CleartextKeysetHandle::Read(std::move(reader_or.ValueOrDie()));
  if (!handle_or.ok()) {
    response->set_err(handle_or.status().error_message());
    return ::grpc::Status::OK;
  }
  auto jwt_mac_or =
      handle_or.ValueOrDie()->GetPrimitive<crypto::tink::JwtMac>();
  if (!jwt_mac_or.ok()) {
    response->set_err(jwt_mac_or.status().error_message());
    return ::grpc::Status::OK;
  }
  auto validator_or = JwtValidatorFromProto(request->validator());
  auto verified_jwt_or = jwt_mac_or.ValueOrDie()->VerifyMacAndDecode(
      request->signed_compact_jwt(), validator_or.ValueOrDie());
  if (!verified_jwt_or.ok()) {
    response->set_err(verified_jwt_or.status().error_message());
    return ::grpc::Status::OK;
  }
  *response->mutable_verified_jwt() =
      VerifiedJwtToProto(verified_jwt_or.ValueOrDie());
  return ::grpc::Status::OK;
}

::grpc::Status JwtImpl::PublicKeySignAndEncode(grpc::ServerContext* context,
                                   const JwtSignRequest* request,
                                   JwtSignResponse* response) {
    response->set_err("Not yet implemented");
    return ::grpc::Status::OK;
}

::grpc::Status JwtImpl::PublicKeyVerifyAndDecode(grpc::ServerContext* context,
                                        const JwtVerifyRequest* request,
                                        JwtVerifyResponse* response) {
    response->set_err("Not yet implemented");
    return ::grpc::Status::OK;
}

}  // namespace tink_testing_api

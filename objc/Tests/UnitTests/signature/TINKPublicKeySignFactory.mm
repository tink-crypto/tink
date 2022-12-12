/**
 * Copyright 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **************************************************************************
 */

#import "TINKPublicKeySignFactory.h"

#import <XCTest/XCTest.h>

#include <memory>
#include <string>
#include <utility>

#import "TINKKeysetHandle.h"
#import "TINKPublicKeySign.h"
#import "TINKPublicKeySignFactory.h"
#import "TINKSignatureConfig.h"
#import "core/TINKKeysetHandle_Internal.h"
#import "signature/TINKPublicKeySignInternal.h"
#import "util/TINKStrings.h"

#include "absl/status/status.h"
#include "tink/crypto_format.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/keyset_handle.h"
#include "tink/proto_keyset_format.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/signature_config.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::EcdsaSignKeyManager;
using crypto::tink::InsecureSecretKeyAccess;
using crypto::tink::KeyFactory;
using crypto::tink::KeysetHandle;
using crypto::tink::ParseKeysetFromProtoKeysetFormat;
using crypto::tink::test::AddTinkKey;
using crypto::tink::util::StatusOr;
using google::crypto::tink::EcdsaPrivateKey;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

static EcdsaPrivateKey GetNewEcdsaPrivateKey() {
  return crypto::tink::test::GetEcdsaTestPrivateKey(EllipticCurveType::NIST_P256, HashType::SHA256,
                                                    EcdsaSignatureEncoding::DER);
}

@interface TINKPublicKeySignFactoryTest : XCTestCase
@end

@implementation TINKPublicKeySignFactoryTest

- (void)testEmptyKeyset {
  Keyset keyset;
  StatusOr<crypto::tink::KeysetHandle> cc_keyset_handle =
      ParseKeysetFromProtoKeysetFormat(keyset.SerializeAsString(), InsecureSecretKeyAccess::Get());
  XCTAssertTrue(cc_keyset_handle.ok());
  TINKKeysetHandle *handle = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:std::make_unique<KeysetHandle>(*cc_keyset_handle)];
  XCTAssertNotNil(handle);

  NSError *error = nil;
  id<TINKPublicKeySign> publicKeySign =
      [TINKPublicKeySignFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNil(publicKeySign);
  XCTAssertNotNil(error);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  XCTAssertTrue([error.localizedFailureReason containsString:@"at least one key"]);
}

- (void)testPrimitive {
  // Prepare a Keyset.
  Keyset keyset;
  std::string key_type = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

  uint32_t key_id_1 = 1234543;
  AddTinkKey(key_type, key_id_1, GetNewEcdsaPrivateKey(), KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);

  uint32_t key_id_2 = 726329;
  AddTinkKey(key_type, key_id_2, GetNewEcdsaPrivateKey(), KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);

  uint32_t key_id_3 = 7213743;
  AddTinkKey(key_type, key_id_3, GetNewEcdsaPrivateKey(), KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  NSError *error = nil;
  TINKSignatureConfig *signatureConfig = [[TINKSignatureConfig alloc] initWithError:&error];
  XCTAssertNotNil(signatureConfig);
  XCTAssertNil(error);

  StatusOr<crypto::tink::KeysetHandle> cc_keyset_handle =
      ParseKeysetFromProtoKeysetFormat(keyset.SerializeAsString(), InsecureSecretKeyAccess::Get());
  XCTAssertTrue(cc_keyset_handle.ok());
  TINKKeysetHandle *handle = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:std::make_unique<KeysetHandle>(*cc_keyset_handle)];
  XCTAssertNotNil(handle);

  id<TINKPublicKeySign> publicKeySign =
      [TINKPublicKeySignFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNotNil(publicKeySign);
  XCTAssertNil(error);
  TINKPublicKeySignInternal *publicKeySignInternal = (TINKPublicKeySignInternal *)publicKeySign;
  XCTAssertTrue(publicKeySignInternal.ccPublicKeySign != NULL);

  // Test the PublicKeySign primitive.
  NSData *data = [@"some data to sign" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *signature = [publicKeySign signatureForData:data error:&error];
  XCTAssertNil(error);
  XCTAssertFalse([signature isEqualToData:data]);
}

@end

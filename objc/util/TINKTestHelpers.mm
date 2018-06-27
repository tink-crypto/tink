/**
 * Copyright 2017 Google Inc.
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

#import "objc/util/TINKTestHelpers.h"

#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"

#import <Foundation/Foundation.h>

#import "GPBMessage.h"
#import "GPBProtocolBuffers.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"
#import "proto/AesGcm.pbobjc.h"
#import "proto/Common.pbobjc.h"
#import "proto/EciesAeadHkdf.pbobjc.h"
#import "proto/Tink.pbobjc.h"

TINKPBKeyset *TINKCreateKeyset(TINKPBKeyset_Key *primaryKey, TINKPBKeyset_Key *key1,
                               TINKPBKeyset_Key *key2) {
  TINKPBKeyset *keyset = [[TINKPBKeyset alloc] init];

  TINKAddKey(primaryKey, keyset);
  TINKAddKey(key1, keyset);
  TINKAddKey(key2, keyset);

  keyset.primaryKeyId = [primaryKey keyId];
  return keyset;
}

TINKPBKeyset_Key *TINKCreateKey(NSString *keyType, uint32_t keyID, GPBMessage *newKey,
                                TINKPBOutputPrefixType outputPrefix, TINKPBKeyStatusType keyStatus,
                                TINKPBKeyData_KeyMaterialType materialType) {
  TINKPBKeyset_Key *key = [[TINKPBKeyset_Key alloc] init];
  key.outputPrefixType = outputPrefix;
  key.keyId = keyID;
  key.status = keyStatus;

  if (!key.hasKeyData) {
    key.keyData = [[TINKPBKeyData alloc] init];
  }

  key.keyData.typeURL = keyType;
  key.keyData.keyMaterialType = materialType;
  key.keyData.value = [newKey data];
  return key;
}

void TINKAddKey(NSString *keyType, uint32_t keyId, GPBMessage *keyMaterial,
                TINKPBOutputPrefixType outputPrefix, TINKPBKeyStatusType keyStatus,
                TINKPBKeyData_KeyMaterialType materialType, TINKPBKeyset *keyset) {
  TINKPBKeyset_Key *key =
      TINKCreateKey(keyType, keyId, keyMaterial, outputPrefix, keyStatus, materialType);

  TINKAddKey(key, keyset);
}

void TINKAddKey(TINKPBKeyset_Key *key, TINKPBKeyset *keyset) {
  if (!keyset.keyArray) {
    keyset.keyArray = [[NSMutableArray alloc] init];
  }

  NSMutableArray<TINKPBKeyset_Key *> *keyArray = [keyset keyArray];

  [keyArray addObject:key];
}

void TINKAddTinkKey(NSString *keyType,
                    uint32_t keyID,
                    GPBMessage *key,
                    TINKPBKeyStatusType keyStatus,
                    TINKPBKeyData_KeyMaterialType materialType,
                    TINKPBKeyset *keyset) {
  TINKAddKey(keyType, keyID, key, TINKPBOutputPrefixType_Tink, keyStatus, materialType, keyset);
}

void TINKAddLegacyKey(NSString *keyType,
                      uint32_t keyID,
                      GPBMessage *key,
                      TINKPBKeyStatusType keyStatus,
                      TINKPBKeyData_KeyMaterialType materialType,
                      TINKPBKeyset *keyset) {
  TINKAddKey(keyType, keyID, key, TINKPBOutputPrefixType_Legacy, keyStatus, materialType, keyset);
}

void TINKAddRawKey(NSString *keyType,
                   uint32_t keyID,
                   GPBMessage *key,
                   TINKPBKeyStatusType keyStatus,
                   TINKPBKeyData_KeyMaterialType materialType,
                   TINKPBKeyset *keyset) {
  TINKAddKey(keyType, keyID, key, TINKPBOutputPrefixType_Raw, keyStatus, materialType, keyset);
}

TINKPBEciesAeadHkdfPrivateKey *TINKGetEciesAesGcmHkdfTestKey(TINKPBEllipticCurveType curveType,
                                                             TINKPBEcPointFormat ecPointFormat,
                                                             TINKPBHashType hashType,
                                                             uint32_t aesGcmKeySize) {
  /* TODO(candrian): replace the static_cast below with an explicit translation */
  auto test_key = crypto::tink::subtle::SubtleUtilBoringSSL::GetNewEcKey(
                      static_cast<crypto::tink::subtle::EllipticCurveType>(curveType))
                      .ValueOrDie();

  TINKPBEciesAeadHkdfPrivateKey *eciesKey = [[TINKPBEciesAeadHkdfPrivateKey alloc] init];
  eciesKey.version = 0;
  eciesKey.keyValue = TINKStringToNSData(test_key.priv);

  if (!eciesKey.hasPublicKey) {
    eciesKey.publicKey = [[TINKPBEciesAeadHkdfPublicKey alloc] init];
  }

  TINKPBEciesAeadHkdfPublicKey *publicKey = eciesKey.publicKey;
  publicKey.version = 0;
  publicKey.x = TINKStringToNSData(test_key.pub_x);
  publicKey.y = TINKStringToNSData(test_key.pub_y);

  if (!publicKey.hasParams) {
    publicKey.params = [[TINKPBEciesAeadHkdfParams alloc] init];
  }

  TINKPBEciesAeadHkdfParams *params = publicKey.params;
  params.ecPointFormat = ecPointFormat;

  if (!params.hasKemParams) {
    params.kemParams = [[TINKPBEciesHkdfKemParams alloc] init];
  }

  TINKPBEciesHkdfKemParams *kemParams = params.kemParams;
  kemParams.curveType = curveType;
  kemParams.hkdfHashType = hashType;

  TINKPBAesGcmKeyFormat *keyFormat = [[TINKPBAesGcmKeyFormat alloc] init];
  keyFormat.keySize = 24;

  if (!params.hasDemParams) {
    params.demParams = [[TINKPBEciesAeadDemParams alloc] init];
  }
  TINKPBEciesAeadDemParams *demParams = params.demParams;

  if (!demParams.hasAeadDem) {
    demParams.aeadDem = [[TINKPBKeyTemplate alloc] init];
  }

  TINKPBKeyTemplate *aeadDem = demParams.aeadDem;
  aeadDem.typeURL = @"type.googleapis.com/google.crypto.tink.AesGcmKey";
  aeadDem.value = [keyFormat data];

  return eciesKey;
}

std::string TINKPBSerializeToString(GPBMessage *message, NSError **error) {
  NSData *serializedPB = [message data];
  if (!serializedPB) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Could not serialize message."));
    }
    return std::string("");
  }
  return std::string(static_cast<const char *>(serializedPB.bytes), serializedPB.length);
}

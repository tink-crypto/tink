#import "objc/util/TINKTestHelpers.h"

#include "cc/subtle/subtle_util_boringssl.h"
#include "proto/common.pb.h"

#import <Foundation/Foundation.h>

#import "GPBMessage.h"
#import "objc/util/TINKStrings.h"
#import "proto/AesGcm.pbobjc.h"
#import "proto/Common.pbobjc.h"
#import "proto/EciesAeadHkdf.pbobjc.h"
#import "proto/Tink.pbobjc.h"

void TINKAddKey(NSString *keyType,
                uint32_t keyID,
                GPBMessage *newKey,
                TINKPBOutputPrefixType outputPrefix,
                TINKPBKeyStatusType keyStatus,
                TINKPBKeyData_KeyMaterialType materialType,
                TINKPBKeyset *keyset) {
  if (!keyset.keyArray) {
    keyset.keyArray = [[NSMutableArray alloc] init];
  }

  NSMutableArray<TINKPBKeyset_Key *> *keyArray = [keyset keyArray];

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
  auto test_key = crypto::tink::SubtleUtilBoringSSL::GetNewEcKey(
                      static_cast<google::crypto::tink::EllipticCurveType>(curveType))
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

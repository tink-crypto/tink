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

#import "GPBMessage.h"
#import "proto/Common.pbobjc.h"
#import "proto/EciesAeadHkdf.pbobjc.h"
#import "proto/Tink.pbobjc.h"

void TINKAddKey(NSString *keyType, NSUInteger keyId, TINKPBKeyset *keyset);

void TINKAddTinkKey(NSString *keyType,
                    uint32_t keyID,
                    GPBMessage *key,
                    TINKPBKeyStatusType keyStatus,
                    TINKPBKeyData_KeyMaterialType materialType,
                    TINKPBKeyset *keyset);

void TINKAddLegacyKey(NSString *keyType,
                      uint32_t keyID,
                      GPBMessage *key,
                      TINKPBKeyStatusType keyStatus,
                      TINKPBKeyData_KeyMaterialType materialType,
                      TINKPBKeyset *keyset);

void TINKAddRawKey(NSString *keyType,
                   uint32_t keyID,
                   GPBMessage *key,
                   TINKPBKeyStatusType keyStatus,
                   TINKPBKeyData_KeyMaterialType materialType,
                   TINKPBKeyset *keyset);

TINKPBEciesAeadHkdfPrivateKey *TINKGetEciesAesGcmHkdfTestKey(TINKPBEllipticCurveType curveType,
                                                             TINKPBEcPointFormat ecPointFormat,
                                                             TINKPBHashType hashType,
                                                             uint32_t aesGcmKeySize);

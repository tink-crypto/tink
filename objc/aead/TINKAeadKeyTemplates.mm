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

#import "objc/aead/TINKAeadKeyTemplates.h"

#import "proto/AesCtr.pbobjc.h"
#import "proto/AesCtrHmacAead.pbobjc.h"
#import "proto/AesGcm.pbobjc.h"
#import "proto/Common.pbobjc.h"
#import "proto/Hmac.pbobjc.h"
#import "proto/Tink.pbobjc.h"

static TINKPBKeyTemplate *NewAesGcmKeyTemplate(uint32_t keySizeInBytes) {
  static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.AesGcmKey";
  TINKPBKeyTemplate *keyTemplate = [[TINKPBKeyTemplate alloc] init];
  keyTemplate.typeURL = kTypeURL;
  keyTemplate.outputPrefixType = TINKPBOutputPrefixType_Tink;
  TINKPBAesGcmKeyFormat *keyFormat = [[TINKPBAesGcmKeyFormat alloc] init];
  keyFormat.keySize = keySizeInBytes;
  keyTemplate.value = keyFormat.data;
  return keyTemplate;
}

static TINKPBKeyTemplate *NewAesCtrHmacAeadKeyTemplate(uint32_t aesKeySizeInBytes,
                                                       uint32_t ivSizeInBytes,
                                                       uint32_t hmacKeySizeInBytes,
                                                       uint32_t tagSizeInBytes,
                                                       TINKPBHashType hashType) {
  static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  TINKPBKeyTemplate *keyTemplate = [[TINKPBKeyTemplate alloc] init];
  keyTemplate.typeURL = kTypeURL;
  keyTemplate.outputPrefixType = TINKPBOutputPrefixType_Tink;
  TINKPBAesCtrHmacAeadKeyFormat *keyFormat = [[TINKPBAesCtrHmacAeadKeyFormat alloc] init];
  if (!keyFormat.hasAesCtrKeyFormat) {
    keyFormat.aesCtrKeyFormat = [[TINKPBAesCtrKeyFormat alloc] init];
  }
  TINKPBAesCtrKeyFormat *aesCtrKeyFormat = keyFormat.aesCtrKeyFormat;
  aesCtrKeyFormat.keySize = aesKeySizeInBytes;
  aesCtrKeyFormat.params.ivSize = ivSizeInBytes;
  if (!keyFormat.hasHmacKeyFormat) {
    keyFormat.hmacKeyFormat = [[TINKPBHmacKeyFormat alloc] init];
  }
  TINKPBHmacKeyFormat *hmacKeyFormat = keyFormat.hmacKeyFormat;
  hmacKeyFormat.keySize = hmacKeySizeInBytes;
  hmacKeyFormat.params.hash_p = hashType;
  hmacKeyFormat.params.tagSize = tagSizeInBytes;
  keyTemplate.value = keyFormat.data;
  return keyTemplate;
}

@implementation TINKAeadKeyTemplates

+ (TINKPBKeyTemplate *)keyTemplateForAes128Gcm {
  return NewAesGcmKeyTemplate(/* keySizeInBytes= */ 16);
}

+ (TINKPBKeyTemplate *)keyTemplateForAes256Gcm {
  return NewAesGcmKeyTemplate(/* keySizeInBytes= */ 32);
}

+ (TINKPBKeyTemplate *)keyTemplateForAes128CtrHmacSha256 {
  return NewAesCtrHmacAeadKeyTemplate(
      /* aesKeySizeInBytes= */ 16,
      /* ivSizeInBytes= */ 16,
      /* hmacKeySizeInBytes= */ 32,
      /* tagSizeInBytes= */ 16, TINKPBHashType_Sha256);
}

+ (TINKPBKeyTemplate *)keyTemplateForAes256CtrHmacSha256 {
  return NewAesCtrHmacAeadKeyTemplate(
      /* aesKeySizeInBytes= */ 32,
      /* ivSizeInBytes= */ 16,
      /* hmacKeySizeInBytes= */ 32,
      /* tagSizeInBytes= */ 32, TINKPBHashType_Sha256);
}

@end

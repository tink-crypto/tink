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

#import "objc/aead/TINKAeadKeyTemplates.h"

#import <XCTest/XCTest.h>

#import "proto/AesCtr.pbobjc.h"
#import "proto/AesCtrHmacAead.pbobjc.h"
#import "proto/AesGcm.pbobjc.h"
#import "proto/Common.pbobjc.h"
#import "proto/Hmac.pbobjc.h"
#import "proto/Tink.pbobjc.h"

@interface TINKAeadKeyTemplatesTest : XCTestCase
@end

@implementation TINKAeadKeyTemplatesTest

- (void)testAesGcmKeyTemplates {
  static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.AesGcmKey";

  // AES-128 GCM
  TINKPBKeyTemplate *keyTemplate = [TINKAeadKeyTemplates keyTemplateForAes128Gcm];
  XCTAssertTrue(kTypeURL == keyTemplate.typeURL);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);
  NSError *error = nil;
  TINKPBAesGcmKeyFormat *keyFormat =
      [TINKPBAesGcmKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);
  XCTAssertTrue(16 == keyFormat.keySize);

  // AES-256 GCM
  keyTemplate = [TINKAeadKeyTemplates keyTemplateForAes256Gcm];
  XCTAssertTrue(kTypeURL == keyTemplate.typeURL);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);
  error = nil;
  keyFormat = [TINKPBAesGcmKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);
  XCTAssertTrue(32 == keyFormat.keySize);
}

- (void)testAesCtrHmacKeyTemplates {
  NSString *kTypeURL = @"type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

  // AES-128 CTR HMAC SHA-256
  TINKPBKeyTemplate *keyTemplate = [TINKAeadKeyTemplates keyTemplateForAes128CtrHmacSha256];
  XCTAssertTrue(kTypeURL == keyTemplate.typeURL);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);
  NSError *error = nil;
  TINKPBAesCtrHmacAeadKeyFormat *keyFormat =
      [TINKPBAesCtrHmacAeadKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);
  XCTAssertTrue(16 == keyFormat.aesCtrKeyFormat.keySize);
  XCTAssertTrue(16 == keyFormat.aesCtrKeyFormat.params.ivSize);
  XCTAssertTrue(32 == keyFormat.hmacKeyFormat.keySize);
  XCTAssertTrue(16 == keyFormat.hmacKeyFormat.params.tagSize);
  XCTAssertTrue(TINKPBHashType_Sha256 == keyFormat.hmacKeyFormat.params.hash_p);

  // AES-256 CTR HMAC SHA-256
  keyTemplate = [TINKAeadKeyTemplates keyTemplateForAes256CtrHmacSha256];
  XCTAssertTrue(kTypeURL == keyTemplate.typeURL);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);
  error = nil;
  keyFormat = [TINKPBAesCtrHmacAeadKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);
  XCTAssertTrue(32 == keyFormat.aesCtrKeyFormat.keySize);
  XCTAssertTrue(16 == keyFormat.aesCtrKeyFormat.params.ivSize);
  XCTAssertTrue(32 == keyFormat.hmacKeyFormat.keySize);
  XCTAssertTrue(32 == keyFormat.hmacKeyFormat.params.tagSize);
  XCTAssertTrue(TINKPBHashType_Sha256 == keyFormat.hmacKeyFormat.params.hash_p);
}

@end

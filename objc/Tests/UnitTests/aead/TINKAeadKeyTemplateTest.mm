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

#import "objc/TINKAeadKeyTemplate.h"

#import <XCTest/XCTest.h>

#include "tink/aead/xchacha20_poly1305_key_manager.h"

#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"
#import "objc/util/TINKProtoHelpers.h"
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

  NSError *error = nil;
  // AES-128 GCM
  TINKAeadKeyTemplate *tpl =
      [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128Gcm error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);
  error = nil;
  TINKPBAesGcmKeyFormat *keyFormat =
      [TINKPBAesGcmKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);
  XCTAssertTrue(16 == keyFormat.keySize);

  // AES-256 GCM
  tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes256Gcm error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
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
  NSError *error = nil;
  TINKAeadKeyTemplate *tpl =
      [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128CtrHmacSha256 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);
  error = nil;
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
  tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes256CtrHmacSha256 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
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

- (void)testAesEaxKeyTemplates {
  static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.AesEaxKey";

  NSError *error = nil;
  // AES-128 EAX
  TINKAeadKeyTemplate *tpl =
      [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128Eax error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);
  error = nil;
  TINKPBAesGcmKeyFormat *keyFormat =
      [TINKPBAesGcmKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);
  XCTAssertEqual(keyFormat.keySize, 16);

  // AES-256 EAX
  tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes256Eax error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);
  error = nil;
  keyFormat = [TINKPBAesGcmKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);
  XCTAssertEqual(keyFormat.keySize, 32);
}

- (void)testXChaCha20Poly1305KeyTemplates {
  static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";

  NSError *error = nil;
  TINKAeadKeyTemplate *tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKXChaCha20Poly1305
                                                                        error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);
  error = nil;

  // Check that the template works with the key manager.
  crypto::tink::XChaCha20Poly1305KeyManager key_manager;
  XCTAssertTrue(key_manager.get_key_type() == tpl.ccKeyTemplate->type_url());
  auto new_key_result = key_manager.get_key_factory().NewKey(tpl.ccKeyTemplate->value());
  XCTAssertTrue(new_key_result.ok());
}

@end

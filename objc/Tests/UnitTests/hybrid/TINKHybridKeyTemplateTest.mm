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

#import "objc/TINKHybridKeyTemplate.h"

#import <XCTest/XCTest.h>

#import "objc/TINKAeadKeyTemplate.h"
#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"
#import "objc/util/TINKProtoHelpers.h"
#import "proto/Common.pbobjc.h"
#import "proto/EciesAeadHkdf.pbobjc.h"
#import "proto/Tink.pbobjc.h"

#include "tink/util/status.h"

@interface TINKHybridKeyTemplateTest : XCTestCase
@end

static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

@implementation TINKHybridKeyTemplateTest

- (void)testInvalidKeyTemplate {
  NSError *error = nil;
  // Specify an invalid keyTemplate.
  TINKHybridKeyTemplate *keyTemplate =
      [[TINKHybridKeyTemplate alloc] initWithKeyTemplate:TINKHybridKeyTemplates(-1) error:&error];
  XCTAssertNotNil(error);
  XCTAssertNil(keyTemplate);
  XCTAssertEqual(error.code, crypto::tink::util::error::INVALID_ARGUMENT);
  NSDictionary *userInfo = [error userInfo];
  NSString *errorString = [userInfo objectForKey:NSLocalizedFailureReasonErrorKey];
  XCTAssertTrue([errorString containsString:@"Invalid TINKHybridKeyTemplate"]);
}

- (void)testEciesP256HkdfHmacSha256Aes128Gcm {
  // Get a EciesP256HkdfHmacSha256Aes128Gcm key template.
  NSError *error = nil;
  TINKHybridKeyTemplate *keyTemplate =
      [[TINKHybridKeyTemplate alloc] initWithKeyTemplate:TINKEciesP256HkdfHmacSha256Aes128Gcm
                                                   error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  TINKPBKeyTemplate *objcKeyTemplate = TINKKeyTemplateToObjc(keyTemplate.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(objcKeyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:objcKeyTemplate.typeURL]);
  XCTAssertEqual(objcKeyTemplate.outputPrefixType, TINKPBOutputPrefixType_Tink);
  error = nil;
  TINKPBEciesAeadHkdfKeyFormat *keyFormat =
      [TINKPBEciesAeadHkdfKeyFormat parseFromData:objcKeyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  // EC Point Format
  XCTAssertEqual(TINKPBEcPointFormat_Uncompressed, keyFormat.params.ecPointFormat);

  // Verify DEM params.
  XCTAssertTrue(keyFormat.params.hasDemParams);
  TINKPBEciesAeadDemParams *demParams = keyFormat.params.demParams;
  error = nil;
  TINKAeadKeyTemplate *expectedDemTpl =
      [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128Gcm error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(expectedDemTpl);

  error = nil;
  TINKPBKeyTemplate *expectedDem = TINKKeyTemplateToObjc(expectedDemTpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(expectedDem);

  XCTAssertTrue(demParams.hasAeadDem);
  XCTAssertEqual(expectedDem.outputPrefixType, demParams.aeadDem.outputPrefixType);
  XCTAssertTrue([expectedDem.typeURL isEqualToString:demParams.aeadDem.typeURL]);
  XCTAssertTrue([expectedDem.value isEqualToData:demParams.aeadDem.value]);

  // Verify KEM params.
  XCTAssertTrue(keyFormat.params.hasKemParams);
  TINKPBEciesHkdfKemParams *kemParams = keyFormat.params.kemParams;
  XCTAssertEqual(TINKPBEllipticCurveType_NistP256, kemParams.curveType);
  XCTAssertEqual(TINKPBHashType_Sha256, kemParams.hkdfHashType);
  XCTAssertTrue(kemParams.hkdfSalt.length == 0);
}

- (void)testEciesP256HkdfHmacSha256Aes128CtrHmacSha256 {
  // Get a EciesP256HkdfHmacSha256Aes128CtrHmacSha256 key template.
  NSError *error = nil;
  TINKHybridKeyTemplate *keyTemplate = [[TINKHybridKeyTemplate alloc]
      initWithKeyTemplate:TINKEciesP256HkdfHmacSha256Aes128CtrHmacSha256
                    error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  TINKPBKeyTemplate *objcKeyTemplate = TINKKeyTemplateToObjc(keyTemplate.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(objcKeyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:objcKeyTemplate.typeURL]);
  XCTAssertEqual(objcKeyTemplate.outputPrefixType, TINKPBOutputPrefixType_Tink);
  error = nil;
  TINKPBEciesAeadHkdfKeyFormat *keyFormat =
      [TINKPBEciesAeadHkdfKeyFormat parseFromData:objcKeyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  // EC Point Format
  XCTAssertEqual(TINKPBEcPointFormat_Uncompressed, keyFormat.params.ecPointFormat);

  // Verify DEM params.
  XCTAssertTrue(keyFormat.params.hasDemParams);
  TINKPBEciesAeadDemParams *demParams = keyFormat.params.demParams;

  error = nil;
  TINKAeadKeyTemplate *tpl =
      [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128CtrHmacSha256 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *expectedDem = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(expectedDem);

  XCTAssertTrue(demParams.hasAeadDem);
  XCTAssertEqual(expectedDem.outputPrefixType, demParams.aeadDem.outputPrefixType);
  XCTAssertTrue([expectedDem.typeURL isEqualToString:demParams.aeadDem.typeURL]);
  XCTAssertTrue([expectedDem.value isEqualToData:demParams.aeadDem.value]);

  // Verify KEM params.
  XCTAssertTrue(keyFormat.params.hasKemParams);
  TINKPBEciesHkdfKemParams *kemParams = keyFormat.params.kemParams;
  XCTAssertEqual(TINKPBEllipticCurveType_NistP256, kemParams.curveType);
  XCTAssertEqual(TINKPBHashType_Sha256, kemParams.hkdfHashType);
  XCTAssertTrue(kemParams.hkdfSalt.length == 0);
}

@end

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

#import "objc/TINKSignatureKeyTemplate.h"

#import <XCTest/XCTest.h>

#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"
#import "objc/util/TINKProtoHelpers.h"
#import "proto/Common.pbobjc.h"
#import "proto/Ecdsa.pbobjc.h"
#import "proto/Tink.pbobjc.h"

#include "tink/util/status.h"

@interface TINKSignatureKeyTemplatesTest : XCTestCase
@end

static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

@implementation TINKSignatureKeyTemplatesTest

- (void)testEcdsaP256KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP256 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBEcdsaKeyFormat *keyFormat =
      [TINKPBEcdsaKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.hashType, TINKPBHashType_Sha256);
  XCTAssertEqual(keyFormat.params.curve, TINKPBEllipticCurveType_NistP256);
  XCTAssertEqual(keyFormat.params.encoding, TINKPBEcdsaSignatureEncoding_Der);
}

- (void)testEcdsaP384KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP384 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBEcdsaKeyFormat *keyFormat =
      [TINKPBEcdsaKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.hashType, TINKPBHashType_Sha512);
  XCTAssertEqual(keyFormat.params.curve, TINKPBEllipticCurveType_NistP384);
  XCTAssertEqual(keyFormat.params.encoding, TINKPBEcdsaSignatureEncoding_Der);
}

- (void)testEcdsaP521KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP521 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBEcdsaKeyFormat *keyFormat =
      [TINKPBEcdsaKeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.hashType, TINKPBHashType_Sha512);
  XCTAssertEqual(keyFormat.params.curve, TINKPBEllipticCurveType_NistP521);
  XCTAssertEqual(keyFormat.params.encoding, TINKPBEcdsaSignatureEncoding_Der);
}

- (void)testInvalidKeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:(TINKSignatureKeyTemplates)-1
                                                      error:&error];
  XCTAssertNil(tpl);
  XCTAssertNotNil(error);
  XCTAssertTrue(error.code == crypto::tink::util::error::INVALID_ARGUMENT);
  XCTAssertTrue([error.localizedFailureReason containsString:@"Invalid TINKSignatureKeyTemplate"]);
}

@end

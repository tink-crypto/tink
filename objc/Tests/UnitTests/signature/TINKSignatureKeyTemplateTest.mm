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
#import "proto/RsaSsaPkcs1.pbobjc.h"
#import "proto/RsaSsaPss.pbobjc.h"
#import "proto/Tink.pbobjc.h"

#include "tink/util/status.h"

@interface TINKSignatureKeyTemplatesTest : XCTestCase
@end

static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
static NSString *const kTypeURLRsaPss =
    @"type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
static NSString *const kTypeURLRsaPkcs1 =
    @"type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";

@implementation TINKSignatureKeyTemplatesTest

- (void)testEcdsaP256KeyTemplateWithDerEncoding {
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

- (void)testEcdsaP256KeyTemplateWithIeeeEncoding {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP256Ieee error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBEcdsaKeyFormat *keyFormat = [TINKPBEcdsaKeyFormat parseFromData:keyTemplate.value
                                                                  error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.hashType, TINKPBHashType_Sha256);
  XCTAssertEqual(keyFormat.params.curve, TINKPBEllipticCurveType_NistP256);
  XCTAssertEqual(keyFormat.params.encoding, TINKPBEcdsaSignatureEncoding_IeeeP1363);
}

- (void)testEcdsaP384KeyTemplateWithDerEncoding {
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

- (void)testEcdsaP384KeyTemplateWithIeeeEncoding {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP384Ieee error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBEcdsaKeyFormat *keyFormat = [TINKPBEcdsaKeyFormat parseFromData:keyTemplate.value
                                                                  error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.hashType, TINKPBHashType_Sha512);
  XCTAssertEqual(keyFormat.params.curve, TINKPBEllipticCurveType_NistP384);
  XCTAssertEqual(keyFormat.params.encoding, TINKPBEcdsaSignatureEncoding_IeeeP1363);
}

- (void)testEcdsaP521KeyTemplateWithDerEncoding {
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

- (void)testEcdsaP521KeyTemplateWithIeeeEncoding {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP521Ieee error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBEcdsaKeyFormat *keyFormat = [TINKPBEcdsaKeyFormat parseFromData:keyTemplate.value
                                                                  error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.hashType, TINKPBHashType_Sha512);
  XCTAssertEqual(keyFormat.params.curve, TINKPBEllipticCurveType_NistP521);
  XCTAssertEqual(keyFormat.params.encoding, TINKPBEcdsaSignatureEncoding_IeeeP1363);
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

- (void)testKRsaSsaPkcs13072Sha256F4KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKRsaSsaPkcs13072Sha256F4
                                                      error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURLRsaPkcs1 isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBRsaSsaPkcs1KeyFormat *keyFormat =
      [TINKPBRsaSsaPkcs1KeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.hashType, TINKPBHashType_Sha256);
  XCTAssertEqual(keyFormat.modulusSizeInBits, 3072);
}

- (void)testKRsaSsaPkcs14096Sha512F4KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKRsaSsaPkcs14096Sha512F4
                                                      error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURLRsaPkcs1 isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBRsaSsaPkcs1KeyFormat *keyFormat =
      [TINKPBRsaSsaPkcs1KeyFormat parseFromData:keyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.hashType, TINKPBHashType_Sha512);
  XCTAssertEqual(keyFormat.modulusSizeInBits, 4096);
}

- (void)testKRsaSsaPss3072Sha256F4KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKRsaSsaPss3072Sha256Sha256F4
                                                      error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURLRsaPss isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBRsaSsaPssKeyFormat *keyFormat = [TINKPBRsaSsaPssKeyFormat parseFromData:keyTemplate.value
                                                                          error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.sigHash, TINKPBHashType_Sha256);
  XCTAssertEqual(keyFormat.params.mgf1Hash, TINKPBHashType_Sha256);
  XCTAssertEqual(keyFormat.params.saltLength, 32);
  XCTAssertEqual(keyFormat.modulusSizeInBits, 3072);
}

- (void)testKRsaSsaPss4096Sha512F4KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKRsaSsaPss4096Sha512Sha512F4
                                                      error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(tpl.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([kTypeURLRsaPss isEqualToString:keyTemplate.typeURL]);
  XCTAssertTrue(keyTemplate.outputPrefixType == TINKPBOutputPrefixType_Tink);

  error = nil;
  TINKPBRsaSsaPssKeyFormat *keyFormat = [TINKPBRsaSsaPssKeyFormat parseFromData:keyTemplate.value
                                                                          error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.params.sigHash, TINKPBHashType_Sha512);
  XCTAssertEqual(keyFormat.params.mgf1Hash, TINKPBHashType_Sha512);
  XCTAssertEqual(keyFormat.params.saltLength, 64);
  XCTAssertEqual(keyFormat.modulusSizeInBits, 4096);
}

@end

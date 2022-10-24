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

#import <Foundation/Foundation.h>

#import "TINKKeysetReader.h"
#import "core/TINKKeysetReader_Internal.h"

#include "tink/keyset_reader.h"

@implementation TINKKeysetReader {
  std::unique_ptr<crypto::tink::KeysetReader> _ccReader;
}

- (void)setCcReader:(std::unique_ptr<crypto::tink::KeysetReader>)ccReader {
  _ccReader = std::move(ccReader);
}

- (std::unique_ptr<crypto::tink::KeysetReader>)ccReader {
  return std::move(_ccReader);
}

- (void)dealloc {
  _ccReader.reset();
}

@end

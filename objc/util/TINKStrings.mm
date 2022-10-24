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

#import "util/TINKStrings.h"

#import <Foundation/Foundation.h>

#import "util/TINKErrors.h"

#include "absl/strings/string_view.h"

NSString* TINKStringPieceToNSString(absl::string_view s) {
  return [[NSString alloc] initWithBytes:s.data() length:s.size() encoding:NSUTF8StringEncoding];
}

NSString* TINKStringToNSString(std::string s) {
  return [[NSString alloc] initWithBytes:s.c_str() length:s.length() encoding:NSUTF8StringEncoding];
}

NSData* TINKStringToNSData(std::string s) {
  return [NSData dataWithBytes:s.data() length:s.size()];
}

NSData* TINKStringViewToNSData(absl::string_view s) {
  return [NSData dataWithBytes:s.data() length:s.size()];
}

std::string NSDataToTINKString(NSData* data) {
  return std::string(static_cast<const char*>(data.bytes), data.length);
}

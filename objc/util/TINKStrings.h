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

#include "absl/strings/string_view.h"

/** Converts a absl::string_view to NSString. */
NSString* TINKStringPieceToNSString(absl::string_view s);

/** Converts a C++ std::string to NSString. */
NSString* TINKStringToNSString(std::string s);

/** Converts a C++ std::string to NSData. */
NSData* TINKStringToNSData(std::string s);

/** Converts a absl::string_view to NSData. */
NSData* TINKStringViewToNSData(absl::string_view s);

/** Converts a NSData to a std::string. */
std::string NSDataToTINKString(NSData* data);

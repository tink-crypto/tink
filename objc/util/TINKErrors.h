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

#include "absl/status/status.h"
#include "tink/util/status.h"

/** Converts a C++ Status code to NSError. */
NSError* TINKStatusToError(const crypto::tink::util::Status& status);

/**
 * Creates an NSError given a Tink error code and a message.
 * @deprecated use absl::StatusCode as the first argument instead.
 */
NSError* TINKError(crypto::tink::util::error::Code code, NSString* message);

/** Creates an NSError given an absl status code and a message. */
NSError* TINKError(absl::StatusCode code, NSString* message);

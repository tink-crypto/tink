// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

/**
 * @fileoverview All error types that the Tink can throw.
 */

goog.provide('tink.Error');
goog.provide('tink.InvalidArgumentsError');
goog.provide('tink.UnsupportedError');

goog.require('goog.debug.Error');

/**
 * The base class for crypto errors.
 * @param {*=} opt_msg The custom error message.
 * @constructor
 * @extends {goog.debug.Error}
 */
tink.Error = function(opt_msg) {
  tink.Error.base(this, 'constructor', opt_msg);
};
goog.inherits(tink.Error, goog.debug.Error);

/**
 * Exception used when a function encounters a security issue.
 * @param {string} message The message with the error details.
 * @constructor
 * @extends {tink.Error}
 */
tink.SecurityError = function(message) {
  tink.SecurityError.base(this, 'constructor', message);
};
goog.inherits(tink.SecurityError, tink.Error);

/**
 * Exception used when a function receives an invalid argument.
 * @param {string} message The message with the error details.
 * @constructor
 * @extends {tink.Error}
 */
tink.InvalidArgumentsError = function(message) {
  tink.InvalidArgumentsError.base(this, 'constructor', message);
};
goog.inherits(tink.InvalidArgumentsError, tink.Error);

/**
 * Exception used when the client requests an unimplemented feature.
 * @param {string} message The message with the error details.
 * @constructor
 * @extends {tink.Error}
 */
tink.UnsupportedError = function(message) {
  tink.UnsupportedError.base(this, 'constructor', message);
};
goog.inherits(tink.UnsupportedError, tink.Error);

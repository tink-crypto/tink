# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

"""Definition of get_android_test_size.

"""

def get_android_test_size(android_version):
    if android_version == "26" or android_version == "27":
        # somehow the emulators for these versions are very slow.
        return "enormous"  # not running on TAP presubmit
    return "large"

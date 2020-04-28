# Copyright 2019 Google LLC.
#
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

"""Aead package."""
from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink.aead import _aead
from tink.aead import _aead_key_manager
from tink.aead import _aead_key_templates as aead_key_templates
from tink.aead import _kms_envelope_aead


Aead = _aead.Aead
AeadCcToPyWrapper = _aead_key_manager.AeadCcToPyWrapper
register = _aead_key_manager.register
KmsEnvelopeAead = _kms_envelope_aead.KmsEnvelopeAead

"""Tink package."""
from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function

from google3.third_party.tink.python import aead
from google3.third_party.tink.python import daead
from google3.third_party.tink.python import key_manager
from google3.third_party.tink.python import mac
from google3.third_party.tink.python import signature
from google3.third_party.tink.python import tink_config


Aead = aead.Aead
DeterministicAead = daead.DeterministicAead
Mac = mac.Mac
PublicKeySign = signature.PublicKeySign
PublicKeyVerify = signature.PublicKeyVerify
KeyManager = key_manager.KeyManager
PrivateKeyManager = key_manager.PrivateKeyManager

del key_manager

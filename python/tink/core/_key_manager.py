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

"""This module defines the basic types and abstract classes in Tink."""
from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc
from typing import Any, Generic, Text, Type, TypeVar
import six

from tink.proto import tink_pb2
from tink.core import _tink_error


P = TypeVar('P')


@six.add_metaclass(abc.ABCMeta)
class KeyManager(Generic[P]):
  """Generates keys and provides primitives for the keys.

  A KeyManager "understands" keys of a specific key types: it can generate keys
  of a supported type and create primitives for supported keys.  A key type is
  identified by the global name of the protocol buffer that holds the
  corresponding key material, and is given by type_url-field of KeyData-protocol
  buffer.
  """

  @abc.abstractmethod
  def primitive_class(self) -> Type[P]:
    """The class of the primitive it uses. Used for internal management."""
    raise NotImplementedError()

  @abc.abstractmethod
  def primitive(self, key_data: tink_pb2.KeyData) -> P:
    """Constructs an primitive for the given key.

    Args:
      key_data: KeyData protocol buffer
    Returns:
      A primitive, for example an instance of Aead or Mac.
    Raises:
      tink.TinkError if getting the primitive fails.
    """
    raise NotImplementedError()

  @abc.abstractmethod
  def key_type(self) -> Text:
    """Returns the type_url identifying the key type handled by this manager."""
    raise NotImplementedError()

  @abc.abstractmethod
  def new_key_data(self,
                   key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyData:
    """Generates a new random key, based on the specified key_template.

    Args:
      key_template: KeyTemplate protocol buffer
    Returns:
      A KeyData protocol buffer that contains the key.
    Raises:
      tink.TinkError if the key generation fails.
    """
    raise NotImplementedError()

  def does_support(self, type_url: Text) -> bool:
    return self.key_type() == type_url


class PrivateKeyManager(KeyManager[P]):
  """Generates keys and provides primitives for the keys."""

  @abc.abstractmethod
  def public_key_data(
      self, private_key_data: tink_pb2.KeyData) -> tink_pb2.KeyData:
    """Generates a new random key, based on the specified key_template.

    Args:
      private_key_data: KeyData protocol buffer
    Returns:
      A KeyData protocol buffer that contains the public key.
    Raises:
      tink.TinkError if the key generation fails.
    """
    raise NotImplementedError()


class KeyManagerCcToPyWrapper(KeyManager[P]):
  """Transforms C++ KeyManager into a Python KeyManager."""

  def __init__(self,
               cc_key_manager: Any,  # A pybinded CcKeyManager<P> instance
               primitive_class: Type[P],
               primitive_py_wrapper: Type[P]):
    self._cc_key_manager = cc_key_manager
    self._primitive_class = primitive_class
    self._primitive_py_wrapper = primitive_py_wrapper

  def primitive_class(self) -> Type[P]:
    return self._primitive_class

  @_tink_error.use_tink_errors
  def primitive(self, key_data: tink_pb2.KeyData) -> P:
    return self._primitive_py_wrapper(
        self._cc_key_manager.primitive(key_data.SerializeToString()))

  def key_type(self) -> Text:
    return self._cc_key_manager.key_type()

  @_tink_error.use_tink_errors
  def new_key_data(self,
                   key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyData:
    return tink_pb2.KeyData.FromString(
        self._cc_key_manager.new_key_data(key_template.SerializeToString()))


class PrivateKeyManagerCcToPyWrapper(PrivateKeyManager[P]):
  """Transforms C++ KeyManager into a Python KeyManager."""

  def __init__(self,
               cc_key_manager: Any,  # A pybinded CcKeyManager<P> instance
               primitive_class: Type[P],
               primitive_py_wrapper: Type[P]):
    self._cc_key_manager = cc_key_manager
    self._primitive_class = primitive_class
    self._primitive_py_wrapper = primitive_py_wrapper

  def primitive_class(self) -> Type[P]:
    return self._primitive_class

  @_tink_error.use_tink_errors
  def primitive(self, key_data: tink_pb2.KeyData) -> P:
    return self._primitive_py_wrapper(
        self._cc_key_manager.primitive(key_data.SerializeToString()))

  def key_type(self) -> Text:
    return self._cc_key_manager.key_type()

  @_tink_error.use_tink_errors
  def new_key_data(self,
                   key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyData:
    return tink_pb2.KeyData.FromString(
        self._cc_key_manager.new_key_data(key_template.SerializeToString()))

  @_tink_error.use_tink_errors
  def public_key_data(self, key_data: tink_pb2.KeyData) -> tink_pb2.KeyData:
    return tink_pb2.KeyData.FromString(
        self._cc_key_manager.public_key_data(key_data.SerializeToString()))

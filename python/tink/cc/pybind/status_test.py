# Copyright 2019 Google Inc.
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
#
###############################################################################

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
import six
from tink.cc.pybind import tink_bindings


class UtilStatusTest(absltest.TestCase):

  def test_pass_status(self):
    test_status = tink_bindings.Status(
        tink_bindings.ErrorCode.CANCELLED, 'test')
    self.assertTrue(
        tink_bindings.check_status(
            test_status, tink_bindings.ErrorCode.CANCELLED))

  def test_return_ok(self):
    # The return_status function should convert an ok status to None.
    self.assertIsNone(
        tink_bindings.return_status(
            tink_bindings.ErrorCode.OK))

  def test_return_not_ok(self):
    # The return_status function should convert a non-ok status to an exception.
    with self.assertRaises(tink_bindings.StatusNotOk) as cm:
      tink_bindings.return_status(
          tink_bindings.ErrorCode.CANCELLED, 'test')
    self.assertEqual(cm.exception.status.error_code(),
                     tink_bindings.ErrorCode.CANCELLED)
    self.assertEqual(cm.exception.status.error_message(), 'test')

  def test_make_ok(self):
    # The make_status function has been set up to return a status object
    # instead of raising an exception (this is done in status_injector.cc).
    test_status = tink_bindings.make_status(
        tink_bindings.ErrorCode.OK)
    self.assertEqual(test_status.error_code(),
                     tink_bindings.ErrorCode.OK)
    self.assertTrue(test_status.ok())

  def test_make_not_ok(self):
    # The make_status function should always return a status object, even if
    # it is not ok (ie, it should *not* convert it to an exception).
    test_status = tink_bindings.make_status(
        tink_bindings.ErrorCode.CANCELLED)
    self.assertEqual(test_status.error_code(),
                     tink_bindings.ErrorCode.CANCELLED)
    self.assertFalse(test_status.ok())

  def test_make_not_ok_manual_cast(self):
    test_status = tink_bindings.make_status_manual_cast(
        tink_bindings.ErrorCode.CANCELLED)
    self.assertEqual(test_status.error_code(),
                     tink_bindings.ErrorCode.CANCELLED)

  def test_make_status_ref(self):
    result_1 = tink_bindings.make_status_ref(
        tink_bindings.ErrorCode.OK)
    self.assertEqual(result_1.error_code(), tink_bindings.ErrorCode.OK)
    result_2 = tink_bindings.make_status_ref(
        tink_bindings.ErrorCode.CANCELLED)
    self.assertEqual(result_2.error_code(),
                     tink_bindings.ErrorCode.CANCELLED)
    # result_1 and 2 reference the same value, so they should always be equal.
    self.assertEqual(result_1.error_code(), result_2.error_code())

  def test_make_status_ptr(self):
    result_1 = tink_bindings.make_status_ptr(
        tink_bindings.ErrorCode.OK)
    self.assertEqual(result_1.error_code(), tink_bindings.ErrorCode.OK)
    result_2 = tink_bindings.make_status_ptr(
        tink_bindings.ErrorCode.CANCELLED)
    self.assertEqual(result_2.error_code(),
                     tink_bindings.ErrorCode.CANCELLED)
    # result_1 and 2 reference the same value, so they should always be equal.
    self.assertEqual(result_1.error_code(), result_2.error_code())

  def test_member_method(self):
    test_status = tink_bindings.TestClass().make_status(
        tink_bindings.ErrorCode.OK)
    self.assertEqual(test_status.error_code(),
                     tink_bindings.ErrorCode.OK)
    test_status = tink_bindings.TestClass().make_status_const(
        tink_bindings.ErrorCode.OK)
    self.assertEqual(test_status.error_code(),
                     tink_bindings.ErrorCode.OK)

  def test_is_ok(self):
    ok_status = tink_bindings.make_status(
        tink_bindings.ErrorCode.OK)
    self.assertTrue(tink_bindings.is_ok(ok_status))
    failure_status = tink_bindings.make_status(
        tink_bindings.ErrorCode.CANCELLED)
    self.assertFalse(tink_bindings.is_ok(failure_status))


class UtilStatusOrTest(absltest.TestCase):

  def test_return_value(self):
    self.assertEqual(tink_bindings.return_value_status_or(5), 5)

  def test_return_not_ok(self):
    with self.assertRaises(tink_bindings.StatusNotOk) as cm:
      tink_bindings.return_failure_status_or(
          tink_bindings.ErrorCode.NOT_FOUND)
    self.assertEqual(cm.exception.status.error_code(),
                     tink_bindings.ErrorCode.NOT_FOUND)

  def test_make_not_ok(self):
    self.assertEqual(
        tink_bindings.make_failure_status_or(
            tink_bindings.ErrorCode.CANCELLED).error_code(),
        tink_bindings.ErrorCode.CANCELLED)

  def test_make_not_ok_manual_cast(self):
    self.assertEqual(
        tink_bindings.make_failure_status_or_manual_cast(
            tink_bindings.ErrorCode.CANCELLED).error_code(),
        tink_bindings.ErrorCode.CANCELLED)

  def test_return_ptr_status_or(self):
    result_1 = tink_bindings.return_ptr_status_or(5)
    self.assertEqual(result_1.value, 5)
    result_2 = tink_bindings.return_ptr_status_or(6)
    self.assertEqual(result_2.value, 6)
    # result_1 and 2 reference the same value, so they should always be equal.
    self.assertEqual(result_1.value, result_2.value)

  def test_return_unique_ptr(self):
    result = tink_bindings.return_unique_ptr_status_or(5)
    self.assertEqual(result.value, 5)

  def test_member_method(self):
    test_status = tink_bindings.TestClass().make_failure_status_or(
        tink_bindings.ErrorCode.ABORTED)
    self.assertEqual(test_status.error_code(),
                     tink_bindings.ErrorCode.ABORTED)

  def test_is_ok(self):
    ok_result = tink_bindings.return_value_status_or(5)
    self.assertEqual(ok_result, 5)
    self.assertTrue(tink_bindings.is_ok(ok_result))
    failure_result = tink_bindings.make_failure_status_or(
        tink_bindings.ErrorCode.CANCELLED)
    self.assertFalse(tink_bindings.is_ok(failure_result))

  def test_return_alpha_beta_gamma(self):
    d = tink_bindings.return_alpha_beta_gamma_decoded()
    self.assertIsInstance(d, six.text_type)
    b = d.encode('utf-8')
    self.assertEqual(b, b'EDD4f89 alpha=\xce\xb1 beta=\xce\xb2 gamma=\xce\xb3')

    e = tink_bindings.return_alpha_beta_gamma_encoded()
    self.assertIsInstance(e, bytes)
    self.assertEqual(e, b)


if __name__ == '__main__':
  absltest.main()

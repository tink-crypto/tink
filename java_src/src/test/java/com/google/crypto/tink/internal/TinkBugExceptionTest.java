// Copyright 2022 Google LLC
//
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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TinkBugExceptionTest {
  private static void throwsTinkBugException() {
    throw new TinkBugException("I have written a test");
  }

  @Test
  public void testException() throws Exception {
    assertThrows(TinkBugException.class, TinkBugExceptionTest::throwsTinkBugException);
  }

  private static void doNothing() throws GeneralSecurityException {}

  @Test
  public void test_exceptionIsBugVoidVersion_whenNotThrown_notThrown() throws Exception {
    TinkBugException.exceptionIsBug(TinkBugExceptionTest::doNothing);
  }

  private static void throwAnException() throws GeneralSecurityException {
    throw new GeneralSecurityException("");
  }

  @Test
  public void test_exceptionIsBugVoidVersion_whenThrown_throws() throws Exception {
    assertThrows(
        TinkBugException.class,
        () -> TinkBugException.exceptionIsBug(TinkBugExceptionTest::throwAnException));
  }

  private static String returnHello() throws GeneralSecurityException {
    return "Hello";
  }

  @Test
  public void test_exceptionIsBugSupplierVersion_whenNotThrown_notThrown() throws Exception {
    assertThat(TinkBugException.exceptionIsBug(TinkBugExceptionTest::returnHello))
        .isEqualTo("Hello");
  }

  private static String throwAnExceptionB() throws GeneralSecurityException {
    throw new GeneralSecurityException("");
  }

  @Test
  public void test_exceptionIsBugSupplierVersion_whenThrown_throws() throws Exception {
    assertThrows(
        TinkBugException.class,
        () -> TinkBugException.exceptionIsBug(TinkBugExceptionTest::throwAnExceptionB));
  }
}

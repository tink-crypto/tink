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

/**
 * An exception to be thrown in case there is a bug in Tink.
 *
 * <p>This exception is thrown by Tink in cases there is a guaranteed bug in Tink. No non-Tink code
 * should throw such an exception.
 */
public final class TinkBugException extends RuntimeException {
  /** Constructs a new TinkBugException with the specified detail message. */
  public TinkBugException(String message) {
    super(message);
  }

  /** Constructs a new TinkBugException with the specified detail message and cause. */
  public TinkBugException(String message, Throwable cause) {
    super(message, cause);
  }

  /** Constructs a new TinkBugException as a wrapper on a root cause */
  public TinkBugException(Throwable cause) {
    super(cause);
  }

  /**
   * A function which returns void and may throw an Exception.
   *
   * <p>Named after java.lang.Runnable.
   */
  public interface ThrowingRunnable {
    void run() throws Exception;
  }

  /**
   * A function which produces a T and may throw an Exception.
   *
   * <p>Named after java.util.function.Supplier.
   */
  public interface ThrowingSupplier<T> {
    T get() throws Exception;
  }

  /** Swallows an exception and translates it into a TinkBugException. */
  public static <T> T exceptionIsBug(ThrowingSupplier<T> t) {
    try {
      return t.get();
    } catch (Exception e) {
      throw new TinkBugException(e);
    }
  }

  /** Swallows an exception and translates it into a TinkBugException. */
  public static void exceptionIsBug(ThrowingRunnable v) {
    try {
      v.run();
    } catch (Exception e) {
      throw new TinkBugException(e);
    }
  }
}

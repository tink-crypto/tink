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

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyFormat;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeyTester}. */
@RunWith(JUnit4.class)
public final class KeyTesterTest {
  private static class TestKeyFormat extends KeyFormat {
    private final int hashCode;

    public TestKeyFormat(int hashCode) {
      this.hashCode = hashCode;
    }

    @Override
    public boolean hasIdRequirement() {
      return false;
    }

    @Override
    public int hashCode() {
      return hashCode;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof TestKeyFormat)) {
        return false;
      }
      return ((TestKeyFormat) o).hashCode == hashCode;
    }
  }

  private static class TestKey extends Key {
    private final int id;
    private final TestKeyFormat format;

    public TestKey(int id, TestKeyFormat format) {
      this.id = id;
      this.format = format;
    }

    public TestKey(int id) {
      this.id = id;
      this.format = new TestKeyFormat(0);
    }

    @Override
    public boolean equalsKey(Key other) {
      return ((TestKey) other).id == id;
    }

    @Override
    public Optional<Integer> getIdRequirement() {
      return format.hasIdRequirement() ? Optional.of(id) : Optional.empty();
    }

    @Override
    public KeyFormat getKeyFormat() {
      return format;
    }
  }

  @Test
  public void keyTester_works() throws Exception {
    TestKeyFormat format0 = new TestKeyFormat(0);
    TestKeyFormat format1 = new TestKeyFormat(1);
    new KeyTester()
        .addEqualityGroup("Group 0a", new TestKey(0, format0), new TestKey(0, format0))
        .addEqualityGroup("Group 0b", new TestKey(1, format0), new TestKey(1, format0))
        .addEqualityGroup("Group 1", new TestKey(2, format1), new TestKey(2, format1))
        .doTests();
  }

  @Test
  public void differentKeysSameGroup_throws() throws Exception {
    KeyTester tester =
        new KeyTester().addEqualityGroup("MyWrongGroup", new TestKey(0), new TestKey(1));
    AssertionError thrown = assertThrows(AssertionError.class, tester::doTests);
    assertThat(thrown).hasMessageThat().contains("from group 'MyWrongGroup' are not equal");
  }

  @Test
  public void sameKeyDifferentGroup_throws() throws Exception {
    KeyTester tester =
        new KeyTester()
            .addEqualityGroup("MyGroup0", new TestKey(0))
            .addEqualityGroup("MyGroup1", new TestKey(0));
    AssertionError thrown = assertThrows(AssertionError.class, tester::doTests);
    assertThat(thrown).hasMessageThat().contains("equalsKey returns true");
    assertThat(thrown).hasMessageThat().contains("MyGroup0");
    assertThat(thrown).hasMessageThat().contains("MyGroup1");
  }

  @Test
  public void sameKeyGroupDifferentFormat_throws() throws Exception {
    TestKeyFormat format0 = new TestKeyFormat(0);
    TestKeyFormat format1 = new TestKeyFormat(1);
    KeyTester tester =
        new KeyTester()
            .addEqualityGroup("MyGroup0", new TestKey(0, format0), new TestKey(0, format1));
    assertThrows(AssertionError.class, tester::doTests);
  }

  @Test
  public void sameKeyGroupFormats_differentHashCode_throws() throws Exception {
    TestKeyFormat format0 = new TestKeyFormat(0);
    TestKeyFormat format1 =
        new TestKeyFormat(0) {
          @Override
          public int hashCode() {
            return 12345;
          }
        };
    KeyTester tester =
        new KeyTester()
            .addEqualityGroup("MyGroup0", new TestKey(0, format0), new TestKey(0, format1));
    assertThrows(AssertionError.class, tester::doTests);
  }

  @Test
  public void sameKeyGroupFormats_differentIdRequirements_throws() throws Exception {
    TestKeyFormat format0 = new TestKeyFormat(0);
    TestKeyFormat format1 =
        new TestKeyFormat(0) {
          @Override
          public boolean hasIdRequirement() {
            return true;
          }
        };
    KeyTester tester =
        new KeyTester()
            .addEqualityGroup("MyGroup0", new TestKey(0, format0), new TestKey(0, format1));
    assertThrows(AssertionError.class, tester::doTests);
  }

  @Test
  public void twoGroupsWithSameName_throws() throws Exception {
    KeyTester tester = new KeyTester().addEqualityGroup("MyGroup0", new TestKey(0));
    assertThrows(AssertionError.class, () -> tester.addEqualityGroup("MyGroup0", new TestKey(0)));
  }

  @Test
  public void testIdRequirementTrue_isOk() throws Exception {
    TestKeyFormat format =
        new TestKeyFormat(1) {
          @Override
          public boolean hasIdRequirement() {
            return true;
          }
        };
    new KeyTester().addEqualityGroup("", new TestKey(0, format)).doTests();
  }

  @Test
  public void testIdRequirementInconsistent_throws() throws Exception {
    TestKeyFormat format =
        new TestKeyFormat(1) {
          @Override
          public boolean hasIdRequirement() {
            return true;
          }
        };
    TestKey key =
        new TestKey(10, format) {
          @Override
          public Optional<Integer> getIdRequirement() {
            return Optional.empty();
          }
        };
    KeyTester tester = new KeyTester().addEqualityGroup("", key);
    assertThrows(AssertionError.class, tester::doTests);
  }

  @Test
  public void testIdRequirementInconsistent2_throws() throws Exception {
    TestKeyFormat format =
        new TestKeyFormat(1) {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };
    TestKey key =
        new TestKey(10, format) {
          @Override
          public Optional<Integer> getIdRequirement() {
            return Optional.of(15);
          }
        };
    KeyTester tester = new KeyTester().addEqualityGroup("", key);
    assertThrows(AssertionError.class, tester::doTests);
  }
}

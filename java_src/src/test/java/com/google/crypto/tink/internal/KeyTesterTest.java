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
import com.google.crypto.tink.Parameters;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeyTester}. */
@RunWith(JUnit4.class)
public final class KeyTesterTest {
  private static class TestParameters extends Parameters {
    private final int hashCode;

    public TestParameters(int hashCode) {
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
      if (!(o instanceof TestParameters)) {
        return false;
      }
      return ((TestParameters) o).hashCode == hashCode;
    }
  }

  private static class TestKey extends Key {
    private final int id;
    private final TestParameters parameters;

    public TestKey(int id, TestParameters parameters) {
      this.id = id;
      this.parameters = parameters;
    }

    public TestKey(int id) {
      this.id = id;
      this.parameters = new TestParameters(0);
    }

    @Override
    public boolean equalsKey(Key other) {
      return ((TestKey) other).id == id;
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      return parameters.hasIdRequirement() ? id : null;
    }

    @Override
    public Parameters getParameters() {
      return parameters;
    }
  }

  @Test
  public void keyTester_works() throws Exception {
    TestParameters parameters0 = new TestParameters(0);
    TestParameters parameters1 = new TestParameters(1);
    new KeyTester()
        .addEqualityGroup("Group 0a", new TestKey(0, parameters0), new TestKey(0, parameters0))
        .addEqualityGroup("Group 0b", new TestKey(1, parameters0), new TestKey(1, parameters0))
        .addEqualityGroup("Group 1", new TestKey(2, parameters1), new TestKey(2, parameters1))
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
  public void sameKeyGroupDifferentParameters_throws() throws Exception {
    TestParameters parameters0 = new TestParameters(0);
    TestParameters parameters1 = new TestParameters(1);
    KeyTester tester =
        new KeyTester()
            .addEqualityGroup("MyGroup0", new TestKey(0, parameters0), new TestKey(0, parameters1));
    assertThrows(AssertionError.class, tester::doTests);
  }

  @Test
  public void sameKeyGroup_parametersDifferentHashCode_throws() throws Exception {
    TestParameters parameters0 = new TestParameters(0);
    TestParameters parameters1 =
        new TestParameters(0) {
          @Override
          public int hashCode() {
            return 12345;
          }
        };
    KeyTester tester =
        new KeyTester()
            .addEqualityGroup("MyGroup0", new TestKey(0, parameters0), new TestKey(0, parameters1));
    assertThrows(AssertionError.class, tester::doTests);
  }

  @Test
  public void sameKeyGroup_parametersDifferentIdRequirements_throws() throws Exception {
    TestParameters parameters0 = new TestParameters(0);
    TestParameters parameters1 =
        new TestParameters(0) {
          @Override
          public boolean hasIdRequirement() {
            return true;
          }
        };
    KeyTester tester =
        new KeyTester()
            .addEqualityGroup("MyGroup0", new TestKey(0, parameters0), new TestKey(0, parameters1));
    assertThrows(AssertionError.class, tester::doTests);
  }

  @Test
  public void twoGroupsWithSameName_throws() throws Exception {
    KeyTester tester = new KeyTester().addEqualityGroup("MyGroup0", new TestKey(0));
    assertThrows(AssertionError.class, () -> tester.addEqualityGroup("MyGroup0", new TestKey(0)));
  }

  @Test
  public void testIdRequirementTrue_isOk() throws Exception {
    TestParameters parameters =
        new TestParameters(1) {
          @Override
          public boolean hasIdRequirement() {
            return true;
          }
        };
    new KeyTester().addEqualityGroup("", new TestKey(0, parameters)).doTests();
  }

  @Test
  public void testIdRequirementInconsistent_throws() throws Exception {
    TestParameters parameters =
        new TestParameters(1) {
          @Override
          public boolean hasIdRequirement() {
            return true;
          }
        };
    TestKey key =
        new TestKey(10, parameters) {
          @Override
          @Nullable
          public Integer getIdRequirementOrNull() {
            return null;
          }
        };
    KeyTester tester = new KeyTester().addEqualityGroup("", key);
    assertThrows(AssertionError.class, tester::doTests);
  }

  @Test
  public void testIdRequirementInconsistent2_throws() throws Exception {
    TestParameters parameters =
        new TestParameters(1) {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };
    TestKey key =
        new TestKey(10, parameters) {
          @Override
          @Nullable
          public Integer getIdRequirementOrNull() {
            return 15;
          }
        };
    KeyTester tester = new KeyTester().addEqualityGroup("", key);
    assertThrows(AssertionError.class, tester::doTests);
  }
}

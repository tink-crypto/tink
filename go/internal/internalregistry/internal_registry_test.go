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

package internalregistry_test

import (
	"testing"

	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/testing/fakemonitoring"
)

func TestRegisterMonitoringClient(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	fakeClient := &fakemonitoring.Client{
		Name: "fake-monitor-client-1",
	}
	if err := internalregistry.RegisterMonitoringClient(fakeClient); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	got := internalregistry.GetMonitoringClient().(*fakemonitoring.Client)
	if got.Name != "fake-monitor-client-1" {
		t.Errorf("got = %q, want %q", got.Name, "fake-monitor-client-1")
	}
}

func TestRegisterTwiceFailsMonitoringClient(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	fakeClient := fakemonitoring.Client{}
	if err := internalregistry.RegisterMonitoringClient(&fakeClient); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	if err := internalregistry.RegisterMonitoringClient(&fakeClient); err == nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = nil, want error")
	}
}

func TestDefaultMonitoringLogger(t *testing.T) {
	defaultClient := internalregistry.GetMonitoringClient()
	defaultLogger, err := defaultClient.NewLogger(nil)
	if err != nil {
		t.Fatalf("defaultClient.NewLogger() err = %v, want nil", err)
	}
	defaultLogger.Log(0, 0)
	defaultLogger.LogFailure()
}

func TestClearMonitoringClient(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	fakeClient := &fakemonitoring.Client{
		Name: "fake-monitor-client-1",
	}
	defaultClient := internalregistry.GetMonitoringClient()
	if err := internalregistry.RegisterMonitoringClient(fakeClient); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	got := internalregistry.GetMonitoringClient()
	if got != fakeClient {
		t.Errorf("internalregistry.GetMonitoringClient() = %v, want %v", got, fakeClient)
	}
	internalregistry.ClearMonitoringClient()
	got = internalregistry.GetMonitoringClient()
	if got != defaultClient {
		t.Errorf("internalregistry.GetMonitoringClient() = %v, want %v", got, defaultClient)
	}
}

func TestClearReRegisterMonitoringClient(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	fakeClient := &fakemonitoring.Client{
		Name: "fake-monitor-client-1",
	}
	if err := internalregistry.RegisterMonitoringClient(fakeClient); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	internalregistry.ClearMonitoringClient()
	fakeClient2 := &fakemonitoring.Client{
		Name: "fake-monitor-client-2",
	}
	if err := internalregistry.RegisterMonitoringClient(fakeClient2); err != nil {
		t.Errorf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	got := internalregistry.GetMonitoringClient()
	if got != fakeClient2 {
		t.Errorf("internalregistry.GetMonitoringClient() = %v, want %v", got, fakeClient2)
	}
}

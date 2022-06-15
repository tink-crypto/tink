// Copyright 2022 Google Inc.
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

package fakemonitoring_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/tink/go/monitoring"
	"github.com/google/tink/go/testing/fakemonitoring"
)

func TestCreateNewClient(t *testing.T) {
	client := fakemonitoring.NewClient("fake-client")
	if client.Name != "fake-client" {
		t.Errorf("client.Name = %q, want %q", client.Name, "fake-client")
	}
}

func TestCreateNewLoggers(t *testing.T) {
	client := fakemonitoring.NewClient("client")
	ctxEnc := monitoring.NewContext("aead", "encrypt", monitoring.NewKeysetInfo(nil, 0, []*monitoring.Entry{}))
	encLogger, err := client.NewLogger(ctxEnc)
	if err != nil {
		t.Fatalf("NewLogger() err = %v, want nil", err)
	}
	ctxDec := monitoring.NewContext("aead", "decrypt", monitoring.NewKeysetInfo(nil, 0, []*monitoring.Entry{}))
	decLogger, err := client.NewLogger(ctxDec)
	if err != nil {
		t.Fatalf("NewLogger() err = %v, want nil", err)
	}
	gotEnc := encLogger.(*fakemonitoring.Logger).Context
	if !cmp.Equal(gotEnc, ctxEnc) {
		t.Errorf("got = %v, want = %v", gotEnc, ctxEnc)
	}
	gotDec := decLogger.(*fakemonitoring.Logger).Context
	if !cmp.Equal(gotDec, ctxDec) {
		t.Errorf("got = %v, want = %v", gotDec, ctxDec)
	}
}

func TestLoggerRecordsEvents(t *testing.T) {
	client := fakemonitoring.NewClient("client")
	ctxEnc := monitoring.NewContext("aead", "encrypt", monitoring.NewKeysetInfo(nil, 0, []*monitoring.Entry{}))
	logger, err := client.NewLogger(ctxEnc)
	if err != nil {
		t.Fatalf("NewLogger() err = %v, want nil", err)
	}
	logger.Log(5, 8)
	logger.Log(10, 3)
	logger.Log(12, 3)
	got := client.Events()
	want := []*fakemonitoring.LogEvent{
		{
			Context:  ctxEnc,
			KeyID:    5,
			NumBytes: 8,
		},
		{
			Context:  ctxEnc,
			KeyID:    10,
			NumBytes: 3,
		},
		{
			Context:  ctxEnc,
			KeyID:    12,
			NumBytes: 3,
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("Events() = %v, want = %v", got, want)
	}
}

func TestLogFailureRecordsFailure(t *testing.T) {
	client := fakemonitoring.NewClient("client")
	ctxEnc := monitoring.NewContext("aead", "encrypt", monitoring.NewKeysetInfo(nil, 0, []*monitoring.Entry{}))
	logger, err := client.NewLogger(ctxEnc)
	if err != nil {
		t.Fatalf("NewLogger() err = %v, want nil", err)
	}
	logger.LogFailure()
	logger.LogFailure()
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: ctxEnc,
		},
		{
			Context: ctxEnc,
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("Failures() = %v, want = %v", got, want)
	}
}

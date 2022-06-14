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

// Package internalregistry provides a container for functionality that is required
// across Tink similar to the `registry` but isn't part of the public API.
package internalregistry

import (
	"fmt"
	"sync"

	"github.com/google/tink/go/monitoring"
)

var (
	monitoringClientMu sync.RWMutex
	monitoringClient   monitoring.Client = nil
)

// RegisterMonitoringClient registers a client that can create loggers.
func RegisterMonitoringClient(client monitoring.Client) error {
	monitoringClientMu.Lock()
	defer monitoringClientMu.Unlock()
	if monitoringClient != nil {
		return fmt.Errorf("monitoring client is already registered")
	}
	monitoringClient = client
	return nil
}

// ClearMonitoringClient removes the registered monitoring client.
func ClearMonitoringClient() {
	monitoringClientMu.Lock()
	defer monitoringClientMu.Unlock()
	monitoringClient = nil
}

// GetMonitoringClient returns the registered monitoring client.
// The return value of this function can be nil, indicating there
// isn't any monitoring client registered.
func GetMonitoringClient() monitoring.Client {
	return monitoringClient
}

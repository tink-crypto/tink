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
	monitoringClient   monitoring.Client = defaultClient
)

type doNothingLogger struct{}

var _ monitoring.Logger = (*doNothingLogger)(nil)

func (l *doNothingLogger) Log(uint32, int) {}

func (l *doNothingLogger) LogFailure() {}

var defaultLogger = &doNothingLogger{}

type doNothingClient struct{}

var _ monitoring.Client = (*doNothingClient)(nil)

func (c *doNothingClient) NewLogger(*monitoring.Context) (monitoring.Logger, error) {
	return defaultLogger, nil
}

var defaultClient = &doNothingClient{}

// RegisterMonitoringClient registers a client that can create loggers.
func RegisterMonitoringClient(client monitoring.Client) error {
	monitoringClientMu.Lock()
	defer monitoringClientMu.Unlock()
	if monitoringClient != nil && monitoringClient != defaultClient {
		return fmt.Errorf("monitoring client is already registered")
	}
	monitoringClient = client
	return nil
}

// ClearMonitoringClient removes the registered monitoring client.
func ClearMonitoringClient() {
	monitoringClientMu.Lock()
	defer monitoringClientMu.Unlock()
	monitoringClient = defaultClient
}

// GetMonitoringClient returns the registered monitoring client.
func GetMonitoringClient() monitoring.Client {
	return monitoringClient
}

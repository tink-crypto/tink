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

// Package fakemonitoring provides a fake implementation of monitoring clients and loggers.
// TODO(b/225071831): implement fake functionality that stores logged events.
package fakemonitoring

import (
	"github.com/google/tink/go/monitoring"
)

// Logger implements a fake monitoring.Logger
type Logger struct{}

var _ monitoring.Logger = (*Logger)(nil)

// Log logs the use of a primitive with a key with `keyID` operating over `numBytes`.
func (l *Logger) Log(keyID uint32, numBytes int) {}

// LogFailure captures a failure.
func (l *Logger) LogFailure() {}

// Client implements a fake monitoring.Client
type Client struct {
	Name string
}

var _ monitoring.Client = (*Client)(nil)

// NewLogger creates a new fake Logger.
func (c *Client) NewLogger(context *monitoring.Context) (monitoring.Logger, error) {
	return &Logger{}, nil
}

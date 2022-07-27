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
package fakemonitoring

import (
	"sync"

	"github.com/google/tink/go/monitoring"
)

// Logger implements a fake monitoring.Logger
type Logger struct {
	Context *monitoring.Context
	client  *Client
}

var _ monitoring.Logger = (*Logger)(nil)

// Log logs the use of a primitive with a key with `keyID` operating over `numBytes`.
func (l *Logger) Log(keyID uint32, numBytes int) {
	l.client.addEvent(&LogEvent{
		Context:  l.Context,
		KeyID:    keyID,
		NumBytes: numBytes,
	})
}

// LogFailure captures a failure.
func (l *Logger) LogFailure() {
	l.client.addFailure(&LogFailure{Context: l.Context})
}

// LogEvent stored on each 'Log' operation.
type LogEvent struct {
	Context  *monitoring.Context
	KeyID    uint32
	NumBytes int
}

// LogFailure stored on each 'LogFailure' operation.
type LogFailure struct {
	Context *monitoring.Context
}

// Client implements a fake monitoring.Client
type Client struct {
	Name string

	eventsMu   sync.Mutex
	events     []*LogEvent
	failuresMu sync.Mutex
	failures   []*LogFailure
}

var _ monitoring.Client = (*Client)(nil)

// NewClient creates a new fake monitoring client.
func NewClient(name string) *Client {
	return &Client{
		Name: name,
	}
}

// NewLogger creates a new fake Logger.
func (c *Client) NewLogger(context *monitoring.Context) (monitoring.Logger, error) {
	return &Logger{
		Context: context,
		client:  c,
	}, nil
}

// Events returns logged events.
func (c *Client) Events() []*LogEvent {
	return c.events
}

// Failures returns logged failures.
func (c *Client) Failures() []*LogFailure {
	return c.failures
}

func (c *Client) addEvent(event *LogEvent) {
	c.eventsMu.Lock()
	defer c.eventsMu.Unlock()
	c.events = append(c.events, event)
}

func (c *Client) addFailure(failure *LogFailure) {
	defer c.failuresMu.Unlock()
	c.failuresMu.Lock()
	c.failures = append(c.failures, failure)

}

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

package keyset

import "fmt"

// Option is used to pass options for a keyset handle.
type Option interface {
	set(k *Handle) error
}

type option func(*Handle) error

func (o option) set(h *Handle) error { return o(h) }

// WithAnnotations adds monitoring annotations to a keyset handle.
func WithAnnotations(annotations map[string]string) Option {
	return option(func(h *Handle) error {
		if h.annotations != nil {
			return fmt.Errorf("keyset already contains annotations")
		}
		h.annotations = annotations
		return nil
	})
}

func applyOptions(h *Handle, opts ...Option) error {
	for _, opt := range opts {
		if err := opt.set(h); err != nil {
			return err
		}
	}
	return nil
}

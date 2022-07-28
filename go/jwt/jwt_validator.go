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

package jwt

import (
	"fmt"
	"time"
)

const (
	jwtMaxClockSkewMinutes = 10
)

// ValidatorOpts define validation options for JWT validators.
type ValidatorOpts struct {
	ExpectedTypeHeader *string
	ExpectedIssuer     *string
	ExpectedAudiences  *string // deprecated. Use ExpectedAudience instead.
	ExpectedAudience   *string

	IgnoreTypeHeader bool
	IgnoreAudiences  bool
	IgnoreIssuer     bool

	AllowMissingExpiration bool
	ExpectIssuedInThePast  bool

	ClockSkew time.Duration
	FixedNow  time.Time
}

// Validator defines how JSON Web Tokens (JWT) should be validated.
type Validator struct {
	opts ValidatorOpts
}

// NewValidator creates a new Validator.
func NewValidator(opts *ValidatorOpts) (*Validator, error) {
	if opts == nil {
		return nil, fmt.Errorf("ValidatorOpts can't be nil")
	}
	if opts.ExpectedAudiences != nil {
		if opts.ExpectedAudience != nil {
			return nil, fmt.Errorf("ExpectedAudiences and ExpectedAudience can't be set at the same time")
		}
		opts.ExpectedAudience = opts.ExpectedAudiences
		opts.ExpectedAudiences = nil
	}
	if opts.ExpectedTypeHeader != nil && opts.IgnoreTypeHeader {
		return nil, fmt.Errorf("ExpectedTypeHeader and IgnoreTypeHeader cannot be used together")
	}
	if opts.ExpectedIssuer != nil && opts.IgnoreIssuer {
		return nil, fmt.Errorf("ExpectedIssuer and IgnoreIssuer cannot be used together")
	}
	if opts.ExpectedAudience != nil && opts.IgnoreAudiences {
		return nil, fmt.Errorf("ExpectedAudience and IgnoreAudience cannot be used together")
	}
	if opts.ClockSkew.Minutes() > jwtMaxClockSkewMinutes {
		return nil, fmt.Errorf("clock skew too large, max is %d minutes", jwtMaxClockSkewMinutes)
	}
	return &Validator{
		opts: *opts,
	}, nil
}

// Validate validates a rawJWT according to the options provided.
func (v *Validator) Validate(rawJWT *RawJWT) error {
	if rawJWT == nil {
		return fmt.Errorf("rawJWT can't be nil")
	}
	if err := v.validateTimestamps(rawJWT); err != nil {
		return err
	}
	if err := v.validateTypeHeader(rawJWT); err != nil {
		return fmt.Errorf("validating type header: %v", err)
	}
	if err := v.validateAudiences(rawJWT); err != nil {
		return fmt.Errorf("validating audience claim: %v", err)
	}
	if err := v.validateIssuer(rawJWT); err != nil {
		return fmt.Errorf("validating issuer claim: %v", err)
	}
	return nil
}

func (v *Validator) validateTimestamps(rawJWT *RawJWT) error {
	now := time.Now()
	if !v.opts.FixedNow.IsZero() {
		now = v.opts.FixedNow
	}

	if !rawJWT.HasExpiration() && !v.opts.AllowMissingExpiration {
		return fmt.Errorf("token doesn't have an expiration set")
	}
	if rawJWT.HasExpiration() {
		exp, err := rawJWT.ExpiresAt()
		if err != nil {
			return err
		}
		if !exp.After(now.Add(-v.opts.ClockSkew)) {
			return fmt.Errorf("token has expired")
		}
	}
	if rawJWT.HasNotBefore() {
		nbf, err := rawJWT.NotBefore()
		if err != nil {
			return err
		}
		if nbf.After(now.Add(v.opts.ClockSkew)) {
			return fmt.Errorf("token cannot be used yet")
		}
	}
	if v.opts.ExpectIssuedInThePast {
		iat, err := rawJWT.IssuedAt()
		if err != nil {
			return err
		}
		if iat.After(now.Add(v.opts.ClockSkew)) {
			return fmt.Errorf("token has an invalid iat claim in the future")
		}
	}
	return nil
}

func (v *Validator) validateTypeHeader(rawJWT *RawJWT) error {
	skip, err := validateFieldPresence(v.opts.IgnoreTypeHeader, rawJWT.HasTypeHeader(), v.opts.ExpectedTypeHeader != nil)
	if err != nil {
		return err
	}
	if skip {
		return nil
	}
	typeHeader, err := rawJWT.TypeHeader()
	if err != nil {
		return err
	}
	if typeHeader != *v.opts.ExpectedTypeHeader {
		return fmt.Errorf("wrong 'type header' type")
	}
	return nil
}

func (v *Validator) validateIssuer(rawJWT *RawJWT) error {
	skip, err := validateFieldPresence(v.opts.IgnoreIssuer, rawJWT.HasIssuer(), v.opts.ExpectedIssuer != nil)
	if err != nil {
		return err
	}
	if skip {
		return nil
	}
	issuer, err := rawJWT.Issuer()
	if err != nil {
		return err
	}
	if issuer != *v.opts.ExpectedIssuer {
		return fmt.Errorf("wrong issuer")
	}
	return nil
}

func (v *Validator) validateAudiences(rawJWT *RawJWT) error {
	skip, err := validateFieldPresence(v.opts.IgnoreAudiences, rawJWT.HasAudiences(), v.opts.ExpectedAudience != nil)
	if err != nil {
		return err
	}
	if skip {
		return nil
	}
	audiences, err := rawJWT.Audiences()
	if err != nil {
		return err
	}
	for i, aud := range audiences {
		if aud == *v.opts.ExpectedAudience {
			break
		}
		if i == len(audiences)-1 {
			return fmt.Errorf("audience not found")
		}
	}
	return nil
}

func validateFieldPresence(ignore bool, isPresent bool, isExpected bool) (bool, error) {
	if ignore {
		return true, nil
	}
	if !isExpected && !isPresent {
		return true, nil
	}
	if !isExpected && isPresent {
		return false, fmt.Errorf("token has claim but validator doesn't expect it")
	}
	if isExpected && !isPresent {
		return false, fmt.Errorf("claim was expected but isn't present")
	}
	return false, nil
}

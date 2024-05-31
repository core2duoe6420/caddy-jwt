package caddyjwt

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"strings"
)

// copied from validate.go to overcome claim not []string but []interface{}

type claimContainsString struct {
	name    string
	value   string
	makeErr func(error) jwt.ValidationError
}

// ClaimContainsString can be used to check if the claim called `name`, which is
// expected to be a list of strings, contains `value`. Currently because of the
// implementation this will probably only work for `aud` fields.
func ClaimContainsString(name, value string) jwt.Validator {
	return claimContainsString{
		name:    name,
		value:   value,
		makeErr: jwt.NewValidationError,
	}
}

func (ccs claimContainsString) Validate(_ context.Context, t Token) jwt.ValidationError {
	v, ok := t.Get(ccs.name)
	if !ok {
		return ccs.makeErr(fmt.Errorf(`claim %q not found`, ccs.name))
	}

	list, ok := v.([]interface{})
	if !ok {
		return ccs.makeErr(fmt.Errorf(`claim %q must be a []interface{} (got %T)`, ccs.name, v))
	}

	for _, v := range list {
		vs, ok := v.(string)
		if ok && strings.EqualFold(vs, ccs.value) {
			return nil
		}
	}
	return ccs.makeErr(fmt.Errorf(`%q not satisfied`, ccs.name))
}

type claimValueIsStringIgnoreCase struct {
	name    string
	value   string
	makeErr func(error) jwt.ValidationError
}

func ClaimValueIsStringIgnoreCase(name string, value string) jwt.Validator {
	return &claimValueIsStringIgnoreCase{
		name:    name,
		value:   value,
		makeErr: jwt.NewValidationError,
	}
}

func (cv *claimValueIsStringIgnoreCase) Validate(_ context.Context, t Token) jwt.ValidationError {
	v, ok := t.Get(cv.name)
	if !ok {
		return cv.makeErr(fmt.Errorf(`%q not satisfied: claim %q does not exist`, cv.name, cv.name))
	}
	vs, ok := v.(string)
	if !ok {
		return cv.makeErr(fmt.Errorf(`%q not satisfied: claim %q not a string`, cv.name, cv.name))
	}
	if !strings.EqualFold(vs, cv.value) {
		return cv.makeErr(fmt.Errorf(`%q not satisfied: values do not match`, cv.name))
	}
	return nil
}

package caddyjwt

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
		if v == ccs.value {
			return nil
		}
	}
	return ccs.makeErr(fmt.Errorf(`%q not satisfied`, ccs.name))
}

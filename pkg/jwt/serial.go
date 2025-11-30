package jwt

// Claimer is an interface for claim validation.
type Claimer interface {
	Valid() error
}

// Marshal generates a JWT from the header, claims, and secret.
func Marshal(header Header, claims any, secret []byte) (string, error) {
	if header.Typ == "" {
		header.Typ = JWT
	}

	return (&token{header: header, payload: payload{claims: claims}}).marshal(secret)
}

// Unmarshal decodes and validates a JWT.
func Unmarshal(jws string, claims any, secret []byte) error {
	t := &token{
		payload: payload{claims: claims},
	}

	if err := t.unmarshal(jws, secret); err != nil {
		return err
	}

	if t.header.Typ != JWT {
		return unsupportedTypeError{typ: t.header.Typ}
	}

	if v, ok := claims.(Claimer); ok {
		if err := v.Valid(); err != nil {
			return err
		}
	}

	return nil
}

package jwt

// Marshal generates a JWT from the header, claims, and secret.
func Marshal(header Header, claims any, secret []byte) (string, error) {
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
		return UnsupportedTypeError{t.header.Typ}
	}

	return nil
}
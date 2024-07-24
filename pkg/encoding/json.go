package encoding

import "encoding/json"

func EncodeJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func DecodeJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

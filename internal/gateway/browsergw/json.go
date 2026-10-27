// SPDX-License-Identifier: Apache-2.0

package browsergw

import "encoding/json"

// marshal encodes a relay table as the relay reads it.
func marshal(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

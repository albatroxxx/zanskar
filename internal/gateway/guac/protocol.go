// SPDX-License-Identifier: Apache-2.0

// Package guac speaks the Guacamole protocol to a guacd sidecar (ADR 0002).
// Zanskar performs the handshake with the connection parameters it holds
// (target address, credential, size, recording flags) and then relays the
// instruction stream between guacd and the browser's guacamole-common-js
// client over a WebSocket. The browser never sees the parameters.
//
// Wire format: instructions are "len.value,len.value,...;" where len is the
// length of value in Unicode code points, and the first element is the
// opcode. Example: "6.select,3.rdp;".
package guac

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Instruction is one opcode with its arguments.
type Instruction struct {
	Opcode string
	Args   []string
}

// Errors.
var (
	ErrMalformed = errors.New("guac: malformed instruction")
	ErrTooLong   = errors.New("guac: instruction exceeds limit")
)

// maxInstruction bounds a single instruction. Screen updates are chunked by
// guacd well below this; anything larger is hostile or broken.
const maxInstruction = 8 << 20

// Encode renders an instruction in wire format.
func Encode(op string, args ...string) string {
	var b strings.Builder
	writeElem := func(s string) {
		b.WriteString(strconv.Itoa(utf8.RuneCountInString(s)))
		b.WriteByte('.')
		b.WriteString(s)
	}
	writeElem(op)
	for _, a := range args {
		b.WriteByte(',')
		writeElem(a)
	}
	b.WriteByte(';')
	return b.String()
}

// String renders the instruction in wire format.
func (in Instruction) String() string { return Encode(in.Opcode, in.Args...) }

// Reader parses instructions from a stream.
type Reader struct {
	r *bufio.Reader
}

// NewReader wraps r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 64<<10)}
}

// ReadRaw returns the next complete instruction in wire format, including
// the trailing ';'. It is what the relay forwards verbatim.
func (rd *Reader) ReadRaw() (string, error) {
	var b strings.Builder
	for {
		// length
		lenStr, err := rd.r.ReadString('.')
		if err != nil {
			return "", err
		}
		n, err := strconv.Atoi(strings.TrimSuffix(lenStr, "."))
		if err != nil || n < 0 {
			return "", ErrMalformed
		}
		b.WriteString(lenStr)
		if b.Len()+n > maxInstruction {
			return "", ErrTooLong
		}
		// value: n runes
		for i := 0; i < n; i++ {
			r, _, err := rd.r.ReadRune()
			if err != nil {
				return "", err
			}
			b.WriteRune(r)
		}
		sep, err := rd.r.ReadByte()
		if err != nil {
			return "", err
		}
		b.WriteByte(sep)
		switch sep {
		case ',':
			continue
		case ';':
			return b.String(), nil
		default:
			return "", ErrMalformed
		}
	}
}

// Read parses the next instruction.
func (rd *Reader) Read() (Instruction, error) {
	raw, err := rd.ReadRaw()
	if err != nil {
		return Instruction{}, err
	}
	return Parse(raw)
}

// Parse decodes one wire-format instruction.
func Parse(raw string) (Instruction, error) {
	if !strings.HasSuffix(raw, ";") {
		return Instruction{}, ErrMalformed
	}
	rest := raw[:len(raw)-1]
	var elems []string
	for len(rest) > 0 {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			return Instruction{}, ErrMalformed
		}
		n, err := strconv.Atoi(rest[:dot])
		if err != nil || n < 0 {
			return Instruction{}, ErrMalformed
		}
		rest = rest[dot+1:]
		// take n runes
		idx := 0
		for i := 0; i < n; i++ {
			if idx >= len(rest) {
				return Instruction{}, ErrMalformed
			}
			_, size := utf8.DecodeRuneInString(rest[idx:])
			idx += size
		}
		elems = append(elems, rest[:idx])
		rest = rest[idx:]
		if len(rest) == 0 {
			break
		}
		if rest[0] != ',' {
			return Instruction{}, ErrMalformed
		}
		rest = rest[1:]
	}
	if len(elems) == 0 {
		return Instruction{}, ErrMalformed
	}
	return Instruction{Opcode: elems[0], Args: elems[1:]}, nil
}

// Opcode extracts just the opcode from a raw instruction without a full parse.
func Opcode(raw string) string {
	dot := strings.IndexByte(raw, '.')
	if dot < 0 {
		return ""
	}
	n, err := strconv.Atoi(raw[:dot])
	if err != nil || n < 0 || dot+1+n > len(raw) {
		return ""
	}
	return raw[dot+1 : dot+1+n]
}

// ErrorInstruction builds a Guacamole "error" instruction with a status code
// (see the protocol's status codes; 519 is "upstream unavailable").
func ErrorInstruction(msg string, status int) string {
	return Encode("error", msg, fmt.Sprint(status))
}

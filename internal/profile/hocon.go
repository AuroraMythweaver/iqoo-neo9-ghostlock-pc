package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Byte constants keep this file free of escape-sequence noise.
const (
	chQuote  = byte(0x22) // "
	chSlash  = byte(0x5c) // backslash
	chTab    = byte(0x09)
	chLF     = byte(0x0a)
	chCR     = byte(0x0d)
	chSpace  = byte(0x20)
	chHash   = byte(0x23) // #
	chSlashF = byte(0x2f) // /
)

// Map is a parsed HOCON object. Values are: map[string]any, []any, string,
// int64, bool or nil (HOCON null).
type Map = map[string]any

// ParseFile parses a HOCON document (the .conf files shipped in
// assets/profiles). Supported: # and // comments, nested objects, arrays
// without commas, quoted and bare scalars, ints (decimal/hex), booleans,
// null, include "file" and dollar-brace substitutions.
func ParseFile(path string) (Map, error) {
	seen := map[string]bool{}
	return parseFile(path, seen)
}

func parseFile(path string, seen map[string]bool) (Map, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if seen[abs] {
		return nil, fmt.Errorf("hocon: include cycle at %s", abs)
	}
	seen[abs] = true
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	p := &parser{src: string(data), dir: filepath.Dir(abs)}
	m, err := p.parseObject(false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	for _, inc := range p.includes {
		mergeUnder(m, inc) // local document wins
	}
	substitute(m, m, 0)
	return m, nil
}

// ParseString parses a HOCON document held in memory.
func ParseString(src string) (Map, error) {
	p := &parser{src: src}
	return p.parseObject(false)
}

func mergeUnder(dst, src Map) {
	for k, v := range src {
		cur, ok := dst[k]
		if !ok {
			dst[k] = v
			continue
		}
		cm, cok := cur.(Map)
		sm, sok := v.(Map)
		if cok && sok {
			mergeUnder(cm, sm)
		}
	}
}

func substitute(root, m Map, depth int) {
	if depth > 16 {
		return
	}
	open := string([]byte{0x24, 0x7b}) // dollar + {
	for k, v := range m {
		switch t := v.(type) {
		case string:
			if strings.HasPrefix(t, open) && strings.HasSuffix(t, "}") {
				path := strings.TrimSuffix(strings.TrimPrefix(t, open), "}")
				if got, ok := Get(root, path); ok {
					m[k] = got
				}
			}
		case Map:
			substitute(root, t, depth+1)
		case []any:
			for _, e := range t {
				if em, ok := e.(Map); ok {
					substitute(root, em, depth+1)
				}
			}
		}
	}
}

type parser struct {
	src      string
	i        int
	dir      string
	includes []Map
}

func (p *parser) eof() bool { return p.i >= len(p.src) }

func (p *parser) skipSpace() {
	for !p.eof() {
		c := p.src[p.i]
		switch {
		case c == chSpace || c == chTab || c == chCR || c == chLF || c == ',':
			p.i++
		case c == chHash:
			for !p.eof() && p.src[p.i] != chLF {
				p.i++
			}
		case c == chSlashF && p.i+1 < len(p.src) && p.src[p.i+1] == chSlashF:
			for !p.eof() && p.src[p.i] != chLF {
				p.i++
			}
		default:
			return
		}
	}
}

func (p *parser) parseObject(nested bool) (Map, error) {
	m := Map{}
	for {
		p.skipSpace()
		if p.eof() {
			if nested {
				return nil, fmt.Errorf("unexpected EOF, missing closing brace")
			}
			return m, nil
		}
		if p.src[p.i] == '}' {
			if !nested {
				return nil, fmt.Errorf("unexpected closing brace at offset %d", p.i)
			}
			p.i++
			return m, nil
		}
		if strings.HasPrefix(p.src[p.i:], "include") {
			save := p.i
			p.i += len("include")
			p.skipSpace()
			if !p.eof() && p.src[p.i] == chQuote {
				name := p.readQuoted()
				inc, err := ParseFile(filepath.Join(p.dir, name))
				if err != nil {
					return nil, err
				}
				p.includes = append(p.includes, inc)
				continue
			}
			p.i = save
		}
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if !p.eof() && (p.src[p.i] == '=' || p.src[p.i] == ':') {
			p.i++
		}
		p.skipSpace()
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		assign(m, key, val)
	}
}

func assign(m Map, key string, val any) {
	if cur, ok := m[key]; ok {
		if cm, cok := cur.(Map); cok {
			if vm, vok := val.(Map); vok {
				mergeUnder(cm, vm)
				return
			}
		}
	}
	m[key] = val
}

func (p *parser) parseKey() (string, error) {
	if p.eof() {
		return "", fmt.Errorf("unexpected EOF while reading key")
	}
	if p.src[p.i] == chQuote {
		return p.readQuoted(), nil
	}
	start := p.i
	for !p.eof() {
		c := p.src[p.i]
		if c == chSpace || c == chTab || c == chCR || c == chLF || c == '=' || c == ':' ||
			c == '{' || c == '}' || c == ',' || c == chHash {
			break
		}
		p.i++
	}
	if start == p.i {
		return "", fmt.Errorf("empty key at offset %d", p.i)
	}
	return p.src[start:p.i], nil
}

func (p *parser) readQuoted() string {
	p.i++ // opening quote
	var sb strings.Builder
	for !p.eof() {
		c := p.src[p.i]
		if c == chSlash {
			p.i++
			if p.eof() {
				break
			}
			switch p.src[p.i] {
			case 'n':
				sb.WriteByte(chLF)
			case 't':
				sb.WriteByte(chTab)
			case 'r':
				sb.WriteByte(chCR)
			default:
				sb.WriteByte(p.src[p.i])
			}
			p.i++
			continue
		}
		p.i++
		if c == chQuote {
			break
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func (p *parser) parseValue() (any, error) {
	if p.eof() {
		return nil, fmt.Errorf("unexpected EOF while reading value")
	}
	switch p.src[p.i] {
	case '{':
		p.i++
		return p.parseObject(true)
	case '[':
		p.i++
		return p.parseArray()
	case chQuote:
		return p.readQuoted(), nil
	}
	start := p.i
	for !p.eof() {
		c := p.src[p.i]
		if c == chLF || c == chCR || c == ',' || c == '}' || c == ']' || c == chHash {
			break
		}
		if c == chSlashF && p.i+1 < len(p.src) && p.src[p.i+1] == chSlashF {
			break
		}
		p.i++
	}
	return scalar(strings.TrimSpace(p.src[start:p.i])), nil
}

func (p *parser) parseArray() ([]any, error) {
	out := []any{}
	for {
		p.skipSpace()
		if p.eof() {
			return nil, fmt.Errorf("unexpected EOF in array")
		}
		if p.src[p.i] == ']' {
			p.i++
			return out, nil
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

func scalar(tok string) any {
	switch tok {
	case "", "null":
		return nil
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := parseInt(tok); err == nil {
		return n
	}
	return tok
}

func parseInt(tok string) (int64, error) {
	s := tok
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	var (
		v   int64
		err error
	)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err = strconv.ParseInt(s[2:], 16, 64)
	} else {
		v, err = strconv.ParseInt(s, 10, 64)
	}
	if err != nil {
		return 0, err
	}
	if neg {
		v = -v
	}
	return v, nil
}

// Get resolves a HOCON path expression. A literal dotted key wins over nesting,
// which matches the resolver in the original app.
func Get(m Map, path string) (any, bool) {
	if v, ok := m[path]; ok {
		return v, true
	}
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			head, rest := path[:i], path[i+1:]
			sub, ok := m[head]
			if !ok {
				return nil, false
			}
			sm, ok := sub.(Map)
			if !ok {
				return nil, false
			}
			return Get(sm, rest)
		}
	}
	return nil, false
}

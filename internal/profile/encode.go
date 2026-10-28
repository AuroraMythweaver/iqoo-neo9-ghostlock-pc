package profile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

// Magic and version of the profile blob consumed by libghostlock.so.
const (
	Magic      uint32 = 218105633 // 0x0D000721
	Version    uint16 = 2
	HeaderSize        = 16
)

// Encode serialises the profile into the binary form the native binary reads
// from --load-prebuilt-profile. The layout was recovered from the app's
// writer and confirmed against the native parser:
//
//	u32 magic, u16 version, u16 frontend, u16 backend, u16 route,
//	u16 releaseLen, u16 reserved, release bytes,
//	u16 sectionCount, per section: u8 nameLen + name, u32 entryCount,
//	per entry: u8 keyLen + key, i64 value
func (p *Profile) Encode() ([]byte, error) {
	if len(p.Release) > 0xFFFF {
		return nil, fmt.Errorf("profile: release string too long")
	}
	buf := new(bytes.Buffer)
	var scratch [8]byte
	put16 := func(v uint16) { binary.LittleEndian.PutUint16(scratch[:2], v); buf.Write(scratch[:2]) }
	put32 := func(v uint32) { binary.LittleEndian.PutUint32(scratch[:4], v); buf.Write(scratch[:4]) }
	put64 := func(v int64) { binary.LittleEndian.PutUint64(scratch[:8], uint64(v)); buf.Write(scratch[:8]) }

	put32(Magic)
	put16(Version)
	put16(1) // frontend: 1 = root_child
	put16(1) // backend:  1 = cve_2026_43499
	put16(uint16(p.RouteIdx))
	put16(uint16(len(p.Release)))
	put16(0)
	buf.WriteString(p.Release)
	put16(uint16(len(p.Sections)))
	for _, s := range p.Sections {
		if len(s.Name) > 0xFF {
			return nil, fmt.Errorf("profile: section name too long: %s", s.Name)
		}
		buf.WriteByte(byte(len(s.Name)))
		buf.WriteString(s.Name)
		put32(uint32(len(s.Entries)))
		for _, e := range s.Entries {
			if len(e.Key) > 0xFF {
				return nil, fmt.Errorf("profile: key too long: %s", e.Key)
			}
			buf.WriteByte(byte(len(e.Key)))
			buf.WriteString(e.Key)
			put64(e.Val)
		}
	}
	return buf.Bytes(), nil
}

// WriteFile encodes and stores the profile at path.
func (p *Profile) WriteFile(path string) error {
	data, err := p.Encode()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Decode reads a profile blob with the same rules as the native parser. It is
// used by the self-test to prove a generated blob is byte-compatible.
type Decoded struct {
	Frontend, Backend, Route uint16
	Release                  string
	Sections                 []Section
}

func Decode(data []byte) (*Decoded, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("profile: blob shorter than %d bytes", HeaderSize)
	}
	if binary.LittleEndian.Uint32(data[0:]) != Magic {
		return nil, fmt.Errorf("profile: bad magic")
	}
	if binary.LittleEndian.Uint16(data[4:]) != Version {
		return nil, fmt.Errorf("profile: unsupported version")
	}
	d := &Decoded{
		Frontend: binary.LittleEndian.Uint16(data[6:]),
		Backend:  binary.LittleEndian.Uint16(data[8:]),
		Route:    binary.LittleEndian.Uint16(data[10:]),
	}
	relLen := int(binary.LittleEndian.Uint16(data[12:]))
	if HeaderSize+relLen+2 > len(data) {
		return nil, fmt.Errorf("profile: truncated release string")
	}
	d.Release = string(data[HeaderSize : HeaderSize+relLen])
	off := HeaderSize + relLen
	count := int(binary.LittleEndian.Uint16(data[off:]))
	off += 2
	for i := 0; i < count; i++ {
		if off+1 > len(data) {
			return nil, fmt.Errorf("profile: truncated section name")
		}
		n := int(data[off])
		off++
		if off+n+4 > len(data) {
			return nil, fmt.Errorf("profile: truncated section header")
		}
		name := string(data[off : off+n])
		off += n
		entries := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		sec := Section{Name: name}
		for j := 0; j < entries; j++ {
			if off+1 > len(data) {
				return nil, fmt.Errorf("profile: truncated key")
			}
			kn := int(data[off])
			off++
			if off+kn+8 > len(data) {
				return nil, fmt.Errorf("profile: truncated entry")
			}
			key := string(data[off : off+kn])
			off += kn
			val := int64(binary.LittleEndian.Uint64(data[off:]))
			off += 8
			sec.Entries = append(sec.Entries, KV{key, val})
		}
		d.Sections = append(d.Sections, sec)
	}
	return d, nil
}

// Get returns a section entry.
func (d *Decoded) Get(section, key string) (int64, bool) {
	for _, s := range d.Sections {
		if s.Name != section {
			continue
		}
		for _, e := range s.Entries {
			if e.Key == key {
				return e.Val, true
			}
		}
	}
	return 0, false
}

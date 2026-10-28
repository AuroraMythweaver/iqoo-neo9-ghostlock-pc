package manager

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// APKPackage reads android:package straight out of the binary
// AndroidManifest.xml. Needed because official SukiSU release builds ship under
// a randomised package name (e.g. rqglxo.qzizju.uholjr) that differs on every
// build, so any hardcoded package list is useless for upgrades.
func APKPackage(apkPath string) (string, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return "", fmt.Errorf("打开 APK 失败: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "AndroidManifest.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		data, err := io.ReadAll(io.LimitReader(rc, 16<<20))
		rc.Close()
		if err != nil {
			return "", err
		}
		return axmlPackage(data)
	}
	return "", fmt.Errorf("APK 里没有 AndroidManifest.xml")
}

func axmlPackage(d []byte) (string, error) {
	if len(d) < 8 || binary.LittleEndian.Uint16(d[0:]) != 0x0003 {
		return "", fmt.Errorf("不是 binary XML")
	}
	var strs []string
	off := 8
	for off+8 <= len(d) {
		typ := binary.LittleEndian.Uint16(d[off:])
		size := int(binary.LittleEndian.Uint32(d[off+4:]))
		if size < 8 || off+size > len(d) {
			break
		}
		switch typ {
		case 0x0001:
			strs = axmlStringPool(d[off : off+size])
		case 0x0102:
			if len(strs) > 0 {
				if p := axmlElementPackage(d[off:off+size], strs); p != "" {
					return p, nil
				}
			}
		}
		off += size
	}
	return "", fmt.Errorf("没找到 package 属性")
}

func axmlStringPool(c []byte) []string {
	if len(c) < 28 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(c[8:]))
	flags := binary.LittleEndian.Uint32(c[16:])
	stringsStart := int(binary.LittleEndian.Uint32(c[20:]))
	utf8 := flags&0x100 != 0
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		p := 28 + i*4
		if p+4 > len(c) {
			break
		}
		so := stringsStart + int(binary.LittleEndian.Uint32(c[p:]))
		if so >= len(c) {
			out = append(out, "")
			continue
		}
		out = append(out, axmlStr(c[so:], utf8))
	}
	return out
}

func axmlStr(b []byte, utf8 bool) string {
	if utf8 {
		// length in UTF-16 units, then byte length (both 1-2 bytes)
		i := 0
		_, n := axmlLen(b, i)
		i += n
		blen, n2 := axmlLen(b, i)
		i += n2
		if i+blen > len(b) {
			return ""
		}
		return string(b[i : i+blen])
	}
	if len(b) < 2 {
		return ""
	}
	l := int(binary.LittleEndian.Uint16(b))
	if l == 0 {
		return ""
	}
	if 2+l*2 > len(b) {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < l; i++ {
		r := rune(binary.LittleEndian.Uint16(b[2+i*2:]))
		sb.WriteRune(r)
	}
	return sb.String()
}

func axmlLen(b []byte, i int) (val, consumed int) {
	if i >= len(b) {
		return 0, 0
	}
	v := int(b[i])
	if v&0x80 != 0 && i+1 < len(b) {
		return ((v & 0x7f) << 8) | int(b[i+1]), 2
	}
	return v, 1
}

func axmlElementPackage(c []byte, strs []string) string {
	if len(c) < 36 {
		return ""
	}
	nameIdx := int(binary.LittleEndian.Uint32(c[20:]))
	if nameIdx < 0 || nameIdx >= len(strs) || strs[nameIdx] != "manifest" {
		return ""
	}
	attrStart := int(binary.LittleEndian.Uint16(c[24:]))
	attrCount := int(binary.LittleEndian.Uint16(c[28:]))
	// attributeStart is relative to ResXMLTree_attrExt (after the 16-byte node)
	base := 16 + attrStart
	for i := 0; i < attrCount; i++ {
		a := base + i*20
		if a+20 > len(c) {
			break
		}
		nIdx := int(binary.LittleEndian.Uint32(c[a+4:]))
		if nIdx < 0 || nIdx >= len(strs) || strs[nIdx] != "package" {
			continue
		}
		dataType := c[a+15]
		data := int(binary.LittleEndian.Uint32(c[a+16:]))
		if dataType == 0x03 && data >= 0 && data < len(strs) {
			return strs[data]
		}
		raw := int(binary.LittleEndian.Uint32(c[a+8:]))
		if raw >= 0 && raw < len(strs) {
			return strs[raw]
		}
	}
	return ""
}

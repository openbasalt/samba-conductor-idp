package branding

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"image"
	_ "image/jpeg" // image.DecodeConfig for JPEG
	_ "image/png"  // image.DecodeConfig for PNG
	"slices"
	"strings"
)

// Image types.
const (
	TypePNG  = "image/png"
	TypeJPEG = "image/jpeg"
	TypeWebP = "image/webp"
	TypeICO  = "image/x-icon"
)

type limit struct {
	bytes int
	dim   int
	types []string
}

// limits per slot: size, largest side in pixels, accepted types. SVG is
// refused everywhere: it is a document that can carry scripts and links,
// and no sanitizer is shipped (decisions in the docs).
var limits = map[string]limit{
	SlotLogoLight:  {256 << 10, 2048, []string{TypePNG, TypeJPEG, TypeWebP}},
	SlotLogoDark:   {256 << 10, 2048, []string{TypePNG, TypeJPEG, TypeWebP}},
	SlotFavicon:    {64 << 10, 256, []string{TypePNG, TypeICO}},
	SlotBackground: {1 << 20, 4096, []string{TypePNG, TypeJPEG, TypeWebP}},
}

// MaxAssetBytes is the largest image of any slot.
const MaxAssetBytes = 1 << 20

// MaxBytes returns the size limit of a slot (0 for an unknown slot).
func MaxBytes(slot string) int { return limits[slot].bytes }

// Types returns the accepted types of a slot.
func Types(slot string) []string { return slices.Clone(limits[slot].types) }

// SlotError is an image refused for a slot; Code is a Problem code.
type SlotError struct {
	Slot, Code, Arg string
}

func (e *SlotError) Error() string { return "branding: " + e.Slot + ": " + e.Code }

// Problem returns the error as a Problem.
func (e *SlotError) Problem() Problem { return Problem{Field: e.Slot, Code: e.Code, Arg: e.Arg} }

// Digest is the hex SHA-256 of data.
func Digest(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// Inspect checks an uploaded image for a slot by its content (never by
// its name or the browser's type) and describes it.
func Inspect(slot string, data []byte) (Asset, error) {
	lim, ok := limits[slot]
	if !ok {
		return Asset{}, &SlotError{Slot: slot, Code: CodeSlot}
	}
	if len(data) == 0 {
		return Asset{}, &SlotError{Slot: slot, Code: CodeImageCorrupt}
	}
	if len(data) > lim.bytes {
		return Asset{}, &SlotError{Slot: slot, Code: CodeImageSize, Arg: kib(lim.bytes)}
	}
	if looksLikeSVG(data) {
		return Asset{}, &SlotError{Slot: slot, Code: CodeSVG}
	}
	typ, w, h, ok := sniff(data)
	if typ == "" || !slices.Contains(lim.types, typ) {
		return Asset{}, &SlotError{Slot: slot, Code: CodeImageType, Arg: strings.Join(shortTypes(lim.types), ", ")}
	}
	if !ok || w <= 0 || h <= 0 {
		return Asset{}, &SlotError{Slot: slot, Code: CodeImageCorrupt}
	}
	if w > lim.dim || h > lim.dim {
		return Asset{}, &SlotError{Slot: slot, Code: CodeImageDims, Arg: itoa(lim.dim)}
	}
	return Asset{SHA256: Digest(data), Type: typ, Size: len(data), Width: w, Height: h}, nil
}

func kib(n int) string { return itoa(n>>10) + " KiB" }

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func shortTypes(ts []string) []string {
	var out []string
	for _, t := range ts {
		switch t {
		case TypePNG:
			out = append(out, "PNG")
		case TypeJPEG:
			out = append(out, "JPEG")
		case TypeWebP:
			out = append(out, "WebP")
		case TypeICO:
			out = append(out, "ICO")
		}
	}
	return out
}

// looksLikeSVG spots an XML or SVG document (with or without a byte order
// mark or leading white space).
func looksLikeSVG(data []byte) bool {
	head := data[:min(len(data), 512)]
	head = bytes.TrimPrefix(head, []byte("\xef\xbb\xbf"))
	head = bytes.ToLower(bytes.TrimLeft(head, " \t\r\n"))
	return bytes.HasPrefix(head, []byte("<?xml")) || bytes.HasPrefix(head, []byte("<svg")) ||
		bytes.HasPrefix(head, []byte("<!doctype")) || bytes.Contains(head, []byte("<svg"))
}

// sniff identifies the type by magic bytes and reads the dimensions from
// the header only (nothing is decoded).
func sniff(data []byte) (typ string, w, h int, ok bool) {
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		c, _, err := image.DecodeConfig(bytes.NewReader(data))
		return TypePNG, c.Width, c.Height, err == nil
	case bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}):
		c, _, err := image.DecodeConfig(bytes.NewReader(data))
		return TypeJPEG, c.Width, c.Height, err == nil
	case len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		w, h, ok := webpSize(data)
		return TypeWebP, w, h, ok
	case len(data) >= 6 && bytes.Equal(data[0:4], []byte{0, 0, 1, 0}):
		w, h, ok := icoSize(data)
		return TypeICO, w, h, ok
	}
	return "", 0, 0, false
}

// webpSize reads the canvas size of a WebP file (VP8, VP8L or VP8X).
func webpSize(d []byte) (int, int, bool) {
	if len(d) < 30 {
		return 0, 0, false
	}
	if riff := int(binary.LittleEndian.Uint32(d[4:8])); riff+8 > len(d) || riff < 4 {
		return 0, 0, false
	}
	switch string(d[12:16]) {
	case "VP8X":
		w := 1 + (int(d[24]) | int(d[25])<<8 | int(d[26])<<16)
		h := 1 + (int(d[27]) | int(d[28])<<8 | int(d[29])<<16)
		return w, h, true
	case "VP8L":
		if d[20] != 0x2f {
			return 0, 0, false
		}
		bits := binary.LittleEndian.Uint32(d[21:25])
		return int(bits&0x3fff) + 1, int(bits>>14&0x3fff) + 1, true
	case "VP8 ":
		// Frame tag (3 bytes) then the start code 9d 01 2a.
		if d[23] != 0x9d || d[24] != 0x01 || d[25] != 0x2a {
			return 0, 0, false
		}
		w := int(binary.LittleEndian.Uint16(d[26:28]) & 0x3fff)
		h := int(binary.LittleEndian.Uint16(d[28:30]) & 0x3fff)
		return w, h, true
	}
	return 0, 0, false
}

// icoSize checks an ICO directory and returns the largest image's size.
func icoSize(d []byte) (int, int, bool) {
	n := int(binary.LittleEndian.Uint16(d[4:6]))
	if n < 1 || n > 32 || len(d) < 6+16*n {
		return 0, 0, false
	}
	w, h := 0, 0
	for i := 0; i < n; i++ {
		e := d[6+16*i:]
		ew, eh := int(e[0]), int(e[1])
		if ew == 0 {
			ew = 256
		}
		if eh == 0 {
			eh = 256
		}
		size := int(binary.LittleEndian.Uint32(e[8:12]))
		off := int(binary.LittleEndian.Uint32(e[12:16]))
		if size <= 0 || off < 6+16*n || off > len(d) || size > len(d)-off {
			return 0, 0, false
		}
		w, h = max(w, ew), max(h, eh)
	}
	return w, h, true
}

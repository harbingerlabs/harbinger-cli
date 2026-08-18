// Package adexplorer reads Sysinternals AD Explorer snapshot (.dat) files
// natively, with no Python and no third-party converter.
//
// WHY THIS EXISTS: SharpHound is flagged by essentially every EDR, because
// attackers use it. An MSP admin running SharpHound on their own or a client's
// network sets off their own alerts. AD Explorer is a Microsoft-signed
// Sysinternals tool that is already trusted and already in the toolkit, and
// taking a snapshot with it looks like what it is: an admin browsing LDAP.
//
// A snapshot is an LDAP dump, so it carries principals, group membership,
// delegation, SID history, and — crucially — nTSecurityDescriptor, which is
// where the ACL attack edges live. It does NOT carry sessions or local group
// membership (those need SMB/remote collection), so a snapshot-derived graph is
// deliberately reported as a PARTIAL collection.
//
// PRIVACY: this package only ever reads a local file. It opens no network
// connections and holds no credentials.
//
// Format reference: the on-disk layout is documented by c3c/ADExplorerSnapshot.py
// (MIT). No code from that project is used here; only the structure definitions
// were consulted. See docs/ADEXPLORER.md.
package adexplorer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

// headerSize is where the object records begin (0x43E).
const headerSize = 0x43E

// sig is the 10-byte file signature.
const sig = "win-ad-obj"

// Guardrails. A snapshot is untrusted input: a corrupt or hostile file must
// produce an error, never a panic and never an unbounded allocation.
const (
	maxStringBytes = 1 << 20 // 1 MiB per single string value
	maxValues      = 1 << 20 // per multi-valued attribute
	maxTableSize   = 1 << 20 // mapping-table entries per object
	maxObjectSize  = 1 << 28 // 256 MiB for one object record
	maxProperties  = 1 << 20 // entries in the global attribute table
	maxOctet       = 1 << 24 // 16 MiB per octet-string value
)

// ADS types (iads.h ADSTYPEENUM). Only the ones a snapshot actually uses.
const (
	adsInvalid            = 0
	adsDNString           = 1
	adsCaseExactString    = 2
	adsCaseIgnoreString   = 3
	adsPrintableString    = 4
	adsNumericString      = 5
	adsBoolean            = 6
	adsInteger            = 7
	adsOctetString        = 8
	adsUTCTime            = 9
	adsLargeInteger       = 10
	adsObjectClass        = 12
	adsNTSecurityDescript = 25
)

// Property is one entry in the snapshot's global attribute table.
type Property struct {
	Name    string
	AdsType uint32
	DN      string
}

// Snapshot is an opened AD Explorer .dat file. Object bodies are read lazily so
// that a multi-gigabyte snapshot of a large directory does not have to fit in
// memory.
type Snapshot struct {
	f    *os.File
	size int64

	Server      string
	Description string
	Taken       time.Time
	NumObjects  int
	NumAttrs    int

	metaOffset int64
	objOffsets []int64

	props     []Property
	propIndex map[string]int // lowercased attribute name -> index

	// window is the currently-loaded object record, served from memory. String
	// values may reference a *negative* offset into an earlier object, which
	// falls through to ReadAt.
	winStart int64
	winBuf   []byte

	// Warnings collects non-fatal recoveries (skipped attribute, odd type).
	// Surfaced to the user; never transmitted.
	Warnings []string
}

func (s *Snapshot) warn(format string, a ...any) {
	if len(s.Warnings) < 200 { // bound the diagnostic, not the parse
		s.Warnings = append(s.Warnings, fmt.Sprintf(format, a...))
	}
}

// ErrNotSnapshot means the file is not an AD Explorer snapshot. Callers use it
// to fall through to the JSON ingest path.
var ErrNotSnapshot = errors.New("not an AD Explorer snapshot")

// IsSnapshot reports whether path looks like an AD Explorer .dat snapshot, by
// signature rather than by file extension.
func IsSnapshot(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, len(sig))
	if _, err := io.ReadFull(f, buf); err != nil {
		return false
	}
	return string(buf) == sig
}

// Open parses the header, the object index, and the attribute table.
func Open(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot stat %q: %w", path, err)
	}
	s := &Snapshot{f: f, size: fi.Size(), propIndex: map[string]int{}}
	if err := s.parseHeader(); err != nil {
		f.Close()
		return nil, err
	}
	if err := s.parseObjectIndex(); err != nil {
		f.Close()
		return nil, err
	}
	if err := s.parseProperties(); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying file.
func (s *Snapshot) Close() error { return s.f.Close() }

func (s *Snapshot) parseHeader() error {
	if s.size < headerSize {
		return fmt.Errorf("%w: file is %d bytes, shorter than a %d-byte header", ErrNotSnapshot, s.size, headerSize)
	}
	b, err := s.readAt(0, headerSize)
	if err != nil {
		return err
	}
	c := &cur{b: b}
	if got := string(c.take(10)); got != sig {
		return fmt.Errorf("%w: signature is %q, expected %q", ErrNotSnapshot, printable(got), sig)
	}
	c.skip(4) // marker
	ft := c.u64()
	s.Description = trimNul(decodeUTF16(c.take(520)))
	s.Server = trimNul(decodeUTF16(c.take(520)))
	s.NumObjects = int(c.u32())
	s.NumAttrs = int(c.u32())
	s.metaOffset = int64(c.u64())
	c.u64() // treeview offset — unused
	if c.err != nil {
		return fmt.Errorf("truncated snapshot header: %w", c.err)
	}
	s.Taken = filetimeToTime(ft)

	if s.NumObjects < 0 || s.NumAttrs < 0 {
		return fmt.Errorf("snapshot header is corrupt (numObjects=%d numAttributes=%d)", s.NumObjects, s.NumAttrs)
	}
	if s.metaOffset < headerSize || s.metaOffset >= s.size {
		return fmt.Errorf("snapshot metadata offset %d is outside the file (size %d) — the file looks truncated or still being written", s.metaOffset, s.size)
	}
	return nil
}

// parseObjectIndex walks the object records once, recording each start offset.
// A snapshot that was truncated mid-write (an MSP cancelling AD Explorer, a
// half-copied file) stops here with what it has and a warning, rather than
// failing the whole run.
func (s *Snapshot) parseObjectIndex() error {
	off := int64(headerSize)
	s.objOffsets = make([]int64, 0, min(s.NumObjects, 1<<20))
	for i := 0; i < s.NumObjects; i++ {
		if off+8 > s.metaOffset {
			s.warn("object index stops at %d of %d objects: the object section ends early (snapshot truncated?)", i, s.NumObjects)
			break
		}
		b, err := s.readAt(off, 4)
		if err != nil {
			s.warn("object index stops at %d of %d objects: %v", i, s.NumObjects, err)
			break
		}
		objSize := int64(binary.LittleEndian.Uint32(b))
		if objSize < 8 || objSize > maxObjectSize || off+objSize > s.size {
			s.warn("object %d declares an implausible size (%d bytes) — stopping the index here", i, objSize)
			break
		}
		s.objOffsets = append(s.objOffsets, off)
		off += objSize
	}
	if len(s.objOffsets) == 0 {
		return fmt.Errorf("snapshot contains no readable objects (header claims %d) — the file is empty or corrupt", s.NumObjects)
	}
	return nil
}

func (s *Snapshot) parseProperties() error {
	b, err := s.readAt(s.metaOffset, int(min64(s.size-s.metaOffset, 1<<26)))
	if err != nil {
		return fmt.Errorf("cannot read the snapshot attribute table: %w", err)
	}
	c := &cur{b: b}
	n := int(c.u32())
	if c.err != nil || n < 0 || n > maxProperties {
		return fmt.Errorf("snapshot attribute table is corrupt (claims %d attributes)", n)
	}
	s.props = make([]Property, 0, n)
	for i := 0; i < n; i++ {
		var p Property
		p.Name = trimNul(decodeUTF16(c.take(int(c.u32()))))
		c.skip(4) // unk1
		p.AdsType = c.u32()
		p.DN = trimNul(decodeUTF16(c.take(int(c.u32()))))
		c.skip(16 + 16 + 4) // schemaIDGUID, attributeSecurityGUID, blob
		if c.err != nil {
			s.warn("attribute table truncated after %d of %d entries", i, n)
			break
		}
		s.props = append(s.props, p)
		if lower := strings.ToLower(p.Name); lower != "" {
			if _, dup := s.propIndex[lower]; !dup {
				s.propIndex[lower] = len(s.props) - 1
			}
		}
	}
	if len(s.props) == 0 {
		return errors.New("snapshot has no attribute table — cannot interpret object data")
	}
	return nil
}

// ---- object access ----

// Object is one directory object, decoded on demand.
type Object struct {
	s     *Snapshot
	start int64
	entry []mapEntry
}

type mapEntry struct {
	attrIndex uint32
	attrOff   int32
}

// Len is the number of readable objects in the snapshot.
func (s *Snapshot) Len() int { return len(s.objOffsets) }

// Object loads the object record at index i and makes it the active window.
func (s *Snapshot) Object(i int) (*Object, error) {
	if i < 0 || i >= len(s.objOffsets) {
		return nil, fmt.Errorf("object index %d out of range", i)
	}
	start := s.objOffsets[i]
	hdr, err := s.readAt(start, 8)
	if err != nil {
		return nil, err
	}
	objSize := int64(binary.LittleEndian.Uint32(hdr[0:4]))
	tableSize := int(binary.LittleEndian.Uint32(hdr[4:8]))
	if tableSize < 0 || tableSize > maxTableSize {
		return nil, fmt.Errorf("object %d has an implausible attribute count (%d)", i, tableSize)
	}
	if objSize < int64(8+tableSize*8) || start+objSize > s.size {
		return nil, fmt.Errorf("object %d is truncated (declares %d bytes)", i, objSize)
	}
	// Load the whole record so attribute reads are in-memory.
	body, err := s.readAt(start, int(objSize))
	if err != nil {
		return nil, err
	}
	s.winStart, s.winBuf = start, body

	o := &Object{s: s, start: start, entry: make([]mapEntry, 0, tableSize)}
	c := &cur{b: body, i: 8}
	for j := 0; j < tableSize; j++ {
		idx := c.u32()
		off := int32(c.u32())
		if c.err != nil {
			s.warn("object at %d: mapping table truncated after %d of %d entries", start, j, tableSize)
			break
		}
		o.entry = append(o.entry, mapEntry{attrIndex: idx, attrOff: off})
	}
	return o, nil
}

// Attr returns the decoded values of one attribute, or nil if absent. Lookup is
// case-insensitive, matching LDAP.
func (o *Object) Attr(name string) []Value {
	idx, ok := o.s.propIndex[strings.ToLower(name)]
	if !ok {
		return nil
	}
	for _, e := range o.entry {
		if int(e.attrIndex) == idx {
			return o.s.decode(o.s.props[idx], o.start, e.attrOff)
		}
	}
	return nil
}

// Str returns the first value of an attribute as a string, or "".
func (o *Object) Str(name string) string {
	for _, v := range o.Attr(name) {
		if v.Str != "" {
			return v.Str
		}
	}
	return ""
}

// Strs returns every string value of an attribute.
func (o *Object) Strs(name string) []string {
	vs := o.Attr(name)
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if v.Str != "" {
			out = append(out, v.Str)
		}
	}
	return out
}

// Int returns the first integer value of an attribute, and whether it existed.
func (o *Object) Int(name string) (int64, bool) {
	for _, v := range o.Attr(name) {
		if v.HasInt {
			return v.Int, true
		}
	}
	return 0, false
}

// Bytes returns the first raw value of an attribute (octet string / descriptor).
func (o *Object) Bytes(name string) []byte {
	for _, v := range o.Attr(name) {
		if len(v.Raw) > 0 {
			return v.Raw
		}
	}
	return nil
}

// Value is one decoded attribute value. Exactly one representation is populated
// depending on the attribute's ADS type.
type Value struct {
	Str    string
	Raw    []byte
	Int    int64
	HasInt bool
}

// decode reads one attribute's values. Every branch is bounds-checked; a value
// that cannot be decoded is skipped with a warning rather than aborting the run,
// because real 20-year-old directories contain attributes with surprising types.
func (s *Snapshot) decode(p Property, objStart int64, attrOff int32) []Value {
	base := objStart + int64(attrOff)
	if base < 0 || base+4 > s.size {
		s.warn("attribute %q points outside the file — skipped", p.Name)
		return nil
	}
	b, err := s.readAt(base, 4)
	if err != nil {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b))
	if n <= 0 || n > maxValues {
		if n > maxValues {
			s.warn("attribute %q declares %d values — skipped", p.Name, n)
		}
		return nil
	}

	switch p.AdsType {
	case adsDNString, adsCaseExactString, adsCaseIgnoreString, adsPrintableString, adsNumericString, adsObjectClass:
		return s.decodeStrings(p, base, n)
	case adsOctetString:
		return s.decodeOctets(p, base, n, false)
	case adsNTSecurityDescript:
		return s.decodeOctets(p, base, n, true)
	case adsBoolean, adsInteger:
		return s.decodeFixed(base, n, 4)
	case adsLargeInteger:
		return s.decodeFixed(base, n, 8)
	case adsUTCTime:
		return s.decodeSystemTime(base, n)
	case adsInvalid:
		return nil
	default:
		s.warn("attribute %q has unhandled ADS type %d — skipped", p.Name, p.AdsType)
		return nil
	}
}

func (s *Snapshot) decodeStrings(p Property, base int64, n int) []Value {
	offs, err := s.readAt(base+4, n*4)
	if err != nil {
		return nil
	}
	out := make([]Value, 0, n)
	for i := 0; i < n; i++ {
		// Signed: a value may live in an earlier object (negative offset).
		rel := int32(binary.LittleEndian.Uint32(offs[i*4 : i*4+4]))
		at := base + int64(rel)
		if at < 0 || at >= s.size {
			s.warn("attribute %q value %d points outside the file — skipped", p.Name, i)
			continue
		}
		str, err := s.wstrAt(at)
		if err != nil {
			s.warn("attribute %q value %d unreadable: %v", p.Name, i, err)
			continue
		}
		out = append(out, Value{Str: str})
	}
	return out
}

func (s *Snapshot) decodeOctets(p Property, base int64, n int, lengthPrefixed bool) []Value {
	out := make([]Value, 0, n)
	if lengthPrefixed {
		// NT security descriptors are stored as consecutive (uint32 len, bytes).
		at := base + 4
		for i := 0; i < n; i++ {
			lb, err := s.readAt(at, 4)
			if err != nil {
				return out
			}
			l := int(binary.LittleEndian.Uint32(lb))
			if l < 0 || l > maxOctet || at+4+int64(l) > s.size {
				s.warn("attribute %q value %d has an implausible length (%d) — skipped", p.Name, i, l)
				return out
			}
			raw, err := s.readAt(at+4, l)
			if err != nil {
				return out
			}
			out = append(out, Value{Raw: clone(raw)})
			at += 4 + int64(l)
		}
		return out
	}
	// Plain octet strings: all lengths first, then the values back to back.
	lens, err := s.readAt(base+4, n*4)
	if err != nil {
		return nil
	}
	at := base + 4 + int64(n*4)
	for i := 0; i < n; i++ {
		l := int(binary.LittleEndian.Uint32(lens[i*4 : i*4+4]))
		if l < 0 || l > maxOctet || at+int64(l) > s.size {
			s.warn("attribute %q value %d has an implausible length (%d) — skipped", p.Name, i, l)
			return out
		}
		raw, err := s.readAt(at, l)
		if err != nil {
			return out
		}
		out = append(out, Value{Raw: clone(raw)})
		at += int64(l)
	}
	return out
}

func (s *Snapshot) decodeFixed(base int64, n, width int) []Value {
	b, err := s.readAt(base+4, n*width)
	if err != nil {
		return nil
	}
	out := make([]Value, 0, n)
	for i := 0; i < n; i++ {
		var v int64
		if width == 4 {
			v = int64(binary.LittleEndian.Uint32(b[i*4 : i*4+4]))
		} else {
			v = int64(binary.LittleEndian.Uint64(b[i*8 : i*8+8]))
		}
		out = append(out, Value{Int: v, HasInt: true})
	}
	return out
}

func (s *Snapshot) decodeSystemTime(base int64, n int) []Value {
	b, err := s.readAt(base+4, n*16)
	if err != nil {
		return nil
	}
	out := make([]Value, 0, n)
	for i := 0; i < n; i++ {
		w := b[i*16 : i*16+16]
		g := func(j int) int { return int(binary.LittleEndian.Uint16(w[j*2 : j*2+2])) }
		yr, mo, dy := g(0), g(1), g(3)
		if yr < 1601 || mo < 1 || mo > 12 || dy < 1 || dy > 31 {
			out = append(out, Value{Int: 0, HasInt: true})
			continue
		}
		t := time.Date(yr, time.Month(mo), dy, g(4), g(5), g(6), 0, time.UTC)
		out = append(out, Value{Int: t.Unix(), HasInt: true})
	}
	return out
}

// ---- low-level IO ----

// readAt serves from the active object window when possible, else from the file.
func (s *Snapshot) readAt(off int64, n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative read length %d", n)
	}
	if n == 0 {
		return nil, nil
	}
	if off < 0 || off+int64(n) > s.size {
		return nil, fmt.Errorf("read of %d bytes at %d is past end of file (%d bytes)", n, off, s.size)
	}
	if s.winBuf != nil && off >= s.winStart && off+int64(n) <= s.winStart+int64(len(s.winBuf)) {
		lo := off - s.winStart
		return s.winBuf[lo : lo+int64(n)], nil
	}
	buf := make([]byte, n)
	if _, err := s.f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
}

// wstrAt reads a NUL-terminated UTF-16LE string, in chunks so that a corrupt
// file cannot make us allocate without bound.
func (s *Snapshot) wstrAt(off int64) (string, error) {
	var units []uint16
	const chunk = 256
	for {
		remain := s.size - off
		if remain <= 0 {
			return "", errors.New("string runs past end of file")
		}
		n := int(min64(chunk, remain))
		n -= n % 2
		if n == 0 {
			return "", errors.New("string runs past end of file")
		}
		b, err := s.readAt(off, n)
		if err != nil {
			return "", err
		}
		for i := 0; i+1 < len(b); i += 2 {
			u := binary.LittleEndian.Uint16(b[i : i+2])
			if u == 0 {
				return string(utf16.Decode(units)), nil
			}
			units = append(units, u)
		}
		off += int64(n)
		if len(units)*2 > maxStringBytes {
			return "", fmt.Errorf("unterminated string longer than %d bytes", maxStringBytes)
		}
	}
}

// cur is a bounds-checked forward cursor over an in-memory buffer. Once it
// overruns it latches an error and every later read is a no-op, so callers can
// parse a whole struct and check once.
type cur struct {
	b   []byte
	i   int
	err error
}

func (c *cur) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || c.i+n > len(c.b) {
		c.err = fmt.Errorf("wanted %d bytes at offset %d, buffer holds %d", n, c.i, len(c.b))
		return nil
	}
	out := c.b[c.i : c.i+n]
	c.i += n
	return out
}
func (c *cur) skip(n int) { c.take(n) }
func (c *cur) u32() uint32 {
	b := c.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}
func (c *cur) u64() uint64 {
	b := c.take(8)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

// ---- small helpers ----

func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(units))
}

func trimNul(s string) string { return strings.TrimRight(s, "\x00") }

func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// filetimeToTime converts a Windows FILETIME (100ns ticks since 1601-01-01).
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksToUnix = 116444736000000000
	if ft < ticksToUnix {
		return time.Time{}
	}
	return time.Unix(int64(ft-ticksToUnix)/1e7, 0).UTC()
}

func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

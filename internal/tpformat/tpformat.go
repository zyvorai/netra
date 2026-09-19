// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package tpformat parses a tracepoint's ftrace `format` file
// (/sys/kernel/tracing/events/<group>/<name>/format) into field offsets.
//
// Why it exists: a classic tracepoint hands a BPF program a raw record whose
// layout is defined by the kernel that built it, and it changes between
// versions and even between sibling tracepoints of one kernel (on Linux 6.8,
// tcp_send_reset carries skbaddr and state so its `sport` is at offset 28,
// while tcp_receive_reset carries neither so its `sport` is at offset 16).
// Without BTF/CO-RE a hard-coded struct silently misreads on some kernel.
// Instead the agent reads the running kernel's own description of the record
// and patches those offsets into the program's read-only data before loading.
package tpformat

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// maxRecord bounds any plausible tracepoint record; ftrace itself caps events
// well below this. A larger offset is corrupt input, not a real field.
const maxRecord = 65535

// Field is one member of a tracepoint record.
type Field struct {
	Name   string
	Type   string // C type as printed, e.g. "__u16", "const void *", "__u8"
	Offset int
	Size   int // total size in bytes (whole array for array fields)
	Signed bool
	// ArrayLen is the element count for `type name[N]` fields, else 0.
	ArrayLen int
}

// Format is a parsed tracepoint description.
type Format struct {
	Name   string
	Fields map[string]Field
}

// Parse reads the text of a format file. Unrecognised lines (ID, print fmt)
// are ignored; a `field:` line that cannot be understood is an error, since a
// silently skipped field would become a wrong offset.
func Parse(text string) (*Format, error) {
	f := &Format{Fields: map[string]Field{}}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "name:"):
			f.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		case strings.HasPrefix(line, "field:"):
			fld, err := parseField(line)
			if err != nil {
				return nil, fmt.Errorf("tracepoint %q: %w", f.Name, err)
			}
			if _, dup := f.Fields[fld.Name]; dup {
				return nil, fmt.Errorf("tracepoint %q: field %q appears twice", f.Name, fld.Name)
			}
			f.Fields[fld.Name] = fld
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(f.Fields) == 0 {
		return nil, errors.New("no fields found: not a tracepoint format")
	}
	return f, nil
}

// parseField reads `field:<decl>;	offset:N;	size:N;	signed:N;`.
func parseField(line string) (Field, error) {
	var out Field
	parts := strings.Split(line, ";")
	if len(parts) < 4 {
		return out, fmt.Errorf("malformed field line %q", line)
	}
	decl := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[0]), "field:"))
	if decl == "" {
		return out, fmt.Errorf("empty field declaration in %q", line)
	}
	attrs := map[string]int{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return out, fmt.Errorf("field %q: %s is not a number", decl, k)
		}
		attrs[strings.TrimSpace(k)] = n
	}
	for _, need := range []string{"offset", "size"} {
		if _, ok := attrs[need]; !ok {
			return out, fmt.Errorf("field %q has no %s", decl, need)
		}
	}
	out.Offset, out.Size, out.Signed = attrs["offset"], attrs["size"], attrs["signed"] == 1
	if out.Offset < 0 || out.Offset > maxRecord || out.Size < 0 || out.Size > maxRecord || out.Offset+out.Size > maxRecord {
		return out, fmt.Errorf("field %q has an implausible offset/size (%d/%d)", decl, out.Offset, out.Size)
	}

	// The name is the last identifier of the declaration: `__u8 saddr[4]`,
	// `const void * skbaddr`, `unsigned short common_type`, `__data_loc char[] name`.
	name := decl
	if i := strings.LastIndexAny(name, " \t*"); i >= 0 {
		name, out.Type = name[i+1:], strings.TrimSpace(name[:i+1])
	}
	if j := strings.Index(name, "["); j >= 0 {
		end := strings.Index(name, "]")
		if end < j {
			return out, fmt.Errorf("field %q has an unterminated array", decl)
		}
		if n, err := strconv.Atoi(name[j+1 : end]); err == nil {
			out.ArrayLen = n
		}
		name = name[:j]
	}
	if name == "" {
		return out, fmt.Errorf("field %q has no name", decl)
	}
	out.Name = name
	return out, nil
}

// Read loads and parses /sys/kernel/tracing/events/<group>/<name>/format,
// falling back to the debugfs mount older kernels use.
func Read(group, name string) (*Format, error) {
	var lastErr error
	for _, root := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		b, err := os.ReadFile(filepath.Join(root, "events", group, name, "format"))
		if err != nil {
			lastErr = err
			continue
		}
		return Parse(string(b))
	}
	return nil, fmt.Errorf("tracepoint %s:%s: %w", group, name, lastErr)
}

// Offset returns a field's offset, requiring it to exist and (when size > 0)
// to be exactly that many bytes. A field of the wrong size means the kernel
// changed its meaning, so the caller must not read it.
func (f *Format) Offset(name string, size int) (int, error) {
	fld, ok := f.Fields[name]
	if !ok {
		return 0, fmt.Errorf("tracepoint %q has no field %q", f.Name, name)
	}
	if size > 0 && fld.Size != size {
		return 0, fmt.Errorf("tracepoint %q field %q is %d bytes, expected %d", f.Name, name, fld.Size, size)
	}
	return fld.Offset, nil
}

// Has reports whether the field exists.
func (f *Format) Has(name string) bool { _, ok := f.Fields[name]; return ok }

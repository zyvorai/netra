// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
// Best-effort L7/DNS byte-level parsers shared by the Netra eBPF datapath
// and its host-side parser tests. These functions only ever look at bytes
// already proven in-bounds against data_end; they never reassemble TCP
// streams and only report what's visible in a single skb.

#ifndef NETRA_L7_H
#define NETRA_L7_H

#ifdef NETRA_BPF
#define NETRA_L7_UNROLL _Pragma("unroll")
#else
#define NETRA_L7_UNROLL
#endif

static __inline__ __attribute__((always_inline)) unsigned char
netra_l7_lower_ascii(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

static __inline__ __attribute__((always_inline)) int
netra_l7_hostname_char(unsigned char c)
{
    c = netra_l7_lower_ascii(c);
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

// dns_qname decodes a plain-DNS question name starting at the UDP payload
// (12-byte header, then the QNAME label sequence), lowercased, into out.
// Returns the decoded length, or 0 if no valid name could be read.
static __inline__ __attribute__((always_inline)) int
netra_l7_dns_qname(void *payload, void *data_end, char out[96])
{
    unsigned char *p = payload;
    if ((void *)(p + 12) > data_end) return 0;
    p += 12;
    int oi = 0, remaining = 0;
    NETRA_L7_UNROLL
    for (int i = 0; i < 96; i++) {
        if ((void *)(p + 1) > data_end || oi >= 95) break;
        unsigned char c = *p++;
        if (remaining == 0) {
            if (c == 0) break;
            if ((c & 0xc0) != 0 || c > 63) break;
            if (oi > 0) out[oi++] = '.';
            remaining = c;
        } else {
            if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
            out[oi++] = (char)c;
            remaining--;
        }
    }
    if (oi < 96) out[oi] = 0;
    return oi;
}

// tls_sni is a best-effort TLS ClientHello SNI parser. It intentionally
// does not reassemble TCP streams and therefore only reports an SNI
// present in this skb.
static __inline__ __attribute__((always_inline)) int
netra_l7_tls_sni(void *payload, void *data_end, char out[96])
{
    unsigned char *p = payload;
    if ((void *)(p + 9) > data_end || p[0] != 0x16 || p[5] != 0x01) return 0;
    for (int i = 43; i < 512; i++) {
        /* Need header bytes i..i+8 and up to 95 name bytes starting at i+9. */
        if ((void *)(p + i + 9 + 95) > data_end) break;
        if (p[i] != 0 || p[i + 1] != 0 || p[i + 6] != 0) continue;
        unsigned short ext_len = ((unsigned short)p[i + 2] << 8) | p[i + 3];
        unsigned short list_len = ((unsigned short)p[i + 4] << 8) | p[i + 5];
        unsigned short name_len = ((unsigned short)p[i + 7] << 8) | p[i + 8];
        if (!name_len || name_len > 95 || ext_len < (unsigned short)(5 + name_len) || list_len < (unsigned short)(3 + name_len)) continue;
        int ok = 1;
        for (int j = 0; j < 95; j++) {
            if (j >= name_len) break;
            unsigned char c = p[i + 9 + j];
            if (!netra_l7_hostname_char(c)) { ok = 0; break; }
            out[j] = (char)netra_l7_lower_ascii(c);
        }
        if (!ok) { __builtin_memset(out, 0, 96); continue; }
        out[name_len] = 0;
        return name_len;
    }
    return 0;
}

static __inline__ __attribute__((always_inline)) int
netra_l7_http_method(void *payload, void *data_end, char out[8])
{
    unsigned char *p = payload;
    if ((void *)(p + 8) > data_end) return 0;
    if (p[0]=='G'&&p[1]=='E'&&p[2]=='T'&&p[3]==' ') { __builtin_memcpy(out,"GET",4); return 3; }
    if (p[0]=='P'&&p[1]=='O'&&p[2]=='S'&&p[3]=='T'&&p[4]==' ') { __builtin_memcpy(out,"POST",5); return 4; }
    if (p[0]=='P'&&p[1]=='U'&&p[2]=='T'&&p[3]==' ') { __builtin_memcpy(out,"PUT",4); return 3; }
    if (p[0]=='H'&&p[1]=='E'&&p[2]=='A'&&p[3]=='D'&&p[4]==' ') { __builtin_memcpy(out,"HEAD",5); return 4; }
    if (p[0]=='P'&&p[1]=='A'&&p[2]=='T'&&p[3]=='C'&&p[4]=='H'&&p[5]==' ') { __builtin_memcpy(out,"PATCH",6); return 5; }
    if (p[0]=='D'&&p[1]=='E'&&p[2]=='L'&&p[3]=='E'&&p[4]=='T'&&p[5]=='E'&&p[6]==' ') { __builtin_memcpy(out,"DELETE",7); return 6; }
    if (p[0]=='O'&&p[1]=='P'&&p[2]=='T'&&p[3]=='I'&&p[4]=='O'&&p[5]=='N'&&p[6]=='S'&&p[7]==' ') { __builtin_memcpy(out,"OPTIONS",8); return 7; }
    return 0;
}

static __inline__ __attribute__((always_inline)) int
netra_l7_http_host(void *payload, void *data_end, char out[96])
{
    unsigned char *p = payload;
    for (int i = 0; i < 512; i++) {
        if ((void *)(p + i + 6) > data_end) break;
        if (i > 0 && p[i - 1] != '\n') continue;
        if (netra_l7_lower_ascii(p[i])!='h'||netra_l7_lower_ascii(p[i+1])!='o'||netra_l7_lower_ascii(p[i+2])!='s'||netra_l7_lower_ascii(p[i+3])!='t'||p[i+4]!=':') continue;
        int pos = i + 5;
        for (int s = 0; s < 8; s++) {
            if ((void *)(p + pos + 1) > data_end) return 0;
            if (p[pos] != ' ' && p[pos] != '\t') break;
            pos++;
        }
        int oi = 0;
        for (int j = 0; j < 95; j++) {
            if ((void *)(p + pos + 1) > data_end) break;
            unsigned char c = p[pos++];
            if (c == '\r' || c == '\n') break;
            if (c < 0x21 || c > 0x7e) return 0;
            out[oi++] = (char)netra_l7_lower_ascii(c);
        }
        if (oi > 0) { out[oi] = 0; return oi; }
    }
    return 0;
}

#endif // NETRA_L7_H

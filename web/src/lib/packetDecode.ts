// decodeL3L4 parses the Ethernet/IPv4/IPv6/TCP/UDP/ICMP headers that are
// already present in every buffered capture frame (frames start at the
// Ethernet header — see internal/capture/capture.go's Frame doc comment
// and Capture.tsx's decodeFrame). No L7 parsing: this covers what
// PROTOCOL_NAMES already tags (TCP/UDP/ICMP/ICMPv6), not HTTP/DNS/TLS.
export type DecodedHeaders = {
  srcIP: string;
  dstIP: string;
  srcPort?: number;
  dstPort?: number;
  tcpFlags?: string;
  icmpType?: number;
  summary: string;
};

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;

function ipv4ToString(data: Uint8Array, off: number): string {
  return `${data[off]}.${data[off + 1]}.${data[off + 2]}.${data[off + 3]}`;
}

function ipv6ToString(data: Uint8Array, off: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 8; i++) {
    groups.push((((data[off + i * 2] << 8) | data[off + i * 2 + 1]) >>> 0).toString(16));
  }
  return groups.join(':');
}

const TCP_FLAG_BITS: [number, string][] = [
  [0x01, 'FIN'], [0x02, 'SYN'], [0x04, 'RST'], [0x08, 'PSH'], [0x10, 'ACK'], [0x20, 'URG'],
];

function tcpFlagsToString(flags: number): string {
  const names = TCP_FLAG_BITS.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name);
  return names.length ? names.join(',') : '-';
}

export function decodeL3L4(data: Uint8Array): DecodedHeaders | null {
  if (data.length < 14) return null;
  const etherType = (data[12] << 8) | data[13];

  let srcIP: string, dstIP: string, ipProto: number, l4Off: number;
  if (etherType === ETHERTYPE_IPV4 && data.length >= 34) {
    const ihl = (data[14] & 0x0f) * 4;
    ipProto = data[14 + 9];
    srcIP = ipv4ToString(data, 14 + 12);
    dstIP = ipv4ToString(data, 14 + 16);
    l4Off = 14 + ihl;
  } else if (etherType === ETHERTYPE_IPV6 && data.length >= 54) {
    ipProto = data[14 + 6];
    srcIP = ipv6ToString(data, 14 + 8);
    dstIP = ipv6ToString(data, 14 + 24);
    l4Off = 14 + 40;
  } else {
    return null;
  }

  let srcPort: number | undefined, dstPort: number | undefined, tcpFlags: string | undefined, icmpType: number | undefined;
  if ((ipProto === 6 || ipProto === 17) && data.length >= l4Off + 4) {
    srcPort = (data[l4Off] << 8) | data[l4Off + 1];
    dstPort = (data[l4Off + 2] << 8) | data[l4Off + 3];
    if (ipProto === 6 && data.length >= l4Off + 14) tcpFlags = tcpFlagsToString(data[l4Off + 13]);
  } else if ((ipProto === 1 || ipProto === 58) && data.length >= l4Off + 2) {
    icmpType = data[l4Off];
  }

  const endpoint = srcPort !== undefined ? `${srcIP}:${srcPort} → ${dstIP}:${dstPort}` : `${srcIP} → ${dstIP}`;
  const summary = tcpFlags ? `${endpoint} [${tcpFlags}]` : endpoint;
  return { srcIP, dstIP, srcPort, dstPort, tcpFlags, icmpType, summary };
}

export function hexDump(data: Uint8Array, max = 64): string {
  return Array.from(data.slice(0, max)).map((b) => b.toString(16).padStart(2, '0')).join(' ');
}

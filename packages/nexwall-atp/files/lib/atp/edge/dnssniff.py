# Copyright (C) 2026 Nexwall
"""DNS view of the firewall for the scorer: reads the DNS packets of the inner interfaces (UDP/53) with an AF_PACKET socket and yields one record per query,
{'ts', 'src_ip', 'name', 'qtype', 'rcode'}, where the rcode comes from the matching reply (same client, port and transaction id). Read-only: it never sends anything.
Needs python3 only. Encrypted DNS (DoH, DoT) is not visible here, and the scorer says so in its status."""
import socket
import struct
import time

QTYPES = {1: 'A', 28: 'AAAA', 16: 'TXT', 15: 'MX', 5: 'CNAME', 2: 'NS', 12: 'PTR', 65: 'HTTPS'}
RCODES = {0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED'}
PENDING_SECONDS = 10.0
MAX_PENDING = 20000


def parse_name(data, pos):
    labels = []
    while pos < len(data) and data[pos]:
        if data[pos] & 0xC0:
            return None, pos
        n = data[pos]
        labels.append(data[pos + 1:pos + 1 + n].decode('ascii', 'replace').lower())
        pos += n + 1
    return '.'.join(labels), pos + 1


def parse_packet(frame):
    """Ethernet frame -> ('query'|'reply', client_ip, client_port, txid, name, qtype, rcode) or None."""
    if len(frame) < 14 + 20 + 8 + 12 or frame[12:14] != b'\x08\x00':
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[14 + 9] != 17:
        return None
    sip, dip = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])
    u = 14 + ihl
    sport, dport = struct.unpack('!HH', frame[u:u + 4])
    if 53 not in (sport, dport):
        return None
    d = frame[u + 8:]
    if len(d) < 12:
        return None
    txid, flags, qd = struct.unpack('!HHH', d[:6])
    if qd < 1:
        return None
    name, pos = parse_name(d, 12)
    if not name or pos + 4 > len(d):
        return None
    qtype = struct.unpack('!H', d[pos:pos + 2])[0]
    if flags & 0x8000:
        return ('reply', dip, dport, txid, name, QTYPES.get(qtype, str(qtype)), RCODES.get(flags & 0xF, 'RCODE%d' % (flags & 0xF)))
    return ('query', sip, sport, txid, name, QTYPES.get(qtype, str(qtype)), None)


def bpf_program():
    """Classic BPF: only IPv4 UDP packets (not fragments) with port 53 as source or destination reach the socket."""
    ins = [(0x28, 0, 0, 12), (0x15, 0, 9, 0x0800), (0x30, 0, 0, 23), (0x15, 0, 7, 17), (0x28, 0, 0, 20), (0x45, 5, 0, 0x1fff), (0xb1, 0, 0, 14),
           (0x48, 0, 0, 14), (0x15, 3, 0, 53), (0x48, 0, 0, 16), (0x15, 1, 0, 53), (0x06, 0, 0, 0), (0x06, 0, 0, 65535)]
    return b''.join(struct.pack('HBBI', c, jt, jf, k) for c, jt, jf, k in ins), len(ins)


class Matcher:
    """Pairs queries with replies; a query that is not answered in PENDING_SECONDS comes out as NOREPLY."""

    def __init__(self):
        self.pending = {}

    def feed(self, parsed, now):
        """-> a finished record or None."""
        if not parsed:
            return None
        kind, ip, port, txid, name, qtype, rcode = parsed
        key = (ip, port, txid, name)
        if kind == 'query':
            if len(self.pending) < MAX_PENDING:
                self.pending[key] = {'ts': now, 'src_ip': ip, 'name': name, 'qtype': qtype, 'rcode': 'NOREPLY'}
            return None
        rec = self.pending.pop(key, None)
        if rec:
            rec['rcode'] = rcode
        return rec

    def expire(self, now):
        out = []
        for key in [k for k, v in self.pending.items() if now - v['ts'] > PENDING_SECONDS]:
            out.append(self.pending.pop(key))
        return out


class Sniffer:
    def __init__(self, interfaces, clock=time.time):
        import select
        self._select = select
        self.clock = clock
        self.matcher = Matcher()
        self.socks = {}
        buf, fprog = None, None
        try:                                   # the kernel filter keeps a busy network cheap; without ctypes the sockets still work, only heavier
            import ctypes
            prog, n = bpf_program()
            buf = ctypes.create_string_buffer(prog)
            fprog = struct.pack('HL', n, ctypes.addressof(buf))
        except ImportError:
            pass
        for iface in interfaces:
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                s.bind((iface, 0))
                if fprog:
                    s.setsockopt(socket.SOL_SOCKET, 26, fprog)      # SO_ATTACH_FILTER
                s.setblocking(False)
                self.socks[iface] = s
            except OSError:
                continue
        self._keep = buf

    def interfaces(self):
        return sorted(self.socks)

    def poll(self, timeout=1.0, limit=2000):
        """Records finished since the last call."""
        out = []
        if self.socks:
            ready, _, _ = self._select.select(list(self.socks.values()), [], [], timeout)
            for s in ready:
                for _ in range(limit):
                    try:
                        frame = s.recv(2048)
                    except (BlockingIOError, OSError):
                        break
                    rec = self.matcher.feed(parse_packet(frame), self.clock())
                    if rec:
                        out.append(rec)
        else:
            time.sleep(timeout)
        out += self.matcher.expire(self.clock())
        return out

    def close(self):
        for s in self.socks.values():
            s.close()

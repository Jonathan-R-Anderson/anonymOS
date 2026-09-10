"""A small, dependency-free NNTP reader client (pull mode).

Implements just the reading subset of RFC 3977 needed to mirror an NNTPChan
peer: connect, MODE READER, LIST ACTIVE overchan.*, GROUP, OVER/XOVER (to list
Message-IDs cheaply) and ARTICLE (to fetch one). We deliberately do NOT
implement the streaming feed side (CHECK/TAKETHIS/IHAVE) — a leaf node only
needs to read, and NNTPChan nodes serve reading for newsreaders. stdlib
``nntplib`` was removed in Python 3.13, so this is hand-rolled over a socket;
under gevent the blocking socket calls cooperatively yield.
"""
import socket
import ssl
import os
import struct


class NNTPError(Exception):
    pass


class NNTPClient:
    def __init__(self, host, port=119, use_tls=False, timeout=30):
        self.host = host
        self.port = int(port or 119)
        self.use_tls = bool(use_tls)
        self.timeout = timeout
        self._sock = None
        self._fp = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_exc):
        self.close()

    def connect(self):
        # Two transports, chosen by the address itself so they cannot disagree.
        # An .i2p host goes through the SOCKS proxy, which is what keeps this
        # server's address hidden from the peer; anything else is a direct
        # connection, which does not. That difference is why the transport is
        # derived from the host rather than configured beside it — a peer whose
        # address says I2P can never be dialed in the clear by mistake.
        from services.i2p_addresses import is_i2p_host

        if is_i2p_host(self.host):
            raw = _i2p_socks_connect(self.host, self.port, self.timeout)
        else:
            try:
                raw = socket.create_connection((self.host, self.port), self.timeout)
            except OSError as exc:
                raise NNTPError("could not reach %s:%s — %s" % (self.host, self.port, exc))
        if self.use_tls:
            context = ssl.create_default_context()
            raw = context.wrap_socket(raw, server_hostname=self.host)
        self._sock = raw
        self._fp = raw.makefile("rb")
        code, line = self._status()
        if code not in (200, 201):
            raise NNTPError("unexpected greeting: %s" % line)
        # Posting-only servers and some feeds require switching to reader mode
        # before GROUP/ARTICLE work; ignore if unsupported.
        try:
            self._command("MODE READER")
        except NNTPError:
            pass

    def close(self):
        try:
            if self._sock is not None:
                self._command("QUIT")
        except Exception:
            pass
        for closeable in (self._fp, self._sock):
            try:
                if closeable is not None:
                    closeable.close()
            except Exception:
                pass
        self._fp = None
        self._sock = None

    # --- low level -------------------------------------------------------
    def _readline(self):
        line = self._fp.readline()
        if not line:
            raise NNTPError("connection closed by peer")
        return line

    def _status(self):
        line = self._readline()
        try:
            code = int(line[:3])
        except (ValueError, IndexError):
            raise NNTPError("malformed status line: %r" % line)
        return code, line.decode("latin-1", "replace").rstrip("\r\n")

    def _command(self, command, expect=None):
        self._sock.sendall(command.encode("utf-8", "replace") + b"\r\n")
        code, line = self._status()
        if expect is not None and code not in expect:
            raise NNTPError("%r -> %s" % (command, line))
        return code, line

    def _read_multiline(self):
        """Read a dot-terminated multiline block, undoing dot-stuffing."""
        lines = []
        while True:
            line = self._readline()
            if line in (b".\r\n", b".\n", b"."):
                break
            if line.startswith(b".."):
                line = line[1:]
            lines.append(line)
        return lines

    # --- reader commands -------------------------------------------------
    def list_overchan_groups(self):
        code, line = self._command("LIST ACTIVE overchan.*")
        if code != 215:
            code, line = self._command("LIST ACTIVE")
            if code != 215:
                raise NNTPError("LIST ACTIVE failed: %s" % line)
        groups = []
        for raw in self._read_multiline():
            parts = raw.decode("latin-1", "replace").split()
            if parts and parts[0].startswith("overchan."):
                groups.append(parts[0])
        return groups

    def list_active_groups(self, wildmat="*"):
        """Return [(name, high, low)] for every group (or those matching wildmat).

        Unlike list_overchan_groups this does NOT filter to overchan.* — the
        admin newsgroup browser wants to see everything the peer carries.
        """
        command = "LIST ACTIVE" if wildmat in ("", "*") else ("LIST ACTIVE %s" % wildmat)
        code, line = self._command(command)
        if code != 215:
            raise NNTPError("LIST ACTIVE failed: %s" % line)
        out = []
        for raw in self._read_multiline():
            parts = raw.decode("latin-1", "replace").split()
            if not parts:
                continue
            try:
                high = int(parts[1]) if len(parts) > 1 else 0
                low = int(parts[2]) if len(parts) > 2 else 0
            except ValueError:
                high = low = 0
            out.append((parts[0], high, low))
        return out

    def group(self, name):
        """Select a group; returns (count, first, last)."""
        code, line = self._command("GROUP %s" % name)
        if code != 211:
            raise NNTPError("GROUP %s -> %s" % (name, line))
        parts = line.split()
        try:
            return int(parts[1]), int(parts[2]), int(parts[3])
        except (IndexError, ValueError):
            raise NNTPError("malformed GROUP response: %s" % line)

    def over_message_ids(self, first, last):
        """List (article_number, message_id, references) for the range.

        The overview format is fixed by RFC 3977: subject, from, date,
        message-id, references, :bytes, :lines — so Message-ID is field index 4
        and References index 5 (after the leading article number). References
        lets a caller derive the thread root cheaply, before fetching.
        """
        if last < first:
            return []
        code, line = self._command("OVER %d-%d" % (first, last))
        if code not in (224,):
            code, line = self._command("XOVER %d-%d" % (first, last))
            if code != 224:
                return []
        out = []
        for raw in self._read_multiline():
            fields = raw.decode("latin-1", "replace").rstrip("\r\n").split("\t")
            if len(fields) < 5:
                continue
            try:
                artnum = int(fields[0])
            except ValueError:
                continue
            message_id = fields[4].strip()
            references = fields[5].strip() if len(fields) > 5 else ""
            if message_id:
                out.append((artnum, message_id, references))
        return out

    def article(self, message_id):
        """Fetch one article by Message-ID; returns raw bytes or None."""
        code, _line = self._command("ARTICLE %s" % message_id)
        if code != 220:
            return None
        return b"".join(self._read_multiline())

    def post_article(self, headers, body):
        """POST an article (used to broadcast fingerprint bans). headers is an
        ordered dict-ish of name->value; body is a unicode string. Returns True
        on 240 (accepted). Raises NNTPError if POSTing is refused."""
        code, line = self._command("POST")
        if code != 340:
            raise NNTPError("POST not permitted: %s" % line)
        lines = []
        for name, value in headers.items():
            lines.append("%s: %s" % (name, value))
        lines.append("")  # header/body separator
        for raw in (body or "").split("\n"):
            raw = raw.rstrip("\r")
            if raw.startswith("."):
                raw = "." + raw  # dot-stuffing
            lines.append(raw)
        payload = "\r\n".join(lines) + "\r\n.\r\n"
        self._sock.sendall(payload.encode("utf-8", "replace"))
        code, line = self._status()
        if code != 240:
            raise NNTPError("POST rejected: %s" % line)
        return True

    def delete_group(self, name, token=None):
        """Delete a newsgroup (and its articles) from the hub via XDELGROUP.
        Authenticates with XADMIN first when a token is provided."""
        if token:
            code, line = self._command("XADMIN %s" % token)
            if code != 281:
                raise NNTPError("XADMIN failed: %s" % line)
        code, line = self._command("XDELGROUP %s" % name)
        if code // 100 != 2:
            raise NNTPError("XDELGROUP %s -> %s" % (name, line))
        return line


def _proxy_address():
    value = (os.getenv("I2P_SOCKS_PROXY") or "127.0.0.1:4447").strip()
    if value.count(":") != 1:
        raise NNTPError("I2P_SOCKS_PROXY must use host:port format")
    host, port = value.rsplit(":", 1)
    try:
        port = int(port)
    except ValueError:
        raise NNTPError("I2P_SOCKS_PROXY has an invalid port")
    if not host or not (0 < port < 65536):
        raise NNTPError("I2P_SOCKS_PROXY is invalid")
    return host, port


def _recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        value = sock.recv(remaining)
        if not value:
            raise NNTPError("I2P SOCKS proxy closed the connection")
        chunks.append(value)
        remaining -= len(value)
    return b"".join(chunks)


def _i2p_socks_connect(host, port, timeout):
    # SOCKS receives the hostname verbatim, so Python performs no DNS lookup and
    # the only remotely visible endpoint is the peer's I2P destination.
    from services.i2p_addresses import normalize_i2p_host
    host = normalize_i2p_host(host)
    encoded = host.encode("ascii")
    if len(encoded) > 255:
        raise NNTPError("I2P destination is too long")
    sock = socket.create_connection(_proxy_address(), timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise NNTPError("I2P SOCKS proxy rejected unauthenticated access")
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes((len(encoded),))
            + encoded
            + struct.pack("!H", int(port))
        )
        header = _recv_exact(sock, 4)
        if header[:3] != b"\x05\x00\x00":
            code = header[1] if len(header) > 1 else -1
            raise NNTPError("I2P SOCKS proxy could not reach peer (code %s)" % code)
        address_type = header[3]
        if address_type == 1:
            _recv_exact(sock, 4)
        elif address_type == 4:
            _recv_exact(sock, 16)
        elif address_type == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        else:
            raise NNTPError("I2P SOCKS proxy returned an invalid address type")
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise

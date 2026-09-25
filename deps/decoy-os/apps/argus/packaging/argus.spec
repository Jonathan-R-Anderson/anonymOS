Name:           argus
Version:        0.4.0
Release:        1%{?dist}
Summary:        eBPF-based syscall telemetry daemon

License:        GPL-2.0-only
URL:            https://github.com/user/argus

# Build in the directory where 'make' was run (no Source tarball needed)
BuildRequires:  clang, bpftool, libbpf-devel, elfutils-libelf-devel, zlib-devel, gcc
Requires:       libbpf

%description
argus monitors process execution, file access, network connections and
security-relevant system calls (chmod, rename, unlink, bind, ptrace) via
eBPF tracepoints.  Events are emitted as structured text or newline-delimited
JSON and can be forwarded over TCP to a SIEM or log aggregator.

Features:
  - Kernel-side filtering by PID, comm, or PID subtree (--follow)
  - Per-comm rate limiting to tame noisy processes
  - Alert rules engine (JSON) with {variable} message templates
  - TCP event forwarding with automatic reconnect
  - DNS reverse-lookup cache for CONNECT/BIND events
  - Baseline / anomaly detection mode

%install
install -Dm755 %{_builddir}/argus                          %{buildroot}%{_bindir}/argus
install -Dm644 %{_builddir}/packaging/argus.service        %{buildroot}/etc/systemd/system/argus.service
install -Dm644 %{_builddir}/packaging/argus.tmpfiles       %{buildroot}/usr/lib/tmpfiles.d/argus.conf
install -Dm644 %{_builddir}/packaging/argus.logrotate      %{buildroot}/etc/logrotate.d/argus

%files
%{_bindir}/argus
/etc/systemd/system/argus.service
/usr/lib/tmpfiles.d/argus.conf
/etc/logrotate.d/argus

%post
systemd-tmpfiles --create /usr/lib/tmpfiles.d/argus.conf || true
systemctl daemon-reload || true

%preun
if [ $1 -eq 0 ]; then
    systemctl stop argus 2>/dev/null || true
    systemctl disable argus 2>/dev/null || true
fi

%changelog
* Sat Jan 01 2025 argus project <noreply@example.com> - 0.1.0-1
- Initial RPM packaging

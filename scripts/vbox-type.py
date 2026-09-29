#!/usr/bin/env python3
"""vbox-type.py VM "text" [--enter] -- type text into a VirtualBox guest, reliably.

`VBoxManage controlvm VM keyboardputstring` loses characters on this guest (the first one after
Enter, every 'm') and can leave Shift held down, after which every later key is wrong.  This sends
explicit PS/2 set-1 make/break scancodes per character instead -- Shift is pressed and released
around each shifted character, never left down -- ONE scancode at a time through the VirtualBox
API with a pause after each: the guest drains a 1-byte i8042 buffer per interrupt, and a burst
(even 8 codes) lost keys and, worse, a Shift release.
"""
import os
import sys
import time
os.environ.setdefault('VBOX_PROGRAM_PATH', '/usr/lib/virtualbox/')
os.environ.setdefault('VBOX_SDK_PATH', '/usr/lib/virtualbox/sdk/')
sys.path.insert(0, '/usr/lib/virtualbox/sdk/bindings/xpcom/python')
sys.path.insert(0, '/usr/lib/virtualbox')
import xpcom.vboxxpcom, xpcom, xpcom.components  # noqa: E401,F401

VM = sys.argv[1]
TEXT = sys.argv[2] if len(sys.argv) > 2 else ""
ENTER = "--enter" in sys.argv[3:]

# unshifted and shifted characters -> scancode (set 1 make code)
BASE = {
    '1': 0x02, '2': 0x03, '3': 0x04, '4': 0x05, '5': 0x06, '6': 0x07, '7': 0x08, '8': 0x09,
    '9': 0x0a, '0': 0x0b, '-': 0x0c, '=': 0x0d, '\t': 0x0f,
    'q': 0x10, 'w': 0x11, 'e': 0x12, 'r': 0x13, 't': 0x14, 'y': 0x15, 'u': 0x16, 'i': 0x17,
    'o': 0x18, 'p': 0x19, '[': 0x1a, ']': 0x1b, 'a': 0x1e, 's': 0x1f, 'd': 0x20, 'f': 0x21,
    'g': 0x22, 'h': 0x23, 'j': 0x24, 'k': 0x25, 'l': 0x26, ';': 0x27, "'": 0x28, '`': 0x29,
    '\\': 0x2b, 'z': 0x2c, 'x': 0x2d, 'c': 0x2e, 'v': 0x2f, 'b': 0x30, 'n': 0x31, 'm': 0x32,
    ',': 0x33, '.': 0x34, '/': 0x35, ' ': 0x39, '\n': 0x1c,
}
SHIFTED = {
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8', '(': '9',
    ')': '0', '_': '-', '+': '=', '{': '[', '}': ']', ':': ';', '"': "'", '~': '`', '|': '\\',
    '<': ',', '>': '.', '?': '/',
}
LSHIFT = 0x2a


def codes_for(ch):
    if ch in BASE:
        c = BASE[ch]
        return [c, c | 0x80]
    if ch.isalpha() and ch.lower() in BASE:
        c = BASE[ch.lower()]
        return [LSHIFT, c, c | 0x80, LSHIFT | 0x80]
    if ch in SHIFTED:
        c = BASE[SHIFTED[ch]]
        return [LSHIFT, c, c | 0x80, LSHIFT | 0x80]
    raise SystemExit(f"vbox-type: no scancode for {ch!r}")


client = xpcom.components.classes["@virtualbox.org/VirtualBoxClient;1"].createInstance()
session = xpcom.components.classes["@virtualbox.org/Session;1"].createInstance()
client.virtualBox.findMachine(VM).lockMachine(session, 1)
try:
    kbd = session.console.keyboard

    def send(codes):
        for c in codes:
            kbd.putScancode(c)
            time.sleep(0.02)

    send([0xaa, 0xb6, 0x9d, 0xb8])      # release every modifier an earlier tool may have left down
    for ch in TEXT + ("\n" if ENTER else ""):
        send(codes_for(ch))
finally:
    session.unlockMachine()

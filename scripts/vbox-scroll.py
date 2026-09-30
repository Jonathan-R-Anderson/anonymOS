#!/usr/bin/env python3
"""vbox-scroll.py VM CLICKS -- turn the guest's mouse wheel CLICKS notches (positive = down) at the
pointer's current position (move it there first with vbox-click.py ... noclick)."""
import os, sys, time
os.environ.setdefault('VBOX_PROGRAM_PATH', '/usr/lib/virtualbox/')
os.environ.setdefault('VBOX_SDK_PATH', '/usr/lib/virtualbox/sdk/')
sys.path.insert(0, '/usr/lib/virtualbox/sdk/bindings/xpcom/python')
sys.path.insert(0, '/usr/lib/virtualbox')
import xpcom.vboxxpcom, xpcom, xpcom.components  # noqa: E401,F401

VM, CLICKS = sys.argv[1], int(sys.argv[2])
client = xpcom.components.classes["@virtualbox.org/VirtualBoxClient;1"].createInstance()
session = xpcom.components.classes["@virtualbox.org/Session;1"].createInstance()
client.virtualBox.findMachine(VM).lockMachine(session, 1)
try:
    mouse = session.console.mouse
    step = 1 if CLICKS > 0 else -1
    for _ in range(abs(CLICKS)):
        mouse.putMouseEvent(0, 0, step, 0, 0)     # dz > 0 scrolls down
        time.sleep(0.15)
finally:
    session.unlockMachine()

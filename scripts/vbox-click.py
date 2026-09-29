#!/usr/bin/env python3
"""vbox-click.py VM X Y [noclick] -- closed-loop left-click at screen (X, Y) in a VirtualBox guest.

For driving the anonymOS desktop from the host when verifying GUI flows (VBoxManage has no mouse
injection; this uses VirtualBox's own XPCOM API, which ships with VirtualBox -- needs Pillow).
The guest only has a RELATIVE PS/2 mouse and Hyprland applies pointer acceleration, so an open-loop
move never lands exactly.  So: home the cursor to (0,0), screenshot, move toward the target, find
the cursor by diffing against the homed screenshot near the target, correct, repeat, click.
Screenshots go next to this script as _home.png / _at.png (set VBCLICK_TMP to redirect).

Example:  scripts/vbox-click.py anonymos-verify 806 222     # the Domain Manager's Applications tab
Keys:     VBoxManage controlvm VM keyboardputscancode e0 5b 2a 20 a0 aa e0 db   # SUPER+SHIFT+D
Note:     Hyprland's hidden dock swallows clicks at the bottom centre of the screen.
"""
import os, subprocess, sys, time
from PIL import Image, ImageChops
os.environ.setdefault('VBOX_PROGRAM_PATH', '/usr/lib/virtualbox/')
os.environ.setdefault('VBOX_SDK_PATH', '/usr/lib/virtualbox/sdk/')
sys.path.insert(0, '/usr/lib/virtualbox/sdk/bindings/xpcom/python')
sys.path.insert(0, '/usr/lib/virtualbox')
import xpcom.vboxxpcom, xpcom, xpcom.components

VM, TX, TY = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
CLICK = not (len(sys.argv) > 4 and sys.argv[4] == 'noclick')
TMP = os.environ.get('VBCLICK_TMP') or os.path.dirname(os.path.abspath(__file__))

def shot(name):
    p = os.path.join(TMP, name)
    subprocess.run(['VBoxManage', 'controlvm', VM, 'screenshotpng', p], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return Image.open(p).convert('RGB')

BAR_H = 30   # the top bar: not searched (see below)

def find_cursor(base, cur, tx, ty, r=140):
    """The cursor's hotspot near (tx, ty): the top-left-most pixel that changed between the homed
    screenshot and this one and is cursor-coloured (white fill / black outline)."""
    w, h = cur.size
    x0, y0, x1, y1 = max(0, tx - r), max(BAR_H, ty - r), min(w, tx + r), min(h, ty + r)
    diff = ImageChops.difference(base.crop((x0, y0, x1, y1)), cur.crop((x0, y0, x1, y1))).convert('L')
    px = diff.load(); cp = cur.load()
    best = None
    for y in range(y1 - y0):
        for x in range(x1 - x0):
            if px[x, y] > 60:
                c = cp[x0 + x, y0 + y]
                if (c[0] > 235 and c[1] > 235 and c[2] > 235):
                    if best is None or (y, x) < (best[1] - y0, best[0] - x0):
                        best = (x0 + x, y0 + y)
    return best

client = xpcom.components.classes["@virtualbox.org/VirtualBoxClient;1"].createInstance()
session = xpcom.components.classes["@virtualbox.org/Session;1"].createInstance()
m = client.virtualBox.findMachine(VM)
m.lockMachine(session, 1)
try:
    mouse = session.console.mouse
    def move(dx, dy, step=20, dt=0.08):
        while dx != 0 or dy != 0:
            sx = max(-step, min(step, dx)); sy = max(-step, min(step, dy))
            mouse.putMouseEvent(sx, sy, 0, 0, 0); time.sleep(dt)
            dx -= sx; dy -= sy
    for _ in range(40): mouse.putMouseEvent(-60, -60, 0, 0, 0); time.sleep(0.03)   # home
    time.sleep(0.4)
    base = shot('_home.png')
    # The top bar is excluded from the cursor search (its clock and hover highlights change on
    # their own), so a target on it is reached by homing in closed-loop on a point just below
    # the bar, then stepping straight up.
    AY = TY if TY >= BAR_H + 10 else BAR_H + 16
    move(TX, AY)
    pos = None
    for it in range(6):
        time.sleep(0.4)
        pos = find_cursor(base, shot('_at.png'), TX, AY)
        if pos is None:
            print('cursor not found near target'); break
        ex, ey = TX - pos[0], AY - pos[1]
        if abs(ex) <= 4 and abs(ey) <= 4: break
        move(ex, ey, step=6, dt=0.06)
    if AY != TY and pos is not None:
        move(0, TY - AY, step=4, dt=0.06)
    print('cursor', pos, 'target', (TX, TY), '' if AY == TY else f'(aimed at y={AY}, then up)')
    if CLICK:
        mouse.putMouseEvent(0, 0, 0, 0, 1); time.sleep(0.15)
        mouse.putMouseEvent(0, 0, 0, 0, 0)
finally:
    session.unlockMachine()

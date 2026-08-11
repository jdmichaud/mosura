#!/usr/bin/env python3
"""Drive a Knowledge Dynamics INSTALL (v3.x) DOS installer unattended under dosemu2.

Used by setup-metaware-dosemu.sh for the MetaWare High C/C++ floppy sets whose files are packed
into MWHC.0NN volumes (docs/metaware-highc-support.md). Nothing here is MetaWare-specific — it
is a screen-driven driver for the installer engine.

WHY A PTY AND A SCREEN BUFFER, not a pipe of keystrokes:

  * The installer's option list is a direct-video sub-window. In dosemu's dumb mode (-td) its
    contents never reach stdout, so you type blind at a widget whose state you cannot see —
    which is how "send SPACE to select the compiler" silently switched the compiler OFF (its
    default is already YES) and produced a successful-looking zero-file install.
  * DOS's BIOS keyboard buffer is 16 bytes: a burst of piped keys is mostly discarded, so early
    screens eat them and later screens receive nothing.
  * An arrow key cannot be delivered as bytes — as an ANSI sequence it starts with ESC, and the
    installer treats ESC as "STOP the installation".

Running dosemu in slang mode (-t) on a pty makes it render real ANSI, which this script
reconstructs into an 80x25 buffer, so every decision is made against what is actually on screen,
and exactly one key is sent per screen.

TWO NON-OBVIOUS REQUIREMENTS, both of which cost a long debugging session:

  1. Source and target must be DIFFERENT DOS drives. The engine refuses with "The output drive
     cannot be the same as the input drive". So the staged volumes are mounted as their own
     drive via `dosemu -d <dir>` (it lands on F:, after C:/D:/E:) and never copied under C:.
  2. Act on a RECOGNISED screen, once each, rate-limiting the generic Enter. Waiting for the
     screen to stop changing does not work: with the idle throttle off dosemu repaints its
     status line continuously, so a "settled" gate never fires and the run crawls.

Exit status: 0 installed and went idle, 2 timed out, 3 the installer aborted or refused.
"""
import argparse, fcntl, os, pty, re, select, struct, sys, termios, time

ROWS, COLS = 25, 80


class Screen:
    """Minimal ANSI screen buffer — enough to read a DOS TUI."""

    def __init__(self):
        self.buf = [[' '] * COLS for _ in range(ROWS)]
        self.r = self.c = 0

    def feed(self, data):
        i = 0
        while i < len(data):
            ch = data[i]
            if ch == 0x1b:
                if i + 2 < len(data) and data[i + 1] in (0x28, 0x29):   # charset select
                    i += 3
                    continue
                m = re.match(rb'\x1b\[([0-9;?]*)([A-Za-z])', data[i:])
                if not m:
                    i += 1
                    continue
                nums = [int(x) for x in m.group(1).split(b';') if x.isdigit()]
                cmd = m.group(2)
                if cmd in (b'H', b'f'):
                    self.r = min(ROWS - 1, (nums[0] - 1) if nums else 0)
                    self.c = min(COLS - 1, (nums[1] - 1) if len(nums) > 1 else 0)
                elif cmd == b'J' and (not nums or nums[0] == 2):
                    self.buf = [[' '] * COLS for _ in range(ROWS)]
                    self.r = self.c = 0
                elif cmd == b'K':
                    for x in range(self.c, COLS):
                        self.buf[self.r][x] = ' '
                i += m.end()
                continue
            if ch == 0x0d:
                self.c = 0
            elif ch == 0x0a:
                self.r = min(ROWS - 1, self.r + 1)
            elif ch == 0x08:
                self.c = max(0, self.c - 1)
            elif 32 <= ch < 127 and self.c < COLS:
                self.buf[self.r][self.c] = chr(ch)
                self.c += 1
            i += 1

    def text(self):
        return '\n'.join(''.join(r).rstrip() for r in self.buf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', default=r'F:\INSTALL.EXE', help='DOS path of INSTALL.EXE')
    ap.add_argument('--mount', required=True, help='host dir holding the staged volumes (becomes F:)')
    ap.add_argument('--dest', required=True, help='host dir the install writes to')
    ap.add_argument('--drive', default='C', help='destination DOS drive letter')
    ap.add_argument('--serial', default='123456', help='6 digits; a FORMAT check, not a licence check')
    ap.add_argument('--timeout', type=int, default=3600)
    ap.add_argument('--idle', type=int, default=180, help='seconds with no new file = finished')
    ap.add_argument('--cooldown', type=float, default=1.0, help='min seconds between generic Enter keys')
    ap.add_argument('--screens', default='/tmp/kd-install-screens.txt')
    a = ap.parse_args()

    # dosemu writes DOS directory names in lower case on a case-sensitive host: watch both, or a
    # perfectly good install reads as "0 files" and you debug a non-problem (this happened).
    base, name = os.path.dirname(a.dest), os.path.basename(a.dest)
    dests = list(dict.fromkeys([a.dest, os.path.join(base, name.lower()),
                                os.path.join(base, name.upper())]))

    def count():
        n = 0
        for p in dests:
            for _, _, fs in os.walk(p):
                n += len(fs)
        return n

    pid, fd = pty.fork()
    if pid == 0:
        os.environ['TERM'] = 'xterm'
        os.environ['LC_ALL'] = 'C'
        # $_hogthreshold = (0) disables dosemu's idle-detection throttle. Without it dosemu
        # sleeps whenever the DOS program looks idle, and this installer polls the keyboard
        # between file operations — so it looks idle while decompressing. Measured ~5% host CPU
        # with the throttle on: the unpack was mostly dosemu sleeping, not work.
        os.execvp('dosemu', ['dosemu', '-t', '-I', '$_hogthreshold = (0)',
                             '-d', a.mount, '-E', a.exe])
        os._exit(1)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', ROWS, COLS, 0, 0))

    scr = Screen()
    log = open(a.screens, 'w')
    handled = set()
    files, rc = 0, 2
    t0 = last_file_change = time.time()
    last_generic = last_periodic = 0.0
    alive = True

    def send(keys, note=''):
        log.write('\n>>> SEND %r  %s\n' % (keys, note))
        log.flush()
        os.write(fd, keys)

    while alive and time.time() - t0 < a.timeout:
        r, _, _ = select.select([fd], [], [], 0.3)
        if fd in r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b''
            if not data:
                log.write('\n[installer exited]\n')
                alive = False
                rc = 0 if files else 3
                break
            scr.feed(data)

        n = count()
        if n != files:
            files, last_file_change = n, time.time()
            print('  %d files' % n, flush=True)

        t = scr.text()
        # Deliberately NOT waiting for a fully static screen: with the idle throttle off dosemu
        # repaints continuously (status line), so a "screen settled" gate never fires and the
        # run crawls. Instead each named screen is acted on exactly once (`handled`), and the
        # generic Enter is rate-limited so the 16-byte BIOS key buffer never overflows.
        key = str(hash(t))
        if 'cannot be the same as the input drive' in t:
            print('FATAL: source and target are the same DOS drive; mount the staged volumes as '
                  'their own drive (--mount)', file=sys.stderr)
            rc = 3
            break

        # Log periodically as well as on banners: the copy phase draws no banner, so a stall
        # there is otherwise invisible in the transcript.
        if time.time() - last_periodic > 20:
            last_periodic = time.time()
            log.write('\n----- +%ds files=%d (periodic)\n%s\n' % (time.time() - t0, files, t))
            log.flush()

        banner = re.search(r'--->\s+(.+?)\s+<---', t)
        if banner:
            log.write('\n===== +%ds files=%d  %s\n%s\n' % (time.time() - t0, files,
                                                           banner.group(1), t))
            log.flush()

        if 'Specify Compiler Drive' in t and 'drive' not in handled:
            handled.add('drive')
            # Enter alone NEVER completes this list; the drive letter does.
            send(a.drive.encode(), 'destination drive letter')
            time.sleep(0.5)
            send(b'\r')
        elif 'Verify Compiler Directory' in t and 'verify' not in handled:
            handled.add('verify')
            # This checkbox defaults to NO; Enter alone loops back to the drive screen forever.
            send(b' ', 'flip "Is this correct?" No -> Yes')
            time.sleep(0.5)
            send(b'\r')
        elif 'Enter Serial Number' in t and 'serial' not in handled:
            handled.add('serial')
            send(a.serial.encode(), 'serial (format check only)')
            time.sleep(0.5)
            send(b'\r')
        elif 'Choose Installation Options' in t and 'options' not in handled:
            handled.add('options')
            # DO NOT send SPACE: @SetOption(1)/@SetOption(2) in INSTALL.DAT already leave
            # "Install the C/C++ compiler" and "Install the debugger" at YES, and SPACE toggles
            # the highlighted line — switching the compiler OFF.
            send(b'\r', 'accept the default YES/YES selection')
        elif time.time() - last_generic > a.cooldown:
            # A @pause, or "place Disk #N in drive F:" — every volume is staged flat in the
            # mount, so any key continues. NEVER send ESC.
            last_generic = time.time()
            os.write(fd, b'\r')

        if files and time.time() - last_file_change > a.idle:
            print('idle %ds after %d files — finished' % (a.idle, files), flush=True)
            rc = 0
            break

    log.write('\n----- FINAL SCREEN (+%ds, files=%d)\n%s\n' % (time.time() - t0, count(), scr.text()))
    log.close()
    for sig in (15, 9):
        try:
            os.kill(pid, sig)
            time.sleep(0.5)
        except OSError:
            break
    try:
        os.close(fd)
    except OSError:
        pass
    print('files installed: %d (screens: %s)' % (count(), a.screens))
    return rc


sys.exit(main())

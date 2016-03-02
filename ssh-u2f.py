#!/usr/bin/env python
from __future__ import print_function

import getpass,os,re,signal,subprocess,sys
import pexpect

ssh = None

def handler(signum, frame):
    global ssh
    if ssh:
        ssh.kill(signum)
    sys.exit(signum)

signal.signal(signal.SIGQUIT, handler)
signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGINT, handler)

def winch_handler(signum, frame):
    global ssh
    if ssh:
        rows, cols = os.popen('stty size', 'r').read().split()
        ssh.setwinsize(int(rows), int(cols))

signal.signal(signal.SIGWINCH, winch_handler)

try:
    command = os.path.splitext(os.path.basename(__file__))[0].split("-")[0]
except:
    command = None

ssh = pexpect.spawn(command or "ssh", sys.argv[1:])
winch_handler(None, None)

index = -1
pattern_list = ssh.compile_pattern_list([
    "Enter additional factors:.*",
    "----- BEGIN U2F CHALLENGE -----\r?\n([^\r\n]*)\r?\n(.*)\r?\n----- END U2F CHALLENGE -----",
    "Welcome.*",
    pexpect.EOF
])
while True:
    index = ssh.expect_list(pattern_list)
    if index == 0:
        try:
            pin = getpass.getpass(ssh.match.group())
        except EOFError:
            pin = ""
        ssh.sendline(pin.strip())
    elif index == 1:
        p = subprocess.Popen(["u2f-host", "-aauthenticate",
                              "-o", ssh.match.group(1)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = p.communicate(ssh.match.group(2))
        p.wait()
        ssh.sendline(out.strip())
    else:
        break
if index == 3:
    sys.exit(0)
sys.stdout.write(ssh.match.group())
ssh.interact()

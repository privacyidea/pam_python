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

def passthrough():
    print()
    sys.stdout.write(ssh.match.group())
    try:
        ssh.interact()
    except UnboundLocalError:
        # Work around bug in pexpect 3.1
        pass
    sys.exit(0)

index = ssh.expect(["Authenticated with partial success.",
                    "[^ \r\n]+",
                    pexpect.EOF])

if index == 0:
    print(ssh.match.group())
elif index == 1:
    passthrough()
elif index == 2:
    sys.exit(0)

while True:
    index = ssh.expect(["Enter additional factors: ",
                        "----- BEGIN U2F CHALLENGE -----\r\n",
                        "[^ \r\n]+",
                        pexpect.EOF])

    if index == 0:
        try:
            pin = getpass.getpass(ssh.match.group())
        except EOFError:
            pin = ""
        ssh.sendline(pin.strip())

    elif index == 1:
        u2f_origin = ssh.readline().strip()
        u2f_challenge = ssh.readline().strip()
        ssh.expect("(.*)----- END U2F CHALLENGE -----")
        message = ssh.match.group(1).strip()
        print(message or "Interact with your U2F token.")
        p = subprocess.Popen(["u2f-host", "-aauthenticate", "-o", u2f_origin],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = p.communicate(u2f_challenge)
        p.wait()
        ssh.sendline(out.strip())

    elif index == 2:
        passthrough()

    elif index == 3:
        sys.exit(0)

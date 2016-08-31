#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
#
# 2016-03-03 Brandon Smith <freedom@reardencode.com>
#            Initial Creation
#
# (c) Brandon Smith
# Info: http://www.privacyidea.org
#
# This code is free software; you can redistribute it and/or
# modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation; either
# version 3 of the License, or any later version.
#
# This code is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU AFFERO GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import print_function

import getpass,os,re,signal,subprocess,sys
import pexpect

__doc__ = """This is an ssh (and ssh-like) wrapper that uses pexpect to
interact with privacyIDEA's pam_python module for u2f challenge/response.

Usage:
    Make executable
    Symlink ssh-u2f, scp-u2f, sftp-u2f, mosh-u2f, etc. into your PATH
    Call just like ssh, eg. "ssh-u2f name@example.com"
"""

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

while True:
    index = ssh.expect(["Authenticated with partial success.",
                        "([Pp]assword[^:\r\n]*|OTP): ?",
                        "----- BEGIN U2F CHALLENGE -----\r\n",
                        "[^ \r\n]+",
                        pexpect.EOF])

    if index == 0:
        print(ssh.match.group())

    if index == 1:
        try:
            pin = getpass.getpass(ssh.match.group())
        except EOFError:
            pin = ""
        ssh.sendline(pin.strip())

    elif index == 2:
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

    elif index == 3:
        passthrough()

    elif index == 4:
        sys.exit(0)

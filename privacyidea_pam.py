# -*- coding: utf-8 -*-
#
# 2016-08-31 Cornelius Kölbel <cornelius.koelgel@netknights.it>
#            Add header user-agent to request
# 2015-03-04 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#            Add normal challenge/response support
# 2016-03-03 Brandon Smith <freedom@reardencode.com>
#            Add U2F challenge/response support
# 2015-11-06 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#            Avoid SQL injections.
# 2015-10-17 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#            Add support for try_first_pass
# 2015-04-03 Cornelius Kölbel  <cornelius.koelbel@netknights.it>
#            Use pbkdf2 to hash OTPs.
# 2015-04-01 Cornelius Kölbel  <cornelius.koelbel@netknights.it>
#            Add storing of OTP hashes
# 2015-03-29 Cornelius Kölbel, <cornelius.koelbel@netknights.it>
#            Initial creation
#
# (c) Cornelius Kölbel
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
__doc__ = """This is the PAM module to be used with python-pam with the
privacyIDEA authentication system.

The code is tested in test_pam_module.py
"""

import json
import requests
import syslog
import sqlite3
import passlib.hash
import time
import traceback
import datetime


def _get_config(argv):
    """
    Read the parameters from the arguments. If the argument can be split with a
    "=", the parameter will get the given value.

    :param argv:
    :return: dictionary with the parameters
    """
    config = {}
    for arg in argv:
        argument = arg.split("=")
        if len(argument) == 1:
            config[argument[0]] = True
        elif len(argument) == 2:
            config[argument[0]] = argument[1]
    return config


class Authenticator(object):

    def __init__(self, pamh, config):
        self.pamh = pamh
        self.user = pamh.get_user(None)
        self.URL = config.get("url", "https://localhost")
        self.sslverify = not config.get("nosslverify", False)
        cacerts = config.get("cacerts")
        # If we do verify SSL certificates and if a CA Cert Bundle file is
        # provided, we set this.
        if self.sslverify and cacerts:
            self.sslverify = cacerts
        self.realm = config.get("realm")
        self.debug = config.get("debug")
        self.sqlfile = config.get("sqlfile", "/etc/privacyidea/pam.sqlite")

    def make_request(self, data, endpoint="/validate/check"):
        # add a user-agent to be displayed in the Client Application Type
        headers = {'user-agent': 'PAM/2.15.0'}
        response = requests.post(self.URL + endpoint, data=data,
                                 headers=headers, verify=self.sslverify)

        json_response = response.json
        if callable(json_response):
            syslog.syslog(syslog.LOG_DEBUG, "requests > 1.0")
            json_response = json_response()

        return json_response

    def offline_refill(self, serial, password):

        # get refilltoken
        conn = sqlite3.connect(self.sqlfile)
        c = conn.cursor()
        refilltoken = None
        # get all possible serial/tokens for a user
        for row in c.execute("SELECT refilltoken FROM refilltokens WHERE serial=?",
                             (serial, )):
            refilltoken = row[0]
            syslog.syslog("Doing refill with token {0!s}".format(refilltoken))

        if refilltoken:
            data = {"serial": serial,
                    "pass": password,
                    "refilltoken": refilltoken}
            json_response = self.make_request(data, "/validate/offlinerefill")

            result = json_response.get("result")
            auth_item = json_response.get("auth_items")
            detail = json_response.get("detail") or {}
            tokentype = detail.get("type", "unknown")
            if self.debug:
                syslog.syslog(syslog.LOG_DEBUG,
                              "%s: result: %s" % (__name__, result))
                syslog.syslog(syslog.LOG_DEBUG,
                              "%s: detail: %s" % (__name__, detail))

            if result.get("status"):
                if result.get("value"):
                    save_auth_item(self.sqlfile, self.user, serial, tokentype,
                                   auth_item)
                    return True
            else:
                syslog.syslog(syslog.LOG_ERR,
                              "%s: %s" % (__name__,
                                          result.get("error").get("message")))
        return False

    def authenticate(self, password):
        rval = self.pamh.PAM_SYSTEM_ERR
        # First we try to authenticate against the sqlitedb
        r, serial = check_offline_otp(self.user, password, self.sqlfile, window=10)
        syslog.syslog(syslog.LOG_DEBUG, "offline check returned: {0!s}, {1!s}".format(r, serial))
        if r:
            syslog.syslog(syslog.LOG_DEBUG,
                          "%s: successfully authenticated against offline "
                          "database %s" % (__name__, self.sqlfile))

            # Try to refill
            try:
                r = self.offline_refill(serial, password)
                syslog.syslog(syslog.LOG_DEBUG, "offline refill returned {0!s}".format(r))
            except Exception as e:
                # If the network is not reachable we will not refill.
                syslog.syslog(syslog.LOG_DEBUG, "failed to refill {0!s}".format(e))

            rval = self.pamh.PAM_SUCCESS
        else:
            if self.debug:
                syslog.syslog(syslog.LOG_DEBUG, "Authenticating %s against %s" %
                              (self.user, self.URL))
            data = {"user": self.user,
                    "pass": password}
            if self.realm:
                data["realm"] = self.realm

            json_response = self.make_request(data)
            result = json_response.get("result")
            auth_item = json_response.get("auth_items")
            detail = json_response.get("detail") or {}
            serial = detail.get("serial", "T%s" % time.time())
            tokentype = detail.get("type", "unknown")
            if self.debug:
                syslog.syslog(syslog.LOG_DEBUG,
                              "%s: result: %s" % (__name__, result))
                syslog.syslog(syslog.LOG_DEBUG,
                              "%s: detail: %s" % (__name__, detail))

            if result.get("status"):
                if result.get("value"):
                    rval = self.pamh.PAM_SUCCESS
                    save_auth_item(self.sqlfile, self.user, serial, tokentype,
                                   auth_item)
                else:
                    transaction_id = detail.get("transaction_id")
                    message = detail.get("message").encode("utf-8")

                    if transaction_id:
                        attributes = detail.get("attributes") or {}
                        if "u2fSignRequest" in attributes:
                            rval = self.u2f_challenge_response(
                                    transaction_id, message,
                                    attributes)
                        else:
                            rval = self.challenge_response(transaction_id,
                                                           message,
                                                           attributes)
                    else:
                        syslog.syslog(syslog.LOG_ERR,
                                      "%s: %s" % (__name__, message))
                        pam_message = self.pamh.Message(self.pamh.PAM_ERROR_MSG, message)
                        self.pamh.conversation(pam_message)
                        rval = self.pamh.PAM_AUTH_ERR
            else:
                error_msg = result.get("error").get("message")
                syslog.syslog(syslog.LOG_ERR,
                              "%s: %s" % (__name__, error_msg))
                pam_message = self.pamh.Message(self.pamh.PAM_ERROR_MSG, error_msg)
                self.pamh.conversation(pam_message)

        # Save history
        save_history_item(self.sqlfile, self.user, serial, (True if rval == self.pamh.PAM_SUCCESS else False))
        return rval

    def challenge_response(self, transaction_id, message, attributes):
        rval = self.pamh.PAM_SYSTEM_ERR

        syslog.syslog(syslog.LOG_DEBUG, "Prompting for challenge response")
        pam_message = self.pamh.Message(self.pamh.PAM_PROMPT_ECHO_ON, message)
        response = self.pamh.conversation(pam_message)
        otp = response.resp
        r_code = response.resp_retcode
        data = {"user": self.user,
                "transaction_id": transaction_id,
                "pass": otp}
        if self.realm:
            data["realm"] = self.realm

        json_response = self.make_request(data)

        result = json_response.get("result")
        detail = json_response.get("detail")

        if self.debug:
            syslog.syslog(syslog.LOG_DEBUG,
                          "%s: result: %s" % (__name__, result))
            syslog.syslog(syslog.LOG_DEBUG,
                          "%s: detail: %s" % (__name__, detail))

        if result.get("status"):
            if result.get("value"):
                rval = self.pamh.PAM_SUCCESS
            else:
                rval = self.pamh.PAM_AUTH_ERR
        else:
            syslog.syslog(syslog.LOG_ERR,
                          "%s: %s" % (__name__,
                                      result.get("error").get("message")))

        return rval

    def u2f_challenge_response(self, transaction_id, message, attributes):
        rval = self.pamh.PAM_SYSTEM_ERR

        syslog.syslog(syslog.LOG_DEBUG, "Prompting for U2F authentication")

# In case of U2F "attributes" looks like this:
# {
#     "img": "static/css/FIDO-U2F-Security-Key-444x444.png#012",
#     "hideResponseInput" "1",
#     "u2fSignRequest": {
#         "challenge": "yji-PL1V0QELilDL3m6Lc-1yahpKZiU-z6ye5Zz2mp8",
#         "version": "U2F_V2",
#         "keyHandle": "fxDKTr6o8EEGWPyEyRVDvnoeA0c6v-dgvbN-6Mxc6XBmEItsw",
#         "appId": "https://172.16.200.138"
#     }
# }
        challenge = """
----- BEGIN U2F CHALLENGE -----
%s
%s
%s
----- END U2F CHALLENGE -----""" % (self.URL,
                                    json.dumps(attributes["u2fSignRequest"]),
                                    str(message or ""))

        if bool(attributes.get("hideResponseInput", True)):
            prompt_type = self.pamh.PAM_PROMPT_ECHO_OFF
        else:
            prompt_type = self.pamh.PAM_PROMPT_ECHO_ON

        message = self.pamh.Message(prompt_type, challenge)
        response = self.pamh.conversation(message)
        chal_response = json.loads(response.resp)

        data = {"user": self.user,
                "transaction_id": transaction_id,
                "pass": self.pamh.authtok,
                "signaturedata": chal_response.get("signatureData"),
                "clientdata": chal_response.get("clientData")}
        if self.realm:
            data["realm"] = self.realm

        json_response = self.make_request(data)

        result = json_response.get("result")
        detail = json_response.get("detail")

        if self.debug:
            syslog.syslog(syslog.LOG_DEBUG,
                          "%s: result: %s" % (__name__, result))
            syslog.syslog(syslog.LOG_DEBUG,
                          "%s: detail: %s" % (__name__, detail))

        if result.get("status"):
            if result.get("value"):
                rval = self.pamh.PAM_SUCCESS
            else:
                rval = self.pamh.PAM_AUTH_ERR
        else:
            syslog.syslog(syslog.LOG_ERR,
                          "%s: %s" % (__name__,
                                      result.get("error").get("message")))

        return rval


def pam_sm_authenticate(pamh, flags, argv):
    config = _get_config(argv)
    debug = config.get("debug")
    try_first_pass = config.get("try_first_pass")
    prompt = config.get("prompt", "Your OTP")
    grace_time = config.get("grace")
    if prompt[-1] != ":":
        prompt += ":"
    rval = pamh.PAM_AUTH_ERR
    syslog.openlog(facility=syslog.LOG_AUTH)

    Auth = Authenticator(pamh, config)
    try:

        if grace_time is not None:
            syslog.syslog(syslog.LOG_DEBUG, "Grace period in minutes: %s " % (str(grace_time)))
            # First we try to check if grace is authorized
            if check_last_history(Auth.sqlfile, Auth.user, grace_time, window=10):
                rval = pamh.PAM_SUCCESS

        if rval != pamh.PAM_SUCCESS:
            if pamh.authtok is None or not try_first_pass:
                message = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "%s " % prompt)
                response = pamh.conversation(message)
                pamh.authtok = response.resp

            if debug and try_first_pass:
                syslog.syslog(syslog.LOG_DEBUG, "%s: running try_first_pass" %
                              __name__)
            rval = Auth.authenticate(pamh.authtok)

            # If the first authentication did not succeed but we have
            # try_first_pass, we ask again for a password:
            if rval != pamh.PAM_SUCCESS and try_first_pass:
                # Now we give it a second try:
                message = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "%s " % prompt)
                response = pamh.conversation(message)
                pamh.authtok = response.resp

                rval = Auth.authenticate(pamh.authtok)

    except Exception as exx:
        syslog.syslog(syslog.LOG_ERR, traceback.format_exc())
        syslog.syslog(syslog.LOG_ERR, "%s: %s" % (__name__, exx))
        rval = pamh.PAM_AUTH_ERR
    except requests.exceptions.SSLError:
        syslog.syslog(syslog.LOG_CRIT, "%s: SSL Validation error. Get a valid "
                                       "SSL certificate for your privacyIDEA "
                                       "system. For testing you can use the "
                                       "options 'nosslverify'." % __name__)
    finally:
        syslog.closelog()

    return rval


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def check_offline_otp(user, otp, sqlfile, window=10, refill=True):
    """
    compare the given otp values with the next hashes of the user.

    DB entries older than the matching counter will be deleted from the
    database.

    :param user: The local user in the sql file
    :param otp: The otp value
    :param sqlfile: The sqlite file
    :return: Tuple of (True or False, serial)
    """
    res = False
    conn = sqlite3.connect(sqlfile)
    c = conn.cursor()
    _create_table(c)
    # get all possible serial/tokens for a user
    serials = []
    matching_serial = None
    for row in c.execute("SELECT serial, user FROM authitems WHERE user=?"
                         "GROUP by serial", (user,)):
        serials.append(row[0])

    for serial in serials:
        for row in c.execute("SELECT counter, user, otp, serial FROM authitems "
                             "WHERE user=? and serial=? ORDER by counter "
                             "LIMIT ?",
                             (user, serial, window)):
            hash_value = row[2]
            if passlib.hash.pbkdf2_sha512.verify(otp, hash_value):
                res = True
                matching_counter = row[0]
                matching_serial = serial
                break

    # We found a matching password, so we remove the old entries
    if res:
        c.execute("DELETE from authitems WHERE counter <= ? and serial = ?",
                  (matching_counter, matching_serial))
        conn.commit()
    conn.close()
    return res, matching_serial


def save_auth_item(sqlfile, user, serial, tokentype, authitem):
    """
    Save the given authitem to the sqlite file to be used later for offline
    authentication.

    There is only one table in it with the columns:

        username, counter, otp

    :param sqlfile: An SQLite file. If it does not exist, it will be generated.
    :type sqlfile: basestring
    :param user: The PAM user
    :param serial: The serial number of the token
    :param tokentype: The type of the token
    :param authitem: A dictionary with all authitem information being:
    username, count, and a response dict with counter and otphash.

    :return:
    """
    conn = sqlite3.connect(sqlfile)
    c = conn.cursor()
    # Create the table if necessary
    _create_table(c)

    syslog.syslog(syslog.LOG_DEBUG, "%s: offline save authitem: %s" % (
        __name__, authitem))
    if authitem:
        offline = authitem.get("offline", [{}])[0]
        tokenowner = offline.get("username")
        for counter, otphash in offline.get("response").items():
            # Insert the OTP hash
            c.execute("INSERT INTO authitems (counter, user, serial,"
                      "tokenowner, otp) VALUES (?,?,?,?,?)",
                      (counter, user, serial, tokenowner, otphash))

        refilltoken = offline.get("refilltoken")
        # delete old refilltoken
        try:
            c.execute('DELETE FROM refilltokens WHERE serial=?', (serial,))
        except sqlite3.OperationalError:
            pass
        c.execute("INSERT INTO refilltokens (serial, refilltoken) VALUES (?,?)",
                  (serial, refilltoken))

    # Save (commit) the changes
    conn.commit()

    # We can also close the connection if we are done with it.
    # Just be sure any changes have been committed or they will be lost.
    conn.close()

def check_last_history(sqlfile, user, grace_time, window=10):
    """
    Get the last event for this user.

    If success reset the error counter.
    If error increment the error counter.

    :param sqlfile: An SQLite file. If it does not exist, it will be generated.
    :type sqlfile: basestring
    :param user: The PAM user
    :param serial: The serial number of the token
    :param success: Boolean

    :return:
    """
    conn = sqlite3.connect(sqlfile, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    # Create the table if necessary
    _create_table(c)

    res = False
    events = []

    for row in c.execute("SELECT user, serial, last_success, last_error FROM history "
                         "WHERE user=? ORDER by last_success "
                         "LIMIT ?",
                         (user, window)):
        events.append(row)

    if len(events)>0:
        for event in events:
            last_success = event[2]
            if last_success is not None:
                # Get the elapsed time in minutes since last success
                last_success_delta = datetime.datetime.now() - last_success
                delta = last_success_delta.seconds / 60 + last_success_delta.days * 1440
                if delta < int(grace_time):
                    syslog.syslog(syslog.LOG_DEBUG, "%s: Last success : %s , was %s minutes ago "
                            "and in the grace period" % (
                            __name__, str(last_success), str(delta)))
                    res = True
                    break

            else:
                syslog.syslog(syslog.LOG_DEBUG, "%s: No last success recorded: %s" % (
                    __name__, user))
    else:
        syslog.syslog(syslog.LOG_DEBUG, "%s: No history for: %s" % (
            __name__, user))


    conn.close()
    return res


def save_history_item(sqlfile, user, serial, success):
    """
    Save the given success/error event.

    If success reset the error counter.
    If error increment the error counter.

    :param sqlfile: An SQLite file. If it does not exist, it will be generated.
    :type sqlfile: basestring
    :param user: The PAM user
    :param serial: The serial number of the token
    :param success: Boolean

    :return:
    """
    conn = sqlite3.connect(sqlfile, detect_types=sqlite3.PARSE_DECLTYPES)
    c = conn.cursor()
    # Create the table if necessary
    _create_table(c)

    syslog.syslog(syslog.LOG_DEBUG, "%s: offline save event: %s" % (
        __name__, ("success" if success else "error")))
    if success:
        # Insert the Event
        c.execute("INSERT OR REPLACE INTO history (user, serial,"
                  "error_counter, last_success) VALUES (?,?,?,?)",
                  (user, serial, 0, datetime.datetime.now()))
    else:
        # Insert the Event
        c.execute("UPDATE history SET error_counter = error_counter + 1, "
                    " serial = ? , last_error = ? "
                    " WHERE user = ? ",
                  (serial, datetime.datetime.now(), user))

        syslog.syslog(syslog.LOG_DEBUG,"Rows affected : %d " % c.rowcount)
        if c.rowcount == 0:
            c.execute("INSERT INTO history (user, serial,"
                      "error_counter, last_error) VALUES (?,?,?,?)",
                      (user, serial, 1, datetime.datetime.now()))


    # Save (commit) the changes
    conn.commit()

    # We can also close the connection if we are done with it.
    # Just be sure any changes have been committed or they will be lost.
    conn.close()


def _create_table(c):
    """
    Create table if necessary
    :param c: The connection cursor
    """
    try:
        c.execute("CREATE TABLE IF NOT EXISTS authitems "
                  "(counter int, user text, serial text, tokenowner text,"
                  "otp text, tokentype text)")
    except sqlite3.OperationalError:
        pass

    try:
        # create refilltokens table
        c.execute("CREATE TABLE IF NOT EXISTS refilltokens (serial text, refilltoken text)")
    except sqlite3.OperationalError:
        pass

    try:
        # create history table
        c.execute("CREATE TABLE IF NOT EXISTS history "
                  "(user text, serial text, error_counter int, "
                  "last_success timestamp, last_error timestamp)")
        c.execute("CREATE UNIQUE INDEX idx_user "
                    "ON history (user);")
    except sqlite3.OperationalError:
        pass

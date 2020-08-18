"""
This test tests the privacyidea_pam.py
"""
import json
import sqlite3
import responses
import unittest

from privacyidea_pam import (pam_sm_authenticate,
                             save_auth_item,
                             check_offline_otp)

REFILL_1 = "a" * 80
REFILL_2 = "b" * 80

SQLFILE = "pam-test.sqlite"
# test100000
# test100001
# test100002
RESP = {1: '$pbkdf2-sha512$19000$Scl5TwmhtPae856zFgJgLA$ZQAqtqmGTf6IY0t9jg2MCg'
           'd92XzxdijFcT4BNVsvONNpHwZkiKsHrf0oeckS8rRQ9KWBdMwZsQzhu8PkpyXnbA',
        2: '$pbkdf2-sha512$19000$4Lx3bi1FiBHiXGutVYpRqg$9mPHGSh1Ylz0PTEMwJKFw'
           '6tB.avOfYhqJsEnl3KMF8vIE//YUrtwNs4IN6ZU4OeoxFZejebOTtxt8wZjp4140w',
        3: '$pbkdf2-sha512$19000$JATgHGNsDSEEIGRMqXXOmQ$Ub67KeNbwObsFk7mwTetNf'
           'lwTOEKXMzJ5BTblZsu3bV4KAP1rEW6nUPfqLf6/f2yoNhpX1mCS3dt77EBKtJM.A'
}

# test100003
# test100004
REFILL_RESP = {
    4: '$pbkdf2-sha512$25000$SSlF6L2XUurdG.N8LyVkTA$hDscUl2n5H84YjlE0Z8I94Y'
       'R0NiCcCrI2weuFPR7XID6mxSzbZOTwMAeYCMPKPritj/VwZAenosNWGhByi16Ng',
    5: '$pbkdf2-sha512$25000$NWYMAeDcuzfGOGds7Z1zLg$wOYEQApbmRMVjmEv1hLqi.n'
       '4ZeSG0AsSIEIR7TqVuwL64XM0yePEqOn/ur7mOWzuo5ak.vZgwQeHwYM71Cjlfw',
}


# TEST100000
# TEST100001
# TEST100002
RESP2 = {1: '$pbkdf2-sha512$19000$DgGA0FrL2ZsTIuS8txYCoA$HAAMTr34j5pMwMA9XZ'
            'euNtNbvHklY0axMKlceqdaCfYzdml9MBH05tgZqvrQToYqCHPDQoBD.GH5/UGvs'
            '7HF4g',
         2: '$pbkdf2-sha512$19000$wfifc07p3dvb.1.LcU6ptQ$NmnYnWMMc9KuCSDG5I'
            'f94qGTmLekRF7Fn9rE4nDxCGuaXBasvEuIyEdp.h2RNqvjbsFd6A/U1T5/9eMC/'
            '7v9GQ',
         3: '$pbkdf2-sha512$19000$53zvvddai/He'
            '.x9DyJnTGg$aUapWKcp21B2eSQzVVKtv9e.9Xs3aoNxg30dgU6TjyzaaHZcUNpvz'
            '7Cqj6yeTFYi1nzQ151I2z8sZWjln1fyag'
}



SUCCESS_BODY = {"detail": {"message": "matching 1 tokens",
                           "serial": "PISP0000AB00",
                           "type": "spass"},
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"status": True,
                           "value": True
                },
                "auth_items": {"offline": [{"refilltoken": REFILL_1,
                                            "username": "corny",
                                            "response": RESP}
                ]
                },
                "version": "privacyIDEA unknown"
}

REFILL_BODY = { "id": 1,
                "jsonrpc": "2.0",
                "result": {"status": True,
                           "value": True
                },
                "auth_items": {"offline": [{"refilltoken": REFILL_2,
                                            "username": "corny",
                                            "response": REFILL_RESP}
                ]
                },
                "version": "privacyIDEA unknown"
}

FAIL_BODY = {"detail": {"message": "wrong otp value"},
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"status": True,
                           "value": False
                },
                "version": "privacyIDEA unknown"
}

USER_TOKEN_BODY = { "id": 1,
                    "jsonrpc": "2.0",
                    "result": {"status": True,
                               "value": {
                                    "count" : 1
                               }
                    }
}

class PAMH(object):

    PAM_AUTH_ERR = 0
    PAM_SUCCESS = 1
    PAM_SYSTEM_ERR = 2
    PAM_AUTHINFO_UNAVAIL = 3

    PAM_PROMPT_ECHO_OFF = 11
    PAM_PROMPT_ECHO_ON = 12
    PAM_ERROR_MSG = 13
    PAM_TEXT_INFO = 14

    exception = Exception

    def __init__(self, user, password, rhost, keyboard_interactive=True):
        self.authtok = password
        self.user = user
        self.rhost = user
        self.keyboard_interactive = keyboard_interactive

    def get_user(self, dummy):
        return self.user

#     def Message(self, prompt_type, prompt):
#         return prompt
#
#     def conversation(self, message):
#         if message == " ":
#             return Response(None if self.keyboard_interactive else '')
#
# class Response(object):
#
#     def __init__(self, resp, ret_code = 0):
#         self.resp = resp
#         self.ret_code = ret_code


class PAMTestCase(unittest.TestCase):

    @staticmethod
    def setUpClass():
        conn = sqlite3.connect(SQLFILE)
        c = conn.cursor()
        try:
            c.execute("DROP table authitems")
            conn.commit()
        except Exception:
            print("No need to drop table authitems.")
        conn.close()

    def test_01_check_offline_otp(self):
        # Check with no entries in the database
        r, matching_serial = check_offline_otp("cornelius", "test123456", SQLFILE)
        self.assertFalse(r)
        self.assertIsNone(matching_serial)

        # Save some values to the database
        r = save_auth_item(SQLFILE,
                           "cornelius",
                           "TOK001",
                           "HOTP",
                           {"offline": [{"username": "corny",
                                         "response": RESP}
                           ]
                           })
        r, matching_serial = check_offline_otp("cornelius", "test100000", SQLFILE)
        self.assertTrue(r)
        self.assertEqual(matching_serial, "TOK001")
        # Authenticating with the same value a second time, fails
        r, matching_serial = check_offline_otp("cornelius", "test100000", SQLFILE)
        self.assertFalse(r)
        self.assertIsNone(matching_serial)

    @responses.activate
    def test_02_authenticate_offline(self):
        responses.add(responses.GET,
                      "http://my.privacyidea.server/token",
                      body=json.dumps(USER_TOKEN_BODY),
                      content_type="application/json")
        responses.add(responses.POST,
                      "http://my.privacyidea.server/validate/check",
                      body=json.dumps(SUCCESS_BODY),
                      content_type="application/json")

        pamh = PAMH("cornelius", "test100001", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertEqual(r, PAMH.PAM_SUCCESS)

        # Authenticate the second time offline
        pamh = PAMH("cornelius", "test100002", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertEqual(r, PAMH.PAM_SUCCESS)

        # Now there are no offline values left

    @responses.activate
    def test_03_authenticate_online(self):
        # authenticate online and fetch offline values
        responses.add(responses.GET,
                      "http://my.privacyidea.server/token",
                      body=json.dumps(USER_TOKEN_BODY),
                      content_type="application/json")
        responses.add(responses.POST,
                      "http://my.privacyidea.server/validate/check",
                      body=json.dumps(SUCCESS_BODY),
                      content_type="application/json")
        pamh = PAMH("cornelius", "test999999", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertTrue(r)
        # Now the offlne values are stored

    def test_04_authenticate_offline(self):
        # and authenticate offline again.
        pamh = PAMH("cornelius", "test100000", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertTrue(r)

    def test_05_two_tokens(self):
        # Save some values to the database
        r = save_auth_item(SQLFILE,
                           "cornelius",
                           "TOK001",
                           "HOTP",
                           {"offline": [{"username": "corny",
                                         "response": RESP}
                           ]
                           })
        r = save_auth_item(SQLFILE,
                           "cornelius",
                           "TOK002",
                           "HOTP",
                           {"offline": [{"username": "corny",
                                         "response": RESP2}
                           ]
                           })

        pamh = PAMH("cornelius", "test100001", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertEqual(r, PAMH.PAM_SUCCESS)

        # An older OTP value of the first token is deleted
        pamh = PAMH("cornelius", "test100000", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertNotEqual(r, PAMH.PAM_SUCCESS)

        # An older value with another token can authenticate!
        pamh = PAMH("cornelius", "TEST100000", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertEqual(r, PAMH.PAM_SUCCESS)

    def test_06_refill(self):
        with responses.RequestsMock() as rsps:
            # Get offline OTPs + refill token
            rsps.add(responses.POST,
                          "http://my.privacyidea.server/validate/check",
                          body=json.dumps(SUCCESS_BODY),
                          content_type="application/json")

            pamh = PAMH("cornelius", "test100000", "192.168.0.1")
            flags = None
            argv = ["url=http://my.privacyidea.server",
                    "sqlfile=%s" % SQLFILE,
                    "try_first_pass"]
            r = pam_sm_authenticate(pamh, flags, argv)
            self.assertEqual(r, PAMH.PAM_SUCCESS)

        # OTP value not known yet, online auth does not work
        pamh = PAMH("cornelius", "test100004", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertNotEqual(r, PAMH.PAM_SUCCESS)

        # now with refill
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST,
                          "http://my.privacyidea.server/validate/offlinerefill",
                          body=json.dumps(REFILL_BODY),
                          content_type="application/json")

            pamh = PAMH("cornelius", "test100001", "192.168.0.1")
            flags = None
            argv = ["url=http://my.privacyidea.server",
                    "sqlfile=%s" % SQLFILE,
                    "try_first_pass"]
            r = pam_sm_authenticate(pamh, flags, argv)
            self.assertEqual(r, PAMH.PAM_SUCCESS)

            self.assertIn('refilltoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                          rsps.calls[0].request.body)

        # authenticate with refilled
        with responses.RequestsMock() as rsps:
            pamh = PAMH("cornelius", "test100004", "192.168.0.1")
            flags = None
            argv = ["url=http://my.privacyidea.server",
                    "sqlfile=%s" % SQLFILE,
                    "try_first_pass"]
            r = pam_sm_authenticate(pamh, flags, argv)
            self.assertEqual(r, PAMH.PAM_SUCCESS)

            # using new refill token
            self.assertIn('refilltoken=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                          rsps.calls[0].request.body)

        # ... but not twice
        pamh = PAMH("cornelius", "test100004", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertNotEqual(r, PAMH.PAM_SUCCESS)

    def test_07_password_auth(self):
        # Authenticator will return PAM_AUTHINFO_UNAVAIL during password auth
        pamh = PAMH("cornelius", "test100007", "192.168.0.1")
        flags = None
        argv = ["url=http://my.privacyidea.server",
                "sqlfile=%s" % SQLFILE,
                "try_first_pass"]
        r = pam_sm_authenticate(pamh, flags, argv)
        self.assertEqual(r, PAMH.PAM_AUTHINFO_UNAVAIL)

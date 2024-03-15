> **Note**
> This repository is archived and not under active development.
>
> While the `pam_python` library seems to support Python 3 now, it is not 
> included in major distributions anymore.
>
> If You do not need the offline functionality, please use 
> [`pam_radius`](https://github.com/FreeRADIUS/pam_radius)


This module is to be used with http://pam-python.sourceforge.net/.
It can be used to authenticate with OTP against privacyIDEA. It will also
cache future OTP values to enable offline authentication.

To be used like this::

   auth   requisite    pam_python.so /path/to/modules/privacyidea-pam.py

It can take the following parameters:

**url=https://your-server**

   default is https://localhost

**debug**

   write debug information to the system log

**realm=yourRealm**

   pass additional realm to privacyidea

**nosslverify**

   Do not verify the SSL certificate

**prompt=<Prompt>**

   The password prompt. Default is "Your OTP".

**api_token=<token>**

   The API Token to access admin REST API for auto-enrollment.

**sqlfile=<file>**

   This is the SQLite file that is used to store the offline authentication
   information.
   The default file is /etc/privacyidea/pam.sqlite

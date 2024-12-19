-----FEATUTES TRIED-----
1) MFA using twilio
2) RBAC -> created a util function called role_required in utils.py & used it as a decorator before calling any view function with input as allowed roles to it.
3) HTTP->HTTPS -> used runserver_plus in local along with open ssl certificates
4) file sharing-> a token is generated as you tried to share file link.
5) File encryption & decryption is done using Fernet Cryptographic libarary.

-----How To RUN-----
1) Clone the repository
2) create a virtual environment
3) openssl may be required to install depending on system (mostly it will not be needed)
4) pip install -r requirements.txt
5) python manage.py runsever_plus --cert-file cert.pem --key-file key.pem
6) Test using curl commands

-------NOTE------
1) Create .env file & use your own twilio credentials
1) For variable you can refer to line 95 of settings.py


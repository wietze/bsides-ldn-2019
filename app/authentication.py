import binascii
import os

from plugins.adversary.app.engine.database import subjectify
from plugins.adversary.app.engine.objects import SiteUser
from plugins.adversary.app.util import tz_utcnow
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

_backend = default_backend()

max_age = 60*60*24*1  # good for 1 day


class NotAuthorized(Exception):
    pass


class Token(object):
    def __init__(self, session_blob, auth_key):
        self._blob = session_blob
        self.auth_key = auth_key

        if self._blob is None:
            raise NotAuthorized
        try:
            s = URLSafeTimedSerializer(self.auth_key)
            self.session_info = s.loads(self._blob, max_age=max_age)
        except (BadSignature, SignatureExpired, UnicodeDecodeError, binascii.Error):
            raise NotAuthorized

    def require_group(self, g):
        if g not in self.session_info['groups']:
            raise NotAuthorized()

    def in_group(self, g):
        return g in self.session_info['groups']


def login_generic(auth_key, groups, attrs) -> str:
    serializer = URLSafeTimedSerializer(auth_key)
    temp = attrs.copy()
    temp.update({'groups': groups})
    return serializer.dumps(subjectify(temp))


def register_user(username, groups, email=None, password=None):
    salt, key = _create_hash(password.encode())
    return SiteUser(username=username, password=key, salt=salt, groups=groups, email=email).save()


def login_user(username, password) -> str:
    try:
        site_user = SiteUser.objects.get(username=username)
    except SiteUser.DoesNotExist:
        return False

    if not _verify(password.encode(), site_user.password, site_user.salt):
        return False
    site_user.update(last_login=tz_utcnow())
    return True


def username_exists(username: str):
    try:
        SiteUser.objects.get(username=username)
        return True
    except SiteUser.DoesNotExist:
        return False


def _verify(glob, key, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=_backend)
    try:
        kdf.verify(glob, key)
        return True
    except InvalidKey:
        return False


def _create_hash(glob):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=_backend)
    return salt, kdf.derive(glob)
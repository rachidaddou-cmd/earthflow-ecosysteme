# Copyright 2025 DJAM Foundation / IA Commune Algeria
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""core/crypto.py — Encryption, key derivation, and HMAC signing."""
import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EarthflowCrypto:
    def __init__(self, master_key: bytes = None):
        if master_key is None:
            master_key = Fernet.generate_key()
        self.master_key = master_key
        self._fernet = Fernet(master_key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode()).decode()

    def rotate_key(self) -> bytes:
        new_key = Fernet.generate_key()
        self.master_key = new_key
        self._fernet = Fernet(new_key)
        return new_key

    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def sign(self, data: str, secret: str) -> str:
        return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()

    def verify_signature(self, data: str, signature: str, secret: str) -> bool:
        return hmac.compare_digest(self.sign(data, secret), signature)

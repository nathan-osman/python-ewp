from os import path
from subprocess import PIPE, Popen
from unittest import TestCase

from ewp import encrypt, sign


class EWPTestCast(TestCase):
    """
    Verify the cryptographic output of sign() and encrypt().
    """

    def setUp(self):
        self._key_fn = path.join(path.dirname(__file__), 'data', 'test.key')
        self._cert_fn = path.join(path.dirname(__file__), 'data', 'test.crt')

    def test_sign(self):
        """
        Use OpenSSL to verify the signature.
        """
        signature = sign(self._key_fn, self._cert_fn, 'test')
        p = Popen(
            ['openssl', 'smime', '-verify', '-inform', 'DER', '-noverify'],
            stdin=PIPE,
        )
        p.communicate(signature)
        self.assertEqual(p.returncode, 0)

    def test_encrypt(self):
        """
        Use OpenSSL to decrypt the ciphertext.
        """
        plaintext = 'test'
        ciphertext = encrypt(self._cert_fn, plaintext)
        p = Popen(
            ['openssl', 'smime', '-decrypt', '-inform', 'DER', '-inkey', self._key_fn],
            stdin=PIPE,
            stdout=PIPE,
        )
        stdout, _ = p.communicate(ciphertext)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(stdout, plaintext)

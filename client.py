## Demonstrates certain parts of accessing (and decoding/decrypting)
## data stored by Firefox Sync ("Weave") from Python
##
##
## (c) 2011 Ivo van der Wijk, m3r consultancy. See LICENSE for licensing 
## details
import requests ## easy_install this
import json
import base64
import hashlib
import hmac
from M2Crypto.EVP import Cipher

class SyncSample(object):
    server = "https://auth.services.mozilla.com"
    api = "1.0"
    HMAC_INPUT = "Sync-AES_256_CBC-HMAC256"

    def __init__(self, username, password, passphrase):
        self.username = self.encode_username(username)
        self._password =  password
        self.passphrase = self.decode_passphrase(passphrase)
        self.node = self.get_node().rstrip('/')
        self.encryption_key = self.hmac_sha256(self.passphrase, "%s%s\x01" % (self.HMAC_INPUT, self.username))
        self.get_key()

    def get_node(self):
        url = self.server + '/user/1.0/' + self.username + '/node/weave'
        r = requests.get(url, auth=(self.username, self._password))
        return r.read()
        
    def get(self, path):
        url = '/'.join((self.node, self.api, self.username, path))
        r = requests.get(url, auth=(self.username, self._password))
        return json.loads(r.read())

    def get_meta(self):
        data = self.get('storage/meta/global')
        payload = json.loads(data['payload'])
        return payload

    def cipher_decrypt(self, ciphertext, key, IV):
        cipher = Cipher(alg='aes_256_cbc', key=key, iv=IV, op=0)
        v = cipher.update(ciphertext)
        v = v + cipher.final()
        del cipher
        return json.loads(v)

    def get_key(self):
        data = self.get("storage/crypto/keys")
        payload = json.loads(data['payload'])
        ciphertext = payload['ciphertext'].decode("base64")
        IV = payload['IV'].decode("base64")
        hmac = payload['hmac'].decode("base64")
        
        default = self.cipher_decrypt(ciphertext, self.encryption_key, IV)['default']
        self.privkey = default[0].decode("base64")
        self.privhmac = default[1].decode("base64")

    def decrypt(self, data):
        ciphertext = data['ciphertext'].decode("base64")
        IV = data['IV'].decode("base64")
        hmac = data['hmac'].decode("base64")

        return self.cipher_decrypt(ciphertext, self.privkey, IV)

    def bookmarks(self):
        d = self.get("storage/bookmarks")
        return d 

    def passwords(self):
        d = self.get("storage/passwords?full=1")
        res = []
        for p in d:
            payload = json.loads(p['payload'])
            res.append( self.decrypt(payload))
        return res

    def bookmark(self, id):
        # url = "storage/bookmarks?ids=%s" % urllib.quote(','.join(ids))
        d = self.get("storage/bookmarks/%s" % id)
        payload = json.loads(d['payload'])
        return self.decrypt(payload)

    @staticmethod
    def encode_username(u):
        return base64.b32encode(hashlib.sha1(u).digest()).lower()

    @staticmethod
    def hmac_sha256(key, s):
        return hmac.new(key, s, hashlib.sha256).digest()

    @staticmethod
    def decode_passphrase(p):
        def denormalize(k):
            """ transform x-xxxxx-xxxxx etc into something b32-decodable """
            tmp = k.replace('-', '').replace('8', 'l').replace('9', 'o').upper()
            padding = (8-len(tmp) % 8) % 8
            return tmp + '=' * padding
        return base64.b32decode(denormalize(p))

if __name__ == '__main__':
    username = "user@bla"
    password = "secret"
    passphrase = "a-abcde-12345-abcde-12345-abcde"

    try:
        from credentials import *
    except ImportError:
        pass

    s = SyncSample(username, password, passphrase)
    meta = s.get_meta()
    assert meta['storageVersion'] == 5

    import pprint
    pprint.pprint(meta)
    # ids = s.bookmarks()
    # for id in ids[:3]:
    #     pprint.pprint(s.bookmark(id))
    passwords = s.passwords()
    pprint.pprint(passwords)

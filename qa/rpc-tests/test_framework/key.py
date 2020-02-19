# Copyright (c) 2011 Sam Rushing
#
# key.py - OpenSSL wrapper
#
# This file is modified from python-bitcoinlib.
#

"""ECC secp256k1 crypto routines

WARNING: This module does not mlock() secrets; your private keys may end up on
disk in swap! Use with caution!
"""

import ctypes
import ctypes.util
import hashlib
import sys
import struct
import ecdsa
from test_framework.util import bytes_to_hex_str, reverse


SECP256K1_MODULE = None
SECP256K1_AVAILABLE = False
CRYPTOGRAPHY_AVAILABLE = False
GMPY2_MODULE = False
if not SECP256K1_MODULE:  # pragma: no branch
    try:
        import secp256k1
        SECP256K1_MODULE = "secp256k1"
        SECP256K1_AVAILABLE = True
    except ImportError:
        try:
            import cryptography
            SECP256K1_MODULE = "cryptography"
            CRYPTOGRAPHY_AVAILABLE = True
        except ImportError:
            SECP256K1_MODULE = "ecdsa"

    try:  # pragma: no branch
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils \
            import decode_dss_signature, encode_dss_signature
        from cryptography.exceptions import InvalidSignature
        CRYPTOGRAPHY_AVAILABLE = True
    except ImportError:
        CRYPTOGRAPHY_AVAILABLE = False
        print("Cryptography not available")

print("Using SECP256K1 module: {}".format(SECP256K1_MODULE))



ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library ('ssl') or 'libeay32')

ssl.BN_new.restype = ctypes.c_void_p
ssl.BN_new.argtypes = []

ssl.BN_bin2bn.restype = ctypes.c_void_p
ssl.BN_bin2bn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]

ssl.BN_CTX_free.restype = None
ssl.BN_CTX_free.argtypes = [ctypes.c_void_p]

ssl.BN_CTX_new.restype = ctypes.c_void_p
ssl.BN_CTX_new.argtypes = []

ssl.ECDH_compute_key.restype = ctypes.c_int
ssl.ECDH_compute_key.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

ssl.ECDSA_sign.restype = ctypes.c_int
ssl.ECDSA_sign.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

ssl.ECDSA_verify.restype = ctypes.c_int
ssl.ECDSA_verify.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]

ssl.EC_KEY_free.restype = None
ssl.EC_KEY_free.argtypes = [ctypes.c_void_p]

ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]

ssl.EC_KEY_get0_group.restype = ctypes.c_void_p
ssl.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]

ssl.EC_KEY_get0_public_key.restype = ctypes.c_void_p
ssl.EC_KEY_get0_public_key.argtypes = [ctypes.c_void_p]

ssl.EC_KEY_set_private_key.restype = ctypes.c_int
ssl.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

ssl.EC_KEY_set_conv_form.restype = None
ssl.EC_KEY_set_conv_form.argtypes = [ctypes.c_void_p, ctypes.c_int]

ssl.EC_KEY_set_public_key.restype = ctypes.c_int
ssl.EC_KEY_set_public_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

ssl.i2o_ECPublicKey.restype = ctypes.c_void_p
ssl.i2o_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

ssl.EC_POINT_new.restype = ctypes.c_void_p
ssl.EC_POINT_new.argtypes = [ctypes.c_void_p]

ssl.EC_POINT_free.restype = None
ssl.EC_POINT_free.argtypes = [ctypes.c_void_p]

ssl.EC_POINT_mul.restype = ctypes.c_int
ssl.EC_POINT_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

ssl.EC_KEY_get_conv_form.restype = ctypes.c_int
ssl.EC_KEY_get_conv_form.argtypes = [ctypes.c_void_p]

ssl.EC_KEY_get0_private_key.restype = ctypes.c_void_p
ssl.EC_KEY_get0_private_key.argtypes = [ctypes.c_void_p]

ssl.BN_bn2bin.restype = ctypes.c_int
ssl.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


# this specifies the curve used with ECDSA.
NID_secp256k1 = 714 # from openssl/obj_mac.h

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_ORDER_HALF = SECP256K1_ORDER // 2

# Thx to Sam Devlin for the ctypes magic 64-bit fix.
def _check_result(val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p (val)

ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.errcheck = _check_result

class CECKey(object):
    """Wrapper around OpenSSL's EC_KEY"""

    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    def __init__(self):
        self.k = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)

    def __del__(self):
        if ssl:
            ssl.EC_KEY_free(self.k)
        self.k = None

    def set_secretbytes(self, secret):
        priv_key = ssl.BN_bin2bn(secret, 32, ssl.BN_new())
        group = ssl.EC_KEY_get0_group(self.k)
        pub_key = ssl.EC_POINT_new(group)
        ctx = ssl.BN_CTX_new()
        if not ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx):
            raise ValueError("Could not derive public key from the supplied secret.")
        ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
        ssl.EC_KEY_set_private_key(self.k, priv_key)
        ssl.EC_KEY_set_public_key(self.k, pub_key)
        ssl.EC_POINT_free(pub_key)
        ssl.BN_CTX_free(ctx)
        return self.k

    def set_privkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return ssl.d2i_ECPrivateKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def set_pubkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def get_privkey(self):
        size = ssl.i2d_ECPrivateKey(self.k, 0)
        mb_pri = ctypes.create_string_buffer(size)
        ssl.i2d_ECPrivateKey(self.k, ctypes.byref(ctypes.pointer(mb_pri)))
        return mb_pri.raw

    def get_pubkey(self):
        size = ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def get_raw_ecdh_key(self, other_pubkey):
        ecdh_keybuffer = ctypes.create_string_buffer(32)
        r = ssl.ECDH_compute_key(ctypes.pointer(ecdh_keybuffer), 32,
                                 ssl.EC_KEY_get0_public_key(other_pubkey.k),
                                 self.k, 0)
        if r != 32:
            raise Exception('CKey.get_ecdh_key(): ECDH_compute_key() failed')
        return ecdh_keybuffer.raw

    def get_ecdh_key(self, other_pubkey, kdf=lambda k: hashlib.sha256(k).digest()):
        # FIXME: be warned it's not clear what the kdf should be as a default
        r = self.get_raw_ecdh_key(other_pubkey)
        return kdf(r)

    def sign(self, hash, low_s = True):
        # FIXME: need unit tests for below cases
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        sig_size0 = ctypes.c_uint32()
        sig_size0.value = ssl.ECDSA_size(self.k)
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = ssl.ECDSA_sign(0, hash, len(hash), mb_sig, ctypes.byref(sig_size0), self.k)
        assert 1 == result
        assert mb_sig.raw[0] == 0x30
        assert mb_sig.raw[1] == sig_size0.value - 2
        total_size = mb_sig.raw[1]
        assert mb_sig.raw[2] == 2
        r_size = mb_sig.raw[3]
        assert mb_sig.raw[4 + r_size] == 2
        s_size = mb_sig.raw[5 + r_size]
        s_value = int.from_bytes(mb_sig.raw[6+r_size:6+r_size+s_size], byteorder='big')
        if (not low_s) or s_value <= SECP256K1_ORDER_HALF:
            return mb_sig.raw[:sig_size0.value]
        else:
            low_s_value = SECP256K1_ORDER - s_value
            low_s_bytes = (low_s_value).to_bytes(33, byteorder='big')
            while len(low_s_bytes) > 1 and low_s_bytes[0] == 0 and low_s_bytes[1] < 0x80:
                low_s_bytes = low_s_bytes[1:]
            new_s_size = len(low_s_bytes)
            new_total_size_byte = (total_size + new_s_size - s_size).to_bytes(1,byteorder='big')
            new_s_size_byte = (new_s_size).to_bytes(1,byteorder='big')
            return b'\x30' + new_total_size_byte + mb_sig.raw[2:5+r_size] + new_s_size_byte + low_s_bytes

    def verify(self, hash, sig):
        """Verify a DER signature"""
        return ssl.ECDSA_verify(0, hash, len(hash), sig, len(sig), self.k) == 1

    def set_compressed(self, compressed):
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        ssl.EC_KEY_set_conv_form(self.k, form)

    def is_compressed(self):
        form = ssl.EC_KEY_get_conv_form(self.k)
        assert(form == self.POINT_CONVERSION_COMPRESSED or form == self.POINT_CONVERSION_UNCOMPRESSED)
        return True if form == self.POINT_CONVERSION_COMPRESSED else False

    def get_secret(self):
        bn = ssl.EC_KEY_get0_private_key(self.k)
        mb = ctypes.create_string_buffer(32)
        len = ssl.BN_bn2bin(bn, mb)
        assert (len >= 0 and len <= 32)
        buffer = b'\0' * (32 - len) + mb.raw
        return buffer[0:32]


class CPubKey(bytes):
    """An encapsulated public key

    Attributes:

    is_valid      - Corresponds to CPubKey.IsValid()
    is_fullyvalid - Corresponds to CPubKey.IsFullyValid()
    is_compressed - Corresponds to CPubKey.IsCompressed()
    """

    def __new__(cls, buf, _cec_key=None):
        self = super(CPubKey, cls).__new__(cls, buf)
        if _cec_key is None:
            _cec_key = CECKey()
        self._cec_key = _cec_key
        self.is_fullyvalid = _cec_key.set_pubkey(self) != 0
        return self

    @property
    def is_valid(self):
        return len(self) > 0

    @property
    def is_compressed(self):
        return len(self) == 33

    def verify(self, hash, sig):
        return self._cec_key.verify(hash, sig)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        # Always have represent as b'<secret>' so test cases don't have to
        # change for py2/3
        if sys.version > '3':
            return '%s(%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())
        else:
            return '%s(b%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())



def verify_secp256k1_module_found():
    if SECP256K1_MODULE != "secp256k1":
        raise AssertionError("secp256k1 module is not found. Type 'pip3 install secp256k1'")


def _is_canonical(sig):
    sig = bytearray(sig)
    return (not (int(sig[0]) & 0x80) and
            not (sig[0] == 0 and not (int(sig[1]) & 0x80)) and
            not (int(sig[32]) & 0x80) and
            not (sig[32] == 0 and not (int(sig[33]) & 0x80)))


def sign_compact(digest, priv_key):
    """ Sign a digest with a priv_key key
        :param priv_key: Private key in
    """
    if not isinstance(priv_key, (bytes, bytearray)):
        raise AssertionError('priv_key must be in binary format')
    if len(priv_key) != 32:
        raise AssertionError('priv_key must be 32 bytes long ({} provided)'.format(len(priv_key)))

    verify_secp256k1_module_found()

    p = bytes(priv_key)
    ndata = secp256k1.ffi.new("const int *ndata")
    ndata[0] = 0
    while True:
        ndata[0] += 1
        privkey = secp256k1.PrivateKey(p, raw=True)
        sig = secp256k1.ffi.new('secp256k1_ecdsa_recoverable_signature *')
        signed = secp256k1.lib.secp256k1_ecdsa_sign_recoverable(
            privkey.ctx,
            sig,
            digest,
            privkey.private_key,
            secp256k1.ffi.NULL,
            ndata
        )
        if not signed == 1:
            raise AssertionError()
        signature, i = privkey.ecdsa_recoverable_serialize(sig)
        if _is_canonical(signature):
            i += 4  # compressed
            i += 27  # compact
            break

    # pack signature
    sigstr = struct.pack("<B", i)
    sigstr += signature
    return sigstr


def recover_public_key(digest, signature):
    """ Recover the public key from the the signature
    """
    verify_secp256k1_module_found()

    i = bytearray(signature)[0] - 4 - 27  # recover parameter only
    signature = signature[1:]
    # See http: //www.secg.org/download/aid-780/sec1-v2.pdf section 4.1.6 primarily
    curve = ecdsa.SECP256k1.curve
    G = ecdsa.SECP256k1.generator
    order = ecdsa.SECP256k1.order
    yp = (i % 2)
    r, s = ecdsa.util.sigdecode_string(signature, order)
    # 1.1
    x = r + (i // 2) * order
    # 1.3. This actually calculates for either effectively 02||X or 03||X depending on 'k' instead of always for 02||X as specified.
    # This substitutes for the lack of reversing R later on. -R actually is defined to be just flipping the y-coordinate in the elliptic curve.
    alpha = ((x * x * x) + (curve.a() * x) + curve.b()) % curve.p()
    beta = ecdsa.numbertheory.square_root_mod_prime(alpha, curve.p())
    y = beta if (beta - yp) % 2 == 0 else curve.p() - beta
    # 1.4 Constructor of Point is supposed to check if nR is at infinity.
    R = ecdsa.ellipticcurve.Point(curve, x, y, order)
    # 1.5 Compute e
    e = ecdsa.util.string_to_number(digest)
    # 1.6 Compute Q = r^-1(sR - eG)
    Q = ecdsa.numbertheory.inverse_mod(r, order) * (s * R + (-e % order) * G)

    if not ecdsa.VerifyingKey.from_public_point(Q, curve=ecdsa.SECP256k1).verify_digest(signature, digest, sigdecode=ecdsa.util.sigdecode_string):
        return None
    return ecdsa.VerifyingKey.from_public_point(Q, curve=ecdsa.SECP256k1)
    # TODO: convert to CPubKey class

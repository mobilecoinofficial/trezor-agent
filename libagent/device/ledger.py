"""Ledger-related code (see https://www.ledgerwallet.com/)."""

import binascii
import logging
import struct

from ledgerblue import comm  # pylint: disable=import-error

from .. import formats
from . import interface

log = logging.getLogger(__name__)


def _expand_path(path):
    """Convert BIP32 path into bytes."""
    return b''.join((struct.pack('>I', e) for e in path))


def _convert_public_key(ecdsa_curve_name, result):
    """Convert Ledger reply into PublicKey object."""
    if ecdsa_curve_name == 'nist256p1':
        if (result[64] & 1) != 0:
            result = bytearray([0x03]) + result[1:33]
        else:
            result = bytearray([0x02]) + result[1:33]
    else:
        result = result[1:]
        keyX = bytearray(result[0:32])
        keyY = bytearray(result[32:][::-1])
        if (keyX[31] & 1) != 0:
            keyY[31] |= 0x80
        result = b'\x00' + bytes(keyY)
    return bytes(result)


class LedgerNanoS(interface.Device):
    """Connection to Ledger Nano S device."""

    @classmethod
    def package_name(cls):
        """Python package name (at PyPI)."""
        return 'ledger-agent'

    def connect(self):
        """Enumerate and connect to the first USB HID interface."""
        try:
            return comm.getDongle()
        except comm.CommException as e:
            raise interface.NotFoundError(
                '{} not connected: "{}"'.format(self, e))

    def pubkey(self, identity, ecdh=False):
        """Get PublicKey object for specified BIP32 address and elliptic curve."""
        curve_name = identity.get_curve_name(ecdh)
        path = _expand_path(identity.get_bip32_address(ecdh))
        if curve_name == 'nist256p1':
            p2 = '01'
        else:
            p2 = '02'
        apdu = '800200' + p2
        apdu = binascii.unhexlify(apdu)
        apdu += bytearray([len(path) + 1, len(path) // 4])
        apdu += path
        log.debug('apdu: %r', apdu)
        result = bytearray(self.conn.exchange(bytes(apdu)))
        log.debug('result: %r', result)
        return formats.decompress_pubkey(
            pubkey=_convert_public_key(curve_name, result[1:]),
            curve_name=identity.curve_name)

    def sign(self, identity, blob):
        """Sign given blob and return the signature (as bytes)."""
        """Note (mc): The SSH/PGP Agent Ledger app an opcode for parsing and signing a ssh challenge as well as an opcode for just signing the blob. When the blob is 32 bytes, it is our Merlin transcript, so we ignore the ssh protocol marker in the identity (SSH challenges are never 32 bytes). This allows us to produce a direct ed25519 signature on a 32 byte blob."""
        path = _expand_path(identity.get_bip32_address(ecdh=False))
        # ins == 04 means to parse blob as an ssh challenges and sign
        # ins == 08 means to directly sign the blob
        # if the blob is 32 bytes, it is a MobileCoin Merlin Transcript and we should directly sign
        if identity.identity_dict['proto'] == 'ssh' and len(blob) != 32:
            ins = '04'
            p1 = '00'
        else:
            ins = '08'
            p1 = '00'
        if identity.curve_name == 'nist256p1':
            p2 = '81' if identity.identity_dict['proto'] == 'ssh' else '01'
        else:
            # p2 & 0x0f == 0x02 instructs to use ed25519
            # p2 & 0x80 is a key handling flag for ssh challenge parsing varient only
            p2 = '82' if (identity.identity_dict['proto'] == 'ssh' and len(blob) != 32) else '02'
        apdu = '80' + ins + p1 + p2
        apdu = binascii.unhexlify(apdu)
        apdu += bytearray([len(blob) + len(path) + 1])
        apdu += bytearray([len(path) // 4]) + path
        apdu += blob
        log.debug('apdu: %r', apdu)
        result = bytearray(self.conn.exchange(bytes(apdu)))
        log.debug('result: %r', result)
        if identity.curve_name == 'nist256p1':
            offset = 3
            length = result[offset]
            r = result[offset+1:offset+1+length]
            if r[0] == 0:
                r = r[1:]
            offset = offset + 1 + length + 1
            length = result[offset]
            s = result[offset+1:offset+1+length]
            if s[0] == 0:
                s = s[1:]
            offset = offset + 1 + length
            return bytes(r) + bytes(s)
        else:
            return bytes(result[:64])

    def ecdh(self, identity, pubkey):
        """Get shared session key using Elliptic Curve Diffie-Hellman."""
        path = _expand_path(identity.get_bip32_address(ecdh=True))
        if identity.curve_name == 'nist256p1':
            p2 = '01'
        else:
            p2 = '02'
        apdu = '800a00' + p2
        apdu = binascii.unhexlify(apdu)
        apdu += bytearray([len(pubkey) + len(path) + 1])
        apdu += bytearray([len(path) // 4]) + path
        apdu += pubkey
        log.debug('apdu: %r', apdu)
        result = bytearray(self.conn.exchange(bytes(apdu)))
        log.debug('result: %r', result)
        assert result[0] == 0x04
        return bytes(result)

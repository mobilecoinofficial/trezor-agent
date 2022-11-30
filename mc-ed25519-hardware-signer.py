#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 The MobileCoin Foundation
# 

""" Fetch Ed25519 pubkey from Ledger Device or sign a hash (Merlin transcript) using one """

from libagent.device.ledger import LedgerNanoS
from libagent.device.trezor import Trezor
from libagent.device.interface import NotFoundError
from libagent.ssh.client import Client
from libagent import device
import argparse
import base64
import json
import ledgerblue
import re
import sys
import trezorlib

CURVE = 'ed25519'

def create_main_parser() -> argparse.Namespace:
    """Create an ArgumentParser for this tool"""

    parser = argparse.ArgumentParser(
        description='Interface with a Ledger Nano to output a public key or sign a hash (32 byte Merlin transcript)'
    )

    parser.add_argument(
        '--hardware',
        help='model of hardware to use',
        type=str,
        required=True,
        choices=['ledger', 'trezor']
    )

    parser.add_argument(
        '--out',
        help='output result to a PEM encoded file',
        type=str, 
        required=False
    )
    parser.add_argument(
        '--sign',
        metavar='HASH',
        help='hex respresentation of a 32 byte hash to sign',
        required=False
    )
    parser.add_argument(
        '--identity',
        help='identity string used in generating the Ed25519 key to use',
        type=str,
        required=True
    )

    args = parser.parse_args()
    return args

def pem_encode(blob: bytearray) -> str:
    """create an Ed25519 PEM formatted string from a blob"""
    """  inferring pubkey vs. signature from length"""
    """  32 bytes is a pubkey, 64 bytes is a signature"""

    assert(len(blob)==32 or len(blob)==64), 'blob must be 32 or 64 bytes'

    is_pubkey = (len(blob) == 32)

    # ed25519 pubkey PEM encodings all start with '302a300506032b6570032100' and
    # ed25519 signature PEM encodings all start with '304a300506032b6570034100'
    # 06 03 2B 65 70 within identifies using the ed25519 curve and the rest
    # is data type specifiers and length indicators
    if is_pubkey:
        ed25519_prefix = bytearray.fromhex('302a300506032b6570032100')
    else:
        ed25519_prefix = bytearray.fromhex('304a300506032b6570034100')

    b64_pem = base64.b64encode(ed25519_prefix+blob)
    # turn into string, inserting line breaks every 64 characters
    b64_pem_str = re.sub("(.{64})", "\\1\n", b64_pem.decode(), 0, re.DOTALL)

    what = 'PUBLIC KEY' if is_pubkey else 'SIGNATURE'
    # leave off the final newline in case the string will be printed
    return f'-----BEGIN {what}-----\n{b64_pem_str}\n-----END {what}-----'


def output_json(obj):
    sys.stdout.write(json.dumps(obj) + '\n')
    sys.stdout.flush()


class UI:
    def get_passphrase(self, prompt='Passphrase:', available_on_device=False):
        output_json({
            'type': 'passphrase_request',
            'prompt': prompt,
            'available_on_device': available_on_device,
        })
        return input().strip()


    def get_pin(self, _code=None):
        output_json({
            'type': 'pin_request',
        })
        return input().strip()

    def button_request(self, _code=None):
        """Called by TrezorClient when device interaction is required."""
        output_json({
            'type': 'button_request',
        })


def main() -> None:

    args = create_main_parser()

    device_type = LedgerNanoS if args.hardware == 'ledger' else Trezor
    # device.ui.UI(device_type=device_type, config=vars(args)) - use this instead for the default behavior
    device_type.ui = UI()
    client = Client(device_type())

    identity = device.interface.Identity(identity_str=args.identity, curve_name=CURVE)
    identity.identity_dict['proto'] = 'ssh'

    try:
        if args.sign is not None:
            blob = bytearray.fromhex(args.sign)
            assert(len(blob) == 32), 'the HASH to be signed must be 32 bytes in length'
            out = client.sign_mc_challenge(blob=blob, identity=identity)
        else:
            keys = client.export_public_keys([identity])
            assert(len(keys)==1), f'expected exactly 1 pubkey from device but got {len(keys)}'
            _,pubkey_sshenc_b64,_ = keys[0].split(' ')
            out = base64.b64decode(pubkey_sshenc_b64)[-32:]
    except NotFoundError as exc:
        output_json({
            'type': 'error',
            'error_code': 'NOT_FOUND',
            'error_str': str(exc),
        })
        return
    except ledgerblue.commException.CommException as exc:
        msg, code, _ = exc.args
        if code == 0x6e01:
            error_code = 'SSH_PGP_APP_NOT_READY'
        elif code == 0x6b0c:
            error_code = 'NEED_PIN'
        else:
            error_code = 'UNKNOWN'
        output_json({
            'type': 'error',
            'error_code': error_code,
            'error_str': str(exc),
        })
        return
    except trezorlib.transport.DeviceIsBusy as exc:
        # This appears to happen when the Trezor is just powered on and not yet unlocked with the PIN
        # Running the trezor suite and unlocking it fixes that
        output_json({
            'type': 'error',
            'error_code': 'DEVICE_IS_BUSY',
            'error_str': str(exc),
        })
        return
    except trezorlib.exceptions.Cancelled as exc:
        output_json({
            'type': 'error',
            'error_code': 'CANCELLED',
            'error_str': str(exc),
        })
        return

    if args.out is not None:
        with open(args.out, 'w') as p:
            p.write(pem_encode(out)+'\n')
            what = 'public key' if args.sign is None else 'signature'
            print(f'Wrote {what} for {args.identity} to {args.out}')
    else:
        if args.sign is None:
            output_json({
                'type': 'public_key',
                'pem': pem_encode(out),
            })
        else:
            output_json({
                'type': 'signature',
                'signature': list(out),
            })

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# simple ICT-Snapshot decryption based on https://github.com/rxwx/pulse-meter/blob/main/pulse-meter.py
import re
import os
import sys
import struct
import argparse
from Crypto.Cipher import DES3
import logging

if sys.version_info.major != 3:
    logger.error("[!] Python3 required")
    sys.exit(1)

HARDCODED_KEY = bytes.fromhex("7e95421a6b886641431b32c52442e2e483f81f58b0e9e9a5")

class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# create logger
logger = logging.getLogger("pulse_meter")
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

def decrypt(ciphertext, key, iv):
    k = DES3.adjust_key_parity(key)
    cipher = DES3.new(k, DES3.MODE_CFB, iv, segment_size=64)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

def parse_encrypted_config(filename):
    key = iv = ciphertext = ''
    f = open(filename, 'rb')
    f.seek(1)
    key = HARDCODED_KEY
    iv = f.read(8)
    f.seek(1, 1) # 00 byte here, means hardcoded key
    size = struct.unpack('<i', f.read(4))[0]
    ciphertext = f.read(size)
    f.close()
    return key, iv, ciphertext

    # Python parsing
    # TODO:
    # - get pulse hash and look up correct timestamp for files
    # - parse netstat output for IOCS / malicious connections

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pulse Secure System Snapshot IOC Checker')
    parser.add_argument("action", help="Action", choices=('decryption', 'collect'))
    parser.add_argument("input", help="Input file")
    args = parser.parse_args()

    if args.action == "decryption":
        logger.info(f'Parsing snapshot file: {args.input}')
        key, iv, ciphertext = parse_encrypted_config(args.input)
        logger.debug('Decrypted Snapshot')
        with open('ICT-Snapshot.tar','wb') as dec_file:
            dec_file.write(decrypt(ciphertext, key, iv))


    elif args.action == 'collect':
        logger.info("[!] This action is currently unimplemented to avoid introducing forensic artifacts")
        logger.info("[*] You can manually generate and download a snapshot at: /dana-admin/dump/dump.cgi")

"""Belt block cipher.

Source: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf

See also:
* https://github.com/bcrypto/belt
* https://github.com/bcrypto/belt-bign-bake

**Note**. Each of the 8 large rounds of Belt is divided into 7 subrounds
resulting in 56 small rounds.
"""

import enum

from cascada.bitvector.core import Constant
from cascada.bitvector.operation import RotateLeft, RotateRight, Extract, Concat
from cascada.bitvector.secondaryop import LutOperation
from cascada.differential.difference import XorDiff
from cascada.bitvector.ssa import RoundBasedFunction
from cascada.primitives.blockcipher import Encryption, Cipher
from cascada.differential.opmodel import get_weak_model as get_differential_weak_model
from cascada.linear.opmodel import get_weak_model as get_linear_weak_model

from pprint import pprint

class BeltKeySchedule(RoundBasedFunction):
    """Key schedule for Belt."""
    num_rounds = 56
    input_widths = [32 for _ in range(8)]
    output_widths = [32 for _ in range(56)]

    @classmethod
    def set_num_rounds(cls, new_num_rounds):
        cls.num_rounds = new_num_rounds
        cls.input_widths = [32 for _ in range(8)]
        cls.output_widths = [32 for _ in range(cls.num_rounds)]

    @classmethod
    def eval(cls, *master_key):
        round_keys = [None for _ in range(cls.num_rounds)]
        for i in range(cls.num_rounds):
            round_keys[i] = master_key[i % 8]
        return round_keys

_H = [
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D,
    0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B,
    0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99,
    0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1,
    0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F,
    0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31,
    0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93,
    0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
    0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6,
    0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2,
    0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11,
    0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1,
    0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A,
    0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21,
    0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D
]

class SboxLut(LutOperation):
    """The 8-bit S-box of Belt."""
    lut = [Constant(x, 8) for x in _H]

# weight 1 to count the number of active S-boxes
SboxLut.xor_model = get_differential_weak_model(SboxLut, XorDiff, 5)
SboxLut.linear_model = get_linear_weak_model(SboxLut, 1)

def BeltG(x, r):
    o1 = SboxLut(Extract(x, 7, 0))
    o2 = SboxLut(Extract(x, 15, 8))
    o3 = SboxLut(Extract(x, 23, 16))
    o4 = SboxLut(Extract(x, 31, 24))
    x = Concat(Concat(Concat(o4, o3), o2), o1)
    x = RotateLeft(x, r)
    return x

class BeltEncryption(Encryption, RoundBasedFunction):
    """Encryption function of Belt."""
    num_rounds = 56
    input_widths = [32, 32, 32, 32]
    output_widths = [32, 32, 32, 32]

    @classmethod
    def set_num_rounds(cls, new_num_rounds):
        cls.num_rounds = new_num_rounds

    @classmethod
    def eval(cls, a, b, c, d):
        K = cls.round_keys
        i = 0
        while True:
            # step 1
            b = b ^ BeltG(a + K[i], 5)
            cls.add_round_outputs(a, b, c, d)
            i += 1
            if i == cls.num_rounds:
                break
            # step 2
            c = c ^ BeltG(d + K[i], 21)
            cls.add_round_outputs(a, b, c, d)
            i += 1
            if i == cls.num_rounds:
                break
            # step 3
            a = a - BeltG(b + K[i], 13)
            cls.add_round_outputs(a, b, c, d)
            i += 1
            if i == cls.num_rounds:
                break
            # step 4
            c = c + b
            b = b + (BeltG(c + K[i], 21) ^ Constant(i // 7 + 1, 32))
            c = c - b
            cls.add_round_outputs(a, b, c, d)
            i += 1
            if i == cls.num_rounds:
                break
            # step 5
            d = d + BeltG(c + K[i], 13)
            cls.add_round_outputs(a, b, c, d)
            i += 1
            if i == cls.num_rounds:
                break
            # step 6
            b = b ^ BeltG(a + K[i], 21)
            cls.add_round_outputs(a, b, c, d)
            i += 1
            if i == cls.num_rounds:
                break
            # step 7
            c = c ^ BeltG(d + K[i], 5)
            a, b, c, d = b, d, a, c
            cls.add_round_outputs(a, b, c, d)
            i += 1
            if i == cls.num_rounds:
                break
        if i == 56:
            a, b, c, d = b, d, a, c
        return a, b, c, d

def Reverse(x):
    r = x % 256
    x = x // 256
    r = r * 256 + x % 256
    x = x // 256
    r = r * 256 + x % 256
    x = x // 256
    r = r * 256 + x % 256
    return r

def ReverseAll(*xs):
    return tuple(Reverse(x) for x in xs)

class BeltCipher(Cipher):
    """The block cipher Belt."""
    key_schedule = BeltKeySchedule
    encryption = BeltEncryption

    @classmethod
    def set_num_rounds(cls, new_num_rounds):
        cls.key_schedule.set_num_rounds(new_num_rounds)
        cls.encryption.set_num_rounds(new_num_rounds)

    @classmethod
    def test(cls):
        old_num_rounds = cls.num_rounds
        cls.set_num_rounds(56)
        pt = ReverseAll(0xb194bac8, 0x0a08f53b, 0x366d008e, 0x584a5de4)
        key =ReverseAll(0xe9dee72c, 0x8f0c0fa6, 0x2ddb49f4, 0x6f739647, 0x06075316, 0xed247a37, 0x39cba383, 0x03a98bf6)
        ct = ReverseAll(0x69cca1c9, 0x3557c9e3, 0xd66bc3e0, 0xfa88fa6e)
        assert cls(pt, key) == ct
        cls.set_num_rounds(old_num_rounds)
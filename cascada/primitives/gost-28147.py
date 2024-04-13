"""Gost-28147 block cipher."""

from cascada.bitvector.core import Constant
from cascada.bitvector.operation import RotateLeft, Extract, Concat
from cascada.primitives.blockcipher import Encryption, Cipher
from cascada.bitvector.ssa import RoundBasedFunction

class GostKeySchedule(RoundBasedFunction):
    """ Key schedule for Gost-28147."""
    num_rounds = 32
    input_widths = [32 for _ in range(8)]
    output_widths = [32 for _ in range(32)]

    @classmethod
    def set_num_rounds(cls, new_num_rounds):
        cls.num_rounds = new_num_rounds
        cls.input_widths = [32 for _ in range(8)]
        cls.output_widths = [32 for _ in range(cls.num_rounds)]

    @classmethod
    def eval(cls, *master_key):
        round_keys = [None for _ in range(cls.num_rounds)]
        for i in range(24):
            round_keys[i] = master_key[i % 8]
        for i in range(24, cls.num_rounds):
            round_keys[i] = master_key[cls.num_rounds - i - 1]
        return round_keys

_S = [2, 6, 3, 14, 12, 15, 7, 5, 11, 13, 8, 9, 10, 0, 4, 1,
      8, 12, 9, 6, 10, 7, 13, 1, 3, 11, 14, 15, 2, 4, 0, 5,
      1, 5, 4, 13, 3, 8, 0, 14, 12, 6, 7, 2, 9, 15, 11, 10,
      4, 0, 5, 10, 2, 11, 1, 9, 15, 3, 6, 7, 14, 12, 8, 13,
      7, 9, 6, 11, 15, 10, 8, 12, 4, 14, 1, 0, 5, 3, 13, 2,
      14, 8, 15, 2, 6, 3, 9, 13, 5, 7, 0, 1, 4, 10, 12, 11,
      9, 13, 8, 5, 11, 4, 12, 2, 0, 10, 15, 14, 1, 7, 3, 6,
      11, 15, 10, 8, 1, 14, 3, 6, 9, 0, 4, 5, 13, 2, 7, 12]

_S = [Constant(s, 4) for s in _S]

def fun(a, k, i):
    x = a + k
    # print(int(str(Extract(x, 3, 0)), 16))
    o1 = _S[i * 15 + int(Extract(x, 3, 0).bin(), 2)]
    o2 = _S[i * 15 + int(Extract(x, 7, 4).bin(), 2)]
    o3 = _S[i * 15 + int(Extract(x, 11, 8).bin(), 2)]
    o4 = _S[i * 15 + int(Extract(x, 15, 12).bin(), 2)]
    o5 = _S[i * 15 + int(Extract(x, 19, 16).bin(), 2)]
    o6 = _S[i * 15 + int(Extract(x, 23, 20).bin(), 2)]
    o7 = _S[i * 15 + int(Extract(x, 27, 24).bin(), 2)]
    o8 = _S[i * 15 + int(Extract(x, 31, 28).bin(), 2)]
    x = Concat(Concat(Concat(Concat(Concat(Concat(Concat(o8, o7), o6), o5), o4), o3), o2), o1)
    x = RotateLeft(x, 11)
    return x

class GostEncryption(Encryption, RoundBasedFunction):
    """Encryption function of Gost-28147."""
    num_rounds = 32
    input_widths = [32, 32]
    output_widths = [32, 32]

    @classmethod
    def set_num_rounds(cls, new_num_rounds):
        cls.num_rounds = new_num_rounds

    @classmethod
    def eval(cls, a, b):
        K = cls.round_keys
        for i in range(cls.num_rounds):
            tmp = b
            b = a
            a = tmp ^ fun(a, K[i], i % 8)
            cls.add_round_outputs(a, b)
        return a, b

class GostCipher(Cipher):
    """The block cipher Gost-28147."""
    key_schedule = GostKeySchedule
    encryption = GostEncryption

    @classmethod
    def set_num_rounds(cls, new_num_rounds):
        cls.key_schedule.set_num_rounds(new_num_rounds)
        cls.encryption.set_num_rounds(new_num_rounds)

    @classmethod
    def test(cls):
        old_num_rounds = cls.num_rounds
        cls.set_num_rounds(32)
        pt = (0xb194bac8, 0x0a08f53b)
        key = (0xe9dee72c, 0x8f0c0fa6, 0x2ddb49f4, 0x6f739647, 0x06075316, 0xed247a37, 0x39cba383, 0x03a98bf6)
        ct = (0xc160ea21, 0x342ebc42)
        cls(pt, key)
        assert cls(pt, key) == ct
        cls.set_num_rounds(old_num_rounds)

GostCipher.test()
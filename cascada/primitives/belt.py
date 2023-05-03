"""Belt block cipher."""
import enum

from cascada.bitvector.core import Constant
from cascada.bitvector.operation import RotateLeft, RotateRight

from cascada.bitvector.ssa import RoundBasedFunction
from cascada.primitives.blockcipher import Encryption, Cipher

from cascada.differential.opmodel import OpModel
from cascada.bitvector.secondaryop import PopCount
from cascada.differential.difference import XorDiff, RXDiff
from cascada.bitvector import core
from cascada.bitvector.operation import (
    SecondaryOperation, RotateLeft, BvComp, Ite, zero_extend
)


class BeltInstance(enum.Enum):
    belt_32_8 = enum.auto()


def get_Belt_instance(belt_instance):

    if belt_instance == BeltInstance.belt_32_8:
        default_rounds = 8
        n = 32
        m = 8
    else:
        raise ValueError("invalid instance of cipher")

    H = [0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
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
         0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D]

    # H-transformation: replacing byte with another value from table
    def htransformation(x):
        return Constant(H[int(str(x), 16)], 8)

    def rot_word(my_word):
        # [a0, a1, a2, a3]  ->  [a3, a2, a1, a0]
        return [my_word[(3 - i) % 4] for i in range(4)]

    def hex2byte_list(state):
        """Convert the hexadecimal string to a byte list

                >>> hex2byte_list("000102030405060708090a0b0c0d0e0f")
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]

            """
        byte_list = []
        for i in range(0, len(state), 2):
            my_byte = int(state[i:i + 2], base=16)
            byte_list.append(Constant(my_byte, 8))
        return byte_list

    def gtransformation(x, k):
        list_hex = hex2byte_list(str(x)[2:])
        res = [htransformation(i) for i in list_hex]
        res_rev = rot_word(res)

        string = str(res_rev[0]) + str(res_rev[1])[2:] + str(res_rev[2])[2:] + str(res_rev[3])[2:]
        value = RotateLeft(Constant(int(string, 16), 32), k)
        list_hex = hex2byte_list(str(value)[2:])
        res_rev = rot_word(list_hex)
        string = str(res_rev[0]) + str(res_rev[1])[2:] + str(res_rev[2])[2:] + str(res_rev[3])[2:]
        res_rev = Constant(int(string, 16), 32)
        return res_rev

    def int2list(x):
        return [x >> i & 0xff for i in [24, 16, 8, 0]]

    def ADD(a, b):
        list_hex_a = hex2byte_list(str(a)[2:])
        rev_a = rot_word(list_hex_a)

        list_hex_b = hex2byte_list(str(b)[2:])
        rev_b = rot_word(list_hex_b)

        int_a = int(str(rev_a[0]), 16) * pow(2, 24) + int(str(rev_a[1]), 16) * pow(2, 16) + int(str(rev_a[2]), 16) * pow(2, 8) + int(str(rev_a[3]), 16)
        int_b = int(str(rev_b[0]), 16) * pow(2, 24) + int(str(rev_b[1]), 16) * pow(2, 16) + int(str(rev_b[2]), 16) * pow(2, 8) + int(str(rev_b[3]), 16)

        res = (int_a + int_b) % 2**32
        res = int2list(res)
        res = rot_word(res)
        res_const = [Constant(res[0], 8), Constant(res[1], 8), Constant(res[2], 8), Constant(res[3], 8)]
        string = str(res_const[0]) + str(res_const[1])[2:] + str(res_const[2])[2:] + str(res_const[3])[2:]
        value = Constant(int(string, 16), 32)

        return value

    def SUB(a, b):
        list_hex_a = hex2byte_list(str(a)[2:])
        rev_a = rot_word(list_hex_a)

        list_hex_b = hex2byte_list(str(b)[2:])
        rev_b = rot_word(list_hex_b)

        int_a = int(str(rev_a[0]), 16) * pow(2, 24) + int(str(rev_a[1]), 16) * pow(2, 16) + int(str(rev_a[2]), 16) * pow(2, 8) + int(str(rev_a[3]), 16)
        int_b = int(str(rev_b[0]), 16) * pow(2, 24) + int(str(rev_b[1]), 16) * pow(2, 16) + int(str(rev_b[2]), 16) * pow(2, 8) + int(str(rev_b[3]), 16)

        res = (int_a - int_b) % 2 ** 32
        res = int2list(res)
        res = rot_word(res)
        res_const = [Constant(res[0], 8), Constant(res[1], 8), Constant(res[2], 8), Constant(res[3], 8)]
        string = str(res_const[0]) + str(res_const[1])[2:] + str(res_const[2])[2:] + str(res_const[3])[2:]
        value = Constant(int(string, 16), 32)

        return value

    class BeltKeySchedule(RoundBasedFunction):
        """Key schedule function."""

        num_rounds = default_rounds - 1
        input_widths = [n for _ in range(m)]
        output_widths = [n for _ in range(default_rounds)]

        @classmethod
        def set_num_rounds(cls, new_num_rounds):  # new_num_rounds = 0 if enc_num_rounds = 1
            cls.num_rounds = new_num_rounds
            cls.input_widths = [n for _ in range(min(m, new_num_rounds + 1))]
            cls.output_widths = [n for _ in range(new_num_rounds + 1)]

        @classmethod
        def eval(cls, *master_key):
            round_keys = [None for _ in range(cls.num_rounds + 1)]
            for i in range(0, 8):
                round_keys[i] = master_key[i]

            return round_keys

    class BeltEncryption(Encryption, RoundBasedFunction):
        """Encryption function."""

        num_rounds = default_rounds
        input_widths = [n, n, n, n]
        output_widths = [n, n, n, n]
        round_keys = None

        @classmethod
        def set_num_rounds(cls, new_num_rounds):
            cls.num_rounds = new_num_rounds


        @classmethod
        def eval(cls, a, b, c, d):
            k = [None for _ in range(56 + 1)]
            for j in range(0, 56):
                k[j] = cls.round_keys[j % 8]
            for i in range(cls.num_rounds):
                b = b ^ gtransformation(ADD(a, k[7 * (i + 1) - 7]), 5)
                # print("b", b)
                c = c ^ gtransformation(ADD(d, k[7 * (i + 1) - 6]), 21)
                # print("c", c)
                a = SUB(a, gtransformation(ADD(b, k[7 * (i + 1) - 5]), 13))
                # print("a", a)
                e = (gtransformation(ADD(ADD(b, c), k[7 * (i + 1) - 4]), 21)) ^ Constant(int("0x0" + str(i+1) + "000000", 16), 32)
                # print(e)
                b = ADD(b, e)
                # print("b", b)
                c = SUB(c, e)
                # print("c", c)
                d = ADD(d, gtransformation(ADD(c, k[7 * (i + 1) - 3]), 13))
                # print("d", d)
                b = b ^ gtransformation(ADD(a, k[7 * (i + 1) - 2]), 21)
                # print("b", b)
                c = c ^ gtransformation(ADD(d, k[7 * (i + 1) - 1]), 5)
                # print("c", c)
                a, b = b, a
                c, d = d, c
                b, c = c, b

                # print(a, b, c, d)

                cls.add_round_outputs(a, b, c, d)
            return b, d, a, c

    class BeltCipher(Cipher):
        key_schedule = BeltKeySchedule
        encryption = BeltEncryption
        _belt_instance = belt_instance

        @classmethod
        def set_num_rounds(cls, new_num_rounds):
            cls.key_schedule.set_num_rounds(new_num_rounds - 1)
            cls.encryption.set_num_rounds(new_num_rounds)

        @classmethod
        def test(cls):
            old_num_rounds = cls.num_rounds
            cls.set_num_rounds(default_rounds)

            if cls._speck_instance == BeltInstance.belt_32_8:
                plaintext = (0xb194bac8, 0x0a08f53b, 0x366d008e, 0x584a5de4)
                key = (0xe9dee72c, 0x8f0c0fa6, 0x2ddb49f4, 0x6f739647, 0x06075316, 0xed247a37, 0x39cba383, 0x03a98bf6)
                assert cls(plaintext, key) == (0xd66bc3e0, 0x69cca1c9, 0xfa88fa6e, 0x3557c9e3)
            else:
                raise ValueError("invalid instance of belt")

            cls.set_num_rounds(old_num_rounds)

    return BeltCipher

class BeltRF(SecondaryOperation):
    """The non-linear part of the round function of Simon.

    This corresponds to ``f(x) = ((x <<< a) & (x <<< b)) ^ (x <<< c)``,
    where ``(a, b, c) = (8, 1, 2)``.
    """
    # a = 8
    # b = 1
    # c = 2
    #
    # arity = [1, 0]
    # is_symmetric = False
    #
    # @classmethod
    # def output_width(cls, x):
    #     return x.width
    #
    # @classmethod
    # def eval(cls, x):
    #     return (RotateLeft(x, cls.a) & RotateLeft(x, cls.b)) ^ RotateLeft(x, cls.c)

class XorModelBelt(OpModel):
    """Represent the `XorDiff` `differential.opmodel.OpModel` of `Belt`.

        >>> from cascada.bitvector.core import Constant, Variable
        >>> from cascada.differential.difference import XorDiff
        >>> from cascada.primitives.belt import XorModelBelt
        >>> alpha = XorDiff(Constant(0, 32))
        >>> f = XorModelBelt(alpha)
        >>> print(f.vrepr())
        XorModelBelt(XorDiff(Constant(0x00000000, width=32)))
        >>> x = Constant(0, 32)
        >>> f.eval_derivative(x)  # f(x + alpha) - f(x)
        XorDiff(0x00000000)
        >>> f.max_weight(), f.weight_width(), f.error(), f.num_frac_bits()

    """

    diff_type = XorDiff
    op = BeltRF

    def max_weight(self):
        n = self.input_diff[0].val.width
        return n - 1  # as an integer

    def weight_width(self):
        n = self.input_diff[0].val.width
        return max((n - 1).bit_length(), PopCount.output_width(core.Variable("x", n)))

    def num_frac_bits(self):
        return 0

    def error(self):
        return 0
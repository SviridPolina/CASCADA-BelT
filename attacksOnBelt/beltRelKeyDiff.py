from cascada.differential.difference import XorDiff
from cascada.smt.chsearch import ChModelAssertType, round_based_cipher_ch_search
from cascada.primitives import belt

Belt = belt.BeltCipher
Belt.test()

"""Search for related-key XOR differentials characteristics of iterated ciphers over multiple number of rounds.

    This function is similar to `round_based_cipher_ch_search` but searching for
    `abstractproperty.characteristic.CipherCharacteristic` instead of
    `abstractproperty.characteristic.Characteristic`.

    A `CipherCharacteristic` is a pair of `Characteristic` objects
    where one covers the `Cipher.key_schedule`
    and the other one covers the `Cipher.encryption`."""

at = ChModelAssertType.ValidityAndWeight
iterator = round_based_cipher_ch_search(Belt, 8, 56, XorDiff, at, at, "btor",
                                        extra_cipherchfinder_args={"ks_exclude_zero_input_prop": True, "solver_seed": 0},
                                        extra_findnextchweight_args={"initial_weight": 0})
for (num_rounds, ch) in iterator:
        print(num_rounds, ":", ch.srepr())
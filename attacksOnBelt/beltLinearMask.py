from cascada.linear.mask import LinearMask
from cascada.smt.chsearch import ChModelAssertType, PrintingMode, round_based_ch_search
from cascada.primitives import belt

Belt = belt.BeltCipher
Belt.test()

"""Search for LinearMask characteristics of round-based functions over multiple number of rounds.

round_based_ch_search function searches for characteristics of ``func``
by modelling the search as a sequence of SMT problems,
but the search is perfomed iteratively over the number of rounds of ``func``.
That is, first characteristics covering ``initial_num_rounds`` rounds
are searched, then ``initial_num_rounds + 1``, until ``final_num_rounds``."""

assert_type = ChModelAssertType.ValidityAndWeight

iterator = round_based_ch_search(Belt, 2, 30, LinearMask, assert_type, "btor",
    extra_chfinder_args={"exclude_zero_input_prop": True, "printing_mode": PrintingMode.Silent},
    extra_findnextchweight_args={"initial_weight": 0})

"""In particular, this function is a Python `generator` function,
    returning an `iterator` that yields
    tuples containing the current number of rounds and the last
    characteristic if ``func`` is a `RoundBasedFunction` object.

    The propagation weight of a characteristic is the negative binary
    logarithm of the characteristic probability, that is, the sum
    of the propagation weights of the `Property` pairs."""

for (num_rounds, ch) in iterator:
    print(num_rounds, ":", ch.srepr())
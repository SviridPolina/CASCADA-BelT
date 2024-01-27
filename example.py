from cascada.differential.difference import XorDiff
from cascada.linear.mask import LinearMask
from cascada.smt.invalidpropsearch import round_based_invalidprop_search, INCREMENT_NUM_ROUNDS
from cascada.smt.chsearch import ChModelAssertType, PrintingMode, round_based_ch_search
from cascada.primitives import belt

Belt = belt.BeltCipher

Belt.test()

#iterator = round_based_invalidprop_search(Belt, 5, 5, LinearMask, "btor")
#tuple_rounds, tuple_chs = next(iterator)
#print(tuple_rounds, ":", ', '.join([ch.srepr() for ch in tuple_chs])) 

assert_type = ChModelAssertType.ValidityAndWeight

iterator = round_based_ch_search(Belt, 1, 25, XorDiff, assert_type, "btor",
    extra_chfinder_args={"exclude_zero_input_prop": True, "printing_mode": PrintingMode.Silent},
    extra_findnextchweight_args={"initial_weight": 0})

for (num_rounds, ch) in iterator:
    print(num_rounds, ":", ch.srepr())

# 23 : Ch(w=26, id=00020000 1fe00000 1defe000 80000040, od=00004000 00008000 80000000 00000000)
# 24 : Ch(w=29, id=00010000 08000000 00480000 80000020, od=80004000 00080000 80000000 00000000)
# 25 : Ch(w=36, id=00080000 01000000 00202000 80000040, od=01004000 80000000 00004000 00000000)


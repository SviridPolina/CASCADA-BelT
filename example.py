from cascada.linear.mask import LinearMask
from cascada.smt.invalidpropsearch import round_based_invalidprop_search, INCREMENT_NUM_ROUNDS
from cascada.primitives import belt

Belt = belt.BeltCipher
iterator = round_based_invalidprop_search(Belt, 5, 5, LinearMask, "btor")
tuple_rounds, tuple_chs = next(iterator)
print(tuple_rounds, ":", ', '.join([ch.srepr() for ch in tuple_chs]))
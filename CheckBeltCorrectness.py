from cascada.primitives import belt
Belt = belt.BeltCipher

""" Checking the SSA form of the cipher
SSA form is beneficial as this is the main internal
representation used by CASCADA. Moreover, the SSA form might differ from the original
implementation (while still being functionally equivalent), as redundant assignments
are removed and additional transformations might be performed (more on that later) """
print("1. Checking the SSA form of the cipher")
Belt.set_num_rounds(2)
Belt.set_round_keys(symbolic_prefix="k")
ssa_2rounds = Belt.encryption.to_ssa(["p0", "p1", "p2", "p3"], "x")
ssa_round1, ssa_round2 = ssa_2rounds.split(ssa_2rounds.get_round_separators())
print(ssa_round1)
print(ssa_round2)

""" Checking a characteristic model
Before checking the characteristics found in the search, it is better to check first
the representation of a characteristic model (i.e., the symbolic characteristic associated with
any characteristics found) and its error """
print("\n2. Checking a characteristic model")
from cascada.differential.difference import XorDiff
from cascada.differential.chmodel import EncryptionChModel
num_raunds = 28
Belt.set_num_rounds(num_raunds)
ch_model_rounds = EncryptionChModel(Belt, XorDiff)
print("Differential EncryptionChModel error for {} raunds: {}".format(num_raunds, ch_model_rounds.error()))

from cascada.linear.mask import LinearMask
from cascada.linear.chmodel import EncryptionChModel
num_raunds = 28
Belt.set_num_rounds(num_raunds)
ch_model_rounds = EncryptionChModel(Belt, LinearMask)
print("Linear EncryptionChModel error for {} raunds: {}".format(num_raunds, ch_model_rounds.error()))

""" Checking the characteristics found in the search
To check the discrepancy between the ``ch_weight`` and the actual weight,
you can compute the ``empirical_ch_weight``, which is another approximation
of the actual weight of the characteristic """
print("\n3. Checking the characteristics found in the search")
print("Checking XorDiff found in the search")
from cascada.differential.difference import XorDiff
from cascada.differential.chmodel import EncryptionChModel
from cascada.smt.chsearch import ChFinder, ChModelAssertType, PrintingMode
Belt.set_num_rounds(6)
ch_model = EncryptionChModel(Belt, XorDiff)
assert_type = ChModelAssertType.ValidityAndWeight
ch_finder = ChFinder(ch_model, assert_type, "btor", solver_seed=0,
                      exclude_zero_input_prop=True, printing_mode=PrintingMode.Debug)
ewo = {"seed": 0, "C_code": True}
ch_found = next(ch_finder.find_next_ch_increasing_weight(0, empirical_weight_options=ewo))
print(ch_found)

print("Checking LinearMask found in the search")
from cascada.linear.mask import LinearMask
from cascada.linear.chmodel import EncryptionChModel
from cascada.smt.chsearch import ChFinder, ChModelAssertType, PrintingMode
Belt.set_num_rounds(6)
ch_model = EncryptionChModel(Belt, LinearMask)
assert_type = ChModelAssertType.ValidityAndWeight
ch_finder = ChFinder(ch_model, assert_type, "btor", solver_seed=0,
                      exclude_zero_input_prop=True, printing_mode=PrintingMode.Debug)
ewo = {"seed": 0, "C_code": True}
ch_found = next(ch_finder.find_next_ch_increasing_weight(0, empirical_weight_options=ewo))
print(ch_found)

""" Checking the specific characteristic found in the search"""

""" Checking XorDiff found in the search
...
6 : Ch(w=5, id=00000000 00000000 00010000 80000000, od=00000000 00000000 00000000 80000000)
... """
print("\n4. Checking the specific characteristic found in the search")
print("XorDiff")
from cascada.bitvector.core import Constant
from cascada.differential.difference import XorDiff
from cascada.differential.chmodel import ChModel, EncryptionChModel
from cascada.smt.chsearch import ChFinder, ChModelAssertType, PrintingMode
Belt.set_num_rounds(6)
assert_type = ChModelAssertType.ValidityAndWeight
ch_model = EncryptionChModel(Belt, XorDiff)
v2c = {v: Constant(c, 32) for v, c in zip(ch_model.input_diff, [0x00000000, 0x00000000, 0x00010000, 0x80000000])}
for v, c in zip(ch_model.output_diff, [0x00000000, 0x00000000, 0x00000000, 0x80000000]):
    v2c[v] = Constant(c, 32)
ch_finder = ChFinder(ch_model, assert_type, "btor", solver_seed=0, printing_mode=PrintingMode.WeightsAndVrepr,
                          var_prop2ct_prop=v2c, exclude_zero_input_prop = True)
ewo = {"seed": 0, "C_code": True, "split_by_max_weight": 20}
ch_found = next(ch_finder.find_next_ch_increasing_weight(0, empirical_weight_options=ewo))

""" Checking LinearMask found in the search 
...
6 : Ch(w=5, id=00000000 00000000 00000000 00004000, od=00000000 00000000 00000001 00004000)
... """
print("LinearMask")
from cascada.bitvector.core import Constant
from cascada.linear.mask import LinearMask
from cascada.linear.chmodel import ChModel, EncryptionChModel
from cascada.smt.chsearch import ChFinder, ChModelAssertType, PrintingMode
Belt.set_num_rounds(6)
assert_type = ChModelAssertType.ValidityAndWeight
ch_model = EncryptionChModel(Belt, LinearMask)
v2c = {v: Constant(c, 32) for v, c in zip(ch_model.input_mask, [0x00000000, 0x00000000, 0x00000000, 0x00004000])}
for v, c in zip(ch_model.output_mask, [0x00000000, 0x00000000, 0x00000001, 0x00004000]):
    v2c[v] = Constant(c, 32)
ch_finder = ChFinder(ch_model, assert_type, "btor", solver_seed=0, printing_mode=PrintingMode.WeightsAndVrepr,
                          var_prop2ct_prop=v2c, exclude_zero_input_prop = True)
ewo = {"seed": 0, "C_code": True, "split_by_max_weight": 20}
ch_found = next(ch_finder.find_next_ch_increasing_weight(0, empirical_weight_options=ewo))

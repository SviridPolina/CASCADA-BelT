from cascada.differential.difference import XorDiff
from cascada.differential.chmodel import EncryptionChModel
from cascada.smt.invalidpropsearch import InvalidPropFinder, ActiveBitMode
from cascada.smt.wrappedchmodel import get_wrapped_chmodel
from cascada.primitives import belt

Belt = belt.BeltCipher
Belt.test()
Belt.set_num_rounds(3)

"""Search for Xor universally-invalid Characteristic of round-based functions over multiple number of rounds.

    round_based_invalidprop_search function searches for universally-invalid characteristics
    by modelling the search as a sequence of SMT problems
    (using `InvalidPropFinder.find_next_invalidprop_miss_in_the_middle`),
    but the search is perfomed iteratively over the number of rounds of ``func``.
    That is, first universally-invalid characteristics covering ``initial_num_rounds`` rounds
    are searched, then ``initial_num_rounds + 1``, until ``final_num_rounds``.

    This function proceed as follows:

    1. Set the current number of rounds of the universally-invalid characteristics to search
       for to ``initial_num_rounds``.
    2. Set the current number of initial rounds to skip  to ``0``.
    3. Set the number of rounds of ``func`` to the sum of the number of rounds
       of step 1 and step 2, and split ``func`` into :math:`E \circ S`
       (:math:`S` denotes the skipped rounds and :math:`E` the target function
       of the universally-invalid characteristics to search for).
    4. Create a `abstractproperty.chmodel.ChModel` object
       of :math:`E` using as arguments ``prop_type`` and ``extra_chmodel_args``.
    5. Split :math:`E` into :math:`E = E_2 \circ E_1 \circ E_0`
       taking into account ``min_num_E0_rounds, min_num_E2_rounds``
       and generate the  characteristic models of :math:`(E_0, E_1, E_2)`.
       See `InvalidPropFinder.find_next_invalidprop_miss_in_the_middle`
       for more details about :math:`(E_0, E_1, E_2)`.
    6. Create an `InvalidPropFinder` object with arguments
       the characteristic model over :math:`E_1`,
       ``solver_name`` and ``extra_invalidpropfinder_args``.
    7. Loop over the generator `InvalidPropFinder.find_next_invalidprop_miss_in_the_middle`
       (with arguments ``exclude_zero_input_prop_E0``
       and ``exclude_zero_input_prop_E2``)
       and yield all the 3-length tuples of characteristics from the
       generator (together with the current number of rounds).
    8. After the generator is exhausted, go to step 5 but splitting :math:`E`
       into antoher another partition :math:`(E_0, E_1, E_2)`.


    This function reuses information from previous partitions :math:`(E_0', E_1', E_2')`
    to directly avoid some new partitions :math:`(E_0, E_1, E_2)` that don't contain
    universally-invalid characteristics.
    Assume that no universally-invalid characteristic was found for the partition
    :math:`(E_0', E_1', E_2')`,
    where :math:`E_0'` covers from the :math:`a'`-th round to the :math:`b'`-th
    round (i.e., ``a'-›b'``) and :math:`E_2'` covers ``c'-›d'``.
    Then it holds that no universally-invalid characteristic can be found
    using `InvalidPropFinder.find_next_invalidprop_miss_in_the_middle` from any partition
    :math:`(E_0, E_1, E_2)` where :math:`E_0` covers ``a-›a'-›b'-›b`` and
    :math:`E_2` covers ``c-›c'-›d'-›d``, that is,
    from any partition :math:`(E_0, E_1, E_2)`
    where :math:`E_0` covers ``a-›b`` and :math:`E_2` covers ``c-›d``
    such that :math:`a \le a', b' \le b, c \le c` and :math:`d' \le d`."""


""" find_next_invalidprop_quantified_logic
    Return an iterator that yields the universally-invalid characteristics found in the quantified SMT-based search.

    This method searches for universally-invalid characteristic using SMT problems
        in the quantified bit-vector logic (with the *ForAll* quantifier)."""

""" find_next_invalidprop_activebitmode
    Return an iterator that yields the universally-invalid characteristics found in the SMT-based search
        with given `ActiveBitMode`.

    This method searches for universally-invalid characteristic using SMT solvers by checking
        one-by-one all input and output properties with given `ActiveBitMode`."""

""" find_next_invalidprop_miss_in_the_middle
    Return an iterator that yields the universally-invalid characteristics found in the SMT+MitM-based search.

    This method searches for universally-invalid characteristic using SMT problems
        and the miss-in-the-middle approach."""

print('find_next_invalidprop_quantified_logic')
wrapped_ch_model = get_wrapped_chmodel(EncryptionChModel(Belt, XorDiff))
invalid_prop_finder1 = InvalidPropFinder(wrapped_ch_model, "z3", solver_seed=0)
for i, ch in enumerate(invalid_prop_finder1.find_next_invalidprop_quantified_logic()):
    print(ch.srepr())
    if i == 2: break

print('find_next_invalidprop_activebitmode')
wrapped_ch_model = get_wrapped_chmodel(EncryptionChModel(Belt, XorDiff))
invalid_prop_finder2 = InvalidPropFinder(wrapped_ch_model, "btor", solver_seed=0)
inab, ipabm, opabm = 1, ActiveBitMode.MSBit, ActiveBitMode.MSBit
for i, ch in enumerate(invalid_prop_finder2.find_next_invalidprop_activebitmode(inab, ipabm, opabm)):
    print(ch.srepr())
    if i == 2: break

print('find_next_invalidprop_miss_in_the_middle')
ch_model_E = EncryptionChModel(Belt, XorDiff)
ch_model_E0, ch_model_E1, ch_model_E2 = ch_model_E.split(ch_model_E.get_round_separators())
ch_model_E1 = get_wrapped_chmodel(ch_model_E1)
invalid_prop_finder = InvalidPropFinder(ch_model_E1, "btor", solver_seed=0)
tuple_iterator = invalid_prop_finder.find_next_invalidprop_miss_in_the_middle(ch_model_E0, ch_model_E2)
for i, (pr1_ch_E0, uni_inv_ch_E1, pr1_ch_E2) in enumerate(tuple_iterator):
    print(pr1_ch_E0.srepr(), uni_inv_ch_E1.srepr(), pr1_ch_E2.srepr())
    if i == 2: break

"""This function is a Python `generator` function,
    returning an `iterator` that yields 2-length tuples:

    * The first element in the tuple is a 4-length tuple containing
      the number of initial skipped rounds, the number of rounds
      of :math:`E_0`, the number of rounds of :math:`E_1`
      and the number of rounds of :math:`E_2`.
    * The second element in the tuple is a 3-length tuple containing
      the characteristics over :math:`E_0`, :math:`E_1` and :math:`E_2`
      respectively (i.e., the outputs of
      `InvalidPropFinder.find_next_invalidprop_miss_in_the_middle`)."""

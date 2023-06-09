=======
CASCADA
=======

.. image:: https://zenodo.org/badge/449991648.svg
   :target: https://zenodo.org/badge/latestdoi/449991648

CASCADA (Characteristic Automated Search of Cryptographic Algorithms for Distinguishing Attacks)
is a Python 3 library to evaluate the security of cryptographic primitives,
specially block ciphers, against distinguishing attacks with bit-vector SMT solvers.

A detailed introduction of CASCADA can be found in the paper
`Characteristic Automated Search of Cryptographic Algorithms for Distinguishing Attacks (CASCADA) <https://eprint.iacr.org/2022/513>`_.

CASCADA implements several SMT-based automated search methods to search for
characteristics and zero-probability properties to evaluate the security of ciphers against:

- differential cryptanalysis
- related-key differential cryptanalysis
- rotational-XOR cryptanalysis
- impossible-differential cryptanalysis
- related-key impossible-differential cryptanalysis
- impossible-rotational-XOR cryptanalysis
- linear cryptanalysis
- zero-correlation cryptanalysis

The online documentation of CASCADA can be found `here <https://ranea.github.io/CASCADA/>`_.


Installation
============

CASCADA requires Python 3 (>= 3.10) and the following Python libraries:

- cython
- sympy
- bidict
- cffi
- wurlitzer
- pySMT

These libraries can be easily installed with pip::

    pip install cython sympy bidict cffi wurlitzer pysmt

CASCADA also requires an SMT solver supporting the bit-vector theory,
installed through `pySMT <https://pysmt.readthedocs.io/en/latest/getting_started.html#getting-started>`_.
For example, the SMT solver boolector can be installed through pySMT by ::

    pysmt-install --btor

Optionally, hypothesis can be installed to run the tests,
and sphinx and sphinx-rtd-theme to build the documentation.


Citation
========

If you use CASCADA, please consider citing the `paper <https://doi.org/10.1049/ise2.12077>`_:

::

   @article{DBLP:journals/iet-ifs/RaneaR22,
     author     = {Adri{\'{a}}n Ranea and Vincent Rijmen},
     title      = {Characteristic automated search of cryptographic algorithms
                   for distinguishing attacks ({CASCADA})},
     journal    = {{IET} Inf. Secur.},
     volume     = {16},
     number     = {6},
     pages      = {470--481},
     year       = {2022},
     doi        = {https://doi.org/10.1049/ise2.12077}
   }

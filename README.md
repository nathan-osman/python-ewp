## python-ewp

This module provides the functions necessary to add support for PayPal's Encrypted Website Payments to your shopping cart. The module is provided as an extension written in C to simplify the process of invoking the necessary OpenSSL functions for signing and encrypting data. Support is provided for both Python 2 and Python 3.

### Requirements

In order to build the `ewp` module, you will need the following installed:

- a C compiler (such as [GCC](https://gcc.gnu.org/) or [Clang](http://clang.llvm.org/))
- Python development files (`python-dev` on Debian / Ubuntu)
- OpenSSL development files (`libssl-dev` on Debian / Ubuntu)

### Installation

To build and install the module, use the following command:

    python setup.py install

### Usage

The module provides two functions:

    output = ewp.sign(key_fn, cert_fn, input)
    output = ewp.encrypt(cert_fn, input)

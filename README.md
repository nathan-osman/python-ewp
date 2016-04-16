## python-ewp

[![Build Status](https://travis-ci.org/nathan-osman/python-ewp.svg?branch=master)](https://travis-ci.org/nathan-osman/python-ewp)
[![PyPI Version](http://img.shields.io/pypi/v/ewp.svg)](https://pypi.python.org/pypi/ewp)
[![PyPI Downloads](http://img.shields.io/pypi/dm/ewp.svg)](https://pypi.python.org/pypi/ewp)
[![License](http://img.shields.io/badge/license-MIT-yellow.svg)](http://opensource.org/licenses/MIT)

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

`signature = sign(key_fn, cert_fn, input)`

- `key_fn` - filename of PEM-encoded private key
- `cert_fn` - filename of PEM-encoded X509 certificate
- `input` - data to sign

`ciphertext = encrypt(cert_fn, input)`

- `cert_fn` - filename of PEM-encoded X509 certificate
- `input` - data to sign

### Example

The following example assumes you have a private key named "test.key", an X509 certificate named "test.crt", and a copy of the PayPal certificate named "paypal.crt" in the current directory:

    import ewp

    # String consisting of key=value lines separated by '\n'
    data = "12345..."

    signature = ewp.sign('test.key', 'test.crt', data)
    ciphertext = ewp.encrypt('paypal.crt', signature)

`ciphertext` can then be used as the value for the `<input name="encrypted">` field.

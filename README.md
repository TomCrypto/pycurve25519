pycurve25519
============

Python 2.7 wrapper for curve25519 (based on [curve25519-donna](https://code.google.com/p/curve25519-donna/)).

Usage
-----

    import curve25519
    
    # Generate two private keys
    privateA = curve25519.genkey()
    privateB = curve25519.genkey()
    
    # Obtain the equivalent public keys
    publicA = curve25519.public(privateA)
    publicB = curve25519.public(privateB)
    
    # Compute the shared secret (sharedA == sharedB)
    sharedA = curve25519.shared(privateA, publicB)
    sharedB = curve25519.shared(privateB, publicA)
    
    # Pass the shared secret in a KDF or other before use

Installation
------------

    python setup.py build
    python setup.py install
    python test_curve25519.py

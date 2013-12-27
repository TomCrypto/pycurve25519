from distutils.core import setup, Extension

module = Extension('curve25519',
                    sources = ['src/pycurve25519.c',
                               'src/curve25519-donna.c'])

setup (name = 'pycurve25519',
       version = '1.0',
       url = 'https://github.com/TomCrypto/pycurve25519',
       license = 'BSD',
       description = 'Python wrapper for curve25519',
       author = 'Thomas BENETEAU',
       author_email = 'thomas.beneteau@yahoo.fr',
       ext_modules = [module])

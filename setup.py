from distutils.core import setup, Extension

module = Extension('curve25519',
                    sources = ['src/pycurve25519.c', 'src/curve25519-donna.c' ])

setup (name = 'pycurve25519',
       version = '1.0',
       description = 'Python wrapper for curve25519',
       ext_modules = [module])

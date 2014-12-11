#include <Python.h>

extern void curve25519_donna(      uint8_t *mypublic,
                             const uint8_t *secret,
                             const uint8_t *basepoint);

static const uint8_t base_pt[32] = {9}; // x = 9

#if PY_MAJOR_VERSION >= 3

#include <string.h>

// Usage: private = curve25519.genkey() -> generate private key
static PyObject *curve25519_genkey(PyObject *self, PyObject *args)
{
    Py_buffer view;
    uint8_t private_key[32];
    PyObject *key_len = PyTuple_Pack(1, Py_BuildValue("i", 32));
    PyObject *os = PyImport_ImportModule("os");
    PyObject *urandom = PyObject_GetAttrString(os, (char*)"urandom");
    PyObject *random_bits = PyObject_CallObject(urandom, key_len);
    PyObject_GetBuffer(random_bits, &view, 0);
    memcpy(private_key, view.buf, 32);
    
    private_key[ 0] &= 248;
    private_key[31] &= 127;
    private_key[31] |=  64;

    return Py_BuildValue("y#", private_key, 32);
}

// Usage: public = curve25519.public(private) -> get public key
static PyObject *curve25519_public(PyObject *self, PyObject *args)
{
    Py_buffer private;

    if (PyArg_ParseTuple(args, "y*", &private))
    {
        uint8_t *pub_key = PyMem_Malloc(32); // public key
        curve25519_donna(pub_key, private.buf, base_pt);
        return Py_BuildValue("y#", pub_key, 32);
    }

    return 0;
}

// Usage: shared = curve25519.shared(your private key, his public key)
static PyObject *curve25519_shared(PyObject *self, PyObject *args)
{
    Py_buffer secret;
    Py_buffer public;

    if (PyArg_ParseTuple(args, "y*y*", &secret, &public))
    {
        uint8_t *shared = PyMem_Malloc(32); // shared secret
        curve25519_donna(shared, secret.buf, public.buf);
        return Py_BuildValue("y#", shared, 32);
    }

    return 0;
}

static PyMethodDef curve25519_methods[] = 
{
    {"genkey",  curve25519_genkey, METH_VARARGS,
     "Randomly generates a new private key"},
    {"public",  curve25519_public, METH_VARARGS,
     "Computes a public key from a private key"},
    {"shared",  curve25519_shared, METH_VARARGS,
     "Generates a shared secret from a key pair"},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef curve25519_module = 
{
    PyModuleDef_HEAD_INIT,
    "curve25519",
    "Python wrapper for curve25519.",
    -1,
    curve25519_methods
};

PyMODINIT_FUNC PyInit_curve25519(void)
{
    return PyModule_Create(&curve25519_module);
}

int main(int argc, char *argv[])
{
    PyImport_AppendInittab("curve25519", PyInit_curve25519);
    wchar_t progname[FILENAME_MAX + 1];
    mbstowcs(progname, argv[0], strlen(argv[0]) + 1);
    Py_SetProgramName(progname);
    Py_Initialize();
    return 0;
}

#else

// Usage: private = curve25519.genkey() -> generate private key
static PyObject *curve25519_genkey(PyObject *self, PyObject *args)
{
    Py_buffer view;
    uint8_t private_key[32];
    PyObject *key_len = PyTuple_Pack(1, Py_BuildValue("i", 32));
    PyObject *os = PyImport_Import(PyString_FromString((char*)"os"));
    PyObject *urandom = PyObject_GetAttrString(os, (char*)"urandom");
    PyObject *random_bits = PyObject_CallObject(urandom, key_len);
    PyObject_GetBuffer(random_bits, &view, 0);
    memcpy(private_key, view.buf, 32);
    
    private_key[ 0] &= 248;
    private_key[31] &= 127;
    private_key[31] |=  64;

    return Py_BuildValue("s#", private_key, 32);
}

// Usage: public = curve25519.public(private) -> get public key
static PyObject *curve25519_public(PyObject *self, PyObject *args)
{
    Py_buffer private;

    if (PyArg_ParseTuple(args, "s*", &private))
    {
        uint8_t *pub_key = PyMem_Malloc(32); // public key
        curve25519_donna(pub_key, private.buf, base_pt);
        return Py_BuildValue("s#", pub_key, 32);
    }

    return 0;
}

// Usage: shared = curve25519.shared(your private key, his public key)
static PyObject *curve25519_shared(PyObject *self, PyObject *args)
{
    Py_buffer secret;
    Py_buffer public;

    if (PyArg_ParseTuple(args, "s*s*", &secret, &public))
    {
        uint8_t *shared = PyMem_Malloc(32); // shared secret
        curve25519_donna(shared, secret.buf, public.buf);
        return Py_BuildValue("s#", shared, 32);
    }

    return 0;
}

static PyMethodDef curve25519_methods[] = 
{
    {"genkey",  curve25519_genkey, METH_VARARGS,
     "Randomly generates a new private key"},
    {"public",  curve25519_public, METH_VARARGS,
     "Computes a public key from a private key"},
    {"shared",  curve25519_shared, METH_VARARGS,
     "Generates a shared secret from a key pair"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initcurve25519(void)
{
    (void)Py_InitModule("curve25519", curve25519_methods);
}

int main(int argc, char *argv[])
{
    Py_SetProgramName(argv[0]);
    Py_Initialize();
    initcurve25519();
    return 0;
}

#endif

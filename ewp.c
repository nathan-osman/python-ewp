/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Nathan Osman
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 **/

#include <Python.h>
#include <bytesobject.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/ssl.h>

/* There are a few subtle differences between Python 2.x and 3.x */
#if PY_MAJOR_VERSION >= 3
#define IS_PY3K
#endif

static PyObject *ewp_sign(PyObject *self, PyObject *args)
{
    const char *keyFn, *certFn, *input;
    int inputLen;
    BIO *bioKey = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bioCert = NULL;
    X509 *x509 = NULL;
    BIO *bioInput = NULL;
    PKCS7 *p7 = NULL;
    BIO *bioOutput = NULL;
    char *output;
    long outputLen;
    PyObject *signature = NULL;

    if (!PyArg_ParseTuple(args, "sss#", &keyFn, &certFn, &input, &inputLen)) {
        return NULL;
    }

    /* Read the contents of the private key */
    bioKey = BIO_new_file(keyFn, "r");
    if (!bioKey) {
        PyErr_SetString(PyExc_IOError, "unable to open private key");
        goto end;
    }

    /* Attempt to load the private key as a PEM-encoded file */
    pkey = PEM_read_bio_PrivateKey(bioKey, NULL, NULL, NULL);
    if (!pkey) {
        PyErr_SetString(PyExc_IOError, "unable to read private key");
        goto end;
    }

    /* Read the contents of the certificate */
    bioCert = BIO_new_file(certFn, "r");
    if (!bioCert) {
        PyErr_SetString(PyExc_IOError, "unable to open certificate");
        goto end;
    }

    /* Attempt to load the certificate as a PEM-encoded file */
    x509 = PEM_read_bio_X509(bioCert, NULL, NULL, NULL);
    if (!x509) {
        PyErr_SetString(PyExc_IOError, "unable to read certificate");
        goto end;
    }

    /* Create a BIO from the input data in memory */
    bioInput = BIO_new_mem_buf((void *)input, inputLen);
    if (!bioInput) {
        PyErr_SetString(PyExc_RuntimeError, "unable to create input BIO");
        goto end;
    }

    /* Sign the data */
    p7 = PKCS7_sign(x509, pkey, NULL, bioInput, PKCS7_BINARY);
    if (!p7) {
        PyErr_SetString(PyExc_RuntimeError, "unable to sign data");
        goto end;
    }

    /* Create a BIO for writing the DER-encoded output */
    bioOutput = BIO_new(BIO_s_mem());
    if (!bioOutput) {
        PyErr_SetString(PyExc_RuntimeError, "unable to create output BIO");
        goto end;
    }

    /* Write the DER-encoded data to the BIO */
    if (!i2d_PKCS7_bio(bioOutput, p7)) {
        PyErr_SetString(PyExc_RuntimeError, "unable to write signature");
        goto end;
    }

    /* Obtain a pointer to the data and set the return value */
    outputLen = BIO_get_mem_data(bioOutput, &output);
    signature = PyBytes_FromStringAndSize(output, outputLen);

end:

    if (bioOutput) {
        BIO_free(bioOutput);
    }

    if (p7) {
        PKCS7_free(p7);
    }

    if (bioInput) {
        BIO_free(bioInput);
    }

    if (x509) {
        X509_free(x509);
    }

    if (bioCert) {
        BIO_free(bioCert);
    }

    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (bioKey) {
        BIO_free(bioKey);
    }

    return signature;
}

static PyMethodDef EWPMethods[] = {
    { "sign", ewp_sign, METH_VARARGS, "Sign input" },
    { NULL, NULL, 0, NULL }
};

#ifdef IS_PY3K
static struct PyModuleDef ewpmodule = {
    PyModuleDef_HEAD_INIT,
    "ewp",
    NULL,
    -1,
    EWPMethods
};
#endif

#ifdef IS_PY3K
PyMODINIT_FUNC PyInit_ewp(void)
#else
PyMODINIT_FUNC initewp(void)
#endif
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
    /* Prior to OpenSSL 1.1.0, the library must be initialized by calling
       SSL_library_init() */
    SSL_library_init();
#endif

#ifdef IS_PY3K
    return PyModule_Create(&ewpmodule);
#else
    (void) Py_InitModule("ewp", EWPMethods);
#endif
}

/* This software was developed at the National Institute of
 * Standards and Technology by employees of the Federal
 * Government in the course of their official duties.
 * Pursuant to title 17 Section 105 of the United States Code
 * this software is not subject to copyright protection and
 * is in the public domain. We would appreciate acknowledgement
 * if the software is used.
 */

/* This program takes as input a file that contains a DER encoded
 * certificate and checks that the certificate is correctly
 * encoded according to X.509 and that it was issued in
 * conformance with RFC 5280.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cert_check.h"

#define	MAX_INPUT		100000	/* maximum length of the input file */

/* indicates whether the subject field contains an empty SEQUENCE */
int is_subject_empty;

/* signature_oid holds the value of the OID
 * in the signature field of TBSCertificate and signature_parameters and
 * signature_parameters_length hold the value and length of the parameters
 * field the signature field of TBSCertificate.  These are to be
 * compared against the same fields in the signatureAlgoritm field of Certificate.
 */
char *signature_oid;
unsigned char *signature_parameters;
int signature_parameters_length;

int subjectPublicKeyType;

/* Validate parameters field for RSA-SSAPSS:
 *       RSASSA-PSS-params  ::=  SEQUENCE  {
 *          hashAlgorithm      [0] HashAlgorithm DEFAULT
 *          sha1Identifier,
 *          maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
 *          mgf1SHA1Identifier,
 *          saltLength         [2] INTEGER DEFAULT 20,
 *          trailerField       [3] INTEGER DEFAULT 1  }
 */
int validate_RSA_SSAPSS_parameters(unsigned char *parameters, int parameters_len)
{
    int tag, length, hashAlgorithm_tag, hashAlgorithm_length, maskGenAlgorithm_tag, maskGenAlgorithm_length, saltLength_value;
    unsigned char *hashAlgorithm = NULL;
    unsigned char *maskGenAlgorithm = NULL;
    unsigned char *saltLength;
    char *hashAlgorithm_OID = NULL;
    char *maskGenAlgorithm_OID = NULL;
    char *maskGenAlgorithm_hashAlgorithm_OID = NULL;

    push_error_stack("RSASSA-PSS parameters");

    if ((tag = get_tag(&parameters, &parameters_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Error: RSASSA-PSS-params is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&parameters, &parameters_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != parameters_len) {
        print_error("Error: parameters field contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        /* All parameter fields set to DEFAULT values */
        pop_error_stack();
        return(0);
    }

    if (*parameters == 0xA0) {
        /* hashAlgorithm ::= SEQUENCE { OBJECT IDENTIFIER, parameters } */
        if ((tag = get_tag(&parameters, &parameters_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((length = get_length(&parameters, &parameters_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        hashAlgorithm = parameters;
        parameters += length;
        parameters_len -= length;

        if ((hashAlgorithm_tag = get_tag(&hashAlgorithm, &length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((hashAlgorithm_length = get_length(&hashAlgorithm, &length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (hashAlgorithm_tag != 0x30) {
            print_error("Error: hashAlgorithm field of RSASSA-PSS-params is not encoded as a SEQUENCE.");
            pop_error_stack();
 	    return(-1);
        }

        if (hashAlgorithm_length != length) {
            print_error("Error: Encoding of hashAlgorithm field of RSASSA-PSS-params contains extraneous data.");
            pop_error_stack();
 	    return(-1);
        }

        if (get_OID(&hashAlgorithm, &hashAlgorithm_length, &hashAlgorithm_OID) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((strcmp(hashAlgorithm_OID, "1.3.14.3.2.26") == 0) ||
            (strcmp(hashAlgorithm_OID, "2.16.840.1.101.3.4.2.1") == 0) ||
            (strcmp(hashAlgorithm_OID, "2.16.840.1.101.3.4.2.2") == 0) ||
            (strcmp(hashAlgorithm_OID, "2.16.840.1.101.3.4.2.3") == 0) ||
            (strcmp(hashAlgorithm_OID, "2.16.840.1.101.3.4.2.4") == 0)) {
            /* hashAlgorithm is SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 */
            if (strcmp(hashAlgorithm_OID, "1.3.14.3.2.26") == 0) {
                print_error("Error: RSASSA-PSS-params are not DER encoded.  DEFAULT value for hashAlgorithm appears in encoding.");
            }
            if (hashAlgorithm_length == 0) {
                /* This is the correct encoding.  Parameters should be absent. */
                ;
            } else if ((hashAlgorithm_length == 2) && (*hashAlgorithm == 0x05) && (*(hashAlgorithm+1) == 0x00)) {
                print_error("Warning: Parameters field for hashAlgorithm in RSASSA-PSS-params should be absent.");
            } else {
                print_error("Error: Incorrect value for parameters field for hashAlgorithm in RSASSA-PSS-params.");
                pop_error_stack();
                return(-1);
            }
        } else {
            print_error("Warning: hashAlgorithm in RSASSA-PSS-params is not recognized.");
        }
    }

    if (hashAlgorithm_OID == NULL) {
        hashAlgorithm_OID = (char *)malloc(14);
        if (hashAlgorithm_OID == NULL) {
            pop_error_stack();
            return(-1);
        }
        strcpy(hashAlgorithm_OID, "1.3.14.3.2.26");
    }

    if (parameters_len == 0) {
        if (strcmp(hashAlgorithm_OID, "1.3.14.3.2.26") != 0) {
            print_error("Warning: RFC 4055 recommends using same hash algorithm in both maskGenAlgorithm and hashAlgorithm and saltLength that is same as length of hash value generated by hashAlgorithm.");
        }
        free(hashAlgorithm_OID);
        pop_error_stack();
        return(0);
    }

    if (*parameters == 0xA1) {
        if ((tag = get_tag(&parameters, &parameters_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((length = get_length(&parameters, &parameters_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        maskGenAlgorithm = parameters;
        parameters += length;
        parameters_len -= length;

        if ((maskGenAlgorithm_tag = get_tag(&maskGenAlgorithm, &length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((maskGenAlgorithm_length = get_length(&maskGenAlgorithm, &length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (maskGenAlgorithm_tag != 0x30) {
            print_error("Error: maskGenAlgorithm field of RSASSA-PSS-params is not encoded as a SEQUENCE.");
            pop_error_stack();
 	    return(-1);
        }

        if (maskGenAlgorithm_length != length) {
            print_error("Error: Encoding of maskGenAlgorithm field of RSASSA-PSS-params contains extraneous data.");
            pop_error_stack();
 	    return(-1);
        }

        if (get_OID(&maskGenAlgorithm, &maskGenAlgorithm_length, &maskGenAlgorithm_OID) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (strcmp(maskGenAlgorithm_OID, "1.2.840.113549.1.1.8") != 0) {
            print_error("Warning: Unknown mask generation algorithm.");
        } else {
            /* mask generation algorithm is MGF1. Parameters field must be a hash function */
            if ((tag = get_tag(&maskGenAlgorithm, &maskGenAlgorithm_length)) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(&maskGenAlgorithm, &maskGenAlgorithm_length)) == -1) {
                pop_error_stack();
                return(-1);
            }

            if (tag != 0x30) {
                print_error("Error: parameters field of maskGenAlgorithm field of RSASSA-PSS-params is not encoded as a SEQUENCE.");
                pop_error_stack();
                return(-1);
            }

            if (length != maskGenAlgorithm_length) {
                print_error("Error: Encoding of &maskGenAlgorithm field of RSASSA-PSS-params contains extraneous data.");
                pop_error_stack();
                return(-1);
            }

            if (get_OID(&maskGenAlgorithm, &maskGenAlgorithm_length, &maskGenAlgorithm_hashAlgorithm_OID) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((strcmp(maskGenAlgorithm_hashAlgorithm_OID, "1.3.14.3.2.26") == 0) ||
                (strcmp(maskGenAlgorithm_hashAlgorithm_OID, "2.16.840.1.101.3.4.2.1") == 0) ||
                (strcmp(maskGenAlgorithm_hashAlgorithm_OID, "2.16.840.1.101.3.4.2.2") == 0) ||
                (strcmp(maskGenAlgorithm_hashAlgorithm_OID, "2.16.840.1.101.3.4.2.3") == 0) ||
                (strcmp(maskGenAlgorithm_hashAlgorithm_OID, "2.16.840.1.101.3.4.2.4") == 0)) {
                /* hashAlgorithm is SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 */
                if (strcmp(maskGenAlgorithm_hashAlgorithm_OID, "1.3.14.3.2.26") == 0) {
                    print_error("Error: RSASSA-PSS-params are not DER encoded.  DEFAULT value for maskGenAlgorithm appears in encoding.");
                }
                if (maskGenAlgorithm_length == 0) {
                    /* This is the correct encoding.  Parameters should be absent. */
                    ;
                } else if ((maskGenAlgorithm_length == 2) && (*maskGenAlgorithm == 0x05) && (*(maskGenAlgorithm+1) == 0x00)) {
                    print_error("Warning: Parameters field for hashAlgorithm in maskGenAlgorithm in RSASSA-PSS-params should be absent.");
                } else {
                    print_error("Error: Incorrect value for parameters field for hashAlgorithm in maskGenAlgorithm in RSASSA-PSS-params.");
                    pop_error_stack();
                    return(-1);
                }
            } else {
                print_error("Warning: hashAlgorithm in maskGenAlgorithm in RSASSA-PSS-params is not recognized.");
            }

            if (strcmp(maskGenAlgorithm_hashAlgorithm_OID, hashAlgorithm_OID) != 0) {
                print_error("Warning: RFC 4055 recommends using the same hash algorihm for maskGenAlgorithm and hashAlgorithm in RSASSA-PSS-params.");
            }
        }
    }

    if (parameters_len == 0) {
        if (strcmp(hashAlgorithm_OID, "1.3.14.3.2.26") != 0) {
            print_error("Warning: RFC 4055 recommends using a saltLength that is same as length of hash value generated by hashAlgorithm.");
        }
        if (hashAlgorithm_OID != NULL) free(hashAlgorithm_OID);
        if (maskGenAlgorithm_OID != NULL) free(maskGenAlgorithm_OID);
        if (maskGenAlgorithm_hashAlgorithm_OID != NULL) free(maskGenAlgorithm_hashAlgorithm_OID);
        pop_error_stack();
        return(0);
    }

    if (*parameters == 0xA2) {
        if ((tag = get_tag(&parameters, &parameters_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((length = get_length(&parameters, &parameters_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        saltLength = parameters;
        parameters += length;
        parameters_len -= length;

        if ((length != 3) || (*saltLength != 0x02) || (*(saltLength+1) != 0x01) || ((*(saltLength+2) & 0x80) != 0)) {
            push_error_stack("saltLength");
            if (validate_INTEGER(&saltLength, &length, 1) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            } else {
                print_error("Warning: RFC 4055 recommends using a saltLength that is same as length of hash value generated by hashAlgorithm.");
            }
            pop_error_stack();
        } else {
            saltLength_value = *(saltLength+2);
            length = 0;

            if (saltLength_value == 20) {
                print_error("Error: RSASSA-PSS-params are not DER encoded.  DEFAULT value for saltLength appears in encoding.");
            }

            if (((strcmp(hashAlgorithm_OID, "1.3.14.3.2.26") == 0) && (saltLength_value != 20)) ||
                ((strcmp(hashAlgorithm_OID, "2.16.840.1.101.3.4.2.1") == 0) && (saltLength_value != 32)) ||
                ((strcmp(hashAlgorithm_OID, "2.16.840.1.101.3.4.2.2") == 0) && (saltLength_value != 48)) ||
                ((strcmp(hashAlgorithm_OID, "2.16.840.1.101.3.4.2.3") == 0) && (saltLength_value != 64)) ||
                ((strcmp(hashAlgorithm_OID, "2.16.840.1.101.3.4.2.4") == 0) && (saltLength_value != 28))) {
                print_error("Warning: RFC 4055 recommends using a saltLength that is same as length of hash value generated by hashAlgorithm.");
            }
        }

        if (length != 0) {
            print_error("Error: Encoding of saltLength field of RSASSA-PSS-params contains extraneous data.");
            pop_error_stack();
 	    return(-1);
        }
    }

    if (parameters_len == 0) {
        if (hashAlgorithm_OID != NULL) free(hashAlgorithm_OID);
        if (maskGenAlgorithm_OID != NULL) free(maskGenAlgorithm_OID);
        if (maskGenAlgorithm_hashAlgorithm_OID != NULL) free(maskGenAlgorithm_hashAlgorithm_OID);
        pop_error_stack();
        return(0);
    }

    /* trailerField */
    if ((tag = get_tag(&parameters, &parameters_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&parameters, &parameters_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0xA4) {
        print_error("Error: Unexpected tag in RSASSA-PSS-params.");
        pop_error_stack();
        return(-1);
    }

    if (length != parameters_len) {
        print_error("Error: Encoding of RSASSA-PSS-params contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if ((length == 3) && (*parameters == 0x02) && (*(parameters+1) == 0x01) && (*(parameters+2) == 0x01)) {
        print_error("Error: RSASSA-PSS-params are not DER encoded.  DEFAULT value for trailerField appears in encoding.");
    } else {
        push_error_stack("trailerField");
        if (validate_INTEGER(&parameters, &parameters_len, 1) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        print_error("Warning: RFC 4055 requires trailerField to have a value of 1.");
        pop_error_stack();
    }

    if (hashAlgorithm_OID != NULL) free(hashAlgorithm_OID);
    if (maskGenAlgorithm_OID != NULL) free(maskGenAlgorithm_OID);
    if (maskGenAlgorithm_hashAlgorithm_OID != NULL) free(maskGenAlgorithm_hashAlgorithm_OID);
    pop_error_stack();
    return(0);
}

/* Validate signature (or signatureAlgorithm) field, which
 * is of type:
 *    AlgorithmIdentifier  ::=  SEQUENCE  {
 *         algorithm               OBJECT IDENTIFIER,
 *         parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *
 * where algorithm contains the OID of a signature algorithm and
 * parameters contains the corresponding parameters, if any.
 * Return -1 if there is an error.
 */
int validate_signatureAlgorithm(unsigned char **input, int *input_len, char **oid, unsigned char **parameters, int *parameters_len)
{
    int tag, AlgorithmIdentifier_length;

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Error: AlgorithmIdentifier is not encoded as a SEQUENCE.");
        return(-1);
    }

    if ((AlgorithmIdentifier_length = get_length(input, input_len)) == -1) {
        return(-1);
    }

    *input_len -= AlgorithmIdentifier_length;

    if (get_OID(input, &AlgorithmIdentifier_length, oid) == -1) {
        return(-1);
    }

    /* get parameters */
    if (AlgorithmIdentifier_length == 0) {
        *parameters_len = 0;
        *parameters = NULL;
    } else {
        /* Assume what's left are the parameters */
        *parameters_len = AlgorithmIdentifier_length;
        *parameters = (unsigned char *)malloc(AlgorithmIdentifier_length);
        memcpy(*parameters, *input, AlgorithmIdentifier_length);

        /* Perform basic sanity check on parameters and verify there is no extraneous data after parameters field. */
        if (validate_generic_DER(input, &AlgorithmIdentifier_length) == -1) {
            print_error("Error: parameters field of AlgorithmIdentifier is not DER encoded.");
            free(*parameters);
            return(-1);
        }

        if (AlgorithmIdentifier_length > 0) {
            print_error("Error: AlgorithmIdentifier SEQUENCE contains extraneous data.");
            return(-1);
        }
    }

    /* Check that the OID and parameters are a valid combination */
    if ((strcmp(*oid, "1.2.840.113549.1.1.2") == 0) ||
        (strcmp(*oid, "1.2.840.113549.1.1.3") == 0) ||
        (strcmp(*oid, "1.2.840.113549.1.1.4") == 0) ||
        (strcmp(*oid, "1.2.840.113549.1.1.5") == 0) ||
        (strcmp(*oid, "1.2.840.113549.1.1.11") == 0) ||
        (strcmp(*oid, "1.2.840.113549.1.1.12") == 0) ||
        (strcmp(*oid, "1.2.840.113549.1.1.13") == 0) ||
        (strcmp(*oid, "1.2.840.113549.1.1.14") == 0)) {
        /* RSA with MD2, MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 */
        /* parameters field must contain NULL */
        if ((*parameters_len != 2) || ((*parameters)[0] != 0x05) || ((*parameters)[1] != 0x00)) {
            print_error("Error: Parameters field does not contain NULL.");
        }
    } else if (strcmp(*oid, "1.2.840.113549.1.1.10") == 0) {
        /* RSA-SSAPSS */
        validate_RSA_SSAPSS_parameters(*parameters, *parameters_len);
    } else if ((strcmp(*oid, "1.2.840.10045.4.1") == 0) ||
                (strcmp(*oid, "1.2.840.10045.4.3.1") == 0) ||
                (strcmp(*oid, "1.2.840.10045.4.3.2") == 0) ||
                (strcmp(*oid, "1.2.840.10045.4.3.3") == 0) ||
                (strcmp(*oid, "1.2.840.10045.4.3.4") == 0) ||
                (strcmp(*oid, "1.2.840.10040.4.3") == 0) ||
                (strcmp(*oid, "2.16.840.1.101.3.4.3.1") == 0) ||
                (strcmp(*oid, "2.16.840.1.101.3.4.3.2") == 0)) {
        /* ECDSA with SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 or
        * DSA with SHA-1, SHA-224, or SHA-256 */
        if (*parameters_len != 0) {
            print_error("Error: Parameters field must be absent for DSA or ECDSA.");
        }
    } else if ((strcmp(*oid, "1.3.101.112") == 0) ||
        (strcmp(*oid, "1.3.101.113") == 0)) {
        /* EdDSA */
        if (*parameters_len != 0) {
            print_error("Error: Parameters field must be absent for EdDSA.");
        }
    } else {
        print_error("Warning: Unrecognized signature algorithm.  Cannot check parameters field.");
    }
    return(0);
}

/*
 * Dss-Parms  ::=  SEQUENCE  {
 *     p             INTEGER,
 *     q             INTEGER,
 *     g             INTEGER  }
 */
int validate_DSA_parameters(unsigned char *input, int input_len)
{
    int tag, pqg_length;

    if ((tag = get_tag(&input, &input_len)) == -1) {
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Error: DSA parameters are not encoded as a SEQUENCE.");
        return(-1);
    }

    if ((pqg_length = get_length(&input, &input_len)) == -1) {
        return(-1);
    }

    if (pqg_length != input_len) {
        print_error("Error: Length of DSA parameters SEQUENCE is incorrect.");
        return(-1);
    }

    if (validate_INTEGER(&input, &input_len, 1) == -1) {
        return(-1);
    }

    if (validate_INTEGER(&input, &input_len, 1) == -1) {
        return(-1);
    }

    if (validate_INTEGER(&input, &input_len, 1) == -1) {
        return(-1);
    }

    if (input_len != 0) {
        print_error("Error: parameters field contains extraneous data.");
        return(-1);
    }

    return(0);
}

/*
 * RSAPublicKey ::= SEQUENCE {
 *    modulus            INTEGER,    -- n
 *    publicExponent     INTEGER  }  -- e
 */
int validate_RSAPublicKey(unsigned char *input, int input_len)
{
    int tag, length;

    push_error_stack("RSAPublicKey");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("RSAPublicKey is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of subjectPublicKey BITSTRING contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (validate_INTEGER(&input, &input_len, 1) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (validate_INTEGER(&input, &input_len, 1) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (input_len > 0) {
        print_error("Error: Encoding of RSAPublicKey SEQUENCE contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/*
 *    SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *         algorithm            AlgorithmIdentifier,
 *         subjectPublicKey     BIT STRING  }
 */
int validate_subjectPublicKeyInfo(unsigned char **input, int *input_len)
{
    int tag, length, AlgorithmIdentifier_length, subjectPublicKeyInfo_length, parameters_len, subjectPublicKey_length;
    unsigned char *parameters, *parameters_contents;
    char *oid, *namedCurve_oid;

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }
    if (tag != 0x30) {
        print_error("AlgorithmIdentifier is not encoded as a SEQUENCE.");
        return(-1);
    }

    if ((subjectPublicKeyInfo_length = get_length(input, input_len)) == -1) {
        return(-1);
    }
    *input_len -= subjectPublicKeyInfo_length;

    /* algorithm is a AlgorithmIdentifier */
    if ((tag = get_tag(input, &subjectPublicKeyInfo_length)) == -1) {
        return(-1);
    }
    if (tag != 0x30) {
        print_error("AlgorithmIdentifier is not encoded as a SEQUENCE.");
    }

    if ((AlgorithmIdentifier_length = get_length(input, &subjectPublicKeyInfo_length)) == -1) {
        return(-1);
    }
    subjectPublicKeyInfo_length -= AlgorithmIdentifier_length;

    if (get_OID(input, &AlgorithmIdentifier_length, &oid) == -1) {
        return(-1);
    }

    /* get parameters */
    if (AlgorithmIdentifier_length == 0) {
        parameters_len = 0;
        parameters = NULL;
    } else {
        /* Assume what's left are the parameters */
        parameters_len = AlgorithmIdentifier_length;
        parameters = (unsigned char *)malloc(AlgorithmIdentifier_length);
        memcpy(parameters, *input, AlgorithmIdentifier_length);

        if ((tag = get_tag(input, &AlgorithmIdentifier_length)) == -1) {
            return(-1);
        }
        if ((length = get_length(input, &AlgorithmIdentifier_length)) == -1) {
            return(-1);
        }

        if (length != AlgorithmIdentifier_length) {
            print_error("Error: AlgorithmIdentifier SEQUENCE contains extraneous data.");
            return(-1);
        }

        *input += length;
    }

    if (strcmp(oid, "1.2.840.113549.1.1.1") == 0) {
        subjectPublicKeyType = SPK_RSA;
    } else if (strcmp(oid, "1.2.840.10045.2.1") == 0) {
        subjectPublicKeyType = SPK_ECC;
    } else if (strcmp(oid, "1.3.132.1.12") == 0) {
        subjectPublicKeyType = SPK_ECDH;
    } else if (strcmp(oid, "1.3.132.1.13") == 0) {
        subjectPublicKeyType = SPK_ECMQV;
    } else if (strcmp(oid, "1.2.840.10040.4.1") == 0) {
        subjectPublicKeyType = SPK_DSA;
    } else if (strcmp(oid, "1.3.101.110") == 0) {
        subjectPublicKeyType = SPK_X25519;
    } else if (strcmp(oid, "1.3.101.111") == 0) {
        subjectPublicKeyType = SPK_X448;
    } else if (strcmp(oid, "1.3.101.112") == 0) {
        subjectPublicKeyType = SPK_ED25519;
    } else if (strcmp(oid, "1.3.101.113") == 0) {
        subjectPublicKeyType = SPK_ED448;
    } else {
        subjectPublicKeyType = SPK_UNKNOWN;
    }


    /* Check that the OID and parameters are a valid combination */
    if (subjectPublicKeyType == SPK_RSA) {
        /* RSA subject public key.  Parameters must be NULL */
        if ((parameters_len != 2) || (parameters[0] != 0x05) || (parameters[1] != 0x00)) {
            print_error("Incorrect or missing parameters for RSA subject public key.");
            return(-1);
        }
    } else if ((subjectPublicKeyType == SPK_ECC) || (subjectPublicKeyType == SPK_ECDH) ||
                (subjectPublicKeyType == SPK_ECMQV)) {
        /* Elliptic curve subject public key - id-ecPublicKey, id-id-ecDH, or id-ecMQV */
        if (parameters_len == 0) {
            print_error("ERROR: Parameters field absent for Elliptic Curve subject public key.");
            return(-1);
        }

        tag = *parameters;
        if (tag == 0x06) {
            /* namedCurve */
            parameters_contents = parameters;
            if (get_OID(&parameters_contents, &parameters_len, &namedCurve_oid) == -1) {
                print_error("ERROR: Parameters field contains invalid value.");
                return(-1);
            }
            free(namedCurve_oid);
        } else if (tag == 0x05) {
            /* implicitCurve */
            if (parameters_len != 2) {
                print_error("ERROR: Parameters field contains invalid value.");
                return(-1);
            }
            if (*(parameters + 1) == 0)
                print_error("Warning: CAs conforming to PKIX profile MUST NOT encode parameters as implicitCurve.");
            else
                print_error("ERROR: Parameters field contains invalid value.");
        } else if (tag == 0x30) {
            /* specifiedCurve */
            print_error("Warning: CAs conforming to PKIX profile MUST NOT encode parameters as specifiedCurve.  Contents of parameters field not checked.");
            parameters_contents = parameters;
            if (validate_generic_DER(&parameters_contents, &parameters_len) == -1) {
                return(-1);
            }
        }
    } else if (subjectPublicKeyType == SPK_DSA) {
        /* DSA */
        if (parameters_len != 0) {
            /* parameters are not inherited */
            push_error_stack("DSA parameters");
            validate_DSA_parameters(parameters, parameters_len);
            pop_error_stack();
    }
    } else if ( (subjectPublicKeyType == SPK_X25519) || (subjectPublicKeyType == SPK_X448) ||
                (subjectPublicKeyType == SPK_ED25519) || (subjectPublicKeyType == SPK_ED448) ) {
        if (parameters_len != 0) {
            print_error("ERROR: Parameters field must be absent for X25519, X448, ED25519, and ED448.");
            return(-1);
        }
    } else {
        print_error("Warning: Unrecognized subject public key algorithm.  Cannot check parameters field.");
        parameters_contents = parameters;
        if ((parameters_len != 0 ) && (validate_generic_DER(&parameters_contents, &parameters_len) == -1)) {
            return(-1);
        }
    }

    free(oid);
    free(parameters);

    push_error_stack("subjectPublicKey");
    if ((tag = get_tag(input, &subjectPublicKeyInfo_length)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x03) {
        print_error("subjectPublicKey is not encoded as a BIT STRING.");
    }

    if ((subjectPublicKey_length = get_length(input, &subjectPublicKeyInfo_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (subjectPublicKey_length != subjectPublicKeyInfo_length) {
        print_error("Error: subjectPublicKeyInfo contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (validate_BITSTRING(subjectPublicKey_length, *input, 0) == -1) {
        pop_error_stack();
        return(-1);
    }

    /* TODO: Check contents of subjectPublicKey.  Just skip over for now. */
    if (subjectPublicKeyType == SPK_RSA) {
        if (**input != 0) {
            print_error("Error: Number of unused bits in subjectPublicKey BIT STRING must be 0.");
            pop_error_stack();
            return(-1);
        }
        *input += 1;
        subjectPublicKey_length -= 1;
        if (validate_RSAPublicKey(*input, subjectPublicKey_length) == -1) {
            pop_error_stack();
            return(-1);
        }
    } else if (subjectPublicKeyType == SPK_DSA) {
        if (**input != 0) {
            print_error("Error: Number of unused bits in subjectPublicKey BIT STRING must be 0.");
            pop_error_stack();
            return(-1);
        }
        *input += 1;
        subjectPublicKey_length -= 1;
        if (validate_INTEGER(input, &subjectPublicKey_length, 1) == -1) {
            pop_error_stack();
            return(-1);
        }
        if (subjectPublicKey_length > 0) {
            print_error("Error: subjectPublicKey BIT STRING contains extraneous data.");
            pop_error_stack();
            return(-1);
        }
    } else if ((subjectPublicKeyType == SPK_ECC) || (subjectPublicKeyType == SPK_ECDH) || (subjectPublicKeyType == SPK_ECMQV)) {
        if (**input != 0) {
            print_error("Error: Number of unused bits in subjectPublicKey BIT STRING must be 0.");
            pop_error_stack();
            return(-1);
        }
        *input += 1;
        subjectPublicKey_length -= 1;
        if ((**input != 0x02) && (**input != 0x03) && (**input != 0x04)) {
            print_error("Error: The first octet of the ECC subjectPublicKey must be 0x02, 0x03, or 0x04 (RFC 5480, Section 2.2).");
            pop_error_stack();
            return(-1);
        }
    } else if ((subjectPublicKeyType == SPK_X25519) || (subjectPublicKeyType == SPK_X448) ||
        (subjectPublicKeyType == SPK_ED25519) || (subjectPublicKeyType == SPK_ED448)) {
        if (**input != 0) {
            print_error("Error: Number of unused bits in subjectPublicKey BIT STRING must be 0.");
            pop_error_stack();
            return(-1);
        }
    }

    *input += subjectPublicKey_length;
    pop_error_stack();
    return(0);
}


/*
 * TBSCertificate  ::=  SEQUENCE  {
 *      version         [0]  EXPLICIT Version DEFAULT v1,
 *      serialNumber         CertificateSerialNumber,
 *      signature            AlgorithmIdentifier,
 *      issuer               Name,
 *      validity             Validity,
 *      subject              Name,
 *      subjectPublicKeyInfo SubjectPublicKeyInfo,
 *      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                           -- If present, version MUST be v2 or v3
 *      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                           -- If present, version MUST be v2 or v3
 *      extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                           -- If present, version MUST be v3
 *      }
 */
int validate_TBSCertificate(unsigned char **input, int *input_len)
{
    int tag, TBSCertificate_length, validity_length, length, version, UniqueID_length;
    int extensions_length, is_issuer_empty;

    push_error_stack("TBSCertificate");

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("TBSCertificate is not encoded as a SEQUENCE.");
    }

    if ((TBSCertificate_length = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    *input_len -= TBSCertificate_length;

    if (TBSCertificate_length == 0) {
        print_error("ERROR: TBSCertificate is empty.");
        return(-1);
    }

    /* version */
    if (**input == 0xA0) {
        if ((tag = get_tag(input, &TBSCertificate_length)) == -1) {
            pop_error_stack();
            return(-1);
        }
        if (tag != 0xA0) {
            print_error("Incorrect tag encountered where either Version (tag A0) or serialNumber (tag 02) should be.");
            pop_error_stack();
            return(-1);
        }

        /* parse version */
        if ((length = get_length(input, &TBSCertificate_length)) == -1) {
            pop_error_stack();
            return(-1);
        }
        if (length != 3) {
            print_error("Incorrect length for encoding of version after tag [1].");
            pop_error_stack();
            return(-1);
        }

        /* next should be the tag for INTEGER */
        if ((tag = get_tag(input, &TBSCertificate_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x02) {
            print_error("Version not encoded as an INTEGER.");
            pop_error_stack();
            return(-1);
        }

        if ((length = get_length(input, &TBSCertificate_length)) == -1) {
            pop_error_stack();
            return(-1);
        }
        if (length != 1) {
            print_error("Version should be encoded as an INTEGER of length 1.");
            pop_error_stack();
            return(-1);
        }

        if (**input == 0) {
            print_error("For Version, default value of v1 MUST NOT appear in DER encoding.");
            pop_error_stack();
            return(-1);
        } else if (**input > 2) {
            print_error("Invalid value for Version.");
            pop_error_stack();
            return(-1);
        }

        version = **input + 1;
        *input += 1;
        TBSCertificate_length -= 1;
    } else {
        /* assume this is a version 1 certificate. */
        version = 1;
    }

    /* serialNumber */
    if ((tag = get_tag(input, &TBSCertificate_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x02) {
        print_error("Incorrect tag encountered where either Version (tag A0) or serialNumber (tag 02) should be.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(input, &TBSCertificate_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: serial number has a length of zero octets.");
        pop_error_stack();
        return(-1);
    }

    if (length > 20) {
        print_error("Warning: Serial number longer than 20 octets.");
    }

    if ((**input & 0x80) != 0) {
        print_error("Warning: Serial number is negative.");
    }

    if ((length > 1) && (**input == 0) && (*(*input + 1) == 0)) {
        print_error("Error: serial number is not DER encoded.");
    }

    *input += length;
    TBSCertificate_length -= length;

    /* signature */

    push_error_stack("signature");

    if (validate_signatureAlgorithm(input, &TBSCertificate_length, &signature_oid, &signature_parameters, &signature_parameters_length) == -1) {
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();

    /* issuer */
    push_error_stack("issuer");
    if (validate_directoryName(input, &TBSCertificate_length, &is_issuer_empty) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (is_issuer_empty) {
        print_error("Error: issuer field contains an empty SEQUENCE.");
    }
    pop_error_stack();

    /* validity */
    push_error_stack("validity");
    /* Validity is a SEQUENCE of notBefore and notAfter */
    if ((tag = get_tag(input, &TBSCertificate_length)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("validity is not encoded as a SEQUENCE.");
    }

    if ((validity_length = get_length(input, &TBSCertificate_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    TBSCertificate_length -= validity_length;

    /* check notBefore */
    push_error_stack("notBefore");
    if ((tag = get_tag(input, &validity_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag == 0x17) {
        if (validate_UTCTime(input, &validity_length) == -1) {
            pop_error_stack();
            return(-1);
        }
    } else if (tag == 0x18) {
        if (validate_GeneralizedTime(input, &validity_length) == -1) {
            pop_error_stack();
            return(-1);
        }
    } else {
        print_error("Invalid tag for notBefore");
    }

    pop_error_stack();

    /* check notAfer */
    push_error_stack("notAfter");
    if ((tag = get_tag(input, &validity_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag == 0x17) {
        if (validate_UTCTime(input, &validity_length) == -1) {
            pop_error_stack();
            return(-1);
        }
    } else if (tag == 0x18) {
        if (validate_GeneralizedTime(input, &validity_length) == -1) {
            pop_error_stack();
            return(-1);
        }
    } else {
        print_error("Invalid tag for notAfter");
    }

    if (validity_length != 0) {
        print_error("Incorrect length for Validity SEQUENCE.");
        return(-1);
    }

    pop_error_stack();
    pop_error_stack();
    /* subject */
    push_error_stack("subject");
    if (validate_directoryName(input, &TBSCertificate_length, &is_subject_empty) == -1) {
        pop_error_stack();
        return(-1);
    }
    pop_error_stack();

    /* subjectPublicKeyInfo */
    push_error_stack("subjectPublicKeyInfo");
    if (validate_subjectPublicKeyInfo(input, &TBSCertificate_length) == -1) {
        pop_error_stack();
        return(-1);
    }
    pop_error_stack();

    if (TBSCertificate_length == 0) {
        /* Certificate contains no unique identifiers or extensions */
        pop_error_stack();
        return(0);
    }

    if (version == 1) {
        print_error("ERROR: Version 1 certificate contains extra data in TBSCertificate");
        return(-1);
    }

    tag = **input;
    if (tag == 0x81) {
        /* issuerUniqueID */
        push_error_stack("issuerUniqueID");
        if ((tag = get_tag(input, &TBSCertificate_length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if ((UniqueID_length = get_length(input, &TBSCertificate_length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (validate_BITSTRING(UniqueID_length, *input, 0) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        *input += UniqueID_length;
        TBSCertificate_length -= UniqueID_length;
        pop_error_stack();
    }

    if (TBSCertificate_length == 0) {
        /* Certificate contains no subject unique identifier or extensions */
        pop_error_stack();
        return(0);
    }

    tag = **input;
    if (tag == 0x82) {
        /* subjectUniqueID */
        push_error_stack("subjectUniqueID");
        if ((tag = get_tag(input, &TBSCertificate_length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if ((UniqueID_length = get_length(input, &TBSCertificate_length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (validate_BITSTRING(UniqueID_length, *input, 0) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        *input += UniqueID_length;
        TBSCertificate_length -= UniqueID_length;
        pop_error_stack();
    }


    if (TBSCertificate_length == 0) {
        /* Certificate does not contain extensions */
        pop_error_stack();
        return(0);
    }

    if (version == 2) {
        print_error("ERROR: Version 2 certificate contains extra data in TBSCertificate");
        return(-1);
    }

    /* extensions */
    push_error_stack("extensions");
    if ((tag = get_tag(input, &TBSCertificate_length)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    if (tag != 0xA3) {
        print_error("Incorrect tag for Extensions.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    if ((extensions_length = get_length(input, &TBSCertificate_length)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    TBSCertificate_length -= extensions_length;

    if (TBSCertificate_length != 0) {
        print_error("Error: Extra data at end of TBSCertificate.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    if (validate_extensions(input, &extensions_length) == -1) {
        pop_error_stack();
        return(-1);
    }
    pop_error_stack();

    pop_error_stack();
    return(0);
}

/* Verify that the string pointed to by input of length
 * input_len is a DER encoding of:
 *
 *    Certificate  ::=  SEQUENCE  {
 *         tbsCertificate       TBSCertificate,
 *         signatureAlgorithm   AlgorithmIdentifier,
 *         signatureValue       BIT STRING  }
 */
int validate_certificate(unsigned char *input, int input_len)
{
    int tag, length, signatureAlgorithm_parameters_length, DSS_sig_value_length;
    char *signatureAlgorithm_oid;
    unsigned char *signatureAlgorithm_parameters;

    push_error_stack("Certificate");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Certificate is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Input string contains data after Certificate.");
        pop_error_stack();
        return(-1);
    }

    if ((validate_TBSCertificate(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    /* validate signatureAlgorithm */
    push_error_stack("signatureAlgorithm");

    if (validate_signatureAlgorithm(&input, &input_len, &signatureAlgorithm_oid,
                        &signatureAlgorithm_parameters, &signatureAlgorithm_parameters_length) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    /* verify that signatureAlgorithm matches signature from TBSCertificate */
    if ((strcmp(signatureAlgorithm_oid, signature_oid) != 0) ||
        (signatureAlgorithm_parameters_length != signature_parameters_length) ||
        (memcmp(signatureAlgorithm_parameters, signature_parameters, signature_parameters_length) != 0)) {
        print_error("Error: Contents of signatureAlgorithm field in Certificate does not match contents of signature field in TBSCertificate.");
    }

    pop_error_stack();

    /* validate signatureValue */
    push_error_stack("signatureValue");
    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x03) {
        print_error("Incorrect tag for signatureValue.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    input_len -= length;

    if (validate_BITSTRING(length, input, 0) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    /* TODO: check that contents of signatureValue are correctly encoded */
    if ((strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.2") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.3") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.4") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.5") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.11") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.12") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.13") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.14") == 0)) {
        /* RSA with MD2, MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 */
        if (*input != 0) {
            print_error("Error: Number of unused bits in signatureValue BIT STRING must be 0.");
        }
    } else if (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.10") == 0) {
        /* RSA-SSAPSS */
        if (*input != 0) {
            print_error("Error: Number of unused bits in signatureValue BIT STRING must be 0.");
        }
    } else if ((strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.1") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.3.1") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.3.2") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.3.3") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.3.4") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10040.4.3") == 0) ||
                (strcmp(signatureAlgorithm_oid, "2.16.840.1.101.3.4.3.1") == 0) ||
                (strcmp(signatureAlgorithm_oid, "2.16.840.1.101.3.4.3.2") == 0)) {
        /* ECDSA with SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 or
         * DSA with SHA-1, SHA-224, or SHA-256 */
        if (*input != 0) {
            print_error("Error: Number of unused bits in signatureValue BIT STRING must be 0.");
        }
        input += 1;
        length -= 1;

        /* Dss-Sig-Value  ::=  SEQUENCE  {
         *         r       INTEGER,
         *         s       INTEGER  }
         */
        if ((tag = get_tag(&input, &length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if (tag != 0x30) {
            print_error("Error: DSA or ECDSA signature is not encoded as a SEQUENCE.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if ((DSS_sig_value_length = get_length(&input, &length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (DSS_sig_value_length != length) {
            print_error("Error: signatureValue BIT STRING contains extraneous data.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (validate_INTEGER(&input, &DSS_sig_value_length, 1) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if (validate_INTEGER(&input, &DSS_sig_value_length, 1) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if (DSS_sig_value_length != 0) {
            print_error("Error: Dss-Sig-Value SEQUENCE contains extraneous data.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
    } else if ((strcmp(signatureAlgorithm_oid, "1.3.101.112") == 0) ||
               (strcmp(signatureAlgorithm_oid, "1.3.101.113") == 0)) {
        /* EdDSA */
        if (*input != 0) {
            print_error("Error: Number of unused bits in signatureValue BIT STRING must be 0.");
        }
    } else {
        print_error("Warning: Unrecognized signature algorithm.  Cannot check signatureValue field.");
    }

    pop_error_stack();

    if (input_len != 0) {
        print_error("Incorrect length for Certifiate SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/*
 * Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *      type   ATTRIBUTE.&id({IOSet}),
 *      values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
 * }
 */
int validate_pkcs10_Attribute(unsigned char **input, int *input_len)
{
    int tag, length, Attribute_len, values_len;
    char *oid;
    char error_str[1000];

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Attribute is not encoded as a SEQUENCE.");
        return(-1);
    }

    if ((Attribute_len = get_length(input, input_len)) == -1) {
        return(-1);
    }

    *input_len -= Attribute_len;

    if (get_OID(input, &Attribute_len, &oid) == -1) {
        return(-1);
    }

    sprintf(error_str, "Attribute %s", oid);
    push_error_stack(error_str);

    if ((tag = get_tag(input, &Attribute_len)) == -1) {
        return(-1);
    }
    if (tag != 0x31) {
        print_error("values is not encoded as a SET.");
        return(-1);
    }

    if ((values_len = get_length(input, &Attribute_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (values_len != Attribute_len) {
        print_error("Error: Encoding of attribute contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (values_len == 0) {
        print_error("Error: values is an empty set.");
        pop_error_stack();
        return(-1);
    }

    /* Perform attribute-type-specific validation of value */
    if (strcmp(oid, "1.2.840.113549.1.9.7") == 0) {
        /* challengePassword ATTRIBUTE ::= {
         *         WITH SYNTAX DirectoryString {pkcs-9-ub-challengePassword}
         *         EQUALITY MATCHING RULE caseExactMatch
         *         SINGLE VALUE TRUE
         *         ID pkcs-9-at-challengePassword
         * }
         */
        pop_error_stack();
        push_error_stack("Attribute: challengePassword");

        if ((tag = get_tag(input, &values_len)) == -1) {
            pop_error_stack();
            return(-1);
        }
        if ((length = get_length(input, &values_len)) == -1) {
            pop_error_stack();
            return(-1);
        }
        if (validate_DirectoryString(tag, *input, length, 255) == -1) {
            pop_error_stack();
            return(-1);
        }
        *input += length;
        values_len -= length;

        if (values_len > 0) {
            print_error("Error: challengePassword is a single value attribute, but values contains data after first attribute value.");
            pop_error_stack();
            return(-1);
        }
    } else if (strcmp(oid, "1.2.840.113549.1.9.14") == 0) {
        /* extensionRequest ATTRIBUTE ::= {
         *         WITH SYNTAX ExtensionRequest
         *         SINGLE VALUE TRUE
         *         ID pkcs-9-at-extensionRequest
         * }
         *
         * ExtensionRequest ::= Extensions
         */
        pop_error_stack();
        push_error_stack("Attribute: extensionRequest");
        if (validate_extensions(input, &values_len) == -1) {
            pop_error_stack();
            return(-1);
        }
        if (values_len > 0) {
            print_error("Error: extensionRequest is a single value attribute, but values contains data after first attribute value.");
            pop_error_stack();
            return(-1);
        }
    } else {
        /* unknown attribute */
        while (values_len > 0) {
            if (validate_generic_DER(input, &values_len) == -1) {
                pop_error_stack();
                return(-1);
            }
        }
        pop_error_stack();
        sprintf(error_str, "Warning:  Unrecognized attribute: %s.  Contents not parsed.", oid);
        print_error(error_str);
    }

    pop_error_stack();

    return(0);
}

/*
 * CertificationRequestInfo ::= SEQUENCE {
 *      version       INTEGER { v1(0) } (v1,...),
 *      subject       Name,
 *      subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *      attributes    [0] Attributes{{ CRIAttributes }}
 * }
 */
int validate_CertificationRequestInfo(unsigned char **input, int *input_len)
{
    int tag, length, CertificationRequestInfo_len, attributes_len;

    push_error_stack("CertificationRequestInfo");

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("CertificationRequestInfo is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((CertificationRequestInfo_len = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    *input_len -= CertificationRequestInfo_len;

    /* version */
    if ((tag = get_tag(input, &CertificationRequestInfo_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x02) {
        print_error("version is not encoded as an INTEGER.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(input, &CertificationRequestInfo_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if ((length != 1) || (**input != 0)) {
        print_error("version does not contain a DER encoding of the value 0.");
        pop_error_stack();
        return(-1);
    }

    *input += 1;
    CertificationRequestInfo_len -= 1;

    /* subject */
    push_error_stack("subject");
    if (validate_directoryName(input, &CertificationRequestInfo_len, &is_subject_empty) == -1) {
        pop_error_stack();
        return(-1);
    }
    pop_error_stack();

    /* subjectPKInfo */
    push_error_stack("subjectPKInfo");
    if (validate_subjectPublicKeyInfo(input, &CertificationRequestInfo_len) == -1) {
        pop_error_stack();
        return(-1);
    }
    pop_error_stack();

    /* attributes */
    push_error_stack("attributes");
    if ((tag = get_tag(input, &CertificationRequestInfo_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0xA0) {
        print_error("Incorrect tag for attributes.");
        pop_error_stack();
        return(-1);
    }

    if ((attributes_len = get_length(input, &CertificationRequestInfo_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (attributes_len != CertificationRequestInfo_len) {
        print_error("Error: CertificationRequestInfo contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    while (attributes_len > 0) {
        if (validate_pkcs10_Attribute(input, &attributes_len) == -1) {
            pop_error_stack();
            return(-1);
        }
    }

    pop_error_stack();

    pop_error_stack();
    return(0);
}

/* Verify that the string pointed to by input of length
 * input_len is a DER encoding of:
 *
 *    CertificationRequest ::= SEQUENCE {
 *         certificationRequestInfo CertificationRequestInfo,
 *         signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
 *         signature          BIT STRING
 *    }
 */
int validate_pkcs10(unsigned char *input, int input_len)
{
    int tag, length, signatureAlgorithm_parameters_length, DSS_sig_value_length;
    char *signatureAlgorithm_oid;
    unsigned char *signatureAlgorithm_parameters;

    push_error_stack("PKCS #10 CertificationRequest");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("CertificationRequest is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Input string contains data after CertificationRequest.");
        pop_error_stack();
        return(-1);
    }

    if ((validate_CertificationRequestInfo(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    /* validate signatureAlgorithm */
    push_error_stack("signatureAlgorithm");

    if (validate_signatureAlgorithm(&input, &input_len, &signatureAlgorithm_oid,
                        &signatureAlgorithm_parameters, &signatureAlgorithm_parameters_length) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();

    /* validate signature */
    push_error_stack("signature");
    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x03) {
        print_error("Incorrect tag for signature.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    input_len -= length;

    if (validate_BITSTRING(length, input, 0) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    /* TODO: check that contents of signature are correctly encoded */
    if ((strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.2") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.3") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.4") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.5") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.11") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.12") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.13") == 0) ||
        (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.14") == 0)) {
        /* RSA with MD2, MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 */
        if (*input != 0) {
            print_error("Error: Number of unused bits in signature BIT STRING must be 0.");
        }
    } else if (strcmp(signatureAlgorithm_oid, "1.2.840.113549.1.1.10") == 0) {
        /* RSA-SSAPSS */
        if (*input != 0) {
            print_error("Error: Number of unused bits in signature BIT STRING must be 0.");
        }
    } else if ((strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.1") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.3.1") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.3.2") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.3.3") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10045.4.3.4") == 0) ||
                (strcmp(signatureAlgorithm_oid, "1.2.840.10040.4.3") == 0) ||
                (strcmp(signatureAlgorithm_oid, "2.16.840.1.101.3.4.3.1") == 0) ||
                (strcmp(signatureAlgorithm_oid, "2.16.840.1.101.3.4.3.2") == 0)) {
        /* ECDSA with SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 or
         * DSA with SHA-1, SHA-224, or SHA-256 */
        if (*input != 0) {
            print_error("Error: Number of unused bits in signature BIT STRING must be 0.");
        }
        input += 1;
        length -= 1;

        /* Dss-Sig-Value  ::=  SEQUENCE  {
         *         r       INTEGER,
         *         s       INTEGER  }
         */
        if ((tag = get_tag(&input, &length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if (tag != 0x30) {
            print_error("Error: DSA or ECDSA signature is not encoded as a SEQUENCE.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if ((DSS_sig_value_length = get_length(&input, &length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (DSS_sig_value_length != length) {
            print_error("Error: signature BIT STRING contains extraneous data.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (validate_INTEGER(&input, &DSS_sig_value_length, 1) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if (validate_INTEGER(&input, &DSS_sig_value_length, 1) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        if (DSS_sig_value_length != 0) {
            print_error("Error: Dss-Sig-Value SEQUENCE contains extraneous data.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
    } else {
        print_error("Warning: Unrecognized signature algorithm.  Cannot check signature field.");
    }

    pop_error_stack();

    if (input_len != 0) {
        print_error("Incorrect length for CertificationRequest SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/* Determine whether the input is a certificate or a PKCS #10 */
enum inputtype {
    X509Certificate,
    PKCS10
};

int is_certificate_or_pkcs10(unsigned char *input, int input_len, enum inputtype *type)
{
    int tag, length;

    if ((tag = get_tag(&input, &input_len)) == -1) {
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Input is not encoded as a SEQUENCE.");
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        return(-1);
    }

    if (length != input_len) {
        print_error("Length value for initial SEQUENCE is incorrect.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        return(-1);
    }
    if (tag != 0x30) {
        print_error("TBSCertificate or CertificationRequestInfo not encoded as a SEQUENCE.");
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        return(-1);
    }

    if (*input == 0xA0) {
        /* This is the tag for the version field in an X.509 certificate */
        *type = X509Certificate;
        return(0);
    }

    /* This is either an X.509 version 1 certificate or a PKCS #10.
     * Next field is either the serialNumber field of a certificate
     * or the version field of a PKCS #10.  In either case, the field
     * is an INTEGER.*/
    if ((tag = get_tag(&input, &input_len)) == -1) {
        return(-1);
    }

    if (tag != 0x02) {
        print_error("Incorrect tag encountered where either Version (tag A0) or serialNumber (tag 02) should be.");
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        return(-1);
    }

    /* Skip over value of this field */
    input += length;
    input_len -= length;

    /* The next field is either the signature field of a certificate or
     * the subject field of a PKCS #10.  In either case, the field is
     * a SEQUENCE */
    if ((tag = get_tag(&input, &input_len)) == -1) {
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Incorrect tag encountered where a SEQUENCE should be.");
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        return(-1);
    }

    if (length == 0) {
        /* signature cannot be an empty SEQUENCE */
        *type = PKCS10;
        return(0);
    }

    /* The first field in the SEQUENCE is either an OBJECT IDENTIFIER (certificate)
     * or a SET (PKCS #10). */
    if (*input == 0x06) {
        *type = X509Certificate;
    } else if (*input == 0x31) {
        *type = PKCS10;
    } else {
        return(-1);
    }

    return(0);
}

int main( int argc, char *argv[] )
{
    FILE *input_file;
    unsigned char input[MAX_INPUT];
    unsigned char decoded_input[MAX_INPUT];
    int i, input_len, decoded_input_len, result;
    enum inputtype type;

    if (argc != 2) {
        fprintf(stderr, "%s [<input file>]\n", argv[0]);
        return(1);
    }

    input_file = fopen(argv[1], "r");

    if (input_file == NULL) {
        fprintf(stderr, "Unable to open %s for reading.\n", argv[1]);
        return(1);
    }

    i = 0;
    while ((i < MAX_INPUT - 1) && !feof(input_file)) {
        input_len = fread(&input[i], 1, MAX_INPUT - i, input_file);
    }

    if (!feof(input_file)) {
        fprintf(stderr, "Input file too long.\n");
        return(1);
    }

    if (argc == 2)
        fclose(input_file);

    if (strncmp((char *)input, "-----BEGIN CERTIFICATE-----", 27) == 0) {
        if (decode_PEM_certificate(input, input_len, decoded_input, &decoded_input_len) == -1) {
            return(-1);
        }
        memcpy(input, decoded_input, decoded_input_len);
        input_len = decoded_input_len;
        type = X509Certificate;
    } else if (strncmp((char *)input, "-----BEGIN CERTIFICATE REQUEST-----", 35) == 0) {
        if (decode_PEM_certreq(input, input_len, decoded_input, &decoded_input_len) == -1) {
            return(-1);
        }
        memcpy(input, decoded_input, decoded_input_len);
        input_len = decoded_input_len;
        type = PKCS10;
    } else {
        result = is_certificate_or_pkcs10(input, input_len, &type);
        if (result == -1) {
            printf("Message type not recognized\n");
            return(result);
        }
    }

    if (type == X509Certificate) {
        result = validate_certificate(input, input_len);
    } else if (type == PKCS10) {
        result = validate_pkcs10(input, input_len);
    } else {
        print_error("Message type not recognized");
    }

    if (!print_error_was_called()) {
        printf("No errors found in %s\n", argv[1]);
    }

    return(result);
}

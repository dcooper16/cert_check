/* This software was developed by employees of the National Institute of
 * Standards and Technology (NIST), an agency of the Federal Government and
 * is being made available as a public service. Pursuant to title 17 United
 * States Code Section 105, works of NIST employees are not subject to
 * copyright protection in the United States. This software may be subject to
 * foreign copyright. Permission in the United States and in foreign
 * countries, to the extent that NIST may hold copyright, to use, copy,
 * modify, create derivative works, and distribute this software and its
 * documentation without fee is hereby granted on a non-exclusive basis,
 * provided that this notice and disclaimer of warranty appears in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER
 * EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY
 * WARRANTY THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 * FREEDOM FROM INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL
 * CONFORM TO THE SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR
 * FREE. IN NO EVENT SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT
 * LIMITED TO, DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING
 * OUT OF, RESULTING FROM, OR IN ANY WAY CONNECTED WITH THIS SOFTWARE,
 * WHETHER OR NOT BASED UPON WARRANTY, CONTRACT, TORT, OR OTHERWISE, WHETHER
 * OR NOT INJURY WAS SUSTAINED BY PERSONS OR PROPERTY OR OTHERWISE, AND
 * WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT OF THE RESULTS OF, OR
 * USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cert_check.h"

static char error_str[1000];

struct KeyUsage_BITSTRING {
    int digitalSignature;
    int nonRepudiation;
    int keyEncipherment;
    int dataEncipherment;
    int keyAgreement;
    int keyCertSign;
    int cRLSign;
    int encipherOnly;
    int decipherOnly;
};

typedef struct KeyUsage_BITSTRING KeyUsage_BITSTRING;

static int isKeyUsagePresent = 0;
static KeyUsage_BITSTRING keyUsage_value;

static int isBasicConstraintsPresent = 0;
static int BasicConstraints_criticality;
static int BasicConstraints_cA = 0;

static int iscertificatePoliciesPresent = 0;
static char *certificatePolicies[100];

static int ispolicyMappingsPresent = 0;
static char *issuerDomainPolicies[100];

static int issubjectAltNamePresent = 0;

/*
 * KeyUsage ::= BIT STRING {
 *      digitalSignature        (0),
 *      nonRepudiation          (1), -- recent editions of X.509 have
 *                           -- renamed this bit to contentCommitment
 *      keyEncipherment         (2),
 *      dataEncipherment        (3),
 *      keyAgreement            (4),
 *      keyCertSign             (5),
 *      cRLSign                 (6),
 *      encipherOnly            (7),
 *      decipherOnly            (8) }
 */
int validate_keyUsage(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("keyUsage");

    if (criticality == 0) {
        print_error("Warning: keyUsage should be marked as critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x03) {
        print_error("Error: keyUsage is not encoded as a BIT STRING.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Encoding of keyUsage extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (validate_BITSTRING(length, input, 1) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length == 1) {
        print_error("Error: keyUsage extension has all bits set to 0.");
        pop_error_stack();
        return(-1);
    }

    /* keyUsage BIT STRING can be at most 9 bits long. If it is longer than 8
     * bits, the number of unused bits must be 7. */
    if ((length > 3) || ((length == 3) && (*input != 7))) {
        print_error("Error: BIT STRING in keyUsage extension is too long.");
        pop_error_stack();
        return(-1);
    }

    input++;
    keyUsage_value.digitalSignature = (*input & 0x80) ? 1 : 0;
    keyUsage_value.nonRepudiation = (*input & 0x40) ? 1 : 0;
    keyUsage_value.keyEncipherment = (*input & 0x20) ? 1 : 0;
    keyUsage_value.dataEncipherment = (*input & 0x10) ? 1 : 0;
    keyUsage_value.keyAgreement = (*input & 0x08) ? 1 : 0;
    keyUsage_value.keyCertSign = (*input & 0x04) ? 1 : 0;
    keyUsage_value.cRLSign = (*input & 0x02) ? 1 : 0;
    keyUsage_value.encipherOnly = (*input & 0x01) ? 1 : 0;

    if (length == 2)
        keyUsage_value.decipherOnly = 0;
    else
        keyUsage_value.decipherOnly = (*(input+1) & 0x80) ? 1 : 0;

    if (subjectPublicKeyType == SPK_RSA) {
        /* keyAgreement, encipherOnly, and decipherOnly are not consistent with an RSA public key */
        if (keyUsage_value.keyAgreement) {
            print_error("Warning: Assertion of the keyAgreement bit is not consistent with an RSA public key.");
        }
        if (keyUsage_value.encipherOnly) {
            print_error("Warning: Assertion of the encipherOnly bit is not consistent with an RSA public key.");
        }
        if (keyUsage_value.decipherOnly) {
            print_error("Warning: Assertion of the decipherOnly bit is not consistent with an RSA public key.");
        }
    } else if (subjectPublicKeyType == SPK_ECC) {
        /* keyEncipherment and dataEncipherment are not consistent with an elliptic curve public key */
        if (keyUsage_value.keyEncipherment) {
            print_error("Warning: Assertion of the keyEncipherment bit is not consistent with an elliptic curve public key.");
        }
        if (keyUsage_value.dataEncipherment) {
            print_error("Warning: Assertion of the dataEncipherment bit is not consistent with an elliptic curve public key.");
        }

        if (keyUsage_value.keyAgreement == 0) {
            if (keyUsage_value.encipherOnly) {
                print_error("Warning: The encipherOnly bit may only be set if the keyAgreement bit is also set.");
            }
            if (keyUsage_value.decipherOnly) {
                print_error("Warning: The decipherOnly bit may only be set if the keyAgreement bit is also set.");
            }
        }

        if (keyUsage_value.encipherOnly && keyUsage_value.decipherOnly) {
            print_error("Warning: The encipherOnly and decipherOnly bits must not both be set in the same certificate.");
        }
    } else if ((subjectPublicKeyType == SPK_ECDH) || (subjectPublicKeyType == SPK_ECMQV) || (subjectPublicKeyType == SPK_X25519) || (subjectPublicKeyType == SPK_X448)) {
        /* keyAgreement must be asserted and encipherOnly and decipherOnly may be asserted */
        if (!keyUsage_value.keyAgreement) {
            print_error("Error: The keyAgreement bit must be asserted when the subject public key is id-ecDH, id-ecMQV, id-X25519, or id-X448.");
        }
        if (keyUsage_value.digitalSignature) {
            print_error("Warning: Assertion of the digitalSignature bit is not consistent with an id-ecDH, id-ecMQV, id-X25519, or id-X448 public key.");
        }
        if (keyUsage_value.nonRepudiation) {
            print_error("Warning: Assertion of the nonRepudiation bit is not consistent with an id-ecDH, id-ecMQV, id-X25519, or id-X448 public key.");
        }
        if (keyUsage_value.keyEncipherment) {
            print_error("Warning: Assertion of the keyEncipherment bit is not consistent with an id-ecDH, id-ecMQV, id-X25519, or id-X448 public key.");
        }
        if (keyUsage_value.dataEncipherment) {
            print_error("Warning: Assertion of the dataEncipherment bit is not consistent with an id-ecDH, id-ecMQV, id-X25519, or id-X448 public key.");
        }
        if (keyUsage_value.keyCertSign) {
            print_error("Warning: Assertion of the keyCertSign bit is not consistent with an id-ecDH, id-ecMQV, id-X25519, or id-X448 public key.");
        }
        if (keyUsage_value.cRLSign) {
            print_error("Warning: Assertion of the cRLSign bit is not consistent with an id-ecDH, id-ecMQV, id-X25519, or id-X448 public key.");
        }
        if (keyUsage_value.encipherOnly && keyUsage_value.decipherOnly) {
            print_error("Warning: The encipherOnly and decipherOnly bits must not both be set in the same certificate.");
        }
    } else if ((subjectPublicKeyType == SPK_DSA) || (subjectPublicKeyType == SPK_ED25519) || (subjectPublicKeyType == SPK_ED448)) {
        /* keyEncipherment, dataEncipherment, keyAgreement, encipherOnly, and decipherOnly are not consistent with a DSA public key */
        if (keyUsage_value.keyEncipherment) {
            print_error("Warning: Assertion of the keyEncipherment bit is not consistent with a DSA or EdDSA public key.");
        }
        if (keyUsage_value.dataEncipherment) {
            print_error("Warning: Assertion of the dataEncipherment bit is not consistent with a DSA or EdDSA public key.");
        }
        if (keyUsage_value.keyAgreement) {
            print_error("Warning: Assertion of the keyAgreement bit is not consistent with a DSA or EdDSA public key.");
        }
        if (keyUsage_value.encipherOnly) {
            print_error("Warning: Assertion of the encipherOnly bit is not consistent with a DSA or EdDSA public key.");
        }
        if (keyUsage_value.decipherOnly) {
            print_error("Warning: Assertion of the decipherOnly bit is not consistent with a DSA or EdDSA public key.");
        }
    } else {
        print_error("Warning: Unknown subject public key type. Not checking consistency keyUsage extension with key type.");
    }

    isKeyUsagePresent = 1;
    pop_error_stack();
    return(0);
}

/*
 * BasicConstraints ::= SEQUENCE {
 *      cA                      BOOLEAN DEFAULT FALSE,
 *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 */
int validate_basicConstraints(unsigned char *input, int input_len, int criticality)
{
    int tag, length, pathLenConstraint_length;

    push_error_stack("BasicConstraints");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: BasicConstraints is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Encoding of BasicConstraints extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        /* cA is FALSE and pathLenConstraint is absent */
        pop_error_stack();
        return(0);
    }

    /* If BasicConstraints is not an empty SEQUENCE then cA must be TRUE,
     * since pathLenConstraint must be absent is cA is FALSE. */
    BasicConstraints_cA = 0;
    if (*input == 1) {
        if (get_BOOLEAN(&input, &input_len, &BasicConstraints_cA) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (BasicConstraints_cA == 0) {
            print_error("Error: cA value of FALSE not DER encoded.  Default value must not appear in encoding.");
        }
    }

    isBasicConstraintsPresent = 1;
    BasicConstraints_criticality = criticality;

    if (input_len == 0) {
        pop_error_stack();
        return(0);
    }

    if ((input_len > 0) & (BasicConstraints_cA == 0)) {
        print_error("Error: pathLenConstraint must be absent is cA is FALSE.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x02) {
        print_error("Error: pathLenConstraint is not encoded as an INTEGER.");
        pop_error_stack();
        return(-1);
    }

    if ((pathLenConstraint_length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (pathLenConstraint_length != input_len) {
        print_error("Error: Encoding of BasicConstraints extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (pathLenConstraint_length == 0) {
        print_error("Error: The pathLenConstraint is encoded as an INTEGER of zero octets.");
        pop_error_stack();
        return(-1);
    }

    if ((*input & 0x80) != 0) {
        print_error("Error: pathLenConstraint is a negative number.");
        pop_error_stack();
        return(-1);
    }

    if ((pathLenConstraint_length > 1) && (*input == 0) && (*(input + 1) == 0)) {
        print_error("Error: pathLenConstraint is not DER encoded.");
        pop_error_stack();
        return(-1);
    }

    if ((pathLenConstraint_length > 1) && (*input > 20)) {
        print_error("Warning: pathLenConstraint is an unusually larger number.");
    }

    pop_error_stack();
    return(0);
}


/*
 * SubjectKeyIdentifier ::= KeyIdentifier
 *
 * KeyIdentifier ::= OCTET STRING
 */
int validate_subjectKeyIdentifier(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("subjectKeyIdentifier");

    if (criticality) {
        print_error("Error: subjectKeyIdentifier extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x04) {
        print_error("Error: subjectKeyIdentifier is not encoded as an OCTET STRING.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Encoding of subjectKeyIdentifier extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/* AuthorityKeyIdentifier ::= SEQUENCE {
 *    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 *
 * KeyIdentifier ::= OCTET STRING
 *
 * CertificateSerialNumber  ::=  INTEGER
 */
int validate_authorityKeyIdentifier(unsigned char *input, int input_len, int criticality)
{
    int tag, length;
    unsigned char *authorityCertIssuer_tag;

    push_error_stack("authorityKeyIdentifier");

    if (criticality) {
        print_error("Error: authorityKeyIdentifier extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: authorityKeyIdentifier is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of authorityKeyIdentifier extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (input_len == 0) {
        print_error("Error: authorityKeyIdentifier extension is an empty sequence.");
        pop_error_stack();
        return(-1);
    }

    if (*input == 0x80) {
        /* This appears to be the keyIdentifier */
        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        input += length;
        input_len -= length;

        if (input_len == 0) {
            pop_error_stack();
            return(0);
        }
    } else {
        print_error("Warning:  The PKIX profile requires the presence of the keyIdentifier field.");
    }

    if (*input == 0x82) {
        print_error("Error: authorityCertSerialNumber cannot be present unless authorityCertIssuer is also present.");
    } else if (*input != 0xA1) {
        print_error("Error: Incorrect tag in authorityKeyIdentifier SEQUENCE.");
        pop_error_stack();
        return(-1);
    } else {
        authorityCertIssuer_tag = input;
        *authorityCertIssuer_tag = 0x30;
        push_error_stack("authorityCertIssuer");
        if (validate_GeneralNames(&input, &input_len) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        pop_error_stack();
        
        *authorityCertIssuer_tag = 0xA1;
    }

    if (input_len == 0) {
        print_error("Error: authorityCertIssuer cannot be present unless authorityCertSerialNumber is also present.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x82) {
        print_error("Error: Incorrect tag in authorityKeyIdentifier SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of authorityKeyIdentifier extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: authorityCertSerialNumber number has a length of zero octets.");
        pop_error_stack();
        return(-1);
    }

    if (length > 20) {
        print_error("Warning: authorityCertSerialNumber longer than 20 octets.");
    }

    if ((*input & 0x80) != 0) {
        print_error("Warning: Serial number is negative.");
    }

    if ((length > 1) && (*input == 0) && (*(input + 1) == 0)) {
        print_error("Error: serial number is not DER encoded.");
    }

    pop_error_stack();
    return(0);
}



/*
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 */
int validate_extKeyUsage(unsigned char *input, int input_len, int criticality)
{
    int tag, length;
    char *KeyPurposeId;

    push_error_stack("extended key usage");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: extended key usage is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of extended key usage extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (input_len == 0) {
        print_error("Error: extended key usage extension is an empty sequence.");
    }

    while (input_len > 0) {
        if (get_OID(&input, &input_len, &KeyPurposeId) == -1) {
            pop_error_stack();
            return(-1);
        }
        if ((strcmp(KeyPurposeId, "2.5.29.37.0") == 0) && criticality) {
            /* anyExtendedKeyUsage is present and extension is marked critical*/
            print_error("Warning: The extended key usage extension should not be marked as critical if the anyExtendedKeyUsage KeyPurposeId is present.");
        }
        free(KeyPurposeId);
    }

    pop_error_stack();
    return(0);
}

/*
 * UserNotice ::= SEQUENCE {
 *      noticeRef        NoticeReference OPTIONAL,
 *      explicitText     DisplayText OPTIONAL }
 *
 * NoticeReference ::= SEQUENCE {
 *      organization     DisplayText,
 *      noticeNumbers    SEQUENCE OF INTEGER }
 */
int validate_UserNotice(unsigned char *input, int input_len)
{
    int tag, UserNotice_length, NoticeReference_length, noticeNumbers_length;
    push_error_stack("UserNotice");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Error: UserNotice is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((UserNotice_length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (UserNotice_length != input_len) {
        print_error("Error: Encoding of UserNotice contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (UserNotice_length == 0) {
        print_error("Warning: userNotice qualifier present with both noticeRef and explicitText absent.");
        pop_error_stack();
        return(0);
    }

    if (*input == 0x30) {
        push_error_stack("noticeRef");
        print_error("Warning: CAs conforming to the PKIX Certificate and CRL Profile should not use the noticeRef option.");

        if ((tag = get_tag(&input, &UserNotice_length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if ((NoticeReference_length = get_length(&input, &UserNotice_length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        UserNotice_length -= NoticeReference_length;

        push_error_stack("organization");
        if (validate_DisplayText(&input, &NoticeReference_length) == -1) {
            pop_error_stack();
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        pop_error_stack();

        if (NoticeReference_length > 0) {
            if ((tag = get_tag(&input, &NoticeReference_length)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            if (tag != 0x30) {
                print_error("Error: Expecting SEQUENCE tag for noticeNumbers.");
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            if ((noticeNumbers_length = get_length(&input, &NoticeReference_length)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            if (noticeNumbers_length != NoticeReference_length) {
                print_error("Error: Extraneous data in NoticeReference SEQUENCE.");
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }

            push_error_stack("noticeNumbers");
        
            while (noticeNumbers_length > 0) {
                if (validate_INTEGER(&input, &noticeNumbers_length, 0) == -1) {
                    pop_error_stack();
                    pop_error_stack();
                    pop_error_stack();
                    return(-1);
                }
            }

            pop_error_stack();
        } else {
            print_error("Warning: noticeRef doesn't include any noticeNumbers.");
        }

        pop_error_stack();
    }

    if (UserNotice_length == 0) {
        /* explicitText is absent */
        pop_error_stack();
        return(0);
    }


    push_error_stack("explicitText");
    if (validate_DisplayText(&input, &UserNotice_length) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    pop_error_stack();

    if (UserNotice_length > 0) {
        print_error("Error: Extraneous data in UserNotice SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/*
 * policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo
 *
 * PolicyQualifierInfo ::= SEQUENCE {
 *      policyQualifierId  PolicyQualifierId,
 *      qualifier          ANY DEFINED BY policyQualifierId }
 *
 * PolicyQualifierId ::= OBJECT IDENTIFIER
 */
int validate_policyQualifiers(unsigned char *input, int input_len, int is_anyPolicy)
{
    int tag, length, PolicyQualifierInfo_length, qualifier_length;
    char *policyQualifierId;
    unsigned char *userNotice;

    push_error_stack("policyQualifiers");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: policyQualifiers is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of policyQualifiers field contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (input_len == 0) {
        print_error("Error: policyQualifiers field is an empty sequence.");
    }

    while (input_len > 0) {
        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x30) {
            print_error("Error: PolicyQualifierInfo is not encoded as a SEQUENCE.");
            pop_error_stack();
            return(-1);
        }

        if ((PolicyQualifierInfo_length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }
        input_len -= PolicyQualifierInfo_length;

        push_error_stack("PolicyQualifierInfo");

        if (get_OID(&input, &PolicyQualifierInfo_length, &policyQualifierId) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (strcmp(policyQualifierId, "1.3.6.1.5.5.7.2.1") == 0) {
            /* cPSuri */
            push_error_stack("cPSuri");
            if ((tag = get_tag(&input, &PolicyQualifierInfo_length)) == -1) {
                pop_error_stack();
                pop_error_stack();
                pop_error_stack();
                free(policyQualifierId);
                return(-1);
            }

            if (tag != 22) {
                print_error("Error: cPSuri is not encoded as an IA5String.");
                pop_error_stack();
                pop_error_stack();
                pop_error_stack();
                free(policyQualifierId);
                return(-1);
            }
            if ((qualifier_length = get_length(&input, &PolicyQualifierInfo_length)) == -1) {
                pop_error_stack();
                pop_error_stack();
                pop_error_stack();
                free(policyQualifierId);
                return(-1);
            }

            if (qualifier_length != PolicyQualifierInfo_length) {
                print_error("Error: Encoding of PolicyQualifierInfo contains extraneous data.");
                pop_error_stack();
                pop_error_stack();
                pop_error_stack();
                free(policyQualifierId);
                return(-1);
            }

            validate_URI(input, qualifier_length);

            input += qualifier_length;

            pop_error_stack();

        } else if (strcmp(policyQualifierId, "1.3.6.1.5.5.7.2.2") == 0) {
            /* userNotice */
            userNotice = input;
            input += PolicyQualifierInfo_length;
            if (validate_UserNotice(userNotice, PolicyQualifierInfo_length) == -1) {
                pop_error_stack();
                pop_error_stack();
                free(policyQualifierId);
                return(-1);
            }
        } else {
            sprintf(error_str, "Warning: Certificate contains a policy qualifier other than cPSuri or userNotice: %s.", policyQualifierId);
            print_error(error_str);
            if (is_anyPolicy) {
                print_error("Warning: The PKIX Certificate and CRL Profile forbids associating any policy qualifiers with anyPolicy other than cPSuri and userNotice.");
            }

            if ((tag = get_tag(&input, &PolicyQualifierInfo_length)) == -1) {
                pop_error_stack();
                pop_error_stack();
                free(policyQualifierId);
                return(-1);
            }

            if ((qualifier_length = get_length(&input, &PolicyQualifierInfo_length)) == -1) {
                pop_error_stack();
                pop_error_stack();
                free(policyQualifierId);
                return(-1);
            }

            if (qualifier_length != PolicyQualifierInfo_length) {
                print_error("Error: Encoding of PolicyQualifierInfo contains extraneous data.");
                pop_error_stack();
                pop_error_stack();
                free(policyQualifierId);
                return(-1);
            }

            input += qualifier_length;
        }

        free(policyQualifierId);
        pop_error_stack();
    }

    pop_error_stack();
    return(0);
}

/* certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 *
 * PolicyInformation ::= SEQUENCE {
 *      policyIdentifier   CertPolicyId,
 *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
 *
 * CertPolicyId ::= OBJECT IDENTIFIER
 */
int validate_certificatePolicies(unsigned char *input, int input_len)
{
    int tag, length, PolicyInformation_length, is_anyPolicy, i, num_policies;
    unsigned char *policyQualifiers;

    push_error_stack("certificatePolicies");

    for(i = 0; i < 100; i++)
        certificatePolicies[i] = NULL;

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: certificatePolicies is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of certificatePolicies extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (input_len == 0) {
        print_error("Error: certificatePolicies extension is an empty sequence.");
    }

    num_policies = 0;

    while (input_len > 0) {
        if (num_policies == 100) {
            print_error("Error: certificatePolicies extension lists more than 100 policy OIDs.");
            pop_error_stack();
            return(-1);
        }
        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x30) {
            print_error("Error: PolicyInformation is not encoded as a SEQUENCE.");
            pop_error_stack();
            return(-1);
        }

        if ((PolicyInformation_length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }
        input_len -= PolicyInformation_length;

        push_error_stack("PolicyInformation");

        if (get_OID(&input, &PolicyInformation_length, &certificatePolicies[num_policies]) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        pop_error_stack();
        sprintf(error_str, "PolicyInformation: %s", certificatePolicies[num_policies]);
        push_error_stack(error_str);

        is_anyPolicy = (strcmp(certificatePolicies[num_policies], "2.5.29.32.0") == 0);

        /* Check that the same policy OID does not appear more than once in the extension. */
        i = 0;
        while (i < num_policies) {
            if (strcmp(certificatePolicies[num_policies], certificatePolicies[i]) == 0) {
                sprintf(error_str, "Error: policy OID %s appears in the certificatePolicies more than once.", certificatePolicies[num_policies]);
                print_error(error_str);
                free(certificatePolicies[num_policies]);
                num_policies--;
                i = num_policies;
            } else {
                i++;
            }
        }

        num_policies++;

        if (PolicyInformation_length > 0) {
            policyQualifiers = input;
            input += PolicyInformation_length;

            if (validate_policyQualifiers(policyQualifiers, PolicyInformation_length, is_anyPolicy) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
        }
        pop_error_stack();
    }

    iscertificatePoliciesPresent = 1;
    pop_error_stack();
    return(0);
}


/*
 * PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId }
 *
 * CertPolicyId ::= OBJECT IDENTIFIER
 */
int validate_policyMappings(unsigned char *input, int input_len, int criticality)
{
    int tag, length, PolicyMapping_length, num_mappings, i;
    char *subjectDomainPolicy;

    push_error_stack("policyMappings");

    for(i = 0; i < 100; i++)
        issuerDomainPolicies[i] = NULL;

    if (criticality == 0) {
        /* print_error("Warning: The PKIX Certificate and CRL profile recommends that the policyMappings extension be marked as critical."); */
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: policyMappings is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of policyMappings extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: policyMappings extension is an empty SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    num_mappings = 0;
    while (input_len > 0) {
        if (num_mappings == 100) {
            print_error("Error: policyMappings extension includes more than 100 policy mappings.");
            pop_error_stack();
            return(-1);
        }

        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x30) {
            print_error("Error: policy mapping is not encoded as a SEQUENCE.");
            pop_error_stack();
            return(-1);
        }

        if ((PolicyMapping_length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }
        input_len -= PolicyMapping_length;

        push_error_stack("issuerDomainPolicy");

        if (get_OID(&input, &PolicyMapping_length, &issuerDomainPolicies[num_mappings]) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        pop_error_stack();
        push_error_stack("subjectDomainPolicy");
        if (get_OID(&input, &PolicyMapping_length, &subjectDomainPolicy) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        pop_error_stack();

        if (strcmp(issuerDomainPolicies[num_mappings], "2.5.29.32.0") == 0) {
            print_error("Error: policyMappings extension attempts to map from anyPolicy (i.e., anyPolicy appears as an issuerDomainPolicy).");
        }
        if (strcmp(subjectDomainPolicy, "2.5.29.32.0") == 0) {
            print_error("Error: policyMappings extension attempts to map to anyPolicy (i.e., anyPolicy appears as a subjectDomainPolicy).");
        }
        free(subjectDomainPolicy);

        if (PolicyMapping_length != 0) {
            print_error("Error: a policy mapping SEQUENCE includes extraneous data.");
            pop_error_stack();
            return(-1);
        }

        num_mappings++;
    }

    ispolicyMappingsPresent = 1;
    pop_error_stack();
    return(0);
}

/* PolicyConstraints ::= SEQUENCE {
 *      requireExplicitPolicy           [0] SkipCerts OPTIONAL,
 *      inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
 *
 * SkipCerts ::= INTEGER (0..MAX)
 */
int validate_policyConstraints(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("policyConstraints");

    if (criticality == 0) {
        print_error("Warning: The PKIX Certificate and CRL profile requires that the policyConstraints extension be marked as critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: policyConstraints is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Encoding of policyConstraints extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Warning: Neither requireExplicitPolicy nor inhibitPolicyMapping is present in the policyConstraints extension.");
        pop_error_stack();
        return(0);
    }

    tag = *input;
    if (tag == 0x80) {
        push_error_stack("requireExplicitPolicy");
        
        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if ((length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (length == 0) {
            print_error("Error: SkipCerts is encoded as zero octets.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if ((*input & 0x80) != 0) {
            print_error("Error: SkipCerts is a negative number.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if ((length > 1) && (*input == 0) && (*(input + 1) == 0)) {
            print_error("Error: SkipCerts is not DER encoded.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if ((length > 1) && (*input > 20)) {
            print_error("Warning: SkipCerts is an unusually larger number.");
        }

        pop_error_stack();
        input += length;
        input_len -= length;

        if (input_len == 0) {
            /* inhibitPolicyMapping is not present */
            pop_error_stack();
            return(0);
        }
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x81) {
        print_error("Error: Unrecognized tag in policyConstraints extension.");
        pop_error_stack();
        return(-1);
    }

    push_error_stack("inhibitPolicyMapping");

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: SkipCerts is encoded as zero octets.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if ((*input & 0x80) != 0) {
        print_error("Error: SkipCerts is a negative number.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if ((length > 1) && (*input == 0) && (*(input + 1) == 0)) {
        print_error("Error: SkipCerts is not DER encoded.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }


    if ((length > 1) && (*input > 20)) {
        print_error("Warning: SkipCerts is an unusually larger number.");
    }

    pop_error_stack();

    input_len -= length;
    if (input_len != 0) {
        print_error("Encoding of policyConstraints extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/*
 * InhibitAnyPolicy ::= SkipCerts
 *
 * SkipCerts ::= INTEGER (0..MAX)
 */
int validate_inhibitAnyPolicy(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("inhibitAnyPolicy");

    if (criticality == 0) {
        print_error("Warning: The PKIX Certificate and CRL profile requires that the inhibitAnyPolicy extension be marked as critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x02) {
        print_error("Error: inhibitAnyPolicy is not encoded as an INTEGER.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Encoding of inhibitAnyPolicy contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: SkipCerts is encoded as an INTEGER of zero octets.");
        pop_error_stack();
        return(-1);
    }

    if ((*input & 0x80) != 0) {
        print_error("Error: SkipCerts is a negative number.");
        pop_error_stack();
        return(-1);
    }

    if ((length > 1) && (*input == 0) && (*(input + 1) == 0)) {
        print_error("Error: SkipCerts is not DER encoded.");
        pop_error_stack();
        return(-1);
    }

    if ((length > 1) && (*input > 20)) {
        print_error("Warning: SkipCerts is an unusually larger number.");
    }

    pop_error_stack();
    return(0);
}


/*
 * SubjectAltName ::= GeneralNames
 */
int validate_subjectAltName(unsigned char *input, int input_len, int criticality)
{
    push_error_stack("subjectAltName");

    if (is_subject_empty && !criticality) {
        print_error("Error: subjectAltName extension must be marked as critical when subject field is an empty SEQUENCE.");
    }

    validate_GeneralNames(&input, &input_len);

    if (input_len != 0) {
        print_error("Error: subjectAltName extension contains extraneous data.");
    }

    issubjectAltNamePresent = 1;

    pop_error_stack();
    return(0);
}

/*
 * IssuerAltName ::= GeneralNames
 */
int validate_issuerAltName(unsigned char *input, int input_len, int criticality)
{
    push_error_stack("issuerAltName");

    if (criticality) {
        print_error("Warning: issuerAltName extension should not be marked as critical.");
    }

    validate_GeneralNames(&input, &input_len);

    if (input_len != 0) {
        print_error("Error: issuerAltName extension contains extraneous data.");
    }

    pop_error_stack();
    return(0);
}

/*
 * PrivateKeyUsagePeriod ::= SEQUENCE {
 *      notBefore       [0]     GeneralizedTime OPTIONAL,
 *      notAfter        [1]     GeneralizedTime OPTIONAL }
 */
int validate_privateKeyUsagePeriod(unsigned char *input, int input_len, int criticality)
{
    int tag, privateKeyUsagePeriod_length;

    push_error_stack("privateKeyUsagePeriod");

    if (criticality) {
        print_error("Error: privateKeyUsagePeriod extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: privateKeyUsagePeriod extension is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((privateKeyUsagePeriod_length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (privateKeyUsagePeriod_length != input_len) {
        print_error("Error: Encoding of privateKeyUsagePeriod extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (privateKeyUsagePeriod_length == 0) {
        print_error("Error: privateKeyUsagePeriod extension is an empty SEQUENCE.  Either notBefore or notAfter must be present");
        pop_error_stack();
        return(-1);
    }

    tag = *input;

    if (tag == 0x80) {
        push_error_stack("notBefore");
        if ((tag = get_tag(&input, &privateKeyUsagePeriod_length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (validate_GeneralizedTime(&input, &privateKeyUsagePeriod_length) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
    } else if (tag != 0x81) {
        print_error("Error: Unexpected tag in privateKeyUsagePeriod SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if (privateKeyUsagePeriod_length == 0) {
        pop_error_stack();
        return(0);
    }

    if ((tag = get_tag(&input, &privateKeyUsagePeriod_length)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x81) {
        print_error("Error: Unexpected tag in privateKeyUsagePeriod SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    push_error_stack("notAfter");

    if (validate_GeneralizedTime(&input, &privateKeyUsagePeriod_length) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    pop_error_stack();
    return(0);
}


/*
 * SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
 *
 * Attribute               ::= SEQUENCE {
 *       type             AttributeType,
 *       values    SET OF AttributeValue }
 *             -- at least one value is required
 *
 * AttributeType ::= OBJECT IDENTIFIER
 *
 * AttributeValue ::= ANY -- DEFINED BY AttributeType
 */
int validate_subjectDirectoryAttributes(unsigned char *input, int input_len, int criticality)
{
    int tag, subjectDirectoryAttributes_length, Attribute_length, values_length, AttributeValue_length;
    char *AttributeType;

    push_error_stack("subjectDirectoryAttributes");

    if (criticality) {
        print_error("Warning: The PKIX Certificate and CRL profile requires that the subjectDirectoryAttributes extension be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: subjectDirectoryAttributes is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((subjectDirectoryAttributes_length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (subjectDirectoryAttributes_length != input_len) {
        print_error("Error: Encoding of subjectDirectoryAttributes extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (subjectDirectoryAttributes_length == 0) {
        print_error("Error: subjectDirectoryAttributes extension is an empty SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    while (subjectDirectoryAttributes_length > 0) {
        if ((tag = get_tag(&input, &subjectDirectoryAttributes_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x30) {
            print_error("Error: Attribute is not encoded as a SEQUENCE.");
            pop_error_stack();
            return(-1);
        }

        if ((Attribute_length = get_length(&input, &subjectDirectoryAttributes_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        subjectDirectoryAttributes_length -= Attribute_length;

        if (get_OID(&input, &Attribute_length, &AttributeType) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((tag = get_tag(&input, &Attribute_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x31) {
            print_error("Error: values field of Attribute is not encoded as a SET.");
            pop_error_stack();
            return(-1);
        }

        if ((values_length = get_length(&input, &Attribute_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (values_length != Attribute_length) {
            print_error("Error: values field of Attribute contains extraneous data.");
            pop_error_stack();
            return(-1);
        }

        /* TODO: Verify that values in SET are in sorted order */
        while (values_length > 0) {
            if ((tag = get_tag(&input, &values_length)) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((AttributeValue_length = get_length(&input, &values_length)) == -1) {
                pop_error_stack();
                return(-1);
            }

            /* TODO: Check that tag and contents are consistent with AttributeType */
            values_length -= AttributeValue_length;
            input += AttributeValue_length;
        }
    }

    pop_error_stack();
    return(0);
}


/*
 * GeneralName ::= CHOICE {
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER }
 */
int validate_nameConstraintsGeneralName(unsigned char **input, int *input_len)
{
    int tag, length, is_empty, ampersand_found;
    char *registeredID;
    unsigned char *i;

    if (*input_len == 0) {
        print_error("Error: Expecting a GeneralName, but input is empty.");
        return(-1);
    }

    tag = **input;

    switch(tag) {
        case 0xA0: /* otherName */
            if (validate_OtherName(input, input_len) == -1) {
                return(-1);
            }
            break;

        case 0x81: /* rfc822Name */
            push_error_stack("rfc822Name");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }

            if (length == 0) {
                print_error("Error: rfc822Name name constraint contains an empty string.");
            } else {
                ampersand_found = 0;
                for(i=*input; i < *input + length; i++) {
                    if (*i == '@') {
                        ampersand_found = 1;
                    }
                }

                if (ampersand_found) {
                    /* Assume constraint is intended to specify a particular mailbox */
                    validate_rfc822Name(*input, length);
                } else if ((length == 1) && (**input == '.')) {
                    print_error("Error: rfc822Name name constraint does not specify a domain.  The constraint consists of a single character: '.'");
                } else if ((length > 1) && (**input == '.')) {
                    /* Assume constraint is intended to specify all addresses at a particular host */
                    validate_dNSName(*input + 1, length - 1);
                } else {
                    /* Assume constraint is intended to specify all mailboxes in a domain */
                    validate_dNSName(*input, length);
                }
            }

            *input_len -= length;
            *input += length;
            pop_error_stack();
            break;

        case 0x82: /* dNSName */
            push_error_stack("dNSName");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }

            validate_dNSName(*input, length);

            *input_len -= length;
            *input += length;
            pop_error_stack();
            break;

        case 0xA3: /* x400Address */
            push_error_stack("x400Address");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }

            /* TODO: Verify syntax of x400Address name constraint */

            *input_len -= length;
            *input += length;
            pop_error_stack();
            break;

        case 0xA4: /* directoryName */
            if ((tag = get_tag(input, input_len)) == -1) {
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                return(-1);
            }
            *input_len -= length;

            if (validate_directoryName(input, &length, &is_empty) == -1) {
                return(-1);
            }

            if (is_empty) {
                print_error("Warning: directoryName is an empty SEQUENCE.");
            }

            if (length > 0) {
                print_error("Error: Encoding of directoryName includes extraneous data.");
                return(-1);
            }
            break;

        case 0xA5: /* ediPartyName */
            push_error_stack("ediPartyName");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }

            /* TODO: Verify syntax of ediPartyName name constraint */

            *input_len -= length;
            *input += length;
            pop_error_stack();
            break;

        case 0x86: /* uniformResourceIdentifier */
            push_error_stack("uniformResourceIdentifier");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }

            if (length == 0) {
                print_error("Error: uniformResourceIdentifier name constraint contains an empty string.");
            } else if ((length == 1) && (**input == '.')) {
                print_error("Error: uniformResourceIdentifier name constraint does not specify a domain.  The constraint consists of a single character: '.'");
            } else if ((length > 1) && (**input == '.')) {
                /* uniformResourceIdentifier constraint specifies a domain */
                validate_dNSName(*input + 1, length - 1);
            } else {
                /* uniformResourceIdentifier constraint specifies a host */
                validate_dNSName(*input, length);
            }

            *input_len -= length;
            *input += length;
            pop_error_stack();
            break;

        case 0x87: /* iPAddress */
            push_error_stack("iPAddress");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }

            if ((length != 8) && (length != 32)) {
                print_error("Error: iPAddress does not contain a valid IP address name constraint.  Length of octet string must be 8 octets for IPv4 or 32 octets for IPv6.");
            }
            /* Verify that second half of string contains a mask */
            i = *input + length/2;
            while ((i < *input + length) && (*i == 0xFF)) {
                i++;
            }
            if ((i < *input + length) && (*i != 0x00) && (*i != 0x80) && (*i != 0xC0) && (*i != 0xE0) &&
                   (*i != 0xF0) && (*i != 0xF8) && (*i != 0xFC) && (*i != 0xFE)) {
                print_error("Error: iPAddress does not contain a valid IP address name constraint.");
            } else if (i < *input + length) {
                i++;
                while (i < *input + length) {
                    if (*i != 0x00) {
                        print_error("Error: iPAddress does not contain a valid IP address name constraint.");
                        i = *input + length;
                    } else {
                        i++;
                    }
                }
            }

            *input_len -= length;
            *input += length;
            pop_error_stack();
            break;

        case 0x88: /* registeredID */
            /* TODO */
            push_error_stack("registeredID");
            i = *input;
            *i = 0x06;
            if (get_OID(input, input_len, &registeredID) == -1) {
                *i = 0x88;
                pop_error_stack();
                return(-1);
            }
            *i = 0x88;
            pop_error_stack();
            break;

        default:
            print_error("Error: Invalid tag.");
            pop_error_stack();
            return(-1);
            break;
    }

    return(0);
}


/*
 * GeneralSubtree ::= SEQUENCE {
 *      base                    GeneralName,
 *      minimum         [0]     BaseDistance DEFAULT 0,
 *      maximum         [1]     BaseDistance OPTIONAL }
 *
 * BaseDistance ::= INTEGER (0..MAX)
 */
int validate_GeneralSubtree(unsigned char **input, int *input_len)
{
    int tag, length;
    unsigned char *minimum, *maximum;

    push_error_stack("GeneralSubtree");

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: GeneralSubtree is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    *input_len -= length;

    if (length == 0) {
        print_error("Error: GeneralSubtree is an empty SEQUENCE.");
        pop_error_stack();
        return(0);
    }

    if (validate_nameConstraintsGeneralName(input, &length) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        pop_error_stack();
        return(0);
    }

    tag = **input;
    if (tag == 0x80) {
        if ((length >= 3) && (*(*input + 1) == 1) && (*(*input + 2) == 0)) {
            print_error("Error: GeneralSubtree is not DER encoded.  DEFAULT value for minimum (0) appears in encoding.");
        } else {
            print_error("Warning: The PKIX Certificate and CRL profile requires that minimum be set to 0.");
        }
        minimum = *input;
        *minimum = 0x02;
        if (validate_INTEGER(input, &length, 1) == -1) {
            *minimum = 0x80;
            pop_error_stack();
            return(-1);
        }
        *minimum = 0x80;
    }

    if (length == 0) {
        pop_error_stack();
        return(0);
    }

    tag = **input;
    if (tag != 0x81) {
        print_error("Error: Unexpected tag encountered.");
        pop_error_stack();
        return(-1);
    }

    print_error("Warning: The PKIX Certificate and CRL profile requires that maximum be absent.");
    maximum = *input;
    *maximum = 0x02;
    if (validate_INTEGER(input, &length, 1) == -1) {
        *maximum = 0x81;
        pop_error_stack();
        return(-1);
    }
    *maximum = 0x81;

    pop_error_stack();
    return(0);
}

/*
 * GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
 */
int validate_GeneralSubtrees(unsigned char **input, int *input_len)
{
    int tag, length;

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        return(-1);
    }

    if (length == 0) {
        print_error("Error: GeneralSubtrees contains a SEQUENCE of zero GeneralSubtree.");
        return(0);
    }

    *input_len -= length;

    while (length > 0) {
        if (validate_GeneralSubtree(input, &length) == -1) {
            return(-1);
        }
    }

    return(0);
}

/*
 * NameConstraints ::= SEQUENCE {
 *      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
 *      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
 */
int validate_nameConstraints(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("nameConstraints");

    if (!criticality) {
        print_error("Warning: The PKIX Certificate and CRL profile requires that the nameConstraints extension be marked as critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: nameConstraints is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of nameConstraints extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: nameConstraints extension is an empty SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    tag = *input;

    if (tag == 0xA0) {
        push_error_stack("permittedSubtrees");
        if (validate_GeneralSubtrees(&input, &input_len) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        pop_error_stack();
    }

    if (input_len == 0) {
        pop_error_stack();
        return(0);
    }

    tag = *input;
    if (tag != 0xA1) {
        print_error("Error: Unexpected tag encountered.");
        pop_error_stack();
        return(-1);
    }

    push_error_stack("excludedSubtrees");
    if (validate_GeneralSubtrees(&input, &input_len) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    pop_error_stack();

    if (input_len != 0) {
        print_error("Error: Encoding of nameConstraints extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/*
 * DistributionPointName ::= CHOICE {
 *      fullName                [0]     GeneralNames,
 *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 */
int validate_DistributionPointName(unsigned char *input, int input_len)
{
    int tag;
    unsigned char *fullName, *nameRelativeToCRLIssuer;

    push_error_stack("DistributionPointName");

    tag = *input;

    if (tag == 0xA0) {
        push_error_stack("fullName");
        fullName = input;
        *fullName = 0x30;
        if (validate_GeneralNames(&input, &input_len) == -1) {
            *fullName = 0xA0;
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        *fullName = 0xA0;
        pop_error_stack();
    } else if (tag == 0xA1) {
        push_error_stack("nameRelativeToCRLIssuer");
        nameRelativeToCRLIssuer = input;
        *nameRelativeToCRLIssuer = 0x31;
        if (validate_RelativeDistinguishedName(&input, &input_len) == -1) {
            *nameRelativeToCRLIssuer = 0xA1;
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        *nameRelativeToCRLIssuer = 0xA1;
        pop_error_stack();
    } else {
        print_error("Error: Unexpected tag.");
        pop_error_stack();
        return(-1);
    }

    if (input_len > 0) {
        print_error("Error: distributionPoint contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/*
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
 *      reasons                 [1]     ReasonFlags OPTIONAL,
 *      cRLIssuer               [2]     GeneralNames OPTIONAL }
 *
 * ReasonFlags ::= BIT STRING {
 *      unused                  (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6),
 *      privilegeWithdrawn      (7),
 *      aACompromise            (8) }
 */
int validate_DistributionPoint(unsigned char **input, int *input_len)
{
    int tag, length, DistributionPointName_length, reasons_length;
    int distributionPoint_present = 0;
    int cRLIssuer_present = 0;
    unsigned char *cRLIssuer;

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: DistributionPoint is not encoded as a SEQUENCE.");
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        return(-1);
    }

    if (length == 0) {
        print_error("Warning: DistributionPoint is an empty SEQUENCE.");
        return(0);
    }

    *input_len -= length;

    tag = **input;
    if (tag == 0xA0) {
        distributionPoint_present = 1;

        if ((tag = get_tag(input, &length)) == -1) {
            return(-1);
        }
        if ((DistributionPointName_length = get_length(input, &length)) == -1) {
            return(-1);
        }

        if (validate_DistributionPointName(*input, DistributionPointName_length) == -1) {
            return(-1);
        }
        length -= DistributionPointName_length;
        *input += DistributionPointName_length;
    }

    if ((length > 0) && (**input == 0x81)) {
        if ((tag = get_tag(input, &length)) == -1) {
            return(-1);
        }
        if ((reasons_length = get_length(input, &length)) == -1) {
            return(-1);
        }
        if (validate_BITSTRING(reasons_length, *input, 1) == -1) {
            return(-1);
        }
        length -= reasons_length;
        *input += reasons_length;
    }

    if ((length > 0) && (**input != 0xA2)) {
        print_error("Error: Unrecognized tag in DistributionPoint.");
        return(-1);
    }

    if (length > 0) {
        push_error_stack("cRLIssuer");
        cRLIssuer_present = 1;

        cRLIssuer = *input;
        *cRLIssuer = 0x30;
        if (validate_GeneralNames(input, &length) == -1) {
            *cRLIssuer = 0xA2;
            pop_error_stack();
            return(-1);
        }
        *cRLIssuer = 0xA2;
        pop_error_stack();
    }

    if (length > 0) {
        print_error("Error: DistributionPoint contains extraneous data.");
    }

    if (!distributionPoint_present && !cRLIssuer_present) {
        print_error("Warning: The PKIX Certificate and CRL profile requires that either distributionPoint or cRLIssuer be present in a DistributionPoint.");
    }

    return(0);
}



/*
 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 */
int validate_cRLDistributionPoints(unsigned char *input, int input_len)
{
    int tag, length;

    push_error_stack("cRLDistributionPoints");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: cRLDistributionPoints is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of cRLDistributionPoints extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: cRLDistributionPoints extension is an empty SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    while (length > 0) {
        if (validate_DistributionPoint(&input, &length) == -1) {
            pop_error_stack();
            return(-1);
        }
    }

    pop_error_stack();
    return(0);
}


/*
 * AuthorityInfoAccessSyntax  ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
 *
 * SubjectInfoAccessSyntax    ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
 *
 * AccessDescription  ::=  SEQUENCE {
 *         accessMethod          OBJECT IDENTIFIER,
 *         accessLocation        GeneralName  }
 */
int validate_InfoAccess(unsigned char *input, int input_len, int criticality, char *extnID)
{
    int tag, length, AccessDescription_length;
    char *accessMethod;


    if (criticality) {
        if (strcmp(extnID, "1.3.6.1.5.5.7.1.1") == 0) {
            print_error("Error: authorityInfoAccess extension must be marked as non-critical.");
        } else {
            print_error("Error: subjectInfoAccess extension must be marked as non-critical.");
        }
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        return(-1);
    }

    if (tag != 0x30) {
        if (strcmp(extnID, "1.3.6.1.5.5.7.1.1") == 0) {
            print_error("Error: authorityInfoAccess extension is not encoded as a SEQUENCE.");
        } else {
            print_error("Error: subjectInfoAccess extension is not encoded as a SEQUENCE.");
        }
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        return(-1);
    }

    if (length != input_len) {
        if (strcmp(extnID, "1.3.6.1.5.5.7.1.1") == 0) {
            print_error("Error: Encoding of authorityInfoAccess extension contains extraneous data.");
        } else {
            print_error("Error: Encoding of subjectInfoAccess extension contains extraneous data.");
        }
        return(-1);
    }

    if (length == 0) {
        if (strcmp(extnID, "1.3.6.1.5.5.7.1.1") == 0) {
            print_error("Error: authorityInfoAccess extension is an empty SEQUENCE.");
        } else {
            print_error("Error: subjectInfoAccess extension is an empty SEQUENCE.");
        }
        return(-1);
    }

    while (input_len > 0) {
        if ((tag = get_tag(&input, &input_len)) == -1) {
            return(-1);
        }
        if (tag != 0x30) {
            print_error("Error: AccessDescription extension is not encoded as a SEQUENCE.");
            return(-1);
        }

        if ((AccessDescription_length = get_length(&input, &input_len)) == -1) {
            return(-1);
        }

        input_len -= AccessDescription_length;

        if (get_OID(&input, &AccessDescription_length, &accessMethod) == -1) {
            return(-1);
        }

        if (strcmp(accessMethod, "1.3.6.1.5.5.7.48.1") == 0) {
            sprintf(error_str, "AccessDescription (accessMethod = id-ad-ocsp)");
            if (strcmp(extnID, "1.3.6.1.5.5.7.1.11") == 0) {
                print_error("Error: The id-ad-ocsp access method should not appear in the subjectInfoAccess extension.");
            }
        } else if (strcmp(accessMethod, "1.3.6.1.5.5.7.48.2") == 0) {
            sprintf(error_str, "AccessDescription (accessMethod = id-ad-caIssuers)");
            if (strcmp(extnID, "1.3.6.1.5.5.7.1.11") == 0) {
                print_error("Error: The id-ad-caIssuers access method should not appear in the subjectInfoAccess extension.");
            }
        } else if (strcmp(accessMethod, "1.3.6.1.5.5.7.48.3") == 0) {
            sprintf(error_str, "AccessDescription (accessMethod = id-ad-timeStamping)");
            if (strcmp(extnID, "1.3.6.1.5.5.7.1.1") == 0) {
                print_error("Error: The id-ad-timeStamping access method should not appear in the authorityInfoAccess extension.");
            }
        } else if (strcmp(accessMethod, "1.3.6.1.5.5.7.48.5") == 0) {
            sprintf(error_str, "AccessDescription (accessMethod = id-ad-caRepository)");
            if (strcmp(extnID, "1.3.6.1.5.5.7.1.1") == 0) {
                print_error("Error: The id-ad-caRepository access method should not appear in the authorityInfoAccess extension.");
            }
        } else {
            sprintf(error_str, "AccessDescription (accessMethod = %s)", accessMethod);
        }
        push_error_stack(error_str);
        if (validate_GeneralName(&input, &AccessDescription_length) == -1) {
            free(accessMethod);
            pop_error_stack();
            return(-1);
        }
        pop_error_stack();

        if (AccessDescription_length > 0) {
            print_error("Error: Encoding of AccessDescription contains extraneous data.");
            free(accessMethod);
            return(-1);
        }

        free(accessMethod);
    }

    return(0);
}

/*
 * id-pkix-ocsp-nocheck is a non-critical extension with a value of NULL.
 */
int validate_OCSP_nocheck(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("ocsp-nocheck");

    if (criticality) {
        print_error("Warning: ocsp-nocheck should be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 5) {
        print_error("Error: Unexpected tag.  ocsp-nocheck should have a value of NULL.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        return(-1);
    }

    if (length != 0) {
        print_error("Error: The DER encoding of the value NULL must have a length of 0.");
        pop_error_stack();
        return(-1);
    }

    if (input_len != 0) {
        print_error("Error: Encoding of ocsp-nocheck contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/*
 * OtherLogotypeInfo ::= SEQUENCE {
 *    logotypeType    OBJECT IDENTIFIER,
 *    info            LogotypeInfo }
 */
int validate_OtherLogotypeInfo(unsigned char **input, int *input_len)
{
    push_error_stack("OtherLogotypeInfo");

    /* TODO */
    if (validate_generic_DER(input, input_len) == -1) {
        pop_error_stack();
        return(-1);
    }
    print_error("Warning: OtherLogotypeInfo not yet supported by this program. Contents not parsed.");
    pop_error_stack();
    return(0);
}

/*
 * LogotypeReference ::= SEQUENCE {
 *    refStructHash   SEQUENCE SIZE (1..MAX) OF HashAlgAndValue,
 *    refStructURI    SEQUENCE SIZE (1..MAX) OF IA5String }
 *                     -- Places to get the same "LTD" file
 */
int validate_LogotypeReference(unsigned char **input, int *input_len)
{
/*
    int tag, length;
*/

    push_error_stack("LogotypeReference");

/*
    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: LogotypeReference is not encoded as a SEQUENCE.");
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        return(-1);
    }
*/

    /* TODO: just skip over for now */
    if (validate_generic_DER(input, input_len) == -1) {
        pop_error_stack();
        return(-1);
    }
    print_error("Warning: LogotypeReference not yet supported by this program. Contents not parsed.");
    pop_error_stack();
    return(0);
}

/*
 * LogotypeImageInfo ::= SEQUENCE {
 *    type            [0] LogotypeImageType DEFAULT color,
 *    fileSize        INTEGER,  -- In octets
 *    xSize           INTEGER,  -- Horizontal size in pixels
 *    ySize           INTEGER,  -- Vertical size in pixels
 *    resolution      LogotypeImageResolution OPTIONAL,
 *    language        [4] IA5String OPTIONAL }  -- RFC 3066 Language Tag
 */
int validate_LogotypeImageInfo(unsigned char **input, int *input_len)
{
    push_error_stack("LogotypeImageInfo");

    /* TODO: just skip over for now */
    if (validate_generic_DER(input, input_len) == -1) {
        pop_error_stack();
        return(-1);
    }
    print_error("Warning: LogotypeImageInfo not yet supported by this program. Contents not parsed.");
    pop_error_stack();
    return(0);
}

/*
 * LogotypeDetails ::= SEQUENCE {
 *    mediaType       IA5String, -- MIME media type name and optional
 *                               -- parameters
 *    logotypeHash    SEQUENCE SIZE (1..MAX) OF HashAlgAndValue,
 *    logotypeURI     SEQUENCE SIZE (1..MAX) OF IA5String }
 *
 * HashAlgAndValue ::= SEQUENCE {
 *    hashAlg         AlgorithmIdentifier,
 *    hashValue       OCTET STRING }
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
int validate_LogotypeDetails(unsigned char **input, int *input_len)
{
    int tag, LogotypeDetails_length, mediaType_length, logotypeHash_length, logotypeURI_length;
    int HashAlgAndValue_length, AlgorithmIdentifier_length, hashValue_length;
    int URI_length;
    int sha1_found = 0;
    char *algorithm_OID, hash_alg[20];

    push_error_stack("LogotypeDetails");

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: LogotypeDetails is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((LogotypeDetails_length = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    *input_len -= LogotypeDetails_length;

    /* mediaType */
    if ((tag = get_tag(input, &LogotypeDetails_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 22) {
        print_error("Error: LogotypeDetails SEQUENCE does not begin with an IA5String (mediaType).");
        pop_error_stack();
        return(-1);
    }

    if ((mediaType_length = get_length(input, &LogotypeDetails_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    validate_IA5String(*input, mediaType_length, mediaType_length);
    *input += mediaType_length;
    LogotypeDetails_length -= mediaType_length;

    /* logotypeHash */
    if ((tag = get_tag(input, &LogotypeDetails_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: Second field of LogotypeDetails SEQUENCE (logotypeHash) is not of type SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((logotypeHash_length = get_length(input, &LogotypeDetails_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (logotypeHash_length == 0) {
        print_error("Error: logotypeHash SEQUENCE is empty.");
        pop_error_stack();
        return(-1);
    }

    LogotypeDetails_length -= logotypeHash_length;

    while (logotypeHash_length > 0) {
        if ((tag = get_tag(input, &logotypeHash_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x30) {
            print_error("Error: HashAlgAndValue in logotypeHash is not of type SEQUENCE.");
            pop_error_stack();
            return(-1);
        }

        if ((HashAlgAndValue_length = get_length(input, &logotypeHash_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (HashAlgAndValue_length == 0) {
            print_error("Error: HashAlgAndValue SEQUENCE is empty.");
            pop_error_stack();
            return(-1);
        }

        logotypeHash_length -= HashAlgAndValue_length;
        
        if ((tag = get_tag(input, &HashAlgAndValue_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x30) {
            print_error("Error: AlgorithmIdentifier in HashAlgAndValue in logotypeHash is not of type SEQUENCE.");
            pop_error_stack();
            return(-1);
        }

        if ((AlgorithmIdentifier_length = get_length(input, &HashAlgAndValue_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (AlgorithmIdentifier_length == 0) {
            print_error("Error: HashAlgAndValue SEQUENCE is empty.");
            pop_error_stack();
            return(-1);
        }

        HashAlgAndValue_length -= AlgorithmIdentifier_length;

        if (get_OID(input, &AlgorithmIdentifier_length, &algorithm_OID) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (strcmp(algorithm_OID, "1.3.14.3.2.26") == 0) {
            sha1_found = 1;
            sprintf(hash_alg, "SHA-1");
        } else if (strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.4") == 0) {
            sprintf(hash_alg, "SHA-224");
        } else if (strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.1") == 0) {
            sprintf(hash_alg, "SHA-256");
        } else if (strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.2") == 0) {
            sprintf(hash_alg, "SHA-384");
        } else if (strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.3") == 0) {
            sprintf(hash_alg, "SHA-512");
        } else if (strcmp(algorithm_OID, "1.2.840.113549.2.2") == 0) {
            sprintf(hash_alg, "MD2");
        } else if (strcmp(algorithm_OID, "1.2.840.113549.2.5") == 0) {
            sprintf(hash_alg, "MD5");
        }

        if ((strcmp(algorithm_OID, "1.3.14.3.2.26") == 0) ||
            (strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.4") == 0) ||
            (strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.1") == 0) ||
            (strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.2") == 0) ||
            (strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.3") == 0) ||
            (strcmp(algorithm_OID, "1.2.840.113549.2.2") == 0) ||
            (strcmp(algorithm_OID, "1.2.840.113549.2.5") == 0)) {
            /* parameters is either absent or contains NULL */

            if (AlgorithmIdentifier_length == 2) {
                if ((tag = get_tag(input, &AlgorithmIdentifier_length)) == -1) {
                    free(algorithm_OID);
                    pop_error_stack();
                    return(-1);
                }
                
                if (tag != 0x05) {
                    sprintf(error_str, "Error: Parameters field for %s must either be absent or NULL.", hash_alg);
                    print_error(error_str);
                    free(algorithm_OID);
                    pop_error_stack();
                    return(-1);
                }

                if (get_length(input, &AlgorithmIdentifier_length) != 0) {
                    free(algorithm_OID);
                    pop_error_stack();
                    return(-1);
                }
            } else if (AlgorithmIdentifier_length != 0) {
                sprintf(error_str, "Error: Parameters field for %s must either be absent or NULL.", hash_alg);
                print_error(error_str);
                free(algorithm_OID);
                pop_error_stack();
                return(-1);
            }

        } else if (AlgorithmIdentifier_length != 0) {
            /* Unknown hash algorithm. Just check that contents is DER encoded. */
            if (validate_generic_DER(input, &AlgorithmIdentifier_length) == -1) {
                free(algorithm_OID);
                pop_error_stack();
                return(-1);
            }
            if (AlgorithmIdentifier_length != 0) {
                print_error("Error: Encoding of AlgorithmIdentifier in HashAlgAndValue in logotypeHash contains extraneous data.");
                free(algorithm_OID);
                pop_error_stack();
                return(-1);
            }
        }

        if ((tag = get_tag(input, &HashAlgAndValue_length)) == -1) {
            free(algorithm_OID);
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x04) {
            print_error("Error: hashValue in HashAlgAndValue in logotypeHash is not of type OCTET STRING.");
            free(algorithm_OID);
            pop_error_stack();
            return(-1);
        }

        if ((hashValue_length = get_length(input, &HashAlgAndValue_length)) == -1) {
            free(algorithm_OID);
            pop_error_stack();
            return(-1);
        }

        if (((strcmp(algorithm_OID, "1.3.14.3.2.26") == 0) && (hashValue_length != 20)) ||
        ((strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.4") == 0) && (hashValue_length != 28)) ||
        ((strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.1") == 0) && (hashValue_length != 32)) ||
        ((strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.2") == 0) && (hashValue_length != 48)) ||
        ((strcmp(algorithm_OID, "2.16.840.1.101.3.4.2.3") == 0) && (hashValue_length != 64)) ||
        ((strcmp(algorithm_OID, "1.2.840.113549.2.2") == 0) && (hashValue_length != 16)) ||
        ((strcmp(algorithm_OID, "1.2.840.113549.2.5") == 0) && (hashValue_length != 16))) {
            sprintf(error_str, "Error: Incorrect hashValue length (%d octets) for specified hash algorithm (%s).", hashValue_length, hash_alg);
            print_error(error_str);
        }

        *input += hashValue_length;

        if (hashValue_length != HashAlgAndValue_length) {
            print_error("Error: Encoding of logotypeHash contains extraneous data.");
            free(algorithm_OID);
            pop_error_stack();
            return(-1);
        }

        free(algorithm_OID);
    }

    if (!sha1_found) {
        print_error("Error: logotypeHash does not include a SHA-1 hash as required by RFC 3709.");
    }

    if (LogotypeDetails_length == 0) {
        print_error("Error: logotypeURI field missing.");
        pop_error_stack();
        return(-1);
    }

    if ((tag = get_tag(input, &LogotypeDetails_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: Third field of LogotypeDetails SEQUENCE (logotypeURI) is not of type SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((logotypeURI_length = get_length(input, &LogotypeDetails_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (logotypeURI_length == 0) {
        print_error("Error: logotypeURI SEQUENCE is empty.");
        pop_error_stack();
        return(-1);
    }

    LogotypeDetails_length -= logotypeURI_length;

    while (logotypeURI_length > 0) {
        if ((tag = get_tag(input, &logotypeURI_length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 22) {
            print_error("Error: URI in logotypeURI is not of type IA5String.");
            pop_error_stack();
            return(-1);
        }

        if ((URI_length = get_length(input, &logotypeURI_length)) == -1) {
            pop_error_stack();
            return(-1);
        }
        
        if (validate_URI(*input, URI_length) == -1) {
            pop_error_stack();
            return(-1);
        }

        *input += URI_length;
        logotypeURI_length -= URI_length;
    }

    if (LogotypeDetails_length != 0) {
        print_error("Error: Encoding of LogotypeDetails SEQUENCE contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/*
 * LogotypeAudio ::= SEQUENCE {
 *    audioDetails    LogotypeDetails,
 *    audioInfo       LogotypeAudioInfo OPTIONAL }
 */
int validate_LogotypeAudio(unsigned char **input, int *input_len)
{
/*
    int tag, length;
*/

    push_error_stack("LogotypeAudio");

/*
    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: LogotypeAudio is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
*/

    /* TODO: just skip over for now */
    if (validate_generic_DER(input, input_len) == -1) {
        pop_error_stack();
        return(-1);
    }
    print_error("Warning: LogotypeAudio not yet supported by this program. Contents not parsed.");
    pop_error_stack();
    return(0);
}

/*
 * LogotypeImage ::= SEQUENCE {
 *    imageDetails    LogotypeDetails,
 *    imageInfo       LogotypeImageInfo OPTIONAL }
 */
int validate_LogotypeImage(unsigned char **input, int *input_len)
{
    int tag, length;

    push_error_stack("LogotypeImage");

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: LogotypeImage is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    *input_len -= length;

    if (validate_LogotypeDetails(input, &length) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        pop_error_stack();
        return(0);
    }

    if (validate_LogotypeImageInfo(input, &length) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != 0) {
        print_error("Error: Encoding of LogotypeImage contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/*
 * LogotypeData ::= SEQUENCE {
 *    image           SEQUENCE OF LogotypeImage OPTIONAL,
 *    audio           [1] SEQUENCE OF LogotypeAudio OPTIONAL }
 */
int validate_LogotypeData(unsigned char **input, int *input_len)
{
    int tag, length, image_length, audio_length;

    push_error_stack("LogotypeData");

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: LogotypeReference is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Warning: LogotypeData is an empty SEQUENCE.");
        pop_error_stack();
        return(0);
    }

    *input_len -= length;

    tag = **input;

    if (tag == 0x30) {
        /* image */
        if ((tag = get_tag(input, &length)) == -1) {
            pop_error_stack();
            return(-1);
        }
        if ((image_length = get_length(input, &length)) == -1) {
            pop_error_stack();
            return(-1);
        }

        length -= image_length;

        while (image_length > 0) {
            if (validate_LogotypeImage(input, &image_length) == -1) {
                pop_error_stack();
                return(-1);
            }
        }
    }

    if (length == 0) {
        pop_error_stack();
        return(0);
    }

    if ((tag = get_tag(input, &length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0xA1) {
        sprintf(error_str, "Error: LogotypeData contains a field with an unexpected tag: %d.", tag);
        print_error(error_str);
        pop_error_stack();
        return(-1);
    }

    if ((audio_length = get_length(input, &length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != audio_length) {
        print_error("Error: Encoding of LogotypeData contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    while (audio_length > 0) {
        if (validate_LogotypeAudio(input, &audio_length) == -1) {
            pop_error_stack();
            return(-1);
        }
    }

    pop_error_stack();
    return(0);
}

/*
 * LogotypeInfo ::= CHOICE {
 *    direct          [0] LogotypeData,
 *    indirect        [1] LogotypeReference }
 */
int validate_LogotypeInfo(unsigned char **input, int *input_len)
{
    int tag;
    unsigned char *LogotypeInfo_tag;

    push_error_stack("LogotypeInfo");

    LogotypeInfo_tag = *input;
    tag = *LogotypeInfo_tag;

    if ((tag != 0xA0) && (tag != 0xA1)) {
        print_error("Error: Unrecognized tag in LogotypeInfo.");
        pop_error_stack();
        return(-1);
    }

    *LogotypeInfo_tag = 0x30;
    if (tag == 0xA0) {
        validate_LogotypeData(input, input_len);
    } else {
        validate_LogotypeReference(input, input_len);
    }
    *LogotypeInfo_tag = tag;

    pop_error_stack();
    return(0);
}

/*
 * LogotypeExtn ::= SEQUENCE {
 *    communityLogos  [0] EXPLICIT SEQUENCE OF LogotypeInfo OPTIONAL,
 *    issuerLogo      [1] EXPLICIT LogotypeInfo OPTIONAL,
 *    subjectLogo     [2] EXPLICIT LogotypeInfo OPTIONAL,
 *    otherLogos      [3] EXPLICIT SEQUENCE OF OtherLogotypeInfo OPTIONAL }
 */
int validate_LogotypeExtn(unsigned char *input, int input_len, int criticality)
{
    int tag, length, LogotypeExtn_field_length, communityLogos_length;
    int issuerLogo_length, subjectLogo_length, otherLogos_length;
    unsigned char *LogotypeExtn_field, *communityLogos, *issuerLogo, *subjectLogo, *otherLogos;

    push_error_stack("logotype");

    if (criticality) {
        print_error("Error: logotype extension must not be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: logotype extension is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: The logotype extension contains no data.");
        pop_error_stack();
        return(-1);
    }

    if (input_len != length) {
        print_error("Error: Encoding of logotype extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    tag = *input;

    if (tag == 0xA0) {
        push_error_stack("communityLogos");

        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((LogotypeExtn_field_length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        LogotypeExtn_field = input;
        input += LogotypeExtn_field_length;
        input_len -= LogotypeExtn_field_length;

        if ((tag = get_tag(&LogotypeExtn_field, &LogotypeExtn_field_length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x30) {
            print_error("Error: communityLogos field of logotype extension is not encoded as a SEQUENCE.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if ((communityLogos_length = get_length(&LogotypeExtn_field, &LogotypeExtn_field_length)) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (communityLogos_length != LogotypeExtn_field_length) {
            print_error("Error: Encoding of communityLogos field in logotype extension contains extraneous data.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        communityLogos = LogotypeExtn_field;
        while (communityLogos_length > 0) {
            if (validate_LogotypeInfo(&communityLogos, &communityLogos_length) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
        }
        
        pop_error_stack();
    }

    if (input_len == 0) {
        pop_error_stack();
        return(0);
    }

    tag = *input;

    if (tag == 0xA1) {
        push_error_stack("issuerLogo");

        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((LogotypeExtn_field_length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        LogotypeExtn_field = input;
        input += LogotypeExtn_field_length;
        input_len -= LogotypeExtn_field_length;

        issuerLogo = LogotypeExtn_field;
        issuerLogo_length = LogotypeExtn_field_length;
        if (validate_LogotypeInfo(&issuerLogo, &issuerLogo_length) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (issuerLogo_length != 0) {
            print_error("Error: Encoding of issuerLogo contains extraneous data.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        pop_error_stack();
    }

    if (input_len == 0) {
        pop_error_stack();
        return(0);
    }

    tag = *input;
    if (tag == 0xA2) {
        push_error_stack("subjectLogo");

        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if ((LogotypeExtn_field_length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        LogotypeExtn_field = input;
        input += LogotypeExtn_field_length;
        input_len -= LogotypeExtn_field_length;

        subjectLogo = LogotypeExtn_field;
        subjectLogo_length = LogotypeExtn_field_length;
        if (validate_LogotypeInfo(&subjectLogo, &subjectLogo_length) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        if (subjectLogo_length != 0) {
            print_error("Error: Encoding of subjectLogo contains extraneous data.");
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }

        pop_error_stack();
    }

    if (input_len == 0) {
        pop_error_stack();
        return(0);
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0xA3) {
        print_error("Error: Unrecognized tag.  Encoding of logotype extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    push_error_stack("otherLogos");

    if ((LogotypeExtn_field_length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    LogotypeExtn_field = input;
    input += LogotypeExtn_field_length;
    input_len -= LogotypeExtn_field_length;


    if ((tag = get_tag(&LogotypeExtn_field, &LogotypeExtn_field_length)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: otherLogos field of logotype extension is not encoded as a SEQUENCE.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if ((otherLogos_length = get_length(&LogotypeExtn_field, &LogotypeExtn_field_length)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if (otherLogos_length != LogotypeExtn_field_length) {
        print_error("Error: Encoding of otherLogos field in logotype extension contains extraneous data.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    otherLogos = LogotypeExtn_field;
    while (otherLogos_length > 0) {
        if (validate_OtherLogotypeInfo(&otherLogos, &otherLogos_length) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
    }
        
    pop_error_stack();

    if (input_len != 0) {
        print_error("Error: Encoding of logotype extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/*
 * NACI-indicator ::= BOOLEAN
 */
int validate_NACI_indicator(unsigned char *input, int input_len, int criticality)
{
    int indicator;
    push_error_stack("NACI indicator");

    if (criticality) {
        print_error("Error: NACI indicator extension must be marked as non-critical.");
    }

    if (get_BOOLEAN(&input, &input_len, &indicator) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (input_len != 0) {
        print_error("Encoding of NACI indicator extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/*
 * SMIMECapabilities ::= SEQUENCE OF SMIMECapability
 *
 * SMIMECapability ::= SEQUENCE {
 *    capabilityID OBJECT IDENTIFIER,
 *    parameters ANY DEFINED BY capabilityID OPTIONAL }
 */
int validate_smimeCapabilities(unsigned char *input, int input_len)
{
    int tag, length, SMIMECapability_length;
    char *capabilityID;

    push_error_stack("SMIMECapabilities");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: SMIMECapabilities is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of SMIMECapabilities extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (input_len == 0) {
        print_error("Warning: SMIMECapabilities extension is an empty sequence.");
    }

    while (input_len > 0) {
        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x30) {
            print_error("Error: SMIMECapability is not encoded as a SEQUENCE.");
            pop_error_stack();
            return(-1);
        }

        if ((SMIMECapability_length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }
        input_len -= SMIMECapability_length;

        push_error_stack("SMIMECapability");

        if (get_OID(&input, &SMIMECapability_length, &capabilityID) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        free(capabilityID);

        if (SMIMECapability_length > 0) {
            push_error_stack("parameters");

            /* TODO: Perform capabilityID specific validation of parameters field. */
            if (validate_generic_DER(&input, &SMIMECapability_length) == -1) {
                pop_error_stack();
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            pop_error_stack();
        
            if (SMIMECapability_length > 0) {
                print_error("Error: Encoding of SMIMECapability contains extraneous data.");
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
        }
        pop_error_stack();
    }

    pop_error_stack();
    return(0);
}

/*
 * EntrustVersInfoSyntax ::=  SEQUENCE {
 *     entrustVers          GeneralString,
 *     entrustInfoFlags     EntrustInfoFlags }
 */
int validate_entrustVersInfo(unsigned char *input, int input_len, int criticality)
{
    int tag, length;
    unsigned char *version;

    push_error_stack("entrustVersInfo");

    if (criticality) {
        print_error("Error: entrustVersInfo extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: entrustVersInfo extension is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of entrustVersInfo extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: entrustVersInfo extension contains an empty SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 27) {
        print_error("Error: entrustVers must be of type GeneralString.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: entrustVers is an empty string.");
        pop_error_stack();
        return(-1);
    }

    version = input;

    /* Check contents of entrustVers: assumes syntax is "V" 1*(0-9) ["." 1*(0-9)] */
    if ((*version != 'V') && (*version != 'v')) {
        print_error("Error: entrustVers does not begin with 'V'.");
    } else {
        version++;
        if (version == input + length) {
            sprintf(error_str, "Error: entrustVers only contains a single character: '%c'.", *(version-1));
            print_error(error_str);
        } else if ((*version < '0') || (*version > '9')) {
            print_error("Error: decimal digit expected following 'V' in entrustVers.");
        } else {
            version++;
            while ((version < input + length) && (*version >= '0') && (*version <= '9')) {
                version++;
            }
            if ((version < input + length) && (*version != '.')) {
                print_error("Error: entrustVers contains an unexpected character.");
            } else if (version < input + length) {
                version++;
                if (version == input + length) {
                    print_error("Error: entrustVers ends with a '.'.");
                } else {
                    while ((version < input + length) && (*version >= '0') && (*version <= '9')) {
                        version++;
                    }
                    if (version < input + length) {
                        print_error("Error: entrustVers contains an unexpected character.");
                    }
                }
            }
        }
    }

    input += length;
    input_len -= length;

    if (input_len == 0) {
        print_error("Error: entrustInfoFlags from entrustVersInfo extension SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    /* Check that entrustInfoFlags is a named bit list */
    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 3) {
        print_error("Error: entrustInfoFlags must be of type BIT STRING.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    validate_BITSTRING(length, input, 1);

    if (length != input_len) {
        print_error("Error: entrustVersInfo extension SEQUENCE contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/* The netscape-cert-type extension contains a named bit list that specifies the
 * applications with which the certifiate may be used.
 */
int validate_netscape_cert_type(unsigned char *input, int input_len)
{
    int tag, length;

    push_error_stack("netscape-cert-type");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 3) {
        print_error("Error: netscape-cert-type extension is not encoded as an BIT STRING.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of netscape-cert-type extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (validate_BITSTRING(length, input, 1) == -1) {
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/*
 * netscape-base-url is an IA5String that holds a URL.  Other Netscape extensions may
 * hold relative URLs, and if they do this extension holds the related base URL.
 */
int validate_netscape_base_url(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("netscape-base-url");

    if (criticality) {
        print_error("Error: netscape-base-url extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 22) {
        print_error("Error: netscape-base-url extension is not encoded as an IA5String.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of netscape-base-url extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: netscape-base-url extension contains an empty string.");
        pop_error_stack();
        return(-1);
    }

    if (validate_URI(input, length) == -1) {
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}

/*
 * netscape-revocation-url contains a relative or absolute URL.
 */
int validate_NetscapeRevocationURL(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("netscape-revocation-url");

    if (criticality) {
        print_error("Error: netscape-revocation-url extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 22) {
        print_error("Error: netscape-revocation-url extension is not encoded as an IA5String.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of netscape-revocation-url extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: netscape-revocation-url extension contains an empty string.");
        pop_error_stack();
        return(-1);
    }

    /* TODO: Check that string contains a valid relative or absolute URL. */
    if (validate_IA5String(input, length, length) == -1) {
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/*
 * netscape-ca-revocation-url contains a relative or absolute URL.
 */
int validate_NetscapeCARevocationURL(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("netscape-ca-revocation-url");

    if (criticality) {
        print_error("Error: netscape-ca-revocation-url extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 22) {
        print_error("Error: netscape-ca-revocation-url extension is not encoded as an IA5String.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of netscape-ca-revocation-url extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: netscape-ca-revocation-url extension contains an empty string.");
        pop_error_stack();
        return(-1);
    }

    /* TODO: Check that string contains a valid relative or absolute URL. */
    if (validate_IA5String(input, length, length) == -1) {
        pop_error_stack();
        return(-1);
    }

    /* TODO: According to
     * http://www.rsa.com/products/bsafe/documentation/certj10javadochtml/com/rsa/certj/cert/extensions/NetscapeCARevocationURL.html
     * this extension is only valid in a CA certificate
     */

    pop_error_stack();
    return(0);
}


/*
 * netscape-cert-renewal-url contains a relative or absolute URL.
 */
int validate_NetscapeCertRenewalURL(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("netscape-cert-renewal-url");

    if (criticality) {
        print_error("Error: netscape-cert-renewal-url extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 22) {
        print_error("Error: netscape-cert-renewal-url extension is not encoded as an IA5String.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of netscape-cert-renewal-url extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: netscape-cert-renewal-url extension contains an empty string.");
        pop_error_stack();
        return(-1);
    }

    /* TODO: Check that string contains a valid relative or absolute URL. */
    if (validate_IA5String(input, length, length) == -1) {
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/*
 * netscape-ca-policy-url contains a relative or absolute URL.
 */
int validate_NetscapeCAPolicyURL(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("netscape-ca-policy-url");

    if (criticality) {
        print_error("Error: netscape-ca-policy-url extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 22) {
        print_error("Error: netscape-ca-policy-url extension is not encoded as an IA5String.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of netscape-ca-policy-url extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: netscape-ca-policy-url extension contains an empty string.");
        pop_error_stack();
        return(-1);
    }

    /* TODO: Check that string contains a valid relative or absolute URL. */
    if (validate_IA5String(input, length, length) == -1) {
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/*
 * netscape-ssl-server-name is an IA5String containing a the host's name as a shell expression.
 */
int validate_NetscapeSSLServerName(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("netscape-ssl-server-name");

    if (criticality) {
        print_error("Error: netscape-ssl-server-name extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 22) {
        print_error("Error: netscape-ssl-server-name extension is not encoded as an IA5String.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of netscape-ssl-server-name extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: netscape-ssl-server-name extension contains an empty string.");
        pop_error_stack();
        return(-1);
    }

    if (validate_IA5String(input, length, length) == -1) {
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/*
 * netscape-comment is an IA5String holding a comment that may be displayed to the user.
 */
int validate_NetscapeComment(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("netscape-comment");

    if (criticality) {
        print_error("Error: netscape-comment extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 22) {
        print_error("Error: netscape-comment extension is not encoded as an IA5String.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of netscape-comment extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: netscape-comment extension contains an empty string.");
        pop_error_stack();
        return(-1);
    }

    if (validate_IA5String(input, length, length) == -1) {
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/*
 * TODO: Guessing that enrollCerttypeExtension is a BMPString.
 */
int validate_enrollCerttypeExtension(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("enrollCerttypeExtension");

    if (criticality) {
        print_error("Error: enrollCerttypeExtension extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 30) {
        print_error("Error: enrollCerttypeExtension extension is not encoded as an BMPString.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of enrollCerttypeExtension extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: enrollCerttypeExtension extension contains an empty string.");
        pop_error_stack();
        return(-1);
    }

    if (validate_BMPString(input, length, length) == -1) {
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}


/* TODO: Verify syntax of this extension. */
int validate_certSrvPreviousCertHash(unsigned char *input, int input_len, int criticality)
{
    int tag, length;

    push_error_stack("szOID_CERTSRV_PREVIOUS_CERT_HASH");

    if (criticality) {
        print_error("Error: szOID_CERTSRV_PREVIOUS_CERT_HASH extension must be marked as non-critical.");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 4) {
        print_error("Error: szOID_CERTSRV_PREVIOUS_CERT_HASH extension is not encoded as an OCTET STRING.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: encoding of szOID_CERTSRV_PREVIOUS_CERT_HASH extension includes extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (length == 0) {
        print_error("Error: szOID_CERTSRV_PREVIOUS_CERT_HASH extension contains an empty string.");
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();
    return(0);
}



/* From http://msdn.microsoft.com/en-us/library/cc249912(PROT.13).aspx:
 *    The encoding rules for this [msPKI-Certificate-Application-Policy] extension
 *    are identical to the encoding rules for the "certificate policies" extension
 *    as specified in [RFC3280] section 4.2.1.5.
 *
 *    For each value in this multivalue attribute, the client MUST encode a
 *    PolicyInformation object where the policyIdentifier MUST contain the value
 *    stored in this attribute and the PolicyQualifier MUST NOT be present.
 *
 * applicationCertPolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 *
 * PolicyInformation ::= SEQUENCE {
 *      policyIdentifier   CertPolicyId,
 *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
 *
 * CertPolicyId ::= OBJECT IDENTIFIER
 */
int validate_applicationCertPolicies(unsigned char *input, int input_len)
{
    int tag, length, PolicyInformation_length;
    char *applicationCertPolicy;

    push_error_stack("szOID_APPLICATION_CERT_POLICIES");

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: szOID_APPLICATION_CERT_POLICIES is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of szOID_APPLICATION_CERT_POLICIES extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (input_len == 0) {
        print_error("Error: szOID_APPLICATION_CERT_POLICIES extension is an empty sequence.");
    }

    while (input_len > 0) {
        if ((tag = get_tag(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (tag != 0x30) {
            print_error("Error: PolicyInformation is not encoded as a SEQUENCE.");
            pop_error_stack();
            return(-1);
        }

        if ((PolicyInformation_length = get_length(&input, &input_len)) == -1) {
            pop_error_stack();
            return(-1);
        }
        input_len -= PolicyInformation_length;

        push_error_stack("PolicyInformation");

        if (get_OID(&input, &PolicyInformation_length, &applicationCertPolicy) == -1) {
            pop_error_stack();
            pop_error_stack();
            return(-1);
        }
        free(applicationCertPolicy);

        pop_error_stack();

        if (PolicyInformation_length > 0) {
            print_error("Error: In the szOID_APPLICATION_CERT_POLICIES extension, PolicyInformation must only contain a policyIdentifier.");
            pop_error_stack();
            return(-1);
        }
    }

    pop_error_stack();
    return(0);
}


/*
 * From http://msdn.microsoft.com/en-us/library/cc250012(PROT.13).aspx:
 *
 * The OID for a certificate template OID extension is: "1.3.6.1.4.1.311.21.7".
 * This extension value MUST be DER-encoded for the following ASN.1 structure.
 *
 * CertificateTemplateOID ::= SEQUENCE {
 *         templateID              OBJECT IDENTIFIER,
 *         templateMajorVersion    INTEGER (0..4294967295) OPTIONAL,
 *         templateMinorVersion    INTEGER (0..4294967295) OPTIONAL
 *    } --#public
 *
 * The critical field for this extension SHOULD be set to FALSE.
 *
 * The templateID MUST be the value of the msPKI-Template-Cert-Template-OID attribute
 * of a certificate template object, as specified in [MS-CRTD] section 2.20.
 *
 * The templateMajorVersion MUST be the value of the revision attribute of a certificate
 * template object, as specified in [MS-CRTD] section 2.6. The templateMinorVersion MUST
 * be the value of the msPKI-Template-Minor-Revision attribute of a certificate template
 * object, as specified in [MS-CRTD] section 2.17.
 */
int validate_CertificateTemplateOID(unsigned char *input, int input_len, int criticality)
{
    int tag, length;
    char *templateID;

    push_error_stack("CertificateTemplateOID");

    if (criticality) {
        print_error("Warning: The CertificateTemplateOID extension should be marked as non-critical");
    }

    if ((tag = get_tag(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (tag != 0x30) {
        print_error("Error: CertificateTemplateOID is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((length = get_length(&input, &input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (length != input_len) {
        print_error("Error: Encoding of CertificateTemplateOID extension contains extraneous data.");
        pop_error_stack();
        return(-1);
    }

    if (input_len == 0) {
        print_error("Error: CertificateTemplateOID extension is an empty sequence.");
    }

    push_error_stack("templateID");

    if (get_OID(&input, &input_len, &templateID) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    free(templateID);

    pop_error_stack();

    if (input_len == 0) {
        pop_error_stack();
        return(0);
    }

    push_error_stack("templateMajorVersion");
    if (validate_INTEGER(&input, &input_len, 1) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(0);
    }
    pop_error_stack();

    if (input_len == 0) {
        pop_error_stack();
        return(0);
    }

    push_error_stack("templateMinorVersion");
    if (validate_INTEGER(&input, &input_len, 1) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(0);
    }
    pop_error_stack();

    pop_error_stack();
    return(0);
}


/*
 *    Extension  ::=  SEQUENCE  {
 *       extnID      OBJECT IDENTIFIER,
 *       critical    BOOLEAN DEFAULT FALSE,
 *       extnValue   OCTET STRING
 *           -- contains the DER encoding of an ASN.1 value
 *           -- corresponding to the extension type identified
 *           -- by extnID
 *       }
 */
int validate_extension(unsigned char **input, int *input_len)
{
    static char *extnID[101];
    static int number_of_extensions = 0;
    int i, tag, extension_length, criticality, extnValue_length, unrecognized_extension_length;
    unsigned char *unrecognized_extension;
    char *oid;

    push_error_stack("Extension");
    if (number_of_extensions >= 100) {
        print_error("Error: This program cannot parse certificates that contain more than 100 extensions.");
        pop_error_stack();
        return(-1);
    }

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Error: Incorrect tag for Extension.");
        pop_error_stack();
        return(-1);
    }

    if ((extension_length = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    *input_len -= extension_length;

    /* get the extension's OID */
    push_error_stack("extnID");
    if (get_OID(input, &extension_length, &oid) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    extnID[number_of_extensions] = oid;

    /* Check that same extnID does not appear more than once in certificate. */
    for(i = 0; i < number_of_extensions; i++) {
        if (strcmp(oid, extnID[i]) == 0) {
            sprintf(error_str, "Error: Extension %s appears more than once in certificate.", oid);
            print_error(error_str);
            break;
        }
    }
    number_of_extensions++;

    pop_error_stack();

    criticality = 0;
    /* next byte may be the criticality indicator */
    if ((extension_length > 0) && (**input == 0x01)) {
        if (get_BOOLEAN(input, &extension_length, &criticality) == -1) {
            pop_error_stack();
            return(-1);
        }

        if (criticality == 0) {
            print_error("Error: Criticality not DER encoded.  DEFAULT value included in encoding.");
        }
    }

    push_error_stack("extnValue");
    if ((tag = get_tag(input, &extension_length)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x04) {
        print_error("Error: Incorrect tag for extnValue.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if ((extnValue_length = get_length(input, &extension_length)) == -1) {
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if (extnValue_length != extension_length) {
        print_error("Error: Incorrect length for extension or extnValue.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    if (extnValue_length == 0) {
        print_error("Error: extnValue is empty.");
        pop_error_stack();
        pop_error_stack();
        return(-1);
    }

    pop_error_stack();

    /* TODO: process extension value */
    if (strcmp(oid, "2.5.29.9") == 0) {
        validate_subjectDirectoryAttributes(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.14") == 0) {
        validate_subjectKeyIdentifier(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.15") == 0) {
        validate_keyUsage(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.16") == 0) {
        validate_privateKeyUsagePeriod(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.17") == 0) {
        validate_subjectAltName(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.18") == 0) {
        validate_issuerAltName(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.19") == 0) {
        validate_basicConstraints(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.30") == 0) {
        validate_nameConstraints(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.31") == 0) {
        validate_cRLDistributionPoints(*input, extnValue_length);
    } else if (strcmp(oid, "2.5.29.32") == 0) {
        validate_certificatePolicies(*input, extnValue_length);
    } else if (strcmp(oid, "2.5.29.33") == 0) {
        validate_policyMappings(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.35") == 0) {
        validate_authorityKeyIdentifier(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.36") == 0) {
        validate_policyConstraints(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.37") == 0) {
        validate_extKeyUsage(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.5.29.54") == 0) {
        validate_inhibitAnyPolicy(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "1.3.6.1.5.5.7.1.1") == 0) {
        push_error_stack("authorityInfoAccess");
        validate_InfoAccess(*input, extnValue_length, criticality, oid);
        pop_error_stack();
    } else if (strcmp(oid, "1.3.6.1.5.5.7.1.11") == 0) {
        push_error_stack("subjectInfoAccess");
        validate_InfoAccess(*input, extnValue_length, criticality, oid);
        pop_error_stack();
    } else if (strcmp(oid, "1.3.6.1.5.5.7.1.12") == 0) {
        validate_LogotypeExtn(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "1.3.6.1.5.5.7.48.1.5") == 0) {
        validate_OCSP_nocheck(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.16.840.1.101.3.6.9.1") == 0) {
        validate_NACI_indicator(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "1.2.840.113549.1.9.15") == 0) {
        validate_smimeCapabilities(*input, extnValue_length);
    } else if (strcmp(oid, "1.2.840.113533.7.65.0") == 0) {
        validate_entrustVersInfo(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.16.840.1.113730.1.1") == 0) {
        validate_netscape_cert_type(*input, extnValue_length);
    } else if (strcmp(oid, "2.16.840.1.113730.1.2") == 0) {
        validate_netscape_base_url(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.16.840.1.113730.1.3") == 0) {
        validate_NetscapeRevocationURL(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.16.840.1.113730.1.4") == 0) {
        validate_NetscapeCARevocationURL(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.16.840.1.113730.1.7") == 0) {
        validate_NetscapeCertRenewalURL(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.16.840.1.113730.1.8") == 0) {
        validate_NetscapeCAPolicyURL(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.16.840.1.113730.1.12") == 0) {
        validate_NetscapeSSLServerName(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "2.16.840.1.113730.1.13") == 0) {
        validate_NetscapeComment(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "1.3.6.1.4.1.311.20.2") == 0) {
        validate_enrollCerttypeExtension(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "1.3.6.1.4.1.311.21.2") == 0) {
        validate_certSrvPreviousCertHash(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "1.3.6.1.4.1.311.21.7") == 0) {
        validate_CertificateTemplateOID(*input, extnValue_length, criticality);
    } else if (strcmp(oid, "1.3.6.1.4.1.311.21.10") == 0) {
        validate_applicationCertPolicies(*input, extnValue_length);
    } else {
        sprintf(error_str, "Unrecognized %s extension - %s", criticality ? "critical" : "non-critical", oid);
        push_error_stack(error_str);
        unrecognized_extension = *input;
        unrecognized_extension_length = extnValue_length;
        if (validate_generic_DER(&unrecognized_extension, &unrecognized_extension_length) == -1) {
            pop_error_stack();
        } else if (unrecognized_extension_length > 0) {
            print_error("Error: extnValue contains extraneous data.");
            pop_error_stack();
        } else {
            pop_error_stack();
            sprintf(error_str, "Warning:  Unrecognized %s extension: %s.  Contents not parsed.", criticality ? "critical" : "non-critical", oid);
            print_error(error_str);
        }
    }

    *input += extnValue_length;

    pop_error_stack();
    return(0);
}

/*
 *    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 */
int validate_extensions(unsigned char **input, int *input_len)
{
    int tag, extensions_length, i, j;

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Error: Incorrect tag for Extensions.");
        return(-1);
    }

    if ((extensions_length = get_length(input, input_len)) == -1) {
        return(-1);
    }
    *input_len -= extensions_length;

    /* Process extensions one at a time */
    while (extensions_length > 0) {
        if (validate_extension(input, &extensions_length) == -1) {
            return(-1);
        }
    }

    /* Conforming CAs MUST include this extension in all CA certificates
     * that contain public keys used to validate digital signatures on
     * certificates and MUST mark the extension as critical in such certificates.
     */
    if (!BasicConstraints_cA && isKeyUsagePresent && keyUsage_value.keyCertSign) {
        print_error("Error: keyUsage extension asserts keyCertSign but BasicConstraints is not present with cA set to TRUE.");
    }

    if (isKeyUsagePresent && keyUsage_value.keyCertSign && BasicConstraints_cA && !BasicConstraints_criticality) {
        print_error("Warning: subject public key may be used to verify signatures on certificates but BasicConstraints extension is not marked as critical.");
    }

    if (ispolicyMappingsPresent && !iscertificatePoliciesPresent) {
        print_error("Warning: the policyMappings extension is present but the certificatePolicies extension is not.");
    }

    if (ispolicyMappingsPresent && iscertificatePoliciesPresent) {
        /* For each policy OID that appeared in an issuerDomainPolicy in policyMappings, check that the OID was
         * also asserted in the certificatePolicies extension
         */
        i = 0;
        while(issuerDomainPolicies[i] != NULL) {
            j = 0;
            while ((certificatePolicies[j] != NULL) && (strcmp(issuerDomainPolicies[i], certificatePolicies[j]) != 0)) {
                j++;
            }
            if (certificatePolicies[j] == NULL) {
                sprintf(error_str, "Warning: %s appears in the issuerDomainPolicy field of policyMappings but was not asserted in the certificatePolicies extension", issuerDomainPolicies[i]);
                print_error(error_str);
            }
            i++;
        }
    }

    if (iscertificatePoliciesPresent) {
        for(i=0; i < 100; i++) {
            if (certificatePolicies[i] != NULL)
                free(certificatePolicies[i]);
        }
    }

    if (ispolicyMappingsPresent) {
        for(i=0; i < 100; i++) {
            if (issuerDomainPolicies[i] != NULL)
                free(issuerDomainPolicies[i]);
        }
    }

    if (is_subject_empty && !issubjectAltNamePresent) {
        print_error("Error: subject field is an empty SEQUENCE and the subjectAltName extension is not present.");
    }

    return(0);
}


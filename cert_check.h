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

/* subject public key types */
#define SPK_UNKNOWN	0
#define	SPK_RSA		1
#define	SPK_ECC		2
#define	SPK_ECDH	3
#define	SPK_ECMQV	4
#define SPK_DSA		5
#define SPK_X25519  6
#define SPK_X448    7
#define SPK_ED25519 8
#define SPK_ED448   9

extern int subjectPublicKeyType;

extern int is_subject_empty;

extern void push_error_stack(char *err_string);

extern void pop_error_stack();
extern void print_error(char *err_string);
extern int print_error_was_called();

extern int get_tag(unsigned char **input, int *input_len);
extern int get_length(unsigned char **input, int *input_len);
extern int get_OID(unsigned char **input, int *input_len, char **oid);
extern int validate_BITSTRING(int length, unsigned char *bitstring, int isnamed);
extern int validate_INTEGER(unsigned char **input, int *input_len, int positive);
extern int get_BOOLEAN(unsigned char **input, int *input_len, int *boolean);
extern int validate_UTCTime(unsigned char **input, int *input_len);
extern int validate_GeneralizedTime(unsigned char **input, int *input_len);
extern int validate_generic_DER(unsigned char **input, int *input_len);
extern int validate_BMPString(unsigned char *DirectoryString, int DirectoryString_len, int max_len);
extern int validate_DisplayText(unsigned char **DisplayText, int *DisplayText_len);
extern int validate_rfc822Name(unsigned char *rfc822Name, int rfc822Name_length);
extern int validate_IA5String(unsigned char *DirectoryString, int DirectoryString_len, int max_len);
extern int validate_DirectoryString(int tag, unsigned char *DirectoryString, int DirectoryString_len, int max_len);
extern int validate_dNSName(unsigned char *input, int input_len);
extern int validate_URI(unsigned char *URI, int URI_length);
extern int validate_directoryName(unsigned char **input, int *input_len, int *is_empty);
extern int validate_RelativeDistinguishedName(unsigned char **input, int *input_len);
extern int validate_OtherName(unsigned char **input, int *input_len);
extern int validate_GeneralName(unsigned char **input, int *input_len);
extern int validate_GeneralNames(unsigned char **input, int *input_len);

extern int validate_extensions(unsigned char **input, int *input_len);

extern int decode_PEM_certificate(unsigned char *input, int input_len, unsigned char *output, int *output_len);
extern int decode_PEM_certreq(unsigned char *input, int input_len, unsigned char *output, int *output_len);

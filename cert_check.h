/* This software was developed at the National Institute of
 * Standards and Technology by employees of the Federal
 * Government in the course of their official duties.
 * Pursuant to title 17 Section 105 of the United States Code
 * this software is not subject to copyright protection and
 * is in the public domain. We would appreciate acknowledgement
 * if the software is used.
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

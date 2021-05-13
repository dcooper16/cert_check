/* This software was developed at the National Institute of
 * Standards and Technology by employees of the Federal
 * Government in the course of their official duties.
 * Pursuant to title 17 Section 105 of the United States Code
 * this software is not subject to copyright protection and
 * is in the public domain. We would appreciate acknowledgement
 * if the software is used.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cert_check.h"

static char error_str[1000];

/* Set output to the value of the next byte in the Base 64 encoding.
 * Return 2 if output contains the next byte.
 * Return 1 if the next byte was '='.
 * Return 0 if end of string was reached.
 * Return -1 if an error was encountered.
 *
 * Set *input to point to the byte immediately following the one containing
 * the value being returned.  Set *input_len to remaining length of string.
 */
static int getnextbyte(unsigned char **input, int *input_len, unsigned char *output)
{
    int result;

    while ((*input_len > 0) && ((**input == '\n') || (**input == '\r'))) {
        *input += 1;
        *input_len -= 1;
    }
    if (*input_len == 0) {
        return(0);
    }

    if ((**input >= 'A') && (**input <= 'Z')) {
        *output = **input - 'A';
        result = 2;
    } else if ((**input >= 'a') && (**input <= 'z')) {
        *output = **input + 26 - 'a';
        result = 2;
    } else if ((**input >= '0') && (**input <= '9')) {
        *output = **input + 52 - '0';
        result = 2;
    } else if (**input == '+') {
        *output = 62;
        result = 2;
    } else if (**input == '/') {
        *output = 63;
        result = 2;
    } else if (**input == '=') {
        if ((*input_len == 1) || ((*input_len == 2) && (*(*input + 1) == '='))) {
            result = 1;
        } else {
            print_error("Error: \'=\' charater encountered before end of base 64 encoded string.");
            return(-1);
        }
    } else {
        if ((**input >= 0x20) && (**input <= 0x7E)) {
            sprintf(error_str, "Error: Base 64 encoded data contains an illegal character: '%c'.", **input);
        } else {
            sprintf(error_str, "Error: Base 64 encoded data contains an illegal character: '%d'.", **input);
        }
        print_error(error_str);
        return(-1);
    }
    *input += 1;
    *input_len -= 1;

    return(result);
}

/* Return the next three bytes from the encoded string in *byte1, *byte2, and *byte3
 * (possibly fewer if at the end of the string).  Set *bytes_returned to the actual
 * number of bytes returned.  Return -1 if an error occurred and 0 otherwise.
 */
static int getnextthreebytes(unsigned char **input, int *input_len, int *bytes_returned,
                        unsigned char *byte1, unsigned char *byte2, unsigned char *byte3)
{
    unsigned char char1, char2, char3, char4;
    int result;
    int characters_returned = 0;

    if ((result = getnextbyte(input, input_len, &char1)) == -1) {
        return(-1);
    }
    if (result == 0) {
        *bytes_returned = 0;
        return(0);
    } else if (result == 1) {
        print_error("Error: Unexpected \'=\' character at end of base 64 encoded string.");
        return(-1);
    }
    characters_returned++;

    if ((result = getnextbyte(input, input_len, &char2)) == -1) {
        return(-1);
    }
    if (result == 0) {
        print_error("Error: Unexpected end of string in base 64 encoded string.");
        return(-1);
    } else if (result == 1) {
        print_error("Error: Unexpected \'=\' character at end of base 64 encoded string.");
        return(-1);
    }
    characters_returned++;

    if ((result = getnextbyte(input, input_len, &char3)) == -1) {
        return(-1);
    }
    if (result == 0) {
        print_error("Error: Unexpected end of string in base 64 encoded string.");
        return(-1);
    } else if (result == 1) {
        /* getnextbyte() has already verified that next character in string is an '='
         * and that it is the final character in the string. */
        *input += 1;
        *input_len -= 1;
    } else {
        characters_returned++;

        if ((result = getnextbyte(input, input_len, &char4)) == -1) {
            return(-1);
        }
        if (result == 0) {
            print_error("Error: Unexpected end of string in base 64 encoded string.");
            return(-1);
        } else if (result == 2) {
            characters_returned++;
        }
    }

    switch(characters_returned) {
        case 2:
            if (char2 & 0x0F) {
                /* final character should only contain 2 bits of data */
                print_error("Error: Invalid final non-padding character in base 64 encoded string.");
                return(-1);
            }
            *byte1 = (char1 << 2) + (char2 >> 4);
            *bytes_returned = 1;
            break;
        case 3:
            if (char3 & 0x03) {
                /* final character should only contain 4 bits of data */
                print_error("Error: Invalid final non-padding character in base 64 encoded string.");
                return(-1);
            }
            *byte1 = (char1 << 2) + (char2 >> 4);
            *byte2 = ((char2 & 0x0F) << 4) + (char3 >> 2);
            *bytes_returned = 2;
            break;
        case 4:
            *byte1 = (char1 << 2) + (char2 >> 4);
            *byte2 = ((char2 & 0x0F) << 4) + (char3 >> 2);
            *byte3 = ((char3 & 0x03) << 6) + char4;
            *bytes_returned = 3;
            break;
    }

    return(0);
}

/* Base 64 decide input, which is of length input_len, and place result in the pre-allocated
 * buffer output.  Set *ouput_len to the length of the output. Return -1 if an error occurred
 * and 0 otherwise.
 */
static int base64_decode(unsigned char *input, int input_len, unsigned char *output, int *output_len)
{
    unsigned char byte1, byte2, byte3;
    int bytes_returned;

    *output_len = 0;

    while (input_len > 0) {
        if (getnextthreebytes(&input, &input_len, &bytes_returned, &byte1, &byte2, &byte3) == -1) {
            return(-1);
        }
        if (bytes_returned >= 1) {
            *output = byte1;
            output++;
            *output_len += 1;
        }
        if (bytes_returned >= 2) {
            *output = byte2;
            output++;
            *output_len += 1;
        }
        if (bytes_returned >= 3) {
            *output = byte3;
            output++;
            *output_len += 1;
        }
    }
    return(0);
}

int decode_PEM_certificate(unsigned char *input, int input_len, unsigned char *output, int *output_len)
{
    unsigned char *end;

    if (strncmp((char *)input, "-----BEGIN CERTIFICATE-----", 27) != 0) {
        print_error("Error: Input string is not a PEM encoded certificate.");
        return(-1);
    }

    /* set input to beginning of base 64 encoding */
    input += 27;
    input_len -= 27;

    while ((input_len > 0) && ((*input == '\n') || (*input == '\r'))) {
        input++;
        input_len--;
    }

    if (input_len == 0) {
        print_error("Error: Input string is not a PEM encoded certificate.");
        return(-1);
    }

    /* find end of base 64 encoding */
    end = (unsigned char *)strstr((char *)input, "-----END CERTIFICATE-----");
    end--;
    while ((*end == '\n') || (*end == '\r')) {
        end--;
    }
    if (end <= input) {
        print_error("Error: Input string is not a PEM encoded certificate.");
        return(-1);
    }
    input_len = end - input + 1;

    if (base64_decode(input, input_len, output, output_len) == -1) {
        return(-1);
    }
    return(0);
}

int decode_PEM_certreq(unsigned char *input, int input_len, unsigned char *output, int *output_len)
{
    unsigned char *end;

    if (strncmp((char *)input, "-----BEGIN CERTIFICATE REQUEST-----", 35) != 0) {
        print_error("Error: Input string is not a PEM encoded certificate request.");
        return(-1);
    }

    /* set input to beginning of base 64 encoding */
    input += 35;
    input_len -= 35;

    while ((input_len > 0) && ((*input == '\n') || (*input == '\r'))) {
        input++;
        input_len--;
    }

    if (input_len == 0) {
        print_error("Error: Input string is not a PEM encoded certificate request.");
        return(-1);
    }

    /* find end of base 64 encoding */
    end = (unsigned char *)strstr((char *)input, "-----END CERTIFICATE REQUEST-----");
    end--;
    while ((*end == '\n') || (*end == '\r')) {
        end--;
    }
    if (end <= input) {
        print_error("Error: Input string is not a PEM encoded certificate request.");
        return(-1);
    }
    input_len = end - input + 1;

    if (base64_decode(input, input_len, output, output_len) == -1) {
        return(-1);
    }
    return(0);
}

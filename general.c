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

#define	MAX_STACK_DEPTH		100
#define MAX_LABEL_LENGTH	100

static int print_error_called = 0;
static int stack_depth = 0;
static char error_stack[MAX_STACK_DEPTH][MAX_LABEL_LENGTH+1];

/* Add string to stack if stack is not full */
void push_error_stack(char *err_string)
{
    if (stack_depth + 1 < MAX_STACK_DEPTH) {
        strncpy(error_stack[stack_depth], err_string, MAX_LABEL_LENGTH);
        error_stack[stack_depth++][MAX_LABEL_LENGTH] = '\0';
    }
}

/* Remove string from top of stack if stack is not empty. */
void pop_error_stack()
{
    if (stack_depth > 0)
        stack_depth--;
}

/* print contents of stack followed by err_string */
void print_error(char *err_string)
{
    int i;

    print_error_called = 1;

    for (i=0; i < stack_depth; i++) {
        printf("%s:\n", error_stack[i]);
    }
    printf("%s\n\n", err_string);
}

int print_error_was_called()
{
    return(print_error_called);
}


/* The string pointed to by *input begins with a DER encoded tag-length-value.
 * Return the value of the tag and set *input to point to the next octet, which
 * should be the encoding of the length. The number of bytes used to encode
 * the tag is subtracted from *input_len. Return -1 if there is an error.
 *
 * Note: This function currently assumes that all tags are encoded as a single
 * octet.
 */
int get_tag(unsigned char **input, int *input_len)
{
    int tag;

    if (*input_len < 1) {
        print_error("Error: There is nothing to parse.");
        return(-1);
    }

    if ((**input & 0x1F) == 0x1F) {
        print_error("Error: This program cannot handle tags that require more than one octet to encode.");
        return(-1);
    }

    tag = **input;
    *input += 1;
    *input_len -= 1;
    return(tag);
}

/* The string pointed to by *input begins with a DER encoded length. Return
 * length and set *input to point to the first character after the length.
 * Return -1 if there is an encoding error.
 */
int get_length(unsigned char **input, int *input_len)
{
    int length, length_bytes;

    if (*input_len < 1)
        return(-1);

    if ((**input & 0x80) == 0) {
        /* This is the short encoding of length */
        length = **input;
    	*input += 1;

        /* check that remaining length is sufficient */
        if (*input_len < length + 1) {
            print_error("Encoded length is longer than actual length.");
            return(-1);
        } else {
            *input_len -= 1;
            return(length);
        }
    }

    /* next byte should indicate number of bytes in encoding of length */
    length_bytes = **input & 0x7F;
    *input += 1;

    if (*input_len < length_bytes + 1) {
        print_error("Input string not long enough to hold encoding of length.");
        return(-1);
    }

    if (length_bytes > 3) {
        print_error("This program cannot process length encodings that require more than 3 bytes.");
        return(-1);
    }

    switch (length_bytes) {
        case 0:
            printf("Indefinite length encoding not permitted in DER.");
            return(-1);
            break;

        case 1:
            length = **input;
            *input += 1;
            if (length < 128) {
                print_error("Length is not DER encoded.");
                return(-1);
            }
            if (*input_len < length + 2) {
                print_error("Encoded length is longer than actual length.");
                return(-1);
            }
            *input_len -= 2;
            break;

        case 2:
            length = **input;
            *input += 1;
            length = 256 * length + **input;
            *input += 1;
            if (length < 256) {
                print_error("Length is not DER encoded.");
                return(-1);
            }
            if (*input_len < length + 3) {
                print_error("Encoded length is longer than actual length.");
                return(-1);
            }
            *input_len -= 3;
            break;

        case 3:
            length = **input;
            *input += 1;
            length = 256 * length + **input;
            *input += 1;
            length = 256 * length + **input;
            *input += 1;
            if (length < 65536) {
                print_error("Length is not DER encoded.");
                return(-1);
            }
            if (*input_len < length + 4) {
                print_error("Encoded length is longer than actual length.");
                return(-1);
            }
            *input_len -= 4;
            break;

        default: print_error("Unknown error."); return(-1); break;
    }

    return(length);
}

/* If the string pointed to by *input contains a DER encoded OID,
 * copy the OID into oid and place the length of the encoded OID in
 * oid_len.  Return -1 if there is an error and 0 otherwise.
 */
int get_OID(unsigned char **input, int *input_len, char **oid)
{
    int tag, DER_oid_len, component_count, component_value1, component_value, component_octets, OID_string_len;
    unsigned char *DER_OID;
    char OID_string[1000], temp[1050];

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }
    if (tag != 0x06) {
        print_error("Error: Expecting tag for OID (06).");
        return(-1);
    }

    if ((DER_oid_len = get_length(input, input_len)) == -1) {
        return(-1);
    }

    DER_OID = *input;

    component_value = 0;
    component_octets = 0;
    while ((DER_OID < *input + DER_oid_len - 1) && (component_octets < 4) && ((*DER_OID & 0x80) == 0x80)) {
        component_value = (component_value << 7) + (*DER_OID & 0x7F);
        component_octets++;
        DER_OID++;
    }
    if ((*DER_OID & 0x80) == 0x80) {
        if (DER_OID == *input + DER_oid_len - 1) {
            print_error("Error: Invalid Object Identifier.");
            return(-1);
        } else {
            print_error("Error: Encoding of first two components of Object Identifier requires more than four octets.");
            return(-1);
        }
    }
    component_value = (component_value << 7) + *DER_OID;
    DER_OID++;

    component_value1 = component_value/40;
    component_value -= 40 * component_value1;
    component_count = 2;
    sprintf(OID_string, "%d.%d", component_value1, component_value);

    while (DER_OID < *input + DER_oid_len) {
        if (component_count > 80) {
            print_error("Error: Object Identifier contains more than 80 components.");
            return(-1);
        }
        component_value = 0;
        component_octets = 0;
        while ((DER_OID < *input + DER_oid_len - 1) && (component_octets < 4) && ((*DER_OID & 0x80) == 0x80)) {
            component_value = (component_value << 7) + (*DER_OID & 0x7F);
            component_octets++;
            DER_OID++;
        }
        if ((*DER_OID & 0x80) == 0x80) {
            if (DER_OID == *input + DER_oid_len - 1) {
                print_error("Error: Invalid Object Identifier.");
                return(-1);
            } else {
                print_error("Error: Encoding of a component of Object Identifier requires more than four octets.");
                return(-1);
            }
        }
        component_value = (component_value << 7) + *DER_OID;
        DER_OID++;

        sprintf(temp, "%s.%d", OID_string, component_value);
        strcpy(OID_string, temp);

        component_count++;
    }

    OID_string_len = strlen(OID_string);
    if (OID_string_len > 100) {
        print_error("Warning: The PKIX Certificate and CRL recommends against use of OIDs with a dotted decimal string representation longer than 100 bytes.");
    }
    if (component_count > 20) {
        print_error("Warning: The PKIX Certificate and CRL recommends against use of OIDs that contain more than 20 components.");
    }

    *oid = (char *)malloc(OID_string_len+1);
    if (*oid == NULL)
        return(-1);

    strcpy(*oid, OID_string);
    *input += DER_oid_len;
    *input_len -= DER_oid_len;

    return(0);
}

/* bistring points to a BIT STRING of length 'length', where
 * the first octet of the bitstring is the number of unused
 * bits. Check that the number of unused bits is less than 8
 * and that all of the unused bits are set to 0. If isnamed
 * is not 0, then check that the final bit in the BIT STRING
 * is set to 1.
 */
int validate_BITSTRING(int length, unsigned char *bitstring, int isnamed)
{
    unsigned int num_unused;
    unsigned char last_octet, mask;

    if (length == 0) {
        print_error("Error: BIT STRING is missing number of unused bits.");
        return(-1);
    }

    num_unused = *bitstring;
    if ((length == 1) && (num_unused != 0)) {
        print_error("Error: BIT STRING of length zero must specify zero unused bits.");
        return(-1);
    }

    if (num_unused > 7) {
        print_error("BIT STRING contains illegal value for number of unused bits.");
        return(-1);
    }

    last_octet = *(bitstring + length - 1);

    /* check that unused bits are all set to 0 */
    switch(num_unused) {
        case 0: mask = 0x00; break;
        case 1: mask = 0x01; break;
        case 2: mask = 0x03; break;
        case 3: mask = 0x07; break;
        case 4: mask = 0x0F; break;
        case 5: mask = 0x1F; break;
        case 6: mask = 0x3F; break;
        case 7: mask = 0x7F; break;
    }

    if ((last_octet & mask) != 0) {
        print_error("Error: BIT STRING contains unused bit set to 1.");
    }

    if (isnamed == 0) {
        return(0);
    }

    /* This is a named bit list.  Check that final bit in BIT STRING is set to 1. */
    switch(num_unused) {
        case 0: mask = 0x01; break;
        case 1: mask = 0x02; break;
        case 2: mask = 0x04; break;
        case 3: mask = 0x08; break;
        case 4: mask = 0x10; break;
        case 5: mask = 0x20; break;
        case 6: mask = 0x40; break;
        case 7: mask = 0x80; break;
    }

    if ((last_octet & mask) == 0) {
        print_error("Error: named bit list is not DER encoded.  Contains trailing zeros");
        return(-1);
    }

    return(0);
}

int validate_INTEGER(unsigned char **input, int *input_len, int positive)
{
    int tag, length;

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }

    if (tag != 0x02) {
        print_error("Error: Expecting tag for an INTEGER.");
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        return(-1);
    }

    if (length == 0) {
        print_error("Error: Encoding of INTEGER has a length of 0.");
        return(-1);
    }

    if (positive && ((**input & 0x80) != 0)) {
        print_error("Warning: INTEGER is a negative number.");
    }

    if ((length > 1) && (**input == 0) && (*(*input + 1) == 0)) {
        print_error("Error: INTEGER is not DER encoded.");
    }

    *input += length;
    *input_len -= length;

    return(0);
}

int get_BOOLEAN(unsigned char **input, int *input_len, int *boolean)
{
    int tag, length;

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }

    if (tag != 0x01) {
        print_error("Error: Expecting tag for a BOOLEAN.");
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        return(-1);
    }

    if (length != 1) {
        print_error("Error: Length of BOOLEAN is not one octet.");
        return(-1);
    }

    if (**input == 0) {
        *boolean = 0;
    } else {
        *boolean = 1;
        if (**input != 0xFF) {
            print_error("Error: BOOLEAN value TRUE is not encoded as 0xFF.");
        }
    }

    *input += 1;
    *input_len -= 1;

    return(0);
}

/* Return the final day of the month for the specified month and year */
int max_day(int month, int year)
{

    switch(month) {
        case 1:
        case 3:
        case 5:
        case 7:
        case 8:
        case 10:
        case 12:
            return(31);
            break;

        case 4:
        case 6:
        case 9:
        case 11:
            return(30);
            break;

        case 2:
            if ((year & 0x03) != 0) {
                /* year is not a multiple of 4 */
                return(28);
            }
            if ((year % 100) != 0) {
                /* year is a multiple of 4, but not 100 */
                return(29);
            }
            if ((year % 100) != 0) {
                /* year is a multiple of 400 */
                return(29);
            }
            /* year is a multple of 100, but not 400 */
            return(28);
            break;
    }
    return(0);
}


int validate_UTCTime(unsigned char **input, int *input_len)
{
    int length, year, month, day, hour, minute, second;
    unsigned char *i;
    char s[50];

    if ((length = get_length(input, input_len)) == -1) {
        return(-1);
    }

    if (length != 13) {
        print_error("Invalid length for UTCTime.");
        return(-1);
    }

    /* Time must be of the form: YYMMDDHHMMSSZ */

    /* First check that each of the first 12 bytes represents a digit */
    for (i=*input; i < (*input) + 12; i++) {
        if ((*i < '0') || (*i > '9')) {
            print_error("Error: Invalid character in UTCTime.");
            return(-1);
        }
    }
    if (*((*input) + 12) != 'Z') {
        print_error("Error: UTCTime does not end with 'Z'.");
        return(-1);
    }

    year = 10 * (**input - '0') + (*(*input + 1) - '0');
    month = 10 * (*(*input + 2) - '0') + (*(*input + 3) - '0');
    day = 10 * (*(*input + 4) - '0') + (*(*input + 5) - '0');
    hour = 10 * (*(*input + 6) - '0') + (*(*input + 7) - '0');
    minute = 10 * (*(*input + 8) - '0') + (*(*input + 9) - '0');
    second = 10 * (*(*input + 10) - '0') + (*(*input + 11) - '0');

    if (year >= 50) {
        year = 1900 + year;
        sprintf(s, "Warning: Time specified is in year %d\n", year);
        print_error(s);
    } else {
        year = 2000 + year;
    }

    if ((month == 0) || (month > 12)) {
        print_error("Error: Invalid month.");
        return(-1);
    }

    if ((day == 0) || (day > max_day(month, year))) {
        print_error("Error: Invalid day.");
        return(-1);
    }
    if (hour > 23) {
        print_error("Error: Invalid hour.");
        return(-1);
    }
    if (minute > 59) {
        print_error("Error: Invalid minute.");
        return(-1);
    }
    if (second > 59) {
        print_error("Error: Invalid second.");
        return(-1);
    }

    *input += length;
    *input_len -= length;

    return(0);
}

int validate_GeneralizedTime(unsigned char **input, int *input_len)
{
    int length, year, month, day, hour, minute, second;
    unsigned char *i;
    char s[50];

    if ((length = get_length(input, input_len)) == -1) {
        return(-1);
    }

    if (length != 15) {
        print_error("Invalid length for GeneralizedTime.");
    }

    /* Time must be of the form: YYYYMMDDHHMMSSZ */

    /* First check that each of the first 14 bytes represents a digit */
    for (i=*input; i < (*input) + 14; i++) {
        if ((*i < '0') || (*i > '9')) {
            print_error("Error: Invalid character in UTCTime.");
            return(-1);
        }
    }
    if (*((*input) + 14) != 'Z') {
        print_error("Error: UTCTime does not end with 'Z'.");
        return(-1);
    }

    year = 1000 * (**input - '0') + 100 * (*(*input + 1) - '0') + 10 * (*(*input + 2) - '0') + (*(*input + 3) - '0');
    month = 10 * (*(*input + 4) - '0') + (*(*input + 5) - '0');
    day = 10 * (*(*input + 6) - '0') + (*(*input + 7) - '0');
    hour = 10 * (*(*input + 8) - '0') + (*(*input + 9) - '0');
    minute = 10 * (*(*input + 10) - '0') + (*(*input + 11) - '0');
    second = 10 * (*(*input + 12) - '0') + (*(*input + 13) - '0');

    if ((month == 0) || (month > 12)) {
        print_error("Error: Invalid month.");
        return(-1);
    }

    if (year < 1990) {
        sprintf(s, "Warning: Time specified is in year %d\n", year);
        print_error(s);
    }
    if ((day == 0) || (day > max_day(month, year))) {
        print_error("Error: Invalid day.");
        return(-1);
    }
    if (hour > 23) {
        print_error("Error: Invalid hour.");
        return(-1);
    }
    if (minute > 59) {
        print_error("Error: Invalid minute.");
        return(-1);
    }
    if (second > 59) {
        print_error("Error: Invalid second.");
        return(-1);
    }

    *input += length;
    *input_len -= length;

    return(0);
}

/* Perform a basic sanity check on DER encoded data. */
int validate_generic_DER(unsigned char **input, int *input_len)
{
    int tag, length;
    unsigned char *constructed_data;

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }

    if ((length = get_length(input, input_len)) == -1) {
        return(-1);
    }

    /* Assuming that any that requires more than one octet to encode
     * to be represented by a value >= 256, but unsure how such
     * values will be encoded, so treated all such values as primitive for now.
     */
    if ((tag > 256) || ((tag & 0x20) == 0)) {
        /* Primitive encoding */
        *input += length;
        *input_len -= length;
    } else {
        /* Constructed encoding */
        constructed_data = *input;
        *input += length;
        *input_len -= length;

        while (length > 0) {
            if (validate_generic_DER(&constructed_data, &length) == -1) {
                return(-1);
            }
        }
    }

    return(0);
}


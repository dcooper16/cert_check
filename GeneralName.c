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
#include <strings.h>
#include <stdlib.h>
#include "cert_check.h"

static char error_str[1000];

int is_letter(unsigned char c)
{
    return(((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')));
}

int is_letter_or_digit(unsigned char c)
{
    return(is_letter(c) || ((c >= '0') && (c <= '9')));
}

int is_hexdigit(unsigned char c)
{
    return(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F')));
}


int validate_IA5String(unsigned char *DirectoryString, int DirectoryString_len, int max_len)
{
    unsigned char *i;

    if (DirectoryString_len > max_len) {
        print_error("Warning: IA5String is too long.");
    }

    for(i=DirectoryString; i < DirectoryString + DirectoryString_len; i++) {
        if (*i > 0x7F) {
            sprintf(error_str, "Error: IA5String contains invalid character: %d.", *i);
            print_error(error_str);
        } else if ((*i < 0x20) || (*i == 0x7F)) {
            sprintf(error_str, "Warning: IA5String contains a control character: %d.", *i);
            print_error(error_str);
        }
    }

    return(0);
}


int validate_domainlabel(unsigned char *domain_label, int domain_label_length)
{
    unsigned char *i;

    if (domain_label_length == 0) {
        print_error("Error: domain label contains an empty string.");
    }
    if (domain_label_length > 63) {
        print_error("Warning: domain label is longer than 63 octets.");
    }

    /* first character of a domain label must be a letter or digit */
    if (!is_letter_or_digit(*domain_label)) {
        if ((*domain_label >= 0x20) && (*domain_label <= 0x7E)) {
            sprintf(error_str, "Error: First character of domain label is not a valid character: '%c'.", *domain_label);
        } else {
            sprintf(error_str, "Error: First character of domain label is not a valid character: %d.", *domain_label);
        }
        print_error(error_str);
    }

    if (domain_label_length > 1) {
        /* final character of a domain label must be a letter or digit */
        i = domain_label + domain_label_length - 1;
        if (!is_letter_or_digit(*i)) {
            if ((*i >= 0x20) && (*i <= 0x7E)) {
                sprintf(error_str, "Error: Final character of domain label is not a valid character: '%c'.", *i);
            } else {
                sprintf(error_str, "Error: Final character of domain label is not a valid character: %d.", *i);
            }
            print_error(error_str);
        }
    }

    /* All other characters in a domain label are limited to letters, digits, and the hyphen character */
    for(i=domain_label + 1; i < domain_label + domain_label_length - 1; i++) {
        if (!is_letter_or_digit(*i) && (*i != '-')) {
            if ((*i >= 0x20) && (*i <= 0x7E)) {
                sprintf(error_str, "Error: domain label contains an invalid character: '%c'.", *i);
            } else {
                sprintf(error_str, "Error: domain label contains an invalid character: %d.", *i);
            }
            print_error(error_str);
        }
    }

    return(0);
}


int validate_domainComponent(int tag, unsigned char *domain_label, int domain_label_length)
{
    if (tag != 22) {
        print_error("Error: Incorrect tag. domainComponent must be encoded as IA5String.");
    }

    return(validate_domainlabel(domain_label, domain_label_length));
}

/* atext           =   ALPHA / DIGIT /    ; Printable US-ASCII
 *                     "!" / "#" /        ;  characters not including
 *                     "$" / "%" /        ;  specials.  Used for atoms.
 *                     "&" / "'" /
 *                     "*" / "+" /
 *                     "-" / "/" /
 *                     "=" / "?" /
 *                     "^" / "_" /
 *                     "`" / "{" /
 *                     "|" / "}" /
 *                     "~"
 */
static int is_atext(unsigned char c)
{
    return(is_letter_or_digit(c) || (c == '!') || (c == '#') || (c == '$') || (c == '%') ||
            (c == '&') || (c == '\'') || (c == '*') || (c == '+') || (c == '-') || (c == '/') ||
            (c == '=') || (c == '?') || (c == '^') || (c == '_') || (c == '`') || (c == '{') ||
            (c == '|') || (c == '}') || (c == '~'));
}

/*
 * Local-part "@" ( Domain / address-literal )
 */
int validate_rfc822Name(unsigned char *rfc822Name, int rfc822Name_length)
{
    unsigned char *i;
    int domain_length;

    /* rfc822Name must begin with a Local-part:
     * Local-part     = Dot-string / Quoted-string
     */
    i = rfc822Name;

    if (*i != '\"') {
        /* Local-part = Dot-string = Atom *("."  Atom)
         * Atom       = 1*atext */
        while ((i < rfc822Name + rfc822Name_length) && (*i != '@')) {
            while ((i < rfc822Name + rfc822Name_length) && (*i != '@') && (*i != '.')) {
                if (!is_atext(*i)) {
                    if ((*i >= 0x20) && (*i <= 0x7E)) {
                        sprintf(error_str, "Error: Local-part of rfc822Name contains an invalid character: '%c'.", *i);
                    } else {
                        sprintf(error_str, "Error: Local-part of rfc822Name contains an invalid character: %d.", *i);
                    }
                    print_error(error_str);
                }
                i++;
            }
            if ((i < rfc822Name + rfc822Name_length) && (*i == '.')) {
                /* A "." must be followed by another atom */
                i++;
                if (i == rfc822Name + rfc822Name_length) {
                    print_error("Error: rfc822Name does not contain an \"@\" or a domain portion.");
                    return(-1);
                } else if (*i == '@') {
                    print_error("Error: Local-part of rfc822Name cannot end with a '.'.");
                } else if (*i == '.') {
                    print_error("Error: Local-part of rfc822Name cannot contain two consequtive '.' characters.");
                }
            }
        }

        if (i == rfc822Name + rfc822Name_length) {
            print_error("Error: rfc822Name does not contain an \"@\" or a domain portion.");
            return(-1);
        }
    } else {
        /* Local-part = Quoted-string = DQUOTE *QcontentSMTP DQUOTE
         * QcontentSMTP   = qtextSMTP / quoted-pairSMTP
         * quoted-pairSMTP  = %d92 %d32-126
         * qtextSMTP      = %d32-33 / %d35-91 / %d93-126
         */
        i++;
        while ((i < rfc822Name + rfc822Name_length) && (*i != '\"')) {
            if (*i == 92) {
                i++;
                if (i == rfc822Name + rfc822Name_length) {
                    print_error("Error: rfc822Name ends in quoted part of Local-part with an escape character.");
                    return(-1);
                } else if ((*i < 32) || (*i > 126)) {
                    sprintf(error_str, "Error: Local-part contains an illegal escaped character: %d.", *i);
                    print_error(error_str);
                }
            } else if ((*i < 32) || (*i > 126)) {
                    sprintf(error_str, "Error: Local-part contains an illegal character: %d.", *i);
                    print_error(error_str);
            }
            i++;
        }

        if (i == rfc822Name + rfc822Name_length) {
            print_error("Error: rfc822Name does not contain an \"@\" or a domain portion.");
            return(-1);
        } else if (*i != '@') {
            print_error("Error: Local-part of rfc822Name, encoded as a Quoted-string, is not followed by '@'.");
            return(-1);
        }
    }

    if (i - rfc822Name > 64) {
        print_error("Error: Local-part of rfc822Name is longer than 64 octets.");
    }

    i++;

    if (i == rfc822Name + rfc822Name_length) {
        print_error("Error: rfc822Name does not contain a domain portion.");
    }

    domain_length = rfc822Name + rfc822Name_length - i;
    if (domain_length > 255) {
        print_error("Error: domain portion of rfc822Name is longer than 255 octets.");
    }

    if (*i != '[') {
        /* Domain  = sub-domain *("." sub-domain) */
        validate_dNSName(i, domain_length);
    } else {
        /* address-literal  = "[" ( IPv4-address-literal /
         *                  IPv6-address-literal /
         *                  General-address-literal ) "]"
         */
        /* TODO */
    }

    return(0);
}

int validate_UUID(unsigned char *UUID, int UUID_length)
{
    unsigned char *i;

    if (UUID_length != 36) {
        print_error("Error: The length of the UUID URN is incorrect.");
        return(-1);
    }

    if ((*(UUID+8) != '-') || (*(UUID+13) != '-') || (*(UUID+18) != '-') || (*(UUID+23) != '-')) {
        print_error("Error: Hyphen characters do not appear in the expected places in the UUID URN.");
        return(-1);
    }

    for(i=UUID; i < UUID + UUID_length; i++) {
        if ((i != UUID + 8) && (i != UUID + 13) && (i != UUID + 18) && (i != UUID + 23) && !is_hexdigit(*i)) {
            if ((*i >= 0x20) && (*i <= 0x7E)) {
                sprintf(error_str, "Error: Unexpected character in UUID URN: '%c'.", *i);
            } else {
                sprintf(error_str, "Error: Unexpected character in UUID URN: %d.", *i);
            }
            print_error(error_str);
            return(-1);
        }
    }

    return(0);
}

int validate_URN(unsigned char *URN, int URN_length)
{
    int NID_length, error_found;
    unsigned char *i;
    char *NID;

    if (URN_length == 0) {
        print_error("Error: uniformResourceIdentifier contains a URN with no namespace identifier.");
        return(-1);
    }

    i = URN;
    /* URN must begin with a namespace identifier of the form <let-num> [ 1,31<let-num-hyp> ]
     * followed by a ':'. */
    if (!is_letter_or_digit(*i)) {
        error_found = 1;
        if ((*i >= 0x20) && (*i <= 0x7E)) {
            sprintf(error_str, "Error: Namespace identifier portion of URN contains an invalid character: '%c'.  First character of NID must be a letter or digit.", *i);
        } else {
            sprintf(error_str, "Error: Namespace identifier portion of URN contains an invalid character: %d.  First character of NID must be a letter or digit.", *i);
        }
        print_error(error_str);
    }
    i++;

    while ((i < URN + URN_length) && (*i != ':')) {
        if (!is_letter_or_digit(*i) && (*i != '-')) {
            error_found = 1;
            if ((*i >= 0x20) && (*i <= 0x7E)) {
                sprintf(error_str, "Error: Namespace identifier portion of URN contains an invalid character: '%c'.", *i);
            } else {
                sprintf(error_str, "Error: Namespace identifier portion of URN contains an invalid character: %d.", *i);
            }
            print_error(error_str);
        }
        i++;
    }

    if (i == URN + URN_length) {
        print_error("Error: URN does not begin with: NID \":\".");
        return(-1);
    }

    NID_length = i - URN;

    if ((NID_length < 2) || (NID_length > 32)) {
        print_error("Error: Invalid length for namespace identifier portion of URN.");
    }

    i++;

    NID = (char *)malloc(NID_length + 1);
    memcpy(NID, URN, NID_length);
    NID[NID_length] = '\0';

    if (i == URN + URN_length) {
        sprintf(error_str, "Error: The Namespace Specific String (NSS) portion of the %s URN is empty.", NID);
        print_error(error_str);
        free(NID);
        return(-1);
    }

    /* Perform namespace identifier validations */
    if (strcasecmp(NID, "uuid") == 0) {
        free(NID);
        return(validate_UUID(URN + 5, URN_length - 5));
    }

    /* check that Namespace Specific String (NSS) portion of URN conforms to the generic RFC 2141 syntax */
    while (i < URN + URN_length) {
        if (*i == '%') {
            /* it has already been verified that the '%' is followed by two hexadecimal digits */
            if ( (*(i+1) == '0') && (*(i+2) == '0') ) {
                sprintf(error_str, "Warning:  The Namespace Specific String (NSS) portion of the %s URN contains a 0 octet (in %%-encoded form).", NID);
                print_error(error_str);
            }
            i += 3;
        } else if ((*i == '/') || (*i == '?') || (*i == '#')) {
            sprintf(error_str, "Warning: The Namespace Specific String (NSS) portion of the %s URN contains a reserved character in unencoded form: '%c'.", NID, *i);
            print_error(error_str);
            i++;
        } else {
            if (!is_letter_or_digit(*i) && (*i != '(') && (*i != ')') && (*i != '+') && (*i != ',') &&
                (*i != '-') && (*i != '.') && (*i != ':') && (*i != '=') && (*i != '@') && (*i != ';') &&
                (*i != '$') && (*i != '_') && (*i != '!') && (*i != '*') && (*i != '\'') ) {
                if ((*i >= 0x20) && (*i <= 0x7E)) {
                    sprintf(error_str, "Error: The Namespace Specific String (NSS) portion of the %s URN contains an illegal character: '%c'.", NID, *i);
                } else {
                    sprintf(error_str, "Error: The Namespace Specific String (NSS) portion of the %s URN contains an illegal character: %d.", NID, *i);
                }
                print_error(error_str);
            }
            i++;
        }
    }

    free(NID);

    if (error_found) {
        return(-1);
    } else {
        return(0);
    }
}


/*
 * gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
 */
static int is_URI_gen_delim(unsigned char c)
{
    return((c == ':') || (c == '/') || (c == '?') || (c == '#') || (c == '[') || (c == ']') || (c == '@'));
}

/*
 * sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
 *             / "*" / "+" / "," / ";" / "="
 */
static int is_URI_sub_delim(unsigned char c)
{
    return((c == '!') || (c == '$') || (c == '&') || (c == '\'') || (c == '(') || (c == ')') ||
           (c == '*') || (c == '+') || (c == ',') || (c == ';') || (c == '='));
}

/*
 * unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
 */
static int is_URI_unreserved(unsigned char c)
{
    return(is_letter_or_digit(c) || (c == '-') || (c == '.') || (c == '_') || (c == '~'));
}

/*
 * userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
 */
static int validate_URI_userinfo(unsigned char *userinfo, int userinfo_length)
{
    unsigned char *i;

    for(i=userinfo; i < userinfo + userinfo_length; i++) {
        if (!is_URI_unreserved(*i) && (*i != '%') && !is_URI_sub_delim(*i) && (*i != ':')) {
            if ((*i >= 0x20) && (*i <= 0x7E)) {
                sprintf(error_str, "Error: userinfo portion of uniformResourceIdentifier contains an illegal character: '%c'.", *i);
            } else {
                sprintf(error_str, "Error: userinfo portion of uniformResourceIdentifier contains an illegal character: %d.", *i);
            }
            print_error(error_str);
        }
    }
    return(0);
}

/*
 * host        = IP-literal / IPv4address / reg-name
 *
 * reg-name    = *( unreserved / pct-encoded / sub-delims )
 *
 * IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
 *
 * IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
 *
 * IPv6address =                            6( h16 ":" ) ls32
 *             /                       "::" 5( h16 ":" ) ls32
 *             / [               h16 ] "::" 4( h16 ":" ) ls32
 *             / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
 *             / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
 *             / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
 *             / [ *4( h16 ":" ) h16 ] "::"              ls32
 *             / [ *5( h16 ":" ) h16 ] "::"              h16
 *             / [ *6( h16 ":" ) h16 ] "::"
 *
 * ls32        = ( h16 ":" h16 ) / IPv4address
 *             ; least-significant 32 bits of address
 *
 * h16         = 1*4HEXDIG
 *             ; 16 bits of address represented in hexadecimal
 *
 * NOTE: IPv4address satisifies syntax for reg-name
 */
static int validate_URI_host(unsigned char *host, int host_length)
{
    unsigned char *i;

    if (*host != '[') {
        /* reg-name or IPv4address */
        for(i=host; i < host + host_length; i++) {
            if (!is_URI_unreserved(*i) && (*i != '%') && !is_URI_sub_delim(*i)) {
                if ((*i >= 0x20) && (*i <= 0x7E)) {
                    sprintf(error_str, "Error: host portion of uniformResourceIdentifier contains an illegal character: '%c'.", *i);
                } else {
                    sprintf(error_str, "Error: host portion of uniformResourceIdentifier contains an illegal character: %d.", *i);
                }
                print_error(error_str);
            }
        }
    } else {
        host++;
        host_length -=2;
        if ((*host != 'v') && (*host != 'V')) {
            /* IPv6address */
            /* TODO:  For now, just check that contents are limited to hexadecimal digits and ':' */
            for(i=host; i < host + host_length; i++) {
                if (!is_hexdigit(*i) && (*i != ':')) {
                    if ((*i >= 0x20) && (*i <= 0x7E)) {
                        sprintf(error_str, "Error: IPv6address in host in uniformResourceIdentifier contains a character that is not a hexadecimal digit or ':': '%c'.", *i);
                    } else {
                        sprintf(error_str, "Error: IPv6address in host in uniformResourceIdentifier contains a character that is not a hexadecimal digit or ':': %d.", *i);
                    }
                    print_error(error_str);
                }
            }
        } else {
            /* IPvFuture */
            i = host + 1;
            while ((i < host + host_length) && (*i != '.')) {
                if (!is_hexdigit(*i)) {
                    if ((*i >= 0x20) && (*i <= 0x7E)) {
                        sprintf(error_str, "Error: version number in IPvFuture host in uniformResourceIdentifier contains a character that is not a hexadecimal digit: '%c'.", *i);
                    } else {
                        sprintf(error_str, "Error: version number in IPvFuture host in uniformResourceIdentifier contains a character that is not a hexadecimal digit: %d.", *i);
                    }
                    print_error(error_str);
                }
                i++;
            }
            if (i == host + 1) {
                print_error("Error: IPvFuture host name in uniformResourceIdentifier is missing version number.");
                return(-1);
            }
            if (i + 1 >= host + host_length) {
                print_error("Error: IPvFuture host name in uniformResourceIdentifier contains no value after version number.");
                return(-1);
            }
            i++;
            while (i < host + host_length) {
                if (!is_URI_unreserved(*i) && !is_URI_sub_delim(*i) && (*i != ':')) {
                    if ((*i >= 0x20) && (*i <= 0x7E)) {
                        sprintf(error_str, "Error: host portion of uniformResourceIdentifier contains an illegal character: '%c'.", *i);
                    } else {
                        sprintf(error_str, "Error: host portion of uniformResourceIdentifier contains an illegal character: %d.", *i);
                    }
                    print_error(error_str);
                }
                i++;
            }
        }
    }
    return(0);
}

/*
 * port        = *DIGIT
 */
static int validate_URI_port(unsigned char *port, int port_length)
{
    unsigned char *i;

    for(i=port; i < port + port_length; i++) {
        if ((*i < '0') || (*i > '9')) {
            if ((*i >= 0x20) && (*i <= 0x7E)) {
                sprintf(error_str, "Error: port number in authority portion of uniformResourceIdentifier contains an illegal character: '%c'.", *i);
            } else {
                sprintf(error_str, "Error: port number in authority portion of uniformResourceIdentifier contains an illegal character: %d.", *i);
            }
            print_error(error_str);
        }
    }
    return(0);
}

int validate_URI(unsigned char *URI, int URI_length)
{
    unsigned char *i, *j, *authority, *userinfo, *host, *port, *path, *query, *fragment;
    char *scheme;
    int scheme_length, authority_length, userinfo_length, host_length, port_length, path_length, query_length, fragment_length;
    int error_found = 0;
    int contains_authority = 0;

    if (URI_length == 0) {
        print_error("Error: uniformResourceIdentifier contains an empty string.");
        return(-1);
    }

    i = URI;
    /* URI must begin with a scheme of the form scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
     * followed by a ':'. */
    if (!is_letter(*i)) {
        error_found = 1;
        if ((*i >= 0x20) && (*i <= 0x7E)) {
            sprintf(error_str, "Error: Scheme portion of uniformResourceIdentifier contains an invalid character: '%c'.  First character of URI must be a letter.", *i);
        } else {
            sprintf(error_str, "Error: Scheme portion of uniformResourceIdentifier contains an invalid character: %d.  First character of URI must be a letter.", *i);
        }
        print_error(error_str);
    }
    i++;

    while ((i < URI + URI_length) && (*i != ':')) {
        if (!is_letter_or_digit(*i) && (*i != '+') && (*i != '-') && (*i != '.')) {
            error_found = 1;
            if ((*i >= 0x20) && (*i <= 0x7E)) {
                sprintf(error_str, "Error: Scheme portion of uniformResourceIdentifier contains an invalid character: '%c'.", *i);
            } else {
                sprintf(error_str, "Error: Scheme portion of uniformResourceIdentifier contains an invalid character: %d.", *i);
            }
            print_error(error_str);
        }
        i++;
    }

    if (i == URI + URI_length) {
        print_error("Error: uniformResourceIdentifier does not begin with: scheme \":\".");
        return(-1);
    }

    scheme_length = i - URI;

    i++;

    scheme = (char *)malloc(scheme_length + 1);
    memcpy(scheme, URI, scheme_length);
    scheme[scheme_length] = '\0';

    j = i;
    /* check for illegal characters in remainder of URI. */
    while (j < URI + URI_length) {
        if (*j == '%') {
            if (j + 2 >= URI + URI_length) {
                sprintf(error_str, "Error: %s uniformResourceIdentifier includes a '%%' character that is not followed by two hexadecimal digits.", scheme);
                print_error(error_str);
                error_found = 1;
                j++;
            } else if (!is_hexdigit(*(j+1))) {
                sprintf(error_str, "Error: %s uniformResourceIdentifier includes a '%%' character that is not followed by two hexadecimal digits.", scheme);
                print_error(error_str);
                error_found = 1;
                j++;
            } else if (!is_hexdigit(*(j+2))) {
                sprintf(error_str, "Error: %s uniformResourceIdentifier includes a '%%' character that is not followed by two hexadecimal digits.", scheme);
                print_error(error_str);
                error_found = 1;
                j += 2;
            } else {
                j += 3;
            }
        } else {
            if (!is_URI_unreserved(*j) && !is_URI_gen_delim(*j) && !is_URI_sub_delim(*j)) {
                error_found = 1;
                if ((*j >= 0x20) && (*j <= 0x7E)) {
                    sprintf(error_str, "Error: %s uniformResourceIdentifier contains an invalid character: '%c'.", scheme, *j);
                } else {
                    sprintf(error_str, "Error: %s uniformResourceIdentifier contains an invalid character: %d.", scheme, *j);
                }
                print_error(error_str);
            }
            j++;
        }
    }

    if (error_found) {
        return(-1);
    }

    if (strcasecmp(scheme, "URN") == 0) {
        free(scheme);
        return(validate_URN(URI + 4, URI_length - 4));
    }

    /* If an authority component is present, then check it. */
    if ((i + 1 < URI + URI_length) && (*i == '/') && (*(i+1) == '/')) {
        contains_authority = 1;
        i += 2;
        authority = i;
        /* next portion of URI must be an authority component */
        /* The authority component is terminated by the next slash ("/"),
         * question mark ("?"), or number sign ("#") character, or by the
         * end of the URI.
         *
         * authority   = [ userinfo "@" ] host [ ":" port ]
         */
        while ((i < URI + URI_length) && (*i != '/') && (*i != '?') && (*i != '#')) {
            i++;
        }
        authority_length = i - authority;

        j = userinfo = authority;
        while ((j < authority + authority_length) && (*j != '@')) {
            j++;
        }
        if (*j == '@') {
            userinfo_length = j - userinfo;
            j++;
            host = j;
        } else {
            userinfo_length = 0;
            j = host = authority;
        }

        if (j == authority + authority_length) {
            host_length = 0;
            port_length = 0;
        } else {
            if (*j == '[') {
                while ((j < authority + authority_length) && (*j != ']')) {
                    j++;
                }
                if (j == authority + authority_length) {
                    sprintf(error_str, "Error: host portion of %s uniformResourceIdentifier begins with ']' but there is no matching ']'.", scheme);
                    print_error(error_str);
                    free(scheme);
                    return(-1);
                }
                j++;
            } else {
                while ((j < authority + authority_length) && (*j != ':')) {
                    j++;
                }
            }
            host_length = j - host;
            if ((j < authority + authority_length) && (*j != ':')) {
                sprintf(error_str, "Error: Unknown syntax error in authority component of %s uniformResourceIdentifier.", scheme);
                print_error(error_str);
                free(scheme);
                return(-1);
            }
            if (j == authority + authority_length) {
                port_length = 0;
            } else {
                j++;
                port = j;
                port_length = authority + authority_length - port;
            }
        }

        if (userinfo_length > 0) {
            if (strcasecmp(scheme, "ldap") == 0) {
                sprintf(error_str, "Error: The authority component of %s URIs must not include a userinfo component [RFC 4516].", scheme);
                print_error(error_str);
                free(scheme);
                return(-1);
            }
            validate_URI_userinfo(userinfo, userinfo_length);
        }
        if (host_length > 0) {
            validate_URI_host(host, host_length);
        }
        if (port_length > 0) {
            validate_URI_port(port, port_length);
        }
    } else if ((strcasecmp(scheme, "http") == 0) || (strcasecmp(scheme, "https") == 0)) {
        sprintf(error_str, "Error: %s URIs must include an authority component [RFC 2616]", scheme);
        print_error(error_str);
    } else if (strcasecmp(scheme, "ldap") == 0) {
        sprintf(error_str, "Error: %s URIs must include an authority component [RFC 4516]", scheme);
        print_error(error_str);
    } else if (strcasecmp(scheme, "rsync") == 0) {
        sprintf(error_str, "Error: %s URIs must include an authority component [RFC 5781]", scheme);
        print_error(error_str);
    }

    if (i == URI + URI_length) {
        free(scheme);
        return(0);
    }

    if (contains_authority && (*i != '/') && (*i != '?') && (*i != '#')) {
        sprintf(error_str, "Error: %s uniformResourceIdentifier includes an authority component, but path is not empty and does not begin with a '/'.", scheme);
        print_error(error_str);
    }

    /* The path is terminated by the first question mark ("?") or
     * number sign ("#") character, or by the end of the URI.
     */
    path = i;
    while ((i < URI + URI_length) && (*i != '?') && (*i != '#')) {
        i++;
    }

    path_length = i - path;

    /* check path component of URI */
    for(j = path; j < path + path_length; j++) {
        if (!is_URI_unreserved(*j) && (*j != '%') && !is_URI_sub_delim(*j) &&
            (*j != ':') && (*j != '@') && (*j != '/')) {
            sprintf(error_str, "Error: Path component of %s URI contains an illegal character: '%c'.", scheme, *j);
            print_error(error_str);
        }
    }

    if (i == URI + URI_length) {
        free(scheme);
        return(0);
    }

    /* The query component is indicated by the first question
     * mark ("?") character and terminated by a number sign ("#") character
     * or by the end of the URI.
     */
    if (*i == '?') {
        i++;
        query = i;
        while ((i < URI + URI_length) && (*i != '#')) {
            i++;
        }
        query_length = i - query;

        /* check query component of URI */
        for(j = query; j < query + query_length; j++) {
            if (!is_URI_unreserved(*j) && (*j != '%') && !is_URI_sub_delim(*j) &&
                (*j != ':') && (*j != '@') && (*j != '/') && (*j != '?')) {
                sprintf(error_str, "Error: Query component of %s URI contains an illegal character: '%c'.", scheme, *j);
                print_error(error_str);
            }
        }
    }

    if (i == URI + URI_length) {
        free(scheme);
        return(0);
    }

    /* skip over '#' */
    i++;

    fragment = i;
    fragment_length = URI + URI_length - fragment;

    /* check fragment component of URI */
    for(j = fragment; j < fragment + fragment_length; j++) {
        if (!is_URI_unreserved(*j) && (*j != '%') && !is_URI_sub_delim(*j) &&
            (*j != ':') && (*j != '@') && (*j != '/') && (*j != '?')) {
            sprintf(error_str, "Error: Fragment component of %s URI contains an illegal character: '%c'.", scheme, *j);
            print_error(error_str);
        }
    }

    free(scheme);
    return(0);
}

int validate_emailAddress(int tag, unsigned char *emailAddress, int emailAddress_length)
{

    if (tag != 22) {
        print_error("Error: Incorrect tag. domainComponent must be encoded as IA5String.");
    }
    if (emailAddress_length == 0) {
        print_error("Error: emailAddress contains an empty string.");
        return(-1);
    } else if (emailAddress_length > 255) {
        print_error("Warning: emailAddress attribute is longer than 255 octets.");
    }

    return(validate_rfc822Name(emailAddress, emailAddress_length));
}

int validate_VisibleString(unsigned char *DirectoryString, int DirectoryString_len, int max_len)
{
    unsigned char *i;

    if (DirectoryString_len > max_len) {
        print_error("Warning: VisibleString is too long.");
    }

    for(i=DirectoryString; i < DirectoryString + DirectoryString_len; i++) {
        if ((*i < 0x20) || (*i >= 0x7F)) {
            sprintf(error_str, "Error: VisibleString contains invalid character: %d.", *i);
            print_error(error_str);
        }
    }

    return(0);
}

int validate_PrintableString(unsigned char *DirectoryString, int DirectoryString_len, int max_len)
{
    unsigned char *i;

    if (DirectoryString_len > max_len) {
        print_error("Warning: PrintableString is too long.");
    }

    for(i=DirectoryString; i < DirectoryString + DirectoryString_len; i++) {
        if (!is_letter_or_digit(*i) && (*i != ' ') && (*i != '\'') && (*i != '(') && (*i != ')') && (*i != '+') &&
                (*i != ',') && (*i != '-') && (*i != '.') && (*i != '/') && (*i != ':') && (*i != '=') && (*i != '?')) {
            if ((*i >= 0x20) && (*i <= 0x7E)) {
                sprintf(error_str, "Error: PrintableString contains invalid character: '%c'.", *i);
            } else {
                sprintf(error_str, "Error: PrintableString contains invalid character: %d.", *i);
            }
            print_error(error_str);
        }
    }

    return(0);
}

/*
 *    Char. number range  |        UTF-8 octet sequence
 *       (hexadecimal)    |              (binary)
 *    --------------------+---------------------------------------------
 *    0000 0000-0000 007F | 0xxxxxxx
 *    0000 0080-0000 07FF | 110xxxxx 10xxxxxx
 *    0000 0800-0000 FFFF | 1110xxxx 10xxxxxx 10xxxxxx
 *    0001 0000-0010 FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
 */
int validate_UTF8String(unsigned char *DirectoryString, int DirectoryString_len, int max_len)
{

    unsigned char *i;
    char error_msg[100];
    int length, c;

    i = DirectoryString;
    length = 0;

    while (i < DirectoryString + DirectoryString_len) {
        if ((*i & 0x80) == 0) {
            /* if most significant bit is a zero, then character is
             * encoded in a single octet: 0xxxxxxx */
            c = *i;
            i += 1;
        } else if (((*i & 0xE0) == 0xC0) && (i < DirectoryString + DirectoryString_len - 1)) {
            /* character is encoded as two octets: 110xxxxx 10xxxxxx */
            c = (*i & 0x1F) << 6;
            i += 1;
            if ((*i & 0xC0) != 0x80) {
                print_error("UTF8String contains an improperly formatted character.");
                return(-1);
            }
            c += *i & 0x3F;
            i += 1;
            if (c < 128) {
                print_error("UTF8String contains an improperly formatted character.");
            }
        } else if (((*i & 0xF0) == 0xE0) && (i < DirectoryString + DirectoryString_len - 2)) {
            /* character is encoded as three octets: 1110xxxx 10xxxxxx 10xxxxxx */
            c = (*i & 0x0F) << 12;
            i += 1;
            if ((*i & 0xC0) != 0x80) {
                print_error("UTF8String contains an improperly formatted character.");
                return(-1);
            }
            c += (*i & 0x3F) << 6;
            i += 1;
            if ((*i & 0xC0) != 0x80) {
                print_error("UTF8String contains an improperly formatted character.");
                return(-1);
            }
            c += *i & 0x3F;
            i += 1;
            if (c < 2048) {
                print_error("UTF8String contains an improperly formatted character.");
            }
        } else if (((*i & 0xF8) != 0xF0) && (i < DirectoryString + DirectoryString_len - 3)) {
            /* character is encoded as four octets: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
            c = (*i & 0x07) << 18;
            i += 1;
            if ((*i & 0xC0) != 0x80) {
                print_error("UTF8String contains an improperly formatted character.");
                return(-1);
            }
            c += (*i & 0x3F) << 12;
            i += 1;
            if ((*i & 0xC0) != 0x80) {
                print_error("UTF8String contains an improperly formatted character.");
                return(-1);
            }
            c += (*i & 0x3F) << 6;
            i += 1;
            if ((*i & 0xC0) != 0x80) {
                print_error("UTF8String contains an improperly formatted character.");
                return(-1);
            }
            c += *i & 0x3F;
            i += 1;
            if (c < 65536) {
                print_error("UTF8String contains an improperly formatted character.");
            }
        } else {
            print_error("UTF8String contains an improperly formatted character.");
            return(-1);
        }

        length++;

        /* check that c is not a control character */
        if (((c >= 0) && (c <= 0x1F)) || ((c >= 0x7F) && (c <= 0x9F))) {
            sprintf(error_msg, "Warning: UTF8String contains control character %d.\n", c);
            print_error(error_msg);
        }
    }

    if (length > max_len) {
        print_error("Warning: UTF8String is too long.");
    }

    return(0);
}


int validate_TeletexString(unsigned char *DirectoryString, int DirectoryString_len, int max_len)
{
    unsigned char *i;

    if (DirectoryString_len > max_len) {
        print_error("Warning: TeletexString is too long.");
    }

    /* TODO: Check contents of string. Current text treats TeletexString like IA5String. */
    for(i=DirectoryString; i < DirectoryString + DirectoryString_len; i++) {
        if ((*i < 0x20) || (*i == 0x7F)) {
            sprintf(error_str, "Warning: TeletexString contains a control character: %d.", *i);
            print_error(error_str);
        }
    }

    return(0);
}

int validate_BMPString(unsigned char *DirectoryString, int DirectoryString_len, int max_len)
{
    unsigned char *i;
    int j;

    if ((DirectoryString_len % 2) != 0) {
        printf("Error: BMPString is not encoded as an even number of octets.");
        return(-1);
    }

    if (DirectoryString_len/2 > max_len) {
        print_error("Warning: BMPString is too long.");
    }

    /* TODO: Check contents of string */
    for(i=DirectoryString; i < DirectoryString + DirectoryString_len; i+=2) {
        j = (*i << 8) + *(i+1);
        if ((j < 0x20) || (j == 0x7F)) {
            sprintf(error_str, "Warning: BMPString contains a control character: %d.", j);
            print_error(error_str);
        }
    }

    return(0);
}

int validate_UniversalString(unsigned char *DirectoryString, int DirectoryString_len, int max_len)
{
    unsigned char *i;
    int j;

    if ((DirectoryString_len % 4) != 0) {
        printf("Error: UniversalString is not encoded as a multiple of 4 octets.");
        return(-1);
    }

    if (DirectoryString_len/4 > max_len) {
        print_error("Warning: UniversalString is too long.");
    }

    /* TODO: Check contents of string */
    for(i=DirectoryString; i < DirectoryString + DirectoryString_len; i+=4) {
        j = (*i << 24) + (*(i+1) << 16) + (*(i+2) << 8) + *(i+3);
        if ((j < 0x20) || (j == 0x7F)) {
            sprintf(error_str, "Warning: UniversalString contains a control character: %d.", j);
            print_error(error_str);
        }
    }
    return(0);
}

/*
 * DisplayText ::= CHOICE {
 *      ia5String        IA5String      (SIZE (1..200)),
 *      visibleString    VisibleString  (SIZE (1..200)),
 *      bmpString        BMPString      (SIZE (1..200)),
 *      utf8String       UTF8String     (SIZE (1..200)) }
 */
int validate_DisplayText(unsigned char **DisplayText, int *DisplayText_len)
{
    int tag, length;
    unsigned char *text;

    if ((tag = get_tag(DisplayText, DisplayText_len)) == -1) {
        return(-1);
    }

    if ((length = get_length(DisplayText, DisplayText_len)) == -1) {
        return(-1);
    }

   if (length == 0) {
        print_error("Error: DisplayText is of length 0.");
        return(-1);
   }

   text = *DisplayText;
   *DisplayText += length;
   *DisplayText_len -= length;

   switch(tag) {
        case 22: /* IA5String */
            return(validate_IA5String(text, length, 200));
            break;

        case 26: /* VisibleString */
            return(validate_VisibleString(text, length, 200));
            break;

        case 30: /* BMPString */
            print_error("Warning: String should be encoded in UTF8String, VisibleString, or IA5String rather than BMPString.");
            return(validate_BMPString(text, length, 200));
            break;

        case 12: /* UTF8String */
            return(validate_UTF8String(text, length, 200));
            break;

        default:
            print_error("Tag does not represent a valid tag for type DisplayText.");
            return(-1);
            break;
   }
   return(0);
}

/*
 * DirectoryString { INTEGER : maxSize } ::= CHOICE {
 *     teletexString TeletexString (SIZE (1..maxSize)),
 *     printableString PrintableString (SIZE (1..maxSize)),
 *     bmpString BMPString (SIZE (1..maxSize)),
 *     universalString UniversalString (SIZE (1..maxSize)),
 *     uTF8String UTF8String (SIZE (1..maxSize)) }
 */
int validate_DirectoryString(int tag, unsigned char *DirectoryString, int DirectoryString_len, int max_len)
{

   if (DirectoryString_len == 0) {
        print_error("Error: DirectoryString is of length 0.");
        return(-1);
   }

   switch(tag) {
        case 20: /* TeletexString */
            print_error("Warning: String should be encoded in UTF8String or PrintableString rather than TeletexString.");
            return(validate_TeletexString(DirectoryString, DirectoryString_len, max_len));
            break;

        case 19: /* printableString */
            return(validate_PrintableString(DirectoryString, DirectoryString_len, max_len));
            break;

        case 30: /* BMPString */
            print_error("Warning: String should be encoded in UTF8String or PrintableString rather than BMPString.");
            return(validate_BMPString(DirectoryString, DirectoryString_len, max_len));
            break;

        case 28: /* UniversalString */
            print_error("Warning: String should be encoded in UTF8String or PrintableString rather than UniversalString.");
            return(validate_UniversalString(DirectoryString, DirectoryString_len, max_len));
            break;

        case 12: /* UTF8String */
            return(validate_UTF8String(DirectoryString, DirectoryString_len, max_len));
            break;

        default:
            print_error("Tag does not represent a valid tag for type DirectoryString.");
            return(-1);
            break;
   }
   return(0);
}

/*
 * AttributeTypeAndValue   ::= SEQUENCE {
 *      type    AttributeType,
 *      value   AttributeValue }
 *
 * AttributeType ::= OBJECT IDENTIFIER
 *
 * AttributeValue ::= ANY -- DEFINED BY AttributeType
 */
int validate_AttributeTypeAndValue(unsigned char **input, int *input_len)
{
    int tag, AttributeTypeAndValue_length, AttributeValue_length;
    char *AttributeType_oid;
    unsigned char *AttributeValue;

    push_error_stack("AttributeTypeAndValue");

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Error: Incorrect tag for AttributeTypeAndValue SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((AttributeTypeAndValue_length = get_length(input, input_len)) == -1) {
        return(-1);
    }

    *input_len -= AttributeTypeAndValue_length;

    if (get_OID(input, &AttributeTypeAndValue_length, &AttributeType_oid) == -1) {
        pop_error_stack();
        return(-1);
    }

    /* Get Attribute value */
    if ((tag = get_tag(input, &AttributeTypeAndValue_length)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if ((AttributeValue_length = get_length(input, &AttributeTypeAndValue_length)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if (AttributeTypeAndValue_length != AttributeValue_length) {
        print_error("Error: Incorrect length in AttributeTypeAndValue.");
        pop_error_stack();
        return(-1);
    }

    AttributeValue = *input;
    *input += AttributeValue_length;

    if (strcmp(AttributeType_oid, "2.5.4.6") == 0) {
        /* Country */
        push_error_stack("Country");
        if (tag != 19) {
            print_error("Country attribute must be encoded as a PrintableString.");
        }
        if (AttributeValue_length != 2) {
            print_error("Country attribute must be exactly two octets in length.");
        }
        if (!is_letter(*AttributeValue)) {
            print_error("Country attribute contains a non-alphabet character.");
        }
        if (!is_letter(*(AttributeValue+1))) {
            print_error("Country attribute contains a non-alphabet character.");
        }
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "1.3.6.1.4.1.311.60.2.1.3") == 0) {
        /* jurisdictionOfIncorporationCountryName */
        push_error_stack("jurisdictionOfIncorporationCountryName");
        if (tag != 19) {
            print_error("jurisdictionOfIncorporationCountryName attribute must be encoded as a PrintableString.");
        }
        if (AttributeValue_length != 2) {
            print_error("jurisdictionOfIncorporationCountryName attribute must be exactly two octets in length.");
        }
        if (!is_letter(*AttributeValue)) {
            print_error("jurisdictionOfIncorporationCountryName attribute contains a non-alphabet character.");
        }
        if (!is_letter(*(AttributeValue+1))) {
            print_error("jurisdictionOfIncorporationCountryName attribute contains a non-alphabet character.");
        }
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.10") == 0) {
        /* Organization */
        push_error_stack("Organization");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 64);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.11") == 0) {
        /* Organizational Unit */
        push_error_stack("Organizational Unit");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 64);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.7") == 0) {
        /* localityName */
        push_error_stack("localityName");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 128);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "1.3.6.1.4.1.311.60.2.1.1") == 0) {
        /* jurisdictionOfIncorporationLocalityName */
        push_error_stack("jurisdictionOfIncorporationLocalityName");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 128);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.8") == 0) {
        /* StateOrProvinceName */
        push_error_stack("StateOrProvinceName");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 128);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "1.3.6.1.4.1.311.60.2.1.2") == 0) {
        /* jurisdictionOfIncorporationStateOrProvinceName */
        push_error_stack("jurisdictionOfIncorporationStateOrProvinceName");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 128);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.3") == 0) {
        /* Common Name */
        push_error_stack("Common Name");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 64);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.4") == 0) {
        /* surname */
        push_error_stack("surname");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 32768);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.9") == 0) {
        /* streetAddress */
        push_error_stack("streetAddress");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 128);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.12") == 0) {
        /* title */
        push_error_stack("title");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 64);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.15") == 0) {
        /* businessCategory */
        push_error_stack("businessCategory");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 128);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.17") == 0) {
        /* postalCode */
        push_error_stack("postalCode");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 40);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.41") == 0) {
        /* name */
        push_error_stack("name");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 32768);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.42") == 0) {
        /* givenName */
        push_error_stack("givenName");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 32768);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.43") == 0) {
        /* initials */
        push_error_stack("initials");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 32768);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.44") == 0) {
        /* generationQualifier */
        push_error_stack("generationQualifier");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 32768);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.65") == 0) {
        /* pseudonym */
        push_error_stack("pseudonym");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, 128);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.5") == 0) {
        /* serial number */
        push_error_stack("serial number");
        if (tag != 19) {
            print_error("Error: Incorrect tag.  Serial number must be of type PrintableString.");
        }
        validate_PrintableString(AttributeValue, AttributeValue_length, 64);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "2.5.4.46") == 0) {
        /* dnQualifier */
        push_error_stack("dnQualifier");
        if (tag != 19) {
            print_error("Error: Incorrect tag. dnQualifier must be of type PrintableString.");
        }
        validate_PrintableString(AttributeValue, AttributeValue_length, AttributeValue_length);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "1.2.840.113549.1.9.1") == 0) {
        /* emailAddress */
        push_error_stack("emailAddress");
        validate_emailAddress(tag, AttributeValue, AttributeValue_length);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "0.9.2342.19200300.100.1.1") == 0) {
        /* userID */
        push_error_stack("userID");
        validate_DirectoryString(tag, AttributeValue, AttributeValue_length, AttributeValue_length);
        pop_error_stack();
    } else if (strcmp(AttributeType_oid, "0.9.2342.19200300.100.1.25") == 0) {
        /* domainComponent */
        push_error_stack("domainComponent");
        validate_domainComponent(tag, AttributeValue, AttributeValue_length);
        pop_error_stack();
    } else {
        sprintf(error_str, "Warning: Unknown attribute type: %s. Value not checked.", AttributeType_oid);
        print_error(error_str);
    }

    pop_error_stack();
    return(0);
}

/*
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 */
int validate_RelativeDistinguishedName(unsigned char **input, int *input_len)
{
    int tag, RDN_length;

    push_error_stack("RelativeDistinguishedName");

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x31) {
        print_error("Error: Incorrect tag for RelativeDistinguishedName.");
        pop_error_stack();
        return(-1);
    }
    if ((RDN_length = get_length(input, input_len)) == -1) {
        return(-1);
    }
    *input_len -= RDN_length;

    if (RDN_length == 0) {
        print_error("RelativeDistinguishedName is an empty SET.");
        pop_error_stack();
        return(-1);
    }

    /* TODO: Make sure elements in SET are in sorted order */

    /* Validate attribute type and value pairs one at a time */
    while (RDN_length > 0) {
        if (validate_AttributeTypeAndValue(input, &RDN_length) == -1) {
            return(-1);
        }
    }
    pop_error_stack();
    return(0);
}

/* The string pointed to by *input contains a DER encoded
 * directory string.  Parse the string, place *input at the
 * first octet after the directory string and decrement *input_len
 * by the length of the directory string.  Return -1 if there is
 * an error and 0 otherwise.
 *
 * Name ::= CHOICE { -- only one possibility for now --
 *       rdnSequence  RDNSequence }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * DistinguishedName ::= RDNSequence
 *
 */
int validate_directoryName(unsigned char **input, int *input_len, int *is_empty)
{
    int tag, directoryName_length;

    if ((tag = get_tag(input, input_len)) == -1) {
        return(-1);
    }
    if (tag != 0x30) {
        print_error("directoryName is not encoded as a SEQUENCE.");
        return(-1);
    }

    if ((directoryName_length = get_length(input, input_len)) == -1) {
        return(-1);
    }
    *input_len -= directoryName_length;

    *is_empty = (directoryName_length == 0);

    /* Process RelativeDistinguishedNames one at a time */
    while (directoryName_length > 0) {
        if (validate_RelativeDistinguishedName(input, &directoryName_length) == -1) {
            return(-1);
        }
    }

    return(0);
}

int validate_FASCN(unsigned char *input)
{
    int FASCN_digits[40], FASCN_bits[200];
    int i, j, k;

    /* place each bit of the FASC-N into a separate array entry */
    for(i=0; i < 200; i++)
        FASCN_bits[i] = 0;

    for(i=0; i < 25; i++) {
        if ((*input & 0x80) != 0) FASCN_bits[8*i]   = 1;
        if ((*input & 0x40) != 0) FASCN_bits[8*i+1] = 1;
        if ((*input & 0x20) != 0) FASCN_bits[8*i+2] = 1;
        if ((*input & 0x10) != 0) FASCN_bits[8*i+3] = 1;
        if ((*input & 0x08) != 0) FASCN_bits[8*i+4] = 1;
        if ((*input & 0x04) != 0) FASCN_bits[8*i+5] = 1;
        if ((*input & 0x02) != 0) FASCN_bits[8*i+6] = 1;
        if ((*input & 0x01) != 0) FASCN_bits[8*i+7] = 1;
        input++;
    }

    /* place each BCD digit of the FASC-N in a separate array entry
     * and verify that the parity bit for each BCD digit is correct */
    for (i=0; i < 40; i++) {
        /* Check the parity bit */
        if (((FASCN_bits[5*i] + FASCN_bits[5*i+1] + FASCN_bits[5*i+2] + FASCN_bits[5*i+3] + FASCN_bits[5*i+4]) & 0x01) == 0) {
            print_error("Error: There is a parity error in one or more digits of the encoded FASC-N.");
            return(-1);
        }

        FASCN_digits[i] = FASCN_bits[5*i] + 2*FASCN_bits[5*i+1] + 4*FASCN_bits[5*i+2] + 8*FASCN_bits[5*i+3];
    }

    /* Check all of the digits' values for correctness */

    /* Start Sentinel must be 11 */
    if (FASCN_digits[0] != 11) {
        print_error("Start Sentinel in FASC-N has incorrect value.");
        return(-1);
    }

    /* Agency Code */
    for(i=1; i < 5; i++)
        if (FASCN_digits[i] > 9) {
            print_error("Agency Code in FASC-N contains a non-BCD digit.");
            return(-1);
        }

    /* Field Separator must be 13 */
    if (FASCN_digits[5] != 13) {
        print_error("Field Separator following Agency Code in FASC-N has incorrect value.");
        return(-1);
    }

    /* System Code */
    for(i=6; i < 10; i++)
        if (FASCN_digits[i] > 9) {
            print_error("System Code in FASC-N contains a non-BCD digit.");
            return(-1);
        }

    /* Field Separator must be 13 */
    if (FASCN_digits[10] != 13) {
        print_error("Field Separator following System Code in FASC-N has incorrect value.");
        return(-1);
    }

    /* Credential Number */
    for(i=11; i < 17; i++)
        if (FASCN_digits[i] > 9) {
            print_error("Credential Number in FASC-N contains a non-BCD digit.");
            return(-1);
        }

    /* Field Separator must be 13 */
    if (FASCN_digits[17] != 13) {
        print_error("Field Separator following Credential Number in FASC-N has incorrect value.");
        return(-1);
    }

    /* Credential Series */
    if (FASCN_digits[18] > 9) {
        print_error("Credential Series in FASC-N contains a non-BCD digit.");
        return(-1);
    }

    /* Field Separator must be 13 */
    if (FASCN_digits[19] != 13) {
        print_error("Field Separator following Credential Number in FASC-N has incorrect value.");
        return(-1);
    }

    /* Individual Credential Issue */
    if (FASCN_digits[20] > 9) {
        print_error("Individual Credential Issue in FASC-N contains a non-BCD digit.");
        return(-1);
    }

    /* Field Separator must be 13 */
    if (FASCN_digits[21] != 13) {
        print_error("Field Separator following Credential Number in FASC-N has incorrect value.");
        return(-1);
    }

    /* Person Identifier */
    for(i=22; i < 32; i++)
        if (FASCN_digits[i] > 9) {
            print_error("Person Identifier in FASC-N contains a non-BCD digit.");
            return(-1);
        }

    /* Organizational Category */
    if (FASCN_digits[32] > 9) {
        print_error("Organizational Category in FASC-N contains a non-BCD digit.");
        return(-1);
    }

    /* Organizational Identifier */
    for(i=33; i < 37; i++)
        if (FASCN_digits[i] > 9) {
            print_error("Organizational Identifier in FASC-N contains a non-BCD digit.");
            return(-1);
        }

    /* Person/Organization Association Category */
    if (FASCN_digits[37] > 9) {
        print_error("Person/Organization Association Category in FASC-N contains a non-BCD digit.");
        return(-1);
    }

    /* End Sentinel must be 15 */
    if (FASCN_digits[38] != 15) {
        print_error("End Sentinel in FASC-N has incorrect value.");
        return(-1);
    }

    /* Longitudinal Redundancy Character */
    for(i=0; i < 4; i++) {
        /* total all of the bits in bit position i */
        k=0;
        for(j=0; j < 40; j++) {
            k += FASCN_bits[j*5 + i];
        }
        /* Verify that the parity is even */
        if ((k & 0x01) != 0) {
            print_error("There is a parity error in the Longitudinal Redundancy Character in the FASC-N");
            return(-1);
        }
    }

    return(0);
}

/*
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 */
int validate_OtherName(unsigned char **input, int *input_len)
{
    int tag, OtherName_length, value0_length, value_length;
    char *typeid;

    push_error_stack("OtherName");

    /* Already checked that tag is 0xA0 */
    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    if ((OtherName_length = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }

    *input_len -= OtherName_length;

    if (get_OID(input, &OtherName_length, &typeid) == -1) {
        pop_error_stack();
        return(-1);
    }

    if ((tag = get_tag(input, &OtherName_length)) == -1) {
        pop_error_stack();
        free(typeid);
        return(-1);
    }
    if (tag != 0xA0) {
        print_error("Error:  Incorrect tag for value in OtherName.");
        pop_error_stack();
        free(typeid);
        return(-1);
    }

    if ((value0_length = get_length(input, &OtherName_length)) == -1) {
        pop_error_stack();
        free(typeid);
        return(-1);
    }

    if (value0_length != OtherName_length) {
        print_error("Error: Encoding of OtherName contains extraneous data.");
        pop_error_stack();
        free(typeid);
        return(-1);
    }

    if ((tag = get_tag(input, &value0_length)) == -1) {
        pop_error_stack();
        free(typeid);
        return(-1);
    }
    if ((value_length = get_length(input, &value0_length)) == -1) {
        pop_error_stack();
        free(typeid);
        return(-1);
    }
    if (value_length != value0_length) {
        print_error("Error: Encoding of value in OtherName contains extraneous data.");
        pop_error_stack();
        free(typeid);
        return(-1);
    }

    /* TODO: Check that tag and value are correct for typeid */
    if (strcmp(typeid, "2.16.840.1.101.3.6.6") == 0) {
        /* FASC-N */
        if (tag != 0x04) {
            print_error("Error: FASC-N is not encoded as an OCTET STRING.");
        }
        if (value_length != 25) {
            print_error("Error: FASC-N must be extactly 25 octets.");
        } else {
            validate_FASCN(*input);
        }
    } else if (strcmp(typeid, "1.3.6.1.4.1.311.20.2.3") == 0) {
        /* universalPrincipalName */
        validate_UTF8String(*input, value_length, value_length);
    } else {
        sprintf(error_str, "unknown name form in OtherName: %s.  Contents not checked.", typeid);
        print_error(error_str);
    }

    free(typeid);
    *input += value_length;

    pop_error_stack();
    return(0);
}


int validate_dNSName(unsigned char *input, int input_len)
{
    unsigned char *label, *i;
    int label_length;

    if (input_len > 255) {
        print_error("Error: dNSName longer than 255 octets.");
    }

    i = label = input;
    label_length = 0;
    while (i < input + input_len) {
        if (*i == '.') {
            if ((label == input) && (label_length == 1) && (*label == '*')) {
                /* Don't issue error if first label if a wildcard character */
            } else if (validate_domainlabel(label, label_length) == -1) {
                return(-1);
            }
            i++;
            label = i;
            label_length = 0;
        } else {
            i++;
            label_length++;
        }
    }
    if (validate_domainlabel(label, label_length) == -1) {
        return(-1);
    }

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
int validate_GeneralName(unsigned char **input, int *input_len)
{
    int tag, length, is_empty;
    char *registeredID;
    unsigned char *i;

    push_error_stack("GeneralName");

    if (*input_len == 0) {
        print_error("Error: Expecting a GeneralName, but input is empty.");
        pop_error_stack();
        return(-1);
    }

    tag = **input;

    switch(tag) {
        case 0xA0: /* otherName */
            if (validate_OtherName(input, input_len) == -1) {
                pop_error_stack();
                return(-1);
            }
            break;

        case 0x81: /* rfc822Name */
            push_error_stack("rfc822Name");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            *input_len -= length;

            validate_rfc822Name(*input, length);
            *input += length;
            pop_error_stack();
            break;

        case 0x82: /* dNSName */
            push_error_stack("dNSName");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            *input_len -= length;

            validate_dNSName(*input, length);
            *input += length;
            pop_error_stack();
            break;

        case 0xA3: /* x400Address */
            push_error_stack("x400Address");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            *input_len -= length;

            /* TODO: Verify syntax of x400Address */
            *input += length;
            pop_error_stack();
            break;

        case 0xA4: /* directoryName */
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                return(-1);
            }
            *input_len -= length;

            if (validate_directoryName(input, &length, &is_empty) == -1) {
                pop_error_stack();
                return(-1);
            }

            if (is_empty) {
                print_error("Warning: directoryName is an empty SEQUENCE.");
            }

            if (length > 0) {
                print_error("Error: Encoding of directoryName includes extraneous data.");
                pop_error_stack();
                return(-1);
            }
            break;

        case 0xA5: /* ediPartyName */
            push_error_stack("ediPartyName");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            *input_len -= length;

            /* TODO: Verify syntax of ediPartyName */
            *input += length;
            pop_error_stack();
            break;

        case 0x86: /* uniformResourceIdentifier */
            push_error_stack("uniformResourceIdentifier");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            *input_len -= length;

            validate_URI(*input, length);
            *input += length;
            pop_error_stack();
            break;

        case 0x87: /* iPAddress */
            push_error_stack("iPAddress");
            if ((tag = get_tag(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            if ((length = get_length(input, input_len)) == -1) {
                pop_error_stack();
                pop_error_stack();
                return(-1);
            }
            *input_len -= length;
            *input += length;

            if ((length != 4) && (length != 16)) {
                print_error("Error: iPAddress does not contain a valid IP address.");
            }
            pop_error_stack();
            break;

        case 0x88: /* registeredID */
            push_error_stack("registeredID");
            i = *input;
            *i = 0x06;
            if (get_OID(input, input_len, &registeredID) == -1) {
                *i = 0x88;
                pop_error_stack();
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

    pop_error_stack();
    return(0);
}


/*
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 */
int validate_GeneralNames(unsigned char **input, int *input_len)
{
    int tag, GeneralNames_length;

    push_error_stack("GeneralNames");

    if ((tag = get_tag(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    if (tag != 0x30) {
        print_error("Error: GeneralNames is not encoded as a SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    if ((GeneralNames_length = get_length(input, input_len)) == -1) {
        pop_error_stack();
        return(-1);
    }
    *input_len -= GeneralNames_length;

    if (GeneralNames_length == 0) {
        print_error("Error: GeneralNames is an empty SEQUENCE.");
        pop_error_stack();
        return(-1);
    }

    /* Process GeneralNames one at a time */
    while (GeneralNames_length > 0) {
        if (validate_GeneralName(input, &GeneralNames_length) == -1) {
            pop_error_stack();
            return(-1);
        }
    }

    pop_error_stack();
    return(0);
}


/*
 * Comprehensive X.509 Certificate Parser using NSS
 *
 * This program initializes the NSS library, loads an X.509 certificate
 * from a file (DER or PEM format), parses various fields, and prints
 * detailed information about the certificate, including extensions.
 *
 * Author: [Your Name]
 * Date: [Date]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nss.h>
#include <pk11pub.h>
#include <cert.h>
#include <secerr.h>
#include <ssl.h>
#include <prtime.h>
#include <ctype.h>

/* Function Prototypes */
int initialize_nss(const char *db_path);
CERTCertificate* load_certificate_der(const char *cert_path);
CERTCertificate* load_certificate_pem(const char *cert_path);
void print_certificate_details(CERTCertificate *cert);
void print_name(const char *label, CERTName *name);
void print_serial_number(CERTCertificate *cert);
void print_validity(CERTCertificate *cert);
void print_signature_algorithm(CERTCertificate *cert);
void print_public_key_info(CERTCertificate *cert);
void print_extensions(CERTCertificate *cert);
void print_signature(CERTCertificate *cert);
void print_general_name(CERTGeneralName *gen_name);
void print_key_type(SECKEYPublicKey *pub_key);
void handle_unknown_extension(SECItem *ext_value, const char *ext_name);

/* Error Handling Macro */
#define CHECK_SECSUCCESS(result, message) \
    if ((result) != SECSuccess) { \
        fprintf(stderr, "Error: %s\n", (message)); \
        return NULL; \
    }

/* Main Function */
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <certificate-file> <format: der|pem>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *cert_path = argv[1];
    const char *format = argv[2];
    CERTCertificate *cert = NULL;

    /* Initialize NSS (in-memory database) */
    if (initialize_nss(NULL) != 0) {
        fprintf(stderr, "NSS initialization failed.\n");
        return EXIT_FAILURE;
    }

    /* Load the certificate based on the specified format */
    if (strcasecmp(format, "der") == 0) {
        cert = load_certificate_der(cert_path);
    } else if (strcasecmp(format, "pem") == 0) {
        cert = load_certificate_pem(cert_path);
    } else {
        fprintf(stderr, "Unknown format: %s. Use 'der' or 'pem'.\n", format);
        NSS_Shutdown();
        return EXIT_FAILURE;
    }

    if (!cert) {
        fprintf(stderr, "Failed to load the certificate.\n");
        NSS_Shutdown();
        return EXIT_FAILURE;
    }

    /* Print detailed certificate information */
    print_certificate_details(cert);

    /* Clean up */
    CERT_DestroyCertificate(cert);
    NSS_Shutdown();

    return EXIT_SUCCESS;
}

/*
 * Function: initialize_nss
 * ------------------------
 * Initializes the NSS library. If db_path is NULL, it uses an in-memory
 * database. Otherwise, it initializes NSS with the specified database path.
 *
 * db_path: Path to NSS database directory or NULL for in-memory.
 *
 * returns: 0 on success, -1 on failure.
 */
int initialize_nss(const char *db_path) {
    if (db_path) {
        /* Initialize NSS with a persistent database */
        if (NSS_Init(db_path) != SECSuccess) {
            fprintf(stderr, "NSS_Init failed.\n");
            return -1;
        }
    } else {
        /* Initialize NSS with an in-memory database */
        if (NSS_NoDB_Init(NULL) != SECSuccess) {
            fprintf(stderr, "NSS_NoDB_Init failed.\n");
            return -1;
        }
    }

    return 0;
}

/*
 * Function: load_certificate_der
 * ------------------------------
 * Loads an X.509 certificate from a DER-formatted file.
 *
 * cert_path: Path to the DER certificate file.
 *
 * returns: Pointer to CERTCertificate on success, NULL on failure.
 */
CERTCertificate* load_certificate_der(const char *cert_path) {
    FILE *fp = fopen(cert_path, "rb");
    if (!fp) {
        perror("Failed to open certificate file");
        return NULL;
    }

    /* Determine the file size */
    fseek(fp, 0, SEEK_END);
    long cert_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Allocate memory for the certificate data */
    unsigned char *cert_data = (unsigned char*)malloc(cert_size);
    if (!cert_data) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(fp);
        return NULL;
    }

    /* Read the certificate data */
    if (fread(cert_data, 1, cert_size, fp) != cert_size) {
        fprintf(stderr, "Failed to read certificate data.\n");
        free(cert_data);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    /* Wrap the certificate data in a SECItem */
    SECItem der_cert;
    der_cert.type = siDERCertBuffer;
    der_cert.data = cert_data;
    der_cert.len = cert_size;

    /* Create a temporary certificate object */
    CERTCertificate *cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(),
                                                    &der_cert,
                                                    NULL,
                                                    CERT_VALIDATION_NO_CHECK,
                                                    true);
    free(cert_data); /* Free the raw data as NSS has its own copy */

    if (!cert) {
        fprintf(stderr, "CERT_NewTempCertificate failed.\n");
        return NULL;
    }

    return cert;
}

/*
 * Function: load_certificate_pem
 * -------------------------------
 * Loads an X.509 certificate from a PEM-formatted file.
 *
 * cert_path: Path to the PEM certificate file.
 *
 * returns: Pointer to CERTCertificate on success, NULL on failure.
 */
CERTCertificate* load_certificate_pem(const char *cert_path) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp) {
        perror("Failed to open certificate file");
        return NULL;
    }

    /* Read the entire file into a string */
    fseek(fp, 0, SEEK_END);
    long cert_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *pem_data = (char*)malloc(cert_size + 1);
    if (!pem_data) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(fp);
        return NULL;
    }

    fread(pem_data, 1, cert_size, fp);
    pem_data[cert_size] = '\0';
    fclose(fp);

    /* Locate the PEM boundaries */
    char *begin = strstr(pem_data, "-----BEGIN CERTIFICATE-----");
    if (!begin) {
        fprintf(stderr, "Invalid PEM format: BEGIN CERTIFICATE not found.\n");
        free(pem_data);
        return NULL;
    }
    begin += strlen("-----BEGIN CERTIFICATE-----");

    char *end = strstr(begin, "-----END CERTIFICATE-----");
    if (!end) {
        fprintf(stderr, "Invalid PEM format: END CERTIFICATE not found.\n");
        free(pem_data);
        return NULL;
    }

    /* Calculate Base64 data length */
    size_t base64_len = end - begin;
    char *base64_data = (char*)malloc(base64_len + 1);
    if (!base64_data) {
        fprintf(stderr, "Memory allocation failed.\n");
        free(pem_data);
        return NULL;
    }
    strncpy(base64_data, begin, base64_len);
    base64_data[base64_len] = '\0';

    /* Decode Base64 to DER */
    SECItem der_cert;
    if (PK11_Base64_DecodeString(&der_cert, base64_data, base64_len) != SECSuccess) {
        fprintf(stderr, "Failed to decode PEM certificate.\n");
        free(pem_data);
        free(base64_data);
        return NULL;
    }
    free(pem_data);
    free(base64_data);

    /* Create a temporary certificate object */
    CERTCertificate *cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(),
                                                    &der_cert,
                                                    NULL,
                                                    CERT_VALIDATION_NO_CHECK,
                                                    true);
    PORT_Free(der_cert.data); /* Free the decoded DER data */

    if (!cert) {
        fprintf(stderr, "CERT_NewTempCertificate failed for PEM.\n");
        return NULL;
    }

    return cert;
}

/*
 * Function: print_certificate_details
 * -----------------------------------
 * Prints all relevant details of an X.509 certificate.
 *
 * cert: Pointer to CERTCertificate.
 */
void print_certificate_details(CERTCertificate *cert) {
    if (!cert) {
        fprintf(stderr, "Invalid certificate.\n");
        return;
    }

    printf("=== X.509 Certificate Details ===\n");

    /* Version */
    int version = cert->version + 1; /* Zero-based in structure */
    printf("Version: v%d\n", version);

    /* Serial Number */
    print_serial_number(cert);

    /* Signature Algorithm */
    print_signature_algorithm(cert);

    /* Issuer */
    print_name("Issuer", &cert->issuer);

    /* Validity Period */
    print_validity(cert);

    /* Subject */
    print_name("Subject", &cert->subject);

    /* Subject Public Key Info */
    print_public_key_info(cert);

    /* Extensions */
    print_extensions(cert);

    /* Signature */
    print_signature(cert);

    /* Optional: Print PEM format */
    char *pem = CERT_CertificateToPEM(cert, NULL);
    if (pem) {
        printf("\n--- PEM Format ---\n%s\n", pem);
        PORT_Free(pem);
    }
}

/*
 * Function: print_name
 * --------------------
 * Converts and prints a CERTName structure to an ASCII string.
 *
 * label: Label for the name (e.g., "Issuer", "Subject").
 * name: Pointer to CERTName structure.
 */
void print_name(const char *label, CERTName *name) {
    char *name_ascii = CERT_NameToAscii(name);
    if (name_ascii) {
        printf("%s: %s\n", label, name_ascii);
        PORT_Free(name_ascii);
    } else {
        printf("%s: <Unable to parse>\n", label);
    }
}

/*
 * Function: print_serial_number
 * -----------------------------
 * Retrieves and prints the serial number of the certificate in hexadecimal.
 *
 * cert: Pointer to CERTCertificate.
 */
void print_serial_number(CERTCertificate *cert) {
    SECItem *serial = CERT_GetCertificateSerialNumber(cert);
    if (serial) {
        printf("Serial Number: ");
        for (unsigned int i = 0; i < serial->len; i++) {
            printf("%02X", serial->data[i]);
        }
        printf("\n");
    } else {
        printf("Serial Number: <Unavailable>\n");
    }
}

/*
 * Function: print_validity
 * ------------------------
 * Formats and prints the validity period of the certificate.
 *
 * cert: Pointer to CERTCertificate.
 */
void print_validity(CERTCertificate *cert) {
    char not_before[100], not_after[100];
    PR_FormatTimeString(not_before, sizeof(not_before), PR_T_DATE | PR_T_SHORT, &cert->validity.notBefore);
    PR_FormatTimeString(not_after, sizeof(not_after), PR_T_DATE | PR_T_SHORT, &cert->validity.notAfter);
    printf("Validity:\n");
    printf("  Not Before: %s\n", not_before);
    printf("  Not After : %s\n", not_after);
}

/*
 * Function: print_signature_algorithm
 * -----------------------------------
 * Retrieves and prints the signature algorithm used in the certificate.
 *
 * cert: Pointer to CERTCertificate.
 */
void print_signature_algorithm(CERTCertificate *cert) {
    SECOidTag sig_alg = cert->signature.algorithm;
    const char *alg_name = SECOID_FindOIDByTag(sig_alg);
    if (alg_name) {
        printf("Signature Algorithm: %s\n", alg_name);
    } else {
        printf("Signature Algorithm: Unknown (OID %d)\n", sig_alg);
    }
}

/*
 * Function: print_public_key_info
 * -------------------------------
 * Extracts and prints information about the subject's public key.
 *
 * cert: Pointer to CERTCertificate.
 */
void print_public_key_info(CERTCertificate *cert) {
    printf("Subject Public Key Info:\n");

    /* Determine the public key algorithm */
    SECOidTag pk_alg_tag = cert->subjectPublicKeyInfo.algorithm.ose;
    const char *pk_alg_name = SECOID_FindOIDByTag(pk_alg_tag);
    if (pk_alg_name) {
        printf("  Algorithm: %s\n", pk_alg_name);
    } else {
        printf("  Algorithm: Unknown (OID %d)\n", pk_alg_tag);
    }

    /* Retrieve the public key */
    SECKEYPublicKey *pub_key = CERT_FindPublicKeyFromCert(cert);
    if (!pub_key) {
        printf("  Public Key: <Unavailable>\n");
        return;
    }

    /* Print key-specific information */
    print_key_type(pub_key);

    /* Free the public key structure */
    SECKEY_DestroyPublicKey(pub_key);
}

/*
 * Function: print_key_type
 * ------------------------
 * Prints information specific to the public key type.
 *
 * pub_key: Pointer to SECKEYPublicKey.
 */
void print_key_type(SECKEYPublicKey *pub_key) {
    switch (pub_key->keyType) {
        case rsaKey:
            {
                RSAPublicKey *rsa_pub = pub_key->u.rsa.publicKey;
                if (rsa_pub) {
                    printf("  RSA Key Size: %d bits\n", rsa_pub->len * 8);
                    /* Optionally, print modulus and exponent */
                } else {
                    printf("  RSA Key: <Unavailable>\n");
                }
            }
            break;
        case dsaKey:
            {
                DSAPublicKey *dsa_pub = pub_key->u.dsa.publicKey;
                if (dsa_pub) {
                    printf("  DSA Key Size: %d bits\n", dsa_pub->len * 8);
                    /* Optionally, print p, q, g, and y */
                } else {
                    printf("  DSA Key: <Unavailable>\n");
                }
            }
            break;
        case ecKey:
            {
                EC_KEY *ec_key = pub_key->u.ec.publicKey;
                if (ec_key) {
                    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
                    if (group) {
                        int degree = EC_GROUP_get_degree(group);
                        printf("  EC Key Size: %d bits\n", degree);
                        /* Optionally, print curve name */
                        char *curve_name = NULL;
                        int curve_nid = EC_GROUP_get_curve_name(group);
                        if (curve_nid != NID_undef) {
                            curve_name = OBJ_nid2sn(curve_nid);
                            if (curve_name) {
                                printf("  EC Curve: %s\n", curve_name);
                            }
                        }
                    } else {
                        printf("  EC Key: <Group Unavailable>\n");
                    }
                } else {
                    printf("  EC Key: <Unavailable>\n");
                }
            }
            break;
        /* Add more key types as needed */
        default:
            printf("  Public Key Type: Unknown (%d)\n", pub_key->keyType);
    }
}

/*
 * Function: print_extensions
 * --------------------------
 * Iterates through and prints various certificate extensions.
 *
 * cert: Pointer to CERTCertificate.
 */
void print_extensions(CERTCertificate *cert) {
    printf("Extensions:\n");

    /* Iterate over all extensions in the certificate */
    for (int i = 0; i < cert->extensions.len; i++) {
        SECOidTag tag = cert->extensions.vec[i].id;
        const char *ext_name = SECOID_FindOIDByTag(tag);
        if (!ext_name) {
            ext_name = "Unknown Extension";
        }
        printf("  %s:\n", ext_name);

        /* Handle specific extensions */
        switch (tag) {
            case SEC_OID_X509_KEY_USAGE:
                /* Key Usage Extension */
                {
                    SECItem *ku = &cert->extensions.vec[i].value;
                    if (ku && ku->data && ku->len > 0) {
                        unsigned char bits = ku->data[0];
                        printf("    Key Usage: ");
                        if (bits & KU_DIGITAL_SIGNATURE) printf("Digital Signature ");
                        if (bits & KU_NON_REPUDIATION) printf("Non Repudiation ");
                        if (bits & KU_KEY_ENCIPHERMENT) printf("Key Encipherment ");
                        if (bits & KU_DATA_ENCIPHERMENT) printf("Data Encipherment ");
                        if (bits & KU_KEY_AGREEMENT) printf("Key Agreement ");
                        if (bits & KU_KEY_CERT_SIGN) printf("Certificate Signing ");
                        if (bits & KU_CRL_SIGN) printf("CRL Signing ");
                        if (bits & KU_ENCIPHER_ONLY) printf("Encipher Only ");
                        if (bits & KU_DECIPHER_ONLY) printf("Decipher Only ");
                        printf("\n");
                    } else {
                        printf("    Key Usage: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_EXT_KEY_USAGE:
                /* Extended Key Usage Extension */
                {
                    CERTEXTKeyUsage *eku = (CERTEXTKeyUsage*)CERT_FindCertExtension(cert, tag);
                    if (eku && eku->length > 0) {
                        printf("    Extended Key Usage:\n");
                        for (int j = 0; j < eku->length; j++) {
                            const char *eku_name = SECOID_FindOIDByTag(eku->elements[j]);
                            if (eku_name) {
                                printf("      - %s\n", eku_name);
                            } else {
                                printf("      - Unknown OID (%d)\n", eku->elements[j]);
                            }
                        }
                    } else {
                        printf("    Extended Key Usage: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_SUBJECT_ALT_NAME:
                /* Subject Alternative Name Extension */
                {
                    CERTGeneralName *gen_names = NULL;
                    int num_gen = CERT_GetAltNames(cert, NULL, 0);
                    if (num_gen > 0) {
                        gen_names = (CERTGeneralName*)PORT_ZAlloc(sizeof(CERTGeneralName) * num_gen);
                        if (CERT_GetAltNames(cert, gen_names, num_gen) > 0) {
                            printf("    Subject Alternative Names:\n");
                            for (int j = 0; j < num_gen; j++) {
                                print_general_name(&gen_names[j]);
                            }
                        }
                        PORT_Free(gen_names);
                    } else {
                        printf("    Subject Alternative Names: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_ISSUER_ALT_NAME:
                /* Issuer Alternative Name Extension */
                {
                    CERTGeneralName *gen_names = NULL;
                    int num_gen = CERT_GetIssuerAltNames(cert, NULL, 0);
                    if (num_gen > 0) {
                        gen_names = (CERTGeneralName*)PORT_ZAlloc(sizeof(CERTGeneralName) * num_gen);
                        if (CERT_GetIssuerAltNames(cert, gen_names, num_gen) > 0) {
                            printf("    Issuer Alternative Names:\n");
                            for (int j = 0; j < num_gen; j++) {
                                print_general_name(&gen_names[j]);
                            }
                        }
                        PORT_Free(gen_names);
                    } else {
                        printf("    Issuer Alternative Names: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_BASIC_CONSTRAINTS:
                /* Basic Constraints Extension */
                {
                    CERTBasicConstraints bc;
                    if (CERT_ParseBasicConstraints(cert, &bc)) {
                        printf("    Basic Constraints:\n");
                        printf("      CA: %s\n", bc.isCA ? "TRUE" : "FALSE");
                        if (bc.pathLenConstraint >= 0) {
                            printf("      Path Length Constraint: %d\n", bc.pathLenConstraint);
                        }
                    } else {
                        printf("    Basic Constraints: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_CERTIFICATE_POLICIES:
                /* Certificate Policies Extension */
                {
                    CERTCertificatePolicies policies;
                    if (CERT_ParseCertificatePolicies(cert, &policies)) {
                        printf("    Certificate Policies:\n");
                        for (int j = 0; j < policies.len; j++) {
                            const char *policy_oid = SECOID_FindOIDByTag(policies.policies[j].id);
                            if (policy_oid) {
                                printf("      - %s\n", policy_oid);
                            } else {
                                printf("      - Unknown OID (%d)\n", policies.policies[j].id);
                            }
                        }
                        CERT_DestroyCertificatePolicies(&policies);
                    } else {
                        printf("    Certificate Policies: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_AUTHORITY_INFO_ACCESS:
                /* Authority Information Access Extension */
                {
                    CERTAuthorityInfoAccess aia;
                    if (CERT_ParseAuthorityInfoAccess(cert, &aia)) {
                        printf("    Authority Information Access:\n");
                        for (int j = 0; j < aia.length; j++) {
                            const char *method = NULL;
                            switch (aia.elements[j].method) {
                                case SEC_OID_AUTHORITY_INFO_ACCESS_CA_ISSUERS:
                                    method = "CA Issuers";
                                    break;
                                case SEC_OID_AUTHORITY_INFO_ACCESS_OCSP:
                                    method = "OCSP";
                                    break;
                                default:
                                    method = "Unknown Method";
                            }
                            printf("      - Method: %s, Location: %s\n", method, aia.elements[j].location);
                        }
                        CERT_DestroyAuthorityInfoAccess(&aia);
                    } else {
                        printf("    Authority Information Access: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_CRL_DISTRIBUTION_POINTS:
                /* CRL Distribution Points Extension */
                {
                    CERTCRLDistributionPoints crl_dp;
                    if (CERT_ParseCRLDistributionPoints(cert, &crl_dp)) {
                        printf("    CRL Distribution Points:\n");
                        for (int j = 0; j < crl_dp.length; j++) {
                            printf("      - %s\n", crl_dp.elements[j].uri);
                        }
                        CERT_DestroyCRLDistributionPoints(&crl_dp);
                    } else {
                        printf("    CRL Distribution Points: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_AUTHORITY_KEY_IDENTIFIER:
                /* Authority Key Identifier Extension */
                {
                    CERTAuthorityKeyIdentifier aki;
                    if (CERT_ParseAuthorityKeyIdentifier(cert, &aki)) {
                        printf("    Authority Key Identifier:\n");
                        printf("      Key Identifier: ");
                        for (unsigned int j = 0; j < aki.keyIdentifier.len; j++) {
                            printf("%02X", aki.keyIdentifier.data[j]);
                        }
                        printf("\n");
                        CERT_DestroyAuthorityKeyIdentifier(&aki);
                    } else {
                        printf("    Authority Key Identifier: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_SUBJECT_KEY_IDENTIFIER:
                /* Subject Key Identifier Extension */
                {
                    CERTSubjectKeyIdentifier ski;
                    if (CERT_ParseSubjectKeyIdentifier(cert, &ski)) {
                        printf("    Subject Key Identifier:\n");
                        printf("      Key Identifier: ");
                        for (unsigned int j = 0; j < ski.keyIdentifier.len; j++) {
                            printf("%02X", ski.keyIdentifier.data[j]);
                        }
                        printf("\n");
                        CERT_DestroySubjectKeyIdentifier(&ski);
                    } else {
                        printf("    Subject Key Identifier: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_NAME_CONSTRAINTS:
                /* Name Constraints Extension */
                {
                    CERTNameConstraints nc;
                    if (CERT_ParseNameConstraints(cert, &nc)) {
                        printf("    Name Constraints:\n");
                        /* Permitted Subtrees */
                        for (int j = 0; j < nc.permittedSubtrees.len; j++) {
                            char *subtree = CERT_NameToAscii(&nc.permittedSubtrees.vec[j]);
                            if (subtree) {
                                printf("      Permitted Subtree: %s\n", subtree);
                                PORT_Free(subtree);
                            }
                        }
                        /* Excluded Subtrees */
                        for (int j = 0; j < nc.excludedSubtrees.len; j++) {
                            char *subtree = CERT_NameToAscii(&nc.excludedSubtrees.vec[j]);
                            if (subtree) {
                                printf("      Excluded Subtree: %s\n", subtree);
                                PORT_Free(subtree);
                            }
                        }
                        CERT_DestroyNameConstraints(&nc);
                    } else {
                        printf("    Name Constraints: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_POLICY_CONSTRAINTS:
                /* Policy Constraints Extension */
                {
                    CERTPolicyConstraints pc;
                    if (CERT_ParsePolicyConstraints(cert, &pc)) {
                        printf("    Policy Constraints:\n");
                        if (pc.requireExplicitPolicy) {
                            printf("      Require Explicit Policy: %d\n", pc.requireExplicitPolicy);
                        }
                        if (pc.inhibitPolicyMapping) {
                            printf("      Inhibit Policy Mapping: %d\n", pc.inhibitPolicyMapping);
                        }
                        CERT_DestroyPolicyConstraints(&pc);
                    } else {
                        printf("    Policy Constraints: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_FRESHEST_CRL:
                /* Freshest CRL Extension */
                {
                    CERTFreshestCRL fresher;
                    if (CERT_ParseFreshestCRL(cert, &fresher)) {
                        printf("    Freshest CRL:\n");
                        for (int j = 0; j < fresher.length; j++) {
                            printf("      - %s\n", fresher.elements[j].uri);
                        }
                        CERT_DestroyFreshestCRL(&fresher);
                    } else {
                        printf("    Freshest CRL: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_SUBJECT_INFORMATION_ACCESS:
                /* Subject Information Access Extension */
                {
                    CERTSubjectInfoAccess sia;
                    if (CERT_ParseSubjectInfoAccess(cert, &sia)) {
                        printf("    Subject Information Access:\n");
                        for (int j = 0; j < sia.length; j++) {
                            const char *method = NULL;
                            switch (sia.elements[j].method) {
                                case SEC_OID_SUBJECT_INFO_ACCESS_OCSP:
                                    method = "OCSP";
                                    break;
                                case SEC_OID_SUBJECT_INFO_ACCESS_CA_ISSUERS:
                                    method = "CA Issuers";
                                    break;
                                default:
                                    method = "Unknown Method";
                            }
                            printf("      - Method: %s, Location: %s\n", method, sia.elements[j].location);
                        }
                        CERT_DestroySubjectInfoAccess(&sia);
                    } else {
                        printf("    Subject Information Access: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_POLICY_MAPPINGS:
                /* Policy Mappings Extension */
                {
                    CERTPolicyMappings mappings;
                    if (CERT_ParsePolicyMappings(cert, &mappings)) {
                        printf("    Policy Mappings:\n");
                        for (int j = 0; j < mappings.len; j++) {
                            const char *issuer_policy = SECOID_FindOIDByTag(mappings.mappings[j].issuerPolicy);
                            const char *subject_policy = SECOID_FindOIDByTag(mappings.mappings[j].subjectPolicy);
                            printf("      - Issuer Policy: %s, Subject Policy: %s\n",
                                   issuer_policy ? issuer_policy : "Unknown OID",
                                   subject_policy ? subject_policy : "Unknown OID");
                        }
                        CERT_DestroyPolicyMappings(&mappings);
                    } else {
                        printf("    Policy Mappings: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_INHIBIT_ANY_POLICY:
                /* Inhibit Any Policy Extension */
                {
                    SECUInteger inhibit_any_policy;
                    if (CERT_ParseInhibitAnyPolicy(cert, &inhibit_any_policy)) {
                        printf("    Inhibit Any Policy: %u\n", inhibit_any_policy.value);
                        CERT_DestroyInhibitAnyPolicy(&inhibit_any_policy);
                    } else {
                        printf("    Inhibit Any Policy: <Unavailable>\n");
                    }
                }
                break;

            case SEC_OID_X509_SUBJECT_DIRECTORY_ATTRIBUTES:
                /* Subject Directory Attributes Extension */
                {
                    CERTSubjectDirectoryAttributes sda;
                    if (CERT_ParseSubjectDirectoryAttributes(cert, &sda)) {
                        printf("    Subject Directory Attributes:\n");
                        for (int j = 0; j < sda.len; j++) {
                            const char *attr_oid = SECOID_FindOIDByTag(sda.attributes[j].id);
                            printf("      - Attribute OID: %s\n", attr_oid ? attr_oid : "Unknown OID");
                            /* Additional parsing of attribute values can be implemented here */
                        }
                        CERT_DestroySubjectDirectoryAttributes(&sda);
                    } else {
                        printf("    Subject Directory Attributes: <Unavailable>\n");
                    }
                }
                break;

            /* Add more extensions as needed */

            default:
                /* Handle unknown or custom extensions */
                {
                    SECItem *ext_value = &cert->extensions.vec[i].value;
                    printf("    %s Extension Value (%d bytes):\n      ", ext_name, ext_value->len);
                    for (unsigned int j = 0; j < ext_value->len; j++) {
                        printf("%02X", ext_value->data[j]);
                        if ((j + 1) % 16 == 0 && j + 1 != ext_value->len) {
                            printf("\n      ");
                        }
                    }
                    printf("\n");
                }
                break;
        }
    }
}

/*
 * Function: print_general_name
 * ----------------------------
 * Prints a general name based on its type.
 *
 * gen_name: Pointer to CERTGeneralName.
 */
void print_general_name(CERTGeneralName *gen_name) {
    switch (gen_name->type) {
        case certDNSName:
            printf("      - DNS:%s\n", gen_name->value.dNSName);
            break;
        case certIPAddress:
            printf("      - IP Address:%s\n", gen_name->value.iPAddress);
            break;
        case certURI:
            printf("      - URI:%s\n", gen_name->value.URIName);
            break;
        case certEmailAddress:
            printf("      - Email:%s\n", gen_name->value.emailAddress);
            break;
        case certOtherName:
            printf("      - Other Name: (Type: %d, Value Length: %d bytes)\n",
                   gen_name->value.otherName.typeID,
                   gen_name->value.otherName.value.len);
            /* Optionally, print or parse the otherName value */
            break;
        /* Handle other general name types as needed */
        default:
            printf("      - Unknown General Name Type: %d\n", gen_name->type);
            break;
    }
}

/*
 * Function: print_signature
 * -------------------------
 * Prints the signature algorithm and signature value of the certificate.
 *
 * cert: Pointer to CERTCertificate.
 */
void print_signature(CERTCertificate *cert) {
    printf("Signature:\n");
    print_signature_algorithm(cert);

    /* Signature Value */
    SECItem *sig = &cert->signature.value;
    printf("  Signature Value (%d bytes):\n    ", sig->len);
    for (unsigned int i = 0; i < sig->len; i++) {
        printf("%02X", sig->data[i]);
        /* Format output for readability */
        if ((i + 1) % 16 == 0 && i + 1 != sig->len) {
            printf("\n    ");
        }
    }
    printf("\n");
}

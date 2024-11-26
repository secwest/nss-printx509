#include <stdio.h>
#include <stdlib.h>
#include <nss.h>
#include <pk11pub.h>
#include <cert.h>
#include <secerr.h>
#include <ssl.h>
#include <string.h>
#include <prtime.h>

// Function to initialize NSS
int initialize_nss(const char *db_path) {
    // Initialize NSS with no specific database (use in-memory DB)
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "Failed to initialize NSS\n");
        return -1;
    }
    return 0;
}

// Function to load a certificate from a DER file
CERTCertificate* load_certificate_der(const char *cert_path) {
    FILE *fp = fopen(cert_path, "rb");
    if (!fp) {
        perror("Failed to open certificate file");
        return NULL;
    }

    // Determine the file size
    fseek(fp, 0, SEEK_END);
    long cert_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allocate memory for the certificate
    unsigned char *cert_data = (unsigned char*)malloc(cert_size);
    if (!cert_data) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(fp);
        return NULL;
    }

    // Read the certificate data
    if (fread(cert_data, 1, cert_size, fp) != cert_size) {
        fprintf(stderr, "Failed to read certificate data\n");
        free(cert_data);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    // Import the certificate
    SECItem der_cert;
    der_cert.type = siDERCertBuffer;
    der_cert.data = cert_data;
    der_cert.len = cert_size;

    CERTCertificate *cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(),
                                                    &der_cert,
                                                    NULL,
                                                    CERT_VALIDATION_NO_CHECK,
                                                    true);
    free(cert_data);

    if (!cert) {
        fprintf(stderr, "Failed to parse DER certificate\n");
        return NULL;
    }

    return cert;
}

// Function to load a certificate from a PEM file
CERTCertificate* load_certificate_pem(const char *cert_path) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp) {
        perror("Failed to open certificate file");
        return NULL;
    }

    // Read the entire file into a string
    fseek(fp, 0, SEEK_END);
    long cert_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *pem_data = (char*)malloc(cert_size + 1);
    if (!pem_data) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(fp);
        return NULL;
    }

    fread(pem_data, 1, cert_size, fp);
    pem_data[cert_size] = '\0';
    fclose(fp);

    // Locate the PEM boundaries
    char *begin = strstr(pem_data, "-----BEGIN CERTIFICATE-----");
    if (!begin) {
        fprintf(stderr, "Invalid PEM format: BEGIN CERTIFICATE not found\n");
        free(pem_data);
        return NULL;
    }
    begin += strlen("-----BEGIN CERTIFICATE-----");
    char *end = strstr(begin, "-----END CERTIFICATE-----");
    if (!end) {
        fprintf(stderr, "Invalid PEM format: END CERTIFICATE not found\n");
        free(pem_data);
        return NULL;
    }

    // Calculate Base64 data length
    size_t base64_len = end - begin;
    char *base64_data = (char*)malloc(base64_len + 1);
    if (!base64_data) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pem_data);
        return NULL;
    }
    strncpy(base64_data, begin, base64_len);
    base64_data[base64_len] = '\0';

    // Decode Base64 to DER
    SECItem der_cert;
    if (PK11_Base64_DecodeString(&der_cert, base64_data, base64_len) != SECSuccess) {
        fprintf(stderr, "Failed to decode PEM certificate\n");
        free(pem_data);
        free(base64_data);
        return NULL;
    }
    free(pem_data);
    free(base64_data);

    // Import the certificate
    CERTCertificate *cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(),
                                                    &der_cert,
                                                    NULL,
                                                    CERT_VALIDATION_NO_CHECK,
                                                    true);
    PORT_Free(der_cert.data);

    if (!cert) {
        fprintf(stderr, "Failed to parse DER certificate from PEM\n");
        return NULL;
    }

    return cert;
}

// Function to get version
int get_certificate_version(CERTCertificate *cert) {
    // Version is zero-based: v1=0, v2=1, v3=2
    return cert->version + 1; // To represent as v1, v2, v3
}

// Function to print subject or issuer name
void print_name(const char *label, CERTName *name) {
    char *name_ascii = CERT_NameToAscii(name);
    if (name_ascii) {
        printf("%s: %s\n", label, name_ascii);
        PORT_Free(name_ascii);
    } else {
        printf("%s: <Unable to parse>\n", label);
    }
}

// Function to print serial number
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

// Function to print validity period
void print_validity(CERTCertificate *cert) {
    char not_before[100], not_after[100];
    PR_FormatTimeString(not_before, sizeof(not_before), PR_T_DATE|PR_T_SHORT, &cert->validity.notBefore);
    PR_FormatTimeString(not_after, sizeof(not_after), PR_T_DATE|PR_T_SHORT, &cert->validity.notAfter);
    printf("Validity:\n");
    printf("  Not Before: %s\n", not_before);
    printf("  Not After : %s\n", not_after);
}

// Function to print signature algorithm
void print_signature_algorithm(CERTCertificate *cert) {
    SECOidTag sig_alg = cert->signature.algorithm;
    const char *alg_name = SECOID_FindOIDByTag(sig_alg);
    if (alg_name) {
        printf("Signature Algorithm: %s\n", alg_name);
    } else {
        printf("Signature Algorithm: Unknown (OID %d)\n", sig_alg);
    }
}

// Function to print public key info
void print_public_key_info(CERTCertificate *cert) {
    char *pk_alg = NULL;
    switch(cert->subjectPublicKeyInfo.algorithm.ose)
    {
        case SEC_OID_PKCS1_RSA_ENCRYPTION:
            pk_alg = "RSA";
            break;
        case SEC_OID_EC_PUBLIC_KEY:
            pk_alg = "ECDSA";
            break;
        // Add more algorithms as needed
        default:
            pk_alg = "Unknown";
    }

    printf("Subject Public Key Info:\n");
    printf("  Algorithm: %s\n", pk_alg);
    // Key size
    if (cert->subjectPublicKeyInfo.algorithm.ose == SEC_OID_PKCS1_RSA_ENCRYPTION) {
        // RSA Key
        SECKEYPublicKey *pubKey = CERT_FindPublicKeyFromCert(cert);
        if (pubKey && pubKey->keyType == rsaKey) {
            RSAPublicKey *rsaPub = pubKey->u.rsa.publicKey;
            if (rsaPub) {
                printf("  RSA Key Size: %d bits\n", rsaPub->len * 8);
            }
        }
    } else if (cert->subjectPublicKeyInfo.algorithm.ose == SEC_OID_EC_PUBLIC_KEY) {
        // ECDSA Key
        SECKEYPublicKey *pubKey = CERT_FindPublicKeyFromCert(cert);
        if (pubKey && pubKey->keyType == ecKey) {
            EC_KEY *ecKey = pubKey->u.ec.publicKey;
            if (ecKey) {
                printf("  EC Key Size: %d bits\n", EC_KEY_get0_group(ecKey) ? EC_GROUP_get_degree(EC_KEY_get0_group(ecKey)) : 0);
            }
        }
    }
    // More detailed key info can be added as needed
}

// Function to print extensions
void print_extensions(CERTCertificate *cert) {
    printf("Extensions:\n");

    // Iterate over all extensions
    SECOidTag tag;
    for (int i = 0; i < cert->extensions.len; i++) {
        tag = cert->extensions.vec[i].id;
        const char *ext_name = SECOID_FindOIDByTag(tag);
        if (!ext_name) {
            ext_name = "Unknown Extension";
        }
        printf("  %s:\n", ext_name);

        // Handle specific extensions
        switch(tag) {
            case SEC_OID_X509_KEY_USAGE:
                // Key Usage is a BIT STRING
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
                    }
                }
                break;
            case SEC_OID_X509_EXT_KEY_USAGE:
                // Extended Key Usage
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
                    }
                }
                break;
            case SEC_OID_X509_SUBJECT_ALT_NAME:
                // Subject Alternative Name
                {
                    CERTGeneralName *gen_names = NULL;
                    int num_gen = CERT_GetAltNames(cert, NULL, 0);
                    if (num_gen > 0) {
                        gen_names = (CERTGeneralName*)PORT_ZAlloc(sizeof(CERTGeneralName) * num_gen);
                        if (CERT_GetAltNames(cert, gen_names, num_gen) > 0) {
                            printf("    Subject Alternative Names:\n");
                            for (int j = 0; j < num_gen; j++) {
                                char *name_str = CERT_GenGeneralName(&gen_names[j], CERT_GetDefaultCertDB());
                                if (name_str) {
                                    printf("      - %s\n", name_str);
                                    PORT_Free(name_str);
                                }
                            }
                        }
                        PORT_Free(gen_names);
                    }
                }
                break;
            case SEC_OID_X509_BASIC_CONSTRAINTS:
                // Basic Constraints
                {
                    CERTBasicConstraints bc;
                    if (CERT_ParseBasicConstraints(cert, &bc)) {
                        printf("    Basic Constraints:\n");
                        printf("      CA: %s\n", bc.isCA ? "TRUE" : "FALSE");
                        if (bc.pathLenConstraint >= 0) {
                            printf("      Path Length Constraint: %d\n", bc.pathLenConstraint);
                        }
                    }
                }
                break;
            case SEC_OID_X509_CERTIFICATE_POLICIES:
                // Certificate Policies
                {
                    CERTCertificatePolicies policies;
                    if (CERT_ParseCertificatePolicies(cert, &policies)) {
                        printf("    Certificate Policies:\n");
                        for (int j = 0; j < policies.len; j++) {
                            const char *policy_oid = SECOID_FindOIDByTag(policies.policies[j].id);
                            printf("      - %s\n", policy_oid ? policy_oid : "Unknown OID");
                        }
                        CERT_DestroyCertificatePolicies(&policies);
                    }
                }
                break;
            case SEC_OID_X509_AUTHORITY_INFO_ACCESS:
                // Authority Information Access
                {
                    CERTAuthorityInfoAccess aia;
                    if (CERT_ParseAuthorityInfoAccess(cert, &aia)) {
                        printf("    Authority Information Access:\n");
                        for (int j = 0; j < aia.length; j++) {
                            const char *method = NULL;
                            switch(aia.elements[j].method) {
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
                    }
                }
                break;
            // Add more extensions as needed
            default:
                printf("    <Extension handling not implemented>\n");
                break;
        }
    }
}

// Function to print signature
void print_signature(CERTCertificate *cert) {
    printf("Signature:\n");
    print_signature_algorithm(cert);

    // Signature Value
    SECItem *sig = &cert->signature.value;
    printf("  Signature Value (%d bytes):\n    ", sig->len);
    for (unsigned int i = 0; i < sig->len; i++) {
        printf("%02X", sig->data[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
    }
    printf("\n");
}

// Function to print all certificate details
void print_certificate_details(CERTCertificate *cert) {
    if (!cert) {
        fprintf(stderr, "Invalid certificate\n");
        return;
    }

    printf("=== X.509 Certificate Details ===\n");

    // Version
    int version = get_certificate_version(cert);
    printf("Version: v%d\n", version);

    // Serial Number
    print_serial_number(cert);

    // Signature Algorithm
    print_signature_algorithm(cert);

    // Issuer
    print_name("Issuer", &cert->issuer);

    // Validity
    print_validity(cert);

    // Subject
    print_name("Subject", &cert->subject);

    // Subject Public Key Info
    print_public_key_info(cert);

    // Extensions
    print_extensions(cert);

    // Signature
    print_signature(cert);

    // Optionally, print the entire certificate in PEM format
    char *pem = CERT_CertificateToPEM(cert, NULL);
    if (pem) {
        printf("\n--- PEM Format ---\n%s\n", pem);
        PORT_Free(pem);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <certificate-file> <format: der|pem>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *cert_path = argv[1];
    const char *format = argv[2];
    CERTCertificate *cert = NULL;

    // Initialize NSS
    if (initialize_nss(NULL) != 0) {
        return EXIT_FAILURE;
    }

    // Load the certificate based on format
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
        NSS_Shutdown();
        return EXIT_FAILURE;
    }

    // Print certificate details
    print_certificate_details(cert);

    // Free the certificate
    CERT_DestroyCertificate(cert);

    // Shutdown NSS
    NSS_Shutdown();

    return EXIT_SUCCESS;
}

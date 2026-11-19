#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(void) {
    printf("=== QuantumVault PQC Demo ===\n");

    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");

    if (kem == NULL) {
        printf("Failed to initialize ML-KEM-768\n");
        return 1;
    }

    printf("Algorithm: %s\n", kem->method_name);
    printf("Public key size: %zu bytes\n", kem->length_public_key);
    printf("Secret key size: %zu bytes\n", kem->length_secret_key);
    printf("Ciphertext size: %zu bytes\n", kem->length_ciphertext);
    printf("Shared secret size: %zu bytes\n", kem->length_shared_secret);

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext ||
        !shared_secret_enc || !shared_secret_dec) {
        printf("Memory allocation failed\n");
        return 1;
    }

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("Key generation failed\n");
        return 1;
    }

    printf("\n[1] Keypair generated successfully\n");

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key) != OQS_SUCCESS) {
        printf("Encapsulation failed\n");
        return 1;
    }

    printf("[2] Encapsulation successful\n");

    if (OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key) != OQS_SUCCESS) {
        printf("Decapsulation failed\n");
        return 1;
    }

    printf("[3] Decapsulation successful\n");

    if (memcmp(shared_secret_enc, shared_secret_dec,
              kem->length_shared_secret) == 0) {
        printf("[4] SUCCESS: Shared secrets match!\n");
    } else {
        printf("[4] ERROR: Shared secrets do not match!\n");
        return 1;
    }

    OQS_KEM_free(kem);
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);

    printf("\nQuantumVault PQC test completed successfully!\n");

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main(void) {

    printf("=== QuantumVault Encryption Demo ===\n");

    /* Initialize ML-KEM-768 */
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");

    if (kem == NULL) {
        printf("ML-KEM-768 initialization failed\n");
        return 1;
    }

    /* Allocate cryptographic buffers */
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);

    uint8_t *shared_secret_sender = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_receiver = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext ||
        !shared_secret_sender || !shared_secret_receiver) {
        printf("Memory allocation failed\n");
        return 1;
    }

    /* Generate keypair */
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("Keypair generation failed\n");
        return 1;
    }

    printf("[1] ML-KEM-768 keypair generated\n");

    /* Sender encapsulation */
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_sender,
                       public_key) != OQS_SUCCESS) {
        printf("Encapsulation failed\n");
        return 1;
    }

    printf("[2] Sender established shared secret\n");

    /* Receiver decapsulation */
    if (OQS_KEM_decaps(kem, shared_secret_receiver, ciphertext,
                       secret_key) != OQS_SUCCESS) {
        printf("Receiver decapsulation failed\n");
        return 1;
    }

    printf("[3] Receiver recovered shared secret\n");

    /* Verify both shared secrets match */
    if (memcmp(shared_secret_sender, shared_secret_receiver,
               kem->length_shared_secret) != 0) {
        printf("ERROR: Shared secrets do not match!\n");
        return 1;
    }

    printf("[4] Sender and receiver secrets match!\n");

    /* Original message */
    const char *message =
        "Hello QuantumVault! Protecting data with post-quantum cryptography.";

    int message_len = (int)strlen(message);

    /* AES-GCM buffers */
    uint8_t encrypted[256];
    uint8_t decrypted[256];
    uint8_t nonce[12];
    uint8_t tag[16];

    /* Generate secure random nonce */
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        printf("Nonce generation failed\n");
        return 1;
    }

    printf("[Secure] Random nonce generated\n");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        printf("Cipher context creation failed\n");
        return 1;
    }

    int len = 0;
    int encrypted_len = 0;

    /* AES-256-GCM encryption using sender's shared secret */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL,
                          shared_secret_sender, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, encrypted, &len,
                         (const uint8_t *)message, message_len) != 1) {
        printf("Encryption initialization failed\n");
        return 1;
    }

    encrypted_len = len;

    if (EVP_EncryptFinal_ex(ctx, encrypted + encrypted_len, &len) != 1) {
        printf("Encryption finalization failed\n");
        return 1;
    }

    encrypted_len += len;

    /* Retrieve authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                           sizeof(tag), tag) != 1) {
        printf("Tag retrieval failed\n");
        return 1;
    }

    printf("[5] AES-256-GCM encryption successful\n");
    printf("Original message: %s\n", message);
    printf("Encrypted size: %d bytes\n", encrypted_len);

    /* Receiver decrypts using its independently recovered secret */
    EVP_CIPHER_CTX_reset(ctx);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(nonce), NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL,
                          shared_secret_receiver, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted, &len,
                         encrypted, encrypted_len) != 1) {
        printf("Decryption initialization failed\n");
        return 1;
    }

    int decrypted_len = len;

    /* Verify authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                           sizeof(tag), tag) != 1) {
        printf("Tag setting failed\n");
        return 1;
    }

    if (EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &len) != 1) {
        printf("Decryption failed: authentication error\n");
        return 1;
    }

    decrypted_len += len;
    decrypted[decrypted_len] = '\0';

    printf("[6] AES-256-GCM decryption successful\n");
    printf("Decrypted message: %s\n", decrypted);

    /* Verify original message */
    if (strcmp(message, (char *)decrypted) == 0) {
        printf("[7] SUCCESS: Original message recovered!\n");
    } else {
        printf("[7] ERROR: Message mismatch!\n");
        return 1;
    }

    /* Cleanup */
    EVP_CIPHER_CTX_free(ctx);
    OQS_KEM_free(kem);

    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_sender);
    free(shared_secret_receiver);

    printf("\nQuantumVault encryption test completed successfully!\n");

    return 0;
}

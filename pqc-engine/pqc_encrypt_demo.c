#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main(void) {
    printf("=== QuantumVault Encryption Demo ===\n");

    int result = 1;
    OQS_KEM *kem = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_sender = NULL;
    uint8_t *shared_secret_receiver = NULL;

    uint8_t encrypted[256] = {0};
    uint8_t decrypted[256] = {0};
    uint8_t nonce[12] = {0};
    uint8_t tag[16] = {0};

    int len = 0;
    int encrypted_len = 0;
    int decrypted_len = 0;

    kem = OQS_KEM_new("ML-KEM-768");

    if (kem == NULL) {
        printf("ML-KEM-768 initialization failed\n");
        goto cleanup;
    }

    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    ciphertext = malloc(kem->length_ciphertext);
    shared_secret_sender = malloc(kem->length_shared_secret);
    shared_secret_receiver = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext ||
        !shared_secret_sender || !shared_secret_receiver) {
        printf("Memory allocation failed\n");
        goto cleanup;
    }

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("Keypair generation failed\n");
        goto cleanup;
    }

    printf("[1] ML-KEM-768 keypair generated\n");

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_sender,
                       public_key) != OQS_SUCCESS) {
        printf("Encapsulation failed\n");
        goto cleanup;
    }

    printf("[2] Sender established shared secret\n");

    if (OQS_KEM_decaps(kem, shared_secret_receiver, ciphertext,
                       secret_key) != OQS_SUCCESS) {
        printf("Receiver decapsulation failed\n");
        goto cleanup;
    }

    printf("[3] Receiver recovered shared secret\n");

    if (memcmp(shared_secret_sender, shared_secret_receiver,
               kem->length_shared_secret) != 0) {
        printf("ERROR: Shared secrets do not match!\n");
        goto cleanup;
    }

    printf("[4] Sender and receiver secrets match!\n");

    const char *message =
        "Hello QuantumVault! Protecting data with post-quantum cryptography.";

    int message_len = (int)strlen(message);

    if (message_len >= (int)sizeof(encrypted)) {
        printf("Message is too large for encryption buffer\n");
        goto cleanup;
    }

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        printf("Nonce generation failed\n");
        goto cleanup;
    }

    printf("[Secure] Random nonce generated\n");

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        printf("Cipher context creation failed\n");
        goto cleanup;
    }

    /* AES-256-GCM encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL,
                          shared_secret_sender, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, encrypted, &len,
                         (const uint8_t *)message, message_len) != 1) {
        printf("Encryption initialization failed\n");
        goto cleanup;
    }

    encrypted_len = len;

    if (EVP_EncryptFinal_ex(ctx, encrypted + encrypted_len, &len) != 1) {
        printf("Encryption finalization failed\n");
        goto cleanup;
    }

    encrypted_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                           sizeof(tag), tag) != 1) {
        printf("Tag retrieval failed\n");
        goto cleanup;
    }

    printf("[5] AES-256-GCM encryption successful\n");
    printf("Original message: %s\n", message);
    printf("Encrypted size: %d bytes\n", encrypted_len);

    /* Receiver decrypts using recovered shared secret */
    if (EVP_CIPHER_CTX_reset(ctx) != 1) {
        printf("Cipher context reset failed\n");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                           sizeof(nonce), NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL,
                          shared_secret_receiver, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted, &len,
                         encrypted, encrypted_len) != 1) {
        printf("Decryption initialization failed\n");
        goto cleanup;
    }

    decrypted_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                           sizeof(tag), tag) != 1) {
        printf("Tag setting failed\n");
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &len) != 1) {
        printf("Decryption failed: authentication error\n");
        goto cleanup;
    }

    decrypted_len += len;

    if (decrypted_len >= (int)sizeof(decrypted)) {
        printf("Decrypted message exceeds buffer size\n");
        goto cleanup;
    }

    decrypted[decrypted_len] = '\0';

    printf("[6] AES-256-GCM decryption successful\n");
    printf("Decrypted message: %s\n", decrypted);

    if (strcmp(message, (char *)decrypted) != 0) {
        printf("[7] ERROR: Message mismatch!\n");
        goto cleanup;
    }

    printf("[7] SUCCESS: Original message recovered!\n");
    printf("\nQuantumVault encryption test completed successfully!\n");

    result = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OQS_KEM_free(kem);

    free(public_key);
    OQS_MEM_secure_free(secret_key,
                       kem != NULL ? kem->length_secret_key : 0);
    free(ciphertext);

    OQS_MEM_secure_free(shared_secret_sender,
                       kem != NULL ? kem->length_shared_secret : 0);
    OQS_MEM_secure_free(shared_secret_receiver,
                       kem != NULL ? kem->length_shared_secret : 0);

    OQS_MEM_cleanse(encrypted, sizeof(encrypted));
    OQS_MEM_cleanse(decrypted, sizeof(decrypted));
    OQS_MEM_cleanse(nonce, sizeof(nonce));
    OQS_MEM_cleanse(tag, sizeof(tag));

    return result;
}

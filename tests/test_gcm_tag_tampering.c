#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main(void) {
    printf("=== QuantumVault AES-GCM Tag Tampering Test ===\n");

    int result = 1;
    EVP_CIPHER_CTX *ctx = NULL;

    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t tag[16] = {0};
    uint8_t ciphertext[256] = {0};
    uint8_t decrypted[256] = {0};

    int len = 0;
    int ciphertext_len = 0;
    int decrypted_len = 0;

    const char *message = "QuantumVault authentication tag test";
    int message_len = (int)strlen(message);

    /* Generate random key and nonce */
    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(nonce, sizeof(nonce)) != 1) {
        printf("Random key/nonce generation failed\n");
        goto cleanup;
    }

    printf("[1] Random key and nonce generated\n");

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        printf("Cipher context creation failed\n");
        goto cleanup;
    }

    /* Encrypt message */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &len,
                         (const uint8_t *)message, message_len) != 1) {
        printf("Encryption failed\n");
        goto cleanup;
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1) {
        printf("Encryption finalization failed\n");
        goto cleanup;
    }

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            sizeof(tag), tag) != 1) {
        printf("Tag retrieval failed\n");
        goto cleanup;
    }

    printf("[2] Message encrypted and authentication tag generated\n");

    /* Tamper with the authentication tag */
    tag[0] ^= 0x01;

    printf("[3] Authentication tag modified intentionally\n");

    /* Attempt decryption with modified tag */
    if (EVP_CIPHER_CTX_reset(ctx) != 1 ||
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                          NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, decrypted, &len,
                         ciphertext, ciphertext_len) != 1) {
        printf("Decryption setup failed\n");
        goto cleanup;
    }

    decrypted_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            sizeof(tag), tag) != 1) {
        printf("Tag setting failed\n");
        goto cleanup;
    }

    /* Authentication must fail with the modified tag */
    if (EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &len) != 1) {
        printf("[4] SUCCESS: Tag tampering detected!\n");
        printf("[5] Authentication failed — modified tag rejected.\n");
        result = 0;
        goto cleanup;
    }

    decrypted_len += len;

    printf("ERROR: Modified authentication tag was accepted!\n");
    printf("Decrypted data: %.*s\n", decrypted_len, decrypted);

cleanup:
    EVP_CIPHER_CTX_free(ctx);

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
    OPENSSL_cleanse(decrypted, sizeof(decrypted));

    return result;
}

#ifndef SECURITY_H
#define SECURITY_H

#include <openssl/aes.h>
#include <string.h>
#include <stdlib.h>

#define AES_KEY_STR "1234567890123456"  // 16-byte key (128-bit)

// Helper: pad length to nearest multiple of AES_BLOCK_SIZE (16)
int pad_length(int len) {
    int remainder = len % AES_BLOCK_SIZE;
    return remainder == 0 ? len : len + (AES_BLOCK_SIZE - remainder);
}

// Encrypt data in-place (with padding)
int aes_encrypt(char *data, int len) {
    AES_KEY enc_key;  
    AES_set_encrypt_key((const unsigned char*)AES_KEY_STR, 128, &enc_key);

    int padded_len = pad_length(len);

    // Pad with spaces (simple padding for coursework)
    for (int i = len; i < padded_len; i++) {
        data[i] = ' ';
    }

    for (int i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        AES_encrypt((unsigned char*)data + i,
                    (unsigned char*)data + i,
                    &enc_key);
    }
    return padded_len; // return new length after padding
}

// Decrypt data in-place
void aes_decrypt(char *data, int len) {
    AES_KEY dec_key;   // Correct struct type
    AES_set_decrypt_key((const unsigned char*)AES_KEY_STR, 128, &dec_key);

    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        AES_decrypt((unsigned char*)data + i,
                    (unsigned char*)data + i,
                    &dec_key);
    }

    // Trim trailing spaces from padding
    for (int i = len - 1; i >= 0; i--) {
        if (data[i] == ' ') {
            data[i] = '\0';
        } else {
            break;
        }
    }
}

#endif

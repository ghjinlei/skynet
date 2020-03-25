#ifndef __RC4_H
#define __RC4_H

#include <stdint.h>

struct rc4_state {
    uint8_t s[256];
    int i;
    int j;
};

typedef struct rc4_state rc4_state_t;

/**
 * init a rc4 state
 */
void rc4_init(rc4_state_t *state, const uint8_t *key, int keysize);

/**
 * create and init a rc4 state
 * rc4_state_t memory will create with molloc, use rc4_state_init if you have custom molloc/free
 */
rc4_state_t *rc4_create(const uint8_t *key, int keysize);

/**
 * encrypt/decrypt data
 */
void rc4_crypt(rc4_state_t *state, const uint8_t *in, uint8_t *out, int buflen);

/**
 * destroy(free) a rc4 state
 */
void rc4_destroy(rc4_state_t *state);

#endif

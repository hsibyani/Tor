#ifndef TOR_RENDAUTH_H
#define TOR_RENDAUTH_H

// Contains password based authorization info for hidden services in clear form.
typedef struct {
  char* username; // not null-terminated
  size_t username_len; // username length
  char* password;
  size_t password_len;
} rend_auth_password_t;

//AUTH_KEY content contains the public introduction point authentication key.
typedef struct{
	  size_t size;
	  uint8_t content[4];
} auth_keyid;

//ENC_KEY content contains the public introduction point encryption key.
typedef struct{
	  size_t size;
	  uint8_t content[4];
} enc_keyid;

int rend_auth_add_user (const char* filename, smartlist_t* new_users,
                        int hash_method);

int verify_auth_signature(const ed25519_signature_t *signature,
                            const ed25519_public_key_t *pubkey,
                            const uint8_t *msg);

int create_auth_signature(const ed25519_keypair_t *keypair,
                                 const auth_keyid *auth,
                                 const enc_keyid *enc,
                                 const ed25519_signature_t *sig);

int create_auth_signature_testing(const ed25519_keypair_t *keypair,
                                 const auth_keyid *auth,
                                 const enc_keyid *enc,
                                 const ed25519_signature_t *sig,
				 const char *nonce);

#endif

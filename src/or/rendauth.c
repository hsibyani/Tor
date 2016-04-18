#include "or.h"
#include "rendauth.h"
#include "container.h"
#include "crypto.h"
#include "crypto_ed25519.h"

/*
 * This section deals with authentication users through introduction-points
 * using usernames and passwords.
 * The passwords are hashed using one of the hash methods provided. The file is
 * stored in a human readable format of one user per line:
 * username:salt:hash:hash_method
 * Empty lines are ignored. Poorly formatted lines are also ignored with a
 * warning.
 * The salt and the hash are stored in base-64.
 * The username can only have printable ascii characters that are not a colon
 * or a new line.
 * The hash_method is stored in base-64 according to the values on the enum.
 * hash_method possible values:
 * - SCRYPT_LOW: scrypt with (N,r,p) = (512,8,1) resulting in 512KB of memory
 * usage per hash. Using a 16 byte salt and resulting in a 32 bit key.
 */

struct rend_auth_password_hashed_t {
  char* username;
  size_t username_len;
  uint8_t* salt;
  size_t salt_len;
  uint8_t* hash;
  size_t hash_len;
};

struct auth_keyid{
  uint8_t* content;
}

struct enc_keyid{
  uint8_t* content;
}

static int hash_user (struct rend_auth_password_t*,
                       struct rend_auth_password_hashed_t*,
                       enum rend_auth_hash_method_t);
static int add_to_file(FILE* password_file,
                      struct rend_auth_password_hashed_t* hashed_data,
                      enum rend_auth_hash_method_t hash_method);

/**
 * Add the usernames and hashed salts and passwords used for
 * authenticating users through the introduction-points to the file referred to
 * by the null-terminated string <b>filename</b>. Read the usernames as
 * "struct rend_auth_password_t*" from <b>new_users</b>. Use method specified
 * in
 * Return 0 on success, -1 on failure.
 */
int rend_auth_add_user (const char* filename, smartlist_t* new_users,
                        enum rend_auth_hash_method_t hash_method)
{
  FILE* password_file = fopen(filename, "a");
  if (password_file == NULL) {
    // TODO log error
    return -1;
  }
  // TODO : wipe the unhashed user data from memory?
  // TODO : parallelize
  SMARTLIST_FOREACH(new_users, struct rend_auth_password_t*, user_data, {
    struct rend_auth_password_hashed_t* hashed_data =
        tor_malloc(sizeof(struct rend_auth_password_hashed_t*));
    if (hash_user(user_data, hashed_data, hash_method) == -1){
      // TODO : log error
      return -1;
    }
    // TODO : write to file
    (void) filename;
  });
  // TODO: check that file closed? what to do
  fclose(password_file);
  return 0;
}

static int add_to_file(FILE* password_file,
                       struct rend_auth_password_hashed_t* hashed_data,
                       enum rend_auth_hash_method_t hash_method)
{
  int b64_flags = 0;
  size_t b64_size_salt = base64_encode_size(hashed_data->salt_len, b64_flags),
         b64_size_hash = base64_encode_size(hashed_data->hash_len, b64_flags),
         b64_size_method = base64_encode_size(sizeof(int), b64_flags);
  char *b64_salt = tor_malloc(b64_size_salt),
       *b64_hash = tor_malloc(b64_size_hash),
       *b64_method = tor_malloc(b64_size_method);
  int method = (int) hash_method;
  base64_encode(b64_salt, b64_size_salt, (const char*)hashed_data->salt,
                hashed_data->salt_len, b64_flags);
  base64_encode(b64_hash, b64_size_hash, (const char*)hashed_data->hash,
                hashed_data->hash_len, b64_flags);
  base64_encode(b64_method, b64_size_method, (const char*)&method,
                sizeof(int), b64_flags);
  // TODO : implement the rest
  return -1;
}


/**
 * Hash <b>user_data</b> and puts it into <b>hashed_data</b>.
 * No <b>hashed_data</b> pointers will equal <b>user_data</b> pointers.
 * Return 0 on success, -1 on failure.
 */
static int hash_user (struct rend_auth_password_t* user_data,
                      struct rend_auth_password_hashed_t* hashed_data,
                      enum rend_auth_hash_method_t hash_method)
{
  switch (hash_method) {
    case REND_AUTH_HASH_SCRYPT_LOW:; // HACK: no declaration after label
      size_t hash_len = 32, salt_len = 16;
      uint64_t N = 512;
      uint32_t r = 8, p = 1;
      hashed_data->username =
          tor_malloc(sizeof(char) * user_data->username_len);
      strlcpy(hashed_data->username, user_data->username,
              user_data->username_len);
      hashed_data->salt = tor_malloc(sizeof(uint8_t) * salt_len);
      hashed_data->hash = tor_malloc(sizeof(uint8_t) * hash_len);
      hashed_data->salt_len = salt_len;
      hashed_data->hash_len = hash_len;
      crypto_rand((char*)hashed_data->salt, salt_len);
      return crypto_scrypt(hashed_data->hash, hash_len,
                           user_data->password, user_data->password_len,
                           hashed_data->salt, salt_len,
                           N, r, p);
      break;
    default:
      return -1;
  }
}
static const char *str_userauth_ed25519 = "hidserv-userauth-ed25519";

/**
 * Generate an authorization siganture.Given a <b>keypair</b> 
 * an <b>AUTH_KEYID</b> and an <b>ENC_KEYID</b> the function will
 * generate the signature.
 * Return 0 on success and -1 on failure.
 */
static int create_auth_signature(const ed25519_keypair_t *keypair,
				 const auth_keyid *auth, 
				 const enc_keyid *enc
				 ed25519_siganture_t *sig)
{
  char rnd[256];
  char *to_sign_block = NULL;
  crypto_rand(*rnd, sizeof(rnd));
  char sha256digest[DIGEST256_LEN];
  crypto_digest256(sha256digest, rnd, sizeof(rnd), DIGEST_SHA256);

      //  "hidserv-userauth-ed25519"
      //  Nonce       (same as above)
      //  Pubkey      (same as above)
      //  AUTH_KEYID  (As in the INTRODUCE1 cell)
      //  ENC_KEYID   (As in the INTRODUCE1 cell)

  smartlist_t *block = smartlist_new();
  smartlist_add(block, str_userauth_ed25199);

  char nonce[16];
  memcpy(nonce, sha256digest, 16);

  smartlist_add(block, nonce);

  char ed_pub_b64[ED25519_BASE64_LEN + 1];
  ret = ed25519_public_to_base64(ed_pub_b64, &keypair->pubkey);

  if (ret < 0) {
    log_warn(LD_BUG, "Can't base64 encode ed25199 public key!");
    goto err;
  }

  smartlist_add(block, ed_pub_b64);
  smartlist_add(block, auth);
  smartlist_add(block, enc);
  to_sign_block = smartlist_join_strings(block, "", 0, NULL);
  return ed25519_sign(&sig, to_sign_block, sizeof(to_sign_block), &keypair);
}

/**
 * Verify <b>signature</b> of a <b>msg</b> and a <b>pubkey</b>.
 * Return 0 if signature is valid, -1 if not.
 */
static int verify_signature(const ed25519_signature_t *signature, 
			    const ed25519_public_key_t *pubkey,
			    const uint8_t *msg)
{
  return ed25519_checksig(signature, msg, sizeof(*msg), pubkey);
}

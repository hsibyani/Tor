#include "or.h"
#include "rendauth.h"
#include "crypto.h"
#include "crypto_s2k.h"

/*
 * This section deals with authentication users through introduction-points
 * using usernames and passwords.
 * Hashing and salting is done using the secret_to_key_new and
 * secret_to_key_check of crypto_s2k.
 * The passwords are hashed using one of the methods provided by the
 * secret_to_key_new flag. The file is stored in a human readable format of one
 * user per line in the following format; username:hash_info
 * Empty lines are ignored. Poorly formatted lines are also ignored with a
 * warning.
 * hash_info contains the hash of the password, the salt, and the parameters
 * stored in base-64. It corresponds to the output of secret_to_key_new in
 * crypto_s2k.
 * The username can only have printable ascii characters that are not a colon
 * or a new line.
 */

typedef struct {
  char *username; // needs to be null-terminated
  uint8_t *hash_info;
  size_t hash_info_len;
} rend_auth_password_hashed_t;

static int hash_user (rend_auth_password_t*,
                      rend_auth_password_hashed_t*,
                      unsigned hash_method);
static int add_to_file(FILE*,
                      rend_auth_password_hashed_t*);
static void clean_hash (rend_auth_password_hashed_t*);

// TODO: authenticate and store in memory

/**
 * Add the usernames and hashed salts and passwords used for
 * authenticating users through the introduction-points to the file referred to
 * by the null-terminated string <b>filename</b>. Read the usernames as
 * "struct rend_auth_password_t*" from <b>new_users</b>. Hashes according to
 * <b>hash_method</b>. Details found in section comment.
 * Return 0 on success, -1 on failure.
 */
int rend_auth_add_user (const char* filename, smartlist_t* new_users,
                        int hash_method)
{
  FILE* password_file = fopen(filename, "a");
  if (password_file == NULL) {
    // TODO log error
    return -1;
  }
  // TODO : wipe the unhashed user data from memory?
  // TODO : parallelize
  // TODO : verify usernames?
  SMARTLIST_FOREACH(new_users, rend_auth_password_t*, user_data, {
    rend_auth_password_hashed_t* hashed_data =
        tor_malloc(sizeof(rend_auth_password_hashed_t));
    if (hash_user(user_data, hashed_data, hash_method) == -1) {
      // TODO : log error
      return -1;
    }
    if (add_to_file(password_file, hashed_data) == -1) {
      // TODO : log error
      return -1;
    }
    clean_hash(hashed_data);
    tor_free(hashed_data);
  });
  // TODO: check that file closed? what to do
  fclose(password_file);
  return 0;
}


/**
 * Appends the hashed user data in <b>hashed_data</b> to the file in
 * <b>password_file</b>.
 */
static int add_to_file(FILE* password_file,
                       rend_auth_password_hashed_t* hashed_data)
{
  // TODO : make sure this is correct
  int b64_flags = 0;
  size_t b64_size_hash = base64_encode_size(hashed_data->hash_info_len,
                                            b64_flags);
  char *b64_hash = tor_malloc(b64_size_hash);
  int result = base64_encode(b64_hash, b64_size_hash,
                             (const char*)hashed_data->hash_info,
                             hashed_data->hash_info_len, b64_flags);
  if (result < 0) {
    tor_free(b64_hash);
    return -1;
  }
  int written = fprintf(password_file, "\n%s:%s", hashed_data->username,
                        b64_hash);
  tor_free(b64_hash);
  if (written < 0)
    return -1;
  return 0;
}


/**
 * Hashes <b>user_data</b> and puts it into <b>hashed_data</b>.
 * No <b>hashed_data</b> pointers will equal <b>user_data</b> pointers.
 * Returns 0 on success, -1 on failure. On success, call clean_hash to clean up
 * allocated memory.
 */
static int hash_user (rend_auth_password_t *user_data,
                      rend_auth_password_hashed_t *hashed_data,
                      unsigned hash_method)
{
  int buffer_len = secret_to_key_output_length(hash_method);
  hashed_data->username = tor_malloc(user_data->username_len + 1);
  strlcpy(hashed_data->username, user_data->username,
          user_data->username_len + 1);
  hashed_data->hash_info = tor_malloc(buffer_len);
  hashed_data->hash_info_len = buffer_len;
  size_t len_out;
  int hash_result = secret_to_key_new(hashed_data->hash_info,
                                      hashed_data->hash_info_len,
                                      &len_out, user_data->password,
                                      user_data->password_len, hash_method);
  hashed_data->hash_info_len = len_out;
  if (hash_result == S2K_OKAY)
    return 0;
  else {
    tor_free(hashed_data->username);
    return -1;
  }
}

/**
 * Cleans heap data inside the <b>hashed_data</b> structure.
 */
static void clean_hash(rend_auth_password_hashed_t *hashed_data) {
  tor_free(hashed_data->username);
  tor_free(hashed_data->hash_info);
}

static const char *str_userauth_ed25519 = "hidserv-userauth-ed25519";

/**
 * Generate an authorization siganture.Given a <b>keypair</b>
 * an <b>AUTH_KEYID</b> and an <b>ENC_KEYID</b> the function will
 * generate the signature.
 * Return 0 on success and -1 on failure.
 */
static int create_auth_signature(const ed25519_keypair_t *keypair,
				 AUTH_KEYID,
				 ENC_KEYID)
{
  char rnd[256];
  char *to_sign_block = NULL;
  ed25519_signature_t sig;
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
  smartlist_add(block, AUTH_KEYID);
  smartlist_add(block, ENC_KEYID);
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

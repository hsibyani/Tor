#include "or.h"
#include "rendauth.h"
#include "container.h"
#include "crypto.h"
#include "crypto_s2k.h"
#include "crypto_ed25519.h"

/*
 * This section deals with authentication users through introduction-points
 * using usernames and passwords.
 * Hashing and salting is done using the secret_to_key_new and
 * secret_to_key_check of crypto_s2k.
 * The passwords are hashed using one of the methods provided by the
 * secret_to_key_new flag. The file is stored in a human readable format of one
 * user per line in the following format; username:hash_info
 * Empty lines are ignored. Poorly formatted lines are also ignored with a
 * warning. Whitespace after the colon is ignored.
 * hash_info contains the hash of the password, the salt, and the parameters
 * stored in base-64. It corresponds to the output of secret_to_key_new in
 * crypto_s2k.
 * The username can only have printable ascii characters that are not a colon
 * or a new line. They are not surrounded with whitespace.
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

static strmap_t *user_to_hash_map = NULL;

static int parse_line (const char *line,
                       rend_auth_password_hashed_t *hashed_data) {
  // Since a colon at the beginning of the line is invalid, we initially set
  // the colon size to be 0, signifying that we haven't found the seperating
  // colon yet.
  int colon_position = 0;
  int i, line_length; // i iterator, at the end corresponds to line_length
  int b64_hash_length;
  for (i = 0; line[i] != '\0'; i++) {
    if (!colon_position) {
      // We have not found the colon yet
      if (line[i] == ':' && i == 0)
        return -1; // Colon at the beginning
      if (line[i] != ':' && !isprint(line[i]))
        return -1; // non-printable character in the username, invalid
      if (line[i] == ':')
        colon_position = i; // We found the seperator
    } else if (line[i] == ':')
      return -1; // Double seperator
  }
  line_length = i;
  b64_hash_length = line_length - colon_position - 1;
  hashed_data->username = tor_malloc(colon_position);
  memcpy(hashed_data->username, line, colon_position);
  // Create a buffer to hold the hash, maximum size
  size_t max_size_hash_info = (b64_hash_length * 3)/4;
  hashed_data->hash_info = tor_malloc(max_size_hash_info);
  // ignores whitespace
  int n_bytes = base64_decode(hashed_data->hash_info, max_size_hash_info,
                              line + colon_position + 1, b64_hash_length);
  if (n_bytes < 0) {
    clean_hash(hashed_data);
    return -1;
  }
  hashed_data->hash_info_len = n_bytes;
  return 0;
}

static int load_users (const char *filename) {
  FILE* password_file = fopen(filename, "r");
  char* line;
  size_t length;
  // TODO : check if loading error or EOF
  while (getline(&line, &length, password_file) >= 0) {
    line[length - 1] = '\0';
    length--;
    // First check if line is empty
    int i, empty = 1;
    for (i = 0; i < length; i++)
      if (!isspace(line[i])){
        empty = 0;
        break;
      }
    if (!empty) {
      // TODO : call parse_line
    }
  }
}

/**
 * Add the usernames and hashed salts and passwords used for
 * authenticating users through the introduction-points to the file referred to
 * by the null-terminated string <b>filename</b>. Read the usernames as
 * "struct rend_auth_password_t*" from <b>new_users</b>. Hashes according to
 * <b>hash_method</b>. Details found in section comment.
 * Return 0 on success, -1 on failure.
 */
int rend_auth_add_user (const char *filename, smartlist_t *new_users,
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
int create_auth_signature(const ed25519_keypair_t *keypair,
                                 const auth_keyid *auth,
                                 const enc_keyid *enc,
                                 const ed25519_signature_t *sig)
{
  crypto_digest_t *digest = crypto_digest256_new(DIGEST_SHA256);
  crypto_digest_add_bytes(digest, "hidserv-userauth-ed25519", 24);

  char nonce[16];
  crypto_rand(nonce, 16);
  crypto_digest_add_bytes(digest, nonce, 16);
  crypto_digest_add_bytes(digest, &keypair->pubkey, 32);
  crypto_digest_add_bytes(digest, auth->content, 4);
  crypto_digest_add_bytes(digest, enc->content, 4);

  uint8_t hashed_block[DIGEST256_LEN];
  crypto_digest_get_digest(digest, hashed_block, DIGEST256_LEN);
  return ed25519_sign(sig, hashed_block, DIGEST256_LEN, keypair);
}


/**
 * This function should only be used for testing.
 * Generate an authorization siganture.Given a <b>keypair</b>
 * an <b>AUTH_KEYID</b> and an <b>ENC_KEYID</b> the function will
 * generate the signature. This method includes a nonce as input
 * which is to be used only in testing.
 * Return 0 on success and -1 on failure.
 */
int create_auth_signature_testing(const ed25519_keypair_t *keypair,
				 const auth_keyid *auth,
				 const enc_keyid *enc,
				 const ed25519_signature_t *sig,
				 const char *nonce)
{
  crypto_digest_t *digest = crypto_digest256_new(DIGEST_SHA256);
  crypto_digest_add_bytes(digest, "hidserv-userauth-ed25519", 24);
  crypto_digest_add_bytes(digest, nonce, 16);
  crypto_digest_add_bytes(digest, &keypair->pubkey, 32);
  crypto_digest_add_bytes(digest, auth->content, 4);
  crypto_digest_add_bytes(digest, enc->content, 4);

  uint8_t hashed_block[DIGEST256_LEN];
  crypto_digest_get_digest(digest, hashed_block, DIGEST256_LEN);
  return ed25519_sign(sig, hashed_block, DIGEST256_LEN, keypair);
}

/**
 * Verify <b>signature</b> of a <b>msg</b> and a <b>pubkey</b>.
 * Return 0 if signature is valid, -1 if not.
 */
int verify_signature(const ed25519_signature_t *signature,
			    const ed25519_public_key_t *pubkey,
			    const uint8_t *msg)
{
  size_t strleng = strlen((const char*)msg);
  return ed25519_checksig(signature, msg, strleng, pubkey);
}

#ifndef TOR_RENDAUTH_H
#define TOR_RENDAUTH_H

// Contains password based authorization info for hidden services in clear form.
typedef struct {
  char* username; // not null-terminated
  size_t username_len; // username length
  char* password;
  size_t password_len;
} rend_auth_password_t;

int rend_auth_add_user (const char* filename, smartlist_t* new_users,
                        int hash_method);


#endif

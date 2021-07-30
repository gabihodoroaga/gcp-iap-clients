#ifndef IAP_H
#define IAP_H

int readFile(const char *path, char **content, int *length);

int readSettings(const char *key_file_path, char **client_email,
                 char **private_key, char **token_uri);

char *createJwtToken(const char *client_email, const char *token_uri,
                     const char *private_key, const char *audience);

char *base64(const unsigned char *input, int length);

unsigned char *decode64(const char *input, int length);

char *signWithPem(const char *payload, int payload_length,
                  const char *pem_content, int pem_length);

char *curl_post(const char *url, const char *data);

char *get_id_token(const char *token, const char *token_uri);

#endif /* IAP_H */
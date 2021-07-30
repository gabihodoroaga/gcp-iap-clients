#include "iap.h"
#include "jsmn.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include <curl/curl.h>
#include <string.h>

/**
Curl callback data struct
*/
typedef struct {
    char *payload;
    size_t size;
} curl_fetch_t;

/**
Helper function to test the json tokens
*/
static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

// You must free the result if result is non-NULL.
static char *str_replace(char *orig, char *rep, char *with) {
    char *result;  // the return string
    char *ins;     // the next insert point
    char *tmp;     // varies
    int len_rep;   // length of rep (the string to remove)
    int len_with;  // length of with (the string to replace rep with)
    int len_front; // distance between rep and end of last rep
    int count;     // number of replacements

    // sanity checks and initialization
    if (!orig || !rep)
        return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL; // empty rep causes infinite loop during count
    if (!with)
        with = "";
    len_with = strlen(with);

    // count the number of replacements needed
    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);
    return result;
}

int readFile(const char *path, char **content, int *length) {
    FILE *file;
    long file_size;
    char *buffer;
    size_t read;

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "error: cannot open file\n");
        return 0;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // allocate memory to contain the whole file:
    buffer = (char *)malloc(sizeof(char) * file_size);
    if (buffer == NULL) {
        fprintf(stderr, "error: cannot allocate memory for\n");
        fclose(file);
        return 0;
    }

    // copy the file into the buffer:
    read = fread(buffer, 1, file_size, file);
    if (read != file_size) {
        fprintf(stderr, "error: file read error\n");
        free(buffer);
        fclose(file);
        return 0;
    }

    *content = buffer;
    *length = file_size;

    fclose(file);
    return 1;
}

/**
Read settings from a service account key file (keys.json)
*/
int readSettings(const char *key_file_path, char **client_email,
                 char **private_key, char **token_uri) {

    int i;
    int r;
    jsmn_parser p;
    jsmntok_t t[24];
    char *private_key_unesc;

    char *key_file;
    int key_file_size;

    if (!readFile(key_file_path, &key_file, &key_file_size)) {
        fprintf(stderr, "error: cannot read file\n");
        return 0;
    }

    jsmn_init(&p);
    r = jsmn_parse(&p, key_file, key_file_size, t, 24);

    if (r < 0) {
        fprintf(stderr, "error: failed to parse JSON: %d\n", r);
        free(key_file);
        return 1;
    }

    if (r < 1 || t[0].type != JSMN_OBJECT) {
        fprintf(stderr, "error: root object expected\n");
        free(key_file);
        return 1;
    }

    /* Loop over all keys of the root object */
    for (i = 1; i < r; i++) {
        if (jsoneq(key_file, &t[i], "private_key") == 0) {
            private_key_unesc = strndup(key_file + t[i + 1].start,
                                        t[i + 1].end - t[i + 1].start);
            i++;
        } else if (jsoneq(key_file, &t[i], "client_email") == 0) {
            *client_email = strndup(key_file + t[i + 1].start,
                                    t[i + 1].end - t[i + 1].start);
            i++;
        } else if (jsoneq(key_file, &t[i], "token_uri") == 0) {
            *token_uri = strndup(key_file + t[i + 1].start,
                                 t[i + 1].end - t[i + 1].start);
            i++;
        }
    }

    // escape \n in json string
    *private_key = str_replace(private_key_unesc, "\\n", "\n");
    free(private_key_unesc);

    free(key_file);
    return 1;
}

char *createJwtToken(const char *client_email, const char *token_uri,
                     const char *private_key, const char *audience) {
    char *jwt_header = "{\"typ\":\"JWT\",\"alg\":\"RS256\"}";
    char *jwt_header_enc =
        base64((unsigned char *)jwt_header, strlen(jwt_header));

    if (!jwt_header_enc) {
        fprintf(stderr, "error: encoding header to base64\n");
        return NULL;
    }

    char *body_format = "{\"iss\":\"%s\",\"aud\":\"%s\",\"exp\":\"%d\",\"iat\":"
                        "\"%d\",\"target_audience\":\"%s\"}";

    int iat = (int)time(NULL);
    int exp = iat + 600;

    int jwt_body_size = snprintf(NULL, 0, body_format, client_email, token_uri,
                                 exp, iat, audience);

    char *jwt_body = (char *)malloc(jwt_body_size + 1);
    if (!jwt_body) {
        fprintf(stderr, "error: cannot allocate memory for jwt_body\n");
        return NULL;
    }

    snprintf(jwt_body, jwt_body_size + 1, body_format, client_email, token_uri,
             exp, iat, audience);

    char *jwt_body_enc = base64((unsigned char *)jwt_body, strlen(jwt_body));
    if (!jwt_body_enc) {
        fprintf(stderr, "error: encoding body to base64\n");
        return NULL;
    }
    free(jwt_body);

    // 344 bytes for signature (RS256 + 2048 key, update if different) + 2
    // for . and 1 for \0
    char *payload =
        (char *)malloc(strlen(jwt_header_enc) + strlen(jwt_body_enc) + 344 + 3);

    if (!payload) {
        fprintf(stderr, "error: cannot allocate memory for payload\n");
        return NULL;
    }

    strcpy(payload, jwt_header_enc);
    strcat(payload, ".");
    strcat(payload, jwt_body_enc);
    free(jwt_header_enc);
    free(jwt_body_enc);

    char *signbase64 =
        signWithPem(payload, strlen(payload), private_key, strlen(private_key));
    if (!signbase64) {
        fprintf(stderr, "error: cannot create signature\n");
        return NULL;
    }

    strcat(payload, ".");
    strcat(payload, signbase64);
    free(signbase64);

    return payload;
}

char *base64(const unsigned char *input, int length) {
    int pl;
    int ol;
    char *output;

    pl = 4 * ((length + 2) / 3);
    //+1 for the terminating null that EVP_EncodeBlock adds on
    output = (char *)calloc(pl + 1, 1);
    ol = EVP_EncodeBlock((unsigned char *)output, input, length);
    if (pl != ol) {
        fprintf(stderr, "warning: encode predicted %d, but we got %d\n", pl,
                ol);
    }

    return output;
}

unsigned char *decode64(const char *input, int length) {
    int pl;
    int ol;
    unsigned char *output;

    pl = 3 * length / 4;
    output = (unsigned char *)calloc(pl + 1, 1);
    ol = EVP_DecodeBlock(output, (const unsigned char *)input, length);
    if (pl != ol) {
        fprintf(stderr, "warning: decode predicted %d but we got %d\n", pl, ol);
    }
    return output;
}

char *signWithPem(const char *payload, int payload_length,
                  const char *pem_content, int pem_length) {

    EVP_MD_CTX *ctx;
    BIO *pem_buffer;
    EVP_PKEY *private_key;

    const EVP_MD *digest_type = EVP_sha256();
    char *signature;
    unsigned char *signature_bytes;
    const int digest_sign_success_code = 1;

    ctx = EVP_MD_CTX_new();

    if (!ctx) {
        fprintf(stderr, "error: cannot create context for OpenSSL digest\n");
        return NULL;
    }

    pem_buffer = BIO_new_mem_buf(pem_content, pem_length);
    if (!pem_buffer) {

        fprintf(stderr, "error: cannot create PEM buffer for private key\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    private_key = PEM_read_bio_PrivateKey(pem_buffer, NULL, NULL, NULL);
    if (!private_key) {
        fprintf(stderr, "error: cannot parse PEM to get private key\n");
        BIO_free(pem_buffer);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    BIO_free(pem_buffer);

    if (digest_sign_success_code !=
        EVP_DigestSignInit(ctx, NULL, digest_type, NULL, private_key)) {

        fprintf(stderr, "error: EVP_DigestSignInit()\n");
        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    if (digest_sign_success_code !=
        EVP_DigestSignUpdate(ctx, payload, payload_length)) {

        fprintf(stderr, "error: EVP_DigestSignUpdate()\n");

        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(ctx);

        return NULL;
    }

    size_t signed_str_size = 0;
    if (digest_sign_success_code !=
        EVP_DigestSignFinal(ctx, NULL, &signed_str_size)) {

        fprintf(stderr, "error: EVP_DigestSignFinal 1/2\n");

        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(ctx);

        return NULL;
    }

    signature_bytes = (unsigned char *)malloc(signed_str_size);
    if (!signature_bytes) {

        fprintf(stderr, "error: cannot allocate memory for signature bytes\n");

        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(ctx);

        return NULL;
    }

    if (digest_sign_success_code !=
        EVP_DigestSignFinal(ctx, signature_bytes, &signed_str_size)) {

        fprintf(stderr, "error: EVP_DigestSignFinal 2/2\n");

        free(signature_bytes);
        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(ctx);

        return NULL;
    }

    EVP_PKEY_free(private_key);
    EVP_MD_CTX_free(ctx);

    signature = base64(signature_bytes, signed_str_size);
    free(signature_bytes);
    return signature;
}

size_t curl_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    curl_fetch_t *p = (curl_fetch_t *)userp;

    char *temp = realloc(p->payload, p->size + realsize + 1);

    if (temp == NULL) {
        fprintf(stderr, "error: failed to expand buffer in curl_callback");
        return 0;
    }

    p->payload = temp;
    memcpy(&(p->payload[p->size]), contents, realsize);
    p->size += realsize;
    p->payload[p->size] = 0;

    return realsize;
}

// creates a request to url
char *curl_post(const char *url, const char *data) {

    CURL *curl;
    CURLcode res;
    struct curl_slist *headers;
    curl_fetch_t curl_fetch;
    curl_fetch_t *curl_fetch_p = &curl_fetch;

    curl_fetch_p->payload = (char *)calloc(1, sizeof(curl_fetch_p->payload));
    if (!curl_fetch_p->payload) {
        fprintf(stderr, "error: cannot allocate payload for curl_fetch_p");
        return NULL;
    }
    curl_fetch_p->size = 0;

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Error: curl_easy_init failed.\n");
        return NULL;
    }

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, -1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)curl_fetch_p);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "error: curl_easy_perform failed: %s\n",
                curl_easy_strerror(res));

        free(curl_fetch_p->payload);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return NULL;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return curl_fetch_p->payload;
}

char *get_id_token(const char *token, const char *token_uri) {
    const int TOKEN_SIZE = 3;
    char *token_payload_format;
    char *token_payload;
    int i, result;
    jsmn_parser parser;
    jsmntok_t tokens[TOKEN_SIZE];
    char *post_data;
    char *id_token;

    token_payload_format = "{\"grant_type\":\"urn:ietf:params:oauth:grant-"
                           "type:jwt-bearer\",\"assertion\":\"%s\"}";

    int token_payload_size = snprintf(NULL, 0, token_payload_format, token);

    token_payload = (char *)malloc(token_payload_size + 1);
    if (!token_payload) {
        fprintf(stderr, "error: cannot allocate memory for token_payload\n");

        return NULL;
    }

    snprintf(token_payload, token_payload_size + 1, token_payload_format,
             token);

    post_data = curl_post(token_uri, token_payload);
    free(token_payload);

    // parse the response and get the id_token
    jsmn_init(&parser);
    result =
        jsmn_parse(&parser, post_data, strlen(post_data), tokens, TOKEN_SIZE);

    if (result < 0) {
        fprintf(stderr, "error: failed to parse curl result\n");

        free(post_data);

        return NULL;
    }

    if (result < 1 || tokens[0].type != JSMN_OBJECT) {
        fprintf(stderr,
                "error: failed to parse curl result, root object expected\n");

        free(post_data);

        return NULL;
    }

    for (i = 1; i < result; i++) {
        if (jsoneq(post_data, &tokens[i], "id_token") == 0) {
            id_token = strndup(post_data + tokens[i + 1].start,
                               tokens[i + 1].end - tokens[i + 1].start);
            i++;
        }
    }

    free(post_data);

    return id_token;
}
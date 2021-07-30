#include "iap.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int make_iap_request(const char *id_token, const char* url) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        char auth_header[1024];
        strcpy(auth_header, "Authorization: Bearer ");
        strcat(auth_header, id_token);

        headers = curl_slist_append(headers, auth_header);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* always cleanup */
        curl_easy_cleanup(curl);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    printf("begin\n");

    char *client_email;
    char *private_key;
    char *token_uri;

    char *keyFile = argv[1];
    char *url = argv[3];
    char *audience = argv[2];

    if (!readSettings(keyFile, &client_email, &private_key, &token_uri)) {
        printf("error: key file\n");
        exit(1);
    }

    char *jwt_token =
        createJwtToken(client_email, token_uri, private_key, audience);

    if (!jwt_token) {
        printf("error: cannot create jwt token\n");
        exit(1);
    }

    char *id_token = get_id_token(jwt_token, token_uri);
    free(jwt_token);

    make_iap_request(id_token, url);

    free(id_token);

    free(client_email);
    free(private_key);
    free(token_uri);

    printf("end\n");
    return 0;
}

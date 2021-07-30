# Access Google IAP-secured resources using python

This is a an example of how to access Google IAP-secured resources using python.

## Solution overview

![OAuth flow](../.doc/oauth_flow.png)

## Run

```bash
python3 main.py "key.json" "audience" "https://example.com"
```

You will need to provide a the key.json file and the audience.

You can follow the tutorial from here [IAP on GKE](https://hodo.dev/posts/post-26-gcp-iap/)
to have a working example of a IAP-secured resource.

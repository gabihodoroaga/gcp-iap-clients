import sys, time
import jwt, json, requests

def make_iap_request(keyFile, audience, url):
    # read the key file
    with open(keyFile) as f:
        data = json.load(f)
        f.close()

    jwt_token = jwt.encode(
            {
            "iss": data["client_email"],
            "aud": data["token_uri"],
            "exp": int(time.time())+3600,
            "iat": int(time.time()),
            "target_audience": audience
        },
        data["private_key"],
        algorithm="RS256",
    )

    r = requests.post(
        data["token_uri"], 
        headers = {"Cache-Control": "no-store", 'Content-Type':"application/json"},
        json={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt_token }
    )

    token_data = r.json()

    r = requests.get(url, 
        headers = {
            'authorization': "Bearer " + token_data["id_token"]
        }, allow_redirects=False)

    print("status:", r.status_code)

if __name__ == '__main__':
    make_iap_request(sys.argv[1],sys.argv[2],sys.argv[3])

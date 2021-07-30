
const request = require("request");
const jsonwebtoken = require("jsonwebtoken");

function make_iap_request(keyFile, audience, url) {
    const keys = require(keyFile);
    const jwtProperties = {
        iss: keys["client_email"],
        aud: keys["token_uri"],
        iat: Math.floor(new Date().getTime() / 1000),
        exp: Math.floor(new Date().getTime() / 1000) + 3600,
        target_audience: audience,
    }

    const jwtToken = jsonwebtoken.sign(jwtProperties, keys["private_key"], { algorithm: "RS256" });
    request.post(keys["token_uri"],
        {
            headers: { "Cache-Control": "no-store", 'Content-Type': "application/json" },
            json: {
                grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
                assertion: jwtToken,
            }
        },
        (error, response) => {
            const openIDToken = response.body.id_token;
            request.get(url,
                {
                    headers: { "Authorization": `Bearer ${openIDToken}` },
                    followAllRedirects: false,
                },
                (err, res, body) => {
                    console.info("Status:", res.statusCode);
                }
            );
        });
}

var argv = process.argv.slice(2);
make_iap_request(argv[0],argv[1],argv[2]);

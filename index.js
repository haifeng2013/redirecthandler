/*
 * Copyright (C) 2019 HERE Technologies
 * HERE Account OpenID Connect web application reference implementation
 */
"use strict";
const async   = require("async");
const cookieParser = require("cookie-parser");
const express = require("express");
const request = require("request");
const swig = require("swig-templates");
const jose = require("node-jose");
const _ = require('underscore');

const app = express();

const oneHourInMsec = 60*60*1000;

// const myAppPort = "3002";   // my web app listens on this port for http requests
// const uatCookieName = "hoe-access-token"; // cookie set by ha-oidc-example (hoe) app

// // The original config object
// const origConfig = {
//     oidcProvider    : "https://st.p.account.here.com",  // OpenID Provider environment, see issuer property of https://confluence.in.here.com/display/HEREAccount/Open+ID+API#OpenIDAPI-ProviderConfigurationRequest
//     clientId        : "HQFjiYTPjiLxBK56EiE1",           // clientId, and accessKeySecret are the credentials for my app obtained from SPOT
//     accessKeyId     : "S-7DPxMP1cU7jZTw2X8a8A",         // access.key.id from credentials-*.properties file, needed e.g. for client signing
//     accessKeySecret : "U0l6Sf_kLgTqaYj6cEEa5jz3XPQ6PpajwzbvJ_wDe9UtKiv-v0R1YZr9dPbnt1TiiWkl4VgtorZYVn98B2mlvw",     // NEVER leak the secret to the user browser !!!
//     tokenEndpointAuthMethod : "client_secret_jwt",      // HERE Account supports client_secret_jwt, client_secret_post and client_secret_basic methods defined in the Section 9 of OIDC specification.
//     myAppPath       : "http://localhost:" + myAppPort,  // my web app is deployed at this url
//     redirectUriAuthcode : "/authCodeRedirectHandler",   // If my app registered for responseType = code, this route registered with SPOT is where my app will receive the Authorization code
//     redirectUriImplicit : "/implicitRedirectHandler"    // If my app registered for responseType = token or idToken, this route registered with SPOT is where my app will receive the Implicit grant flow response
// };

const myAppPort = "3004";   // my web app listens on this port for http requests
const uatCookieName = "hoe-access-token"; // cookie set by ha-oidc-example (hoe) app
// const appUrl = "d2un26jatk0l3k.cloudfront.net";
// const appUrl = "demo-auth.routing.ext.here.com";
const appUrl = "63.33.59.62:3004";

// The original config object
const origConfig = {
    oidcProvider    : "https://account.here.com",  // OpenID Provider environment, see issuer property of https://confluence.in.here.com/display/HEREAccount/Open+ID+API#OpenIDAPI-ProviderConfigurationRequest
    clientId        : "XpWGEOGS27GFs7tFDjFy",           // clientId, and accessKeySecret are the credentials for my app obtained from SPOT
    accessKeyId     : "6wOy7yZRMfWuPtq56QNVdg",         // access.key.id from credentials-*.properties file, needed e.g. for client signing
    accessKeySecret : "WYe0sMWYAh-dQpPK0VLJ1NijqC7U0ho7cK2CGB8G3gReIAHpcnPMtrBiYVUbSkmPZ6tcqeHQzFe1qAnrK_ObbQ",     // NEVER leak the secret to the user browser !!!
    tokenEndpointAuthMethod : "client_secret_jwt",      // HERE Account supports client_secret_jwt, client_secret_post and client_secret_basic methods defined in the Section 9 of OIDC specification.
    myAppPath       : "http://" + appUrl,  // my web app is deployed at this url
    redirectUriAuthcode : "/authCodeRedirectHandler",   // If my app registered for responseType = code, this route registered with SPOT is where my app will receive the Authorization code
    redirectUriImplicit : "/implicitRedirectHandler"    // If my app registered for responseType = token or idToken, this route registered with SPOT is where my app will receive the Implicit grant flow response
};

const config = origConfig;

// loadRootPage
var loadRootPage = function(req, res) {
    var opts = {
        // never pass secrets to the frontend user agent
        oidcProvider        : config.oidcProvider,
        haBaseUri           : getHAbaseUri(),
        clientId            : config.clientId,
        myAppPath           : config.myAppPath,
        redirectUriAuthcode : config.redirectUriAuthcode,
        redirectUriImplicit : config.redirectUriImplicit
    };

    console.log("\nloadRootPage() \x1b[36m opts: " + objToStr(opts) + "\x1b[0m");
    res.render("ha-oidc-example.home.html", opts);
};

// Redirect URI handler for Implicit grant flow - no processing (no secret handling) on backend.
var handleRedirectUriImplicit = function(req, res) {
    console.log("\nhandleRedirectUriImplicit() \x1b[36m req.query: " + objToStr(req.query) + "\x1b[0m");
    res.render("ha-oidc-example.implicit.html", {
        // never pass secrets to the frontend user agent
        action : "completed",
        flow   : "Implicit",
        uri    : config.myAppPath,
        oidcProvider    : config.oidcProvider,
        data   : ""
    });
};

// Redirect URI handler for Authorization code grant flow - generate client assertion (using secret) and calls HAW's token endpoint to exchange the code for token.
var handleRedirectUriAuthcode = function(req, res) {
    var data = {};
    if (req.query.code) {
        console.log("\nhandleRedirectUriAuthcode() \x1b[36m req.query: " + objToStr(req.query) + "\x1b[0m");

        async.waterfall([
            function generateClientAssertion(callback) {
                // Construct client_secret_jwt client_assertion for authorization
                // see http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
                // uses node jose library

                var audience = config.oidcProvider+"/token";
                if ((config.oidcProvider.indexOf("http://localhost") === 0 ) ||
                    (config.oidcProvider.indexOf("https://dv.rd.account.here.com") === 0 )) {
                    // this assumes that if the OP (HAWeb) is running on localhost or DV, is connected to HA Stg
                    audience = "https://st.p.account.here.com/token";
                }

                var jwtClaimSet = {
                    iss: config.clientId,
                    sub: config.clientId,
                    aud: audience,
                    jti: generateNonce(10),
                    iat: Math.floor(Date.now() / 1000),
                    exp: Math.floor(Date.now() / 1000) + (10 * 60)  // ten minutes
                };
                var keyJson = {
                    kty: "oct",
                    use: "sig",
                    k: config.accessKeySecret,
                    alg: "HS256"
                };

                setTimeout(function() {
                    // generate the key from the base64 encoded key
                    jose.JWK.asKey(keyJson, "json")
                        .then(function (key) {
                            // key is the converted jose.JWK.Key instance
                            // sign the input and callback with the token
                            jose.JWS.createSign({format: "compact", alg: "HS256"}, key)
                                .update(jose.util.asBuffer(JSON.stringify(jwtClaimSet)))
                                .final()
                                .then(function (clientAssertion) {
                                    console.log("handleRedirectUriAuthcode generateClientAssertion() \x1b[32m clientAssertion: " + objToStr(clientAssertion) + "\x1b[0m");
                                    // call the callback with the resulting token
                                    callback(null, clientAssertion);
                                });
                        });
                }, 1000);
            },

            function authCodeExchangeReq(clientAssertion, callback) {
                console.log("handleRedirectUriAuthcode authCodeExchangeReq() tokenEndpointAuthMethod " + config.tokenEndpointAuthMethod + "\x1b[0m");

                var formCredentials = "";
                if ("client_secret_post" === config.tokenEndpointAuthMethod) {
                    formCredentials =
                        "&client_id=" + encodeURIComponent(config.clientId) +
                        "&client_secret=" + encodeURIComponent(config.accessKeySecret);
                } else if ("client_secret_jwt" === config.tokenEndpointAuthMethod) {
                    formCredentials =
                        "&client_assertion_type=" + "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" +
                        "&client_assertion=" + clientAssertion;
                }

                var authCodeExchangeRequestData = {
                    uri: config.oidcProvider + "/token",
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json"
                    },
                    form: "grant_type=authorization_code" +
                        "&code=" + req.query.code +
                        "&redirect_uri=" + encodeURIComponent(config.myAppPath + config.redirectUriAuthcode) +
                        formCredentials
                };
                if ("client_secret_basic" === config.tokenEndpointAuthMethod) {
                    authCodeExchangeRequestData.headers.Authorization = "Basic " +
                      Buffer.from(config.clientId + ":" + config.accessKeySecret).toString('base64');
                }

                if ("client_secret_post" === config.tokenEndpointAuthMethod || "client_secret_basic" === config.tokenEndpointAuthMethod) {
                    // we can't add the client_secret to the logs
                    console.log("handleRedirectUriAuthcode: \x1b[36m authCodeExchangeRequestData: <redacted_due_to_credentials>" + "\x1b[0m");
                } else {
                    console.log("handleRedirectUriAuthcode: \x1b[36m authCodeExchangeRequestData: " + objToStr(authCodeExchangeRequestData) + "\x1b[0m");
                }

                // calls back with (err, response, authCodeExchangeResponseBody)
                request(authCodeExchangeRequestData, callback);
            },

            function authCodeExchangeRespHandler(response, authCodeExchangeResponseBody, callback) {

                if (response && response.statusCode && response.statusCode === 200) {
                    console.log("handleRedirectUriAuthcode authCodeExchangeRespHandler() \x1b[32m success: " + objToStr(JSON.parse(authCodeExchangeResponseBody)) + "\x1b[0m");

                    var userAccessToken = JSON.parse(authCodeExchangeResponseBody).access_token;

                    // 1. put token in data object for current operation response
                    data.userAccessToken = userAccessToken;

                    // 2. put token in cookie for persistence and session association
                    // if not using localhost, cookie should only be sent over https
                    var secureUnlessLocalhost = (config.myAppPath.substr(0,16) === "http://localhost") ? false : true;

                    res.cookie(uatCookieName, userAccessToken, {
                        expires: new Date(new Date().getTime() + oneHourInMsec) ,
                        secure: secureUnlessLocalhost,
                        httpOnly: true
                    });
                    callback(null);
                }
                else {
                    // some error when exchanging code for token
                    data = JSON.stringify(authCodeExchangeResponseBody);
                    console.log("handleRedirectUriAuthcode authCodeExchangeRespHandler() \x1b[33m not 200, data: " + objToStr(JSON.parse(authCodeExchangeResponseBody)) + "\x1b[0m");
                    callback("response.statusCode!==200", authCodeExchangeResponseBody);
                }
            },

            function userInfoRequest(callback) {

                var userInfoRequestData = {
                    uri: config.oidcProvider+"/openid/userinfo",
                    method: "GET",
                    headers: {
                        "Authorization": "Bearer " + data.userAccessToken,
                        "Accept": "application/json"
                    }
                };
                console.log("handleRedirectUriAuthcode: \x1b[36m userInfoRequestData: " + objToStr(userInfoRequestData) + "\x1b[0m");

                // calls back with (err, response, userInfoRespBody)
                request(userInfoRequestData, callback);
            },

            function userInfoRespHandler(response, userInfoRespBody, callback) {

                if (response && response.statusCode && response.statusCode === 200) {
                    data.userInfo = userInfoRespBody;
                    data.message  = "success! user access token is now in cookie named ha-open-id-client-cookie";
                    console.log("handleRedirectUriAuthcode userInfoRespHandler() \x1b[32m success: " + objToStr(JSON.parse(userInfoRespBody)) + "\x1b[0m");

                    callback(null);
                }
                else {
                    // some error when calling userinfo
                    data.userInfo = userInfoRespBody;
                    data.message  = "warning! user access token is now in cookie named ha-open-id-client-cookie, but userinfo not 200 OK";

                    console.log("handleRedirectUriAuthcode userInfoRespHandler() \x1b[33m not 200, data: " + objToStr(JSON.parse(userInfoRespBody)) + "\x1b[0m");
                    callback("response.statusCode!==200", userInfoRespBody);
                }
            },

            function userMeRequest(callback) {

                var userMeRequestData = {
                    uri: getHAbaseUri()+"/user/me",
                    method: "GET",
                    headers: {
                        "Authorization": "Bearer " + data.userAccessToken,
                        "Accept": "application/json"
                    }
                };
                console.log("handleRedirectUriAuthcode: \x1b[36m userMeRequestData: " + objToStr(userMeRequestData) + "\x1b[0m");

                // calls back with (err, response, userMeRespBody)
                request(userMeRequestData, callback);
            },

            function userMeRespHandler(response, userMeRespBody, callback) {

                if (response && response.statusCode && response.statusCode === 200) {
                    data.userMe = userMeRespBody;
                    data.message  = "success! user access token is now in cookie named ha-open-id-client-cookie";
                    console.log("handleRedirectUriAuthcode userMeRespHandler() \x1b[32m success: " + objToStr(JSON.parse(userMeRespBody)) + "\x1b[0m");

                    callback(null);
                }
                else {
                    // some error when calling userMe
                    data.userMe = userMeRespBody;
                    data.message  = "warning! user access token is now in cookie named ha-open-id-client-cookie, but userMe not 200 OK";

                    console.log("handleRedirectUriAuthcode userMeRespHandler() \x1b[33m not 200, data: " + objToStr(JSON.parse(userMeRespBody)) + "\x1b[0m");
                    callback("response.statusCode!==200", userMeRespBody);
                }
            }
            ],
            function callback(err, result){

                if (err) {
                    console.log("\x1b[33m waterfall error: " + err + "\x1b[0m");
                }
                console.log("\x1b[34m ==================== \x1b[0m\n");
                sendAuthcodeResponse(data, res);
            }
        );
    }
    else if (req.query.error) {

        data = "error: " + req.query.error +
            (req.query.error_description ? "; error_description: " + req.query.error_description : "") +
            (req.query.state ? "; state: " + req.query.state : "");

        console.log("handleRedirectUriAuthcode \x1b[31m error in query param received, req.query: " + objToStr(req.query) + "\x1b[0m");
        sendAuthcodeResponse(data, res);
    }
    else {
        // no error and no code - unknown error
        data = "error: unknown error, uri was: " + req.originalUrl;
        console.log("handleRedirectUriAuthcode \x1b[33m no code, data: " + data + "\x1b[0m");
        sendAuthcodeResponse(data, res);
    }
};


// Handler for clearing JWT Token stored in cookie "ha-open-id-client-cookie"
var handleClearAccessToken = function(req, res) {
    var action = "completed";
    var statusCode = 200;
    console.log("handleClearAccessToken invoked");

    var secureUnlessLocalhost = (config.myAppPath.substr(0,16) === "http://localhost") ? false : true;
    res.clearCookie(uatCookieName, {
        secure: secureUnlessLocalhost,
        httpOnly: true
    });
    var options = {
        action : action,
        flow   : "handleClearAccessToken",
        uri    : config.myAppPath,
        data   : 'ok'
    };

    res.status(statusCode).send(options);
};

// Handler for getUserMe request
var handleGetUserMe = function(req, res) {
    var data = {};
    var action = "completed";
    var statusCode = 200;
    console.log("handleGetUserMe invoked");

    async.waterfall([

            function getUserMeRequest(callback) {

                var uat = req.cookies[uatCookieName] || req.query.targetToken;

                var getUserMeData = {
                    uri     : getHAbaseUri() + "/user/me",
                    method  : "GET",
                    headers : {
                        "Authorization": "Bearer " + uat,
                        "Accept": "application/json"
                    }
                };
                console.log("handleGetUserMe: \x1b[36m getUserMeRequest: " + objToStr(getUserMeData) + "\x1b[0m");

                // calls back with (err, response, getUserMeRespBody) - getUserMeRespBody is null if no error!)
                request(getUserMeData, callback);
            },

            function getUserMeRespHandler(response, getUserMeRespBody, callback) {
                console.log("handleGetUserMe: getUserMeRespHandler() \x1b[35m response headers: " + objToStr(response.headers) + "\x1b[0m");
                if (response.statusCode === 200) {
                    data.statusCode = response.statusCode;
                    data.userMeResp = JSON.parse(getUserMeRespBody);
                    console.log("handleGetUserMe: getUserMeRespHandler() \x1b[32m 200 success!" + objToStr(data.userMeResp) + "\x1b[0m");
                    callback(null, data);
                }
                else {
                    console.log("handleGetUserMe: getUserMeRespHandler() \x1b[31m response.statusCode: " + response.statusCode + "\x1b[0m");
                    console.log("handleGetUserMe: getUserMeRespHandler() \x1b[31m getUserMeRespBody: " + getUserMeRespBody + "\x1b[0m");
                    callback("getUserMe response.statusCode = " + response.statusCode, getUserMeRespBody);
                }
            }
        ],

        function callback(err, result){

            if (err) {
                console.log("\x1b[33m handleGetUserMe waterfall error: " + err + "\x1b[0m");
                action = "error";
                statusCode = 400;
            }
            else {
                console.log("handleGetUserMe completed");
            }

            var options = {
                action : action,
                flow   : "handleGetUserMe",
                uri    : config.myAppPath,
                data   : result
            };

            res.status(statusCode).send(options);
        }
    );
};

var sendAuthcodeResponse = function(data, res) {
    var options = {
        action : "error",
        flow   : "Authorize",
        uri    : config.myAppPath,
        data   : data
    };
    if (data.userAccessToken) {
        options.action = "completed";
        options.token = data.userAccessToken;
        options.data = JSON.stringify(data);
    }

    res.render("ha-oidc-example.authcode.html", options);
};


// this assumes that the OP (HAWeb) running on localhost is connected to HA Stg
var envMap = {
    "https://account.here.com"              : { ha: "https://account.api.here.com" },
    "https://st.p.account.here.com"         : { ha: "https://stg.account.api.here.com" },
    "https://qa.rd.account.here.com"        : { ha: "https://qa.account.api.here.com" },
    "https://web.account.sit.hereolp.cn"    : { ha: "https://elb.cn-northwest-1.account.sit.hereapi.cn" },
    "https://web.account.hereolp.cn"        : { ha: "https://elb.cn-northwest-1.account.hereapi.cn" },
    "http://localhost:3000"                 : { ha: "https://stg.account.api.here.com" }
};


function getHAbaseUri() {
    var provider = config.oidcProvider.replace("cn-northwest-1.","");   // strip out Rt53 bug artifact

    if (envMap.hasOwnProperty(provider)) {
        return envMap[provider].ha;
    }
    else {
        throw "getHAbaseUri: unexpected provider value: " + provider;
    }
}

function generateNonce(len) {
    var nonce = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < len; i++) {
        nonce += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return nonce;
}

function objToStr(obj, indent) {
    if (("string" === typeof obj) || ("number" === typeof obj) || ("boolean" === typeof obj)) {
        return obj;
    }
    else if (!obj) {
        return "undefined";
    }
    else if (obj === null) {
        return "null";
    }
    else if (obj.isArray) {
        return obj;
    }
    else {
        if (!indent) {
            indent = "  ";
        }
        else {
            indent += "  ";
        }

        var outStr = indent + "{";
        for (var prop in obj) {
            if (("function" === typeof obj.hasOwnProperty) &&   // skip objects that don't implement "hasOwnProperty"
                // (prop.indexOf("_") !== 0) &&                    // skip properties named with leading "_"
                obj.hasOwnProperty(prop)                        // skip properties that are inherited
            ) {
                if (("string" === typeof obj[prop]) ||("number" === typeof obj[prop])) {
                    outStr += "\n" + indent + prop + ":" + indent + obj[prop];
                }
                else if (indent.length > 10) {
                    outStr += "\n" + indent + prop + ": <<< recursion limit reached >>>";
                }
                else {
                    outStr += "\n" + indent + prop + ":" + objToStr(obj[prop], indent);
                }
            }
        }
        outStr += "\n" + indent + "}";
        return outStr;
    }

}

////////////////////
// Server and routes
app.engine("html", swig.renderFile);
app.use(cookieParser());

app.get("/",                        loadRootPage);

app.get(config.redirectUriImplicit, handleRedirectUriImplicit);

app.get(config.redirectUriAuthcode, handleRedirectUriAuthcode);

app.get("/clearAccessToken",        handleClearAccessToken);

app.get("/getUserMe",               handleGetUserMe);

app.listen(myAppPort, function() {
    console.log("\x1b[34mHERE Account OpenID Connect Relying Party Node.js Reference Implementation Backend\x1b[0m" +
        "\n" +
        "ClientId configured is \x1b[36m" + config.clientId + "\x1b[0m" +
        "\n" +
        "Redirect Uri for Authentication code grant flow configured is \x1b[36m" + config.myAppPath + config.redirectUriAuthcode + "\x1b[0m" +
        "\n" +
        "Redirect Uri for Implicit grant flow configured is \x1b[36m" + config.myAppPath + config.redirectUriImplicit + "\x1b[0m" +
        "\n" +
        "Listening on port " + myAppPort +
        "\n" +
        "Connected to OIDC Provider: \x1b[36m" + config.oidcProvider + "\x1b[0m"
    );
});


# middy-oauth2
Middy JS middleware to validate OAuth2 tokens

## Installation
Download node at [nodejs.org](http://nodejs.org) and install it, if you haven't already.

```sh
npm install middy-aouth2 --save
```

## Configuration

Middleware options:
 - logger - function to use for logging, by default uses console.error
 - realm - realm value to include in WWW-Authenticate response header
 - secretOrPublicKey - is a string, buffer, or object containing either the secret for HMAC algorithms or the PEM encoded private key for RSA and ECDSA. Middleware uses [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) under the hood
 - jwtOptions - options to verify jwt based on [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken).
 
### Usage

```javascript
const createHttpError = require('http-errors')
const middy = require('middy')
const { httpHeaderNormalizer } = require('middy/middlewares')
const { verifyBearerToken } = require('middy-oauth2')

// This is your AWS handler
const helloWorld = async (event) => {
  return {
    body: JSON.stringify({ data: 'Hello world!' }),
    statusCode: 200
  }
}

const handler = middy(helloWorld)
  .use(httpHeaderNormalizer()) // Make sure authorization header is saved in lower case
  .use(verifyBearerToken({
      logger: console.error,
      realm: "Hello world",
      secretOrPublicKey: "secret",
      jwtOptions: null
  }))
```
const middy = require('middy')
const { validateBearerToken } = require('../middy-oauth2')

test('Request without authentication info should create a 401 Unauthorized response with WWW-Authenticate header',
  async (endTest) => {
    const handler = middy(async (event, context, cb) => {})
      .use(validateBearerToken({ logger: false }))

    handler({}, {}, async (err, response) => {
      if (err) {
        return endTest(err)
      }
      await expect(response).toEqual({
        statusCode: 401,
        headers: {
          "WWW-Authenticate": 'Bearer'
        }
      })
      endTest()
    })
  }
)


test('Request with missing parameter should create a 400 Bad Request response with WWW-Authenticate header',
  async (endTest) => {
    const handler = middy(async (event, context, cb) => {})
      .use(validateBearerToken({ logger: false }))

    handler({
      headers: {
        Authorization: ''
      }
    }, {}, async (err, response) => {
      if (err) {
        return endTest(err)
      }
      await expect(response).toEqual({
        statusCode: 401,
        headers: {
          "WWW-Authenticate": 'Bearer'
        }
      })
      endTest()
    })
  }
)

test('Request with invalid schema should create a 401 Unauthorized response with WWW-Authenticate header',
  async (endTest) => {
    const handler = middy(async (event, context, cb) => {})
      .use(validateBearerToken({ logger: false }))

    handler({
      headers: {
        Authorization: 'Basic 123'
      }
    }, {}, async (err, response) => {
      if (err) {
        return endTest(err)
      }
      await expect(response).toEqual({
        statusCode: 401,
        headers: {
          "WWW-Authenticate": 'Bearer'
        }
      })
      endTest()
    })
  }
)

test('Request with invalid token should create a 401 Unauthorized response with WWW-Authenticate header',
  async (endTest) => {
    const handler = middy(async (event, context, cb) => {})
      .use(validateBearerToken({ logger: false }))

    handler({
      headers: {
        Authorization: 'Bearer 123'
      }
    }, {}, async (err, response) => {
      if (err) {
        return endTest(err)
      }
      await expect(response).toEqual({
        statusCode: 401,
        headers: {
          "WWW-Authenticate": 'Bearer error="invalid_token", error_description="jwt malformed"'
        }
      })
      endTest()
    })
  }
)

test('Request with multiple tokens should create a 400 Bad Request response with WWW-Authenticate header',
  async (endTest) => {
    const handler = middy(async (event, context, cb) => {})
      .use(validateBearerToken({ logger: false }))

    handler({
      headers: {
        Authorization: 'Bearer 123',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: 'access_token=12345'
    }, {}, async (err, response) => {
      if (err) {
        return endTest(err)
      }
      await expect(response).toEqual({
        statusCode: 400,
        headers: {
          "WWW-Authenticate": 'Bearer error="invalid_request", error_description="More than one method for including access token used"'
        }
      })
      endTest()
    })
  }
)

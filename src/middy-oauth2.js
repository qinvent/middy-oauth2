
const jwt = require('jsonwebtoken')
const createError = require('http-errors')

const AUTHENTICATION_SCHEMA = 'Bearer'
const AUTHORIZATION_HEADER = 'Authorization'
const WWW_AUTHENTICATE_HEADER = 'WWW-Authenticate'
const CONTENT_TYPE_HEADER = 'Content-Type'
const FORM_URLENCODED = 'application/x-www-form-urlencoded'

const validateBearerToken = (opts) => {
    const defaults = {
        logger: console.error
    }

    const options = Object.assign({}, defaults, opts)

    return ({
        before: async (handler) => {
            handler.event.headers = handler.event.headers || {}

            const getAuthenticationCredentials = () => {
                const authorizationHeader = handler.event.headers[AUTHORIZATION_HEADER]
                if (authorizationHeader) {
                    const [schema, token] = authorizationHeader.split(" ")
                    if (schema && schema === AUTHENTICATION_SCHEMA) {
                        return token
                    }
                }

                const contentTypeHeader = handler.event.headers[CONTENT_TYPE_HEADER]
                if (contentTypeHeader && contentTypeHeader === FORM_URLENCODED) {
                    const parserFn = options.extended ? require('qs').parse : require('querystring').decode
                    const body = parserFn(handler.event.body)
                    return body.access_token
                }
                throw createError.BadRequest('invalid_request')
            }

            const token = getAuthenticationCredentials()

            try {
                let { secretOrPublicKey, jwtOptions } = options
                let decoded = jwt.verify(token, secretOrPublicKey, jwtOptions)
                handler.event.user = decoded

                return
            } catch (err) {
                throw createError.Unauthorized('invalid_token')
            }
        },

        onError: async (handler) => {
            if ((handler.error.constructor.super_ && handler.error.constructor.super_.name === 'HttpError')
                && (handler.error.__proto__ && handler.error.__proto__.statusCode === 401)) {

                handler.response = {
                    statusCode: handler.error.statusCode,
                    body: 'Unauthorized',
                    headers: handler.error.headers || {}
                }

                handler.response.headers[WWW_AUTHENTICATE_HEADER] = options.realm
                    ? `${AUTHENTICATION_SCHEMA} realm="${options.realm}"`
                    : `${AUTHENTICATION_SCHEMA}`

                return
            }

            return handler.error
        }
    })
}

module.exports = { validateBearerToken }
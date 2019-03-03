
const jwt = require('jsonwebtoken')
const createError = require('http-errors')

const AUTHENTICATION_SCHEMA = 'Bearer'
const AUTHORIZATION_HEADER = 'Authorization'
const WWW_AUTHENTICATE_HEADER = 'WWW-Authenticate'
const CONTENT_TYPE_HEADER = 'Content-Type'
const FORM_URLENCODED = 'application/x-www-form-urlencoded'
const INVALID_REQUEST_ERROR_CODE = 'invalid_request'
const INVALID_TOKEN_ERROR_CODE = 'invalid_token'
const INSUFFICIENT_SCOPE = 'insufficient_scope'

const buildInvalidRequestError = (description) => {
    return createError.BadRequest({
        error: INVALID_REQUEST_ERROR_CODE,
        error_description: description
    })
}

const buildInvalidTokenError = (description) => {
    return createError.Unauthorized({
        error: INVALID_TOKEN_ERROR_CODE,
        error_description: description
    })
}

const validateBearerToken = (opts) => {
    const defaults = {
        logger: console.error,
        extended: false,
        realm: null, 
        secretOrPublicKey: null,
        jwtOptions: null
    }

    const options = Object.assign({}, defaults, opts)

    return ({
        before: async (handler) => {
            handler.event.headers = handler.event.headers || {}

            const getAuthenticationCredentials = () => {

                const getAuthorizationRequestHeaderField = () => {
                    const authorizationHeader = handler.event.headers[AUTHORIZATION_HEADER]

                    if (authorizationHeader) {
                        const [schema, token] = authorizationHeader.split(" ")
                        if (schema && schema === AUTHENTICATION_SCHEMA) {
                            return token
                        }
                    }
                    return null
                }

                const getFormEncodedBodyParameter = () => {
                    const contentTypeHeader = handler.event.headers[CONTENT_TYPE_HEADER]
                    if (contentTypeHeader && contentTypeHeader === FORM_URLENCODED) {
                        const parserFn = options.extended ? require('qs').parse : require('querystring').decode
                        const body = parserFn(handler.event.body)
                        return body.access_token
                    }
                    return null
                }

                const getUriQueryParameter = () => {
                    return null
                }

                const tokenFromHeader = getAuthorizationRequestHeaderField()
                const tokenFromBody = getFormEncodedBodyParameter()
                const tokenFromQuery = getUriQueryParameter()

                if (tokenFromHeader || tokenFromBody || tokenFromQuery) {
                    if (tokenFromHeader && tokenFromBody || tokenFromHeader && tokenFromQuery || tokenFromBody && tokenFromQuery) {
                        throw buildInvalidRequestError('More than one method for including access token used')
                    } else {
                        return tokenFromHeader ? tokenFromHeader : tokenFromBody ? tokenFromBody : tokenFromQuery
                    }
                } else {
                    // request lacks any authentication information
                    throw createError.Unauthorized()
                }
            }

            const token = getAuthenticationCredentials()

            try {
                let { secretOrPublicKey, jwtOptions } = options
                let decoded = jwt.verify(token, secretOrPublicKey, jwtOptions)
                handler.event.auth = decoded

                return
            } catch (err) {
                if (err && (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError' || err.name === 'NotBeforeError')) {
                    throw buildInvalidTokenError(err.message)
                }
                throw createError.InternalServerError(err)
            }
        },

        onError: async (handler) => {
            const isHttpError = (handler) => {
                return handler.error.constructor.super_
                    && handler.error.constructor.super_.name === 'HttpError'
            }

            const isUnauthorizedError = (handler) => {
                return handler.error.__proto__
                    && handler.error.__proto__.statusCode === 401
            }

            const isInvalidRequestError = (handler) => {
                return handler.error.__proto__
                    && handler.error.__proto__.statusCode === 400
                    && handler.error.message && handler.error.message.error === INVALID_REQUEST_ERROR_CODE
            }

            if (isHttpError(handler) && (isUnauthorizedError(handler) || isInvalidRequestError(handler))) {

                const buildWwwAuthenticateHeaderValue = (realm, error, error_description) => {
                    let attributes = realm ? `realm="${realm}"` : ''
                    attributes = attributes ? attributes + ', ' : attributes
                    attributes = error ? attributes + `error="${error}"` : attributes
                    attributes = error && error_description ? attributes + `, error_description="${error_description}"` : attributes

                    return attributes ? `${AUTHENTICATION_SCHEMA} ${attributes}` : AUTHENTICATION_SCHEMA
                }

                handler.response = {
                    statusCode: handler.error.statusCode,
                    headers: {}
                }

                let error = handler.error.message.error
                let error_description = handler.error.message.error_description

                handler.response.headers[WWW_AUTHENTICATE_HEADER] = buildWwwAuthenticateHeaderValue(options.realm, error, error_description)

                return
            }

            return handler.error
        }
    })
}

module.exports = { validateBearerToken }
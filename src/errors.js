class NotDialableError extends Error {
  constructor (message = 'not dialable') {
    super(message)
    this.name = 'NotDialableError'
    this.code = NotDialableError.code
  }
}

NotDialableError.code = 'ERR_NOT_DIALABLE'

exports.NotDialableError = NotDialableError

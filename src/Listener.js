'use strict'

const Quic = require('quic')
const { AbortError } = require('abortable-iterator')
const log = require('debug')('libp2p:quic:Listener')

class Listener {
  constructor ({ handler, privateKey, upgrader }, options) {
    options = options || {}
    this._handler = handler
    this._privateKey = privateKey
    this._upgrader = upgrader
    this._options = options
  }
}

module.exports = Listener

'use strict'

// https://github.com/nodejs/quic/blob/master/doc/api/quic.md
const QUIC = require('quic')
const { AbortError } = require('abortable-iterator')
const log = require('debug')('libp2p:quic:Transport')
const Listener = require('./Listener')
const MultiaddrConnection = require('./MultiaddrConnection')

class Transport {
  constructor ({ privateKey, upgrader }) {
    this._privateKey = privateKey
    this._upgrader = upgrader
  }

  async dial (addr, options) {
    options = options || {}

    if (options.signal && options.signal.aborted) {
      throw new AbortError()
    }

    log('dial %s', addr)

    const socket = QUIC.createSocket(/* TODO: options? */)
    const session = socket.connect(/* TODO: options? */)

    await new Promise(resolve => session.on('secure', resolve))
    log('dial secure %s', addr)

    const stream = session.openStream({ halfOpen: true })
    const maConn = new MultiaddrConnection(stream, { remoteAddr: addr, signal: options.signal })

    return this._upgrader.upgradeOutbound(maConn)
  }

  createListener (options, handler) {
    if (typeof options === 'function') {
      handler = options
      options = {}
    }
    options = options || {}
    return new Listener({
      handler,
      privateKey: this._privateKey,
      upgrader: this._upgrader
    }, options)
  }

  filter (addrs) {
    // TODO: PR to mafmt
    // TODO: filter correctly circuit addrs
    return (Array.isArray(addrs) ? addrs : [addrs]).filter(addr => `${addr}`.includes('quic'))
  }
}

module.exports = Transport

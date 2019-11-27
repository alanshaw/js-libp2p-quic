'use strict'

// https://github.com/nodejs/quic/blob/master/doc/api/quic.md
const Quic = require('quic')
const Fs = require('fs')
const Path = require('path')
const { AbortError } = require('abortable-iterator')
const log = require('debug')('libp2p:quic:Transport')
const Multiaddr = require('multiaddr')
const PeerId = require('peer-id')
const Listener = require('./Listener')
const toCapableConn = require('./to-capable-conn')
const { NotDialableError } = require('./errors')

const key = Fs.readFileSync(Path.join(__dirname, '..', 'agent1-key.pem'))
const cert = Fs.readFileSync(Path.join(__dirname, '..', 'agent1-cert.pem'))
const ca = Fs.readFileSync(Path.join(__dirname, '..', 'ca1-cert.pem'))

class Transport {
  constructor ({ privateKey }) {
    this._privateKey = privateKey
  }

  async dial (addr, options) {
    options = options || {}

    if (options.signal && options.signal.aborted) {
      throw new AbortError()
    }

    if (typeof addr === 'string') {
      addr = Multiaddr(addr)
    } else if (!Multiaddr.isMultiaddr(addr)) {
      throw new TypeError('address is not a multiaddr')
    }

    if (!isQuicAddr(addr)) {
      throw new NotDialableError()
    }

    log('dial %s', addr)

    // TODO: extract key and cert from libp2p private key
    const { address, port } = addr.nodeAddress()
    const socket = Quic.createSocket()
    socket.on('error', err => log('socket error', err))
    const session = socket.connect({ key: this._privateKey, cert, ca, address, port })
    session.on('error', err => log('session error', err))

    await new Promise(resolve => session.on('secure', resolve))
    log('dial to %s is now secure', addr)

    const localAddr = (() => {
      const { address, port, family } = socket.address
      return `/ip${family.slice(-1)}/${address}/udp/${port}/quic`
    })()

    if (!this._localPeer) {
      this._localPeer = await PeerId.createFromPrivateKey(this._privateKey)
    }

    return toCapableConn({
      socket,
      session,
      localAddr,
      remoteAddr: addr,
      localPeer: this._localPeer
    }, { signal: options.signal })
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
    return (Array.isArray(addrs) ? addrs : [addrs]).filter(isQuicAddr)
  }
}

function isQuicAddr (addr) {
  return `${addr}`.includes('quic')
}

module.exports = Transport

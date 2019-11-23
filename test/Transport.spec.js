// Generate a key and cert
// https://nodejs.org/en/knowledge/cryptography/how-to-use-the-tls-module/
const test = require('tape')
const Quic = require('quic')
const Fs = require('fs')
const Path = require('path')
const pipe = require('it-pipe')
const log = require('debug')('libp2p:quic:Transport.spec')
const Transport = require('../src/Transport')

const key = Fs.readFileSync(Path.join(__dirname, '..', 'agent1-key.pem'))
const cert = Fs.readFileSync(Path.join(__dirname, '..', 'agent1-cert.pem'))
const ca = Fs.readFileSync(Path.join(__dirname, '..', 'ca1-cert.pem'))

const passThroughUpgrader = {
  upgradeOutbound: c => c,
  upgradeInbound: c => c
}

const collect = async source => {
  const chunks = []
  for await (const chunk of source) chunks.push(chunk)
  return chunks
}

const logChunk = prefix => async function * (source) {
  for await (const chunk of source) {
    log(`${prefix}: ${chunk}`)
    yield chunk
  }
}


test('should do a quic echo', async t => {
  t.plan(1)

  const socket = Quic.createSocket({ address: 'localhost' })

  socket.on('session', session => {
    log('server session created')
    session.on('stream', stream => {
      log('server incoming stream')
      // echo server
      stream.on('data', data => {
        log('server recieved:', data.toString())
        stream.write(data)
      })
      stream.on('end', () => stream.end())
    })
    session.on('error', err => log('session error', err))
    session.on('close', () => log('session closed'))
  })
  socket.on('error', err => log('socket error', err))

  const { address, port, family } = await new Promise(resolve => {
    socket.listen({ key, cert, ca, alpn: '/libp2p/quic' })
    socket.on('listening', () => resolve(socket.address))
  })

  const addr = `/ip${family.slice(-1)}/${address}/udp/${port}/quic`

  log('quic server listening at', addr)

  const transport = new Transport({ upgrader: passThroughUpgrader })

  const conn = await transport.dial(addr)
  log('dial to echo server success, testing connectivity...')

  const input = [
    Buffer.from('hello'),
    Buffer.from('world'),
    Buffer.from(Date.now().toString())
  ]

  const output = await pipe(
    input,
    logChunk('client sending'),
    conn,
    logChunk('client received'),
    collect
  )

  t.deepEqual(Buffer.concat(input), Buffer.concat(output))

  socket.close()
})

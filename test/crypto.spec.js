const test = require('tape')
const PeerId = require('peer-id')
const { privateKeyToCertificate } = require('../src/crypto')
const PeerCertFixture = require('./fixtures/peer-cert.json')

test('should convert private key to certificate', async t => {
  const peerId = await PeerId.create()
  const { cert, keyPair } = await privateKeyToCertificate(peerId.privKey)
  console.log({ cert, keyPair })
  console.log(cert)
  t.pass()
  t.end()
})

test('should convert private key to certificate interoperable with go-libp2p-tls', async t => {
  const peerId = await PeerId.createFromPrivKey(PeerCertFixture.PrivKey)
  const { cert, certRaw } = await privateKeyToCertificate(peerId.privKey)
  console.log(certRaw.toString('base64'))
  t.equal(cert, PeerCertFixture.Cert) // Note this will never pass because of the expiry dates
  t.end()
})

const test = require('tape')
const PeerId = require('peer-id')
const { privateKeyToCertificate } = require('../src/crypto')

test('should convert private key to certificate', async t => {
  const peerId = await PeerId.create()
  const cert = await privateKeyToCertificate(peerId.privKey)
  console.log(cert)
})

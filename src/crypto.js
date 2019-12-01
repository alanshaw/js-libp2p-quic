// https://github.com/libp2p/go-libp2p-tls/blob/master/crypto.go
const { ec: EC } = require('elliptic')
const X509 = require('@root/x509')
const ASN1 = require('asn1.js')
const Crypto = require('crypto')
const Forge = require('node-forge')

// https://github.com/libp2p/go-libp2p-tls/blob/702fd537463ac5a1ef209c0b64457da0d1251b3f/crypto.go#L22
const certValidityPeriod = 100 * 365 * 24 * 60 * 60 * 1000 // ~100 years
// https://github.com/libp2p/go-libp2p-tls/blob/702fd537463ac5a1ef209c0b64457da0d1251b3f/crypto.go#L23
const certificatePrefix = Buffer.from('libp2p-tls-handshake:')

// https://github.com/libp2p/go-libp2p-tls/blob/702fd537463ac5a1ef209c0b64457da0d1251b3f/extension.go#L3
const extensionPrefix = Buffer.from([1, 3, 6, 1, 4, 1, 53594])
const extensionId = Buffer.concat([extensionPrefix, Buffer.from([1, 1])])

const SignedKey = ASN1.define(function () {
  this.seq().obj(
    this.key('PubKey').octstr(),
    this.key('Signature').octstr()
  )
})

exports.privateKeyToCertificate = async privateKey => {
  const ec = new EC('p256')
  const certKey = ec.genKeyPair()
  const publicKeyBytes = privateKey.public().marshal()
  const publicCertKey = certKey.getPublic()
  const pkixPublicCertKey = X509.packPkix(publicCertKey)
  const signature = await privateKey.sign(Buffer.concat([certificatePrefix, pkixPublicCertKey]))
  const serialNumber = Crypto.randomBytes(2147483647)

  const extensionValue = SignedKey.encode({
    PubKey: publicKeyBytes,
    Signature: signature
  })

  // https://github.com/digitalbazaar/forge#x509
  const cert = Forge.pki.createCertificate()
  cert.publicKey = publicCertKey
  cert.serialNumber = serialNumber // TODO: check
  cert.validity.notBefore = Date.now()
  cert.validity.notAfter = Date.now() + certValidityPeriod
  cert.setExtensions([{ id: extensionId, value: extensionValue }])
  cert.sign(certKey.getPrivate())

  return cert
}

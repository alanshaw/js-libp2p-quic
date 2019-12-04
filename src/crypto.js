// https://github.com/libp2p/go-libp2p-tls/blob/master/crypto.go
const X509 = require('@root/x509')
const { fromBER, Sequence, OctetString, BitString } = require('asn1js')
const Forge = require('node-forge')
const Eckles = require('eckles')
const { Certificate, PublicKeyInfo, AlgorithmIdentifier, Extension } = require('pkijs')
const Crypto = require('crypto')

// https://github.com/libp2p/go-libp2p-tls/blob/702fd537463ac5a1ef209c0b64457da0d1251b3f/crypto.go#L22
const certValidityPeriod = 100 * 365 * 24 * 60 * 60 * 1000 // ~100 years
// https://github.com/libp2p/go-libp2p-tls/blob/702fd537463ac5a1ef209c0b64457da0d1251b3f/crypto.go#L23
const certificatePrefix = Buffer.from('libp2p-tls-handshake:')

// https://github.com/libp2p/go-libp2p-tls/blob/702fd537463ac5a1ef209c0b64457da0d1251b3f/extension.go#L3
// http://www.oid-info.com/get/1.3.6.1.4.1.53594
const extensionPrefix = '1.3.6.1.4.1.53594'
const extensionId = `${extensionPrefix}.1.1`

exports.privateKeyToCertificate = async privateKey => {
  const certKey = await Eckles.generate({ format: 'jwk', namedCurve: 'P-256' })
  const publicKey = privateKey.public.marshal()
  const pkixPublicCertKey = X509.packPkix(certKey.public)
  const signature = await privateKey.sign(Buffer.concat([certificatePrefix, pkixPublicCertKey]))

  // https://github.com/loop-os/katapult/pull/29/files#diff-c8c10f77ecde8c22a238f78c8e78fb99
  const cert = new Certificate()

  cert.version = 2
  cert.subjectPublicKeyInfo = await toPublicKeyInfo(certKey.public)

  const serial = Crypto.randomBytes(12)
  serial[0] = 0x01
  cert.serialNumber.valueBlock.valueHex = serial

  cert.notBefore.value = new Date()
  cert.notAfter.value = new Date(Date.now() + certValidityPeriod)

  const signedKey = new Sequence({
    value: [
      new OctetString({ name: 'PubKey', value: publicKey }),
      new OctetString({ name: 'Signature', value: signature })
    ]
  })

  cert.extensions = [new Extension({
    extnID: extensionId,
    critical: false,
    extnValue: signedKey.toBER(false),
    parsedValue: signedKey
  })]

  // ecdsa-with-SHA256
  // http://www.oid-info.com/get/1.2.840.10045.4.3.2
  cert.signature = new AlgorithmIdentifier({
    algorithmId: '1.2.840.10045.4.3.2'
  })

  // ecdsa-with-SHA256
  // http://www.oid-info.com/get/1.2.840.10045.4.3.2
  cert.signatureAlgorithm = new AlgorithmIdentifier({
    algorithmId: '1.2.840.10045.4.3.2'
  })

  cert.tbs = cert.encodeTBS()
  const signer = Crypto.createSign('SHA256')
  signer.update(Buffer.from(cert.tbs.toBER(false)))
  const signResult = signer.sign(await Eckles.export({ jwk: certKey.private }))
  cert.signatureValue = new BitString({ valueHex: signResult })

  return {
    keyPair: certKey,
    cert: `-----BEGIN CERTIFICATE-----
${Buffer.from(cert.toSchema(true).toBER(false)).toString('base64').replace(/(.{64})/g, '$1\n')}
-----END CERTIFICATE-----
`
  }
}

const toPublicKeyInfo = async jwk => {
  const pem = await Eckles.export({ jwk })
  const data = Forge.pem.decode(pem)[0]
  const asn1 = fromBER(stringToArrayBuffer(data.body))
  return new PublicKeyInfo({ schema: asn1.result })
}

function stringToArrayBuffer (str) {
  const stringLength = str.length

  const resultBuffer = new ArrayBuffer(stringLength)
  const resultView = new Uint8Array(resultBuffer)

  for (let i = 0; i < stringLength; i++) {
    resultView[i] = str.charCodeAt(i)
  }

  return resultBuffer
}

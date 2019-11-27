const { ec: EC } = require('elliptic')

exports.privateKeyToCertificate = privateKey => {
  const ec = new EC('p256')
  const certKey = ec.genKeyPair()
  const privateKeyBytes = privateKey.public().marshal()
  const publicCertKey = certKey.getPublic()
}

const toIterable = require('stream-to-it')

module.exports = ({ socket, session, localAddr, remoteAddr, localPeer, remotePeer, stat }, options) => {
  options = options || {}

  const capableConn = {
    sess: session,
    localAddr,
    remoteAddr,
    localPeer,
    remotePeer,

    openStream () {
      const stream = session.openStream({ halfOpen: false })
      return toIterable.duplex(stream)
    },

    onStream: null,

    close () {
      // TODO: close gracefully?
      session.destroy()
      // TODO: socket reuse, destroy when no sessions left
    },

    stat
  }

  session.on('stream', stream => {
    if (!capableConn.onStream) return stream.end()
    capableConn.onStream(toIterable.duplex(stream))
  })

  return capableConn
}

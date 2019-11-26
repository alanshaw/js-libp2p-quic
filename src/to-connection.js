const toIterable = require('stream-to-it')
const MSS = require('multistream-select')
const { Connection } = require('libp2p-interfaces/src/connection')

module.exports = ({ socket, session, localAddr, localPeer, remotePeer, stat }, options) => {
  options = options || {}

  stat.timeline.upgraded = Date.now()

  return new Connection({
    localAddr,
    remoteAddr: options.remoteAddr,
    localPeer,
    remotePeer,

    // TODO: move multistream select out of Connection interface
    // This should just be openStream()
    newStream (protocols) {
      const stream = session.openStream({ halfOpen: false })
      const mss = new MSS.Dialer(toIterable.duplex(stream))
      return mss.select(protocols)
    },

    close () {
      // TODO: close gracefully?
      session.destroy()
      // TODO: socket reuse, destroy when no sessions left
    },

    getStreams () {
      return [] // TODO: keep track of streams
    },

    stat
  })
}

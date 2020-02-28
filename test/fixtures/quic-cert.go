package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	tls "github.com/libp2p/go-libp2p-tls"
)

func generateCert() {
	privKey, _, _ := ic.GenerateKeyPair(ic.RSA, 2048)
	privKeyBytes, _ := privKey.Bytes()
	privKeyB64 := base64.StdEncoding.EncodeToString(privKeyBytes)
	peerId, _ := peer.IDFromPrivateKey(privKey)

	identity, _ := tls.NewIdentity(privKey)
	conf, _ := identity.ConfigForAny()

	cert := fmt.Sprintf(
		"-----BEGIN CERTIFICATE-----%v-----END CERTIFICATE-----",
		base64.StdEncoding.EncodeToString(conf.Certificates[0].Certificate[0]),
	)

	json, _ := json.MarshalIndent(struct{ PeerID, PrivKey, Cert string }{
		PeerID:  peerId.String(),
		PrivKey: privKeyB64,
		Cert:    cert,
	}, "", "  ")

	fmt.Printf("%s", json)
}

func parseCert() {
	certBytes, _ := base64.StdEncoding.DecodeString("MIIDTjCCAvSgAwIBAgIMATKgIx4Ocomf7TBLMAoGCCqGSM49BAMCMAIxADAiGA8wMDAxMDEwMTAwMDAwMFoYDzIxMTkwMjA0MTUwNzE5WjACMQAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATgex0Z6QaCWQWwhvY6hQtlcpuhuS1hFm9hwbvfoHIb6iePiygelE8uMwS2DhxZJqoUee0gYt8g9zeOOnKd/tYvo4ICSjCCAkYwggJCBgorBgEEAYOiWgEBBIICMjCCAi4EggEmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx+GSkLttp8VDXjSUBgY42xXC2J2/JCmt4bJ4k4I2gV6D99JM4VKrEPkYzBAHUV14JC3ul2x8Y+ZIUVP0ve95tytOtE7bb5cZjO4du0+4pSpY6WwsTDjD24btNaGcmcMH90kYV1nGwR2Y7isYTyF90zQyPJxnCthA+l3zD6+lYEY3Dn0Dq5I9HRPX2rZUQC5cpzoitASHiUGs2hJmEb+YMU7vggvti/VYZiJ7yElxArAqTn8TsnGtonxp/Wwnr89DXjbHBOPGdBtyLXNRqpAhRLbW5bT3ppHWzJ2cneixSiTMsY4y1d+F/cUxOtKfC0Cn826X/VbG6XoFimRZjD8aXwIDAQABBIIBAHnz3a/HrW7B08EPtoW20EcRXByNmons+QftmOhJmjxcau5XOoHndjE5H35o3JfmnSqHK6E6rSwlA+Vl1yU1ml2spOL01/Egbx82fKkZrCPpcsy4cb+VAxKCxJqZ2vUSkjiVwuSkVQLRflJAG/X9jiNLgR87y/WnqJL3Wf1NpbKc31o992CUInpbOMklBUOkexYKiYnQpd4WqY2oSX1tURwVN9pt55d91EGlymBCjWmiBOoCDxQruBJpAT3gY6FlfLM3klO52qkUNA4roxVdmKDFnUDPHurpeJAloK+DzVJjB4Y8JrXj8elCULOpKtEPpCWVV0q657W8tDhX36ehkRwwCgYIKoZIzj0EAwIDSAAwRQIhAJmGQXdbVLiN5xVEBUzookYs8pL6N8bmx49XMNNBQyI5AiBDQAqgfVTD5p/uksklrt+mJNzBZE/3QVi0prCqSlKXBA==")
	cert, err := x509.ParseCertificate(certBytes)

	if err != nil {
		log.Fatalln("Failed to parse cert", err)
	}

	pubKey, err := tls.PubKeyFromCertChain([]*x509.Certificate{cert})

	if err != nil {
		log.Fatalln("Failed to extract public key from cert chain", err)
	}

	fmt.Println(pubKey)
}

func main() {
	generateCert()
	// parseCert()
}

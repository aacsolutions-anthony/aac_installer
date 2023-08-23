// The author of this code is not affiliated with, endorsed by, or associated with Microsoft or any of its subsidiaries or affiliates.
//
//DATE          : 23/08/2023
//AUTHOR        : ANTHONY GRACE
//COMPANY       : AAC SOLUTIONS PTY LTD
//DEPARTMENT    : IT TECHNICIAN
//COMP / VERSION: BETA-0.0.1
//
// PRG: AAC INSTALLER 
// PUR: Install and automate the server setup checklist. 
//


import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
)



//IMPORT OTHER VARIABLES HERE
// JSON VARS TO COME FROM MATT

type Config struct {
	AuthToken string `json:"authtoken"`
	Label     string `json:"label"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
}

func buildPowerShellScript(lines ...string) string {
	return strings.Join(lines, "; ")
}



// BELOW TO BE IMPLEMENTED, SSL CERT GENERATION

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

var pem = "cert.pem"
var key = "cert.key"

func genCert() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			Country:            []string{"AU"},
			Organization:       []string{"AAC Solutions Pty Ltd"},
			OrganizationalUnit: []string{"IT"},
		},
		SignatureAlgorithm:    x509.SHA512WithRSA,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 10),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		log.Fatalf("create cert failed %#v", err)
		return
	}
	log.Println("save", pem)
	ioutil.WriteFile(pem, ca_b, 0644)
	log.Println("save", key)
	ioutil.WriteFile(key, x509.MarshalPKCS1PrivateKey(priv), 0644)
}

func main() {
	if _, err := ioutil.ReadFile(pem); err != nil {
		if _, err := ioutil.ReadFile(key); err != nil {
			log.Println("No certs found, generating new self-signed certs.")
			genCert()
		}
	}
}

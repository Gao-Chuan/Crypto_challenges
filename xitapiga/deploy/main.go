package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Nik-U/pbc"
)

var pl = fmt.Println

var service = ":10068"

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
	}
}

func _min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func _bytesXor(msg, hash []byte) []byte {
	buf := hash
	for i := 0; i < _min(len(msg), len(hash)); i++ {
		buf[i] = msg[i] ^ hash[i]
	}
	return buf
}

func _hash(msg []byte) []byte {
	sum := sha256.Sum256(msg)
	return sum[:]
}

func _eccEnc(x, bg, bh, msg []byte) (c []byte) {
	var buffer bytes.Buffer
	buffer.Write(x)
	buffer.Write(bg)
	buffer.Write(bh)
	buffer.Write(msg)

	c = _hash(buffer.Bytes())
	return c
}

func _eccDec(key, c1 []byte, c2x, c2y *big.Int, curve elliptic.Curve) (msg []byte) {
	tx, ty := curve.ScalarMult(c2x, c2y, key)
	t := _hash(elliptic.Marshal(curve, tx, ty))
	msg = _bytesXor(c1, t)
	return msg
}

func Enc(msg, key, bg, bh []byte) (c []byte) {
	r := big.NewInt(0)
	r.SetString("730750818665534535851578973600197997769233793023", 0)
	paramString := `type a
	q 3698984342507268824966932197768218730881052393607057553754621459570209307990270984339599664803672825013615138006559004830434348693880950080625538841829179
	h 5061895584683974307210596086928108717023019017803612190717456473103941840033472072728744574582803149758660
	r 730750818665534535851578973600197997769233793023
	exp2 159
	exp1 116
	sign1 1
	sign0 -1`
	pbc.SetCryptoRandom()

	pairing, err := pbc.NewPairingFromString(paramString)
	checkError(err)

	bgp := pairing.NewG1()
	bhp := pairing.NewG2()

	bgp.SetBytes(bg)
	bhp.SetBytes(bh)

	msgI := big.NewInt(1)
	msgI.SetBytes(msg)
	keyI := big.NewInt(1)
	keyI.SetBytes(key)

	bgp.MulBig(bgp, msgI)
	bhp.MulBig(bhp, keyI)

	xp := pairing.NewGT()
	xp.Pair(bgp, bhp)

	c = _eccEnc(xp.Bytes(), bgp.Bytes(), bhp.Bytes(), msg)
	return c
}

func Dec(key, c1, c2 []byte, curve elliptic.Curve) (msg []byte) {
	c2x, c2y := elliptic.Unmarshal(curve, c2)
	return _eccDec(key, c1, c2x, c2y, curve)
}

var blockSize = 32

func _padding(msg []byte) []byte {
	padding := blockSize - len(msg)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(msg, padtext...)
}

func Ecmac(msg, key, bg, bh []byte) []byte {
	msg = _padding(msg)
	var msgSlice [][]byte
	var mac []byte

	for i := 0; i < len(msg)/blockSize; i++ {
		msgSlice = append(msgSlice, msg[i*32:(i+1)*32])
	}

	for i, e := range msgSlice {
		if i == 0 {
			mac = Enc(e, key, bg, bh)
		} else {
			mac = Enc(e, mac, bg, bh)
		}
	}

	return mac
}

func VerifyEcmac(mac, msg, key, bg, bh []byte) bool {
	return bytes.Equal(Ecmac(msg, key, bg, bh), mac)
}

func main() {
	r := big.NewInt(0)
	r.SetString("730750818665534535851578973600197997769233793023", 0)
	paramString := `type a
	q 3698984342507268824966932197768218730881052393607057553754621459570209307990270984339599664803672825013615138006559004830434348693880950080625538841829179
	h 5061895584683974307210596086928108717023019017803612190717456473103941840033472072728744574582803149758660
	r 730750818665534535851578973600197997769233793023
	exp2 159
	exp1 116
	sign1 1
	sign0 -1`
	pbc.SetCryptoRandom()

	pairing, err := pbc.NewPairingFromString(paramString)
	checkError(err)

	bgp := pairing.NewG1()
	bhp := pairing.NewG2()
	bgp.Rand()
	bhp.Rand()

	key, err := ioutil.ReadFile("sign.key")
	checkError(err)

	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, bgp.Bytes(), bhp.Bytes(), key)
	}
}

func handleClient(conn net.Conn, bg, bh, key []byte) {
	conn.SetReadDeadline(time.Now().Add(time.Minute))
	defer conn.Close()

	conn.Write([]byte("\nYour params:>>"))
	conn.Write([]byte("\n" + hex.EncodeToString(bg)))
	conn.Write([]byte("\n" + hex.EncodeToString(bh)))
	challengerName := make([]byte, 1024)
	conn.Write([]byte("\nShow me your name:>>"))
	readLen, err := conn.Read(challengerName)
	if err != nil {
		return
	}
	if readLen == 0 {
		return
	}
	if strings.Contains(string(challengerName), "admin") {
		conn.Write([]byte("\nNo \"admin\" in your name!"))
		return
	} else {
		name := challengerName[:readLen]
		signature := Ecmac(name, key, bg, bh)
		conn.Write([]byte("\nYour signature:>>"))
		signB := []byte(hex.EncodeToString(signature))
		conn.Write(signB)
	}

	signedFromChallenger := make([]byte, 1024)
	conn.Write([]byte("\nShow me your signature:>>"))
	readLen, err = conn.Read(signedFromChallenger)
	if err != nil {
		return
	}
	if readLen == 0 {
		return
	}

	challengerFakeName := make([]byte, 1024)
	conn.Write([]byte("\nShow me your name:>>"))
	nmreadLen, err := conn.Read(challengerFakeName)
	if err != nil {
		return
	}
	if nmreadLen == 0 {
		return
	}
	if strings.Contains(string(challengerFakeName), "admin") {
		fakeSign, err := hex.DecodeString(string(signedFromChallenger[:readLen-1]))
		checkError(err)
		fakeName := challengerFakeName[:nmreadLen]
		res := VerifyEcmac(fakeSign, fakeName, key, bg, bh)

		if res {
			var flag, _ = ioutil.ReadFile("flag.txt")
			conn.Write(flag)
		} else {
			conn.Write([]byte("\nWrong!\n"))
		}
	} else {
		fakeSign, err := hex.DecodeString(string(signedFromChallenger[:readLen-1]))
		checkError(err)
		fakeName := challengerFakeName[:nmreadLen]
		res := VerifyEcmac(fakeSign, fakeName, key, bg, bh)

		// res := VerifyEcmac(fakeSign, challengerFakeName, key, bg, bh)

		if res {
			conn.Write([]byte("\nHello, "))
			conn.Write(fakeName)
		} else {
			conn.Write([]byte("\nWrong!\n"))
		}

	}

	return
}

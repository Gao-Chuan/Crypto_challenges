package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Nik-U/pbc"
)

const (
	port = 10086
)

func getflag(conn net.Conn) {
	w := bufio.NewWriter(conn)
	content, _ := ioutil.ReadFile("flag.txt")
	w.Write([]byte(content))
	w.Flush()
}

func hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sign(sk *pbc.Element, msg string, pairing *pbc.Pairing) *pbc.Element {
	hm := pairing.NewG2().SetFromStringHash(msg, sha256.New())
	sig := pairing.NewG2().PowZn(hm, sk)
	return sig
}

func verify(pk *pbc.Element, user_pk *pbc.Element, msg string, sig *pbc.Element, pairing *pbc.Pairing, g *pbc.Element) bool {
	h1_raw := binary.BigEndian.Uint16(hash([]byte(pk.String()))[:2])
	h2_raw := binary.BigEndian.Uint16(hash([]byte(user_pk.String()))[:2])
	h1 := pairing.NewZr().SetInt32(int32(h1_raw))
	h2 := pairing.NewZr().SetInt32(int32(h2_raw))
	hm := pairing.NewG2().SetFromStringHash(msg, sha256.New())
	apk := pairing.NewG1().Add(pairing.NewG1().MulZn(pk, h1), pairing.NewG1().MulZn(user_pk, h2))

	return pairing.NewGT().Pair(apk, hm).String() == pairing.NewGT().Pair(g, sig).String()
}

func handler(conn net.Conn) {
	defer conn.Close()

	var (
		buf  = make([]byte, 2048)
		r    = bufio.NewReader(conn)
		w    = bufio.NewWriter(conn)
		menu = "\n1.Register\n2.Sign in\n"
	)

	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
	g := pairing.NewG1().Rand()

	sharedParams := params.String()

	w.Write([]byte(sharedParams))
	w.Write([]byte("\ng:>>"))
	w.Write([]byte(hex.EncodeToString(g.Bytes())))

	privKey := pairing.NewZr().Rand()
	pubKey := pairing.NewG1().PowZn(g, privKey)
	w.Write([]byte("\nPublic Key:>>"))
	w.Write([]byte(hex.EncodeToString(pubKey.Bytes()) + "\n"))
	h1_raw := binary.BigEndian.Uint16(hash([]byte(pubKey.String()))[:2])
	if h1_raw < 100 {
		w.Write([]byte("\nYou are not lucky.\n"))
		w.Write([]byte("\nTry again\n"))
		w.Flush()
		return
	}

	w.Write([]byte("\nWelcome to BLS v2.\nShow me your public key:>>"))
	w.Flush()
	n, _ := r.Read(buf)
	if n <= 0 {
		return
	}
	decoded, err := hex.DecodeString(strings.Trim(string(buf[:n]), "\n"))
	if err != nil {
		w.Write([]byte("Invalid public key."))
		w.Flush()
		return
	}
	user_pb := pairing.NewG1().SetBytes(decoded)

	for i := 0; i < 10; i++ {
		w.Write([]byte(menu))
		w.Flush()
		n, _ := r.Read(buf)
		if n <= 0 {
			return
		}
		data := string(buf[:n])
		switch data[0] {
		case '1':
			//Sign
			w.Write([]byte("What's your name:>>\n"))
			w.Flush()
			n, _ := r.Read(buf)
			name := strings.Trim(string(buf[:n]), "\n")
			if strings.Contains(name, "admin") {
				w.Write([]byte("\nNo you are not.\n"))
				w.Flush()
				return
			}
			sig := sign(privKey, name, pairing)
			w.Write([]byte("This is your ticket:>>"))
			w.Write([]byte(hex.EncodeToString(sig.Bytes()) + "\n"))
			w.Flush()
		case '2':
			//Verify
			w.Write([]byte("What's your name:>>\n"))
			w.Flush()
			n, _ := r.Read(buf)
			if n <= 0 {
				return
			}
			name := strings.Trim(string(buf[:n]), "\n")
			w.Write([]byte("What's your ticket:>>\n"))
			w.Flush()
			n, _ = r.Read(buf)
			if n <= 0 {
				return
			}
			decoded, err := hex.DecodeString(strings.Trim(string(buf[:n]), "\n"))
			if err != nil {
				w.Write([]byte("Invalid ticket."))
				w.Flush()
				return
			}
			user_sig := pairing.NewG2().SetBytes(decoded)
			if verify(pubKey, user_pb, name, user_sig, pairing, g) && name == "admin" {
				getflag(conn)
				return
			} else if verify(pubKey, user_pb, name, user_sig, pairing, g) {
				w.Write([]byte("hi, " + name + "\n"))
				w.Flush()
			} else {
				w.Write([]byte("Invalid ticket. Exiting..."))
				w.Flush()
				return
			}
		default:
			w.Write([]byte("Invalid choice. Exiting..."))
			w.Flush()
			return
		}
		w.Flush()
	}
}

func main() {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("Socket listen port %d failed,%s", port, err)
		os.Exit(1)
	}
	defer l.Close()
	log.Printf("Listening port: %d", port)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalln(err)
			continue
		}
		go handler(conn)
	}
}

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Nik-U/pbc"
)

func hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func verify(pk *pbc.Element, user_pk *pbc.Element, msg string, sig *pbc.Element, pairing *pbc.Pairing, g *pbc.Element) bool {
	h1_raw := binary.BigEndian.Uint16(hash([]byte(pk.String()))[:2])
	h2_raw := binary.BigEndian.Uint16(hash([]byte(user_pk.String()))[:2])
	h1 := pairing.NewZr().SetInt32(int32(h1_raw))
	h2 := pairing.NewZr().SetInt32(int32(h2_raw))
	fmt.Printf("h1 and h2:>> %d, %d\n", h1, h2)
	hm := pairing.NewG2().SetFromStringHash(msg, sha256.New())
	apk := pairing.NewG1().Add(pairing.NewG1().MulZn(pk, h1), pairing.NewG1().MulZn(user_pk, h2))

	return pairing.NewGT().Pair(apk, hm).String() == pairing.NewGT().Pair(g, sig).String()
}

func SocketClient(ip string, port int) {

	addr := strings.Join([]string{ip, strconv.Itoa(port)}, ":")
	conn, err := net.Dial("tcp", addr)

	var (
		buf = make([]byte, 2048)
		r   = bufio.NewReader(conn)
		w   = bufio.NewWriter(conn)
	)

	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}

	defer conn.Close()

	n, _ := r.Read(buf)
	re := regexp.MustCompile(`type.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n`)
	param := re.Find(buf[:n])
	re = regexp.MustCompile(`g:>>.*`)
	sharedG, _ := hex.DecodeString(string(re.Find(buf[:n])[4:]))
	re = regexp.MustCompile(`Public Key:>>.*`)
	pk_b, _ := hex.DecodeString(string(re.Find(buf[:n])[13:]))

	pairing, _ := pbc.NewPairingFromString(string(param))
	g := pairing.NewG1().SetBytes(sharedG)
	pubKey := pairing.NewG1().SetBytes(pk_b)
	// fmt.Println(hex.EncodeToString(g.Bytes()))
	// fmt.Println(hex.EncodeToString(pubKey.Bytes()))

	h1 := int32(binary.BigEndian.Uint16(hash([]byte(pubKey.String()))[:2]))
	fmt.Printf("h1:>> %d\n", h1)

	pub_user := pairing.NewG1()
	beta := pairing.NewZr()

	i := 2
	for ; i < 262144; i++ {
		beta = pairing.NewZr().Rand()
		pb_tmp := pairing.NewG1().Sub(pairing.NewG1().MulZn(g, beta), pubKey)
		h2 := int32(binary.BigEndian.Uint16(hash([]byte(pb_tmp.String()))[:2]))
		if h2 == h1 {
			pub_user.Set(pb_tmp)
			break
		}
	}

	fmt.Println("The i is:>>" + fmt.Sprint(i))

	w.Write([]byte(hex.EncodeToString(pub_user.Bytes())))
	w.Flush()

	n, _ = r.Read(buf)
	fmt.Println(string(buf[:n]))

	w.Write([]byte("2"))
	w.Flush()

	n, _ = r.Read(buf)
	fmt.Println(string(buf[:n]))

	w.Write([]byte("admin"))
	w.Flush()

	n, _ = r.Read(buf)
	fmt.Println(string(buf[:n]))

	hm := pairing.NewG2().SetFromStringHash("admin", sha256.New())
	h := pairing.NewZr().SetInt32(h1)
	sig := pairing.NewG2().MulZn(pairing.NewG2().MulZn(hm, beta), h)
	w.Write([]byte(hex.EncodeToString(sig.Bytes())))
	w.Flush()

	fmt.Println(verify(pubKey, pub_user, "admin", sig, pairing, g))

	n, _ = r.Read(buf)
	fmt.Println(string(buf[:n]))

	os.Exit(1)
}

func main() {

	var (
		ip   = "127.0.0.1"
		port = 10086
	)

	for {
		SocketClient(ip, port)
	}

}

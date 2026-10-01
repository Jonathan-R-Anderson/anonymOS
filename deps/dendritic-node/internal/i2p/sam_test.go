package i2p

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

type fakeSAM struct {
	listener net.Listener
	public   string
	private  string
	wg       sync.WaitGroup
}

func openFakeSAM(t *testing.T) *fakeSAM {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicBytes := make([]byte, 387)
	for index := range publicBytes {
		publicBytes[index] = byte(index)
	}
	public := strings.NewReplacer("+", "-", "/", "~").Replace(
		base64.StdEncoding.EncodeToString(publicBytes),
	)
	server := &fakeSAM{
		listener: listener,
		public:   public,
		private:  public + strings.Repeat("A", 368),
	}
	server.wg.Add(1)
	go server.serve()
	t.Cleanup(func() {
		listener.Close()
		server.wg.Wait()
	})
	return server
}

func (s *fakeSAM) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			reader := bufio.NewReader(conn)
			line, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "HELLO VERSION") {
				return
			}
			io.WriteString(conn, "HELLO REPLY RESULT=OK VERSION=3.3\n")
			line, err = reader.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "DEST GENERATE"):
				fmt.Fprintf(conn, "DEST REPLY PUB=%s PRIV=%s\n", s.public, s.private)
			case strings.HasPrefix(line, "SESSION CREATE"):
				io.WriteString(conn, "SESSION STATUS RESULT=OK DESTINATION="+s.public+"\n")
				line, err = reader.ReadString('\n')
				if err != nil || line != "NAMING LOOKUP NAME=ME\n" {
					return
				}
				io.WriteString(conn, "NAMING REPLY RESULT=OK NAME=ME VALUE="+s.public+"\n")
				io.Copy(io.Discard, reader)
			case strings.HasPrefix(line, "STREAM CONNECT"):
				io.WriteString(conn, "STREAM STATUS RESULT=OK\n")
				io.Copy(io.Discard, reader)
			}
		}()
	}
}

func TestSessionPersistsDestinationAndDialsBase32(t *testing.T) {
	server := openFakeSAM(t)
	keyPath := t.TempDir() + "/i2p.destination"
	session, err := Open(context.Background(), server.listener.Addr().String(), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if len(session.Base32()) != 52 {
		t.Fatalf("unexpected Base32 destination: %q", session.Base32())
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private destination mode is %o", info.Mode().Perm())
	}
	conn, err := session.Dial(context.Background(), session.Base32())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(conn.RemoteAddr().String(), ".b32.i2p") {
		t.Fatalf("remote address leaked a non-I2P endpoint: %s", conn.RemoteAddr())
	}
	conn.Close()
}

func TestMultiaddrRejectsClearnet(t *testing.T) {
	address, err := Multiaddr(strings.Repeat("a", 52))
	if err != nil {
		t.Fatal(err)
	}
	if !IsI2PAddr(address) {
		t.Fatal("garlic32 address was not recognized")
	}
	clearnet, err := ma.NewMultiaddr("/ip4/192.0.2.1/tcp/4001")
	if err != nil {
		t.Fatal(err)
	}
	if IsI2PAddr(clearnet) {
		t.Fatal("clearnet multiaddress was accepted as I2P")
	}
}

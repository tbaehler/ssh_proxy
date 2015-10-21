package main

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
	"fmt"
)

const (
	APPLICATION_HEADER = "application/x-ssh"
)

var (
	url (string)
	linfo  = log.New(os.Stderr, "INFO ", log.LstdFlags)
	lerr   = log.New(os.Stdout, "ERROR ", log.LstdFlags)
	ldebug = log.New(ioutil.Discard, "DEBUG ", log.LstdFlags)
	debugon = false
	maxSleepTime = time.Second *3
)

func debugOutOf(data []byte) {
	if !debugon {
		return
	}
	ldebug.Printf("Dumping data (max 50 bytes)")
	
	for i:=0;i<len(data) && i<50;i++{
		print(data[i])
	}
	println()
}

func handleMessage(c net.Conn) error {
	defer c.Close()
	var err error
	for {
		buf := make([]byte, 256*1024)

		for {
			readCharacters := 0

			err = nil
			nr := 0
			c.SetReadDeadline(time.Now().Add(maxSleepTime))

			for readCharacters < 5 && err == nil {
				nr, err = c.Read(buf[readCharacters:])
				readCharacters += nr
				ldebug.Printf("read :%d\n", nr)
				if err != nil {
					ldebug.Printf("read channel closed\n")
					return nil
				}
			}
			data := buf[:readCharacters]
			if readCharacters < 4 || readCharacters >= 256*1024 {
				return errors.New("msg from ssh to small/big")
			}
			debugOutOf(data)			

			str := base64.StdEncoding.EncodeToString(buf)
			ldebug.Printf("send request")
			resp, err := http.Post(url, APPLICATION_HEADER, strings.NewReader(str))
			if err != nil {
				return err
			}
			ldebug.Printf("try to read answer")
			hash, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			answer, err := base64.StdEncoding.DecodeString(string(hash))
			if err != nil {
				return err
			}
			if len(answer) < 4 {
				debugOutOf(answer)
				return errors.New("answer too short ignorinig it")
			}
			size := binary.BigEndian.Uint32(answer[:4]) + 4
			ldebug.Printf("data2Answer")
			debugOutOf(answer)
		
			nr, err = c.Write(answer[:size])
			ldebug.Printf("wrote :%d\n", nr)
			if err != nil {
				return err
			}

		}
		ldebug.Printf("read finished")

	}
	return nil
}

func handleSignal(l net.Listener) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		for _ = range c {
			l.Close()
		}
	}()
}

func main() {
	hn,_ := os.Hostname()
	url = fmt.Sprintf("http://%s:8483/",hn)
	sock := "/tmp/ssh-agent.sock"
	pid := os.Getpid() 
	
	//unset Proxy settings
	os.Setenv("http_proxy","")
	os.Setenv("https_proxy","")
	
	for _, arg := range os.Args {
		if arg == "-d" {
			ldebug = log.New(os.Stdout, "DEBUG ", log.LstdFlags)
			debugon = true
			ldebug.Printf("Debug on")
		} 
	}
	
	l, err := net.Listen("unix", sock)
	if err != nil {
		lerr.Printf("listen error %v", err)
		return
	}
	//handle signal
	handleSignal(l)
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n",sock)
	fmt.Printf("SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n",pid)
	fmt.Printf("echo Agent pid %d;\n",pid)
	for {
		fd, err := l.Accept()
		ldebug.Printf("accept\n")
		if err != nil {
			lerr.Printf("error in accept: %v", err)
			return
		}

		go handleMessage(fd)
	}
}

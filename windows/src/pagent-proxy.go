package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"net"
	"strings"
	"pgutil"
	"sync"
)

const (
	APPLICATION_HEADER                = "application/x-ssh"
	SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1
	SSH_AGENT_RSA_IDENTITIES_ANSWER   = 2

	SSH2_AGENTC_REQUEST_IDENTITIES = 11
	SSH2_AGENT_IDENTITIES_ANSWER   = 12
	SSH2_AGENTC_SIGN_REQUEST       = 13
	SSH2_AGENT_SIGN_RESPONSE       = 14

	SSH_AGENT_SUCCESS = 6
	SSH_AGENT_FAILURE = 5
)

func copyBlob(data []byte, toCopy []byte) int {
	ldebug.Printf("Copy String data size:%d toCopy size:%d\n", len(data), len(toCopy))
	binary.BigEndian.PutUint32(data, uint32(len(toCopy)-1))
	for idx := 0; idx < len(toCopy); idx++ {
		data[idx+4] = toCopy[idx]
	}
	return len(toCopy) + 4 - 1
}

func copyString(data []byte, toCopy []byte) int {
	ldebug.Printf("Copy String data size:%d toCopy size:%d\n", len(data), len(toCopy))
	binary.BigEndian.PutUint32(data, uint32(len(toCopy)))
	for idx := 0; idx < len(toCopy); idx++ {
		data[idx+4] = toCopy[idx]
	}

	return len(toCopy) + 4
}

func readBlob(data []byte) (int, []byte) {
	ldebug.Printf("Read Blob\n")
	size := int(binary.BigEndian.Uint32(data))
	pos := 4
	blob := make([]byte, size+1)
	for idx := 0; idx <= size; idx++ {
		blob[idx] = data[pos+idx]
	}
	return size, blob
}

func debugOutOf(data []byte) {
	if !debugon {
		return
	}
	ldebug.Printf("Dumping data (max 50 bytes)")

	for i := 0; i < len(data) && i < 50; i++ {
		print(data[i])
	}
	println()
}

func send_failed(w http.ResponseWriter) {
	data := make([]byte, 5)
	data[3] = 1
	data[4] = SSH_AGENT_FAILURE
	str := base64.StdEncoding.EncodeToString(data)
	w.Write([]byte(str))
}

func process_sign_request_identities(w http.ResponseWriter, data []byte) {
	//size of blob
	ldebug.Println("in process_sign")

	sizeOfBlob, blob := readBlob(data)
	pos := sizeOfBlob + 4 //and 4bytes size
	ldebug.Printf("size of key to sign:%d\n", sizeOfBlob)
	sizeOfDataToSign, data2Sign := readBlob(data[pos:])
	ldebug.Printf("size of data to sign:%d\n", sizeOfDataToSign)

	ident := new(pgutil.Identity)
	ident.Blob = blob

	signature, err := ident.Sign(agent, data2Sign, sizeOfDataToSign)
	if err != nil {
		lerr.Printf("was not able to sign: \v \n", err)
		send_failed(w)
		return
	}
	ldebug.Printf("signature\n")
	ldebug.Printf(hex.Dump(signature.Signature))

	//size
	binary.BigEndian.PutUint32(data, uint32(len(signature.Signature)+9))
	data[4] = SSH2_AGENT_SIGN_RESPONSE
	//copy Signature
	copyString(data[5:], signature.Signature)

	str := base64.StdEncoding.EncodeToString(data)

	w.Write([]byte(str))
	ldebug.Printf("response sent\n")
	return
}

func process_request_identities(w http.ResponseWriter, protocol int) {
	data := make([]byte, 256*1024)
	size := 5
	if protocol == 1 {
		//we do not support version 1 so return empty answer
		data[3] = 5
		data[4] = SSH_AGENT_RSA_IDENTITIES_ANSWER
		//number of entries
		data[8] = 0
	} else {
		identities, err := agent.Query()
		if err != nil {
			lerr.Printf("Cannot query agent\n", err)
			lerr.Printf("I try to reconnect\n");
			agent.Close()
			err := agent.Connect()
			if err != nil {
				lerr.Printf("reconnect failed\n");
			}
			send_failed(w)
			return
		}
		offset := 4
		data[4] = SSH2_AGENT_IDENTITIES_ANSWER
		data[8] = byte(len(identities))
		nr := 0
		for ident := 0; ident < len(identities); ident++ {
			//len of blob as int
			nr = copyBlob(data[(size+offset):], identities[ident].Blob)
			size += nr
			nr = copyString(data[(size+offset):], []byte(identities[ident].Name))
			size += nr
		}

		//size
		binary.BigEndian.PutUint32(data, uint32(size))
		size += 4
	}

	ldebug.Printf("data2Answer\n")
	debugOutOf(data)

	str := base64.StdEncoding.EncodeToString(data)
	ldebug.Printf("send response\n")
	w.Write([]byte(str))
	return
}

func handler(w http.ResponseWriter, r *http.Request) {
	//only local address is accepted
	
	//because we use shared memory. each request need to be sequential. 
	//one can use channels with only one writer, or just use a lock
	lock.Lock()
	//make sure we unlock at end of method.
	defer lock.Unlock()
	adr, _ := net.LookupHost(hostname)
	allowed := false
	for _, a := range adr {
		if strings.Contains(r.RemoteAddr, a){
			ldebug.Printf("found matching local ip, access granted")
			allowed =true
		}
	}
	if !allowed {
		lerr.Printf("access not granted for this ip")
		return
	}
	
	hash, err := ioutil.ReadAll(r.Body)

	if err != nil {
		fmt.Fprintf(w, "%s", err)
	}

	data, err := base64.StdEncoding.DecodeString(string(hash))
	if err != nil {
		lerr.Printf("Cannot query agent\n", err)
		send_failed(w)
		return
	}
	ldebug.Printf("got request\n")

	debugOutOf(data)

	command := data[4]
	ldebug.Printf("\n Command:%d", command)
	switch command {
	case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
		linfo.Printf("reveiced SSH_AGENTC_REQUEST_RSA_IDENTITIES\n")
		process_request_identities(w, 1)
		return
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		linfo.Printf("reveiced SSH2_AGENTC_REQUEST_IDENTITIES\n")
		process_request_identities(w, 2)
		return
	case SSH2_AGENTC_SIGN_REQUEST:
		linfo.Printf("reveiced SSH2_AGENTC_SIGN_REQUEST\n")
		process_sign_request_identities(w, data[5:])
		return

	default:
		linfo.Printf("default case send SSH_AGENT_FAILURE\n")
		send_failed(w)
		return
	}

}

var (
	agent   (*pgutil.Pagent)
	linfo   = log.New(os.Stderr, "INFO ", log.LstdFlags)
	lerr    = log.New(os.Stdout, "ERROR ", log.LstdFlags)
	ldebug  = log.New(ioutil.Discard, "DEBUG ", log.LstdFlags)
	debugon = false
	hostname,_ = os.Hostname()
	lock    = new(sync.Mutex)
)

func main() {
	linfo.Printf("Starting windows proxy Agent\n")

	for _, arg := range os.Args {
		if arg == "-d" {
			ldebug = log.New(os.Stdout, "DEBUG ", log.LstdFlags)
			debugon = true
			ldebug.Printf("Debug on")
		}
	}

	agent = new(pgutil.Pagent)
	err := agent.Connect()
	if err != nil {
		lerr.Fatalf("Cannot connect to agent, check if it is running. %v \n", err)
	}

	defer agent.Close()

	http.HandleFunc("/", handler)
	if err := http.ListenAndServe(":8483", nil); err != nil {
		lerr.Printf("Cannot bind to port 8483: %v \n", err)
	}
}

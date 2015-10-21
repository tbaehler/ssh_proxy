package pgutil

import (
	"encoding/binary"
	"syscall"
	"os"
	"fmt"
	"errors"
	"unsafe"

)

const (
	SSH2_AGENTC_REQUEST_IDENTITIES byte = 11
	WM_COPY_AREA = 0x4A
	SSH2_AGENTC_SIGN_REQUEST byte = 13;
    SSH2_AGENT_SIGN_RESPONSE byte = 14;
    MAX_MSG_LEN = 8192
)

var (
	MAPNAME = fmt.Sprintf("agentProxy%d", os.Getpid())
	user32, _ = syscall.LoadLibrary("user32.dll")
	
	procSendMessageW, _ = syscall.GetProcAddress(user32, "SendMessageW")
	findWindow, _       = syscall.GetProcAddress(user32, "FindWindowW")
)

	
type Identity struct {
	Blob []byte
	Type string
	Name string
}

type Pagent struct{
	Hwnd syscall.Handle
	Fmap syscall.Handle
	SharedMemory uintptr
	Data *[MAX_MSG_LEN]byte
} 

type Signature struct{
	Size int
	Signature [] byte
}

func ConvertToByteArray(mapname string) unsafe.Pointer {
	mapnameArr := make([]byte, len(mapname)+1)
	//convert to byte array for second convertsion
	for i, len := 0, len(mapname); i < len; i++ {
		mapnameArr[i] = byte(mapname[i])
	}
	mapnamePtr := unsafe.Pointer(&mapnameArr[0])
	return mapnamePtr
}


func GetCDSP(mapname string) []byte {
	msg := make([]byte, 24)

	binary.LittleEndian.PutUint64(msg, uint64(0x804e50ba)) //8byte
	binary.LittleEndian.PutUint64(msg[8:], uint64(len(mapname)+1))
	binary.LittleEndian.PutUint64(msg[16:], uint64((uintptr(ConvertToByteArray(mapname)))))
	return msg
}

func FindWindow(lpClassName, lpWindowName *uint16) (syscall.Handle, error) {
	ret, _, err := syscall.Syscall(findWindow, 2,
		uintptr(unsafe.Pointer(lpClassName)),
		uintptr(unsafe.Pointer(lpWindowName)),
		0)

	if err > 0 || ret == 0 {
		return syscall.Handle(ret), errors.New("pgagent not found")
	}
	return syscall.Handle(ret), nil
}

func SendMessage(hWnd syscall.Handle, Msg uint32, wParam int32, lParam uintptr) uintptr {
	ret, _, _ := syscall.Syscall6(uintptr(procSendMessageW), 4, uintptr(hWnd), uintptr(Msg), uintptr(wParam), uintptr(lParam), 0, 0)
	return uintptr(ret)
}

func (agent *Pagent) Connect() error{
	var err (error)
	agent.Hwnd, err = FindWindow(syscall.StringToUTF16Ptr("Pageant"), syscall.StringToUTF16Ptr("Pageant"))
	if (err != nil){
		return err
	}
	
	agent.Fmap, err = syscall.CreateFileMapping(syscall.InvalidHandle, nil, syscall.PAGE_READWRITE, 0, 8129, syscall.StringToUTF16Ptr(MAPNAME))
	if err != nil {
		return errors.New("CreateFileMapping failed..")
	}

	agent.SharedMemory, err = syscall.MapViewOfFile(agent.Fmap, syscall.FILE_MAP_WRITE, 0, 0, 0)
	if err != nil {
		return errors.New("Was not able to map agent..")
	}
	agent.Data = (*[MAX_MSG_LEN]byte)(unsafe.Pointer(agent.SharedMemory))
	return nil
}

func (agent Pagent) Close() {
	defer syscall.CloseHandle(agent.Hwnd)
	defer syscall.CloseHandle(agent.Fmap)
	defer syscall.UnmapViewOfFile(agent.SharedMemory) 
	 
}

func (agent Pagent) resetData() {
	for i:=0; i< MAX_MSG_LEN; i++ {
		agent.Data[i] = 0;
	}
}

func (ident Identity) Sign(agent *Pagent, s []byte, size int) (*Signature, error){
	agent.resetData()
	pos :=4
	agent.Data[pos] = SSH2_AGENTC_SIGN_REQUEST
	//string
	pos +=1
	binary.BigEndian.PutUint32(agent.Data[pos:], uint32(len(ident.Blob)-1))
	pos+=4
	for i, len := 0, len(ident.Blob); i < len; i++ {
		agent.Data[pos+i] = ident.Blob[i]
	}
	pos += len(ident.Blob)-1
	//binary.BigEndian.PutUint32(agent.Data[9:], uint32(uintptr(unsafe.Pointer(&ident.Blob))))
	
	binary.BigEndian.PutUint32(agent.Data[pos:], uint32(size))
	pos +=4
	for i, len := 0, len(s); i < len; i++ {
		agent.Data[pos+i] = byte(s[i])
	}
	pos += len(s)
	//size of Data
	binary.BigEndian.PutUint32(agent.Data[0:], uint32(pos))
	
	
	
	//informAgent
	msg := GetCDSP(MAPNAME)
	sig := new(Signature)
	sndmsg := SendMessage(agent.Hwnd, WM_COPY_AREA, 0, uintptr(unsafe.Pointer(&msg[0])))
	if (sndmsg == 0){
		return  nil, errors.New("sendMsg failed")
	}
	if (agent.Data[4] != SSH2_AGENT_SIGN_RESPONSE){
		return  nil, errors.New("agent did not return expectet msg")
	}
	
	/*println("data")
	for i := 0; i < pos; i++ {
		print(agent.Data[i])
		print(",")
	}*/
	
	pos = 5
	sig.Size = int(binary.BigEndian.Uint32(agent.Data[pos:]))
	pos += 4
	sig.Signature = make([]byte,sig.Size)
	
	for i := 0; i < sig.Size; i++ {
		sig.Signature[i] = agent.Data[pos+i]
	}
		
	return sig, nil
	
}
func (agent Pagent) Query()([]Identity, error){
	//query
	agent.resetData()
	agent.Data[4] = SSH2_AGENTC_REQUEST_IDENTITIES
	//size
	agent.Data[3] = 1
	
	//cdsMessage
	msg := GetCDSP(MAPNAME)
	//informAgent
	sndmsg := SendMessage(agent.Hwnd, WM_COPY_AREA, 0, uintptr(unsafe.Pointer(&msg[0])))
	if (sndmsg == 0){
		return nil, errors.New("sendMsg failed")
	}
	pos := 5
	size := binary.BigEndian.Uint32(agent.Data[pos:])
	pos += 4
	
	identities := make([] Identity, size)
	
	for i:=0; i< int(size); i++ {
    	identities[i],pos = ReadIdentity(*agent.Data, pos)
    }
	return identities, nil
}

func ConvertToString(bytes []byte) string {
	ret := ""
	for i:=0; i < len(bytes); i++ {
		ret += string(bytes[i])
	}
	
	return ret
}


func ReadIdentity(data [MAX_MSG_LEN] byte, pos int) (Identity, int) {
	ident := new(Identity)
	sizeOfString := binary.BigEndian.Uint32(data[pos:])
	//fmt.Printf("got sizeOfString:%d\n",sizeOfString)
	pos += 4
	end := pos+int(sizeOfString)
	ident.Blob = data[pos:end+1] //the end +1 
	pos += int(sizeOfString)
    
    sizeOfString = binary.BigEndian.Uint32(data[pos:])
    pos += 4
	//fmt.Printf("got sizeOfString2:%d\n",sizeOfString)
	ident.Name = ConvertToString(data[pos:pos+ int(sizeOfString)])
	pos += int(sizeOfString)
	
    return *ident, pos
}

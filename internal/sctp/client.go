package sctp

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/ishidawataru/sctp"
)

// 1. Định nghĩa lại Struct (Sửa lỗi undefined SctpConn)
type SctpConn struct {
	Conn *sctp.SCTPConn
}

func NewSctpConn(ip string, port int) *SctpConn {
	amfAddr := fmt.Sprintf("%s:%d", ip, port)
	addr, _ := sctp.ResolveSCTPAddr("sctp", amfAddr)
	
	conn, err := sctp.DialSCTP("sctp", nil, addr)
	if err != nil {
		log.Printf("❌ Lỗi kết nối SCTP: %v", err)
		return nil
	}

	// 2. XỬ LÝ LỖI PPID (Endianness fix)
	// AMF yêu cầu PPID = 60 (Big Endian). 
	// Trên máy Linux/Windows thường (Little Endian), số 60 bị lộn ngược.
	// Ta dùng binary.BigEndian để ép nó về đúng chuẩn mạng 5G.
	
	var ppidBuf [4]byte
	binary.BigEndian.PutUint32(ppidBuf[:], 60) // Ghi số 60 kiểu Big Endian vào buffer
	ppidFixed := binary.LittleEndian.Uint32(ppidBuf[:]) // "Đánh lừa" lib SCTP để gửi đúng 4 byte đó

	info := &sctp.SndRcvInfo{
		Stream: 0,
		PPID:   ppidFixed, // Sử dụng giá trị đã fix
	}
	
	conn.SetDefaultSentParam(info)

	return &SctpConn{Conn: conn}
}

func (s *SctpConn) GetConn() *sctp.SCTPConn {
	return s.Conn
}
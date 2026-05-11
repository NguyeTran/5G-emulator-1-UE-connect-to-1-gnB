package main

import (
	"fmt"
	"log"

	"emulator/internal/gnbcontext"
	"emulator/internal/sctp"
	"emulator/internal/uecontext"
	"emulator/pkg/config"
)

func main() {
	fmt.Println("=======================================")
	fmt.Println("🚀 KÍCH HOẠT GIAI ĐOẠN 3: UE REGISTER (BẢN FINAL)")
	fmt.Println("=======================================")

	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("❌ Lỗi nạp config: %v", err)
	}

	sctpClient := sctp.NewSctpConn(cfg.AMF.IP, cfg.AMF.Port)
	if sctpClient == nil {
		log.Fatal("❌ Không thể kết nối AMF!")
	}
	defer sctpClient.GetConn().Close()

	gnb := gnbcontext.NewGnbContext("000001", cfg.UE.SUPI, sctpClient)
	if err := gnb.SendNgSetupRequest(); err != nil {
		log.Fatalf("❌ Lỗi NG Setup: %v", err)
	}

	buf := make([]byte, 8192)
	sctpClient.GetConn().Read(buf)
	fmt.Println("✅ gNB: NG Setup thành công.")

	// Tạo đường ống giao tiếp giữa UE và gNB
	msgFromGnbChan := make(chan []byte, 10)
	msgToGnbChan := make(chan []byte, 10)

	ue := uecontext.NewUEContext(cfg.UE.SUPI, "20893", 1, msgFromGnbChan, msgToGnbChan)

	// Bật công tắc cho não bộ UE chạy ngầm
	go ue.HandlerNasMsg()

	// UE Tự kích hoạt gửi bản tin đầu tiên
	if err := ue.TriggerInitRegistration(); err != nil {
		log.Printf("❌ Lỗi kích hoạt UE: %v", err)
	}

	// [LUỒNG UPLINK]: gNB đón NAS từ UE -> Bọc NGAP -> Gửi AMF
	var isInitial = true
	var amfUeNgapId int64 = 0
	go func() {
		for nasPdu := range msgToGnbChan {
			if isInitial {
				fmt.Println("📡 gNB: Đang bọc Initial UE Message gửi lên AMF...")
				gnb.SendInitialUEMessage(int64(ue.RanUeNgapId), nasPdu)
				isInitial = false
			} else {
				fmt.Println("📡 gNB: Đang bọc Uplink NAS Transport gửi lên AMF...")
				gnb.SendUplinkNasTransport(int64(ue.RanUeNgapId), amfUeNgapId, nasPdu)
			}
		}
	}()

	// [LUỒNG DOWNLINK]: gNB đọc SCTP từ AMF -> Bóc NGAP -> Đẩy NAS cho UE
	for {
		n, err := sctpClient.GetConn().Read(buf)
		if err != nil {
			break
		}
		importBytes := buf[:n]

		// Trích xuất ID mạng (AMF_UE_NGAP_ID)
		for i := 0; i < len(importBytes)-5; i++ {
			if importBytes[i] == 0x00 && importBytes[i+1] == 0x0a && importBytes[i+2] == 0x00 && importBytes[i+3] == 0x02 {
				amfUeNgapId = int64(importBytes[i+4])<<8 | int64(importBytes[i+5])
				break
			}
		}

		// 🚨 VŨ KHÍ MỚI: MÁY QUÉT MÃ LỆNH NGAP ĐỂ KÝ GIẤY BIÊN NHẬN
		if len(importBytes) > 2 && importBytes[0] == 0x00 { // 0x00 = Initiating Message
			procCode := importBytes[1]
			if procCode == 0x0e { // 14: Initial Context Setup Request
				fmt.Println("⚙️ [gNB] AMF yêu cầu Initial Context Setup -> Gửi Response chốt sổ!")
				gnb.SendInitialContextSetupResponse(int64(ue.RanUeNgapId), amfUeNgapId)
			} else if procCode == 0x1d { // 29: PDU Session Resource Setup Request
				fmt.Println("⚙️ [gNB] AMF yêu cầu PDU Session Setup -> Gửi Response chốt sổ!")
				gnb.SendPduSessionResourceSetupResponse(int64(ue.RanUeNgapId), amfUeNgapId)
			}
		}

		// Trích xuất lõi NAS (Dò byte 7e) và bơm vào não UE
		for i := 0; i < len(importBytes); i++ {
			if importBytes[i] == 0x7e {
				msgFromGnbChan <- importBytes[i:]
				break
			}
		}
	}
}
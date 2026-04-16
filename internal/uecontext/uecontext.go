package uecontext

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"emulator/internal/uecontext/sec"
	"github.com/reogac/nas"
)

const (
	PDUSessionInactive = 0
	PDUSessionActive   = 1
	InitPduSessionEstablishmentRequestEvent = 100
	
	AUTH_SUCCESS       uint8 = 0
	AUTH_MAC_FAILURE   uint8 = 1
	AUTH_SYNC_FAILURE  uint8 = 2
)

type UEContext struct {
	SUPI           string
	PLMN           string
	RanUeNgapId    int
	AmfUeNgapId    int
	Snssai         []byte
	MsgFromGnbChan chan []byte
	MsgToGnbChan   chan []byte
	AuthCtx        *AuthContext
	AuthKey        string
	AuthOpc        string
	MCC            string
	MNC            string
	nasPdu         []byte
	sessions       [16]*PduSession
	UplinkNASChan  chan []byte
	secCtx         *sec.SecurityContext
	
	ulNasCtx       *nas.NasContext
	dlNasCtx       *nas.NasContext
}

type AuthContext struct {
	supi     string
	snn      []byte
	amf      []byte
	milenage *sec.Milenage
	rand     []byte
	sqn      sec.Sqn
	ngKsi    nas.KeySetIdentifier
	kamf     []byte
	xresStar []byte
}

type PduSession struct {
	id    int
	state int
}

func (p *PduSession) SendEventSm(event any) {
	fmt.Println("[PDU] SendEventSm:", event)
}

func NewUEContext(supi, plmn string, ranUeNgapId int, msgFromGnbChan, msgToGnbChan chan []byte) *UEContext {
	ue := &UEContext{
		SUPI:           supi,
		PLMN:           plmn,
		RanUeNgapId:    ranUeNgapId,
		AmfUeNgapId:    0,
		Snssai:         []byte{0x01, 0x01, 0x02, 0x03},
		MsgFromGnbChan: msgFromGnbChan,
		MsgToGnbChan:   msgToGnbChan,
		AuthKey:        "8baf473f2f8fd09487cccbd7097c6862",
		AuthOpc:        "8e27b6af0e97669e076510fd71224732",
		MCC:            plmn[:3],
		MNC:            plmn[3:],
	}

	opc, _ := hex.DecodeString(ue.AuthOpc)
	key, _ := hex.DecodeString(ue.AuthKey)

	milenage, _ := sec.NewMilenage(key, opc, true)
	ue.AuthCtx = &AuthContext{
		supi:     supi,
		snn:      []byte(plmn),
		amf:      []byte{0x80, 0x00},
		milenage: milenage,
		sqn:      sec.Sqn{},
		rand:     make([]byte, 16),
	}
	ue.secCtx = nil

	return ue
}

func (ue *UEContext) getNasContext(isUplink bool) *nas.NasContext {
	if ue.secCtx == nil {
		return nil
	}
	if isUplink {
		if ue.ulNasCtx == nil {
			ue.ulNasCtx = ue.secCtx.NasContext(true)
		}
		return ue.ulNasCtx
	} else {
		if ue.dlNasCtx == nil {
			ue.dlNasCtx = ue.secCtx.NasContext(false)
		}
		return ue.dlNasCtx
	}
}

func (ue *UEContext) HandlerNasMsg() {
	timeout := 20 * time.Second
	for {
		select {
		case msg := <-ue.MsgFromGnbChan:
			fmt.Printf("\n[UE] Received NAS from gNB, len: %d\n", len(msg))
			ue.handleNasMsg(msg)
		case <-time.After(timeout):
			fmt.Println("[UE] Timeout waiting for NAS message from gNB, continue...")
		}
	}
}

func (ue *UEContext) handleNasMsg(nasBytes []byte) {
	if len(nasBytes) < 2 { return }

	secHeaderType := nasBytes[1] & 0x0F
	isPlain := secHeaderType == nas.NasSecNone

	var nasCtx *nas.NasContext
	if !isPlain {
		nasCtx = ue.getNasContext(false) // Giải mã với làn Downlink
		if nasCtx == nil { isPlain = true }
	}

	nasMsg, err := nas.Decode(nasCtx, nasBytes, isPlain)
	if err != nil {
		fmt.Printf("❌ [UE] Lỗi Decode NAS: %v (Gói tin bị drop)\n", err)
		ue.handleDlNasTransportRaw(nasBytes, secHeaderType)
		return
	}

	if nasMsg.Gmm != nil && (nasMsg.Gmm.MsgType == 0x67 || nasMsg.Gmm.MsgType == nas.DlNasTransportMsgType) {
		ue.handleDlNasTransportRaw(nasBytes, secHeaderType)
		return
	}

	ue.handleNasGmm(&nasMsg, secHeaderType)
}

func (ue *UEContext) handleNasGmm(nasMsg *nas.NasMessage, secHeaderType uint8) {
	gmm := nasMsg.Gmm
	if gmm == nil { return }

	switch gmm.MsgType {
	case nas.AuthenticationRequestMsgType:
		ue.handleAuthenticationRequest(gmm.AuthenticationRequest)
	case nas.IdentityRequestMsgType:
		ue.handleIdentityRequest(gmm.IdentityRequest)
	case nas.SecurityModeCommandMsgType:
		ue.handleSecurityModeCommand(gmm.SecurityModeCommand)
	case nas.RegistrationAcceptMsgType:
		ue.handleRegistrationAccept(gmm.RegistrationAccept)
	case nas.ConfigurationUpdateCommandMsgType:
		ue.handleConfigurationUpdateCommand(gmm.ConfigurationUpdateCommand)
	}
}

func (ue *UEContext) TriggerInitRegistration() error {
	ue.ulNasCtx = nil
	ue.dlNasCtx = nil

	ueSecCap := &nas.UeSecurityCapability{}
	ueSecCap.SetEA(0, true); ueSecCap.SetEA(1, true); ueSecCap.SetEA(2, true)
	ueSecCap.SetIA(0, true); ueSecCap.SetIA(1, true); ueSecCap.SetIA(2, true)

	msin := extractMSIN(ue.SUPI)
	suci := new(nas.SupiImsi)
	suci.Parse([]string{ue.MCC, ue.MNC, "0000", "0", "1", msin})

	msg := &nas.RegistrationRequest{UeSecurityCapability: ueSecCap}
	msg.RegistrationType = nas.NewRegistrationType(true, nas.RegistrationType5GSInitialRegistration)
	msg.MobileIdentity = nas.MobileIdentity{Id: &nas.Suci{Content: suci}}
	msg.Ngksi = nas.KeySetIdentifier{Tsc: 1, Id: 0}

	var gmmCap [13]byte
	gmmCap[0] = 0x07
	msg.GmmCapability = new(nas.GmmCapability)
	msg.GmmCapability.Bytes = gmmCap[:]

	msg.RequestedNssai = &nas.Nssai{
		List: []nas.SNssai{{Sst: 0x01, Sd: []byte{0x01, 0x02, 0x03}}},
	}
	msg.SetSecurityHeader(nas.NasSecNone)

	buf, err := nas.EncodeMm(nil, msg, true)
	if err != nil { return err }

	ue.nasPdu = make([]byte, len(buf))
	copy(ue.nasPdu, buf)

	ue.MsgToGnbChan <- buf
	fmt.Printf("🚀 NAS RegistrationRequest sent: SUPI=%s\n", ue.SUPI)
	return nil
}

func (ue *UEContext) handleAuthenticationRequest(msg *nas.AuthenticationRequest) {
	ue.AuthCtx.rand = msg.AuthenticationParameterRand
	ue.AuthCtx.ngKsi = msg.Ngksi

	autn := msg.AuthenticationParameterAutn
	errCode, resStar := ue.AuthCtx.ProcessAuthenticationInfo(autn, msg.Abba)
	if errCode != AUTH_SUCCESS {
		fmt.Println("❌ [UE] Authentication failed.")
		return
	}

	ue.secCtx = sec.NewSecurityContext(&ue.AuthCtx.ngKsi, ue.AuthCtx.kamf, false)

	msgResp := &nas.AuthenticationResponse{AuthenticationResponseParameter: resStar}
	msgResp.SetSecurityHeader(nas.NasSecNone)
	responsePdu, _ := nas.EncodeMm(nil, msgResp, true)

	ue.MsgToGnbChan <- responsePdu
	fmt.Println("✅ [UE] Sent Authentication Response")
}

func (ue *UEContext) handleSecurityModeCommand(message *nas.SecurityModeCommand) {
	algs := message.SelectedNasSecurityAlgorithms

	// Đúc chìa khóa ngay lập tức cho cả hai làn đường
	ulCtx := ue.getNasContext(true)
	dlCtx := ue.getNasContext(false)

	if ulCtx != nil && ue.secCtx != nil {
		ulCtx.DeriveKeys(algs.EncAlg(), algs.IntAlg(), ue.secCtx.Kamf())
	}
	if dlCtx != nil && ue.secCtx != nil {
		dlCtx.DeriveKeys(algs.EncAlg(), algs.IntAlg(), ue.secCtx.Kamf())
	}

	response := &nas.SecurityModeComplete{}

	rinmr := false
	if message.AdditionalSecurityInformation != nil {
		rinmr = message.AdditionalSecurityInformation.GetRetransmission()
	}
	if rinmr {
		response.NasMessageContainer = ue.nasPdu
	}

	response.SetSecurityHeader(nas.NasSecBothNew)

	responsePdu, err := nas.EncodeMm(ulCtx, response, true)
	if err != nil {
		fmt.Println("[UE] Lỗi Encode SMC:", err)
		return
	}

	ue.MsgToGnbChan <- responsePdu
	fmt.Println("🛡️ [UE] ===== Đã gửi Security Mode Complete =====")
}

func (ue *UEContext) handleIdentityRequest(msg *nas.IdentityRequest) {
	fmt.Println("⚡ [UE] ĐÃ VÀO HÀM XỬ LÝ IDENTITY REQUEST!")
	
	if msg == nil { return }
	
	plmn := nas.PlmnId{}
	plmn.Parse(ue.MCC + ue.MNC)
	msinBytes, _ := nas.ParseMsin(extractMSIN(ue.SUPI))
	suci := &nas.Suci{Content: &nas.SupiImsi{PlmnId: plmn, SchemeOutput: msinBytes}}
	
	resp := &nas.IdentityResponse{MobileIdentity: nas.MobileIdentity{Id: suci}}
	resp.SetSecurityHeader(nas.NasSecBoth)
	
	ulCtx := ue.getNasContext(true)
	if ulCtx == nil { return }

	buf, err := nas.EncodeMm(ulCtx, resp, true)
	if err != nil {
		fmt.Printf("❌ [UE] Lỗi Encode Identity Response: %v\n", err)
		return
	}
	
	ue.MsgToGnbChan <- buf
	fmt.Println("🛡️ [UE] ===== Đã gửi Identity Response (Có mã hóa bảo mật) =====")
}

func (ue *UEContext) handleRegistrationAccept(msg *nas.RegistrationAccept) {
	resp := &nas.RegistrationComplete{}
	
	ulCtx := ue.getNasContext(true)
	resp.SetSecurityHeader(nas.NasSecBoth)

	buf, _ := nas.EncodeMm(ulCtx, resp, true) 

	ue.MsgToGnbChan <- buf
	fmt.Println("\n🎉🎉🎉 [UE] ===== ĐÃ NHẬN REGISTRATION ACCEPT → GỬI COMPLETE ===== 🎉🎉🎉\n")
}

func (ue *UEContext) handleConfigurationUpdateCommand(msg *nas.ConfigurationUpdateCommand) {
	if msg == nil { return }
	response := &nas.ConfigurationUpdateComplete{}
	
	ulCtx := ue.getNasContext(true)

	if ulCtx == nil {
		response.SetSecurityHeader(nas.NasSecNone)
		buf, _ := nas.EncodeMm(nil, response, true)
		ue.MsgToGnbChan <- buf
		return
	}

	response.SetSecurityHeader(nas.NasSecBoth)
	buf, _ := nas.EncodeMm(ulCtx, response, true)

	ue.MsgToGnbChan <- buf
	fmt.Println("⚙️ [UE] ===== Đã xử lý Configuration Update Command =====")
}

func (ue *UEContext) TriggerInitPduSessionRequest(sessionId int) {
	session := &PduSession{id: sessionId, state: PDUSessionInactive}
	ue.sessions[sessionId] = session
	session.SendEventSm(InitPduSessionEstablishmentRequestEvent)
}

func (ue *UEContext) SendUplinkNAS(nasPdu []byte) {
	if ue.UplinkNASChan != nil { ue.UplinkNASChan <- nasPdu }
}

func (ue *UEContext) handleDlNasTransportRaw(nasBytes []byte, secHeaderType uint8) {
	inner := nasBytes
	if secHeaderType != nas.NasSecNone {
		pos := bytes.IndexByte(nasBytes[1:], 0x7e)
		if pos >= 0 { inner = nasBytes[1+pos:] }
	}
	if len(inner) < 4 || inner[0] != 0x7e || inner[2] != 0x68 { return }

	smStartRel := bytes.IndexByte(inner[3:], 0x2e)
	if smStartRel < 0 { return }
	sm := inner[3+smStartRel:]
	pduSessionID := sm[1]
	gsmMsgType := sm[3]

	if gsmMsgType == 0xC2 {
		fmt.Printf("\n🌐 [UE] PDU Session Establishment ACCEPT (ID=%d)\n", pduSessionID)
	}
}

func extractIMSI(supi string) string {
	return strings.TrimPrefix(strings.ToLower(supi), "imsi-")
}

func extractMSIN(supi string) string {
	imsi := extractIMSI(supi)
	if len(imsi) > 5 { return imsi[5:] }
	return imsi
}

func buildServingNetworkFromSNN(snn []byte) string {
	s := string(snn)
	if len(s) < 4 { return "5G:mnc093.mcc208.3gppnetwork.org" }
	mcc, mnc := s[:3], s[3:]
	if len(mnc) == 2 { mnc = "0" + mnc } else if len(mnc) == 1 { mnc = "00" + mnc }
	return fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

func (auth *AuthContext) ProcessAuthenticationInfo(autn, abba []byte) (errCode uint8, output []byte) {
	if len(autn) < 14 {
		return AUTH_MAC_FAILURE, nil
	}

	auth.milenage.SetRand(auth.rand)
	res, _ := auth.milenage.F2F5()
	ck := auth.milenage.F3()
	ik := auth.milenage.F4()
	key := append(ck, ik...)

	servingNetBytes := []byte(buildServingNetworkFromSNN(auth.snn))
	imsiOnly := []byte(extractIMSI(auth.supi))

	sqnXorAk := autn[0:6]

	kAusf, _ := sec.KAUSF(key, servingNetBytes, sqnXorAk)
	kSeaf, _ := sec.SeafKey(kAusf, servingNetBytes)
	auth.kamf, _ = sec.KAMF(kSeaf, imsiOnly, abba)

	resstar, _, _ := sec.ResstarXresstar(key, servingNetBytes, auth.rand, res)
	
	return AUTH_SUCCESS, resstar
}
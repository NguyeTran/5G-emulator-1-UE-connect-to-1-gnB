package gnbcontext

import (
	"fmt"
	"emulator/internal/sctp"
	"github.com/lvdund/ngap"
	"github.com/lvdund/ngap/aper"
	"github.com/lvdund/ngap/ies"
)

type GnbContext struct {
	GnbId      string
	Plmn       []byte
	SctpClient *sctp.SctpConn
}

func NewGnbContext(gnbId string, plmn string, sctpClient *sctp.SctpConn) *GnbContext {
	return &GnbContext{
		GnbId:      gnbId,
		Plmn:       []byte{0x02, 0xf8, 0x39},
		SctpClient: sctpClient,
	}
}

func (gnb *GnbContext) SendNgSetupRequest() error {
	ngSetup := &ies.NGSetupRequest{
		GlobalRANNodeID: ies.GlobalRANNodeID{
			Choice: 1,
			GlobalGNBID: &ies.GlobalGNBID{
				PLMNIdentity: gnb.Plmn,
				GNBID: ies.GNBID{
					Choice: 1,
					GNBID:  &aper.BitString{Bytes: []byte{0x00, 0x00, 0x01}, NumBits: 24},
				},
			},
		},
		SupportedTAList: []ies.SupportedTAItem{{
			TAC: []byte{0x00, 0x00, 0x01},
			BroadcastPLMNList: []ies.BroadcastPLMNItem{{
				PLMNIdentity: gnb.Plmn,
				TAISliceSupportList: []ies.SliceSupportItem{{
					SNSSAI: ies.SNSSAI{
						SST: []byte{0x01},
						SD:  []byte{0x01, 0x02, 0x03},
					},
				}},
			}},
		}},
	}
	data, err := ngap.NgapEncode(ngSetup)
	if err != nil { return err }
	_, err = gnb.SctpClient.GetConn().Write(data)
	return err
}

func (gnb *GnbContext) SendInitialUEMessage(ranUeNgapId int64, nasPdu []byte) error {
	var ueReq ies.UEContextRequest
	ueReq.Value = ies.UEContextRequestRequested

	initialUE := &ies.InitialUEMessage{
		RANUENGAPID: ranUeNgapId,
		NASPDU:      nasPdu,
		UserLocationInformation: ies.UserLocationInformation{
			Choice: 2,
			UserLocationInformationNR: &ies.UserLocationInformationNR{
				NRCGI: ies.NRCGI{
					PLMNIdentity:   gnb.Plmn,
					NRCellIdentity: aper.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x10}, NumBits: 36},
				},
				TAI: ies.TAI{
					PLMNIdentity: gnb.Plmn,
					TAC:          []byte{0x00, 0x00, 0x01},
				},
			},
		},
		RRCEstablishmentCause: ies.RRCEstablishmentCause{Value: ies.RRCEstablishmentCauseMosignalling},
		UEContextRequest:      &ueReq,
	}

	data, err := ngap.NgapEncode(initialUE)
	if err != nil { return err }
	_, err = gnb.SctpClient.GetConn().Write(data)
	return err
}

func (gnb *GnbContext) SendUplinkNasTransport(ranUeNgapId int64, amfUeNgapId int64, nasPdu []byte) error {
	uplinkNas := &ies.UplinkNASTransport{
		AMFUENGAPID: amfUeNgapId,
		RANUENGAPID: ranUeNgapId,
		NASPDU:      nasPdu,
		UserLocationInformation: ies.UserLocationInformation{
			Choice: 2,
			UserLocationInformationNR: &ies.UserLocationInformationNR{
				NRCGI: ies.NRCGI{
					PLMNIdentity:   gnb.Plmn,
					NRCellIdentity: aper.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x10}, NumBits: 36},
				},
				TAI: ies.TAI{
					PLMNIdentity: gnb.Plmn,
					TAC:          []byte{0x00, 0x00, 0x01},
				},
			},
		},
	}

	data, err := ngap.NgapEncode(uplinkNas)
	if err != nil { return err }
	_, err = gnb.SctpClient.GetConn().Write(data)
	return err
}

func (gnb *GnbContext) SendInitialContextSetupResponse(ranUeNgapId int64, amfUeNgapId int64) error {
	fmt.Printf("📡 [gNB] Gửi Initial Context Setup Response chốt sổ với AMF...\n")
	resp := &ies.InitialContextSetupResponse{
		AMFUENGAPID: amfUeNgapId,
		RANUENGAPID: ranUeNgapId,
	}
	data, err := ngap.NgapEncode(resp)
	if err != nil { return err }
	_, err = gnb.SctpClient.GetConn().Write(data)
	return err
}

func (gnb *GnbContext) SendPduSessionResourceSetupResponse(ranUeNgapId int64, amfUeNgapId int64) error {
	fmt.Printf("📡 [gNB] Gửi PDU Session Resource Setup Response cho AMF...\n")
	resp := &ies.PDUSessionResourceSetupResponse{
		AMFUENGAPID: amfUeNgapId,
		RANUENGAPID: ranUeNgapId,
	}
	data, err := ngap.NgapEncode(resp)
	if err != nil { return err }
	_, err = gnb.SctpClient.GetConn().Write(data)
	return err
}
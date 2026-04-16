package sec

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/reogac/nas"
	"github.com/reogac/utils/sec5g"
)

const (
	HDP_NONE uint8 = iota
	HDP_HANDOVER
	HDP_MOBILITY_UPDATE
)

type SecurityContext struct {
	isAmf bool

	gppNas    *nas.NasContext
	nonGppNas *nas.NasContext

	ngKsi nas.KeySetIdentifier
	kamf  []byte

	kgnb   []uint8 
	kn3iwf []uint8 
	nh     []uint8 
	ncc    uint8   
}

func NewSecurityContext(ksi *nas.KeySetIdentifier, kamf []byte, isAmf bool) *SecurityContext {
	ctx := &SecurityContext{
		ngKsi:     *ksi,
		isAmf:     isAmf,
		kamf:      make([]byte, len(kamf)),
		gppNas:    nas.NewNasContext(isAmf),
		nonGppNas: nas.NewNasContext(isAmf),
	}
	copy(ctx.kamf, kamf)
	return ctx
}

func (ctx *SecurityContext) NgKsi() *nas.KeySetIdentifier {
	return &ctx.ngKsi
}

func (ctx *SecurityContext) NasContext(isGpp bool) *nas.NasContext {
	if isGpp { return ctx.gppNas }
	return ctx.nonGppNas
}

func (ctx *SecurityContext) MatchNgKsi(ngksi *nas.KeySetIdentifier) bool {
	return ctx.ngKsi.Tsc == ngksi.Tsc && ctx.ngKsi.Id == ngksi.Id
}

func (ctx *SecurityContext) Kamf() []byte { return ctx.kamf }
func (ctx *SecurityContext) Kgnb() []byte { return ctx.kgnb }
func (ctx *SecurityContext) Kn3iwf() []byte { return ctx.kn3iwf }

func (ctx *SecurityContext) createAnKey() (err error) {
	P0 := make([]byte, 4)
	P1 := []byte{nas.AccessType3GPP}
	binary.BigEndian.PutUint32(P0, uint32(ctx.gppNas.UlCounter()))
	if ctx.kgnb, err = sec5g.RanKey(ctx.kamf, P0, P1); err != nil { return }
	
	P1[0] = nas.AccessTypeNon3GPP
	binary.BigEndian.PutUint32(P0, uint32(ctx.nonGppNas.UlCounter()))
	ctx.kn3iwf, err = sec5g.RanKey(ctx.kamf, P0, P1)
	return
}

func (ctx *SecurityContext) createNh(syncinput []byte) (err error) {
	ctx.nh, err = sec5g.NhKey(ctx.kamf, syncinput)
	return
}

func (ctx *SecurityContext) DeriveAsKeys() (err error) {
	if err = ctx.createAnKey(); err != nil { return }
	err = ctx.createNh(ctx.kgnb)
	ctx.ncc = 1
	return
}

func (ctx *SecurityContext) UpdateNh() error {
	ctx.ncc++
	ctx.ncc &= 0x07
	return ctx.createNh(ctx.nh)
}

func (ctx *SecurityContext) DeriveNasKeys(encAlg, intAlg, hdp uint8) (err error) {
	var p0 []byte
	var p1 [4]byte
	var kamf []byte
	switch hdp {
	case HDP_HANDOVER:
		p0, _ = hex.DecodeString("01")
		binary.BigEndian.PutUint32(p1[:], uint32(ctx.gppNas.DlCounter()))
		kamf, err = sec5g.KamfPrime(ctx.kamf, p0, p1[:])
	case HDP_MOBILITY_UPDATE:
		p0, _ = hex.DecodeString("00")
		binary.BigEndian.PutUint32(p1[:], uint32(ctx.gppNas.UlCounter()))
		kamf, err = sec5g.KamfPrime(ctx.kamf, p0, p1[:])
	default:
		kamf = ctx.kamf
	}
	if err != nil { return }

	if err = ctx.gppNas.DeriveKeys(encAlg, intAlg, kamf); err != nil { return }
	if err = ctx.nonGppNas.DeriveKeys(encAlg, intAlg, kamf); err != nil { return }
	ctx.kamf = kamf
	return
}
package sec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type Milenage struct {
	block   cipher.Block
	opc     [16]uint8
	randxor [16]uint8
	rand    [16]uint8
	reader  io.Reader
}

func NewMilenage(k []uint8, opopc []uint8, isopc bool) (m *Milenage, err error) {
	return NewMilenageEx(k, rand.Reader, opopc, isopc)
}

func NewMilenageEx(k []uint8, r io.Reader, opopc []uint8, isopc bool) (m *Milenage, err error) {
	if len(k) != 16 || len(opopc) != 16 {
		return nil, fmt.Errorf("Wrong input size")
	}
	m = &Milenage{reader: r}
	if r == nil { m.reader = rand.Reader }

	if m.block, err = aes.NewCipher(k); err != nil {
		return nil, err
	}

	if !isopc {
		m.block.Encrypt(m.opc[:], opopc)
		for i := range 16 { m.opc[i] ^= opopc[i] }
	} else {
		copy(m.opc[:], opopc[:])
	}
	m.Refresh()
	return m, nil
}

func (m *Milenage) Refresh() {
	m.reader.Read(m.rand[:])
	var tmp [16]uint8
	for i := range 16 { tmp[i] = m.rand[i] ^ m.opc[i] }
	m.block.Encrypt(m.randxor[:], tmp[:])
}

func (m *Milenage) SetRand(r []uint8) error {
	if len(r) != 16 { return fmt.Errorf("Wrong rand size") }
	copy(m.rand[:], r)
	var tmp [16]uint8
	for i := range 16 { tmp[i] = m.rand[i] ^ m.opc[i] }
	m.block.Encrypt(m.randxor[:], tmp[:])
	return nil
}

func (m *Milenage) GetRand() []uint8 { return m.rand[:] }

func (m *Milenage) F1(sqn, amf []uint8) (maca []uint8, macs []uint8, err error) {
	if len(sqn) != 6 || len(amf) != 2 {
		return nil, nil, fmt.Errorf("Wrong size input")
	}
	var a, b, c [16]uint8
	copy(b[0:], sqn[:]); copy(b[6:], amf[:]); copy(b[8:], b[0:8])

	var j int
	for i := range 16 {
		j = (i + 8) % 16
		c[j] = b[i] ^ m.opc[i] ^ m.randxor[j]
	}

	m.block.Encrypt(a[:], c[:])
	for i := range 16 { a[i] ^= m.opc[i] }
	return a[0:8], a[8:], nil
}

func (m *Milenage) F2F5() ([]uint8, []uint8) {
	tmp := m.operation(0, 1)
	return tmp[8:16], tmp[:6] 
}
func (m *Milenage) F3() []uint8     { return m.operation(12, 2) } 
func (m *Milenage) F4() []uint8     { return m.operation(8, 4) }  
func (m *Milenage) F5star() []uint8 { tmp := m.operation(4, 8); return tmp[:6] }

func (m *Milenage) operation(rot int, v uint8) []uint8 {
	var a, b, c [16]uint8
	c[15] = v
	var j int
	for i := range 16 {
		j = (i + rot) % 16
		a[j] = m.randxor[i] ^ m.opc[i] ^ c[j]
	}
	m.block.Encrypt(b[:], a[:])
	for i := range 16 { b[i] ^= m.opc[i] }
	return b[:]
}

// Bổ sung struct Sqn để đồng bộ với code của thư viện mới
type Sqn [6]uint8
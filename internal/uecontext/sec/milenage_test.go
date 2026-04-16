package sec

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestMilenage_3GPP_Vectors kiểm tra thuật toán dựa trên 3GPP TS 35.208 (Test Set 1)
func TestMilenage_3GPP_Vectors(t *testing.T) {
	// 1. Dữ liệu đầu vào chuẩn 3GPP
	k, _ := hex.DecodeString("465b5ce8b199b49faa5f0a2ee238a6bc")
	op, _ := hex.DecodeString("cdc202d5123e20f62b6d676ac72cb318")
	randData, _ := hex.DecodeString("23553cbe9637a89d218ae64dae47bf35")
	sqn, _ := hex.DecodeString("ff9bb4d0b607")
	amf, _ := hex.DecodeString("b9b9")

	// 2. Kết quả kỳ vọng (Expected Outputs)
	expMacA, _ := hex.DecodeString("4a9ffac354dfafb3")
	expMacS, _ := hex.DecodeString("01cfaf9ec4e871e9")
	expRes, _ := hex.DecodeString("a54211d5e3ba50bf")
	expCk, _ := hex.DecodeString("b40ba9a3c58b2a05bbf0d987b21bf8cb")
	expIk, _ := hex.DecodeString("f769bcd751044604127672711c6d3441")
	expAk, _ := hex.DecodeString("aa689c648370")

	// 3. Khởi tạo Milenage (Dùng OP thay vì OPc, nên isopc = false)
	m, err := NewMilenage(k, op, false)
	if err != nil {
		t.Fatalf("❌ Khởi tạo Milenage thất bại: %v", err)
	}

	// 4. Bơm RAND vào lõi
	if err := m.SetRand(randData); err != nil {
		t.Fatalf("❌ Bơm RAND thất bại: %v", err)
	}

	// ==========================================
	// THỰC THI KIỂM TRA TỪNG HÀM F1 -> F5
	// ==========================================

	// Kiểm tra F1 (MAC-A, MAC-S)
	macA, macS, err := m.F1(sqn, amf)
	if err != nil {
		t.Fatalf("❌ Hàm F1 chạy lỗi: %v", err)
	}
	if !bytes.Equal(macA, expMacA) {
		t.Errorf("❌ Lệch MAC-A. \nNhận được: %x \nKỳ vọng:  %x", macA, expMacA)
	} else {
		t.Logf("✅ MAC-A chuẩn xác: %x", macA)
	}

	if !bytes.Equal(macS, expMacS) {
		t.Errorf("❌ Lệch MAC-S. \nNhận được: %x \nKỳ vọng:  %x", macS, expMacS)
	} else {
		t.Logf("✅ MAC-S chuẩn xác: %x", macS)
	}

	// Kiểm tra F2 và F5 (RES, AK)
	res, ak := m.F2F5()
	if !bytes.Equal(res, expRes) {
		t.Errorf("❌ Lệch RES. \nNhận được: %x \nKỳ vọng:  %x", res, expRes)
	} else {
		t.Logf("✅ RES chuẩn xác: %x", res)
	}

	if !bytes.Equal(ak, expAk) {
		t.Errorf("❌ Lệch AK. \nNhận được: %x \nKỳ vọng:  %x", ak, expAk)
	} else {
		t.Logf("✅ AK chuẩn xác: %x", ak)
	}

	// Kiểm tra F3 (CK - Ciphering Key)
	ck := m.F3()
	if !bytes.Equal(ck, expCk) {
		t.Errorf("❌ Lệch CK. \nNhận được: %x \nKỳ vọng:  %x", ck, expCk)
	} else {
		t.Logf("✅ CK chuẩn xác: %x", ck)
	}

	// Kiểm tra F4 (IK - Integrity Key)
	ik := m.F4()
	if !bytes.Equal(ik, expIk) {
		t.Errorf("❌ Lệch IK. \nNhận được: %x \nKỳ vọng:  %x", ik, expIk)
	} else {
		t.Logf("✅ IK chuẩn xác: %x", ik)
	}
}
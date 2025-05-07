package interfaces

import (
	"bytes"
	"testing"
)

func TestEscapeHDLC(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{"NoEscape", []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x03}},
		{"EscapeFlag", []byte{0x01, HDLC_FLAG, 0x03}, []byte{0x01, HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK, 0x03}},
		{"EscapeEsc", []byte{0x01, HDLC_ESC, 0x03}, []byte{0x01, HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK, 0x03}},
		{"EscapeBoth", []byte{HDLC_FLAG, HDLC_ESC}, []byte{HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK, HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK}},
		{"Empty", []byte{}, []byte{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := escapeHDLC(tc.input)
			if !bytes.Equal(result, tc.expected) {
				t.Errorf("escapeHDLC(%x) = %x; want %x", tc.input, result, tc.expected)
			}
		})
	}
}

func TestEscapeKISS(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{"NoEscape", []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x03}},
		{"EscapeFEND", []byte{0x01, KISS_FEND, 0x03}, []byte{0x01, KISS_FESC, KISS_TFEND, 0x03}},
		{"EscapeFESC", []byte{0x01, KISS_FESC, 0x03}, []byte{0x01, KISS_FESC, KISS_TFESC, 0x03}},
		{"EscapeBoth", []byte{KISS_FEND, KISS_FESC}, []byte{KISS_FESC, KISS_TFEND, KISS_FESC, KISS_TFESC}},
		{"Empty", []byte{}, []byte{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := escapeKISS(tc.input)
			if !bytes.Equal(result, tc.expected) {
				t.Errorf("escapeKISS(%x) = %x; want %x", tc.input, result, tc.expected)
			}
		})
	}
}

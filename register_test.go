package nmsg_test

import (
	"github.com/farsightsec/go-nmsg"
	_ "github.com/farsightsec/go-nmsg/nmsg_base"
	"testing"
)

func TestRegisterVendor(t *testing.T) {
	vname, err := nmsg.VendorName(1)
	if err != nil || vname != "base" {
		t.Errorf("VendorName(1): %s, %v", vname, err)
	}

	vid, err := nmsg.VendorByName("base")
	if err != nil || vid != 1 {
		t.Errorf("VendorByName(base): %d, %v", vid, err)
	}
}

func TestRegisterMessageByName(t *testing.T) {
	vid, msgtype, err := nmsg.MessageTypeByName("base", "ncap")
	if err != nil || vid != 1 || msgtype != 1 {
		t.Errorf("MessageTypeByName(base,ncap): %d, %d, %v", vid, msgtype, err)
	}
}

func TestRegisterMessageName(t *testing.T) {
	vname, mname, err := nmsg.MessageTypeName(1, 1)
	if err != nil || vname != "base" || mname != "ncap" {
		t.Errorf("MessageTypeByName(base,ncap): %s, %s, %v", vname, mname, err)
	}
}

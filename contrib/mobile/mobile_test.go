package mobile

import "testing"

func TestStartRuvchain(t *testing.T) {
	riv := &Mesh{}
	if err := ruvchain.StartAutoconfigure(); err != nil {
		t.Fatalf("Failed to start Ruvchain: %s", err)
	}
	t.Log("Address:", riv.GetAddressString())
	t.Log("Subnet:", riv.GetSubnetString())
	t.Log("Coords:", riv.GetCoordsString())
	if err := ruvchain.Stop(); err != nil {
		t.Fatalf("Failed to stop Ruvchain: %s", err)
	}
}

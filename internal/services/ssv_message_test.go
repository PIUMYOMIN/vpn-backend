package services

import "testing"

func TestBuildSSVMessageKeepsOrderDropsSig(t *testing.T) {
	raw := "ad_network=545021321328589&ad_unit=123&custom_data=install%3Aabc&signature=AAA&key_id=1&transaction_id=txn"
	got := buildSSVMessage(raw)
	want := "ad_network=545021321328589&ad_unit=123&custom_data=install:abc&transaction_id=txn"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

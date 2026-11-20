package tlspin

import "testing"

func TestCheckURL(t *testing.T) {
	for _, tc := range []struct {
		url   string
		allow bool
		ok    bool
	}{
		{"https://api.osv.dev", false, true},
		{"http://127.0.0.1:8080", false, true},
		{"http://localhost/x", false, true},
		{"http://[::1]:9/", false, true},
		{"http://192.168.1.2:8123", false, false},
		{"http://192.168.1.2:8123", true, true},
		{"ftp://example.com", true, false},
		{"https://user:pw@example.com", false, false},
		{"https://", false, false},
	} {
		if err := CheckURL(tc.url, tc.allow); (err == nil) != tc.ok {
			t.Errorf("%s allow=%v: %v", tc.url, tc.allow, err)
		}
	}
}

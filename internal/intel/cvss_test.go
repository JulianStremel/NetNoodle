package intel

import (
	"math"
	"strings"
	"testing"
)

func TestScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
		ok     bool
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, true},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, true},
		{"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, true},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0, true},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N", 0, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:U/MC:N", 9.8, true},
		{"CVSS:3.1/S:U/A:H/I:H/C:H/UI:N/PR:N/AC:L/AV:N", 9.8, true},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, true},
		{"AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3, true},
		{"AV:L/AC:L/Au:N/C:C/I:C/A:C", 7.2, true},
		{"(AV:N/AC:L/Au:N/C:P/I:P/A:P)", 7.5, true},
		{"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, true},
		{" (CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P) ", 7.5, true},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P/E:U/RL:OF/CR:H", 7.5, true},
		{"AV:N/AC:L/Au:N/C:N/I:N/A:N", 0, true},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 0, false},
		{"CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0, false},
		{"garbage", 0, false},
		{"", 0, false},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P/AV:L", 0, false},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P/", 0, false},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P/E:", 0, false},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P/E:X:Y", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, ok := Score(tt.vector)
			if got != tt.want || ok != tt.ok {
				t.Errorf("Score(%q) = (%v, %v), want (%v, %v)", tt.vector, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestScoreRequiresValidBaseMetrics(t *testing.T) {
	for _, vector := range []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"AV:N/AC:L/Au:N/C:P/I:P/A:P",
	} {
		parts := strings.Split(vector, "/")
		for i, part := range parts {
			if strings.HasPrefix(part, "CVSS:") {
				continue
			}
			missing := append([]string{}, parts[:i]...)
			missing = append(missing, parts[i+1:]...)
			if _, ok := Score(strings.Join(missing, "/")); ok {
				t.Errorf("accepted vector missing %s: %s", part, vector)
			}
			invalid := append([]string{}, parts...)
			key, _, _ := strings.Cut(part, ":")
			invalid[i] = key + ":invalid"
			if _, ok := Score(strings.Join(invalid, "/")); ok {
				t.Errorf("accepted invalid %s: %s", part, vector)
			}
		}
	}
}

func TestRoundup(t *testing.T) {
	for _, tt := range []struct{ input, want float64 }{
		{0, 0}, {4, 4}, {4.02, 4.1}, {4.000000000001, 4},
		{4.000006, 4.1}, {0.30000000000000004, 0.3}, {9.999999, 10},
	} {
		if got := roundup(tt.input); got != tt.want {
			t.Errorf("roundup(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestLabel(t *testing.T) {
	for _, tt := range []struct {
		score float64
		want  string
	}{
		{10, "critical"}, {9, "critical"}, {8.9, "high"}, {7, "high"},
		{6.9, "medium"}, {4, "medium"}, {3.9, "low"}, {0.1, "low"},
		{0, "unknown"}, {-1, "unknown"}, {math.NaN(), "unknown"},
	} {
		if got := Label(tt.score); got != tt.want {
			t.Errorf("Label(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestLabelScore(t *testing.T) {
	for word, want := range map[string]float64{
		"critical": 9, "high": 7.5, "important": 7.5, "moderate": 5,
		"medium": 5, "low": 3, "negligible": 0.1, "unimportant": 0.1,
	} {
		for _, input := range []string{word, strings.ToUpper(word), " " + word + " "} {
			if got, ok := LabelScore(input); !ok || got != want {
				t.Errorf("LabelScore(%q) = (%v, %v), want (%v, true)", input, got, ok, want)
			}
		}
	}
	for _, word := range []string{"", "unknown", "severe", "9.0"} {
		if got, ok := LabelScore(word); got != 0 || ok {
			t.Errorf("LabelScore(%q) = (%v, %v), want (0, false)", word, got, ok)
		}
	}
}

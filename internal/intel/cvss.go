package intel

import (
	"math"
	"strings"
)

// Score returns the CVSS v2, v3.0, or v3.1 base score. Unsupported or
// incomplete vectors return ok=false. Temporal and environmental metrics
// do not affect the result.
func Score(vector string) (score float64, ok bool) {
	vector = strings.TrimSpace(vector)
	if strings.HasPrefix(vector, "(") && strings.HasSuffix(vector, ")") {
		vector = vector[1 : len(vector)-1]
	}
	v3 := false
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0/"), strings.HasPrefix(vector, "CVSS:3.1/"):
		v3 = true
		vector = vector[len("CVSS:3.1/"):]
	case strings.HasPrefix(vector, "CVSS:2.0/"):
		vector = vector[len("CVSS:2.0/"):]
	case strings.HasPrefix(vector, "CVSS:"):
		return 0, false
	}
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		key, val, found := strings.Cut(part, ":")
		if !found || key == "" || val == "" || strings.Contains(val, ":") {
			return 0, false
		}
		if _, duplicate := metrics[key]; duplicate {
			return 0, false
		}
		metrics[key] = val
	}
	if v3 {
		return scoreV3(metrics)
	}
	return scoreV2(metrics)
}

// metricWeights validates every required metric, including zero-valued ones.
func metricWeights(metrics map[string]string, tables map[string]map[string]float64) (map[string]float64, bool) {
	weights := make(map[string]float64, len(tables))
	for key, table := range tables {
		weight, ok := table[metrics[key]]
		if !ok {
			return nil, false
		}
		weights[key] = weight
	}
	return weights, true
}

func scoreV3(metrics map[string]string) (float64, bool) {
	if metrics["S"] != "U" && metrics["S"] != "C" {
		return 0, false
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if metrics["S"] == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	}
	impactWeights := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}
	w, ok := metricWeights(metrics, map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
		"AC": {"L": 0.77, "H": 0.44},
		"PR": pr,
		"UI": {"N": 0.85, "R": 0.62},
		"C":  impactWeights, "I": impactWeights, "A": impactWeights,
	})
	if !ok {
		return 0, false
	}
	// FIRST CVSS v3.1 specification, section 7.1 (also used by v3.0).
	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	impact := 6.42 * iss
	if metrics["S"] == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * w["AV"] * w["AC"] * w["PR"] * w["UI"]
	base := impact + exploitability
	if metrics["S"] == "C" {
		base *= 1.08
	}
	return roundup(math.Min(base, 10)), true
}

// roundup implements the integer method in Appendix A of the v3.1 spec:
// https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding
func roundup(value float64) float64 {
	n := int64(math.Round(value * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

func scoreV2(metrics map[string]string) (float64, bool) {
	impactWeights := map[string]float64{"N": 0, "P": 0.275, "C": 0.660}
	w, ok := metricWeights(metrics, map[string]map[string]float64{
		"AV": {"L": 0.395, "A": 0.646, "N": 1},
		"AC": {"H": 0.35, "M": 0.61, "L": 0.71},
		"Au": {"M": 0.45, "S": 0.56, "N": 0.704},
		"C":  impactWeights, "I": impactWeights, "A": impactWeights,
	})
	if !ok {
		return 0, false
	}
	// https://www.first.org/cvss/v2/guide#3-2-1-Base-Equation
	impact := 10.41 * (1 - (1-w["C"])*(1-w["I"])*(1-w["A"]))
	if impact == 0 {
		return 0, true
	}
	exploitability := 20 * w["AV"] * w["AC"] * w["Au"]
	return math.Round(((0.6*impact)+(0.4*exploitability)-1.5)*1.176*10) / 10, true
}

// Label returns the severity corresponding to a base score.
func Label(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

// LabelScore maps an advisory severity word to a representative base score.
func LabelScore(word string) (float64, bool) {
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "critical":
		return 9, true
	case "high", "important":
		return 7.5, true
	case "moderate", "medium":
		return 5, true
	case "low":
		return 3, true
	case "negligible", "unimportant":
		return 0.1, true
	default:
		return 0, false
	}
}

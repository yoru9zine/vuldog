package vuldog

import "time"

type NVD struct {
	Entries []NVDEntry `xml:"entry"`
}

type NVDEntry struct {
	ID                     string    `xml:"id,attr"`
	CVEID                  string    `xml:"cve-id"`
	CWE                    CWE       `xml:"cwe"`
	VulnerableSoftwareList []string  `xml:"vulnerable-software-list>product"`
	Published              time.Time `xml:"published-datetime"`
	LastModified           time.Time `xml:"last-modified-datetime"`
	Summary                string    `xml:"summary"`
	CVSS                   CVSS      `xml:"cvss"`
}

type CWE struct {
	ID string `xml:"id,attr"`
}

type CVSS struct {
	Base CVSSBase `xml:"base_metrics"`
}

type CVSSBase struct {
	Score                 float64   `xml:"score" json:"score"`
	AccessVector          string    `xml:"access-vector"`
	AccessComplexity      string    `xml:"access-complexity"`
	Authentication        string    `xml:"authentication"`
	ConfidentialityImpact string    `xml:"confidentiality-impact"`
	IntegrityImpact       string    `xml:"integrity-impact"`
	AvailabilityImpact    string    `xml:"availability-impact"`
	Source                string    `xml:"source"`
	GeneratedOnDatetime   time.Time `xml:"generated-on-datetime"`
}

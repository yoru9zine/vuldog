package vulweb

import (
	"time"

	cpe "github.com/umisama/go-cpe"
	"github.com/yoru9zine/vuldog"
)

type CVE struct {
	ID                     string          `json:"id"`
	Published              time.Time       `json:"published"`
	LastModified           time.Time       `json:"last_modified"`
	Summary                string          `json:"summary"`
	VulnerableSoftwareList []string        `json:"vulnerable_software_list"`
	CVSSBase               vuldog.CVSSBase `json:"cvss_base"`
}

func (cve *CVE) SummaryHead(n int) string {
	if len(cve.Summary) < n {
		return cve.Summary
	}
	return cve.Summary[:n] + "..."
}

func (cve *CVE) PublishedString() string {
	return cve.Published.Format("01/02/2006 15:04")
}

func (cve *CVE) LastModifiedString() string {
	return cve.LastModified.Format("01/02/2006 15:04")
}

func (cve *CVE) ScoreColor() string {
	if cve.CVSSBase.Score >= 7 {
		return "grey-text text-darken-4"
	} else if cve.CVSSBase.Score >= 4 {
		return "grey-text text-darken-1"
	}
	return "grey-text text-lighten-1"
}

func (cve *CVE) Vendors() []string {
	m := map[string]struct{}{}
	for _, cpestr := range cve.VulnerableSoftwareList {
		i, _ := cpe.NewItemFromUri(cpestr)
		m[i.Vendor().String()] = struct{}{}
	}
	list := []string{}
	for k := range m {
		list = append(list, k)
	}
	return list
}

func (cve *CVE) Products() []string {
	m := map[string]struct{}{}
	for _, cpestr := range cve.VulnerableSoftwareList {
		i, _ := cpe.NewItemFromUri(cpestr)
		m[i.Product().String()] = struct{}{}
	}
	list := []string{}
	for k := range m {
		list = append(list, k)
	}
	return list
}

func NewCVE(entry *vuldog.NVDEntry) *CVE {
	return &CVE{
		ID:                     entry.ID,
		Published:              entry.Published,
		LastModified:           entry.LastModified,
		Summary:                entry.Summary,
		VulnerableSoftwareList: entry.VulnerableSoftwareList,
		CVSSBase:               entry.CVSS.Base,
	}
}

package vuldog

import "time"

type CPEList struct {
	ProductName    string    `xml:"generator>product_name"`
	ProductVersion float64   `xml:"generator>product_version"`
	SchemaVersion  float64   `xml:"generator>schema_version"`
	Timestamp      time.Time `xml:"generator>timestamp"`
	Items          []CPEItem `xml:"cpe-item"`
}

type CPEItem struct {
	Name  string `xml:"name,attr"`
	Title string `xml:"title"`
}

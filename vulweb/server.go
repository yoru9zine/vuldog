package vulweb

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/yoru9zine/vuldog/vuldb"
)

func NewHandler(db *vuldb.DB) http.Handler {
	h := &Handler{db: db}
	if err := h.initTemplates(); err != nil {
		log.Fatalf("failed to load templates: %s", err)
	}
	h.HandleFunc("/", h.ServeRoot)
	h.HandleFunc("/cve/", h.ServeCVEList)
	h.HandleFunc("/search/", h.ServeSearch)
	return h
}

type Handler struct {
	http.ServeMux
	db *vuldb.DB
}

func (h *Handler) ServeCVEList(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimPrefix(r.URL.Path, "/cve/")
	if target != "" {
		h.ServeCVE(w, r, target)
		return
	}
	cvelist, err := h.db.GetRecentCVE(10)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	respCVEList := make([]*CVE, len(cvelist))
	for i, entry := range cvelist {
		respCVEList[i] = NewCVE(&entry)
	}

	tmplPath := "cve.html.tmpl"
	b, err := h.template(tmplPath, respCVEList)
	if err != nil {
		log.Printf("failed to render template %s: %s", tmplPath, err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Write(b)
}

func (h *Handler) ServeCVE(w http.ResponseWriter, r *http.Request, target string) {
	entry, err := h.db.GetCVE(target)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tmplPath := "cve_detail.html.tmpl"
	b, err := h.template(tmplPath, NewCVE(entry))
	if err != nil {
		log.Printf("failed to render template %s: %s", tmplPath, err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Write(b)
}

func (h *Handler) ServeSearch(w http.ResponseWriter, r *http.Request) {
	tmplPath := "search.html.tmpl"
	b, err := h.template(tmplPath, nil)
	if err != nil {
		log.Printf("failed to render template %s: %s", tmplPath, err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Write(b)
}

func (h *Handler) ServeRoot(w http.ResponseWriter, r *http.Request) {
	data, err := Asset("vulweb/static/hello.html")
	if err != nil {
		log.Fatal(err)
	}
	w.Write(data)
}

var (
	tmpl *template.Template
)

func (h *Handler) initTemplates() error {
	tmpl = template.New("name").Funcs(map[string]interface{}{
		"tolower": strings.ToLower,
	})
	files, err := AssetDir("vulweb/template")
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := h.parseTemplate("vulweb/template/" + f); err != nil {
			return fmt.Errorf("failed to setup template %s: %s", err)
		}
	}
	return nil
}

func (h *Handler) parseTemplate(bindataPath string) error {
	data, err := Asset(bindataPath)
	if err != nil {
		return fmt.Errorf("asset not found:: %s", err)
	}
	tmpl, err = tmpl.Parse(string(data))
	if err != nil {
		return fmt.Errorf("failed to parse template: %s", err)
	}
	return nil
}
func (h *Handler) template(bindataPath string, param interface{}) ([]byte, error) {
	b := &bytes.Buffer{}
	if err := tmpl.ExecuteTemplate(b, bindataPath, param); err != nil {
		return nil, fmt.Errorf("failed to execute template: %s", err)
	}
	return b.Bytes(), nil
}

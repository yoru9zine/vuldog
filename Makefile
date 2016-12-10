SRC = $(shell find . -name \*.go)
CONTENTS = $(shell find vulweb/static vulweb/template -type f)

PROG = vuldog
PROGPATH = $(PROG)/$(PROG)

$(PROGPATH): $(SRC) vulweb/bindata.go
	go get -d ./...
	go build -i -o ./$(PROGPATH) ./$(PROG)

vulweb/bindata.go: $(CONTENTS)
	go get -u github.com/jteeuwen/go-bindata/...
	go-bindata -o vulweb/bindata.go -pkg vulweb ./vulweb/static ./vulweb/template

run: $(PROGPATH)
	$(PROGPATH) server

data/dev/nvd/nvdcve-2.0-Recent.xml:
	mkdir -p data/dev/nvd
	curl -O https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.gz
	gunzip nvdcve-2.0-Recent.xml.gz
	mv nvdcve-2.0-Recent.xml data/dev/nvd

init-dev: $(PROGPATH) data/dev/nvd/nvdcve-2.0-Recent.xml
	$(PROGPATH) db init data/dev

clean:
	rm -f ./vulweb/bindata.go
	rm -f ./$(PROGPATH)

.PHONY: run clean

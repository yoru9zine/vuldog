package vuldb

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/k0kubun/pp"
	_ "github.com/lib/pq"
	cpe "github.com/umisama/go-cpe"
	"github.com/yoru9zine/vuldog"
)

type DB struct {
	*sql.DB
}

func New(dsn string) (*DB, error) {
	sqldb, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %s", err)
	}
	db := &DB{sqldb}
	return db, nil
}

func (db *DB) Create() error {
	for _, stmt := range []string{
		"CREATE DATABASE vuldog;",
		`CREATE TABLE cpe(
           id SERIAL PRIMARY KEY,
           cpe VARCHAR(256),
           part VARCHAR(1),
           vendor VARCHAR(256),
           product VARCHAR(256)
         );`,
		`CREATE TABLE nvd(
           id SERIAL PRIMARY KEY,
           cve_id VARCHAR(14),
           published TIMESTAMP,
           last_modified TIMESTAMP,
           summary TEXT
         );`,
		`CREATE TABLE cvss_base(
           nvd_id integer REFERENCES nvd (id),
           score DOUBLE PRECISION,
           access_vector VARCHAR(64),
           access_complexity VARCHAR(64),
           authentication VARCHAR(64),
           confidentiality_impact VARCHAR(64),
           integrity_impact VARCHAR(64),
           availability_impact VARCHAR(64),
           source VARCHAR(64),
           generated_on_datetime TIMESTAMP
         );`,
		`CREATE TABLE nvd_and_cpe(
           id SERIAL PRIMARY KEY,
           nvd_id INTEGER REFERENCES nvd (id),
           cpe_id INTEGER REFERENCES cpe (id)
         )`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute sql for `%s`: %s", stmt, err)
		}
	}
	return nil
}

func (db *DB) Drop() {
	for _, stmt := range []string{
		"DROP TABLE nvd_and_cpe;",
		"DROP TABLE cvss_base;",
		"DROP TABLE nvd;",
		"DROP TABLE cpe;",
		"DROP DATABASE vuldog;",
	} {
		if _, err := db.Exec(stmt); err != nil {
			log.Printf("failed to execute sql for `%s`: %s", stmt, err)
		}
	}
}

func (db *DB) InsertNVD(nvd *vuldog.NVD) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %s", err)
	}
	for _, entry := range nvd.Entries {
		// store nvd
		if entry.ID != entry.CVEID {
			if err := tx.Rollback(); err != nil {
				log.Printf("failed to rollback: %s", err)
			}
			return fmt.Errorf("ID(%s) and CVEID(%s) mismatch", entry.ID, entry.CVEID)
		}
		var nvdid int
		if err := tx.QueryRow(`INSERT INTO nvd(
                                 cve_id,
                                 summary,
                                 published,
                                 last_modified
                              ) VALUES($1, $2, $3, $4) RETURNING id;`,
			entry.ID,
			entry.Summary,
			entry.Published,
			entry.LastModified).Scan(&nvdid); err != nil {
			if err := tx.Rollback(); err != nil {
				log.Printf("failed to rollback: %s", err)
			}
			return fmt.Errorf("failed to insert %s: %s", entry.ID, err)
		}

		// store cvss base
		if _, err := tx.Exec(`INSERT INTO cvss_base(
                                nvd_id,
                                score,
                                access_vector,
                                access_complexity,
                                authentication,
                                confidentiality_impact,
                                integrity_impact,
                                availability_impact,
                                source,
                                generated_on_datetime
                              ) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);`,
			nvdid,
			entry.CVSS.Base.Score,
			entry.CVSS.Base.AccessVector,
			entry.CVSS.Base.AccessComplexity,
			entry.CVSS.Base.Authentication,
			entry.CVSS.Base.ConfidentialityImpact,
			entry.CVSS.Base.IntegrityImpact,
			entry.CVSS.Base.AvailabilityImpact,
			entry.CVSS.Base.Source,
			entry.CVSS.Base.GeneratedOnDatetime,
		); err != nil {
			if err := tx.Rollback(); err != nil {
				log.Printf("failed to rollback: %s", err)
			}
			return fmt.Errorf("failed to insert %s: %s", entry.ID, err)
		}

		// store cpe
		for _, cpestr := range entry.VulnerableSoftwareList {
			i, err := cpe.NewItemFromUri(cpestr)
			if err != nil {
				if err := tx.Rollback(); err != nil {
					log.Printf("failed to rollback: %s", err)
				}
				return fmt.Errorf("invalid cpe(%s) found: %s", cpestr, err)
			}
			var cpeid int
			// upsert and return id
			// see: http://stackoverflow.com/questions/18192570/insert-if-not-exists-else-return-id-in-postgresql
			err = tx.QueryRow(`WITH s AS (
                                 SELECT id FROM cpe WHERE cpe = $5
                               ),
                               i AS (
                                 INSERT INTO cpe(
                                   cpe, part, vendor, product
                                 )
                                 SELECT $1, $2, $3, $4
                                 WHERE NOT EXISTS (
                                   SELECT cpe FROM cpe WHERE cpe = $5
                                 )
                                 RETURNING id
                               )
                               SELECT id FROM i
                               UNION ALL
                               SELECT id FROM s;
                               `, cpestr, string(i.Part()), i.Vendor().String(), i.Product().String(), cpestr).Scan(&cpeid)
			if err != nil {
				if err != sql.ErrNoRows {
					if err := tx.Rollback(); err != nil {
						log.Printf("failed to rollback: %s", err)
					}
					return fmt.Errorf("failed to insert %s: %s", cpestr, err)
				}
			}
			pp.Println(nvdid, cpeid)
			if _, err := tx.Exec(`INSERT INTO nvd_and_cpe(
                                    nvd_id, cpe_id
                                  )
                                  VALUES (
                                    $1, $2
                                  );`, nvdid, cpeid); err != nil {
				if err != nil {
					if err := tx.Rollback(); err != nil {
						log.Printf("failed to rollback: %s", err)
					}
					return fmt.Errorf("failed to insert nvd_and_cpe(%d, %d) found: %s", nvdid, cpeid, err)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %s", err)
	}
	return nil
}

func (db *DB) GetRecentCVE(n int) ([]vuldog.NVDEntry, error) {
	rows, err := db.Query(`SELECT nvd.cve_id, nvd.summary, nvd.published, nvd.last_modified, cvss_base.score from nvd JOIN cvss_base ON nvd.id=cvss_base.nvd_id`)
	if err != nil {
		return nil, fmt.Errorf("failed to select database: %s", err)
	}
	defer rows.Close()
	entries := []vuldog.NVDEntry{}
	for rows.Next() {
		entry := vuldog.NVDEntry{}
		if err := rows.Scan(&entry.ID, &entry.Summary, &entry.Published, &entry.LastModified, &entry.CVSS.Base.Score); err != nil {
			return nil, fmt.Errorf("failed to scan cve_list: %s", err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func (db *DB) GetCVE(id string) (*vuldog.NVDEntry, error) {
	row := db.QueryRow(`SELECT
                          nvd.id,
                          nvd.cve_id,
                          nvd.summary,
                          nvd.published,
                          nvd.last_modified,
                          cvss_base.score,
                          cvss_base.access_vector,
                          cvss_base.access_complexity,
                          cvss_base.authentication,
                          cvss_base.confidentiality_impact,
                          cvss_base.integrity_impact,
                          cvss_base.availability_impact,
                          cvss_base.source,
                          cvss_base.generated_on_datetime
                        FROM nvd JOIN cvss_base ON nvd.id=cvss_base.nvd_id WHERE nvd.cve_id=$1`, strings.ToUpper(id))
	var entry vuldog.NVDEntry
	var nvdid int
	if err := row.Scan(
		&nvdid,
		&entry.ID,
		&entry.Summary,
		&entry.Published,
		&entry.LastModified,
		&entry.CVSS.Base.Score,
		&entry.CVSS.Base.AccessVector,
		&entry.CVSS.Base.AccessComplexity,
		&entry.CVSS.Base.Authentication,
		&entry.CVSS.Base.ConfidentialityImpact,
		&entry.CVSS.Base.IntegrityImpact,
		&entry.CVSS.Base.AvailabilityImpact,
		&entry.CVSS.Base.Source,
		&entry.CVSS.Base.GeneratedOnDatetime,
	); err != nil {
		return nil, fmt.Errorf("failed to scan cve_detail: %s", err)
	}
	rows, err := db.Query(`SELECT cpe.cpe FROM nvd_and_cpe
                           JOIN nvd ON nvd_and_cpe.nvd_id=nvd.id
                           JOIN cpe ON nvd_and_cpe.cpe_id=cpe.id
                           WHERE nvd.id=$1`, nvdid)
	defer rows.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to select nvd_and_cpe: %s", err)
	}
	for rows.Next() {
		var cpestr string
		if err := rows.Scan(&cpestr); err != nil {
			return nil, fmt.Errorf("failed to scan cpe: %s", err)
		}
		entry.VulnerableSoftwareList = append(entry.VulnerableSoftwareList, cpestr)
	}
	return &entry, nil
}

func (db *DB) GetVendors(n int) ([]string, error) {
	rows, err := db.Query(`SELECT DISTINCT vendor FROM cpe LIMIT $1`, n)
	if err != nil {
		return nil, fmt.Errorf("failed to get vendor list: %s", err)
	}
	defer rows.Close()

	vendors := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("failed to scan vendor: %s", err)
		}
		vendors = append(vendors, v)
	}
	return vendors, nil
}

package licenseserver

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

const (
	dashboardPass   = "adminpass"
	clientUserAgent = "WoolCNC-License-Client"
	privateKeyFile  = "license_private.asc"
)

var db *sql.DB

// Debug controls verbose license server logging.
var Debug bool

func debugf(format string, args ...interface{}) {
	if Debug {
		log.Printf(format, args...)
	}
}

func InitDB(path string) error {
	var err error
	db, err = sql.Open("sqlite3", path)
	if err != nil {
		return err
	}
	schema := `CREATE TABLE IF NOT EXISTS licenses(
        key TEXT PRIMARY KEY,
        expiration TEXT NOT NULL,
        server_id TEXT
    );`
	_, err = db.Exec(schema)
	return err
}

func Start(addr string) error {
	http.HandleFunc("/validate", handleValidate)
	http.HandleFunc("/dashboard", handleDashboard)
	http.HandleFunc("/add", handleAdd)
	debugf("license server started on %s", addr)
	return http.ListenAndServe(addr, nil)
}

type license struct {
	Key        string
	Expiration string
	ServerID   sql.NullString
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	debugf("validate request from %s", r.RemoteAddr)
	if r.Header.Get("User-Agent") != clientUserAgent {
		debugf("invalid user agent: %s", r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusForbidden)
		return
	}
	enc := r.URL.Query().Get("data")
	priv, err := os.Open(privateKeyFile)
	if err != nil {
		debugf("open private key error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("open private key"))
		return
	}
	defer priv.Close()
	el, err := openpgp.ReadArmoredKeyRing(priv)
	if err != nil {
		debugf("read private key error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("read private key"))
		return
	}
	block, err := armor.Decode(strings.NewReader(enc))
	if err != nil {
		debugf("bad armored: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad armored"))
		return
	}
	md, err := openpgp.ReadMessage(block.Body, el, nil, nil)
	if err != nil {
		debugf("decrypt error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("decrypt error"))
		return
	}
	decBytes, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		debugf("read body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("read body"))
		return
	}
	key := string(decBytes)
	server := r.URL.Query().Get("server")
	row := db.QueryRow("SELECT expiration, server_id FROM licenses WHERE key=?", key)
	var exp string
	var sid sql.NullString
	if err := row.Scan(&exp, &sid); err != nil {
		debugf("license not found: %s", key)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"Valid": false})
		return
	}
	t, _ := time.Parse("2006-01-02", exp)
	if time.Now().After(t) {
		debugf("license expired: %s", exp)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"Valid": false})
		return
	}
	if sid.Valid {
		if sid.String != server {
			debugf("server mismatch: %s vs %s", sid.String, server)
			json.NewEncoder(w).Encode(map[string]bool{"Valid": false})
			return
		}
	} else {
		// bind key to server
		debugf("binding license %s to server %s", key, server)
		db.Exec("UPDATE licenses SET server_id=? WHERE key=?", server, key)
	}
	debugf("license valid: %s", key)
	json.NewEncoder(w).Encode(map[string]bool{"Valid": true})
}

var tmpl = template.Must(template.New("dash").Parse(`
<html><body>
{{if .Message}}<p>{{.Message}}</p>{{end}}
<form method="POST" action="/add?pass={{.Pass}}">
Days: <input name="days" type="number" />
<input type="submit" value="Generate" />
</form>
<table border="1"><tr><th>Key</th><th>Expiration</th><th>ServerID</th></tr>
{{range .Licenses}}
<tr><td>{{.Key}}</td><td>{{.Expiration}}</td><td>{{.ServerID.String}}</td></tr>
{{end}}
</table>
</body></html>`))

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	pass := r.URL.Query().Get("pass")
	if pass != dashboardPass {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("invalid password"))
		return
	}
	rows, _ := db.Query("SELECT key, expiration, server_id FROM licenses")
	defer rows.Close()
	var list []license
	for rows.Next() {
		var l license
		rows.Scan(&l.Key, &l.Expiration, &l.ServerID)
		list = append(list, l)
	}
	tmpl.Execute(w, map[string]any{"Licenses": list, "Pass": pass})
}

func handleAdd(w http.ResponseWriter, r *http.Request) {
	pass := r.URL.Query().Get("pass")
	if pass != dashboardPass {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	daysStr := r.FormValue("days")
	daysInt, _ := strconv.Atoi(daysStr)
	exp := time.Now().AddDate(0, 0, daysInt).Format("2006-01-02")
	key := randString(16)
	_, err := db.Exec("INSERT INTO licenses(key,expiration) VALUES(?,?)", key, exp)
	msg := ""
	if err != nil {
		msg = err.Error()
	} else {
		msg = fmt.Sprintf("generated key: %s", key)
	}
	rows, _ := db.Query("SELECT key,expiration,server_id FROM licenses")
	defer rows.Close()
	var list []license
	for rows.Next() {
		var l license
		rows.Scan(&l.Key, &l.Expiration, &l.ServerID)
		list = append(list, l)
	}
	tmpl.Execute(w, map[string]any{"Licenses": list, "Pass": pass, "Message": msg})
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

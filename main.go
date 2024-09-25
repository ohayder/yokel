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
	"io"

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


// Update the Voucher struct
type Voucher struct {
    gorm.Model
    VoucherID string    `gorm:"uniqueIndex"`
    UserID    uint
    ExpiresAt time.Time
    UserData  []byte    `gorm:"size:64"` // Up to 64 bytes of user data
}

// Update the Session struct
type Session struct {
    gorm.Model
    SessionUUID   string    `gorm:"uniqueIndex"`
    UserID        uint
    ExpiresAt     time.Time
    BumpAttempts  int       // Track the number of bump attempts
    FailedBumps   int       // Track the number of failed bumps
}

// Update the Config struct (if needed)
type Config struct {
    Port               int    `yaml:"port"`
    Binding            string `yaml:"binding"`
    URL                string `yaml:"url"`
    Key                string `yaml:"key"`
    Cert               string `yaml:"cert"`
    VoucherMaxLifetime string `yaml:"voucher_max_lifetime"`
    VoucherMaxPerUser  int    `yaml:"voucher_max_per_user"`
    NoKV               bool   `yaml:"no_kv"`
    UserDataMax        int    `yaml:"user_data_max"`
    JWTSecretKey       string `yaml:"jwt_secret_key"`
}

// The User struct seems to be already aligned with ABOUT.md, but here it is for reference:
type User struct {
    gorm.Model
    Username string `gorm:"uniqueIndex"`
    Email    string
    Password string
}

// Update the UserSettings struct
type UserSettings struct {
    gorm.Model
    UserID           uint   `gorm:"uniqueIndex"`
    NotificationsOn  bool
    DarkModeEnabled  bool
    Language         string
    // Add other settings fields as needed
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
	err = db.AutoMigrate(&User{}, &Session{}, &Voucher{}, &UserSettings{})
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

func authenticateVoucherHandler(w http.ResponseWriter, r *http.Request) {
    // Extract the voucher ID from the request header
    voucherID := r.Header.Get(HeaderUserVoucher)
    if voucherID == "" {
        http.Error(w, "Voucher ID is required", http.StatusBadRequest)
        return
    }

    // Find the voucher in the database
    var voucher Voucher
    if err := db.Where("voucher_id = ?", voucherID).First(&voucher).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            http.Error(w, "Invalid voucher", http.StatusUnauthorized)
        } else {
            http.Error(w, "Internal server error", http.StatusInternalServerError)
        }
        return
    }

    // Check if the voucher has expired
    if time.Now().After(voucher.ExpiresAt) {
        http.Error(w, "Voucher has expired", http.StatusUnauthorized)
        return
    }

    // Voucher is valid, create a new session for the user
    sessionUUID := generateUUID()
    expirationTime := time.Now().Add(30 * time.Minute)
    
    // Create and sign the JWT token
    claims := &jwt.RegisteredClaims{
        ExpiresAt: jwt.NewNumericDate(expirationTime),
        ID:        sessionUUID,
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        http.Error(w, "Failed to generate session token", http.StatusInternalServerError)
        return
    }

    // Store the new session in the database
    session := Session{
        SessionUUID: sessionUUID,
        UserID:      voucher.UserID,
        ExpiresAt:   expirationTime,
    }
    if err := db.Create(&session).Error; err != nil {
        http.Error(w, "Failed to create session", http.StatusInternalServerError)
        return
    }

    // Respond with the new session information
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "session_uuid":  sessionUUID,
        "session_token": tokenString,
    })
}

func bumpSessionHandler(w http.ResponseWriter, r *http.Request) {
    // Extract the session UUID from the URL parameters
    vars := mux.Vars(r)
    sessionUUID := vars["sessionUUID"]

    // Retrieve the session from the database
    var session Session
    if err := db.Where("session_uuid = ?", sessionUUID).First(&session).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            http.Error(w, "Session not found", http.StatusNotFound)
        } else {
            http.Error(w, "Internal server error", http.StatusInternalServerError)
        }
        return
    }

    // Check if the session has expired
    if time.Now().After(session.ExpiresAt) {
        http.Error(w, "Session has expired", http.StatusUnauthorized)
        return
    }

    // Check if the session needs to be bumped (less than 5 minutes remaining)
    if time.Until(session.ExpiresAt) > 5*time.Minute {
        session.FailedBumps++
        if session.FailedBumps >= 5 {
            // Delete the session if too many failed bumps
            db.Delete(&session)
            http.Error(w, "Session terminated due to excessive failed bumps", http.StatusUnauthorized)
            return
        }
        if err := db.Save(&session).Error; err != nil {
            http.Error(w, "Failed to update session", http.StatusInternalServerError)
            return
        }
        http.Error(w, "Session does not need to be bumped yet", http.StatusBadRequest)
        return
    }

    // Extend the session expiration time
    newExpirationTime := time.Now().Add(30 * time.Minute)
    session.ExpiresAt = newExpirationTime
    session.FailedBumps = 0 // Reset failed bumps on successful bump

    // Update the session in the database
    if err := db.Save(&session).Error; err != nil {
        http.Error(w, "Failed to update session", http.StatusInternalServerError)
        return
    }

    // Create a new JWT token with the updated expiration time
    claims := &jwt.RegisteredClaims{
        ExpiresAt: jwt.NewNumericDate(newExpirationTime),
        ID:        sessionUUID,
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        http.Error(w, "Failed to generate new session token", http.StatusInternalServerError)
        return
    }

    // Respond with the updated session information
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "session_uuid":  sessionUUID,
        "session_token": tokenString,
    })
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    // Extract the session UUID from the URL parameters
    vars := mux.Vars(r)
    sessionUUID := vars["sessionUUID"]

    // Delete the session from the database
    result := db.Where("session_uuid = ?", sessionUUID).Delete(&Session{})
    if result.Error != nil {
        http.Error(w, "Failed to logout", http.StatusInternalServerError)
        return
    }

    // Check if a session was actually deleted
    if result.RowsAffected == 0 {
        http.Error(w, "Session not found", http.StatusNotFound)
        return
    }

    // Respond with a success message
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Logged out successfully",
    })

    // Note: In a production environment, you might want to add the token
    // to a blacklist or implement a token revocation mechanism
}

func readAccountHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Retrieve the user from the database
    var user User
    if err := db.First(&user, userID).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            http.Error(w, "User not found", http.StatusNotFound)
        } else {
            http.Error(w, "Failed to retrieve user data", http.StatusInternalServerError)
        }
        return
    }

    // Create a response struct with the user data we want to expose
    type AccountResponse struct {
        Username string `json:"username"`
        Email    string `json:"email"`
        // Add any other fields you want to include in the response
    }

    response := AccountResponse{
        Username: user.Username,
        Email:    user.Email,
    }

    // Send the response
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(response); err != nil {
        http.Error(w, "Failed to encode response", http.StatusInternalServerError)
    }
}

func updateAccountHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Parse the request body
    var updateRequest struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Retrieve the user from the database
    var user User
    if err := db.First(&user, userID).Error; err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    // Update email if provided
    if updateRequest.Email != "" {
        if err := validateEmail(updateRequest.Email); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        user.Email = updateRequest.Email
    }

    // Update password if provided
    if updateRequest.Password != "" {
        hashedPassword, err := hashPassword(updateRequest.Password)
        if err != nil {
            http.Error(w, "Failed to process new password", http.StatusInternalServerError)
            return
        }
        user.Password = hashedPassword
    }

    // Save the updated user to the database
    if err := db.Save(&user).Error; err != nil {
        http.Error(w, "Failed to update user", http.StatusInternalServerError)
        return
    }

    // Respond with success message
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Account updated successfully",
    })
}

func deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Start a transaction
    tx := db.Begin()

    // Delete all sessions for the user
    if err := tx.Where("user_id = ?", userID).Delete(&Session{}).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Failed to delete user sessions", http.StatusInternalServerError)
        return
    }

    // Delete all vouchers for the user
    if err := tx.Where("user_id = ?", userID).Delete(&Voucher{}).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Failed to delete user vouchers", http.StatusInternalServerError)
        return
    }

    // Delete the user
    if err := tx.Delete(&User{}, userID).Error; err != nil {
        tx.Rollback()
        http.Error(w, "Failed to delete user", http.StatusInternalServerError)
        return
    }

    // Commit the transaction
    if err := tx.Commit().Error; err != nil {
        http.Error(w, "Failed to commit changes", http.StatusInternalServerError)
        return
    }

    // Respond with success message
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Account deleted successfully",
    })

    // Note: In a production environment, you might want to implement a soft delete
    // or archive user data instead of permanent deletion
}

func readSettingsHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Retrieve the user's settings from the database
    var settings UserSettings
    if err := db.Where("user_id = ?", userID).First(&settings).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            // If settings don't exist, return default settings
            settings = UserSettings{
                UserID:           userID,
                NotificationsOn:  true,
                DarkModeEnabled:  false,
                Language:         "en",
                // Add other default settings as needed
            }
        } else {
            http.Error(w, "Failed to retrieve user settings", http.StatusInternalServerError)
            return
        }
    }

    // Create a response struct
    type SettingsResponse struct {
        NotificationsOn bool   `json:"notifications_on"`
        DarkModeEnabled bool   `json:"dark_mode_enabled"`
        Language        string `json:"language"`
        // Add other settings fields as needed
    }

    response := SettingsResponse{
        NotificationsOn:  settings.NotificationsOn,
        DarkModeEnabled:  settings.DarkModeEnabled,
        Language:         settings.Language,
        // Map other settings fields
    }

    // Send the response
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(response); err != nil {
        http.Error(w, "Failed to encode response", http.StatusInternalServerError)
    }
}

func updateSettingsHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Parse the request body
    var updateRequest struct {
        NotificationsOn  *bool   `json:"notifications_on,omitempty"`
        DarkModeEnabled  *bool   `json:"dark_mode_enabled,omitempty"`
        Language         *string `json:"language,omitempty"`
        // Add other settings fields as needed
    }
    if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Retrieve the user's settings from the database
    var settings UserSettings
    if err := db.Where("user_id = ?", userID).First(&settings).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            // If settings don't exist, create new settings
            settings = UserSettings{UserID: userID}
        } else {
            http.Error(w, "Failed to retrieve user settings", http.StatusInternalServerError)
            return
        }
    }

    // Update settings if provided
    if updateRequest.NotificationsOn != nil {
        settings.NotificationsOn = *updateRequest.NotificationsOn
    }
    if updateRequest.DarkModeEnabled != nil {
        settings.DarkModeEnabled = *updateRequest.DarkModeEnabled
    }
    if updateRequest.Language != nil {
        // You might want to add validation for supported languages
        settings.Language = *updateRequest.Language
    }
    // Update other settings fields as needed

    // Save the updated settings to the database
    if err := db.Save(&settings).Error; err != nil {
        http.Error(w, "Failed to update settings", http.StatusInternalServerError)
        return
    }

    // Respond with success message
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Settings updated successfully",
    })
}

func createVoucherHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Parse the voucher lifetime from the header
    lifetimeStr := r.Header.Get(HeaderVoucherLifetime)
    lifetime, err := time.ParseDuration(lifetimeStr)
    if err != nil || lifetime <= 0 {
        http.Error(w, "Invalid voucher lifetime", http.StatusBadRequest)
        return
    }

    // Check if the lifetime exceeds the maximum allowed
    maxLifetime, _ := time.ParseDuration(config.VoucherMaxLifetime)
    if lifetime > maxLifetime {
        http.Error(w, "Voucher lifetime exceeds maximum allowed", http.StatusBadRequest)
        return
    }

    // Read user data from request body
    userData, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read request body", http.StatusBadRequest)
        return
    }
    if len(userData) > 64 {
        http.Error(w, "User data exceeds 64 bytes limit", http.StatusBadRequest)
        return
    }

    // Generate a new voucher
    voucherID := generateUUID()
    expiresAt := time.Now().Add(lifetime)
    voucher := Voucher{
        VoucherID: voucherID,
        UserID:    userID,
        ExpiresAt: expiresAt,
        UserData:  userData,
    }

    // Check if the user has reached the maximum number of vouchers
    var voucherCount int64
    if err := db.Model(&Voucher{}).Where("user_id = ?", userID).Count(&voucherCount).Error; err != nil {
        http.Error(w, "Failed to check voucher count", http.StatusInternalServerError)
        return
    }
    if int(voucherCount) >= config.VoucherMaxPerUser {
        http.Error(w, "Maximum number of vouchers reached", http.StatusForbidden)
        return
    }

    // Save the voucher to the database
    if err := db.Create(&voucher).Error; err != nil {
        http.Error(w, "Failed to create voucher", http.StatusInternalServerError)
        return
    }

    // Respond with the created voucher
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "voucher_id": voucherID,
        "expires_at": expiresAt.Format(time.RFC3339),
    })
}

func readVouchersHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Retrieve all vouchers for the user from the database
    var vouchers []Voucher
    if err := db.Where("user_id = ?", userID).Find(&vouchers).Error; err != nil {
        http.Error(w, "Failed to retrieve vouchers", http.StatusInternalServerError)
        return
    }

    // Create a response struct to control what data is sent back
    type VoucherResponse struct {
        VoucherID string    `json:"voucher_id"`
        ExpiresAt time.Time `json:"expires_at"`
    }

    var response []VoucherResponse
    for _, v := range vouchers {
        response = append(response, VoucherResponse{
            VoucherID: v.VoucherID,
            ExpiresAt: v.ExpiresAt,
        })
    }

    // Send the response
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(response); err != nil {
        http.Error(w, "Failed to encode response", http.StatusInternalServerError)
        return
    }
}

func deleteVoucherHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Get the voucher ID from the query parameters
    voucherID := r.URL.Query().Get("voucher_id")
    if voucherID == "" {
        http.Error(w, "Voucher ID is required", http.StatusBadRequest)
        return
    }

    // Find the voucher in the database
    var voucher Voucher
    if err := db.Where("voucher_id = ? AND user_id = ?", voucherID, userID).First(&voucher).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            http.Error(w, "Voucher not found or does not belong to the user", http.StatusNotFound)
        } else {
            http.Error(w, "Failed to retrieve voucher", http.StatusInternalServerError)
        }
        return
    }

    // Delete the voucher
    if err := db.Delete(&voucher).Error; err != nil {
        http.Error(w, "Failed to delete voucher", http.StatusInternalServerError)
        return
    }

    // Respond with success message
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Voucher deleted successfully",
    })
}

// Add this struct to your models
type UserKV struct {
    gorm.Model
    UserID uint   `gorm:"index"`
    Key    string `gorm:"index"`
    Value  string
}

func kvReadHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Get the key from the URL parameters
    vars := mux.Vars(r)
    key := vars["key"]

    // Retrieve the key-value pair from the database
    var kv UserKV
    if err := db.Where("user_id = ? AND key = ?", userID, key).First(&kv).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            http.Error(w, "Key not found", http.StatusNotFound)
        } else {
            http.Error(w, "Failed to retrieve key-value pair", http.StatusInternalServerError)
        }
        return
    }

    // Respond with the value
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "key":   kv.Key,
        "value": kv.Value,
    })
}

func kvWriteHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Get the key and value from the URL parameters
    vars := mux.Vars(r)
    key := vars["key"]
    value := vars["value"]

    // Check if the key already exists
    var kv UserKV
    result := db.Where("user_id = ? AND key = ?", userID, key).First(&kv)

    if result.Error == nil {
        // Key exists, update the value
        kv.Value = value
        if err := db.Save(&kv).Error; err != nil {
            http.Error(w, "Failed to update key-value pair", http.StatusInternalServerError)
            return
        }
    } else if result.Error == gorm.ErrRecordNotFound {
        // Key doesn't exist, create a new key-value pair
        kv = UserKV{
            UserID: userID,
            Key:    key,
            Value:  value,
        }
        if err := db.Create(&kv).Error; err != nil {
            http.Error(w, "Failed to create key-value pair", http.StatusInternalServerError)
            return
        }
    } else {
        // Other database error
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    // Check if the user has exceeded the maximum allowed key-value pairs
    var count int64
    if err := db.Model(&UserKV{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
        http.Error(w, "Failed to count key-value pairs", http.StatusInternalServerError)
        return
    }

    if int(count) > config.UserDataMax {
        http.Error(w, "Maximum number of key-value pairs reached", http.StatusForbidden)
        return
    }

    // Respond with success message
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Key-value pair written successfully",
    })
}

func kvClearHandler(w http.ResponseWriter, r *http.Request) {
    // Get the user ID from the context (set by the authenticateSession middleware)
    userID, ok := r.Context().Value("userID").(uint)
    if !ok {
        http.Error(w, "User ID not found in context", http.StatusInternalServerError)
        return
    }

    // Delete all key-value pairs for the user
    result := db.Where("user_id = ?", userID).Delete(&UserKV{})
    if result.Error != nil {
        http.Error(w, "Failed to clear key-value pairs", http.StatusInternalServerError)
        return
    }

    // Respond with success message and number of deleted pairs
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message":        "All key-value pairs cleared successfully",
        "pairs_deleted":  result.RowsAffected,
    })
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



package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

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

// Update the Session struct
type Session struct {
    gorm.Model
    SessionUUID   string    `gorm:"uniqueIndex"`
    UserID        uint
    ExpiresAt     time.Time
    BumpAttempts  int       // Track the number of bump attempts
    FailedBumps   int       // Track the number of failed bumps
}

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

    // Parse the request body to get the password
    var deleteRequest struct {
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&deleteRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Retrieve the user from the database
    var user User
    if err := db.First(&user, userID).Error; err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    // Verify the provided password
    if !checkPasswordHash(deleteRequest.Password, user.Password) {
        http.Error(w, "Invalid password", http.StatusUnauthorized)
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
    if err := tx.Delete(&user).Error; err != nil {
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
}
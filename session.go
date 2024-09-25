package main

import (
	"encoding/json"
	"net/http"
	"context"
	"gorm.io/gorm"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"time"
)



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
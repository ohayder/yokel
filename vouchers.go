package main

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

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

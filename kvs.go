package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

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

package main

import (
	"encoding/json"
	"net/http"

	"gorm.io/gorm"
)

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

package handler

import "net/http"

// Version is the API version reported by GET /version.
const Version = "0.1.0"

// VersionInfo returns the running API version.
func VersionInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": Version})
}

package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-playground/validator/v10"
)

// decodeAndValidate reads a JSON body into dst and validates it. On failure it
// writes the 400 response itself and returns false, so callers just return.
func decodeAndValidate(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON with known fields")
		return false
	}

	if err := validate.Struct(dst); err != nil {
		var verrs validator.ValidationErrors
		if errors.As(err, &verrs) {
			writeValidationError(w, fieldMessages(verrs))
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request")
		return false
	}
	return true
}

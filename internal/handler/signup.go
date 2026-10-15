package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// Same shape as the CHECK constraint on tenants.subdomain.
var subdomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Subdomains we keep for ourselves.
var reservedSubdomains = map[string]bool{
	"www": true, "api": true, "app": true, "admin": true, "mail": true,
	"static": true, "status": true, "support": true, "billing": true,
}

// validate is safe for concurrent use and caches struct info, so build it once.
var validate = newValidator()

func newValidator() *validator.Validate {
	v := validator.New()
	// Report errors using JSON field names ("company_name"), not Go names.
	v.RegisterTagNameFunc(func(f reflect.StructField) string {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		return name
	})
	// Rejects strings that are empty or only whitespace.
	_ = v.RegisterValidation("notblank", func(fl validator.FieldLevel) bool {
		return strings.TrimSpace(fl.Field().String()) != ""
	})
	_ = v.RegisterValidation("subdomain", func(fl validator.FieldLevel) bool {
		s := fl.Field().String() // strict: uppercase or padded input is rejected, not silently fixed
		return subdomainRe.MatchString(s) && !reservedSubdomains[s]
	})
	return v
}

// Signuper creates a new tenant and its owner. Defined here, where it is
// used, so tests can supply a fake.
type Signuper interface {
	Signup(ctx context.Context, in auth.SignupInput) (auth.SignupResult, error)
}

type signupRequest struct {
	CompanyName string `json:"company_name" validate:"required,min=1,max=100"`
	Subdomain   string `json:"subdomain"    validate:"required,subdomain"`
	Email       string `json:"email"        validate:"required,email,max=254"`
	Password    string `json:"password"     validate:"required,min=10,max=128"`
}

type signupResponse struct {
	Tenant struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Subdomain string `json:"subdomain"`
	} `json:"tenant"`
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

// Signup handles POST /signup: parse, validate, call the service, respond.
func Signup(svc Signuper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req signupRequest
		if !decodeAndValidate(w, r, &req) {
			return
		}

		res, err := svc.Signup(r.Context(), auth.SignupInput{
			CompanyName: req.CompanyName,
			Subdomain:   req.Subdomain,
			Email:       req.Email,
			Password:    req.Password,
		})
		switch {
		case errors.Is(err, auth.ErrSubdomainTaken):
			writeError(w, http.StatusConflict, "subdomain_taken", "that subdomain is already taken")
			return
		case errors.Is(err, auth.ErrEmailTaken):
			writeError(w, http.StatusConflict, "email_taken", "that email is already registered")
			return
		case err != nil:
			// Log the detail for us; tell the client nothing about internals.
			slog.Error("signup failed", "error", err, "request_id", middleware.GetReqID(r.Context()))
			writeError(w, http.StatusInternalServerError, "internal_error", "something went wrong")
			return
		}

		var resp signupResponse
		resp.Tenant.ID = res.TenantID.String()
		resp.Tenant.Name = res.CompanyName
		resp.Tenant.Subdomain = res.Subdomain
		resp.User.ID = res.UserID.String()
		resp.User.Email = res.Email
		writeJSON(w, http.StatusCreated, resp)
	}
}

// fieldMessages converts validator errors into a field -> message map.
func fieldMessages(verrs validator.ValidationErrors) map[string]string {
	out := make(map[string]string, len(verrs))
	for _, fe := range verrs {
		switch fe.Tag() {
		case "required":
			out[fe.Field()] = "is required"
		case "email":
			out[fe.Field()] = "must be a valid email address"
		case "min":
			out[fe.Field()] = "is too short (minimum " + fe.Param() + ")"
		case "max":
			out[fe.Field()] = "is too long (maximum " + fe.Param() + ")"
		case "notblank":
			out[fe.Field()] = "must not be blank"
		case "oneof":
			out[fe.Field()] = "must be one of: " + fe.Param()
		case "subdomain":
			out[fe.Field()] = "must be lowercase letters, digits or hyphens, and not reserved"
		default:
			out[fe.Field()] = "is invalid"
		}
	}
	return out
}

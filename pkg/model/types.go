package model

import (
	"time"
)

const (
	// ColumnKeyEnv the environment name of the variable used to specify the private encryption key used
	// on columns of type ColumnSecret
	ColumnKeyEnv = "DB_COL_KEY"
)

// ColumnSecret a type for a gorm model column whose value is encrypted before persisting to
// the database and is unencrypted in the struct.
type ColumnSecret string

type YubiUser struct {
	ID        uint      `json:"-" gorm:"primary_key"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// Email the email address of the owner
	Email string `json:"email"`
	// Is the user enabled?
	IsEnabled bool `json:"is_enabled"`
	// An admin user has additional capabilities. It can register other users, for instance.
	IsAdmin bool `json:"is_admin"`
	// Counter the token usage counter. It represents the last counter provided by the Yubi token from a OTP.
	Counter int64 `json:"counter"`
	// Session the session usage counter provided by the Yubi token from a OTP. Used to protect against token reuse.
	Session int64 `json:"session"`
	// Public the Yubikey ID assigned to the physical token
	Public string `json:"public" gorm:"unique;not null"`
	// Secret the user's secret AES key associated with the Yubi token slot
	Secret ColumnSecret `json:"secret,omitempty"`
	// Description info about the owner; email, name, et.al
	Description string `json:"description"`
}

// Editable convert a YubiUser to a struct of values we allow to be edited
func (u YubiUser) Editable() *YubiUserEditable {
	return &YubiUserEditable{
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		Email:       &u.Email,
		IsEnabled:   &u.IsEnabled,
		IsAdmin:     &u.IsAdmin,
		Public:      u.Public, // not editable but needed to select
		Description: &u.Description,
	}
}

// YubiUserEditable are the editable fields of a registered user
type YubiUserEditable struct {
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// Email the email address of the owner
	Email *string `json:"email,omitempty"`
	// Is the user enabled?
	IsEnabled *bool `json:"is_enabled,omitempty"`
	// An admin user has additional capabilities. It can register other users, for instance.
	IsAdmin *bool `json:"is_admin,omitempty"`
	// Public the Yubikey ID assigned to the physical token
	Public string `json:"public"`
	// Description info about the owner; email, name, et.al
	Description *string `json:"description,omitempty"`
}

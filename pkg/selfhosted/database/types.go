package database

import "github.com/dsggregory/yubiv/pkg/selfhosted/model"

// Databaser interface to the underlying database that manages known Yubi keys
type Databaser interface {
	Add(user model.YubiUser) error
	Get(ykid string) (*model.YubiUser, error)
	GetAll() ([]*model.YubiUser, error)
	UpdateCounts(user model.YubiUser) error
	UpdateUser(user model.YubiUser) error
	SetSecretColumnKeyFunc(model.SecretColumnKeyT)
}

type RegistrationError struct {
	msg string
	err error
}

func (e *RegistrationError) Error() string {
	return e.msg
}

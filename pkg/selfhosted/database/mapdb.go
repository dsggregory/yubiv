/*** An implementation of the Databaser interface as an in-memory map for testing
 */
package database

import (
	"errors"
	"os"
	"time"

	"github.com/dsggregory/yubiv/pkg/selfhosted/model"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
)

// MapDb implements Databaser interface.
// This should be a real database that stores known user yubikey IDs and their secrets.
type MapDb struct {
	recs map[string]*model.YubiUser
}

// See README.md for info on how to determine the yubikey ID and secret AES key.
func (db *MapDb) Add(user model.YubiUser) error {
	r := model.YubiUser{
		ID:          user.ID,
		CreatedAt:   time.Now(),
		Counter:     0,
		Session:     0,
		Public:      user.Public,
		Secret:      user.Secret,
		Description: user.Description,
		Email:       user.Email,
		IsAdmin:     user.IsAdmin,
		IsEnabled:   user.IsEnabled,
	}
	db.recs[user.Public] = &r

	return nil
}

// Find key in database or return an error
func (db *MapDb) Get(ykid string) (*model.YubiUser, error) {
	r := db.recs[ykid]
	if r == nil {
		return nil, errors.New("Not found")
	}
	return r, nil
}

func (db *MapDb) GetAll() ([]*model.YubiUser, error) {
	a := []*model.YubiUser{}
	for _, v := range db.recs {
		a = append(a, v)
	}
	return a, nil
}

// Intent is we are updating the usage count for the yubikey
func (db *MapDb) UpdateCounts(rec model.YubiUser) error {
	db.recs[rec.Public] = &rec
	return nil
}

// Intent is we are updating the usage count for the yubikey
func (db *MapDb) UpdateUser(rec model.YubiUser) error {
	db.recs[rec.Public] = &rec
	return nil
}

// SetSecretColumnKeyFunc specifies the func to call to acquire the application's secret key for DB column encryption
func (db *MapDb) SetSecretColumnKeyFunc(kf model.SecretColumnKeyT) {
	model.SecretColumnKeyFunc = kf
}

func NewMapDb() *MapDb {
	db := MapDb{
		recs: make(map[string]*model.YubiUser),
	}

	type knownKey struct {
		ID          string `json:"yubi_id"`
		Secret      string `json:"yubi_secret"`
		Description string `json:"description"`
	}
	type keys struct {
		Keys []knownKey
	}
	kk := keys{}
	kkDataPath := os.Getenv("YUBI_KEY_MAP")
	if kkDataPath != "" {
		fp, err := os.Open(kkDataPath)
		defer func() { _ = fp.Close() }()
		if err == nil {
			if err = yaml.NewDecoder(fp).Decode(&kk); err == nil {
				for i := range kk.Keys {
					r := model.YubiUser{
						Email:       kk.Keys[i].ID + "@domain.com",
						Counter:     0,
						Session:     0,
						Public:      kk.Keys[i].ID,
						Secret:      model.ColumnSecret(kk.Keys[i].Secret),
						Description: kk.Keys[i].Description,
					}
					_ = db.Add(r)
				}
				log.WithField("nRecords", len(db.recs)).Debug("loaded Yubi DB map")
			}
		}
		if err != nil {
			log.WithError(err).Error("failed loading yubi map")
		}
	} else {
		log.Warn("YUBI_KEY_MAP env not set")
	}

	return &db
}

package database

import (
	"fmt"
	"net/url"
	"time"

	"github.com/dsggregory/yubiv/pkg/selfhosted/model"
	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"

	_ "gorm.io/driver/mysql"
	_ "gorm.io/driver/sqlite"
)

// Db implements Databaser interface
type Db struct {
	// used to query the yubi users DB
	db *gorm.DB
}

func (db *Db) Add(req model.YubiUser) error {
	req.ID = 0
	req.CreatedAt = time.Now()
	req.UpdatedAt = time.Now()
	req.Session = 0
	req.Counter = 0

	return db.db.Create(&req).Error
}

func (db *Db) Get(ykid string) (*model.YubiUser, error) {
	user := &model.YubiUser{Public: ykid}
	if err := db.db.Where(user).First(user).Error; err != nil {
		//log.WithField("pubkey", ykid).WithError(err).Error("failed looking up YubiUser")
		return nil, fmt.Errorf("unregistered yubikey")
	}

	return user, nil
}

func (db *Db) GetAll() ([]*model.YubiUser, error) {
	var users []*model.YubiUser
	err := db.db.Find(&users).Error
	return users, err
}

// UpdateCounts update counters for the YubiKey
func (db *Db) UpdateCounts(user model.YubiUser) error {
	user.UpdatedAt = time.Now()
	err := db.db.Model(&user).Updates(model.YubiUser{
		UpdatedAt: time.Now(),
		Counter:   user.Counter,
		Session:   user.Session,
	}).Error
	if err != nil {
		log.WithError(err).Error("unable to update record")
	}
	return err
}

// UpdateUser update registration-editable fields
func (db *Db) UpdateUser(user model.YubiUser) error {
	user.UpdatedAt = time.Now()
	err := db.db.Model(&user).Updates(model.YubiUser{
		UpdatedAt:   time.Now(),
		Email:       user.Email,
		IsAdmin:     user.IsAdmin,
		IsEnabled:   user.IsEnabled,
		Description: user.Description,
	}).Error
	if err != nil {
		log.WithError(err).Error("unable to update record")
		return err
	}
	return nil
}

func (db *Db) SetSecretColumnKeyFunc(func() string) {

}

// NewDb creates a new interface to the database identified by `dsn`. Supports the following types to select the proper dialect:
//
//   * sqlite -> "file:/home/user/data.db"
//   * mysql -> "mysql://user@pass/dbname?charset=utf8&parseTime=True&loc=Local"
func NewDb(dsn string) (*Db, error) {
	var err error
	var db *gorm.DB
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "file": // sqlite -> file:/home/user/data.db
		db, err = gorm.Open("sqlite3", dsn[7:])
	case "mysql": // mysql://user@pass/dbname?charset=utf8&parseTime=True&loc=Local
		db, err = gorm.Open("mysql", dsn[8:])
	default: // user@pass/dbname?charset=utf8&parseTime=True&loc=Local
		db, err = gorm.Open("mysql", dsn)
	}
	if err != nil {
		err = fmt.Errorf("%s - %s", err.Error(), dsn)
		return nil, err
	}

	db.AutoMigrate(&model.YubiUser{})

	dbRtn := &Db{
		db: db,
	}
	return dbRtn, nil
}

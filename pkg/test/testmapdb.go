package testing

/*** Shared testing functions and data
 */

import (
	"fmt"
	"time"

	yubidb "github.com/dsggregory/yubiv/pkg/selfhosted/database"
	"github.com/dsggregory/yubiv/pkg/selfhosted/model"
)

// TestToken is a single user with a few OTPs
type TestToken struct {
	// Pub yubikey id and public key
	Pub string
	// Secret yubikey OTP secret key
	Secret string
	// OTPs (without pub leader) generated from pub and Secret with incrementing session counters beginning at 1
	OTPs []string
}

// Token returns a concatonated public key and OTP representing a YubiKey token (as if the user pressed the device)
func (t TestToken) Token(i int) string {
	return t.Pub + t.OTPs[i]
}

// TestTokens These values were generated for testing using https://github.com/Yubico/yubico-c
var TestTokens = []TestToken{
	{"6782a7960cf0", "9a781c53532db8eb0c51ed87188cae98", []string{
		"jhvhgtetkdektuiucfgijuitkjjtdngt",
		"ffhdggktgrknbdiljhrvntvecgjidbcg",
		"ugecurgeghjlhheejifherejlrrkhhcf",
		"vcgreechrrkhfnrrltjnrbvdjjtrujlf",
		"gcnvtdhlrvvektrnhlunlhthitughrlg",
	},
	},
	{"8e76172284d4", "4cf039957d01a7a11ce59b6c10d27d50", []string{
		"iruikbviungfulfgjldibvjecgfgfvdf",
		"reeblctrdjutvnkhhtiunltignncibeb",
		"lvntfdcfkhujgnvrklkvcknfvcgvtnic",
		"chugnnetdbndbrlfuhbcvgujffbuehtk",
		"ucblkhnkktgjncvfdvuijehchgbljbdh",
	},
	},
	{"34af90f2ab88", "57724f2129d41cfe110da556fc680340", []string{
		"erhlblrbrlrbndlgknrurftkkbldbjtd",
		"fktetgbfkivhkvickdihgherejhlhfvn",
		"nutllbukbbdggdcdnherhlikctukcgic",
		"deeblibundeuhrcfkcvenjrhrukdnflf",
		"triugfrjuknvtlrhcrbuggkgugkdbijr",
	},
	},
	{"1de0dc832585", "3513c74392d6c8a384e071d8a1982d6d", []string{
		"gjedegnuicnhtejkkfgfjchtcefjjebv",
		"tejkntgruuttbrfnrvhkkdbbdrvlrktn",
		"ctbvhiuhhddftcjnjneebbjvnjrflull",
		"bhilhcilfthlvkfkuhiihtfrhnjvvggr",
		"jrlthhftjigjvbkrrljulcchrrjtchkh",
	},
	},
	{"4cb46b6cd4d2", "22fc59b26e9f58de45531789cc5318ed", []string{
		"rvtecndjgnrgfudlkvnregvbcufkrrkj",
		"chgegnirtlrdcvglturbnfrefkehefie",
		"hlfgrntggjitdkvrlehgfiunnuhibbir",
		"ddkteufutjbighkbtiebgkifeujbicvt",
		"fvbnckndilfrujviejhjbjjedjjrnvcb",
	},
	},
}

func MapDbFromTestTokens() *yubidb.MapDb {
	db := yubidb.NewMapDb()
	for i, tt := range TestTokens {
		_ = db.Add(model.YubiUser{
			ID:          0,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Email:       fmt.Sprintf("test%d@domain.com", i),
			IsAdmin:     false,
			IsEnabled:   true,
			Counter:     0,
			Session:     0,
			Public:      tt.Pub,
			Secret:      model.ColumnSecret(tt.Secret),
			Description: fmt.Sprintf("rec #%d", i),
		})
	}

	return db
}

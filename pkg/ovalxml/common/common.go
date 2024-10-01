package common

import (
	"context"
	"ct_oval_tool/pkg/ent"
	"ct_oval_tool/pkg/logger"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

const CTyunOSId = "oval:cn.ctyun.ctyunos"
const CTyunOSDefinitionStr = CTyunOSId + ":def:"
const CTyunOSTestStr = CTyunOSId + ":tst:"
const CTyunOSObjectStr = CTyunOSId + ":obj:"
const CTyunOSStateStr = CTyunOSId + ":ste:"
const OvalDef = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
const OvalCommon = "http://oval.mitre.org/XMLSchema/oval-common-5"
const OvalUnixDef = "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
const OvalRedDef = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
const OvalIndDef = "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
const XmlSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance"
const XSISchemaLocation = "http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd" +
	" http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd" +
	" http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd" +
	" http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd"
const CveRef = "https://ctyunos.ctyun.cn/#/support/cveDetail?id="
const SaRef = "https://ctyunos.ctyun.cn/#/support/safetyDetail?id="
const CvelistAPI = "https://ctyunos.ctyun.cn/ctadmin/official/support/security-notice/"
const Host = "ctyunos.ctyun.cn"
const SaSource = "CTyunOS-SA"
const ProductName = "CTyunOS Linux"
const ProductVersion = "v1.0.0"
const SchemaVersion = "5.11"
const OvalVersion = "506"
const CopyRights = "Copyright 2024 CTyunOS Linux, Inc."
const Class = "patch"
const Family = "unix"
const Productlist = "2.0.1 23.01"
const Archlist = "x86_64 aarch64"

var log = logger.GetLogger()
var DBstr = ""
var CNstr = ""

func InitDB() (DBstr string, CNstr string) {
	_, err := os.Stat("/etc/ct-oval/config.yaml")
	if os.IsNotExist(err) {
		pwd, _ := os.Getwd()
		dir := strings.Split(pwd, "ct-oval")
		log.Debug("/etc/ct-oval/config.yaml doesn't exist, trying local config: " + dir[0] + "ct-oval/config.yaml")
		viper.SetConfigFile(dir[0] + "ct-oval/config.yaml")
	} else {
		viper.SetConfigFile("/etc/ct-oval/config.yaml")
	}
	viper.ReadInConfig()
	dbtype := viper.Get("dbtype")
	var connstr string
	if dbtype == "sqlite" {
		connstr = viper.GetString("sqlite.path") + "?_fk=1"
		return "sqlite3", "file:" + connstr
	} else if dbtype == "postgres" {
		connstr = "host=" + viper.GetString("postgres.host") + " port=" + viper.GetString("postgres.port") +
			" user=" + viper.GetString("postgres.user") + " dbname=" + viper.GetString("postgres.dbname") +
			" password=" + viper.GetString("postgres.password")
		return "postgres", connstr
	}
	return "", ""
}
func ConnectDB() (*ent.Client, error) {
	var db *ent.Client
	var err error
	if DBstr == "" && CNstr == "" {
		DBstr, CNstr = InitDB()
		if DBstr == "" || CNstr == "" {
			log.Fatal("failed to initialize database connection")
			return nil, nil
		}
		db, err = ent.Open(DBstr, CNstr)
		if err != nil || db == nil {
			log.Fatal("failed opening connection to ", DBstr, " With EORRR:", err)
			return nil, err
		}
		// Create all tables if they don't exist
		if err = db.Schema.Create(context.Background()); err != nil {
			log.Fatal("failed creating oval table in ", CNstr, " With EORRR:", err)
			return nil, err
		}
	} else {
		db, err = ent.Open(DBstr, CNstr)
		if err != nil || db == nil {
			log.Fatal("failed opening connection to ", DBstr, " With EORRR:", err)
			return nil, err
		}
	}
	return db, nil
}

func RemoveDuplication(arr []string) []string {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
		_, ok := set[v]
		if ok {
			continue
		}
		set[v] = struct{}{}
		arr[j] = v
		j++
	}
	return arr[:j]
}

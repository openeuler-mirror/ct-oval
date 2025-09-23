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

var log = logger.GetLogger()

// Config‑driven variables (formerly consts)
var (
	OSId            string
	OSDefinitionStr string
	OSTestStr       string
	OSObjectStr     string
	OSStateStr      string

	OvalDef           string
	OvalCommon        string
	OvalUnixDef       string
	OvalRedDef        string
	OvalIndDef        string
	XmlSchemaInstance string
	XSISchemaLocation string

	CveRef     string
	SaRef      string
	CvelistAPI string

	Host           string
	SaSource       string
	ProductName    string
	ProductVersion string
	SchemaVersion  string
	OvalVersion    string
	CopyRights     string
	Class          string
	Family         string
	Productlist    string
	Archlist       string
)

var (
	// for DB connection
	DBstr string
	CNstr string
)

func init() {
	// 1) Tell Viper where to find config.yaml
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/ct-oval/")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("common: failed to read config file: %v", err)
	}

	// 2) Focus on the top‑level "common:" section
	sub := viper.Sub("common")
	if sub == nil {
		log.Fatal("common: no 'common' section in config.yaml")
	}

	// 3) Populate vars from config
	OSId = sub.GetString("os_id")
	OSDefinitionStr = OSId + sub.GetString("definition_prefix")
	OSTestStr = OSId + sub.GetString("test_prefix")
	OSObjectStr = OSId + sub.GetString("object_prefix")
	OSStateStr = OSId + sub.GetString("state_prefix")

	OvalDef = sub.GetString("oval.def")
	OvalCommon = sub.GetString("oval.common")
	OvalUnixDef = sub.GetString("oval.unix")
	OvalRedDef = sub.GetString("oval.linux")
	OvalIndDef = sub.GetString("oval.independent")
	XmlSchemaInstance = sub.GetString("oval.xsi")
	XSISchemaLocation = sub.GetString("oval.xsi_schema_location")

	CveRef = sub.GetString("references.cve_base")
	SaRef = sub.GetString("references.sa_base")
	CvelistAPI = sub.GetString("references.cvelist")

	Host = sub.GetString("product.host")
	SaSource = sub.GetString("product.sa_source")
	ProductName = sub.GetString("product.name")
	ProductVersion = sub.GetString("product.version")
	SchemaVersion = sub.GetString("product.schema_version")
	OvalVersion = sub.GetString("product.oval_version")
	CopyRights = sub.GetString("product.copyright")
	Class = sub.GetString("product.class")
	Family = sub.GetString("product.family")
	Productlist = sub.GetString("product.versions")
	Archlist = sub.GetString("product.arch")
}

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

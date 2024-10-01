package common

import (
	"ct_oval_tool/pkg/ent"
	"reflect"
	"testing"

	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestConnectDB(t *testing.T) {
	// Set up test cases
	testCases := []struct {
		name      string
		dbtype    string
		dbname    string
		sqlite    map[string]interface{}
		postgres  map[string]interface{}
		expectErr bool
	}{
		{
			name:      "SQLite",
			dbtype:    "sqlite",
			dbname:    "main",
			sqlite:    map[string]interface{}{"path": "d:/work/ct-oval/sqlite.db"},
			postgres:  map[string]interface{}{},
			expectErr: false,
		},
		{
			name:      "Postgres",
			dbtype:    "postgres",
			sqlite:    map[string]interface{}{},
			postgres:  map[string]interface{}{"host": "172.25.205.63", "port": "5432", "user": "yuedong", "dbname": "ctadmin", "password": "123456"},
			expectErr: false,
		},
	}
	var connstr string
	var err error
	var db *ent.Client
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("dbtype", tc.dbtype)
			if tc.dbtype == "sqlite" {
				for k, v := range tc.sqlite {
					viper.Set("sqlite."+k, v)
				}
				connstr = viper.GetString("sqlite.path") + "?_fk=1"
				db, err = ent.Open("sqlite3", "file:"+connstr)
				if err != nil || db == nil {
					log.Fatal("failed opening connection to sqlite:", connstr, " With EORRR:", err)
				}
			} else if tc.dbtype == "postgres" {
				for k, v := range tc.postgres {
					viper.Set("postgres."+k, v)
				}
				connstr = "host=" + viper.GetString("postgres.host") + " port=" + viper.GetString("postgres.port") +
					" user=" + viper.GetString("postgres.user") + " dbname=" + viper.GetString("postgres.dbname") +
					" password=" + viper.GetString("postgres.password")
				db, err = ent.Open("postgres", connstr)
				if err != nil || db == nil {
					log.Fatal("failed opening connection to postgres:", connstr, " With EORRR:", err)
				}
			}
			// Check the result
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, db)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, db)
			}
			defer db.Close()
		})
	}
}

func TestRemoveDuplication(t *testing.T) {
	tests := []struct {
		name string
		arr  []string
		want []string
	}{
		{
			name: "Test Case 1",
			arr:  []string{"apple", "banana", "apple", "orange"},
			want: []string{"apple", "banana", "orange"},
		},
		{
			name: "Test Case 2",
			arr:  []string{"apple", "banana", "apple", "orange", "banana"},
			want: []string{"apple", "banana", "orange"},
		},
		{
			name: "Test Case 3",
			arr:  []string{"apple", "banana", "apple", "orange", "banana", "apple"},
			want: []string{"apple", "banana", "orange"},
		},
		{
			name: "Test Case 4",
			arr:  []string{},
			want: []string{},
		},
		{
			name: "Test Case 5",
			arr:  []string{"apple"},
			want: []string{"apple"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoveDuplication(tt.arr); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveDuplication() = %v, want %v", got, tt.want)
			}
		})
	}
}

package cmd

import (
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	cmd := New()

	assert.Equal(t, "ct_oval", cmd.Use)
	assert.Equal(t, "CTyunOS OVAL CLI", cmd.Short)
	assert.True(t, cmd.SilenceUsage)

	// expectedFlags := map[string]string{
	// 	"debug":      "Enable debug messages",
	// 	"product":    "generate oval for a single product (eg: ctyunos22.09)",
	// 	"dateFrom":   "include elements revised on or after this day (format: YYYY-MM-DD)",
	// 	"dateTo":     "include elements revised on or before this day (format: YYYY-MM-DD)",
	// 	"type":       "only match CVEs of this type (1-low 2-meduim 3-high 4-critical)",
	// 	"keyword":    "only match CVEs contains this keyword (eg: openssl)",
	// 	"outputFile": "the name of output xml file (eg: oval_ouput.xml)",
	// }

	// for _, flag := range cmd.PersistentFlags() {
	// 	assert.Equal(t, expectedFlags[flag.Name], flag.Usage)
	// }

	assert.NotNil(t, cmd.PersistentPreRun)

	assert.NotNil(t, cmd.Commands())
	assert.Len(t, cmd.Commands(), 5)
	for id, c := range cmd.Commands() {
		log.Debug(id, c.Use, c.Short)
	}
	parseJsonCmd := cmd.Commands()[2]
	assert.Equal(t, "parsejson <json_file> ...", parseJsonCmd.Use)
	assert.Equal(t, "parse security notice from json files", parseJsonCmd.Short)
	assert.NotNil(t, parseJsonCmd.RunE)

	parseJsonDirCmd := cmd.Commands()[1]
	assert.Equal(t, "parsedir <json_dir> ...", parseJsonDirCmd.Use)
	assert.Equal(t, "parse security notice from dirs", parseJsonDirCmd.Short)
	assert.NotNil(t, parseJsonDirCmd.RunE)

	parseRestfulUrl := cmd.Commands()[3]
	assert.Equal(t, "parseurl [--from|--to|--product|--type|--keyword]", parseRestfulUrl.Use)
	assert.Equal(t, "parse security notice from pre-configured ct-admin restful url API", parseRestfulUrl.Short)
	assert.NotNil(t, parseRestfulUrl.RunE)

	generateXml := cmd.Commands()[0]
	assert.Equal(t, "genxml [--from|--to|--product|--output]", generateXml.Use)
	assert.Equal(t, "generate xml file with given options", generateXml.Short)
	assert.NotNil(t, generateXml.RunE)

	version := cmd.Commands()[4]
	assert.Equal(t, "version", version.Use)
	assert.Equal(t, "print the version number", version.Short)
	assert.NotNil(t, version.Run)

	// Test parseJsonCmd.RunE
	err := parseJsonCmd.RunE(nil, []string{"../example/security_notice1.json", "../example/security_notice2.json"})
	assert.Nil(t, err)

	// Test parseJsonDirCmd.RunE
	err = parseJsonDirCmd.RunE(nil, []string{"../example"})
	assert.Nil(t, err)

	// Test parseRestfulUrl.RunE. Use options to avoid too much parsing
	viper.Set("from", "2024-03-01")
	err = parseRestfulUrl.RunE(nil, []string{})
	assert.Nil(t, err)

	// Test generateXml.RunE
	err = generateXml.RunE(nil, []string{})
	assert.Nil(t, err)

	// Test version.Run
	viper.Set("version", "1.0.0")
	version.Run(nil, []string{})
	expectedVersion := fmt.Sprintf("ct_oval version: %s", viper.GetString("version"))
	assert.Equal(t, expectedVersion, "ct_oval version: 1.0.0")
}

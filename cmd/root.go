package cmd

import (
	"ct_oval_tool/cmd/flag"
	"ct_oval_tool/pkg/logger"
	"ct_oval_tool/pkg/ovalxml"
	"ct_oval_tool/pkg/ovalxml/common"
	"ct_oval_tool/pkg/securitynotice"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var log = logger.GetLogger()

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "ct_oval",
		Short:        "CTyunOS OVAL CLI",
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if viper.GetBool(flag.KeyDebug) {
				logger.DefaultLogger.SetLevel(logrus.DebugLevel)
			}
		},
	}

	flags := cmd.PersistentFlags()
	flags.BoolP(flag.KeyDebug, "d", false, "Enable debug messages")
	flags.String(flag.KeyProduct, "ctyunos-2.0.1", "generate oval for a single product (eg: ctyunos-2.0.1 ctyunos-23.01)")
	flags.String(flag.KeyDateFrom, "1990-01-01", "include elements revised on or after this day (format: YYYY-MM-DD)")
	flags.String(flag.KeyDateTo, "", "include elements revised on or before this day (format: YYYY-MM-DD)")
	viper.BindPFlags(flags)

	parseJsonCmd := &cobra.Command{
		Use:   "parsejson <json_file> ...",
		Short: "parse security notice from json files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for i, arg := range args {
				log.Debugf("Parsing json[%d]: %s\n", i, arg)
				//Parse json and save into DB
				var err = securitynotice.ParseSecNoticeFromJson(arg)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}

	parseJsonDirCmd := &cobra.Command{
		Use:   "parsedir <json_dir> ...",
		Short: "parse security notice from dirs",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for i, arg := range args {
				log.Debugf("Parsing json_dir[%d]: %s", i, arg)
				//Parse json files for dir and save into DB
				var err = securitynotice.ParseSecNoticesFormJsonDir(arg)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}

	parseRestfulUrl := &cobra.Command{
		Use:   "parseurl [--from|--to|--product|--type|--keyword]",
		Short: "parse security notice from pre-configured ct-admin restful url API",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Debug("Parsing from API: ", common.CvelistAPI)
			return securitynotice.ParseRestfulUrl()
		},
	}
	options := parseRestfulUrl.Flags()
	options.Int(flag.KeyType, 0, "only match CVEs of this type (1-low 2-meduim 3-high 4-critical)")
	options.String(flag.KeyKeyword, "", "only match CVEs contains this keyword (eg: openssl)")
	viper.BindPFlags(options)

	generateXml := &cobra.Command{
		Use:   "genxml [--from|--to|--product|--output]",
		Short: "generate xml file with given options",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ovalxml.GeneratedOvalXml()
		},
	}
	options = generateXml.Flags()
	options.String(flag.KeyOutputFile, "CTyunos-oval.xml", "the name of output xml file")
	viper.BindPFlags(options)

	version := &cobra.Command{
		Use:   "version",
		Short: "print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("ct_oval version:", common.ProductVersion)
		},
	}

	cmd.AddCommand(parseJsonCmd)
	cmd.AddCommand(parseJsonDirCmd)
	cmd.AddCommand(parseRestfulUrl)
	cmd.AddCommand(generateXml)
	cmd.AddCommand(version)
	return cmd
}

func Execute() {
	if err := New().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

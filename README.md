# Summary
This tool is used to parse data from json file/restful api/socket, and save into DB (sqlite/postgres/mysql).<br>
Then generate xml file according to DB, with filter options.<br>
The output xml file can be used as openscap source file. Check systems whether have vulnerabilities.<br>

# Contributors
Leon Wang <wangl29@chinatelecom.cn><br>
Yong Qin <qiny15@chinatelecom.cn><br>
Copyright 2024 Chinatelecom CTyun Ltd.<br>

# Base commands & Global flags
CTyunOS OVAL CLI<br>
Usage:<br>
  ct-oval [flags]<br>
  ct-oval [command]<br>

Available Commands:<br>
  completion  Generate the autocompletion script for the specified shell<br>
  genxml      generate xml file with given options<br>
  help        Help about any command<br>
  parsedir    parse security notice from dirs<br>
  parsejson   parse security notice from json files<br>
  parseurl    parse security notice from Restful URL API<br>
  version     print the version number<br>

Global Flags:<br>
  -d, --debug            Enable debug messages<br>
      --from string      include elements revised on or after this day (format: YYYY-MM-DD) (default "1990-01-01")<br>
  -h, --help             help for ct_oval<br>
      --product string   generate oval for a single product (eg: ctyunos-2.0.1 ctyunos-23.01 all. "all" only works for parseurl) (default "ctyunos-2.0.1")<br>
      --to string        include elements revised on or before this day (format: YYYY-MM-DD)<br>

# ct-oval parse
parse security notice from json files<br>
Usage:<br>
  ct-oval parse <json_file> ... [flags]<br>

# ct-oval parsedir
parse security notice from dirs<br>
Usage:<br>
  ct-oval parsedir <json_dir> ... [flags]<br>

# ct-oval parseurl
parse security notice from pre-configured ct-admin restful url API<br>
Usage:<br>
  ct-oval parseurl [--from|--to|--product|--type|--keyword] [flags]<br>

subcommand options description:<br>
  --keyword string   only match CVEs contains this keyword (eg: openssl)<br>
  --type int         only match CVEs of this type (1-low 2-meduim 3-high 4-critical)<br>

# ct-oval genxml
generate xml file with given options<br>
Usage:<br>
  ct-oval genxml [--from|--to|--product|--output] [flags]<br>

subcommand options description:<br>
  --output string    the name of output xml file (default "CTyunos-oval.xml")<br>

# ct-oval completion
Generate the autocompletion script for ct-oval for the specified shell.<br>
Usage:<br>
  ct-oval completion [command]<br>

Available Commands:
  bash        Generate the autocompletion script for bash<br>
  fish        Generate the autocompletion script for fish<br>
  powershell  Generate the autocompletion script for powershell<br>
  zsh         Generate the autocompletion script for zsh<br>

# Const config
Notice: API URL, productlist and archlist currently are hard coded in common.go.
You can change them and recompile the project if needed. These configs are:<br>
  - CTyunOSId = "oval:cn.ctyun.ctyunos"
  - CTyunOSDefinitionStr = CTyunOSId + ":def:"
  - CTyunOSTestStr = CTyunOSId + ":tst:"
  - CTyunOSObjectStr = CTyunOSId + ":obj:"
  - CTyunOSStateStr = CTyunOSId + ":ste:"
  - OvalDef = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
  - OvalCommon = "http://oval.mitre.org/XMLSchema/oval-common-5"
  - OvalUnixDef = "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
  - OvalRedDef = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
  - OvalIndDef = "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
  - XmlSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance"
  - XSISchemaLocation = "http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd" +
	" http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd" +
	" http://oval.mitre.org/XMLSchema/oval-definitions-5#unix unix-definitions-schema.xsd" +
	" http://oval.mitre.org/XMLSchema/oval-definitions-5#linux linux-definitions-schema.xsd"
  - CveRef = "https://ctyunos.ctyun.cn/#/support/cveDetail?id="
  - SaRef = "https://ctyunos.ctyun.cn/#/support/safetyDetail?id="
  - CvelistAPI = "https://ctyunos.ctyun.cn/ctadmin/official/support/security-notice/"
  - Host = "ctyunos.ctyun.cn"
  - SaSource = "CTyunOS-SA"
  - ProductName = "CTyunOS Linux"
  - ProductVersion = "v1.0.0"
  - SchemaVersion = "5.11"
  - OvalVersion = "506"
  - CopyRights = "Copyright 2024 CTyunOS Linux, Inc."
  - Class = "patch"
  - Family = "unix"
  - Productlist = "2.0.1 23.01"
  - Archlist = "x86_64 aarch64"

# Unit tests
To make sure tests passed, you need to delete sqlite.db before running unit tests in source directory
 $ go test ./...<br>
?       ct-oval_tool    [no test files]<br>
?       ct-oval_tool/cmd/flag   [no test files]<br>
?       ct-oval_tool/pkg/ent    [no test files]<br>
?       ct-oval_tool/pkg/ent/cveref     [no test files]<br>
?       ct-oval_tool/pkg/ent/enttest    [no test files]<br>
?       ct-oval_tool/pkg/ent/hook       [no test files]<br>
?       ct-oval_tool/pkg/ent/state      [no test files]<br>
?       ct-oval_tool/pkg/ent/test       [no test files]<br>
?       ct-oval_tool/pkg/ent/oval       [no test files]<br>
?       ct-oval_tool/pkg/ent/predicate  [no test files]<br>
?       ct-oval_tool/pkg/ent/runtime    [no test files]<br>
?       ct-oval_tool/pkg/ent/schema     [no test files]<br>
?       ct-oval_tool/pkg/ent/migrate    [no test files]<br>
?       ct-oval_tool/pkg/ent/object     [no test files]<br>
ok      ct-oval_tool/cmd        0.780s<br>
ok      ct-oval_tool/pkg/logger (cached)<br>
?       ct-oval_tool/pkg/ovalxml/ovaldefinitions        [no test files]<br>
ok      ct-oval_tool/pkg/ovalxml        0.143s<br>
ok      ct-oval_tool/pkg/ovalxml/common (cached)<br>
ok      ct-oval_tool/pkg/ovalxml/defintions     (cached)<br>
ok      ct-oval_tool/pkg/ovalxml/generator      (cached)<br>
ok      ct-oval_tool/pkg/ovalxml/objects        (cached)<br>
ok      ct-oval_tool/pkg/ovalxml/states (cached)<br>
ok      ct-oval_tool/pkg/ovalxml/tests  (cached)<br>
ok      ct-oval_tool/pkg/securitynotice 0.958s<br>

PS. Some dirs don't have functions, so they don't have test. It is not a problem.

# Test example
$ go run main.go genxml --from 2024-01-23<br>
INFO[2024-04-17T20:53:29+08:00] OVAL CTyunos-oval.xml generated successfully.<br>

go run main.go parseurl --from 2024-01-23 --type 2<br>
INFO[2024-04-17T20:55:06+08:00] 4 CVEs are prceeded successfully.<br>

$ go run main.go parseurl --from 2023-01-23 --to 2024-01-23 --type 2 --keyword=mysql<br>
INFO[2024-04-17T20:55:35+08:00] 2 CVEs are prceeded successfully.<br>

$ go run main.go parsedir example
INFO[2024-04-17T20:56:33+08:00] oval:cn.ctyun.ctyunos:def:20210207 file is prceeded<br>
INFO[2024-04-17T20:56:33+08:00] oval:cn.ctyun.ctyunos:def:20210208 file is prceeded<br>

$ go run main.go parsejson example/security_notice1.json<br>
INFO[2024-04-17T20:57:10+08:00] oval:cn.ctyun.ctyunos:def:20210207 file is prceeded<br>

# Integration tests
- Test with openscap (check xml format, check if any package not updated)
`oscap oval eval --report vulnerability.html CTyunOS-oval.xml`
Passed

# Future plan
Integration with ct-admin: parse from grpc API, use postgres DB, publish xml files into web

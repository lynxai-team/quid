package main

import (
	"flag"
	"net/url"

	"github.com/TealsFi/quid/crypt"
	"github.com/TealsFi/quid/server/api"
	"github.com/TealsFi/quid/server/db"

	"github.com/lynxai-team/emo"
	"github.com/lynxai-team/garcon/gg"
)

var log = emo.NewZone("quid")

const (
	// defaultKey is AES-128-bits (16 bytes) in hexadecimal form (32 digits).
	// Attention: Heroku generates secrets with 64 hexadecimal digits.
	defaultKey      = "00112233445566778899aabbccddeeff"
	defaultDBUser   = "pguser"
	defaultDBPass   = "myDBpwd"
	defaultDBHost   = "localhost"
	defaultDBPort   = "5432"
	defaultDBName   = "quid"            // Web login: namespace
	defaultAdminUsr = "admin"           // Web login: username
	defaultAdminPwd = "myAdminPassword" // Web login: password
	defaultOrigins  = "http://localhost:"
)

var defaultDBurl = buildURL(defaultDBUser, defaultDBPass, defaultDBHost, defaultDBPort, defaultDBName)

func buildURL(usr, pwd, host, port, name string) string {
	return "postgres://" + usr + ":" + pwd + "@" + host + ":" + port + "/" + name + "?sslmode=disable"
}

func main() {
	var (
		dev     = flag.Bool("dev", false, "Development mode")
		verbose = flag.Bool("v", false, "Verbose (enables the info and debug logs)")
		key     = flag.String("key", gg.EnvStr("QUID_KEY", defaultKey), "AES-128 key to encrypt the private keys of the refresh/access tokens in the database. Accept 32 hexadecimal digits or 22 Base64 characters. Env. var: QUID_KEY")
		admin   = flag.String("admin", gg.EnvStr("QUID_ADMIN_USR", defaultAdminUsr), "The username of the Quid Administrator. Env. var: QUID_ADMIN_USR")
		pwd     = flag.String("pwd", gg.EnvStr("QUID_ADMIN_PWD", defaultAdminPwd), "The password of the Quid Administrator. Env. var: QUID_ADMIN_PWD")
		conf    = flag.Bool("conf", false, `Generate a "config.json" file with a random AES-128 key`)
		drop    = flag.Bool("drop", false, "Reset the DB: drop tables and indexes")
		dbUser  = flag.String("db-user", gg.EnvStr("POSTGRES_USER", defaultDBUser), "Username to read/write the database. Env. var: POSTGRES_USER")
		dbPass  = flag.String("db-pass", gg.EnvStr("POSTGRES_PASSWORD", defaultDBPass), "Password of the database user. Env. var: POSTGRES_PASSWORD")
		dbName  = flag.String("db-name", gg.EnvStr("POSTGRES_DB", defaultDBName), "Name of the Postgres database. Env. var: POSTGRES_DB")
		dbHost  = flag.String("db-host", gg.EnvStr("DB_HOST", defaultDBHost), "Network location of the Postgres server. Env. var: DB_HOST")
		dbPort  = flag.String("db-port", gg.EnvStr("DB_PORT", defaultDBPort), "TCP port of the Postgres server. Env. var: DB_PORT")
		dbURL   = flag.String("db-url", gg.EnvStr("DB_URL", defaultDBurl), "The endpoint of the PostgreSQL server. Env. var: DB_URL")
		origins = flag.String("origins", gg.EnvStr("ALLOWED_ORIGINS", defaultOrigins), "Allowed origins (CORS) separated by comas")
		www     = flag.String("www", gg.EnvStr("WWW_DIR", "ui/dist"), "Folder of the web static files. Env. var: WWW_DIR")
		port    = flag.Int("port", gg.EnvInt("PORT", 8090), "Listening port of the Quid server")
	)
	flag.Parse()

	cfgName, cfgUsr, cfgPwd, cfgKey := readConfigFile()
	if cfgName != "" && *dbName == defaultDBName {
		*dbName = cfgName
	}
	if cfgUsr != "" && *dbUser == defaultDBUser {
		*dbUser = cfgUsr
	}
	if cfgPwd != "" && *dbPass == defaultDBPass {
		*dbPass = cfgPwd
	}
	if cfgKey != "" && *key == defaultKey {
		*key = cfgKey
	}

	if *dbURL == "" || *dbURL == defaultDBurl {
		*dbURL = buildURL(*dbUser, *dbPass, *dbHost, *dbPort, *dbName)
	}

	if (!*dev) && (*key == defaultKey) && (*dbURL == defaultDBurl) && (*origins == defaultOrigins) {
		if !*verbose {
			log.Print("Enable -v verbose mode because default values for -dev, -key QUID_KEY, -db DB_URL and -origins ALLOWED_ORIGINS")
			*verbose = true
		}
		log.Print("Enable -dev mode because default values for -key QUID_KEY, -db DB_URL and -origins ALLOWED_ORIGINS")
		*dev = true
	}
	emo.GlobalVerbosity(*verbose)

	if !*dev && *pwd == defaultAdminPwd {
		log.Print("Flag -dev disabled => Do not use default admin password -pwd QUID_ADMIN_PWD:", defaultAdminPwd)
		*pwd = ""
	}

	obfuscatedPwdURL := *dbURL
	u, err := url.Parse(*dbURL)
	if err == nil {
		*dbURL = u.String()
		obfuscatedPwdURL = u.Redacted()
	}

	log.V().Param("-dev                        =", *dev)
	log.V().Param("-v                          =", *verbose)
	log.V().Param("-conf                       =", *conf)
	log.V().Param("-drop                       =", *drop)
	log.V().Param("-key     QUID_KEY           =", len(*key), "bytes")
	log.V().Param("-admin   QUID_ADMIN_USR     =", *admin)
	if *pwd == defaultAdminPwd {
		log.Warning("-pwd     QUID_ADMIN_PWD     =", *pwd, " UNSECURED DEFAULT PASSWORD")
	} else {
		log.V().Param("-pwd     QUID_ADMIN_PWD     =", len(*pwd), "bytes")
	}
	log.V().Param("-db-user POSTGRES_USER      =", *dbUser)
	if *dbPass == defaultDBPass {
		log.Warning("-db-pass POSTGRES_PASSWORD  =", *dbPass, "         UNSECURED DEFAULT PASSWORD")
	} else {
		log.V().Param("-db-pass POSTGRES_PASSWORD  =", len(*dbPass), "bytes")
	}
	log.V().Param("-db-name POSTGRES_DB        =", *dbName)
	log.V().Param("-db-host DB_HOST            =", *dbHost)
	log.V().Param("-db-port DB_PORT            =", *dbPort)
	log.V().Param("-db-url  DB_URL             =", obfuscatedPwdURL)
	log.V().Param("-origins ALLOWED_ORIGINS    =", *origins)
	log.V().Param("-www     WWW_DIR            =", *www)
	log.V().Param("-port    PORT               =", *port)

	if !*dev && *dbPass == defaultDBPass {
		log.Error("Running in prod mode (flag -dev disabled), but default DB password:", defaultDBPass)
		log.Error("Use flag -db-pass or env. var. POSTGRES_PASSWORD to use a different password")
	}

	if *conf {
		log.Info(`Generating "config.json" file with random AES-128 key`)
		if err := createConfigFile(*dbName, *dbUser, *dbPass); err != nil {
			log.Fatal(`Cannot create "config.json" file`, err)
		}
		log.State(`Config file created: edit "config.json" to provide your database settings`)
		return
	}

	// fix for Heroku-generated secret always composed of 64 hexadecimal digits
	if len(*key) == 64 {
		*key = (*key)[:32]
	}

	crypt.EncodingKey, err = gg.DecodeHexOrB64(*key, 16)
	if err != nil {
		log.Error(err)
		log.Fatal("Want AES-128 key in hexadecimal (32 digits) or Base64 (unpadded 22 characters, RFC 4648 §5), but got", len(*key), "bytes:", *key)
	}

	if err := db.Connect(*dbURL); err != nil {
		log.Error(err)
		log.Fatal("Cannot connect to", obfuscatedPwdURL, "(obfuscated password)")
	}

	if *drop {
		if err := db.DropTablesIndexes(); err != nil {
			log.Warn("Try to drop the whole database because:", err)
			if err := db.DropDatabase(*dbName); err != nil {
				log.Warn("Continue even if:", err)
			}
		}
	}

	if err := db.CreateTablesIndexesIfMissing(); err != nil {
		log.Fatal(err)
	}

	if err := db.CreateQuidAdminIfMissing(*admin, *pwd); err != nil {
		log.Fatal(err)
	}

	api.RunServer(*port, *dev, *origins, *www)
}

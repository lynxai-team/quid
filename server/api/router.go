package api

import (
	"net/http"

	color "github.com/acmacalister/skittles"
	"github.com/go-chi/chi/v5"

	"github.com/TealsFi/quid/crypt"

	"github.com/lynxai-team/emo"
	"github.com/lynxai-team/garcon/gc"
	"github.com/lynxai-team/garcon/gg"
	"github.com/lynxai-team/garcon/vv"
	"github.com/lynxai-team/incorruptible"
)

var log = emo.NewZone("api")

var incorr *incorruptible.Incorruptible

var gw gg.Writer

// RunServer : configure and run the server.
func RunServer(port int, devMode bool, allowedOrigins, wwwDir string) {
	server := newServer(port, devMode, allowedOrigins, wwwDir)

	if devMode {
		log.Print(color.BoldRed("Running in development mode"))
	}

	log.Print("Server listening on " + color.UnderlineBlue("http://localhost"+server.Addr))
	log.Fatal(gc.ListenAndServe(&server))
}

func newServer(port int, devMode bool, allowedOrigins, wwwDir string) http.Server {
	g := gc.New(
		gc.WithURLs(gg.SplitClean(allowedOrigins)...),
		gc.WithServerName("Quid"),
		gc.WithDev(devMode))

	gw = g.Writer

	maxAge := 3600 * 3 // three hours
	if devMode {
		maxAge = 3600 * 24 * 365 // one year
	}
	incorr = g.IncorruptibleCheckerBin(crypt.EncodingKey[:16], maxAge, false)

	middleware := gg.NewChain(
		g.MiddlewareRejectUnprintableURI(),
		g.MiddlewareLogRequest(),  // log incoming requests
		g.MiddlewareLogDuration(), // log output responses (with their processing durations)
		g.MiddlewareRateLimiter(10, 30),
		g.MiddlewareCORSWithMethodsHeaders(
			[]string{http.MethodGet, http.MethodOptions, http.MethodPost, http.MethodDelete},
			[]string{"Origin", "Content-Type", "Authorization"},
		))

	router := newRouter(g, wwwDir)
	handler := middleware.Then(router)

	return gc.Server(handler, port, nil)
}

func newRouter(g *gc.Garcon, wwwDir string) http.Handler {
	r := chi.NewRouter()

	// Static website: set the Incorruptible cookie only when visiting index.html
	ws := g.NewStaticWebServer(wwwDir)
	r.NotFound(ws.ServeFile("index.html", "text/html; charset=utf-8"))
	r.Get("/favicon.ico", ws.ServeFile("favicon.ico", "image/x-icon"))
	r.Get("/js/*", ws.ServeDir("text/javascript; charset=utf-8"))
	r.Get("/assets/*", ws.ServeAssets())
	r.Get("/img/*", ws.ServeImages())

	// public routes: not protected by login cookie
	r.Post("/token/refresh/{timeout}", requestRefreshToken)
	r.Post("/token/access/{timeout}", requestAccessToken)
	r.Post("/token/refresh-access/{timeout}", requestRefreshAndAccessTokens)
	r.Post("/token/public", getAccessPublicKey)
	r.Post("/admin_login", adminLogin)
	r.Get("/logout", adminLogout)
	r.Get("/status", status)

	// Quid admin routes
	r.Route("/admin", func(r chi.Router) {
		r.Use(quidAdminMiddleware)

		// HTTP API
		r.Route("/groups", func(r chi.Router) {
			r.Post("/add", createGroup)
			r.Post("/delete", deleteGroup)
			r.Post("/info", groupsInfo)
			r.Post("/add_user", addUserInGroup)
			r.Post("/remove_user", removeUserFromGroup)
			r.Post("/nsall", allNsGroups)
		})

		// only admin can see the Git version & commit date.
		r.Get("/version", vv.ServeVersion())

		r.Route("/users", func(r chi.Router) {
			r.Post("/add", createUser)
			r.Post("/delete", deleteUser)
			r.Post("/groups", userGroupsInfo)
			r.Post("/orgs", userOrgsInfo)
			r.Post("/nsall", listUsersInNs)
		})

		r.Route("/namespaces", func(r chi.Router) {
			r.Post("/add", createNamespace)
			r.Post("/delete", deleteNamespace)
			r.Post("/find", findNamespace)
			r.Post("/info", namespaceInfo)
			r.Post("/key", getAccessVerificationKey)
			r.Post("/max-ttl", setTokenMaxTTL)
			r.Post("/max-refresh-ttl", setRefreshMaxTTL)
			r.Post("/groups", nsGroups)
			r.Post("/endpoint", enableNsEndpoint)
			r.Get("/all", allNamespaces)
		})

		r.Route("/orgs", func(r chi.Router) {
			r.Get("/all", allOrgs)
			r.Post("/add", createOrg)
			r.Post("/delete", deleteOrg)
			r.Post("/find", findOrg)
			r.Post("/add_user", addUserInOrg)
			r.Post("/remove_user", removeUserFromOrg)
		})

		r.Route("/nsadmin", func(r chi.Router) {
			r.Post("/add", createAdministrators)
			r.Post("/delete", deleteAdministrator)
			r.Post("/nsall", listAdministrators)
			r.Post("/nonadmins", listNonAdministrators)
		})
	})

	// Namespace admin endpoints
	r.Route("/ns", func(r chi.Router) {
		r.Use(nsAdminMiddleware)

		r.Post("/valid", validAccessToken)

		// nsadmin users
		r.Route("/users", func(r chi.Router) {
			r.Post("/add", createUser)
			r.Post("/delete", deleteUser)
			r.Post("/groups", userGroupsInfo)
			r.Post("/nsall", listUsersInNs)
		})

		// nsadmin groups
		r.Route("/groups", func(r chi.Router) {
			r.Post("/add", createGroup)
			r.Post("/delete", deleteGroup)
			r.Post("/info", groupsInfo)
			r.Post("/add_user", addUserInGroup)
			r.Post("/remove_user", removeUserFromGroup)
			r.Post("/nsall", allNsGroups)
		})
	})

	return r
}

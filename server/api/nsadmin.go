package api

import (
	"net/http"

	_ "github.com/lib/pq"

	"github.com/TealsFi/quid/server"
	"github.com/TealsFi/quid/server/db"

	"github.com/lynxai-team/garcon/gg"
)

// listAdministrators : select all admin users for a namespace.
func listAdministrators(w http.ResponseWriter, r *http.Request) {
	var m server.NamespaceIDRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("listAdministrators:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	data, err := db.SelectAdministrators(m.NsID)
	if err != nil {
		log.QueryError("listAdministrators: error SELECT admin users:", err)
		gw.WriteErr(w, r, http.StatusInternalServerError, "error SELECT admin users")
		return
	}

	gw.WriteOK(w, data) // respond administrator.username
}

// listNonAdministrators : search from a username in namespace
func listNonAdministrators(w http.ResponseWriter, r *http.Request) {
	var m server.NonAdminUsersRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("listNonAdministrators:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if p := gg.Printable(m.Pattern); p >= 0 {
		log.Warn("listNonAdministrators: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	users, err := db.SelectNonAdministrators(m.NsID, m.Pattern)
	if err != nil {
		log.QueryError("listNonAdministrators: error searching for non admin users:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error searching for non admin users", "error", err, "ns_id", m.NsID, "pattern", m.Pattern)
		return
	}

	if len(users) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		w.Write([]byte(`{"users":[]}`)) // frontend prefers `[]` rather than `null`
	}

	gw.WriteOK(w, "users", users) // respond non_admin.username
}

// CreateUserAdministrators : create admin users handler.
func createAdministrators(w http.ResponseWriter, r *http.Request) {
	var m server.AdministratorsCreation
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("CreateAdministrators:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON", "err", err)
		return
	}

	for _, uID := range m.UsrIDs {
		// check if user is admin
		yes, err := db.IsUserAnAdmin(m.NsID, uID)
		if err != nil {
			log.QueryError("CreateAdministrators: error checking admin user:", err)
			gw.WriteErr(w, r, http.StatusConflict, "error checking admin user")
			return
		}
		if yes {
			log.Query("CreateAdministrators: user is already an administrator:", err)
			continue
		}

		// create admin user
		if err = db.CreateAdministrator(m.NsID, uID); err != nil {
			log.QueryError("CreateAdministrators: error creating admin user:", err)
			gw.WriteErr(w, r, http.StatusConflict, "error creating admin user")
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// deleteAdministrator : delete an admin user handler.
func deleteAdministrator(w http.ResponseWriter, r *http.Request) {
	var m server.AdministratorDeletion
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.ParamError("DeleteAdministrator:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	err := db.DeleteAdministrator(m.UsrID, m.NsID)
	if err != nil {
		log.QueryError("DeleteAdministrator: error deleting admin users:", err)
		gw.WriteErr(w, r, http.StatusInternalServerError, "error deleting admin users")
		return
	}

	w.WriteHeader(http.StatusOK)
}

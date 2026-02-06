package api

import (
	"net/http"

	"github.com/TealsFi/quid/server"
	"github.com/TealsFi/quid/server/db"

	"github.com/lynxai-team/garcon/gg"
)

// allOrgs : get all orgs http handler.
func allOrgs(w http.ResponseWriter, r *http.Request) {
	data, err := db.SelectAllOrgs()
	if err != nil {
		log.QueryError("AllOrgs: error SELECT orgs:", err)
		gw.WriteErr(w, r, http.StatusConflict, "error SELECT orgs")
		return
	}
	gw.WriteOK(w, data)
}

// findOrg : find an org from name.
func findOrg(w http.ResponseWriter, r *http.Request) {
	var m server.NameRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.ParamError("FindOrg:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if p := gg.Printable(m.Name); p >= 0 {
		log.Warn("FindOrg: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	data, err := db.SelectOrgStartsWith(m.Name)
	if err != nil {
		log.QueryError("FindOrg:", err)
		gw.WriteErr(w, r, http.StatusInternalServerError, "error finding org")
		return
	}

	gw.WriteOK(w, data)
}

// userOrgsInfo : get orgs info for a user.
func userOrgsInfo(w http.ResponseWriter, r *http.Request) {
	var m server.InfoRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.ParamError("UserOrgsInfo:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	o, err := db.SelectOrgsForUser(m.ID)
	if err != nil {
		log.QueryError("UserOrgsInfo: error SELECT orgs:", err)
		gw.WriteErr(w, r, http.StatusInternalServerError, "error SELECT orgs")
		return
	}

	if len(o) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		w.Write([]byte(`{"orgs":[]}`)) // frontend prefers `[]` rather than `null`
	}

	gw.WriteOK(w, "orgs", o)
}

// deleteOrg : org deletion http handler.
func deleteOrg(w http.ResponseWriter, r *http.Request) {
	var m server.InfoRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.ParamError("DeleteOrg:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if err := db.DeleteOrg(m.ID); err != nil {
		log.QueryError("DeleteOrg:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error deleting org")
		return
	}

	gw.WriteOK(w, "message", "ok")
}

// createOrg : org creation http handler.
func createOrg(w http.ResponseWriter, r *http.Request) {
	var m server.NameRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.ParamError("CreateOrg:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if m.Name == "" {
		log.ParamError("CreateOrg: Empty organization name")
		gw.WriteErr(w, r, http.StatusUnauthorized, "Empty organization name")
		return
	}

	if p := gg.Printable(m.Name); p >= 0 {
		log.ParamError("CreateOrg: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	exists, err := db.OrgExists(m.Name)
	if err != nil {
		log.QueryError("createOrg OrgExists:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error checking org", "org", m.Name)
		return
	}
	if exists {
		log.QueryError("createOrg: already exist:", m.Name)
		gw.WriteErr(w, r, http.StatusUnauthorized, "org already exists", "org", m.Name)
		return
	}

	gid, err := db.CreateOrg(m.Name)
	if err != nil {
		log.QueryError("createOrg:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error creating org", "org", m.Name)
		return
	}

	gw.WriteOK(w, "org_id", gid)
}

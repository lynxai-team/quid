package api

import (
	"net/http"

	"github.com/lynxai-team/garcon/gg"
	"github.com/lynxai-team/quid/server"
	"github.com/lynxai-team/quid/server/db"
)

// allNsGroups : get all groups for a namespace http handler.
func allNsGroups(w http.ResponseWriter, r *http.Request) {
	var m server.NamespaceIDRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("AllGroupsForNamespace:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if !isNsAdmin(r, m.NsID) {
		gw.WriteErr(w, r, http.StatusUnauthorized, "user is not admin for requested namespace", "ns_id", m.NsID)
		return
	}

	data, err := db.SelectNsGroups(m.NsID)
	if err != nil {
		log.QueryError("AllGroupsForNamespace: error SELECT groups:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error SELECT groups")
		return
	}

	gw.WriteOK(w, data)
}

// allGroups : get all groups for a namespace http handler.
// Deprecated because this function is not used.
func allGroups(w http.ResponseWriter, r *http.Request) {
	data, err := db.SelectAllGroups()
	if err != nil {
		log.QueryError("AllGroups: error SELECT groups:", err)
		gw.WriteErr(w, r, http.StatusConflict, "error SELECT groups")
		return
	}
	gw.WriteOK(w, data)
}

// groupsInfo : group creation http handler.
func groupsInfo(w http.ResponseWriter, r *http.Request) {
	var m server.UserRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("GroupsInfo:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if !isNsAdmin(r, m.NsID) {
		gw.WriteErr(w, r, http.StatusUnauthorized, "user is not admin for requested namespace", "ns_id", m.NsID)
		return
	}

	n, err := db.CountUsersInGroup(m.ID)
	if err != nil {
		log.QueryError("GroupsInfo: error counting in group:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error counting in group")
		return
	}

	gw.WriteOK(w, "num_users", n)
}

// deleteGroup : group deletion http handler.
func deleteGroup(w http.ResponseWriter, r *http.Request) {
	var m server.UserRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("DeleteGroup:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if !isNsAdmin(r, m.NsID) {
		gw.WriteErr(w, r, http.StatusUnauthorized, "user is not admin for requested namespace", "ns_id", m.NsID)
		return
	}

	if err := db.DeleteGroup(m.ID); err != nil {
		log.QueryError("DeleteGroup: error deleting group:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error deleting group")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// createGroup : group creation http handler.
func createGroup(w http.ResponseWriter, r *http.Request) {
	var m server.GroupCreation
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("CreateGroup:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if m.Name == "" {
		log.ParamError("CreateGroup: Empty group name")
		gw.WriteErr(w, r, http.StatusUnauthorized, "Empty group name")
		return
	}

	if p := gg.Printable(m.Name); p >= 0 {
		log.Warn("CreateGroup: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	if !isNsAdmin(r, m.NsID) {
		gw.WriteErr(w, r, http.StatusUnauthorized, "user is not admin for requested namespace", "ns_id", m.NsID)
		return
	}

	exists, err := db.GroupExists(m.Name, m.NsID)
	if err != nil {
		log.QueryError("createGroup GroupExists:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "DB error while checking group", "group", m.Name, "ns_id", m.NsID)
		return
	}
	if exists {
		log.ParamError("createGroup: group '" + m.Name + "' already exists")
		gw.WriteErr(w, r, http.StatusUnauthorized, "group already exists", "group", m.Name, "ns_id", m.NsID)
		return
	}

	gid, err := db.CreateGroup(m.Name, m.NsID)
	if err != nil {
		log.QueryError("createGroup CreateGroup:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "DB error while creating group", "group", m.Name, "ns_id", m.NsID)
		return
	}

	gw.WriteOK(w, "grp_id", gid)
}

package api

import (
	"net/http"

	"github.com/lynxai-team/garcon/gg"
	"github.com/lynxai-team/incorruptible"
	"github.com/lynxai-team/quid/server"
	"github.com/lynxai-team/quid/server/db"
)

// Key IDs for the Incorruptible TValues
const (
	keyUsername = iota
	KeyUsrID
	keyNsName
	keyNsID
	keyAdminType
)

// adminLogout : http logout handler for the admin interface.
func adminLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, incorr.DeadCookie())
}

// adminLogin : http login handler for the admin interface.
func adminLogin(w http.ResponseWriter, r *http.Request) {
	var m server.PasswordRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.ParamError("AdminLogin DecodeJSONBody:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if p := gg.Printable(m.Username, m.Namespace); p >= 0 {
		log.ParamError("AdminLogin: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	// get the namespace
	ns, err := db.SelectNsFromName(m.Namespace)
	if err != nil {
		log.QueryError("AdminLogin SelectNsFromName:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot SELECT namespace", "namespace", m.Namespace, "error", err)
		return
	}

	// check the user password
	u, err := checkUserPassword(m.Username, m.Password, ns.ID)
	if err != nil {
		log.Error("AdminLogin checkUserPassword:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "inexistent/disabled user or invalid password", "usr", m.Username, "namespace", m.Namespace)
		return
	}

	userType, err := db.GetUserType(ns.Name, ns.ID, u.ID)
	if err != nil {
		log.QueryError("AdminLogin AdminType:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "DB error when getting user type", "usr", m.Username, "namespace", m.Namespace)
		return
	}
	if userType == db.UserNoAdmin {
		log.ParamError("AdminLogin: u=" + m.Username + " is not admin")
		gw.WriteErr(w, r, http.StatusUnauthorized, "user is not admin", "usr", m.Username, "namespace", m.Namespace)
		return
	}

	adminType := server.QuidAdmin
	if userType == db.NsAdmin {
		adminType = server.NsAdmin
	}
	log.Result("AdminLogin OK u=" + u.Name + " ns=" + m.Namespace + " AdminType=" + adminType.String())

	// create a new Incorruptible cookie
	cookie, tv, err := incorr.NewCookie(r,
		incorruptible.String(keyUsername, u.Name),
		incorruptible.Int64(KeyUsrID, u.ID),
		incorruptible.String(keyNsName, ns.Name),
		incorruptible.Int64(keyNsID, ns.ID),
		incorruptible.Bool(keyAdminType, bool(adminType)),
	)
	if err != nil {
		log.Error("AdminLogin NewCookie:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "internal error when creating a new incorruptible cookie", "usr", m.Username, "namespace", m.Namespace)
		return
	}

	http.SetCookie(w, cookie)

	sendStatusResponse(w, tv)
}

// status returns 200 if incorruptible cookie says user is admin.
func status(w http.ResponseWriter, r *http.Request) {
	tv, err := incorr.DecodeCookieToken(r)
	if err != nil {
		log.Warn("/status wants cookie name = '"+incorr.Cookie(0).Name+"' but DecodeCookieToken err:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "missing or invalid incorruptible cookie", "want_cookie_name", incorr.Cookie(0).Name)
		return
	}

	sendStatusResponse(w, tv)
}

// status returns 200 if user is admin.
func sendStatusResponse(w http.ResponseWriter, tv incorruptible.TValues) {
	adminType := tv.BoolIfAny(keyAdminType)

	gw.WriteOK(w, server.StatusResponse{
		AdminType: server.AdminType(adminType).String(),
		Username:  tv.StringIfAny(keyUsername),
		Ns: server.NSInfo{
			ID:   tv.Int64IfAny(keyNsID),
			Name: tv.StringIfAny(keyNsName),
		},
	})
}

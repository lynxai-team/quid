package api

import (
	"net/http"

	"github.com/TealsFi/quid/server"
	"github.com/TealsFi/quid/server/db"
)

// quidAdminMiddleware : check the token claim to see if the user is admin.
func quidAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tv, err := incorr.DecodeCookieToken(r)
		if err != nil {
			log.Warn("quidAdminMiddleware wants cookie", incorr.Cookie(0).Name, "but", err)
			gw.WriteErr(w, r, http.StatusUnauthorized, "missing or invalid incorruptible cookie", "want_cookie_name", incorr.Cookie(0).Name)
			return
		}

		values, err := tv.Get(
			tv.KString(keyUsername),
			tv.KInt64(KeyUsrID),
			tv.KString(keyNsName),
			tv.KInt64(keyNsID),
			tv.KString(keyAdminType))
		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		username := values[keyUsername].String()
		usrID := values[KeyUsrID].Int64()
		namespace := values[keyNsName].String()
		nsID := values[keyNsID].Int64()
		adminType := values[keyAdminType].Bool()

		if server.AdminType(adminType) != server.QuidAdmin {
			log.ParamError("User '" + username + "' is not QuidAdmin")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userType, err := db.GetUserType(namespace, nsID, usrID)
		if err != nil {
			log.QueryError(err)
			gw.WriteErr(w, r, http.StatusUnauthorized, "DB error while getting user type", "ns_id", nsID, "uid", usrID)
			return
		}
		if userType != db.QuidAdmin {
			gw.WriteErr(w, r, http.StatusUnauthorized,
				log.Data("quidAdminMiddleware: u="+username+" is not Admin in database").Err().Error())
			return
		}

		log.Param("quidAdminMiddleware OK u="+username+" (id=", usrID, ") ns="+namespace+" (id=", nsID, ")")
		r = tv.ToCtx(r) // save the token in the request context
		next.ServeHTTP(w, r)
	})
}

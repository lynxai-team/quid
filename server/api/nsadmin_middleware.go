package api

import (
	"net/http"

	"github.com/TealsFi/quid/server"
	"github.com/TealsFi/quid/server/db"

	"github.com/lynxai-team/incorruptible"
)

// isNsAdmin checks that the requested namespace operation
// matches the request ns admin permissions
func isNsAdmin(r *http.Request, nsID int64) bool {
	tv, ok := incorruptible.FromCtx(r)
	if !ok {
		log.ParamError("VerifyAdminNs: missing Incorruptible token: cannot check Admin nsID=", nsID)
		return false
	}

	adminType := server.AdminType(tv.BoolIfAny(keyAdminType))
	if adminType == server.QuidAdmin {
		log.Param("VerifyAdminNs OK: Incorruptible token contains IsNsAdmin=true => Do not check the nsID")
		return true
	}

	gotID, err := tv.Int64(keyNsID)
	if err != nil {
		log.ParamError("VerifyAdminNs: missing field nsID in Incorruptible token, want nsID=", nsID, err)
		return false
	}
	if gotID != nsID {
		log.ParamError("VerifyAdminNs: user is nsAdmin for", gotID, ", but not", nsID)
		return false
	}

	return true
}

// nsAdminMiddleware : check the token claim to see if the user is namespace admin.
func nsAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tv, err := incorr.DecodeCookieToken(r)
		if err != nil {
			log.Warn("nsAdminMiddleware wants cookie", incorr.Cookie(0).Name, "but", err)
			gw.WriteErr(w, r, http.StatusUnauthorized, "missing or invalid incorruptible cookie", "want_cookie_name", incorr.Cookie(0).Name)
			return
		}

		values, err := tv.Get(
			tv.KString(keyUsername),
			tv.KInt64(KeyUsrID),
			tv.KString(keyNsName),
			tv.KInt64(keyNsID))
		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		username := values[keyUsername].String()
		usrID := values[KeyUsrID].Int64()
		namespace := values[keyNsName].String()
		nsID := values[keyNsID].Int64()

		userType, err := db.GetUserType(namespace, nsID, usrID)
		if err != nil {
			log.QueryError("nsAdminMiddleware:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if userType == db.UserNoAdmin {
			log.ParamError("nsAdminMiddleware: u=" + username + " is admin, but not for ns=" + namespace)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		log.RequestPost("nsAdminMiddleware OK u="+username+" (id=", usrID, ") ns="+namespace+" (id=", nsID, ")")
		r = tv.ToCtx(r) // save the token in the request context
		next.ServeHTTP(w, r)
	})
}

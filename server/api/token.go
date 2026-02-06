package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/TealsFi/quid/server"
	"github.com/TealsFi/quid/server/db"
	"github.com/TealsFi/quid/tokens"

	"github.com/lynxai-team/garcon/gg"
)

// requestRefreshToken : http login handler.
func requestRefreshToken(w http.ResponseWriter, r *http.Request) {
	var m server.PasswordRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.ParamError("RequestRefreshToken:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	timeout := chi.URLParam(r, "timeout")

	if p := gg.Printable(m.Username, m.Namespace, timeout); p >= 0 {
		log.ParamError("RequestRefreshToken: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	// get the namespace
	ns, err := db.SelectNsFromName(m.Namespace)
	if err != nil {
		log.QueryError("RequestRefreshToken SelectNsFromName:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot SELECT namespace", "namespace", m.Namespace, "error", err)
		return
	}

	// check if the endpoint is available
	if !ns.Enabled {
		log.Data("RequestRefreshToken: public endpoint unauthorized")
		gw.WriteErr(w, r, http.StatusUnauthorized, "endpoint disabled", "namespace", m.Namespace)
		return
	}

	// check if the user password matches
	u, err := checkUserPassword(m.Username, m.Password, ns.ID)
	if err != nil {
		log.Error("RequestRefreshToken checkUserPassword:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "inexistent/disabled user or invalid password", "usr", m.Username, "ns_id", ns.ID)
		return
	}

	// generate the token
	t, err := tokens.GenRefreshToken(timeout, ns.MaxRefreshTTL, ns.Name, u.Name, ns.RefreshKey)
	if err != nil {
		log.Error("RequestRefreshToken GenRefreshToken:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error while generating a new RefreshToken", "namespace", ns.Name, "usr", u.Name)
		return
	}
	if t == "" {
		log.Info("RequestRefreshToken: max timeout exceeded")
		gw.WriteErr(w, r, http.StatusUnauthorized, "max timeout exceeded", "timeout", timeout, "max", ns.MaxRefreshTTL)
		return
	}

	log.RefreshToken("RequestRefreshToken: user=" + u.Name + " t=" + timeout + " TTL=" + ns.MaxRefreshTTL + " ns=" + ns.Name)
	gw.WriteOK(w, "token", t)
}

// requestAccessToken : request an access token from a refresh token.
func requestAccessToken(w http.ResponseWriter, r *http.Request) {
	accessToken, _, _, _ := genAccessToken(w, r)
	if accessToken != "" {
		gw.WriteOK(w, "token", accessToken)
	}
}

func requestRefreshAndAccessTokens(w http.ResponseWriter, r *http.Request) {
	accessToken, timeout, ns, u := genAccessToken(w, r)
	if accessToken == "" {
		return
	}

	refreshToken, err := tokens.GenRefreshToken(timeout, ns.MaxRefreshTTL, ns.Name, u.Name, ns.RefreshKey)
	if err != nil {
		log.Error("RequestRefreshToken GenRefreshToken:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error while generating a new RefreshToken", "namespace", ns.Name, "usr", u.Name)
		return
	}

	if refreshToken == "" {
		log.Info("RequestRefreshToken: max timeout exceeded")
		gw.WriteErr(w, r, http.StatusUnauthorized, "max timeout exceeded", "timeout", timeout, "max", ns.MaxRefreshTTL)
		return
	}

	gw.WriteOK(w, "refresh_token", refreshToken, "access_token", accessToken)
}

func genAccessToken(w http.ResponseWriter, r *http.Request) (accessToken, timeout string, _ server.Namespace, _ server.User) {
	var m server.AccessTokenRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.ParamError("RequestAccessToken:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	timeout = chi.URLParam(r, "timeout")

	if p := gg.Printable(m.RefreshToken, m.Namespace, timeout); p >= 0 {
		log.Warn("RequestAccessToken: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	// get the namespace
	ns, err := db.SelectNsFromName(m.Namespace)
	if err != nil {
		log.QueryError(err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot SELECT namespace", "namespace", m.Namespace, "error", err)
		return
	}

	// check if the endpoint is available
	if !ns.Enabled {
		log.Warn("RequestAccessToken: Public endpoint disabled")
		gw.WriteErr(w, r, http.StatusUnauthorized, "public endpoint disabled", "namespace", m.Namespace)
		return
	}

	// verify the refresh token
	token, err := jwt.ParseWithClaims(m.RefreshToken, &tokens.RefreshClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(ns.RefreshKey), nil
	})
	if err != nil {
		log.Warn("RequestAccessToken ParseWithClaims:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		log.Warn("RequestAccessToken: invalid token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*tokens.RefreshClaims)
	if !ok {
		log.Error("RequestAccessToken: cannot convert to RefreshClaims")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.AccessToken("RequestAccessToken:", claims.Username, claims.ExpiresAt)

	// get the user
	u, err := db.SelectEnabledUser(claims.Username, ns.ID)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// get the user groups names
	groupNames, err := db.SelectGroupsNamesForUser(u.ID)
	if err != nil {
		log.QueryError("RequestAccessToken: Groups error:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// get the user orgs names
	orgsNames, err := db.SelectOrgsNamesForUser(u.ID)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// generate the access token
	t, err := tokens.GenAccessTokenWithAlgo(ns.Alg, timeout, ns.MaxAccessTTL, u.Name, groupNames, orgsNames, ns.AccessKey)
	if err != nil {
		log.Error("RequestAccessToken GenAccessToken:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if t == "" {
		log.Warn("RequestAccessToken: Timeout unauthorized")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.AccessToken("RequestAccessToken: user="+u.Name+" t="+timeout+" TTL="+ns.MaxAccessTTL+" grp=", groupNames, "org=", orgsNames)
	return t, timeout, ns, u
}

func getAccessPublicKey(w http.ResponseWriter, r *http.Request) {
	var m server.NamespaceRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn(err)
		gw.WriteErr(w, r, http.StatusBadRequest, "cannot decode JSON")
		return
	}

	if p := gg.Printable(m.Namespace); p >= 0 {
		log.Warn(`JSON {"name":....} has forbidden character at p=`, p)
		gw.WriteErr(w, r, http.StatusBadRequest, "forbidden character", "position", p)
		return
	}

	// get the namespace
	ns, err := db.SelectNsFromName(m.Namespace)
	if err != nil {
		log.QueryError(err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot SELECT namespace", "namespace", m.Namespace, "error", err)
		return
	}

	switch ns.Alg {
	case "RS256", "RS384", "RS512": // OK
	case "PS256", "PS384", "PS512": // OK
	case "ES256", "ES384", "ES512": // OK
	case "EdDSA": // OK
	default: // "", "HS256", "HS384", "HS512"
		log.ParamError("Namespace", m.Namespace, "has algo", ns.Alg, "without public key")
		gw.WriteErr(w, r, http.StatusUnauthorized, "namespace signing algo has no public key", "algo", ns.Alg)
		return
	}

	keyDER, err := tokens.DecryptVerificationKeyDER(ns.Alg, ns.AccessKey)
	if err != nil {
		log.Error(err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decrypt verification key and convert it to DER format", "algo", ns.Alg, "error", err)
		return
	}

	isBase64 := strings.HasSuffix(m.EncodingForm, "64") // Base64 or base64 or b64...
	keyTxt := gg.EncodeHexOrB64Bytes(keyDER, !isBase64)

	gw.WriteOK(w, server.PublicKeyResponse{Alg: ns.Alg, Key: keyTxt})
}

//nolint:errcheck // no need to check last write of this function
func validAccessToken(w http.ResponseWriter, r *http.Request) {
	var m server.AccessTokenValidationRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.ParamError(err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if p := gg.Printable(m.AccessToken, m.Namespace); p >= 0 {
		log.Warn("JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	// get the namespace
	ns, err := db.SelectNsFromName(m.Namespace)
	if err != nil {
		log.QueryError(err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot SELECT namespace", "namespace", m.Namespace, "error", err)
		return
	}

	verificationKeyDER, err := tokens.DecryptVerificationKeyDER(ns.Alg, ns.AccessKey)
	if err != nil {
		gw.WriteErr(w, r, http.StatusBadRequest, "error decrypting verification key", "namespace", m.Namespace)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	err = tokens.ValidAccessToken(m.AccessToken, ns.Alg, verificationKeyDER)
	if err != nil {
		log.Result("Invalid AccessToken:", err)
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"valid":false}`))
	} else {
		log.Result("Valid AccessToken")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"valid":true}`))
	}
}

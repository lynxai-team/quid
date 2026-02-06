package api

import (
	"net/http"
	"strings"

	"github.com/TealsFi/quid/server"
	"github.com/TealsFi/quid/server/db"
	"github.com/TealsFi/quid/tokens"

	"github.com/lynxai-team/garcon/gg"
)

// allNamespaces : get all namespaces.
func allNamespaces(w http.ResponseWriter, r *http.Request) {
	data, err := db.SelectAllNamespaces()
	if err != nil {
		log.QueryError("AllNamespaces: error SELECT namespaces:", err)
		gw.WriteErr(w, r, http.StatusInternalServerError, "error SELECT namespaces")
		return
	}

	gw.WriteOK(w, data)
}

// setRefreshMaxTTL : set a max refresh token ttl for a namespace.
func setRefreshMaxTTL(w http.ResponseWriter, r *http.Request) {
	var m server.RefreshMaxTTLRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("SetNamespaceRefreshTokenMaxTTL:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if p := gg.Printable(m.RefreshMaxTTL); p >= 0 {
		log.Warn("SetNamespaceRefreshTokenMaxTTL: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	err := db.UpdateNsRefreshMaxTTL(m.ID, m.RefreshMaxTTL)
	if err != nil {
		log.QueryError("SetNamespaceRefreshTokenMaxTTL: error updating tokens max TTL in namespace:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error updating tokens max TTL in namespace")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// setTokenMaxTTL : set a max access token ttl for a namespace.
func setTokenMaxTTL(w http.ResponseWriter, r *http.Request) {
	var m server.MaxTTLRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("SetNamespaceTokenMaxTTL:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if p := gg.Printable(m.MaxTTL); p >= 0 {
		log.Warn("SetNamespaceTokenMaxTTL: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	err := db.UpdateNsTokenMaxTTL(m.ID, m.MaxTTL)
	if err != nil {
		log.QueryError("SetNamespaceTokenMaxTTL: error updating tokens max TTL in namespace:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error updating tokens max TTL in namespace")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// namespaceInfo : info about a namespace.
func namespaceInfo(w http.ResponseWriter, r *http.Request) {
	var m server.InfoRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("NamespaceInfo:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	nu, err := db.CountUsersForNamespace(m.ID)
	if err != nil {
		log.QueryError("NamespaceInfo: error counting users in namespace:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error counting users in namespace")
		return
	}

	g, err := db.SelectNsGroups(m.ID)
	if err != nil {
		log.QueryError("NamespaceInfo: error counting groups in namespace:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error counting groups in namespace")
		return
	}

	data := server.NamespaceInfo{
		NumUsers: nu,
		Groups:   g,
	}

	gw.WriteOK(w, data)
}

// getAccessVerificationKey : get the key for a namespace.
func getAccessVerificationKey(w http.ResponseWriter, r *http.Request) {
	var m server.InfoRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("GetNamespaceAccessKey:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	found, algo, keyDER, err := db.SelectVerificationKeyDER(m.ID)
	if err != nil {
		log.QueryError(err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error SELECT namespace access key", "ns_id", m.ID)
		return
	}
	if !found {
		log.QueryError("GetNamespaceAccessKey: namespace not found")
		gw.WriteErr(w, r, http.StatusUnauthorized, "namespace not found", "ns_id", m.ID)
		return
	}

	isBase64 := strings.HasSuffix(m.EncodingForm, "64") // Base64 or base64 or b64...
	keyTxt := gg.EncodeHexOrB64Bytes(keyDER, !isBase64)

	log.AccessToken("AccessVerificationKey DER", len(keyDER), "bytes base64=", isBase64, len(keyTxt), "bytes", string(keyTxt))

	gw.WriteOK(w, server.PublicKeyResponse{Alg: algo, Key: keyTxt})
}

// findNamespace : namespace creation http handler.
func findNamespace(w http.ResponseWriter, r *http.Request) {
	var m server.NameRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("FindNamespace:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if p := gg.Printable(m.Name); p >= 0 {
		log.Warn("FindNamespace: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	data, err := db.SelectNsStartsWith(m.Name)
	if err != nil {
		log.QueryError("FindNamespace: error SELECT namespace:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "error SELECT namespace")
		return
	}

	gw.WriteOK(w, data)
}

// deleteNamespace : namespace creation http handler.
func deleteNamespace(w http.ResponseWriter, r *http.Request) {
	var m server.InfoRequest
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("DeleteNamespace:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	qRes := db.DeleteNamespace(m.ID)
	if qRes.HasError {
		log.QueryError(qRes.Error.Message)
		if qRes.Error.HasUserMessage {
			log.Warn("DeleteNamespace: error deleting namespace")
			gw.WriteErr(w, r, http.StatusUnauthorized, "error deleting namespace", "error", qRes.Error.Message)
			return
		}
		log.Error("DeleteNamespace")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// enableNsEndpoint :.
func enableNsEndpoint(w http.ResponseWriter, r *http.Request) {
	var m server.Availability
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("SetNamespaceEndpointAvailability:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	err := db.EnableNsEndpoint(m.ID, m.Enable)
	if err != nil {
		log.QueryError("SetNamespaceEndpointAvailability: error updating namespace:", err)
		gw.WriteErr(w, r, http.StatusConflict, "error updating namespace")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// createNamespace : namespace creation http handler.
func createNamespace(w http.ResponseWriter, r *http.Request) {
	var m server.NamespaceCreation
	if err := gg.DecodeJSONRequest(w, r, &m); err != nil {
		log.Warn("CreateNamespace:", err)
		gw.WriteErr(w, r, http.StatusUnauthorized, "cannot decode JSON")
		return
	}

	if m.Name == "" {
		log.ParamError("CreateNamespace: Empty namespace name")
		gw.WriteErr(w, r, http.StatusUnauthorized, "Empty namespace name")
		return
	}

	if p := gg.Printable(m.Name, m.MaxTTL, m.RefreshMaxTTL); p >= 0 {
		log.Warn("CreateNamespace: JSON contains a forbidden character at p=", p)
		gw.WriteErr(w, r, http.StatusUnauthorized, "forbidden character", "position", p)
		return
	}

	exist, err := db.NamespaceExists(m.Name)
	if err != nil {
		gw.WriteErr(w, r, http.StatusUnauthorized, "DB error while checking namespace", "namespace", m.Name, "error", err)
		return
	}
	if exist {
		gw.WriteErr(w, r, http.StatusUnauthorized, "namespace already exists", "namespace", m.Name)
		return
	}

	if m.Alg == "" {
		m.Alg = "HS256"
		log.Param("No signing algo provided, defaults to " + m.Alg)
	}

	refreshKey := tokens.GenerateKeyHMAC(256)
	accessKey, err := tokens.GenerateSigningKey(m.Alg)
	if err != nil {
		log.Warn("Generate AccessKey algo=" + m.Alg + " err: " + err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	nsID, err := db.CreateNamespace(m.Name, m.MaxTTL, m.RefreshMaxTTL, m.Alg, accessKey, refreshKey, m.EnableEndpoint)
	if err != nil {
		gw.WriteErr(w, r, http.StatusUnauthorized, "DB error while creating the namespace", "namespace", m.Name, "error", err)
		return
	}

	gw.WriteOK(w, "ns_id", nsID)
}

package db

import (
	"database/sql"
	"errors"

	// pg import.
	_ "github.com/lib/pq"

	"github.com/TealsFi/quid/crypt"
	"github.com/TealsFi/quid/server"
	"github.com/TealsFi/quid/tokens"
)

// SelectAllNamespaces : get the namespaces.
func SelectAllNamespaces() ([]server.Namespace, error) {
	var data []namespace
	err := db.Select(&data, "SELECT id,name,alg,max_access_ttl,max_refresh_ttl,public_endpoint_enabled FROM namespaces ORDER BY name")
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	res := make([]server.Namespace, 0, len(data))
	for _, u := range data {
		res = append(res, server.Namespace{
			Name:          u.Name,
			Alg:           u.Alg,
			AccessKey:     nil,
			RefreshKey:    nil,
			MaxAccessTTL:  u.MaxAccessTTL,
			MaxRefreshTTL: u.MaxRefreshTTL,
			ID:            u.ID,
			Enabled:       u.PublicEndpointEnabled,
		})
	}

	return res, nil
}

// SelectNsStartsWith : get a namespace.
func SelectNsStartsWith(name string) ([]server.Namespace, error) {
	var data []namespace
	err := db.Select(&data, "SELECT id,name FROM namespaces WHERE name LIKE '"+name+"%'")
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	res := make([]server.Namespace, 0, len(data))
	for _, u := range data {
		res = append(res, server.Namespace{
			ID:   u.ID,
			Name: u.Name,
		})
	}

	return res, nil
}

// SelectNsFromName : get a namespace.
func SelectNsFromName(nsName string) (server.Namespace, error) {
	q := "SELECT id,name,alg,access_key,refresh_key,max_access_ttl,max_refresh_ttl,public_endpoint_enabled" +
		" FROM namespaces WHERE name=$1"

	var ns server.Namespace

	row := db.QueryRowx(q, nsName)

	var data namespace
	err := row.StructScan(&data)
	if err != nil {
		log.Error(err)
		if errors.Is(err, sql.ErrNoRows) {
			return ns, log.ParamError("namespace " + nsName + " does not exist").Err()
		}
		return ns, err
	}

	refreshKey, err := crypt.AesGcmDecryptBin(data.EncryptedRefreshKey)
	if err != nil {
		log.DecryptError("RefreshKey", err)
		return ns, err
	}

	accessKey, err := crypt.AesGcmDecryptBin(data.EncryptedAccessKey)
	if err != nil {
		log.DecryptError("AccessKey", err)
		return ns, err
	}

	ns = server.Namespace{
		Name:          data.Name,
		Alg:           "HS256",
		RefreshKey:    refreshKey,
		AccessKey:     accessKey,
		MaxRefreshTTL: data.MaxRefreshTTL,
		MaxAccessTTL:  data.MaxAccessTTL,
		ID:            data.ID,
		Enabled:       data.PublicEndpointEnabled,
	}

	return ns, nil
}

// SelectVerificationKeyDER get the AccessToken key (in DER form) for a namespace.
func SelectVerificationKeyDER(id int64) (found bool, algo string, der []byte, _ error) {
	row := db.QueryRowx("SELECT alg,access_key FROM namespaces WHERE id=$1", id)

	var data namespace
	if err := row.StructScan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, "", nil, nil
		}
		log.QueryError(err)
		return false, "", nil, err
	}

	der, err := tokens.DecryptVerificationKeyDER(data.Alg, data.EncryptedAccessKey)
	if err != nil {
		log.Error(err)
		return true, "", nil, err
	}

	return true, data.Alg, der, nil
}

// SelectNsID : get a namespace.
func SelectNsID(name string) (int64, error) {
	var data []namespace
	err := db.Select(&data, "SELECT id,name FROM namespaces WHERE name=$1", name)
	if err != nil {
		log.Warn(err)
		return 0, err
	}
	if len(data) == 0 {
		return 0, log.Warn("SelectNsID has no data").Err()
	}
	return data[0].ID, nil
}

// EnableNsEndpoint : enable or disable public endpoint.
func EnableNsEndpoint(id int64, enable bool) error {
	q := "UPDATE namespaces SET public_endpoint_enabled=$2 WHERE id=$1"
	_, err := db.Query(q, id, enable)
	if err != nil {
		log.Warn(err)
	}
	return err
}

// CreateNamespace : create a namespace.
func CreateNamespace(name, ttl, refreshTTL, algo string, accessKey, refreshKey []byte, endpoint bool) (int64, error) {
	ak, err := crypt.AesGcmEncryptBin(accessKey)
	if err != nil {
		log.EncryptError("AccessKey", err)
		return 0, err
	}

	rk, err := crypt.AesGcmEncryptBin(refreshKey)
	if err != nil {
		log.EncryptError("RefreshKey", err)
		return 0, err
	}

	q := "INSERT INTO namespaces(name,alg,access_key,refresh_key,max_access_ttl,max_refresh_ttl,public_endpoint_enabled)" +
		" VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id"
	rows, err := db.Query(q, name, algo, ak, rk, ttl, refreshTTL, endpoint)
	if err != nil {
		log.QueryError(err)
		return 0, err
	}

	return getFirstID(name, rows)
}

// UpdateNsTokenMaxTTL : update a max access token ttl for a namespace.
func UpdateNsTokenMaxTTL(id int64, maxTTL string) error {
	q := "UPDATE namespaces set max_access_ttl=$2 WHERE id=$1"
	_, err := db.Query(q, id, maxTTL)
	if err != nil {
		log.Warn(err)
	}
	return err
}

// UpdateNsRefreshMaxTTL : update a max refresh token ttl for a namespace.
func UpdateNsRefreshMaxTTL(id int64, refreshMaxTTL string) error {
	q := "UPDATE namespaces set max_refresh_ttl=$2 WHERE id=$1"
	_, err := db.Query(q, id, refreshMaxTTL)
	if err != nil {
		log.Warn(err)
	}
	return err
}

// DeleteNamespace : delete a namespace.
func DeleteNamespace(id int64) QueryResult {
	q := "DELETE FROM namespaces where id=$1"
	tx, _ := db.Begin()

	_, err := tx.Exec(q, id)
	if err != nil {
		return queryError(err)
	}

	err = tx.Commit()
	if err != nil {
		return queryError(err)
	}

	return queryNoError()
}

// NamespaceExists : check if a namespace exists.
func NamespaceExists(name string) (bool, error) {
	q := "SELECT COUNT(id) FROM namespaces WHERE(name=$1)"

	var n int
	err := db.Get(&n, q, name)
	if err != nil {
		log.QueryError(err)
		return false, err
	}

	exists := (n > 0)
	return exists, nil
}

// CountUsersForNamespace : count users in a namespace.
func CountUsersForNamespace(id int64) (int, error) {
	q := "SELECT COUNT(id) FROM users WHERE(ns_id=$1)"

	var n int
	err := db.Get(&n, q, id)
	if err != nil {
		log.Warn(err)
		return 0, err
	}

	return n, nil
}

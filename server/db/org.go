package db

import (
	// pg import.
	_ "github.com/lib/pq"

	"github.com/lynxai-team/quid/server"
)

// SelectAllOrgs : get all the orgs.
func SelectAllOrgs() ([]server.Org, error) {
	q := "SELECT id,name FROM organizations"

	data := []server.Org{}
	err := db.Select(&data, q)
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	return data, nil
}

// SelectOrg : get a org.
func SelectOrg(name string) (server.Org, error) {
	q := "SELECT id,name FROM organizations WHERE(name=$1)"

	var data []server.Org
	err := db.Select(&data, q, name)
	if err != nil {
		log.Warn(err)
		return server.Org{}, err
	}

	return data[0], nil
}

// SelectOrgsForUser : get the orgs for a user.
func SelectOrgsForUser(usrID int64) ([]server.Org, error) {
	q := "SELECT organizations.id as id, organizations.name as name FROM user_organizations " +
		"JOIN organizations ON user_organizations.org_id = organizations.id " +
		"WHERE user_organizations.usr_id=$1 ORDER BY organizations.name"

	var data []server.Org
	err := db.Select(&data, q, usrID)
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	return data, nil
}

// SelectOrgStartsWith : get a namespace.
func SelectOrgStartsWith(name string) ([]server.Org, error) {
	q := "SELECT id,name FROM organizations WHERE name LIKE '" + name + "%'"

	var data []org
	err := db.Select(&data, q)
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	res := make([]server.Org, 0, len(data))
	for _, u := range data {
		res = append(res, server.Org{
			ID:   u.ID,
			Name: u.Name,
		})
	}

	return res, nil
}

// SelectOrgsNamesForUser : get the orgs for a user.
func SelectOrgsNamesForUser(usrID int64) ([]string, error) {
	q := "SELECT organizations.name as name FROM user_organizations " +
		"JOIN organizations ON user_organizations.org_id = organizations.id " +
		"WHERE user_organizations.usr_id=$1 ORDER BY organizations.name"

	var data []userOrgName
	err := db.Select(&data, q, usrID)
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	names := make([]string, 0, len(data))
	for _, row := range data {
		names = append(names, row.Name)
	}

	return names, nil
}

// OrgExists : check if an org exists.
func OrgExists(name string) (bool, error) {
	q := "SELECT COUNT(id) FROM organizations WHERE(name=$1)"

	var n int
	err := db.Get(&n, q, name)
	if err != nil {
		log.Warn(err)
		return false, err
	}

	exists := (n > 0)
	return exists, nil
}

// DeleteOrg : delete an org.
func DeleteOrg(id int64) error {
	q := "DELETE FROM organizations WHERE id=$1"

	tx := db.MustBegin()
	tx.MustExec(q, id)

	err := tx.Commit()
	if err != nil {
		log.Warn(err)
	}
	return err
}

// CreateOrg : create an org.
func CreateOrg(name string) (int64, error) {
	q := "INSERT INTO organizations(name) VALUES($1) RETURNING id"

	rows, err := db.Query(q, name)
	if err != nil {
		log.QueryError(err)
		return 0, err
	}

	return getFirstID(name, rows)
}

// AddUserInOrg : add a user into an org.
func AddUserInOrg(usrID, orgID int64) error {
	q := "INSERT INTO user_organizations(usr_id,org_id) VALUES($1,$2)"

	tx := db.MustBegin()
	tx.MustExec(q, usrID, orgID)

	err := tx.Commit()
	if err != nil {
		log.Warn(err)
	}
	return err
}

// RemoveUserFromOrg : remove a user from an org.
func RemoveUserFromOrg(usrID, orgID int64) error {
	q := "DELETE FROM user_organizations WHERE usr_id=$1 AND org_id=$2"

	tx := db.MustBegin()
	tx.MustExec(q, usrID, orgID)

	err := tx.Commit()
	if err != nil {
		log.Warn(err)
	}
	return err
}

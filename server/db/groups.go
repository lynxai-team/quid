package db

import (
	// pg import.

	_ "github.com/lib/pq"

	"github.com/lynxai-team/quid/server"
)

// SelectAllGroups : get all the groups.
func SelectAllGroups() ([]server.Group, error) {
	q := "SELECT groups.id,groups.name,namespaces.name as namespace" +
		" FROM groups" +
		" JOIN namespaces ON groups.ns_id = namespaces.id" +
		" ORDER BY groups.name"

	var data []server.Group
	err := db.Select(&data, q)
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	return data, nil
}

// SelectGroupsForUser : get the groups for a user.
func SelectGroupsForUser(usrID int64) ([]server.Group, error) {
	q := "SELECT groups.id as id, groups.name as name" +
		" FROM user_groups" +
		" JOIN groups ON user_groups.grp_id = groups.id" +
		" WHERE user_groups.usr_id=$1 ORDER BY groups.name"

	var data []server.Group
	err := db.Select(&data, q, usrID)
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	return data, nil
}

// SelectGroupsNamesForUser : get the groups for a user.
func SelectGroupsNamesForUser(usrID int64) ([]string, error) {
	q := "SELECT groups.name as name FROM user_groups" +
		" JOIN groups ON user_groups.grp_id = groups.id" +
		" WHERE user_groups.usr_id=$1 ORDER BY groups.name"

	var data []userGroupName
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

// SelectNsGroups : get the groups for a namespace.
func SelectNsGroups(nsID int64) ([]server.Group, error) {
	q := "SELECT groups.id,groups.name,namespaces.name as namespace" +
		" FROM groups" +
		" JOIN namespaces ON groups.ns_id = namespaces.id" +
		" WHERE groups.ns_id=$1 ORDER BY groups.name"

	var data []server.Group
	err := db.Select(&data, q, nsID)
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	return data, nil
}

// SelectGroup : get a group.
func SelectGroup(name string, nsID int64) (server.Group, error) {
	var data []server.Group
	err := db.Select(&data, "SELECT id,name FROM groups WHERE(name=$1 AND ns_id=$2)", name, nsID)
	if err != nil {
		log.S().Warn(err)
		return server.Group{}, err
	}

	if len(data) == 0 {
		return server.Group{}, nil
	}

	return data[0], nil
}

// CreateGroup : create a group.
func CreateGroup(name string, nsID int64) (int64, error) {
	q := "INSERT INTO groups(name,ns_id) VALUES($1,$2) RETURNING id"

	rows, err := db.Query(q, name, nsID)
	if err != nil {
		log.QueryError(err)
		return 0, err
	}

	return getFirstID(name, rows)
}

// DeleteGroup : delete a group.
func DeleteGroup(id int64) error {
	q := "DELETE FROM groups WHERE id=$1"

	tx := db.MustBegin()
	tx.MustExec(q, id)

	err := tx.Commit()
	if err != nil {
		log.Warn(err)
	}
	return err
}

// GroupExists : check if an group exists.
func GroupExists(name string, nsID int64) (bool, error) {
	q := "SELECT COUNT(id) FROM groups WHERE(name=$1 AND ns_id=$2)"

	var n int
	err := db.Get(&n, q, name, nsID)
	if err != nil {
		log.Warn(err)
		return false, err
	}

	exists := (n > 0)
	return exists, nil
}

// AddUserInGroup : add a user into a group.
func AddUserInGroup(usrID, grpID int64) error {
	q := "INSERT INTO user_groups(usr_id,grp_id) VALUES($1,$2)"

	tx := db.MustBegin()
	tx.MustExec(q, usrID, grpID)

	err := tx.Commit()
	if err != nil {
		log.Warn(err)
	}
	return err
}

// RemoveUserFromGroup : remove a user from a group.
func RemoveUserFromGroup(usrID, grpID int64) error {
	q := "DELETE FROM user_groups WHERE usr_id=$1 AND grp_id=$2"

	tx := db.MustBegin()
	tx.MustExec(q, usrID, grpID)

	err := tx.Commit()
	if err != nil {
		log.Warn(err)
	}
	return err
}

// IsUserInGroup : check if a user is in a group.
func IsUserInGroup(usrID, grpID int64) (bool, error) {
	q := "SELECT COUNT(id) FROM user_groups WHERE(usr_id=$1 AND grp_id=$2)"
	log.Query(q, usrID, grpID)

	var n int
	err := db.Get(&n, q, usrID, grpID)
	if err != nil {
		log.Warn(err)
		return false, err
	}

	exists := (n > 0)
	return exists, nil
}

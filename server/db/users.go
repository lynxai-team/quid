package db

import (
	"database/sql"
	"errors"

	// pg import.
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/TealsFi/quid/server"
)

// selectEnabledUsrID : get a user id from it's name.
// Deprecated because this function is not really used.
func selectEnabledUsrID(name string) (int64, error) {
	row := db.QueryRowx("SELECT id,name,password,enabled FROM users WHERE(name=$1)", name)

	var u user
	err := row.StructScan(&u)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, log.NotFound("User", name, "does not exist in DB").Err()
		}
		return 0, err
	}

	if !u.Enabled {
		return 0, log.Data("User", name, "is disabled in DB").Err()
	}

	return u.ID, nil
}

// SelectEnabledUser : get a user from it's name.
func SelectEnabledUser(name string, nsID int64) (server.User, error) {
	var usr server.User

	row := db.QueryRowx("SELECT id,name,password,enabled FROM users WHERE(name=$1 AND ns_id=$2)", name, nsID)

	var u user
	err := row.StructScan(&u)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return usr, log.NotFound("User", name, "not found in namespace ID=", nsID).Err()
		}
		log.QueryError(err)
		return usr, err
	}

	if !u.Enabled {
		return usr, log.Data("User", name, "is disabled in namespace ID=", nsID).Err()
	}

	usr = server.User{
		DateCreated:  u.DateCreated,
		ID:           u.ID,
		Name:         u.Name,
		PasswordHash: u.PasswordHash,
		Namespace:    u.Namespace,
		Org:          "",
		Groups:       []server.Group{}, // frontend prefers `[]` rather than `null` in JSON response
		Enabled:      u.Enabled,
	}

	return usr, nil
}

// SelectAllUsers : get the users.
func SelectAllUsers() ([]server.User, error) {
	var data []user
	err := db.Select(&data,
		"SELECT users.id,users.name,namespaces.name as namespace FROM users "+
			"JOIN namespaces ON users.ns_id = namespaces.id "+
			"ORDER BY users.name")
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	users := make([]server.User, 0, len(data))
	for _, u := range data {
		users = append(users, server.User{
			Name:         u.Name,
			PasswordHash: "",
			Namespace:    u.Namespace,
			Org:          "",
			Groups:       nil,
			ID:           u.ID,
		})
	}

	return users, nil
}

// SelectNsUsers : get the users in a namespace.
func SelectNsUsers(nsID int64) ([]server.User, error) {
	var data []user
	err := db.Select(&data,
		"SELECT users.id,users.name,namespaces.name as namespace FROM users "+
			"JOIN namespaces ON users.ns_id = namespaces.id  "+
			"WHERE users.ns_id=$1 ORDER BY users.name", nsID)
	if err != nil {
		log.Warn(err)
		return nil, err
	}

	users := make([]server.User, 0, len(data))
	for _, d := range data {
		users = append(users, server.User{
			ID:        d.ID,        // user ID
			Name:      d.Name,      // username
			Namespace: d.Namespace, // namespace name
		})
	}

	return users, nil
}

// CreateUser : create a user.
func CreateUser(name, password string, nsID int64) (server.User, error) {
	var user server.User

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Warn(err)
		return user, err
	}

	uid, err := CreateUserFromNameAndPassword(name, string(hashedPassword), nsID)
	if err != nil {
		log.Warn(err)
		return user, err
	}

	user.ID = uid
	user.Name = name

	return user, nil
}

// CreateUserFromNameAndPassword : create a user.
func CreateUserFromNameAndPassword(name, passwordHash string, nsID int64) (int64, error) {
	q := "INSERT INTO users(name,password,ns_id) VALUES($1,$2,$3) RETURNING id"
	rows, err := db.Query(q, name, passwordHash, nsID)
	if err != nil {
		log.QueryError(err)
		return 0, err
	}

	return getFirstID(name, rows)
}

/*
// SelectGroupsForUser : get the groups for a user in a namespace
func SelectGroupsForUser(usrID int64) ([]server.Group, error) {
	var data []group
	err := db.Select(&data, "SELECT groups.id,groups.name FROM user_groups "+
		"JOIN groups ON user_groups.grp_id = groups.id WHERE user_groups.usr_id=$1 ORDER BY groups.name",
		usrID)
	var gr []server.Group
	if err != nil {
		log.Warn(err)
		return gr, err
	}
	for _, g := range gr {
		res := server.Group{
			ID:   g.ID,
			Name: g.Name,
		}
		gr = append(gr, res)
	}
	return gr, nil
}*/

// CountUsersInGroup : count the users in a group.
func CountUsersInGroup(grpID int64) (int, error) {
	q := "SELECT COUNT(usr_id) FROM user_groups WHERE grp_id=$1"

	var n int
	err := db.Get(&n, q, grpID)

	return n, err
}

// UserExists : check if a name exists.
func UserExists(name string, nsID int64) (bool, error) {
	q := "SELECT COUNT(id) FROM users WHERE (name=$1 AND ns_id=$2)"

	var n int
	err := db.Get(&n, q, name, nsID)
	if err != nil {
		log.Warn(err)
		return false, err
	}

	exists := (n > 0)
	return exists, nil
}

// DeleteUser : delete a user.
func DeleteUser(id int64) error {
	q := "DELETE FROM users WHERE id=$1"

	tx := db.MustBegin()
	tx.MustExec(q, id)

	err := tx.Commit()
	if err != nil {
		log.Warn(err)
	}
	return err
}

// IsUserInAdminGroup : check if a user is in quid admin group
func IsUserInAdminGroup(uID, nsID int64) (bool, error) {
	g, err := SelectGroup("quid_admin", nsID)
	if err != nil {
		return false, err
	}
	return IsUserInGroup(uID, g.ID)
}

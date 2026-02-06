package db

import (
	"errors"
	"fmt"

	"github.com/manifoldco/promptui"

	"github.com/TealsFi/quid/server"
	"github.com/TealsFi/quid/tokens"
)

var (
	ErrUsernameTooShort = errors.New("username must have more than 2 characters")
	ErrPasswordTooShort = errors.New("password must have more than 5 characters")
)

func CreateQuidAdminIfMissing(username, password string) error {
	exist, err := NamespaceExists("quid")
	if err != nil {
		return err
	}

	var nsID int64
	if exist {
		nsID, err = SelectNsID("quid")
	} else {
		log.V().Data(`Creating the "quid" namespace`)
		algo := "HS256"
		accessKey := tokens.GenerateKeyHMAC(256)
		refreshKey := tokens.GenerateKeyHMAC(256)
		nsID, err = CreateNamespace("quid", "6m", "24h", algo, accessKey, refreshKey, false)
	}
	if err != nil {
		return err
	}

	exist, err = GroupExists("quid_admin", nsID)
	if err != nil {
		return err
	}

	var gid int64
	if exist {
		var g server.Group
		g, err = SelectGroup("quid_admin", nsID)
		gid = g.ID
	} else {
		log.V().Data(`Creating the "quid_admin" group`)
		gid, err = CreateGroup("quid_admin", nsID)
	}
	if err != nil {
		return err
	}

	n, err := CountUsersInGroup(gid)
	if err != nil {
		return err
	}
	if n > 0 {
		log.Dataf(`Quid Admin already created (%d user in "quid_admin" group)`, n)
		return nil
	}

	if username == "" {
		username, err = promptForUsername()
		if err != nil {
			return err
		}
	}

	if password == "" {
		password, err = promptForPassword()
		if err != nil {
			return err
		}
	}

	log.V().Dataf("Create the Quid Admin usr=%q pwd=%d bytes", username, len(password))
	u, err := CreateUser(username, password, nsID)
	if err != nil {
		return err
	}

	return AddUserInGroup(u.ID, gid)
}

func promptForUsername() (string, error) {
	fmt.Println(`
Enter the Quid Admin username.
` + ErrUsernameTooShort.Error())

	prompt := promptui.Prompt{
		Label:   "Username",
		Default: "admin",
		Validate: func(s string) error {
			if len(s) <= 2 {
				return ErrUsernameTooShort
			}
			return nil
		},
	}

	username, err := prompt.Run()
	if err != nil {
		log.ParamError(err)
	}
	return username, err
}

func promptForPassword() (string, error) {
	fmt.Println(`
Enter the Quid Admin password.
` + ErrPasswordTooShort.Error())

	prompt := promptui.Prompt{
		Label:   "Password",
		Default: "",
		Validate: func(input string) error {
			if len(input) <= 5 {
				return ErrPasswordTooShort
			}
			return nil
		},
		Mask: '*',
	}

	password, err := prompt.Run()
	if err != nil {
		log.ParamError(err)
	}
	return password, err
}

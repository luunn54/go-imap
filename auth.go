package imap

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

// Generates an unencoded XOAuth2 string of the form
//
//	"user=" {User} "^Aauth=Bearer " {Access Token} "^A^A"
//
// as defined at https://developers.google.com/google-apps/gmail/xoauth2_protocol#the_sasl_xoauth2_mechanism.
//
// The function XOAuth2String in this package returns the base64 encoding of this string.
func OAuth2String(user, accessToken string) string {
	return fmt.Sprint("user=", user, "\001auth=Bearer ", accessToken, "\001\001")
}

// Generates a base64-encoded XOAuth2 string suitable for use in SASL XOAUTH2, as
// defined at https://developers.google.com/google-apps/gmail/xoauth2_protocol#the_sasl_xoauth2_mechanism.
func XOAuth2String(user, accessToken string) string {
	s := OAuth2String(user, accessToken)
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write([]byte(s))
	encoder.Close()
	return buf.String()
}

// Authenticate performs XOAUTH2 authentication using an access token
func (d *Dialer) Authenticate(user string, accessToken string) (err error) {
	b64 := XOAuth2String(user, accessToken)
	// Don't retry authentication - auth failures should not trigger reconnection
	_, err = d.Exec(fmt.Sprintf("AUTHENTICATE XOAUTH2 %s", b64), false, 0, nil)
	return err
}

// Login performs LOGIN authentication using username and password
func (d *Dialer) Login(username string, password string) (err error) {
	// Don't retry authentication - auth failures should not trigger reconnection
	_, err = d.Exec(fmt.Sprintf(`LOGIN "%s" "%s"`, AddSlashes.Replace(username), AddSlashes.Replace(password)), false, 0, nil)
	return err
}

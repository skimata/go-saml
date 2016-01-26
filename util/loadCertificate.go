package util

import (
	"io/ioutil"
	"regexp"
	"strings"
)

// LoadCertificate from file system
func LoadCertificate(certPath string) (string, error) {
	return LoadFile(certPath, "---(.*)CERTIFICATE(.*)---|---(.*)BEGIN PUBLIC KEY(.*)---")
}

func LoadFile(certPath string, headPattern string) (string, error) {
	b, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	cert := string(b)

	re := regexp.MustCompile(headPattern)
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\n", "", -1)

	return cert, nil
}

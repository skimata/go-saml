package saml

import "github.com/skimata/go-saml/util"

// ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
// Expect only one IDP per SP in this configuration. If you need to configure multipe IDPs for an SP
// then configure multiple instances of this module
type ServiceProviderSettings struct {
	PublicCertPath                string
	PrivateKeyPath                string
	IDPSSOURL                     string
	IDPSSODescriptorURL           string
	IDPPublicCertPath             string
	AssertionConsumerServiceURL   string
	SPSignRequest                 bool
	XmlResponseIdNameSpaceAndNode string
	XmlSecVerifyFlag              string

	IsInitialized bool
	publicCert    string
	privateKey    string
	idpPublicCert string
}

type IdentityProviderSettings struct {
}

func (s *ServiceProviderSettings) Init() error {
	var err error

	if s.IsInitialized {
		return nil
	}

	if s.SPSignRequest {
		s.publicCert, err = util.LoadCertificate(s.PublicCertPath)
		if err != nil {
			return err
		}

		s.privateKey, err = util.LoadCertificate(s.PrivateKeyPath)
		if err != nil {
			return err
		}
	}

	//support for a IDP cert or a PEM encoded public key
	if s.IDPPublicCertPath != "" {
		s.idpPublicCert, err = util.LoadCertificate(s.IDPPublicCertPath)
		if err != nil {
			return err
		}
	}

	s.IsInitialized = true
	return nil
}

func (s *ServiceProviderSettings) PublicCert() string {
	return s.publicCert
}

func (s *ServiceProviderSettings) PrivateKey() string {
	return s.privateKey
}

func (s *ServiceProviderSettings) IDPPublicCert() string {
	return s.idpPublicCert
}

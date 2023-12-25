package authenticationFile

import "github.com/mailhedgehog/contracts"

type smtpAuthentication struct {
}

func (authentication *smtpAuthentication) RequiresAuthentication() bool {
	return authentication.ViaPasswordAuthentication().Enabled() ||
		authentication.ViaIpAuthentication().Enabled()
}

func (authentication *smtpAuthentication) IpsAllowList() contracts.IpsAllowList {
	return &smtpIpsAllowList{}
}

func (authentication *smtpAuthentication) ViaPasswordAuthentication() contracts.ViaPasswordAuthentication {
	return &smtpViaPasswordAuthentication{}
}

func (authentication *smtpAuthentication) ViaIpAuthentication() contracts.ViaIpAuthentication {
	return &smtpViaIpAuthentication{}
}

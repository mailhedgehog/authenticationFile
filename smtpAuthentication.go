package authenticationFile

import "github.com/mailhedgehog/contracts"

type smtpAuthentication struct {
	context *storageContext
}

func (authentication *smtpAuthentication) RequiresAuthentication() bool {
	return authentication.ViaPasswordAuthentication().Enabled() ||
		authentication.ViaIpAuthentication().Enabled()
}

func (authentication *smtpAuthentication) IpsAllowList() contracts.IpsAllowList {
	return &smtpIpsAllowList{authentication.context}
}

func (authentication *smtpAuthentication) ViaPasswordAuthentication() contracts.ViaPasswordAuthentication {
	return &smtpViaPasswordAuthentication{authentication.context}
}

func (authentication *smtpAuthentication) ViaIpAuthentication() contracts.ViaIpAuthentication {
	return &smtpViaIpAuthentication{authentication.context}
}

package authenticationFile

import "github.com/mailhedgehog/contracts"

type dashboardAuthentication struct {
	context *storageContext
}

func (authentication *dashboardAuthentication) RequiresAuthentication() bool {
	return authentication.ViaPasswordAuthentication().Enabled() ||
		authentication.ViaEmailAuthentication().Enabled()
}

func (authentication *dashboardAuthentication) ViaPasswordAuthentication() contracts.ViaPasswordAuthentication {
	return &dashboardViaPasswordAuthentication{authentication.context}
}

func (authentication *dashboardAuthentication) ViaEmailAuthentication() contracts.ViaEmailAuthentication {
	return &dashboardViaEmailAuthentication{authentication.context}
}

package authenticationFile

import "github.com/mailhedgehog/contracts"

type dashboardAuthentication struct {
}

func (authentication *dashboardAuthentication) RequiresAuthentication() bool {
	return authentication.ViaPasswordAuthentication().Enabled() ||
		authentication.ViaEmailAuthentication().Enabled()
}

func (authentication *dashboardAuthentication) ViaPasswordAuthentication() contracts.ViaPasswordAuthentication {
	return &dashboardViaPasswordAuthentication{}
}

func (authentication *dashboardAuthentication) ViaEmailAuthentication() contracts.ViaEmailAuthentication {
	return &dashboardViaEmailAuthentication{}
}

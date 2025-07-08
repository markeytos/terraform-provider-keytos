// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package acctest

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

func PreCheck(t *testing.T) {
	t.Helper()
}

// testAccProtoV6ProviderFactories is used to instantiate a provider during acceptance testing.
// The factory function is called for each Terraform CLI command to create a provider
// server that the CLI can connect to and interact with.
func ProtoV6ProviderFactories(pfs map[string]func() provider.Provider) map[string]func() (tfprotov6.ProviderServer, error) {
	f := make(map[string]func() (tfprotov6.ProviderServer, error), len(pfs))
	for k, pf := range pfs {
		f[k] = providerserver.NewProtocol6WithError(pf())
	}
	return f
}

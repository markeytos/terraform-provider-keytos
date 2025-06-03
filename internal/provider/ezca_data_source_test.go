// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccKeytosEzcaSslAuthorityDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccKeytosEzcaSslAuthorityDataSourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"data.keytos_ezca_ssl_authority.test",
						tfjsonpath.New("authority_id"),
						knownvalue.StringExact("00000000-0000-0000-0000-000000000001"),
					),
					statecheck.ExpectKnownValue(
						"data.keytos_ezca_ssl_authority.test",
						tfjsonpath.New("template_id"),
						knownvalue.StringExact("00000000-0000-0000-0000-000000000002"),
					),
				},
			},
		},
	})
}

const testAccKeytosEzcaSslAuthorityDataSourceConfig = `
data "keytos_ezca_ssl_authority" "test" {
  authority_id = "00000000-0000-0000-0000-000000000001"
  template_id = "00000000-0000-0000-0000-000000000002"
}
`

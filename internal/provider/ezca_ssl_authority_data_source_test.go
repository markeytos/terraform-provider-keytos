// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/markeytos/terraform-provider-keytos/internal/acctest"
)

func TestAccKeytosEzcaSslAuthority(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccKeytosEzcaSslAuthorityConfig(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"data.keytos_ezca_ssl_authority.test",
						tfjsonpath.New("authority_id"),
						knownvalue.StringExact(test_authority_id),
					),
					statecheck.ExpectKnownValue(
						"data.keytos_ezca_ssl_authority.test",
						tfjsonpath.New("template_id"),
						knownvalue.StringExact(test_template_id),
					),
					statecheck.ExpectKnownValue(
						"data.keytos_ezca_ssl_authority.test",
						tfjsonpath.New("key_type"),
						knownvalue.StringExact("RSA 4096"),
					),
					statecheck.ExpectKnownValue(
						"data.keytos_ezca_ssl_authority.test",
						tfjsonpath.New("hash_algorithm"),
						knownvalue.StringExact("SHA512"),
					),
					statecheck.ExpectKnownValue(
						"data.keytos_ezca_ssl_authority.test",
						tfjsonpath.New("is_public"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"data.keytos_ezca_ssl_authority.test",
						tfjsonpath.New("is_root"),
						knownvalue.Bool(true),
					),
				},
			},
		},
	})
}

func testAccKeytosEzcaSslAuthorityConfig() string {
	return fmt.Sprintf(`
data "keytos_ezca_ssl_authority" "test" {
  authority_id = %q
  template_id = %q
}
`, test_authority_id, test_template_id)
}

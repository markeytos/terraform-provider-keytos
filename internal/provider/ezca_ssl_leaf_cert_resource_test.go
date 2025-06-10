// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/markeytos/ezca-go"
	"github.com/markeytos/terraform-provider-keytos/internal/acctest"
	"github.com/stretchr/testify/require"
)

func TestAccKeytosEzcaSslLeafCert(t *testing.T) {
	certPEMRegexp, err := regexp.Compile(`-----BEGIN CERTIFICATE-----[\r\n]+([A-Za-z0-9+/=\r\n]+)[\r\n]+-----END CERTIFICATE-----`)
	require.NoError(t, err)
	hexRegexp, err := regexp.Compile(`[0-9a-f]+`)
	require.NoError(t, err)
	serialNumberRegexp, err := regexp.Compile(`[0-9]+`)
	require.NoError(t, err)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccKeytosEzcaSslLeafCertConfig("24h", "0"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("authority_id"),
						knownvalue.StringExact(test_authority_id),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("template_id"),
						knownvalue.StringExact(test_template_id),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("cert_request_pem"),
						knownvalue.StringExact(testCSR),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("validity_period"),
						knownvalue.StringExact("24h"),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("key_usages"),
						knownvalue.ListExact([]knownvalue.Check{
							knownvalue.StringExact(string(ezca.KeyUsageKeyEncipherment)),
							knownvalue.StringExact(string(ezca.KeyUsageDigitalSignature)),
						}),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("extended_key_usages"),
						knownvalue.ListExact([]knownvalue.Check{
							knownvalue.StringExact(string(ezca.ExtKeyUsageServerAuth)),
							knownvalue.StringExact(string(ezca.ExtKeyUsageClientAuth)),
						}),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("overwrite_subject_name"),
						knownvalue.Null(),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("overwrite_subject_name_str"),
						knownvalue.Null(),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("additional_subject_alternative_names"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"dns_names": knownvalue.ListExact([]knownvalue.Check{
								knownvalue.StringExact("test.com"),
							}),
							"email_addresses": knownvalue.Null(),
							"ip_addresses":    knownvalue.Null(),
							"uris":            knownvalue.Null(),
						}),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("early_renewal_period"),
						knownvalue.StringExact("0"),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("cert_pem"),
						knownvalue.StringRegexp(certPEMRegexp),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("cert_thumbprint_hex"),
						knownvalue.StringRegexp(hexRegexp),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("cert_serial_number"),
						knownvalue.StringRegexp(serialNumberRegexp),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("ready_for_renewal"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("validity_not_before"),
						knownvalue.StringFunc(verifyRFC3339),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("validity_not_after"),
						knownvalue.StringFunc(verifyRFC3339),
					),
				},
			},
			// Update and Read testing
			{
				Config: testAccKeytosEzcaSslLeafCertConfig("72h", "48h"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("authority_id"),
						knownvalue.StringExact(test_authority_id),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("template_id"),
						knownvalue.StringExact(test_template_id),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("cert_request_pem"),
						knownvalue.StringExact(testCSR),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("validity_period"),
						knownvalue.StringExact("72h"),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("key_usages"),
						knownvalue.ListExact([]knownvalue.Check{
							knownvalue.StringExact(string(ezca.KeyUsageKeyEncipherment)),
							knownvalue.StringExact(string(ezca.KeyUsageDigitalSignature)),
						}),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("extended_key_usages"),
						knownvalue.ListExact([]knownvalue.Check{
							knownvalue.StringExact(string(ezca.ExtKeyUsageServerAuth)),
							knownvalue.StringExact(string(ezca.ExtKeyUsageClientAuth)),
						}),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("overwrite_subject_name"),
						knownvalue.Null(),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("overwrite_subject_name_str"),
						knownvalue.Null(),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("additional_subject_alternative_names"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"dns_names": knownvalue.ListExact([]knownvalue.Check{
								knownvalue.StringExact("test.com"),
							}),
							"email_addresses": knownvalue.Null(),
							"ip_addresses":    knownvalue.Null(),
							"uris":            knownvalue.Null(),
						}),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("early_renewal_period"),
						knownvalue.StringExact("48h"),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("cert_pem"),
						knownvalue.StringRegexp(certPEMRegexp),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("cert_thumbprint_hex"),
						knownvalue.StringRegexp(hexRegexp),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("cert_serial_number"),
						knownvalue.StringRegexp(serialNumberRegexp),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("ready_for_renewal"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("validity_not_before"),
						knownvalue.StringFunc(verifyRFC3339),
					),
					statecheck.ExpectKnownValue(
						"keytos_ezca_ssl_leaf_cert.test",
						tfjsonpath.New("validity_not_after"),
						knownvalue.StringFunc(verifyRFC3339),
					),
				},
			},
		},
	})
}

const testCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIIC1zCCAb8CAQAwgZExCzAJBgNVBAYTAlVTMRYwFAYDVQQIDA1NYXNzYWNodXNl
dHRzMQ8wDQYDVQQHDAZCb3N0b24xDzANBgNVBAoMBktleXRvczEbMBkGA1UECwwS
S2V5dG9zIE9wZW4gU291cmNlMSswKQYDVQQDDCJLZXl0b3MgVGVycmFmb3JtIFBy
b3ZpZGVyIFRlc3QgQ1NSMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
oS8jvIjn1mBrVZKBjZ6QUAWCaONF1cUO1NoGPkUSkh+bEWG3yrf8dzsvmVzBQOZr
ueze0QWxJyHE1UJ24DkQWfSa6c2kZF4i7BtOWK8VWTxRBylYfKm6mu6f7HRVsvIh
UjHBSUoXs+KdXVVijDz2yxDn/bX5pwyS+FarceZN4YkEFelbpgqUejcwzB7jtGz8
uo9VU7Mf4K9cwq/Th5XfMd4ediUmxsaecanJX/RMs5/L/g0jFaYaO6f4h6gU4mc7
Vt6+XG+hK7mf1KxO+BHsJloAJlKHNO2+NCFXpK6KWEnP9UFDijMmgSgSIL/xVbHK
UzXcbCrEcQN1AOYFCoYFgQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBADIjQEBW
/VrT2WnBlIlpjxoeYvjq60fHVrWIV4SmPioEAURoHKy3aAD2Ui+HHJxRBVfOQtea
h45V8zKNwHvXyyN5UqwuQlTMVn5KZoaR186XcDaXXGPfBsBxGpr9EEjMEfqd+Kc/
Al+kmG+x9vdf3W/5L5O6lTiXh3Vmn3LJszzApMTjutirGTKhiSt9b2lfd6dJ7h3R
l2Lq6Gh11E8kIqzCsm8yLbqUpW1eaaknXrER3YylfzPpn4QU5XH8Bvm2fxZdUiGb
E6egfmwvg4KzwzlystEVW4f0YKajplLxnjFqn5uboEfkaFsyXBdDXovEnilZ/xWi
RsBLHqHbu9mDMjg=
-----END CERTIFICATE REQUEST-----`

func testAccKeytosEzcaSslLeafCertConfig(validity, earlyRenewal string) string {

	return fmt.Sprintf(`
resource "keytos_ezca_ssl_leaf_cert" "test" {
  authority_id = %q
  template_id = %q
  cert_request_pem = %q
  validity_period = %q
  additional_subject_alternative_names = {
    dns_names = ["test.com"]
  }
  early_renewal_period = %q
}
`, test_authority_id, test_template_id, testCSR, validity, earlyRenewal)
}

func verifyRFC3339(s string) error {
	_, err := time.Parse(time.RFC3339, s)
	return err
}

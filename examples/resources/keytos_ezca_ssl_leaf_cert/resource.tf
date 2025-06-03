resource "keytos_ezca_ssl_leaf_cert" "example" {
  authority_id     = "00000000-0000-0000-0000-100000000000"
  template_id      = "00000000-0000-0000-0000-200000000000"
  cert_request_pem = "CERTIFICATE_PEM"
  validity_period  = "14d"
  overwrite_subject_name = {
    common_name  = "Test 101"
    organization = "Keytos"
  }
  early_renewal_period = "7d"
}

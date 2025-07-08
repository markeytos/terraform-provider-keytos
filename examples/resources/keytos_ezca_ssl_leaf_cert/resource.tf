resource "keytos_ezca_ssl_leaf_cert" "example" {
  authority_id     = var.authority_id
  template_id      = var.template_id
  cert_request_pem = file("cert_request.pem")
  validity_period  = "336h" # 14d
  overwrite_subject_name = {
    common_name  = "Test 101"
    organization = "Keytos"
  }
  early_renewal_period = "24h" # 1d
}

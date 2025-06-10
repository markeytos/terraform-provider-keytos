// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/markeytos/terraform-provider-keytos/internal/acctest"
)

const (
	test_authority_id = "6ffae128-1999-43fa-91f2-7ac1ab35b965"
	test_template_id  = "e6b6f458-ca44-4c43-b639-7d1fc601781d"
)

var ProtoV6ProviderFactories = acctest.ProtoV6ProviderFactories(map[string]func() provider.Provider{"keytos": New("test")})

// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// KeytosProvider defines the provider implementation.
type KeytosProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// KeytosProviderModel describes the provider data model.
type KeytosProviderModel struct {
	EZCAUrl types.String `tfsdk:"ezca_url"`
}

func (p *KeytosProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "keytos"
	resp.Version = p.version
}

func (p *KeytosProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"ezca_url": schema.StringAttribute{
				MarkdownDescription: "EZCA instance URL",
				Required:            true,
			},
		},
	}
}

func (p *KeytosProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data KeytosProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Configuration values are now available.
	// if data.Endpoint.IsNull() { /* ... */ }

	// Example client configuration for data sources and resources
	client := http.DefaultClient
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *KeytosProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewKeytosEzcaSslLeafCertResource,
	}
}

func (p *KeytosProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewKeytosEzcaSslAuthorityDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &KeytosProvider{
			version: version,
		}
	}
}

// Ensure KeytosProvider satisfies provider interface.
var _ provider.Provider = &KeytosProvider{}

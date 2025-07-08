// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/markeytos/ezca-go"
)

const defaultEzcaURL = "portal.ezca.io"

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
				Optional:            true,
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

	ezcaURL := data.EZCAUrl.ValueString()
	if ezcaURL == "" {
		ezcaURL = defaultEzcaURL
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		resp.Diagnostics.AddError("Could not get azure credential", fmt.Sprintf("Could not get Azure credential: %v", err))
		return
	}
	c, err := ezca.NewClient(ezcaURL, cred)
	if err != nil {
		resp.Diagnostics.AddError("Could not initialize EZCA client", fmt.Sprintf("EZCA Client initialization error: %v", err))
		return
	}

	resp.DataSourceData = c
	resp.ResourceData = c
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

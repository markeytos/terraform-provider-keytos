// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &KeytosEzcaSslAuthorityDataSource{}

func NewKeytosEzcaSslAuthorityDataSource() datasource.DataSource {
	return &KeytosEzcaSslAuthorityDataSource{}
}

// KeytosEzcaSslAuthorityDataSource defines the data source implementation.
type KeytosEzcaSslAuthorityDataSource struct {
	client *http.Client
}

// KeytosEzcaSslAuthorityDataSourceModel describes the data source data model.
type KeytosEzcaSslAuthorityDataSourceModel struct {
	AuthorityId types.String `tfsdk:"authority_id"`
	TemplateId  types.String `tfsdk:"template_id"`
}

func (d *KeytosEzcaSslAuthorityDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ezca_ssl_authority"
}

func (d *KeytosEzcaSslAuthorityDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "EZCA SSL authority data source",

		Attributes: map[string]schema.Attribute{
			"authority_id": schema.StringAttribute{
				MarkdownDescription: "EZCA SSL authority identifier",
				Required:            true,
			},
			"template_id": schema.StringAttribute{
				MarkdownDescription: "EZCA authority SSL template identifier",
				Required:            true,
			},

			"key_algorithm": schema.StringAttribute{
				MarkdownDescription: "Key algorithms of the authority",
				Computed:            true,
			},
			"subject_name_str": schema.StringAttribute{
				MarkdownDescription: "Subject Name of the authority as a string.",
				Computed:            true,
			},
			"validity_not_before": schema.StringAttribute{
				MarkdownDescription: "Time after which the certificate is valid as an RFC3339 timestamp. Validity start time stamp.",
				Computed:            true,
			},
			"validity_not_after": schema.StringAttribute{
				MarkdownDescription: "Time prior which the certificate is valid as an RFC3339 timestamp. Expiration time stamp.",
				Computed:            true,
			},
			"is_root": schema.BoolAttribute{
				MarkdownDescription: "Whether the authority is a root certificate",
				Computed:            true,
			},
			"issuer_authority": schema.ObjectAttribute{
				AttributeTypes: map[string]attr.Type{
					"authority_id":        types.StringType,
					"template_id":         types.StringType,
					"subject_name":        types.StringType,
					"validity_not_before": types.StringType,
					"validity_not_after":  types.StringType,
				},
				MarkdownDescription: "If authority is not root, contain information about the issuer",
				Computed:            true,
				Optional:            true,
			},
		},
	}
}

func (d *KeytosEzcaSslAuthorityDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*http.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *http.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func (d *KeytosEzcaSslAuthorityDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data KeytosEzcaSslAuthorityDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// If applicable, this is a great opportunity to initialize any necessary
	// provider client data and make a call using it.
	// httpResp, err := d.client.Do(httpReq)
	// if err != nil {
	//     resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read example, got error: %s", err))
	//     return
	// }

	// Write logs using the tflog package
	// Documentation: https://terraform.io/plugin/log
	tflog.Trace(ctx, "read a data source")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

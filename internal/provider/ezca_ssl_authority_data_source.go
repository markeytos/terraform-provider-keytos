// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/markeytos/ezca-go"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &KeytosEzcaSslAuthorityDataSource{}

func NewKeytosEzcaSslAuthorityDataSource() datasource.DataSource {
	return &KeytosEzcaSslAuthorityDataSource{}
}

// KeytosEzcaSslAuthorityDataSource defines the data source implementation.
type KeytosEzcaSslAuthorityDataSource struct {
	client *ezca.Client
}

// KeytosEzcaSslAuthorityDataSourceModel describes the data source data model.
type KeytosEzcaSslAuthorityDataSourceModel struct {
	AuthorityId     types.String `tfsdk:"authority_id"`
	TemplateId      types.String `tfsdk:"template_id"`
	KeyAlgorithm    types.String `tfsdk:"key_algorithm"`
	SubjectName     types.String `tfsdk:"subject_name_str"`
	IsRoot          types.Bool   `tfsdk:"is_root"`
	IssuerAuthority types.Object `tfsdk:"issuer_authority"`
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
			"is_root": schema.BoolAttribute{
				MarkdownDescription: "Whether the authority is a root certificate",
				Computed:            true,
			},
			"issuer_authority": schema.ObjectAttribute{
				AttributeTypes: map[string]attr.Type{
					"authority_id": types.StringType,
					"template_id":  types.StringType,
					"subject_name": types.StringType,
				},
				MarkdownDescription: "If authority is not root, contain information about the issuer",
				Computed:            true,
				Optional:            true,
			},
		},
	}
}

func (d *KeytosEzcaSslAuthorityDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	data, ok := req.ProviderData.(*KeytosData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *KeytosData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = data.EZCAClient
}

func (d *KeytosEzcaSslAuthorityDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data KeytosEzcaSslAuthorityDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	authorityId, err := uuid.Parse(data.AuthorityId.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Authority ID", fmt.Sprintf("Expected a valid UUID for Authority ID, got %s: %v", authorityId, err))
		return
	}

	templateId, err := uuid.Parse(data.TemplateId.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Template ID", fmt.Sprintf("Expected a valid UUID for Template ID, got %s: %v", templateId, err))
		return
	}

	authority := ezca.NewSSLAuthority(authorityId, templateId)
	_, err = ezca.NewSSLAuthorityClient(d.client, authority)
	if err != nil {
		resp.Diagnostics.AddError("Invalid SSL authority", fmt.Sprintf("Error validating SSL Authority: %v", err))
		return
	}

	// TODO: populate the following from data
	// KeyAlgorithm
	// SubjectName
	// IsRoot
	// IssuerAuthority

	tflog.Trace(ctx, "read a ssl authority data source")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

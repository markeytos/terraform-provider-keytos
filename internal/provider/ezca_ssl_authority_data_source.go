// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/google/uuid"
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

// KeytosEzcaSslAuthorityModel describes the data source data model.
type KeytosEzcaSslAuthorityDataSourceModel struct {
	AuthorityID   types.String `tfsdk:"authority_id"`
	TemplateID    types.String `tfsdk:"template_id"`
	KeyType       types.String `tfsdk:"key_type"`
	HashAlgorithm types.String `tfsdk:"hash_algorithm"`
	IsPublic      types.Bool   `tfsdk:"is_public"`
	IsRoot        types.Bool   `tfsdk:"is_root"`
	// NOTE: set subject name and issuer authority below when uncommented
	// SubjectName     types.String `tfsdk:"subject_name_str"`
	// IssuerAuthority types.Object `tfsdk:"issuer_authority"`
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

			"key_type": schema.StringAttribute{
				MarkdownDescription: "Key type of the authority",
				Computed:            true,
			},
			"hash_algorithm": schema.StringAttribute{
				MarkdownDescription: "Hash algorithms of the authority",
				Computed:            true,
			},
			"is_public": schema.BoolAttribute{
				MarkdownDescription: "Whether the authority is a public certificate",
				Computed:            true,
			},
			"is_root": schema.BoolAttribute{
				MarkdownDescription: "Whether the authority is a root certificate",
				Computed:            true,
			},
			// NOTE: uncomment when data source model uncomment these
			// "subject_name_str": schema.StringAttribute{
			// 	MarkdownDescription: "Subject Name of the authority as a string.",
			// 	Computed:            true,
			// },
			// "issuer_authority": schema.ObjectAttribute{
			// 	AttributeTypes: map[string]attr.Type{
			// 		"authority_id": types.StringType,
			// 		"template_id":  types.StringType,
			// 		"subject_name": types.StringType,
			// 	},
			// 	MarkdownDescription: "If authority is not root, contain information about the issuer",
			// 	Computed:            true,
			// 	Optional:            true,
			// },
		},
	}
}

func (d *KeytosEzcaSslAuthorityDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*ezca.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *KeytosData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func (d *KeytosEzcaSslAuthorityDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data KeytosEzcaSslAuthorityDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	authorityId, err := uuid.Parse(data.AuthorityID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Authority ID", fmt.Sprintf("Expected a valid UUID for Authority ID, got %s: %v", authorityId, err))
	}
	templateId, err := uuid.Parse(data.TemplateID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Template ID", fmt.Sprintf("Expected a valid UUID for Template ID, got %s: %v", templateId, err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := ezca.NewSSLAuthorityClient(ctx, d.client, authorityId, templateId)
	if err != nil {
		resp.Diagnostics.AddError("Invalid SSL authority", fmt.Sprintf("Error validating SSL Authority: %v", err))
		return
	}

	info, err := c.Info(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Invalid SSL authority", fmt.Sprintf("Error getting SSL Authority information: %v", err))
		return
	}

	data.KeyType = types.StringValue(string(info.KeyType))
	data.HashAlgorithm = types.StringValue(string(info.HashAlgorithm))
	data.IsPublic = types.BoolValue(info.IsPublic)
	data.IsRoot = types.BoolValue(info.IsRoot)
	// NOTE: set subject name and issuer authority when uncommented

	tflog.Trace(ctx, "read a ssl authority data source")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

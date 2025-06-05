// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/markeytos/ezca-go"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &KeytosEzcaSslLeafCertResource{}

func NewKeytosEzcaSslLeafCertResource() resource.Resource {
	return &KeytosEzcaSslLeafCertResource{}
}

// KeytosEzcaSslLeafCertResource defines the resource implementation.
type KeytosEzcaSslLeafCertResource struct {
	client *ezca.Client
}

// KeytosEzcaSslLeafCertResourceModel describes the resource data model.
type KeytosEzcaSslLeafCertResourceModel struct {
	AuthorityId                       types.String `tfsdk:"authority_id"`
	TemplateId                        types.String `tfsdk:"template_id"`
	CertRequestPEM                    types.String `tfsdk:"cert_request_pem"`
	ValidityPeriod                    types.String `tfsdk:"validity_period"`
	KeyUsages                         types.String `tfsdk:"key_usages"`
	ExtendedKeyUsages                 types.List   `tfsdk:"extended_key_usages"`
	OverwriteSubjectName              types.Object `tfsdk:"overwrite_subject_name"`
	OverwriteSubjectNameStr           types.String `tfsdk:"overwrite_subject_name_str"`
	AdditionalSubjectAlternativeNames types.Object `tfsdk:"additional_subject_alternative_names"`
	EarlyRenewalPeriod                types.String `tfsdk:"early_renewal_period"`
	CertPEM                           types.String `tfsdk:"cert_pem"`
	CertSerialNumber                  types.String `tfsdk:"cert_serial_number"`
	ReadyForRenewal                   types.Bool   `tfsdk:"ready_for_renewal"`
	ValidityNotBefore                 types.String `tfsdk:"validity_not_before"`
	ValidityNotAfter                  types.String `tfsdk:"validity_not_after"`
}

func (r *KeytosEzcaSslLeafCertResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ezca_ssl_leaf_cert"
}

func (r *KeytosEzcaSslLeafCertResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Crates a leaf certificate that is issued by an EZCA SSL authority. If the resource is deleted prior to expiration, it will be revoked.",

		Attributes: map[string]schema.Attribute{
			"authority_id": schema.StringAttribute{
				MarkdownDescription: "EZCA SSL authority identifier",
				Required:            true,
			},
			"template_id": schema.StringAttribute{
				MarkdownDescription: "EZCA authority SSL template identifier",
				Required:            true,
			},
			"cert_request_pem": schema.StringAttribute{
				MarkdownDescription: "Certificate request data in PEM format",
				Required:            true,
			},
			"validity_period": schema.StringAttribute{
				MarkdownDescription: "Validity period that the certificate will remain valid for",
				Required:            true,
			},

			"key_usages": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of key usages", // TODO: show default
				Optional:            true,
			},
			"extended_key_usages": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of extended key usages", // TODO: show default
				Optional:            true,
			},
			"overwrite_subject_name": schema.ObjectAttribute{
				AttributeTypes: map[string]attr.Type{
					"common_name":         types.StringType,
					"country":             types.ListType{ElemType: types.StringType},
					"organization":        types.ListType{ElemType: types.StringType},
					"organizational_unit": types.ListType{ElemType: types.StringType},
					"locality":            types.ListType{ElemType: types.StringType},
					"province":            types.ListType{ElemType: types.StringType},
					"street_address":      types.ListType{ElemType: types.StringType},
					"postal_code":         types.ListType{ElemType: types.StringType},
				},
				MarkdownDescription: "Set to override the Subject Name of the certificate structurally. Can only define one of `overwrite_subject_name` or `overwrite_subject_name_str`.",
				Optional:            true,
			},
			"overwrite_subject_name_str": schema.StringAttribute{
				MarkdownDescription: "Set to override the Subject Name of the certificate as a string. Can only define one of `overwrite_subject_name` or `overwrite_subject_name_str`.",
				Optional:            true,
			},
			"additional_subject_alternative_names": schema.ObjectAttribute{
				AttributeTypes: map[string]attr.Type{
					"dns_names":       types.ListType{ElemType: types.StringType},
					"email_addresses": types.ListType{ElemType: types.StringType},
					"ip_addresses":    types.ListType{ElemType: types.StringType},
					"uris":            types.ListType{ElemType: types.StringType},
				},
				MarkdownDescription: "Additional subject alternative names to add to the certificate",
				Optional:            true,
			},
			"early_renewal_period": schema.StringAttribute{
				MarkdownDescription: "Resource will consider the leaf certificate ready for renewal early by the duration defined here. This can be used to update the resource-managed certificate when close to expiring when it is applied during the early renewal period.",
				Optional:            true,
			},

			"cert_pem": schema.StringAttribute{
				MarkdownDescription: "Certificate data in PEM format.",
				Computed:            true,
			},
			"cert_serial_number": schema.StringAttribute{
				MarkdownDescription: "Certificate serial number. The unique identifier for this resource.",
				Computed:            true,
			},
			"ready_for_renewal": schema.BoolAttribute{
				MarkdownDescription: "True when the certificate is expired or when in the early renewal period.",
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
		},
	}
}

func (r *KeytosEzcaSslLeafCertResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	data, ok := req.ProviderData.(*KeytosData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *KeytosData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = data.EZCAClient
}

func (r *KeytosEzcaSslLeafCertResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KeytosEzcaSslLeafCertResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TODO: Read model: Populate it

	// If applicable, this is a great opportunity to initialize any necessary
	// provider client data and make a call using it.
	// httpResp, err := r.client.Do(httpReq)
	// if err != nil {
	//     resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create example, got error: %s", err))
	//     return
	// }

	// For the purposes of this example code, hardcoding a response value to
	// save into the Terraform state.
	// data.Id = types.StringValue("example-id")

	tflog.Trace(ctx, "created a resource")

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeytosEzcaSslLeafCertResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KeytosEzcaSslLeafCertResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TODO: Read state: Check state

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeytosEzcaSslLeafCertResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data KeytosEzcaSslLeafCertResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TODO: Read state: Check state and view if renewable. If renewable, sign again

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeytosEzcaSslLeafCertResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KeytosEzcaSslLeafCertResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TODO: Read state: Initialize client and delete
}

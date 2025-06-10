// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2025 Keytos
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/markeytos/ezca-go"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &KeytosEzcaSslLeafCertResource{}

func NewKeytosEzcaSslLeafCertResource() resource.Resource {
	return &KeytosEzcaSslLeafCertResource{}
}

// KeytosEzcaSslLeafCert defines the resource implementation.
type KeytosEzcaSslLeafCertResource struct {
	client *ezca.Client
}

// KeytosEzcaSslLeafCertModel describes the resource data model.
type KeytosEzcaSslLeafCertResourceModel struct {
	AuthorityID    types.String `tfsdk:"authority_id"`
	TemplateID     types.String `tfsdk:"template_id"`
	CertRequestPEM types.String `tfsdk:"cert_request_pem"`
	ValidityPeriod types.String `tfsdk:"validity_period"`

	KeyUsages                         types.List   `tfsdk:"key_usages"`
	ExtendedKeyUsages                 types.List   `tfsdk:"extended_key_usages"`
	OverwriteSubjectName              types.Object `tfsdk:"overwrite_subject_name"`
	OverwriteSubjectNameStr           types.String `tfsdk:"overwrite_subject_name_str"`
	AdditionalSubjectAlternativeNames types.Object `tfsdk:"additional_subject_alternative_names"`
	EarlyRenewalPeriod                types.String `tfsdk:"early_renewal_period"`

	CertPEM           types.String `tfsdk:"cert_pem"`
	CertThumbprintHex types.String `tfsdk:"cert_thumbprint_hex"`
	CertSerialNumber  types.String `tfsdk:"cert_serial_number"`
	ReadyForRenewal   types.Bool   `tfsdk:"ready_for_renewal"`
	ValidityNotBefore types.String `tfsdk:"validity_not_before"`
	ValidityNotAfter  types.String `tfsdk:"validity_not_after"`
}

type SubjectNameAttributeModel struct {
	CommonName         types.String `tfsdk:"common_name"`
	Country            types.List   `tfsdk:"country"`
	Organization       types.List   `tfsdk:"organization"`
	OrganizationalUnit types.List   `tfsdk:"organizational_unit"`
	Locality           types.List   `tfsdk:"locality"`
	Province           types.List   `tfsdk:"province"`
	StreetAddress      types.List   `tfsdk:"street_address"`
	PostalCode         types.List   `tfsdk:"postal_code"`
}

type SubjectAlternativeNamesAttributeModel struct {
	DNSNames       types.List `tfsdk:"dns_names"`
	EmailAddresses types.List `tfsdk:"email_addresses"`
	IPAddresses    types.List `tfsdk:"ip_addresses"`
	URIs           types.List `tfsdk:"uris"`
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
				MarkdownDescription: "List of key usages. Defaults to key encipherment and digital signature.",
				Optional:            true,
				Computed:            true,
			},
			"extended_key_usages": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of extended key usages. Defaults to server authentication and client authentication.",
				Optional:            true,
				Computed:            true,
			},
			"overwrite_subject_name": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"common_name": schema.StringAttribute{Optional: true},
					"country": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"organization": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"organizational_unit": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"locality": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"province": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"street_address": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"postal_code": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
				},
				MarkdownDescription: "Set to override the Subject Name of the certificate structurally. Can only define one of `overwrite_subject_name` or `overwrite_subject_name_str`.",
				Optional:            true,
				Computed:            true,
			},
			"overwrite_subject_name_str": schema.StringAttribute{
				MarkdownDescription: "Set to override the Subject Name of the certificate as a string. Can only define one of `overwrite_subject_name` or `overwrite_subject_name_str`.",
				Optional:            true,
				Computed:            true,
			},
			"additional_subject_alternative_names": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"dns_names": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"email_addresses": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"ip_addresses": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"uris": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
				},
				MarkdownDescription: "Additional subject alternative names to add to the certificate",
				Optional:            true,
				Computed:            true,
			},
			"early_renewal_period": schema.StringAttribute{
				MarkdownDescription: "Resource will consider the leaf certificate ready for renewal early by the duration defined here. This can be used to update the resource-managed certificate when close to expiring when it is applied during the early renewal period.",
				Optional:            true,
				Computed:            true,
			},

			"cert_pem": schema.StringAttribute{
				MarkdownDescription: "Certificate data in PEM format.",
				Computed:            true,
			},
			"cert_thumbprint_hex": schema.StringAttribute{
				MarkdownDescription: "Certificate thumbprint. This is a SHA-1 sum of the raw certificate contents.",
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

	client, ok := req.ProviderData.(*ezca.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *KeytosData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *KeytosEzcaSslLeafCertResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KeytosEzcaSslLeafCertResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := r.sslAuthorityClient(ctx, &data)
	if err != nil {
		resp.Diagnostics.AddError("Error creating SSL authority client", fmt.Sprintf("Errors encountered creating SSL authority client: %v", err))
		return
	}

	csr, err := csr(data.CertRequestPEM.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Certificate Request PEM", fmt.Sprintf("Error raised when getting CSR PEM: %v", err))
		return
	}

	signOptions := buildSignOptions(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "validated inputs")

	erp := time.Duration(0)
	if !data.EarlyRenewalPeriod.IsUnknown() {
		erp, err = time.ParseDuration(data.EarlyRenewalPeriod.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid Validity Period", fmt.Sprintf("Invalid duration string: %v", err))
			return
		}
	} else {
		data.EarlyRenewalPeriod = types.StringNull()
	}

	if erp > signOptions.Duration {
		resp.Diagnostics.AddError("Invalid Early Renewal Period", "Early renewal period greater than certificate duration")
		return
	}

	certs, err := c.Sign(ctx, csr, signOptions)
	if err != nil {
		resp.Diagnostics.AddError("Error Signing", fmt.Sprintf("Error signing CSR: %v", err))
		return
	}
	saveCertificate(&data, certs[0], erp)
	tflog.Trace(ctx, "signed certificate request")

	tflog.Trace(ctx, "created a resource")

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeytosEzcaSslLeafCertResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KeytosEzcaSslLeafCertResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := r.sslAuthorityClient(ctx, &data)
	if err != nil {
		resp.Diagnostics.AddError("Error creating SSL authority client", fmt.Sprintf("Errors encountered creating SSL authority client: %v", err))
		return
	}

	notAfterStr := data.ValidityNotAfter.ValueString()
	notAfter, err := time.Parse(time.RFC3339, notAfterStr)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Internal State",
			fmt.Sprintf("Invalid certificate expiration time stamp: %q: %v", notAfterStr, err),
		)
		return
	}

	erp := time.Duration(0)
	if data.EarlyRenewalPeriod.IsUnknown() {
		resp.Diagnostics.AddError(
			"Invalid Internal State",
			"Invalid certificate early renewal period: unknown",
		)
		return
	}
	if !data.EarlyRenewalPeriod.IsNull() {
		erp, err = time.ParseDuration(data.EarlyRenewalPeriod.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid Validity Period", fmt.Sprintf("Invalid duration string: %v", err))
		}
	}

	renewal := readyForRenewal(notAfter, erp)

	if renewal {
		csr, err := csr(data.CertRequestPEM.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid Certificate Request PEM", fmt.Sprintf("Error raised when getting CSR PEM: %v", err))
			return
		}
		signOptions := buildSignOptions(ctx, &data, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		tflog.Trace(ctx, "fetched existing CSR and sign options")

		certs, err := c.Sign(ctx, csr, signOptions)
		if err != nil {
			resp.Diagnostics.AddError("Error Renewing Certificate", fmt.Sprintf("Error signing CSR: %v", err))
			return
		}
		saveCertificate(&data, certs[0], erp)
		tflog.Trace(ctx, "renewed certificate")
	} else {
		data.ReadyForRenewal = types.BoolValue(renewal)
	}

	tflog.Trace(ctx, "read and updated the resource")

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeytosEzcaSslLeafCertResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var newm, oldm KeytosEzcaSslLeafCertResourceModel
	var err error

	resp.Diagnostics.Append(req.Plan.Get(ctx, &newm)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &oldm)...)
	if resp.Diagnostics.HasError() {
		return
	}

	csr, err := csr(newm.CertRequestPEM.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid Certificate Request PEM", fmt.Sprintf("Error raised when getting CSR PEM: %v", err))
		return
	}

	signOptions := buildSignOptions(ctx, &newm, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	erp := time.Duration(0)
	if !newm.EarlyRenewalPeriod.IsUnknown() {
		erp, err = time.ParseDuration(newm.EarlyRenewalPeriod.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid Validity Period", fmt.Sprintf("Invalid duration string: %v", err))
			return
		}
	} else {
		newm.EarlyRenewalPeriod = types.StringNull()
	}

	if erp > signOptions.Duration {
		resp.Diagnostics.AddError("Invalid Early Renewal Period", "Early renewal period greater than certificate duration")
		return
	}

	if requireNewCertificate(newm, oldm) {
		c, err := r.sslAuthorityClient(ctx, &oldm)
		if err != nil {
			resp.Diagnostics.AddError("Error creating SSL authority client", fmt.Sprintf("Errors encountered creating SSL authority client: %v", err))
			return
		}
		thumbHex := oldm.CertThumbprintHex.ValueString()
		thumb, err := hex.DecodeString(thumbHex)
		if err != nil {
			resp.Diagnostics.AddError("Invalid Certificate Thumbprint", fmt.Sprintf("Error retrieving certificate thumbprint: thumbprint %q: %v", thumbHex, err))
			return
		}
		err = c.RevokeWithThumbprint(ctx, [20]byte(thumb))
		if err != nil {
			resp.Diagnostics.AddError("Error Revoking Certificate", fmt.Sprintf("Encountered an error when trying to revoke the old certificate: %v", err))
		}

		c, err = r.sslAuthorityClient(ctx, &newm)
		if err != nil {
			resp.Diagnostics.AddError("Error creating SSL authority client", fmt.Sprintf("Errors encountered creating SSL authority client: %v", err))
			return
		}

		certs, err := c.Sign(ctx, csr, signOptions)
		if err != nil {
			resp.Diagnostics.AddError("Error Signing", fmt.Sprintf("Error signing CSR: %v", err))
			return
		}
		saveCertificate(&newm, certs[0], erp)

		tflog.Trace(ctx, "updated the resource with new certificate")
		resp.Diagnostics.Append(resp.State.Set(ctx, &newm)...)
	} else {
		notAfterStr := oldm.ValidityNotAfter.ValueString()
		notAfter, err := time.Parse(time.RFC3339, notAfterStr)
		if err != nil {
			resp.Diagnostics.AddError(
				"Invalid Internal State",
				fmt.Sprintf("Invalid certificate expiration time stamp: %q: %v", notAfterStr, err),
			)
			return
		}

		if readyForRenewal(notAfter, erp) {
			c, err := r.sslAuthorityClient(ctx, &newm)
			if err != nil {
				resp.Diagnostics.AddError("Error creating SSL authority client", fmt.Sprintf("Errors encountered creating SSL authority client: %v", err))
				return
			}

			thumbHex := oldm.CertThumbprintHex.ValueString()
			thumb, err := hex.DecodeString(thumbHex)
			if err != nil {
				resp.Diagnostics.AddError("Invalid Certificate Thumbprint", fmt.Sprintf("Error retrieving certificate thumbprint: thumbprint %q: %v", thumbHex, err))
				return
			}

			err = c.RevokeWithThumbprint(ctx, [20]byte(thumb))
			if err != nil {
				resp.Diagnostics.AddError("Error Revoking Certificate", fmt.Sprintf("Encountered an error when trying to revoke the certificate: %v", err))
			}

			certs, err := c.Sign(ctx, csr, signOptions)
			if err != nil {
				resp.Diagnostics.AddError("Error Renewing Certificate", fmt.Sprintf("Error signing CSR: %v", err))
				return
			}
			saveCertificate(&newm, certs[0], erp)
			tflog.Trace(ctx, "renewed certificate")
		} else {
			newm.CertPEM = types.StringValue(oldm.CertPEM.ValueString())
			newm.CertThumbprintHex = types.StringValue(oldm.CertThumbprintHex.ValueString())
			newm.CertSerialNumber = types.StringValue(oldm.CertSerialNumber.ValueString())
			newm.ReadyForRenewal = types.BoolValue(false)
			newm.ValidityNotBefore = types.StringValue(oldm.ValidityNotBefore.ValueString())
			newm.ValidityNotAfter = types.StringValue(oldm.ValidityNotAfter.ValueString())
		}

		tflog.Trace(ctx, "updated the resource")
		resp.Diagnostics.Append(resp.State.Set(ctx, &newm)...)
	}
}

func (r *KeytosEzcaSslLeafCertResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KeytosEzcaSslLeafCertResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := r.sslAuthorityClient(ctx, &data)
	if err != nil {
		resp.Diagnostics.AddError("Error creating SSL authority client", fmt.Sprintf("Errors encountered creating SSL authority client: %v", err))
		return
	}

	thumbHex := data.CertThumbprintHex.ValueString()
	thumb, err := hex.DecodeString(thumbHex)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Certificate Thumbprint", fmt.Sprintf("Error retrieving certificate thumbprint: thumbprint %q: %v", thumbHex, err))
		return
	}

	tflog.Trace(ctx, "deleted the resource")

	err = c.RevokeWithThumbprint(ctx, [20]byte(thumb))
	if err != nil {
		resp.Diagnostics.AddError("Error Revoking Certificate", fmt.Sprintf("Encountered an error when trying to revoke the certificate: %v", err))
	}
}

func (r *KeytosEzcaSslLeafCertResource) sslAuthorityClient(ctx context.Context, data *KeytosEzcaSslLeafCertResourceModel) (c *ezca.SSLAuthorityClient, err error) {
	authorityId, e := uuid.Parse(data.AuthorityID.ValueString())
	if e != nil {
		err = errors.Join(err, fmt.Errorf("expected a valid UUID for Authority ID, got %s: %w", authorityId, e))
	}
	templateId, e := uuid.Parse(data.TemplateID.ValueString())
	if e != nil {
		err = errors.Join(err, fmt.Errorf("expected a valid UUID for Template ID, got %s: %w", templateId, e))
	}
	if err != nil {
		return
	}

	c, e = ezca.NewSSLAuthorityClient(ctx, r.client, authorityId, templateId)
	if e != nil {
		err = errors.Join(err, fmt.Errorf("error getting SSL Authority client: %w", e))
	}
	return
}

func csr(s string) ([]byte, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("no valid PEM block passed as certificate request")
	}
	if b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("passed PEM block is not of certificate request type")
	}
	return b.Bytes, nil
}

func buildSignOptions(ctx context.Context, m *KeytosEzcaSslLeafCertResourceModel, diags *diag.Diagnostics) *ezca.SignOptions {
	var e error
	var listVals []types.String
	signOptions := &ezca.SignOptions{SourceTag: "keytos terraform provider"}

	signOptions.Duration, e = time.ParseDuration(m.ValidityPeriod.ValueString())
	if e != nil {
		diags.AddError("Invalid Duration String", fmt.Sprintf("Invalid duration string: %v", e))
		return nil
	}

	if !m.KeyUsages.IsUnknown() {
		if m.KeyUsages.ElementType(ctx) != types.StringType {
			diags.AddError("Invalid Key Usages", "Passed key usages must be strings")
			return nil
		}
		listVals = make([]types.String, 0, len(m.KeyUsages.Elements()))
		signOptions.KeyUsages = make([]ezca.KeyUsage, 0, len(m.KeyUsages.Elements()))
		m.KeyUsages.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			signOptions.KeyUsages = append(signOptions.KeyUsages, ezca.KeyUsage(v.ValueString()))
		}
	} else {
		m.KeyUsages, _ = types.ListValue(types.StringType, []attr.Value{
			types.StringValue(string(ezca.KeyUsageKeyEncipherment)),
			types.StringValue(string(ezca.KeyUsageDigitalSignature)),
		})
	}
	if !m.ExtendedKeyUsages.IsUnknown() {
		if m.ExtendedKeyUsages.ElementType(ctx) != types.StringType {
			diags.AddError("Invalid Extended Key Usages", "Passed extended key usages must be strings")
			return nil
		}
		listVals = make([]types.String, 0, len(m.ExtendedKeyUsages.Elements()))
		signOptions.ExtendedKeyUsages = make([]ezca.ExtKeyUsage, 0, len(m.ExtendedKeyUsages.Elements()))
		m.ExtendedKeyUsages.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			signOptions.ExtendedKeyUsages = append(signOptions.ExtendedKeyUsages, ezca.ExtKeyUsage(v.ValueString()))
		}
	} else {
		m.ExtendedKeyUsages, _ = types.ListValue(types.StringType, []attr.Value{
			types.StringValue(string(ezca.ExtKeyUsageServerAuth)),
			types.StringValue(string(ezca.ExtKeyUsageClientAuth)),
		})
	}
	if !m.OverwriteSubjectName.IsUnknown() {
		var snm SubjectNameAttributeModel
		diag := m.OverwriteSubjectName.As(ctx, &snm, basetypes.ObjectAsOptions{})
		diags.Append(diag...)
		if diags.HasError() {
			return nil
		}

		sn := pkix.Name{CommonName: snm.CommonName.String()}

		listVals = make([]types.String, 0, len(snm.Country.Elements()))
		sn.Country = make([]string, 0, len(snm.Country.Elements()))
		snm.Country.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			sn.Country = append(sn.Country, v.ValueString())
		}

		listVals = make([]types.String, 0, len(snm.Organization.Elements()))
		sn.Organization = make([]string, 0, len(snm.Organization.Elements()))
		snm.Organization.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			sn.Organization = append(sn.Organization, v.ValueString())
		}

		listVals = make([]types.String, 0, len(snm.OrganizationalUnit.Elements()))
		sn.OrganizationalUnit = make([]string, 0, len(snm.OrganizationalUnit.Elements()))
		snm.OrganizationalUnit.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			sn.OrganizationalUnit = append(sn.OrganizationalUnit, v.ValueString())
		}

		listVals = make([]types.String, 0, len(snm.Locality.Elements()))
		sn.Locality = make([]string, 0, len(snm.Locality.Elements()))
		snm.Locality.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			sn.Locality = append(sn.Locality, v.ValueString())
		}

		listVals = make([]types.String, 0, len(snm.Province.Elements()))
		sn.Province = make([]string, 0, len(snm.Province.Elements()))
		snm.Province.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			sn.Province = append(sn.Province, v.ValueString())
		}

		listVals = make([]types.String, 0, len(snm.StreetAddress.Elements()))
		sn.StreetAddress = make([]string, 0, len(snm.StreetAddress.Elements()))
		snm.StreetAddress.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			sn.StreetAddress = append(sn.StreetAddress, v.ValueString())
		}

		listVals = make([]types.String, 0, len(snm.PostalCode.Elements()))
		sn.PostalCode = make([]string, 0, len(snm.PostalCode.Elements()))
		snm.PostalCode.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			sn.PostalCode = append(sn.PostalCode, v.ValueString())
		}

		signOptions.SubjectName = sn.String()
	} else {
		m.OverwriteSubjectName = types.ObjectNull(map[string]attr.Type{
			"common_name":         types.StringType,
			"country":             types.ListType{ElemType: types.StringType},
			"organization":        types.ListType{ElemType: types.StringType},
			"organizational_unit": types.ListType{ElemType: types.StringType},
			"locality":            types.ListType{ElemType: types.StringType},
			"province":            types.ListType{ElemType: types.StringType},
			"street_address":      types.ListType{ElemType: types.StringType},
			"postal_code":         types.ListType{ElemType: types.StringType},
		})
	}
	if !m.OverwriteSubjectNameStr.IsUnknown() {
		if signOptions.SubjectName != "" {
			diags.AddError("Invalid Overwrite Subject Name", "Only one of \"overwrite_subject_name\" or \"overwrite_subject_name_str\" can be defined")
			return nil
		}
		signOptions.SubjectName = m.OverwriteSubjectNameStr.ValueString()
	} else {
		m.OverwriteSubjectNameStr = types.StringNull()
	}
	if !m.AdditionalSubjectAlternativeNames.IsUnknown() {
		var sanm SubjectAlternativeNamesAttributeModel
		e := m.AdditionalSubjectAlternativeNames.As(ctx, &sanm, basetypes.ObjectAsOptions{})
		if e != nil {
			diags.AddError("Invalid Subject Alternative Names", fmt.Sprintf("Unknown subject alternative name format: %v", e))
			return nil
		}

		listVals = make([]types.String, 0, len(sanm.DNSNames.Elements()))
		signOptions.DNSNames = make([]string, 0, len(sanm.DNSNames.Elements()))
		sanm.DNSNames.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			signOptions.DNSNames = append(signOptions.DNSNames, v.ValueString())
		}

		listVals = make([]types.String, 0, len(sanm.EmailAddresses.Elements()))
		signOptions.EmailAddresses = make([]string, 0, len(sanm.EmailAddresses.Elements()))
		sanm.EmailAddresses.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			signOptions.EmailAddresses = append(signOptions.EmailAddresses, v.ValueString())
		}

		listVals = make([]types.String, 0, len(sanm.IPAddresses.Elements()))
		signOptions.IPAddresses = make([]net.IP, 0, len(sanm.IPAddresses.Elements()))
		sanm.IPAddresses.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			ip := net.ParseIP(v.ValueString())
			if ip == nil {
				diags.AddError("Invalid Subject Alternative Name", fmt.Sprintf("Invalid IP string: %q", v.ValueString()))
			} else {
				signOptions.IPAddresses = append(signOptions.IPAddresses, ip)
			}
		}

		listVals = make([]types.String, 0, len(sanm.URIs.Elements()))
		signOptions.URIs = make([]*url.URL, 0, len(sanm.URIs.Elements()))
		sanm.URIs.ElementsAs(ctx, &listVals, false)
		for _, v := range listVals {
			uri, e := url.Parse(v.ValueString())
			if e != nil {
				diags.AddError("Invalid Subject Alternative Name", fmt.Sprintf("Invalid URI string: %q: %v", v.ValueString(), e))
			} else {
				signOptions.URIs = append(signOptions.URIs, uri)
			}
		}
	} else {
		m.AdditionalSubjectAlternativeNames = types.ObjectNull(map[string]attr.Type{
			"dns_names":       types.ListType{ElemType: types.StringType},
			"email_addresses": types.ListType{ElemType: types.StringType},
			"ip_addresses":    types.ListType{ElemType: types.StringType},
			"uris":            types.ListType{ElemType: types.StringType},
		})
	}

	return signOptions
}

func readyForRenewal(notAfter time.Time, earlyRenewalPeriod time.Duration) bool {
	return notAfter.Add(-earlyRenewalPeriod).Before(time.Now())
}

func saveCertificate(m *KeytosEzcaSslLeafCertResourceModel, cert *x509.Certificate, erp time.Duration) {
	thumb := sha1.Sum(cert.Raw)
	m.CertPEM = types.StringValue(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})))
	m.CertThumbprintHex = types.StringValue(hex.EncodeToString(thumb[:]))
	m.CertSerialNumber = types.StringValue(cert.SerialNumber.String())
	m.ValidityNotBefore = types.StringValue(cert.NotBefore.Format(time.RFC3339))
	m.ValidityNotAfter = types.StringValue(cert.NotAfter.Format(time.RFC3339))
	m.ReadyForRenewal = types.BoolValue(readyForRenewal(cert.NotAfter, erp))
}

func requireNewCertificate(left, right KeytosEzcaSslLeafCertResourceModel) bool {
	return !left.AuthorityID.Equal(right.AuthorityID) ||
		!left.TemplateID.Equal(right.TemplateID) ||
		!left.CertRequestPEM.Equal(right.CertRequestPEM) ||
		!left.ValidityPeriod.Equal(right.ValidityPeriod) ||
		!left.KeyUsages.Equal(right.KeyUsages) ||
		!left.ExtendedKeyUsages.Equal(right.ExtendedKeyUsages) ||
		!left.OverwriteSubjectName.Equal(right.OverwriteSubjectName) ||
		!left.OverwriteSubjectNameStr.Equal(right.OverwriteSubjectNameStr) ||
		!left.AdditionalSubjectAlternativeNames.Equal(right.AdditionalSubjectAlternativeNames)
}

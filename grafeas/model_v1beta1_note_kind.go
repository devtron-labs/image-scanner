/*
 * grafeas.proto
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: version not set
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package grafeas
// V1beta1NoteKind : Kind represents the kinds of notes supported.   - NOTE_KIND_UNSPECIFIED: Unknown.  - VULNERABILITY: The note and occurrence represent a package vulnerability.  - BUILD: The note and occurrence assert build provenance.  - IMAGE: This represents an image basis relationship.  - PACKAGE: This represents a package installed via a package manager.  - DEPLOYMENT: The note and occurrence track deployment events.  - DISCOVERY: The note and occurrence track the initial discovery status of a resource.  - ATTESTATION: This represents a logical \"role\" that can attest to artifacts.  - INTOTO: This represents an in-toto link.
type V1beta1NoteKind string

// List of v1beta1NoteKind
const (
	NOTE_KIND_UNSPECIFIED_V1beta1NoteKind V1beta1NoteKind = "NOTE_KIND_UNSPECIFIED"
	VULNERABILITY_V1beta1NoteKind V1beta1NoteKind = "VULNERABILITY"
	BUILD_V1beta1NoteKind V1beta1NoteKind = "BUILD"
	IMAGE_V1beta1NoteKind V1beta1NoteKind = "IMAGE"
	PACKAGE__V1beta1NoteKind V1beta1NoteKind = "PACKAGE"
	DEPLOYMENT_V1beta1NoteKind V1beta1NoteKind = "DEPLOYMENT"
	DISCOVERY_V1beta1NoteKind V1beta1NoteKind = "DISCOVERY"
	ATTESTATION_V1beta1NoteKind V1beta1NoteKind = "ATTESTATION"
	INTOTO_V1beta1NoteKind V1beta1NoteKind = "INTOTO"
)

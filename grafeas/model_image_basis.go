/*
 * grafeas.proto
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: version not set
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package grafeas

// Basis describes the base image portion (Note) of the DockerImage relationship. Linked occurrences are derived from this or an equivalent image via:   FROM <Basis.resource_url> Or an equivalent reference, e.g. a tag of the resource_url.
type ImageBasis struct {
	// Required. Immutable. The resource_url for the resource representing the basis of associated occurrence images.
	ResourceUrl string `json:"resourceUrl,omitempty"`
	// Required. Immutable. The fingerprint of the base image.
	Fingerprint *ImageFingerprint `json:"fingerprint,omitempty"`
}


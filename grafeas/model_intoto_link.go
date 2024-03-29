/*
 * grafeas.proto
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: version not set
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package grafeas

// This corresponds to an in-toto link.
type IntotoLink struct {
	EffectiveCommand []string `json:"effective_command,omitempty"`
	Materials []IntotoLinkArtifact `json:"materials,omitempty"`
	// Products are the supply chain artifacts generated as a result of the step. The structure is identical to that of materials.
	Products []IntotoLinkArtifact `json:"products,omitempty"`
	// ByProducts are data generated as part of a software supply chain step, but are not the actual result of the step.
	Byproducts *LinkByProducts `json:"byproducts,omitempty"`
	Environment *LinkEnvironment `json:"environment,omitempty"`
}

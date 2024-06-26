/*
 * Copyright (c) 2024. Devtron Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * grafeas.proto
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: version not set
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package grafeas

import (
	"time"
)

// A type of analysis that can be done for a resource.
type V1beta1Note struct {
	// Output only. The name of the note in the form of `projects/[PROVIDER_ID]/notes/[NOTE_ID]`.
	Name string `json:"name,omitempty"`
	// A one sentence description of this note.
	ShortDescription string `json:"shortDescription,omitempty"`
	// A detailed description of this note.
	LongDescription string `json:"longDescription,omitempty"`
	// Output only. The type of analysis. This field can be used as a filter in list requests.
	Kind *V1beta1NoteKind `json:"kind,omitempty"`
	// URLs associated with this note.
	RelatedUrl []V1beta1RelatedUrl `json:"relatedUrl,omitempty"`
	// Time of expiration for this note. Empty if note does not expire.
	ExpirationTime time.Time `json:"expirationTime,omitempty"`
	// Output only. The time this note was created. This field can be used as a filter in list requests.
	CreateTime time.Time `json:"createTime,omitempty"`
	// Output only. The time this note was last updated. This field can be used as a filter in list requests.
	UpdateTime time.Time `json:"updateTime,omitempty"`
	// Other notes related to this note.
	RelatedNoteNames []string `json:"relatedNoteNames,omitempty"`
	// A note describing a package vulnerability.
	Vulnerability *VulnerabilityVulnerability `json:"vulnerability,omitempty"`
	// A note describing build provenance for a verifiable build.
	Build *BuildBuild `json:"build,omitempty"`
	// A note describing a base image.
	BaseImage *ImageBasis `json:"baseImage,omitempty"`
	// A note describing a package hosted by various package managers.
	Package_ *PackagePackage `json:"package,omitempty"`
	// A note describing something that can be deployed.
	Deployable *DeploymentDeployable `json:"deployable,omitempty"`
	// A note describing the initial analysis of a resource.
	Discovery *DiscoveryDiscovery `json:"discovery,omitempty"`
	// A note describing an attestation role.
	AttestationAuthority *AttestationAuthority `json:"attestationAuthority,omitempty"`
	// A note describing an in-toto link.
	Intoto *IntotoInToto `json:"intoto,omitempty"`
}

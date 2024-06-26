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

// Version contains structured information about the version of a package.
type PackageVersion struct {
	// Used to correct mistakes in the version numbering scheme.
	Epoch int32 `json:"epoch,omitempty"`
	// Required only when version kind is NORMAL. The main part of the version name.
	Name string `json:"name,omitempty"`
	// The iteration of the package build from the above version.
	Revision string `json:"revision,omitempty"`
	// Required. Distinguishes between sentinel MIN/MAX versions and normal versions.
	Kind *VersionVersionKind `json:"kind,omitempty"`
}

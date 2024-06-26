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
// DiscoveredAnalysisStatus : Analysis status for a resource. Currently for initial analysis only (not updated in continuous analysis).   - ANALYSIS_STATUS_UNSPECIFIED: Unknown.  - PENDING: Resource is known but no action has been taken yet.  - SCANNING: Resource is being analyzed.  - FINISHED_SUCCESS: Analysis has finished successfully.  - FINISHED_FAILED: Analysis has finished unsuccessfully, the analysis itself is in a bad state.  - FINISHED_UNSUPPORTED: The resource is known not to be supported
type DiscoveredAnalysisStatus string

// List of DiscoveredAnalysisStatus
const (
	ANALYSIS_STATUS_UNSPECIFIED_DiscoveredAnalysisStatus DiscoveredAnalysisStatus = "ANALYSIS_STATUS_UNSPECIFIED"
	PENDING_DiscoveredAnalysisStatus DiscoveredAnalysisStatus = "PENDING"
	SCANNING_DiscoveredAnalysisStatus DiscoveredAnalysisStatus = "SCANNING"
	FINISHED_SUCCESS_DiscoveredAnalysisStatus DiscoveredAnalysisStatus = "FINISHED_SUCCESS"
	FINISHED_FAILED_DiscoveredAnalysisStatus DiscoveredAnalysisStatus = "FINISHED_FAILED"
	FINISHED_UNSUPPORTED_DiscoveredAnalysisStatus DiscoveredAnalysisStatus = "FINISHED_UNSUPPORTED"
)

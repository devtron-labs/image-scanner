# V1beta1provenanceArtifact

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Checksum** | **string** | Hash or checksum value of a binary, or Docker Registry 2.0 digest of a container. | [optional] [default to null]
**Id** | **string** | Artifact ID, if any; for container images, this will be a URL by digest like &#x60;gcr.io/projectID/imagename@sha256:123456&#x60;. | [optional] [default to null]
**Names** | **[]string** | Related artifact names. This may be the path to a binary or jar file, or in the case of a container build, the name used to push the container image to Google Container Registry, as presented to &#x60;docker push&#x60;. Note that a single Artifact ID can have multiple names, for example if two tags are applied to one image. | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



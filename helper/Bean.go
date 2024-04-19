package helper

import (
	"log"
	"time"
)

type CiProjectDetails struct {
	GitRepository   string      `json:"gitRepository"`
	FetchSubmodules bool        `json:"fetchSubmodules"`
	MaterialName    string      `json:"materialName"`
	CheckoutPath    string      `json:"checkoutPath"`
	CommitHash      string      `json:"commitHash"`
	GitTag          string      `json:"gitTag"`
	CommitTime      time.Time   `json:"commitTime"`
	SourceType      SourceType  `json:"sourceType"`
	SourceValue     string      `json:"sourceValue"`
	Type            string      `json:"type"`
	Message         string      `json:"message"`
	Author          string      `json:"author"`
	GitOptions      GitOptions  `json:"gitOptions"`
	WebhookData     WebhookData `json:"webhookData"`
	CloningMode     string      `json:"cloningMode"`
}

func (prj *CiProjectDetails) GetCheckoutBranchName() string {
	var checkoutBranch string
	if prj.SourceType == SOURCE_TYPE_WEBHOOK {
		webhookData := prj.WebhookData
		webhookDataData := webhookData.Data

		checkoutBranch = webhookDataData[WEBHOOK_SELECTOR_TARGET_CHECKOUT_BRANCH_NAME]
		if len(checkoutBranch) == 0 {
			//webhook type is tag based
			checkoutBranch = webhookDataData[WEBHOOK_SELECTOR_TARGET_CHECKOUT_NAME]
		}
	} else {
		if len(prj.SourceValue) == 0 {
			checkoutBranch = "main"
		} else {
			checkoutBranch = prj.SourceValue
		}
	}
	if len(checkoutBranch) == 0 {
		log.Fatal("could not get target checkout from request data")
	}
	return checkoutBranch
}

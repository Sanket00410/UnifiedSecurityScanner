package scoring

import (
	"time"

	controlrisk "unifiedsecurityscanner/control-plane/internal/risk"
	riskmodels "unifiedsecurityscanner/control-plane/risk-engine/internal/models"
)

func Score(request riskmodels.ScoreRequest) riskmodels.ScoreResponse {
	finding := controlrisk.EnrichWithInputs(request.Finding, controlrisk.Inputs{
		EnvironmentOverride:          request.Inputs.EnvironmentOverride,
		ExposureOverride:             request.Inputs.ExposureOverride,
		AssetCriticalityOverride:     request.Inputs.AssetCriticalityOverride,
		OwnerTeam:                    request.Inputs.OwnerTeam,
		OwnerHierarchy:               request.Inputs.OwnerHierarchy,
		ServiceName:                  request.Inputs.ServiceName,
		ServiceTier:                  request.Inputs.ServiceTier,
		ServiceCriticalityClass:      request.Inputs.ServiceCriticalityClass,
		ExternalSource:               request.Inputs.ExternalSource,
		ExternalReference:            request.Inputs.ExternalReference,
		LastSyncedAt:                 request.Inputs.LastSyncedAt,
		CompensatingControlReduction: request.Inputs.CompensatingControlReduction,
	})

	if request.Inputs.WaiverReduction > 0 {
		finding = controlrisk.ApplyWaiverReduction(finding, request.Inputs.WaiverReduction)
	}

	referenceTime := time.Now().UTC()
	if request.ReferenceTime != nil {
		referenceTime = request.ReferenceTime.UTC()
	}
	finding = controlrisk.ApplyTemporalSignals(finding, referenceTime)

	return riskmodels.ScoreResponse{Finding: finding}
}

func BatchScore(request riskmodels.BatchScoreRequest) riskmodels.BatchScoreResponse {
	out := make([]riskmodels.ScoreResponse, 0, len(request.Items))
	for _, item := range request.Items {
		out = append(out, Score(item))
	}
	return riskmodels.BatchScoreResponse{Items: out}
}

func QueueCatalog() []riskmodels.QueueDescriptor {
	return []riskmodels.QueueDescriptor{
		{Priority: "p0", SLAClass: "24h", Queue: "queue:p0:24h"},
		{Priority: "p1", SLAClass: "72h", Queue: "queue:p1:72h"},
		{Priority: "p2", SLAClass: "14d", Queue: "queue:p2:14d"},
		{Priority: "p3", SLAClass: "30d", Queue: "queue:p3:30d"},
		{Priority: "p4", SLAClass: "90d", Queue: "queue:p4:90d"},
	}
}

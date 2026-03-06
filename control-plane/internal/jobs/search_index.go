package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Store) SearchFindingsForTenant(ctx context.Context, organizationID string, query models.FindingSearchQuery) (models.FindingSearchResult, error) {
	organizationID = strings.TrimSpace(organizationID)
	normalized := normalizeFindingSearchQuery(query)

	var total int64
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM normalized_findings
		WHERE tenant_id = $1
		  AND ($2 = '' OR LOWER(COALESCE(finding_json->>'severity', '')) = $2)
		  AND ($3 = '' OR LOWER(COALESCE(finding_json->'risk'->>'priority', '')) = $3)
		  AND ($4 = '' OR LOWER(COALESCE(finding_json->'source'->>'layer', '')) = $4)
		  AND ($5 = '' OR LOWER(COALESCE(finding_json->>'status', '')) = $5)
		  AND (
		        $6 = ''
		        OR TO_TSVECTOR(
		            'simple',
		            COALESCE(finding_json->>'title', '') || ' ' ||
		            COALESCE(finding_json->>'description', '') || ' ' ||
		            COALESCE(finding_json->>'category', '') || ' ' ||
		            COALESCE(finding_json->'asset'->>'asset_id', '') || ' ' ||
		            COALESCE(finding_json->'asset'->>'asset_name', '')
		        ) @@ WEBSEARCH_TO_TSQUERY('simple', $6)
		      )
		  AND ($7::boolean IS NULL OR (COALESCE(LOWER(finding_json->'risk'->>'overdue'), 'false') = 'true') = $7::boolean)
	`, organizationID, normalized.Severity, normalized.Priority, normalized.Layer, normalized.Status, normalized.Query, normalized.Overdue).Scan(&total)
	if err != nil {
		return models.FindingSearchResult{}, fmt.Errorf("count tenant finding search results: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT finding_json
		FROM normalized_findings
		WHERE tenant_id = $1
		  AND ($2 = '' OR LOWER(COALESCE(finding_json->>'severity', '')) = $2)
		  AND ($3 = '' OR LOWER(COALESCE(finding_json->'risk'->>'priority', '')) = $3)
		  AND ($4 = '' OR LOWER(COALESCE(finding_json->'source'->>'layer', '')) = $4)
		  AND ($5 = '' OR LOWER(COALESCE(finding_json->>'status', '')) = $5)
		  AND (
		        $6 = ''
		        OR TO_TSVECTOR(
		            'simple',
		            COALESCE(finding_json->>'title', '') || ' ' ||
		            COALESCE(finding_json->>'description', '') || ' ' ||
		            COALESCE(finding_json->>'category', '') || ' ' ||
		            COALESCE(finding_json->'asset'->>'asset_id', '') || ' ' ||
		            COALESCE(finding_json->'asset'->>'asset_name', '')
		        ) @@ WEBSEARCH_TO_TSQUERY('simple', $6)
		      )
		  AND ($7::boolean IS NULL OR (COALESCE(LOWER(finding_json->'risk'->>'overdue'), 'false') = 'true') = $7::boolean)
		ORDER BY COALESCE(NULLIF(finding_json->'risk'->>'overall_score', '')::double precision, 0) DESC,
		         updated_at DESC
		LIMIT $8 OFFSET $9
	`, organizationID, normalized.Severity, normalized.Priority, normalized.Layer, normalized.Status, normalized.Query, normalized.Overdue, normalized.Limit, normalized.Offset)
	if err != nil {
		return models.FindingSearchResult{}, fmt.Errorf("query tenant finding search results: %w", err)
	}
	defer rows.Close()

	items := make([]models.CanonicalFinding, 0, normalized.Limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return models.FindingSearchResult{}, fmt.Errorf("scan tenant finding search row: %w", err)
		}

		var finding models.CanonicalFinding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return models.FindingSearchResult{}, fmt.Errorf("unmarshal tenant finding search row: %w", err)
		}
		items = append(items, finding)
	}
	if err := rows.Err(); err != nil {
		return models.FindingSearchResult{}, fmt.Errorf("iterate tenant finding search results: %w", err)
	}

	items, err = s.applyEffectiveRiskAdjustments(ctx, organizationID, items)
	if err != nil {
		return models.FindingSearchResult{}, err
	}

	return models.FindingSearchResult{
		Items:  items,
		Total:  total,
		Limit:  normalized.Limit,
		Offset: normalized.Offset,
	}, nil
}

func normalizeFindingSearchQuery(query models.FindingSearchQuery) models.FindingSearchQuery {
	query.Query = strings.TrimSpace(query.Query)
	query.Severity = strings.ToLower(strings.TrimSpace(query.Severity))
	query.Priority = strings.ToLower(strings.TrimSpace(query.Priority))
	query.Layer = strings.ToLower(strings.TrimSpace(query.Layer))
	query.Status = strings.ToLower(strings.TrimSpace(query.Status))

	if query.Limit <= 0 || query.Limit > 1000 {
		query.Limit = 100
	}
	if query.Offset < 0 {
		query.Offset = 0
	}

	return query
}

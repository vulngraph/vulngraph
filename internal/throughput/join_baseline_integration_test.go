//go:build integration

package throughput

// Pre-change dashboard SQL retained for matched comparisons.
const baselineSummaryOpenFindings = `SELECT sev, band, owner, env, count()
	FROM (
		SELECT legacy.sev AS sev, fe.band AS band, fe.owner AS owner, fe.env AS env
		FROM (
			SELECT id,
				argMax(severity, synced_at)   AS sev,
				argMax(resolved_at, synced_at) AS resolved_at
			FROM findings
			%s
			GROUP BY source, id
			HAVING resolved_at < toDateTime('2000-01-01 00:00:00')
		) legacy
		LEFT JOIN (
			SELECT id,
				argMax(score_band, enriched_at) AS band,
				if(argMax(owner_source, enriched_at) = 'none', '` + "unowned" + `',
				   argMax(owner_team, enriched_at)) AS owner,
				argMax(environment, enriched_at) AS env
			FROM finding_enrichment
			GROUP BY id
		) fe ON legacy.id = fe.id
	)
	GROUP BY sev, band, owner, env`

const baselineClustersByCheck = `SELECT
		check_id,
		argMax(title, score)       AS title,
		argMax(severity, score)    AS severity,
		any(source)                AS source,
		argMax(remediation, score) AS remediation,
		max(score)                 AS max_score,
		argMax(score_band, score)  AS worst_band,
		count()                    AS instances,
		uniq(resource_id)          AS resources,
		max(known_exploited)       AS kev,
		max(detected_at)           AS last_detected,
		count() OVER ()            AS total_checks
	FROM (
		SELECT legacy.check_id     AS check_id,
			legacy.source          AS source,
			legacy.resource_id     AS resource_id,
			legacy.title           AS title,
			legacy.severity        AS severity,
			legacy.remediation     AS remediation,
			fe.score                AS score,
			fe.score_band           AS score_band,
			fe.known_exploited      AS known_exploited,
			legacy.detected_at      AS detected_at
		FROM (
			SELECT id, check_id, source, resource_id,
				argMax(title, synced_at)       AS title,
				argMax(severity, synced_at)    AS severity,
				argMax(remediation, synced_at) AS remediation,
				argMax(detected_at, synced_at) AS detected_at,
				argMax(resolved_at, synced_at) AS resolved_at
			FROM findings
			%s
			GROUP BY source, id, check_id, resource_id
			HAVING resolved_at < toDateTime('2000-01-01 00:00:00')
		) legacy
		LEFT JOIN (
			SELECT id,
				argMax(score, enriched_at)          AS score,
				argMax(score_band, enriched_at)     AS score_band,
				argMax(known_exploited, enriched_at) AS known_exploited
			FROM finding_enrichment
			GROUP BY id
		) fe ON legacy.id = fe.id
	)
	GROUP BY check_id
	ORDER BY max_score DESC, instances DESC
	LIMIT ?`

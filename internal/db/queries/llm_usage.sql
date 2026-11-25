-- name: InsertLLMUsage :exec
INSERT INTO llm_usage (
    purpose, interactive, provider, model,
    input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
    usage_reported, failed, cost_micro_usd, user_id
) VALUES (
    @purpose, @interactive, @provider, @model,
    @input_tokens, @output_tokens, @cache_read_tokens, @cache_write_tokens,
    @usage_reported, @failed, @cost_micro_usd, @user_id
);

-- name: SumLLMSpendSince :one
-- The budget check: total and interactive-only spend since @since.
SELECT
    COALESCE(SUM(cost_micro_usd), 0)::bigint                            AS total_micro_usd,
    COALESCE(SUM(cost_micro_usd) FILTER (WHERE interactive), 0)::bigint AS interactive_micro_usd
FROM llm_usage
WHERE ts >= @since;

-- name: SumLLMUserSpend :one
-- The per-user budget check: one user's spend since @month_start and since
-- @day_start (both bounds are in the same month or day_start is later).
SELECT
    COALESCE(SUM(cost_micro_usd), 0)::bigint                               AS month_micro_usd,
    COALESCE(SUM(cost_micro_usd) FILTER (WHERE ts >= @day_start), 0)::bigint AS day_micro_usd
FROM llm_usage
WHERE user_id = @user_id AND ts >= @month_start;

-- name: SummarizeLLMUsage :many
-- Per purpose and model, for the admin usage view, over [@since, @until).
SELECT
    purpose,
    model,
    bool_or(interactive)                                    AS interactive,
    COUNT(*)::bigint                                        AS calls,
    COUNT(*) FILTER (WHERE NOT usage_reported)::bigint      AS unreported_calls,
    COUNT(*) FILTER (WHERE failed)::bigint                  AS failed_calls,
    COALESCE(SUM(input_tokens), 0)::bigint                  AS input_tokens,
    COALESCE(SUM(output_tokens), 0)::bigint                 AS output_tokens,
    COALESCE(SUM(cache_read_tokens), 0)::bigint             AS cache_read_tokens,
    COALESCE(SUM(cache_write_tokens), 0)::bigint            AS cache_write_tokens,
    COALESCE(SUM(cost_micro_usd), 0)::bigint                AS cost_micro_usd
FROM llm_usage
WHERE ts >= @since AND ts < @until
GROUP BY purpose, model
ORDER BY cost_micro_usd DESC, purpose, model;

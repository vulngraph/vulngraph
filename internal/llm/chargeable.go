package llm

import "encoding/json"

// conservativeBytesPerToken converts request bytes into an input-token
// estimate for a call whose provider reported no usage. Real tokenizers average
// about four bytes of English or JSON per token, so three over-counts typical
// content on purpose (ADR 085 §7). Dense content such as hex, base64, random
// IDs or some CJK text can tokenize at fewer bytes per token and be
// under-estimated here; the full output budget charged alongside it is what
// keeps the total conservative.
const conservativeBytesPerToken = 3

// ChargeableUsage is the usage to charge a call against a budget: the
// provider's report when it sent one, otherwise a conservative estimate: the
// request bytes estimated as input and the call's whole output budget as output. resp
// may be nil (the call failed before a response existed); a failed call is
// charged the same way, since the provider may have done the work anyway.
func ChargeableUsage(req Request, resp *Response) Usage {
	if resp != nil && resp.Usage.Reported {
		return resp.Usage
	}
	output := req.MaxTokens
	if req.Reasoning != nil {
		output = max(output, req.Reasoning.MaxTokens)
	}
	if resp != nil {
		output = max(output, resp.MaxTokens)
	}
	return Usage{InputTokens: estimateInputTokens(req), OutputTokens: output}
}

func estimateInputTokens(req Request) int64 {
	var n int
	for _, s := range req.System {
		n += len(s.Text)
	}
	for _, m := range req.Messages {
		n += len(m.Text)
		for _, tc := range m.ToolCalls {
			n += len(tc.Name) + len(tc.Input)
		}
		for _, tr := range m.ToolResults {
			n += len(tr.Content)
		}
	}
	for _, t := range req.Tools {
		schema, _ := json.Marshal(t.InputSchema)
		n += len(t.Name) + len(t.Description) + len(schema)
	}
	if req.JSONSchema != nil {
		schema, _ := json.Marshal(req.JSONSchema)
		n += len(schema)
	}
	return int64((n + conservativeBytesPerToken - 1) / conservativeBytesPerToken)
}

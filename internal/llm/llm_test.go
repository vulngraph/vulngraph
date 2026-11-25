package llm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeMessages(t *testing.T) {
	call := ToolCall{ID: "c1", Name: "get_asset", Input: []byte(`{}`)}
	result := ToolResult{CallID: "c1", Content: "ok"}
	tests := []struct {
		name string
		in   []Message
		want []Message
	}{
		{
			name: "empty assistant turn between user turns is dropped and the users merge",
			in:   []Message{UserText("q1"), AssistantText(""), UserText("q2")},
			want: []Message{{Role: RoleUser, Text: "q1\n\nq2"}},
		},
		{
			name: "whitespace-only text counts as empty",
			in:   []Message{UserText("q1"), AssistantText("  \n"), UserText("q2"), AssistantText("a2")},
			want: []Message{{Role: RoleUser, Text: "q1\n\nq2"}, {Role: RoleAssistant, Text: "a2"}},
		},
		{
			name: "a turn with only tool calls or tool results is kept",
			in: []Message{
				UserText("q"),
				{Role: RoleAssistant, ToolCalls: []ToolCall{call}},
				{Role: RoleUser, ToolResults: []ToolResult{result}},
			},
			want: []Message{
				{Role: RoleUser, Text: "q"},
				{Role: RoleAssistant, ToolCalls: []ToolCall{call}},
				{Role: RoleUser, ToolResults: []ToolResult{result}},
			},
		},
		{
			name: "merging keeps tool results and text from both turns",
			in: []Message{
				{Role: RoleUser, ToolResults: []ToolResult{result}},
				AssistantText(""),
				UserText("follow-up"),
			},
			want: []Message{{Role: RoleUser, Text: "follow-up", ToolResults: []ToolResult{result}}},
		},
		{
			name: "all-empty history normalizes to nothing",
			in:   []Message{AssistantText("")},
			want: []Message{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeMessages(tt.in)
			require.Len(t, got, len(tt.want))
			for i := range tt.want {
				require.Equal(t, tt.want[i].Role, got[i].Role)
				require.Equal(t, tt.want[i].Text, got[i].Text)
				require.Equal(t, tt.want[i].ToolCalls, got[i].ToolCalls)
				require.Equal(t, tt.want[i].ToolResults, got[i].ToolResults)
			}
		})
	}
}

// Merging must never write into the caller's backing arrays: chat reuses its
// history slice across iterations of the tool loop.
func TestNormalizeMessages_DoesNotAliasInput(t *testing.T) {
	backing := make([]ToolResult, 1, 2)
	backing[0] = ToolResult{CallID: "a"}
	in := []Message{
		{Role: RoleUser, ToolResults: backing},
		{Role: RoleUser, ToolResults: []ToolResult{{CallID: "b"}}},
	}
	got := normalizeMessages(in)
	require.Len(t, got[0].ToolResults, 2)
	require.Empty(t, backing[:2][1].CallID, "the merge appended into the caller's array")
}

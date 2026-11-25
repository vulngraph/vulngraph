// Chat transcripts live in localStorage, keyed by the signed-in user's id, so a
// second user of the same browser profile never sees the first one's
// conversations. Answers can quote live cloud data fetched with the asker's
// role, so logout and session expiry remove every chat key (clearChatStorage).
// Every access is guarded: storage can be unavailable (private windows,
// blocked site data) and the panel must still work, just without history.

const PREFIX = "graph.chat.";

// generation advances on every clear. A store opened before a clear stops
// writing, so a panel still mounted while the login screen takes over (a
// stream ending after a 401) cannot put the transcript back.
let generation = 0;

export type ChatField = "sessions" | "active";

export interface ChatStore {
  load(field: ChatField): string | null;
  save(field: ChatField, value: string | null): void;
}

export function openChatStore(userId: string): ChatStore {
  const opened = generation;
  const key = (field: ChatField) => `${PREFIX}${userId}.${field}`;
  return {
    load(field) {
      if (opened !== generation) return null;
      try {
        return localStorage.getItem(key(field));
      } catch {
        return null;
      }
    },
    save(field, value) {
      if (opened !== generation) return;
      try {
        if (value === null) localStorage.removeItem(key(field));
        else localStorage.setItem(key(field), value);
      } catch {
        // Storage full or unavailable: the conversation stays in memory only.
      }
    },
  };
}

// clearChatStorage removes every user's chat keys and retires every open store.
export function clearChatStorage() {
  generation++;
  try {
    const keys: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k?.startsWith(PREFIX)) keys.push(k);
    }
    for (const k of keys) localStorage.removeItem(k);
  } catch {
    // Unavailable storage holds nothing to clear.
  }
}

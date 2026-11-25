// copyText writes to the clipboard and resolves to whether it worked. It never
// throws or rejects: navigator.clipboard is undefined on plain HTTP (kubectl
// port-forward) and writeText rejects when permission is denied; either must
// not escape a click handler as an uncaught error / unhandled rejection.
export async function copyText(text: string): Promise<boolean> {
  try {
    if (!navigator.clipboard?.writeText) return false;
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

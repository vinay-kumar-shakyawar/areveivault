/** Request/response to the service worker from extension pages (popup, onboarding). */
export async function rpc<T = any>(method: string, args: Record<string, unknown> = {}): Promise<T> {
  const r = await chrome.runtime.sendMessage({ target: "sw", method, args });
  return r as T;
}

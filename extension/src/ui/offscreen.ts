/** Offscreen document: clipboard write + timed clear (MV3 service workers have no clipboard). */

let clearTimer: number | undefined;

function write(text: string) {
  const ta = document.getElementById("clip") as HTMLTextAreaElement;
  ta.value = text || " ";
  ta.select();
  document.execCommand("copy");
  ta.value = "";
}

chrome.runtime.onMessage.addListener((m, sender) => {
  if (sender.id !== chrome.runtime.id || m?.target !== "offscreen" || m.type !== "copy") return;
  write(String(m.text ?? ""));
  clearTimeout(clearTimer);
  // Always clear: checking whether the clipboard still holds our value would need clipboardRead.
  clearTimer = window.setTimeout(() => write(""), Number(m.clearAfterMs) || 30_000);
});

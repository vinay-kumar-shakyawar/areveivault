export function bytesToB64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

export function b64ToBytes(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export async function fileToB64(file: Blob): Promise<string> {
  return bytesToB64(new Uint8Array(await file.arrayBuffer()));
}

export async function readText(file: Blob): Promise<string> {
  return file.text();
}

/** First image found in a paste event (for 2FA QR screenshots). */
export function imageFromPaste(e: ClipboardEvent | React.ClipboardEvent): File | null {
  const items = e.clipboardData?.items;
  if (!items) return null;
  for (const it of Array.from(items)) {
    if (it.type.startsWith("image/")) return it.getAsFile();
  }
  return null;
}

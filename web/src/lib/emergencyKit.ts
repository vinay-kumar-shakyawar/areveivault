/**
 * Emergency Kit PDF, generated entirely client-side (no network). Contains the
 * email, sign-in URL, Secret Key, a blank line for the master password, and a QR
 * setup code for adding devices (architecture §6.1).
 */
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import { qrMatrix } from "./qr";

export function setupCode(email: string, secretKey: string, url: string): string {
  const p = new URLSearchParams({ email, secret_key: secretKey, url });
  return `arevei-vault://setup?${p.toString()}`;
}

export async function buildEmergencyKit(opts: { email: string; secretKey: string; signInUrl: string; createdAt: Date }): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  pdf.setTitle("Arevei Vault Emergency Kit");
  pdf.setCreator("Arevei Vault");
  pdf.setProducer("Arevei Vault (generated in your browser)");
  const page = pdf.addPage([595.28, 841.89]); // A4
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const mono = await pdf.embedFont(StandardFonts.Courier);
  const black = rgb(0.04, 0.04, 0.04);
  const muted = rgb(0.42, 0.42, 0.42);
  const line = rgb(0.85, 0.85, 0.85);
  const W = page.getWidth();
  const M = 56;
  let y = 790;

  // Header bar + mark
  page.drawRectangle({ x: 0, y: 760, width: W, height: 82, color: black });
  page.drawText("Arevei Vault", { x: M, y: 800, size: 22, font: bold, color: rgb(0.96, 0.96, 0.96) });
  page.drawText("EMERGENCY KIT", { x: M, y: 780, size: 10, font, color: rgb(0.75, 0.75, 0.75) });
  y = 720;

  const para = (text: string, size = 10, f = font, color = muted) => {
    const words = text.split(" ");
    let lineText = "";
    for (const w of words) {
      const next = lineText ? `${lineText} ${w}` : w;
      if (f.widthOfTextAtSize(next, size) > W - 2 * M) {
        page.drawText(lineText, { x: M, y, size, font: f, color });
        y -= size + 5;
        lineText = w;
      } else lineText = next;
    }
    if (lineText) {
      page.drawText(lineText, { x: M, y, size, font: f, color });
      y -= size + 5;
    }
  };

  para("Print this page or store it somewhere safe and offline. You need it to sign in on a new device or to recover your account.", 10.5, font, black);
  y -= 14;

  const box = (label: string, value: string, opts: { mono?: boolean; height?: number } = {}) => {
    const h = opts.height ?? 46;
    page.drawText(label.toUpperCase(), { x: M, y, size: 8.5, font: bold, color: muted });
    y -= 8;
    page.drawRectangle({ x: M, y: y - h, width: W - 2 * M, height: h, borderColor: line, borderWidth: 1 });
    if (value) {
      page.drawText(value, { x: M + 12, y: y - h / 2 - 5, size: opts.mono ? 14 : 12, font: opts.mono ? mono : font, color: black });
    }
    y -= h + 22;
  };

  box("Sign-in address", opts.signInUrl);
  box("Email", opts.email);
  box("Secret Key", opts.secretKey, { mono: true });
  box("Master password (write it by hand, or leave blank and memorize it)", "", { height: 52 });

  // QR setup code
  const m = qrMatrix(setupCode(opts.email, opts.secretKey, opts.signInUrl));
  const cell = 3.2;
  const qrSize = m.size * cell;
  const qx = M;
  const qy = y - qrSize;
  page.drawRectangle({ x: qx - 6, y: qy - 6, width: qrSize + 12, height: qrSize + 12, color: rgb(1, 1, 1), borderColor: line, borderWidth: 1 });
  for (let r = 0; r < m.size; r++) {
    for (let c = 0; c < m.size; c++) {
      if (m.isDark(r, c)) page.drawRectangle({ x: qx + c * cell, y: qy + (m.size - 1 - r) * cell, width: cell, height: cell, color: black });
    }
  }
  const tx = qx + qrSize + 24;
  page.drawText("Setup code", { x: tx, y: y - 14, size: 11, font: bold, color: black });
  const note = [
    "Scan to add a new device. It contains your email,",
    "sign-in address and Secret Key — but never your",
    "master password. Anyone with this page AND your",
    "master password can open your vault.",
  ];
  note.forEach((l, i) => page.drawText(l, { x: tx, y: y - 32 - i * 14, size: 9.5, font, color: muted }));
  y = qy - 36;

  para("Forgot your master password? Arevei cannot recover it. Your organization's administrators can restore your access to shared client projects, but items in your Personal Vault cannot be recovered without your master password.", 9.5);
  y -= 6;
  para(`Created ${opts.createdAt.toISOString().slice(0, 10)}. This document was generated in your browser and was never sent to Arevei's servers.`, 8.5);

  return pdf.save();
}

export function downloadBytes(bytes: Uint8Array | string, filename: string, mime: string): void {
  const blob = new Blob([bytes as BlobPart], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

import { useRef, useState } from "react";
import { ImageUp } from "lucide-react";
import { Button } from "@arevei/ui";
import { engine, errorMessage } from "../lib/app";
import { fileToB64, imageFromPaste } from "../lib/files";

export interface ParsedOtp {
  issuer: string;
  account: string;
  secret: string;
  algorithm: string;
  digits: number;
  period: number;
}

/** Decode a 2FA QR code from an uploaded or pasted image — locally, in the engine. */
export function QrImport({ onParsed }: { onParsed: (p: ParsedOtp, uri: string) => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handle = async (file: Blob) => {
    setBusy(true);
    setError(null);
    try {
      const { contents } = await engine.call<{ contents: string[] }>("decode_qr", { image: await fileToB64(file) });
      const uri = contents.find((c) => c.toLowerCase().startsWith("otpauth://")) ?? contents[0];
      const p = await engine.call<ParsedOtp>("parse_otpauth", { uri });
      onParsed(p, uri);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="rounded-sm border border-dashed border-line-input p-3 text-[12px] text-muted"
      tabIndex={0}
      onPaste={(e) => {
        const img = imageFromPaste(e);
        if (img) {
          e.preventDefault();
          void handle(img);
        }
      }}
    >
      <div className="flex items-center gap-2">
        <Button size="sm" onClick={() => fileRef.current?.click()} loading={busy}>
          <ImageUp aria-hidden /> Scan QR image
        </Button>
        <span>or click here and paste a screenshot (Ctrl/Cmd+V). Decoded on this device.</span>
      </div>
      <input
        ref={fileRef}
        type="file"
        accept="image/png,image/jpeg"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) void handle(f);
          e.target.value = "";
        }}
      />
      {error ? <div className="mt-2 text-danger">{error}</div> : null}
    </div>
  );
}

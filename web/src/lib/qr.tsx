/** QR rendering via qrcode-generator → React <rect>s (no innerHTML, no data: SVG strings). */
import qrcode from "qrcode-generator";

export interface QrMatrix {
  size: number;
  isDark(r: number, c: number): boolean;
}

export function qrMatrix(text: string): QrMatrix {
  const q = qrcode(0, "M");
  q.addData(text, "Byte");
  q.make();
  const size = q.getModuleCount();
  return { size, isDark: (r, c) => q.isDark(r, c) };
}

export function QrCode({ text, size = 176, label }: { text: string; size?: number; label: string }) {
  const m = qrMatrix(text);
  const quiet = 2;
  const dim = m.size + quiet * 2;
  const cells: JSX.Element[] = [];
  for (let r = 0; r < m.size; r++) {
    for (let c = 0; c < m.size; c++) {
      if (m.isDark(r, c)) cells.push(<rect key={`${r}-${c}`} x={c + quiet} y={r + quiet} width={1.02} height={1.02} />);
    }
  }
  return (
    <svg
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`0 0 ${dim} ${dim}`}
      shapeRendering="crispEdges"
      className="rounded-sm"
    >
      <rect width={dim} height={dim} fill="#ffffff" />
      <g fill="#0a0a0a">{cells}</g>
    </svg>
  );
}

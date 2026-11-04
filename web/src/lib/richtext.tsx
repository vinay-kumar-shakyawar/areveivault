/**
 * Secure-note rich text as a structured, allow-listed JSON document — never HTML
 * (architecture §12.1). Notes may be authored by other users (shared projects), so
 * the renderer treats every field as untrusted: only known block kinds, plain text
 * children via React, and links restricted to https/http/mailto.
 *
 * Editing uses a small markdown subset: # heading, - list, 1. list, > quote,
 * ``` code fences, **bold**, *italic*, `code`, [text](url).
 */
import { Fragment, type ReactNode } from "react";

export interface Inline {
  t: string;
  b?: 1;
  i?: 1;
  c?: 1;
  href?: string;
}
export type Block =
  | { k: "p" | "h" | "quote"; c: Inline[] }
  | { k: "ul" | "ol"; items: Inline[][] }
  | { k: "code"; text: string };
export interface Doc {
  v: 1;
  blocks: Block[];
}

const SAFE_HREF = /^(https?:\/\/|mailto:)/i;
export const safeHref = (h: unknown): string | undefined =>
  typeof h === "string" && SAFE_HREF.test(h.trim()) ? h.trim() : undefined;

// ---------- markdown subset → doc ----------
export function parseInline(s: string): Inline[] {
  const out: Inline[] = [];
  const re = /(\*\*([^*]+)\*\*)|(`([^`]+)`)|(\[([^\]]+)\]\(([^)\s]+)\))|(\*([^*]+)\*)|(_([^_]+)_)/g;
  let last = 0;
  for (const m of s.matchAll(re)) {
    if (m.index! > last) out.push({ t: s.slice(last, m.index) });
    if (m[1]) out.push({ t: m[2], b: 1 });
    else if (m[3]) out.push({ t: m[4], c: 1 });
    else if (m[5]) {
      const href = safeHref(m[7]);
      out.push(href ? { t: m[6], href } : { t: m[0] });
    } else if (m[8]) out.push({ t: m[9], i: 1 });
    else if (m[10]) out.push({ t: m[11], i: 1 });
    last = m.index! + m[0].length;
  }
  if (last < s.length) out.push({ t: s.slice(last) });
  return out;
}

export function fromMarkdown(md: string): Doc {
  const lines = md.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let para: string[] = [];
  const flush = () => {
    if (para.length) blocks.push({ k: "p", c: parseInline(para.join("\n")) });
    para = [];
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("```")) {
      flush();
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) code.push(lines[i++]);
      blocks.push({ k: "code", text: code.join("\n") });
      continue;
    }
    const h = /^#{1,3}\s+(.*)$/.exec(line);
    const ul = /^\s*[-*]\s+(.*)$/.exec(line);
    const ol = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    const q = /^>\s?(.*)$/.exec(line);
    if (h) {
      flush();
      blocks.push({ k: "h", c: parseInline(h[1]) });
    } else if (ul || ol) {
      flush();
      const kind = ul ? "ul" : "ol";
      const prev = blocks[blocks.length - 1];
      const item = parseInline((ul ?? ol)![1]);
      if (prev && prev.k === kind) prev.items.push(item);
      else blocks.push({ k: kind, items: [item] });
    } else if (q) {
      flush();
      blocks.push({ k: "quote", c: parseInline(q[1]) });
    } else if (line.trim() === "") {
      flush();
    } else {
      para.push(line);
    }
  }
  flush();
  return { v: 1, blocks };
}

// ---------- doc → markdown (for editing) ----------
const inlineMd = (c: Inline[]) =>
  c
    .map((n) => {
      const t = String(n.t ?? "");
      if (n.href) return `[${t}](${n.href})`;
      if (n.c) return `\`${t}\``;
      if (n.b) return `**${t}**`;
      if (n.i) return `*${t}*`;
      return t;
    })
    .join("");

export function toMarkdown(doc: Doc): string {
  return doc.blocks
    .map((b) => {
      switch (b.k) {
        case "h":
          return `# ${inlineMd(b.c)}`;
        case "quote":
          return `> ${inlineMd(b.c)}`;
        case "ul":
          return b.items.map((i) => `- ${inlineMd(i)}`).join("\n");
        case "ol":
          return b.items.map((i, n) => `${n + 1}. ${inlineMd(i)}`).join("\n");
        case "code":
          return "```\n" + b.text + "\n```";
        default:
          return inlineMd(b.c);
      }
    })
    .join("\n\n");
}

// ---------- storage ----------
/** Notes are stored as a JSON doc string; anything else (e.g. imported text) is plain text. */
export function parseNotes(notes: string | undefined | null): Doc {
  if (!notes) return { v: 1, blocks: [] };
  if (notes.startsWith("{")) {
    try {
      const d = JSON.parse(notes);
      if (d && d.v === 1 && Array.isArray(d.blocks)) return d as Doc;
    } catch {
      /* fall through to plain text */
    }
  }
  return {
    v: 1,
    blocks: notes
      .split(/\n{2,}/)
      .filter((p) => p.length)
      .map((p) => ({ k: "p" as const, c: [{ t: p }] })),
  };
}

export const notesToMarkdown = (notes: string | undefined) => toMarkdown(parseNotes(notes));
export const markdownToNotes = (md: string) => (md.trim() ? JSON.stringify(fromMarkdown(md)) : "");
const inlineText = (c: Inline[]) => c.map((n) => n.t).join("");
export const notesPlainText = (notes: string | undefined) =>
  parseNotes(notes)
    .blocks.map((b) => {
      if (b.k === "code") return b.text;
      if ("items" in b) return b.items.map(inlineText).join("\n");
      return inlineText(b.c);
    })
    .join("\n\n");

// ---------- renderer (React elements only) ----------
function renderInline(c: unknown): ReactNode {
  if (!Array.isArray(c)) return null;
  return c.map((n: Inline, i) => {
    const t = typeof n?.t === "string" ? n.t : "";
    let el: ReactNode = t;
    if (n?.c) el = <code className="rounded bg-raised px-1 font-mono text-[13px]">{t}</code>;
    if (n?.b) el = <strong>{el}</strong>;
    if (n?.i) el = <em>{el}</em>;
    const href = safeHref(n?.href);
    if (href)
      el = (
        <a href={href} target="_blank" rel="noopener noreferrer nofollow" className="underline decoration-silver-strong underline-offset-2">
          {el}
        </a>
      );
    return <Fragment key={i}>{el}</Fragment>;
  });
}

export function RichText({ doc }: { doc: Doc }) {
  const blocks = Array.isArray(doc?.blocks) ? doc.blocks : [];
  return (
    <div className="space-y-3 text-sm leading-relaxed" data-testid="rich-text">
      {blocks.map((b: any, i) => {
        switch (b?.k) {
          case "h":
            return (
              <h4 key={i} className="text-sm font-semibold">
                {renderInline(b.c)}
              </h4>
            );
          case "quote":
            return (
              <blockquote key={i} className="border-l-2 border-line pl-3 text-muted">
                {renderInline(b.c)}
              </blockquote>
            );
          case "ul":
          case "ol": {
            const L = b.k === "ul" ? "ul" : "ol";
            return (
              <L key={i} className={b.k === "ul" ? "list-disc pl-5" : "list-decimal pl-5"}>
                {(Array.isArray(b.items) ? b.items : []).map((it: Inline[], j: number) => (
                  <li key={j}>{renderInline(it)}</li>
                ))}
              </L>
            );
          }
          case "code":
            return (
              <pre key={i} className="overflow-auto rounded border border-line bg-bg p-3 font-mono text-[13px]">
                {typeof b.text === "string" ? b.text : ""}
              </pre>
            );
          case "p":
            return (
              <p key={i} className="whitespace-pre-wrap">
                {renderInline(b.c)}
              </p>
            );
          default:
            return null;
        }
      })}
    </div>
  );
}

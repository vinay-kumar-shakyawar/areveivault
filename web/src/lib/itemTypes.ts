import {
  Database,
  FileText,
  Globe,
  KeyRound,
  ListChecks,
  Paperclip,
  ShieldCheck,
  Terminal,
  type LucideIcon,
} from "lucide-react";
import type { ItemType } from "@arevei/client";

export type FieldKind = "text" | "secret" | "textarea" | "secretarea" | "number" | "select";

export interface FieldSpec {
  key: string;
  label: string;
  kind: FieldKind;
  options?: string[];
  mono?: boolean;
  generator?: boolean;
  placeholder?: string;
}

export interface TypeSpec {
  label: string;
  icon: LucideIcon;
  fields: FieldSpec[];
  defaults: Record<string, unknown>;
}

export const TYPES: Record<ItemType, TypeSpec> = {
  login: {
    label: "Login",
    icon: Globe,
    fields: [
      { key: "username", label: "Username", kind: "text" },
      { key: "password", label: "Password", kind: "secret", generator: true },
    ],
    defaults: { username: "", password: "", urls: [{ url: "", match_mode: "domain" }], totp: null },
  },
  authenticator: {
    label: "Authenticator (2FA)",
    icon: ShieldCheck,
    fields: [
      { key: "issuer", label: "Issuer", kind: "text", placeholder: "e.g. GitHub" },
      { key: "account", label: "Account", kind: "text" },
      { key: "secret", label: "Secret key", kind: "secret", mono: true },
      { key: "algorithm", label: "Algorithm", kind: "select", options: ["SHA1", "SHA256", "SHA512"] },
      { key: "digits", label: "Digits", kind: "select", options: ["6", "7", "8"] },
      { key: "period", label: "Period (seconds)", kind: "number" },
    ],
    defaults: { issuer: "", account: "", secret: "", algorithm: "SHA1", digits: 6, period: 30 },
  },
  recovery_codes: {
    label: "Backup / recovery codes",
    icon: ListChecks,
    fields: [{ key: "service", label: "Service", kind: "text" }],
    defaults: { service: "", codes: [] },
  },
  api_key: {
    label: "API key / token",
    icon: KeyRound,
    fields: [
      { key: "service", label: "Service", kind: "text" },
      { key: "key", label: "Key / token", kind: "secret", mono: true },
      { key: "secret", label: "Secret", kind: "secret", mono: true },
      { key: "environment", label: "Environment", kind: "select", options: ["", "production", "staging", "development"] },
    ],
    defaults: { service: "", key: "", secret: "", environment: "" },
  },
  ssh_key: {
    label: "SSH key",
    icon: Terminal,
    fields: [
      { key: "public_key", label: "Public key", kind: "textarea", mono: true },
      { key: "private_key", label: "Private key", kind: "secretarea", mono: true },
      { key: "passphrase", label: "Passphrase", kind: "secret" },
      { key: "fingerprint", label: "Fingerprint", kind: "text", mono: true },
    ],
    defaults: { public_key: "", private_key: "", passphrase: "", fingerprint: "" },
  },
  server: {
    label: "Server / database",
    icon: Database,
    fields: [
      { key: "host", label: "Host", kind: "text", mono: true },
      { key: "port", label: "Port", kind: "number" },
      { key: "username", label: "Username", kind: "text" },
      { key: "password", label: "Password", kind: "secret", generator: true },
      { key: "database", label: "Database", kind: "text" },
      { key: "connection_string", label: "Connection string", kind: "secret", mono: true },
    ],
    defaults: { host: "", port: null, username: "", password: "", database: "", connection_string: "" },
  },
  secure_note: { label: "Secure note", icon: FileText, fields: [], defaults: {} },
  document: { label: "File attachment", icon: Paperclip, fields: [], defaults: {} },
};

export const TYPE_ORDER: ItemType[] = ["login", "authenticator", "recovery_codes", "api_key", "ssh_key", "server", "secure_note", "document"];

export function emptyItem(type: ItemType) {
  return {
    title: "",
    data: { type, ...structuredClone(TYPES[type].defaults) },
    notes: "",
    tags: [] as string[],
    custom_fields: [] as { name: string; value: string; kind: "text" | "hidden" | "url" | "date" }[],
    password_history: [],
    attachments: [],
    expires_at: null as string | null,
  };
}

import type { ReactNode } from "react";
import { Logo } from "@arevei/ui";

export function AuthLayout({ children, footer }: { children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="flex min-h-full flex-col items-center justify-center px-4 py-10">
      <div className="mb-8">
        <Logo size={30} gradient />
      </div>
      <div className="av-card w-full max-w-[440px] p-6 sm:p-8">{children}</div>
      {footer ? <div className="mt-6 text-center text-[13px] text-muted">{footer}</div> : null}
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div role="alert" className="rounded-sm border border-danger px-3 py-2 text-[13px] text-danger" data-testid="form-error">
      {error}
    </div>
  );
}

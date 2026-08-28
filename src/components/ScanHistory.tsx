import { History, RotateCw, Trash2 } from "lucide-react";
import type { HistoryEntry } from "@/lib/scan-history";
import { Button } from "@/components/ui/button";

const GRADE_TONE: Record<string, string> = {
  A: "text-sev-pass",
  B: "text-sev-pass",
  C: "text-sev-medium",
  D: "text-sev-high",
  F: "text-sev-critical",
};

function when(iso: string) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function ScanHistory({
  entries,
  onRerun,
  onRemove,
  onClear,
}: {
  entries: HistoryEntry[];
  onRerun: (host: string) => void;
  onRemove: (id: string) => void;
  onClear: () => void;
}) {
  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h2 className="flex items-center gap-2 font-mono text-sm tracking-widest uppercase">
          <History className="size-4" /> Scan history
        </h2>
        {entries.length ? (
          <Button variant="ghost" size="sm" className="font-mono text-xs" onClick={onClear}>
            Clear all
          </Button>
        ) : null}
      </div>

      {entries.length === 0 ? (
        <p className="px-4 py-6 text-sm text-muted-foreground">
          No scans yet. Past targets, dates and grades will be listed here on this device.
        </p>
      ) : (
        <ul className="divide-y divide-border">
          {entries.map((e) => (
            <li key={e.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <span
                className={`w-8 shrink-0 font-mono text-2xl leading-none font-bold ${
                  GRADE_TONE[e.grade] ?? "text-foreground"
                }`}
              >
                {e.grade}
              </span>
              <div className="min-w-0 flex-1">
                <p className="truncate font-mono text-sm text-accent">{e.host}</p>
                <p className="font-mono text-[11px] text-muted-foreground">
                  {when(e.scannedAt)} · {e.score}/100 · {e.counts.critical ?? 0} critical ·{" "}
                  {e.counts.high ?? 0} high
                </p>
              </div>
              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  className="font-mono text-xs"
                  onClick={() => onRerun(e.host)}
                >
                  <RotateCw className="size-3" /> Re-scan
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`Remove ${e.host} from history`}
                  onClick={() => onRemove(e.id)}
                >
                  <Trash2 className="size-4" />
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

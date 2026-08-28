import { useCallback, useEffect, useState } from "react";
import type { ScanReport, Severity } from "./scan.server";

export type HistoryEntry = {
  id: string;
  host: string;
  scannedAt: string;
  score: number;
  grade: string;
  counts: Partial<Record<Severity, number>>;
};

const KEY = "netprobe.scan-history.v1";
const LIMIT = 25;
const EVENT = "netprobe:history";

function read(): HistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    const parsed = raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function write(entries: HistoryEntry[]) {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(entries));
  } catch {
    /* quota / private mode */
  }
  window.dispatchEvent(new Event(EVENT));
}

export function toEntry(r: ScanReport): HistoryEntry {
  const counts: Partial<Record<Severity, number>> = {};
  for (const f of r.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return {
    id: `${r.host}-${r.scannedAt}`,
    host: r.host,
    scannedAt: r.scannedAt,
    score: r.score,
    grade: r.grade,
    counts,
  };
}

export function useScanHistory() {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);

  useEffect(() => {
    const sync = () => setEntries(read());
    sync();
    window.addEventListener(EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const record = useCallback((report: ScanReport) => {
    const entry = toEntry(report);
    write([entry, ...read().filter((e) => e.id !== entry.id)].slice(0, LIMIT));
  }, []);

  const remove = useCallback((id: string) => {
    write(read().filter((e) => e.id !== id));
  }, []);

  const clear = useCallback(() => write([]), []);

  return { entries, record, remove, clear };
}

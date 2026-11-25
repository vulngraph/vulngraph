// CSV export shared by every "Export CSV" button. Cells come from the API and
// so from attacker-influenceable data (finding titles, resource names, tags):
// a cell starting with = + - @ (or a tab / carriage return that some
// spreadsheets strip before parsing) runs as a formula when the file is opened
// in Excel, Sheets or LibreOffice. Such text cells get a leading single quote,
// which spreadsheets treat as "this is text". Numbers are written as-is: they
// are our own values, and quoting would turn a negative number into text.

export type CSVValue = string | number | undefined | null;

const FORMULA_START = /^[=+\-@\t\r]/;

export function csvCell(v: CSVValue): string {
  if (v === undefined || v === null) return "";
  let s = String(v);
  if (typeof v === "string" && FORMULA_START.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCSV(header: string[], rows: CSVValue[][]): string {
  return [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\n");
}

export function downloadCSV(filename: string, csv: string) {
  const anchor = document.createElement("a");
  anchor.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
  anchor.download = filename;
  anchor.click();
}

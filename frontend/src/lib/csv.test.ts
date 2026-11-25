import { expect, test } from "vitest";
import { csvCell, toCSV } from "./csv";

test.each([
  ["=HYPERLINK(\"https://evil.example\",\"x\")", `"'=HYPERLINK(""https://evil.example"",""x"")"`],
  ["+1+cmd|' /C calc'!A0", "'+1+cmd|' /C calc'!A0"],
  ["-2+3", "'-2+3"],
  ["@SUM(A1)", "'@SUM(A1)"],
  ["\t=1", "'\t=1"],
  ["\r=1", `"'\r=1"`],
])("neutralises formula-leading text %j", (input, want) => {
  expect(csvCell(input)).toBe(want);
});

test("leaves ordinary text, numbers and empties alone", () => {
  expect(csvCell("bucket-1")).toBe("bucket-1");
  expect(csvCell("a=b")).toBe("a=b");
  expect(csvCell(-3)).toBe("-3");
  expect(csvCell(0)).toBe("0");
  expect(csvCell(undefined)).toBe("");
  expect(csvCell(null)).toBe("");
});

test("quotes cells with separators, quotes or newlines", () => {
  expect(csvCell("a,b")).toBe('"a,b"');
  expect(csvCell('say "hi"')).toBe('"say ""hi"""');
  expect(csvCell("two\nlines")).toBe('"two\nlines"');
});

test("toCSV joins header and rows", () => {
  expect(toCSV(["id", "name"], [["1", "=x"], ["2", "ok"]])).toBe("id,name\n1,'=x\n2,ok");
});

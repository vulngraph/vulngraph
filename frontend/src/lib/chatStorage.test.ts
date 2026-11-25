import { beforeEach, expect, test } from "vitest";
import { clearChatStorage, openChatStore } from "./chatStorage";

beforeEach(() => localStorage.clear());

test("each user's chat lives under its own key", () => {
  openChatStore("u1").save("sessions", "[1]");
  openChatStore("u2").save("sessions", "[2]");
  expect(openChatStore("u1").load("sessions")).toBe("[1]");
  expect(openChatStore("u2").load("sessions")).toBe("[2]");
  expect(openChatStore("u3").load("sessions")).toBeNull();
});

test("clearing removes every user's chat keys and nothing else", () => {
  openChatStore("u1").save("sessions", "[1]");
  openChatStore("u1").save("active", "s1");
  openChatStore("u2").save("sessions", "[2]");
  localStorage.setItem("graph.theme", "dark");

  clearChatStorage();

  expect(Object.keys(localStorage)).toEqual(["graph.theme"]);
});

test("a store opened before a clear cannot write the transcript back", () => {
  const stale = openChatStore("u1");
  clearChatStorage();
  stale.save("sessions", "[1]");
  expect(localStorage.getItem("graph.chat.u1.sessions")).toBeNull();
  expect(stale.load("sessions")).toBeNull();

  const fresh = openChatStore("u1");
  fresh.save("sessions", "[2]");
  expect(fresh.load("sessions")).toBe("[2]");
});

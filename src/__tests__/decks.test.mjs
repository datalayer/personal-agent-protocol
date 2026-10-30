/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The four cases as decks: the package's `./decks` entry, and the docs pages that
// show them. One deck per case, in the deck format, each naming its case, at draft
// 0.3: every operation is asked of the person, and nothing stands in for them.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import { parse } from "yaml";

import { PAP_DECKS, PAP_DECK_IDS, papDeck } from "../../lib/decks/index.js";

const ROOT = new URL("../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT), "utf8");

const CASES = [
  ["pap-a-person-and-a-company", "A Person and a Company"],
  ["pap-approve-once", "A Change, Approved Once"],
  ["pap-your-application-a-company", "Your Application, a Company"],
  ["pap-two-companies", "Two Companies Together"],
];

// The slide types of `@datalayer/decks` (its `SlideType`).
const SLIDE_TYPES = new Set([
  "title", "section", "statement", "bullets", "columns", "two-columns", "three-columns",
  "metrics", "artifact", "image", "screenshot", "quote", "comparison", "flow",
  "feature-showcase", "timeline", "chart", "logos", "code", "mermaid", "component", "closing",
]);

// What each slide type must say (the engine's `validateDeck`).
const REQUIRED = {
  title: ["title"],
  statement: ["statement"],
  bullets: ["items"],
  comparison: ["columns", "rows"],
  flow: ["items"],
  mermaid: ["diagram"],
  closing: ["title"],
};

const textOf = (value) =>
  typeof value === "string"
    ? value
    : Array.isArray(value)
      ? value.map(textOf).join(" ")
      : value && typeof value === "object"
        ? Object.values(value).map(textOf).join(" ")
        : "";

test("the package exports one deck per case, in the order of the cases", () => {
  assert.deepEqual([...PAP_DECK_IDS], CASES.map(([id]) => id));
  assert.deepEqual(PAP_DECKS.map((deck) => deck.id), CASES.map(([id]) => id));
  const manifest = JSON.parse(read("package.json"));
  assert.deepEqual(manifest.exports["./decks"], {
    types: "./lib/decks/index.d.ts",
    import: "./lib/decks/index.js",
  });
  assert.ok(manifest.dependencies.yaml, "the entry parses its YAML at run time");
  assert.match(manifest.scripts.build, /src\/decks\/index\.ts/);
});

test("papDeck finds a deck by its case, and refuses any other", () => {
  assert.equal(papDeck("pap-approve-once").title, "A Change, Approved Once");
  assert.throws(() => papDeck("ucp-a-purchase-approved"), /no deck/);
});

for (const [id, name] of CASES) {
  test(`${id}: its YAML is its spec, in the deck format`, () => {
    const deck = papDeck(id);
    assert.deepEqual(parse(deck.yaml), deck.spec);
    assert.equal(typeof deck.spec.deck.title, "string");
    assert.equal(deck.spec.deck.template, "datalayer");
    assert.ok(deck.spec.slides.length >= 6, "a deck explains its case");
    assert.ok(deck.spec.slides.length <= 10, "the docs site allows ten slides");
    deck.spec.slides.forEach((slide, index) => {
      const where = `${id} slide ${index}`;
      assert.ok(SLIDE_TYPES.has(slide.type), `${where}: ${slide.type}`);
      for (const key of REQUIRED[slide.type] ?? []) {
        assert.ok(slide[key]?.length, `${where} needs ${key}`);
      }
      assert.ok(slide.notes?.trim().length > 40, `${where} has notes to read aloud`);
    });
    const ids = deck.spec.slides.map((slide) => slide.id);
    assert.equal(new Set(ids).size, ids.length, "slide ids are distinct");
  });

  test(`${id}: it names its case`, () => {
    const deck = papDeck(id);
    assert.equal(deck.title, name);
    assert.equal(deck.spec.deck.title, name);
    assert.equal(deck.spec.slides[0].type, "title");
    assert.equal(deck.spec.slides[0].id, id);
    assert.equal(deck.spec.slides.at(-1).type, "closing");
  });

  test(`${id}: it says draft 0.3 and no standing permission`, () => {
    const words = textOf(papDeck(id).spec);
    assert.match(words, /draft 0\.3/);
    assert.doesNotMatch(words, /standing|approved_by|in advance without asking/i);
  });

  test(`${id}: a docs page shows it, from the package, under its name`, () => {
    const path = `docs/docs/examples/cases/${id}.mdx`;
    assert.ok(existsSync(new URL(path, ROOT)), path);
    const page = read(path);
    assert.match(page, new RegExp(`^title: ${name}$`, "m"));
    assert.ok(page.includes(`<CaseDeck id="${id}" />`), `${path} shows its deck`);
    assert.ok(read("docs/sidebars.js").includes(`"examples/cases/${id}"`), "in the sidebar");
    assert.ok(!page.includes(".deck.json"), "one source: the package");
  });
}

test("the sidebar lists the cases in their order, ahead of the flows", () => {
  const sidebars = read("docs/sidebars.js");
  const at = CASES.map(([id]) => sidebars.indexOf(`"examples/cases/${id}"`));
  assert.deepEqual(at, [...at].sort((a, b) => a - b));
  assert.ok(at[3] < sidebars.indexOf('"examples/company-discovery"'));
});

test("the words a company says are the demo company's own", () => {
  const manzanita = read("personal_agent_protocol/demo/manzanita.py").replace(/"\s*\n\s*"/g, "");
  const said = textOf(papDeck("pap-a-person-and-a-company").spec) + textOf(papDeck("pap-approve-once").spec);
  for (const line of [
    "I can look that up once you sign in to your Manzanita account.",
    "Your order ord_7Hk2: Ridge Jacket, size M, delivered.",
    "Exchange the Ridge Jacket (M) from order ord_7Hk2 for the insulated Ridge Jacket (M), USD 70.00 more.",
  ]) {
    assert.ok(manzanita.includes(line), `the demo says: ${line}`);
    assert.ok(said.includes(line), `a deck says: ${line}`);
  }
});

test("no deck of the docs site keeps a standing permission: draft 0.3 asks every time", () => {
  for (const name of ["two-companies", "operations", "user-with-a-company"]) {
    assert.doesNotMatch(read(`docs/decks/examples/${name}.deck.json`), /standing|approved_by|Session Key/i);
  }
});

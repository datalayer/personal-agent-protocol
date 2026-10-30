/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * The Personal Agent Protocol's four cases, each explained as a deck.
 *
 * `@datalayer/personal-agent-protocol/decks`: a deck is a specification, its
 * slides, their types and their words, in the format of `@datalayer/decks`.
 * Each is written as YAML in a TypeScript file of its own, so `yaml` is what a
 * tool stores or serves and `spec` is the same deck parsed, ready to draw.
 * The documentation site and the Datalayer home page read them here, in the
 * same order, under the same names, so the three tell one story.
 *
 * Decks describe draft 0.3: every operation is asked of the person, and
 * nothing approves in their place. No part of the SDK proper imports this
 * entry, and it imports no part of the SDK.
 */

import { parse } from "yaml";

import { yaml as aPersonAndACompany } from "./pap-a-person-and-a-company.js";
import { yaml as approveOnce } from "./pap-approve-once.js";
import { yaml as twoCompanies } from "./pap-two-companies.js";
import { yaml as yourApplicationACompany } from "./pap-your-application-a-company.js";

/** The cases, in the order they are told. */
export const PAP_DECK_IDS = [
  "pap-a-person-and-a-company",
  "pap-approve-once",
  "pap-your-application-a-company",
  "pap-two-companies",
] as const;

export type PapDeckId = (typeof PAP_DECK_IDS)[number];

/** One slide: its `type` says what else it holds (`SlideSpec` of `@datalayer/decks`). */
export type PapDeckSlide = {
  type: string;
  id?: string;
  title?: string;
  notes?: string;
  [key: string]: unknown;
};

/** A deck's specification, assignable to `DeckSpec` of `@datalayer/decks`. */
export type PapDeckSpec = {
  deck: { title: string; subtitle?: string; template: string; [key: string]: unknown };
  slides: PapDeckSlide[];
};

export type PapDeck = {
  /** The case it explains. */
  id: PapDeckId;
  /** The case's name. */
  title: string;
  /** The deck as YAML. */
  yaml: string;
  /** The same deck, parsed. */
  spec: PapDeckSpec;
};

const SOURCES: Record<PapDeckId, string> = {
  "pap-a-person-and-a-company": aPersonAndACompany,
  "pap-approve-once": approveOnce,
  "pap-your-application-a-company": yourApplicationACompany,
  "pap-two-companies": twoCompanies,
};

/** Every deck, in the order of the cases. */
export const PAP_DECKS: readonly PapDeck[] = PAP_DECK_IDS.map((id) => {
  const yaml = SOURCES[id];
  const spec = parse(yaml) as PapDeckSpec;
  return { id, title: spec.deck.title, yaml, spec };
});

/** The deck of a case; refused when the case has none. */
export function papDeck(id: string): PapDeck {
  const deck = PAP_DECKS.find((one) => one.id === id);
  if (deck === undefined) {
    throw new Error(`There is no deck for the case "${id}".`);
  }
  return deck;
}

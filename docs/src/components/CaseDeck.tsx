/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * A case's deck, from the package's own export: the same deck the Datalayer
 * home page presents, the link to the case played there, and its YAML.
 */

import type { JSX } from 'react';
import CodeBlock from '@theme/CodeBlock';
import Deck from '@theme/Deck';
import Link from '@docusaurus/Link';
import { PAP_DECKS, papDeck } from '@datalayer/personal-agent-protocol/decks';

const played = (id: string): string => `https://datalayer.ai/examples?stage=${id}`;

export default function CaseDeck({ id }: { id: string }): JSX.Element {
  const deck = papDeck(id);
  return (
    <>
      <Deck spec={deck.spec} />
      <p>
        <Link href={played(id)}>Play this case on datalayer.ai</Link>, where you take the person’s part.
      </p>
      <details>
        <summary>
          This deck as YAML, from <code>@datalayer/personal-agent-protocol/decks</code>
        </summary>
        <CodeBlock language="yaml">{deck.yaml}</CodeBlock>
      </details>
    </>
  );
}

/** The cases, in their order, with where each is explained and played. */
export function CaseList(): JSX.Element {
  return (
    <ol>
      {PAP_DECKS.map(deck => (
        <li key={deck.id}>
          <Link to={`/examples/cases/${deck.id}`}>{deck.title}</Link>:{' '}
          {String(deck.spec.slides[0]?.subtitle ?? '')} <Link href={played(deck.id)}>Play it</Link>.
        </li>
      ))}
    </ol>
  );
}

/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/** Your Application, a Company, as a deck in YAML. */
export const yaml = `deck:
  title: Your Application, a Company
  subtitle: Personal Agent Protocol, by example
  template: datalayer
slides:
  - id: pap-your-application-a-company
    type: title
    title: Your Application, a Company
    subtitle: An application answers people’s own agents as a company does.
    meta: Personal Agent Protocol · draft 0.3 · a case
    notes: >-
      So far a person’s agent has gone to a shop. Now look from the other side.
      You built an application, and you want people’s own agents to use it.
      Under the protocol, your application is a company.
  - id: who
    type: columns
    title: Who is in this case
    columns:
      - heading: Maker
        type: text
        content: Builds the application and decides what it offers.
      - heading: Exchange desk
        type: text
        content: The application, answering as a company.
      - heading: Sam’s agent
        type: text
        content: Somebody’s personal agent, never seen before.
      - heading: Sam
        type: text
        content: A customer. His approval is the one that counts.
    notes: >-
      Four parties. The Maker built an application called Exchange desk. Sam is
      a customer and Sam’s agent is his own personal agent, which the Maker has
      never heard of. Nothing is arranged between them in advance.
  - id: what-is-public
    type: bullets
    title: What the Maker makes public
    items:
      - Its own domain, with the page personal agents read first
      - "How agents reach it: its agent, its API and its server for agents"
      - "What it offers: orders:read and orders:write"
      - What changes something is proposed, and done only with the person’s approval
    notes: >-
      The Maker turns on working with personal agents, and names what the
      application offers. That publishes one page at the application’s own
      domain, which says how to reach it and how a person signs in. What changes
      something is an operation the application proposes, never something an
      agent may simply do.
  - id: what-happens
    type: mermaid
    title: What happens
    diagram: |-
      sequenceDiagram
        participant Agent as Sam's agent
        actor Sam
        participant App as Exchange desk
        Agent->>App: Do you exchange jackets?
        App-->>Agent: Yes. Sign in to see your orders.
        Agent->>Sam: Sign in at Exchange desk
        Sam->>App: Signs in on its page
        App-->>Agent: An operation, order ord_7Hk2 for size L
        Agent->>Sam: Shows it
        Sam->>Agent: Approve
        Agent->>App: The same request, with his approval
        App-->>Agent: Done, once
    notes: >-
      Sam’s agent finds the application by its domain and asks before anybody
      signed in. The application answers what anybody may ask, as its Maker
      allowed. Sam signs in on the application’s page. The application
      proposes the exchange, Sam approves it, and it is done once.
  - id: whose-words
    type: two-columns
    title: The proposal is not the model’s
    left:
      heading: The application’s model gives
      type: bullets
      items:
        - The terms, as data
    right:
      heading: The Maker wrote
      type: text
      content: >-
        The sentence people read, once, ahead of time. “Exchange order ord_7Hk2
        for size L.”
    notes: >-
      A model may fill in which order and which size. The sentence Sam reads
      is the Maker’s own, so what he approves says what the application will
      actually do, however the model happened to phrase things.
  - id: does-it
    type: flow
    title: On the company’s side
    items:
      - label: "1"
        title: Checks
        detail: This Session may approve, and this revision is one it returned
      - label: "2"
        title: Performs
        detail: Once, with the application’s own code, on exactly those terms
      - label: "3"
        title: Records
        detail: Which agent, which revision, approved by Sam and when
        current: true
    notes: >-
      When the approval arrives, the application checks that this Session may
      approve, that the action has not been performed already, and that the
      revision is one it returned, unexpired, for exactly this request. Its own
      code does the work once, and the record keeps the approval.
  - id: why
    type: statement
    title: Why it matters
    statement: >-
      One published page and **every person’s agent can use your application**,
      with its rules intact and no integration built for each of them.
    notes: >-
      The Maker writes no integration per agent, and does not give up control.
      Sign-in stays on the application’s page, what anybody may ask is what the
      Maker allowed, and every change is approved by the person it affects.
  - id: run-it
    type: closing
    title: Build one
    cta: The next case puts two companies together, Two Companies Together.
    notes: >-
      This case is a story, described at draft 0.3 of the protocol. The SDK’s
      company kit is how an application takes this role: the company guide
      shows it, and the reference company in the SDK is built that way.
`;

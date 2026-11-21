/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/** A Change, Approved Once, as a deck in YAML. */
export const yaml = `deck:
  title: A Change, Approved Once
  subtitle: Personal Agent Protocol, by example
  template: datalayer
slides:
  - id: pap-approve-once
    type: title
    title: A Change, Approved Once
    subtitle: The shop proposes an exchange; Ada approves its exact terms, and it is done once.
    meta: Personal Agent Protocol · 1.0 · a case
    notes: >-
      Reading an order is harmless. Changing one costs money. This case is
      about the moment an agent is about to do something that matters, and how
      the protocol makes sure the person decides, and that the company knows
      who approved.
  - id: who
    type: three-columns
    title: Who is in this case
    columns:
      - heading: Ada
        type: text
        content: The person. The decision is hers.
      - heading: Her agent
        type: text
        content: Asks, shows her what is proposed, and carries her answer.
      - heading: Manzanita Outfitters
        type: text
        content: A company. It proposes, then performs what she approved.
    notes: >-
      The same three parties as the first case, and Ada is already signed in.
      The jacket arrived and it is not warm enough, so she asks her agent to
      exchange it for the insulated one.
  - id: what-happens
    type: mermaid
    title: What happens
    diagram: |-
      sequenceDiagram
        actor Ada
        participant Agent as Her agent
        participant M as Manzanita
        Ada->>Agent: Exchange it for the insulated one
        Agent->>M: Asks for the exchange
        M-->>Agent: An operation, not done yet
        Agent->>Ada: Shows its summary and terms
        Ada->>Agent: Approve
        Agent->>M: The same request, with her approval
        M-->>Agent: What it did
        Agent->>Ada: Done, once
    notes: >-
      Ada asks. The agent asks the company. The company does not do it yet: it
      answers with an operation, the exact terms of what it proposes. The
      agent shows that to Ada. If she approves, the agent makes the same
      request again with her approval attached, and the company does it.
  - id: operation
    type: two-columns
    title: The company proposes an operation
    left:
      heading: In the company’s words
      type: text
      content: >-
        Exchange the Ridge Jacket (M) from order ord_7Hk2 for the insulated
        Ridge Jacket (M), USD 70.00 more.
    right:
      heading: What travels with it
      type: bullets
      items:
        - Its terms, as data the agent can check
        - A revision, naming this exact version
        - When it expires
    notes: >-
      An operation always has terms, what the company proposes as data, and
      here a summary too, the same thing written by the company in plain
      language. The agent compares the two with what Ada asked for and points
      out any difference. A revision names this exact version, and the
      operation expires.
  - id: asked
    type: statement
    title: Every approval says who approved
    statement: >-
      Here **Ada approves it herself**. The approval says so, and the company
      knows whether it came from her or from her agent.
    attribution: Poppy 1.0, with version 3 of the Operations extension
    notes: >-
      At 1.0 every approval names its approver, the person or the personal
      agent. Her agent may approve only on an instruction Ada gave it in its
      own interface, and only when its check shows the terms fall within it;
      every doubt goes to Ada. The company sees which it is and may decline an
      approval her agent gave. Text from the company is never an approval, and
      the model can explain a proposal but cannot accept it.
  - id: approved-or-not
    type: comparison
    title: What Ada’s answer does
    columns:
      - Ada approves
      - Ada declines
    rows:
      - label: The agent
        values:
          - Sends the same request with her approval
          - Sends nothing
      - label: The company
        values:
          - Performs that exact revision
          - Performs nothing
      - label: The jacket
        values:
          - Exchanged, USD 70.00 charged
          - Stays as it is
    notes: >-
      She may say no, and then her agent sends nothing, nothing happens, and the
      operation simply expires. If she approves, her approval
      covers one revision. If the terms change, the company returns a new
      revision and Ada is asked again: approving version one never approves
      version two.
  - id: once
    type: flow
    title: Done at most once
    items:
      - label: "1"
        title: Send
        detail: The approved request goes out
      - label: "2"
        title: No answer
        detail: The network fails, or the company is busy
      - label: "3"
        title: Send it again
        detail: The same approval, unchanged
      - label: "4"
        title: Same answer
        detail: The company repeats its result and performs nothing new
        current: true
    notes: >-
      Networks fail. If the agent does not hear back it sends the same approval
      again, and the company answers with its original response. However many
      times an approval arrives, the action is performed at most once. If the
      outcome stays unknown, the agent finds out before it asks Ada again.
  - id: why
    type: statement
    title: Why it matters
    statement: >-
      The agent can do the work; **the decision stays with the person**, on
      terms the company wrote and cannot change afterwards.
    notes: >-
      Ada does not have to trust the model’s reading of a chat, and the company
      does not have to trust that a chat message meant yes. Both hold the same
      exact terms, and the company’s record keeps the revision that was
      approved, who approved it, and when.
  - id: run-it
    type: closing
    title: Run it yourself
    cta: The next case turns it round, Your Application, a Company.
    notes: >-
      This case is played from the SDK’s demo company and described at version
      1.0 of the protocol, Poppy 1.0, as published, with version 3 of the
      Operations extension. The Operations example flow shows the exact
      revision, new terms, and a lost answer sent again.
`;

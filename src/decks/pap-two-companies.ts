/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/** Two Companies Together, as a deck in YAML. */
export const yaml = `deck:
  title: Two Companies Together
  subtitle: Personal Agent Protocol, by example
  template: datalayer
slides:
  - id: pap-two-companies
    type: title
    title: Two Companies Together
    subtitle: An accounting firm pays a bill at Ada’s bank, and every payment is Ada’s approval.
    meta: Personal Agent Protocol · draft 0.3 · a case
    notes: >-
      Ada’s accounting firm pays her suppliers from her bank account. That means
      one company acting for a person at another company, with real money, and
      it needs nothing new from the protocol.
  - id: who
    type: columns
    title: Who is in this case
    columns:
      - heading: Ada
        type: text
        content: The person. Every payment is hers to approve.
      - heading: Atlas
        type: text
        content: Ada’s personal agent.
      - heading: Ledgerly
        type: text
        content: An accounting firm. A company to Ada, an agent at her bank.
      - heading: Northwind Bank
        type: text
        content: Ada’s bank. It proposes each payment and sends it.
    notes: >-
      Four parties. Ada and her agent Atlas. Ledgerly, an accounting firm. And
      Northwind Bank. Ledgerly is the interesting one, because it plays two
      roles at once.
  - id: composition
    type: statement
    title: Composition, not a new protocol
    statement: >-
      Draft 0.3 defines **no company-to-company protocol**. Two ordinary
      relationships, for the same person, are enough.
    notes: >-
      There is no special protocol between companies. To Atlas, Ledgerly is a
      company like any other. To Northwind, Ledgerly is a personal agent acting
      for Ada, with an identity of its own on its own domain.
  - id: roles
    type: mermaid
    title: Ledgerly plays both roles
    diagram: |-
      flowchart LR
        A["Ada and Atlas"] -- "as to any company" --> L1["Ledgerly, a company"]
        L1 --> L2["Ledgerly, a personal agent"]
        L2 -- "as any personal agent" --> N["Northwind Bank"]
    notes: >-
      Read it left to right. Ada and Atlas talk to Ledgerly as they would talk
      to any company. Inside Ledgerly, the same firm is a personal agent at
      Northwind. Northwind only ever sees a personal agent called Ledgerly.
  - id: connect
    type: statement
    title: Ada connects Ledgerly herself
    statement: >-
      On northwind.example, with a code Ledgerly shows her. Ledgerly **never
      sees her bank password**.
    notes: >-
      Before it can do anything at the bank, Ledgerly needs Ada’s Northwind
      account. Ada approves Ledgerly on Northwind’s own page, with a code. It is
      the same sign-in any personal agent would ask for, and the password never
      leaves the bank.
  - id: what-happens
    type: mermaid
    title: The first payment
    diagram: |-
      sequenceDiagram
        actor Ada
        participant Atlas
        participant L as Ledgerly
        participant N as Northwind
        Ada->>Atlas: Ask Ledgerly to pay INV-0042
        Atlas->>L: Pay INV-0042
        L->>N: Pay INV-0042
        N-->>L: An operation, EUR 1250.00 to Acme GmbH
        L-->>Atlas: Its own operation, quoting the bank's
        Ada->>Atlas: Approve
        Atlas->>L: The approval
        L->>N: Unchanged? The approval of that revision
        N-->>L: Sent, bank reference NW-0001
        L-->>Atlas: What the bank says, as written
    notes: >-
      Northwind proposes the payment and does not make it yet. Ledgerly passes
      the proposal on to Ada, quoting the bank as written. Ada approves. Ledgerly
      checks that the bank’s revision has not changed, sends the bank the
      approval of that exact revision, and relays what the bank says it did.
  - id: every-payment
    type: comparison
    title: “Pay Acme without asking me each time”
    columns:
      - Amount
      - What happens
    rows:
      - label: INV-0042
        values:
          - EUR 1250.00
          - Paid, with Ada’s approval
      - label: INV-0043
        values:
          - EUR 980.00
          - Waits for Ada’s approval
    notes: >-
      Ada asks not to be bothered, and the answer is no. Every operation the bank
      returns goes to Ada, this one and the next, and nothing approves one in
      her name. So the next bill, INV-0043, waits for her like the first did.
  - id: seen
    type: two-columns
    title: What the model sees
    left:
      heading: Visible
      type: bullets
      items:
        - Summaries, as the companies wrote them
        - Who approved each payment
    right:
      heading: Never
      type: bullets
      items:
        - A token of any party
        - A device code
        - A proof
    notes: >-
      The model can explain what happened and who approved it. It never sees a
      token, a code or a proof belonging to any of the three parties.
  - id: why
    type: statement
    title: Why it matters
    statement: >-
      Firms can work for a person across companies, and **the person’s approval
      reaches the bank intact**.
    notes: >-
      Northwind’s records show the exact revision approved and when. Ledgerly can
      only ever carry an approval Ada gave. No company needed a bilateral
      integration, and no new protocol was invented.
  - id: run-it
    type: closing
    title: Run it yourself
    cta: The Two companies example flow runs all three parties in one process.
    notes: >-
      This case is the SDK’s own demonstration, described at draft 0.3 of the
      protocol, with Ledgerly and Northwind Bank as demo companies. Read the
      Operations guide for approvals, and the company guide to build either side.
`;

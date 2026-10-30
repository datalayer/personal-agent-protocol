/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/** A Person and a Company, as a deck in YAML. */
export const yaml = `deck:
  title: A Person and a Company
  subtitle: Personal Agent Protocol, by example
  template: datalayer
slides:
  - id: pap-a-person-and-a-company
    type: title
    title: A Person and a Company
    subtitle: Ada’s agent asks a shop about her order, and she signs in at the shop itself.
    meta: Personal Agent Protocol · draft 0.3 · a case
    notes: >-
      Ada bought a jacket from an online shop and wants to know where it is.
      She asks her personal agent. This is the first thing the Personal Agent
      Protocol is for: a person’s own agent working with a company, with no
      integration built between the two.
  - id: who
    type: three-columns
    title: Who is in this case
    columns:
      - heading: Ada
        type: text
        content: The person. She decides what her agent may do.
      - heading: Her agent
        type: text
        content: Works for Ada. In the SDK’s runnable example it is called Atlas.
      - heading: Manzanita Outfitters
        type: text
        content: A company, at manzanita.example, with its own agent, its pages and its API.
    notes: >-
      Three parties. Ada is the person. Her agent works for her and nobody
      else. Manzanita Outfitters is a company, and it has never heard of this
      agent before. Nothing was set up between them in advance.
  - id: what-happens
    type: mermaid
    title: What happens
    diagram: |-
      sequenceDiagram
        actor Ada
        participant Agent as Her agent
        participant M as Manzanita
        Ada->>Agent: Has my Ridge Jacket arrived?
        Agent->>M: Reads what the company publishes
        Agent->>M: Asks, signed out
        M-->>Agent: Sign in first, and what it needs
        Agent->>Ada: Sign in at Manzanita
        Ada->>M: Signs in on Manzanita's page
        M-->>Agent: Her order, delivered
        Agent->>Ada: Yes, it was delivered
    notes: >-
      Follow it from the top. Ada asks her agent. The agent finds the company
      by its domain and reads what it publishes. It asks its question before
      anybody signed in. The company says it needs a sign-in and names what
      for. Ada signs in on the company’s own page, the company answers, and
      the agent tells Ada.
  - id: found
    type: flow
    title: Step by step, before anybody signs in
    items:
      - label: "1"
        title: Find
        detail: The agent reads the company’s published page by its domain
      - label: "2"
        title: Check
        detail: The domain and who signs its sign-ins belong together
      - label: "3"
        title: Open a Session
        detail: The agent proves who it is, signed out
      - label: "4"
        title: Ask
        detail: A conversation answers what anybody may ask
        current: true
    notes: >-
      Every company publishes one page for personal agents, at a well-known
      address on its domain. The agent reads it and checks that the domain and
      whoever signs the company’s sign-ins belong together. Then it opens a
      Session, proving its own identity with a short-lived key, and starts a
      conversation. Nobody is signed in yet, so the company answers only what
      anybody may ask.
  - id: asked-to-sign-in
    type: statement
    title: The company asks for a sign-in
    statement: >-
      “I can look that up once you sign in to your Manzanita account.”
    attribution: Manzanita’s agent, and it names what it needs. See your orders.
    notes: >-
      The company’s agent answers in the conversation, and alongside that
      answer it sends a sign-in request that names what it needs, here to see
      Ada’s orders. The agent does not guess at this and does not ask for a
      password. It passes the request to Ada.
  - id: sign-in
    type: two-columns
    title: Ada signs in at the company
    left:
      heading: On Manzanita’s own page
      type: bullets
      items:
        - The agent never sees her password
        - She can keep fewer permissions than it asks for
        - The Session the agent already has becomes signed in
    right:
      heading: What the agent gets
      type: bullets
      items:
        - A sign-in of its own, for Ada and this agent only
        - Tokens kept by the host, out of the model’s reach
        - The order, answered by the company
    notes: >-
      Ada signs in on manzanita.example, never in the chat. She can allow less
      than the agent asked for. The same Session carries on, now signed in,
      and the company answers with what it knows. The tokens are held by the
      host around the agent, so the model that writes the agent’s replies
      never sees them.
  - id: answer
    type: statement
    title: Then the company answers
    statement: >-
      “Your order ord_7Hk2: Ridge Jacket, size M, delivered.”
    attribution: Manzanita’s agent. Her agent tells Ada, and keeps a record of what it did.
    notes: >-
      The company answers, the agent tells Ada that her jacket was delivered,
      and a record shows what it did: signed in at Manzanita for Ada, allowed
      to see her orders, read one order. Ada can see that record, and can
      disconnect the agent whenever she likes.
  - id: why
    type: statement
    title: Why it matters
    statement: >-
      Any person’s agent can work with **any company that publishes the
      protocol**, and the person’s password stays between her and the company.
    notes: >-
      Without a protocol, an agent either scrapes a website with the person’s
      password, or someone builds an integration for each pair of agent and
      company. Here the agent needs no prior arrangement, the company keeps
      its own sign-in page, and the person decides what is allowed.
  - id: run-it
    type: closing
    title: Run it yourself
    cta: The next case takes the same order further, A Change, Approved Once.
    notes: >-
      This case is played from the SDK’s demo company, Manzanita Outfitters,
      and described at draft 0.3 of the protocol. The example flow called A
      user with a company runs the whole journey in one process, both sides
      from the SDK.
`;

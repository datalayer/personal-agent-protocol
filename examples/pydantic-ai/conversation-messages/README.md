# Conversation messages

This local Pydantic AI tool starts and continues a PAP conversation while the
host retains the Session Token, DPoP proof, pairwise identity, and message IDs.
Retry a message with the same `Message` object so its ID and content remain
identical.

Read the [conversation messages flow](https://personalagentprotocol.org/examples/conversation-messages/).

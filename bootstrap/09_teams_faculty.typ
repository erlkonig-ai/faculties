= Teams: Microsoft Graph Archive and Bridge

`teams` connects a professional Microsoft Teams account to the local pile. It
pulls chats, users, presence, and attachments through Microsoft Graph; it can
also send messages and perform other outward mutations. The resulting source,
message, receipt, and cursor facts form an append-only Teams collection rather
than a second mutable cache.

== Safety boundary

Credentials are not stored in Teams facts. App secrets and delegated tokens
are encrypted versions in a Secrets vault; the Teams collection names only
their exact version ids. A presentation context records the professional name
and boundary reminder used for outward work. Mutating commands refuse to run
without that context.

```sh
# Set the outward identity once for a tenant.
teams --tenant <tenant-id> context set Bulti \
  --boundary "Professional work context; keep private conversation private."

# Interactive device-code login. Secret input comes from a file or stdin,
# never a command-line literal. The target vault must already be ready.
teams login --tenant <tenant-id> --client-id <app-id> \
  --client-secret @/secure/app-secret --vault <vault-id>

# Inspect only safe profile metadata and exact secret-version references.
teams --tenant <tenant-id> auth status
```

== Ordinary use

```sh
# Pull Graph deltas, persist them, then show recent messages.
teams --tenant <tenant-id> read --limit 20

# Read one chat or send through the configured professional identity.
teams --tenant <tenant-id> read <chat-id>
teams --tenant <tenant-id> send <chat-id> @message.txt

# Search the directory and inspect presence.
teams --tenant <tenant-id> users list Ada
teams --tenant <tenant-id> presence get <user-id>
```

Ingestion is retry-safe: intrinsic source and observation identities collapse
exact replays, while immutable receipt coverage records where Graph pagination
has reached. Mutable operational convenience never becomes a last-writer-wins
sidecar.

== Collection sharing is separate

Microsoft tenancy does not define TribleSpace authorization. The Teams
collection has the same descriptor-local READ and WRITE policies as every
other collection. To replicate it to another node, grant that node the exact
collection capability and activate the descriptor handle in `pile net sync`;
see [Recipe: Share a Collection Between Agents](wiki:d06247b9d9183721e47a2940806e5d7f).

Next stop: [Relations: People and Handle Mappings](wiki:e7e3f672a66b39e0b5b3c0eaf212b1da).

# UNWIND Dashboard — Operator Actions Guide

## What You're Looking At

The UNWIND dashboard shows a timeline of everything your AI agent has done or tried to do. Each event shows the tool used, the target (file path, URL, etc.), and a status: **allowed**, **blocked**, or **waiting for your decision**.

You have three possible actions: **Allow**, **Deny**, and **Rewind**. Not every event gets these buttons — they appear only when they're relevant.

---

## Allow / Deny (Amber Challenges)

### When do these appear?

Allow and Deny buttons appear when your agent tries to do something **high-risk while its session is tainted**. Two conditions must both be true:

1. **The session is tainted** — the agent has received external input (fetched a web page, read an email, processed user-uploaded content). This means the agent *could* be acting on instructions injected by someone else, not you.

2. **The action is high-risk** — the agent is trying to do something with real-world consequences: sending an email, running a system command, executing code, or calling an external API.

If both conditions are met, UNWIND blocks the action and presents it to you as an **amber challenge**. The agent cannot proceed until you decide.

### What should I do?

**Read the event carefully.** The timeline shows you:
- What tool the agent is trying to use (e.g. `send_email`, `exec_process`)
- The target (e.g. the email address, the command it wants to run)
- Why it was blocked (the result summary)

Click the event to expand its full details if you need more context.

**Allow** if:
- You recognise the action as something you asked the agent to do
- The target looks correct (right email address, right command, right file)
- You understand why the agent is doing this

**Deny** if:
- You didn't ask the agent to do this
- The target looks wrong or unexpected (emailing someone you don't know, running a command you didn't request)
- You're not sure — **when in doubt, deny**. You can always ask your agent to try again and allow it next time with more confidence.

### Examples

**Allow scenario:** You asked your agent to "send the weekly report to sarah@company.com". The agent fetched data from a web API (tainting the session), then tried to send an email to sarah@company.com with the report attached. You recognise this as exactly what you asked for. → **Allow**

**Deny scenario:** You asked your agent to "summarise this article". The agent fetched the article (tainting the session), then tried to run `exec_process` with a curl command to an unfamiliar URL. You didn't ask it to call any external service. This could be a prompt injection from the article. → **Deny**

**Deny scenario:** You asked your agent to "email the team update to dev@company.com". The agent tried to send email to marketing@company.com instead. The target doesn't match what you asked for. → **Deny**

### How do I do it?

1. Find the amber event in the timeline (it has an amber badge and Allow/Deny buttons)
2. Click the event to read the full details
3. Click **Allow** or **Deny**
4. Confirm your choice in the dialog that appears
5. The decision is recorded permanently in the audit trail — it cannot be undone or altered

### Timing

Amber challenges expire after 90 seconds. If you don't act in time, the challenge expires and the action stays blocked. The agent would need to try again, generating a new challenge.

---

## Rewind (Undo a File Change)

### When does this appear?

The Rewind button (↩️) appears on events where your agent **successfully changed a file** — writes, edits, deletes, renames, moves. UNWIND automatically takes a snapshot of the file before the agent changes it.

Rewind does **not** appear on:
- Blocked actions (nothing happened, nothing to undo)
- Read-only actions (nothing was changed)
- Non-file actions (emails sent, commands run — these can't be unsent or unrun)

### What should I do?

**Rewind** if:
- The agent wrote the wrong content to a file
- The agent deleted or overwrote something you wanted to keep
- You changed your mind about an edit
- Something went wrong and you want to go back to how the file was before

**Don't rewind** if:
- Other changes have been made to the same file since — the rewind restores the snapshot from *that specific moment*, which could overwrite later work

### Examples

**Rewind scenario:** Your agent edited your config file and broke something. You see the `fs_write` event for that config file in the timeline with a Rewind button. → Click **Rewind** to restore the file to its state before the edit.

**Rewind scenario:** Your agent deleted a file you actually needed. The `fs_delete` event shows in the timeline. → Click **Rewind** to restore the deleted file.

### How do I do it?

1. Find the event in the timeline (it has a ↩️ Rewind button)
2. Click **Rewind**
3. Confirm in the dialog
4. The file is restored to its pre-change state
5. The button changes to ✅ Restored so you know it's done

### What gets restored?

The exact file contents from before the agent's action. If the agent wrote to `/home/user/report.txt`, clicking Rewind puts back whatever was in that file before the write happened.

---

## Summary

| Action | Appears when | You're deciding |
|--------|-------------|----------------|
| **Allow** | Agent tries a high-risk action while tainted | "Yes, I asked for this" |
| **Deny** | Agent tries a high-risk action while tainted | "No, this isn't right" |
| **Rewind** | Agent successfully changed a file | "Undo this file change" |

### The golden rule

**If you're unsure, deny or don't rewind.** A denied action can be retried. A rewind can't be undone. But neither is catastrophic — UNWIND keeps a permanent record of everything, so you always have full visibility of what happened and when.

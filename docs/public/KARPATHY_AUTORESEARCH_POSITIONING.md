# Positioning UNWIND for the Autoresearch Era

The release of Andrej Karpathy's `Autoresearch` marks a fundamental shift in how AI agents operate: moving from **synchronous pair-programming** to **asynchronous, overnight, autonomous experimentation loops**.

When an agent runs 700 autonomous file modifications and bash executions over a two-day period while the human operator is asleep, the security and visibility paradigm must change. 

UNWIND is perfectly positioned to be the safety harness for this new era.

## The Autoresearch Problem Space

`Autoresearch` architectures rely on minimal codebases (`prepare.py`, `train.py`) and a tight loop: 
1. The agent rewrites the code.
2. The agent executes the code (`bash_exec`).
3. The agent reads the results.
4. The agent commits or reverts based on success.

**The inherent risks of this loop without UNWIND:**
*   **Runaway Execution:** If the agent hallucinates a destructive shell command during an overnight run, it can wipe the workspace or the host machine.
*   **Blind Commits:** The human operator wakes up to an "optimised" model, but has no verifiable, tamper-evident audit trail of *exactly* what commands the agent ran to get there.
*   **Silent Failures:** If the agent gets stuck in a loop of modifying the wrong file, the operator wastes 12 hours of compute time.

## How UNWIND Solves the Autonomous Loop

UNWIND's architecture maps perfectly to the needs of developers running tools like `Autoresearch`:

### 1. "While You Were Away" (Cadence & Dashboard)
The UNWIND dashboard's **Away Mode** is purpose-built for overnight runs. When the developer wakes up, they don't have to parse thousands of lines of terminal logs. UNWIND provides a clean summary:
* *"126 experiments ran."*
* *"700 file modifications passed the pipeline."*
* *"1 action blocked: Agent attempted to write outside the workspace jail."*

### 2. The Workspace Jail (Path Confinement)
In an autonomous loop, the agent is trusted to modify `train.py`. It is *not* trusted to read `~/.ssh/id_rsa` or modify system binaries. UNWIND's **Path Jail (Stage 3)** ensures that no matter what the agent hallucinates overnight, it cannot escape the designated workspace directory.

### 3. Exec Tunnel Detection & Circuit Breakers
Agents running experiments rely heavily on `bash_exec`. UNWIND's **Exec Tunnel (Stage 2b)** and **Circuit Breaker (Stage 6)** ensure the agent can run its 5-minute training loops without being able to tunnel malicious commands or run amok with infinite rapid-fire state modifications.

### 4. Smart Snapshots & Rollback
If the agent's overnight loop corrupts the core training script in a way that its own internal revert mechanism fails to catch, the human operator can use `unwind undo --since "12h"` to instantly restore the entire workspace to its pre-sleep state using APFS/btrfs reflinks.

### 5. The Flight Recorder (CRAFT)
For enterprise teams (like Shopify adapting this for internal use), having an agent rewrite code overnight creates an auditing nightmare. The **CRAFT Protocol** and SQLite flight recorder provide a cryptographically verified hash-chain of every single action the agent took. You aren't just trusting the agent's output; you have cryptographic proof of its exact methodology.

## Marketing Hook for the Launch

*"Karpathy just showed us the power of overnight, autonomous agent loops with Autoresearch. But you can't leave an agent running bash commands on your machine while you sleep without a safety net.*

*UNWIND is the flight recorder, the path jail, and the physical undo button for the era of autonomous agents. Go to sleep. Let the agent work. If it breaks something, UNWIND has the snapshot."*
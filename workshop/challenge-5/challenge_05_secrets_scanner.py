"""
Challenge 05 — Secrets Scanner Agent
=====================================
Hardcoded secrets are one of the most common and dangerous vulnerabilities.
API keys, passwords, and tokens committed to source code can be exploited
by anyone with access to the repository.

Your task: Build an agent that scans files for hardcoded secrets and
credentials, reporting each finding to the shared scan memory.

⚠️ IMPORTANT: Your agent MUST call report_vulnerability for every
finding and mark_file_scanned after analyzing each file. The final
workflow scores results from memory — not from agent text output.

Export:
    secrets_scanner  — an agent that detects hardcoded secrets
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _paths  # noqa: F401

import asyncio
import os
import nest_asyncio
nest_asyncio.apply()

from dotenv import load_dotenv
from agent_framework import Agent

from shared_models import GITHUB_REPO, create_mcp_client2, create_chat_client2

load_dotenv()

chat_client = create_chat_client2()
chat_client_mcp = create_mcp_client2()

# Import tools from previous challenges
from challenge_01_repo_access import github_mcp_tool
from challenge_02_file_tools import read_repo_file, list_repo_files
from challenge_03_memory import scan_memory, report_vulnerability, mark_file_scanned
from challenge_04_middleware import agent_logging_middleware, tool_logging_middleware


# ═════════════════════════════════════════════════════════════════════
# TODO: Create a secrets_scanner agent
#
# This agent should:
#   - Read source code files from the repository
#   - Identify hardcoded secrets, API keys, passwords, tokens, and
#     credentials embedded in the code
#   - Call report_vulnerability for EACH finding
#   - Call mark_file_scanned after analyzing each file
#
# Think about:
#   - What tools does this agent need? (file tools + memory tools)
#   - What instructions would guide it to recognize different types
#     of secrets? (API keys, database passwords, encryption keys, etc.)
#   - Which files are most likely to contain secrets?
#   - The agent needs context_providers=[scan_memory] to see previous findings
#   - Use middleware=[agent_logging_middleware, tool_logging_middleware]
#     to get observability from Challenge 04
#
# NOTE: Every secret is self-contained in its own file — no cross-file
# correlation is needed. Each file has secrets directly visible as
# string literals or variable assignments.
#
# Assign to: secrets_scanner
# ═════════════════════════════════════════════════════════════════════
    
secrets_scanner = Agent(  # שים לב: שימוש ב-Agent (לפי ייבוא בסקריפט) ולא chat_client_mcp.as_agent
    client=chat_client_mcp,
    name="SecretsScanner",
    instructions=f"""You are a security expert agent. Your task is to scan the repository '{GITHUB_REPO}' for hardcoded secrets, API keys, passwords, tokens, and credentials.

Follow these strict steps:
1. Use 'list_repo_files' to get the full list of files.
2. For EVERY relevant source code or configuration file (e.g., .py, .env, .yml, .json), use 'read_repo_file' to fetch its content. 
   IMPORTANT: When using 'read_repo_file', you must specify both the file path AND mention the repository '{GITHUB_REPO}' in your internal thought process so the tool gets the right context.
3. Analyze the content for hardcoded secrets.
4. If a secret is found, IMMEDIATELY call 'report_vulnerability' with the file, start_line, end_line, and a description.
5. After analyzing a file (whether secrets were found or not), you MUST call 'mark_file_scanned(file_path)'.

Do not stop until all relevant files are scanned and marked.
    """,
    tools=[read_repo_file, list_repo_files, report_vulnerability, mark_file_scanned],
    context_providers=[scan_memory],
    middleware=[agent_logging_middleware, tool_logging_middleware]
)


# ─── Test (DO NOT MODIFY) ────────────────────────────────────────────
async def test_challenge_05():
    assert secrets_scanner is not None, "secrets_scanner is not set"

    scan_memory.reset()

    print("🔑 Running secrets scanner...")
    result = await secrets_scanner.run(
        f"Scan the repository {GITHUB_REPO} for hardcoded secrets, "
        f"API keys, passwords, tokens, and credentials. "
        f"Check all source code and configuration files. "
        f"Call report_vulnerability for each finding with file, start_line, end_line, description. "
        f"Call mark_file_scanned after analyzing each file."
    )

    print(f"\n🔍 Scanner output:\n{result.text[:500]}...")
    print(f"\n🧠 Vulnerabilities in memory: {len(scan_memory.vulnerabilities)}")
    print(f"📂 Files covered: {scan_memory.files_covered}")

    assert len(scan_memory.vulnerabilities) > 0, "Should find at least one secret"

    for v in scan_memory.vulnerabilities[:5]:
        print(f"   📌 {v['file']}:{v['start_line']}-{v['end_line']} — {v['description'][:60]}")

    print("\n✅ Challenge 05 complete — secrets scanner is operational!")

if __name__ == "__main__":
    asyncio.run(test_challenge_05())

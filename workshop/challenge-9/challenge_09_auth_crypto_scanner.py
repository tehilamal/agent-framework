"""
Challenge 09 — Authentication & Cryptography Scanner
=====================================================
Authentication weaknesses and cryptographic flaws are critical:
  - Weak password hashing (MD5, SHA1 without salt)
  - JWT algorithm confusion ('none' algorithm allowed)
  - Deprecated crypto (DES, ECB mode, hardcoded IVs)
  - Timing-attack vulnerable comparisons
  - Predictable tokens and session management flaws

Your task: Build a dedicated auth/crypto scanner agent that
specializes in authentication and cryptography vulnerabilities.
It reports all findings to the shared scan memory.

Export:
    auth_crypto_scanner  — an agent that detects auth & crypto issues
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

from shared_models import GITHUB_REPO, VulnerabilityList, create_mcp_client2, create_chat_client2

load_dotenv()

chat_client = create_chat_client2()
chat_client_mcp = create_mcp_client2()

# Import tools from previous challenges
from challenge_01_repo_access import github_mcp_tool
from challenge_02_file_tools import read_repo_file, list_repo_files
from challenge_03_memory import scan_memory, report_vulnerability, mark_file_scanned
from challenge_04_middleware import agent_logging_middleware, tool_logging_middleware


# ═════════════════════════════════════════════════════════════════════
# TODO: Create an auth_crypto_scanner agent
#
# This agent specializes in authentication & cryptography issues:
#
#   WEAK PASSWORD HANDLING:
#   - Weak hashing (MD5, SHA1 without salt)
#   - Timing-attack vulnerable string comparison (== instead of
#     hmac.compare_digest)
#   - Plaintext passwords logged to files or stdout
#
#   JWT / TOKEN ISSUES:
#   - JWT algorithm confusion: 'none' algorithm allowed
#   - Excessively long token expiry (e.g. 1 year)
#   - Weak/hardcoded JWT signing secrets
#
#   WEAK / DEPRECATED CRYPTOGRAPHY:
#   - DES encryption (deprecated)
#   - Hardcoded IV reuse in AES-CBC
#   - SHA1 for hashing sensitive data
#   - ECB mode encryption
#   - Static encryption keys or IVs
#
#   AUTHENTICATION BYPASS:
#   - Predictable random seeds for security tokens
#   - No authentication on admin endpoints
#   - Missing CSRF protection
#
# The agent MUST:
#   - Use tools: read_repo_file, list_repo_files,
#     report_vulnerability, mark_file_scanned
#   - Use context_providers=[scan_memory]
#   - Use response_format=VulnerabilityList
#   - Use middleware=[agent_logging_middleware, tool_logging_middleware]
#   - Focus on auth.py, utils/crypto.py, and related files
#
# NOTE: Each vulnerability is self-contained within its file.
# The agent does NOT need cross-file memory correlation to find
# these issues — each weak pattern is visible in the file itself.
#
# Assign to: auth_crypto_scanner
# ═════════════════════════════════════════════════════════════════════

auth_crypto_scanner = Agent(
    client=chat_client_mcp,
    name="Auth & Crypto Scanner",
    instructions=f"""You are a specialized authentication and cryptography security expert.
Your task is to scan the repository '{GITHUB_REPO}' for authentication weaknesses and cryptography issues. Focus on files like auth.py, utils/crypto.py, and any file handling sessions, tokens, or encryption.
Identify issues such as weak password hashing (MD5, SHA1 without salt), JWT misconfigurations (e.g., 'none' algorithm allowed), deprecated crypto usage (DES, ECB mode), timing-attack vulnerable comparisons, and predictable tokens.
Follow these strict steps:
1. Use 'list_repo_files' to get the full list of files.
2. For EVERY relevant source code file (e.g., auth.py), use 'read_repo_file' to fetch its content. Always keep the repository '{GITHUB_REPO}' in context.
3. Analyze the code deeply for the vulnerabilities listed above.
4. If an issue is found, IMMEDIATELY call 'report_vulnerability' with the file, start_line, end_line, description, AND scanner=\"Auth & Crypto Scanner\"."
5. After analyzing a file, you MUST call 'mark_file_scanned(file_path)'.
6. Focus on the specific patterns of weak authentication and cryptography, such as weak hashing algorithms, JWT misconfigurations, and deprecated crypto usage.
7. CRITICAL: Return your final response STRICTLY as a raw JSON object matching the VulnerabilityList schema. Do NOT add any conversational text like "Here are the findings". Do NOT wrap the JSON in markdown formatting blocks (e.g., ```json). Output ONLY the raw JSON.
    """,
    tools=[github_mcp_tool, list_repo_files, read_repo_file, report_vulnerability, mark_file_scanned],
    context_providers=[scan_memory],
    response_format=VulnerabilityList,
    middleware=[agent_logging_middleware, tool_logging_middleware]
)


# ─── Test (DO NOT MODIFY) ────────────────────────────────────────────
async def test_challenge_09():
    assert auth_crypto_scanner is not None, "auth_crypto_scanner is not set"

    scan_memory.reset()

    print("🔐 Running auth & crypto scanner...")
    result = await auth_crypto_scanner.run(
        f"Scan the repository {GITHUB_REPO} for authentication weaknesses "
        f"and cryptography issues. Focus on auth.py, utils/crypto.py, "
        f"and any file handling sessions, tokens, or encryption. "
        f"Call report_vulnerability for each finding with file, start_line, end_line, description. "
        f"Call mark_file_scanned after analyzing each file."
    )

    findings = VulnerabilityList.model_validate_json(result.text)

    print(f"\n🔐 Structured output: {len(findings.vulnerabilities)} auth/crypto issues")
    for v in findings.vulnerabilities[:5]:
        print(f"   {v.file}:{v.start_line}-{v.end_line} — {v.description[:60]}")

    print(f"\n🧠 Memory: {len(scan_memory.vulnerabilities)} vulnerabilities")

    assert len(scan_memory.vulnerabilities) > 0, "Should find at least one auth/crypto issue"
    print("\n✅ Challenge 09 complete — auth/crypto scanner operational!")

if __name__ == "__main__":
    asyncio.run(test_challenge_09())

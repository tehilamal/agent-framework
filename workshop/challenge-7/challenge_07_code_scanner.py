"""
Challenge 07 — Code Vulnerability Scanner
==========================================
Secrets are just one category. The application also has code-level
vulnerabilities: SQL injection, command injection, XSS, SSRF,
insecure deserialization, path traversal, and more.

Your task: Build a dedicated code vulnerability scanner agent that
specializes in finding injection flaws and unsafe code patterns.
It outputs structured results AND reports findings to shared memory.

Export:
    code_vuln_scanner  — an agent that detects code vulnerabilities
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
# TODO: Create a code_vuln_scanner agent
#
# This agent specializes in finding code-level vulnerabilities:
#   - SQL injection
#   - Command injection (os.system, subprocess with shell=True)
#   - Cross-site scripting (XSS)
#   - Server-side request forgery (SSRF)
#   - Insecure deserialization (pickle, yaml.load)
#   - Path traversal
#   - XML external entity injection (XXE)
#   - Use of eval/exec with user input
#   - Missing authentication/authorization checks
#   - Sensitive data in logs
#
# The agent MUST:
#   - Use tools: read_repo_file, list_repo_files,
#     report_vulnerability, mark_file_scanned
#   - Use context_providers=[scan_memory]
#   - Use response_format=VulnerabilityList for structured output
#   - Use middleware=[agent_logging_middleware, tool_logging_middleware]
#   - Call report_vulnerability for EACH finding
#   - Call mark_file_scanned after analyzing each file
#
# Assign to: code_vuln_scanner
# ═════════════════════════════════════════════════════════════════════

code_vuln_scanner = Agent(
    client=chat_client_mcp,  # הלקוח הנכון שתומך ב-MCP
    name="CodeVulnScanner",
    # הנחיות מפורטות לחיפוש חולשות אבטחה, כולל אילוץ פלט JSON נקי
    instructions=f"""You are a specialized application security expert. 
Your task is to scan the repository '{GITHUB_REPO}' specifically for code-level vulnerabilities.

Focus heavily on:
- SQL injection
- Command injection (os.system, subprocess with shell=True)
- Cross-site scripting (XSS)
- Server-side request forgery (SSRF)
- Insecure deserialization (pickle, yaml.load)
- Path traversal
- XML external entity injection (XXE)
- Use of eval/exec with user input
- Missing authentication/authorization checks
- Sensitive data in logs

Follow these strict steps:
1. Use 'list_repo_files' to get the full list of files.
2. For EVERY relevant source code file (e.g., .py), use 'read_repo_file' to fetch its content. Always keep the repository '{GITHUB_REPO}' in context.
3. Analyze the code deeply for the vulnerabilities listed above.
4. If a vulnerability is found, IMMEDIATELY call 'report_vulnerability' with the file, start_line, end_line, and a technical description.
5. After analyzing a file, you MUST call 'mark_file_scanned(file_path)'.
6. CRITICAL: Return your final response strictly as a raw JSON object matching the VulnerabilityList schema. Do NOT wrap the JSON in markdown formatting blocks (e.g., ```json ... ```).
    """,
    tools=[list_repo_files, read_repo_file, report_vulnerability, mark_file_scanned],
    context_providers=[scan_memory],
    response_format=VulnerabilityList,
    middleware=[agent_logging_middleware, tool_logging_middleware]
)


# ─── Test (DO NOT MODIFY) ────────────────────────────────────────────
async def test_challenge_07():
    assert code_vuln_scanner is not None, "code_vuln_scanner is not set"

    scan_memory.reset()

    print("🐛 Running code vulnerability scanner...")
    result = await code_vuln_scanner.run(
        f"Scan the repository {GITHUB_REPO} for code-level security vulnerabilities. "
        f"Focus on injection flaws, unsafe deserialization, path traversal, "
        f"and dangerous function usage. Check all Python source files. "
        f"Call report_vulnerability for each finding. "
        f"Call mark_file_scanned after analyzing each file."
    )

    findings = VulnerabilityList.model_validate_json(result.text)

    print(f"\n🐛 Structured output: {len(findings.vulnerabilities)} code vulnerabilities")
    for v in findings.vulnerabilities[:5]:
        print(f"   {v.file}:{v.start_line}-{v.end_line} — {v.description[:60]}")

    print(f"\n🧠 Memory: {len(scan_memory.vulnerabilities)} vulnerabilities")

    assert len(scan_memory.vulnerabilities) > 0, "Should find at least one code vulnerability"
    print("\n✅ Challenge 07 complete — code vulnerability scanner operational!")

if __name__ == "__main__":
    asyncio.run(test_challenge_07())

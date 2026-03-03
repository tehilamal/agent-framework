"""
Challenge 01 — Connect to the Repository via MCP
=================================================
The vulnerable application lives in a GitHub repository.
Before any scanning can happen, you need to connect to it.

Your task: Set up a GitHub MCP tool and create an agent that can
explore the repository structure — list files, read directory contents,
and understand the codebase layout.

Export:
    github_mcp_tool  — the MCP tool configured for GitHub (via client.get_mcp_tool())
    repo_explorer     — an agent that can navigate the repository
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _paths  # noqa: F401

import asyncio
import nest_asyncio
nest_asyncio.apply()

from dotenv import load_dotenv
from agent_framework_azure_ai import AzureAIAgentClient
from agent_framework import Agent

import os

from shared_models import GITHUB_REPO, create_mcp_client2, create_chat_client2

load_dotenv()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.popen("gh auth token").read().strip()

# ─── Chat clients (provided) ─────────────────────────────────────────
chat_client = create_chat_client2()
# Needs to be redefined inside each tool/agent that uses it due to how AzureAIAgentClient manages state
chat_client_mcp = create_mcp_client2()


# ═════════════════════════════════════════════════════════════════════
# TODO: Create an MCP tool for GitHub
#
# Create MCP tools via
# the client that supports hosted tools (AzureAIAgentClient):
github_mcp_tool = chat_client_mcp.get_mcp_tool(
    name="github",
    url="https://api.githubcopilot.com/mcp",
    headers={"Authorization": f"Bearer {GITHUB_TOKEN}"},
    approval_mode="never_require",  # תיקון: מתאים יותר לפעולות קריאה בלבד ולזרימה אוטומטית
    description="Tool for accessing GitHub repository contents via MCP. Use it to list files, read file contents, and explore the repository structure."
)

#
# Think about:
#   - What URL does GitHub's MCP server live at?
#   - What approval mode makes sense for read-only operations?
#
# Assign it to: github_mcp_tool
# ═════════════════════════════════════════════════════════════════════




# ═════════════════════════════════════════════════════════════════════
# TODO: Create a repo_explorer agent
#
# This agent's job is to explore the GitHub repository:
#   - List all files and directories
#   - Understand the project structure
#   - It should use the MCP tool you just created
#
# Use the new Agent class (ChatAgent was renamed to Agent):
repo_explorer = Agent(
    client=chat_client_mcp,
    name="repo_explorer",
    instructions=""" You have access to a GitHub MCP tool that allows you to interact with a repository. Use this tool to explore the repository structure, list files, and read file contents as needed to understand the codebase.""",
    tools=[github_mcp_tool],
)
#
# Think about what instructions would make this agent effective
# at navigating a codebase it has never seen before.
#
# Assign it to: repo_explorer
# ═════════════════════════════════════════════════════════════════════



# ─── Test (DO NOT MODIFY) ────────────────────────────────────────────
async def test_challenge_01():
    assert github_mcp_tool is not None, "github_mcp_tool is not set"
    assert repo_explorer is not None, "repo_explorer is not set"

    print("🔌 Testing GitHub MCP connection...")
    result = await repo_explorer.run(
        f"List all files and directories in the repository {GITHUB_REPO}. "
        f"Show me the complete project structure."
    )
    print(f"\n📂 Repository structure:\n{result.text}")
    print("\n✅ Challenge 01 complete — you can now explore the repo via MCP!")

if __name__ == "__main__":
    asyncio.run(test_challenge_01())

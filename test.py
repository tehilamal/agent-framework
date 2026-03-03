# Copyright (c) Microsoft. All rights reserved.
import asyncio
import os
from random import randint
from typing import Annotated
from agent_framework import SupportsChatGetResponse
from agent_framework.openai import OpenAIChatClient, OpenAIResponsesClient, OpenAIAssistantsClient
from dotenv import load_dotenv
from pydantic import Field
from agent_framework import SupportsChatGetResponse, tool
# Load environment variables from .env file
load_dotenv()
"""
OpenAI Chat Client Example
This sample demonstrates how to run a prompt against OpenAI chat clients.
"""
from agent_framework.openai import OpenAIChatClient, OpenAIResponsesClient, OpenAIAssistantsClient
@tool
def get_weather(
    location: Annotated[str, Field(description="The location to get the weather for.")],
) -> str:
    """Get the weather for a given location."""
    conditions = ["sunny", "cloudy", "rainy", "stormy"]
    return f"The weather in {location} is {conditions[randint(0, 3)]} with a high of {randint(10, 30)}°C."
def get_openai_client(client_type: str = "chat") -> SupportsChatGetResponse:
    """Create an OpenAI chat client."""
    if client_type == "chat":
        return OpenAIChatClient()
    elif client_type == "responses":
        return OpenAIResponsesClient()
    elif client_type == "assistants":
        return OpenAIAssistantsClient()
    else:
        raise ValueError(f"Unsupported client type: {client_type}")
    
async def main(client_type: str = "chat") -> None:
    """Run a basic prompt using an OpenAI client."""
    client = get_openai_client(client_type)
    
    # 1. Configure prompt and streaming mode.
    message = "What's the weather in Amsterdam and in Paris?"
    stream = os.getenv("STREAM", "false").lower() == "true"
    print(f"Client: {client_type}")
    print(f"User: {message}")
    
    # 2. Run with context-managed assistants client.
    if isinstance(client, OpenAIAssistantsClient):
        async with client:
            if stream:
                # תיקון: עטיפת הכלי ברשימה
                response_stream = client.get_response(message, stream=True, options={"tools": [get_weather]})
                print("Assistant: ", end="")
                async for chunk in response_stream:
                    if chunk.text:
                        print(chunk.text, end="")
                print("")
            else:
                # תיקון: עטיפת הכלי ברשימה
                print(f"Assistant: {await client.get_response(message, stream=False, options={'tools': [get_weather]})}")
        return
        
    # 3. Run with non-context-managed clients.
    if stream:
        response_stream = client.get_response(message, 
                                              stream=True, 
                                              options={"tools": [get_weather]})
        print("Assistant: ", end="")
        async for chunk in response_stream:
            if chunk.text:
                print(chunk.text, end="")
        print("")
    else:
        # תיקון: עטיפת הכלי ברשימה
        print(f"Assistant: {await client.get_response(message, stream=False, options={'tools': [get_weather]})}")

if __name__ == "__main__":
    asyncio.run(main("chat"))
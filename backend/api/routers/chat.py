"""
Chat API router
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from ...chat import chat_with_agent

router = APIRouter()

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[Dict[str, str]]] = None

class ChatResponse(BaseModel):
    response: str

@router.post("/", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Chat with the AI assistant
    """
    try:
        response = chat_with_agent(request.message, request.history)
        return ChatResponse(response=str(response))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

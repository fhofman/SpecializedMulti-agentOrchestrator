"""Fábrica única del LLM: un solo lugar para cambiar modelo o parámetros."""

import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()


def get_llm(temperature: float = 0.0) -> ChatOpenAI:
    # temperature=0 -> respuestas más deterministas: clave para que el
    # supervisor enrute siempre igual ante el mismo estado.
    return ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), temperature=temperature)

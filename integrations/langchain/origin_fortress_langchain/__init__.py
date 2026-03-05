"""Origin Fortress security integration for LangChain.

Provides callback handlers that scan prompts, tool calls, and outputs
for security threats in real-time.

Usage:
    from origin_fortress_langchain import OriginFortressCallbackHandler

    handler = OriginFortressCallbackHandler(base_url="http://localhost:8080")
    chain = my_chain.with_config(callbacks=[handler])
"""

from origin_fortress_langchain.callback import OriginFortressCallbackHandler
from origin_fortress_langchain.callback import Origin FortressAsyncCallbackHandler

__all__ = ["OriginFortressCallbackHandler", "Origin FortressAsyncCallbackHandler"]
__version__ = "0.1.0"

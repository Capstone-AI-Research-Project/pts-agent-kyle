"""
title: CASA CyberAnalysis Investigation
author: Kyle
version: 1.5.0
description: Routes security investigation queries through the CASA multi-agent pipeline via n8n webhook. Supports text queries and log file uploads.
"""

from pydantic import BaseModel, Field
from typing import Union, Generator, Iterator
import httpx
import json
import base64


class Pipe:
    class Valves(BaseModel):
        n8n_webhook_url: str = Field(
            default="http://n8n-main:5678/webhook/casa-investigate",
            description="N8N CASA webhook URL (use Docker service name internally)"
        )
        request_timeout: int = Field(
            default=1800,
            description="Request timeout in seconds (30 min for full pipeline)"
        )
        debug: bool = Field(
            default=True,
            description="Show debug status events (query length, file extraction)"
        )

    def __init__(self):
        self.type = "pipe"
        self.id = "casa_investigation"
        self.name = "CASA CyberAnalysis"
        self.valves = self.Valves()

    def _extract_file_content(self, file_obj: dict) -> str:
        """Extract text content from an OpenWebUI file object.

        Handles multiple formats:
        - base64 inline: file_obj["data"] contains base64 string
        - nested data: file_obj["file"]["data"]["content"] contains text
        - raw content: file_obj["content"] contains text
        - url reference: file_obj["url"] (logged but not fetched)
        """
        file_name = (
            file_obj.get("name")
            or file_obj.get("filename")
            or (file_obj.get("file", {}) or {}).get("filename")
            or (file_obj.get("file", {}) or {}).get("name")
            or "uploaded_file"
        )

        # Format 1: base64 inline data (original OpenWebUI format)
        if "data" in file_obj and isinstance(file_obj["data"], str):
            try:
                # Strip data URI prefix if present (e.g., "data:text/plain;base64,...")
                raw = file_obj["data"]
                if "," in raw and raw.startswith("data:"):
                    raw = raw.split(",", 1)[1]
                decoded = base64.b64decode(raw).decode("utf-8", errors="replace")
                return f"\n\n--- Log File: {file_name} ---\n{decoded}"
            except Exception:
                pass

        # Format 2: nested file object with content (file.data.content)
        nested_file = file_obj.get("file", {}) or {}
        nested_data = nested_file.get("data", {}) or {}
        if isinstance(nested_data, dict) and "content" in nested_data:
            return f"\n\n--- Log File: {file_name} ---\n{nested_data['content']}"

        # Format 3: direct content field
        if "content" in file_obj and isinstance(file_obj["content"], str):
            return f"\n\n--- Log File: {file_name} ---\n{file_obj['content']}"

        # Format 4: text field (some OpenWebUI versions)
        if "text" in file_obj and isinstance(file_obj["text"], str):
            return f"\n\n--- Log File: {file_name} ---\n{file_obj['text']}"

        # Format 5: data dict with content key (Open WebUI 0.4.x+ common format)
        if "data" in file_obj and isinstance(file_obj["data"], dict):
            content_val = file_obj["data"].get("content")
            if isinstance(content_val, str) and content_val:
                return f"\n\n--- Log File: {file_name} ---\n{content_val}"

        # Format 6: nested file object with direct content (file.content without data wrapper)
        if isinstance(nested_file, dict) and "content" in nested_file:
            content_val = nested_file["content"]
            if isinstance(content_val, str) and content_val:
                return f"\n\n--- Log File: {file_name} ---\n{content_val}"

        return ""

    async def pipe(
        self,
        body: dict,
        __user__: dict = None,
        __event_emitter__=None,
        __event_call__=None,
    ) -> Union[str, Generator, Iterator]:

        messages = body.get("messages", [])

        if not messages or messages[-1].get("role") != "user":
            return "No investigation query provided. Describe a security event or paste log data to investigate."

        # Detect OpenWebUI internal task requests (auto-tagging, title generation, etc.)
        # These should NEVER be forwarded to the n8n pipeline.
        _owui_task_prefixes = ("### Task:", "### title", "Generate a concise")
        last_content = messages[-1].get("content", "")
        if any(last_content.lstrip().startswith(prefix) for prefix in _owui_task_prefixes):
            # Return a generic tag/title so OpenWebUI's internal systems get a response
            # without triggering a full CASA investigation
            return '["Security", "Investigation"]'

        # Check body-level task indicator — only intercept background housekeeping tasks,
        # NOT query_generation (which Open WebUI uses for RAG-enhanced main messages).
        # Intercepting query_generation was causing file-upload queries to return early
        # instead of forwarding to n8n.
        _background_tasks = ("title_generation", "tags_generation", "emoji_generation")
        task_type = (
            body.get("task")
            or body.get("metadata", {}).get("task")
            or ""
        )
        if task_type in _background_tasks:
            return '["Security", "Investigation"]'

        # Extract ONLY the user's original message — skip any OpenWebUI system prompt injection
        user_message = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                # Newer OpenWebUI versions send content as a list of typed parts
                if isinstance(content, list):
                    content = " ".join(
                        part.get("text", "")
                        for part in content
                        if isinstance(part, dict) and part.get("type") == "text"
                    ).strip()
                # Skip OpenWebUI's injected system/search prompts
                if content and not content.startswith("### Task:"):
                    user_message = content
                    break
                elif content and content.startswith("### Task:"):
                    continue

        if not user_message:
            # All messages were internal prompts — don't forward to n8n
            return '["Security", "Investigation"]'

        # Handle file uploads — check all known OpenWebUI file delivery locations
        file_content = ""
        files_found = 0
        files_extracted = 0
        extraction_debug = []

        # Source 1: body["files"] — top-level, primary location in Open WebUI v0.4.x+
        for file_obj in body.get("files", []):
            files_found += 1
            extracted = self._extract_file_content(file_obj)
            if extracted:
                file_content += extracted
                files_extracted += 1
                extraction_debug.append(f"body[files] OK: {len(extracted)} chars")
            else:
                keys = list(file_obj.keys())
                extraction_debug.append(f"body[files] SKIP: keys={keys}")

        # Source 2: msg["files"] inside each user message (older OpenWebUI format)
        # Guard changed to files_extracted==0: if Source 1 found metadata but no content,
        # Source 2 may have the same files in a different format with actual content.
        if files_extracted == 0:
            for msg in messages:
                if msg.get("role") != "user":
                    continue
                for file_obj in msg.get("files", []):
                    files_found += 1
                    extracted = self._extract_file_content(file_obj)
                    if extracted:
                        file_content += extracted
                        files_extracted += 1
                        extraction_debug.append(f"msg[files] OK: {len(extracted)} chars")
                    else:
                        keys = list(file_obj.keys())
                        extraction_debug.append(f"msg[files] SKIP: keys={keys}")

        # Source 3: content list parts with type "file" (some OpenWebUI versions)
        # Same guard change: try even if Source 1 found files but couldn't extract content.
        if files_extracted == 0:
            for msg in messages:
                if msg.get("role") != "user":
                    continue
                content = msg.get("content", "")
                if isinstance(content, list):
                    for part in content:
                        if not isinstance(part, dict):
                            continue
                        if part.get("type") == "file":
                            files_found += 1
                            extracted = self._extract_file_content(part)
                            if extracted:
                                file_content += extracted
                                files_extracted += 1
                                extraction_debug.append(f"content[file] OK: {len(extracted)} chars")
                            else:
                                keys = list(part.keys())
                                extraction_debug.append(f"content[file] SKIP: keys={keys}")

        # Source 4: system message injection
        # Open WebUI sometimes extracts file text and injects it into the system message
        # as context (especially when RAG is disabled). Detect JSON log data there.
        if files_extracted == 0:
            for msg in messages:
                if msg.get("role") != "system":
                    continue
                sys_content = msg.get("content", "")
                if not isinstance(sys_content, str):
                    continue
                # Check for JSON log data signatures from filter_casa.py output
                if any(marker in sys_content for marker in [
                    '"capture_summary"', '"flagged_flows"', '"indicators"'
                ]) and len(sys_content) > 200:
                    file_content += f"\n\n--- Injected Log Context ---\n{sys_content}"
                    files_extracted += 1
                    extraction_debug.append(f"system_msg OK: {len(sys_content)} chars")
                    break

        # Build the investigation query
        query = user_message
        if file_content:
            query += file_content

        if not query.strip():
            return "Please provide a security investigation query or upload a log file."

        # Debug status: show what we extracted
        if __event_emitter__ and self.valves.debug:
            debug_msg = f"Query: {len(query)} chars"
            if files_found > 0:
                debug_msg += f" | Files: {files_extracted}/{files_found} extracted"
                if extraction_debug:
                    debug_msg += f" [{', '.join(extraction_debug)}]"
            else:
                debug_msg += " | No files attached"
            await __event_emitter__({
                "type": "status",
                "data": {"description": debug_msg, "status": "in_progress"}
            })
            # When no files found, emit body structure to diagnose delivery format
            if files_found == 0:
                body_keys = sorted(body.keys())
                last_msg = messages[-1] if messages else {}
                last_msg_keys = sorted(last_msg.keys())
                content_sample = last_msg.get("content", "")
                content_info = (
                    f"list({len(content_sample)} parts, types={[p.get('type') for p in content_sample if isinstance(p, dict)]})"
                    if isinstance(content_sample, list)
                    else f"str({len(content_sample)} chars)"
                )
                await __event_emitter__({
                    "type": "status",
                    "data": {
                        "description": f"File debug: body.keys={body_keys} | msg.keys={last_msg_keys} | content={content_info}",
                        "status": "in_progress",
                    }
                })

        # Warn if files were found but none extracted
        if files_found > 0 and files_extracted == 0:
            warning = (
                f"**Warning:** {files_found} file(s) detected but content could not be extracted. "
                f"File object keys: {extraction_debug}. "
                "Try pasting log content directly into the chat instead.\n\n"
                "Proceeding with text query only...\n\n"
            )
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": f"File extraction failed — sending text only", "status": "in_progress"}
                })
        else:
            warning = ""

        # Status: starting investigation
        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {
                    "description": "CASA agents analyzing — this may take several minutes on CPU...",
                    "status": "in_progress",
                }
            })

        try:
            payload = {"query": query}

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.valves.request_timeout, connect=30.0)
            ) as client:
                response = await client.post(
                    self.valves.n8n_webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )

            # Check for HTTP errors
            if response.status_code >= 400:
                return (
                    f"{warning}"
                    f"n8n returned HTTP {response.status_code}.\n"
                    f"Check n8n Executions page for details.\n\n"
                    f"Response: {response.text[:500]}"
                )

            # Handle empty response
            if not response.text or not response.text.strip():
                return (
                    f"{warning}"
                    f"n8n returned an empty response (HTTP {response.status_code}).\n\n"
                    f"The workflow may have completed but produced no output.\n"
                    f"Check n8n Executions page — look at the Respond to Webhook node output.\n\n"
                    f"**Debug:** Query sent was {len(query)} chars, "
                    f"{files_extracted}/{files_found} files extracted."
                )

            # Parse JSON response safely
            try:
                result = response.json()
            except (json.JSONDecodeError, ValueError):
                return (
                    f"{warning}"
                    f"n8n returned a non-JSON response (HTTP {response.status_code}, "
                    f"{len(response.text)} bytes).\n\n"
                    f"Raw response (first 500 chars):\n```\n{response.text[:500]}\n```"
                )

            # n8n sometimes wraps the response body in an array — unwrap it
            if isinstance(result, list) and len(result) > 0:
                result = result[0]

            # n8n Code nodes can nest data under a "json" key — unwrap it
            if isinstance(result, dict) and "json" in result and isinstance(result.get("json"), dict):
                result = result["json"]

            # Extract the investigation report
            report = result.get("investigation_report", "") if isinstance(result, dict) else ""
            if not report:
                report = result.get("response", "") if isinstance(result, dict) else ""
            if not report:
                report = json.dumps(result, indent=2)

            # Status: complete
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {
                        "description": "Investigation complete",
                        "status": "complete",
                        "done": True,
                    }
                })

            return f"{warning}{report}"

        except httpx.TimeoutException:
            error_msg = (
                f"{warning}"
                "Investigation timed out. The CASA pipeline may still be running — "
                "check n8n Executions page for status. "
                f"(Timeout: {self.valves.request_timeout}s)\n\n"
                f"**Debug:** Query was {len(query)} chars, "
                f"{files_extracted}/{files_found} files extracted."
            )
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": "Timeout", "status": "complete", "done": True}
                })
            return error_msg

        except httpx.ConnectError:
            error_msg = (
                "Cannot connect to n8n. Verify:\n"
                "1. n8n container is running (`docker compose ps`)\n"
                "2. Master workflow is activated in n8n\n"
                f"3. Webhook URL is correct: {self.valves.n8n_webhook_url}"
            )
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": "Connection failed", "status": "complete", "done": True}
                })
            return error_msg

        except Exception as e:
            error_msg = f"CASA pipeline error: {type(e).__name__}: {str(e)}"
            if __event_emitter__:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": "Error", "status": "complete", "done": True}
                })
            return error_msg

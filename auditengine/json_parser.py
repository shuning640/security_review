#!/usr/bin/env python3
"""Utilities for parsing JSON from text output."""

import json
import re
import logging
import json_repair

# Configure logging
logger = logging.getLogger(__name__)


def extract_json_from_text(text):
    """
    Extract JSON object from text, looking in various formats and locations.
    
    Args:
        text: The text that may contain JSON
        
    Returns:
        dict: Parsed JSON object if found, None otherwise
    """
    try:
        # First, try to extract JSON from markdown code blocks (with or without language tag)
        json_matches = [
            re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL),
            re.search(r'```\s*(\{.*?\})\s*```', text, re.DOTALL)
        ]
        
        for json_match in json_matches:
            if json_match:
                try:
                    return json_repair.loads(json_match.group(1))
                except json.JSONDecodeError:
                    continue
        
        # If no JSON found in code blocks, try to find JSON objects anywhere in the text
        # Find all potential JSON objects (looking for balanced braces)
        brace_count = 0
        json_start = -1
        for i, char in enumerate(text):
            if char == '{':
                if brace_count == 0:
                    json_start = i
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0 and json_start != -1:
                    # Found a complete JSON object
                    potential_json = text[json_start:i+1]
                    try:
                        return json_repair.loads(potential_json)
                    except json.JSONDecodeError:
                        # This wasn't valid JSON, continue looking
                        continue
    except Exception:
        pass
    
    return None


def parse_json_with_fallbacks(text, error_context=""):
    """
    Parse JSON from text with multiple fallback strategies and error handling.
    
    Args:
        text: The text to parse
        error_context: Context string for error messages
        
    Returns:
        tuple: (success, result) where result is either the parsed JSON dict or error info
    """
    try:
        # First, try direct JSON parsing
        return True, json_repair.loads(text)
    except json.JSONDecodeError:
        pass
    
    # 【新增逻辑】：处理 JSONL (JSON Lines) 格式，这是 opencode 的标准多行输出格式
    try:
        lines = text.strip().split('\n')
        if len(lines) > 1:
            combined_text = ""
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    line_json = json_repair.loads(line)
                    # 提取 opencode 输出中真正包含大模型回复的文本内容
                    if isinstance(line_json, dict):
                        if line_json.get('type') == 'text' and 'part' in line_json:
                            part = line_json['part']
                            if isinstance(part, dict) and part.get('type') == 'text' and 'text' in part:
                                combined_text += part['text'] + "\n"
                        # 处理可能直接包含在 text 字段的格式
                        elif 'text' in line_json and isinstance(line_json['text'], str):
                            combined_text += line_json['text'] + "\n"
                except json.JSONDecodeError:
                    continue
            
            # 将拼接好的真实文本（此时 \n 等转义符已恢复成真实回车）交给提取函数处理
            if combined_text:
                extracted_json = extract_json_from_text(combined_text)
                if extracted_json:
                    return True, extracted_json
    except Exception:
        pass
    
    # Try extracting JSON from text directly (original fallback)
    extracted_json = extract_json_from_text(text)
    if extracted_json:
        return True, extracted_json
    
    # If all parsing failed, return error info
    error_msg = "Failed to parse JSON"
    if error_context:
        error_msg = f"{error_context}: {error_msg}"
    
    logger.error(f"{error_msg}. Raw output: {repr(text)}")
    return False, {"error": f"Invalid JSON response -- raw output: {repr(text)}"}
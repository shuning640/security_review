"""OpenCode session management for phased analysis workflows."""

import os
import json
import time
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import subprocess

from opencode_ai import Opencode

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from claudecode.constants import DEFAULT_TIMEOUT_SECONDS, DEFAULT_CLAUDE_MODEL, DEFAULT_CLAUDE_PROVIDER
from claudecode.logger import get_logger

logger = get_logger(__name__)


class OpenCodeSessionManager:
    """OpenCode会话管理器 - 实现单session多消息流"""
    
    def __init__(self, 
                 host: Optional[str] = None, 
                 timeout_seconds: Optional[int] = None,
                 model: str = DEFAULT_CLAUDE_MODEL,
                 provider_id: str = DEFAULT_CLAUDE_PROVIDER,
                 repo_path: Optional[str] = None):
        """初始化会话管理器
        
        Args:
            host: OpenCode服务器地址
            timeout_seconds: 请求超时时间
            model: 模型标识符
            provider_id: 提供商标识符
        """
        self.repo_path = repo_path
        self.host = (host or os.environ.get("OPENCODE_API_URL") or "http://127.0.0.1:4096").rstrip('/')
        self.timeout_seconds = timeout_seconds or DEFAULT_TIMEOUT_SECONDS
        self.model = model
        self.provider_id = provider_id
        
        self.client = Opencode(base_url=self.host, timeout=self.timeout_seconds)
        self.session_id = None

        self._server_process = None

        # 如果指定了 repo_path，则在本地启动 Opencode 服务
        if self.repo_path:
            self._start_server()
        
    
    def _start_server(self):
        """在后台启动 Opencode 服务端进程"""
        repo_abs_path = str(Path(self.repo_path).resolve())
        if not os.path.exists(repo_abs_path):
            raise ValueError(f"Repository path does not exist: {repo_abs_path}")

        cmd =[
            "opencode.cmd", "serve"
        ]
        
        logger.info(f"Starting Opencode server in background: {' '.join(cmd)}")
        
        try:
            self._server_process = subprocess.Popen(
                cmd,
                cwd=repo_abs_path,
                text=True
            )
        except FileNotFoundError:
            raise RuntimeError("Failed to start Opencode server: 'opencode' command not found. Is it installed?")

    def _stop_server(self):
        """停止后台运行的 Opencode 服务"""
        if self._server_process and self._server_process.poll() is None:
            logger.info("Stopping background Opencode server...")
            self._server_process.terminate()
            try:
                self._server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._server_process.kill() # 如果 terminate 无效则强行 kill
            self._server_process = None
            logger.info("Opencode server stopped.")

    def create_session(self) -> str:
        """创建新会话
        
        Returns:
            session_id: 创建的会话ID
        """
        try:
            session = self.client.session.create(
                extra_body={}
            )
            self.session_id = session.id
            
            if not self.session_id:
                raise ValueError("Failed to obtain session ID from OpenCode server.")
                
            logger.info(f"OpenCode session created successfully. ID: {self.session_id}")
            return self.session_id
            
        except Exception as e:
            logger.error(f"Failed to create OpenCode session: {e}")
            raise Exception(f"Session creation failed: {str(e)}")       
            
    def send_message(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """在单个会话中发送消息
        
        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词
            
        Returns:
            Dict: API响应数据
        """
        if not self.session_id:
            raise ValueError("No active session. Call create_session() first.")
            
        try:
            parts = [
                {"type": "text", "text": f"{prompt}"}
            ]
            
            kwargs = dict(
                id=self.session_id,
                model_id=self.model,
                provider_id=self.provider_id,
                parts=parts
            )

            if system_prompt:
                kwargs["system"] = system_prompt

            response = self.client.session.chat(**kwargs)

            response_data = response.to_dict()                
            logger.info(f"Message sent successfully to session {self.session_id}")
            return response_data
            
        except Exception as e:
            logger.error(f"Failed to send message to session {self.session_id}: {str(e)}")
            raise Exception(f"Message sending failed: {str(e)}")
        
    def close_session(self) -> bool:
        """关闭会话
        
        Returns:
            bool: 操作是否成功
        """
        result = True
        if self.session_id:
            try:
                self.client.session.delete(id=self.session_id)
                self.session_id = None
                logger.info("Session closed successfully")
            except Exception as e:
                logger.warning(f"Failed to close session: {str(e)}")
                result = False
        
        # 无论 session 是否关闭成功，都尝试关闭绑定的 Server
        self._stop_server()
        return result

            
    def get_session_info(self) -> Dict[str, Any]:
        """获取会话信息
        
        Returns:
            Dict: 会话信息
        """
        if not self.session_id:
            return {"status": "no_active_session"}
            
        try:
            sessions = self.client.session.messages(id=self.session_id)
            return sessions         
        except Exception as e:
            logger.error(f"Failed to get session info: {str(e)}")
            return {"error": str(e)}
            
    def __enter__(self):
        """上下文管理器入口"""
        self.create_session()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出"""
        self.close_session()

    def __del__(self):
        """确保对象被垃圾回收时结束子进程"""
        self._stop_server()

def get_session_manager(host: Optional[str] = None, repo_path: Optional[str] = None,
                        timeout_seconds: Optional[int] = None) -> OpenCodeSessionManager:
    """获取会话管理器的工厂函数
    
    Args:
        host: OpenCode服务器地址
        timeout_seconds: 请求超时时间
        model: 模型标识符
        provider_id: 提供商标识符
        
    Returns:
        OpenCodeSessionManager: 初始化的会话管理器实例
    """
    return OpenCodeSessionManager(host, timeout_seconds, repo_path=repo_path)


if __name__ == "__main__":
    # 测试会话管理器功能
    try:
        repo_path = os.environ.get('REPO_PATH')
        repo_dir = Path(repo_path) if repo_path else Path.cwd()
        with get_session_manager(repo_path=str(repo_dir)) as manager:
            # 测试基本功能
            info = manager.get_session_info()
            logger.info(f"Session info: {info}")
            
            # 测试消息发送
            test_response = manager.send_message("@explore 搜索一下关于 auth 的所有文件和逻辑")
            logger.info(f"Test response: {test_response}")
            
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
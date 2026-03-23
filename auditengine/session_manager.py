"""OpenCode server/session lifecycle helpers for phased analysis workflows."""

import os
import sys
import time
import socket
import signal
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from opencode_ai import Opencode

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditengine.constants import (
    DEFAULT_MODEL_ID,
    DEFAULT_PROVIDER_ID,
    DEFAULT_TIMEOUT_SECONDS,
    OPENCODE_API_URL,
    OPENCODE_PORT,
    OPENCODE_SERVER_BIN,
    REPO_PATH,
)
from auditengine.logger import get_logger

logger = get_logger(__name__)


class OpenCodeSessionManager:
    """Manage one OpenCode session lifecycle."""

    def __init__(
        self,
        host: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        model: str = DEFAULT_MODEL_ID,
        provider_id: str = DEFAULT_PROVIDER_ID,
        port: Optional[int] = None,
    ):
        self.timeout_seconds = timeout_seconds or DEFAULT_TIMEOUT_SECONDS
        self.model = model
        self.provider_id = provider_id

        self.host, self.port = self._resolve_host_and_port(host, port)
        self.client = Opencode(base_url=self.host, timeout=self.timeout_seconds)

        self.session_id: Optional[str] = None
        self._closed = False

    def _resolve_host_and_port(self, host: Optional[str], port: Optional[int]) -> Tuple[str, int]:
        default_port = OPENCODE_PORT
        chosen_port = int(port) if port is not None else default_port

        raw_host = (host or OPENCODE_API_URL or f"http://127.0.0.1:{chosen_port}").rstrip("/")
        parsed = urlparse(raw_host)

        # If host is missing scheme, assume http.
        if not parsed.scheme:
            raw_host = f"http://{raw_host}"
            parsed = urlparse(raw_host)

        hostname = parsed.hostname or "127.0.0.1"
        final_port = int(port) if port is not None else (parsed.port or chosen_port)
        final_host = f"{parsed.scheme}://{hostname}:{final_port}"
        return final_host, final_port

    @staticmethod
    def _is_local_host(base_url: str) -> bool:
        parsed = urlparse(base_url)
        return (parsed.hostname or "") in {"127.0.0.1", "localhost", "::1"}

    @staticmethod
    def _is_windows() -> bool:
        return os.name == "nt"

    @staticmethod
    def _is_port_listening(port: int, timeout_seconds: float = 0.5) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout_seconds):
                return True
        except OSError:
            return False

    @staticmethod
    def _wait_server_ready(port: int, process: Optional[subprocess.Popen], timeout_seconds: float = 10.0) -> bool:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if OpenCodeSessionManager._is_port_listening(port):
                return True
            if process is not None and process.poll() is not None:
                return False
            time.sleep(0.2)
        return OpenCodeSessionManager._is_port_listening(port)

    @staticmethod
    def _kill_port_listener(port: int) -> None:
        try:
            is_windows = os.name == "nt"
            if is_windows:
                cmd = f"netstat -ano | findstr :{port}"
            else:
                cmd = f"lsof -nP -iTCP:{port} -sTCP:LISTEN -t"

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3,
                shell=is_windows,
            )
        except Exception:
            return

        if result.returncode != 0:
            return

        if os.name == "nt":
            pids = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if not parts:
                    continue
                try:
                    pids.append(int(parts[-1]))
                except ValueError:
                    continue
            for pid in set(pids):
                try:
                    subprocess.run(f"taskkill /PID {pid} /T /F", timeout=3, shell=True)
                except Exception:
                    continue
        else:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    pid = int(line)
                except ValueError:
                    continue
                try:
                    os.kill(pid, signal.SIGTERM)
                except Exception:
                    continue

    def create_session(self, model: Optional[str] = None, provider_id: Optional[str] = None) -> str:
        try:
            if model is not None:
                self.model = model
            if provider_id is not None:
                self.provider_id = provider_id

            session = self.client.session.create(extra_body={})
            self.session_id = session.id
            if not self.session_id:
                raise ValueError("Failed to obtain session ID from OpenCode server")
            logger.info(
                f"OpenCode session created successfully. ID: {self.session_id}, "
                f"model={self.model}, provider={self.provider_id}"
            )
            return self.session_id
        except Exception as exc:
            logger.error(f"Failed to create OpenCode session: {exc}")
            raise Exception(f"Session creation failed: {exc}")

    def send_message(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        provider_id: Optional[str] = None,
        tools: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        if not self.session_id:
            raise ValueError("No active session. Call create_session() first.")

        try:
            effective_model = model or self.model
            effective_provider = provider_id or self.provider_id
            kwargs: Dict[str, Any] = {
                "id": self.session_id,
                "model_id": effective_model,
                "provider_id": effective_provider,
                "parts": [{"type": "text", "text": prompt}],
            }
            if system_prompt:
                kwargs["system"] = system_prompt
            if tools is not None:
                kwargs["tools"] = tools

            response = self.client.session.chat(**kwargs)
            response_data = response.to_dict()
            logger.info(
                f"Message sent successfully to session {self.session_id} "
                f"(model={effective_model}, provider={effective_provider})"
            )
            return response_data
        except Exception as exc:
            logger.error(f"Failed to send message to session {self.session_id}: {exc}")
            raise Exception(f"Message sending failed: {exc}")

    def close_session(self) -> bool:
        result = True
        if self.session_id:
            try:
                self.client.session.delete(id=self.session_id)
                logger.info(f"Session closed successfully. ID: {self.session_id}")
            except Exception as exc:
                logger.warning(f"Failed to close session: {exc}")
                result = False
            finally:
                self.session_id = None
        self._closed = True
        return result

    def get_session_info(self) -> Dict[str, Any]:
        if not self.session_id:
            return {"status": "no_active_session"}
        try:
            response = self.client.session.messages(id=self.session_id)
            return response
        except Exception as exc:
            logger.error(f"Failed to get session info: {exc}")
            return {"error": str(exc)}

    def __enter__(self):
        self.create_session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_session()

    def __del__(self):
        try:
            if not self._closed:
                self.close_session()
        except Exception:
            pass


class OpenCodeServerRuntime:
    """Manage one global OpenCode serve process for the full workflow."""

    def __init__(self, repo_path: str, host: Optional[str] = None, port: Optional[int] = None):
        self.repo_path = repo_path
        default_port = OPENCODE_PORT
        chosen_port = int(port) if port is not None else default_port

        raw_host = (host or OPENCODE_API_URL or f"http://127.0.0.1:{chosen_port}").rstrip("/")
        parsed = urlparse(raw_host)
        if not parsed.scheme:
            raw_host = f"http://{raw_host}"
            parsed = urlparse(raw_host)

        hostname = parsed.hostname or "127.0.0.1"
        final_port = int(port) if port is not None else (parsed.port or chosen_port)
        self.host = f"{parsed.scheme}://{hostname}:{final_port}"
        self.port = final_port
        self._server_process: Optional[subprocess.Popen] = None
        self._server_pgid: Optional[int] = None
        self._owns_server = False

    def start(self) -> None:
        repo_abs_path = str(Path(self.repo_path).resolve())
        if not os.path.exists(repo_abs_path):
            raise ValueError(f"Repository path does not exist: {repo_abs_path}")

        if not OpenCodeSessionManager._is_local_host(self.host):
            logger.info(f"Using remote OpenCode host, skip local server startup: {self.host}")
            self._owns_server = False
            return

        if OpenCodeSessionManager._is_port_listening(self.port):
            logger.info(f"Reusing existing OpenCode server on port {self.port}")
            self._owns_server = False
            return

        cmd_candidate = [OPENCODE_SERVER_BIN, "serve", "--port", str(self.port)]
        cmd = " ".join(cmd_candidate) if OpenCodeSessionManager._is_windows() else cmd_candidate
        logger.info(f"Starting OpenCode server: {' '.join(cmd_candidate)}")
        try:
            process = subprocess.Popen(
                cmd,
                cwd=repo_abs_path,
                text=True,
                start_new_session=True,
                shell=OpenCodeSessionManager._is_windows(),
            )
        except FileNotFoundError:
            process = None

        if process is None:
            raise RuntimeError("Failed to start OpenCode server: command not found (tried opencode, opencode.cwd)")

        self._server_process = process
        if hasattr(os, "getpgid") and not OpenCodeSessionManager._is_windows():
            self._server_pgid = os.getpgid(self._server_process.pid)
        else:
            self._server_pgid = None
        self._owns_server = True

        if not OpenCodeSessionManager._wait_server_ready(self.port, self._server_process):
            return_code = self._server_process.poll() if self._server_process else None
            self.stop()
            raise RuntimeError(
                f"Failed to start OpenCode server on port {self.port}"
                + (f" (exit code: {return_code})" if return_code is not None else "")
            )

        logger.info(f"OpenCode server ready on {self.host}")

    def stop(self) -> None:
        if not self._owns_server:
            return
        if self._server_process is None:
            return
        if self._server_process.poll() is not None:
            return

        logger.info("Stopping global OpenCode server...")
        if self._server_pgid is not None and hasattr(os, "killpg"):
            os.killpg(self._server_pgid, signal.SIGTERM)
        else:
            self._server_process.terminate()

        try:
            self._server_process.wait(timeout=5)
        except Exception:
            if self._server_pgid is not None and hasattr(os, "killpg"):
                os.killpg(self._server_pgid, signal.SIGKILL)
            else:
                self._server_process.kill()
            self._server_process.wait(timeout=5)
        finally:
            self._server_process = None
            self._server_pgid = None
            self._owns_server = False

        # if OpenCodeSessionManager._is_port_listening(self.port):
        #     OpenCodeSessionManager._kill_port_listener(self.port)

        logger.info("OpenCode server stopped.")


def get_session_manager(
    host: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    port: Optional[int] = None,
) -> OpenCodeSessionManager:
    """Factory function for OpenCodeSessionManager."""
    return OpenCodeSessionManager(
        host=host,
        timeout_seconds=timeout_seconds,
        port=port,
    )


if __name__ == "__main__":
    try:
        repo_path = REPO_PATH
        repo_dir = Path(repo_path) if repo_path else Path.cwd()
        runtime = OpenCodeServerRuntime(repo_path=str(repo_dir))
        runtime.start()
        with get_session_manager() as manager:
            test_response = manager.send_message("这个项目代码的主要编程语言是什么")
            logger.info(f"Test response: {test_response}")
            info = manager.get_session_info()
            serializable_history = [x.model_dump(mode="json", warnings=False) for x in info]

        runtime.stop()
    except Exception as exc:
        logger.error(f"Test failed: {exc}")

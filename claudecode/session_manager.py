"""OpenCode session manager for phased analysis workflows."""

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

from claudecode.constants import DEFAULT_CLAUDE_MODEL, DEFAULT_CLAUDE_PROVIDER, DEFAULT_TIMEOUT_SECONDS
from claudecode.logger import get_logger

logger = get_logger(__name__)


class OpenCodeSessionManager:
    """Manage one OpenCode server + one session lifecycle."""

    def __init__(
        self,
        host: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        model: str = DEFAULT_CLAUDE_MODEL,
        provider_id: str = DEFAULT_CLAUDE_PROVIDER,
        repo_path: Optional[str] = None,
        port: Optional[int] = None,
    ):
        self.repo_path = repo_path
        self.timeout_seconds = timeout_seconds or DEFAULT_TIMEOUT_SECONDS
        self.model = model
        self.provider_id = provider_id

        self.host, self.port = self._resolve_host_and_port(host, port)
        self.client = Opencode(base_url=self.host, timeout=self.timeout_seconds)

        self.session_id: Optional[str] = None
        self._server_process: Optional[subprocess.Popen] = None
        self._server_pgid: Optional[int] = None
        self._owns_server = False

        # Start local server only when scanning local repo with localhost target.
        if self.repo_path and self._is_local_host(self.host):
            self._start_server()

    def _resolve_host_and_port(self, host: Optional[str], port: Optional[int]) -> Tuple[str, int]:
        env_port = os.environ.get("OPENCODE_PORT")
        default_port = int(env_port) if env_port and env_port.isdigit() else 4096
        chosen_port = int(port) if port is not None else default_port

        raw_host = (host or os.environ.get("OPENCODE_API_URL") or f"http://127.0.0.1:{chosen_port}").rstrip("/")
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

    def _wait_server_ready(self, timeout_seconds: float = 10.0) -> bool:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if self._is_port_listening(self.port):
                return True
            if self._server_process is not None and self._server_process.poll() is not None:
                return False
            time.sleep(0.2)
        return self._is_port_listening(self.port)

    def _start_server(self) -> None:
        repo_abs_path = str(Path(self.repo_path).resolve())
        if not os.path.exists(repo_abs_path):
            raise ValueError(f"Repository path does not exist: {repo_abs_path}")

        if self._is_port_listening(self.port):
            logger.info(f"Reusing existing OpenCode server on port {self.port}")
            self._owns_server = False
            return

        server_bin_candidates = ["opencode", "opencode.cwd"]
        server_bin = os.environ.get("OPENCODE_SERVER_BIN")
        if server_bin:
            server_bin_candidates = [server_bin]

        cmd = None
        for candidate in server_bin_candidates:
            cmd_candidate = [candidate, "serve", "--port", str(self.port)]
            if self._is_windows():
                cmd = " ".join(cmd_candidate)
            else:
                cmd = cmd_candidate
            logger.info(f"Starting OpenCode server: {' '.join(cmd_candidate)}")
            try:
                self._server_process = subprocess.Popen(
                    cmd,
                    cwd=repo_abs_path,
                    text=True,
                    start_new_session=True,
                    shell=self._is_windows(),
                )
                break
            except FileNotFoundError:
                self._server_process = None
                continue

        if self._server_process is None:
            raise RuntimeError("Failed to start OpenCode server: command not found (tried opencode, opencode.cwd)")

        if hasattr(os, "getpgid") and not self._is_windows():
            self._server_pgid = os.getpgid(self._server_process.pid)
        else:
            self._server_pgid = None
        self._owns_server = True

        if not self._wait_server_ready():
            return_code = self._server_process.poll() if self._server_process else None
            self._stop_server()
            raise RuntimeError(
                f"Failed to start OpenCode server on port {self.port}"
                + (f" (exit code: {return_code})" if return_code is not None else "")
            )

        logger.info(f"OpenCode server ready on {self.host}")

    def _stop_server(self) -> None:
        if not self._owns_server:
            return
        if self._server_process is None:
            return
        if self._server_process.poll() is not None:
            return

        logger.info("Stopping background OpenCode server...")
        if self._server_pgid is not None and hasattr(os, "killpg"):
            os.killpg(self._server_pgid, signal.SIGTERM)
        else:
            self._server_process.terminate()
        try:
            self._server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if self._server_pgid is not None and hasattr(os, "killpg"):
                os.killpg(self._server_pgid, signal.SIGKILL)
            else:
                self._server_process.kill()
            self._server_process.wait(timeout=5)
        finally:
            self._server_process = None
            self._server_pgid = None
            self._owns_server = False

        # Some opencode versions may leave a detached listener; cleanup by port.
        if self._is_port_listening(self.port):
            self._kill_port_listener(self.port)

        logger.info("OpenCode server stopped.")

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

    def create_session(self) -> str:
        try:
            session = self.client.session.create(extra_body={})
            self.session_id = session.id
            if not self.session_id:
                raise ValueError("Failed to obtain session ID from OpenCode server")
            logger.info(f"OpenCode session created successfully. ID: {self.session_id}")
            return self.session_id
        except Exception as exc:
            logger.error(f"Failed to create OpenCode session: {exc}")
            raise Exception(f"Session creation failed: {exc}")

    def send_message(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        if not self.session_id:
            raise ValueError("No active session. Call create_session() first.")

        try:
            kwargs: Dict[str, Any] = {
                "id": self.session_id,
                "model_id": self.model,
                "provider_id": self.provider_id,
                "parts": [{"type": "text", "text": prompt}],
            }
            if system_prompt:
                kwargs["system"] = system_prompt

            response = self.client.session.chat(**kwargs)
            response_data = response.to_dict()
            logger.info(f"Message sent successfully to session {self.session_id}")
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

        self._stop_server()
        return result

    def get_session_info(self) -> Dict[str, Any]:
        if not self.session_id:
            return {"status": "no_active_session"}
        try:
            return self.client.session.messages(id=self.session_id)
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
            self.close_session()
        except Exception:
            pass


def get_session_manager(
    host: Optional[str] = None,
    repo_path: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    port: Optional[int] = None,
) -> OpenCodeSessionManager:
    """Factory function for OpenCodeSessionManager."""
    return OpenCodeSessionManager(
        host=host,
        timeout_seconds=timeout_seconds,
        repo_path=repo_path,
        port=port,
    )


if __name__ == "__main__":
    try:
        repo_path = os.environ.get("REPO_PATH")
        repo_dir = Path(repo_path) if repo_path else Path.cwd()
        with get_session_manager(repo_path=str(repo_dir)) as manager:
            info = manager.get_session_info()
            logger.info(f"Session info: {info}")

            test_response = manager.send_message("@explore 搜索一下关于 auth 的所有文件和逻辑")
            logger.info(f"Test response: {test_response}")
    except Exception as exc:
        logger.error(f"Test failed: {exc}")

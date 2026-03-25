"""Utilities for rendering repository file trees with line counts."""

import argparse
import os
from pathlib import Path
from typing import Callable, Dict, Optional, Union


TreeNode = Dict[str, Union[str, int, bool, Dict[str, "TreeNode"]]]


def count_physical_lines(file_path: Path) -> int:
    """Count physical lines in a file (binary/unreadable files return 0)."""
    try:
        with open(file_path, "rb") as handle:
            sample = handle.read(8192)
            if b"\x00" in sample:
                return 0

            data = sample + handle.read()
            if not data:
                return 0

            line_count = data.count(b"\n")
            if not data.endswith(b"\n"):
                line_count += 1
            return line_count
    except (OSError, UnicodeError):
        return 0


def _new_dir_node(name: str) -> TreeNode:
    return {
        "name": name,
        "is_dir": True,
        "loc": 0,
        "children": {},
    }


def _new_file_node(name: str, loc: int) -> TreeNode:
    return {
        "name": name,
        "is_dir": False,
        "loc": loc,
    }


def _aggregate_loc(node: TreeNode) -> int:
    if not node.get("is_dir", False):
        return int(node.get("loc", 0))

    children = node.get("children", {})
    total = 0
    if isinstance(children, dict):
        for child in children.values():
            if isinstance(child, dict):
                total += _aggregate_loc(child)

    node["loc"] = total
    return total


def _render_tree(node: TreeNode, prefix: str = "", is_last: bool = True, is_root: bool = True) -> str:
    name = str(node.get("name", ""))
    loc = int(node.get("loc", 0))
    is_dir = bool(node.get("is_dir", False))

    if is_root:
        current_line = f"{name}{'/' if is_dir else ''} ({loc} LOC)"
    else:
        branch = "`-- " if is_last else "|-- "
        current_line = f"{prefix}{branch}{name}{'/' if is_dir else ''} ({loc} LOC)"

    if not is_dir:
        return current_line

    children = node.get("children", {})
    if not isinstance(children, dict) or not children:
        return current_line

    child_nodes = [child for child in children.values() if isinstance(child, dict)]
    child_nodes.sort(key=lambda item: (not bool(item.get("is_dir", False)), str(item.get("name", "")).lower()))

    lines = [current_line]
    child_prefix = prefix if is_root else (f"{prefix}    " if is_last else f"{prefix}|   ")
    for idx, child in enumerate(child_nodes):
        child_is_last = idx == len(child_nodes) - 1
        lines.append(_render_tree(child, prefix=child_prefix, is_last=child_is_last, is_root=False))
    return "\n".join(lines)


def build_project_file_tree_with_loc(
    repo_dir: Path,
    is_excluded: Optional[Callable[[str], bool]] = None,
) -> str:
    """Generate repository file tree string with physical line counts."""
    root = _new_dir_node(repo_dir.name)

    for current_root, _, filenames in os.walk(repo_dir):
        current_root_path = Path(current_root)
        for filename in filenames:
            abs_path = current_root_path / filename
            rel_path = abs_path.relative_to(repo_dir).as_posix()

            if is_excluded and is_excluded(rel_path):
                continue
            if "/.git/" in f"/{rel_path}/":
                continue

            parts = rel_path.split("/")
            node = root
            children = node["children"]
            if not isinstance(children, dict):
                continue

            for directory in parts[:-1]:
                child = children.get(directory)
                if not isinstance(child, dict):
                    child = _new_dir_node(directory)
                    children[directory] = child
                node = child
                next_children = node.get("children", {})
                if not isinstance(next_children, dict):
                    next_children = {}
                    node["children"] = next_children
                children = next_children

            children[parts[-1]] = _new_file_node(parts[-1], count_physical_lines(abs_path))

    _aggregate_loc(root)
    return _render_tree(root)


def main() -> int:
    """CLI entrypoint for manual testing."""
    parser = argparse.ArgumentParser(
        description="Print repository file tree with physical line counts.",
    )
    parser.add_argument("--path", default=".", help="Repository directory path")
    args = parser.parse_args()

    repo_dir = Path(args.path).expanduser().resolve()
    if not repo_dir.exists() or not repo_dir.is_dir():
        print(f"Invalid directory: {repo_dir}")
        return 1

    print(build_project_file_tree_with_loc(repo_dir=repo_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

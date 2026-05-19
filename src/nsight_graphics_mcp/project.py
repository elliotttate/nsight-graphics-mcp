"""Nsight Graphics project file (.nsight-gfxproj) authoring.

Nsight projects are XML files describing the launch target + activity +
per-activity settings. The Nsight Graphics UI writes them when you save a
project; ``ngfx --project <file>`` accepts them on the command line.

This module writes a minimally-valid project file from a small Python dict,
plus reads existing ones and lets you mutate them. The XML structure is a
documented superset of what the CLI supports — different Nsight versions
recognise a slightly different schema, so we treat unknown elements as
opaque and preserve them across round-trips.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


PROJECT_TEMPLATE = """\
<?xml version="1.0" encoding="utf-8"?>
<NsightProject version="1">
  <Target platform="Windows" hostname="localhost"/>
  <Activity name="Graphics Capture"/>
  <Launch>
    <Executable></Executable>
    <Arguments></Arguments>
    <WorkingDirectory></WorkingDirectory>
    <Environment></Environment>
  </Launch>
  <Settings/>
</NsightProject>
"""


def create_project(
    path: Path,
    *,
    activity: str = "Graphics Capture",
    exe: str | None = None,
    args: str | None = None,
    working_dir: str | None = None,
    env_pairs: str | None = None,
    platform: str = "Windows",
    hostname: str = "localhost",
    settings: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Write a new Nsight project file at ``path``."""
    root = ET.fromstring(PROJECT_TEMPLATE)
    target = root.find("Target")
    if target is not None:
        target.set("platform", platform)
        target.set("hostname", hostname)
    act = root.find("Activity")
    if act is not None:
        act.set("name", activity)
    launch = root.find("Launch")
    if launch is not None:
        if exe is not None:
            launch.find("Executable").text = exe  # type: ignore[union-attr]
        if args is not None:
            launch.find("Arguments").text = args  # type: ignore[union-attr]
        if working_dir is not None:
            launch.find("WorkingDirectory").text = working_dir  # type: ignore[union-attr]
        if env_pairs is not None:
            launch.find("Environment").text = env_pairs  # type: ignore[union-attr]
    if settings:
        settings_node = root.find("Settings")
        if settings_node is not None:
            for k, v in settings.items():
                ET.SubElement(settings_node, "Setting", {"key": k, "value": str(v)})
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
    return {"ok": True, "path": str(path)}


def read_project(path: Path) -> dict[str, Any]:
    """Read an existing Nsight project XML and return a flattened dict."""
    if not path.is_file():
        return {"ok": False, "error": f"project not found: {path}"}
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        return {"ok": False, "error": f"parse error: {exc}"}
    root = tree.getroot()
    out: dict[str, Any] = {"ok": True, "path": str(path), "root_tag": root.tag, "root_attrib": dict(root.attrib)}
    for child in root:
        out[child.tag] = {"attrib": dict(child.attrib), "text": (child.text or "").strip()}
        # one level deeper for nested elements
        for sub in child:
            out.setdefault(f"{child.tag}/{sub.tag}", []).append(
                {"attrib": dict(sub.attrib), "text": (sub.text or "").strip()}
            )
    return out


def update_project(
    path: Path,
    *,
    activity: str | None = None,
    exe: str | None = None,
    args: str | None = None,
    working_dir: str | None = None,
    env_pairs: str | None = None,
    set_settings: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Mutate fields in an existing project file in-place. Unset args left alone."""
    if not path.is_file():
        return {"ok": False, "error": f"project not found: {path}"}
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        return {"ok": False, "error": f"parse error: {exc}"}
    root = tree.getroot()
    if activity is not None:
        act = root.find("Activity")
        if act is None:
            act = ET.SubElement(root, "Activity")
        act.set("name", activity)
    launch = root.find("Launch")
    if launch is None and any(v is not None for v in (exe, args, working_dir, env_pairs)):
        launch = ET.SubElement(root, "Launch")
    if launch is not None:
        for tag, value in (
            ("Executable", exe),
            ("Arguments", args),
            ("WorkingDirectory", working_dir),
            ("Environment", env_pairs),
        ):
            if value is None:
                continue
            node = launch.find(tag)
            if node is None:
                node = ET.SubElement(launch, tag)
            node.text = value
    if set_settings:
        node = root.find("Settings")
        if node is None:
            node = ET.SubElement(root, "Settings")
        existing = {s.get("key"): s for s in node.findall("Setting")}
        for k, v in set_settings.items():
            if k in existing:
                existing[k].set("value", str(v))
            else:
                ET.SubElement(node, "Setting", {"key": k, "value": str(v)})
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return {"ok": True, "path": str(path)}

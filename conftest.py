"""Pytest glue for the KDE Connect integration test suite.

Makes the HA core test harness fixtures available:

- adds the HA core checkout root to ``sys.path`` so ``tests.conftest`` /
  ``tests.common`` can be imported;
- adds this repo root to ``sys.path`` so ``custom_components.kde_connect``
  is importable;
- symlinks the custom integration into the harness config dir
  (``tests/testing_config/custom_components/kde_connect``) so Home Assistant's
  loader discovers it when tests call ``enable_custom_integrations``;
- registers ``tests.conftest`` as a pytest plugin so all harness fixtures
  (``hass``, ``enable_custom_integrations``, registry fixtures, socket
  policy, patch_json/patch_time monkeypatches) are active.
"""

from __future__ import annotations

import os
import pathlib
import sys

HA_CORE = pathlib.Path(
    os.environ.get("HA_CORE_PATH") or "~/.hermes/cache/scratch/ha-core"
).expanduser()
REPO = pathlib.Path(__file__).resolve().parent

for _path in (str(HA_CORE), str(REPO)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# Discover the custom integration through the harness config dir, where
# homeassistant.loader looks for custom_components.
_cc_dir = HA_CORE / "tests" / "testing_config" / "custom_components"
_link = _cc_dir / "kde_connect"
if not _link.exists():
    if _link.is_symlink():
        _link.unlink()
    _link.symlink_to(REPO / "custom_components" / "kde_connect")

pytest_plugins = ("tests.conftest",)

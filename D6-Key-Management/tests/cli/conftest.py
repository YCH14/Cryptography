"""Run every CLI test inside its own temporary folder.

Some commands write files into the current directory by default (for example the revocation notice),
and the tests must not leave them in the repository.
"""

import pytest


@pytest.fixture(autouse=True)
def _run_in_temporary_directory(tmp_path_factory, monkeypatch):
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))

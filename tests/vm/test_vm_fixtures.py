"""Fixture-level tests for tests/vm_fixtures.py's shared nix_darwin_vm fixture.

Two complementary tests, not redundant with each other:

- test_nix_darwin_vm_yields_usable_manager uses normal pytest fixture
  injection (the same path every real consumer, e.g. test_scaffold_vm.py,
  actually uses) to verify the fixture provides a usable, cloned, started
  TartVMManager.
- test_nix_darwin_vm_tears_down_even_on_generator_exit drives the fixture's
  underlying generator directly (via its `__wrapped__` attribute, since
  pytest fixture functions can't be called directly) specifically to
  observe state *after* its teardown runs — something a normally-injected
  consumer test structurally cannot do, since the fixture's own teardown
  always runs after the consuming test's body has already returned.
"""

from __future__ import annotations

import pytest

from mac2nix.vm.manager import TartVMManager
from tests.vm_fixtures import local_vm_names, nix_darwin_vm

pytestmark = pytest.mark.nix_vm


def test_nix_darwin_vm_yields_usable_manager(nix_darwin_vm: TartVMManager) -> None:
    assert isinstance(nix_darwin_vm, TartVMManager)
    clone_name = nix_darwin_vm._current_clone
    assert clone_name is not None
    assert clone_name in local_vm_names()


@pytest.mark.skipif(not TartVMManager.is_available(), reason="tart not available")
def test_nix_darwin_vm_tears_down_even_on_generator_exit() -> None:
    gen = nix_darwin_vm.__wrapped__()
    mgr = next(gen)
    clone_name = mgr._current_clone

    try:
        assert isinstance(mgr, TartVMManager)
        assert clone_name is not None
        assert clone_name in local_vm_names()
    finally:
        with pytest.raises(StopIteration):
            next(gen)

    assert clone_name not in local_vm_names()

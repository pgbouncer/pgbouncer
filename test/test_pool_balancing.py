"""Tests for pool-level active connection load balancing.

Pool-level load balancing tracks active connections per (database, user)
and distributes new connections to the least-loaded backend host when reusing
connections.
"""

import pytest
from .connection_tracker import scenario
from .utils import WINDOWS


# --- Load balancing tests ---


@scenario
def test_round_robin():
    """Check that connections are in round robin mode"""
    return "10*(+1a +1b) =10a =10b"


@scenario
def test_tie_breaking():
    """
      Since we use a stable sorting we can tell that if two servers are 
      equally loaded the next connection goes to the server that was 
      lower before the tie.
    
      Here are some scenarios.
    """
    return """
      +8 =4a =4b     # 4 eash
      -3a -3b        # 1 each but a was lower before the tie
      +1a +1b        # a used before b
      -1b -1a        # 1 each but b was lower before the tie
      +1b +1a        # b used before a
      -1a            # now b = a + 1
      +2a            # a gets 2 consecutive, now a = b + 1
      +1b            # but after that connections goes to b
      +1b            # same logic 2 consecutive to b
    """


@scenario
def test_rebalance():
    """New connections go to least-loaded host after disconnects"""
    return "+4 =2a =2b -2b +2b"


@scenario
def test_repeated_rebalance():
    """Repeatedly rebalances when connections from one host close"""
    return "+6 4*(=3a =3b -3b +3b)"


# --- Test involving reboot and takeover ---


@pytest.mark.skipif(WINDOWS, reason="takeover hangs on Windows")
@scenario
def test_survives_takeover():
    """Connections survive online restart"""
    return "+4 =2a =2b R =2a =2b +1 =3a =2b +1 =3b =3a"


@pytest.mark.skipif(WINDOWS, reason="takeover hangs on Windows")
@scenario
def test_reboot_bias():
    """
       One scenario where the active connections can become 
       imbalanceed is after repeated reboots with incomplete rounds of connections.
       
       A potential fix would be to open one connection every host simmultaneously.
       But this seems too artificial, so I won't handle it.
    """
    return """
       +5 R =3a =2b    # a > b before reboot
       +1a R =4a =2b   # round robing doesn't care and goes to a again
       +1a R =5a =2b   # and this continues
       +1a R =6a =2b   # indefinitely
    """


@pytest.mark.skipif(WINDOWS, reason="takeover hangs on Windows")
@scenario
def test_multiple_takeovers():
    """Multiple online restarts with new connections"""
    return "3*(R +1) =3a =0b"

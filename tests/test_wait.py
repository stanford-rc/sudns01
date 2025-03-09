# vim: ts=4 sw=4 noet

# Copyright 2025 The Board of Trustees of the Leland Stanford Junior University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Stdlib imports
import datetime
import logging
import time
import zoneinfo
from typing import NamedTuple

# PyPi imports
import pytest

# local imports
from sudns01.wait import FixedWaiter, StanfordWaiter

# Make some datetime objects for test cases.  Include the times when Big Ben
# chimes, plus the refresh times, and one minute before & after.
# All objects will be dated March 10, 2020.
t15_00 = datetime.datetime(
	year=2020,
	month=3,
	day=10,
	hour=15,
	tzinfo=zoneinfo.ZoneInfo('US/Pacific'),
)
# All further times use 15:00 as the starting point, and change specific fields.
t15_04 = t15_00.replace(
	minute=4,
)
t15_05 = t15_00.replace(
	minute=5,
)
t15_06 = t15_00.replace(
	minute=6,
)
t15_15 = t15_00.replace(
	minute=15,
)
t15_30 = t15_00.replace(
	minute=30,
)
t15_34 = t15_00.replace(
	minute=34,
)
t15_35 = t15_00.replace(
	minute=35,
)
t15_36 = t15_00.replace(
	minute=36,
)
t15_45 = t15_00.replace(
	minute=45,
)

# Make a set of additional times, which will be used for comparison.
# (These won't be used as test cases directly.)
t16_06 = t15_45.replace(
	hour=16,
	minute=6,
)

# Test FixedWaiter
def test_fixed() -> None:
	# Test initializing some waiters
	waiter_zero = FixedWaiter(0.0)
	assert waiter_zero.how_long == 0.0

	waiter_sixty = FixedWaiter(60.0)
	assert waiter_sixty.how_long == 60.0

	with pytest.raises(TypeError):
		waiter_bad1 = FixedWaiter(0)
	with pytest.raises(ValueError):
		waiter_bad2 = FixedWaiter(-0.25)
	
	# Make sure step gives us expected results
	step_zero1 = waiter_zero.step()
	assert (t15_00 + step_zero1) == t15_00
	step_zero2 = waiter_zero.step()
	assert (t15_00 + step_zero2) == t15_00

	step_sixty1 = waiter_sixty.step()
	assert (t15_04 + step_sixty1) == t15_05
	step_sixty2 = waiter_sixty.step()
	assert (t15_04 + step_sixty2) == t15_05

# Test waiting, using the FixedWaiter
def test_fixed_wait(monkeypatch) -> None:
	waiter_sixty = FixedWaiter(60.0)

	# Make a class to hold how long we wait.
	# Why do this?  Because we need to record how long we waited; we can't
	# get that info by just mocking time.wait() to return a value, because the
	# call to time.wait() is buried in other code.
	class FakeSleep():
		waited_time: float | None
		def __init__(self) -> None:
			self.waited_time = None

		def __call__(self, how_long: float) -> None:
			self.waited_time = how_long
	fs = FakeSleep()

	with monkeypatch.context() as m:
		m.setattr(time, "sleep", fs) 
		waiter_sixty.wait()
		assert fs.waited_time == 60.0

def test_stanford_start() -> None:
	"""Test StanfordWaiter starting states.

	There are only two times when our starting state will be IN_REFRESH.
	All other times will be BEFORE_REFRESH.
	"""

	expect_before_refresh: list[datetime.datetime] = [
		t15_00,
		t15_04,
		t15_06,
		t15_15,
		t15_30,
		t15_34,
		t15_36,
		t15_45,
	]

	expect_in_refresh: list[datetime.datetime] = [
		t15_05,
		t15_35
	]

	for case in expect_before_refresh:
		assert (
			StanfordWaiter.get_starting_state(case) ==
			StanfordWaiter.SUWaitState.BEFORE_REFRESH
		)
	for case in expect_in_refresh:
		assert (
			StanfordWaiter.get_starting_state(case) ==
			StanfordWaiter.SUWaitState.IN_REFRESH
		)

def test_stanford_change() -> None:
	"""Test StanfordWaiter state change.

	Given a current time and current state, we check to see what next-state and
	next-time are returned.  Repeat for both possible starting states, using
	each test case as the "current time".
	"""
	# Here is a matrix showing current time, current state, and expected values.
	# |       | BEFORE_REFRESH   | IN_REFRESH       |
	# |-------|------------------|------------------|
	# | 15:00 | IN_REFRESH 15:06 | IN_REFRESH 15:01 |
	# | 15:04 | IN_REFRESH 15:06 | IN_REFRESH 15:05 |
	# | 15:05 | IN_REFRESH 15:06 | IN_REFRESH 15:06 |
	# | 15:06 | IN_REFRESH 15:36 | IN_REFRESH 15:07 |
	# | 15:15 | IN_REFRESH 15:36 | IN_REFRESH 15:16 |
	# | 15:30 | IN_REFRESH 15:36 | IN_REFRESH 15:31 |
	# | 15:34 | IN_REFRESH 15:36 | IN_REFRESH 15:35 |
	# | 15:35 | IN_REFRESH 15:36 | IN_REFRESH 15:36 |
	# | 15:36 | IN_REFRESH 16:06 | IN_REFRESH 15:37 |
	# | 15:45 | IN_REFRESH 16:06 | IN_REFRESH 15:46 |

	# What do we need to define a test case?
	class ChangeCase(NamedTuple):
		current_time: datetime.datetime
		before_refresh_expected_time: datetime.datetime

		# The in_refresh_expected_time is simply current_time + (1 minute)
		# Both expected states are IN_REFRESH

	cases: list[ChangeCase] = [
		ChangeCase(t15_00, t15_06),
		ChangeCase(t15_04, t15_06),
		ChangeCase(t15_05, t15_06),
		ChangeCase(t15_06, t15_36),
		ChangeCase(t15_15, t15_36),
		ChangeCase(t15_30, t15_36),
		ChangeCase(t15_34, t15_36),
		ChangeCase(t15_35, t15_36),
		ChangeCase(t15_36, t16_06),
		ChangeCase(t15_45, t16_06),
	]

	# Make a duration object of one minute
	one_minute = datetime.timedelta(minutes=1)

	for case in cases:
		# Test the current time with the BEFORE_REFRESH state
		(next_state, next_time) = StanfordWaiter.get_next_state(
			StanfordWaiter.SUWaitState.BEFORE_REFRESH,
			case.current_time,
		)
		assert next_state == StanfordWaiter.SUWaitState.IN_REFRESH
		assert next_time == case.before_refresh_expected_time

		# Test the current time with the IN_REFRESH state
		(next_state, next_time) = StanfordWaiter.get_next_state(
			StanfordWaiter.SUWaitState.IN_REFRESH,
			case.current_time,
		)
		assert next_state == StanfordWaiter.SUWaitState.IN_REFRESH
		assert (next_time - case.current_time) == one_minute

def test_stanford_step(monkeypatch) -> None:
	"""Test stepping from one state to another.

	We take our set of testcases, and mock datetime.datetime.now to return the
	testcase time as the current time.  We then create a StanfordWaiter, step
	it, and check to see what time it returns.  If that looks good, we step it
	again, and check to see if it returns a one-minute wait.
	"""
	# What is our current time?
	stanford_now = datetime.datetime.now(
		tz=zoneinfo.ZoneInfo('US/Pacific'),
	)

	# Make a class that we can use to monkeypatch datetime.datetime, which
	# gives us a now() that we can control
	class FakeDateTime(datetime.datetime):
		now_time: datetime.datetime

		@classmethod
		def now(cls, # type: ignore[override]
			tz: datetime.tzinfo | None = None,
		) -> datetime.datetime: 
			return cls.now_time
	monkeypatch.setattr(datetime, "datetime", FakeDateTime)

	# What do we need to define a test case?
	class StepCase(NamedTuple):
		# What time to we feed into the first step()?
		step1_time: datetime.datetime

		# What do we expect from the first step()?
		step1_expected_time: datetime.datetime

		# NOTE: We'll never see a state of BEFORE_REFRESH, because
		# get_next_state will move us to IN_REFRESH as part of the first wait.

	# Make our list of test cases
	cases: list[StepCase] = [
		StepCase(t15_00, t15_06),
		StepCase(t15_05, t15_06),
		StepCase(t15_06, t15_36),
		StepCase(t15_15, t15_36),
		StepCase(t15_30, t15_36),
		StepCase(t15_34, t15_36),
		StepCase(t15_35, t15_36),
		StepCase(t15_36, t16_06),
		StepCase(t15_45, t16_06),
	]

	# Go through each test case
	for case in cases:
		# Make our waiter and check it has no state
		waiter = StanfordWaiter()
		assert waiter.state is None

		# Do our first step, check state, and time difference
		FakeDateTime.now_time = case.step1_time
		step_td1 = waiter.step()
		assert waiter.state == StanfordWaiter.SUWaitState.IN_REFRESH
		assert step_td1 == (case.step1_expected_time - case.step1_time)

		# Step again and check state & time difference
		FakeDateTime.now_time = case.step1_expected_time
		step_td2 = waiter.step()
		assert waiter.state == StanfordWaiter.SUWaitState.IN_REFRESH
		assert step_td2 == datetime.timedelta(seconds=60)

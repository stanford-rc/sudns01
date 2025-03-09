#!python3
# vim: ts=4 sw=4 noet

# Copyright 2025 The Board of Trustees of the Leland Stanford Junior University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Stdlib imports
import abc
import datetime
import enum
import logging
import time
from typing import Any
import zoneinfo

# PyPi imports

# local imports

# Set up logging
logger = logging.getLogger(__name__)
exception = logger.exception
error = logger.error
warning = logger.warning
info = logger.info
debug = logger.debug

class Waiter(metaclass=abc.ABCMeta):
	def __init__(self,
		*args,
		**kwargs
	) -> None:
		...

	@abc.abstractmethod
	def step(self) -> datetime.timedelta:
		"""Return a number of seconds to wait before checking DNS.

		This is intended to be called immediately before waiting.  As such, it
		may manipulate the instance's internal state.  (That is why this is
		called `step` isntead of `time_to_wait`.)

		:returns: A float, suitable for passing to `time.sleep()`.
		"""
		...

	def wait(self) -> None:
		"""Wait.

		This calls `step`, then sleeps for that amount of time.
		"""
		how_long = self.step().total_seconds()
		debug(f"Waiting {how_long} seconds.")
		time.sleep(how_long)

class FixedWaiter(Waiter):
	"""Wait for a fixed amount of time.

	:param how_long: How many seconds to wait (greater than or equal to zero).

	:raises TypeError: Wait time must be a float.

	:raises ValueError: Waiting for a negative amount of time.
	"""

	def __init__(self,
		how_long: float,
	) -> None:
		if not isinstance(how_long, float):
			raise TypeError('Wait time must be a floating-point number.')
		if how_long < 0.0:
			raise ValueError('Waiting for a negative amount of time.')
		super().__init__()
		self.how_long = how_long

	def step(self) -> datetime.timedelta:
		debug(f"Saying to wait {self.how_long} seconds")
		return datetime.timedelta(seconds=self.how_long)

# For Stanford DNS, we need to track our position relative to refresh

class StanfordWaiter(Waiter):
	"""Wait based on the Stanford DNS Refresh cycle.

	Our source for DNS refresh information:
	https://web.stanford.edu/group/networking/dist/sunet.reports/dns-update.txt
	DNS refresh happens at :05 and :35.  Changes appear in DNS "within 10
	minutes", and "certainly … within 20 minutes".

	Wait until :06 or :36 (whichever comes first), then start waiting one
	minute at a time.
	"""

	class SUWaitState(enum.Enum):
		"""Track if we have reached DNS Refresh.
		"""
		BEFORE_REFRESH = enum.auto()
		IN_REFRESH = enum.auto()

	# What is our current state?
	state: SUWaitState | None
	"""Our current state.

	This might be `None`, for a newly-instantiated instance.
	"""

	def __init__(self) -> None:
		super().__init__()
		self.state = None

	@classmethod
	def get_starting_state(
		cls,
		now: datetime.datetime,
	) -> SUWaitState:
		"""Figure out what state we should start in.

		:param now: The cuurrent time on the Stanford campus.

		:returns: Our starting state, either before refresh or in refresh.
		"""
		debug(f"Getting starting state for time {now}")
		# If we're exactly at :05:00 or :35:00, immediately put us in refresh!
		if now.second == 0 and now.minute in (5, 35):
			debug('Starting us out IN refresh')
			return cls.SUWaitState.IN_REFRESH
		else:
			# Otherwise, wait for the next refresh.
			debug('Starting us out BEFORE refresh')
			return cls.SUWaitState.BEFORE_REFRESH

	@classmethod
	def get_next_state(cls,
		current_state: SUWaitState | None,
		now: datetime.datetime,
	) -> tuple[SUWaitState, datetime.datetime]:
		"""Figure out what our next state should be, and how long to wait.

		:param current_state: The current state.

		:param now: The current time on the Stanford campus.

		:returns: The next state, and when we should check again.

		:raises TypeError: We are in an unknown state.
		"""

		# What we need to do depends on the current state
		if current_state is None:
			# Get our starting state, then call again.
			return cls.get_next_state(
				current_state=cls.get_starting_state(now),
				now=now
			)
		if current_state is cls.SUWaitState.BEFORE_REFRESH:
			# We need to wait until either :05 or :35
			target_time: datetime.datetime
			if now.minute < 5:
				debug('Waiting until :05')
				# Wait until :05 of this hour.
				target_time = now.replace(
					minute=5,
					second=0,
					microsecond=0,
				)
			elif now.minute == 5:
				# Oof, we're right on the refresh time.
				# Let's be hopeful and start checking immediately.
				debug('Not waiting at all!')
				target_time = now
			elif now.minute > 5 and now.minute <= 35:
				debug('Waiting until :35')
				# Wait until :35 of this hour.
				target_time = now.replace(
					minute=35,
					second=0,
					microsecond=0,
				)
			elif now.minute == 35:
				# Oof, we're right on the refresh time.
				# Let's be hopeful and start checking immediately.
				debug('Not waiting at all!')
				target_time = now
			else:
				# Wait until :05 of the next hour.
				debug('Waiting until :05')
				target_time = (
					now + datetime.timedelta(hours=1)
				).replace(
					minute=5,
					second=0,
					microsecond=0,
				)

			# Add one minute to the target time: DNS refresh is not instant.
			# Return our target time, and say to move us into IN_REFRESH.
			target_time += datetime.timedelta(minutes=1)
			debug(f"Target time is {target_time}")
			return (
				cls.SUWaitState.IN_REFRESH,
				target_time
			)

		elif current_state is cls.SUWaitState.IN_REFRESH:
			# We've already waited once for a refresh to begin.
			# So, wait for one minute.
			return (
				cls.SUWaitState.IN_REFRESH,
				now + datetime.timedelta(minutes=1)
			)

		else:
			raise TypeError(f"Unknown wait state {current_state.name}")

	def step(self) -> datetime.timedelta:
		# What time is it at Stanford right now?
		stanford_now = datetime.datetime.now(
			tz=zoneinfo.ZoneInfo('US/Pacific'),
		)

		# Figure out what our next state and wait time should be.
		next_state_info = self.get_next_state(
			self.state,
			stanford_now,
		)

		# Store the state, and return the difference between now and target.
		self.state = next_state_info[0]
		wait_duration = next_state_info[1] - stanford_now
		debug(f"Step {stanford_now} -> {next_state_info[1]} {wait_duration}")
		return wait_duration

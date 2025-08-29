# sitewatcher/bot/constants.py
"""Bot-level constants shared across handlers."""

# Conversation states for /add
ADD_WAIT_KEYWORDS = 1001
ADD_WAIT_INTERVAL = 1002

# Allowed intervals (minutes) for quick /add wizard
ALLOWED_INTERVALS = {1, 5, 10, 30, 60, 120, 1440}

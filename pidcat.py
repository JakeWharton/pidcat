#!/usr/bin/python -u

'''
Copyright 2009, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

# Script to highlight adb logcat output for console
# Originally written by Jeff Sharkey, http://jsharkey.org/
# Piping detection and popen() added by other Android team members
# Package filtering and output improvements by Jake Wharton, http://jakewharton.com
# Verbose mode, input key listener and time stamps added by Mike Wallace, http://www.risesoftware.com

import argparse
import sys
import re
import subprocess
from subprocess import PIPE
import os
import threading

LOG_LEVELS = 'VDIWEF'
LOG_LEVELS_MAP = dict([(LOG_LEVELS[i], i) for i in range(len(LOG_LEVELS))])
parser = argparse.ArgumentParser(description='Filter logcat by package name')
parser.add_argument('package', nargs='*', help='Application package name(s)')
parser.add_argument('-w', '--tag-width', metavar='N', dest='tag_width', type=int, default=22, help='Width of log tag')
parser.add_argument('-l', '--min-level', dest='min_level', type=str, choices=LOG_LEVELS+LOG_LEVELS.lower(), default='V', help='Minimum level to be displayed')
parser.add_argument('--color-gc', dest='color_gc', action='store_true', help='Color garbage collection')
parser.add_argument('--always-display-tags', dest='always_tags', action='store_true',help='Always display the tag name')
parser.add_argument('-s', '--serial', dest='device_serial', help='Device serial number (adb -s option)')
parser.add_argument('-d', '--device', dest='use_device', action='store_true', help='Use first device for log input (adb -d option).')
parser.add_argument('-e', '--emulator', dest='use_emulator', action='store_true', help='Use first emulator for log input (adb -e option).')
parser.add_argument('-c', '--clear', dest='clear_logcat', action='store_true', help='Clear the entire log before running.')
parser.add_argument('-t', '--tag', dest='tag', action='append', help='Filter output by specified tag(s)')
parser.add_argument('-i', '--ignore-tag', dest='ignored_tag', action='append', help='Filter output by ignoring specified tag(s)')
parser.add_argument('--verbose', dest='verbose', action='store_true', help='Shows all logcat lines and some script debug info')

args = parser.parse_args()
min_level = LOG_LEVELS_MAP[args.min_level.upper()]

verbose = args.verbose

if not args.package:
  print ("Warning: No package name provided\r")

# Store the names of packages for which to match all processes.
catchall_package = filter(lambda package: package.find(":") == -1, args.package)

if verbose:
  print ("catchall_package" + str(catchall_package))
  
# Store the name of processes to match exactly.
named_processes = filter(lambda package: package.find(":") != -1, args.package)

if verbose:
  print ("named_processes" + str(named_processes))


# Convert default process names from <package>: (cli notation) to <package> (android notation) in the exact names match group.
named_processes = map(lambda package: package if package.find(":") != len(package) - 1 else package[:-1], named_processes)

header_size = args.tag_width + 1 + 3 + 1 # space, level, space

width = -1
try:
  # Get the current terminal width
  import fcntl, termios, struct
  h, width = struct.unpack('hh', fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('hh', 0, 0)))
except:
  pass

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

RESET = '\033[0m'

def termcolor(fg=None, bg=None):
  codes = []
  if fg is not None: codes.append('3%d' % fg)
  if bg is not None: codes.append('10%d' % bg)
  return '\033[%sm' % ';'.join(codes) if codes else ''

def colorize(message, fg=None, bg=None):
  return termcolor(fg, bg) + message + RESET

# Defining the getch() function. Will use msvcrt's in Windows, and raw keystrokes in Linux
try:
  from msvcrt import getch
except ImportError:
  def getch():
    """Gets a single character from STDIO."""
    import sys
    import tty
    import termios
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
      tty.setraw(fd)
      ch = sys.stdin.read(1)
    finally:
      termios.tcsetattr(fd, termios.TCSADRAIN, old)

    return ch

class KeyEventThread(threading.Thread):
    def run(self):
      while True:
        key = getch()
        value = ord(key)
        if value == 32 or value == 67 or value == 99:
          # clear screen on 'c', 'C', or space
          os.system("clear")
          # Print this line so that the user knows they are still in adb
          linebuf = colorize(' ' * (header_size - 1), bg=WHITE)
          linebuf += ' Cleared.  adb is running...\r'
          print(linebuf)
        elif ord(key) == 3:  # Ctrl-C
          adb.terminate()
          exit()

def indent_wrap(message):
  if width == -1:
    return message
  message = message.replace('\t', '    ')
  wrap_area = width - header_size
  messagebuf = ''
  current = 0
  while current < len(message):
    next = min(current + wrap_area, len(message))
    messagebuf += message[current:next]
    if next < len(message):
      messagebuf += '\r\n'
      messagebuf += ' ' * header_size
    current = next
  return messagebuf


LAST_USED = [RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN]
KNOWN_TAGS = {
  'dalvikvm': WHITE,
  'Process': WHITE,
  'ActivityManager': WHITE,
  'ActivityThread': WHITE,
  'AndroidRuntime': CYAN,
  'jdwp': WHITE,
  'StrictMode': WHITE,
  'DEBUG': YELLOW,
}

def allocate_color(tag):
  # this will allocate a unique format for the given tag
  # since we dont have very many colors, we always keep track of the LRU
  if tag not in KNOWN_TAGS:
    KNOWN_TAGS[tag] = LAST_USED[0]
  color = KNOWN_TAGS[tag]
  if color in LAST_USED:
    LAST_USED.remove(color)
    LAST_USED.append(color)
  return color


RULES = {
  # StrictMode policy violation; ~duration=319 ms: android.os.StrictMode$StrictModeDiskWriteViolation: policy=31 violation=1
  re.compile(r'^(StrictMode policy violation)(; ~duration=)(\d+ ms)')
    : r'%s\1%s\2%s\3%s' % (termcolor(RED), RESET, termcolor(YELLOW), RESET),
}

# Only enable GC coloring if the user opted-in
if args.color_gc:
  # GC_CONCURRENT freed 3617K, 29% free 20525K/28648K, paused 4ms+5ms, total 85ms
  key = re.compile(r'^(GC_(?:CONCURRENT|FOR_M?ALLOC|EXTERNAL_ALLOC|EXPLICIT) )(freed <?\d+.)(, \d+\% free \d+./\d+., )(paused \d+ms(?:\+\d+ms)?)')
  val = r'\1%s\2%s\3%s\4%s' % (termcolor(GREEN), RESET, termcolor(YELLOW), RESET)

  RULES[key] = val


TAGTYPES = {
  'V': colorize(' V ', fg=WHITE, bg=BLACK),
  'D': colorize(' D ', fg=BLACK, bg=BLUE),
  'I': colorize(' I ', fg=BLACK, bg=GREEN),
  'W': colorize(' W ', fg=BLACK, bg=YELLOW),
  'E': colorize(' E ', fg=BLACK, bg=RED),
  'F': colorize(' F ', fg=BLACK, bg=RED),
}

PID_START = re.compile(r'^.*(\d+:\d+:\d+).*: Start proc ([a-zA-Z0-9._:]+) for ([a-z]+ [^:]+): pid=(\d+) uid=(\d+) gids=(.*)$')
PID_START_DALVIK = re.compile(r'^E/dalvikvm\(\s*(\d+)\): >>>>> ([a-zA-Z0-9._:]+) \[ userId:0 \| appId:(\d+) \]$')
PID_KILL  = re.compile(r'^Killing (\d+):([a-zA-Z0-9._:]+)/[^:]+: (.*)$')
PID_LEAVE = re.compile(r'^No longer want ([a-zA-Z0-9._:]+) \(pid (\d+)\): .*$')
PID_DEATH = re.compile(r'^Process ([a-zA-Z0-9._:]+) \(pid (\d+)\) has died.?$')
LOG_LINE  = re.compile(r'^.*(\d+:\d+:\d+).* ([A-Z])/(.+?)\( *(\d+)\): (.*?)$')
BUG_LINE  = re.compile(r'.*nativeGetEnabledTags.*')
BACKTRACE_LINE = re.compile(r'^#(.*?)pc\s(.*?)$')

adb_command = ['adb']
if args.device_serial:
  adb_command.extend(['-s', args.device_serial])

if args.use_device:
  adb_command.append('-d')

if args.use_emulator:
  adb_command.append('-e')

adb_command.append('logcat')
adb_command.append('-v')
adb_command.append('time')

if verbose:
  linebuf = "adb_command " + str(adb_command) + "\r"
  print (linebuf)

# Clear log before starting logcat
if args.clear_logcat:
  adb_clear_command = list(adb_command)
  adb_clear_command.append('-c')
  adb_clear = subprocess.Popen(adb_clear_command)

  while adb_clear.poll() is None:
    pass

# This is a ducktype of the subprocess.Popen object
class FakeStdinProcess():
  def __init__(self):
    self.stdout = sys.stdin
  def poll(self):
    return None

if sys.stdin.isatty():
  adb = subprocess.Popen(adb_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
else:
  adb = FakeStdinProcess()
pids = set()
last_tag = None
app_pid = None

if verbose:
  print ("adb is runnnig...\r")

# Start the thread that checks for keystrokes
keythread = KeyEventThread()
keythread.start()

def match_packages(token):
  if len(args.package) == 0:
    return True
  if token in named_processes:
    return True
  index = token.find(':')
  return (token in catchall_package) if index == -1 else (token[:index] in catchall_package)

def parse_death(tag, message):
  if tag != 'ActivityManager':
    return None, None
  kill = PID_KILL.match(message)
  if kill:
    pid = kill.group(1)
    package_line = kill.group(2)
    if match_packages(package_line) and pid in pids:
      return pid, package_line
  leave = PID_LEAVE.match(message)
  if leave:
    pid = leave.group(2)
    package_line = leave.group(1)
    if match_packages(package_line) and pid in pids:
      return pid, package_line
  death = PID_DEATH.match(message)
  if death:
    pid = death.group(2)
    package_line = death.group(1)
    if match_packages(package_line) and pid in pids:
      return pid, package_line
  return None, None

def parse_start_proc(line):
  start = PID_START.match(line)
  if start is not None:
    log_time, line_package, target, line_pid, line_uid, line_gids = start.groups()
    return log_time, line_package, target, line_pid, line_uid, line_gids
  start = PID_START_DALVIK.match(line)
  if start is not None:
    line_pid, line_package, line_uid = start.groups()
    return line_package, '', line_pid, line_uid, ''
  return None

while adb.poll() is None:
  try:
    line = adb.stdout.readline().decode('utf-8', 'replace').strip()
  except KeyboardInterrupt:
    break
  if len(line) == 0:
    break

  if verbose:
    linebuf = line + "\r"
    print (linebuf)

  bug_line = BUG_LINE.match(line)
  if bug_line is not None:
    continue

  log_line = LOG_LINE.match(line)
  if log_line is None:
    continue

  log_time, level, tag, owner, message = log_line.groups()
  start = parse_start_proc(line)
  if start:
    log_time, line_package, target, line_pid, line_uid, line_gids = start
    if match_packages(line_package):
      pids.add(line_pid)

      app_pid = line_pid

      linebuf  = '\r\n'
      linebuf += colorize(' ' * (header_size - 1), bg=WHITE)
      linebuf += indent_wrap(' Process %s created for %s\r\n' % (line_package, target))
      linebuf += colorize(' ' * (header_size - 1), bg=WHITE)
      linebuf += ' PID: %s   UID: %s   GIDs: %s\r\n' % (line_pid, line_uid, line_gids)
      linebuf += colorize(' ' * (header_size - 1), bg=WHITE)
      linebuf += ' Start time: %s' % log_time
      linebuf += '\r'
      print(linebuf)
      last_tag = None # Ensure next log gets a tag printed

  dead_pid, dead_pname = parse_death(tag, message)
  if dead_pid:
    pids.remove(dead_pid)
    linebuf  = '\r\n'
    linebuf += colorize(' ' * (header_size - 1), bg=RED)
    linebuf += ' Process %s (PID: %s) ended' % (dead_pname, dead_pid)
    linebuf += '\r\n'
    linebuf += colorize(' ' * (header_size - 1), bg=RED)
    linebuf += ' End time: %s' % log_time
    linebuf += '\r\n'
    print(linebuf)
    last_tag = None # Ensure next log gets a tag printed

  # Make sure the backtrace is printed after a native crash
  if tag.strip() == 'DEBUG':
    bt_line = BACKTRACE_LINE.match(message.lstrip())
    if bt_line is not None:
      message = message.lstrip()
      owner = app_pid

  if owner not in pids:
    continue
  if level in LOG_LEVELS_MAP and LOG_LEVELS_MAP[level] < min_level:
    continue
  if args.ignored_tag and tag.strip() in args.ignored_tag:
    continue
  if args.tag and tag.strip() not in args.tag:
    continue

  linebuf = ''

  # right-align tag title and allocate color if needed
  tag = tag.strip()
  if tag != last_tag or args.always_tags:
    last_tag = tag
    color = allocate_color(tag)
    tag = tag[-args.tag_width:].rjust(args.tag_width)
    linebuf += colorize(tag, fg=color)
  else:
    linebuf += ' ' * args.tag_width
  linebuf += ' '

  # write out level colored edge
  if level in TAGTYPES:
    linebuf += TAGTYPES[level]
  else:
    linebuf += ' ' + level + ' '
  linebuf += ' '

  # format tag message using rules
  for matcher in RULES:
    replace = RULES[matcher]
    message = matcher.sub(replace, message)

  linebuf += indent_wrap(message)
  linebuf += "\r"

  #~  print (linebuf.encode('utf-8'))
  print (linebuf)

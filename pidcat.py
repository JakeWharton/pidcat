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
# Written by Jeff Sharkey, http://jsharkey.org/
# Piping detection and popen() added by other Android team members
# Package name restriction by Jake Wharton, http://jakewharton.com

import argparse
import os
import sys
import re
import subprocess
from subprocess import PIPE


LOG_LEVELS = 'VDIWEF'
LOG_LEVELS_MAP = dict([(LOG_LEVELS[i], i) for i in range(len(LOG_LEVELS))])
parser = argparse.ArgumentParser(description='Filter logcat by package name')
parser.add_argument('package', nargs='*', help='Application package name(s)')
parser.add_argument('-w', '--tag-width', metavar='N', dest='tag_width', type=int, default=22, help='Width of log tag')
parser.add_argument('-l', '--min-level', dest='min_level', type=str, choices=LOG_LEVELS, default='V', help='Minimum level to be displayed')
parser.add_argument('--color-gc', dest='color_gc', action='store_true', help='Color garbage collection')
parser.add_argument('--always-display-tags', dest='always_tags', action='store_true',help='Always display the tag name')
parser.add_argument('-s', '--serial', dest='device_serial', help='Device serial number (adb -s option)')
parser.add_argument('-d', '--device', dest='use_device', action='store_true', help='Use first device for log input (adb -d option).')
parser.add_argument('-e', '--emulator', dest='use_emulator', action='store_true', help='Use first emulator for log input (adb -e option).')

args = parser.parse_args()
min_level = LOG_LEVELS_MAP[args.min_level]

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
      messagebuf += '\n'
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

PID_START = re.compile(r'^Start proc ([a-zA-Z0-9._:]+) for ([a-z]+ [^:]+): pid=(\d+) uid=(\d+) gids=(.*)$')
PID_KILL  = re.compile(r'^Killing (\d+):([a-zA-Z0-9._]+)/[^:]+: (.*)$')
PID_LEAVE = re.compile(r'^No longer want ([a-zA-Z0-9._]+) \(pid (\d+)\): .*$')
PID_DEATH = re.compile(r'^Process ([a-zA-Z0-9._]+) \(pid (\d+)\) has died.?$')
LOG_LINE  = re.compile(r'^([A-Z])/(.+?)\( *(\d+)\): (.*?)$')
BUG_LINE  = re.compile(r'.*nativeGetEnabledTags.*')

adb_command = ['adb']
if args.device_serial:
  adb_command.extend(['-s', args.device_serial])
if args.use_device:
  adb_command.append('-d')
if args.use_emulator:
  adb_command.append('-e')
adb_command.append('logcat')

adb = subprocess.Popen(adb_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
pids = set()
last_tag = None

def match_packages(token):
  if len(args.package) == 0:
    return True
  index = token.find(':')
  return (token in args.package) if index == -1 else (token[:index] in args.package)

def parse_death(tag, message):
  if tag != 'ActivityManager':
    return None
  kill = PID_KILL.match(message)
  if kill:
    pid = kill.group(1)
    if match_packages(kill.group(2)) and pid in pids:
      return pid
  leave = PID_LEAVE.match(message)
  if leave:
    pid = leave.group(2)
    if match_packages(leave.group(1)) and pid in pids:
      return pid
  death = PID_DEATH.match(message)
  if death:
    pid = death.group(2)
    if match_packages(death.group(1)) and pid in pids:
      return pid
  return None

while adb.poll() is None:
  try:
    line = adb.stdout.readline().decode('utf-8', 'replace').strip()
  except KeyboardInterrupt:
    break
  if len(line) == 0:
    break

  bug_line = BUG_LINE.match(line)
  if bug_line is not None:
    continue

  log_line = LOG_LINE.match(line)
  if log_line is None:
    continue

  level, tag, owner, message = log_line.groups()

  start = PID_START.match(message)
  if start is not None:
    line_package, target, line_pid, line_uid, line_gids = start.groups()

    if match_packages(line_package):
      pids.add(line_pid)

      linebuf  = '\n'
      linebuf += colorize(' ' * (header_size - 1), bg=WHITE)
      linebuf += indent_wrap(' Process created for %s\n' % target)
      linebuf += colorize(' ' * (header_size - 1), bg=WHITE)
      linebuf += ' PID: %s   UID: %s   GIDs: %s' % (line_pid, line_uid, line_gids)
      linebuf += '\n'
      print(linebuf)
      last_tag = None # Ensure next log gets a tag printed

  dead_pid = parse_death(tag, message)
  if dead_pid:
    pids.remove(dead_pid)
    linebuf  = '\n'
    linebuf += colorize(' ' * (header_size - 1), bg=RED)
    linebuf += ' Process %s ended' % dead_pid
    linebuf += '\n'
    print(linebuf)
    last_tag = None # Ensure next log gets a tag printed

  if owner not in pids:
    continue
  if LOG_LEVELS_MAP[level] < min_level:
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
  if level not in TAGTYPES: break
  linebuf += TAGTYPES[level]
  linebuf += ' '

  # format tag message using rules
  for matcher in RULES:
    replace = RULES[matcher]
    message = matcher.sub(replace, message)

  linebuf += indent_wrap(message)
  print(linebuf.encode('utf-8'))

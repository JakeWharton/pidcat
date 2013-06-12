#!/usr/bin/python

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
import fcntl
import termios
import struct

parser = argparse.ArgumentParser(description='Filter logcat by package name')
parser.add_argument('package', help='Application package name')
parser.add_argument('--tag-width', metavar='N', dest='tag_width', type=int, default=22, help='Width of log tag')

args = parser.parse_args()

tag_width = args.tag_width
package = args.package

header_size = tag_width + 1 + 3 + 1 # space, level, space

# unpack the current terminal width/height
data = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, '1234')
HEIGHT, WIDTH = struct.unpack('hh',data)

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

def colorize(message, fg=None, bg=None):
  ret = ''
  codes = []
  if fg is not None: codes.append('3%d' % fg)
  if bg is not None: codes.append('10%d' % bg)
  if codes:
    ret += '\033[%sm' % ';'.join(codes)
  ret += message
  if codes:
    ret += '\033[0m'
  return ret

def indent_wrap(message):
  wrap_area = WIDTH - header_size
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
  #re.compile(r"([\w\.@]+)=([\w\.@]+)"): r"%s\1%s=%s\2%s" % (format(fg=BLUE), format(fg=GREEN), format(fg=BLUE), format(reset=True)),
}

TAGTYPES = {
  'V': colorize(' V ', fg=WHITE, bg=BLACK),
  'D': colorize(' D ', fg=BLACK, bg=BLUE),
  'I': colorize(' I ', fg=BLACK, bg=GREEN),
  'W': colorize(' W ', fg=BLACK, bg=YELLOW),
  'E': colorize(' E ', fg=BLACK, bg=RED),
}

PID_START = re.compile(r'^Start proc ([a-zA-Z0-9._]+) for ([a-z]+ [^:]+): pid=(\d+) uid=(\d+) gids=(.*)\r?$')
PID_KILL  = re.compile(r'^Killing (\d+):([a-zA-Z0-9._]+)/[^:]+: (.*)\r?$')
PID_LEAVE = re.compile(r'^No longer want ([a-zA-Z0-9._]+) \(pid (\d+)\): .*\r?$')
PID_DEATH = re.compile(r'^\rProcess ([a-zA-Z0-9._]+) \(pid (\d+)\) has died.?$')
LOG_LINE  = re.compile(r'^([A-Z])/([^\(]+)\( *(\d+)\): (.*)\r?$')

input = os.popen('adb logcat')
pid = None

while True:
  try:
    line = input.readline()
  except KeyboardInterrupt:
    break
  if len(line) == 0:
    break

  log_line = LOG_LINE.match(line)
  if not log_line is None:
    level, tag, owner, message = log_line.groups()

    start = PID_START.match(message)
    if start is not None:
      line_package, target, line_pid, line_uid, line_gids = start.groups()

      if line_package == package:
        pid = line_pid

        linebuf  = '\n\n\n'
        linebuf += colorize(' ' * (header_size - 1), bg=WHITE)
        linebuf += indent_wrap(' Process created for %s\n' % target)
        linebuf += colorize(' ' * (header_size - 1), bg=WHITE)
        linebuf += ' PID: %s   UID: %s   GIDs: %s' % (line_pid, line_uid, line_gids)
        linebuf += '\n'
        print linebuf

    kill = PID_KILL.match(message)
    if kill is not None:
      line_pid, line_package, reason = kill.groups()
      if 'ActivityManager' == tag and pid == line_pid and package == line_package:
        pid = None

        linebuf  = '\n'
        linebuf += colorize(' ' * (header_size - 1), bg=RED)
        linebuf += ' Process killed because %s' % reason
        linebuf += '\n\n\n'
        print linebuf

    death = PID_DEATH.match(message)
    if death is not None:
      line_package, line_pid = death.groups()
      if 'ActivityManager' == tag and pid == line_pid and package == line_package:
        pid = None

        linebuf  = '\n'
        linebuf += colorize(' ' * (header_size - 1), bg=RED)
        linebuf += ' Process killed because no longer wanted\n\n\n'
        print linebuf

    if pid is None or owner != pid:
      continue

    linebuf = ''

    # right-align tag title and allocate color if needed
    tag = tag.strip()
    color = allocate_color(tag)
    tag = tag[-tag_width:].rjust(tag_width)
    linebuf += colorize(tag, fg=color)
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
    print linebuf

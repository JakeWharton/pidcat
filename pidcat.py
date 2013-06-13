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
import time

parser = argparse.ArgumentParser(description='Filter logcat by package name')
parser.add_argument('package', nargs='+', help='Application package name(s)')
parser.add_argument('--device-id', metavar='D', dest='device_id', type=str, default="", help='Device ID')
parser.add_argument('--tag-width', metavar='N', dest='tag_width', type=int, default=22, help='Width of log tag')
parser.add_argument('--color-gc', dest='color_gc', action='store_true', help='Color garbage collection')

args = parser.parse_args()

header_size = args.tag_width + 1 + 3 + 1 # space, level, space

# unpack the current terminal width/height
data = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, '1234')
HEIGHT, WIDTH = struct.unpack('hh',data)

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
}

PID_START = re.compile(r'^Start proc ([a-zA-Z0-9._:]+) for ([a-z]+ [^:]+): pid=(\d+) uid=(\d+) gids=(.*)\r?$')
PID_KILL  = re.compile(r'^Killing (\d+):([a-zA-Z0-9._]+)/[^:]+: (.*)\r?$')
PID_LEAVE = re.compile(r'^No longer want ([a-zA-Z0-9._]+) \(pid (\d+)\): .*\r?$')
PID_DEATH = re.compile(r'^Process ([a-zA-Z0-9._]+) \(pid (\d+)\) has died.?\r$')
LOG_LINE  = re.compile(r'^([A-Z])/([^\(]+)\( *(\d+)\): (.*)\r?$')
BUG_LINE  = re.compile(r'^(?!.*(nativeGetEnabledTags)).*$')

pids = set()
last_tag = None

def match_pacakges(token):
  index = token.find(':')
  return (token in args.package) if index == -1 else (token[:index] in args.package)

def parse_death(tag, message):
  if tag != 'ActivityManager':
    return None
  kill = PID_KILL.match(message)
  if kill:
    pid = kill.group(1)
    if match_pacakges(kill.group(2)) and pid in pids:
      return pid
  leave = PID_LEAVE.match(message)
  if leave:
    pid = leave.group(2)
    if match_pacakges(leave.group(1)) and pid in pids:
      return pid
  death = PID_DEATH.match(message)
  if death:
    pid = death.group(2)
    if match_pacakges(death.group(1)) and pid in pids:
      return pid
  return None

def logcat(device_id=""):
  device_cmd = ""
  if device_id:
    device_cmd = " -s " + device_id

  input = os.popen('adb' + device_cmd + ' logcat')

  last_tag = None  
  while True:
    try:
      line = input.readline()
    except KeyboardInterrupt:
      #break
      sys.exit()
    if len(line) == 0:
      break

    bug_line = BUG_LINE.match(line)
    if bug_line is None:
      continue

    log_line = LOG_LINE.match(line)
    if not log_line is None:
      level, tag, owner, message = log_line.groups()

      start = PID_START.match(message)
      if start is not None:
        line_package, target, line_pid, line_uid, line_gids = start.groups()

        if line_package == args.package:
          pids.add(line_pid)

          linebuf  = colorize(' ' * (header_size - 1), bg=WHITE)
          linebuf += indent_wrap(' Process created for %s\n' % target)
          linebuf += colorize(' ' * (header_size - 1), bg=WHITE)
          linebuf += ' PID: %s   UID: %s   GIDs: %s' % (line_pid, line_uid, line_gids)
          linebuf += '\n'
          print linebuf
          last_tag = None # Ensure next log gets a tag printed

      dead_pid = parse_death(tag, message)
      if dead_pid:
        pids.remove(dead_pid)
        linebuf  = '\n'
        linebuf += colorize(' ' * (header_size - 1), bg=RED)
        linebuf += ' Process %s ended' % dead_pid
        linebuf += '\n'
        print linebuf
        last_tag = None # Ensure next log gets a tag printed

      if owner not in pids:
        continue

      linebuf = ''

      # right-align tag title and allocate color if needed
      tag = tag.strip()
      if tag != last_tag:
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
      print linebuf

def check_for_devices():
  choosen_device = ""
  devices = []
  while True:
    res = os.popen('adb devices').read()
    raw_devices = res.splitlines()[1:-1]
    if raw_devices:
      if choosen_device in devices:
        print "\nOutputing logcat for device: " + choosen_device + "\n\n"
        logcat(choosen_device)
      else:
        print "Available devices:"
        devices = map(lambda d: str(re.compile("(\s)").split(d)[0]), raw_devices)
        
        for i, d in enumerate(devices):
          print str(i+1) + ": " + str(d)

        while True:
          choice = raw_input("> ")

          if re.compile("\d").match(choice):
            #is number
            if (int(choice) -1) < len(devices):
              choosen_device = devices[int(choice) -1]
              break

        
    else:
      print "\nCurrently no device is connected, will retry in few seconds\n"
      time.sleep(5)
      continue
  

check_for_devices()

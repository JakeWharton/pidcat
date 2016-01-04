Change Log
==========

Version 2.0.0 *(2015-05-25)*
----------------------------

 * New: Display package and process name in birth & death messages.
 * New: Process can be matched in addition to package. For example `com.android.chrome` will match
   all of Chrome's processes, `com.android.chrome:` will match only its main process, and
   `com.android.chrome:sandboxed_process1` will match that specific process name.
 * New: `-c` option clears log before reading logs.
 * New: If data is piped to `pidcat` it will be used as the log source instead of `adb`.
 * New: `-t` / `--tag` option allows filtering by tag name (regex supported).
 * New: `-i` / `--ignore-tag` option allows filtering out tags from the logs by name (regex supported).
 * New: `--version` option reports Pidcat's version.
 * New: Obtain unknown process IDs of currently-running apps.
 * New: `--current` option uses the package of the currently visible app for filtering.
 * New: Bash completion support for package names and device names. Requires manual installation of
   file in `bash_completion.d/`.
 * Fix: Properly match process birth & death from secondary processes.
 * Fix: Support leading spaces in PID numbers.
 * Fix: Default maximum tag length is now 23 (Android's maximum length).
 * Fix: Properly parse Android 5.1+ birth & death messages.


Version 1.4.1 *(2014-01-09)*
----------------------------

 * Fix: Ignore manufacturer-added invalid tag levels.


Version 1.4.0 *(2013-10-12)*
----------------------------

 * Add '--always-display-tags' argument for improved grepping.
 * Ignore bad UTF-8 data.
 * Replace tab characters in log message with four spaces.
 * Package name is now optional.


Version 1.3.1 *(2013-07-12)*
----------------------------

 * Add fatal to log level filtering.
 * Add '-e' and '-d' arguments for quickly selecting the emulator or device.
 * Improve removal of 'nativeGetEnabledTags' log spam.


Version 1.3.0 *(2013-06-19)*
----------------------------

 * Add support for Python 3.
 * Add '-s' argument for specifying device serial.
 * UTF-8 decode log messages.


Version 1.2.1 *(2013-06-14)*
----------------------------

 * Add support for 'fatal' log level.


Version 1.2.0 *(2013-06-13)*
----------------------------

 * Allow multiple packages to be specified.
 * Add argument to filter output based on log level.


Version 1.1.0 *(2013-06-12)*
----------------------------

 * De-duplicate tag name in output.
 * Color strict mode violations and optionally GC messages.
 * Support multiple processes for a package.


Version 1.0.0 *(2013-06-11)*
----------------------------

Initial version.

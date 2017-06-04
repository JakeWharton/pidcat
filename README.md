# About

This is a slightly modified version of the [original Pidcat](https://github.com/JakeWharton/pidcat). This version is kept up-to-date with the original one and essentially simply makes `python2` the standard for execution so it plays well with Arch Linux based distros.



PID Cat
=======

An update to Jeff Sharkey's excellent [logcat color script][1] which only shows
log entries for processes from a specific application package.

During application development you often want to only display log messages
coming from your app. Unfortunately, because the process ID changes every time
you deploy to the phone it becomes a challenge to grep for the right thing.

This script solves that problem by filtering by application package. Supply the
target package as the sole argument to the python script and enjoy a more
convenient development process.

    pidcat com.oprah.bees.android


Here is an example of the output when running for the Google Plus app:

![Example screen](screen.png)


Install
-------



*Note:* `<path to Android SDK>` should be absolute and not relative.

[1]: http://jsharkey.org/blog/2009/04/22/modifying-the-android-logcat-stream-for-full-color-debugging/

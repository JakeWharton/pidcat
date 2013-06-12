PID Cat
=======

An update to Jeff Sharkey's excellent [logcat color script][1] which only shows
log entries for processes from a specific application package.

During application development you often want to only display log messages
coming from your app. Unfortunately, because the process ID changes every time
you deploy to the phone it becomes a challenge to grep for the right thing.

This script solves that problem by filtering by application package. Supply the
target pacakge as the sole argument to the python script and enjoy a more
convenient development process.

    ./pidcat.py com.oprah.bees.android


Here is an example of the output when running for the Google Plus app:

![Example screen](screen.png)





 [1]: http://jsharkey.org/blog/2009/04/22/modifying-the-android-logcat-stream-for-full-color-debugging/

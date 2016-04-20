# locfg.pl Dockerfile

## What this is for

Some older HP servers require SSLv3 to run, but newer Linux distributions have
removed SSLv3 support from openssl libraries.  This Dockerfile allows you to
run the script with a custom openssl with SSLv3 support.

There is also a modified version of the locfg.pl command here.  This is
because (In my experience) the ILO system isn't good at negotiating SSL
capabilities so you need to force it to use a specific version.

This copy of locfg.pl defaults to TLSv1 which will run on newer blades and
doesn't require the Dockerfile.

## Setting up

On the initial run you will need to execute this command:

    docker build -t rfdrake/locfg .

## running the script

    docker run rfdrake/locfg -u admin -p password -s 10.80.80.80 --sslproto=SSLv3 -f Update_Firmware.xml

# Copyright and things

The HP script is owned by HP.  It comes with the "HP Lights-Out XML PERL
Scripting Sample for Linux" and is generally freely available.  You can get a
new version here

    http://h20564.www2.hpe.com/hpsc/swd/public/detail?swItemId=MTX_11193baaa82348e993033ccc77

But HPE tends to move files around so I don't know how long that url will
last, you might be better off google searching for it.


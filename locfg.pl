#!/usr/bin/perl

###########################################################################
##
## Simplified perl version of HPQLOCFG
## Version 4.50
##
## (C) Copyright 2015 Hewlett Packard Development Company, L.P.
##
## To use this program, you may need to install the following Perl modules
##       Net::SSLeay
##       IO::Socket::SSL
##       Term::ReadKey
## You may obtain these modules from http://www.cpan.org/
##
## You may use and modify this program to suit your needs.
##
## Perl version 5.14.0 or later is required for "getaddrinfo" support.
##
###########################################################################

use Socket;
use Socket6;
use Sys::Hostname;
use IO::Socket::SSL qw(SSL_VERIFY_NONE);
#$IO::Socket::SSL::DEBUG=2;
use Getopt::Long;
use Config;
#use HTTP::Request::Common;
use Term::ReadKey;         #needed if use ReadMode()

STDOUT->autoflush(1);      # Flush printf output

$Net::SSLeay::slowly = 5; # Add sleep so broken servers can keep up

###########################################################################
##
##                       MAIN PROGRAM STARTS HERE
##
###########################################################################


use constant VERSION => "4.50";     #program version, sent with HTTP headers
use constant RETRY_TIMEOUT => 20;   #retry up to 20s if RIBCL parse is busy
use constant RETRY_DELAY => 2;      #delay 2s between the retries

my ($socket,
    $server, $logfile, $infile, $help, $uname, $pword, $ilo2, $ilo3,
    $verbose, $interactive,
    $firmware, $firmwarelen, $firmwarebuf,
    $cookie,
    $ln, $response, $RIBCLbusy, $retry,
    $ConnectionErrorMessage,
    %valuepair,
    $sslver,
);
$cookie = "";
$RIBCLbusy = 0; $retry = 0;
$verbose = 0;
$response = "";
$ConnectionErrorMessage = "ERROR: SSL connection error.\r\n";

my $retstat = 0;

#--------------------------------------------------------------------------
# Get and check command options
#--------------------------------------------------------------------------

my $r = GetOptions("server|s=s" => \$server,
                   "logfile|l=s" => \$logfile,
                   "input|f=s" => \$infile,
                   "var|t=s" => sub {
                                    if (defined $rawvarvalues) {
                                       print "\nError: -t can be specified only once.\n\n";
                                       exit 1;
                                    } else {
                                       $rawvarvalues = $_[1];
                                    }
                                },
                   "u=s" => \$uname,
                   "p=s" => \$pword,
                   "interactive|i" => \$interactive,
                   "verbose|v" => \$verbose,
                   "help|?" => \$help,
                   "ilo2" => \$ilo2,
                   "ilo3" => \$ilo3,
                   "ilo4" => \$ilo3,
                   "sslproto=s" => \$sslver,
                   );

#print "GetOptions returns = $r\n";

if (!$r) {
   # Unknown or ambiguous option(s)
   exit 1;
}

if ($help || !$server || !$infile) {
    usage();
}

if ($interactive) {
    $OSType= "$Config{osname}\n";
    print "Enter the username: ";
    chomp ($uname = <STDIN>);
	
    print "Enter the password: ";
    #$pword = prompt "enter password: ", -echo=>"*";
    chomp($pword);
	
    if($OSType="MSWin32")
    {
        use Term::ReadKey;
	ReadMode('noecho');                #turn echo off, need Term::ReadKey
    }
    else
    {
        system("stty -echo") ;            #turn echo off, for UNIX only
    }   
    chomp ($pword = <STDIN>);
	
    print ("\r\n");
    if($OSType="MSWin32")
    {
        use Term::ReadKey;
	ReadMode('normal');				 #turn echo off, need Term::ReadKey
    }
    else
    {
        system("stty echo");               #turn echo on, for UNIX only
    } 
        #turn echo on
}

# Username and Password must be entered together
if( ($uname && !($pword)) || (!($uname) && $pword) ) {
    usage_err();
}

if ($ilo2 && $ilo3) {
    usage_err1();
}

if ($logfile) {
    # If a logfile is specified, open it and select it as the default
    # filehandle
    open(L, ">$logfile") || die "ERROR: Can't create logfile \"$logfile\"\n\n";
    select(L);
}

%valuepair = ();
# print "----- $rawvarvalues \n" if ($verbose);
if ($rawvarvalues) {
   # parse rawvarvalues and stores them in %valuepair hash
   $rawvarvalues =~ s/,(\w+=)/0x01\1/g;                 # subsitute delimiters ',' with 0x01.
   my @varvalues = split(/0x01/, $rawvarvalues);
   # print "----- @varvalues\n" if ($verbose);
   for my $onepair (@varvalues) {
      my ($name, $value) = split(/=(.*){1}/, $onepair); #only split into two sub-strings
      $valuepair{$name} = $value;
   }
   if (keys(%valuepair) > 0) {
      for my $key (keys %valuepair) {
          my $value = $valuepair{$key};
          print "----- process_variable_substitution $key => $value\n" if ($verbose);
      }
   }
}

#--------------------------------------------------------------------------
# Open Input File
#--------------------------------------------------------------------------

open(IN, "<$infile") || die "ERROR: Can't open input file \"$infile\"\n\n";
my $filesize = -s $infile;
print "\n----- Size of $infile is $filesize\n" if ($verbose);

if ($ilo3) {
    # Size must be <= 10239 bytes for HTTP POST request
    if ($filesize >= 10240) {
        print "ERROR: Size of $infile ($filesize bytes) is greater than 10239.\n\n";
        exit 1;
    }
}

#--------------------------------------------------------------------------
# Set the default SSL port number if no port is specified
#--------------------------------------------------------------------------

my $port = "443";
my $temp = $server;

$sslver ||= "TLSv1";

if ($temp =~ m/\[(.*?)\]/)
{
    $server = $1;
    if ($temp =~ m/\]:/)  
    {
        $port = $';
    }
}
elsif(!($server =~ m/\[(.*?)\]/))
{
    if (!($server =~ /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/) && $server =~ m/\:/)
    {
        $port = $';
        $server = $`;
    }
}
else
{
    print "Invalid Argument";
    usage();
    exit 1;
}

#It is checking whether the server is valid DNS,ipV4 address and ipV6 address
if (($server =~  /^[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)?$/)
|| ($server =~  /^[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)?(\.[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)?$/)
|| ($server=~ /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/)
|| ($server =~ /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/))
{
    print "Valid IP Address \n\n" if ($verbose);
}
else
{
    print "Invalid IP Address $server \n\n";
    exit 1;
}

if ($port =~ /^(6553[0-5]|655[0-2][0-9]\d|65[0-4](\d){2}|6[0-4](\d){3}|[1-5]\d{4}|[1-9]\d{0,3})$/)
{
   print "Valid Port Number \n\n" if ($verbose);
}
else
{
   print "Invalid Port Number \n\n";
   exit 1;
}


my $localhost = hostname() || 'localhost';
print "\n----- Localhost name is \"$localhost\".\n" if ($verbose);

#--------------------------------------------------------------------------
# Detect iLO version (iLO2 or iLO3 (iLO4 is same as iLO3)) if not specified
#--------------------------------------------------------------------------

if (!$ilo2 && !$ilo3) {
    my ($sec,$min,$hour) = localtime(time);
    print "\n----- Start detecting iLO2/iLO3/iLO4 at $hour:$min:$sec\n" if ($verbose);

    @res = getaddrinfo($server,$port,AF_UNSPEC,SOCK_STREAM);
    while (scalar(@res) >= 5){
        ($family,$socktype,$proto,$saddr,$canonname,@res) = @res;
        socket($socket,$family,$socktype,$proto) || next;
        connect($socket,$saddr) || next;
    }
    
    if ($socket)
    {
        IO::Socket::SSL->start_SSL($socket, SSL_version => $sslver, SSL_verify_mode => SSL_VERIFY_NONE ) || die "Error: Failed to establish SSL connection with $server $@.\n\n";
    }
    else
    {
        print "Error : Failed to establish TCP connection with $server\n\n";
        exit 1;
    } 

    print $socket 'POST /ribcl HTTP/1.1' . "\r\n";
    print $socket "HOST: $localhost" . "\r\n";      # Mandatory for http 1.1
    print $socket "User-Agent: locfg-Perl-script/".VERSION."\r\n";
    print $socket "Content-length: 30" . "\r\n";    # Mandatory for http 1.1
    print $socket 'Connection: Close' . "\r\n";     # Required
    print $socket "\r\n";                           # End of http header
    #print $socket "\r\n";
    print $socket "<RIBCL VERSION=\"2.0\"></RIBCL>\r\n"; # Used by Content-length
    $ln=<$socket>;    # Read first line of response
    if ($ln =~ m/HTTP.1.1 200 OK/) {
        print "\n----- Found iLO3 or iLO4\n" if ($verbose);
        $ilo3 = 1;                                  # It is iLO 3
    }
    else {
        print "\n----- Found iLO2 or iLO\n" if ($verbose);
        $ilo2 = 1;
    }

    while($ln=<$socket> && length($ln)!=0) {};         # Empty response buffer
    $socket->close();

    ($sec,$min,$hour) = localtime(time);
    print "\n----- Finish detecting iLO2/iLO3/iLO4 at $hour:$min:$sec\n" if ($verbose);
}

#--------------------------------------------------------------------------
# Open the SSL connection
#--------------------------------------------------------------------------

    @res = getaddrinfo($server,$port,AF_UNSPEC,SOCK_STREAM);
    while (scalar(@res) >= 5){
        ($family,$socktype,$proto,$saddr,$canonname,@res) = @res;
        socket($socket,$family,$socktype,$proto) || next;
        connect($socket,$saddr) || next;
    }

    if ($socket)
    {
        IO::Socket::SSL->start_SSL($socket, SSL_version => $sslver, SSL_verify_mode => SSL_VERIFY_NONE ) || die "Error: Failed to establish SSL connection with $server $@.\n\n";
    }
    else
    {
        print "Error : Failed to establish TCP connection with $server\n\n";
        exit 1;
    }

print "\n----- Cipher '" . $socket->get_cipher() . "'\n" if ($verbose);

#--------------------------------------------------------------------------
# iLO 2
#--------------------------------------------------------------------------
if ($ilo2) {
    # Send the XML header and begin processing the file
    print "\n----- Connected to iLO 2\n\n" if ($verbose);
    print $socket '<?xml version="1.0"?>' . "\r\n";

    while($ln=<IN>) {

        do_variable_substitutions($ln);

        # Chomp off any EOL characters
        $ln =~ s/\r|\n//g;

        # Find LOGIN tag.
        if ((($ln =~ /<[ \t]*LOGIN[ \t]/) || ($ln =~ /<[ \t]*LOGIN$/)) && ($pword) && ($uname)) {

            while( !($ln =~ m/\>/i) ) { #seek the end of LOGIN tag
              $ln = <IN>;
            }

            print $socket "<LOGIN USER_LOGIN=\"$uname\" PASSWORD=\"$pword\">\r\n";
            print "\n<LOGIN USER_LOGIN=\"$uname\" PASSWORD=\"$pword\">\n" if ($verbose);
            # print "\nOverriding credentials in scripts with those from command line.\n" if ($verbose);
            next;
        }

        #------------------------------------------------------------------
        # Special case: UPDATE_RIB_FIRMWARE violates XML.  Send the full
        # UPDATE firmware tag followed by the binary firmware image
        #------------------------------------------------------------------
        if ($ln =~ m/UPDATE_RIB_FIRMWARE/i) {
            if ($ln =~ m/IMAGE_LOCATION=\"(.*)\"/i) {
                $firmware = $1;
                open(FW, "<$firmware") || die "ERROR: Can't open $firmware\n\n";
				#Binary files need to treated differently than text files on some operating systems (eg, Windows). 
				binmode FW;
                $firmwarelen = (stat(FW))[7];
                print $socket "\r\n<UPDATE_RIB_FIRMWARE IMAGE_LOCATION=\"$firmware\" IMAGE_LENGTH=\"$firmwarelen\"/>\r\n";
                print "\r\n<UPDATE_RIB_FIRMWARE IMAGE_LOCATION=\"$firmware\" IMAGE_LENGTH=\"$firmwarelen\"/>\r\n" if ($verbose);
                my $x = read(FW, $firmwarebuf, $firmwarelen);
                print "Read $x bytes from $firmware\n" if ($verbose);
                $x = $socket->write($firmwarebuf, $x);
                print "Wrote $x bytes\n" if ($verbose);
                close(FW);
                next;
            }
            # print "\nERROR: syntax error detected in $ln\n" if ($verbose);
        }#end of firmware update

        # Send the script to the iLO board
        print $ln . "\n" if ($verbose);
        print $socket $ln . "\r\n" ;
    }

    close(IN);

    print "----\n" if ($verbose);

    #----------------------------------------------------------------------
    # Ok, now read the responses from iLO
    #----------------------------------------------------------------------
    while($ln=<$socket>) {
        last if (length($ln) == 0);

        # This isn't really required, but it makes the output look nicer
        $ln =~ s/<\/RIBCL>/<\/RIBCL>\n/g;
        print $ln;
    }
    $socket->close();

    # All done
    exit 0;

}#end of iLO 2

#--------------------------------------------------------------------------
# iLO 3 or iLO 4
#--------------------------------------------------------------------------

print "\n----- Connected to iLO 3 or iLO 4\n\n" if ($verbose);

my $updateribfwcmd = 0;
my $boundary;
my $sendsize;

send_or_calculate(0);                                    # Calculate $sendsize

if ($updateribfwcmd) { # it's a firmware update
    
    #upload firmware image using multipart post
    my ($body1, $body1size,                                 # multipart body
        $body2, $body2size,                                 # multipart body
        $body3, $body3size,                                 # multipart body
        $sendsize_saved,
    );

    $sendsize_saved = $sendsize;

    $body1 = "--$boundary\r\n" .
             "Content-Disposition: form-data; name=\"fileType\"\r\n" . 
             "\r\n";
    $body1size = length($body1);
    $body2 = "\r\n--$boundary\r\n" .
             "Content-Disposition: form-data; name=\"fwimgfile\"; filename=\"$firmware\"\r\n" .
             "Content-Type: application/octet-stream\r\n" .
             "\r\n";
    $body2size = length($body2) + $firmwarelen;
    $body3 = "\r\n--$boundary--\r\n";                    # last boundary
    $body3size = length($body3);

    $sendsize=$body1size+$body2size+$body3size;

    send_to_client(0, "POST /cgi-bin/uploadRibclFiles HTTP/1.1\r\n");
    send_to_client(0, "HOST: $localhost\r\n");           # Mandatory for http 1.1
    send_to_client(0, "User-Agent: locfg-Perl-script/".VERSION."\r\n");
    send_to_client(0, "TE: chunked\r\n");
    send_to_client(0, "Connection: close\r\n");          # Required
    #send_to_client(0, "Connection: keep-alive\r\n");          # Required
    send_to_client(0, "Content-Length: $sendsize\r\n");
    send_to_client(0, "Content-Type: multipart/form-data; boundary=$boundary\r\n");
    send_to_client(0, "\r\n");                           # End of request header 

    send_to_client(1, $body1);

    send_to_client(1, $body2);
    # Send firmware
    my $sentbytes = 0;
    #$sentblocksize = 1024*1024;
    my $sentblocksize = 4*1024;
    if ($firmwarelen > (15*1024*1024)) {
        printf "\nStart sending iLO 4 firmware (size: $firmwarelen bytes).\n";
    } else {
       printf "\nStart sending firmware (size: $firmwarelen bytes).\n";
    }
    while ($sentbytes < $firmwarelen) {
       if (($firmwarelen - $sentbytes) >= $sentblocksize) {
           send_to_client(1, substr($firmwarebuf, $sentbytes, $sentblocksize));
           $sentbytes += $sentblocksize;
       }
       else {
           send_to_client(1, substr ($firmwarebuf, $sentbytes));
           $sentbytes += $firmwarelen - $sentbytes;           # done
       }
       printf "\r%10u bytes of firmware sent. (%3.2f%%)", $sentbytes, $sentbytes*100/$firmwarelen;
    }
    printf "\n\n";
    #send_to_client(1, $firmwarebuf);                    # send firmware
    #print "Wrote ". length($firmwarebuf) . " bytes of firmware.\n" if ($verbose);

    send_to_client(1, $body3);                    # last boundary

    if ($sendsize) {                              # should be zero
       print "Warning: Remaining sendsize = $sendsize\n";
    }
    while ($sendsize > 0) {
      print $socket " "; 
      print "~" if ($verbose);
      $sendsize--;
    }
    print "----- Responses -----\n" if ($verbose);

    $cookie = "";
    while($ln=<$socket>) {                        # Empty responses
        last if (length($ln) == 0);
        if ($ln =~ m/^Set-Cookie: *RibclFlash=/i) {
            $cookie = $ln;
            $cookie =~ s/^Set-//;
            print "Found cookie = $cookie" if ($verbose);
        }
        print "----- $ln" if ($verbose);
    }
    print "\n----- End of responses -----\n" if ($verbose);
    $socket->close();
    $sendsize = $sendsize_saved;
}# end if

# Send XML script

my ($start_time, $end_time);
$RIBCLbusy = 0;
$retry = 0;
$start_time = 0;
$end_time = 0;
$response = "";

while (!$retry || $RIBCLbusy) {
    @res = getaddrinfo($server,$port,AF_UNSPEC,SOCK_STREAM);

    while (scalar(@res) >= 5){
        ($family,$socktype,$proto,$saddr,$canonname,@res) = @res;
        socket($socket,$family,$socktype,$proto) || next;
        connect($socket,$saddr) || next;
    }

    if ($socket)
    {
        IO::Socket::SSL->start_SSL($socket,SSL_version => $sslver, SSL_verify_mode => SSL_VERIFY_NONE ) || die "Error: Failed to establish SSL connection with $server $@.\n\n";
    }
    else
    {
        print "Error : Failed to establish TCP connection with $server\n\n";
        exit 1;
    }

    if ($retry == 1) { # 1st retry
        my ($sec,$min) = localtime(time);
        $start_time = $min * 60 + $sec;
    }
    if ($retry > 1) {
        my ($sec,$min) = localtime(time);
        $end_time = $min * 60 + $sec;
        if ($end_time-$start_time > RETRY_TIMEOUT) {     # retry upto RETRY_TIMEOUT seconds
            print "\n----- Retry timed out. Script sent unsuccessfully.\n" if ($verbose);
            last;
        }
    }
    if ($retry) {
        print "\n----- iLO is busy. Resending the script... (Attempt #$retry)\n" if ($verbose);
        sleep(RETRY_DELAY);  # delay RETRY_DELAY seconds 
    }


    # Send the HTTP header and begin processing the file
    send_to_client(0, "POST /ribcl HTTP/1.1\r\n");
    send_to_client(0, "HOST: $localhost\r\n");           # Mandatory for http 1.1
    send_to_client(0, "User-Agent: locfg-Perl-script/".VERSION."\r\n");
    send_to_client(0, "TE: chunked\r\n");
    if ($cookie) {
        send_to_client(0, $cookie);
        $cookie = "";
    }
    send_to_client(0, "Connection: Close\r\n");          # Required
    send_to_client(0, "Content-length: $sendsize\r\n");  # Mandatory for http 1.1
    send_to_client(0, "\r\n");
    send_or_calculate(1);  #Send it to iLO
        
    # Ok, now read the responses from iLO
    print "\n----- Responses -----\n" if ($verbose);
    read_chunked_reply();
    $retry++;

    $socket->close();

} # end while
if ($RIBCLbusy) {
    print $response;
}
close(IN);

# All done
exit 0;

###########################################################################
##                      SUBROUTINES DEFINITIONS
###########################################################################

sub usage
{
    print "\n";
    print "Usage: perl locfg.pl -s server -f inputfile [options]\n";
    print "       perl locfg.pl -s ipV4Address -f inputfile [options]\n";
    print "       perl locfg.pl -s ipV4Address:portNumber -f inputfile [options]\n";
    print "       perl locfg.pl -s ipV6Address -f inputfile [options]\n";
    print "       perl locfg.pl -s [ipV6Address] -f inputfile [options]\n";
    print "       perl locfg.pl -s [ipV6Address]:portNumber -f inputfile [options]\n";
    print "       perl locfg.pl -s DnsName:portnumber -f inputfile [options]\n";
    print "    -l logfile         log file\n";
    print "    -v                 enable verbose mode\n";
    print "    -t                 substitute variables with values specified(ab=xy,c=z)\n";
    print "    -i                 entering username and password interactively\n";
    print "    -u username        username\n";
    print "    -p password        password\n";
    print "    -ilo2|-ilo3|-ilo4  target is iLO 2, iLO 3 or iLO 4\n";
    print "\n  Note: Use -u and -p with caution as command line options are\n";
    print "        visible on Linux. The '-i' option is for entering the\n";
    print "        username and password interactively.\n";
    
    exit 1;
}

sub usage_err
{
    print "Note:\n";
    print "  Both username and password must be specified with the -u and -p switches.\n";
    print "  Use -u and -p with caution as command line options are visible on Linux.\n";
    exit 1;
}

sub usage_err1
{
    print "Note:\n";
    print "  Both -ilo2, -ilo3 and -ilo4 can not be specified at same time.\n";
    exit 1;
}

sub send_to_client
{
    print $socket $_[1];
    if ($verbose && length($_[1]) < 1024) { 
        print $_[1]; 
    }
    if ($_[0]) {
        $sendsize -= length($_[1]);
    }
}

sub send_or_calculate    # used for iLO 3 and iLO 4 only
{
  seek(IN, 0, 0);         # Point to begining of the file
  $sendsize = 0;
  while($ln=<IN>) {
    do_variable_substitutions($ln);
    $ln =~ s/\r|\n//g;   # Chomp off any EOL characters

    # Find LOGIN tag.
    if ((($ln =~ /<[ \t]*LOGIN[ \t]/) || ($ln =~ /<[ \t]*LOGIN$/)) && ($pword) && ($uname)) {
       while( !($ln =~ m/\>/i) ) {
          $ln = <IN>;
       }
       $ln="<LOGIN USER_LOGIN=\"$uname\" PASSWORD=\"$pword\">\n";
       $sendsize += length($ln);
       if ($_[0]) {
         print "\n" . $ln if ($verbose);
         print $socket $ln;
       }
       print "\n----- Overriding credentials in scripts with those from command line.\n\n" if ($verbose);
       next;
    }

    if ($ln =~ m/UPDATE_RIB_FIRMWARE/i) {
        $updateribfwcmd = 1;
        if ($ln =~ m/IMAGE_LOCATION=\"(.*)\"/i) {
            $firmware = $1;
            if (!($firmware =~ m/\.bin$/i)) {
               die "ERROR: Firmware ($firmware) is not a \".bin\" file\n\n";
            }
            open(FW, "<$firmware") || die "ERROR: Can't open $firmware\n\n";
            binmode FW;       #required by Windows
            $firmwarelen = (stat($firmware))[7];
            $ln="\r\n<UPDATE_RIB_FIRMWARE IMAGE_LOCATION=\"$firmware\" IMAGE_LENGTH=\"$firmwarelen\"/>\r\n";
            $sendsize += length($ln);
            if ($_[0]) {           # Subroutine argument #1
                print "\n----- $ln" if ($verbose);
                print $socket $ln;
            }
            if (! $_[0]) {         # firmware will be sent later
                $firmwarelen = read(FW, $firmwarebuf, $firmwarelen);
                print "----- Read $firmwarelen bytes from $firmware\n\n" if ($verbose);
                # find boundary for multipart form POST
                $boundary = "------hpiLO3t";
                my $randomnumber = int(rand(1000000));
                $boundary .= "$randomnumber" . "z";
                while ($firmwarebuf =~ /$boundary/) {
                   $randomnumber = int(rand(1000000));
                   $boundary .= "$randomnumber" . "z";
                }
                print "----- Boundary for multipart POST is $boundary\n\n" if ($verbose);
            }
            close(FW);
            next;
        }
        # print "\n----- ERROR: syntax error detected in $ln\n" if ($verbose);
    } elsif ($ln =~ m/UPDATE_FIRMWARE/i) {
        $updateribfwcmd = 3;
        if ($ln =~ m/IMAGE_LOCATION=\"(.*)\"/i) {
            $firmware = $1;
            open(FW, "<$firmware") || die "ERROR: Can't open $firmware\n\n";
            binmode FW;       #required by Windows
            $firmwarelen = (stat($firmware))[7];
            $ln="\r\n<UPDATE_FIRMWARE IMAGE_LOCATION=\"$firmware\" IMAGE_LENGTH=\"$firmwarelen\"/>\r\n";
            $sendsize += length($ln);
            if ($_[0]) {           # Subroutine argument #1
                print "\n----- $ln" if ($verbose);
                print $socket $ln;
            }
            if (! $_[0]) {         # firmware will be sent later
                $firmwarelen = read(FW, $firmwarebuf, $firmwarelen);
                print "----- Read $firmwarelen bytes from $firmware\n\n" if ($verbose);
                # find boundary for multipart form POST
                $boundary = "------hpiLO3t";
                my $randomnumber = int(rand(1000000));
                $boundary .= "$randomnumber" . "z";
                while ($firmwarebuf =~ /$boundary/) {
                   $randomnumber = int(rand(1000000));
                   $boundary .= "$randomnumber" . "z";
                }
                print "----- Boundary for multipart POST is $boundary\n\n" if ($verbose);
            }
            close(FW);
            next;
        }
        # print "\n----- ERROR: syntax error detected in $ln\n" if ($verbose);
    } elsif ($ln =~ m/UPDATE_LANG_PACK/i) {
        $updateribfwcmd = 2;
        if ($ln =~ m/IMAGE_LOCATION=\"(.*)\"/i) {
            $firmware = $1;
            if (!($firmware =~ m/\.lpk$/i)) {
               die "ERROR: Firmware ($firmware) is not a \".lpk\" file\n\n";
            }
            open(FW, "<$firmware") || die "ERROR: Can't open $firmware\n\n";
            binmode FW;       #required by Windows
            $firmwarelen = (stat($firmware))[7];
            print "----- Firmware Length $firmwarelen\n\n" if ($verbose);
            $ln="\r\n<UPDATE_LANG_PACK IMAGE_LOCATION=\"$firmware\" IMAGE_LENGTH=\"$firmwarelen\"/>\r\n";
            $sendsize += length($ln);
            if ($_[0]) {           # Subroutine argument #1
                print "\n----- $ln" if ($verbose);
                print $socket $ln;
            }
            if (! $_[0]) {         # firmware will be sent later
                $firmwarelen = read(FW, $firmwarebuf, $firmwarelen);
                print "----- Read $firmwarelen bytes from $firmware\n\n" if ($verbose);
                # find boundary for multipart form POST
                $boundary = "------hpiLOt";
                my $randomnumber = int(rand(1000000));
                $boundary .= "$randomnumber" . "z";
                while ($firmwarebuf =~ /$boundary/) {
                   $randomnumber = int(rand(1000000));
                   $boundary .= "$randomnumber" . "z";
                }
                print "----- Boundary for multipart POST is $boundary\n\n" if ($verbose);
            }
            close(FW);
            next;
        }
        # print "\n----- ERROR: syntax error detected in $ln\n" if ($verbose);
    }
    
    # Send the script to the iLO board
    if ($_[0]) {                   # Subroutine argument #1
      print $ln . "\n" if ($verbose);
      print $socket $ln . "\r\n" ;
    }
    $sendsize += length($ln) + 2;
  }
}


sub read_chunked_reply    # used for iLO 3 and iLO 4 only
{
  my $hide=1;
  my $isSizeOfChunk=1;
  my $chunkSize;
  my $cache = 1;

  $response = "";
  $RIBCLbusy = 0;

  while(1) {
    $ln=<$socket>;
    if (length($ln) == 0) {
        print "----- read_chunked_reply: read a zero-length line. Continue...\n" if ($verbose);
        last;
    }
    if ($hide) {
        # Skip HTTP response headers and "\r\n"s preceding chunked responses
        if (length($ln) <= 2) {
            $hide=0;
        }
        #print $ln;                      #Print HTTP headers
    }
    else {
        # Process chunked responses
        if ($isSizeOfChunk) {
            chomp($ln);
            $ln =~ s/\r|\n//g;           # clean $ln up
            $chunkSize=hex($ln);
            $isSizeOfChunk=0;
            #print $ln;                  #Print size of chunk
            next;
        }
        if ($chunkSize == 0) {           #End of responses; Empty responses
			
			if (($retstat == "0000") || ($retstat == "003C")) {
				print "...Script Succeeded...\n";
			}
			else  {			
				print "...Script Failed...\n";
			}
	        print "----- read_chunked_reply: reach end of responses.\n" if ($verbose);
            last;
        }
        if ($chunkSize == length($ln)) {
            $isSizeOfChunk=1;
            $hide=1;                     #End of chunk; Skip next line
        }
        else {
            if ($chunkSize > length($ln)) {
                $chunkSize -= length($ln);
                #$ln = substr($ln,0,length($ln));
            }
            else {
                $isSizeOfChunk=1;        #Next line is size of next chunk
                $ln = substr($ln,0,$chunkSize);
            }
        }

        #now, print or cache the response
        if ($cache && $ln =~ m/MESSAGE/i) {
            if ($ln =~ m/RIBCL parser is busy/i) {
                $RIBCLbusy = 1;
            }
            else {
                $cache = 0;
                print $response;
                $response = "";
            }
        }
        if ($cache) {
            # This isn't really required, but it makes the output look nicer
            $ln =~ s/<\/RIBCL>/<\/RIBCL>\n/g;
            $response = $response.$ln;
        }
        else {
            # This isn't really required, but it makes the output look nicer
            $ln =~ s/<\/RIBCL>/<\/RIBCL>\n/g;
            print $ln;
			if ($ln =~ m/STATUS="0x/i) {             
				$retstat = substr($ln,index($ln,"x")+1,4); 
			}
        }
    }
  }

  if (!$RIBCLbusy && $cache) {
      # no "MESSAGE" attribute encountered
      print $response;
      $response = "";
  }

  if ($socket->error()) {
     print "Error: connection error " . $socket->error() . "\n";
  }
}
sub do_variable_substitutions
{
   if (keys(%valuepair) > 0) {
      for my $key (keys %valuepair) {
          my $value = $valuepair{$key};
          # print "process_variable_substitution $key => $value\n";
          $_[0] =~ s/\%$key\%/$value/g;
      }
   }
   # print "----- $_[0]\n" if ($verbose);
}

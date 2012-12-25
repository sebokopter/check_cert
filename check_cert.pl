#!/usr/bin/perl

=head1 NAME

check_cert.pl - A nagios plug-in to check the remaining days for the given cert.

=head1 SYNOPSIS

check_cert.pl -w 14 -c 7 -u mail.example.com:143 -proto imap -starttls

check_cert.pl --warn 7 --critical 2 --url web.example.org:443

=head1 DESCRIPTION

=head1 REQUIREMENTS
Nagios
and 
the following perl modules are required:
- Getopt::Long
- Date::Language
- Time::Piece
- URI

=head1 CAVEATS

Currently only checks for none file URL.

More protocols!1!11!

=head1 BUGS

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT

=head1 AVAILABILITY

=head1 AUTHOR

Sebastian Heil <sebi@wh-netz.de>

=head1 SEE ALSO

=cut

use strict;
use warnings;
use Getopt::Long;

# to use the german date output of a certificate
use Date::Language;
# make localtime creating date-objects
use Time::Piece;
# to break down the URL
use URI;
# use nagios' error codes
use lib '/usr/lib/nagios/plugins';
use utils qw(%ERRORS);

sub usage {
  my %params = @_;
 
  print STDERR <<HERE;
Usage $0 --warn|-w <days> --critical|-c <days> --url|-u <url> [--proto|-p <protocol>] [--lang|-l <lang>] [--starttls|-s] [--help|-h|-?]

--warn|-w number of days before certification expiration to
return a warning status

--critical|-c number of days before certificate expiration to
return a critical status

--url|-u URL to check

--proto|-p Which protocol to check

--lang|-l What Language has the date in the certificate

--starttls|-s Use STARTTLS

--help|-h|-? display this message

HERE

  if(defined($params{'message'})) {
    my $message = $params{'message'};
    print STDERR $message,"\n";
  }
 
  exit($ERRORS{'UNKNOWN'});
}

my %opt;
GetOptions(\%opt,'warn|w=i','critical|c=i','url|u=s','proto|p=s','lang|l=s','starttls|s','help|h|?');

# promt the usage text if help is wanted
if (defined($opt{'help'})) {
  usage();
} else {
  # check for required options
  foreach my $option (qw{warn critical url}) {
    if (!defined($opt{$option})) {
      usage(message => "Usage error: --$option requried");
    }
  }
  # check for valid lang arguments
  if (defined($opt{'lang'})) {
    my @availableLanguages = qw{de fr en};
    my $found = 0;
    foreach my $availableLanguage (@availableLanguages) {
      print $availableLanguage."\n";
      $found=1 if ($opt{'lang'} eq $availableLanguage);
    }
    if ($found==0) {
      usage(message => "Usage error: --lang requires one of the available Languages: @{availableLanguages}");
    }
  }
  # check for valid proto arguments
  if (defined($opt{'proto'})) {
    my @availableProtocols = qw{http smtp imap};
	my $found = 0;
    foreach my $availableProtocol (@availableProtocols) {
      $found = 1 if($opt{'proto'} eq $availableProtocol);
    }
    if ($found==0) {
      usage(message => "Usage error: --proto requires one of the available Protocols: @availableProtocols" );
    }
  }
}

my $warn = $opt{'warn'};
my $critical = $opt{'critical'};

my $lang = $opt{'lang'} ||= 'de';

# create date object
my $date;
if ($lang eq 'de') {
  $date = Date::Language->new('German');
} elsif ($lang eq 'fr') {
  $date = Date::Language->new('French');
} elsif ($lang eq 'en') {
  $date = Date::Language->new('English');
}

my $proto = $opt{'proto'} ||= 'http';
my $sproto = $proto."s";
my $uri = URI->new("${sproto}://${opt{'url'}}");
if (!defined($uri->authority)) {
  usage(message => 'invalid URL');
}
if (!defined($uri->port)) {
  $uri->authority("$uri->authority:443");
}

my $url = $uri->authority;

my $clientArgs = $url;
if (defined($opt{'starttls'})) {
  $clientArgs = "$clientArgs -starttls $proto";
}

# QUIT exits the openssl s_client regardless of the protocol
if (system("echo QUIT | openssl s_client -connect $clientArgs >/dev/null 2>&1") != 0) {
  print "URL doesn\'t provide a certificate\n";
  exit $ERRORS{'UNKNOWN'};
}
my $enddate=scalar(`echo QUIT | openssl s_client -connect $clientArgs 2>/dev/null| openssl x509 -noout -enddate`);
$enddate=~s/notAfter=(.*)/$1/;
$enddate=$date->str2time($enddate);

my $date1 = localtime($enddate);
my $date2 = localtime(time);
my $diff = $date1 - $date2;
my $daysLeft = int($diff->days);

if ($warn < $daysLeft and $critical < $daysLeft) {
  print "CERTIFICATE OK - Certificate expires in ".$daysLeft." Days.\n";
  exit($ERRORS{'OK'});
} elsif ($warn >= $daysLeft and $critical < $daysLeft) {
  print "CERTIFICATE WARNING - Certificate expires in ".int($diff->days)." Days.\n";
  exit($ERRORS{'WARNING'});
} elsif ($critical >= $daysLeft) {
  print "CERTIFICATE CRITICAL - Certificate expires in ".int($diff->days)." Days.\n";
  exit($ERRORS{'CRITICAL'});
} else {
  print "CERTIFICATE UNKOWN - Certificate expires in ".int($diff->days)." Days.\n";
  exit($ERRORS{'UNKNOWN'});
}

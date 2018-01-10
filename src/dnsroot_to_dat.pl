#! /usr/bin/perl -w

# 2325, Tue, 1 Nov 05 (PST)
#
# Nevil Brownlee, CAIDA || The University of Auckland

# Sample program to extract data from CAIDA DNS root/gTLD 
#    flow data files.  Intended to document the way the 
#    files are put together, rather than to be directly
#    useful for any particular purpose.  Use it as a
#    starting point to convert a days data into the
#    format you need ...

# Command line: 
#   ./dnsroot_to_dat.pl  fromfile.dif  tofile.dif


use strict;
$^W = 1;  # Warnings on

my %month = (  # Used in get_time()
   "Jan" =>  1, "Feb" =>  2, "Mar" =>  3, "Apr" =>  4,
   "May" =>  5, "Jun" =>  6, "Jul" =>  7, "Aug" =>  8,
   "Sep" =>  9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
   );

my ($from_file, $to_file);

$from_file = shift;  # First item from command line
if (defined($from_file)) {
   open(FROM, $from_file)
   or die "Can't open from_file: $!\n";
   }
else { printf "No from_file specified!\n"; }
 

# A new file to store RTT values
open(RTT, ">rtt.py");


$to_file = shift;  # Second item from command line
if (defined($to_file)) {
   open(TO, ">$to_file")
   or die "Can't open to_file: $!\n";
   }
else { printf "No to_file specified!\n"; }


my %format;        # Attribute names from #Format record
my $n_attributes;  # Number of items in the format 
#                      (we know that d_turnaroundtime is the last one)
my $srv_idx;       # Index in data records, values 1=A, 2=B, .. 13=M
my $srv_typex;     # Index in data records, values 1=root, 2=gTLD


my $t;             # Reading time (from last #Time record)
while (<FROM>) { # Read .dif file
   chop;    # trim new line
   my $rec = $_;
   if (/^#/) { # starts with a #
      if ($rec =~s/^#Time: //) {
         $t = get_time($rec);
	 } 
      elsif ($rec =~ s/^#EndData: //) {
         }
      elsif ($rec =~ s/^#Format: //) {
            # We know #Format appears before any data
         unpack_format($rec);
         print "type ix = $srv_typex, id ix = $srv_idx," .
            " n_attribs = $n_attributes\n";
         }

      next;
      }  # End of # record handling

   my @flow = split(/ +/, $rec, $n_attributes-1);
   $rec =~ /\((.+)\)/;  # Pull out distribution data from ()

# Distribution layout:
#   0  type     5 = dynamic (actual values), 6 = binned (linear scale)
#   1  scale   (actual, upper/lower limit) * 10**scale 
#                 give real RTT values in microseconds
#   2  lower limit
#   3  upper limit
#   4  nv       type 5: nv=number of values
#               type 6: nv=number of bins, overflow bin not included
#                       Note: bin counts are *not* scaled
#   5  11       distribution is for DNS rtt
#   6  0
#   7  0
#   8 to 8+(nv-1) values (actual or count for bin)
#   8+nv        count for overflow bin

   print TO "$t  $flow[$srv_typex] $flow[$srv_idx]  $1\n";
# Output records:  time, root/gTLD, server_id,  distrib values (as above)

   display_distrib($1);  # See listing for info on how to unpack the data

   #if ($. == 20) { exit; }
   }

exit;


sub unpack_format{  # Format record => $n_attributes, %format, etc.
   my ($rec) = @_;

   my @fmt = split(/ +/, $rec);
   $n_attributes = scalar(@fmt);
   for (my $j = 0; $j != scalar(@fmt); ++$j) {
      $format{$fmt[$j]} = $j;
      }
   $srv_idx = $format{flowkind};     # 1=A, 2=B, ...
   $srv_typex = $format{flowclass};  # 1=root, 2=gTLD
   }


sub get_time {  # Time record => Unix time (
   my ($rec) = @_;  # Arguments

   if ($rec =~ /(^\d+):(\d+):(\d+) +\w+ +(\d+) +(\w+) +(\d+) +/) {
      #    HH    MM   SS    day    dd    mm     yyyy  >>day not saved<<
      return sprintf("%04d%02d%02d.%02d%02d%02d", 
         $6,$month{$5},$4, $1,$2,$3);  # YYYYmmdd.HHMMSS 
      }
   }


sub display_distrib{  # Print out a distribution

#  This routine demonstrates how to unpack the data.

#  Limits are the same for both distribution types.

#  Binned: counts for each bin (upper edge in nv steps from
#    lower to upper), plus count for oflo (> upper)

#  Dynanmic: data areactual values, in the order they were observed.
#    Note that there is no timestamp data for them, we only know that
#    they arrived in this order during the 5-minute measurement interval.

   my ($distrib) = @_;
   my @dv = split(/ +/, $distrib);

   my $type = $dv[0];
   my $scale = (10**$dv[1])/1000.0;  # ms
   my $lower = $dv[2]*$scale;
   my $upper = $dv[3]*$scale;
   my $nv = $dv[4];
   print "lower=$lower, upper=$upper, nv=$nv";

   # first value/count in $dv[8]

   if ($type == 6) {  # Binned distribution, display counts
      print "  Bin counts:";
      for (my $j = 0; $j != $nv; ++$j) { print " $dv[8+$j]"; }
      print " oflo=$dv[8+$nv]\n"
      }
   else {
      print "  RTT values:";
      for (my $j = 0; $j != $nv; ++$j) {
         my $v = $dv[8+$j]*$scale;
         print " $v";
	 print RTT " $v,";
         }
      print "\n";
      }
   }

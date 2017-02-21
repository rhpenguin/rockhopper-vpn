#! /usr/bin/perl

#
#  Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
#  All rights reserved.
#
#  You can redistribute and/or modify this software under the
#  LESSER GPL version 2.1.
#  See also LICENSE.txt and LICENSE_LGPL2.1.txt.
#

#
# Clean-up Tool for Rockhopper's virtual network interfaces.
#

use strict;

my $ifconfig = "/sbin/ifconfig";
my $tuntap_tool = "/usr/local/sbin/rhp_tuntap_tool";

my @ifconfig_lines = `$ifconfig -a`;

foreach my $ifconfig_line (@ifconfig_lines) {
        
  if ( $ifconfig_line =~ /rhpvif/ ){

    my @vif = split( /\s/, $ifconfig_line );

    print "$tuntap_tool -a delete -i $vif[0]\n";
    system("$tuntap_tool -a delete -i $vif[0]");

    print "Deleted ". $vif[0] . "\n";
  }
}

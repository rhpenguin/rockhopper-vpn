#! /usr/bin/perl

#
#  Copyright (C) 2009-2015 TETSUHARU HANADA <rhpenguine@gmail.com>
#  All rights reserved.
#
#  This library may be distributed, used, and modified under the terms of
#  BSD license:
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
#  3. Neither the name(s) of the above-listed copyright holder(s) nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

#
# Too Simple management tool for Rockhopper.
#

#
# [ Memo ]
#
# Perl API's Info:
#   http://search.cpan.org/~gaas/libwww-perl/
#   http://search.cpan.org/~pajas/XML-LibXML-1.70/
#

use strict;
use warnings;


use threads;
use threads::shared;

use Getopt::Long;

# (Ubuntu 8.x--) NOT need to import libwww-perl by package manager.
use LWP::UserAgent;
use LWP::Authen::Basic;
use HTTP::Request::Common;

# (Ubuntu 8.x--) Need to import libxml-libxml-perl by package manager.
use XML::LibXML;

=comm    
use JSON;
=cut

use Switch;


my $rhp_version = '1.0';

my $action   = $ARGV[0];
my $detail   = 0;
my $show_xml = 0;
my $cache_eap_key = 0;
my %cmd_opts = ();

my $help = 0;
my $no_pager = 0;

GetOptions(
  \%cmd_opts,
  'admin=s',
  'password=s',       
  'port=i',           
  'realm=i',
  'peerid_type=s',    
  'peerid=s',
  'connection_name=s',
  'uid=s',
  'mng_address=s',    
  'mng_address_v6=s',    
  'allowed_address=s',    
  'allowed_address_v6=s',    
  'mng_port=s',
  'admin_id=s',       
  'admin_password=s',
  'file=s',
  'archive_password=s',
  'start_time=s',     
  'elapsing_time=s',
  'key=s',
  'keygen=s',
  'myid_type=s',
  'myid=s',
  'pkcs12_file=s',
  'pem_cert_file=s',
  'pem_priv_key_file=s',
  'pem_file=s',
  'priv_key_password=s',
  'accept_expired_cert=s',
  'eap_method=s',
  'eap_id=s',
  'eap_key=s',
  'no_pager' => \$no_pager,
  'cache_eap_key' => \$cache_eap_key,
  'detail' => \$detail,
  'xml' => \$show_xml,
  'help' => \$help
);


my $IPV4_REGEX 
  = '^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])$';
my $IPV6_REGEX 
  = '^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:)))(%.+)?$';


my $admin    = $cmd_opts{admin};
my $password = $cmd_opts{password};

# Only limited operations are allowed for this user_id.
my $nobody_admin       = 'rhp_mng_cmd_perl';
# Fixed dummy password.
my $nobody_admin_pw    = 'secret'; 

if( defined($action) && (!defined($admin) || !defined($password)) ){

  if( $action eq "connect" ||
      $action eq "disconnect" ||
      $action eq "close" ||
      $action eq "vpn" ||
      $action eq "bridge" ||
      $action eq "arp" ||
      $action eq "neigh" ||
      $action eq "source-if" ||
      $action eq "if" ||
      $action eq "tuntap-if" ||
      $action eq "rt-check" ){
        
    $admin = $nobody_admin;
    $password = $nobody_admin_pw;
  }
}


my $address = "127.0.0.1";
my $port = 32501;
if ( defined($cmd_opts{port}) ) {
  $port = $cmd_opts{port};
}

my $stdout_pipe = undef;

sub open_stdout_pipe {
  if( !defined($stdout_pipe) && !$no_pager ){
    if( !open($stdout_pipe, '|-', 'less') ){
      print "Can't open pipe.\n";
    }
    print $stdout_pipe "\n*Showing information by 'less' command.\nEnter 'q' to quit.\n\n";
  }
}

sub print_stdout {
  if( scalar(@_) && defined($_[0]) ){
    if( defined($stdout_pipe) ){
      print $stdout_pipe $_[0];
    }else{
      print $_[0];
    }  
  }
}

sub close_stdout_pipe {
  if( defined($stdout_pipe) ){
    close($stdout_pipe);  
  }
}


my $realm = $cmd_opts{realm};
if( defined($realm) && $realm !~ /^\d+$/ ) {
  print "Invalid realm number specified: $realm\n";
  exit;
}

my $auth_basic_key = undef;

my $peerid = $cmd_opts{peerid};
my $peerid_type = $cmd_opts{peerid_type};
if( defined($peerid_type) && 
    ( $peerid_type ne 'fqdn' && $peerid_type ne 'email' && $peerid_type ne 'dn' && $peerid_type ne 'eap-mschapv2' ) ){
  print "Invalid peerid_type specified: $peerid_type\n";
  exit;
}

sub enter_password {

  my($label,$retype) = @_;

  print " Enter $label: ";
  system('stty','-echo');
  my $new_password = <STDIN>;
  chomp($new_password);
  system('stty','echo');
  print "\n";

  if( !defined($new_password) || length($new_password) < 1 ){
    return undef;        
  }

  if( $retype ){
  
    print " Retype $label: ";
    system('stty','-echo');
    my $retype_pw = <STDIN>;
    chomp($retype_pw);
    system('stty','echo');
    print "\n";
        
    if( !defined($new_password) || !defined($retype_pw) || 
        length($new_password) < 1 || length($retype_pw) < 1 ||
        $retype_pw ne $new_password ){
  
      return undef;        
    }
  }
  print "\n";
    
  return $new_password;
}

sub print_usage {

  my ($action,$arg0) = @_;

  my $is_help = 0;
  if( defined($action) && $action eq 'help' ){
    $action = $arg0;
    $is_help = 1;
  }

  print_stdout "[ Usage ]\n";
  if( !defined($action) ){
    
    goto gen_error;

  }elsif ( $action eq 'debug' ) {

    print_stdout "% rockhopper <command> ...\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>] [-xml] [-no_pager]\n\n";
    print_stdout " command:\n";
    print_stdout "\n";
    print_stdout "  memory-dbg    Helper to debug memory allocation.\n";
    print_stdout "  bus-read      Reading async messages from Rockhopper process.\n";
    print_stdout "\n";
    print_stdout "\n";

    print_usage('memory-dbg');
    print_usage('bus-read');

  }elsif ( $action eq 'connect' ) {

    print_stdout "% rockhopper connect -realm <realm_no>\n";
    print_stdout " [-peerid_type <fqdn/email/dn> -peerid <peerid>]\n";
    print_stdout " [-connection_name <NULL Authentication's connection name>]\n";
    print_stdout " [-eap_method mschapv2]\n";
    print_stdout " [-eap_id <username/id> -eap_key <passowrd/key>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  }elsif ( $action eq 'disconnect' ) {

    print_stdout "% rockhopper disconnect -realm <realm_no>\n";
    print_stdout " [-peerid_type <fqdn/email/dn> -peerid <peerid>]\n";
    print_stdout " [-connection_name <NULL Authentication's connection name>]\n";
    print_stdout " [-uid <vpn_uid>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'vpn' ) {

    print_stdout "% rockhopper vpn -realm <realm_no>\n";
    print_stdout " [-peerid_type <fqdn/email/dn/eap-mschapv2> -peerid <peerid>]\n";
    print_stdout " [-uid <vpn_uid>] [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'admin' ) {

    if( !$is_help ){
      print_stdout "admin operation(update, delete or show) not specified.\n\n";    
    }
    
    print_stdout "% rockhopper admin <add/update/delete/show>\n";
    print_stdout " [-admin_id <admin_id>] ...\n";
    print_stdout " [-realm <realm_no>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

    print_usage('admin_update');
    print_usage('admin_delete');
    print_usage('admin_show');

  } elsif ( $action eq 'admin_update' ) {

    print_stdout "% rockhopper admin <add/update> -admin_id <admin_id>\n";
    print_stdout " [-admin_password <new_admin_passowrd>] [-realm <new_realm_no>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'admin_delete' ) {

    print_stdout "% rockhopper admin delete -admin_id <admin_id>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'admin_show' ) {

    print_stdout "% rockhopper admin show\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'web-mng' ) {

    print_stdout "% rockhopper web-mng [-mng_address <ipv4>]\n";
    print_stdout " [-mng_address_v6 <ipv6>]\n";
    print_stdout " [-mng_port <listening_port>]\n";
    print_stdout " [-allowed_address <IPv4>/<IPv4/PrefixLength>]\n";
    print_stdout " [-allowed_address_v6 <IPv6>/<IPv6/PrefixLength>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";
    print_stdout "\n";

    print_stdout "* Reset all settings.\n";
    print_stdout "% rockhopper web-mng reset\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'bridge' ) {

    print_stdout "% rockhopper bridge -realm <realm_no> [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'arp' ) {

    print_stdout "% rockhopper arp -realm <realm_no> [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'neigh' ) {

    print_stdout "% rockhopper neigh -realm <realm_no> [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'route' ) {

    print_stdout "% rockhopper route [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'ip-route-table' ) {

    print_stdout "% rockhopper ip-route-table [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'ip-route-cache' ) {

    print_stdout "% rockhopper ip-route-cache [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'nhrp-cache' ) {

    print_stdout "% rockhopper nhrp-cache [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'flush-bridge' ) {

    print_stdout "% rockhopper flush-bridge [-realm <realm_no>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'flush-ip-route-cache' ) {

    print_stdout "% rockhopper flush-ip-route-cache\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'address-pool' ) {

    print_stdout "% rockhopper address-pool -realm <realm_no> [-detail]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";
    print_stdout "\n";

    print_stdout "* Flush cached addresses.\n";
    print_stdout "% rockhopper address-pool flush -realm <realm_no>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'source-if' ) {

    print_stdout "% rockhopper source-if -realm <realm_no>\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'if' ) {

    print_stdout "% rockhopper interface\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'tuntap-if' ) {

    print_stdout "% rockhopper tuntap-if [-realm <realm_no>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'cfg-archive' ) {

    if( !$is_help ){
      print_stdout "cfg-archive operation(save, upload or extract) not specified.\n\n";    
    }
    
    print_stdout "% rockhopper cfg-archive <save/upload/extract> \n";
    print_stdout " [-archive_password <password>] [-file <file_name>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";
  
    print_usage('cfg-archive-save');
    print_usage('cfg-archive-upload');
    print_usage('cfg-archive-extract');
  
  } elsif ( $action eq 'cfg-archive-save' ) {
  
    print_stdout "% rockhopper cfg-archive save\n";
    print_stdout " [-file <output_archive_file>]\n";
    print_stdout " [-archive_password <password>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'cfg-archive-upload' ) {
  
    print_stdout "% rockhopper cfg-archive upload\n";
    print_stdout " -file <saved_archive_file>\n";
    print_stdout " [-archive_password <password>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";
  
  } elsif ( $action eq 'cfg-archive-extract' ) {
  
    print_stdout "% rockhopper cfg-archive extract\n";
    print_stdout " -file <saved_archive_file>\n";
    print_stdout " [-archive_password <password>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'peer-key' ) {

    if( !$is_help ){
      print_stdout "peer-key operation(add, update, delete or show) not specified.\n\n";    
    }
    
    print_stdout "% rockhopper peer-key <add/update/delete/show>\n";
    print_stdout " -realm <realm_no> ...\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

    print_usage('peer-key-update');
    print_usage('peer-key-delete');
    print_usage('peer-key-show');

  } elsif ( $action eq 'peer-key-update' ) {

    print_stdout "% rockhopper peer-key <add/update>\n";
    print_stdout " -realm <realm_no>\n";
    print_stdout " -peerid_type <fqdn/email/any/eap-mschapv2>\n";
    print_stdout " -peerid <peerid>\n";
    print_stdout " [-key <pre_shared_key(PSK)/password>]\n";
    print_stdout " [-keygen <num of characters>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'peer-key-delete' ) {

    print_stdout "% rockhopper peer-key delete -realm <realm_no>\n";
    print_stdout " -peerid_type <fqdn/email/any/eap-mschapv2>\n";
    print_stdout " -peerid <peerid>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'peer-key-show' ) {

    print_stdout "% rockhopper peer-key show [-realm <realm_no>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'my-key' ) {

    if( !$is_help ){
      print_stdout "my-key operation(add, update, delete or show) not specified.\n\n";    
    }
    
    print_stdout "% rockhopper my-key <update/delete/show>\n";
    print_stdout " -realm <realm_no> ...\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

    print_usage('my-key-update');
    print_usage('my-key-delete');
    print_usage('my-key-show');

  } elsif ( $action eq 'my-key-update' ) {

    print_stdout "% rockhopper my-key update -realm <realm_no>\n";
    print_stdout " -myid_type <fqdn/email/eap-mschapv2>\n";
    print_stdout " -myid <myid>\n";
    print_stdout " [-key <pre_shared_key(PSK)/password>]\n";
    print_stdout " [-keygen <num of characters>]\n";
    print_stdout " [-cache_eap_key]";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'my-key-delete' ) {

    print_stdout "% rockhopper my-key delete -realm <realm_no>\n";
    print_stdout " -myid_type <eap-mschapv2>\n";
    print_stdout " [-cache_eap_key]";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'my-key-show' ) {

    print_stdout "% rockhopper my-key show [-realm <realm_no>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'my-cert' ) { 

    if( !$is_help ){
      print_stdout "my-cert operation(update or show) not specified.\n\n";    
    }
    
    print_stdout "% rockhopper my-cert <show/update>\n";
    print_stdout " -realm <realm_no> ...\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

    print_usage('my-cert-show');
    print_usage('my-cert-update-pkcs12');
    print_usage('my-cert-update-pem');

  } elsif ( $action eq 'my-cert-update-pkcs12' ) {

    print_stdout "* PKCS12\n";
    print_stdout "% rockhopper my-cert update -realm <realm_no>\n";
    print_stdout " -pkcs12_file <pkcs12_file>\n";
    print_stdout " [-priv_key_password <password>]\n";
    print_stdout " [-myid_type <dn/san/auto>]\n";
    print_stdout " [-accept_expired_cert <enable/disable>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'my-cert-update-pem' ) {

    print_stdout "* PEM\n";
    print_stdout "% rockhopper my-cert update -realm <realm_no>\n";
    print_stdout " -pem_cert_file <cert_pem_file>\n";
    print_stdout " -pem_priv_key_file <priv_key_pem_file>\n";
    print_stdout " [-priv_key_password <password>]\n";
    print_stdout " [-myid_type <dn/san/auto>]\n";
    print_stdout " [-accept_expired_cert <enable/disable>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'my-cert-show' ) {

    print_stdout "% rockhopper my-cert show -realm <realm_no>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'ca-cert' ) { 

    if( !$is_help ){
      print_stdout "ca-cert operation(update or show) not specified.\n\n";    
    }
    
    print_stdout "% rockhopper ca-cert <show/update>\n";
    print_stdout " -realm <realm_no> ...\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

    print_usage('ca-cert-show');
    print_usage('ca-cert-update-pem');

  } elsif ( $action eq 'ca-cert-update-pem' ) {

    print_stdout "* PEM\n";
    print_stdout "% rockhopper ca-cert update -realm <realm_no>\n";
    print_stdout " -pem_file <cert_pem_file>\n";
    print_stdout " [-accept_expired_cert <enable/disable>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'ca-cert-show' ) {

    print_stdout "% rockhopper ca-cert show -realm <realm_no>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'crl' ) { 

    if( !$is_help ){
      print_stdout "crl operation(update or show) not specified.\n\n";    
    }
    
    print_stdout "% rockhopper crl <show/update>\n";
    print_stdout " -realm <realm_no> ...\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

    print_usage('crl-show');
    print_usage('crl-update-pem');

  } elsif ( $action eq 'crl-update-pem' ) {

    print_stdout "* PEM\n";
    print_stdout "% rockhopper crl update -realm <realm_no>\n";
    print_stdout " -pem_file <crl_pem_file>\n";
    print_stdout " [-accept_expired_cert <enable/disable>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'crl-show' ) {

    print_stdout "% rockhopper crl show -realm <realm_no>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'peer-cert' ) {

    print_stdout "% rockhopper peer-cert -realm <realm_no>\n";
    print_stdout " [-peerid_type <fqdn/email/dn> -peerid <peerid>]\n";
    print_stdout " [-uid <vpn_uid>] [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'show-cfg' ) {

    print_stdout "% rockhopper show-cfg [-realm <realm_no>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'show-realm' ) {

    print_stdout "% rockhopper show-realm [-realm <realm_no>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-detail] [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'realm' ) {

    print_stdout "% rockhopper realm <enable/disable> -realm <realm_no>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'show-global-cfg' ) {

    print_stdout "% rockhopper show-global-cfg\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'clear-all-conn' ) {

    print_stdout "% rockhopper clear-all-conn -realm <realm_no>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'clear-dormant-conn' ) {

    print_stdout "% rockhopper clear-dormant-conn -realm <realm_no>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  }elsif ( $action eq 'rt-check' ) {

    print_stdout "% rockhopper rt-check <restart/show> -realm <realm_no>\n";
    print_stdout " [-peerid_type <fqdn/email/dn> -peerid <peerid>]\n";
    print_stdout " [-uid <vpn_uid>] [-detail]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout " [-no_pager]\n";
    print_stdout "\n";

  } elsif ( $action eq 'clear-eap-key-cache' ) {

    print_stdout "% rockhopper clear-eap-key-cache -realm <realm_no>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'reset-qcd-key' ) {

    print_stdout "% rockhopper reset-qcd-key\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'reset-sess-resume-key' ) {

    print_stdout "% rockhopper reset-sess-resume-key\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'invalidate-sess-resume-tkts' ) {

    print_stdout "% rockhopper invalidate-sess-resume-tkts -realm <realm_no>\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'memory-dbg' ) {

    print_stdout "% rockhopper memory-dbg\n";
    print_stdout " [-elapsing_time <seconds>(> 0)]\n";
    print_stdout " [-start_time <seconds>(> 0)]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } elsif ( $action eq 'bus-read' ) {

    print_stdout "% rockhopper bus-read\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } else {
    
gen_error:

    print_stdout "% rockhopper <command> ...\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>] [-xml] [-no_pager]\n\n";
    print_stdout " command:\n";
    print_stdout "  help <command>  Show help info.\n";
    print_stdout "\n";
    print_stdout "  connect         Connect VPN.\n";
    print_stdout "  disconnect      Disconnect VPN.\n";
    print_stdout "\n";
    print_stdout "  vpn             Show VPN status.\n";
    print_stdout "  bridge          Show internal Bridge(MAC) table.\n";
    print_stdout "  arp             Show internal ARP table.(IPv4)\n";
    print_stdout "  neigh           Show internal Neighbors table.(IPv6)\n";
    print_stdout "  address-pool    Show or flush address-pool. [Remote Cfg Server]\n";
    print_stdout "  source-if       Show source network interface.\n";
    print_stdout "  tuntap-if       Show TUN/TAP interface.\n";
    print_stdout "  if              Show network interface.\n";
    print_stdout "  ip-route-table  Show route tables for IP routing.\n";
    print_stdout "  ip-route-cache  Show route caches for IP routing.\n";
    print_stdout "  route           Show routing table.\n";
    print_stdout "  nhrp-cache      Show NHRP cache (NHS).\n";
    print_stdout "\n";
    print_stdout "  flush-bridge    Flush MAC and ARP/Neigh cache.\n";
    print_stdout "  clear-all-conn  Clear all VPN connections.\n";
    print_stdout "  clear-dormant-conn  Clear all dormant VPN connections.\n";
    print_stdout "  flush-ip-route-cache  Flush route caches for IP routing.\n";
    print_stdout "  rt-check        Start routability check. (MOBIKE Initiator)\n";
    print_stdout "  clear-eap-key-cache Clear cached EAP's password. (EAP Client)\n";
    print_stdout "  reset-qcd-key   Reset IKEv2 QCD key.\n";
    print_stdout "  reset-sess-resume-key Reset IKEv2 Session Resumption keys.\n";
    print_stdout "  invalidate-sess-resume-tkts Invalidate IKEv2 Session Resumption tickets.\n";
    print_stdout "\n";
    print_stdout "  peer-key        Configure remote peer's ID/key.(PSK/EAP)\n";
    print_stdout "  my-key          Configure this node's ID/key.(PSK/EAP)\n";
    print_stdout "  my-cert         Update or show this node's certificate.(RSA-Sig)\n";
    print_stdout "  ca-cert         Update or show CA's certificate.(RSA-Sig)\n";
    print_stdout "  peer-cert       Show remote peer's certificate.(RSA-Sig)\n";
    print_stdout "  crl             Update or show CRL.(RSA-Sig)\n";
    print_stdout "  realm           Enable or disable realm's config.\n";
    print_stdout "  show-realm      Show realm's status summary.\n";
    print_stdout "  show-cfg        Show config. [XML]\n";
    print_stdout "  show-global-cfg Show global config. [XML]\n";
    print_stdout "\n";
    print_stdout "  admin           Configure administrator's ID/key.\n";    
    print_stdout "  web-mng         Configure address/port of Web Management Service.\n";
    print_stdout "  cfg-archive     Save, upload or extract config archive(backup).\n";
    print_stdout "\n";
    print_stdout "% rockhopper <command> -h   Show help info.\n";
    print_stdout "\n";
  }
  
  return;
}

our $EAELM = undef;
sub EAA {

  my ($elm, $attr_name, $defval) = @_;
   
  if( !defined($elm) ){
    $elm = $EAELM;
  }
  my $ret = $elm->getAttribute($attr_name);  
  
  if( !defined($ret) && defined($defval) ){
    return $defval;
  }
  
  return $ret;
}

sub EAD {
  my ($attr_name, $defval) = @_;
  return EAA(undef,$attr_name,$defval);
}

sub EA {
  my ($attr_name) = @_;
  return EAA(undef,$attr_name,undef);
}

sub create_bus_req_doc2 {

  my ( $attr_names_ref, $attr_vals_ref, $root_elm_ref ) = @_;
  
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  for( my $i = 0; $i < @$attr_names_ref; $i++ ){
    
    if( defined($attr_vals_ref->[$i]) ){
      my $attr = $doc->createAttribute( $attr_names_ref->[$i], $attr_vals_ref->[$i] );
      $root->setAttributeNode($attr);
    }
  }
  
  if( defined($root_elm_ref) ){
    $$root_elm_ref = $root;
  }

  return $doc;  
}

sub create_bus_req_doc {
  my ( $attr_names_ref, $attr_vals_ref ) = @_;
  return create_bus_req_doc2($attr_names_ref, $attr_vals_ref,undef);
}

sub create_bus_write_req {

  my ($bus_session_id) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $bus_session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  
  if( $show_xml ){
    print_stdout "create_bus_write_req: \n" . $req->as_string() . "\n";
  }
  
  return $req;
}


sub need_admin_password()
{
  my $retries = 0;
  my $resp = undef;

  while( 1 ){
    
    if ( !defined($admin) || !defined($password) ) {
  
      print " Admin Name: ";
      if( defined($admin) ){
        print $admin . "\n";
      }else{
        $admin = <STDIN>;
        chomp($admin);
      }
            
      print " Password: ";
      system('stty','-echo');
      $password = <STDIN>;
      chomp($password);
      system('stty','echo');
      print "\n";
    }

    if( !defined($admin) || !defined($password) || 
         length($admin) < 1 || length($password) < 1 ){        
  
      $retries++;
  
      next;
    }
  
    $auth_basic_key = LWP::Authen::Basic->auth_header( $admin, $password );
           
    my $ua = LWP::UserAgent->new();
  
    my $url = 'http://' . $address . ':' . $port . '/protected/authentication';
    my $req = HTTP::Request->new( PUT => $url );
    
    $req->header( "Accept"         => 'text/xml' );
    $req->header( "Accept-Charset" => 'utf-8' );
    $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
    $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  
    if( $show_xml ){
      print_stdout "need_admin_password: \n" . $req->as_string() . " admin name: " . $admin . "\n\n";
    }
  
    $resp = $ua->request($req);
    
    if( !$resp->is_success ){
  
      $admin = undef;
      $password = undef;
  
      if( $retries < 3 ){
  
        $retries++;
  
        next;
          
      }else{

        print "\nPlease confirm Admin Name and/or Password.\n\n";
        exit;
      }

    }else{
      last;
    }
  }
  
  my $parser     = XML::LibXML->new;
  my $resp_doc   = $parser->parse_string( $resp->decoded_content );

  if( $show_xml ){
    print_stdout "need_admin_password: \n" . $resp_doc->toString(1) . "\n";
  }
    
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_auth_response') ){

    if( EA('http_bus_is_open') eq "1" ){
      
      print "Simultaneous logins by the same administrator are\n";
      print "not allowed. If you want to continue, push 'y'.\n";

      my $nxtans = <STDIN>;
      chomp($nxtans);
      if( $nxtans ne 'y' && $nxtans ne 'Y' ){
        exit;
      }
    }     

    last;
  }
  
  return;  
}

sub bus_open {
  
  my ( $ua ) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/open';
  my $req = HTTP::Request->new( POST => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {
    print_stdout "ERROR: /protected/bus/open :" . $resp->status_line . " or no content.\n";
    return '';
  }

  my $parser     = XML::LibXML->new;
  my $resp_doc   = $parser->parse_string( $resp->decoded_content );
  my $bus_session_id;

  if( $show_xml ){
    print_stdout "bus_open: \n" . $req->as_string() . "\n";
    print_stdout "bus_open: \n" . $resp_doc->toString(1) . "\n";
  }

  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_http_bus_response') ){

    if ( EA('version') ne $rhp_version ) {
      print_stdout "ERROR: RHP version not supported. :" . EA('version') . "\n";
      return '';
    }

    $EAELM = $EAELM->getElementsByTagName('rhp_http_bus_record')->item(0);

    if ( EA('service') ne 'http_bus' ) {
      print_stdout "ERROR: RHP service not supported. :" . EA('service') . "\n";
      return '';
    }

    if ( EA('action') ne 'open' ) {
      print_stdout "ERROR: RHP action not supported. :" . EA('action') . "\n";
      return '';
    }

    $bus_session_id = EAD('session_id','');
    if ( $bus_session_id eq '' ) {
      print_stdout "ERROR: Session ID not found.\n";
      return '';
    }
  }

  return $bus_session_id;
}

sub bus_close {
  
  my ( $ua, $session_id ) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/close/' . $session_id;
  my $req = HTTP::Request->new( DELETE => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );

  if( $show_xml ){
    print_stdout "bus_close: \n" . $req->as_string() . "\n";
  }

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/close/$session_id :" . $resp->status_line . "\n";
  }
  
  return;
}

sub bus_read {

  my ($bus_session_id,$bus_read_cb_ref,$bus_read_cb_ctx_ref) = @_;
  my $ret = 1;

  if ( !defined($bus_session_id) ) {
    print_stdout "bus_read: bus_session_id=null\n";
    return 0;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/read/' . $bus_session_id;

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( GET => $url );

  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );
  $req->header( "Content-Type"        => 'text/xml; charset=utf-8' );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {

      $ret = 0;

    } else {

      print_stdout "No event occurred: /protected/bus/read/$bus_session_id :" . $resp->status_line . "\n";
    }

  } else {

    $ret = $bus_read_cb_ref->($bus_session_id,$bus_read_cb_ctx_ref,$resp);
  }

  return $ret;
}

#
# Actually, it is unnecessary to invoke another thread for 
# bus_read opearation in most cases.
#
sub bus_read_begin_thread {

  my ( $bus_session_id, $bus_read_cb_ref, $bus_read_cb_ctx_ref ) = @_;
  
  return threads->new(
    sub {

      $SIG{'KILL'} = sub { print_stdout "KILLed\n"; threads->exit(); };  
      
      while (1) {

        my $ret;

        $ret = bus_read($bus_session_id,$bus_read_cb_ref,$bus_read_cb_ctx_ref);          
        if ( $ret == 0 ) {
          print_stdout "bus_session_read error!\n";
          last;
        }elsif( $ret == 1 ){
          last;
        }
      }
    }
  );
}


sub create_post_req_upload_config_file {

  my ($bus_session_id, $file_path) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/config';

  my $req = POST( $url,
                  'Content_Type' => 'multipart/form-data',
                  'Content' => [ 'upload_config_bus_session_id' => $bus_session_id,
                                 'upload_config' => [$file_path,
                                                     'rockhopper.rcfg',
                                                     'Content-Type' => 'application/octet-stream'],
                                                     ]
                 );
                       
  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  
  if( $show_xml ){
    print_stdout "create_post_req_upload_config_file: \n" . $req->as_string() . "\n";
  }
  
  return $req;
}

sub print_ascii {
  
  my($src_txt) = @_;
  
  foreach my $ch (split //, $src_txt) {
    if( $ch =~ /^[\x20-\x7E]+$/ ){      
      print_stdout $ch;
    }elsif( $ch =~ /^[\x0d]+$/ ){      
      print_stdout '[\r]';
    }elsif( $ch =~ /^[\x0a]+$/ ){      
      print_stdout '[\n]' . "\n";
    }else{
      print_stdout ".";
    }
  }
    
  return;  
}

sub create_post_upload_my_cert_pkcs12 {

  my ($bus_session_id, $file_path) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/certs/' . $realm . '/' . $bus_session_id;

  my $req = POST( $url,
                  'Content_Type' => 'multipart/form-data',
                  'Content' => [ 'upload_cert_file_vpn_realm' => $realm,
                                 'upload_cert_file_bus_session_id' => $bus_session_id,
                                 'upload_cert_file_pkcs12' => [$file_path,
                                                     'rockhopper_my_cert_' . $realm . '.p12',
                                                     'Content-Type' => 'application/octet-stream'],
                               ]
                 );
                       
  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  
  if( $show_xml ){
    print_stdout "create_post_upload_my_cert_pkcs12: \n";
    print_ascii($req->as_string());
    print "\n";
  }
  
  return $req;
}

sub create_post_upload_my_cert_pem {

  my ($bus_session_id, $cert_file_path, $priv_key_file_path) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/certs/' . $realm . '/' . $bus_session_id;

  my $req = POST( $url,
                  'Content_Type' => 'multipart/form-data',
                  'Content' => [ 'upload_cert_file_vpn_realm' => $realm,
                                 'upload_cert_file_bus_session_id' => $bus_session_id,
                                 'upload_cert_file_my_cert_pem' => [$cert_file_path,
                                                     'rockhopper_my_cert_' . $realm . '.pem',
                                                     'Content-Type' => 'application/octet-stream'],
                                 'upload_cert_file_privkey_pem' => [$priv_key_file_path,
                                                     'rockhopper_my_priv_key_' . $realm . '.pem',
                                                     'Content-Type' => 'application/octet-stream'],
                               ]
                 );
                       
  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  
  if( $show_xml ){
    print_stdout "create_post_upload_my_cert_pem: \n" . $req->as_string() . "\n";
  }
  
  return $req;
}

sub create_post_upload_ca_cert_pem {

  my ($bus_session_id, $file_path, $accept_expired_cert) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/certs/' . $realm . '/' . $bus_session_id;

  my $req = POST( $url,
                  'Content_Type' => 'multipart/form-data',
                  'Content' => [ 'upload_cert_file_vpn_realm' => $realm,
                                 'upload_cert_file_bus_session_id' => $bus_session_id,
                                 'accept_expired_cert' => $accept_expired_cert,
                                 'upload_ca_cert_file_pem' => [$file_path,
                                                     'rockhopper_ca_cert_' . $realm . '.pem',
                                                     'Content-Type' => 'application/octet-stream'],
                               ]
                 );
                       
  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  
  if( $show_xml ){
    print_stdout "create_post_upload_ca_cert_pem: \n" . $req->as_string() . "\n";
  }
  
  return $req;
}

sub create_post_upload_crl_pem {

  my ($bus_session_id, $file_path, $accept_expired_cert) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/certs/' . $realm . '/' . $bus_session_id;

  my $req = POST( $url,
                  'Content_Type' => 'multipart/form-data',
                  'Content' => [ 'upload_cert_file_vpn_realm' => $realm,
                                 'upload_cert_file_bus_session_id' => $bus_session_id,
                                 'accept_expired_cert' => $accept_expired_cert,
                                 'upload_crl_file_pem' => [$file_path,
                                                     'rockhopper_crl_' . $realm . '.pem',
                                                     'Content-Type' => 'application/octet-stream'],
                               ]
                 );
                       
  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  
  if( $show_xml ){
    print_stdout "create_post_upload_crl_pem: \n" . $req->as_string() . "\n";
  }
  
  return $req;
}


my $eap_sup_method_u = undef;
my $eap_sup_user_id_u = undef;
my $eap_sup_user_key_u = undef;

sub vpn_connect_read_cb {
  
  my ($bus_session_id, $cb_ctx_ref, $resp) = @_;
  my $ret = 2;
    
  my $parser   = XML::LibXML->new;
  my $resp_doc = $parser->parse_string( $resp->decoded_content );

  if( $show_xml ){
    print_stdout "vpn_connect_read_cb: \n" . $resp_doc->toString(1) . "\n";
  }
    
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_http_bus_record') ) {

    my $rec_action = EA('action');
#    print_stdout "Rec_action: $rec_action\n";

    if ($rec_action eq "vpn_established" ) {

      print_stdout "VPN is successfully connected.\n";
      $ret = 1;
      last;

    }elsif ($rec_action eq "vpn_connect_i_error" ) {

      print_stdout "Failed to connect VPN.\n";
      $ret = 1;
      last;

    }elsif ($rec_action eq "vpn_connect_i_exists" ) {

      print_stdout "VPN is already connected.\n";
      $ret = 1;
      last;

    }elsif ($rec_action eq "eap_sup_vpn_connect_i_user_key_needed" || 
            $rec_action eq "eap_sup_ask_for_user_key_req" ) {

      my $eap_sup_method = EA('eap_sup_method');
      if( $eap_sup_method eq 'mschapv2' ){

        if( $rec_action eq "eap_sup_ask_for_user_key_req" ){
          print_stdout "Authentication failed. Confirm your user name and password.\n";
        }
          
        my $eap_sup_user_id = undef;
        my $eap_sup_user_key = undef;
        
        if( $rec_action eq "eap_sup_vpn_connect_i_user_key_needed" && 
            defined($eap_sup_user_id_u) ){

          $eap_sup_method = $eap_sup_method_u;
          $eap_sup_user_id = $eap_sup_user_id_u;
          $eap_sup_user_key = $eap_sup_user_key_u;

        }else{

get_stdin_again:
          print_stdout "[EAP-MSCHAPv2] User name: ";
          $eap_sup_user_id = <STDIN>;
          chomp($eap_sup_user_id);
            
          print_stdout "[EAP-MSCHAPv2] Password: ";
          system('stty','-echo');
          $eap_sup_user_key = <STDIN>;
          chomp($eap_sup_user_key);
          system('stty','echo');
          print_stdout "\n";

          if( !defined($eap_sup_user_id) || !defined($eap_sup_user_key) ){
            print_stdout "\n";
            goto get_stdin_again;
          }
        }
          
        $eap_sup_method_u = undef;
        $eap_sup_user_id_u = undef;
        $eap_sup_user_key_u = undef;

        if( $rec_action eq "eap_sup_vpn_connect_i_user_key_needed" ){

          $ret = vpn_connect_eap($bus_session_id,
                    $eap_sup_method,$eap_sup_user_id,$eap_sup_user_key);
          if( !$ret ){
            $ret = 2;
          }else{
            $ret = 1;
          }
            
        }elsif( $rec_action eq "eap_sup_ask_for_user_key_req" ){
            
          $ret = vpn_connect_eap_retry_user_key($bus_session_id,$realm,
                    "continue",EA('txn_id'),EA('vpn_unique_id'),
                    $eap_sup_method,$eap_sup_user_id,$eap_sup_user_key);
          if( !$ret ){
            $ret = 2;
          }else{
            $ret = 1;
          }
        }    

      }else{
          
        print_stdout "Unknown EAP's authentication method: $eap_sup_method\n";
        $ret = 1;
      }

      last;
        
    }else{
       
#      print_stdout "vpn_connect_read_cb: Unknown action: $rec_action\n";
      $ret = 2;
    }
  }
  
  return $ret;    
}

sub vpn_connect_eap_retry_user_key {
  
  my ($bus_session_id,$realm,$eap_sup_action,$txn_id,$vpn_uid,$eap_sup_method,$eap_sup_user_id,$eap_sup_user_key) = @_;

  my $ret = 0;
  
  my $ua = LWP::UserAgent->new();


  my @attr_names = ("version",  "service",    "action",               "vpn_realm",
                    "txn_id","eap_sup_action","peer_id_type","peer_id","vpn_unique_id",
                    "eap_sup_method","eap_sup_user_id","eap_sup_user_key");
  my @attr_vals = ($rhp_version,"ui_http_vpn","eap_sup_user_key_reply",$realm,
                   $txn_id, $eap_sup_action, $peerid_type,  $peerid,  $vpn_uid ,
                   $eap_sup_method, $eap_sup_user_id, $eap_sup_user_key);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "eap_sup_user_key_reply: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {    
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
    $ret = 1;
  }
  
  return $ret;
}

sub vpn_connect_eap {
  
  my ($bus_session_id,$eap_sup_method,$eap_sup_user_id,$eap_sup_user_key) = @_;
  my $ret = 0;
  
  my $ua = LWP::UserAgent->new();

  my @attr_names = ("version",  "service",    "action", "vpn_realm",
                    "peer_id_type","peer_id","eap_sup_method","eap_sup_user_id","eap_sup_user_key");
  my @attr_vals = ($rhp_version,"ui_http_vpn","connect",$realm,     
                   $peerid_type,  $peerid,  $eap_sup_method, $eap_sup_user_id, $eap_sup_user_key);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "connect_eap: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {    
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
    $ret = 1;
  }
  
  return $ret;
}

sub vpn_connect {

  my ($eap_sup_method,$eap_sup_user_id,$eap_sup_user_key) = @_;
  
  if ( !defined($realm) ) {
    print_stdout "-realm <realm_no> not specified.\n";
    print_usage("connect");
    return;
  }
  
  if ( !defined($peerid_type) || !defined($peerid) ){
    print_stdout "-peerid_type or -peerid not specified.\n";
    print_usage("connect");
    return;
  }

  if( !defined($eap_sup_method) ){
    $eap_sup_method = "mschapv2"
  }
  
  if( defined($eap_sup_user_id) && !defined($eap_sup_user_key) ||
      !defined($eap_sup_user_id) && defined($eap_sup_user_key) ){
    print_stdout "Please specify both -eap_id and -eap_key.\n";
    print_usage("connect");
    return;
  }

  if( defined($eap_sup_user_id) ){
    $eap_sup_method_u = $eap_sup_method;
    $eap_sup_user_id_u = $eap_sup_user_id;
    $eap_sup_user_key_u = $eap_sup_user_key;
  }

  need_admin_password();
  

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open( $ua );
  if ( $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action", "vpn_realm","peer_id_type","peer_id");
  my @attr_vals = ($rhp_version,"ui_http_vpn","connect",$realm,     $peerid_type,  $peerid);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "connect: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( $resp->is_success ) {

    my $th = bus_read_begin_thread($bus_session_id,\&vpn_connect_read_cb,undef);
    $th->join();

  }else{
    
    if ( $resp->status_line =~ '409' ) {
      print_stdout "Authentication process is busy. Wait for a short while and retry later.\n";
    }else{    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
    }
  }

  bus_close( $ua, $bus_session_id );
  
  return;
}

sub vpn_disconnect {

  my ($uid) = @_;

  if ( !defined($realm) ) {
    print_stdout "-realm <realm_no> not specified.\n";
    print_usage("disconnect");
    return;
  }
  
  if( !defined($uid) ){
   
    if ( !defined($peerid_type) || !defined($peerid) ){
      print_stdout "-peerid_type or -peerid not specified.\n";
      print_usage("disconnect");
      return;
    }
  }
  
  need_admin_password();
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open( $ua );
  if ( $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action", "vpn_realm","peer_id_type","peer_id","vpn_unique_id");
  my @attr_vals = ($rhp_version,"ui_http_vpn","close",  $realm,     $peerid_type,  $peerid, $uid);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "disconnect: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close( $ua, $bus_session_id );
  
  return;
}


sub show_rt_ck_result {
  
  my ( $vpn_elm, $show_title ) = @_;
 
  my $rt_ck_res_idx = 0;
  foreach $EAELM ( $vpn_elm->getElementsByTagName('mobike_init_rt_check_result') ) {
  
    my $rt_ck_res_elm = $EAELM;
  
    if( $show_title && $rt_ck_res_idx == 0 ){
      print_stdout "\n *MOBIKE Routability Check:\n\n";
    }
  
    my $addr = EA('my_addr_v4');
    my $peer_addr = EA('peer_addr_v4');
    if( !defined($addr) ){
      $addr = EA('my_addr_v6');
      $peer_addr = EA('peer_addr_v6');
    }
  
    my $rt_result = (EA('result') ne '0' ? "*REACHABLE" : "FAILED");
  
    my $dno = length("$rt_ck_res_idx") + 4;

    print_stdout " \[" . ($rt_ck_res_idx + 1) . "\] Local:  " . $addr . " (" . EA('my_if') . ")\n";
    for(my $dnn = 0; $dnn < $dno; $dnn++){
      print_stdout " ";
    }
    print_stdout "Remote: " . $peer_addr . " (" . EA('peer_type') . ") " . $rt_result . "\n\n";
        
    $rt_ck_res_idx++;
  }
  $EAELM = $vpn_elm;    
  
  return;
}

sub show_status_vpn_detail {
  
  my ($resp_doc,$vpn_idx) = @_;

  foreach $EAELM ( $resp_doc->getElementsByTagName('vpn') ) {

    my $vpn_elm = $EAELM;

    print_stdout "\n";

    if ( !defined(EA('vpn_realm_name')) ) {
      print_stdout "VPN\[$vpn_idx\]: Realm(" . EA('vpn_realm_id') . ")";
    } else {      
      print_stdout "VPN\[$vpn_idx\]: Realm(" . EA('vpn_realm_name') . ":" . EA('vpn_realm_id') . ")";
    }
    if( EAD('exec_mobike',"0") eq "1" &&
        (EAD('rt_ck_pending','0') ne '0' ||
         EAD('rt_ck_waiting','0') ne '0' ||
         EAD('mobike_keepalive_pending','0') ne '0') ){
      print_stdout "  *Dormant"      
    }
    if( EAD('exec_sess_resume',"0") eq "1" &&
        EAD('gen_by_sess_resume','0') eq '1' ){
      print_stdout "  *Resumed"      
    }
    print_stdout "\n";
    

    if( defined(EA('eap_my_identity')) ){
      print_stdout "  Local ID: " . EA('eap_my_identity') . "(eap) " . EA('myid') . "(" . EA('myid_type') . ")\n";        
    }else{
      print_stdout "  Local ID: " . EA('myid') . "(" . EA('myid_type') . ")\n";        
    }

    my $my_addr = EA('my_addr_v4');
    my $peer_addr = EA('peer_addr_v4');
    my $portdlm = ":";
    if( !defined($my_addr) ){
      $my_addr = EA('my_addr_v6');
      $peer_addr = EA('peer_addr_v6');
      $portdlm = ".";
    }
    print_stdout "        IP: " . $my_addr . "(" . EA('my_if_name') . ")$portdlm" . EA('my_port') . "\n";


    print_stdout "  Peer ID :";
    if( defined(EA('eap_peer_identity')) ){
      print_stdout " " . EA('eap_peer_identity') . "(eap)";
    }
    if ( EA('peerid') eq 'any' ) {
      print_stdout " N/A";
    } else {
      print_stdout " " . EA('peerid') . "(" . EA('peerid_type') . ")";        
      if( EA('alt_peerid_type') ){
        print_stdout " Alt: " . EA('alt_peerid') . "(" . EA('alt_peerid_type') . ")";        
      }
    }
    print_stdout "\n";

    print_stdout "       IP : " . $peer_addr . "$portdlm" . EA('peer_port') . "  ";
    if( EAD('peer_is_access_point',"0") eq "1" ){
      print_stdout " AP";      
    }
    if( EAD('qcd_peer_token_enabled',"0") eq "1" ){
      print_stdout " QCD";      
    }
    if( EAD('peer_is_rockhopper',"0") eq "1" ){
      print_stdout " Rockhopper";      
    }else{
      print_stdout " Non-Rockhopper";      
    }
    print_stdout "\n";



    if( EAD('exec_nat_t',"0") eq "1" ){
      
      print_stdout "  \[NAT_T\]";
      
      my $vpn_behind_a_nat = EA('behind_a_nat');
      
      if( $vpn_behind_a_nat == 1 ){
        print_stdout " LOCAL: BEHIND_A_NAT";        
      }elsif( $vpn_behind_a_nat == 2 ){
        print_stdout " PEER: BEHIND_A_NAT";        
      }elsif( $vpn_behind_a_nat == 3){
        print_stdout " BOTH: BEHIND_A_NAT";        
      }            
      print_stdout "\n";
    }


    my @itnl_if_addrs = ();
    my $itnl_if_addrs_idx = 0;
    foreach $EAELM ( $vpn_elm->getElementsByTagName('internal_if_addr_ifc') ) {
      if( defined(EA('address_v4')) ){
        $itnl_if_addrs[$itnl_if_addrs_idx] = EA('address_v4');
        $itnl_if_addrs_idx++;
      }
    }
    foreach $EAELM ( $vpn_elm->getElementsByTagName('internal_if_addr_ifc') ) {
      if( defined(EA('address_v6')) ){
        $itnl_if_addrs[$itnl_if_addrs_idx] = EA('address_v6');
        $itnl_if_addrs_idx++;
      }
    }
    $EAELM = $vpn_elm;
    print_stdout "  \[IN\] Local IP: " . EA('internal_if_name') . " " . EA('internal_if_addr_type');
    if( $itnl_if_addrs_idx == 0 ){
      print_stdout " IP:N/A\n";
    }else{
       print_stdout "\n";
       for( my $i = 0; $i < $itnl_if_addrs_idx; $i++){
        print_stdout "                 " . $itnl_if_addrs[$i] . "\n";
      }
    }

    my @itnl_peer_addrs = ();
    my $itnl_peer_addrs_idx = 0;
    foreach $EAELM ( $vpn_elm->getElementsByTagName('internal_peer_addr') ) {
      if( defined(EA('address_v4')) ){
        $itnl_peer_addrs[$itnl_peer_addrs_idx] = EA('address_v4');
        $itnl_peer_addrs_idx++;
      }
    }
    foreach $EAELM ( $vpn_elm->getElementsByTagName('internal_peer_addr') ) {
      if( defined(EA('address_v6')) ){
        $itnl_peer_addrs[$itnl_peer_addrs_idx] = EA('address_v6');
        $itnl_peer_addrs_idx++;
      }
    }
    $EAELM = $vpn_elm;
    print_stdout "  \[IN\] Peer IP:";
    if ( EA('internal_peer_addr_cp')) {
      print_stdout " ikev2cfg\n";
      if( EA('peer_exec_ipv6_autoconf') ){
        print_stdout " ipv6-autoconf";
      }
      print_stdout "\n";
      for( my $i = 0; $i < $itnl_peer_addrs_idx; $i++){
        print_stdout "                " . $itnl_peer_addrs[$i] . "\n";
      }
    }elsif( EA('peer_exec_ipv6_autoconf')) {
      print_stdout " ipv6-autoconf\n";
      for( my $i = 0; $i < $itnl_peer_addrs_idx; $i++){
        print_stdout "                " . $itnl_peer_addrs[$i] . "\n";
      }
    }elsif( $itnl_peer_addrs_idx == 0 ){
      print_stdout " N/A\n";
    }else{
      for( my $i = 0; $i < $itnl_peer_addrs_idx; $i++){
        if( $i == 0 ){
          print_stdout " " . $itnl_peer_addrs[$i] . "\n";
        }else{
          print_stdout "                " . $itnl_peer_addrs[$i] . "\n";
        }
      }
    }


    print_stdout "  \[IN\] MAC:" . EA('internal_if_mac') . " MTU:" . EA('internal_if_mtu');
    if ( EA('encap_mode') eq 'ipip' ) {
      print_stdout " Peer-Dmy-MAC:" . EA('dummy_peer_mac');
    }
    print_stdout "\n";


    my @itnl_gw_addrs = ();
    my $itnl_gw_addrs_idx = 0;
    if( defined(EA('internal_gateway_addr_v4')) ){
      $itnl_gw_addrs[$itnl_gw_addrs_idx] = EA('internal_gateway_addr_v4') . "(cfg)";
      $itnl_gw_addrs_idx++;
    }
    if( defined(EA('internal_gateway_addr_v6')) ){
      $itnl_gw_addrs[$itnl_gw_addrs_idx] = EA('internal_gateway_addr_v6') . "(cfg)";
      $itnl_gw_addrs_idx++;
    }
    if( defined(EA('internal_sys_def_gateway_addr_v4')) ){
      $itnl_gw_addrs[$itnl_gw_addrs_idx] = EA('internal_sys_def_gateway_addr_v4') . "(sys)";
      $itnl_gw_addrs_idx++;
    }
    if( defined(EA('internal_sys_def_gateway_addr_v6')) ){
      $itnl_gw_addrs[$itnl_gw_addrs_idx] = EA('internal_sys_def_gateway_addr_v6') . "(sys)";
      $itnl_gw_addrs_idx++;
    }
    if( $itnl_gw_addrs_idx ){
      print_stdout "  \[IN\] GW:";
      for( my $i = 0; $i < $itnl_gw_addrs_idx; $i++){
        if( $i == 0 ){
          print_stdout " " . $itnl_gw_addrs[$i] . "\n";
        }else{
          print_stdout "                 " . $itnl_gw_addrs[$i] . "\n";
        }
      }
    }

    
    my $itnl_cfg_gw_v4 = undef;
    my $itnl_cfg_gw_v6 = undef;
    my @itnl_cfg_net = ();
    my $itnl_cfg_net_idx = 0;
    foreach $EAELM ( $vpn_elm->getElementsByTagName('internal_networks') ) {
      
      $itnl_cfg_gw_v4 = EA('internal_gateway_v4');
      $itnl_cfg_gw_v6 = EA('internal_gateway_v6');
      
      foreach $EAELM ( $vpn_elm->getElementsByTagName('internal_subnet_v4') ) {
        if( defined(EA('network_v4')) ){
          $itnl_cfg_net[$itnl_cfg_net_idx] = EA('network_v4');
          $itnl_cfg_net_idx++;
        }
      }    
      foreach $EAELM ( $vpn_elm->getElementsByTagName('internal_subnet_v6') ) {
        if( defined(EA('network_v6')) ){
          $itnl_cfg_net[$itnl_cfg_net_idx] = EA('network_v6');
          $itnl_cfg_net_idx++;
        }
      }    
    }
    $EAELM = $vpn_elm;
    if( $itnl_cfg_net_idx ){
      if( !defined($itnl_cfg_gw_v4) ){
        $itnl_cfg_gw_v4 = "N/A";
      }
      $itnl_cfg_gw_v4 = "v4:" . $itnl_cfg_gw_v4;
      if( !defined($itnl_cfg_gw_v6) ){
        $itnl_cfg_gw_v6 = "N/A";
      }
      $itnl_cfg_gw_v6 = "v6:" . $itnl_cfg_gw_v6;
      print_stdout "  \[IN\] Remote Network: GW(" . $itnl_cfg_gw_v4 . " " . $itnl_cfg_gw_v6 . ")\n";
      for( my $i = 0; $i < $itnl_cfg_net_idx; $i++){
        print_stdout "                       " . $itnl_cfg_net[$i] . "\n";
      }
    }


    my $itnl_cfg_dns_v4 = undef;
    my $itnl_cfg_dns_v6 = undef;
    my @itnl_cfg_dns = ();
    my $itnl_cfg_dns_idx = 0;
    foreach $EAELM ( $vpn_elm->getElementsByTagName('split_dns') ) {
      
      $itnl_cfg_dns_v4 = EA('internal_dns_server_v4');
      $itnl_cfg_dns_v6 = EA('internal_dns_server_v6');
      
      foreach $EAELM ( $vpn_elm->getElementsByTagName('split_dns_domain') ) {
        if( defined(EA('internal_domain_suffix')) ){
          $itnl_cfg_dns[$itnl_cfg_dns_idx] = EA('internal_domain_suffix');
          $itnl_cfg_dns_idx++;
        }
      }    
    }
    $EAELM = $vpn_elm;
    if( $itnl_cfg_dns_idx ){
      if( !defined($itnl_cfg_dns_v4) ){
        $itnl_cfg_dns_v4 = "N/A";
      }
      $itnl_cfg_dns_v4 = "v4:" . $itnl_cfg_dns_v4;
      if( !defined($itnl_cfg_dns_v6) ){
        $itnl_cfg_dns_v6 = "N/A";
      }
      $itnl_cfg_dns_v6 = "v6:" . $itnl_cfg_dns_v6;
      print_stdout "  \[IN\] DNS Server: " . $itnl_cfg_dns_v4 . " " . $itnl_cfg_dns_v6 . "\n";
      for( my $i = 0; $i < $itnl_cfg_dns_idx; $i++){
        if( $i == 0 ){
          print_stdout "       DNS Suffix: " . $itnl_cfg_dns[$i] . "\n";
        }else{
          print_stdout "                   " . $itnl_cfg_dns[$i] . "\n";
        }
      }
    }
        

    my @mobike_additional_addrs = ();
    my $mobike_additional_addrs_idx = 0;
    foreach $EAELM ( $vpn_elm->getElementsByTagName('mobike_additional_addr') ) {
      if( defined(EA('mobike_peer_addr_v4')) ){
        $mobike_additional_addrs[$mobike_additional_addrs_idx] = EA('mobike_peer_addr_v4');
        $mobike_additional_addrs_idx++;
      }
    }
    foreach $EAELM ( $vpn_elm->getElementsByTagName('mobike_additional_addr') ) {
      if( defined(EA('mobike_peer_addr_v6')) ){
        $mobike_additional_addrs[$mobike_additional_addrs_idx] = EA('mobike_peer_addr_v6');
        $mobike_additional_addrs_idx++;
      }
    }
    $EAELM = $vpn_elm;
    if( $mobike_additional_addrs_idx ){
      print_stdout "  \[MOBIKE\] Peer IP:";
      for( my $i = 0; $i < $mobike_additional_addrs_idx; $i++){
        if( $i == 0 ){
          print_stdout " " . $mobike_additional_addrs[$i] . "\n";
        }else{
          print_stdout "                    " . $mobike_additional_addrs[$i] . "\n";
        }
      }
    }


    print_stdout "  " . EA('origin_side') . " Encap:" . EA('encap_mode') . "";
    if( EAD('is_access_point',"0") eq "1" ){
      print_stdout " AP";
    }
    if( EAD('is_config_server',"0") eq "1" ){
      print_stdout " CFG-SVR";
    }
    if( EAD('eap_role',"0") eq "server" ){
      print_stdout " EAP-SVR";
    }
    if( EAD('exec_mobike',"0") eq "1" ){
      print_stdout " MOBIKE";
    }
    if( EAD('http_cert_lookup_supported',"0") eq "1" ){
      print_stdout " HTTP-CERT";
    }
    if( EAD('exec_ikev2_fragmentation',"0") eq "1" ){
      print_stdout " FRAG";
    }
    if( EAD('qcd_my_token_enabled',"0") eq "1" ){
      print_stdout " QCD";      
    }
    my $exec_sess_resume = 0;
    if( EAD('exec_sess_resume',"0") eq "1" ){
      print_stdout " RESUME";    
      $exec_sess_resume = 1;  
    }
    
    my $nhrp_role = EA('nhrp_role');
    if( $nhrp_role eq "server" ){
      print_stdout " NHS";      
    }elsif( $nhrp_role eq "client" ){
      print_stdout " NHC";      
    }
    
    if( EAD('dmvpn_enabled',"0") eq "1" ){
      
      if( EAD('is_dmvpn_shortcut',"0") eq "1" ){
        print_stdout " DMVPN-S2S";      
      }else{
        print_stdout " DMVPN-H2S";      
      }
    }

    my $ike_ver = 2;
    if( EAD('ike_version',"2") eq "1" ){
      
      print_stdout " IKEv1";
      
      if( EAD('v1_commit_bit_enabled',"0") eq "1" ){
        print_stdout " P2-CB";
      }
      if( EAD('v1_dpd_enabled',"0") eq "1" ){
        print_stdout " DPD";
      }
      $ike_ver = 1;
    }        
    
    print_stdout "\n";


    print_stdout "  Elapsed(" . EA('time_elapsed') . 
          ") Created IKE SAs(" . EA('created_ikesas') . ") & Child SAs(" . EA('created_childsas') . ")\n";
    print_stdout "  ESP Pkts: Tx(" . EA('tx_esp_packets') . ") Rx(" . EA('rx_esp_packets') . ")\n";
    print_stdout "  UID:" . EA('vpn_unique_id') . "\n";


    my $ikesa_idx = 1;
    my $eap_method = EAD('eap_method',undef);
    my $eap_role = EAD('eap_role',"disabled");
    foreach $EAELM ( $vpn_elm->getElementsByTagName('ikesa') ) {

      my $ikesa_elm = $EAELM;

      print_stdout "\n";

      print_stdout "  *IKE SA\[" . $ikesa_idx . "\]:\n";
      print_stdout "   SPI I:" . EA('initiator_spi') . "\n";
      print_stdout "       R:" . EA('responder_spi') . "\n";
      print_stdout "   " . EA('side');
      if( $eap_role eq "peer" || $eap_role eq "server" ){
        print_stdout " " . EA('state') . "/" . EA('eap_state') . "(eap)";
      }else{
        print_stdout " " . EA('state');
      }
      if( $ike_ver == 1 ){
        print_stdout " " . EA('v1_exchange_mode') . "-mode";
      }
      print_stdout "\n";

      print_stdout "   Rekeyed(" . EA('rekeyed_gen') . ")";
      if ( EA('established_time_elapsed') ) {
        print_stdout " Elapsed(" . EA('established_time_elapsed') . ")";
      }
      print_stdout " Lifetime(Rekey:";
      if ( EA('expire_soft') ) {
        print_stdout EA('expire_soft');
      } else {
        print_stdout "--";
      }

      print_stdout " Exp:";
      if ( EA('expire_hard') ) {
        print_stdout EA('expire_hard') . ")\n";
      } else {
        print_stdout "--)\n";
      }

      my $auth_method = EA('auth_method');
      if( (!defined($auth_method) || $auth_method eq "unknown" || $auth_method eq "psk") && defined($eap_method) ){
        $auth_method = "EAP(" . $eap_method . ")";
      }
      if( $exec_sess_resume && defined(EA('auth_method_i_org')) ){
        $auth_method .= " (" . EA('auth_method_i_org') . ")";
      }
      my $peer_auth_method = EA('peer_auth_method');
      if( (!defined($peer_auth_method) || $peer_auth_method eq "unknown" || $peer_auth_method eq "psk") && defined($eap_method) ){
        $peer_auth_method = "EAP(" . $eap_method . ")";
      }
      if( $exec_sess_resume && defined(EA('auth_method_r_org')) ){
        $peer_auth_method .= " (" . EA('auth_method_r_org') . ")";
      }
      if ( EA('encr_key_bits') ) {
        print_stdout "   Auth: Local:". $auth_method . " Peer:" . $peer_auth_method . "\n   Prop\[" . EA('proposal_no') 
        . "\] PRF:" . EA('prf') . " DH:" . EA('dh_group') . " Integ:" . EA('integ') . " Encr:" 
        . EA('encr') . "(" . EA('encr_key_bits') . ")\n";
      } else {
        print_stdout "   Auth: " . $auth_method . " ==> " . EA('peer_auth_method') . "\n   Prop\[" 
        . EA('proposal_no') . "\] PRF:" . EA('prf') . " DH:" . EA('dh_group') . " Integ:" 
        . EA('integ') . " Encr:" . EA('encr') . "\n";
      }

      $ikesa_idx++;
    }
    $EAELM = $vpn_elm;


    my $childsa_idx = 1;
    my $v6_udp_encap = EAD('udp_encap_v6','0');
    foreach $EAELM ( $vpn_elm->getElementsByTagName('childsa') ) {

      my $childsa_elm = $EAELM;

      print_stdout "\n";      
      if( $ike_ver == 1 ){
        print_stdout "  *IPSEC SA\[" . $childsa_idx . "\]: SPI IN:" . EA('inbound_spi') . "OUT:" . EA('outbound_spi') . "\n";
      }else{
        print_stdout "  *CHILD SA\[" . $childsa_idx . "\]: SPI IN:" . EA('inbound_spi') . "OUT:" . EA('outbound_spi') . "\n";
      }
      print_stdout "   " . EA('side') . " " . EA('state') . "\n";
      print_stdout "   mode:" . EA('ipsec_mode') . " Rekeyed(" . EA('rekeyed_gen') . ")";

      if ( defined(EA('established_time_elapsed')) ) {
        print_stdout " Elapsed(" . EA('established_time_elapsed') . ")";
      }

      print_stdout " Lifetime(Rekey:";
      if ( defined(EAD('expire_soft',undef)) ) {
        print_stdout EA('expire_soft');
      } else {
        print_stdout "--";
      }
      
      print_stdout " Exp:";
      if ( defined(EAD('expire_hard',undef)) ) {
        print_stdout EA('expire_hard');
      } else {
        print_stdout "--";
      }
      print_stdout ")\n";

      if ( defined(EAD('encr_key_bits',undef)) ) {
        print_stdout "   Prop\[" . EA('proposal_no') . "\] Integ:" . EA('integ') . 
        " Encr:" . EA('encr') . "(" . EA('encr_key_bits') . ")";
      } else {
        print_stdout "   Prop\[" . EA('proposal_no') . "\] Integ:" . EA('integ') . 
        " Encr:" . EA('encr');
      }
      print_stdout "\n";

      print_stdout "   PMTU(Def:" . EA('pmtu_default') . ", Cache:" . EA('pmtu_cache') . ")";

      if ( EA('esn') ) {
        print_stdout " ESN";
      }

      if (EA('pfs')) {
        print_stdout " PFS";
      }

      if (EA('anti_replay')) {
        print_stdout " Anti-Replay";
      }

      if (EA('tfc_padding')) {
        print_stdout " TFC-Pad";
      }

      if (EA('udp_encap')) {
        if( !$v6_udp_encap ){
          print_stdout " UDP-Encap(v4)";
        }else{
          print_stdout " UDP-Encap";
        }
      }

      if (EA('out_of_order_drop')) {
        print_stdout " OoO-Drp";
      }

      if (EA('collision_detected')) {
        print_stdout " Nego-Col";
      }


      my $tss_idx = 1;
      foreach $EAELM ($childsa_elm->getElementsByTagName('my_traffic_selector') ){

        if( $tss_idx == 1 ){
          print_stdout "\n";
          print_stdout "   \[TS: Local ==> Peer\]:\n";
        }

        my $my_tss = EA('traffic_selector');
        $my_tss =~ s/ANY\(0\)/ANY/g;
        $my_tss =~ s/0--65535/ANY/g;
        $my_tss =~ s/0.0.0.0--255.255.255.255/ANY/g;
        $my_tss =~ s/::--ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ANY/g;

        print_stdout "    [$tss_idx] $my_tss\n";
        $tss_idx++;
      }
      $EAELM = $childsa_elm;
      

      $tss_idx = 1;
      foreach $EAELM ($childsa_elm->getElementsByTagName('peer_traffic_selector') ){

        if( $tss_idx == 1 ){
          print_stdout "\n";
          print_stdout "   \[TS: Peer ==> Local\]:\n";
        }
        
        my $peer_tss = EA('traffic_selector');
        $peer_tss =~ s/ANY\(0\)/ANY/g;
        $peer_tss =~ s/0--65535/ANY/g;
        $peer_tss =~ s/0.0.0.0--255.255.255.255/ANY/g;
        $peer_tss =~ s/::--ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ANY/g;

        print_stdout "    [$tss_idx] $peer_tss\n";
        $tss_idx++;
      }
      $EAELM = $childsa_elm;


      my $childsa_ar_tx_seq = EA('antireplay_tx_seq');
      my $childsa_ar_rx_window_size = EA('antireplay_rx_window_size');
      my $childsa_ar_rx_nesn_seq_last = EA('antireplay_rx_non_esn_seq_last');
      my $childsa_ar_rx_esn_seq_b = EA('antireplay_rx_esn_seq_b');
      my $childsa_ar_rx_esn_seq_t = EA('antireplay_rx_esn_seq_t');
      my $childsa_ar_rx_window_mask = EA('antireplay_rx_window_mask');

      if( $childsa_ar_rx_window_size ){

        print_stdout "\n";
        print_stdout "   \[Anti-Replay\]:\n";
        
        print_stdout "   Tx: Seq: $childsa_ar_tx_seq\n";
        print_stdout "   Rx: WinSize $childsa_ar_rx_window_size,";
        if( $childsa_ar_rx_nesn_seq_last ){
          my $seqt = $childsa_ar_rx_nesn_seq_last + $childsa_ar_rx_window_size;
          print_stdout " Seq B: $childsa_ar_rx_nesn_seq_last, Seq T: $seqt";
        }else{
          print_stdout " Seq B: $childsa_ar_rx_esn_seq_b, Seq T: $childsa_ar_rx_esn_seq_t";
        }
        print_stdout "\n";

        print_stdout "   Rx: WinMask\n";
        print_stdout "   ";
        my $msk_idx2 = 0;
        for( my $msk_idx = 1; $msk_idx <= $childsa_ar_rx_window_size; $msk_idx++ ){
          if( ($msk_idx % 10) == 0 ){
            print_stdout "$msk_idx2";
          }elsif( ($msk_idx % 10) == 1 ){
            print_stdout " ";
            $msk_idx2++;
          }else{
            print_stdout " ";
          }
        }
        print_stdout "\n   ";
        for( my $msk_idx = 1; $msk_idx <= $childsa_ar_rx_window_size; $msk_idx++ ){
          if( ($msk_idx % 10) == 1 ){
            print_stdout "1";            
          }elsif( ($msk_idx % 10) == 0 ){
            print_stdout "0";            
          }elsif( ($msk_idx % 5) == 0 ){
            print_stdout "+";            
          }else{
            print_stdout "-";            
          }
        }
        print_stdout "\n   $childsa_ar_rx_window_mask\n";
      }
      
      $childsa_idx++;
    }
    $EAELM = $vpn_elm;

    show_rt_ck_result($EAELM,1);
  }
  print_stdout "\n";
  
  return;
}

sub show_status_vpn_summary {
  
  my ($resp_doc,$vpn_idx,$rt_ck_res) = @_;

  foreach $EAELM ( $resp_doc->getElementsByTagName('vpn') ) {

    my $vpn_elm = $EAELM;

    print_stdout "\n";

    if ( !defined(EA('vpn_realm_name')) ) {
      print_stdout "VPN\[$vpn_idx\]: Realm(" . EA('vpn_realm_id') . ")";
    } else {      
      print_stdout "VPN\[$vpn_idx\]: Realm(" . EA('vpn_realm_name') . ":" . EA('vpn_realm_id') . ")";
    }
    if( EAD('exec_mobike',"0") eq "1" &&
        (EAD('rt_ck_pending','0') ne '0' ||
         EAD('rt_ck_waiting','0') ne '0' ||
         EAD('mobike_keepalive_pending','0') ne '0') ){
      print_stdout "  *Dormant"      
    }
    print_stdout "\n";
    print_stdout "  UID:" . EA('vpn_unique_id');
    print_stdout "\n";
    

    if( defined(EA('eap_my_identity')) ){
      print_stdout "  Local ID: " . EA('eap_my_identity') . "(eap) " . EA('myid') . "(" . EA('myid_type') . ")\n";        
    }else{
      print_stdout "  Local ID: " . EA('myid') . "(" . EA('myid_type') . ")\n";        
    }

    my $my_addr = EA('my_addr_v4');
    my $peer_addr = EA('peer_addr_v4');
    my $portdlm = ":";
    if( !defined($my_addr) ){
      $my_addr = EA('my_addr_v6');
      $peer_addr = EA('peer_addr_v6');
      $portdlm = ".";
    }
    print_stdout "        IP: " . $my_addr . "(" . EA('my_if_name') . ")$portdlm" . EA('my_port');
    if( EAD('is_access_point',"0") eq "1" ){
      print_stdout " AP";
    }
    if( EAD('is_config_server',"0") eq "1" ){
      print_stdout " CFG-SVR";
    }
    if( EAD('eap_role',"0") eq "server" ){
      print_stdout " EAP-SVR";
    }
    print_stdout "\n";


    print_stdout "  Peer ID :";
    if( defined(EA('eap_peer_identity')) ){
      print_stdout " " . EA('eap_peer_identity') . "(eap)";
    }
    if ( EA('peerid') eq 'any' ) {
      print_stdout " unknown";
    } else {
      print_stdout " " . EA('peerid') . "(" . EA('peerid_type') . ")";        
      if( EA('alt_peerid_type') ){
        print_stdout " Alt: " . EA('alt_peerid') . "(" . EA('alt_peerid_type') . ")";        
      }
    }
    print_stdout "\n";

    print_stdout "       IP : " . $peer_addr . "$portdlm" . EA('peer_port');
    if( EAD('peer_is_access_point',"0") eq "1" ){
      print_stdout " AP";      
    }
    print_stdout "\n";


    my $ikesa_idx = 1;
    my $eap_method = EAD('eap_method',undef);
    my $eap_role = EAD('eap_role',"disabled");
    foreach $EAELM ( $vpn_elm->getElementsByTagName('ikesa') ) {

      my $ikesa_elm = $EAELM;

      print_stdout "  *IKE SA\[$ikesa_idx\]  :";
      print_stdout " " . EA('side');
      if( $eap_role eq "peer" || $eap_role eq "server" ){
        print_stdout " " . EA('state') . "/" . EA('eap_state') . "(eap)";
      }else{
        print_stdout " " . EA('state');
      }
      print_stdout "\n";

      $ikesa_idx++;
    }
    $EAELM = $vpn_elm;


    my $childsa_idx = 1;
    my $v6_udp_encap = EAD('udp_encap_v6','0');
    foreach $EAELM ( $vpn_elm->getElementsByTagName('childsa') ) {

      my $childsa_elm = $EAELM;

      print_stdout "  *CHILD SA\[$childsa_idx\]: ";
      print_stdout EA('side') . " " . EA('state') . "\n";
      
      $childsa_idx++;
    }
    $EAELM = $vpn_elm;    
    
    if( $rt_ck_res ){
      print_stdout "\n";
      show_rt_ck_result($EAELM,0);
    }    
  }
  print_stdout "\n";
  
  return;
}

sub status_vpn {
  
  my($vpn_uid,$bus_session_id,$vpn_idx) = @_;

  if ( !defined($realm) || 
       ((!defined($peerid_type) || !defined($peerid)) && !defined($vpn_uid)) ) {
    print_stdout "-realm, -peerid_type, -peerid or -uid not specified.\n";
    print_usage("vpn");
    return;
  }

  if( defined($peerid_type) && $peerid_type eq "eap-mschapv2" ){
    $peerid_type = "mschapv2";
  }  

  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    need_admin_password();
  }
  
  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $exec_open = 0;
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {

    $bus_session_id = bus_open($ua);
    if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
      return undef;
    }

    $exec_open = 1;
  }

  my @attr_names = ("version",  "service",    "action",   "vpn_realm","peer_id_type","peer_id",  "vpn_unique_id");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_vpn",  $realm,  $peerid_type,  $peerid, $vpn_uid);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_vpn: \n" . $doc->toString(1) . "\n";
  }
  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if( $exec_open ){
    bus_close( $ua, $bus_session_id );
  }

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

    }else{

      return undef;
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    return $resp_doc;
  }

  return undef;
}

sub print_status_vpn {

  my($resp_doc,$vpn_idx) = @_;

  if( $show_xml ){
    print_stdout "status_vpn: \n" . $resp_doc->toString(1) . "\n";
  }
  if ($detail) {
    show_status_vpn_detail($resp_doc,$vpn_idx);
  } else {
    show_status_vpn_summary($resp_doc,$vpn_idx,0);
  }
  
  return;
}

sub show_brief_status_vpn {
  
  my ($peer_elm,$vpn_idx) = @_;

  $EAELM = $peer_elm;

  print_stdout "\n";

  if ( !defined(EA('vpn_realm_name')) ) {
    print_stdout "VPN\[$vpn_idx\]: Realm(" . EA('vpn_realm_id') . ")";
  } else {      
    print_stdout "VPN\[$vpn_idx\]: Realm(" . EA('vpn_realm_name') . ":" . EA('vpn_realm_id') . ")";
  }
  print_stdout "\n";
  print_stdout "  UID:" . EA('vpn_unique_id');
  print_stdout "\n";
    
  my $my_addr = EA('my_addr_v4');
  my $peer_addr = EA('peer_addr_v4');
  if( !defined($my_addr) ){
    $my_addr = EA('my_addr_v6');
    $peer_addr = EA('peer_addr_v6');
  }


  print_stdout "  Peer ID :";
  if( defined(EA('eap_peer_identity')) ){
    print_stdout " " . EA('eap_peer_identity') . "(eap)";
  }
  if ( EA('peerid') eq 'any' ) {
    print_stdout " N/A";
  } else {
    print_stdout " " . EA('peerid') . "(" . EA('peerid_type') . ")";        
    if( EA('alt_peerid_type') ){
      print_stdout " Alt: " . EA('alt_peerid') . "(" . EA('alt_peerid_type') . ")";        
    }
  }
  print_stdout "\n";

  print_stdout "       IP : " . $peer_addr;
  print_stdout "\n";

  print_stdout "  Local IP: " . $my_addr . "(" . EA('my_if_name') . ")";
  print_stdout "\n";


  my @itnl_if_addrs = ();
  my $itnl_if_addrs_idx = 0;
  foreach $EAELM ( $peer_elm->getElementsByTagName('internal_if_addr_ifc') ) {
    if( defined(EA('address_v4')) ){
      $itnl_if_addrs[$itnl_if_addrs_idx] = EA('address_v4');
      $itnl_if_addrs_idx++;
    }
  }
  foreach $EAELM ( $peer_elm->getElementsByTagName('internal_if_addr_ifc') ) {
    if( defined(EA('address_v6')) ){
      $itnl_if_addrs[$itnl_if_addrs_idx] = EA('address_v6');
      $itnl_if_addrs_idx++;
    }
  }
  $EAELM = $peer_elm;
  print_stdout "  \[IN\] Local IP:";
  if( $itnl_if_addrs_idx == 0 ){
    print_stdout " N/A\n";
  }else{
    for( my $i = 0; $i < $itnl_if_addrs_idx; $i++){
      if( $i == 0 ){
        print_stdout " " . $itnl_if_addrs[$i] . "\n";
      }else{
        print_stdout "                 " . $itnl_if_addrs[$i] . "\n";
      }
    }
  }

  my @itnl_peer_addrs = ();
  my $itnl_peer_addrs_idx = 0;
  foreach $EAELM ( $peer_elm->getElementsByTagName('internal_peer_addr') ) {
    if( defined(EA('address_v4')) ){
      $itnl_peer_addrs[$itnl_peer_addrs_idx] = EA('address_v4');
      $itnl_peer_addrs_idx++;
    }
  }
  foreach $EAELM ( $peer_elm->getElementsByTagName('internal_peer_addr') ) {
    if( defined(EA('address_v6')) ){
      $itnl_peer_addrs[$itnl_peer_addrs_idx] = EA('address_v6');
      $itnl_peer_addrs_idx++;
    }
  }
  $EAELM = $peer_elm;
  print_stdout "  \[IN\] Peer IP:";
  if( $itnl_peer_addrs_idx == 0 ){
    print_stdout " N/A\n";
  }else{
    for( my $i = 0; $i < $itnl_peer_addrs_idx; $i++){
      if( $i == 0 ){
        print_stdout " " . $itnl_peer_addrs[$i] . "\n";
      }else{
        print_stdout "                " . $itnl_peer_addrs[$i] . "\n";
      }
    }
  }


  if( EAD('exec_mobike',"0") eq "1" &&
      (EAD('rt_ck_pending','0') ne '0' ||
       EAD('rt_ck_waiting','0') ne '0' ||
       EAD('mobike_keepalive_pending','0') ne '0') ){
    print_stdout "  *Dormant  ";      
  }else{
    print_stdout "  ";
  }
  print_stdout "IKE SA: ". EA('ikesa_state') . "  CHILD SA: " . EA('childsa_state');
  print_stdout "\n";

  
  return;
}


sub status_enum_vpn {

#
# First, getting peer IDs' list. Next, getting each info about each peer one by one.
# This is for preventing programs from handling a too huge XML response
# which needs huge memory.
#

  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("vpn");
    return;
  }

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",           "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_vpn_peers", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_vpn_peers(VPN): \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

    }else{

      print_stdout "No information found.\n";      
    }

    bus_close($ua, $bus_session_id);

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_vpn_peers(VPN): \n" . $resp_doc->toString(1) . "\n";
    }

    my $peer_idx = 0;
    my @resp_docs = ();
    foreach $EAELM ( $resp_doc->getElementsByTagName('peer') ) {

      if( $detail ){

        $peerid_type = EA('peerid_type');
        $peerid      = EA('peerid');

        push(@resp_docs, status_vpn(EA('vpn_unique_id'),$bus_session_id,$peer_idx));

      }else{

        show_brief_status_vpn($EAELM,$peer_idx);          
      }
      
      $peer_idx++;
    }

    bus_close($ua, $bus_session_id);

    if( $detail ){

      $peer_idx = 0;
      foreach my $resp_doc (@resp_docs){
        
        print_status_vpn($resp_doc,$peer_idx);
        $peer_idx++;
      }
    }
  }
  
  return;
}

sub web_mng_update {
  
  my ( $mng_address_v4, $mng_address_v6, $mng_port, $allowed_address_v4, $allowed_address_v6 ) = @_;

  if ( !defined($mng_address_v4) && !defined($mng_address_v6) ) {
    print_stdout "-mng_address or -mng_address_v6 NOT specified.\n";
    print_usage("web-mng");
    return;
  }

  if( defined($mng_address_v4) && 
      $mng_address_v4 !~ $IPV4_REGEX ){   
    print_stdout "Invalid -mng_address specified. $mng_address_v4\n";
    return;
  }

  if( defined($mng_address_v6) && 
      $mng_address_v6 !~ $IPV6_REGEX ){   
    print_stdout "Invalid -mng_address_v6 specified. $mng_address_v6\n";
    return;
  }

  my $allowed_address_v4_netmask = undef;
  if( defined($allowed_address_v4) ){
    
    if( !defined($mng_address_v4) ){
      print_stdout "-mng_address must be specified with -allowed_address.\n";
      return;
    }
    
    if( $allowed_address_v4 !~ /\// ){

      if( $allowed_address_v4 !~ $IPV4_REGEX ){
        print_stdout "Invalid -allowed_address specified. $allowed_address_v4\n";
        return;
      }
            
    }else{

      my @tmp = split(/\//,$allowed_address_v4);
      my $tmpnum = @tmp;

      if( $tmpnum != 2 || $tmp[0] !~ $IPV4_REGEX ||
          $tmp[1] =~ /\D+/ ||
          $tmp[1] < 1 || $tmp[1] > 32 ){
        print_stdout "Invalid -allowed_address specified. $allowed_address_v4\n";
        return;
      }
      
      $allowed_address_v4_netmask = $tmp[1];
    }
  }

  my $allowed_address_v6_netmask = undef;
  if( defined($allowed_address_v6) ){
    
    if( !defined($mng_address_v6) ){
      print_stdout "-mng_address_v6 must be specified with -allowed_address_v6.\n";
      return;
    }
    
    if( $allowed_address_v6 !~ /\// ){

      if( $allowed_address_v6 !~ $IPV6_REGEX ){
        print_stdout "Invalid -allowed_address_v6 specified. $allowed_address_v6\n";
        return;
      }
            
    }else{

      my @tmp = split(/\//,$allowed_address_v6);
      my $tmpnum = @tmp;

      if( $tmpnum != 2 || $tmp[0] !~ $IPV6_REGEX ||
          $tmp[1] =~ /\D+/ ||
          $tmp[1] < 1 || $tmp[1] > 64 ){
        print_stdout "Invalid -allowed_address_v6 specified. $allowed_address_v6\n";
        return;
      }
      
      $allowed_address_v6_netmask = $tmp[1];
    }
  }
  
  if ( !defined($mng_port) ) {
    $mng_port = '32501';
  }
  

  need_admin_password();

  
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_update_global_config" );
  $root->setAttributeNode($attr_action);

  my $rhp_config = $doc->createElement("rhp_config");
  $root->addChild($rhp_config);
  
  my $admin_services = $doc->createElement("admin_services");
  $rhp_config->addChild($admin_services);

  my $admin_service = $doc->createElement("admin_service");
  $admin_services->addChild($admin_service);

  my $attr_id = $doc->createAttribute( "id", "1" );
  $admin_service->setAttributeNode($attr_id);

  if ( defined($mng_address_v4) ) {
    my $attr_mng_addr = $doc->createAttribute( "address_v4", $mng_address_v4 );
    $admin_service->setAttributeNode($attr_mng_addr);
  }

  if ( defined($mng_address_v6) ) {
    my $attr_mng_addr = $doc->createAttribute( "address_v6", $mng_address_v6 );
    $admin_service->setAttributeNode($attr_mng_addr);
  }
  
  my $attr_mng_port = $doc->createAttribute( "port", $mng_port );
  $admin_service->setAttributeNode($attr_mng_port);

  my $attr_mng_protocol = $doc->createAttribute( "protocol", "http" );
  $admin_service->setAttributeNode($attr_mng_protocol);


  if( defined($allowed_address_v4) ){

    my $client_acl = $doc->createElement("client_acl");
    $admin_service->addChild($client_acl);
    
    my $attr_cacl_priority = $doc->createAttribute( "priority", "10" );
    $client_acl->setAttributeNode($attr_cacl_priority);

    my $attr_cacl_type;
    if( !defined($allowed_address_v4_netmask) ){ 
      $attr_cacl_type = $doc->createAttribute( "type", "ipv4" );
    }else{
      $attr_cacl_type = $doc->createAttribute( "type", "ipv4_subnet" );
    }
    $client_acl->setAttributeNode($attr_cacl_type);
    
    my $attr_cacl_match = $doc->createAttribute( "match", $allowed_address_v4 );
    $client_acl->setAttributeNode($attr_cacl_match);
      
    my $attr_cacl_rlm = $doc->createAttribute( "vpn_realm", "0" );
    $client_acl->setAttributeNode($attr_cacl_rlm);
  }
  
  if( defined($allowed_address_v6) ){

    my $client_acl = $doc->createElement("client_acl");
    $admin_service->addChild($client_acl);
    
    my $attr_cacl_priority = $doc->createAttribute( "priority", "10" );
    $client_acl->setAttributeNode($attr_cacl_priority);

    my $attr_cacl_type;
    if( !defined($allowed_address_v6_netmask) ){ 
      $attr_cacl_type = $doc->createAttribute( "type", "ipv6" );
    }else{
      $attr_cacl_type = $doc->createAttribute( "type", "ipv6_subnet" );
    }
    $client_acl->setAttributeNode($attr_cacl_type);
    
    my $attr_cacl_match = $doc->createAttribute( "match", $allowed_address_v6 );
    $client_acl->setAttributeNode($attr_cacl_match);
      
    my $attr_cacl_rlm = $doc->createAttribute( "vpn_realm", "0" );
    $client_acl->setAttributeNode($attr_cacl_rlm);
  }


  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "web_mng_update: \n" . $doc->toString(1) . "\n";
  }


  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
    
  }

  bus_close($ua, $bus_session_id);

  return;
}

sub web_mng_reset {

  my $mng_address_v4 = '127.0.0.1';  
  my $mng_port = '32501';

  need_admin_password();

  
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_update_global_config" );
  $root->setAttributeNode($attr_action);

  my $rhp_config = $doc->createElement("rhp_config");
  $root->addChild($rhp_config);
  
  my $admin_services = $doc->createElement("admin_services");
  $rhp_config->addChild($admin_services);

  my $admin_service = $doc->createElement("admin_service");
  $admin_services->addChild($admin_service);

  my $attr_id = $doc->createAttribute( "id", "1" );
  $admin_service->setAttributeNode($attr_id);

  my $attr_mng_addr = $doc->createAttribute( "address_v4", $mng_address_v4 );
  $admin_service->setAttributeNode($attr_mng_addr);
  
  my $attr_mng_port = $doc->createAttribute( "port", $mng_port );
  $admin_service->setAttributeNode($attr_mng_port);

  my $attr_mng_protocol = $doc->createAttribute( "protocol", "http" );
  $admin_service->setAttributeNode($attr_mng_protocol);


  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "web_mng_reset: \n" . $doc->toString(1) . "\n";
  }


  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
    
  }

  bus_close($ua, $bus_session_id);

  return;
}

sub admin_update {
  
  my ( $admin_id,$admin_password ) = @_;

  if ( !defined($realm) ) {
    $realm = "0";
  }

  if ( !defined($admin_id) ) {
    print_stdout " -admin_id not specified. \n";
    print_usage("admin_update");
    return;
  }
  
  if ( !defined($admin_password) ) {

    $admin_password = enter_password("new admin password",1);
    if( !defined($admin_password) ){    
      print_stdout "Please specify -admin_password or a correct password. \n";
      print_usage("admin_update");
      return;
    }
  }


  need_admin_password();

  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_update_admin" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $admin_elm = $doc->createElement("admin");
  $root->addChild($admin_elm);

  my $attr_id = $doc->createAttribute( "id", $admin_id );
  $admin_elm->setAttributeNode($attr_id);

  my $attr_key = $doc->createAttribute( "key", $admin_password );
  $admin_elm->setAttributeNode($attr_key);



  if( $show_xml ){
    print_stdout "vpn_admin_update: \n" . $doc->toString(1) . "\n";
  }
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }
  
  my $req = create_bus_write_req($bus_session_id);

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";

  } else {

    if ( $admin_id eq $admin ) {
      $auth_basic_key = LWP::Authen::Basic->auth_header( $admin, $admin_password );
    }
  }

  bus_close($ua, $bus_session_id);

  return;
}

sub admin_delete {
  
  my ( $admin_id ) = @_;

  if ( !defined($admin_id) ) {
    print_stdout " -admin_id not specified. \n";
    print_usage("admin_delete");
    return;
  }


  need_admin_password();

  if ( $admin_id eq $admin || $admin_id eq "admin" ) {
    print_stdout " -admin_id is the same id as 'admin' or -admin's value.\n";
    print_usage("admin_delete");
    return;
  }


  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_delete_admin" );
  $root->setAttributeNode($attr_action);

  my $admin_elm = $doc->createElement("admin");
  $root->addChild($admin_elm);

  my $attr_id = $doc->createAttribute( "id", $admin_id );
  $admin_elm->setAttributeNode($attr_id);

  if( $show_xml ){
    print_stdout "admin_delete: \n" . $doc->toString(1) . "\n";
  }

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }
  
  my $req = create_bus_write_req($bus_session_id);

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);

  return;
}

sub admin_show {

  need_admin_password();
  
  open_stdout_pipe();
  
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_enum_admin" );
  $root->setAttributeNode($attr_action);

  if( $show_xml ){
    print_stdout "admin_show: \n" . $doc->toString(1) . "\n";
  }

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }
  
  my $req = create_bus_write_req($bus_session_id);

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

  }else{

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout $resp_doc->toString(1);
    }
    
    foreach $EAELM ( $resp_doc->getElementsByTagName('admin') ) {
      
      print_stdout "Name: " . EA('id') . "\tRealm: " . EA('vpn_realm') . "\n";
      
    }  
  }

  bus_close($ua, $bus_session_id);

  return;
}

sub status_bridge {
  
  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("bridge");
    return;
  }

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",        "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_bridge", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_bridge: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

    }else{

      print_stdout "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_bridge: \n" . $resp_doc->toString(1) . "\n";
    }

    my $br_idx = 0;
    foreach $EAELM ( $resp_doc->getElementsByTagName('bridge') ) {

      if ( !$detail ) {

        print_stdout " \[$br_idx\] " . EA('dest_mac') . "  " . EA('side');

      } else {

        if ( !defined(EA('peerid')) ) {
          print_stdout " \[$br_idx\] " . EA('dest_mac') . " " . EA('side');
        } else {
          print_stdout " \[$br_idx\] " . EA('dest_mac') . " " . EA('side') . "     " . EA('peerid') . "(" . EA('peerid_type') . ")";
        }

        if ( !defined(EA('static_cache')) ) {
          print_stdout " dynamic";
        } else {
          print_stdout " " . EA('static_cache');
        }

        print_stdout " Elapsed(" . EA('time_elapsed') . ")";
      }

      print_stdout "\n";
      $br_idx++;
    }
  }
  
  return;
}

sub status_neigh {

  my ($ipver) = @_;

  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("arp");
    return;
  }

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",       "vpn_realm", "ip_version");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_neigh", $realm,      $ipver);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_arp: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
      

    }else{

      print_stdout "No information found.\n";      
    }

  } else {
    
    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_arp: \n" . $resp_doc->toString(1) . "\n";
    }
    
    my $tag;
    if( $ipver eq "ipv4" ){
      print_stdout "\[ARP table\] Rlm($realm)\n";
      $tag = "arp";
    }elsif( $ipver eq "ipv6" ){
      print_stdout "\[Neigh table\] Rlm($realm)\n";
      $tag = "ipv6_nd";
    }
    
    my $br_idx = 0;
    foreach $EAELM ( $resp_doc->getElementsByTagName($tag) ) {

      if ( !$detail ) {

        print_stdout "\[$br_idx\] " . EA('dest_addr') . " " . EA('dest_mac') . " " . EA('side');

      } else {

        if ( !defined(EA('eap_peer_id')) ) {
          if ( !defined(EA('peerid')) ) {
            print_stdout " \[$br_idx\] " . EA('dest_addr') . " " . EA('dest_mac') . " " . EA('side');
          } else {
            print_stdout " \[$br_idx\] " . EA('dest_addr') . " " . EA('dest_mac') . " " . EA('side') . " " . EA('peerid') . "(" . EA('peerid_type') . ")";
          }
        }else{
          print_stdout " \[$br_idx\] " . EA('dest_addr') . " " . EA('dest_mac') . " " . EA('side') . " " . EA('eap_peer_id') . "(eap)";
        }
        
        if ( !defined(EA('static_cache')) ) {
          print_stdout " dynamic";
        } else {
          print_stdout " " . EA('static_cache');
        }

        print_stdout " Elapsed(" . EA('time_elapsed') . ")";
      }

      print_stdout "\n";
      $br_idx++;
    }
  }

  return;
}

sub status_route_maps {

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_enum_route_maps");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_route_maps: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
      

    }else{

      print_stdout "No information found.\n";      
    }

  } else {
    
    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_route_maps: \n" . $resp_doc->toString(1) . "\n";
    }
        
    my $br_idx = 0;
    foreach $EAELM ( $resp_doc->getElementsByTagName("route_map") ) {
      
      my $gw = "N/A";
      my $oif_name = "N/A";
      my $oif_index = "-";
      
      if ( defined(EA('gateway')) ) {
        $gw = EA('gateway');
      }

      if ( defined(EA('oif_name')) ) {
        $oif_name = EA('oif_name');
      }

      if ( defined(EA('oif_index')) ) {
        $oif_index = EA('oif_index');
      }

      if ( !$detail ) {
        print_stdout " \[$br_idx\] " . EA('destination') . " " . $gw . " " . $oif_name . "(" . $oif_index . ")";
      }else{

        if( $br_idx == 0 ){
          print_stdout "     Destination   Gateway   Out-I/F   Type   Metric\n";
        }

        print_stdout " \[$br_idx\] " . EA('destination') . " " . $gw . " " . $oif_name . "(" . $oif_index . ") " . EA('type') . ":" . EA('rtn_type') . " " . EA('metric');
      }
              
      print_stdout "\n";
      $br_idx++;
    }
  }

  return;
}

sub status_ip_route_table {

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_ip_routing_table");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_ip_routing_table: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
      

    }else{

      print_stdout "No information found.\n";      
    }

  } else {
    
    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_ip_routing_table: \n" . $resp_doc->toString(1) . "\n";
    }

        
    my $br_idx = 0;
    
    if ( $detail ) {
    
      foreach $EAELM ( $resp_doc->getElementsByTagName("ip_routing_bucket") ) {
        
        if( $br_idx == 0 ){
          print_stdout "\n";
        }
        
        print_stdout " \[$br_idx\] " . EA('ip_version') .  " Prefix:" . EA('prefix_len') . " Entries:" . EA('entries_num') . " Bucket Size:" . EA('bucket_size');
        print_stdout " Mask: " . EA('netmask') . " Rehashed:" . EA('rehashed');
                
        print_stdout "\n";
        $br_idx++;
      }
        
      print_stdout "\n";
    }
    
    $br_idx = 0;
    my $prefix_len = -1;
    my $addr_family = undef;
    foreach $EAELM ( $resp_doc->getElementsByTagName("ip_routing_entry") ) {
      
      my $gw = "N/A";
      my $oif_name = "N/A";
      my $oif_index = "-";
      my $out_rlm = "-";
      
      if( ($prefix_len > -1 && $prefix_len != EA('prefix_len')) ||
          (defined($addr_family) && $addr_family ne EA('ip_version')) ){
        print_stdout "\n";
      }
      
      if ( defined(EA('gateway')) ) {
        $gw = EA('gateway');
      }

      if ( defined(EA('oif_name')) ) {
        $oif_name = EA('oif_name');
      }

      if ( defined(EA('oif_index')) ) {
        $oif_index = EA('oif_index');
      }

      if ( defined(EA('out_realm_id')) ) {
        $out_rlm = EA('out_realm_id');
      }

      if ( !$detail ) {
        print_stdout " \[$br_idx\] " . EA('destination') . " " . $gw . " " . $oif_name . "(" . $oif_index . ")";
      }else{

        if( $br_idx == 0 ){
          print_stdout "\n   Prefix  Destination  Gateway  Out-I/F  Out-Rlm  Type    Metric\n";
        }

        print_stdout " \[$br_idx\] " . EA('prefix_len') . " " . EA('destination') . " " . $gw . " " . $oif_name . "(" . $oif_index . ") " . $out_rlm . " " . EA('type') . ":" . EA('rtn_type') . " " . EA('metric');
      }
              
      print_stdout "\n";
      $br_idx++;
      
      $prefix_len = EA('prefix_len');
      $addr_family = EA('ip_version');
    }
  }

  return;
}

sub status_ip_route_cache {

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_ip_routing_cache");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_ip_route_cache: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
      

    }else{

      print_stdout "No information found.\n";      
    }

  } else {
    
    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_ip_route_cache: \n" . $resp_doc->toString(1) . "\n";
    }
        
    my $br_idx = 0;
    foreach $EAELM ( $resp_doc->getElementsByTagName("ip_routing_cache") ) {
      
      my $out_rlm = "-";

      if ( defined(EA('out_realm_id')) ) {
        $out_rlm = EA('out_realm_id');
      }

      print_stdout " \[$br_idx\] " . EA('src_address') . " -> " . EA('dst_address') . " Next-Hop:" . EA('next_hop_address') . " Out-Rlm:" . $out_rlm;
      if( $detail ){
        print_stdout " Elapsed:" . EA('elapsed') . " Used:" . EA('used');  
      }
              
      print_stdout "\n";
      $br_idx++;
    }
  }

  return;
}

sub status_nhrp_cache {

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_nhrp_cache");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_nhrp_cache: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
      

    }else{

      print_stdout "No information found.\n";      
    }

  } else {
    
    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_nhrp_cache: \n" . $resp_doc->toString(1) . "\n";
    }
        
    my $br_idx = 0;
    foreach $EAELM ( $resp_doc->getElementsByTagName("nhrp_cache") ) {
      
      my $nat_addr = "N/A";
      
      if ( defined(EA('nat_addr_ip_version')) ) {
        $nat_addr = EA('nat_addr');
      }

      if ( !$detail ) {
        print_stdout " \[$br_idx\] Rlm:" . EA('vpn_realm_id') . " " . EA('protocol_addr') . " " . EA('nbma_addr');
        if( $nat_addr ne "N/A" ){
          print_stdout " NAT:" . $nat_addr;
        }
      }else{

        if( $br_idx == 0 ){
          print_stdout "\n   Realm  Protocol  NBMA  NAT  Dmy-MAC  VPN-UID  Elapsed  Rx-MTU  Rx-Hold-Time  Unique\n";
        }

        print_stdout " \[$br_idx\] " . EA('vpn_realm_id') . " " . EA('protocol_addr') . " " . EA('nbma_addr') . " " 
                     . $nat_addr . " " . EA('vpn_dummy_mac') . " " . EA('vpn_unique_id') . " " . EA('elapsed') . " "
                     . EA('rx_mtu') . " " . EA('rx_hold_time') . " " . EA('uniqueness');
      }
              
      print_stdout "\n";
      $br_idx++;
    }
  }

  return;
}

sub cfg_archive_extract {

  my ( $arch_password, $file ) = @_;
  
  if( !defined($file) ){
    print_stdout "Please specify a configuration archive(*.rcfg).\n";
    print_usage("cfg-archive-extract");
    return;
  }

  if( ! -e "./$file" ){
    print_stdout "./$file does not exist.\n";
    return;
  }
  
  if( !defined($arch_password) ){

    $arch_password = enter_password("archive's password",0);
    if( !defined($arch_password) ){    
      print_stdout "Please specify a password to extract the configuration archive($file).\n";
      print_usage("cfg-archive-extract");
      return;
    }
  }

  if( ! -e "./cfg-archive" ){
    if( ! mkdir("./cfg-archive",0700) ){
      print_stdout "Failed to make directory ./cfg-archive.\n";  
      return;
    }
  }

  if( ! -e "./cfg-archive/rhpmain" ){
    if( ! mkdir("./cfg-archive/rhpmain",0700) ){
      print_stdout "Failed to make directory ./cfg-archive/rhpmain.\n";  
      return;
    }
  }

  if( ! -e "./cfg-archive/rhpprotected" ){
    if( ! mkdir("./cfg-archive/rhpprotected",0700) ){
      print_stdout "Failed to make directory ./cfg-archive/rhpprotected.\n";  
      return;
    }
  }

  system("rm -f ./cfg-archive/rhpmain/*");
  system("rm -f ./cfg-archive/rhpprotected/*");
  system("rm -f ./cfg-archive/*");

    
  if( system("openssl enc -d -base64 -in $file -out ./cfg-archive/tmp0.tar") ){
    print_stdout "[ERROR] Fail to decrypt the configuraiton archive.(1)\n";
    return;
  }

  if( system("tar x -f ./cfg-archive/tmp0.tar -C ./cfg-archive") ){
    print_stdout "[ERROR] Fail to extract the configuraiton archive.(1)\n";
    return;
  }
  
  if( system("openssl enc -d -aes256 -in ./cfg-archive/rockhopper_main.rcfg -out ./cfg-archive/rockhopper_main.tgz -pass pass:$arch_password") ){
    print_stdout "[ERROR] Fail to decrypt the configuraiton archive.(2)\n";
    return;
  }
  
  if( system("openssl enc -d -aes256 -in ./cfg-archive/rockhopper_syspxy.rcfg -out ./cfg-archive/rockhopper_syspxy.tgz -pass pass:$arch_password") ){
    print_stdout "[ERROR] Fail to decrypt the configuraiton archive.(3)\n";
    return;
  }

  if( system("tar xz -f ./cfg-archive/rockhopper_main.tgz -C ./cfg-archive/rhpmain") ){
    print_stdout "[ERROR] Fail to extract the configuraiton archive.(2)\n";
    return;
  }

  if( system("tar xz -f ./cfg-archive/rockhopper_syspxy.tgz -C ./cfg-archive/rhpprotected") ){
    print_stdout "[ERROR] Fail to extract the configuraiton archive.(3)\n";
    return;
  }

  system("rm -f ./cfg-archive/*.tgz");
  system("rm -f ./cfg-archive/*.rcfg");
  system("rm -f ./cfg-archive/*.tar");

  print_stdout "\n[CAUTION]\n";
  print_stdout " All files are successfully extracted into ./cfg-archive.\n";
  print_stdout " These files include secret keys and other important files.\n\n";
  
  return;
}

sub cfg_archive_save_cb {
  
  my ($bus_session_id, $cb_ctx_ref, $resp) = @_;
  my $ret = 2;
    
  my $parser   = XML::LibXML->new;
  my $resp_doc = $parser->parse_string( $resp->decoded_content );

  if( $show_xml ){
    print_stdout "cfg_archive_save_cb: \n" . $resp_doc->toString(1) . "\n";
  }
    
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_http_bus_record') ) {

    my $rec_action = EA('action');
#   print_stdout "Rec_action: $rec_action\n";

    if ($rec_action eq "config_archive_save_done" ) {

#     print_stdout "Config archive is successfully saved.\n";
      $ret = 1;
      last;
        
    }else{
       
#     print_stdout "cfg_archive_save_cb: Unknown action: $rec_action\n";
      $ret = 2;
    }
  }
  
  return $ret;    
}

sub cfg_archive_save {
  
  my ( $arch_password, $file ) = @_;

  if ( !defined($arch_password) ) {

    $arch_password = enter_password("archive's password",1);
    if( !defined($arch_password) ){    
      print_stdout "Please specify -archive_password or  a correct password to\n";
      print_stdout "generate configuration archive.\n";
      print_usage("cfg-archive-save");
      exit;
    }
  }

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",             "password");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_backup_save", $arch_password);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "cfg_archive_save: \n" . $doc->toString(1) . "\n";
  }


  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
    

    bus_close($ua, $bus_session_id);

  } else {

    print_stdout "Generating configuration's archive...\n";

    my $th = bus_read_begin_thread($bus_session_id,\&cfg_archive_save_cb,undef);
    $th->join();

    bus_close($ua, $bus_session_id);
    
    
    my $res = 0;
    my $arc_url = 'http://' . $address . ':' . $port . '/protected/config/rockhopper.rcfg';
    my $arc_req = HTTP::Request->new( GET => $arc_url );
    
    $arc_req->header( "Accept"         => 'application/octet-stream' );
    $arc_req->header( "Accept-Charset" => 'utf-8' );
    $arc_req->header( "X-Rhp-Authorization"  => $auth_basic_key );
    $arc_req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
    
    if( $show_xml ){
      print_stdout "cfg_archive_save: \n" . $arc_req->as_string() . "\n";
    }
    
    my $arc_resp = $ua->request($arc_req);
    
    if ( $arc_resp->is_success ) {
      
      if( !defined($file) ){
        $file = "rockhopper.rcfg"
      }
  
      if ( !open( CONFIG_ARCH, "> ./$file" ) ) {
        print_stdout "Can't open $file.\n";
      } else {
        print CONFIG_ARCH $arc_resp->decoded_content;
        close(CONFIG_ARCH);
      }
        
      $res = 1;

    }else{
      
      print_stdout "ERROR: " . $arc_resp->status_line . "\n";
    }
    
    if( !$res ){
      print_stdout "Failed to show configuration's archive.\n";
    }else{
      print_stdout "Configuration's archive was saved as ./$file.\n";
    }
  }

  return;
}

sub cfg_archive_upload_cb {
  
  my ($bus_session_id, $cb_ctx_ref, $resp) = @_;
  my $ret = 2;
    
  my $parser   = XML::LibXML->new;
  my $resp_doc = $parser->parse_string( $resp->decoded_content );

  if( $show_xml ){
    print_stdout "cfg_archive_upload_cb: \n" . $resp_doc->toString(1) . "\n";
  }
    
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_http_bus_record') ) {

    my $rec_action = EA('action');
#    print_stdout "Rec_action: $rec_action\n";

    if ($rec_action eq "config_archive_restore_done" ) {

      sleep(2);
      print_stdout "\nThe configuration archive was successfully uploaded\n" .
            "and extracted. Please reboot system or restart\n" .
            "Rockhopper to actually apply the configuration.\n\n";
      $ret = 1;
      last;

    }elsif ($rec_action eq "config_archive_restore_error" ) {

      sleep(2);
      print_stdout "\nFailed to extract the configuration's archive.\n" .
            "Please specify a valid archive file and/or\n" .
            "a correct password.\n\n";
      $ret = 1;
      last;
        
    }else{
       
#      print_stdout "cfg_archive_upload_cb: Unknown action: $rec_action\n";
      $ret = 2;
    }
  }
  
  return $ret;    
}

sub cfg_archive_upload {
  
  my ( $arch_password, $file ) = @_;

  if( !defined($file) ){
    print_stdout "Please specify your saved archive file(*.rcfg).\n";
    print_usage("cfg-archive-upload");
    return;
  }

  if( !defined($arch_password) ){

    $arch_password = enter_password("archive's password",0);
    if( !defined($arch_password) ){    
      print_stdout "Please specify a password to extract configuration archive.\n";
      print_usage("cfg-archive-upload");
      return;
    }
  }


  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my @attr_names = ("version",  "service",    "action",               "upload_config_password");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_backup_restore", $arch_password);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "cfg_archive_upload: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

  } else {

    $req = create_post_req_upload_config_file($bus_session_id, $file);
    
    $resp = $ua->request($req);
  
    if ( !$resp->is_success ) {
  
      print_stdout "ERROR: /protected/config :" . $resp->status_line . " or no content.\n";
  
    } else {
  
      print_stdout "\nUploading the configuration's archive...\n";
  
      my $th = bus_read_begin_thread($bus_session_id,\&cfg_archive_upload_cb,undef);
      $th->join();      
    }
  }
  
  bus_close($ua, $bus_session_id);
  return;
}

sub status_address_pool {
  
  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("address-pool");
    return;
  }

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",             "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_address_pool", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_address_pool: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);
  
  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
      

    }else{

      print_stdout "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_address_pool: \n" . $resp_doc->toString(1) . "\n";
    }
    
    my $addr_pool_idx = 0;
    foreach $EAELM ( $resp_doc->getElementsByTagName('address_pool') ){
      
      my $assigned_addr_v4 = EA('assigned_addr_v4');
      my $assigned_addr_v6 = EA('assigned_addr_v6');
      my $peerid_type = EA('peerid_type');
      my $peerid = EA('peerid');
      my $alt_peerid_type = EA('alt_peerid_type');
      my $alt_peerid = EA('alt_peerid');
      my $eap_peerid = EA('eap_peer_identity');
      
      my $peerid_type1 = $peerid_type;
      my $peerid1 = $peerid;
      if( ($peerid_type eq "ipv4" || $peerid_type eq "ipv6") ){
        
        if( defined($alt_peerid_type) && defined($alt_peerid) ){

          $peerid_type1 = $alt_peerid_type;
          $peerid1 = $alt_peerid;

        }elsif( defined($eap_peerid) ){

          $peerid_type1 = "eap";
          $peerid1 = $eap_peerid;
        }
      }
      
      if( !defined($assigned_addr_v4) ){
        $assigned_addr_v4 = "N/A";        
      }

      if( !defined($assigned_addr_v6) ){
        $assigned_addr_v6 = "N/A";        
      }

      if( $detail ){
        
        print_stdout "  [$addr_pool_idx\] " . $peerid1 . "(" . $peerid_type1 . ")\n   IPv4: " . $assigned_addr_v4 . " IPv6: " . $assigned_addr_v6;
        print_stdout "\n";

        print_stdout "   Peer ID: " . $peerid . "(" . $peerid_type . ")\n";
        
        if( defined($alt_peerid) ){
          print_stdout "   Peer ID(Alt): " . $alt_peerid . "(" . $alt_peerid_type . ")\n";
        }

        if( defined($eap_peerid) ){
          print_stdout "   EAP ID: " . $eap_peerid . "\n";
        }

        print_stdout "   Status:";        
        if ( defined(EA('expire')) && EA('expire') == "0" ) {
          print_stdout " In-Use";
        } else {
          print_stdout " Cached (Expire:" . EA('expire') . ")";
        }
        print_stdout "\n";

      }else{
        
        print_stdout "  [$addr_pool_idx\] ";
        if ( defined(EA('expire')) && EA('expire') == "0" ) {
          print_stdout " U ";
        } else {
          print_stdout " C ";
        }
        print_stdout $peerid1 . "(" . $peerid_type1 . ") IPv4: " . $assigned_addr_v4 . " IPv6: " . $assigned_addr_v6;
      }
      
      print_stdout "\n";
      $addr_pool_idx++;
    }
  }

  return;
}

# <?xml version="1.0"?><rhp_http_bus_request version="1.0" service="ui_http_vpn" action="flush_address_pool" vpn_realm="10"/>
sub flush_address_pool {
  
  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("address-pool-flush");
    return;
  }

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",       "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","flush_address_pool", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "flush_address_pool: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}


sub status_source_if {
  
  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("source-if");
    return;
  }

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",                   "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_enum_src_interfaces", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_source_if: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);
  
  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
      

    }else{

      print_stdout "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_source_if: \n" . $resp_doc->toString(1) . "\n";
    }
    
    my $src_if_idx = 0;
    foreach $EAELM ( $resp_doc->getElementsByTagName('interface') ){

      my $ifelm = $EAELM;

      my $ipver = EA('ip_version');
      if( $ipver eq "all" ){
        $ipver = "ipv4/ipv6";
      }
      
      my $is_def_route = "";
      if( EA('is_def_route') eq "1" ){
        $is_def_route = ", default route";
      }

      print_stdout " [$src_if_idx\] " . EA('name') . " (" . EA('status') . ", " . $ipver . $is_def_route . ")\n";
      print_stdout "  MAC: " . EA('mac') . " MTU: " . EA('mtu') . "\n";
      print_stdout "  Priority: " . EA('priority') . ", Cfg-priority: " . EA('cfg_priority') . "\n";

      my $if_addr_idx = 0;      
      foreach $EAELM ( $ifelm->getElementsByTagName('interface_address') ){
        if( defined(EA('address_v4')) ){
          if( $if_addr_idx == 0 ){
            print_stdout "  IP: " . EA('address_v4') . "/" . EA('prefix_length') . "\n";
          }else{
            print_stdout "      " . EA('address_v4') . "/" . EA('prefix_length') . "\n";
          }
          $if_addr_idx++;
        }
      }    

      foreach $EAELM ( $ifelm->getElementsByTagName('interface_address') ){
        if( defined(EA('address_v6')) ){
          if( $if_addr_idx == 0 ){
            print_stdout "  IP: " . EA('address_v6') . "/" . EA('prefix_length') . "\n";
          }else{
            print_stdout "      " . EA('address_v6') . "/" . EA('prefix_length') . "\n";
          }
          $if_addr_idx++;
        }
      }    

      print_stdout "\n";
      $src_if_idx++;
    }
    
    if( $src_if_idx < 1 ){
      print_stdout "No information found.\n";      
    }
  }

  return;
}

sub flush_bridge {
  
  if( !defined($realm) ){
    $realm = "0";    
  }

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",       "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","flush_bridge", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "flush_bridge: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub flush_ip_route_cache {
  
  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","flush_ip_route_cache");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "flush_ip_route_cache: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub status_if {
  
  my ( $flag ) = @_;

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",                 "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_enum_interfaces", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_if: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
      

    }else{

      print_stdout "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "status_if: \n" . $resp_doc->toString(1) . "\n";
    }
    
    
    my $if_idx = 0;
    if( !$flag ){
      
      foreach $EAELM ( $resp_doc->getElementsByTagName('interface') ) {

        my $ifelm = $EAELM;

        if ( !defined(EA('vpn_realm')) || EA('vpn_realm') eq '0' ) {

          print_stdout "\[$if_idx\] " . EA('name') . ":";
          if( defined(EA('used')) && EA('used') > 0 ){
            print_stdout " *USED"
          }
          print_stdout "\n";
          if ( defined(EA('mac')) ) {
            print_stdout " MAC: " . EA('mac') . " MTU(" . EA('mtu') . ") Index(" . EA('id') . ")";
          }
          print_stdout "\n";
  
          my $ipstr = 0;
          foreach $EAELM ( $ifelm->getElementsByTagName('interface_address') ) {
            if ( defined(EA('address_v4')) ) {
              if( $ipstr == 0 ){
                print_stdout " IP:" . EA('address_v4') . "/" . EA('prefix_length') . "\n";
              }else{
                print_stdout "    " . EA('address_v4') . "/" . EA('prefix_length') . "\n";
              }
              $ipstr++;
            }
          }
          
          foreach $EAELM ( $ifelm->getElementsByTagName('interface_address') ) {
            if ( defined(EA('address_v6')) ) {
              if( $ipstr == 0 ){
                print_stdout " IP:" . EA('address_v6') . "/" . EA('prefix_length') . "\n";
              }else{
                print_stdout "    " . EA('address_v6') . "/" . EA('prefix_length') . "\n";
              }
              $ipstr++;
            }
          }
          print_stdout "\n";
          
          $if_idx++;
        }
      }
      
    }else{
  
      $if_idx = 0;
      foreach $EAELM ( $resp_doc->getElementsByTagName('interface') ) {

        my $ifelm = $EAELM;
  
        if( defined($realm) && defined(EA('vpn_realm')) && 
            EA('vpn_realm') ne "$realm" ){
          next;
        }
        
        if ( !defined(EA('vpn_realm')) || EA('vpn_realm') ne '0' ) {
    
          print_stdout "\[$if_idx\] ". EA('name') . ": Realm(" . EA('vpn_realm') . ")  " . EA('address_type') . "\n";
          if ( defined(EA('mac')) ) {
            print_stdout " MAC: " . EA('mac') . " MTU(" . EA('mtu') . ") Index(" . EA('id') . ")\n";
          }
          
          if ( defined(EA('v6_aux_lladdr_mac')) ) {            
            print_stdout " Aux-MAC: " . EA('v6_aux_lladdr_mac') . "  Aux-IPv6: " . EA('v6_aux_lladdr_lladdr') . "\n";
          }

          print_stdout " Fixed MTU(" . EA('fixed_mtu') . ") Default MTU(" . EA('default_mtu') . ")\n";
          
          my $ipstr = 0;
          foreach $EAELM ( $ifelm->getElementsByTagName('interface_address') ) {
            if ( defined(EA('address_v4')) ) {
              if( $ipstr == 0 ){
                print_stdout " IP:" . EA('address_v4') . "/" . EA('prefix_length') . "\n";
              }else{
                print_stdout "    " . EA('address_v4') . "/" . EA('prefix_length') . "\n";
              }
              $ipstr++;
            }
          }
            
          foreach $EAELM ( $ifelm->getElementsByTagName('interface_address') ) {
            if ( defined(EA('address_v6')) ) {
              if( $ipstr == 0 ){
                print_stdout " IP:" . EA('address_v6') . "/" . EA('prefix_length') . "\n";
              }else{
                print_stdout "    " . EA('address_v6') . "/" . EA('prefix_length') . "\n";
              }
              $ipstr++;
            }
          }
          
          if( defined(EA('bridge_name')) ){

            print_stdout " Bridge: " . EA('bridge_name') . "  MTU(" . EA('bridge_def_mtu') . ")\n";
            
            $ipstr = 0;
            foreach $EAELM ( $ifelm->getElementsByTagName('bridge_interface_address') ) {
              if ( defined(EA('address_v4')) ) {
                if( $ipstr == 0 ){
                  print_stdout " IP:" . EA('address_v4') . "\n";
                }else{
                  print_stdout "    " . EA('address_v4') . "\n";
                }
                $ipstr++;
              }
            }
              
            foreach $EAELM ( $ifelm->getElementsByTagName('bridge_interface_address') ) {
              if ( defined(EA('address_v6')) ) {
                if( $ipstr == 0 ){
                  print_stdout " IP:" . EA('address_v6') . "\n";
                }else{
                  print_stdout "    " . EA('address_v6') . "\n";
                }
                $ipstr++;
              }
            }
          }
          print_stdout "\n";

          $if_idx++;
        }
      }
    }
    
    if( $if_idx < 1 ){
      print_stdout "No information found.\n";      
    }
  }

  return;
}

sub rand_key {
  my ( $key_len ) = @_;
  my $cmd = "cat /dev/urandom | tr -dc '[:alnum:]' | head -c " . $key_len;
  return `$cmd`;
}

sub peer_key_update {
  
  my ( $key, $keygen ) = @_;

  if ( !defined($realm) ) {

    print_stdout "-realm not specified.\n";
    print_usage("peer-key-update");
    return;
  }

  if( !defined($peerid) || !defined($peerid_type) ){
    
    print_stdout "-peerid_type or -peerid not specified.\n";
    print_usage("peer-key-update");
    return;
  }
  
  if ( ( $peerid_type ne "fqdn" ) && ( $peerid_type ne "email" ) && 
       ( $peerid_type ne "eap-mschapv2" ) && ( $peerid_type ne "any" ) ) {
      
    print_stdout "Invalid -peerid_type specified. : $peerid_type\n";
    print_usage("peer-key-update");
    return;
  }

  if( !defined($keygen) && !defined($key) ){

    $key = enter_password("new peer's key",1);
    if( !defined($key) ){    
      print_stdout "Please specify -key, -keygen or a correct password.\n";
      print_usage("peer-key-update");
      return;
    }
  }

  if( defined($keygen) ){    
    if( $keygen > 64 ){
      $keygen = 64;
    }elsif( $keygen < 4 ){
      $keygen = 4;
    }
    $key = rand_key($keygen);    
  }

  my $is_psk = 1;
  if( $peerid_type eq "psk-any" ){
    $peerid = "any";
  }elsif( $peerid_type eq "eap-mschapv2" ){
    $peerid_type = "mschapv2";
    $is_psk = 0;
  }


  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my $root_elm;
  my @attr_names = ("version",  "service",    "action",                    "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_update_peer_key_info", $realm);

  my $doc = create_bus_req_doc2(\@attr_names,\@attr_vals,\$root_elm);
  my $req = create_bus_write_req($bus_session_id);


  my $peer_elm = $doc->createElement("peer");
  $root_elm->addChild($peer_elm);

  my $attr_id_type = $doc->createAttribute( "id_type", $peerid_type );
  $peer_elm->setAttributeNode($attr_id_type);

  my $attr_id = $doc->createAttribute( "id", $peerid );
  $peer_elm->setAttributeNode($attr_id);

  my $peer_psk_elm = $doc->createElement("peer_psk");
  $peer_elm->addChild($peer_psk_elm);

  if( $is_psk ){

    my $attr_key = $doc->createAttribute( "key", $key );
    $peer_psk_elm->setAttributeNode($attr_key);

  }else{
    
    my $attr_key = $doc->createAttribute( "mschapv2_key", $key );
    $peer_psk_elm->setAttributeNode($attr_key);
  }
  
  if( $show_xml ){
    print_stdout "peer_key_update: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";

  }else{

    update_realm_state($bus_session_id);

    if( $keygen ){
      print_stdout "=\n";
      print_stdout "Peer ID Type:  " . $peerid_type . "\n";
      print_stdout "Peer ID:       " . $peerid . "\n";
      print_stdout "Generated key: " . $key  . "\n";
      print_stdout "=\n";
    }
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub peer_key_delete {

  if ( !defined($realm) ) {

    print_stdout "-realm not specified.\n";
    print_usage("peer-key-delete");
    return;
  }

  if( !defined($peerid) || !defined($peerid_type) ){
    
    print_stdout "-peerid_type or -peerid not specified.\n";
    print_usage("peer-key-delete");
    return;
  }
  
  if ( ( $peerid_type ne "fqdn" ) && ( $peerid_type ne "email" ) && 
       ( $peerid_type ne "eap-mschapv2" ) && ( $peerid_type ne "any" ) ) {
      
    print_stdout "Invalid -peerid_type specified. : $peerid_type\n";
    print_usage("peer-key-delete");
    return;
  }

  if( $peerid_type eq "psk-any" ){
    $peerid = "any";
  }elsif( $peerid_type eq "eap-mschapv2" ){
    $peerid_type = "mschapv2";
  }

  
  need_admin_password();


  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my $root_elm;
  my @attr_names = ("version",  "service",    "action",                    "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_delete_peer_key_info", $realm);

  my $doc = create_bus_req_doc2(\@attr_names,\@attr_vals,\$root_elm);
  my $req = create_bus_write_req($bus_session_id);


  my $peer_elm = $doc->createElement("peer");
  $root_elm->addChild($peer_elm);

  my $attr_id_type = $doc->createAttribute( "id_type", $peerid_type );
  $peer_elm->setAttributeNode($attr_id_type);

  my $attr_id = $doc->createAttribute( "id", $peerid );
  $peer_elm->setAttributeNode($attr_id);

  
  if( $show_xml ){
    print_stdout "peer_key_delete: \n" . $doc->toString(1) . "\n";
  }


  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";

  }else{
    
    update_realm_state($bus_session_id);
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub peer_key_show {

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",     "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_get", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "peer_key_show: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "peer_key_show: \n" . $resp_doc->toString(1) . "\n";
    }
    
    my @auth_elm = $resp_doc->getElementsByTagName('rhp_auth');
    if( scalar(@auth_elm) ){
      
      foreach $EAELM ( $auth_elm[0]->getElementsByTagName('vpn_realm') ){
  
        my $rlm_elm = $EAELM;
  
        print_stdout " *Realm(" . EA('id') . ")\n";
  
        my $id_idx = 0;      
        foreach $EAELM ( $rlm_elm->getElementsByTagName('peer') ){

          if( defined(EA('id_type')) && defined(EA('id')) ){

            print_stdout "\[$id_idx\] ID Type: " . EA('id_type') . "\tID: " . EA('id') . "\n";             
            $id_idx++;

          }else{
            
            if( $show_xml ){
              my $inv_id_type = "unknown";
              my $inv_id = "unknown";
              if( defined(EA('id_type')) ){
                $inv_id_type = EA('id_type');
              }
              if( defined(EA('id')) ){
                $inv_id = EA('id');
              }
              print_stdout "Invalid peer element: ID Type: " . $inv_id_type . " ID:" . $inv_id . "\n";
            }
          }
        }    
    
        print_stdout "\n";
      }
    }
  }

  return;
}

sub my_key_update {
  
  my ( $myid_type, $myid, $myid_cache_eap_key, $key, $keygen ) = @_;

  if ( !defined($realm) ) {

    print_stdout "-realm not specified.\n";
    print_usage("my-key-update");
    return;
  }

  if( !defined($myid) || !defined($myid_type) ){
    
    print_stdout "-myid_type or -myid not specified.\n";
    print_usage("my-key-update");
    return;
  }
  
  if ( ( $myid_type ne "fqdn" ) && ( $myid_type ne "email" ) && 
       ( $myid_type ne "eap-mschapv2" ) ) {
      
    print_stdout "Invalid -myid_type specified. : $myid_type\n";
    print_usage("my-key-update");
    return;
  }

  if( !defined($keygen) && !defined($key) ){
    
    $key = enter_password("new my key",1);
    if( !defined($key) ){    
      print_stdout "Plese specify -key, -keygen or a correct key.\n";
      print_usage("my-key-update");
      return;
    }
  }

  if( defined($keygen) ){    
    if( $keygen > 64 ){
      $keygen = 64;
    }elsif( $keygen < 4 ){
      $keygen = 4;
    }
    $key = rand_key($keygen);    
  }

  my $auth_method;
  if( $myid_type eq "eap-mschapv2" ){
    $auth_method = "eap";
    $myid_type = "mschapv2";
  }else{
    $auth_method = "psk";
  }


  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my $root_elm;
  my @attr_names = ("version",  "service",    "action",                    "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_update_my_key_info", $realm);

  my $doc = create_bus_req_doc2(\@attr_names,\@attr_vals,\$root_elm);
  my $req = create_bus_write_req($bus_session_id);


  my $my_auth_elm = $doc->createElement("my_auth");
  $root_elm->addChild($my_auth_elm);

  my $attr_auth_method = $doc->createAttribute( "auth_method", $auth_method );
  $my_auth_elm->setAttributeNode($attr_auth_method);

  my $attr_id_type = $doc->createAttribute( "id_type", $myid_type );
  $my_auth_elm->setAttributeNode($attr_id_type);

  my $attr_id = $doc->createAttribute( "id", $myid );
  $my_auth_elm->setAttributeNode($attr_id);

  if( $auth_method eq "eap" ){

    my $attr_cache_key;
    if( $cache_eap_key ){
      $attr_cache_key = $doc->createAttribute( "eap_sup_key_cached", "enable" );
    }else{
      $attr_cache_key = $doc->createAttribute( "eap_sup_key_cached", "disable" );
    }
    $my_auth_elm->setAttributeNode($attr_cache_key);
  }
  
  my $my_psk_elm = $doc->createElement("my_psk");
  $my_auth_elm->addChild($my_psk_elm);

  if( $auth_method eq "psk" ){

    my $attr_key = $doc->createAttribute( "key", $key );
    $my_psk_elm->setAttributeNode($attr_key);

  }elsif( $auth_method eq "eap" ){
    
    my $attr_key = $doc->createAttribute( "mschapv2_key", $key );
    $my_psk_elm->setAttributeNode($attr_key);

    my $attr_key_action = $doc->createAttribute( "key_update_action", "update" );
    $my_psk_elm->setAttributeNode($attr_key_action);
  }
  
  if( $show_xml ){
    print_stdout "my_key_update: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";

  }else{

    update_realm_state($bus_session_id);

    if( $keygen ){
      print_stdout "=\n";
      print_stdout "My ID Type:    " . $myid_type . "\n";
      print_stdout "My ID:         " . $myid . "\n";
      print_stdout "Generated key: " . $key  . "\n";
      print_stdout "=\n";
    }
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub my_key_delete {
  
  my ($myid_type, $cache_eap_key) = @_;

  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("my-key-delete");
    return;
  }

  if( !defined($myid_type) ){
    
    print_stdout "-myid_type not specified.\n";
    print_usage("my-key-delete");
    return;
  }
  
  if ( $myid_type ne "eap-mschapv2" ) {
      
    print_stdout "Invalid -myid_type specified. : $myid_type\n";
    print_usage("my-key-delete");
    return;
  }

  my $auth_method = "eap";
  $myid_type = "mschapv2";

  
  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my $root_elm;
  my @attr_names = ("version",  "service",    "action",                   "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_update_my_key_info", $realm);

  my $doc = create_bus_req_doc2(\@attr_names,\@attr_vals,\$root_elm);
  my $req = create_bus_write_req($bus_session_id);


  my $my_auth_elm = $doc->createElement("my_auth");
  $root_elm->addChild($my_auth_elm);

  my $attr_auth_method = $doc->createAttribute( "auth_method", $auth_method );
  $my_auth_elm->setAttributeNode($attr_auth_method);

  my $attr_id_type = $doc->createAttribute( "id_type", $myid_type );
  $my_auth_elm->setAttributeNode($attr_id_type);

  if( $auth_method eq "eap" ){

    my $attr_key_action = $doc->createAttribute( "key_update_action", "delete" );
    $my_auth_elm->setAttributeNode($attr_key_action);
  
    my $attr_cache_key;
    if( $cache_eap_key ){
      $attr_cache_key = $doc->createAttribute( "eap_sup_key_cached", "enable" );
    }else{
      $attr_cache_key = $doc->createAttribute( "eap_sup_key_cached", "disable" );
    }
    $my_auth_elm->setAttributeNode($attr_cache_key);
  }
  
  if( $show_xml ){
    print_stdout "my_key_delete: \n" . $doc->toString(1) . "\n";
  }


  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";

  }else{
    
    update_realm_state($bus_session_id);
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub my_key_show {

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",     "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_get", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "my_key_show: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "my_key_show: \n" . $resp_doc->toString(1) . "\n";
    }
    
    my @auth_elm = $resp_doc->getElementsByTagName('rhp_auth');
    if( scalar(@auth_elm) ){
      
      foreach $EAELM ( $auth_elm[0]->getElementsByTagName('vpn_realm') ){
  
        my $rlm_elm = $EAELM;
  
        print_stdout " *Realm(" . EA('id') . ")\n";
  
        my @my_auth_elm = $rlm_elm->getElementsByTagName('my_auth');
        if( scalar(@my_auth_elm) ){
        
          $EAELM = $my_auth_elm[0];
          
          print_stdout " Auth Method: " . EA('auth_method') . "\n";
          print_stdout " ID Type: " . EA('id_type') . "\n";
          if( defined(EA('id')) ){
            print_stdout " ID:      " . EA('id') . "\n";
          }
          print_stdout "\n";
                    
        }else{

          print_stdout "  No information found.\n";
        }
      }
    }
  }

  return;
}

sub show_cfg {

  need_admin_password();
  
  open_stdout_pipe();
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",     "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_get", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "show_cfg: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    print_stdout "\n\n" . $resp_doc->toString(1) . "\n\n";
  }

  return;
}

sub show_realm {

  need_admin_password();
  
  open_stdout_pipe();
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",           "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_enum_realms", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "show_cfg: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

  } else {

    my $parser = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "show_realm:\n" . $resp_doc->toString(1) . "\n\n";
    }
    
    foreach $EAELM ( $resp_doc->getElementsByTagName('vpn_realm') ){
  
      my $status = EA('status');
      if( !defined($status) ) {
        $status = "enable";
      }
      $status .= "d";
  
      if( $status eq "enabled" ){
        print_stdout " * ";
      }else{
        print_stdout " D ";
      }

      print_stdout "Realm:" . EA('id') . "  " . EA('name') . " [" . EA('mode') . "]\n";

      if( $detail ){
        print_stdout "    Status: " . $status . "\n";
        if( EA('description') ){
          print_stdout "    Description: " . EA('description') . "\n"; 
        }else{
          print_stdout "    Description: N/A\n"; 
        }  
        if( EA('created_local_time') ){
          print_stdout "    Created: " . EA('created_local_time') . "\n"; 
        }else{
          print_stdout "    Created: N/A\n"; 
        }
        if( EA('updated_local_time') ){
          print_stdout "    Updated: " . EA('updated_local_time') . "\n"; 
        }else{
          print_stdout "    Updated: N/A\n"; 
        }
      }
    }
  }

  return;
}

sub clear_all_conn {
  
  my ($type) = @_;
  
  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    if( $type eq "all" ){
      print_usage("clear-all-conn");
    }elsif( $type eq "dormant" ){
      print_usage("clear-dormant-conn")    ;
    }
    return;
  }

  
  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",       "vpn_realm", "type");
  my @attr_vals = ($rhp_version,"ui_http_vpn","vpn_clear_all", $realm, $type);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "clear_all_conn: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub clear_eap_key_cache {
  
  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("clear-eap-key-cache");
    return;
  }

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my @attr_names = ("version",  "service",    "action",                       "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","eap_sup_clear_user_key_cache", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "clear_eap_key_cache: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub reset_qcd_key {

  {
    print "\nDo you really reset a QCD key? [N/y]\n";
  
    my $ans = <STDIN>;
    chomp($ans);
    if ( $ans eq "y" || $ans eq "Y" ) {
    }else{
      return;
    }
  }

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my @attr_names = ("version",  "service",    "action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","ikev2_qcd_reset_key");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "reset_qcd_key: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }else{
    print "\nA new key is actually generated after you restart Rockhopper.\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub reset_sess_resume_key {

  {
    print "\nDo you really reset Session Resumption keys? [N/y]\n";
  
    my $ans = <STDIN>;
    chomp($ans);
    if ( $ans eq "y" || $ans eq "Y" ) {
    }else{
      return;
    }
  }

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my @attr_names = ("version",  "service",    "action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","ikev2_sess_resume_reset_key");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "reset_sess_resume_key: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }else{
    print "\nA new key is actually generated after you restart Rockhopper.\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub invalidate_sess_resume_tkts {

  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("invalidate-sess-resume-tkts");
    return;
  }

  {
    print "\nDo you really invalidate Session Resumption's tickets? [N/y]\n";
  
    my $ans = <STDIN>;
    chomp($ans);
    if ( $ans eq "y" || $ans eq "Y" ) {
    }else{
      return;
    }
  }

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action", "vpn_realm","state_action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_update_realm_state",$realm,"sess_resume_policy_index");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "invalidate_sess_resume_tkts: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}



sub rt_check_show_res {
  
  my ($vpn_uid,$bus_session_id) = @_;
    
  my $ua = LWP::UserAgent->new();

  my @attr_names = ("version",  "service",    "action",   "vpn_realm","peer_id_type","peer_id",  "vpn_unique_id");
  my @attr_vals = ($rhp_version,"ui_http_vpn","status_vpn",  $realm, $peerid_type,  $peerid, $vpn_uid);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "rt_check_cb: \n" . $doc->toString(1) . "\n";
  }
      
  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close( $ua, $bus_session_id );


  if ( !$resp->is_success || !$resp->decoded_content ) {
    
    if ( $resp->status_line !~ '404' ) {
        
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
    
    }else{
    
      print_stdout "No information found.\n";      
    }
    
  } else {
    
    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );
    
    if( $show_xml ){
      print_stdout "rt_check_cb: \n" . $resp_doc->toString(1) . "\n";
    }

    show_status_vpn_summary($resp_doc,0,1);
  }

  return;
}

sub rt_check_cb {
  
  my ($bus_session_id, $cb_ctx_ref, $resp) = @_;
  my $ret = 2;
    
  my $parser   = XML::LibXML->new;
  my $resp_doc = $parser->parse_string( $resp->decoded_content );

  if( $show_xml ){
    print_stdout "rt_check_cb: \n" . $resp_doc->toString(1) . "\n";
  }
    
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_http_bus_record') ) {

    my $rec_action = EA('action');
#   print_stdout "Rec_action: $rec_action\n";

    if ($rec_action eq "vpn_mobike_i_routability_check_start" ) {

      if( $show_xml ){
        print_stdout "Routability check process started.\n";
      }
      $ret = 2;
      
    }elsif ($rec_action eq "vpn_mobike_i_routability_check_finished" ) {

      print_stdout "Routability check process finished.\n";

      rt_check_show_res(EA('vpn_unique_id'),$bus_session_id);

      $ret = 1;
      last;
        
    }else{
       
#     print_stdout "rt_check_cb: Unknown action: $rec_action\n";
      $ret = 2;
    }
  }
  
  return $ret;    
}

sub rt_check {
  
  my($opr,$vpn_uid) = @_;

  if( !defined($opr) ||
      ($opr ne "restart" && $opr ne "show") ){
    print_stdout "rt-check operation(restart or show) not specified.\n\n";    
    print_usage("rt-check");
    return;
  }

  if ( !defined($realm) || 
       ((!defined($peerid_type) || !defined($peerid)) && !defined($vpn_uid)) ) {
    print_stdout "-realm, -peerid_type, -peerid or -uid not specified.\n";
    print_usage("rt-check");
    return;
  }

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  if( $opr eq "restart" ){

    my @attr_names = ("version",  "service",    "action",   "vpn_realm","peer_id_type","peer_id",  "vpn_unique_id");
    my @attr_vals = ($rhp_version,"ui_http_vpn","mobike_i_start_routability_check",  $realm,  $peerid_type,  $peerid, $vpn_uid);
  
    my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
    my $req = create_bus_write_req($bus_session_id);
  
    if( $show_xml ){
      print_stdout "rt_check: \n" . $doc->toString(1) . "\n";
    }
    $req->content( $doc->toString(0) );
  
    my $resp = $ua->request($req);
  
    if ( !$resp->is_success ) {
  
      if( $show_xml ){
        print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
      }
      
      print "Failed to start routability check.\n";
     
      bus_close( $ua, $bus_session_id );
      
    } else {
  
      print_stdout "Now routability check is ongoing. It may take several seconds...\n\n";
  
      my $th = bus_read_begin_thread($bus_session_id,\&rt_check_cb,undef);
      $th->join();
    }

  }elsif( $opr eq "show" ){
    
    rt_check_show_res(undef,$bus_session_id);
  }
  

  return;
}

sub show_global_cfg {

  need_admin_password();
  
  open_stdout_pipe();
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_get_global_config");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "show_global_cfg: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);


  if ( !$resp->is_success || !$resp->decoded_content ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    print_stdout $resp_doc->toString(1);
  }

  return;
}


my $my_cert_priv_key_password_u = undef;

sub my_cert_update_cb {
  
  my ($bus_session_id, $cb_ctx_ref, $resp) = @_;
  my $ret = 2;
    
  my $parser   = XML::LibXML->new;
  my $resp_doc = $parser->parse_string( $resp->decoded_content );

  if( $show_xml ){
    print_stdout "cfg_archive_upload_cb: \n" . $resp_doc->toString(1) . "\n";
  }
    
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_http_bus_record') ) {

    my $rec_action = EA('action');
#    print_stdout "Rec_action: $rec_action\n";

    if ($rec_action eq "config_cert_file_upload_done" ) {

      my $ua = LWP::UserAgent->new();

      my $root_elm;
      my @attr_names = ("version",  "service",    "action",                 "vpn_realm");
      my @attr_vals = ($rhp_version,"ui_http_vpn","config_update_cert_file", $realm);
    
      my $doc = create_bus_req_doc2(\@attr_names,\@attr_vals,\$root_elm);
      my $req = create_bus_write_req($bus_session_id);
    
      my $cert_store_elm = $doc->createElement("cert_store");
      $root_elm->addChild($cert_store_elm);
      
      if( defined($my_cert_priv_key_password_u) ){
        my $attr_password = $doc->createAttribute( "password", $my_cert_priv_key_password_u );
        $cert_store_elm->setAttributeNode($attr_password);
      }
        
      if( $show_xml ){
        print_stdout "my_cert_update_cb: \n" . $doc->toString(1) . "\n";
      }

      $req->content( $doc->toString(0) );

      my $resp = $ua->request($req);

      if ( !$resp->is_success ) {

        print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";

      }else{

        update_realm_state($bus_session_id);

        sleep(2);
      }  

      $ret = 1;
      last;

    }elsif ($rec_action eq "config_cert_file_upload_error" ) {

      sleep(2);
      print_stdout "\nFailed to upload the file(or files).\n" .
            "Please specify a valid file name(or names) and/or\n" .
            "a correct password(if needed).\n\n";
      $ret = 1;
      last;
        
    }else{
       
#      print_stdout "my_cert_update_cb: Unknown action: $rec_action\n";
      $ret = 2;
    }
  }
  
  return $ret;    
}

sub my_cert_update {

  my( $pkcs12_file, $pem_cert_file, $pem_priv_key_file, 
    $priv_key_password, $myid_type,$accept_expired_cert ) = @_;

  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("my-cert-update-pkcs12");
    print_usage("my-cert-update-pem");
    return;
  }
  
  
  if ( !defined($pkcs12_file) &&
       !defined($pem_cert_file) && !defined($pem_priv_key_file) ) {
    print_stdout "-pkcs12_file, -pem_cert_file or -pem_priv_key_file not specified.\n";
    print_usage("my-cert-update-pkcs12");
    print_usage("my-cert-update-pem");
    return;
  }

  if ( (defined($pem_cert_file) && !defined($pem_priv_key_file)) ||
       (!defined($pem_cert_file) && defined($pem_priv_key_file)) ) {
    print_stdout "-pem_cert_file or -pem_priv_key_file not specified.\n";
    print_usage("my-cert-update-pkcs12");
    print_usage("my-cert-update-pem");
    return;
  }

  if ( defined($pkcs12_file) && !-f $pkcs12_file ){
    print_stdout "-pkcs12_file: $pkcs12_file not found.\n";
    return;
  }
  
  if( defined($pem_cert_file) && !-f $pem_cert_file  ){
    print_stdout "-pem_cert_file: $pem_cert_file not found.\n";
    return;
  }

  if( defined($pem_priv_key_file) && !-f $pem_priv_key_file  ){
    print_stdout "-pem_priv_key_file: $pem_priv_key_file not found.\n";
    return;
  }

  if( !defined($priv_key_password) ){
    
    $priv_key_password = enter_password("private key's password",1);
     if( !defined($priv_key_password) ){    
      print_stdout "Please specify -priv_key_password or a correct password.\n";
      print_usage("my-cert-update-pkcs12");
      print_usage("my-cert-update-pem");
      return;
    }
  }
  $my_cert_priv_key_password_u = $priv_key_password;


  if( defined($accept_expired_cert) &&
      $accept_expired_cert ne "enable" && $accept_expired_cert ne "disable" ){
    print_stdout "Invalid -accept_expired_cert specified. : $accept_expired_cert\n";
    print_usage("my-cert-update-pkcs12");
    print_usage("my-cert-update-pem");
    return;
  }
  
  if( !defined($myid_type) ){
    
    $myid_type = "cert_auto";
    
  }else{
  
    if ( $myid_type eq "dn"  ){

      # OK..

    }elsif( $myid_type eq "san" ){
      
      $myid_type = "subjectAltName";

    }elsif( $myid_type eq "auto" ){

      $myid_type = "cert_auto";

    }else{

      print_stdout "Invalid -myid_type specified. : $myid_type\n";
      print_usage("my-cert-update-pkcs12");
      print_usage("my-cert-update-pem");
      return;
    }
  }
  
  my $auth_method = "rsa-sig";

  need_admin_password();


  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my $root_elm;
  my @attr_names = ("version",  "service",    "action",                    "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_update_my_key_info", $realm);

  my $doc = create_bus_req_doc2(\@attr_names,\@attr_vals,\$root_elm);
  my $req = create_bus_write_req($bus_session_id);


  my $my_auth_elm = $doc->createElement("my_auth");
  $root_elm->addChild($my_auth_elm);

  my $attr_auth_method = $doc->createAttribute( "auth_method", $auth_method );
  $my_auth_elm->setAttributeNode($attr_auth_method);

  my $attr_id_type = $doc->createAttribute( "id_type", $myid_type );
  $my_auth_elm->setAttributeNode($attr_id_type);

  my $attr_priv_key_pw_type = $doc->createAttribute( "upload_cert_file_password", $priv_key_password );
  $my_auth_elm->setAttributeNode($attr_priv_key_pw_type);

  if( defined($accept_expired_cert) ){
    my $attr_accept_expired_cert = $doc->createAttribute( "accept_expired_cert", $accept_expired_cert );
    $my_auth_elm->setAttributeNode($attr_accept_expired_cert);
  }

  if( $show_xml ){
    print_stdout "my_cert_update: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";

  }else{
    
    if( defined($pkcs12_file) ){
      
      $req = create_post_upload_my_cert_pkcs12($bus_session_id, $pkcs12_file);

    }elsif( defined($pem_cert_file) ){

      $req = create_post_upload_my_cert_pem($bus_session_id,$pem_cert_file,$pem_priv_key_file);
    } 
     
    $resp = $ua->request($req);
  
    if ( !$resp->is_success ) {
  
      print_stdout "ERROR: /protected/config :" . $resp->status_line . " or no content.\n";
  
    } else {
  
      my $th = bus_read_begin_thread($bus_session_id,\&my_cert_update_cb,undef);
      $th->join();      
    }
  }

  bus_close($ua, $bus_session_id);
  return;
}

# $xml_action: config_get_my_printed_cert, config_get_printed_ca_certs or config_get_printed_crls
# $cmd_str: my-cert-show, ca-cert-show or crl-show
sub cert_get_impl {
  
  my ( $xml_action, $cmd_str, $need_pw ) = @_;

  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage($cmd_str);
    return;
  }

  if( defined($need_pw) && $need_pw ){
    need_admin_password();
  }

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my @attr_names = ("version",  "service",    "action",    "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn",$xml_action, $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "cert_get_impl: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close($ua, $bus_session_id);

  if ( !$resp->is_success ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";

    }else{

      print_stdout "No information found.\n";      
    }

  }else{

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "cert_get_impl: \n" . $resp_doc->toString(1) . "\n";
    }

    my $certs_elm = $resp_doc->getElementsByTagName('rhp_printed_certs');
    print_stdout $certs_elm;
  }

  return;
}

sub my_cert_show {
  
  cert_get_impl("config_get_my_printed_cert","my-cert-show",1);
}

sub peer_cert_show {
  
  my($vpn_uid) = @_;

  if ( !defined($realm) || 
       ((!defined($peerid_type) || !defined($peerid)) && !defined($vpn_uid)) ) {
    print_stdout "-realm, -peerid_type, -peerid or -uid not specified.\n";
    print_usage("peer-cert");
    return;
  }

  need_admin_password();
  
  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my @attr_names = ("version",  "service",    "action",   "vpn_realm","peer_id_type","peer_id",  "vpn_unique_id");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_get_peer_printed_certs",  $realm,  $peerid_type,  $peerid, $vpn_uid);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "status_vpn: \n" . $doc->toString(1) . "\n";
  }
  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  bus_close( $ua, $bus_session_id );


  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

    }else{

      print_stdout "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( $show_xml ){
      print_stdout "peer_cert_show: \n" . $resp_doc->toString(1) . "\n";
    }

    my $certs_elm = $resp_doc->getElementsByTagName('rhp_printed_certs');
    print_stdout $certs_elm;
  }


  return;
}


sub ca_cert_update {

  my( $pem_cert_file, $accept_expired_cert ) = @_;

  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("ca-cert-update");
    return;
  }
  
  if ( !defined($pem_cert_file) ) {
    print_stdout "-pem_file not specified.\n";
    print_usage("ca-cert-update");
    return;
  }

  if( defined($accept_expired_cert) &&
      $accept_expired_cert ne "enable" && $accept_expired_cert ne "disable" ){
    print_stdout "Invalid -accept_expired_cert specified. : $accept_expired_cert\n";
    print_usage("ca-cert-update");
    return;
  }


  need_admin_password();
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my $req = create_post_upload_ca_cert_pem($bus_session_id,$pem_cert_file,$accept_expired_cert);
     
  my $resp = $ua->request($req);
  
  if ( !$resp->is_success ) {
  
    print_stdout "ERROR: /protected/config :" . $resp->status_line . " or no content.\n";
  
  } else {
  
    my $th = bus_read_begin_thread($bus_session_id,\&my_cert_update_cb,undef);
    $th->join();      
  }
    

  bus_close($ua, $bus_session_id);
  return;
}

sub ca_cert_show {
  
  cert_get_impl("config_get_printed_ca_certs","ca-cert-show",1);
}

sub crl_update {

  my( $pem_crl_file, $accept_expired_cert ) = @_;

  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    print_usage("crl-update");
    return;
  }
  
  if ( !defined($pem_crl_file) ) {
    print_stdout "-pem_file not specified.\n";
    print_usage("crl-update");
    return;
  }

  if( defined($accept_expired_cert) &&
      $accept_expired_cert ne "enable" && $accept_expired_cert ne "disable" ){
    print_stdout "Invalid -accept_expired_cert specified. : $accept_expired_cert\n";
    print_usage("crl-update");
    return;
  }


  need_admin_password();
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my $req = create_post_upload_crl_pem($bus_session_id,$pem_crl_file,$accept_expired_cert);
     
  my $resp = $ua->request($req);
  
  if ( !$resp->is_success ) {
  
    print_stdout "ERROR: /protected/config :" . $resp->status_line . " or no content.\n";
  
  } else {
  
    my $th = bus_read_begin_thread($bus_session_id,\&my_cert_update_cb,undef);
    $th->join();      
  }
    

  bus_close($ua, $bus_session_id);
  return;
}

sub crl_show {
  
  cert_get_impl("config_get_printed_crls","crl-show",1);
}


sub realm_delete {
  
  if ( !defined($realm) ) {
    print_stdout "-realm not specified.\n";
    return;
  }
  
  {
    print "\nDo you really delete a configuration of the VPN realm($realm)? [N/y]\n";
  
    my $ans = <STDIN>;
    chomp($ans);
    if ( $ans eq "y" || $ans eq "Y" ) {
    }else{
      return;
    }
  }
  

  need_admin_password();
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",              "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_delete_realm", $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "realm_delete: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);
}


sub enable_or_disable_realm {
  
  my ($opr) = @_;
  
  if( !defined($realm) ){
    print_stdout "-realm <realm_no> not specified.\n";
    print_usage("realm");
    return;
  }

  my $opr_action;
  if( $opr eq "enable" ){
    $opr_action = "config_enable_realm";
  }else{
    $opr_action = "config_disable_realm";
  }

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action", "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn",$opr_action,  $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "enable_or_disable_realm: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}

sub update_realm_state {

  my ($bus_session_id) = @_;

  my $ua = LWP::UserAgent->new();

  my @attr_names = ("version",  "service",    "action", "vpn_realm");
  my @attr_vals = ($rhp_version,"ui_http_vpn","config_update_realm_state",  $realm);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "update_realm_state: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR(update_realm_state): /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  return;
}

sub rhp_memory_dbg {
  
  my ( $start_time, $elapsing_time ) = @_;

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }


  my @attr_names = ("version",  "service",    "action",   "vpn_realm","elapsing_time","start_time");
  my @attr_vals = ($rhp_version,"ui_http_vpn","memory_dbg", $realm   ,$elapsing_time, $start_time);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "rhp_memory_dbg: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print_stdout "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }

  bus_close($ua, $bus_session_id);
  return;
}


sub exec_bus_read_cb {
    
  my ($bus_session_id, $cb_ctx_ref, $resp) = @_;
  my $ret = 2;
    
  my $parser   = XML::LibXML->new;
  my $resp_doc = $parser->parse_string( $resp->decoded_content );

  if( $show_xml ){
    print_stdout "exec_bus_read_cb: \n" . $resp_doc->toString(1) . "\n";
  }
    
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_http_bus_record') ) {

    print_stdout "=\n";

    my $rec_action = EA('action');

    print_stdout "*$rec_action:\n";          

=comm    
    # JSON library is needed.
    if( $rec_action eq "log_record" ){

      my $fc = $EAELM->firstChild();
      if( defined($fc) ){
  
        my $json_data = $fc->nodeValue();

        if( $show_xml ){
          print_stdout "json_data: $json_data\n\n";
        }
        
        my $items = JSON->new()->decode("[".$json_data."]");

        foreach my $item (@$items) {
          printf "src:\t" . $item->{src} . "\n";
          printf "realm:\t" . $item->{realm} . "\n";
          printf "lv:\t" . $item->{lv} . "\n";
          printf "id:\t" . $item->{id} . "\n";
          printf "ts:\t" . $item->{ts} . "\n";
          printf "args:\n";
          
          my @item_args = @{$item->{args}};
          for(my $i = 0; $i < scalar(@item_args); $i++){
            my $item_arg = $item_args[$i];
            $item_arg =~ s/\<br\>/ /g;
            print_stdout "  [$i]:\t" . $item_arg . "\n";
          }
        }        
      }

    }else{
=cut      
      print_stdout "$EAELM\n";
=comm      
    }
=cut    

    print_stdout "\n";
  }
  
  return $ret;    
}

sub exec_bus_read {

  need_admin_password();
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open( $ua );
  if ( $bus_session_id eq '' ) {
    return;
  }

  my $th = bus_read_begin_thread($bus_session_id,\&exec_bus_read_cb,undef);

  while (defined(my $ans = <STDIN>)){
    
    chomp($ans);

    if( $ans eq "q" || $ans eq "quit" ){

      bus_close( $ua, $bus_session_id );
      last;      

    }else{

      print_stdout "\nTo quit, please enter 'q' and push <ENTER>\n\n";
    }
  }

  $th->join();
  
  return;
}


if( $help && defined($action) ) {

  open_stdout_pipe();

  print_usage($action);
  
}elsif( defined($action) && $action eq 'help' ){
  
  open_stdout_pipe();
  
  print_usage('help',$ARGV[1]);

}elsif( !defined($action) ){

  open_stdout_pipe();

  print_usage();
  
} elsif ( $action eq 'connect' ) {

  if( $cmd_opts{connection_name} ){
    $peerid_type = "null-id";
    $peerid = $cmd_opts{connection_name};
  }

  vpn_connect($cmd_opts{eap_method},$cmd_opts{eap_id},$cmd_opts{eap_key});

} elsif ( $action eq 'disconnect' || $action eq 'close' ) {

  if( $cmd_opts{connection_name} ){
    $peerid_type = "null-id";
    $peerid = $cmd_opts{connection_name};
  }

  vpn_disconnect($cmd_opts{uid});

} elsif ( $action eq 'vpn' ) {
  
  if ( defined($peerid_type) || defined($peerid) || defined($cmd_opts{uid}) ) {
      
    my $resp_doc = status_vpn($cmd_opts{uid},undef,0);
    if( defined($resp_doc) ){
      print_status_vpn($resp_doc,0);
    }else{
      print_stdout "No information found.\n";
    }

  } else {
      
    status_enum_vpn();
  }

} elsif ( $action eq 'web-mng' ) {

  my $web_mng_target = $ARGV[1];
  
  if( !defined($web_mng_target) || $web_mng_target eq "update" ){

    web_mng_update($cmd_opts{mng_address},$cmd_opts{mng_address_v6},$cmd_opts{mng_port}, 
      $cmd_opts{allowed_address},$cmd_opts{allowed_address_v6});

  }elsif( $web_mng_target eq "reset" ){
    
    web_mng_reset();
    
  }else{
    
    print_usage("web-mng");
  }
  
} elsif ( $action eq 'admin' ) {

  my $admin_target = $ARGV[1];

  if( !defined($admin_target) ){

    goto no_admin_target;
    
  }elsif ( $admin_target eq 'add' || $admin_target eq 'update' ) {

    admin_update( $cmd_opts{admin_id},$cmd_opts{admin_password}, $realm );

  } elsif ( $admin_target eq 'delete' ) {

    admin_delete( $cmd_opts{admin_id} );

  } elsif ( $admin_target eq 'show' ) {

    admin_show();

  } else {
    
no_admin_target:
    open_stdout_pipe();
    print_usage("admin");
  }

} elsif ( $action eq 'bridge' ) {

  status_bridge();

} elsif ( $action eq 'arp' ) {

  status_neigh("ipv4");

} elsif ( $action eq 'neigh' ) {

  status_neigh("ipv6");

} elsif ( $action eq 'route' ) {
  
  status_route_maps();

} elsif ( $action eq 'ip-route-table' ) {
  
  status_ip_route_table();

} elsif ( $action eq 'ip-route-cache' ) {
  
  status_ip_route_cache();

} elsif ( $action eq 'nhrp-cache' ) {
  
  status_nhrp_cache();

} elsif ( $action eq 'address-pool' ) {

  my $addr_pool_target = $ARGV[1];
  
  if( !defined($addr_pool_target) || $addr_pool_target eq "show" ){
    
    status_address_pool();

  }elsif( $addr_pool_target eq "flush" ){

    flush_address_pool();

  }else{
        
    print_usage("address-pool");
  }
  
} elsif ( $action eq 'source-if' ) {

  status_source_if();

} elsif ( $action eq 'flush-bridge' ) {

  flush_bridge();

} elsif ( $action eq 'flush-ip-route-cache' ) {

  flush_ip_route_cache();

} elsif ( $action eq 'if' ) {

  status_if(0);

} elsif ( $action eq 'tuntap-if' ) {

  status_if(1);

} elsif ( $action eq 'cfg-archive' ) {

  my $cfg_arch_target = $ARGV[1];
  
  if( !defined($cfg_arch_target) ){
    
    goto no_cfg_arch_target;    

  }elsif ( $cfg_arch_target eq 'save' ) {
  
    cfg_archive_save( $cmd_opts{archive_password}, $cmd_opts{file} );
  
  }elsif( $cfg_arch_target eq 'upload' ){
  
    cfg_archive_upload( $cmd_opts{archive_password}, $cmd_opts{file} );
  
  }elsif( $cfg_arch_target eq 'extract' ){
  
    cfg_archive_extract( $cmd_opts{archive_password}, $cmd_opts{file} );
  
  }else{

no_cfg_arch_target:
    open_stdout_pipe();
    print_usage("cfg-archive");
  }

} elsif ( $action eq 'peer-key' ) {

  my $peer_key_target = $ARGV[1];
  
  if( !defined($peer_key_target) ){
    
    goto no_peer_key_target;    

  }elsif ( $peer_key_target eq 'add' || $peer_key_target eq 'update' ) {
  
    peer_key_update( $cmd_opts{key}, $cmd_opts{keygen} );
  
  }elsif( $peer_key_target eq 'delete' ){
  
    peer_key_delete();

  }elsif( $peer_key_target eq 'show' ){
  
    peer_key_show();
  
  }else{

no_peer_key_target:
    open_stdout_pipe();
    print_usage("peer-key");
  }

} elsif ( $action eq 'my-key' ) {

  my $my_key_target = $ARGV[1];
  
  if( !defined($my_key_target) ){
    
    goto no_my_key_target;    

  }elsif ( $my_key_target eq 'update' ) {
  
    my_key_update( $cmd_opts{myid_type}, $cmd_opts{myid}, 
      $cache_eap_key, $cmd_opts{key}, $cmd_opts{keygen} );
  
  }elsif( $my_key_target eq 'delete' ){
  
    my_key_delete($cmd_opts{myid_type}, $cache_eap_key);

  }elsif( $my_key_target eq 'show' ){
  
    my_key_show();
  
  }else{

no_my_key_target:
    open_stdout_pipe();
    print_usage("my-key");
  }

} elsif ( $action eq 'my-cert' ) {

  my $my_cert_target = $ARGV[1];
  
  if( !defined($my_cert_target) ){
    
    goto no_my_cert_target;    

  }elsif ( $my_cert_target eq 'update' ) {
  
    my_cert_update( $cmd_opts{pkcs12_file},
        $cmd_opts{pem_cert_file}, $cmd_opts{pem_priv_key_file},        
        $cmd_opts{priv_key_password}, 
        $cmd_opts{myid_type},
        $cmd_opts{accept_expired_cert} );

  }elsif( $my_cert_target eq 'show' ){
  
    my_cert_show();
  
  }else{

no_my_cert_target:
    open_stdout_pipe();
    print_usage("my-cert");
  }

} elsif ( $action eq 'peer-cert' ) {
  
  peer_cert_show($cmd_opts{uid});

} elsif ( $action eq 'ca-cert' ) {

  my $ca_cert_target = $ARGV[1];
  
  if( !defined($ca_cert_target) ){
    
    goto no_ca_cert_target;    

  }elsif ( $ca_cert_target eq 'update' ) {
  
    ca_cert_update($cmd_opts{pem_file},$cmd_opts{accept_expired_cert} );

  }elsif( $ca_cert_target eq 'show' ){
  
    ca_cert_show();
  
  }else{

no_ca_cert_target:
    open_stdout_pipe();
    print_usage("ca-cert");
  }

} elsif ( $action eq 'crl' ) {

  my $crl_cert_target = $ARGV[1];
  
  if( !defined($crl_cert_target) ){
    
    goto no_crl_cert_target;    

  }elsif ( $crl_cert_target eq 'update' ) {
  
    crl_update($cmd_opts{pem_file},$cmd_opts{accept_expired_cert});

  }elsif( $crl_cert_target eq 'show' ){
  
    crl_show();
  
  }else{

no_crl_cert_target:
    open_stdout_pipe();
    print_usage("crl");
  }

} elsif ($action eq 'realm') {

  my $realm_target = $ARGV[1];
  
  if( !defined($realm_target) ){
    
    goto no_realm_target;    

  }elsif ( $realm_target eq 'enable' || $realm_target eq 'disable' ) {
  
    enable_or_disable_realm($realm_target);
  
  }elsif ( $realm_target eq 'delete' ) {

    realm_delete();

  }else{

no_realm_target:
    open_stdout_pipe();
    print_usage("realm");
  }

} elsif ( $action eq 'show-cfg' ) {

  show_cfg();

} elsif ( $action eq 'show-realm' ) {

  show_realm();

} elsif ( $action eq 'show-global-cfg' ) {

  show_global_cfg();

} elsif ( $action eq 'clear-all-conn' ) {

  clear_all_conn("all");

} elsif ( $action eq 'clear-dormant-conn' ) {

  clear_all_conn("dormant");

} elsif ( $action eq 'rt-check' ) {

  rt_check($ARGV[1],$cmd_opts{uid});

} elsif ( $action eq 'clear-eap-key-cache' ) {

  clear_eap_key_cache();

} elsif ( $action eq 'reset-qcd-key' ) {

  reset_qcd_key();

} elsif ( $action eq 'reset-sess-resume-key' ) {

  reset_sess_resume_key();

} elsif ( $action eq 'invalidate-sess-resume-tkts' ) {

  invalidate_sess_resume_tkts();

} elsif ( $action eq 'memory-dbg' ) {

  rhp_memory_dbg($cmd_opts{start_time},$cmd_opts{elapsing_time});

} elsif ( $action eq 'bus-read' ) {

  exec_bus_read();
  
}else{
  
  open_stdout_pipe();

  print_usage();
}


close_stdout_pipe();

exit;

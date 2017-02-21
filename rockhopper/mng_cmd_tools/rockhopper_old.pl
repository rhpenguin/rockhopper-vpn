#! /usr/bin/perl

#
#  Copyright (C) 2009-2012 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#use warnings;

use Getopt::Long;

# (Ubuntu 8.x--) NOT need to import libwww-perl by package manager.
use LWP::UserAgent;
use LWP::Authen::Basic;

# (Ubuntu 8.x--) Need to import libxml-libxml-perl by package manager.
use XML::LibXML;

use Switch;

my $rhp_version = '1.0';
my $brctl    = "/usr/sbin/brctl";
my $ifconfig = "/sbin/ifconfig";

sub print_usage {

  my ($action) = @_;

  print "[ Usage ]\n";
  if ( $action eq 'connect' ) {

    print "% rockhopper.pl connect -realm <realm_no>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-peerid_type <id_type> -peerid <peerid>]\n";
    print " [-peer_address <address, hostname>]\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'close' ) {

    print "% rockhopper.pl close -realm <realm_no>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-peerid_type <id_type> -peerid <peerid>]\n";
    print " [-peer_address <address, hostname>]\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'status' ) {

    print "% rockhopper.pl status <vpn, peers, bridge, arp, address-pool, interface> ...\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

    print_usage('status_vpn');
    print_usage('status_peers');
    print_usage('status_bridge');
    print_usage('status_arp');
    print_usage('status_address_pool');

  } elsif ( $action eq 'status_vpn' ) {

    print "% rockhopper.pl status vpn -realm <realm_no>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-peerid_type <id_type> -peerid <peerid>] [-detail]\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'status_peers' ) {

    print "% rockhopper.pl status peers -realm <realm_no> [-detail]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'status_bridge' ) {

    print "% rockhopper.pl status bridge -realm <realm_no> [-detail]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'status_arp' ) {

    print "% rockhopper.pl status arp -realm <realm_no> [-detail]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'status_address_pool' ) {

    print "% rockhopper.pl status address-pool -realm <realm_no>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'config' ) {

    print "Show configuration:\n";
    print "% rockhopper.pl config get [-realm <realm_no>] [-file output_xml]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";
    print "Show a list of configured peers:\n";
    print "% rockhopper.pl config peers [-realm <realm_no>]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";
    print "Show a list of configured VPN realms:\n";
    print "% rockhopper.pl config realms\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'realm' ) {

    print "% rockhopper.pl realm <create, update, delete> -realm <realm_no> ...\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

    print_usage('realm_create');
    print_usage('realm_update');
    print_usage('realm_delete');

  } elsif ( $action eq 'realm_create' ) {

    print "% rockhopper.pl realm create -realm <realm_no> [-realm_name '<name>']\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-realm_desc '<description>']\n";
    print " [-realm_mode <'Router', 'Bridge', 'Remote Client', 'End Node'>]\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'realm_update' ) {

    print "% rockhopper.pl realm update -realm <realm_no> -file config_xml\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'realm_delete' ) {

    print "% rockhopper.pl realm delete -realm <realm_no>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'global' ) {

    print "% rockhopper.pl global <update, get> ...\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

    print_usage('global_update');
    print_usage('global_get');

  } elsif ( $action eq 'global_update' ) {

    print "% rockhopper.pl global update -file config_xml\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'global_get' ) {

    print "% rockhopper.pl global get\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'auth' ) {

    print "% rockhopper.pl auth <update, delete> -realm <realm_no> ...\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

    print_usage('auth_update');
    print_usage('auth_delete');

  } elsif ( $action eq 'auth_update' ) {

    print "myid:\n";
    print "% rockhopper.pl auth update -realm <realm_no>\n";
    print " -myid_type <fqdn, email, dn, subjectaltname, cert_auto> [-myid <myid>]\n";
    print " [-my_auth_method <psk, rsa-sig>] [-psk <my_pre_shared_key>]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";
    print "peerid\n";
    print "% rockhopper.pl auth update -realm <realm_no>\n";
    print " -peerid_type <fqdn, email, dn, any> [-peerid <peerid>]\n";
    print " [-psk <peer_pre_shared_key>]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'auth_delete' ) {

    print "% rockhopper.pl auth delete -realm <realm_no>\n";
    print " -peerid_type <fqdn, email, dn, any> -peerid <peerid>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'cert' ) {

#    print "% rockhopper.pl cert <get, update, delete> -realm <realm_no> ...\n";
    print "% rockhopper.pl cert <get, update> -realm <realm_no> ...\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

    print_usage('cert_update');
    print_usage('cert_get');
##    print_usage('cert_delete');

  } elsif ( $action eq 'cert_update' ) {

    print "% rockhopper.pl cert update -realm <realm_no>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-my_cert <my_cert_pem> -my_priv_key <my_priv_key_pem>]\n";
    print " [-ca_certs <ca_certs_pem>] [-cert_password <password>]";
    print " [-port <admin_port>]\n";
    print "\n";

#  } elsif ( $action eq 'cert_delete' ) {

#    print "% rockhopper.pl cert delete -realm <realm_no>\n";
#    print " -admin <admin_id> -password <password>\n";
#    print " [-port <admin_port>]\n";
#    print "\n";

  } elsif ( $action eq 'cert_get' ) {

    print "% rockhopper.pl cert get -realm <realm_no>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'admin' ) {

    print "% rockhopper.pl admin <update, delete, get> -admin_id <admin_id> ...\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-realm <realm_no>]\n";
    print " [-port <admin_port>]\n";
    print "\n";

    print_usage('admin_update');
    print_usage('admin_delete');
    print_usage('admin_get');

  } elsif ( $action eq 'admin_update' ) {

    print "% rockhopper.pl admin update -admin_id <admin_id>\n";
    print " -admin_password <new_admin_passowrd> [-realm <new_realm_no>]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'admin_delete' ) {

    print "% rockhopper.pl admin delete -admin_id <admin_id>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'admin_get' ) {

    print "% rockhopper.pl admin get -admin_id <admin_id>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

#  } elsif ( $action eq 'policy_get' ) {

#    print "% rockhopper.pl policy get [-file output_xml]\n";
#    print " -admin <admin_id> -password <password>\n";
#    print " [-port <admin_port>]\n";
#    print "\n";

#  } elsif ( $action eq 'policy_update' ) {

#    print "% rockhopper.pl policy update -file <policy_xml>\n";
#    print " -admin <admin_id> -password <password>\n";
#    print " [-port <admin_port>]\n";
#    print "\n";

#  } elsif ( $action eq 'config-wizard' ) {

#    print "% rockhopper.pl config-wizard -realm <realm_no>\n";
#    print " -admin <admin_id> -password <password>\n";
#    print " [-port <admin_port>]\n";
#    print "\n";

  } elsif ( $action eq 'flush-bridge' ) {

    print "% rockhopper.pl flush-bridge [-realm <realm_no>]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'web-mng' ) {

    print "% rockhopper.pl web-mng [-mng_address <listening_address>]\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-mng_port <listening_port>]\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'cfg-archive' ) {

    print "% rockhopper.pl cfg-archive <save, extract> -archive_password <password>\n";
    print " [-admin <admin_id> -password <password>]\n";
    print " [-port <admin_port>]\n";
    print "\n";

    print_usage('cfg-archive-save');
    print_usage('cfg-archive-extract');

  } elsif ( $action eq 'cfg-archive-save' ) {

    print "% rockhopper.pl cfg-archive save -archive_password <password>\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-file <output_archive_file>]\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } elsif ( $action eq 'cfg-archive-extract' ) {

    print "% rockhopper.pl cfg-archive extract -archive_password <password>\n";
    print " -file <input_archive_file>\n";
    print "\n";

#  } elsif ( $action eq 'cfg-archive-restore' ) {
#
#    print "% rockhopper.pl cfg-archive restore -archive_password <password>\n";
#    print " -admin <admin_id> -password <password>\n";
#    print " [-file <input_archive_file>]\n";
#    print " [-port <admin_port>]\n";
#    print "\n";

  } elsif ( $action eq 'memory-dbg' ) {

    print "% rockhopper.pl memory-dbg\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-elapsing_time <seconds>(>0)]\n";
    print " [-start_time <seconds>(>0)]\n";
    print " [-port <admin_port>]\n";
    print "\n";

  } else {

    print "% rockhopper.pl <command> ...\n";
    print " -admin <admin_id> -password <password>\n";
    print " [-port <admin_port>]\n\n";
    print " command:\n";
    print "  help <command>  Show help info.\n";
    print "  connect         Connect VPN.\n";
    print "  close           Close VPN.\n";
    print "  status          Show VPN status.\n";
    print "  config          Show configuration.\n";
    print "  realm           Configure VPN realm.\n";
    print "  global          Configure global settings.\n";
    print "  auth            Configure VPN's authentication information.\n";
    print "  cert            Update VPN's X.509 certificates and private key.\n";
#   print "  config-wizard   Configure VPN by simple wizard.\n";
    print "  flush-bridge [-realm <realm_no>]  Flush cached MAC and ARP table.\n";
#   print "  policy          Setup configuration policy.\n";
    print "  admin           Setup administrator's ID and key.\n";
    print "  web-mng         Setup address/port of Web Management Service.\n";
#   print "  cfg-archive     Save, extract or restore configuration's archive(backup).\n";
    print "  cfg-archive     Save or extract configuration's archive(backup).\n";
    print "\n";
  }
  
  return;
}

sub is_valid_ipv4 {
  
  my ($address) = @_;
  chomp($address);

  my @aa = split( /\./, $address );

  if ( @aa != 4 ) {
    return 0;
  }

  foreach my $a (@aa) {

    my $len = length($a);

    if ( $len < 1 || $len > 3 ) {
      return 0;
    }

    if ( $a !~ /^\d+$/ || $a =~ /^0\d+$/ || $a =~ /^00\d$/ ) {
      return 0;
    }
  }

  return 1;
}

sub is_valid_ipv4_subnet {
  
  my ($address) = @_;

  chomp($address);

  my @aa = split( /\//, $address );

  if ( @aa != 2 ) {
    return 0;
  }

  if ( $aa[1] !~ /^\d+$/ ) {
    return 0;
  }

  if ( $aa[1] < 1 || $aa[1] > 32 ) {
    return 0;
  }

  return is_valid_ipv4( $aa[0] );
}

my $config_wizard_doc;

sub get_stdin2 {

  my($ignore_sp,$tolc) = @_;

get_stdin_again:
  print "\n>>";
  my $ans = <STDIN>;

  chomp($ans);
  if( $tolc ){
    $ans = lc($ans);
  }
  $ans =~ s/^\s*(.*?)\s*$/$1/;

  if( $ignore_sp && ( !$ans || length($ans) < 1 || $ans =~ /^\s*$/) ){
    goto get_stdin_again;
  }
  
  if( $config_wizard_doc && $ans eq "show_doc"){
    print $config_wizard_doc->toString(1);
    goto get_stdin_again;
  }

  return $ans;  
}

sub get_stdin {

  my($ignore_sp) = @_;
  
  return get_stdin2($ignore_sp,1);
}

sub confirm_exit {

  print "Do you really quit this configuration? [N/y]\n";

  my $ans = get_stdin(0);

  if ( $ans eq "y" ) {
    exit;
  }
  
  return; 
}

sub get_stdin_chars {

  my($def_opt,@opts) = @_;

  my $ok = 0;
  while ( !$ok ) {

    my $ans = get_stdin(0);

    if( $def_opt && ( !$ans || $ans =~ /^\s*$/) ){

      return $def_opt;      

    }elsif( $ans eq "q" ){

      confirm_exit();
      
    }else{

      foreach my $opt (@opts){
        
        if( $ans eq $opt ){
          return $opt;        
        }      
      }
        
      print "Unknown character(s) \[$ans\] specified. Try again.\n";
    }

  }
}

sub open_bus_session {
  
  my ( $ua, $address, $port, $auth_basic_key ) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/open';
  my $req = HTTP::Request->new( POST => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {
    print "ERROR: /protected/bus/open :" . $resp->status_line . " or no content.\n";
    return '';
  }

  my $parser     = XML::LibXML->new;
  my $resp_doc   = $parser->parse_string( $resp->decoded_content );
  my $session_id = '';

  foreach my $resp_elm ( $resp_doc->getElementsByTagName('rhp_http_bus_response') ){

    my $server_version = $resp_elm->getAttribute('version');

    if ( $server_version ne $rhp_version ) {
      print "ERROR: RHP version not supported. : $server_version \n";
      return '';
    }

    my $resp_rec = $resp_elm->getElementsByTagName('rhp_http_bus_record')->item(0);

    my $service = $resp_rec->getAttribute('service');
    if ( $service ne 'http_bus' ) {
      print "ERROR: RHP service not supported. : $service \n";
      return '';
    }

    my $server_action = $resp_rec->getAttribute('action');
    if ( $server_action ne 'open' ) {
      print "ERROR: RHP action not supported. : $server_action \n";
      return '';
    }

    $session_id = $resp_rec->getAttribute('session_id');
    if ( $session_id eq '' ) {
      print "ERROR: Session ID not found. : $session_id \n";
      return '';
    }
  }

  return $session_id;
}

sub close_bus_session {
  
  my ( $ua, $address, $port, $auth_basic_key, $session_id ) = @_;

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/close/' . $session_id;
  my $req = HTTP::Request->new( DELETE => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/close/$session_id :" . $resp->status_line . "\n";
  }
  
  return;
}

sub vpn_connect {
  
  my ($address,$port,$auth_basic_key,$realm,$peerid_type, $peerid, $peer_address) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print print_usage("connect");
    return;
  }

  if ( ( !$peerid_type || !$peerid ) && !$peer_address ) {
    print "peerid_type, peerid or peer_address not specified.\n";
    print print_usage("connect");
    return;
  }

  if ( !$peerid_type && $peerid ) {
    print "peerid_type not specified.\n";
    print print_usage("connect");
    return;
  }

  if ( !$peerid ) {
    $peerid_type = 'any';
    $peerid      = 'any';
  }

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(1);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="http_bus" action="connect" vpn_realm="10" 
# peer_id_type="fqdn" peer_id="responder.companya.com"/>
#

  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "connect" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $attr_peerid_type = $doc->createAttribute( "peer_id_type", $peerid_type );
  $root->setAttributeNode($attr_peerid_type);

  my $attr_peerid = $doc->createAttribute( "peer_id", $peerid );
  $root->setAttributeNode($attr_peerid);

  if ($peer_address) {
    my $attr_peer_address = $doc->createAttribute( "peer_address", $peer_address );
    $root->setAttributeNode($attr_peer_address);
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1) . "\n";
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  
  return;
}

sub vpn_close {
  
  my ( $address, $port, $auth_basic_key, $realm, $peerid_type, $peerid ,$peer_address) = @_;

  if ( !$realm ){
    print "realm not specified.\n";
    print print_usage("close");
    return;
  }

  if( !$peerid_type && !$peerid && !$peer_address ) {
    print "peerid_type, peerid, or peer_address not specified.\n";
    print print_usage("close");
    return;
  }

  if( (!$peerid_type && $peerid) || ($peerid_type && !$peerid) ){
    print "peerid_type or peerid not specified.\n";
    print print_usage("close");
    return;
  }

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(1);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="close" vpn_realm="10" peer_id_type="fqdn" peer_id="responder.companya.com"/>
#
  my $doc  = XML::LibXML->createDocument;
  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "close" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  if( $peerid_type ){

    my $attr_peerid_type = $doc->createAttribute( "peer_id_type", $peerid_type );
    $root->setAttributeNode($attr_peerid_type);
  
    my $attr_peerid = $doc->createAttribute( "peer_id", $peerid );
    $root->setAttributeNode($attr_peerid);
  }
  
  if ($peer_address) {
    my $attr_peer_address = $doc->createAttribute( "peer_address", $peer_address );
    $root->setAttributeNode($attr_peer_address);
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1) . "\n";
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  
  return;
}

sub show_status_vpn_summary {

  my ($resp_doc,$vpn_idx) = @_;

  foreach my $vpn_elm ( $resp_doc->getElementsByTagName('vpn') ) {

    print "\n";

    my $vpn_realm_id           = $vpn_elm->getAttribute('vpn_realm_id');
    my $vpn_vpn_realm_name     = $vpn_elm->getAttribute('vpn_realm_name');
    my $vpn_peerid             = $vpn_elm->getAttribute('peerid');
    my $vpn_myid               = $vpn_elm->getAttribute('myid');
    my $vpn_encap_mode         = $vpn_elm->getAttribute('encap_mode');
    my $vpn_internal_if_addr   = $vpn_elm->getAttribute('internal_if_addr');
    my $vpn_internal_peer_addr = $vpn_elm->getAttribute('internal_peer_addr');
    my $vpn_internal_peer_addr_cp = $vpn_elm->getAttribute('internal_peer_addr_cp');
    my $vpn_internal_if_name = $vpn_elm->getAttribute('internal_if_name');
    my $vpn_peer_is_access_point = $vpn_elm->getAttribute('peer_is_access_point');
    my $vpn_is_access_point = $vpn_elm->getAttribute('is_access_point');
    my $vpn_is_config_server = $vpn_elm->getAttribute('is_config_server');

    my $vpn_my_if_name = $vpn_elm->getAttribute('my_if_name');
    my $vpn_my_addr    = $vpn_elm->getAttribute('my_addr');
    my $vpn_peer_addr  = $vpn_elm->getAttribute('peer_addr');

    if ( !$vpn_internal_peer_addr ) {
      $vpn_internal_peer_addr = "unknown";
    }
    if( !$vpn_internal_if_addr ){
      $vpn_internal_if_addr = "unknown";
    }

    if ( !$vpn_vpn_realm_name ) {
      print "VPN[$vpn_idx]: Rlm($vpn_realm_id)";
    } else {
      print "VPN[$vpn_idx]: Rlm($vpn_vpn_realm_name:$vpn_realm_id)";
    }
    print "\n";

    print "  $vpn_myid";

    print " ==>";

    if ( $vpn_peerid eq 'any' ) {
      print " unknown";
    } else {
      print " $vpn_peerid";
    }

    if( $vpn_peer_is_access_point ){
      print " AP";      
    }
    if( $vpn_is_config_server ){
      print " CFG";      
    }
    print "\n";

    print "  $vpn_my_addr($vpn_my_if_name) ==> $vpn_peer_addr\n";

    print "  \[IN\] $vpn_internal_if_addr($vpn_internal_if_name) ==> $vpn_internal_peer_addr";

    if ( $vpn_internal_peer_addr_cp ) {
      print "(ikev2cfg)";
    }

    print " encap($vpn_encap_mode)";

    if( $vpn_is_access_point ){
      print "  AP";
    }
    print "\n";
    


    my $ikesa_idx = 0;

    foreach my $ikesa_elm ( $vpn_elm->getElementsByTagName('ikesa') ) {

      print "\n";
      my $ikesa_side             = $ikesa_elm->getAttribute('side');
      my $ikesa_init_spi         = $ikesa_elm->getAttribute('initiator_spi');
      my $ikesa_resp_spi         = $ikesa_elm->getAttribute('responder_spi');
      my $ikesa_state            = $ikesa_elm->getAttribute('state');
      my $ikesa_auth_method      = $ikesa_elm->getAttribute('auth_method');
      my $ikesa_peer_auth_method = $ikesa_elm->getAttribute('peer_auth_method');
      my $ikesa_prf              = $ikesa_elm->getAttribute('prf');
      my $ikesa_dh_group         = $ikesa_elm->getAttribute('dh_group');
      my $ikesa_integ            = $ikesa_elm->getAttribute('integ');
      my $ikesa_encr             = $ikesa_elm->getAttribute('encr');
      my $ikesa_encr_key_bits    = $ikesa_elm->getAttribute('encr_key_bits');

      print "  IKE SA[$ikesa_idx]:\n";
      print "   SPI I:$ikesa_init_spi\n";
      print "       R:$ikesa_resp_spi\n";
      print "   $ikesa_side $ikesa_state\n";

      if ($ikesa_encr_key_bits) {
        print "   A:$ikesa_auth_method,$ikesa_peer_auth_method, P:$ikesa_prf, DH:$ikesa_dh_group, I:$ikesa_integ, E:$ikesa_encr($ikesa_encr_key_bits)\n";
      } else {
        print "   A:$ikesa_auth_method,$ikesa_peer_auth_method, P:$ikesa_prf, DH:$ikesa_dh_group, I:$ikesa_integ, E:$ikesa_encr\n";
      }

      $ikesa_idx++;
    }


    my $childsa_idx = 0;
    foreach my $childsa_elm ( $vpn_elm->getElementsByTagName('childsa') ) {

      print "\n";
      my $childsa_side          = $childsa_elm->getAttribute('side');
      my $childsa_rekeyed       = $childsa_elm->getAttribute('rekeyed_gen');
      my $childsa_inb_spi       = $childsa_elm->getAttribute('inbound_spi');
      my $childsa_outb_spi      = $childsa_elm->getAttribute('outbound_spi');
      my $childsa_state         = $childsa_elm->getAttribute('state');
      my $childsa_ipsec_mode    = $childsa_elm->getAttribute('ipsec_mode');
      my $childsa_esn           = $childsa_elm->getAttribute('esn');
      my $childsa_integ         = $childsa_elm->getAttribute('integ');
      my $childsa_encr          = $childsa_elm->getAttribute('encr');
      my $childsa_encr_key_bits = $childsa_elm->getAttribute('encr_key_bits');

      print "  Child SA[$childsa_idx]: SPI IN:$childsa_inb_spi OUT:$childsa_outb_spi\n";
      print "   $childsa_side $childsa_state\n";

      if ($childsa_encr_key_bits) {
        print "   mode($childsa_ipsec_mode) I:$childsa_integ, E:$childsa_encr($childsa_encr_key_bits)";
      } else {
        print "   mode($childsa_ipsec_mode) I:$childsa_integ, E:$childsa_encr";
      }

      if ($childsa_esn) {
        print " ESN\n";
      } else {
        print "\n";
      }

      $childsa_idx++;
    }
  }

  print "\n";
  
  return;
}

sub show_status_vpn_detail {
  
  my ($resp_doc,$vpn_idx) = @_;

  foreach my $vpn_elm ( $resp_doc->getElementsByTagName('vpn') ) {

    print "\n";
    my $vpn_unique_id             = $vpn_elm->getAttribute('vpn_unique_id');
    my $vpn_realm_id              = $vpn_elm->getAttribute('vpn_realm_id');
    my $vpn_vpn_realm_name        = $vpn_elm->getAttribute('vpn_realm_name');
    my $vpn_peerid_type           = $vpn_elm->getAttribute('peerid_type');
    my $vpn_peerid                = $vpn_elm->getAttribute('peerid');
    my $vpn_myid_type             = $vpn_elm->getAttribute('myid_type');
    my $vpn_myid                  = $vpn_elm->getAttribute('myid');
    my $vpn_encap_mode            = $vpn_elm->getAttribute('encap_mode');
    my $vpn_internal_if_addr_type = $vpn_elm->getAttribute('internal_if_addr_type');
    my $vpn_internal_if_addr    = $vpn_elm->getAttribute('internal_if_addr');
    my $vpn_internal_if_mac     = $vpn_elm->getAttribute('internal_if_mac');
    my $vpn_internal_if_mtu     = $vpn_elm->getAttribute('internal_if_mtu');
    my $vpn_internal_gateway_addr = $vpn_elm->getAttribute('internal_gateway_addr');
    my $vpn_internal_if_name   = $vpn_elm->getAttribute('internal_if_name');
    my $vpn_internal_peer_addr = $vpn_elm->getAttribute('internal_peer_addr');
    my $vpn_internal_peer_addr_cp = $vpn_elm->getAttribute('internal_peer_addr_cp');
    my $vpn_dummy_peer_mac = $vpn_elm->getAttribute('dummy_peer_mac');
    my $vpn_time_elapsed   = $vpn_elm->getAttribute('time_elapsed');
    my $vpn_peer_is_access_point = $vpn_elm->getAttribute('peer_is_access_point');
    my $vpn_is_access_point = $vpn_elm->getAttribute('is_access_point');
    my $vpn_is_config_server = $vpn_elm->getAttribute('is_config_server');

    my $vpn_my_if_name = $vpn_elm->getAttribute('my_if_name');
    my $vpn_my_addr    = $vpn_elm->getAttribute('my_addr');
    my $vpn_my_port    = $vpn_elm->getAttribute('my_port');
    my $vpn_peer_addr  = $vpn_elm->getAttribute('peer_addr');
    my $vpn_peer_port  = $vpn_elm->getAttribute('peer_port');
    my $vpn_exec_nat_t  = $vpn_elm->getAttribute('exec_nat_t');
    my $vpn_behind_a_nat = $vpn_elm->getAttribute('behind_a_nat');

    if ( !$vpn_internal_peer_addr ) {
      $vpn_internal_peer_addr = "unknown";
    }

    if ( !$vpn_vpn_realm_name ) {
      print "VPN\[$vpn_idx\]: Rlm($vpn_realm_id)";
    } else {
      print "VPN\[$vpn_idx\]: Rlm($vpn_vpn_realm_name:$vpn_realm_id)";
    }
    print "\n";


    print "  $vpn_myid($vpn_myid_type)";
    
    print " ==>";

    if ( $vpn_peerid eq 'any' ) {
      print " unknown";
    } else {
      print " $vpn_peerid($vpn_peerid_type)";
    }

    if( $vpn_peer_is_access_point ){
      print ":AP";      
    }
    print "\n";

    print "  $vpn_my_addr($vpn_my_if_name):$vpn_my_port ==> $vpn_peer_addr:$vpn_peer_port\n";
    if( $vpn_exec_nat_t ){
      
      print "  \[NAT_T\]";
      
      if( $vpn_behind_a_nat == 1 ){
        print " LOCAL: BEHIND_A_NAT";        
      }elsif( $vpn_behind_a_nat == 2 ){
        print " PEER: BEHIND_A_NAT";        
      }elsif( $vpn_behind_a_nat == 3){
        print " BOTH: BEHIND_A_NAT";        
      }      
      print "\n";
    }
    
    print "  \[IN\] $vpn_internal_if_addr ($vpn_internal_if_name, $vpn_internal_if_addr_type) ==> $vpn_internal_peer_addr";

    if ( $vpn_internal_peer_addr_cp ) {
      print "(ikev2cfg)";
    }

    print " encap($vpn_encap_mode)\n";

    print "  \[IN\] MAC($vpn_internal_if_mac) MTU($vpn_internal_if_mtu)";

    if( $vpn_is_access_point ){
      print " ACCESS-POINT";
    }
    
    if( $vpn_is_config_server ){
      print " CFG-SVR";
    }
    print "\n";

    my $olp = 0;
    if ($vpn_internal_gateway_addr) {
      print " PeerGW($vpn_internal_gateway_addr)";
      $olp++;
    }

    if ( $vpn_encap_mode eq 'ipip' ) {
      print "  Dmy-Peer-MAC($vpn_dummy_peer_mac)";
      $olp++;
    }

    if( $olp ){
      print "\n";
    }
    print "  UID:$vpn_unique_id Elapsed($vpn_time_elapsed)\n";

    my $ikesa_idx = 0;
    foreach my $ikesa_elm ( $vpn_elm->getElementsByTagName('ikesa') ) {

      print "\n";

      my $ikesa_side       = $ikesa_elm->getAttribute('side');
      my $ikesa_init_spi   = $ikesa_elm->getAttribute('initiator_spi');
      my $ikesa_resp_spi   = $ikesa_elm->getAttribute('responder_spi');
      my $ikesa_state      = $ikesa_elm->getAttribute('state');
      my $ikesa_rekeyed    = $ikesa_elm->getAttribute('rekeyed_gen');
      my $ikesa_established_time_elapsed = $ikesa_elm->getAttribute('established_time_elapsed');
      my $ikesa_expire_hard      = $ikesa_elm->getAttribute('expire_hard');
      my $ikesa_expire_soft      = $ikesa_elm->getAttribute('expire_soft');
      my $ikesa_prop_no          = $ikesa_elm->getAttribute('proposal_no');
      my $ikesa_auth_method      = $ikesa_elm->getAttribute('auth_method');
      my $ikesa_peer_auth_method = $ikesa_elm->getAttribute('peer_auth_method');
      my $ikesa_prf              = $ikesa_elm->getAttribute('prf');
      my $ikesa_dh_group         = $ikesa_elm->getAttribute('dh_group');
      my $ikesa_integ            = $ikesa_elm->getAttribute('integ');
      my $ikesa_encr             = $ikesa_elm->getAttribute('encr');
      my $ikesa_encr_key_bits    = $ikesa_elm->getAttribute('encr_key_bits');
      print "  IKE SA\[$ikesa_idx\]:\n";
      print "   SPI I:$ikesa_init_spi\n";
      print "       R:$ikesa_resp_spi\n";
      print "   $ikesa_side $ikesa_state  Rekeyed($ikesa_rekeyed)";

      if ($ikesa_established_time_elapsed) {
        print " Elapsed($ikesa_established_time_elapsed)";
      }

      print " Lifetime(Rekey:";
      if ($ikesa_expire_soft) {
        print "$ikesa_expire_soft";
      } else {
        print "--";
      }

      print " Exp:";
      if ($ikesa_expire_hard) {
        print "$ikesa_expire_hard)\n";
      } else {
        print "--)\n";
      }

      if ($ikesa_encr_key_bits) {
        print "   A:$ikesa_auth_method ==> $ikesa_peer_auth_method, Prop\[$ikesa_prop_no\] P:$ikesa_prf, DH:$ikesa_dh_group, I:$ikesa_integ, E:$ikesa_encr($ikesa_encr_key_bits)\n";
      } else {
        print "   A:$ikesa_auth_method ==> $ikesa_peer_auth_method, Prop\[$ikesa_prop_no\] P:$ikesa_prf, DH:$ikesa_dh_group, I:$ikesa_integ, E:$ikesa_encr\n";
      }

      $ikesa_idx++;
    }

    my $childsa_idx = 0;
    foreach my $childsa_elm ( $vpn_elm->getElementsByTagName('childsa') ) {

      print "\n";

      my $childsa_side       = $childsa_elm->getAttribute('side');
      my $childsa_rekeyed    = $childsa_elm->getAttribute('rekeyed_gen');
      my $childsa_inb_spi    = $childsa_elm->getAttribute('inbound_spi');
      my $childsa_outb_spi   = $childsa_elm->getAttribute('outbound_spi');
      my $childsa_state      = $childsa_elm->getAttribute('state');
      my $childsa_ipsec_mode = $childsa_elm->getAttribute('ipsec_mode');
      my $childsa_established_time_elapsed = $childsa_elm->getAttribute('established_time_elapsed');
      my $childsa_expire_hard   = $childsa_elm->getAttribute('expire_hard');
      my $childsa_expire_soft   = $childsa_elm->getAttribute('expire_soft');
      my $childsa_prop_no       = $childsa_elm->getAttribute('proposal_no');
      my $childsa_esn           = $childsa_elm->getAttribute('esn');
      my $childsa_integ         = $childsa_elm->getAttribute('integ');
      my $childsa_encr          = $childsa_elm->getAttribute('encr');
      my $childsa_encr_key_bits = $childsa_elm->getAttribute('encr_key_bits');
      my $childsa_pfs           = $childsa_elm->getAttribute('pfs');
      my $childsa_anti_replay   = $childsa_elm->getAttribute('anti_replay');
      my $childsa_tfc_padding   = $childsa_elm->getAttribute('tfc_padding');
      my $childsa_udp_encap     = $childsa_elm->getAttribute('udp_encap');
      my $childsa_out_of_order_drop = $childsa_elm->getAttribute('out_of_order_drop');
      my $childsa_pmtu_default = $childsa_elm->getAttribute('pmtu_default');
      my $childsa_pmtu_cache   = $childsa_elm->getAttribute('pmtu_cache');
      my $childsa_collision_detected = $childsa_elm->getAttribute('collision_detected');
      
      print "  Child SA\[$childsa_idx\]: SPI IN:$childsa_inb_spi OUT:$childsa_outb_spi\n";
      print "   $childsa_side $childsa_state\n";
      print "   mode($childsa_ipsec_mode) Rekeyed($childsa_rekeyed)";

      if ($childsa_established_time_elapsed) {
        print " Elapsed($childsa_established_time_elapsed)";
      }

      print " Lifetime(Rekey:";
      if ($childsa_expire_soft) {
        print "$childsa_expire_soft";
      } else {
        print "--";
      }

      print " Exp:";
      if ($childsa_expire_hard) {
        print "$childsa_expire_hard)\n";
      } else {
        print "--)\n";
      }

      if ($childsa_encr_key_bits) {
        print "   Prop\[$childsa_prop_no\] I:$childsa_integ, E:$childsa_encr($childsa_encr_key_bits)";
      } else {
        print "   Prop\[$childsa_prop_no\] I:$childsa_integ, E:$childsa_encr";
      }

      if ($childsa_esn) {
        print " ESN";
      }

      if ($childsa_pfs) {
        print " PFS";
      }

      if ($childsa_anti_replay) {
        print " Anti-Replay";
      }

      if ($childsa_tfc_padding) {
        print " TFC-Pad";
      }

      if ($childsa_udp_encap) {
        print " UDP-Encap";
      }

      if ($childsa_out_of_order_drop) {
        print " OoO-Drp";
      }

      if ($childsa_collision_detected) {
        print " Nego-Col";
      }

      print "\n";
      print "   PMTU(D:$childsa_pmtu_default, C:$childsa_pmtu_cache)\n";

      my $tss_idx = 0;
      foreach my $tss_elm ($childsa_elm->getElementsByTagName('my_traffic_selector') ){

        if( $tss_idx == 0 ){
          print "\n";
          print "   \[TS: Local ==> Remote\]:\n";
        }

        my $my_tss = $tss_elm->getAttribute('traffic_selector');
        $my_tss =~ s/\s//g;

        print "    [$tss_idx] $my_tss\n";
        $tss_idx++;
      }

      $tss_idx = 0;
      foreach my $tss_elm ($childsa_elm->getElementsByTagName('peer_traffic_selector') ){

        if( $tss_idx == 0 ){
          print "\n";
          print "   \[TS: Remote ==> Local\]:\n";
        }
        
        my $peer_tss = $tss_elm->getAttribute('traffic_selector');
        $peer_tss =~ s/\s//g;

        print "    [$tss_idx] $peer_tss\n";
        $tss_idx++;
      }


      my $childsa_ar_tx_seq = $childsa_elm->getAttribute('antireplay_tx_seq');
      my $childsa_ar_rx_window_size = $childsa_elm->getAttribute('antireplay_rx_window_size');
      my $childsa_ar_rx_nesn_seq_last = $childsa_elm->getAttribute('antireplay_rx_non_esn_seq_last');
      my $childsa_ar_rx_esn_seq_b = $childsa_elm->getAttribute('antireplay_rx_esn_seq_b');
      my $childsa_ar_rx_esn_seq_t = $childsa_elm->getAttribute('antireplay_rx_esn_seq_t');
      my $childsa_ar_rx_window_mask = $childsa_elm->getAttribute('antireplay_rx_window_mask');

      if( $childsa_ar_rx_window_size ){

        print "\n";
        print "   \[Anti-Replay\]:\n";
        
        print "   Tx: Seq: $childsa_ar_tx_seq\n";
        print "   Rx: WinSize $childsa_ar_rx_window_size,";
        if( $childsa_ar_rx_nesn_seq_last ){
          my $seqt = $childsa_ar_rx_nesn_seq_last + $childsa_ar_rx_window_size;
          print " Seq B: $childsa_ar_rx_nesn_seq_last, Seq T: $seqt";
        }else{
          print " Seq B: $childsa_ar_rx_esn_seq_b, Seq T: $childsa_ar_rx_esn_seq_t";
        }
        print "\n";

        print "   Rx: WinMask\n";
        print "   ";
        my $msk_idx2 = 0;
        for( my $msk_idx = 1; $msk_idx <= $childsa_ar_rx_window_size; $msk_idx++ ){
          if( ($msk_idx % 10) == 0 ){
            print "$msk_idx2";
          }elsif( ($msk_idx % 10) == 1 ){
            print " ";
            $msk_idx2++;
          }else{
            print " ";
          }
        }
        print "\n   ";
        for( my $msk_idx = 1; $msk_idx <= $childsa_ar_rx_window_size; $msk_idx++ ){
          if( ($msk_idx % 10) == 1 ){
            print "1";            
          }elsif( ($msk_idx % 10) == 0 ){
            print "0";            
          }elsif( ($msk_idx % 5) == 0 ){
            print "+";            
          }else{
            print "-";            
          }
        }
        print "\n   $childsa_ar_rx_window_mask\n";
      }
      
      $childsa_idx++;
    }

    foreach my $internal_sns_elm ($resp_doc->getElementsByTagName('intenal_networks') ){

      print "\n  [ikev2cfg: Internal networks]:";

      my $internal_internal_gateway = $internal_sns_elm->getAttribute('internal_gateway');

      if ($internal_internal_gateway) {
        print " Gateway: $internal_internal_gateway\n";
      }else{
        print "\n";
      }

      my $internal_idx = 0;
      foreach my $internal_sn_elm ($internal_sns_elm->getElementsByTagName('intenal_subnet') ){

        my $internal_subnet = $internal_sn_elm->getAttribute('network');
        if ($internal_subnet) {
          print "    \[$internal_idx\] $internal_subnet\n";
        }

        $internal_idx++;
      }
    }

    foreach my $internal_split_dns_elm ($resp_doc->getElementsByTagName('split_dns') ){

      print "\n  [ikev2cfg: Internal DNS](Split DNS):";

      my $internal_internal_dns_server = $internal_split_dns_elm->getAttribute('internal_dns_server');

      if ($internal_internal_dns_server) {
        print " DNS server: $internal_internal_dns_server\n";
      }

      print "    Domain suffixes:\n";

      my $internal_idx = 0;
      foreach my $internal_sdn_elm ($internal_split_dns_elm->getElementsByTagName('split_dns_domain') ){

        my $domain_suffix = $internal_sdn_elm->getAttribute('internal_domain_suffix');

        if ($domain_suffix) {
          print "    \[$internal_idx\] $domain_suffix\n";
        }

        $internal_idx++;
      }
    }
  }

  print "\n";
  
  return;
}

sub vpn_status_vpn {
  
  my($address,$port,$auth_basic_key,$realm,$peerid_type,$peerid,$vpn_unique_id,$detail,$session_id,$vpn_idx) = @_;

  if ( !$realm || ( ( !$peerid_type || !$peerid ) && !$vpn_unique_id ) ) {
    print "realm, peerid_type, peerid or vpn_unique_id not specified.\n";
    print print_usage("status_vpn");
    return;
  }
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $exec_open = 0;
  if ( $session_id eq '' ) {

    $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
    if ( $session_id eq '' ) {
      return;
    }

    $exec_open = 1;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="status_vpn" vpn_realm="10" \
#  peer_id_type="fqdn" peer_id="responder.companya.com" vpn_unique_id="0x00000000000000000100000000000000"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "status_vpn" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $attr_peerid_type = $doc->createAttribute( "peer_id_type", $peerid_type );
  $root->setAttributeNode($attr_peerid_type);

  my $attr_peerid = $doc->createAttribute( "peer_id", $peerid );
  $root->setAttributeNode($attr_peerid);

  if ($vpn_unique_id) {
    my $attr_unique_id = $doc->createAttribute( "vpn_unique_id", $vpn_unique_id );
    $root->setAttributeNode($attr_unique_id);
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );
  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );
  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    # print "Status(VPN): \n" . $resp_doc->toString(1) . "\n";
    if ($detail) {
      show_status_vpn_detail($resp_doc,$vpn_idx);
    } else {
      show_status_vpn_summary($resp_doc,$vpn_idx);
    }
  }

  if ($exec_open) {
    close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  }

  return;
}

sub vpn_status_enum_vpn {

#
# First, getting peer IDs' list. Next, getting each info about each peer one by one.
# This is for preventing programs from handling a too huge XML response
# which needs huge memory.
#
  my ( $address, $port, $auth_basic_key, $realm, $detail ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print print_usage("status_vpn");
    return;
  }

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="status_vpn_peers" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "status_vpn_peers" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    # print "Status(VPN): \n" . $resp_doc->toString(1) . "\n";
    my $peer_idx = 0;

    foreach my $peer_elm ( $resp_doc->getElementsByTagName('peer') ) {

      my $vpn_peer_id_type = $peer_elm->getAttribute('peerid_type');
      my $vpn_peer_id      = $peer_elm->getAttribute('peerid');
      my $vpn_unique_id    = $peer_elm->getAttribute('vpn_unique_id');

      vpn_status_vpn($address,$port,$auth_basic_key,$realm,$vpn_peer_id_type,$vpn_peer_id,$vpn_unique_id,$detail,$session_id,$peer_idx);

      $peer_idx++;
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  
  return;
}

sub vpn_status_peers {

  my ( $address, $port, $auth_basic_key, $realm, $detail ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print print_usage("status_peers");
    return;
  }

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="status_vpn_peers" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "status_vpn_peers" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    # print "Status(VPN): \n" . $resp_doc->toString(1) . "\n";
    my $peer_idx = 0;
    foreach my $peer_elm ( $resp_doc->getElementsByTagName('peer') ) {

      my $vpn_vpn_realm_id      = $peer_elm->getAttribute('vpn_realm_id');
      my $vpn_vpn_realm_name    = $peer_elm->getAttribute('vpn_realm_name');
      my $vpn_peer_id_type      = $peer_elm->getAttribute('peerid_type');
      my $vpn_peer_id           = $peer_elm->getAttribute('peerid');
      my $vpn_internal_if_addr  = $peer_elm->getAttribute('internal_if_addr');
      my $vpn_intenal_peer_addr = $peer_elm->getAttribute('intenal_peer_addr');
      my $vpn_peer_addr         = $peer_elm->getAttribute('peer_addr');
      my $vpn_my_addr           = $peer_elm->getAttribute('my_addr');
      my $vpn_my_if_name        = $peer_elm->getAttribute('my_if_name');
      my $vpn_ike_state         = $peer_elm->getAttribute('ikesa_state');
      my $vpn_childsa_state     = $peer_elm->getAttribute('childsa_state');

      if( !$vpn_intenal_peer_addr ){
        $vpn_intenal_peer_addr = "unknown";          
      }
      
      if( !$vpn_internal_if_addr ){
        $vpn_internal_if_addr = "unknown";
      }

      if ( !$vpn_vpn_realm_name ) {
        print "\[$peer_idx\] Rlm($vpn_vpn_realm_id)";
      } else {
        print "\[$peer_idx\] Rlm($vpn_vpn_realm_name:$vpn_vpn_realm_id)";
      }

      if ( $vpn_peer_id eq 'any' ) {
        print " unknown";
      } else {
        print " $vpn_peer_id($vpn_peer_id_type)";
      }

      if ($detail) {

        print "\n  $vpn_my_addr($vpn_my_if_name,\[IN\]$vpn_internal_if_addr) ==> $vpn_peer_addr(\[IN\]$vpn_intenal_peer_addr)\n";

        if ($vpn_ike_state) {
          print "  IKE($vpn_ike_state)";
        } else {
          print "  IKE(--)";
        }

        if ($vpn_childsa_state) {
          print " Child SA($vpn_childsa_state)";
        } else {
          print " Child SA(--)";
        }

      } else {
        print " $vpn_peer_addr(\[IN\]$vpn_intenal_peer_addr)";
      }

      print "\n";
      $peer_idx++;
    }
  }
  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
}

sub vpn_status_bridge {
  
  my ( $address, $port, $auth_basic_key, $realm, $detail ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print print_usage("status_bridge");
    return;
  }

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="status_bridge" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "status_bridge" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    #print "Status(Bridge): \n" . $resp_doc->toString(1) . "\n";
    print "\[Bridge table\] Rlm($realm)\n";

    my $br_idx = 0;
    foreach my $br_elm ( $resp_doc->getElementsByTagName('bridge') ) {

      my $br_peer_id_type = $br_elm->getAttribute('peerid_type');
      my $br_peer_id      = $br_elm->getAttribute('peerid');
      my $br_dest_mac     = $br_elm->getAttribute('dest_mac');
      my $br_side         = $br_elm->getAttribute('side');
      my $br_static_cache = $br_elm->getAttribute('static_cache');
      my $br_time_elapsed = $br_elm->getAttribute('time_elapsed');

      if ( !$detail ) {

        print " \[$br_idx\] $br_dest_mac  $br_side";

      } else {

        if ( !$br_peer_id ) {
          print " \[$br_idx\] $br_dest_mac  $br_side";
        } else {
          print " \[$br_idx\] $br_dest_mac  $br_side       $br_peer_id($br_peer_id_type)";
        }

        if ( !$br_static_cache || $br_static_cache eq "0" ) {
          print " dynamic";
        } else {
          print " $br_static_cache";
        }

        print " Elapsed($br_time_elapsed)";
      }

      print "\n";
      $br_idx++;
    }
  }
  
  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_status_arp {
  
  my ( $address, $port, $auth_basic_key, $realm, $detail ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print print_usage("status_arp");
    return;
  }
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="status_arp" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "status_arp" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }

  } else {
    
    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    #print "Status(Bridge): \n" . $resp_doc->toString(1) . "\n";
    print "\[ARP table\] Rlm($realm)\n";

    my $br_idx = 0;
    foreach my $br_elm ( $resp_doc->getElementsByTagName('arp') ) {

      my $br_peer_id_type = $br_elm->getAttribute('peerid_type');
      my $br_peer_id      = $br_elm->getAttribute('peerid');
      my $br_dest_mac     = $br_elm->getAttribute('dest_mac');
      my $br_dest_ip      = $br_elm->getAttribute('dest_addr');
      my $br_side         = $br_elm->getAttribute('side');
      my $br_static_cache = $br_elm->getAttribute('static_cache');
      my $br_time_elapsed = $br_elm->getAttribute('time_elapsed');

      if ( !$detail ) {

        print "\[$br_idx\] $br_dest_ip  $br_dest_mac  $br_side";

      } else {

        if ( !$br_peer_id ) {
          print " \[$br_idx\] $br_dest_ip  $br_dest_mac  $br_side";
        } else {
          print " \[$br_idx\] $br_dest_ip  $br_dest_mac  $br_side       $br_peer_id($br_peer_id_type)";
        }

        if ( !$br_static_cache || $br_static_cache eq "0" ) {
          print " dynamic";
        } else {
          print " $br_static_cache";
        }

        print " Elapsed($br_time_elapsed)";
      }

      print "\n";
      $br_idx++;
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_status_address_pool {
  
  my ( $address, $port, $auth_basic_key, $realm, $detail ) = @_;
  if ( !$realm ) {
    print "realm not specified.\n";
    print print_usage("status_address_pool");
    return;
  }
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="status_address_pool" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "status_address_pool" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    # print "Status(Bridge): \n" . $resp_doc->toString(1) . "\n";
    print "\[Internal address pool\] Rlm($realm)\n";

    my $addr_pool_idx = 0;
    foreach my $addr_pool_elm ( $resp_doc->getElementsByTagName('address_pool') )
    {
      my $addr_pool_peer_id_type  = $addr_pool_elm->getAttribute('peerid_type');
      my $addr_pool_peer_id       = $addr_pool_elm->getAttribute('peerid');
      my $addr_pool_assigned_addr = $addr_pool_elm->getAttribute('assigned_addr');
      my $addr_pool_expire = $addr_pool_elm->getAttribute('expire');

      print "  [$addr_pool_idx\] $addr_pool_assigned_addr $addr_pool_peer_id($addr_pool_peer_id_type)";
      if ( !$addr_pool_expire ) {
        print " In-Use";
      } else {
        print " Cached(Expire:$addr_pool_expire)";
      }

      print "\n";
      $addr_pool_idx++;
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_config_peers {
  
  my ( $address, $port, $auth_basic_key, $realm, $detail ) = @_;

  if( !$realm ){
    $realm = "0";    
  }

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_peers" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_peers" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    # print "Status(VPN): \n" . $resp_doc->toString(1) . "\n";
    my $peer_idx = 0;
    foreach my $peer_elm ( $resp_doc->getElementsByTagName('peer') ) {

      my $vpn_vpn_realm_id    = $peer_elm->getAttribute('vpn_realm_id');
      my $vpn_vpn_realm_name  = $peer_elm->getAttribute('vpn_realm_name');
      my $vpn_peer_id_type    = $peer_elm->getAttribute('peerid_type');
      my $vpn_peer_id         = $peer_elm->getAttribute('peerid');
      my $vpn_peer_addr       = $peer_elm->getAttribute('peer_addr');
      my $vpn_is_access_point = $peer_elm->getAttribute('is_access_point');

      if ( !$vpn_vpn_realm_name ) {
        print "\[$peer_idx\] Rlm($vpn_vpn_realm_id)";
      } else {
        print "\[$peer_idx\] Rlm($vpn_vpn_realm_name:$vpn_vpn_realm_id)";
      }

      print " $vpn_peer_id($vpn_peer_id_type)";

      if ( $vpn_peer_addr && ( $vpn_peer_addr ne '0.0.0.0' ) ) {
        print " \[$vpn_peer_addr\]";
      } else {
        print " \[--\]";
      }

      if ($vpn_is_access_point) {
        print " AP";
      }
      print "\n";

      $peer_idx++;
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  
  return;
}

sub vpn_config_get {
  
  my ( $address, $port, $auth_basic_key, $realm, $file, $detail ) = @_;

  if( !$realm ){
    $realm = "0";    
  }

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_get" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_get" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
    print $doc->toString(1);

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if ( !$file ) {

      print $resp_doc->toString(1);

    } else {

      if ( !open( CONFIG_XML, "> ./$file" ) ) {
        print "Can't open $file.\n";
      } else {
        print CONFIG_XML $resp_doc->toString(1);
        close(CONFIG_XML);
      }
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );

  return;
}

sub vpn_config_realms {
  
  my ( $address, $port, $auth_basic_key ) = @_;


  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_enum_realms"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_enum_realms" );
  $root->setAttributeNode($attr_action);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    #print "Status(VPN): \n" . $resp_doc->toString(1) . "\n";
    my $rlm_idx = 0;
    foreach my $peer_elm ( $resp_doc->getElementsByTagName('vpn_realm') ) {

      my $vpn_vpn_realm_id    = $peer_elm->getAttribute('id');
      my $vpn_vpn_realm_name  = $peer_elm->getAttribute('name');
      my $vpn_vpn_realm_mode  = $peer_elm->getAttribute('mode');
      my $vpn_vpn_realm_desc  = $peer_elm->getAttribute('description');

      print "\[$rlm_idx\] $vpn_vpn_realm_id:";
      if ( $vpn_vpn_realm_name ) {
        print " $vpn_vpn_realm_name";
      }
      if ( $vpn_vpn_realm_mode ) {
        print " (mode: $vpn_vpn_realm_mode)";
      }
      if ( $vpn_vpn_realm_desc ) {
        print " :$vpn_vpn_realm_desc";
      }
      print "\n";
      $rlm_idx++;
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );

  return;
}

sub vpn_status_interface {
  
  my ( $address, $port, $auth_basic_key, $flag ) = @_;


  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_enum_realms"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "status_enum_interfaces" );
  $root->setAttributeNode($attr_action);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    #print "Status(VPN): \n" . $resp_doc->toString(1) . "\n";
    my $rlm_idx = 0;
    foreach my $peer_elm ( $resp_doc->getElementsByTagName('interface') ) {

      my $if_vpn_realm_id  = $peer_elm->getAttribute('vpn_realm');

      if ( !$if_vpn_realm_id || $if_vpn_realm_id eq '0' ) {

        my $if_id    = $peer_elm->getAttribute('id');
        my $if_name  = $peer_elm->getAttribute('name');
        my $if_addr_v4  = $peer_elm->getAttribute('address_v4');
        my $if_prefixlen  = $peer_elm->getAttribute('prefix_length');
        my $if_mac  = $peer_elm->getAttribute('mac');
        my $if_mtu  = $peer_elm->getAttribute('mtu');

        print "\[$rlm_idx\] $if_name:";
        if ( $if_addr_v4 ) {
          print " $if_addr_v4";
          if ( $if_prefixlen ) {
            print "/$if_prefixlen";
           }
         }
        if ( $if_mac ) {
          print " (MAC:$if_mac, MTU:$if_mtu, index:$if_id)";
         }
        print "\n";
        $rlm_idx++;
      }
    }

    if( $flag ){
  
      print "\nTUN/TAP interfaces:\n";
  
      $rlm_idx = 0;
      foreach my $peer_elm ( $resp_doc->getElementsByTagName('interface') ) {
  
        my $if_vpn_realm_id  = $peer_elm->getAttribute('vpn_realm');
  
        if ( $if_vpn_realm_id && $if_vpn_realm_id ne '0' ) {
  
          my $if_id    = $peer_elm->getAttribute('id');
          my $if_name  = $peer_elm->getAttribute('name');
          my $if_addr_v4  = $peer_elm->getAttribute('address_v4');
          my $if_prefixlen  = $peer_elm->getAttribute('prefix_length');
          my $if_mac  = $peer_elm->getAttribute('mac');
          my $if_mtu  = $peer_elm->getAttribute('mtu');
  
          print "\[$rlm_idx\] $if_name:(Rlm:$if_vpn_realm_id)";
          if ( $if_addr_v4 ) {
            print " $if_addr_v4";
            if ( $if_prefixlen ) {
              print "/$if_prefixlen";
             }
           }
          if ( $if_mac ) {
            print " (MAC:$if_mac, MTU:$if_mtu, index:$if_id)";
           }
          print "\n";
          $rlm_idx++;
        }
      }
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );

  return;
}

sub vpn_realm_exists {

  my ( $address, $port, $auth_basic_key, $realm ) = @_;

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return -1;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_realm_exists"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_realm_exists" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp   = $ua->request($req);
  my $result = 1;

  if ( !$resp->is_success ) {

    if ( $resp->status_line !~ '404' ) {

      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
      print $doc->toString(1);
      $result = -1;

    } else {

      $result = 0;
    }
  }
  
  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );

  return $result;
}

sub vpn_realm_create {
  
  my ( $address, $port, $auth_basic_key, $realm, $realm_name, $realm_mode, $realm_desc ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print_usage("realm_create");
    return -1;
  }

  my $realm_exists = vpn_realm_exists( $address, $port, $auth_basic_key, $realm );

  if ( $realm_exists < 0 ) {

    print "Error occured. Abort!\n";
    return -1;

  } elsif ( $realm_exists == 1 ) {
    
    print "VPN realm $realm already exists. \n";
    return 0;
  }


  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return -1;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_create_realm" vpn_realm="10" 
# vpn_realm_name="CompanyA"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_create_realm" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  if( $realm_name ){
    
    my $attr_realm_name = $doc->createAttribute( "vpn_realm_name", $realm_name );
    $root->setAttributeNode($attr_realm_name);
  }

  if( $realm_mode ){
    
    my $attr_realm_mode = $doc->createAttribute( "vpn_realm_mode", $realm_mode );
    $root->setAttributeNode($attr_realm_mode);
  }

  if( $realm_desc ){
    
    my $attr_realm_desc = $doc->createAttribute( "vpn_realm_desc", $realm_desc );
    $root->setAttributeNode($attr_realm_desc);
  }
  
  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp   = $ua->request($req);
  my $result = 0;

  if ( !$resp->is_success ) {

    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);

    $result = -1;
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );

  return 0;
}

sub vpn_realm_delete {
  
  my ( $address, $port, $auth_basic_key, $realm ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print_usage("realm_delete");
    return;
  }

  my $realm_exists = vpn_realm_exists( $address, $port, $auth_basic_key, $realm );

  if ( $realm_exists < 0 ) {

    print "Error occured. Abort!\n";
    return;

  } elsif ( $realm_exists == 0 ) {
    
    print "VPN realm $realm does not exist. \n";
    return;
  }
  
  {
    print "Do you really delete a configuration of the VPN realm $realm? [N/y]\n";
  
    my $ans = get_stdin(0);
  
    if ( $ans eq "y" ) {
    }else{
      return;
    }
  }
  

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_delete_realm" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;
  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);
  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);
  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);
  my $attr_action = $doc->createAttribute( "action", "config_delete_realm" );
  $root->setAttributeNode($attr_action);
  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);
  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );
  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );
  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }
  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
}

sub vpn_realm_update {
  
  my ( $address, $port, $auth_basic_key, $realm, $file ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print_usage("realm_update");
    return;
  }

  if ( !$file ) {
    print " file not specified.\n";
    print_usage("realm_update");
    return;
  }

  my $parser          = XML::LibXML->new;
  my $cfg_doc         = $parser->parse_file($file);
  my @cfg_realm_elms  = $cfg_doc->getElementsByTagName('rhp_config');
  my @auth_realm_elms = $cfg_doc->getElementsByTagName('rhp_auth');

  if ( @cfg_realm_elms == 0 && @auth_realm_elms == 0 ) {
    print " \<rhp_config\> and \<rhp_auth\> not found.\n";
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_update_realm" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_update_realm" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  if ( @cfg_realm_elms > 0 ) {
    $root->addChild( $cfg_realm_elms[0] );
  }

  if ( @auth_realm_elms > 0 ) {
    $root->addChild( $auth_realm_elms[0] );
  }

  #print $doc->toString(1);
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;

  my $req = HTTP::Request->new( PUT => $url );
  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );
  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  
  return;
}

sub vpn_auth_update_my_info {

  my($address,$port,$auth_basic_key,$realm,$myid_type,$myid,$my_auth_method,$psk)= @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print_usage("auth_update");
    return;
  }

  if( !$myid_type ){
    print "myid_type not specified.\n";
    print_usage("auth_update");
    return;
  }

  if ( ( $myid_type ne "fqdn" ) && ( $myid_type ne "email" ) && 
       ( $myid_type ne "dn" ) && ( $myid_type ne "subjectaltname" ) && ( $myid_type ne "cert_auto" ) ) {
         
    print "Invalid myid_type specified.: $myid_type\n";
    print_usage("auth_update");
    return;
  }
  
  if ( $my_auth_method eq "psk" ) {

    if ( !$myid ) {
      print "my_id not specified.\n";
      print_usage("auth_update");
      return;
    }
    
    if ( !$psk ) {
      print "psk not specified.\n";
      print_usage("auth_update");
      return;
    }

    if ( ( $myid_type ne "email" ) && ( $myid_type ne "fqdn" ) ) {

      print "Invalid myid_type specified. : $myid_type\n";
      print_usage("auth_update");
      return;
    }

  }elsif ( $my_auth_method eq "rsa-sig" ) {

    if( $myid ){
      print "Can't specify my_id for rsa-sig method.: $myid\n";
      print_usage("auth_update");
      return;
    }

    if ( ( $myid_type ne "dn" ) && ( $myid_type ne "subjectaltname" ) && ( $myid_type ne "cert_auto" ) ) {

      print "Invalid myid_type specified. : $myid_type\n";
      print_usage("auth_update");
      return;
    }

  }else{

    print "Valid my_auth_method not specified.\n";
    print_usage("auth_update");
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_update_my_key_info" vpn_realm="10">
#  <my_auth id_type="fqdn" id="initiator.companya.com" auth_method="psk">
#    <my_psk key="secret"/>
#  </my_auth>
# </rhp_http_bus_request>
#
  my $doc  = XML::LibXML->createDocument;
  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_update_my_key_info" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $my_auth = $doc->createElement("my_auth");
  $root->addChild($my_auth);

  my $attr_id_type = $doc->createAttribute( "id_type", $myid_type );
  $my_auth->setAttributeNode($attr_id_type);

  if ($myid) {
    my $attr_id = $doc->createAttribute( "id", $myid );
    $my_auth->setAttributeNode($attr_id);
  }

  my $attr_auth_method = $doc->createAttribute( "auth_method", $my_auth_method );

  $my_auth->setAttributeNode($attr_auth_method);

  if ($psk) {

    my $my_psk = $doc->createElement("my_psk");
    $my_auth->addChild($my_psk);

    my $attr_key = $doc->createAttribute( "key", $psk );
    $my_psk->setAttributeNode($attr_key);
  }

  #print $doc->toString(1);
  
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  
  return;
}

sub vpn_auth_update_peer_info {
  
  my ( $address, $port, $auth_basic_key, $realm, $peerid_type, $peerid, $psk ) = @_;

  if ( !$realm ) {

    print "realm not specified.\n";
    print_usage("auth_update");
    return;
  }

  if( !$peerid || !$peerid_type ){
    
    print "peerid_type or peerid not specified.\n";
    print_usage("auth_update");
    return;
  }

  if ( ( $peerid_type ne "fqdn" ) && ( $peerid_type ne "email" ) && 
       ( $peerid_type ne "dn" ) && ( $peerid_type ne "any" ) ) {
      
    print "Invalid peerid_type specified. : $peerid_type\n";
    print_usage("auth_update");
    return;
  }
  
  if( $peerid_type eq "any" ){
    $peerid = "any";
  }


#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_update_peer_key_info" vpn_realm="10">
#  <peer id_type="fqdn" id="initiator.companya.com">
#    <peer_psk key="secret"/>
#  </peer>
# </rhp_http_bus_request>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_update_peer_key_info" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $peer = $doc->createElement("peer");
  $root->addChild($peer);

  my $attr_id_type = $doc->createAttribute( "id_type", $peerid_type );
  $peer->setAttributeNode($attr_id_type);

  my $attr_id = $doc->createAttribute( "id", $peerid );
  $peer->setAttributeNode($attr_id);

  if( $psk ){

    my $peer_psk = $doc->createElement("peer_psk");
    $peer->addChild($peer_psk);

    my $attr_key = $doc->createAttribute( "key", $psk );
    $peer_psk->setAttributeNode($attr_key);
  }
  
  #print $doc->toString(1);

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  
  return;
}

sub vpn_auth_delete_peer_info {
  
  my ( $address, $port, $auth_basic_key, $realm, $peerid_type, $peerid ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print_usage("admin_delete");
    return;
  }

  if ( !$peerid ) {

    if ( $peerid_type ne "any" ) {

      print_usage("admin_delete");
      return;

    } else {

      $peerid = "any";
    }
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_delete_peer_key_info" vpn_realm="10">
#  <peer id_type="fqdn" id="initiator.companya.com">
#  </peer>
# </rhp_http_bus_request>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_delete_peer_key_info" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $peer = $doc->createElement("peer");
  $root->addChild($peer);

  my $attr_id_type = $doc->createAttribute( "id_type", $peerid_type );
  $peer->setAttributeNode($attr_id_type);

  my $attr_id = $doc->createAttribute( "id", $peerid );
  $peer->setAttributeNode($attr_id);

  #print $doc->toString(1);
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_cert_update {
  
  my($address,$port,$auth_basic_key,$realm,$cert_password,$my_cert,$my_priv_key,$ca_certs) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print_usage("cert_update");
    return;
  }

  if ( ( $my_cert && !$my_priv_key ) || ( !$my_cert && $my_priv_key ) ) {
    print "my_cert or my_priv_key not specified.\n";
    print_usage("cert_update");
    return;
  }
  
  if( !$cert_password && !$my_cert && !$my_priv_key && !$ca_certs ){
    print_usage("cert_update");
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_update_cert" vpn_realm="10">
#  <cert_store password="secret">
#    <my_cert>
#    ............
#    </my_cert>
#    <my_priv_key>
#    ............
#    </my_priv_key>
#    <ca_certs>
#    ............
#    </ca_certs>
#  </cert_store>
# </rhp_http_bus_request>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_update_cert" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $cert_store = $doc->createElement("cert_store");
  $root->addChild($cert_store);

#    $hoge_text = $doc->createTextNode("HOGE-");
#    $cert_store->addChild($hoge_text);

  if ($cert_password) {
    my $attr_password = $doc->createAttribute( "password", $cert_password );
    $cert_store->setAttributeNode($attr_password);
  }

  if ($my_cert) {

    my $my_cert_elm = $doc->createElement("my_cert");
    $cert_store->addChild($my_cert_elm);

    if ( !open( FH, "$my_cert" ) ) {
      print "my_cert: $my_cert not found.\n";
      return;
    }

    my $cont;
    while (<FH>) {
      $cont = $cont . $_;
    }

    my $cert_text = $doc->createCDATASection($cont);
    $my_cert_elm->addChild($cert_text);
    close(FH);
  }

  if ($my_priv_key) {

    my $my_priv_key_elm = $doc->createElement("my_priv_key");
    $cert_store->addChild($my_priv_key_elm);

    if ( !open( FH, "$my_priv_key" ) ) {
      print "my_priv_key: $my_priv_key not found.\n";
      return;
    }

    my $cont = "";
    while (<FH>) {
      $cont = $cont . $_;
    }

    my $cert_text = $doc->createCDATASection($cont);
    $my_priv_key_elm->addChild($cert_text);
    close(FH);
  }

  if ($ca_certs) {

    my $ca_certs_elm = $doc->createElement("ca_certs");
    $cert_store->addChild($ca_certs_elm);

    if ( !open( FH, "$ca_certs" ) ) {
      print "ca_cert: $ca_certs not found.\n";
      return;
    }

    my $cont = "";
    while (<FH>) {
      $cont = $cont . $_;
    }

    my $cert_text = $doc->createCDATASection($cont);
    $ca_certs_elm->addChild($cert_text);
    close(FH);
  }

  # print $doc->toString(1);

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  
  return;
}

sub vpn_cert_delete {
  
  my ( $address, $port, $auth_basic_key, $realm ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print_usage("cert_delete");
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_delete_cert" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_delete_cert" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);
  

  #print $doc->toString(1);
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_cert_get_printed_impl {
  
  my ( $address, $port, $auth_basic_key, $realm, $is_my_cert ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print_usage("cert_get");
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_get_my_printed_cert" vpn_realm="10"/>
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_get_printed_ca_certs" vpn_realm="10"/>
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action;
  if($is_my_cert){
    $attr_action = $doc->createAttribute( "action", "config_get_my_printed_cert" );
  }else{
    $attr_action = $doc->createAttribute( "action", "config_get_printed_ca_certs" );
  }
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);
  

  #print $doc->toString(1);
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    #print $doc->toString(1);

  }else{

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    #print "Printed Cert(s): \n" . $resp_doc->toString(1) . "\n";
    my $certs_elm = $resp_doc->getElementsByTagName('rhp_printed_certs');
    print $certs_elm;
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_cert_get_printed {
  
  my ( $address, $port, $auth_basic_key, $realm, $is_my_cert ) = @_;
  
  print '[My Certificate]:' . "\n";
  vpn_cert_get_printed_impl($address, $port, $auth_basic_key, $realm,1);

  print "\n\n";
  print '[CA Certificate]:' . "\n";
  vpn_cert_get_printed_impl($address, $port, $auth_basic_key, $realm,0);
}

sub vpn_admin_update {
  
  my ( $address, $port, $auth_basic_key, $admin, $password, $admin_id,$admin_password, $realm ) = @_;

  if ( !$realm ) {
    $realm = "0";
  }

  if ( !$admin_id || !$admin_password ) {
    print " admin_id or admin_password not specified. \n";
    print_usage("admin_update");
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_update_admin" vpn_realm="10">
#   <admin id="admin" key="secret"/>
# </rhp_http_bus_request>
#
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

  #print $doc->toString(1);
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }
  
  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);

  } else {

    if ( $admin_id eq $admin ) {
      $auth_basic_key = LWP::Authen::Basic->auth_header( $admin, $admin_password );
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_admin_delete {
  
  my ( $address, $port, $auth_basic_key, $admin, $password, $admin_id ) = @_;

  if ( !$admin_id ) {
    print " admin_id not specified. \n";
    print_usage("admin_delete");
    return;
  }

  if ( $admin_id eq $admin ) {
    print " admin_id is the same id as admin. Can't delete own account.\n";
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_delete_admin">
#   <admin id="admin"/>
# </rhp_http_bus_request>
#
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

  #print $doc->toString(1);
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }
  
  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_admin_get {
  
  my ( $address, $port, $auth_basic_key, $admin, $password ) = @_;

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_enum_admin">
#   <admin id="admin"/>
# </rhp_http_bus_request>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_enum_admin" );
  $root->setAttributeNode($attr_action);

  #print $doc->toString(1);
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }
  
  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
    print $doc->toString(1);

  }else{

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    print $resp_doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_web_mng_update {
  
  my ( $address, $port, $auth_basic_key, $mng_address, $mng_port ) = @_;

  if ( !$mng_address ) {
    print "Listening address NOT specified.\n";
    print_usage("web-mng");
    return;
  }
  
  if ( !$mng_port ) {
    $mng_port = '32501';
  }
  

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_update_global_config"/>
#
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

  my $attr_mng_addr = $doc->createAttribute( "address_v4", $mng_address );
  $admin_service->setAttributeNode($attr_mng_addr);

  my $attr_mng_port = $doc->createAttribute( "port", $mng_port );
  $admin_service->setAttributeNode($attr_mng_port);

  my $attr_mng_protocol = $doc->createAttribute( "protocol", "http" );
  $admin_service->setAttributeNode($attr_mng_protocol);


  #print $doc->toString(1);
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub cfg_archive_extract {

  my ( $arch_password, $file ) = @_;
  
  if( !$file ){
    print "Please specify a configuration archive(*.rcfg).\n";
    print_usage("cfg-archive-extract");
    return;
  }

  if( ! -e "./$file" ){
    print "./$file does not exist.\n";
    return;
  }
  
  if( !$arch_password ){
    print "Please specify password to extract the configuration archive($file).\n";
    print_usage("cfg-archive-extract");
    return;
  }

  if( ! -e "./cfg-archive" ){
    if( ! mkdir("./cfg-archive",0700) ){
      print "Failed to make directory ./cfg-archive.\n";  
      return;
    }
  }

  if( ! -e "./cfg-archive/rhpmain" ){
    if( ! mkdir("./cfg-archive/rhpmain",0700) ){
      print "Failed to make directory ./cfg-archive/rhpmain.\n";  
      return;
    }
  }

  if( ! -e "./cfg-archive/rhpprotected" ){
    if( ! mkdir("./cfg-archive/rhpprotected",0700) ){
      print "Failed to make directory ./cfg-archive/rhpprotected.\n";  
      return;
    }
  }

  system("rm -f ./cfg-archive/rhpmain/*");
  system("rm -f ./cfg-archive/rhpprotected/*");
  system("rm -f ./cfg-archive/*");

    
  if( system("openssl enc -d -base64 -in $file -out ./cfg-archive/tmp0.tar") ){
    print "[ERROR] Fail to decrypt the configuraiton archive.(1)\n";
    return;
  }

  if( system("tar x -f ./cfg-archive/tmp0.tar -C ./cfg-archive") ){
    print "[ERROR] Fail to extract the configuraiton archive.(1)\n";
    return;
  }
  
  if( system("openssl enc -d -aes256 -in ./cfg-archive/rockhopper_main.rcfg -out ./cfg-archive/rockhopper_main.tgz -pass pass:$arch_password") ){
    print "[ERROR] Fail to decrypt the configuraiton archive.(2)\n";
    return;
  }
  
  if( system("openssl enc -d -aes256 -in ./cfg-archive/rockhopper_syspxy.rcfg -out ./cfg-archive/rockhopper_syspxy.tgz -pass pass:$arch_password") ){
    print "[ERROR] Fail to decrypt the configuraiton archive.(3)\n";
    return;
  }

  if( system("tar xz -f ./cfg-archive/rockhopper_main.tgz -C ./cfg-archive/rhpmain") ){
    print "[ERROR] Fail to extract the configuraiton archive.(2)\n";
    return;
  }

  if( system("tar xz -f ./cfg-archive/rockhopper_syspxy.tgz -C ./cfg-archive/rhpprotected") ){
    print "[ERROR] Fail to extract the configuraiton archive.(3)\n";
    return;
  }

  system("rm -f ./cfg-archive/*.tgz");
  system("rm -f ./cfg-archive/*.rcfg");
  system("rm -f ./cfg-archive/*.tar");

  print "\n[CAUTION]\n";
  print " All files are successfully extracted into ./cfg-archive.\n";
  print " These files include secret keys and other important settings.\n\n";
  
  return;
}

sub cfg_archive_save {
  
  my ( $address, $port, $auth_basic_key, $arch_password, $file ) = @_;

  if( !$arch_password ){
    print "Please specify password to generate configuration archive.\n";
    print_usage("cfg-archive-save");
    return;
  }

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_backup_save" password="$arch_password"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_backup_save" );
  $root->setAttributeNode($attr_action);

  my $attr_arch_password = $doc->createAttribute( "password", $arch_password );
  $root->setAttributeNode($attr_arch_password);


  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
    print $doc->toString(1);

    close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );

  } else {
  
    close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
    
    my $res = 0;

    print "Generating configuration's archive...\n";
    for( my $i = 1; $i <= 10; $i++ ){

      sleep(3);    
      
      my $arc_url = 'http://' . $address . ':' . $port . '/protected/config/rockhopper.rcfg';
      my $arc_req = HTTP::Request->new( GET => $arc_url );
    
      $arc_req->header( "Accept"         => 'application/octet-stream' );
      $arc_req->header( "Accept-Charset" => 'utf-8' );
      $arc_req->header( "Authorization"  => $auth_basic_key );
      $arc_req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
      $arc_req->content( $doc->toString(1) );
    
      my $arc_resp = $ua->request($arc_req);
    
      if ( $arc_resp->is_success ) {
      
        if( !$file ){
          $file = "rockhopper.rcfg"
        }
  
        if ( !open( CONFIG_ARCH, "> ./$file" ) ) {
          print "Can't open $file.\n";
        } else {
          print CONFIG_ARCH $arc_resp->decoded_content;
          close(CONFIG_ARCH);
        }
        
        $res = 1;
        last;

      }else{
        print "ERROR: " . $arc_resp->status_line . "\n";
        print "Now retrying to get configuration's archive...($i/5)\n";
      }
    }
    
    if( !$res ){
        print "Failed to get configuration's archive.\n";
    }else{
        print "Configuration's archive was saved as ./$file.\n";
    }
  }

  return;
}

sub vpn_global_update {
  
  my ( $address, $port, $auth_basic_key, $file ) = @_;

  if ( !$file ) {
    print " file not specified.\n";
    print_usage("global_update");
    return;
  }

  my $parser         = XML::LibXML->new;
  my $cfg_doc        = $parser->parse_file($file);
  my @cfg_realm_elms = $cfg_doc->getElementsByTagName('rhp_config');
  if ( @cfg_realm_elms == 0 ) {
    print " \<rhp_config\> not found.\n";
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_update_global_config"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_update_global_config" );
  $root->setAttributeNode($attr_action);

  if ( @cfg_realm_elms > 0 ) {
    $root->addChild( $cfg_realm_elms[0] );
  }

  #print $doc->toString(1);
  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #$ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  return;
}

sub vpn_global_get {
  
  my ( $address, $port, $auth_basic_key, $file) = @_;

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_get_global_config"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_get_global_config" );
  $root->setAttributeNode($attr_action);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . " or no content.\n";
    print $doc->toString(1);

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if ( !$file ) {

      print $resp_doc->toString(1);

    } else {

      if ( !open( CONFIG_XML, "> ./$file" ) ) {
        print "Can't open $file.\n";
      } else {
        print CONFIG_XML $resp_doc->toString(1);
        close(CONFIG_XML);
      }
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );

  return;
}

sub vpn_flush_bridge {
  
  my ( $address, $port, $auth_basic_key, $realm ) = @_;

  if( !$realm ){
    $realm = "0";    
  }

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="flush_bridge" vpn_realm="10"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "flush_bridge" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
      print $doc->toString(1);

    }else{

      print "No information found.\n";      
    }
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );

  return;
}

sub wizard_confirm_vpn {

  my ( $address, $port, $auth_basic_key, $realm ) = @_;

  my $create_new_realm = 0;
  my $realm_exists = vpn_realm_exists( $address, $port, $auth_basic_key, $realm );
  
  if ( $realm_exists < 0 ) {

    print "Error occured. Abort!\n";
    return -1;

  } elsif ( $realm_exists == 0 ) {

    print "\n";
    print "VPN realm $realm does not exist. Do you create the new realm?\n";
    print "[Y/n/q]\n";

    my $ans = get_stdin_chars("y","y","n");

    if ( $ans ne "y" ) {
      return -1;
    }


    $create_new_realm = 1;

  } else {

    while( 1 ){

      print "\n";
      print "VPN realm $realm exists. Do you overwrite the realm's config?\n";
      print "To see the config, please specify 's'.  [y/N/s]\n";
  
      my $ans = get_stdin_chars("n","y","n","s");
  
      if ( $ans eq "n" ) {

        return -1;      
      
      } elsif ( $ans eq "s" ) {
      
        vpn_config_get( $address, $port, $auth_basic_key, $realm, 0, 1 );
        print "\n";

      }else{
        last;
      }
    }        
  }
  
  return $create_new_realm;
}

sub wizard_get_new_vpn_name {
  
  my ($realm) = @_;

  my $vpn_realm_name;
  
  while( 1 ){

    print "\n";
    print "Please specify a name of the VPN realm $realm.\n";
    print "[realm_name/q]\n";

    my $ans = get_stdin2(1,0);
  
    if ( $ans eq "q" ) { 
        
      confirm_exit(); 
        
    }else{
        
      $vpn_realm_name = $ans;
      last;
    }      
  }
  
  return $vpn_realm_name;
}

sub wizard_get_roles {
  
  my ($roles_type,$roles,$realm) = @_;
  
  my $idx = 0;
  while ( 1 ) {

    if ( $idx == 0 ) {

      print "\n";
      print "Do you configure role substrings for this realm $realm?\n";
      print "If you create multiple VPN realms, please specify roles\n";
      print "for each realm. If you manage only one VPN realm or this\n";
      print "machine connects other peers only as an initiator, this \n";
      print "configuration is NOT necessary.  [y/N/q]\n";

    } else {
      
      print "\n";
      print "Do you configure additional role substrings for this realm"; 
      print "$realm?  [y/N/q]\n";
    }
    
    my $ans = get_stdin_chars("n","y","n");
    
    if ( $ans eq "y" ) {

roles_type_again:
      print "\n";
      print "Please specify a type of role substring.\n";
      print "[\n 1:Hostname(FQDN)\n 2:E-mail\n 3:X.509 subject\n"; 
      print " 4:X.509 subjectAltName FQDN\n 5:X.509 subjectAltName E-mail\n 6:any\nq\n]\n"; 
      
      my $ans = get_stdin_chars(0,"1","2","3","4","5","6");
      
      switch ($ans) {
      case "1"  { @$roles_type[$idx] = "fqdn";}
      case "2"  { @$roles_type[$idx] = "email";}
      case "3"  { @$roles_type[$idx] = "subject";}
      case "4"  { @$roles_type[$idx] = "subjectAltName_fqdn";}
      case "5"  { @$roles_type[$idx] = "subjectAltName_email";}
      case "6"  { @$roles_type[$idx] = "any"; @$roles[$idx] = "any"; goto roles_end; }
      else      { goto roles_type_again;}
      }      

      print "\n";
      print "Please specify a role substring. \n";

      while( 1 ){

        my $ans = get_stdin(1);

        if ( $ans eq "q" ) {
          
          confirm_exit();
          
        } else {

          @$roles[$idx] = $ans;
          last;          
        }
      }     
      
      $idx++;

    } elsif ( $ans eq "n" ) {

      last;
    }
  }

roles_end:
  return;
}

sub wizard_get_auth_ikev2_auth_method {

  my $my_auth_method = "psk";

auth_method_again:
  print "[1:Pre-Shared-Key(PSK)/2:RSA signature/q]\n";

  my $ans = get_stdin_chars(0,"1","2");
      
  switch ($ans) {
  case "1"  { $my_auth_method = "psk";}
  case "2"  { $my_auth_method = "rsa-sig";}
  else      { goto auth_method_again;}
  }

  return $my_auth_method;  
}

sub wizard_get_psk_my_auth_info {
  
  my ( $id_type,$id,$psk ) = @_;
  
psk_my_id_type_again:    
  print "[1:Hostname(FQDN)/2:E-mail address/q]\n"; 

  my $ans = get_stdin(1);

  switch ($ans) {
  case "1"  { $$id_type = "fqdn";}
  case "2"  { $$id_type = "email";}
  else      { goto psk_my_id_type_again;}
  }      
    
  print "\n";
  print "Please specify this machine's ID.\n";
    
  while( 1 ){

    my $ans = get_stdin(1);

    if ( $ans eq "q" ) {

      confirm_exit();
          
    } else {

      $$id = $ans;
      last;          
    }
  }     

  print "\n";
  print "Please specify a Pre-Shared-Key(PSK) of this machine.\n";
    
  while( 1 ){

    my $ans = get_stdin(1);

    if ( $ans eq "q" ) {

      confirm_exit();
          
    } else {
        
      $$psk = $ans;
      last;          
    }
  }     
  
  return;
}

sub wizard_get_rsasig_my_auth_info {

  my ($id_type) = @_;
  
rsasig_my_id_type_again:  
  print "[\n 1:X.509 subject(DN)\n 2:X.509 subjectAltName\n 3:auto\n]\n"; 

  my $ans = get_stdin(1);

  switch ($ans) {
  case "1"  { $$id_type = "dn";}
  case "2"  { $$id_type = "subjectaltname";}
  case "3"  { $$id_type = "cert_auto";}
  else      { goto rsasig_my_id_type_again;}
  }
  
  return;      
}

sub wizard_get_psk_peer_auth_info {
  
  my ( $id_type,$id,$psk ) = @_;
  
psk_peer_id_type_again:    

  print "[1:Hostname(FQDN)/2:E-mail/3:any]\n"; 

  my $ans = get_stdin_chars(0,"1","2","3");
        
  switch ($ans) {
  case "1"  { $$id_type = "fqdn";}
  case "2"  { $$id_type = "email";}
  case "3"  { $$id_type = "any";}
  case "q"  { confirm_exit(); goto psk_peer_id_type_again;}
  else      { goto psk_peer_id_type_again;}
  }      

  if( $$id_type ne "any" ){
    
    print "\n";
    print "Please specify the peer's ID. \n";
      
    while( 1 ){
  
      my $ans = get_stdin(1);
  
      if ( $ans eq "q" ) {
  
        confirm_exit();
            
      } else {
  
        $$id = $ans;
        last;          
      }
    }     

  }else{
      
    $$id = "any";
  }

    
  print "\n";
  print "Please specify a Pre-Shared-Key(PSK) of the ID.\n";
    
  while( 1 ){

    my $ans = get_stdin(1);

    if ( $ans eq "q" ) {

      confirm_exit();
          
    } else {
        
      $$psk = $ans;
      last;          
    }
  }     
  
  return;
}

sub wizard_get_rsasig_peer_auth_info
{

  my ( $id_type,$id ) = @_;
  
rsa_sig_peer_id_type_again:  
  print "[\n 1:X.509 subject(DN)\n"; 
  print " 2:X.509 subjectAltName FQDN\n 3:X.509 subjectAltName E-mail address\n 4:any\n]\n"; 

  my $ans = get_stdin_chars(0,"1","2","3","4");
        
  switch ($ans) {
  case "1"  { $$id_type = "dn";}
  case "2"  { $$id_type = "fqdn";}
  case "3"  { $$id_type = "email";}
  case "4"  { $$id_type = "any";}
  case "q"  { confirm_exit(); goto rsa_sig_peer_id_type_again;}
  else      { goto rsa_sig_peer_id_type_again;}
  }      
  
  if( $$id_type ne "any" ){
    
    print "\n";
    print "Please specify the peer's ID. [id/q]\n";
      
    while( 1 ){
  
      my $ans = get_stdin(1);
  
      if ( $ans eq "q" ) {
  
        confirm_exit();
            
      } else {
  
        $$id = $ans;
        last;          
      }
    }     

  }else{
      
    $$id = "any";
  }

  return;
}

sub wizard_get_type_of_mode {

  my $typeofmode = "router";

mode_type_again:
  print "[\n 1:Bridge\n 2:Router\n 3:Remote Access Client\n 4:End Host(General)\n q\n]\n";

  my $ans = get_stdin_chars(0,"1","2","3","4");

  switch ($ans) {
  case "1"  { $typeofmode = "bridge";}
  case "2"  { $typeofmode = "router";}
  case "3"  { $typeofmode = "remote-client";}
  case "4"  { $typeofmode = "end-host";}
  else      { goto mode_type_again;}
  }      

  return $typeofmode;  
}

sub wizard_get_ipv4_address_with_skip_flag {

  my ($skip_flag) = @_;

  my $ipv4_address;
  
  print "[ipv4-address/s/q]\n";
  
  while( 1 ){

    my $ans = get_stdin(1);
      
    if ( $ans eq "q" ) {
        
      confirm_exit();

    }elsif( $skip_flag && $ans eq "s" ){

      return;
      
    } else {

      if ( is_valid_ipv4($ans) ) {
          
        $ipv4_address = $ans;
        last;

      } else {

        print "Invalid IPv4 format specified. $ans \n";
      }
    }
  }
  
  return $ipv4_address;  
}

sub wizard_get_ipv4_address {

  return wizard_get_ipv4_address_with_skip_flag(0);
}

sub wizard_get_ipv4_subnet {
  
  my $ipv4_subnet;
  
  print "['ipv4-address/prefix' or 'ipv4-subnet-address/prefix'/q]\n";

  while( 1 ){

    my $ans = get_stdin(1);
      
    if ( $ans eq "q" ) {
        
      confirm_exit();

    } else {

      if ( is_valid_ipv4_subnet($ans) ) {
          
        $ipv4_subnet = $ans;
        last;

      } else {

        print "Invalid IPv4 format specified. $ans \n";
      }
    }
  }
  
  return $ipv4_subnet;  
}

sub wizard_get_bridge_name {

  my $bridge_name;

  while ( 1 ) {

    print "[bridge_name/q]\n";

    my $ans = get_stdin(1);
      
    if ( $ans eq "q\n" ) {
        
      confirm_exit();

    } else {

      if( length($ans) >= 16 ){

        print "Bridge name must be less than 16 characters. \n";

      }else{

        $bridge_name = $ans;
        last;
      }
    }
  }

  return $bridge_name;  
}

sub wizard_get_my_interfaces {

  my ($address, $port, $auth_basic_key,$my_interfaces) = @_;

add_interface_again:

  my $idx = 0;
  while ( 1 ) {

    if ( $idx == 0 ) {

add_interface:

      print "(ex) eth0\n";
      print "Don't specify 'rhpvifN' and 'lo' interfaces.\n";
      print "If you want to see a list of interfaces, please specify 'L'.\n";
      print "[L/interface_name/q]\n";

    } elsif ($idx) {

      print "\n";
      print "Do you want to specify additional network interfaces?\n";
      print "[y/N/q]\n";

      my $ans = get_stdin_chars("n","y","n");

      switch ($ans) {
      case "y"  { }
      case "n"  { goto add_interface_end; }
      else      { }
      }      

      goto add_interface;
    }


    my $ans = get_stdin(1);

    if ( $ans eq 'q' ) {

      confirm_exit();
      goto add_interface;
      
    }elsif ( $ans eq "l" ) {

      vpn_status_interface($address,$port,$auth_basic_key,0);
      print "\n";
      
      goto add_interface;

    } else {
  
      @$my_interfaces[$idx] = $ans;
      $idx++;
      
      #Multiple interfaces will be supported by MOBIKE function in the near future.
      goto add_interface_end; 
    }
  }
  
add_interface_end:  

  if( @$my_interfaces == 0 ){
    
    print "No interface was chosen. This may cause problems if this machine\n";
    print "has multiple interfaces.\n";
    print "If you want to configure interfaces again, please specify 'r'.\n";
    print "To continue, specify 'c', though it's NOT recommended.  [R/c/q]\n";

    my $ans = get_stdin_chars("r","r","c");

    switch ($ans) {
    case "r"  { goto add_interface_again; }
    case "c"  { }
    else      { goto add_interface_again; }
    }      
  }
  
  return;  
}

sub wizard_get_hub_or_spoke {

  print "\n";
  print "Is this machine a hub or a spoke?\n";
  print "'Hub' means a network node or an access-point which concentrates\n";
  print "VPN connections from other remote nodes('spoke's).\n";
  print "If you want to configure a remote gateway for remote access\n";
  print "clients, please choose '1'.  [1:hub/2:spoke/q]\n";

  my $hub_or_spoke; 

  my $ans = get_stdin_chars(0,"1","2");

  if ( $ans eq "1" ) {

    $hub_or_spoke = "hub";
      
  } elsif ( $ans eq "2" ) {

    $hub_or_spoke = "spoke";
  }

  return $hub_or_spoke;  
}

sub wizard_setup_config_server {
  
  my($doc,$typeofmode,$vpn_realm_elm) = @_;
  
  print "\n";
  print "Do you setup an auto configuration service for remote access\n";
  print "clients?  [y/n/q]\n";

  my $ans = get_stdin_chars(0,"y","n");

  if( $ans ne "y" ){
    return;
  }
      

  my $config_server_elm = $$doc->createElement("service");
  $$vpn_realm_elm->addChild($config_server_elm);
            
  my $config_server_attr = $$doc->createAttribute( "name", "config_server" );
  $config_server_elm->setAttributeNode($config_server_attr);
      
  print "\n";
  print "Do you configure an internal address pool?\n";
  print "[Y/n/q]\n";
  
  $ans = get_stdin_chars("y","y","n");
      
  if( $ans eq "y" ){

    my $internal_address_elm = $$doc->createElement("internal_address");
    $config_server_elm->addChild($internal_address_elm);

    my $address_pool_elm = $$doc->createElement("address_pool");
    $internal_address_elm->addChild($address_pool_elm);

        
    my $internal_address_pool_start;
    my $internal_address_pool_end;
    my $internal_address_pool_netmask;
    
    print "\n";
    print "Please specify a start IPv4 address for the address pool.\n";
    print "(ex) 192.168.1.110\n";

    $internal_address_pool_start = wizard_get_ipv4_address();
    

    print "\n";
    print "Please specify an end IPv4 address for the address pool.\n";
    print "(ex) 192.168.1.150\n";
    
    $internal_address_pool_end = wizard_get_ipv4_address();
  

    print "\n";
    print "Please specify an IPv4 netmask for the address pool.\n";
    print "(ex) 255.255.255.0\n";
      
    $internal_address_pool_netmask = wizard_get_ipv4_address();
          

    my $internal_address_pool_start_attr = $$doc->createAttribute( "start_address_v4", $internal_address_pool_start );
    $address_pool_elm->setAttributeNode($internal_address_pool_start_attr);
          
    my $internal_address_pool_end_attr = $$doc->createAttribute( "end_address_v4", $internal_address_pool_end );
    $address_pool_elm->setAttributeNode($internal_address_pool_end_attr);
  
    my $internal_address_pool_netmask_attr = $$doc->createAttribute( "netmask_v4", $internal_address_pool_netmask );
    $address_pool_elm->setAttributeNode($internal_address_pool_netmask_attr);
  }    
    
    
  print "\n";
  print "Do you configure routing information for internal networks?\n";
  print "[Y/n/q]\n";
  
  $ans = get_stdin_chars("y","y","n");
        
  if( $ans eq "y" ){
  
    my $internal_networks_elm = $$doc->createElement("internal_networks");
    $config_server_elm->addChild($internal_networks_elm);

    my $idx = 0;          
    while ( 1 ) {
        
      if( $idx == 0 ){
  
config_internal_route_map:  
        print "\n";
        print "Please specify an internal network address (a destination\n";
        print "address) by IPv4 subnet address.  (ex) 192.168.10.0/24\n";

      }else{
                
        print "\n";
        print "Do you configure additional internal network addresses?\n";
        print "[y/n/q]\n";
                
        my $ans = get_stdin_chars(0,"y","n");
                
        switch ($ans) {
        case "y"  { goto config_internal_route_map; }
        case "n"  { goto config_internal_route_map_end; }
        case "q"  { confirm_exit(); goto config_internal_route_map;}
        else      { goto config_internal_route_map; }
        }                      
      }      

      my $route_map_destination_v4 = wizard_get_ipv4_subnet();

      my $route_map_elm = $$doc->createElement("route_map");
      $internal_networks_elm->addChild($route_map_elm);

      my $route_map_destination_v4_attr = $$doc->createAttribute("destination_v4",$route_map_destination_v4);
      $route_map_elm->setAttributeNode($route_map_destination_v4_attr);

      $idx++;
    }

config_internal_route_map_end:

    if( $typeofmode eq "bridge" ){

      print "This machine is configured as a bridge node.\n";
      print "If necessary, please specify a next-hop gateway's address\n";
      print "for other internal networks.\n";
      print "If not needed, please specify 's'.\n";
      print "(ex) 192.168.1.100\n";
            
      my $internal_br_gateway_addr_v4 = wizard_get_ipv4_address_with_skip_flag(1);

      my $internal_br_gateway_addr_v4_attr 
      = $$doc->createAttribute("gateway_address_v4",$internal_br_gateway_addr_v4);

      $internal_networks_elm->setAttributeNode($internal_br_gateway_addr_v4_attr);
    }
  }
    
    
  print "\n";
  print "Do you configure internal DNS information? (Split DNS)\n";
  print "[Y/n/q]\n";
  
  $ans = get_stdin_chars("y","y","n");
        
  if( $ans eq "y" ){
  
    my $internal_dns_elm = $$doc->createElement("internal_dns");
    $config_server_elm->addChild($internal_dns_elm);

    print "\n";
    print "Please specify a IPv4 address of the internal DNS server.\n";
    print "(ex) 192.168.1.100\n";
  
    my $dns_server_address_ipv4 = wizard_get_ipv4_address();
  
    my $dns_server_address_ipv4_attr = $$doc->createAttribute("server_address_v4",$dns_server_address_ipv4);
    $internal_dns_elm->setAttributeNode($dns_server_address_ipv4_attr);
  
    my $idx = 0;          
    while ( 1 ) {
        
      if( $idx == 0 ){
  
config_internal_domain:  
        print "\n";
        print "Please specify a domain name suffix for internal networks.\n";
        print "It means a substring of FQDNs attached to PCs/servers on\n";
        print "internal protected networks.   (ex) .company.com\n";
        print "[domain_name_suffix/q]\n";
  
      }else{
                
        print "\n";
        print "Do you configure additional domain name suffixes?\n";
        print "[y/n/q]\n";
                
        my $ans = get_stdin_chars(0,"y","n");
                
        switch ($ans) {
        case "y"  { goto config_internal_domain; }
        case "n"  { goto config_internal_domain_end; }
        case "q"  { confirm_exit(); goto config_internal_domain;}
        else      { goto config_internal_domain; }
        }                      
      }      
  
      my $ans = get_stdin(1);
              
      if ( $ans eq "q\n" ) {
                
        confirm_exit();
        
      } else {
        
        my $domain_match = $ans;
  
        my $domain_elm = $$doc->createElement("domain");
        $internal_dns_elm->addChild($domain_elm);
  
        my $domain_match_attr = $$doc->createAttribute("match",$domain_match);
        $domain_elm->setAttributeNode($domain_match_attr);

        $idx++;
      }
    }
    
config_internal_domain_end:
  }        
  
  return;
}

sub wizard_get_internal_gw_addr {
  
  my($internal_gateway_address_v4,$internal_is_gateway) = @_;

  $$internal_is_gateway = 0;
  $$internal_gateway_address_v4 = 0;

  print "Do you configure a next-hop gateway for this machine?\n";
  print "This is optional. If some spoke peer nodes connect this\n";
  print "machine(hub) by 'IP over IP' mode, this setting is effective\n";
  print "to learn a next-hop gateway's MAC address by ARP.\n";
  print "[y/N/q]\n";

  my $ans = get_stdin_chars("n","y","n");

  if ( $ans ne "y" ) {
    return;
  }

  print "Does this machine also provide IP-routing service to other\n";
  print "subnets? If not necessary, please specify 's'.\n";
  print "[y/N/s/q]\n";

  $ans = get_stdin_chars("n","y","n","s");

  if ( $ans eq "y" ) {
    
    $$internal_is_gateway = 1;
    
    return;
  }

  print "Please specify a IPv4 address of the next-hop gateway.\n";
  print "If not necessary, please specify 's'.\n";
  print "(ex)192.168.1.100\n";

  $$internal_gateway_address_v4 = wizard_get_ipv4_address_with_skip_flag(1);

  return;  
}

sub vpn_config_wizard {

  my ( $address, $port, $auth_basic_key, $realm ) = @_;

  if ( !$realm ) {
    print "realm not specified.\n";
    print_usage("config-wizard");
    return;
  }

  print "\n";
  print "By this wizard, you can make a simple and typical configuration\n";
  print "for Rockhopper.\n";
  print "\n";


  my $vpn_realm_name;
  my $create_new_realm = 0;

  my $doc  = XML::LibXML->createDocument;
  my $root = $doc->createElement("rhp_realm_update");
  $doc->setDocumentElement($root);
  $config_wizard_doc = $doc;

  my $rhp_config_elm = $doc->createElement("rhp_config");
  $root->addChild($rhp_config_elm);

  my $rhp_auth_elm = $doc->createElement("rhp_auth");
  $root->addChild($rhp_auth_elm);


  $create_new_realm = wizard_confirm_vpn($address,$port,$auth_basic_key,$realm);
  
  if( $create_new_realm < 0 ){

    return;    

  }elsif( $create_new_realm == 1 ){
    
    $vpn_realm_name = wizard_get_new_vpn_name($realm);
  }
  
  
  my $vpn_realm_elm = $doc->createElement("vpn_realm");
  $rhp_config_elm->addChild($vpn_realm_elm);

  my $vpn_realm_id_attr = $doc->createAttribute( "id", $realm );
  $vpn_realm_elm->setAttributeNode($vpn_realm_id_attr);

  if( $vpn_realm_name ){
    my $vpn_realm_name_attr = $doc->createAttribute( "name", $vpn_realm_name );
    $vpn_realm_elm->setAttributeNode($vpn_realm_name_attr);
  }

  my $vpn_auth_realm_elm = $doc->createElement("vpn_realm");
  $rhp_auth_elm->addChild($vpn_auth_realm_elm);

  my $vpn_auth_realm_id_attr = $doc->createAttribute( "id", $realm );
  $vpn_auth_realm_elm->setAttributeNode($vpn_auth_realm_id_attr);

  if( $vpn_realm_name ){
    my $vpn_auth_realm_name_attr = $doc->createAttribute( "name", $vpn_realm_name );
    $vpn_auth_realm_elm->setAttributeNode($vpn_auth_realm_name_attr);
  }


  print "\n";
  print "Please choose a type of this machine's mode.\n";

  my $typeofmode = wizard_get_type_of_mode();

  if( $typeofmode ){

    my $typeofmodelabel;
    
    if( $typeofmode eq 'router' ){
      $typeofmodelabel = "Router";
    }elsif( $typeofmode eq 'bridge' ){
      $typeofmodelabel = "Bridge";
    }elsif( $typeofmode eq 'remote-client' ){
      $typeofmodelabel = "Remote Client";
    }elsif( $typeofmode eq 'end-host' ){
      $typeofmodelabel = "End Host";
    }else{
      $typeofmodelabel = "Not Specified";
     }

    my $vpn_realm_mode_attr = $doc->createAttribute( "mode", $typeofmodelabel );
    $vpn_realm_elm->setAttributeNode($vpn_realm_mode_attr);
  }


  print "\n";
  print "Please configure authentication information for this machine\n";
  print "in the VPN realm $realm.\n";

  my @roles_type = ();
  my @roles      = ();

  if( $typeofmode ne "remote-client" ){  
    
    wizard_get_roles(\@roles_type,\@roles,$realm);
  
    my $idx = 0;
    if( @roles ){
        
      my $roles_elm = $doc->createElement("roles");
      $vpn_auth_realm_elm->addChild($roles_elm);
    
      $idx = 0;
      foreach my $role_type (@roles_type){
          
        my $role_elm = $doc->createElement("role");
        $roles_elm->addChild($role_elm);
          
        my $role_type_attr = $doc->createAttribute( "type", $role_type );
        $role_elm->setAttributeNode($role_type_attr);
          
        if( $role_type ne "any" ){
          my $role_match_attr = $doc->createAttribute( "match", $roles[$idx] );
          $role_elm->setAttributeNode($role_match_attr);
        }
              
        $idx++;
      }        
    }
  }

  print "\n";
  print "Which IKEv2 authentication methods do you use for this\n";
  print "machine, Pre-Shared-Key(PSK) or RSA signature?\n";
  print "\n";
  print "To use RSA signature method, you must prepare 3 files:\n";
  print "a X.509 certificate file and a private key file for\n";
  print "this machine and a CA certificate file. These files must\n";
  print "be encoded in PEM format.\n\n";

  my $my_auth_method = wizard_get_auth_ikev2_auth_method();


  print "\n";
  print "Please specify a type of this machine's ID.\n";

  my $myid_type;
  my $myid;
  my $my_psk;

  if( $my_auth_method eq "psk" ){

    wizard_get_psk_my_auth_info(\$myid_type,\$myid,\$my_psk);
    
  }elsif( $my_auth_method eq "rsa-sig" ){
    
    wizard_get_rsasig_my_auth_info(\$myid_type);

  }else{
    
    print "Unknown IKEv2 authentication method specified. $my_auth_method\n";
    return;    
  }
  
  
  
  my $internal_interface_elm = $doc->createElement("internal_interface");
  $vpn_realm_elm->addChild($internal_interface_elm);


  if ( $typeofmode eq "router" || $typeofmode eq "end-host" ) {

    if( $typeofmode eq "router" ){
      print "[INFO] Please enable IP Forwarding. See man sysctl.conf(5).\n";
      print "(ex) Add a line 'net.ipv4.ip_forward = 1' to /etc/sysctl.conf.\n";
    }

    print "\n";
    print "Please specify a static IPv4 address and prefix length for a\n";
    print "internal virtual network interface.\n";
    print "(ex)192.168.1.100/24\n";

    my $internal_interface_static_ipv4 = wizard_get_ipv4_subnet();

    
    my $address_type_attr = $doc->createAttribute("address_type","static");
    $internal_interface_elm->setAttributeNode($address_type_attr);
    
    my $address_v4_attr = $doc->createAttribute("address_v4", $internal_interface_static_ipv4);
    $internal_interface_elm->setAttributeNode($address_v4_attr);

  } elsif ( $typeofmode eq "bridge" ) {

    print "\n";
    print "[INFO] Please enable IP Forwarding, if necessary.\n"; 
    print "       See man sysctl.conf(5).\n";
    print "(ex) Add a line 'net.ipv4.ip_forward = 1' to /etc/sysctl.conf.\n";

    if ( -e $brctl ) {

      print "\n";
      print "[INFO] To configure bridge, please use a '$brctl' command in\n";
      print "       bridge-utils package.\n";

    } else {
      
      print "\n";
      print "[WARNING] If you want to configure bridge, please install\n";
      print "          bridge-utils package.\n";
      print "          (ex) sudo apt-get install bridge-utils\n";
    }

    print "\n";
    print "[INFO] For more information about bridge-utils, please see man brctl(8)\n";
    print "       and man bridge-utils-interfaces(5) after the utils' installation.\n";

    my $address_type_attr = $doc->createAttribute("address_type","none");
    $internal_interface_elm->setAttributeNode($address_type_attr);


    print "\n";
    print "Please specify a bridge's name this VPN connects to. (ex) br0\n";

    my $bridge_name = wizard_get_bridge_name();

    my $bridge_name_attr = $doc->createAttribute("bridge",$bridge_name);
    $internal_interface_elm->setAttributeNode($bridge_name_attr);


  } elsif ( $typeofmode eq "remote-client" ) {

    while ( 1 ) {

      print "\n";
      print "How do you configure a IP address for an internal virtual\n";
      print "network interface of this VPN realm?\n";
      print "[1:static/2:auto(Configured by remote gateway)/q]\n";

      my $ans = get_stdin_chars(0,"1","2");

      if ( $ans eq "1" ) {

        print "\n";
        print "Please specify static IPv4 address and prefix length for\n";
        print "the internal virtual network interface.\n";
        print "(ex)192.168.1.100/24\n";
        
        my $internal_interface_static_ipv4 = wizard_get_ipv4_subnet();

        
        my $address_type_attr = $doc->createAttribute( "address_type", "static" );
        $internal_interface_elm->setAttributeNode($address_type_attr);
        
        my $address_v4_attr = $doc->createAttribute( "address_v4",$internal_interface_static_ipv4 );
        $internal_interface_elm->setAttributeNode($address_v4_attr);


      } elsif ( $ans eq "2" ) {

        my $address_type_attr = $doc->createAttribute( "address_type", "ikev2-config-v4" );
        $internal_interface_elm->setAttributeNode($address_type_attr);
        
        print "[NOTICE] Internal IP address will be automatically configured\n";
        print "         by gateway.\n";
        last;

      }else{
        
        print "Unknown network interface type specified. $ans\n";        
        return;
      }
    }

    my $service_elm = $doc->createElement("service");
    $vpn_realm_elm->addChild($service_elm);
    
    my $service_name_attr = $doc->createAttribute( "name", "config_client" );
    $service_elm->setAttributeNode($service_name_attr);

  } else {

    print "Unknown network usage type specified. $typeofmode\n";        
    return;
  }


  my @my_interfaces = ();

  print "\n";
  print "Please specify network interface(s) used to establish VPN.\n";

  wizard_get_my_interfaces($address, $port, $auth_basic_key,\@my_interfaces);

  if( @my_interfaces ){
    
    my $my_interfaces_elm = $doc->createElement("my_interfaces");
    $vpn_realm_elm->addChild($my_interfaces_elm);

    my $idx = 0;
    foreach my $my_interface (@my_interfaces) {

      my $my_interface_elm = $doc->createElement("my_interface");
      $my_interfaces_elm->addChild($my_interface_elm);

      my $my_interface_name_attr = $doc->createAttribute( "name", $my_interfaces[$idx] );
      $my_interface_elm->setAttributeNode($my_interface_name_attr);

      my $my_interface_priority_attr = $doc->createAttribute( "priority", ( $idx + 1 ) * 10 );
      $my_interface_elm->setAttributeNode($my_interface_priority_attr);

      $idx++;
    }
  }


  my $hub_or_spoke;

  if ( $typeofmode eq "router" || $typeofmode eq "bridge" || $typeofmode eq "end-host" ) {

    $hub_or_spoke = wizard_get_hub_or_spoke();

  } elsif ( $typeofmode eq "remote-client" ) {

    $hub_or_spoke = "spoke";
  }


  my @peerids_type = ();
  my @peerids = ();
  my @peer_psks = ();

  {
    print "\n";
    
    if( $typeofmode eq "remote-client" ){

      print "Please configure authentication information for a remote\n";
      print "access gateway.\n";
    
    }else{
      
      print "Please configure authentication information for peer nodes.\n"; 
    }

    my $idx = 0;
    my $peer_id_any_specified = 0;
    while( 1 ){
      
      my $peerid_type;
      my $peerid;
      my $peer_psk;
      my $peer_ipv4;
      my $peer_auth_method;
  
      if( $idx == 0 ){

peers_auth_method_again:      
        print "\n";
        print "Which IKEv2 authentication methods do you use to authenticate\n"; 
        print "peer node(s)?\n";
        print "To use 'RSA signature' method, you must prepare a CA certificate\n";
        print "file encoded in PEM format.\n";
        
        $peer_auth_method = wizard_get_auth_ikev2_auth_method();

        print "\n";
        print "Please specify a type of the peer's ID.  [id_type/q]\n";
    
        if( $peer_auth_method eq "psk" ){
    
          wizard_get_psk_peer_auth_info(\$peerid_type,\$peerid,\$peer_psk);
        
        }elsif( $peer_auth_method eq "rsa-sig" ){
        
          wizard_get_rsasig_peer_auth_info(\$peerid_type,\$peerid);
    
        }else{
        
          print "Unknown IKEv2 authentication method specified. $peer_auth_method\n";
          return;    
        }

      }else{

peers_auth_method_again_q:      
        print "\n";
        print "Do you configure additional peers' authentication information?\n";
        print "[y/n/q]\n";
                
        my $ans = get_stdin_chars(0,"y","n");
                
        switch ($ans) {
        case "y"  { goto peers_auth_method_again; }
        case "n"  { goto peers_id_end; }
        case "q"  { confirm_exit(); goto peers_auth_method_again;}
        else      { goto peers_auth_method_again; }
        }                      
      }      

      if( $peerid_type eq "any"){
        
        if( !$peer_id_any_specified ){
          $peer_id_any_specified = 1;
        }else{
          goto peers_auth_method_again_q;        
        }
      }      
  
  
      $peerids_type[$idx]  = $peerid_type;
      $peerids[$idx]       = $peerid;
      
      if( $peer_auth_method eq "psk" ){
        $peer_psks[$idx]     = $peer_psk;
      }
      
      $idx++;
    }

peers_id_end:
  }



  if ( $hub_or_spoke eq "spoke" ) {

    my $peers_elm = $doc->createElement("peers");
    $vpn_realm_elm->addChild($peers_elm);

    print "\n";
    print "This machine offers service as a 'spoke' node or a remote\n";
    print "access client.\n";

    if( $typeofmode eq "router" || $typeofmode eq "bridge" ){

      print "\n";
      print "Please configure a peer hub's(an access-point's or a remote\n";
      print "gateway's) network information.\n";

      my $ac_peer_elm = $doc->createElement("peer");
      $peers_elm->addChild($ac_peer_elm);


      print "Please specify a IPv4 address of the peer hub.\n";
      print "(ex)192.168.1.100\n";

      my $ac_peer_ipv4 = wizard_get_ipv4_address();

      my $peer_ipv4_attr = $doc->createAttribute( "address_v4", $ac_peer_ipv4);
      $ac_peer_elm->setAttributeNode($peer_ipv4_attr);

      print "\n";
      print "[NOTICE] \'always_on_connection\' setting is automatically enabled\n";
      print "         as a default.\n\n";

      my $peer_always_on_connection_attr = $doc->createAttribute( "always_on_connection", "enable");
      $ac_peer_elm->setAttributeNode($peer_always_on_connection_attr);
    }
    
  }elsif ( $hub_or_spoke eq "hub" ) {

    my $service_elm = $doc->createElement("service");
    $vpn_realm_elm->addChild($service_elm);
      
    my $service_name_attr = $doc->createAttribute( "name", "access_point" );
    $service_elm->setAttributeNode($service_name_attr);


    print "\n";
    print "This machine offers service as a 'hub'(an access-point or\n";
    print "a gateway).\n";


    wizard_setup_config_server(\$doc,$typeofmode,\$vpn_realm_elm);


    #if( $typeofmode eq "bridge" ){
      
      #my $internal_gateway_address_v4;
      #my $internal_is_gateway;
  
      #wizard_get_internal_gw_addr(\$internal_gateway_address_v4,\$internal_is_gateway);
  
      #if( $internal_is_gateway ){
  
      #  my $interna_is_gateway_attr = $doc->createAttribute("gateway","enable");
      #  $internal_interface_elm->setAttributeNode($interna_is_gateway_attr);
        
      #}elsif( $internal_gateway_address_v4 ){
  
      #  my $interna_gw_addr_v4_attr = $doc->createAttribute("gateway_address_v4",$internal_gateway_address_v4);
      #  $internal_interface_elm->setAttributeNode($interna_gw_addr_v4_attr);
      #}
    #}
  }


  my $file = "vpn_realm_" . $realm . "_conf.xml";
  if ( !open( CONFIG_XML, "> ./$file" ) ) {

    print "Can't open $file.\n";

  } else {

    print CONFIG_XML $doc->toString(1);
    close(CONFIG_XML);
  }


confirm_commit_config:

  print "\n======\n\n";
  print "Finally, do you actually upload this configuration now?\n";
  print "To see the configuration, please specify 's'.  [y/n/s/q]\n";

  my $ans = get_stdin_chars(0,"y","n","s");
                
  switch ($ans) {
  case "y"  { goto do_commit_config; }
  case "s"  { 
              
              print "\n";                
              if( $create_new_realm ){
                print " A NEW VPN realm $realm will be created.\n";
              }else{
                print " A existing VPN realm $realm will be overwritten.\n";
              }

              print "\n";                
              print "[Config]\n";
              print $doc->toString(1); 
              
              print "\n";              

              if( $myid ){  
                print "[This machine's Auth Info]\n";            
                print "  $myid($myid_type), Auth-Method: $my_auth_method\n";
              }
            
              print "\n";              
              if( @peerids_type ){

                print "[Peer Nodes' Auth Info]\n";                

                my $idx = 0;
                foreach my $peerid_type (@peerids_type){
            
                  print "  [$idx] $peerids[$idx]($peerid_type), ";
                  if( $peer_psks[$idx] ){
                    print " Auth-Method: psk";                    
                  }else{
                    print " Auth-Method: rsa-sig";                    
                  }
                  print "\n";

                  $idx++;
                }
              }
              
              goto confirm_commit_config; 
            }
  case "q"  { confirm_exit(); goto confirm_commit_config; }
  case "n"  { goto confirm_not_commit_config; }
  else      { goto confirm_commit_config; }
  }                      


do_commit_config:  

  if( $create_new_realm ){

    if ( vpn_realm_create( $address, $port, $auth_basic_key, $realm ) ) {
      print "[ERROR] Creating a new VPN realm $realm failed.\n";
      return;
    }

    print "\n";
    print "[NOTICE] A new VPN realm '$realm' is created.\n";
    sleep(2);
  }  

  if( $myid ){  

    vpn_auth_update_my_info($address,$port,$auth_basic_key,$realm,$myid_type,$myid,$my_auth_method,$my_psk);

    print "\n";
    print "[NOTICE] Uploaded this machine's authentication information.\n  $myid($myid_type)\n";
    sleep(2);
  }

  if( @peerids_type ){
    
    my $idx = 0;
    foreach my $peerid_type (@peerids_type){

      vpn_auth_update_peer_info($address,$port,$auth_basic_key,$realm,$peerid_type,$peerids[$idx],$peer_psks[$idx]);

      print "\n";
      print "[NOTICE] Uploaded the peers' authentication information.\n  $peerids[$idx]($peerid_type)\n";

      $idx++;
      sleep(2);
    }
  }

  vpn_realm_update($address,$port,$auth_basic_key,$realm,$file);
  print "\n";
  print "[NOTICE] Uploaded a configuration of the VPN realm $realm.\n";
  sleep(2);


confirm_not_commit_config:
  print "\n";
  print "[NOTICE] If this machine or some peer nodes use the 'RSA signature'\n";
  print "         IKEv2 authentication method, please upload certificate\n";
  print "         files and a private key file which are saved in PEM encoding.\n";
  print "         To upload these files, please use the 'cert update' option\n";
  print "         of this rockhopper.pl tool.\n";
  sleep(5);

  print "\n";
  print "[NOTICE] This configuration is saved to './$file'.\n";
  print "         You can use the file as a basic template when configuring more\n";  
  print "         detailed settings later, if necessary.\n";
  print "         To upload the configuration file, please use 'realm update'\n";
  print "         option of this rockhopper.pl tool.\n";
  print "\n";
  print "         On the other hand, all information related to authenticatin is\n";
  print "         NOT saved to the file. To update authentication information,\n";
  print "         please use 'auth update' option.\n";
  print "\n";
  
  print "\n";
  print "Enjoy!\n";
  print "\n";
  
  $config_wizard_doc = 0;
  return;
}


sub rhp_memory_dbg {
  
  my ( $address, $port, $auth_basic_key, $start_time, $elapsing_time ) = @_;

  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="memory_dbg"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "memory_dbg" );
  $root->setAttributeNode($attr_action);


  if( $elapsing_time ){
    my $attr_elapsing_time = $doc->createAttribute("elapsing_time",$elapsing_time);
    $root->setAttributeNode($attr_elapsing_time);
  }

  if( $start_time ){
    my $attr_start_time = $doc->createAttribute("start_time",$start_time);
    $root->setAttributeNode($attr_start_time);
  }

  
  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }

  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );
  
  return;
}

sub tx_dummy_packet {

  my( $address,$port,$auth_basic_key,$realm,
      $protocol,$data_len,$src_mac,$dst_mac,
      $src_ip_addr,$dst_ip_addr,$src_port,$dst_port,
      $esp_tx_seq) = @_;

  if( !$realm ){
    print "realm not specified.\n";
    return;    
  }

  if( !$src_ip_addr ){
    print "src_ip_addr not specified.\n";
    return;    
  }

  if( !$dst_ip_addr ){
    print "dst_ip_addr not specified.\n";
    return;    
  }


  my $ua = LWP::UserAgent->new();

  #$ua->timeout(2);
  # If proxy config exists, ...
  #  $ua->env_proxy;
  my $session_id = open_bus_session( $ua, $address, $port, $auth_basic_key );
  if ( $session_id eq '' ) {
    return -1;
  }

#
# [ Example ]
#
# <?xml version="1.0"?>
# <rhp_http_bus_request version="1.0" service="ui_http_vpn" action="config_realm_exists"/>
#
  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "tx_dummy_pkt" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  if( !$protocol ){
    $protocol = "udp"
  }

  {
    my $attr = $doc->createAttribute( "protocol", $protocol );
    $root->setAttributeNode($attr);
  }

  if( $data_len ){  
    my $attr = $doc->createAttribute( "data_len", $data_len );
    $root->setAttributeNode($attr);
  }

  if( $src_mac ){    
    my $attr = $doc->createAttribute( "src_mac", $src_mac );
    $root->setAttributeNode($attr);
  }
  
  if( $dst_mac ){    
    my $attr = $doc->createAttribute( "dst_mac", $dst_mac );
    $root->setAttributeNode($attr);
  }
  
  {
    my $attr = $doc->createAttribute( "src_ip_addr", $src_ip_addr );
    $root->setAttributeNode($attr);
  }
  
  {
    my $attr = $doc->createAttribute( "dst_ip_addr", $dst_ip_addr );
    $root->setAttributeNode($attr);
  }
  
  if( $src_port ){
    my $attr = $doc->createAttribute( "src_port", $src_port );
    $root->setAttributeNode($attr);
  }
  
  if( $dst_port ){
    my $attr = $doc->createAttribute( "dst_port", $dst_port );
    $root->setAttributeNode($attr);
  }
  
  if( $esp_tx_seq ){
    my $attr = $doc->createAttribute( "esp_tx_seq", $esp_tx_seq );
    $root->setAttributeNode($attr);
  }


  my $url = 'http://' . $address . ':' . $port . '/protected/bus/write/' . $session_id;
  my $req = HTTP::Request->new( PUT => $url );

  $req->header( "Accept"         => 'text/xml' );
  $req->header( "Accept-Charset" => 'utf-8' );
  $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  $req->header( "Content-Type"   => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp   = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$session_id :" . $resp->status_line . "\n";
    print $doc->toString(1);
  }
  
  close_bus_session( $ua, $address, $port, $auth_basic_key, $session_id );

  return;
}


my $admin_default;
my $password_default;

########################################################
# Default admin user/password (NOT recommended)        #
#                                                      #
#$admin_default    = "admin";
#$password_default = "secret";
#                                                      #
#                                                      #
########################################################

if( $admin_default || $password_default ){
  print "\n";
  print "[CAUTION]\n";
  print "[CAUTION] **NOT RECOMMENDED!**\n";
  print "[CAUTION] Default admin's name and password are directly\n";
  print "[CAUTION] written in this script file!\n";
  print "[CAUTION] Please be careful about this insecure usage!\n";
  print "[CAUTION]\n";
  print "\n";
}

my $action   = $ARGV[0];
my $detail   = 0;
my %cmd_opts = ();

GetOptions(
  \%cmd_opts,
  'port=i',           'admin=s',
  'password=s',       'realm=i',
  'realm_name=s',
  'realm_mode=s',
  'realm_desc=s',
  'peer_address=s',   'file=s',
  'peerid_type=s',    'peerid=s',
  'myid_type=s',      'myid=s',
  'my_auth_method=s', 'psk=s',
  'cert_password=s',  'ca_certs=s',
  'my_cert=s',        'my_priv_key=s',
  'admin_id=s',       'admin_password=s',
  'mng_address=s',    'mng_port=s',
  'archive_password=s',
  'protocol=s',       'data_len=s',
  'src_port=s',       'dst_port=s',
  'src_ip_addr=s',    'dst_ip_addr=s',
  'src_mac=s',        'dst_mac=s',
  'esp_tx_seq=s',
  'start_time=s',     'elapsing_time=s',
  'detail' => \$detail
);

if ( $action ne 'connect'
  && $action ne 'close'
  && $action ne 'config'
  && $action ne 'status'
  && $action ne 'config-wizard'
  && $action ne 'realm'
  && $action ne 'global'
  && $action ne 'auth'
  && $action ne 'cert'
  && $action ne 'admin'
  && $action ne 'flush-bridge'
  && $action ne 'web-mng'
  && $action ne 'cfg-archive'
  && $action ne 'memory-dbg'
  && $action ne 'tx_dmy_pkt'
  && $action ne 'help' )
{
  print "Unknown command: $action\n";
  print_usage;
  exit;
}

my $admin    = $cmd_opts{admin};
my $password = $cmd_opts{password};

if ( !$admin || !$password ) {
  $admin    = $admin_default;
  $password = $password_default;
}

my $address = "127.0.0.1";
my $port = 32501;
if ( $cmd_opts{port} ) {
  $port = $cmd_opts{port};
}


my $realm          = $cmd_opts{realm};
my $realm_name     = $cmd_opts{realm_name};
my $realm_mode     = $cmd_opts{realm_mode};
my $realm_desc     = $cmd_opts{realm_desc};
my $peerid_type    = $cmd_opts{peerid_type};
my $peerid         = $cmd_opts{peerid};
my $peer_address   = $cmd_opts{peer_address};
my $myid_type      = $cmd_opts{myid_type};
my $myid           = $cmd_opts{myid};
my $my_auth_method = $cmd_opts{my_auth_method};
my $psk            = $cmd_opts{psk};
my $cert_password  = $cmd_opts{cert_password};
my $ca_certs       = $cmd_opts{ca_certs};
my $my_cert        = $cmd_opts{my_cert};
my $my_priv_key    = $cmd_opts{my_priv_key};
my $admin_id       = $cmd_opts{admin_id};
my $admin_password = $cmd_opts{admin_password};
my $file           = $cmd_opts{file};
my $mng_address    = $cmd_opts{mng_address};
my $mng_port       = $cmd_opts{mng_port};
my $arch_password  = $cmd_opts{archive_password};

my $protocol        = $cmd_opts{protocol};
my $data_len        = $cmd_opts{data_len};
my $src_port        = $cmd_opts{src_port};
my $dst_port        = $cmd_opts{dst_port};
my $src_ip_addr     = $cmd_opts{src_ip_addr};
my $dst_ip_addr     = $cmd_opts{dst_ip_addr};
my $src_mac         = $cmd_opts{src_mac};
my $dst_mac         = $cmd_opts{dst_mac};
my $esp_tx_seq      = $cmd_opts{esp_tx_seq};

my $start_time      = $cmd_opts{start_time};
my $elapsing_time   = $cmd_opts{elapsing_time};
my $help_action     = $cmd_opts{help_action};

if ($realm) {

  if ( $realm !~ /^\d+$/ ) {
    print "Invalid realm number specified.\n";
    exit;
  }
}


my $auth_basic_key = LWP::Authen::Basic->auth_header( $admin, $password );
#print "auth_basic_key:$auth_basic_key\n"; 

if( $action eq 'help' ){
  
  print_usage($ARGV[1]);
  
} elsif ( $action eq 'connect' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  vpn_connect($address,$port,$auth_basic_key,$realm,$peerid_type,$peerid,$peer_address);

} elsif ( $action eq 'close' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  vpn_close($address,$port,$auth_basic_key,$realm,$peerid_type,$peerid,$peer_address);

} elsif ( $action eq 'status' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  my $status_target = $ARGV[1];

  if ( $status_target eq 'vpn' ) {

    if ( $peerid_type || $peerid ) {
      
      vpn_status_vpn($address,$port,$auth_basic_key,$realm, $peerid_type,$peerid,$detail,'');

    } else {
      vpn_status_enum_vpn($address, $port, $auth_basic_key,$realm,$detail);
    }

  } elsif ( $status_target eq 'peers' ) {

    vpn_status_peers($address,$port,$auth_basic_key,$realm,$detail);

  } elsif ( $status_target eq 'bridge' ) {

    vpn_status_bridge( $address,$port,$auth_basic_key,$realm,$detail);

  } elsif ( $status_target eq 'arp' ) {

    vpn_status_arp($address,$port,$auth_basic_key, $realm, $detail);

  } elsif ( $status_target eq 'address-pool' ) {

    vpn_status_address_pool($address,$port,$auth_basic_key,$realm,$detail);

  } elsif ( $status_target eq 'interface' ) {

    vpn_status_interface($address,$port,$auth_basic_key,1);

  } else {

    print "Unknown status operation. : $ARGV[1] \n";
    print_usage("status");
  }

} elsif ( $action eq 'config' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  my $config_target = $ARGV[1];

  if ( $config_target eq 'peers' ) {

    vpn_config_peers( $address, $port, $auth_basic_key, $realm, $detail );

  } elsif ( $config_target eq 'get' ) {

    vpn_config_get( $address, $port, $auth_basic_key, $realm, $file, $detail );

  } elsif ( $config_target eq 'realms' ) {

    vpn_config_realms( $address, $port, $auth_basic_key );

  } else {

    print "Unknown config operation. : $ARGV[1] \n";
    print_usage("config");
  }

} elsif ( $action eq 'config-wizard' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  vpn_config_wizard( $address, $port, $auth_basic_key, $realm );
  $config_wizard_doc = 0;

} elsif ( $action eq 'realm' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  my $realm_target = $ARGV[1];

  if ( $realm_target eq 'create' ) {

    vpn_realm_create( $address, $port, $auth_basic_key, $realm, $realm_name, $realm_mode, $realm_desc );

  } elsif ( $realm_target eq 'update' ) {

    vpn_realm_update( $address, $port, $auth_basic_key, $realm, $file );

  } elsif ( $realm_target eq 'delete' ) {

    vpn_realm_delete( $address, $port, $auth_basic_key, $realm );

  } else {

    print "Unknown realm operation. : $ARGV[1] \n";
    print_usage("realm");
  }

} elsif ( $action eq 'global' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  my $global_target = $ARGV[1];

  if ( $global_target eq 'update' ) {

    vpn_global_update( $address, $port, $auth_basic_key, $file );

  }elsif( $global_target eq 'get' ){

    vpn_global_get( $address, $port, $auth_basic_key, $file );

  }else{
    
    print "Unknown global operation. : $ARGV[1] \n";
    print_usage("global");
  }

} elsif ( $action eq 'auth' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  my $auth_target = $ARGV[1];

  if ( $auth_target eq 'update' ) {

    if ($myid_type) {

      vpn_auth_update_my_info($address,$port,$auth_basic_key,$realm,$myid_type,$myid,$my_auth_method,$psk);

    } elsif ($peerid_type) {

      vpn_auth_update_peer_info($address,$port,$auth_basic_key,$realm,$peerid_type,$peerid,$psk);

    } else {

      print_usage("auth_update");
    }

  } elsif ( $auth_target eq 'delete' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

    if ($peerid_type) {

      vpn_auth_delete_peer_info( $address, $port, $auth_basic_key, $realm,$peerid_type, $peerid );

    } else {
      print_usage("auth_delete");
    }
    
  } else {

    print "Unknown auth operation. : $ARGV[1] \n";
    print_usage("auth");
  }

} elsif ( $action eq 'cert' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  my $cert_target = $ARGV[1];

  if ( $cert_target eq 'update' ) {

    vpn_cert_update( $address, $port, $auth_basic_key, $realm, $cert_password,$my_cert, $my_priv_key, $ca_certs );

#  } elsif ( $cert_target eq 'delete' ) {

#    vpn_cert_delete( $address, $port, $auth_basic_key, $realm );

  } elsif ( $cert_target eq 'get' ) {

    vpn_cert_get_printed($address, $port, $auth_basic_key, $realm);

  } else {

    print "Unknown cert operation. : $ARGV[1] \n";
    print_usage("cert");
  }

} elsif ( $action eq 'admin' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  my $admin_target = $ARGV[1];

  if ( $admin_target eq 'update' ) {

    vpn_admin_update( $address, $port, $auth_basic_key, $admin, $password,$admin_id, $admin_password, $realm );

  } elsif ( $admin_target eq 'delete' ) {

    vpn_admin_delete( $address, $port, $auth_basic_key, $admin, $password,$admin_id );

  } elsif ( $admin_target eq 'get' ) {

    vpn_admin_get( $address, $port, $auth_basic_key, $admin, $password );

  } else {

    print "Unknown admin operation. : $ARGV[1] \n";
    print_usage("admin");
  }

} elsif ( $action eq 'flush-bridge' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }
  
  vpn_flush_bridge($address, $port, $auth_basic_key, $realm);

} elsif ( $action eq 'web-mng' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }
  
  vpn_web_mng_update($address, $port, $auth_basic_key, $mng_address, $mng_port);

} elsif ( $action eq 'cfg-archive' ) {

  my $global_target = $ARGV[1];

  if ( $global_target eq 'save' ) {

    if ( !$admin || !$password ) {
      print "admin or password not specified.\n";
      print_usage;
      exit;
    }

    cfg_archive_save( $address, $port, $auth_basic_key, $arch_password, $file );

  }elsif( $global_target eq 'extract' ){

    cfg_archive_extract( $arch_password, $file );

#  }elsif( $global_target eq 'restore' ){
#
#    cfg_archive_restore( $arch_password, $file );
#
  }else{
    
    print "Unknown cfg-archive operation. : $ARGV[1] \n";
    print_usage("cfg-archive");
  }

} elsif ( $action eq 'memory-dbg' ) {

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }

  rhp_memory_dbg($address,$port,$auth_basic_key,$start_time,$elapsing_time);

} elsif ( $action eq 'tx-dmy-pkt' ){

  if ( !$admin || !$password ) {
    print "admin or password not specified.\n";
    print_usage;
    exit;
  }
  
  tx_dummy_packet($address,$port,$auth_basic_key,$realm,
  $protocol,$data_len,$src_mac,$dst_mac,$src_ip_addr,$dst_ip_addr,$src_port,$dst_port,$esp_tx_seq);
}

exit;

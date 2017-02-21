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
# A sample GTK2-Perl script for a Rockhopper's client GUI.
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

#
# - By default, Perl does NOT share any variables between threads. 
#   All of them are copied into TLSs before the threads start. 
#   You need to use ': share' modifier or shared() to share the variables.
#
# - A referecne of the not-shared variable can't be shared. If you 
#   want to share a reference of the variable, you also have to 
#   declare it as a shared one. See the following:
#
#   (ex.)
#    my $var0 : shared = 0;
#    my $var1 = 1;
#    my %hash1 : shared = ();
#   
#    sub thread_run {
#      $hash{"key0"} = \$val0; # OK!
#      $hash{"key1"} = \$val1; # NG! $val1 must be a shared variable.
#    } 
#
# - Perl allows duplicated(recursive) locks in the same thread.
#
# - GTK2's objects are protected by using a global lock.
#   So, before calling any GTK2 APIs, call Gtk2::Gdk::Threads->enter()
#   to acquire the lock. 
#   And, after they return, call Gtk2::Gdk::Threads->leave() to release
#   the lock.
#

use Getopt::Long;

use Gtk2 qw/-init -threads-init/;
use Glib qw(TRUE FALSE);

# (Ubuntu 8.x--) Need to import libxml-libxml-perl by package manager.
use XML::LibXML;

# (Ubuntu 8.x--) NOT need to import libwww-perl by package manager.
use LWP::UserAgent;
use LWP::Authen::Basic;

use Switch;

my $rhp_version = '1.0';
my $rhp_addr    = '127.0.0.1';
my $rhp_port    = '32501';

# Only limited operations are allowed for this user_id.
my $admin       = 'rhp_client_gtk2_perl';
# Fixed dummy password.
my $admin_pw    = 'secret'; 

my $auth_basic_key = LWP::Authen::Basic->auth_header( $admin, $admin_pw );


my $bus_session_id : shared = undef;

my $bus_read_thread;


my %peers_info : shared = ();
my $peers_info_num : shared = 0;


my $win_base_height = 50;
my $column_height   = 40;
my $column_width    = 450;
my $peer_rows       = 1;

my $status_dialog_height = 180;
my $status_dialog_width = 450;

my $eap_usrkey_dialog_height = 100;
my $eap_usrkey_dialog_width = 350;

my $window = undef;
my $tview;
my $tstore;

my $win_icon_path = "/usr/share/icons/gnome/48x48/devices/network-vpn.png";

my $browser_cfg = "firefox http://". $rhp_addr . ":" . $rhp_port . " &";


my $op_disabled : shared = 0;
my $op_disabled2 : shared = 0;
my $dmy_col_appended : shared = 0;


sub peer_info_key {

  my ($realm_id,$peerid_type,$peerid) = @_;
  
  my $peerid_key = $realm_id . ":" . $peerid . '(' . $peerid_type . ')';
    
  return $peerid_key;
}


sub bus_session_open {

  my $url = 'http://' . $rhp_addr . ':' . $rhp_port . '/protected/bus/open';

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( POST => $url );

  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {
    print "bus_session_open: ERROR: /protected/bus/open :" . $resp->status_line . " or no content.\n";
    return undef;
  }

  my $parser     = XML::LibXML->new;
  my $resp_doc   = $parser->parse_string( $resp->decoded_content );
  my $session_id = undef;

  foreach my $resp_elm ( $resp_doc->getElementsByTagName('rhp_http_bus_response') )
  {

    my $server_version = $resp_elm->getAttribute('version');

    if ( $server_version ne $rhp_version ) {
      print "bus_session_open: ERROR: RHP version not supported. : $server_version \n";
      return undef;
    }

    my $resp_rec = $resp_elm->getElementsByTagName('rhp_http_bus_record')->item(0);

    my $service = $resp_rec->getAttribute('service');
    if ( $service ne 'http_bus' ) {
      print "bus_session_open: ERROR: RHP service not supported. : $service \n";
      return undef;
    }

    my $server_action = $resp_rec->getAttribute('action');
    if ( $server_action ne 'open' ) {
      print "bus_session_open: ERROR: RHP action not supported. : $server_action \n";
      return undef;
    }

    $session_id = $resp_rec->getAttribute('session_id');
    if ( $session_id eq '' ) {
      print "bus_session_open: ERROR: Session ID not found. : $session_id \n";
      return undef;
    }
  }

  return $session_id;
}

sub bus_session_close {

  if ( !defined($bus_session_id) ) {
    #print "bus_session_close bus_session_id=null\n";
    return;
  }

  my $url = 'http://' . $rhp_addr . ':' . $rhp_port . '/protected/bus/close/' . $bus_session_id;

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( DELETE => $url );

  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "bus_session_close: ERROR: /protected/bus/close/$bus_session_id :" . $resp->status_line . "\n";
  }

  return;
}

sub bus_session_read_vpn_status {
  
  my ($realm_id,$uqnique_id) = @_;
  
  my $peer_status_ref = bus_session_vpn_status($realm_id,undef,undef,$uqnique_id);

  if( defined($peer_status_ref) ){

    my $peerid_type = $$peer_status_ref{"peerid_type"};
    my $peerid = $$peer_status_ref{"peerid"};

    my $peer_ref = $peers_info{peer_info_key($realm_id,$peerid_type,$peerid)};

    if( !defined($peer_ref) ){
      print "bus_session_read_vpn_status: No peer's info found. $realm_id, $uqnique_id, $peerid_type, $peerid\n";
      return;
    }
    
    $$peer_ref{"vpn_status"} = $peer_status_ref;
    
    return ($realm_id,$peerid_type,$peerid);
  }
  
  return (undef,undef,undef);
}

sub bus_session_read_vpn_added {
  
  my($resp_doc,$rec_elm) = @_;
  
  my $realm_id = $rec_elm->getAttribute('vpn_realm_id');
  my $uqnique_id = $rec_elm->getAttribute('vpn_unique_id');
  my $auto_reconnect_retries = $rec_elm->getAttribute('vpn_auto_reconnect_retries');

  my($realm_id2,$peerid_type,$peerid) = bus_session_read_vpn_status($realm_id,$uqnique_id);  
    
  if( defined($peerid) ){    
    
    my $peer_ref = $peers_info{peer_info_key($realm_id,$peerid_type,$peerid)};

    if( !defined($peer_ref) ){
      print "bus_session_read_vpn_added: No peer's info found. $realm_id, $peerid_type, $peerid\n";
      return;
    }
    $$peer_ref{"connecting"} = 1;
    
    my $label = "Connecting";
    if( defined($auto_reconnect_retries) && $auto_reconnect_retries ){
      $$peer_ref{"reconnecting"} = 1;
      $label = "Reconnecting ($auto_reconnect_retries)."
    }
    
    view_update_peer_row($realm_id2,$peerid_type,$peerid,"",$label);
  }
}

sub bus_session_read_vpn_deleted {

  my($resp_doc,$rec_elm) = @_;
  
  my $realm_id = $rec_elm->getAttribute('vpn_realm_id');
  my $peerid_type = $rec_elm->getAttribute('peerid_type');
  my $peerid = $rec_elm->getAttribute('peerid');
  my $auto_reconnect_failed = $rec_elm->getAttribute('auto_reconnect_failed');
  my $auto_reconnect_retries = $rec_elm->getAttribute('vpn_auto_reconnect_retries');

  if( defined($peerid) ){    
    
    my $peer_ref = $peers_info{peer_info_key($realm_id,$peerid_type,$peerid)};

    if( !defined($peer_ref) ){
      print "bus_session_read_vpn_deleted: No peer's info found. $realm_id, $peerid_type, $peerid\n";
      return;
    }

    my $dc_label = "Disconnected";
    if( $$peer_ref{"reconnecting"} == 1 ){
      $dc_label = "Reconnect Error";
      if( defined($auto_reconnect_failed) && $auto_reconnect_failed == 0 ){
        $dc_label = "Reconnecting";
      }
      if( defined($auto_reconnect_retries) && $auto_reconnect_retries ){
        $dc_label .= " ($auto_reconnect_retries)";
      }
    }elsif( $$peer_ref{"connecting"} == 1 ){
      $dc_label = "Connect Error";
    }elsif( defined($auto_reconnect_retries) && $auto_reconnect_retries ){
        $dc_label = "Waiting";
        if( defined($auto_reconnect_retries) && $auto_reconnect_retries ){
          $dc_label .= " ($auto_reconnect_retries)";
        }
    }
    $$peer_ref{"connecting"} = 0;
    $$peer_ref{"reconnecting"} = 0;
    
    view_update_peer_row($realm_id,$peerid_type,$peerid,"",$dc_label);
  }
}

sub bus_session_read_vpn_established {

  my($resp_doc,$rec_elm) = @_;
  
  my $realm_id = $rec_elm->getAttribute('vpn_realm_id');
  my $uqnique_id = $rec_elm->getAttribute('vpn_unique_id');

  my($realm_id2,$peerid_type,$peerid) = bus_session_read_vpn_status($realm_id,$uqnique_id);  
    
  if( defined($peerid) ){    
    
    my $peer_ref = $peers_info{peer_info_key($realm_id,$peerid_type,$peerid)};

    if( !defined($peer_ref) ){
      print "bus_session_read_vpn_established: No peer's info found. $realm_id, $peerid_type, $peerid\n";
      return;
    }
    $$peer_ref{"connecting"} = 0;
    $$peer_ref{"reconnecting"} = 0;
    
    view_update_peer_row($realm_id2,$peerid_type,$peerid,"","Connected");
  }
}

sub bus_session_read_vpn_conn_i_err {
  
  my($resp_doc,$rec_elm) = @_;
  
  my $realm_id = $rec_elm->getAttribute('vpn_realm_id');
  my $peerid_type = $rec_elm->getAttribute('peerid_type');
  my $peerid = $rec_elm->getAttribute('peerid');

  if( defined($peerid) ){    
    
    view_update_peer_row($realm_id,$peerid_type,$peerid,"","Connect Error");
  }
}

sub bus_session_read_vpn_closing {
  
  my($resp_doc,$rec_elm) = @_;
  
  my $realm_id = $rec_elm->getAttribute('vpn_realm_id');
  my $uqnique_id = $rec_elm->getAttribute('vpn_unique_id');

  my($realm_id2,$peerid_type,$peerid) = bus_session_read_vpn_status($realm_id,$uqnique_id);  
    
  if( defined($peerid) ){    
    
    view_update_peer_row($realm_id2,$peerid_type,$peerid,"","Disconnected");
  }
}

sub bus_session_read_vpn_mobike_i_rt_check_start {
  
  my($resp_doc,$rec_elm) = @_;
  
  my $realm_id = $rec_elm->getAttribute('vpn_realm_id');
  my $uqnique_id = $rec_elm->getAttribute('vpn_unique_id');

  my($realm_id2,$peerid_type,$peerid) = bus_session_read_vpn_status($realm_id,$uqnique_id);  
    
  if( defined($peerid) ){    
    
    view_update_peer_row($realm_id2,$peerid_type,$peerid,"","Dormant");
  }
}

sub bus_session_read_vpn_mobike_i_rt_check_finished {
  
  my($resp_doc,$rec_elm) = @_;
  
  my $realm_id = $rec_elm->getAttribute('vpn_realm_id');
  my $uqnique_id = $rec_elm->getAttribute('vpn_unique_id');

  my($realm_id2,$peerid_type,$peerid) = bus_session_read_vpn_status($realm_id,$uqnique_id);  
    
  if( defined($peerid) ){    
    
    view_update_peer_row($realm_id2,$peerid_type,$peerid,"","Connected");
  }
}

sub bus_session_read_realm_cfg_updated {

  my($resp_doc,$rec_elm) = @_;

  view_flush_peer_rows();

  load_peers_info();
  $peer_rows = $peers_info_num;
  if( $peer_rows < 1 ){
    $peer_rows = 1;
  }

  view_add_peers();
  
  if( $peers_info_num == 0 ){
    $window->signal_connect("button-press-event" => \&view_default_pressed);
  }

  $window->resize( $column_width, $win_base_height + ($column_height * $peer_rows) );
}

sub eap_sup_user_key_dialog {
  
  my($resp_doc,$rec_elm,$eap_sup_method,$mesg,$old_eap_sup_user_id) = @_;
  my %ret = ();
  my $eap_method_str;

  if( $eap_sup_method eq "mschapv2"  ){
    $eap_method_str = "EAP-MSCHAPv2";
  }else{
    return;
  }

  my $dialog = Gtk2::Dialog->new("EAP Authentication - " . $eap_method_str, 
                                $window, 
                                [qw/modal destroy-with-parent/],
                                'OK' => 'ok',
                                'Cancel' => 10);

  $dialog->set_response_sensitive ('ok', FALSE);

  $dialog->set_default_size($eap_usrkey_dialog_width,$eap_usrkey_dialog_height);                               

  my $table = Gtk2::Table->new (3, 2, FALSE);

  my $mesg_label = Gtk2::Label->new($mesg);
  $mesg_label->set_alignment(0,0.5);
  $table->attach_defaults ($mesg_label, 0, 2, 0, 1);

  my $username_label = Gtk2::Label->new("User name: ");
  $username_label->set_alignment(0.6,0.5);
  $table->attach_defaults ($username_label, 0, 1, 1, 2);
  
  my $username_entry = Gtk2::Entry->new();     
  if( defined($old_eap_sup_user_id) ){
    $username_entry->set_text($old_eap_sup_user_id);
  }
  $table->attach_defaults($username_entry, 1, 2, 1, 2);

  my $password_label = Gtk2::Label->new("Password:   ");
  $password_label->set_alignment(0.6,0.5);
  $table->attach_defaults ($password_label, 0, 1, 2, 3);
  
  my $password_entry = Gtk2::Entry->new();     
  $password_entry->set_visibility(FALSE);
  $table->attach_defaults($password_entry, 1, 2, 2, 3);

  my $enable_dialog_ok_btn = sub {

    my $username = $username_entry->get_text();
    $username =~ s/\s+//g;
    my $password = $password_entry->get_text();
    $password =~ s/\s+//g;
    
    if( $username ne '' && $password ne '' ){
      $dialog->set_response_sensitive ('ok', TRUE);
    }else{
      $dialog->set_response_sensitive ('ok', FALSE);
    }
  };

  $username_entry->signal_connect (changed => $enable_dialog_ok_btn);
  $password_entry->signal_connect (changed => $enable_dialog_ok_btn);

  $dialog->vbox->add( $table );

  $dialog->set_default_response ('ok');
  $dialog->set_position('center-always');

  $dialog->show_all();

  my $response = $dialog->run();
  if( $response eq "ok" ){

    $ret{'action'} = "continue";

    my $username = $username_entry->get_text();
    $username =~ s/\s+//g;
    my $password = $password_entry->get_text();
    $password =~ s/\s+//g;

    $ret{'method'} = $eap_sup_method;
    $ret{'username'} = $username;
    $ret{'password'} = $password;
    
  }else{
    
    $ret{'action'} = "cancel";
  }

  $dialog->destroy();
  
  return \%ret;
}

sub bus_session_read_eap_sup_conn_i_usrkey_needed {

  my($resp_doc,$rec_elm) = @_;

  my $realm_id = $rec_elm->getAttribute('vpn_realm_id');
  my $peer_address = $rec_elm->getAttribute('peer_address_v4');
  my $peer_port = $rec_elm->getAttribute('peer_port');
  my $peerid_type = $rec_elm->getAttribute('peerid_type');
  my $peerid = $rec_elm->getAttribute('peerid');
  my $peer_fqnd = $rec_elm->getAttribute('peer_fqdn');
  my $eap_sup_method = $rec_elm->getAttribute('eap_sup_method');

  if( !defined($peer_address) ){
    $peer_address = $rec_elm->getAttribute('peer_address_v6');
  }

  my $userkey = eap_sup_user_key_dialog($resp_doc,$rec_elm,$eap_sup_method,"",undef);
  
  if( $userkey->{'action'} eq "continue" ){
    
    bus_session_vpn_connect($realm_id,$peerid_type,$peerid,
      $userkey->{'method'},$userkey->{'username'},$userkey->{'password'});

  }else{

#    print "bus_session_read_eap_sup_conn_i_usrkey_needed: canceled.\n";    
  }
}

sub bus_session_read_eap_sup_ask_for_usrkey {

  my($resp_doc,$rec_elm) = @_;

  my $realm_id = $rec_elm->getAttribute('vpn_realm_id');
  my $unique_id = $rec_elm->getAttribute('vpn_unique_id');
  my $peerid_type = $rec_elm->getAttribute('peerid_type');
  my $peerid = $rec_elm->getAttribute('peerid');
  my $eap_sup_method = $rec_elm->getAttribute('eap_sup_method');
  my $txn_id = $rec_elm->getAttribute('txn_id');
  my $old_eap_sup_user_id = $rec_elm->getAttribute('eap_sup_user_id');


  my $userkey = eap_sup_user_key_dialog($resp_doc,$rec_elm,$eap_sup_method,
    "Authentication failed. Confirm your user name and password.",$old_eap_sup_user_id);
  
  if( $userkey->{'action'} eq "continue" ){

    bus_session_eap_sup_usr_key_reply($realm_id,"continue",$txn_id,$unique_id,$peerid_type,$peerid,
       $userkey->{'method'},$userkey->{'username'},$userkey->{'password'});

  }else{

    bus_session_eap_sup_usr_key_reply($realm_id,"cancel",$txn_id,$unique_id,$peerid_type,$peerid,
      undef,undef,undef);
  }
}


sub bus_session_read {

  my $ret = TRUE;

  if ( !defined($bus_session_id) ) {
    #print "bus_session_read bus_session_id=null\n";
    return $ret;
  }

  my $url = 'http://' . $rhp_addr . ':' . $rhp_port . '/protected/bus/read/' . $bus_session_id;

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( GET => $url );

  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );
  $req->header( "Content-Type"        => 'text/xml; charset=utf-8' );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {

      #print "ERROR: /protected/bus/read/$bus_session_id :" . $resp->status_line . "\n";
      $ret = FALSE;

    } else {

      #print "No event occurred: /protected/bus/read/$bus_session_id :" . $resp->status_line . "\n";
    }

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

#    print "body: " . $resp_doc->toString(1) . "\n";
    
    foreach my $rec_elm ( $resp_doc->getElementsByTagName('rhp_http_bus_record') ) {

      my $rec_action = $rec_elm->getAttribute('action');

      Gtk2::Gdk::Threads->enter();

      #print "Rec_action: $rec_action\n";
      switch ($rec_action) {
      case "vpn_added"            
        { bus_session_read_vpn_added($resp_doc,$rec_elm);}
      case "vpn_deleted"          
        { bus_session_read_vpn_deleted($resp_doc,$rec_elm);}
      case "vpn_established"      
        { bus_session_read_vpn_established($resp_doc,$rec_elm);}
      case "vpn_connect_i_error"  
        { bus_session_read_vpn_conn_i_err($resp_doc,$rec_elm);}
      case "vpn_closing"          
        { bus_session_read_vpn_closing($resp_doc,$rec_elm);}
      case "vpn_mobike_i_routability_check_start"          
        { bus_session_read_vpn_mobike_i_rt_check_start($resp_doc,$rec_elm);}
      case "vpn_mobike_i_routability_check_finished"          
        { bus_session_read_vpn_mobike_i_rt_check_finished($resp_doc,$rec_elm);}
      case "realm_config_updated" 
        { bus_session_read_realm_cfg_updated($resp_doc,$rec_elm); }
      case "realm_config_deleted"
        { bus_session_read_realm_cfg_updated($resp_doc,$rec_elm); }
      case "realm_config_enabled"
        { bus_session_read_realm_cfg_updated($resp_doc,$rec_elm); }
      case "realm_config_disabled"
        { bus_session_read_realm_cfg_updated($resp_doc,$rec_elm); }
      case "eap_sup_vpn_connect_i_user_key_needed"
        { bus_session_read_eap_sup_conn_i_usrkey_needed($resp_doc,$rec_elm); }
      case "eap_sup_ask_for_user_key_req"
        { bus_session_read_eap_sup_ask_for_usrkey($resp_doc,$rec_elm); }
      else 
        { 
          #print "bus_session_read: Unknown action: $rec_action\n";
        }
      }      

      Gtk2::Gdk::Threads->leave();
    }    
  }

  return $ret;
}

sub bus_session_config_peers {

  my($peers_info_ref,$peers_info_num_ref) = @_;

  if ( !defined($bus_session_id) ) {
    #print "bus_session_config_peers bus_session_id=null\n";
    return FALSE;
  }

  my $url = 'http://' . $rhp_addr . ':' . $rhp_port . '/protected/bus/write/' . $bus_session_id;
  
  %$peers_info_ref = ();
  $$peers_info_num_ref = 0;


  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "config_peers" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", "0" );
  $root->setAttributeNode($attr_realm);


  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( PUT => $url );


  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );
  $req->header( "Content-Type"        => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    print "bus_session_config_peers: ERROR: /protected/bus/put/$bus_session_id :" . $resp->status_line . "\n";

    return FALSE;
    
  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    # print "body: " . $resp_doc->toString(1) . "\n";
    
    my $peer_idx = 0;
    foreach my $peer_elm ( $resp_doc->getElementsByTagName('peer') ) {

      my $peer_addr_ipver = "ipv4";    
      my $peer_addr = $peer_elm->getAttribute('peer_addr_v4');
      my $realm_id = $peer_elm->getAttribute('vpn_realm_id');
      my $peerid_type = $peer_elm->getAttribute('peerid_type');
      my $peerid = $peer_elm->getAttribute('peerid');

      if( !defined($peer_addr) ){

        $peer_addr = $peer_elm->getAttribute('peer_addr_v6');
        
        if( !defined($peer_addr) ){
          $peer_addr_ipver = undef;
        }else{
          $peer_addr_ipver = "ipv6";
        }
      }
    
      if( (defined($peer_addr) && $peer_addr ne "0.0.0.0" && $peer_addr ne "::" ) ||
          (defined($peerid_type) && defined($peerid_type) && ($peerid_type eq "fqdn" || $peerid_type eq "null-id")) ){

        my %peer : shared = (
              "index" => $peer_idx,
              "vpn_realm_id" => $realm_id,
              "vpn_realm_name" => $peer_elm->getAttribute('vpn_realm_name'),
              "peerid_type" => $peerid_type,
              "peerid" => $peerid,
              "peer_addr_ipver" => $peer_addr_ipver,
              "peer_addr" => $peer_addr,
              "is_access_point" => $peer_elm->getAttribute('is_access_point'),
              "vpn_status" => undef,
              "connecting" => 0,
              "reconnecting" => 0
        );
        
        $peer_idx++;

        my $pkey : shared = peer_info_key($realm_id,$peerid_type,$peerid);

        $$peers_info_ref{$pkey} = \%peer;
        $$peers_info_num_ref++;
      }
    }
  }

  return TRUE;
}

sub parse_vpn_status {
  
  my ($resp_doc) = @_;

  my %ret : shared = ();
  my @ikesas : shared = ();
  my @childsas : shared = ();
  my @internal_nets : shared = ();
  my @split_dnss : shared = ();
  my @internal_if_addrs : shared = ();
  my @internal_peer_addrs : shared = ();
  
  $ret{"ikesas"} = \@ikesas;
  $ret{"childsas"} = \@childsas;
  $ret{"internal_nets"} = \@internal_nets;
  $ret{"split_dns_domains"} = \@split_dnss;
  $ret{"internal_if_addrs"} = \@internal_if_addrs;
  $ret{"internal_peer_addrs"} = \@internal_peer_addrs;

  foreach my $vpn_elm ( $resp_doc->getElementsByTagName('vpn') ) {

    $ret{"vpn_unique_id"} = $vpn_elm->getAttribute('vpn_unique_id');
    $ret{"vpn_realm_id"} = $vpn_elm->getAttribute('vpn_realm_id');
    $ret{"vpn_realm_name"} = $vpn_elm->getAttribute('vpn_realm_name');
    $ret{"peerid_type"} = $vpn_elm->getAttribute('peerid_type');
    $ret{"peerid"} = $vpn_elm->getAttribute('peerid');
    $ret{"myid_type"} = $vpn_elm->getAttribute('myid_type');
    $ret{"myid"} = $vpn_elm->getAttribute('myid');
    $ret{"encap_mode"} = $vpn_elm->getAttribute('encap_mode');
    $ret{"internal_if_addr_type"} = $vpn_elm->getAttribute('internal_if_addr_type');
    $ret{"internal_if_mac"} = $vpn_elm->getAttribute('internal_if_mac');
    $ret{"internal_if_mtu"} = $vpn_elm->getAttribute('internal_if_mtu');
    $ret{"internal_gateway_addr_v4"} = $vpn_elm->getAttribute('internal_gateway_addr_v4');
    $ret{"internal_gateway_addr_v6"} = $vpn_elm->getAttribute('internal_gateway_addr_v6');
    $ret{"internal_if_name"} = $vpn_elm->getAttribute('internal_if_name');
    $ret{"internal_peer_addr_cp"} = $vpn_elm->getAttribute('internal_peer_addr_cp');
    $ret{"dummy_peer_mac"} = $vpn_elm->getAttribute('dummy_peer_mac');
    $ret{"time_elapsed"} = $vpn_elm->getAttribute('time_elapsed');
    $ret{"peer_is_access_point"} = $vpn_elm->getAttribute('peer_is_access_point');
    $ret{"is_access_point"} = $vpn_elm->getAttribute('is_access_point');
    $ret{"is_config_server"} = $vpn_elm->getAttribute('is_config_server');

    $ret{"my_if_name"} = $vpn_elm->getAttribute('my_if_name');

    $ret{"my_addr_ipver"} = undef;
    $ret{"my_addr"} = $vpn_elm->getAttribute('my_addr_v4');
    if( defined($ret{"my_addr"}) ){
      $ret{"my_addr_ipver"} = "ipv4";
    }else{
      $ret{"my_addr"} = $vpn_elm->getAttribute('my_addr_v6');
      if( defined($ret{"my_addr"}) ){
        $ret{"my_addr_ipver"} = "ipv6";
      }
    }
    $ret{"my_port"} = $vpn_elm->getAttribute('my_port');

    $ret{"peer_addr_ipver"} = undef;
    $ret{"peer_addr"} = $vpn_elm->getAttribute('peer_addr_v4');
    if( defined($ret{"peer_addr"}) ){
      $ret{"peer_addr_ipver"} = "ipv4";
    }else{
      $ret{"peer_addr"} = $vpn_elm->getAttribute('peer_addr_v6');
      if( defined($ret{"peer_addr"}) ){
        $ret{"peer_addr_ipver"} = "ipv6";
      }
    }
    $ret{"peer_port"} = $vpn_elm->getAttribute('peer_port');

    $ret{"exec_nat_t"} = $vpn_elm->getAttribute('exec_nat_t');
    $ret{"behind_a_nat"} = $vpn_elm->getAttribute('behind_a_nat');
    $ret{"exec_mobike"} = $vpn_elm->getAttribute('exec_mobike');
    $ret{"rt_ck_pending"} = $vpn_elm->getAttribute('rt_ck_pending');
    $ret{"rt_ck_waiting"} = $vpn_elm->getAttribute('rt_ck_waiting');
    
    
    $ret{"qcd_my_token_enabled"} = $vpn_elm->getAttribute('qcd_my_token_enabled');
    $ret{"qcd_peer_token_enabled"} = $vpn_elm->getAttribute('qcd_peer_token_enabled');

    $ret{"exec_ikev2_fragmentation"} = $vpn_elm->getAttribute('exec_ikev2_fragmentation');

    $ret{"eap_role"} = $vpn_elm->getAttribute('eap_role');
    $ret{"eap_method"} = $vpn_elm->getAttribute('eap_method');
    $ret{"eap_my_identity"} = $vpn_elm->getAttribute('eap_my_identity');

    $ret{"ikesa_state"} = "disconnected";
    $ret{"childsa_state"} = "disconnected";

    $ret{"exec_sess_resume"} = $vpn_elm->getAttribute('exec_sess_resume');
    $ret{"gen_by_sess_resume"} = $vpn_elm->getAttribute('gen_by_sess_resume');
  
    $ret{"auth_method_i_org"} = $vpn_elm->getAttribute('auth_method_i_org');
    $ret{"auth_method_r_org"} = $vpn_elm->getAttribute('auth_method_r_org');
    
    $ret{"exec_ipv6_autoconf"} = $vpn_elm->getAttribute('exec_ipv6_autoconf');
    
    
    my $itnl_if_addr_idx = 0;
    foreach my $itnl_if_addr_elm ( $vpn_elm->getElementsByTagName('internal_if_addr') ) {
      
      my $itnl_if_addr = $itnl_if_addr_elm->getAttribute('address_v4');
      my $itnl_if_addr_family = "ipv4";
      if( !defined($itnl_if_addr) ){
        $itnl_if_addr = $itnl_if_addr_elm->getAttribute('address_v6');
        $itnl_if_addr_family = "ipv6";
      }

      my %itnl_if_addr : shared = (
        "index" => $itnl_if_addr_idx,
        "addr_family" => $itnl_if_addr_family,
        "address" => $itnl_if_addr
      );
            
      $itnl_if_addr_idx++;
      push(@internal_if_addrs,\%itnl_if_addr);
    }    


    my $itnl_peer_addr_idx = 0;
    foreach my $itnl_peer_addr_elm ( $vpn_elm->getElementsByTagName('internal_peer_addr') ) {
      
      my $itnl_peer_addr = $itnl_peer_addr_elm->getAttribute('address_v4');
      my $itnl_peer_addr_family = "ipv4";
      if( !defined($itnl_peer_addr) ){
        $itnl_peer_addr = $itnl_peer_addr_elm->getAttribute('address_v6');
        $itnl_peer_addr_family = "ipv6";
      }

      my %itnl_peer_addr : shared = (
        "index" => $itnl_peer_addr_idx,
        "addr_family" => $itnl_peer_addr_family,
        "address" => $itnl_peer_addr
      );
            
      $itnl_peer_addr_idx++;
      push(@internal_peer_addrs,\%itnl_peer_addr);
    }    
    

    my $ikesa_idx = 0;
    foreach my $ikesa_elm ( $vpn_elm->getElementsByTagName('ikesa') ) {

      my $ikesa_state = $ikesa_elm->getAttribute('state');

      my %ikesa : shared = (
        "index" => $ikesa_idx,
        "side" => $ikesa_elm->getAttribute('side'),
        "initiator_spi" => $ikesa_elm->getAttribute('initiator_spi'),
        "responder_spi" => $ikesa_elm->getAttribute('responder_spi'),
        "state" => $ikesa_state,
        "rekeyed_gen" => $ikesa_elm->getAttribute('rekeyed_gen'),
        "established_time_elapsed" => $ikesa_elm->getAttribute('established_time_elapsed'),
        "expire_hard" => $ikesa_elm->getAttribute('expire_hard'),
        "expire_soft" => $ikesa_elm->getAttribute('expire_soft'),
        "proposal_no" => $ikesa_elm->getAttribute('proposal_no'),
        "auth_method" => $ikesa_elm->getAttribute('auth_method'),
        "peer_auth_method" => $ikesa_elm->getAttribute('peer_auth_method'),
        "prf" => $ikesa_elm->getAttribute('prf'),
        "dh_group" => $ikesa_elm->getAttribute('dh_group'),
        "integ" => $ikesa_elm->getAttribute('integ'),
        "encr" => $ikesa_elm->getAttribute('encr'),
        "encr_key_bits" => $ikesa_elm->getAttribute('encr_key_bits')
      );
      
      $ikesa_idx++;
      
#      print "ikesa-state: " . $ikesa_state . " Rlm: " . $ret{"vpn_realm_id"}. "\n";
      
      if( $ret{"ikesa_state"} ne "established" ){
        
        if( $ikesa_state eq "i_ike_sa_init_sent" || $ikesa_state eq "i_auth_sent" ){
          $ret{"ikesa_state"} = "connecting";
        }elsif( $ikesa_state eq "delete" || $ikesa_state eq "delete_wait" || $ikesa_state eq "dead" ){
          $ret{"ikesa_state"} = "disconnected";
        }
      }
      
      if( $ikesa_state eq "established" || $ikesa_state eq "rekeying" ){
        $ret{"ikesa_state"} = "connected";
      }
      
      push(@ikesas,\%ikesa);
    }

    my $childsa_idx = 0;
    foreach my $childsa_elm ( $vpn_elm->getElementsByTagName('childsa') ) {

      my @my_tss : shared = ();
      foreach my $tss_elm ($childsa_elm->getElementsByTagName('my_traffic_selector') ){

        my $my_tss = $tss_elm->getAttribute('traffic_selector');
        #$my_tss =~ s/\s//g;

        push(@my_tss,$my_tss);
      }

      my @peer_tss : shared = ();
      foreach my $tss_elm ($childsa_elm->getElementsByTagName('peer_traffic_selector') ){
        
        my $peer_tss = $tss_elm->getAttribute('traffic_selector');
        #$peer_tss =~ s/\s//g;

        push(@peer_tss,$peer_tss);
      }

      my $childsa_state = $childsa_elm->getAttribute('state');

      my %childsa : shared = (
        "index" => $childsa_idx,
        "side" => $childsa_elm->getAttribute('side'),
        "rekeyed_gen" => $childsa_elm->getAttribute('rekeyed_gen'),
        "inbound_spi" => $childsa_elm->getAttribute('inbound_spi'),
        "outbound_spi" => $childsa_elm->getAttribute('outbound_spi'),
        "state" => $childsa_state,
        "ipsec_mode" => $childsa_elm->getAttribute('ipsec_mode'),
        "established_time_elapsed" => $childsa_elm->getAttribute('established_time_elapsed'),
        "expire_hard" => $childsa_elm->getAttribute('expire_hard'),
        "expire_soft" => $childsa_elm->getAttribute('expire_soft'),
        "proposal_no" => $childsa_elm->getAttribute('proposal_no'),
        "esn" => $childsa_elm->getAttribute('esn'),
        "integ" => $childsa_elm->getAttribute('integ'),
        "encr" => $childsa_elm->getAttribute('encr'),
        "encr_key_bits" => $childsa_elm->getAttribute('encr_key_bits'),
        "pfs" => $childsa_elm->getAttribute('pfs'),
        "anti_replay" => $childsa_elm->getAttribute('anti_replay'),
        "tfc_padding" => $childsa_elm->getAttribute('tfc_padding'),
        "udp_encap" => $childsa_elm->getAttribute('udp_encap'),
        "out_of_order_drop" => $childsa_elm->getAttribute('out_of_order_drop'),
        "pmtu_default" => $childsa_elm->getAttribute('pmtu_default'),
        "pmtu_cache" => $childsa_elm->getAttribute('pmtu_cache'),
        "collision_detected" => $childsa_elm->getAttribute('collision_detected'),
        "my_tss" => \@my_tss,
        "peer_tss" => \@peer_tss
      );


      $childsa_idx++;

      if( $childsa_state eq "established" || $childsa_state eq "rekeying" ){
        $ret{"childsa_state"} = "connected";
      }

      push(@childsas,\%childsa);
    }


    foreach my $internal_sns_elm ($resp_doc->getElementsByTagName('internal_networks') ){

      $ret{"internal_gateway_v4"} = $internal_sns_elm->getAttribute('internal_gateway_v4');
      $ret{"internal_gateway_v6"} = $internal_sns_elm->getAttribute('internal_gateway_v6');

      foreach my $internal_sn_elm ($internal_sns_elm->getElementsByTagName('internal_subnet_v4') ){

        my $network = $internal_sn_elm->getAttribute('network_v4');
        if( defined($network) ){

          my %network_v4 : shared = (
            "addr_family" => "ipv4",
            "network" => $network
          );    
  
          push(@internal_nets,\%network_v4);
        }
      }

      foreach my $internal_sn_elm ($internal_sns_elm->getElementsByTagName('internal_subnet_v6') ){

        my $network = $internal_sn_elm->getAttribute('network_v6');
        if( defined($network) ){

          my %network_v6 : shared = (
            "addr_family" => "ipv6",
            "network" => $network
          );    
  
          push(@internal_nets,\%network_v6);
        }
      }
      
      last;
    }

    foreach my $internal_split_dns_elm ($resp_doc->getElementsByTagName('split_dns') ){

      $ret{"internal_dns_server_v4"} = $internal_split_dns_elm->getAttribute('internal_dns_server_v4');
      $ret{"internal_dns_server_v6"} = $internal_split_dns_elm->getAttribute('internal_dns_server_v6');

      foreach my $internal_sdn_elm ($internal_split_dns_elm->getElementsByTagName('split_dns_domain') ){

        push(@split_dnss,$internal_sdn_elm->getAttribute('internal_domain_suffix'));
      }

      last;
    }
    
    last;
  }
  
  return \%ret;
}

sub bus_session_vpn_status {
  
  my($realm,$peerid_type,$peerid,$vpn_unique_id) = @_;

  #print "bus_session_vpn_status: Rlm: $realm, peerid_type:$peerid_type, peerid: $peerid, uid: $vpn_unique_id\n";

  if ( !defined($bus_session_id) ) {
    #print "bus_session_vpn_status bus_session_id=null\n";
    return undef;
  }

  my $url = 'http://' . $rhp_addr . ':' . $rhp_port . '/protected/bus/write/' . $bus_session_id;


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

  if( defined($peerid) ){
    
    my $attr_peerid_type = $doc->createAttribute( "peer_id_type", $peerid_type );
    $root->setAttributeNode($attr_peerid_type);

    my $attr_peerid = $doc->createAttribute( "peer_id", $peerid );
    $root->setAttributeNode($attr_peerid);
  }
  
  if( defined($vpn_unique_id) ){

    my $attr_unique_id = $doc->createAttribute( "vpn_unique_id", $vpn_unique_id );
    $root->setAttributeNode($attr_unique_id);
  }

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( PUT => $url );
  
  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );
  $req->header( "Content-Type"        => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    if ( $resp->status_line !~ '404' ) {
    
      print "bus_session_vpn_status: ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";
      print $doc->toString(1);

    }else{

#      print "bus_session_vpn_status: No information found.\n";      
    }
    
    return undef;

  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

#    print "Status(VPN): \n" . $resp_doc->toString(1) . "\n";

    return parse_vpn_status($resp_doc);
  }
}

sub bus_session_read_begin_thread {
  
  return threads->new(
    sub {
  
      while (1) {
  
        my $ret;
        $ret = bus_session_read();
        
        if( $op_disabled ){
          last;
        }
  
        if ( !$ret ) {

          print "bus_session_read error!\n";
          
          $op_disabled2 = 1;
          $bus_session_id = undef;

          $bus_session_id = bus_session_open();
          
          if( !defined($bus_session_id) ){
            print "bus_session_read re-open session error!\n";
            last;
          }
          
          $op_disabled2 = 0;
        }
      }
    }
  );
}

sub load_peers_info {

  bus_session_config_peers(\%peers_info,\$peers_info_num);
  
  if( $peers_info_num ){

    foreach my $pkey (keys %peers_info){  

      my $peer_ref = $peers_info{$pkey};

      $$peer_ref{"vpn_status"} = bus_session_vpn_status(
          $$peer_ref{"vpn_realm_id"},
          $$peer_ref{"peerid_type"},$$peer_ref{"peerid"});
    }
  }
}

sub bus_session_vpn_connect {
  
  my ($realm,$peerid_type,$peerid,$eap_sup_method,$eap_sup_user_id,$eap_sup_user_key) = @_;

  if ( !defined($bus_session_id) ) {
    #print "bus_session_vpn_connect=null\n";
    return;
  }

  my $url = 'http://' . $rhp_addr . ':' . $rhp_port . '/protected/bus/write/' . $bus_session_id;

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( PUT => $url );


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

  if( defined($eap_sup_method) && defined($eap_sup_user_id) && defined($eap_sup_user_key) ){

    my $attr_eap_sup_method = $doc->createAttribute( "eap_sup_method", $eap_sup_method );
    $root->setAttributeNode($attr_eap_sup_method);

    my $attr_eap_sup_user_id = $doc->createAttribute( "eap_sup_user_id", $eap_sup_user_id );
    $root->setAttributeNode($attr_eap_sup_user_id);

    my $attr_eap_sup_user_key = $doc->createAttribute( "eap_sup_user_key", $eap_sup_user_key );
    $root->setAttributeNode($attr_eap_sup_user_key);
  }


#  my $attr_auto_reconn = $doc->createAttribute( "auto_reconnect", "enable" );
#  $root->setAttributeNode($attr_auto_reconn);

  #print "bus_session_vpn_connect:\n" . $doc->toString(1) . "\n";

  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );
  $req->header( "Content-Type"        => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
    print $doc->toString(1) . "\n";
  }
  
  return;
}

sub bus_session_vpn_close {
  
  my ($realm,$peerid_type,$peerid) = @_;

  if ( !defined($bus_session_id) ) {
    #print "bus_session_vpn_close bus_session_id=null\n";
    return;
  }

  my $url = 'http://' . $rhp_addr . ':' . $rhp_port . '/protected/bus/write/' . $bus_session_id;

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( PUT => $url );


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

  my $attr_peerid_type = $doc->createAttribute( "peer_id_type", $peerid_type );
  $root->setAttributeNode($attr_peerid_type);
  
  my $attr_peerid = $doc->createAttribute( "peer_id", $peerid );
  $root->setAttributeNode($attr_peerid);


  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );
  $req->header( "Content-Type"        => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
    print $doc->toString(1) . "\n";
  }
  
  return;
}

sub bus_session_vpn_mobike_start_rt_check {
  
  my ($realm,$peerid_type,$peerid) = @_;

  if ( !defined($bus_session_id) ) {
    #print "bus_session_vpn_mobike_start_rt_check bus_session_id=null\n";
    return;
  }

  my $url = 'http://' . $rhp_addr . ':' . $rhp_port . '/protected/bus/write/' . $bus_session_id;

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( PUT => $url );


  my $doc  = XML::LibXML->createDocument;
  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "mobike_i_start_routability_check" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $attr_peerid_type = $doc->createAttribute( "peer_id_type", $peerid_type );
  $root->setAttributeNode($attr_peerid_type);
  
  my $attr_peerid = $doc->createAttribute( "peer_id", $peerid );
  $root->setAttributeNode($attr_peerid);


  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );
  $req->header( "Content-Type"        => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
    print $doc->toString(1) . "\n";
  }
  
  return;
}


sub bus_session_eap_sup_usr_key_reply {
  
  my ($realm,$action,$txn_id,$vpn_unique_id,$peerid_type,$peerid,$eap_sup_method,$eap_sup_user_id,$eap_sup_user_key) = @_;

  if ( !defined($bus_session_id) ) {
    #print "bus_session_close bus_session_id=null\n";
    return;
  }

  my $url = 'http://' . $rhp_addr . ':' . $rhp_port . '/protected/bus/write/' . $bus_session_id;

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( PUT => $url );


  my $doc  = XML::LibXML->createDocument;

  my $root = $doc->createElement("rhp_http_bus_request");
  $doc->setDocumentElement($root);

  my $attr_version = $doc->createAttribute( "version", $rhp_version );
  $root->setAttributeNode($attr_version);

  my $attr_service = $doc->createAttribute( "service", "ui_http_vpn" );
  $root->setAttributeNode($attr_service);

  my $attr_action = $doc->createAttribute( "action", "eap_sup_user_key_reply" );
  $root->setAttributeNode($attr_action);

  my $attr_realm = $doc->createAttribute( "vpn_realm", $realm );
  $root->setAttributeNode($attr_realm);

  my $attr_txn_id = $doc->createAttribute( "txn_id", $txn_id );
  $root->setAttributeNode($attr_txn_id);

  my $attr_eap_action = $doc->createAttribute( "eap_sup_action", $action );
  $root->setAttributeNode($attr_eap_action);

  if( defined($peerid_type) && defined($peerid) ){

    my $attr_peerid_type = $doc->createAttribute( "peer_id_type", $peerid_type );
    $root->setAttributeNode($attr_peerid_type);
  
    my $attr_peerid = $doc->createAttribute( "peer_id", $peerid );
    $root->setAttributeNode($attr_peerid);
  }
  
  my $attr_vpn_unique_id = $doc->createAttribute( "vpn_unique_id", $vpn_unique_id );
  $root->setAttributeNode($attr_vpn_unique_id);
  
  if( defined($eap_sup_method) && defined($eap_sup_user_id) && defined($eap_sup_user_key) ){

    my $attr_eap_sup_method = $doc->createAttribute( "eap_sup_method", $eap_sup_method );
    $root->setAttributeNode($attr_eap_sup_method);

    my $attr_eap_sup_user_id = $doc->createAttribute( "eap_sup_user_id", $eap_sup_user_id );
    $root->setAttributeNode($attr_eap_sup_user_id);

    my $attr_eap_sup_user_key = $doc->createAttribute( "eap_sup_user_key", $eap_sup_user_key );
    $root->setAttributeNode($attr_eap_sup_user_key);
  }


  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  $req->header( "X-Rhp-Authorization" => $auth_basic_key );
  $req->header( "Content-Type"        => 'text/xml; charset=utf-8' );
  $req->content( $doc->toString(1) );

  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {
    print "ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
    print $doc->toString(1) . "\n";
  }
  
  return;
}


my @view_mitem_cb_args = undef;

sub view_mitem_config_cb {
  system($browser_cfg);
}

sub view_mitem_connect_cb {

  my($realm_id,$peerid_type,$peerid) = @view_mitem_cb_args;

  my $peer_ref = $peers_info{peer_info_key($realm_id,$peerid_type,$peerid)};

  if( !defined($peer_ref) ){
    print "view_mitem_connect_cb: No peer's info found. $realm_id, $peerid_type, $peerid\n";
    @view_mitem_cb_args = undef;
    return;
  }

  $$peer_ref{"vpn_status"} = bus_session_vpn_status($realm_id,$peerid_type,$peerid);

  if( !defined($$peer_ref{"vpn_status"}) || 
      $$peer_ref{"vpn_status"}->{"ikesa_state"} ne "connected" ){

    bus_session_vpn_connect($realm_id,$peerid_type,$peerid,undef,undef,undef);

  }else{
    print "view_mitem_connect_cb: VPN already connected";    
  }
  
  @view_mitem_cb_args = undef;
}

sub view_mitem_disconnect_cb {

  my($realm_id,$peerid_type,$peerid) = @view_mitem_cb_args;

  my $peer_ref = $peers_info{peer_info_key($realm_id,$peerid_type,$peerid)};

  if( !defined($peer_ref) ){
    print "view_mitem_disconnect_cb: No peer's info found. $realm_id, $peerid_type, $peerid\n";
    @view_mitem_cb_args = undef;
    return;
  }

  $$peer_ref{"vpn_status"} = bus_session_vpn_status($realm_id,$peerid_type,$peerid);

  if( defined($$peer_ref{"vpn_status"}) &&
      $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connected" ){

    bus_session_vpn_close($realm_id,$peerid_type,$peerid);

  }else{
    print "view_mitem_disconnect_cb: VPN NOT connected.";    
  }

  @view_mitem_cb_args = undef;
}

sub mobike_i_rt_ck_enabled {

  my ($peer_ref) = @_;

  my $mobike_rt_ck = 0;  
    
  if( defined($$peer_ref{"vpn_status"}->{"exec_mobike"}) ){

    if( $$peer_ref{"vpn_status"}->{"exec_mobike"} == "1" ){

      if( (defined($$peer_ref{"vpn_status"}->{"rt_ck_pending"}) && 
           $$peer_ref{"vpn_status"}->{"rt_ck_pending"} != "0") ){

        if( (defined($$peer_ref{"vpn_status"}->{"rt_ck_waiting"}) && 
          $$peer_ref{"vpn_status"}->{"rt_ck_waiting"} != "0") ){

          $mobike_rt_ck = 1;

        }else{

#          print "Mobike I is pending. \n";
        }
        
      }else{

        $mobike_rt_ck = 1;
      }
    }
  }
    
  return $mobike_rt_ck;
}

sub mobike_i_rt_ck_pending {

  my ($peer_ref) = @_;

  my $mobike_rt_pending = 0;  
    
  if( defined($$peer_ref{"vpn_status"}->{"exec_mobike"}) ){

    if( $$peer_ref{"vpn_status"}->{"exec_mobike"} == "1" ){

      if( (defined($$peer_ref{"vpn_status"}->{"rt_ck_pending"}) && 
           $$peer_ref{"vpn_status"}->{"rt_ck_pending"} != "0") ){

        $mobike_rt_pending = 1;
      }
    }
  }
    
  return $mobike_rt_pending;
}

sub view_mitem_mobike_start_rt_check_cb {

  my($realm_id,$peerid_type,$peerid) = @view_mitem_cb_args;

  my $peer_ref = $peers_info{peer_info_key($realm_id,$peerid_type,$peerid)};

  if( !defined($peer_ref) ){
    print "view_mitem_mobike_start_rt_check_cb: No peer's info found. $realm_id, $peerid_type, $peerid\n";
    @view_mitem_cb_args = undef;
    return;
  }

  $$peer_ref{"vpn_status"} = bus_session_vpn_status($realm_id,$peerid_type,$peerid);

  if( defined($$peer_ref{"vpn_status"}) &&
      $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connected" ){

    my $mobike_rt_ck = mobike_i_rt_ck_enabled($peer_ref);    
    if( $mobike_rt_ck ){  
      bus_session_vpn_mobike_start_rt_check($realm_id,$peerid_type,$peerid);
    }
    
  }else{
    print "view_mitem_mobike_start_rt_check_cb: VPN NOT connected.";    
  }

  @view_mitem_cb_args = undef;
}

sub view_mitem_status_cb {

  my($realm_id,$peerid_type,$peerid) = @view_mitem_cb_args;

  my $dialog_height = $status_dialog_height;

  my $peer_ref = $peers_info{peer_info_key($realm_id,$peerid_type,$peerid)};

  if( !defined($peer_ref) ){
    print "view_mitem_status_cb: No peer's info found. $realm_id, $peerid_type, $peerid\n";
    @view_mitem_cb_args = undef;
    return;
  }

  $$peer_ref{"vpn_status"} = bus_session_vpn_status($realm_id,$peerid_type,$peerid);

  my $abtn = undef;
  my $abtn_key = undef;
  my $rtck = undef;
  my $rtck_key = undef;
  if( !defined($$peer_ref{"vpn_status"}) ||
      $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "disconnected"){

    $abtn = "Connect";
    $abtn_key = 10;

  }elsif( defined($$peer_ref{"vpn_status"}) &&
          $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connected" ){
    
    $abtn = "Disconnect";
    $abtn_key = 20;

    my $mobike_rt_ck = mobike_i_rt_ck_enabled($peer_ref);    
    if( $mobike_rt_ck ){
      $rtck = "Routability Check";
      $rtck_key = 40;
    }
  }
  
  my $dialog;
  if( defined($abtn) ){

    if( defined($rtck) ){

      $dialog = Gtk2::Dialog->new("VPN Status  " . $realm_id . ":" . view_peer_label($peerid_type,$peerid), 
                                $window, 
                                [qw/modal destroy-with-parent/],
                                'Web Console' => 30,
                                $rtck => $rtck_key,
                                $abtn => $abtn_key,
                                'OK' => 'ok');
      
    }else{  

      $dialog = Gtk2::Dialog->new("VPN Status  " . $realm_id . ":" . view_peer_label($peerid_type,$peerid), 
                                $window, 
                                [qw/modal destroy-with-parent/],
                                'Web Console' => 30,
                                $abtn => $abtn_key,
                                'OK' => 'ok');
    }
    
  }else{
    
    $dialog = Gtk2::Dialog->new("VPN Status  " . $realm_id . ":" . view_peer_label($peerid_type,$peerid), 
                                $window, 
                                [qw/modal destroy-with-parent/],
                                'Web Console' => 30,
                                'OK' => 'ok');
  }                             

  my $st_scrolled_window = Gtk2::ScrolledWindow->new();
  $st_scrolled_window->set_border_width(5);
  $st_scrolled_window->set_policy( "automatic", "automatic" );

  my $st_tstore = Gtk2::TreeStore->new('Glib::String','Glib::String');
  my $st_tree  = Gtk2::TreeView->new_with_model($st_tstore);
  $st_tree->get_selection->set_mode('none');
  $st_tree->set_headers_visible(0);

  my $idx = 0;
  my @labels = ("Name", "Value");
  foreach my $label (@labels){
    my $renderer = Gtk2::CellRendererText->new();
    my $column = Gtk2::TreeViewColumn->new_with_attributes($label,$renderer,'text' => $idx);
    $column->set_resizable(TRUE);
    $st_tree->append_column($column);
    $idx++;
  }


  my $root_itr = $st_tstore->append(undef);
  my $realm_name = "";
  if( defined($$peer_ref{"vpn_realm_name"}) && $$peer_ref{"vpn_realm_name"} ){
    $realm_name = ": " . $$peer_ref{"vpn_realm_name"};
  }
  
  $st_tstore->set($root_itr, 0 => " Realm", 1 => " " . $$peer_ref{"vpn_realm_id"} . $realm_name);

  my $peerid_label = view_peer_label($peerid_type,$peerid);
  $peerid_label =~ s/^\s+//;
  $root_itr = $st_tstore->append(undef);
  $st_tstore->set($root_itr, 0 => " Remote Peer ID", 1 => " " . $peerid_label);


  my $peer_addr_ipver = undef;
  my $peer_addr = undef;

  if( defined($$peer_ref{"vpn_status"}) ) {
    
    $peer_addr_ipver = $$peer_ref{"vpn_status"}->{"peer_addr_ipver"};
    if( $peer_addr_ipver eq "ipv4" ){
      $peer_addr_ipver = "IPv4: "; 
    }elsif( $peer_addr_ipver eq "ipv6" ){
      $peer_addr_ipver = "IPv6: "; 
    }else{
      $peer_addr_ipver = ""; 
    }
    $peer_addr = $$peer_ref{"vpn_status"}->{"peer_addr"};

  }else{

    $peer_addr = "0.0.0.0";
  }
  
  if( !defined($$peer_ref{"vpn_status"}) ||
      $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "disconnected"){

    $root_itr = $st_tstore->append(undef);

    if( $peer_addr eq "0.0.0.0" || $peer_addr eq "::" ){
      $peer_addr = " -";
      $peer_addr_ipver = "";
    }
    $st_tstore->set($root_itr, 0 => " Remote Peer Address", 1 => " " . $peer_addr_ipver . $peer_addr);
    
    $root_itr = $st_tstore->append(undef);
    $st_tstore->set($root_itr, 0 => " Status", 1 => " Not connected.");

  }else{

    my $peer_port = $$peer_ref{"vpn_status"}->{"peer_port"};
    my $peer_addr_txt = $peer_addr_ipver . $peer_addr;
    if( defined($peer_port) ){
      $peer_addr_txt .= ":" . $peer_port;
    }
    $root_itr = $st_tstore->append(undef);
    $st_tstore->set($root_itr, 0 => " Remote Peer Address", 1 => " " . $peer_addr_txt);

    $root_itr = $st_tstore->append(undef);

    if( $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connecting" ){
      
      $st_tstore->set($root_itr, 0 => " Status", 1 => " Connecting");

    }elsif( $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connected" ){

      $dialog_height = 450;

      my $exec_mobike = " Disabled";
      my $exec_mobike_detecting = undef;
      if( defined($$peer_ref{"vpn_status"}->{"exec_mobike"}) ){

        if( $$peer_ref{"vpn_status"}->{"exec_mobike"} == "1" ){

          $exec_mobike = " Enabled";        
          
          if( (defined($$peer_ref{"vpn_status"}->{"rt_ck_pending"}) && 
               $$peer_ref{"vpn_status"}->{"rt_ck_pending"} != "0")  ||
              (defined($$peer_ref{"vpn_status"}->{"rt_ck_waiting"}) && 
               $$peer_ref{"vpn_status"}->{"rt_ck_waiting"} != "0")  ){

            $exec_mobike_detecting = " Dormant";        
          }
        }
      }  

      if( defined($exec_mobike_detecting) ){
        $st_tstore->set($root_itr, 0 => " Status", 1 => $exec_mobike_detecting);
      }else{
        $st_tstore->set($root_itr, 0 => " Status", 1 => " Connected");
      }

      my $my_id 
      = " " . $$peer_ref{"vpn_status"}->{"myid"} . " (" . $$peer_ref{"vpn_status"}->{"myid_type"} . ")";
      if( defined($$peer_ref{"vpn_status"}->{"eap_my_identity"}) && 
          $$peer_ref{"vpn_status"}->{"eap_my_identity"} ){

        $my_id = " " . $$peer_ref{"vpn_status"}->{"eap_my_identity"};

        if( defined($$peer_ref{"vpn_status"}->{"eap_method"}) && 
            $$peer_ref{"vpn_status"}->{"eap_method"} ){
          $my_id = $my_id . " (eap-" . $$peer_ref{"vpn_status"}->{"eap_method"} . ")";
        }     
      }
      $root_itr = $st_tstore->append(undef);
      $st_tstore->set($root_itr, 0 => " My ID", 1 => $my_id);
            

      my $vif_name = $$peer_ref{"vpn_status"}->{"internal_if_name"};
      $root_itr = $st_tstore->append(undef);
      $st_tstore->set($root_itr, 0 => " VPN I/F", 1 => " " . $vif_name);

      if( defined($$peer_ref{"vpn_status"}->{"internal_if_addrs"}) ){

        my $itnl_if_addrs_ref = $$peer_ref{"vpn_status"}->{"internal_if_addrs"};
        if( defined($itnl_if_addrs_ref) ){

          my $nidx = 1;
          foreach my $itnl_if_addr_ref (@$itnl_if_addrs_ref){
            
            my $itr = $st_tstore->append($root_itr);
            my $dlabel = "";
            if( $nidx == 1 ){
              $dlabel = "Internal Address"
            }
            my $addr_family = $$itnl_if_addr_ref{"addr_family"};
            my $addr = $$itnl_if_addr_ref{"address"};
            if( $addr_family eq "ipv4" ){
              $st_tstore->set($itr, 0 => " " . $dlabel, 1 => " IPv4: " . $addr);
            }elsif( $addr_family eq "ipv6" ){
              $st_tstore->set($itr, 0 => " " . $dlabel, 1 => " IPv6: " . $addr);
            }else{
              $st_tstore->set($itr, 0 => " " . $dlabel, 1 => " " . $addr);
            }

            $nidx++;
          }
        }
      }  
            
      
      if( defined($$peer_ref{"vpn_status"}->{"internal_peer_addrs"}) ){


        my $itnl_peer_addrs_ref = $$peer_ref{"vpn_status"}->{"internal_peer_addrs"};
        if( defined($itnl_peer_addrs_ref) ){

          my $nidx = 1;
          foreach my $itnl_peer_addr_ref (@$itnl_peer_addrs_ref){
            
            my $itr;
            my $dlabel = "";
            if( $nidx == 1 ){
              $root_itr = $st_tstore->append(undef);
              $itr = $root_itr;
              $dlabel = "Internal Peer Address";
            }else{
              $itr = $st_tstore->append($root_itr);
            }
            
            my $addr_family = $$itnl_peer_addr_ref{"addr_family"};
            my $addr = $$itnl_peer_addr_ref{"address"};
            if( $addr_family eq "ipv4" ){
              if( $itr == $root_itr ){
                $st_tstore->set($itr, 0 => " " . $dlabel, 1 => " IPv4: " . $addr);
              }else{
                $st_tstore->set($itr, 0 => " ", 1 => " IPv4: " . $addr);
              }
            }elsif( $addr_family eq "ipv6" ){
              if( $itr == $root_itr ){
                $st_tstore->set($itr, 0 => " " . $dlabel, 1 => " IPv6: " . $addr);
              }else{
                $st_tstore->set($itr, 0 => " ", 1 => " IPv6: " . $addr);
              }
            }else{
              if( $itr == $root_itr ){
                $st_tstore->set($itr, 0 => " " . $dlabel, 1 => " " . $addr);
              }else{
                $st_tstore->set($itr, 0 => " ", 1 => " " . $addr);
              }
            }

            $nidx++;
          }
        }
      }  


      if( defined($$peer_ref{"vpn_status"}->{"internal_gateway_addr_v4"}) ){

        $root_itr = $st_tstore->append(undef);
        $st_tstore->set($root_itr, 0 => " Internal Gateway", 
          1 => " IPv4: " . $$peer_ref{"vpn_status"}->{"internal_gateway_addr_v4"});
      }  

      if( defined($$peer_ref{"vpn_status"}->{"internal_gateway_addr_v6"}) ){

        $root_itr = $st_tstore->append(undef);
        $st_tstore->set($root_itr, 0 => " Internal Gateway", 
          1 => " IPv6: " . $$peer_ref{"vpn_status"}->{"internal_gateway_addr_v6"});
      }  


      my $itnl_gw_v4 = $$peer_ref{"vpn_status"}->{"internal_gateway_v4"};
      my $itnl_gw_v6 = $$peer_ref{"vpn_status"}->{"internal_gateway_v6"};
      if( defined($itnl_gw_v4) || defined($itnl_gw_v6) ){

        $root_itr = $st_tstore->append(undef);

        if( defined($itnl_gw_v4) ){          
          $st_tstore->set($root_itr, 0 => " Internal Gateway", 1 => " IPv4: " . $itnl_gw_v4);
        }

        if( defined($itnl_gw_v6) ){

          if( defined($itnl_gw_v4) ){          
            my $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " ", 1 => " IPv6: " . $itnl_gw_v6);
          }else{
            $st_tstore->set($root_itr, 0 => " Internal Gateway", 1 => " IPv6: " . $itnl_gw_v6);
          }
        }
      }  


      my $itnl_nets_ref = $$peer_ref{"vpn_status"}->{"internal_nets"};
      if( defined($itnl_nets_ref) ){

        my $nidx = 1;
        foreach my $itnl_net_ref (@$itnl_nets_ref){
            
          my $itr;
          my $dlabel = "";
          if( $nidx == 1 ){
            $dlabel = "Internal Network";
            $root_itr = $st_tstore->append(undef);
            $itr = $root_itr;
          }else{
            $itr = $st_tstore->append($root_itr);
          }

          my $addr_family = $$itnl_net_ref{"addr_family"};
          my $addr = $$itnl_net_ref{"network"};
          if( $addr_family eq "ipv4" ){
            if( $itr == $root_itr ){
              $st_tstore->set($root_itr, 0 => " " . $dlabel, 1 => " IPv4: " . $addr);
            }else{
              $st_tstore->set($itr, 0 => " ", 1 => " IPv4: " . $addr);
            }
          }elsif( $addr_family eq "ipv6" ){
            if( $itr == $root_itr ){
              $st_tstore->set($root_itr, 0 => " " . $dlabel, 1 => " IPv6: " . $addr);
            }else{
              $st_tstore->set($itr, 0 => " ", 1 => " IPv6: " . $addr);
            }
          }else{
            if( $itr == $root_itr ){
              $st_tstore->set($root_itr, 0 => " " . $dlabel, 1 => " " . $addr);
            }else{
              $st_tstore->set($itr, 0 => " ", 1 => $addr);
            }
          }

          $nidx++;
        }
      }
            

      my $itnl_dns_svr_v4 = $$peer_ref{"vpn_status"}->{"internal_dns_server_v4"};
      my $itnl_dns_svr_v6 = $$peer_ref{"vpn_status"}->{"internal_dns_server_v6"};
      if( defined($itnl_dns_svr_v4) || defined($itnl_dns_svr_v6) ){

        $root_itr = $st_tstore->append(undef);

        if( defined($itnl_dns_svr_v4) ){
          $st_tstore->set($root_itr, 0 => " Internal DNS Server", 1 => " IPv4: " . $itnl_dns_svr_v4);
        }

        if( defined($itnl_dns_svr_v6) ){

          if( defined($itnl_dns_svr_v4) ){
            my $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " ", 1 => " IPv6: " . $itnl_dns_svr_v6);
          }else{
            $st_tstore->set($root_itr, 0 => " Internal DNS Server", 1 => " IPv6: " . $itnl_dns_svr_v6);
          }
        }

        my $split_domains_ref = $$peer_ref{"vpn_status"}->{"split_dns_domains"};
        if( defined($split_domains_ref) ){

          my $nidx = 1;
          foreach my $domain (@$split_domains_ref){
            
            my $itr = $st_tstore->append($root_itr);
            my $dlabel = "";
            if( $nidx == 1 ){
              $dlabel = "DNS Suffix"
            }
            $st_tstore->set($itr, 0 => " " . $dlabel, 1 => " " . $domain);

            $nidx++;
          }
        }
      }  

      my $my_addr_ipver = $$peer_ref{"vpn_status"}->{"my_addr_ipver"};
      if( $my_addr_ipver eq "ipv4" ){
        $my_addr_ipver = "IPv4: ";
      }elsif( $my_addr_ipver eq "ipv6" ){
        $my_addr_ipver = "IPv6: ";
      }else{
        $my_addr_ipver = "";
      }
      $root_itr = $st_tstore->append(undef);
      $st_tstore->set($root_itr, 0 => " Source I/F", 
        1 => " " . $$peer_ref{"vpn_status"}->{"my_if_name"} . " (" . $my_addr_ipver . $$peer_ref{"vpn_status"}->{"my_addr"} . ":" . $$peer_ref{"vpn_status"}->{"my_port"} . ")");
      

      my $bnat = " -";
      if( defined($$peer_ref{"vpn_status"}->{"behind_a_nat"}) ){

        if( $$peer_ref{"vpn_status"}->{"behind_a_nat"} == "1" ){
          $bnat = " This Node: BEHIND_A_NAT";        
        }elsif( $$peer_ref{"vpn_status"}->{"behind_a_nat"} == "2" ){
          $bnat = " Remote Peer: BEHIND_A_NAT";        
        }elsif( $$peer_ref{"vpn_status"}->{"behind_a_nat"} == "3" ){
          $bnat = " This Node & Remote Peer: BEHIND_A_NAT";        
        }      
      }  
      $root_itr = $st_tstore->append(undef);
      $st_tstore->set($root_itr, 0 => " NAT-T", 1 => $bnat);
      
            
      $root_itr = $st_tstore->append(undef);
      $st_tstore->set($root_itr, 0 => " MOBIKE", 1 => $exec_mobike);


      my $my_qcd = 0;
      if( defined($$peer_ref{"vpn_status"}->{"qcd_my_token_enabled"}) ){

        if( $$peer_ref{"vpn_status"}->{"qcd_my_token_enabled"} == "1" ){
          $my_qcd = 1;        
        }
      }  
      my $peer_qcd = 0;
      if( defined($$peer_ref{"vpn_status"}->{"qcd_peer_token_enabled"}) ){

        if( $$peer_ref{"vpn_status"}->{"qcd_peer_token_enabled"} == "1" ){
          $peer_qcd = 1;        
        }
      }  
      my $qcd = " -";
      if( $my_qcd && $peer_qcd ){
        $qcd = " This Node & Remote Peer: Enabled"
      }elsif( !$my_qcd && !$peer_qcd  ){
        $qcd = " This Node & Remote Peer: Disabled"
      }elsif( $my_qcd ){
        $qcd = " This Node: Enabled"
      }else{
        $qcd = " Remote Peer: Enabled"
      }
      $root_itr = $st_tstore->append(undef);
      $st_tstore->set($root_itr, 0 => " QCD", 1 => $qcd);

      $root_itr = $st_tstore->append(undef);
      if( $$peer_ref{"vpn_status"}->{"exec_sess_resume"} == "1" ){
        if( $$peer_ref{"vpn_status"}->{"gen_by_sess_resume"} == "1" ){
          $st_tstore->set($root_itr, 0 => " Session Resumption", 1 =>  " Enabled (Resumed)");
        }else{
          $st_tstore->set($root_itr, 0 => " Session Resumption", 1 =>  " Enabled");
        }
      }else{
        $st_tstore->set($root_itr, 0 => " IKEv2 Session Resumption", 1 =>  " Disabled");
      }    

      $root_itr = $st_tstore->append(undef);
      if( $$peer_ref{"vpn_status"}->{"exec_ikev2_fragmentation"} == "1" ){
        $st_tstore->set($root_itr, 0 => " IKEv2 Fragmentation", 1 =>  " Enabled");
      }else{
        $st_tstore->set($root_itr, 0 => " IKEv2 Fragmentation", 1 =>  " Disabled");
      }    


      my $ikesas_ref = $$peer_ref{"vpn_status"}->{"ikesas"};
      if( defined($ikesas_ref) ){

        foreach my $ikesa_ref (@$ikesas_ref){
          
          if( $$ikesa_ref{"state"} eq "established" || $$ikesa_ref{"state"} eq "rekeying" ){

            $root_itr = $st_tstore->append(undef);
            $st_tstore->set($root_itr, 0 => " IKE SA", 1 => "");
            
            my $this_node_auth_method = $$ikesa_ref{"auth_method"};
            if( defined($$peer_ref{"vpn_status"}->{"eap_method"}) && 
                $$peer_ref{"vpn_status"}->{"eap_method"} ){
              $this_node_auth_method = "eap-" . $$peer_ref{"vpn_status"}->{"eap_method"};
            }
            my $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " AUTH Method", 
              1 => " (This Node) " . $this_node_auth_method . " - (Remote Peer) " . $$ikesa_ref{"peer_auth_method"});
            
            $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " PRF", 1 => " " . $$ikesa_ref{"prf"});

            $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " DH Group", 1 => " " . $$ikesa_ref{"dh_group"});

            $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " Integrity", 1 => " " . $$ikesa_ref{"integ"});

            my $encr = $$ikesa_ref{"encr"};
            if( defined($$ikesa_ref{"encr_key_bits"}) ){
              $encr .= "_" . $$ikesa_ref{"encr_key_bits"};
            }
            $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " Encryption", 1 => " " . $encr);

            last;
          }
        }
      }


      my $childsas_ref = $$peer_ref{"vpn_status"}->{"childsas"};
      if( defined($childsas_ref) ){

        foreach my $childsa_ref (@$childsas_ref){
          
          if( $$childsa_ref{"state"} eq "established" || $$childsa_ref{"state"} eq "rekeying" ){

            $root_itr = $st_tstore->append(undef);
            $st_tstore->set($root_itr, 0 => " Child SA", 1 => "");
            
            my $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " Encapsulation Mode", 1 => " " . $$peer_ref{"vpn_status"}->{"encap_mode"});
            
            $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " Integrity", 1 => " " . $$childsa_ref{"integ"});

            my $encr = $$childsa_ref{"encr"};
            if( defined($$childsa_ref{"encr_key_bits"}) ){
              $encr .= "_" . $$childsa_ref{"encr_key_bits"};
            }
            $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " Encryption", 1 => " " . $encr);

            my $esn;
            if( $$childsa_ref{"esn"} eq "0" ){
              $esn = "Disabled"
            }else{
              $esn = "Enabled"
            }
            $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " ESN", 1 => " " . $esn );

            $itr = $st_tstore->append($root_itr);
            $st_tstore->set($itr, 0 => " Path MTU", 
              1 => " " . $$childsa_ref{"pmtu_cache"} . " (default: " . $$childsa_ref{"pmtu_default"} . ")");

            if( defined($$childsa_ref{"my_tss"}) ){

              $itr = $st_tstore->append($root_itr);
              $st_tstore->set($itr, 0 => " My Traffic Selectors", 1 => " ");
              
              my $my_tss_ref = $$childsa_ref{"my_tss"};
              foreach my $tss (@$my_tss_ref){

                my $itr2 = $st_tstore->append($itr);
                $st_tstore->set($itr2, 0 => " ", 1 => " " . $tss );
              }
            }

            if( defined($$childsa_ref{"peer_tss"}) ){

              $itr = $st_tstore->append($root_itr);
              $st_tstore->set($itr, 0 => " Peer Traffic Selectors", 1 => " ");
              
              my $my_tss_ref = $$childsa_ref{"peer_tss"};
              foreach my $tss (@$my_tss_ref){

                my $itr2 = $st_tstore->append($itr);
                $st_tstore->set($itr2, 0 => " ", 1 => " " . $tss );
              }
            }

            last;
          }
        }
      }
    }
  }

  $dialog->set_default_size($status_dialog_width,$dialog_height);                               

  $st_scrolled_window->add_with_viewport($st_tree);

  $dialog->vbox->add( $st_scrolled_window );

  $dialog->set_default_response ('ok');
  $dialog->set_position('center-always');

  $dialog->show_all();

  my $response = $dialog->run();
  if( $response eq 'delete-event' ){

    #print "response: $response\n";

  }elsif( $response eq "ok" ){

    #print "response: $response\n";

  }elsif( $response == 10 ){

    view_mitem_connect_cb();

  }elsif( $response == 20 ){

    view_mitem_disconnect_cb();

  }elsif( $response == 30 ){

    system($browser_cfg);

  }elsif( $response == 40 ){
    
    view_mitem_mobike_start_rt_check_cb();
  }

  $dialog->destroy();
  
  @view_mitem_cb_args = undef;
}

sub view_show_popup_menu_default {
  
  
  my $menu = Gtk2::Menu->new();

  my $mitem_config;

  $mitem_config = Gtk2::MenuItem->new("Web Console");
  $mitem_config->signal_connect( 'activate', \&view_mitem_config_cb );
  
  $menu->append($mitem_config);
  $mitem_config->show();

  $menu->show();
  
  $menu->popup(undef,undef,undef,undef,0,0);
}

sub view_show_popup_menu {
  
  my($realm_id,$peerid_type,$peerid) = @_;
  
  
  my $peer_ref = $peers_info{peer_info_key($realm_id,$peerid_type,$peerid)};

  if( !defined($peer_ref) ){
    print "view_show_popup_menu: No peer's info found. $realm_id, $peerid_type, $peerid\n";
    return;
  }
  
  my $menu = Gtk2::Menu->new();

  my($mitem_connect, $mitem_disconnect, $mitem_status, $mitem_config, $mitem_mobike_rtck);
  
  @view_mitem_cb_args = ($realm_id,$peerid_type,$peerid);


  $$peer_ref{"vpn_status"} = bus_session_vpn_status($realm_id,$peerid_type,$peerid);

  if( !defined($$peer_ref{"vpn_status"}) || 
      $$peer_ref{"vpn_status"}->{"ikesa_state"} ne "connected" ){

    
    if( defined($$peer_ref{"vpn_status"}) &&
        $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connecting" ){

      $mitem_connect = Gtk2::MenuItem->new("Connecting");
      $mitem_connect->set_sensitive(FALSE);

    }else{

      $mitem_connect = Gtk2::MenuItem->new("Connect");
      $mitem_connect->signal_connect( 'activate', \&view_mitem_connect_cb );
    }
  }

  if( defined($$peer_ref{"vpn_status"}) &&
      $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connected" ){
  
    $mitem_disconnect = Gtk2::MenuItem->new("Disconnect");
    $mitem_disconnect->signal_connect( 'activate', \&view_mitem_disconnect_cb );
  }
      
  if( defined($$peer_ref{"vpn_status"}) &&
      $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connected" ){
  
    my $mobike_rt_ck = mobike_i_rt_ck_enabled($peer_ref);    
    if( $mobike_rt_ck ){  
      $mitem_mobike_rtck = Gtk2::MenuItem->new("Routability Check");
      $mitem_mobike_rtck->signal_connect( 'activate', \&view_mitem_mobike_start_rt_check_cb );
    }
  }

  $mitem_status = Gtk2::MenuItem->new("Status");
  $mitem_status->signal_connect( 'activate', \&view_mitem_status_cb );
            
  $mitem_config = Gtk2::MenuItem->new("Web Console");
  $mitem_config->signal_connect( 'activate', \&view_mitem_config_cb );
  
  if( defined($mitem_connect) ){
    $menu->append($mitem_connect);
    $mitem_connect->show();
  }

  $menu->append($mitem_status);
  $mitem_status->show();
  
  if( defined($mitem_mobike_rtck) ){
    $menu->append($mitem_mobike_rtck);
    $mitem_mobike_rtck->show();
  }

  if( defined($mitem_disconnect) ){
    $menu->append($mitem_disconnect);
    $mitem_disconnect->show();
  }
    
  $menu->append($mitem_config);
  $mitem_config->show();


  $menu->show();
  
  $menu->popup(undef,undef,undef,undef,0,0);
}

# return : boolean
sub view_peer_col_pressed {
  
  my($tview,$tevent) = @_;

  if( $op_disabled == 1 || $op_disabled2 == 1 ){
    return TRUE;
  }


  if($tevent->type eq "button-press" || $tevent->type eq "2button-press"){

    # $tevent->button : 1 ==> Mouse's left button, 3 ==> right button.
    #print "col_pressed: Col pressed. " . $tevent->button . "\n";

    my $tselection = $tview->get_selection();
    my($path, $column, $cell_x, $cell_y) = $tview->get_path_at_pos($tevent->x,$tevent->y);

    $tselection->unselect_all();    
    $tselection->select_path($path);    
    
    my ($tmodel,$titr) = $tselection->get_selected();
  
    my $realm_id = $tmodel->get($titr,0);
    my $peer_label = $tmodel->get($titr,1);
    #print("col_pressed: Selected Col: $realm_id : $peer_label, $tview\n");   
    
    if( $dmy_col_appended ){

      view_show_popup_menu_default();

    }else{
    
      if( $tevent->button == 3 ){
  
        view_show_popup_menu($realm_id,view_peer_label2id($peer_label));
  
      }elsif( $tevent->type eq "2button-press" && $tevent->button == 1 ){
  
        my($peerid_type,$peerid) = view_peer_label2id($peer_label);
  
        @view_mitem_cb_args = ($realm_id,$peerid_type,$peerid);
  
        view_mitem_status_cb();
        
        return TRUE;
      }
    }
  }
  
  return FALSE;
}

sub view_peer_label {

  my ($peerid_type,$peerid,$apdx_label) = @_;
  
  my $peerid_label = '  ' . $peerid;
  if( $peerid_type eq "null-id" ){
    $peerid_label .= '  ';
  }elsif( $peerid_type ne "" ){
    $peerid_label .= ' (' . $peerid_type . ')  ';
  }else{
    $peerid_label .= '  ';
  }
    
  return $peerid_label;
}

sub view_peer_label2id {
  
  my($peer_label) = @_;
  
  $peer_label =~ s/\s//g;
  $peer_label =~ s/\)//g;

  my($peerid,$peerid_type);
  if( $peer_label !~ /\(/ ){
    $peerid = $peer_label;
    $peerid_type = "null-id";
  }else{
    ($peerid,$peerid_type) = split(/\(/,$peer_label);
  }
  
  #print "view_peer_label2id: " . $peerid_type . " " . $peerid . "\n";
  
  return ($peerid_type,$peerid);  
}

# (ex) view_update_peer_row("10","fqdn","yyy.example.com","","Connected");
sub view_update_peer_row_enum {
  
  my ($tmodel,$tpath,$titr,$user_data) = @_;
  my ($realm_id,$peerid_type,$peerid,$apdx_label,$status) = @$user_data;

  my $peerid_label = view_peer_label($peerid_type,$peerid,$apdx_label);
  
  my $mtch_str = $peerid_label;
  $mtch_str =~ s/\(/\\\(/;
  $mtch_str =~ s/\)/\\\)/;

  my $row_realm_id = $tmodel->get($titr,0);
  my $row_peerid_label = $tmodel->get($titr,1);
  
  if( $row_realm_id eq $realm_id &&
      ( $row_peerid_label =~ /^$mtch_str$/ || $row_peerid_label =~ /^$mtch_str\s/ ) ){
  
    if( $apdx_label ne "" ){
      $peerid_label = $peerid_label . " " . $apdx_label;
    }
    
    $tstore->set( $titr, 0 => $realm_id, 1 => $peerid_label, 2 => $status );
    return TRUE;
  }
  
  return FALSE;
}

# args: ($realm_id,$peerid_type,$peerid,$apdx_label,$status)
sub view_update_peer_row {

  my $tmodel = $tview->get_model();
  $tmodel->foreach(\&view_update_peer_row_enum,\@_);    
}

#
# peer-row:1 ==> $idx eq "0"
# peer-row:2 ==> $idx eq "1"
# ...
#
sub view_remove_peer_row {
  
  my ($idx) = @_;

  my $tmodel = $tview->get_model();    
  my $titr = $tmodel->get_iter(Gtk2::TreePath->new($idx));
  $tmodel->remove($titr);
}

sub view_flush_peer_rows {
  
  for( my $idx = 0; $idx < $peers_info_num; $idx++){

    view_remove_peer_row(0);
  }
  
  if( $dmy_col_appended ){
    view_remove_peer_row(0);
  }
}

# (ex) view_add_peer_row("10","fqdn","yyy.example.com","","Connected");
sub view_add_peer_row {
  
  my ($realm_id,$peerid_type,$peerid,$apdx_label,$status) = @_;
  
  my $peerid_label = view_peer_label($peerid_type,$peerid,$apdx_label);
    
  if( $apdx_label ne "" ){
    $peerid_label = $peerid_label . " " . $apdx_label;
  }
    
  my $titr = $tstore->append();
  $tstore->set( $titr, 0 => $realm_id, 1 => $peerid_label, 2 => $status );
}

sub view_create_tree_view {

  $tstore = Gtk2::ListStore->new( 'Glib::String', 'Glib::String', 'Glib::String' );
  $tview = Gtk2::TreeView->new_with_model($tstore);
  $tview->get_selection->set_mode('single');

  $tstore->set_sort_column_id( 0, 'ascending' );

  my $renderer = Gtk2::CellRendererText->new();
  my $column = Gtk2::TreeViewColumn->new_with_attributes( "Realm", $renderer, 'text' => 0 );
  $column->set_sort_column_id(0);
  $column->set_resizable(TRUE);
  $tview->append_column($column);

  $renderer = Gtk2::CellRendererText->new();
  $column   = Gtk2::TreeViewColumn->new_with_attributes( "Remote peers", $renderer, 'text' => 1 );
  $column->set_sort_column_id(1);
  $column->set_resizable(TRUE);
  $tview->append_column($column);

  $renderer = Gtk2::CellRendererText->new();
  $column   = Gtk2::TreeViewColumn->new_with_attributes( "Status", $renderer, 'text' => 2 );
  $column->set_sort_column_id(2);
  $column->set_resizable(TRUE);
  $tview->append_column($column);


  $tview->set_reorderable(TRUE);

  $tview->signal_connect("button-press-event" => \&view_peer_col_pressed);
}

sub view_destroy_window {

  $op_disabled = 1;

  bus_session_close();
  $bus_session_id = undef;

  if( $bus_read_thread ){
    $bus_read_thread->join();
  }

  Gtk2->main_quit();
}

sub view_default_pressed {
 
  my($wdt,$tevent) = @_;
  
  if( $peers_info_num ){
    return FALSE;
  }

  if($tevent->type eq "button-press" || $tevent->type eq "2button-press"){

    view_show_popup_menu_default();
  }
    
  return TRUE;
}

sub view_create_window {

  $window = Gtk2::Window->new;
  $window->set_title("Rockhopper VPN Client");
  $window->signal_connect( "delete_event" => \&view_destroy_window );
  $window->set_default_size( $column_width, $win_base_height + ($column_height * $peer_rows) );
  $window->set_position('center');
  
  if( -e $win_icon_path ){
    $window->set_icon_from_file($win_icon_path);
  }
  
  my $win_vbox = Gtk2::VBox->new( FALSE, 5 );
  $window->add($win_vbox);

  my $scrolled_window = Gtk2::ScrolledWindow->new();
  $scrolled_window->set_border_width(5);
  $scrolled_window->set_policy( "automatic", "automatic" );
  $win_vbox->pack_start( $scrolled_window, TRUE, TRUE, 5 );

  my $base_vbox = Gtk2::VBox->new( FALSE, 5 );
  $scrolled_window->add_with_viewport($base_vbox);

  view_create_tree_view();

  if( $peers_info_num == 0 ){
    
    $window->signal_connect("button-press-event" => \&view_default_pressed);
  }
  
  my $tview_vbox = Gtk2::VBox->new( FALSE, 5 );
  $tview_vbox->pack_start( $tview, TRUE, TRUE, 5 );

  $base_vbox->pack_start( $tview_vbox, FALSE, FALSE, 5 );

  $window->show_all();
}

sub view_add_peers {

  if( $peers_info_num ){
    
    my @peers_info_lst = ();
    foreach my $pkey (keys %peers_info){
      push(@peers_info_lst,$peers_info{$pkey});
    }
    
    my @peers_info_sorted 
      = sort {$$b{"vpn_realm_id"} <=> $$a{"vpn_realm_id"}} @peers_info_lst;
 
    foreach my $peer_ref (@peers_info_sorted){
    
      $$peer_ref{"vpn_status"} = bus_session_vpn_status(
        $$peer_ref{"vpn_realm_id"},$$peer_ref{"peerid_type"},$$peer_ref{"peerid"});


      my $status = "-";
      if( !defined($$peer_ref{"vpn_status"}) || 
          $$peer_ref{"vpn_status"}->{"ikesa_state"} ne "connected" ){

    
        if( defined($$peer_ref{"vpn_status"}) &&
            $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connecting" ){

          $status = "Connecting";
        }
      }
      
      if( defined($$peer_ref{"vpn_status"}) &&
          $$peer_ref{"vpn_status"}->{"ikesa_state"} eq "connected" ){
  
        my $mobike_rt_pending = mobike_i_rt_ck_pending($peer_ref);    
        if( $mobike_rt_pending ){
          $status = "Dormant";
        }else{ 
          $status = "Connected";
        }
      }
      
      view_add_peer_row($$peer_ref{"vpn_realm_id"},
        $$peer_ref{"peerid_type"},$$peer_ref{"peerid"},"",$status);
    }

    $dmy_col_appended = 0;

  }else{

    if( !defined($bus_session_id) ){
      view_add_peer_row("","","VPN Client is not enabled.","","");
    }else{
      view_add_peer_row("","","No remote peers configured.","","");
    }
    
    $dmy_col_appended = 1;
  }
}

sub view_deiconify_window {

  Gtk2::Gdk::Threads->enter();
  if( defined($window) ){
    $window->deiconify();
  }
  Gtk2::Gdk::Threads->leave();
}

my $dup_pid = undef;
sub check_dup_exec {
  
  my $eusr = `whoami`;
  chop($eusr);
  $dup_pid = `pgrep -o -u $eusr rhp_client.pl`;
  chop($dup_pid);

  if( $$ eq $dup_pid ){
    return TRUE;
  }else{
    return FALSE;
  } 
}



my $lsb = `lsb_release -i`;
chomp($lsb);
my $dist_name = "";
if( $lsb =~ /LinuxMint/ ){
#  $win_base_height = 0;
}

# a SIGUSR1's handler to deiconify the window.
$SIG{USR1} = \&view_deiconify_window;

if( !check_dup_exec() ){

  kill USR1 => $dup_pid;

}else{

  $bus_session_id = bus_session_open();
  
  load_peers_info();
  
  
  $peer_rows = $peers_info_num;
  if( $peer_rows < 1 ){
    $peer_rows = 1;
  }
    
  view_create_window();
  view_add_peers();
  
  if( defined($bus_session_id) ){
    
    $bus_read_thread = bus_session_read_begin_thread();
  }
  
  Gtk2::Gdk::Threads->enter();
  Gtk2->main();
  Gtk2::Gdk::Threads->leave();
}

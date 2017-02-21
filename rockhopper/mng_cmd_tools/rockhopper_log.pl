#! /usr/bin/perl

#
#  Copyright (C) 2015 TETSUHARU HANADA <rhpenguine@gmail.com>
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
# Command-line Log tool for Rockhopper.
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

use Class::Struct;

use Getopt::Long;

# (Ubuntu 8.x--) NOT need to import libwww-perl by package manager.
use LWP::UserAgent;
use LWP::Authen::Basic;
use HTTP::Request::Common;

# (Ubuntu 8.x--) Need to import libxml-libxml-perl by package manager.
use XML::LibXML;

use JSON;

use Switch;


my $rhp_version = '1.0';

my $action   = $ARGV[0];
my $show_xml = 0;
my $one_line = 0;

my $tail_logs_cb_template_xml = undef;
my @tail_logs_cb_event_sources = ();
my @tail_logs_cb_event_levels = ();
my %tail_logs_cb_event_errors = ();
my %tail_logs_cb_event_labels = ();
my %tail_logs_cb_event_mesg_tmpls = ();
my $tail_logs_cb_idx = 0;  
my $dont_overwrite = 0;

my $help = 0;
my $no_pager = 0;

my %cmd_opts = ();

my $summary = 0;

GetOptions(
  \%cmd_opts,
  'admin=s',
  'password=s',       
  'port=i',           
  'admin_id=s',       
  'admin_password=s',
  'file=s',
  'log_xml=s',
  'formatter_xml=s',
  'max_records=s',
  'match=s',
  'debug_log=s',
  'dont_overwrite' => \$dont_overwrite,
  'one_line' => \$one_line,
  'xml' => \$show_xml,
  'no_pager' => \$no_pager,
  'summary' => \$summary,
  'help' => \$help
);


my $admin    = $cmd_opts{admin};
my $password = $cmd_opts{password};

my $address = "127.0.0.1";
my $port = 32501;
if ( defined($cmd_opts{port}) ) {
  $port = $cmd_opts{port};
}

my $auth_basic_key = undef;

my $log_record_match_str = $cmd_opts{match};

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


sub print_usage {

  my ($action) = @_;

  print_stdout "[ Usage ]\n";
  if( !defined($action) ){
    
    goto gen_error;

  }elsif ( $action eq 'debug' ) {

    print_stdout "% rockhopper_log <command> ...\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-xml] [-no_pager] [-summary] [-h]\n";
    print_stdout " [-port <admin_port>]\n\n";
    print_stdout " command:\n";
    print_stdout "  help <command>  Show help info.\n";
    print_stdout "\n";
    print_stdout "  bus-read      Reading async messages from Rockhopper process.\n";
    print_stdout "\n";
    print_stdout "\n";

    print_usage('bus-read');

  }elsif ( $action eq 'show' ) {

    print_stdout "% rockhopper_log show \n";
    print_stdout " [-no_pager] [-one_line] [-summary]\n";
    print_stdout " [-match <substring/regex>]\n";
    print_stdout " [-max_records <num>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  }elsif ( $action eq 'save' ) {

    print_stdout "% rockhopper_log save \n";
    print_stdout " -file <saved_file_name> [-max_records <num>]\n";
    print_stdout " [-match <substring/regex>]\n";
    print_stdout " [-one_line] [-summary]\n";
    print_stdout " [-dont_overwrite]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  }elsif ( $action eq 'clear' ) {

    print_stdout "% rockhopper_log clear \n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  }elsif ( $action eq 'follow' ) {

    print_stdout "% rockhopper_log follow \n";
    print_stdout " [-debug_log <enalble/disable>]\n";
    print_stdout " [-one_line] [-summary]\n";
    print_stdout " [-match <substring/regex>]\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  }elsif ( $action eq 'xml2txt' ) {

    print_stdout "% rockhopper_log xml2txt \n";
    print_stdout " -log_xml <log_file>\n";
    print_stdout " -formatter_xml <formatter_file>\n";
    print_stdout " -file <converted_file>]\n";
    print_stdout " [-dont_overwrite]\n";
    print_stdout " [-one_line] [-summary]\n";
    print_stdout "\n";

  } elsif ( $action eq 'bus-read' ) {

    print_stdout "% rockhopper_log bus-read\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-port <admin_port>]\n";
    print_stdout "\n";

  } else {
    
gen_error:
    print_stdout "% rockhopper_log <command> ...\n";
    print_stdout " [-admin <admin_id> -password <password>]\n";
    print_stdout " [-xml] [-no_pager] [-summary] [-h]\n\n";
    print_stdout " [-port <admin_port>]\n\n";
    print_stdout " command:\n";
    print_stdout "  help <command>  Show help info.\n";
    print_stdout "\n";
    print_stdout "  show         Show event log.\n";
    print_stdout "  save         Save event log.\n";
    print_stdout "  follow       Follow event log.\n";
    print_stdout "  clear        Clear old event records.\n";
    print_stdout "  xml2txt      Convert log file(xml) to formatted text.\n";
    print_stdout "\n";
    print_stdout "% rockhopper_log <command> -h   Show help info.\n";
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

sub need_admin_password()
{
  my $retries = 0;
  my $resp = undef;

  while( 1 ){
    
    if( $retries ){
      print "\nInvalid Username and/or Password specified.\n\n";
    }
    
    if ( !defined($admin) || !defined($password) ) {
  
      print " Name(Admin): ";
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
  
    $resp = $ua->request($req);
  
    if( !$resp->is_success ){
  
      $admin = undef;
      $password = undef;
  
      if( $retries < 3 ){
  
        $retries++;
  
        next;
          
      }else{

        print "\nPlease confirm Username and/or Password.\n\n";
        exit;
      }

    }else{
      last;
    }
  }
  
  my $parser     = XML::LibXML->new;
  my $resp_doc   = $parser->parse_string( $resp->decoded_content );
  
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_auth_response') ){
    
    if( defined(EA('http_bus_is_open')) && EA('http_bus_is_open') eq "1" ){
      
      print "Simultaneous logins by the same administrator are\n";
      print "not allowed. If you want to continue, push 'y'. [y/N]\n";

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

    if( $show_xml ){
      print_stdout "bus_read:\n" . $resp . "\n";
    }

    $ret = $bus_read_cb_ref->($bus_session_id,$bus_read_cb_ctx_ref,$resp);
  }

  return $ret;
}

#
# Actually, it is NOT necessary to invoke another thread for 
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
#         print_stdout "bus_session_read error!\n";
          last;
        }elsif( $ret == 1 ){
          last;
        }
      }
    }
  );
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
    }

    print_stdout "$EAELM\n";
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


struct EventLogMesgTmpl => {
  tag => '$',
  mesg => '$'
};

sub dump_event_log_template {

  my ($event_sources_ref,$event_levels_ref,$event_errors_ref,
      $event_labels_ref,$event_mesg_tmpls_ref) = @_;

  my @event_sources = @$event_sources_ref;
  my @event_levels = @$event_levels_ref;
  my %event_errors = %$event_errors_ref;
  my %event_labels = %$event_labels_ref;
  my %event_mesg_tmpls = %$event_mesg_tmpls_ref;

  my $num = 0;

  print_stdout "\n";  
  print_stdout "event_sources: \n";
  for( my $i = 0; $i < scalar(@event_sources); $i++ ){
    print_stdout "[$i]: " . $event_sources[$i] . "\n";
    $num++;
  }
  print_stdout "Num: $num\n";

  print_stdout "\n";  
  print_stdout "event_levels: \n";
  $num = 0;
  for( my $i = 0; $i < scalar(@event_levels); $i++ ){
    print_stdout "[$i]: " . $event_levels[$i] . "\n";
    $num++;
  }
  print_stdout "Num: $num\n";

  print_stdout "\n";  
  print_stdout "event_errors: \n";
  $num = 0;
  while ( my( $key, $value ) = each ( %event_errors ) ) {
    print_stdout $key . ":" . $value . "\n";
    $num++;
  }
  print_stdout "Num: $num\n";

  print_stdout "\n";  
  print_stdout "event_labels: \n";
  $num = 0;
  while ( my( $key, $value ) = each ( %event_labels ) ) {
    print_stdout $key . ":" . $value . "\n";
    $num++;
  }
  print_stdout "Num: $num\n";

  print_stdout "\n";  
  print_stdout "event_mesg_tmpls: \n";
  $num = 0;
  while ( my( $key, $value ) = each ( %event_mesg_tmpls ) ) {
    
    my $event_mesg_tmpl = $$value;
    
    print_stdout "[" . $key . "]:" . $event_mesg_tmpl->tag  . " : " . $event_mesg_tmpl->mesg . "\n";
    $num++;
  }
  print_stdout "Num: $num\n";
      
  return;  
}

sub parse_event_log_template {
  
  my ($template_xml,$event_sources_ref,$event_levels_ref,
      $event_errors_ref,$event_labels_ref,$event_mesg_tmpls_ref) = @_;

  foreach $EAELM ( $template_xml->getElementsByTagName('event_source') ){
    @$event_sources_ref[EA('id')] = EA('name');
  }    

  foreach $EAELM ( $template_xml->getElementsByTagName('level') ){
    @$event_levels_ref[EA('id')] = EA('name');
  }    

  foreach $EAELM ( $template_xml->getElementsByTagName('error_label') ){

    my $error_label_elm = $EAELM;
    foreach $EAELM ( $error_label_elm->getElementsByTagName('label_item') ){
      
      my $value = EA('value');
      my $label = EA('label');
            
      ${$event_errors_ref}{'#E(-' . $value . ')#'} = $label;
    }    
  }

  foreach $EAELM ( $template_xml->getElementsByTagName('rhp_error_label') ){

    my $error_label_elm = $EAELM;
    foreach $EAELM ( $error_label_elm->getElementsByTagName('label_item') ){
      
      my $value = EA('value');
      my $label = EA('label');
      
      ${$event_errors_ref}{'#E(' . $value . ')#'} = $label;
    }    
  }
  
  foreach $EAELM ( $template_xml->getElementsByTagName('label') ){

    my $label_elm = $EAELM;
    my $tag = EA('tag');
    
    foreach $EAELM ( $label_elm->getElementsByTagName('label_item') ){
      
      my $value = EA('value');
      my $label = EA('label');
      
      ${$event_labels_ref}{"#L#" . $tag . "," . $value . "##"} = $label;
    }    
  }
  
  
  foreach $EAELM ( $template_xml->getElementsByTagName('event_log') ){
    
    my $id = EA('id');
    
    my $event_mesg_tmpl = EventLogMesgTmpl->new();
    $event_mesg_tmpl->tag(EA('tag'));
  
    my @cnodes = $EAELM->childNodes();
    if( scalar(@cnodes) ){

      for( my $i = 0; $i < scalar(@cnodes); $i++){

        if( $cnodes[$i]->nodeName eq "#cdata-section" ){

          $event_mesg_tmpl->mesg($cnodes[$i]->nodeValue());
          last;
        }
      }
        
    }else{
      
      $event_mesg_tmpl->mesg("no mesg template");
    }
    
    ${$event_mesg_tmpls_ref}{$id} = \$event_mesg_tmpl;
  }    
  
  return;
}

sub get_xml_file {

  my ($path,$file,$with_pw) = @_;

  my $url = 'http://' . $address . ':' . $port . $path;

  my $ua = LWP::UserAgent->new();
  my $req = HTTP::Request->new( GET => $url );

  $req->header( "Accept"              => 'text/xml' );
  $req->header( "Accept-Charset"      => 'utf-8' );
  if( $with_pw ){
    $req->header( "X-Rhp-Authorization"  => $auth_basic_key );
  }
  $req->header( "Content-Type"        => 'text/xml; charset=utf-8' );

  my $resp = $ua->request($req);

  if ( !$resp->is_success || !$resp->decoded_content ) {

    print_stdout "get_xml_file: Error occurs or no content " . $url . ":" . $resp->status_line . "\n";
    return undef;
    
  } else {

    my $parser   = XML::LibXML->new;
    my $resp_doc = $parser->parse_string( $resp->decoded_content );

    if( defined($file) ){
    
      if ( !open( SAVED_FILE, ">> $file" ) ) {
        print_stdout "Can't open $file.\n";
      } else {
        print SAVED_FILE $resp_doc->toString(1);
        close(SAVED_FILE);
      }
    }
        
    if( $show_xml ){
      print_stdout "get_xml_file: \n" . $resp_doc->toString(1) . "\n";
    }
    
    return $resp_doc;
  }
}


struct EventLogCvtRecord => {
  source => '$',
  realm => '$',
  level => '$',
  id => '$',
  timestamp => '$',
  tag => '$',
  mesg => '$',
  record_elm => '$'
};

sub parse_log_record {
  
  my ($record_elm,$event_sources_ref,$event_levels_ref,
      $event_errors_ref,$event_labels_ref,$event_mesg_tmpls_ref) = @_;

  my $log_cvt_record = EventLogCvtRecord->new();
  $log_cvt_record->record_elm($record_elm);
  $log_cvt_record->mesg(undef);

  my $json_log_record_ref = undef;
  my @cnodes = $record_elm->childNodes();
  if( scalar(@cnodes) ){

    for( my $i = 0; $i < scalar(@cnodes); $i++){

      if( $cnodes[$i]->nodeName eq "#cdata-section" ){

        my $json_data = $cnodes[$i]->nodeValue();
        
        $json_log_record_ref = JSON->new()->decode("[".$json_data."]");
      }
    }
  }

  if( !defined($json_log_record_ref) || scalar(@$json_log_record_ref) < 1 ){
#    print_stdout "parse_log_record: Empty record returned.\n";
    return $log_cvt_record;
  }

  my $json_log_record = @$json_log_record_ref[0];
        
  if( defined( @$event_sources_ref[$json_log_record->{src}] ) ){
    $log_cvt_record->source(@$event_sources_ref[$json_log_record->{src}] . "(" . $json_log_record->{src} . ")");
  }else{
    $log_cvt_record->source($json_log_record->{src});
  } 
  
  if( $json_log_record->{realm} eq "4294967295" || $json_log_record->{realm} eq "0" ){
    $log_cvt_record->realm("Rlm:-") ;
  }else{
    $log_cvt_record->realm("Rlm:" . $json_log_record->{realm});
  }
  
  if( defined(@$event_levels_ref[$json_log_record->{lv}]) ){
    $log_cvt_record->level(@$event_levels_ref[$json_log_record->{lv}] . "(" . $json_log_record->{lv} . ")");
  }else{
    $log_cvt_record->level($json_log_record->{lv});
  }
  
  $log_cvt_record->id($json_log_record->{id});
  $log_cvt_record->timestamp($json_log_record->{ts});
  
  
  my $event_mesg_tmpl_ref = ${$event_mesg_tmpls_ref}{$json_log_record->{id}};  

  my @log_record_args = @{$json_log_record->{args}};

  my $unknown_log_mesg = "*No mesg template:";  
  my $log_mesg = undef;
  my $no_log_tmpl = 0;

  if( defined($event_mesg_tmpl_ref) ){
    $log_cvt_record->tag($$event_mesg_tmpl_ref->tag);
    $log_mesg = $$event_mesg_tmpl_ref->mesg;
  }

  for(my $i = 0; $i < scalar(@log_record_args); $i++){
    
    if( !defined($event_mesg_tmpl_ref) ){
  
      $unknown_log_mesg .= $log_record_args[$i] . " ";
      $no_log_tmpl++;
      
    }else{
       
      my $log_record_arg = $log_record_args[$i];
      
      if( $log_record_arg =~ /^#E\(\S+\)#$/ ){

        my $err_label = ${$event_errors_ref}{$log_record_arg};
        if( defined($err_label) ){
          $log_record_arg = "[Error: " . $err_label . "]";
        }
      }

      while( 1 ){
        
        if( $log_record_arg =~ /#L#\S+##/ ){

          my $matched_str = $&;

          my @tmp = split(/,/, $matched_str);          
          $tmp[1] =~ s/#*//g;
                             
          my $label = ${$event_labels_ref}{$matched_str};
          if( defined($label) ){
            $label .= "(" . $tmp[1] . ")";
            $log_record_arg =~ s/$matched_str/$label/g;
          }else{
            $label = "UNKNOWN(" . $tmp[1] . ")";
            $log_record_arg =~ s/$matched_str/unknown/g;
          }
          
        }else{
          last;
        }      
      }
        
      my $arg_mkr = "#ARG" . $i . "#";
      $log_mesg =~ s/$arg_mkr/$log_record_arg/g;
    }      
  }
    
  if( $no_log_tmpl ){
    
    $log_cvt_record->tag("unknown");
    $log_cvt_record->mesg($unknown_log_mesg);

  }else{

    my $sh = "\n";
    my $tb = "\t";
    if( $one_line ){
      $sh = " ";
      $tb = "";
    }
    
    if( !$summary ){
      $log_mesg =~ s/(<label.*">|<\/label>)//g;
    }else{
      my @sms = split(/<\/label>/,$log_mesg,2);
      if( scalar(@sms) < 2 ){
        $log_mesg =~ s/(<label.*">|<\/label>)//g;
      }else{
        $log_mesg = $sms[0];
        $log_mesg =~ s/(<label.*">|<\/label>)//g;
      }
    }
    $log_mesg =~ s/(<br>|<br\/>|<p>|<\/p>)/$sh$tb/g;
    $log_mesg =~ s/(<ul>|<ol>)/$sh/g;
    $log_mesg =~ s/(<\/ul>|<\/ol>)/$sh/g;
    $log_mesg =~ s/<li>/- /g;
    $log_mesg =~ s/<\/li>//g;
    
    $log_cvt_record->mesg($log_mesg);
  }
  
#  print_stdout "parse_log_record: Full record returned.\n";
  return $log_cvt_record;  
}

sub format_log_record {
  
  my ($idx,$log_cvt_record,$record_elm) = @_;
  
  my $res_str;  
  if( defined($log_cvt_record) ){

    my $sh = "\n";
    my $tb = "\t";
    if( $one_line || $summary ){
      $sh = " ";
      $tb = "";
    }
                  
    $res_str = '[' . $idx . '] ';
    $res_str .= $log_cvt_record->timestamp . " ";
    $res_str .= $log_cvt_record->source . " ";
    $res_str .= $log_cvt_record->realm . " ";
    $res_str .= $log_cvt_record->level . " ";
    if( defined($log_cvt_record->mesg) ){
      $res_str .= $log_cvt_record->mesg;
    }else{
      $res_str .= "NO MESG TEMPLATE: $record_elm$sh";          
    }
    if( defined($log_cvt_record->tag) ){
      $res_str .= "$sh$tb" . $log_cvt_record->tag . "(" . $log_cvt_record->id . ") ";          
    }else{
      if( !defined($log_cvt_record->id) ){
        $log_cvt_record->id = 0;
      }
      $res_str .= "$sh$tb" . "UNKNOWN(" . $log_cvt_record->id . ") ";
    }
    
    if( $show_xml ){
      $res_str .= "\n" . $record_elm . "\n";
    }    
                  
  }else{
    
    $res_str = '[' . $idx . '] *Failed to parse log_record(1): ' . $record_elm . '\n';          
  }
                
  return $res_str;
}

sub get_event_template_file {

  my ($file) = @_;
  return get_xml_file('/pub/rhp_event_log.xml',$file,0);
}


sub convert_event_record {
  
  my ($idx,$file,$log_cvt_record,
      $event_sources_ref,$event_levels_ref,$event_errors_ref,$event_labels_ref,$event_mesg_tmpls_ref,
      $str_head,$str_tail) = @_;

  my $p_num = 0;
  my $record_formatted_str = "";

  if( defined($log_cvt_record) && defined($log_cvt_record->mesg) ){

    $record_formatted_str = format_log_record($idx,$log_cvt_record,$log_cvt_record->record_elm);
    
  }else{

    $record_formatted_str = '[' . $idx . '] *Failed to parse log_record: ' . $log_cvt_record->record_elm . '\n';  
  }

  if( defined($str_head) ){
    $record_formatted_str = $str_head . $record_formatted_str;
  }

  if( defined($str_tail) ){
    $record_formatted_str .= $str_tail;
  }

  if( !defined($log_record_match_str) || $record_formatted_str =~ /$log_record_match_str/ ){
    
    if( defined($file) ){
  
      if ( !open( SAVED_FILE, ">> $file" ) ) {
        print_stdout "Can't open $file.\n";
      } else {
        print SAVED_FILE $record_formatted_str;
        close(SAVED_FILE);
      }
  
    }else{
      
      print_stdout $record_formatted_str;
    }
    
    $p_num++;

  }else{
#    print_stdout "convert_event_record NOT stdout: $record_formatted_str\n";
  }    

  return $p_num;
}

sub convert_event_log {
  
  my ($template_xml,$log_xml,$file) = @_;
  
  my @event_sources = ();
  my @event_levels = ();
  my %event_errors = ();
  my %event_labels = ();
  my %event_mesg_tmpls = ();

  parse_event_log_template($template_xml,\@event_sources,\@event_levels,
    \%event_errors,\%event_labels,\%event_mesg_tmpls);
    
  if( $show_xml ){  
    dump_event_log_template(\@event_sources,\@event_levels,\%event_errors,
     \%event_labels,\%event_mesg_tmpls);
  }

  my @log_cvt_records = ();
  
  foreach $EAELM ( $log_xml->getElementsByTagName('rhp_http_bus_record') ) {

    if( EA('action') eq "log_record" ){
  
      my $log_cvt_record = parse_log_record($EAELM,
        \@event_sources,\@event_levels,\%event_errors,\%event_labels,\%event_mesg_tmpls);

      if( defined($log_cvt_record) ){          
        push(@log_cvt_records,$log_cvt_record);
      }
    }
  }

  @log_cvt_records = sort {$a->timestamp cmp $b->timestamp} @log_cvt_records;
  
  my $records_num = scalar(@log_cvt_records);    
  
  my $idx = 0;    
  for( ; $idx < $records_num; $idx++ ){
      
      convert_event_record(($idx + 1),$file,$log_cvt_records[$idx],
        \@event_sources,\@event_levels,\%event_errors,\%event_labels,\%event_mesg_tmpls,
        undef,"\n\n");
  }    
  
  if( $idx == 0 ){
    print_stdout "No log record found.\n";
  }
  
  return;
}

sub get_event_log_file_cb {
    
  my ($bus_session_id, $ctx_ref, $resp) = @_;
  my $ret = 2;

  my $dir_name = undef;
  my $file = undef;
  if( defined($ctx_ref) ){
    $dir_name = ${$ctx_ref}[0];
    $file = ${$ctx_ref}[1];
  } 
  my $close_sess = ${$ctx_ref}[2];
    
  my $parser   = XML::LibXML->new;
  my $resp_doc = $parser->parse_string( $resp->decoded_content );

  if( $show_xml ){
    print_stdout "get_event_log_file_cb: \n" . $resp_doc->toString(1) . "\n";
  }
  
    
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_http_bus_record') ) {

    my $rec_action = EA('action');
#   print_stdout "Rec_action: $rec_action\n";

    if ($rec_action eq "save_event_log_done" ) {

      my $url = EA('url');
      
      my $rhp_saved_log_xml = undef;
      if( defined($file) ){
        $rhp_saved_log_xml = $dir_name . "/rhp_saved_log.xml";
      }
      
      my $log_xml =  get_xml_file($url,$rhp_saved_log_xml,1);
      if( !defined($log_xml) ){

        print_stdout "get_event_log_file failed.\n";
        
      }else{

        my $rhp_event_log_tmpl_xml = undef;
        if( defined($file) ){
          $rhp_event_log_tmpl_xml = $dir_name . '/rhp_event_log.xml';
        }      

        my $template_xml = get_event_template_file($rhp_event_log_tmpl_xml);
        if( !defined($template_xml) ){
  
          print_stdout "get_event_template_file failed.\n";
  
        }else{
          
          if( $close_sess ){

            my $ua = LWP::UserAgent->new();

            bus_close($ua, $bus_session_id);
          }
          
          convert_event_log($template_xml,$log_xml,$file);
        }   
      }

      $ret = 1;
      last;

    }elsif ($rec_action eq "save_event_log_error" ) {

      print_stdout "\nFailed to get event log.\n\n";
      $ret = 1;
      last;
        
    }else{
       
#     print_stdout "get_event_log_file_cb: Unknown action: $rec_action\n";
      $ret = 2;
    }
  }
  
  return $ret;    
}

sub get_event_log_file {

  my ($ua,$bus_session_id,$dir_name,$file,$max_records,$close_sess) = @_;
  my $ret = 1;


  my @attr_names = ("version",  "service",    "action", "limit");
  my @attr_vals = ($rhp_version,"ui_http_vpn","event_log_save",$max_records);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "get_event_log_file: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );


  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "get_event_log_file ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . " or no content.\n";

  }else{

    my @ctx = ($dir_name,$file,$close_sess);

    my $th = bus_read_begin_thread($bus_session_id,\&get_event_log_file_cb,\@ctx);
    $th->join();    
  }
  
  return $ret;
}


sub save_files {

  my ($max_records,$file) = @_;

  if( !defined($file) ){
    print_stdout "-file not specified.\n";
    print_usage("save");
    return;
  }


  if( substr($file,0,1) ne '/' ){

    $file = './' . $file;
  }

  my $dir_name;
  my $pos = rindex($file,'/');
  if( $pos < 0 ){
    $dir_name = '.';
  }else{
    $dir_name = substr($file,0,$pos);
  }

  if( -d $file ){
    print_stdout "-file: The same name directory exists. : $file\n";
    print_usage("save");
    return;
  }
  
  if( !defined($dir_name) || $dir_name eq '/' || ($dir_name ne '.' && !-d $dir_name) ){
    print_stdout "-file: Invalid direcotry path included. : $file\n";
    print_usage("save");
    return;
  }

  my $t = time();
  if( -e $file ){
    if( $dont_overwrite ){
      rename($file,$file . "." . $t . ".old");
    }else{
      unlink($file);      
    }
  }
  
  if( -e $dir_name . '/rhp_saved_log.xml' ){
    if( $dont_overwrite ){
      rename($dir_name . '/rhp_saved_log.xml',$dir_name . '/rhp_saved_log.xml' . "." . $t . ".old");
    }else{
      unlink($dir_name . '/rhp_saved_log.xml');      
    }
  }

  if( -e $dir_name . '/rhp_event_log.xml' ){
    if( $dont_overwrite ){
      rename($dir_name . '/rhp_event_log.xml',$dir_name . '/rhp_event_log.xml' . "." . $t . ".old");
    }else{
      unlink($dir_name . '/rhp_event_log.xml');      
    }
  }
  
  need_admin_password();

  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  get_event_log_file($ua,$bus_session_id,$dir_name,$file,$max_records,0);
  
  bus_close($ua, $bus_session_id);
  return;
}

sub convert_xml2txt {
  
  my($log_xml_file,$formatter_xml_file,$file) = @_;

  if( !defined($log_xml_file) ){
    print_stdout "-log_xml not specified.\n";
    print_usage("xml2txt");
    return;
  }

  if( !defined($formatter_xml_file) ){
    print_stdout "-formatter_xml not specified.\n";
    print_usage("xml2txt");
    return;
  }

  if( !defined($file) ){
    print_stdout "-file not specified.\n";
    print_usage("xml2txt");
    return;
  }


  if( substr($file,0,1) ne '/' ){

    $file = './' . $file;
  }

  if( substr($log_xml_file,0,1) ne '/' ){

    $log_xml_file = './' . $log_xml_file;
  }

  if( substr($formatter_xml_file,0,1) ne '/' ){

    $formatter_xml_file = './' . $formatter_xml_file;
  }

  if( !-e $formatter_xml_file ){
    print_stdout "-formatter_xml: The file doesn't exist. : $formatter_xml_file\n";
    print_usage("xml2txt");
    return;
  }

  if( !-e $log_xml_file ){
    print_stdout "-log_xml: The file doesn't exist. : $log_xml_file\n";
    print_usage("xml2txt");
    return;
  }

  if( -d $file ){
    print_stdout "-file: The same name directory exists. : $file\n";
    print_usage("xml2txt");
    return;
  }
  
  if( -e $file ){
    if( $dont_overwrite ){
      my $t = time();
      rename($file,$file . "." . $t . ".old");
    }else{
      unlink($file);
    }
  }


  my $parser   = XML::LibXML->new;
  my $template_xml = $parser->parse_file( $formatter_xml_file );
  my $log_xml = $parser->parse_file( $log_xml_file );

  convert_event_log($template_xml,$log_xml,$file);

  return;  
}

sub show_logs {

  my ($max_records) = @_;

  need_admin_password();

  open_stdout_pipe();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  get_event_log_file($ua,$bus_session_id,undef,undef,$max_records,1);
  
#  bus_close($ua, $bus_session_id);

  return;
}

sub clear_old_records {

  need_admin_password();

  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open($ua);
  if ( !defined($bus_session_id) || $bus_session_id eq '' ) {
    return;
  }

  my @attr_names = ("version",  "service",    "action");
  my @attr_vals = ($rhp_version,"ui_http_vpn","event_log_reset");

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "clear_old_records: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );


  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "clear_old_records ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }
  
  bus_close($ua, $bus_session_id);
  return;
}


sub tail_debug_log_ctrl {

  my ($ua,$bus_session_id,$opr) = @_;


  my @attr_names = ("version",  "service",    "action", "debug_log");
  my @attr_vals = ($rhp_version,"ui_http_vpn","event_log_control",$opr);

  my $doc = create_bus_req_doc(\@attr_names,\@attr_vals);
  my $req = create_bus_write_req($bus_session_id);

  if( $show_xml ){
    print_stdout "debug_log_ctrl: \n" . $doc->toString(1) . "\n";
  }

  $req->content( $doc->toString(0) );


  my $resp = $ua->request($req);

  if ( !$resp->is_success ) {

    print_stdout "tail_debug_log_ctrl ERROR: /protected/bus/write/$bus_session_id :" . $resp->status_line . "\n";
  }
  
  return;
}

sub tail_logs_cb {
    
  my ($bus_session_id, $cb_ctx_ref, $resp) = @_;
  my $ret = 2;
    
  my $parser   = XML::LibXML->new;
  my $resp_doc = $parser->parse_string( $resp->decoded_content );

  if( $show_xml ){
    print_stdout "tail_logs_cb: \n" . $resp_doc->toString(1) . "\n";
  }

  my @log_cvt_records = ();
    
  foreach $EAELM ( $resp_doc->getElementsByTagName('rhp_http_bus_record') ) {

    if( !defined($tail_logs_cb_template_xml) ){
      
      $tail_logs_cb_template_xml = get_event_template_file(undef);
      if( !defined($tail_logs_cb_template_xml) ){
  
        print_stdout "get_event_template_file failed.\n";
        $ret = 1;
        last;
      }   

      parse_event_log_template($tail_logs_cb_template_xml,\@tail_logs_cb_event_sources,
        \@tail_logs_cb_event_levels,\%tail_logs_cb_event_errors,
        \%tail_logs_cb_event_labels,\%tail_logs_cb_event_mesg_tmpls);
        
      if( $show_xml ){  
        dump_event_log_template(\@tail_logs_cb_event_sources,\@tail_logs_cb_event_levels,
          \%tail_logs_cb_event_errors,\%tail_logs_cb_event_labels,\%tail_logs_cb_event_mesg_tmpls);
      }
    }
    
    my $rec_action = EA('action');

    if( $rec_action eq "log_record" ){

      my $log_cvt_record = parse_log_record($EAELM,
        \@tail_logs_cb_event_sources,\@tail_logs_cb_event_levels,
        \%tail_logs_cb_event_errors,\%tail_logs_cb_event_labels,\%tail_logs_cb_event_mesg_tmpls);
        
      if( defined($log_cvt_record) ){          
        push(@log_cvt_records,$log_cvt_record);
      }else{
#        print_stdout "rec_action: $rec_action No log_cvt_record\n";        
      }

    }else{

      if( $show_xml ){
        print_stdout "rec_action: $rec_action\n$EAELM\n";        
      }
    }
  }

  @log_cvt_records = sort {$a->timestamp cmp $b->timestamp} @log_cvt_records;
  
  my $records_num = scalar(@log_cvt_records);    

#  print_stdout "Record Num: $records_num\n";

  for(my $idx = 0 ; $idx < $records_num; $idx++){
    
    my $p_num = convert_event_record(($tail_logs_cb_idx + 1),undef,$log_cvt_records[$idx],
        \@tail_logs_cb_event_sources,\@tail_logs_cb_event_levels,\%tail_logs_cb_event_errors,
        \%tail_logs_cb_event_labels,\%tail_logs_cb_event_mesg_tmpls,
        undef,undef);

    if( $p_num ){

      if( $show_xml ){
        print_stdout $log_cvt_records[$idx]->record_elm . "\n";
      }
      
      print_stdout "\n";

    }else{
            
#      print_stdout "convert_event_record: not stdout.\n";
    }
    
    $tail_logs_cb_idx++;
  }
  
  return $ret;    
}

sub tail_logs {

  my($debug_log) = @_;


  if( defined($debug_log) && 
      $debug_log ne "enable" && $debug_log ne "disable" ){
    print_stdout "Invalid -debug-log operation specified. : $debug_log\n";
    print_usage("follow");
    exit;
  }

  need_admin_password();
  
  my $ua = LWP::UserAgent->new();

  my $bus_session_id = bus_open( $ua );
  if ( $bus_session_id eq '' ) {
    return;
  }

  if( defined($debug_log) ){
    tail_debug_log_ctrl($ua,$bus_session_id,$debug_log);
  }

  print_stdout "\nTo quit, please enter 'q' and push <ENTER>\n\n";
  sleep(3);


  my $cb_ctx = undef;
  my $th = bus_read_begin_thread($bus_session_id,\&tail_logs_cb,\$cb_ctx);

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

  print_usage($action);
  
}elsif( defined($action) && $action eq 'help' ){
  
  print_usage($ARGV[1]);

}elsif( !defined($action) ){

  print_usage();
  
} elsif ( $action eq 'show' ) {

  show_logs($cmd_opts{max_records});

} elsif ( $action eq 'save' ) {

  save_files($cmd_opts{max_records},$cmd_opts{file});

} elsif ( $action eq 'follow' ) {

  tail_logs($cmd_opts{debug_log});

} elsif ( $action eq 'clear' ) {

  clear_old_records();

} elsif ( $action eq 'xml2txt' ) {

  convert_xml2txt($cmd_opts{log_xml},$cmd_opts{formatter_xml},$cmd_opts{file});

} elsif ( $action eq 'bus-read' ) {

  exec_bus_read();
  
}else{
  
  print_usage();
}

close_stdout_pipe();

exit;

#! /usr/bin/perl

#
# Upgrade conf files for a newer Rockhopper version.
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

use Getopt::Long;

# (Ubuntu 8.x--) Need to import libxml-libxml-perl by package manager.
use XML::LibXML;

use Switch;


my %cmd_opts = ();

GetOptions(
  \%cmd_opts,
  'target=s'
);

my $target = $cmd_opts{target};



my $main_main_xml = "/home/rhpmain/restore/rhpmain/config/main.xml";
my $main_main_xml_org = "/home/rhpmain/restore/rhpmain/config/main.xml.org";
my $syspxy_protected_xml = "/home/rhpmain/restore/rhpprotected/config/protected.xml";
my $syspxy_protected_xml_org = "/home/rhpmain/restore/rhpprotected/config/protected.xml.org";
my $syspxy_auth_xml = "/home/rhpmain/restore/rhpprotected/config/auth.xml";
my $syspxy_auth_xml_org = "/home/rhpmain/restore/rhpprotected/config/auth.xml.org";

if( $target eq "install-overwrite" ){
  $main_main_xml = "/home/rhpmain/config/main.xml";
  $main_main_xml_org = "/home/rhpmain/config/main.xml.org";
  $syspxy_protected_xml = "/home/rhpprotected/config/protected.xml";
  $syspxy_protected_xml_org = "/home/rhpprotected/config/protected.xml.org";
  $syspxy_auth_xml = "/home/rhpprotected/config/auth.xml";
  $syspxy_auth_xml_org = "/home/rhpprotected/config/auth.xml.org";
}


#
#
# main.xml
#
#
if( -e $main_main_xml ){
  
  my $xml_updated = 0;

  my $xml_dom = XML::LibXML->load_xml(location => $main_main_xml);
  if( !defined($xml_dom) ){
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml: Not found.\n";
    exit;
  }
  
  my $xml_root_elm = $xml_dom->documentElement();
  if( !defined($xml_root_elm) ){
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml: No root element.\n";
    exit;
  }
  
  
  my $event_log_convert_elm_found = 0;
  foreach my $evtlog_conv_elm ( $xml_dom->getElementsByTagName('event_log_convert_script') ) {
    $event_log_convert_elm_found = 1;
    last;
  }
  
  if( !$event_log_convert_elm_found ){
  
    #
    # Add event_log_convert_script.
    #
    my $evtlog_conv_elm = $xml_dom->createElement("event_log_convert_script");
    $xml_root_elm->addChild($evtlog_conv_elm);
  
    my $attr = $xml_dom->createAttribute( "script", '/home/rhpmain/script/rhp_event_log_convert' );
    $evtlog_conv_elm->setAttributeNode($attr);
      
    $xml_updated++;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml : Add 'event_log_convert_script' element for event service(xml2txt).\n";

  }else{
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml : A 'event_log_convert_script' element is found.\n";
  }
  
  
  my $now = time();
  foreach my $vpn_realm_elm ( $xml_dom->getElementsByTagName('vpn_realm') ) {
    
    my $created_time_attr = $vpn_realm_elm->getAttribute('created_time');
    if( !defined($created_time_attr) ){
      
      my $created_time = $now;
      my ($sec,$min,$hh,$dd,$mm,$yy,$weak,$yday,$opt) = localtime($created_time);
      
      $yy += 1900;
      $mm++;
      
      if( $mm < 10 ){
        $mm = '0' . $mm;
      }
      if( $dd < 10 ){
        $dd = '0' . $dd;
      }
      if( $hh < 10 ){
        $hh = '0' . $hh;
      }
      if( $min < 10 ){
        $min = '0' . $min;
      }
      if( $sec < 10 ){
        $sec = '0' . $sec;
      }
      
      my $created_localtime = "$yy-$mm-$dd $hh:$min:$sec";
      
      my $attr = $xml_dom->createAttribute( "created_time", $created_time );
      $vpn_realm_elm->setAttributeNode($attr);
      
      $attr = $xml_dom->createAttribute( "created_local_time", $created_localtime );
      $vpn_realm_elm->setAttributeNode($attr);
      
      $xml_updated++;

      print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml : A 'created_time' attribute for a 'vpn_realm' element is added.\n";
    }

    my $updated_time_attr = $vpn_realm_elm->getAttribute('updated_time');
    if( !defined($updated_time_attr) ){
      
      my $updated_time = $now;
      my ($sec,$min,$hh,$dd,$mm,$yy,$weak,$yday,$opt) = localtime($updated_time);
      
      $yy += 1900;
      $mm++;
      
      if( $mm < 10 ){
        $mm = '0' . $mm;
      }
      if( $dd < 10 ){
        $dd = '0' . $dd;
      }
      if( $hh < 10 ){
        $hh = '0' . $hh;
      }
      if( $min < 10 ){
        $min = '0' . $min;
      }
      if( $sec < 10 ){
        $sec = '0' . $sec;
      }
      
      my $updated_localtime = "$yy-$mm-$dd $hh:$min:$sec";
      
      my $attr = $xml_dom->createAttribute( "updated_time", $updated_time );
      $vpn_realm_elm->setAttributeNode($attr);
      
      $attr = $xml_dom->createAttribute( "updated_local_time", $updated_localtime );
      $vpn_realm_elm->setAttributeNode($attr);

      $xml_updated++;

      print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml : A 'updated_time' attribute for a 'vpn_realm' element is added.\n";
    }
  }
    
     
  my $packet_capture_elm_found = 0;
  foreach my $packet_capture_elm ( $xml_dom->getElementsByTagName('packet_capture') ) {
    $packet_capture_elm_found = 1;
    last;
  }
  
  if( !$packet_capture_elm_found ){
  
    #
    # Add packet_capture.
    #
    my $packet_capture_elm = $xml_dom->createElement("packet_capture");
    $xml_root_elm->addChild($packet_capture_elm);
  
    my $attr = $xml_dom->createAttribute( "path", '/home/rhpmain/tmp/rockhopper.pcap' );
    $packet_capture_elm->setAttributeNode($attr);
      
    $xml_updated++;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml : Add 'packet_capture' element for event service(xml2txt).\n";

  }else{
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml : A 'packet_capture' element is found.\n";
  }

  
  if( $xml_updated ){

    rename($main_main_xml,$main_main_xml_org);
    $xml_dom->toFile($main_main_xml,1);
    unlink $main_main_xml_org;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml is replaced.\n";
  }
  
}else{

  print "[ROCKHOPPER:rhp_upgrade_conf.pl] main.xml : Not found(2). $main_main_xml\n";  
}


#
#
# protected.xml
#
#
if( -e $syspxy_protected_xml ){
  
  my $xml_updated = 0;

  my $xml_dom = XML::LibXML->load_xml(location => $syspxy_protected_xml);
  if( !defined($xml_dom) ){
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml: Not found.\n";
    exit;
  }
  
  my $xml_root_elm = $xml_dom->documentElement();
  if( !defined($xml_root_elm) ){
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml: No root element.\n";
    exit;
  }
  
  
  my $qcd_secret_elm_found = 0;
  foreach my $qcd_elm ( $xml_dom->getElementsByTagName('qcd_secret') ) {
    $qcd_secret_elm_found = 1;
    last;
  }
  
  if( !$qcd_secret_elm_found ){
  
    #
    # Add qcd_secret element for IKEv2 QCD(Quick Crash Detection) service.
    #
    my $qcd_elm = $xml_dom->createElement("qcd_secret");
    $xml_root_elm->addChild($qcd_elm);
  
    my $attr = $xml_dom->createAttribute( "path", '/home/rhpprotected/config/qcd_secret' );
    $qcd_elm->setAttributeNode($attr);
      
    $xml_updated++;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml : Add 'qcd_secret' element for IKEv2 QCD service.\n";

  }else{
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml : A 'qcd_secret' element is found.\n";
  }


  my $sess_resume_key_elm_found = 0;
  foreach my $sess_resume_key_elm ( $xml_dom->getElementsByTagName('sess_resume_key') ) {
    $sess_resume_key_elm_found = 1;
    last;
  }
  
  if( !$sess_resume_key_elm_found ){
  
    #
    # Add sess_resume_key element for IKEv2 Session Resumption service.
    #
    my $sess_resume_elm = $xml_dom->createElement("sess_resume_key");
    $xml_root_elm->addChild($sess_resume_elm);
  
    my $attr = $xml_dom->createAttribute( "key_path", '/home/rhpprotected/config/sess_resume_key' );
    $sess_resume_elm->setAttributeNode($attr);

    $attr = $xml_dom->createAttribute( "old_key_path", '/home/rhpprotected/config/sess_resume_key_old' );
    $sess_resume_elm->setAttributeNode($attr);

    $attr = $xml_dom->createAttribute( "revocation_bfltr_path", '/home/rhpprotected/config/sess_resume_rvk_bfltr' );
    $sess_resume_elm->setAttributeNode($attr);

    $attr = $xml_dom->createAttribute( "revocation_old_bfltr_path", '/home/rhpprotected/config/sess_resume_rvk_old_bfltr' );
    $sess_resume_elm->setAttributeNode($attr);
      
    $xml_updated++;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml : Add 'sess_resume_key' element for IKEv2 Session Resumption service.\n";

  }else{
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml : A 'sess_resume_key' element is found.\n";
  }


  my $mng_script_elm_found = 0;
  foreach my $mng_script_elm ( $xml_dom->getElementsByTagName('mng_script') ) {
    $mng_script_elm_found = 1;
    last;
  }
  
  if( !$mng_script_elm_found ){
  
    #
    # Add mng_script element for IKEv2 Session Resumption and QCD services.
    #
    my $mng_script_elm = $xml_dom->createElement("mng_script");
    $xml_root_elm->addChild($mng_script_elm);
  
    my $attr = $xml_dom->createAttribute( "script", '/home/rhpprotected/script/rhp_mng' );
    $mng_script_elm->setAttributeNode($attr);

    $attr = $xml_dom->createAttribute( "dir", '/home/rhpprotected/script/' );
    $mng_script_elm->setAttributeNode($attr);
      
    $xml_updated++;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml : Add 'mng_script' element for IKEv2 Session Resumption and QCD services.\n";

  }else{
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml : A 'mng_script' element is found.\n";
  }
  
  
  if( $xml_updated ){

    rename($syspxy_protected_xml,$syspxy_protected_xml_org);
    $xml_dom->toFile($syspxy_protected_xml,1);
    unlink $syspxy_protected_xml_org;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml is replaced.\n";
  }
  
}else{

  print "[ROCKHOPPER:rhp_upgrade_conf.pl] protected.xml : Not found(2). $syspxy_protected_xml\n";  
}



#
#
# auth.xml
#
#
if( -e $syspxy_auth_xml ){
  
  my $auth_xml_updated = 0;

  my $auth_xml_dom = XML::LibXML->load_xml(location => $syspxy_auth_xml);
  if( !defined($auth_xml_dom) ){
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] auth.xml: Not found.\n";
    exit;
  }
  
  my $auth_xml_root_elm = $auth_xml_dom->documentElement();
  if( !defined($auth_xml_root_elm) ){
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] auth.xml: No root element.\n";
    exit;
  }
  
  
  my $rhp_client_gtk2_perl_user = 0;
  my $rhp_mng_cmd_perl_user = 0;
  foreach my $admin_elm ( $auth_xml_dom->getElementsByTagName('admin') ) {
  
      my $admin_id = $admin_elm->getAttribute('id');
      
      if( defined($admin_id) && $admin_id eq "rhp_client_gtk2_perl" ){
        $rhp_client_gtk2_perl_user = 1;
      }elsif( defined($admin_id) && $admin_id eq "rhp_mng_cmd_perl" ){
        $rhp_mng_cmd_perl_user = 1;
      }
  }
  
  if( !$rhp_client_gtk2_perl_user ){
  
    #
    # Add rhp_client_gtk2_perl for WebMng service. (Web Console)
    #
    my $admin_elm = $auth_xml_dom->createElement("admin");
    $auth_xml_root_elm->addChild($admin_elm);
  
    my $attr = $auth_xml_dom->createAttribute( "id", "rhp_client_gtk2_perl" );
    $admin_elm->setAttributeNode($attr);
  
    $attr = $auth_xml_dom->createAttribute( "prf_method", "hmac-sha1" );
    $admin_elm->setAttributeNode($attr);
  
    $attr = $auth_xml_dom->createAttribute( "hashed_key", "fdxz6CE0M6VPHwGA0mpCfezfCGg=" );
    $admin_elm->setAttributeNode($attr);
  
    $attr = $auth_xml_dom->createAttribute( "vpn_realm", "any" );
    $admin_elm->setAttributeNode($attr);
  
    $attr = $auth_xml_dom->createAttribute( "is_nobody", "enable" );
    $admin_elm->setAttributeNode($attr);
    
    $auth_xml_updated++;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] auth.xml : Add rhp_client_gtk2_perl for WebMng service.\n";

  }else{
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] auth.xml : rhp_client_gtk2_perl is found.\n";
  }
  
  if( !$rhp_mng_cmd_perl_user ){
  
    #
    # Add rhp_mng_cmd_perl for WebMng service. (rockhopper command)
    #
    my $admin_elm = $auth_xml_dom->createElement("admin");
    $auth_xml_root_elm->addChild($admin_elm);
  
    my $attr = $auth_xml_dom->createAttribute( "id", "rhp_mng_cmd_perl" );
    $admin_elm->setAttributeNode($attr);
  
    $attr = $auth_xml_dom->createAttribute( "prf_method", "hmac-sha1" );
    $admin_elm->setAttributeNode($attr);
  
    $attr = $auth_xml_dom->createAttribute( "hashed_key", "Mc5Df5n+pfRhRGScHE54CxBYxoE=" );
    $admin_elm->setAttributeNode($attr);
  
    $attr = $auth_xml_dom->createAttribute( "vpn_realm", "any" );
    $admin_elm->setAttributeNode($attr);
  
    $attr = $auth_xml_dom->createAttribute( "is_nobody", "enable" );
    $admin_elm->setAttributeNode($attr);
    
    $auth_xml_updated++;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] auth.xml : Add rhp_mng_cmd_perl for WebMng service.\n";

  }else{
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] auth.xml : rhp_mng_cmd_perl is found.\n";
  }
  
  if( $auth_xml_updated ){

    rename($syspxy_auth_xml,$syspxy_auth_xml_org);
    $auth_xml_dom->toFile($syspxy_auth_xml,1);
    unlink $syspxy_auth_xml_org;
    
    print "[ROCKHOPPER:rhp_upgrade_conf.pl] auth.xml is replaced.\n";
  }
  
}else{

  print "[ROCKHOPPER:rhp_upgrade_conf.pl] auth.xml : Not found(2). $syspxy_auth_xml\n";  
}
#! /usr/bin/perl

#
#  Copyright (C) 2009-2015 TETSUHARU HANADA <rhpenguine@gmail.com>
#  All rights reserved.
#  
#  You can redistribute and/or modify this software under the 
#  LESSER GPL version 2.1.
#  See also LICENSE.txt and LICENSE_LGPL2.1.txt.
#

#
# Too Simple and ugly Installer for rockhopper. 
#


use strict;

use File::Copy;
use File::Path;

my $verbose = 1;


#
# Add extra gcc -Dxxx manually.
#
#my $added_dbg_flags = "-DRHP_PKT_DBG_IKEV2_BAD_COOKIE_TEST -DRHP_PKT_DBG_IKEV2_BAD_TKT_TEST"; 
#my $added_dbg_flags = "-DRHP_PKT_DBG_IKEV2_RETRANS_TEST -DRHP_PKT_DBG_IKEV2_RETRANS_FRAG_TEST"; 
#my $added_dbg_flags = "-DRHP_SESS_RESUME_DEBUG_1"; 
#my $added_dbg_flags = "-DRHP_DBG_IPV6_AUTOCONF_TEST"; 
#my $added_dbg_flags = "-DRHP_DBG_NHRP_MESG_LOOP_TEST_1"; 
#my $added_dbg_flags = "-DRHP_DBG_NHRP_MESG_LOOP_TEST_2"; 
#my $added_dbg_flags = "-DRHP_DBG_NHRP_TX_REG_REQ_WD"; 
#my $added_dbg_flags = "-DRHP_DBG_V1_DPD_TEST_1"; 
my $added_dbg_flags = undef;


my $centos_label = "centos";
my $ubuntu_label = "ubuntu";

my $root_dir = `pwd`;
print "Current Dir: $root_dir\n";

my $kernel_release = `uname -r`;
chomp($kernel_release);
my $kernel_version = `uname -v`;
chomp($kernel_version);
my $cpu_name = `uname -p`;
chomp($cpu_name);

my @kernel_mjr_ver_tmp = split(/-/,$kernel_release);
my $kernel_major_ver = $kernel_mjr_ver_tmp[0]; 
my $lc_ker_ver = lc($kernel_version);

my $nxtrtn;

my $use_systemd_cfg = 0;
my $systemdctl = undef;
my $systemdcfg_path = undef;

my $lsb = `lsb_release -i`;
chomp($lsb);
my $dist_name = "";

if( $lsb =~ /CentOS/ || $lsb =~ /Fedora/ || 
    $lsb !~ /Distributor ID/ ){ # lsb_release not installed.
  
  if( -e "/etc/redhat-release" ){
    
    $lsb = `cat /etc/redhat-release`;
    chomp($lsb);

  }else{
    
    $lsb = "";
    print "\n/etc/redhat-release NOT found.\n\n";    
  }
  
  if( $lsb =~ /CentOS/ ){

    $dist_name = $centos_label;

    my $centos_ver = $lsb;
    $centos_ver =~ s/.*release\s//;
    $centos_ver =~ s/\s.*//g;
    my @centos_ver2 = split(/\./, $centos_ver); 
  
    if( $centos_ver2[0] >= 7 ){ # Cent OS 7      

      $use_systemd_cfg = 1;
      $systemdctl = "/usr/bin/systemctl";
      $systemdcfg_path = "/usr/lib/systemd/system";

      print "CentOS >= 7 : $centos_ver\n\n";      

    }else{

      print "CentOS < 7 : $centos_ver\n\n";      
    }

  }elsif( $lsb =~ /Fedora/ ){

    $dist_name = $centos_label;

    my $fedora_ver = $lsb;
    $fedora_ver =~ s/\D*//g;
  
    if( $fedora_ver >= 21 ){ # Fedora OS 21

      $use_systemd_cfg = 1;
      $systemdctl = "/usr/bin/systemctl";
      $systemdcfg_path = "/usr/lib/systemd/system";

#      print "Fedora >= 21 : $fedora_ver Len: " . length($fedora_ver) . "\n\n";      
      print "Fedora >= 21 : $fedora_ver\n\n";      

    }else{

      print "Fedora < 21 : $fedora_ver\n\n";      
    }  
  }
  
}elsif( $lsb =~ /Ubuntu/ || $lsb =~ /LinuxMint/ || $lsb =~ /Debian/ ){
  
  $dist_name = $ubuntu_label;

  if( $lsb =~ /Ubuntu/ ){
  
    my $ubuntu_ver =  `lsb_release -r`;
  
    $ubuntu_ver =~ s/.*Release:\s//;
    $ubuntu_ver =~ s/\s.*//g;
    my @ubuntu_ver2 = split(/\./, $ubuntu_ver); 
    
    if( $ubuntu_ver2[0] >= 15 ){ # Ubuntu 15.04

      $use_systemd_cfg = 1;
      $systemdctl = "/bin/systemctl";
      $systemdcfg_path = "/lib/systemd/system";

      print "Ubuntu >= 15 : $ubuntu_ver\n\n";      

    }else{
      
      print "Ubuntu < 15 : $ubuntu_ver\n\n";      
    }  

  }elsif( $lsb =~ /Debian/ ){
    
    my $debian_ver =  `lsb_release -r`;
  
    $debian_ver =~ s/.*Release:\s//;
    $debian_ver =~ s/\s.*//g;
    my @debian_ver2 = split(/\./, $debian_ver); 
    
    if( $debian_ver2[0] >= 8 ){ # Debian 8.0

      $use_systemd_cfg = 1;
      $systemdctl = "/bin/systemctl";
      $systemdcfg_path = "/lib/systemd/system";

      print "Debian >= 8 : $debian_ver\n\n";      

    }else{
      
      print "Debian < 8 : $debian_ver\n\n";      
    }  
  }
}




my $mv        = "/bin/mv";
my $cp        = "/bin/cp";
my $chown     = "/bin/chown";
my $chmod     = "/bin/chmod";
my $make      = "/usr/bin/make";
my $gcc       = "/usr/bin/gcc";
my $ip_cmd     = "/bin/ip";
my $ip_cmd2    = "/sbin/ip";
my $iptables  = "/sbin/iptables";
my $ip6tables  = "/sbin/ip6tables";
my $setcap    = "/sbin/setcap";
my $setcap2   = "/usr/sbin/setcap";
my $brctl     = "/usr/sbin/brctl";
my $brctl2    = "/sbin/brctl";

my $usrlib_dir = "/usr/lib/";
if( $dist_name eq $centos_label && $cpu_name eq 'x86_64' ){
  $usrlib_dir = "/usr/lib64/";
}


my $action = $ARGV[0];
my $action2 = "";

if( $action ne 'install' && $action ne 'install_dbg' && $action ne 'uninstall'){
  
  print "Unknown action: $action\n";
  
  print "(Usage)\n";
  print " % ./install_uninstall.pl install\n\n";
  print " % ./install_uninstall.pl install_dbg\n";
  print " % ./install_uninstall.pl install_dbg memory\n\n";
  print " % ./install_uninstall.pl uninstall\n\n";
  
  exit;
}


sub check_installed_pkg {

  my($pkgname,$pkgdistname) = @_;
  my $ret;
  
#  print "check_installed_pkg($pkgname,$pkgdistname)\n";
  
  if( !$pkgdistname ){
    
    $pkgdistname = $dist_name;

  }else{
    
    if( $pkgdistname ne $dist_name ){
#      print "($pkgdistname:$dist_name) The package($pkgname) name is not for $pkgdistname.\n";
      return 0;
    }
  }
  
  if( $pkgdistname eq $ubuntu_label ){
    
    $ret = system("dpkg -l $pkgname > /dev/null");    
    if( !$ret ){

      my @dpkgrs = `dpkg -l $pkgname`;
      foreach my $dpkgrs_line (@dpkgrs){
         
        if( $dpkgrs_line =~ /$pkgname/ ){
    
          $dpkgrs_line =~ s/\s*$pkgname.*\s*//;
    
          if( $dpkgrs_line eq "ii" ){
#           print "($pkgdistname) dpkg -l $pkgname OK! The package found.\n";
            return 1;
          }else{
            print "[Exec dpkg -l $pkgname] Desired/Status is \'$dpkgrs_line\'.\n";
          }          
        }   
      }
    }
  
  }elsif( $pkgdistname eq $centos_label ){
    
    $ret = system("yum list installed $pkgname > /dev/null");    
    if( !$ret ){
#      print "($pkgdistname) yum list installed $pkgname OK! The package found.\n";
      return 1;
    }
  }

  print "$pkgname package NOT found.\n";
  return 0;  
}

# [FIXME] Ugly temp code!!! 
sub check_dependencies { 

  my($recur) = @_;
  my $ret = 0;
  my @packages = ();
  my @packages2 = ();
  my $idx = 0;
  my $idx2 = 0;
  my $optpkg = 0;

  print "\n\n";

  if( -e "/dev/net/tun" ){

    print "Universal TUN/TAP device found.\n";

  }else{
    
    if( -e "/lib/modules/$kernel_release/kernel/drivers/net/tun.ko" ){

#     print "/lib/modules/$kernel_release/kernel/drivers/net/tun.ko\n";
#     print "found.\n";
      print "\n";
      print "[ERROR] Please activate Universal TUN/TAP device driver\n";
      print "        (tun.ko).\n";
      print "(e.g.) To activate TUN/TAP device, please add line 'tun'\n";
      print "       to /etc/modules and restart system, if needed.\n"

    }else{
      
      print "[ERROR] Please install Universal TUN/TAP device driver\n";
      print "(tun.ko).\n"; 
    }

    $ret = -1;    
  }


  if( (check_installed_pkg("gcc",undef) && check_installed_pkg("make",undef)) ){  # || 
#      (-e $gcc && -e $make) ){
    
    print "gcc/make found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "build-essential";
#    $packages2[$idx2++] = "make gcc kernel-devel";
    $packages2[$idx2++] = "make gcc";
  }


  if( check_installed_pkg("iproute",undef) ||
      check_installed_pkg("iproute2",undef) ){  # ||
#      -e $ip_cmd || -e $ip_cmd2 ){

    print "ip command (iproute) found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "iproute2";
    $packages2[$idx2++] = "iproute";
  }
  
  if( check_installed_pkg("libcap2",$ubuntu_label) ||
      check_installed_pkg("libcap",$centos_label) ){ # ||
#      -e '/lib/libcap.so.1' || -e '/lib/libcap.so.2' || 
#      -e '/lib/i386-linux-gnu/libcap.so.2' || -e '/lib/x86_64-linux-gnu/libcap.so.2' ||
#      -e '/lib64/libcap.so.2'  ){
    
    print "libcap.so.? found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "libcap2";
    $packages2[$idx2++] = "libcap";
  }

  if( check_installed_pkg("libcap2-bin",$ubuntu_label) ||
      check_installed_pkg("libcap",$centos_label) ){ # ||
#      -e $setcap || -e $setcap2 ){

    print "setcap found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "libcap2-bin";
    $packages2[$idx2++] = "libcap";
  }
  
  if( (check_installed_pkg("libwww-perl",$ubuntu_label) && check_installed_pkg("libxml-libxml-perl",$ubuntu_label)) ||
      (check_installed_pkg("perl-libwww-perl",$centos_label) && check_installed_pkg("perl-XML-LibXML",$centos_label)) ){ # ||
#      -e "$usrlib_dir/perl5/XML/LibXML" ||
#      -e "$usrlib_dir/perl5/vendor_perl/XML/LibXML" ){

    print "Perl XML::LibXML library found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "libwww-perl";
    $packages[$idx++] = "libxml-libxml-perl";
    $packages2[$idx2++] = "perl-libwww-perl";
    $packages2[$idx2++] = "perl-XML-LibXML";
  }

  if( (check_installed_pkg("libjson-perl",$ubuntu_label)) ||
      (check_installed_pkg("perl-JSON",$centos_label)) ){

    print "Perl JSON library found.\n";

  }else{

#
# Web console internally uses rockhopper_log to convert log into a text file and
# so this lib is installed by default but $optpkg is still incremented. 
# (i.e. Not critical lib.)
#

#    if( !$recur ){
#      print "\n";
#      print "[NOTICE] If you want to use a command-line log tool(rockhopper_log),\n";
#      print "         it needs a Perl JSON package.\n";
#     print "         Do you want to install the package by this installer script?";    
#      print "[y/N]\n";
#      my $ans = <STDIN>;
#      if( $ans eq "y\n" || $ans eq "Y\n"){
  
        $packages[$idx++] = "libjson-perl";
        $packages2[$idx2++] = "perl-JSON";
        $optpkg++;
        
#      }else{ 
#        print "\n";
#        print "You can install the additonal package manually.\n";
#        print "  - Open a terminal window.\n";
#        print "  - Install it by apt-get or yum.\n";
#        print "    (e.g.) sudo apt-get install libjson-perl\n";  
#        print "           sudo yum install perl-JSON\n";  
#        print "\nPush <Enter>\n\n";
  
#        my $nxtrtn = <STDIN>;
#      }
#    }
  }

  if( check_installed_pkg("libswitch-perl",$ubuntu_label) ||
      check_installed_pkg("perl-Switch",$centos_label) ){  # ||
#      -e "/usr/share/perl5/Switch.pm" ||
#      -e "/usr/share/perl5/vendor_perl/Switch.pm" ){

    print "Switch statement module for Perl found.\n";

  }else{

    $packages[$idx++] = "libswitch-perl";
    $packages2[$idx2++] = "perl-Switch";
  }
  
  if( check_installed_pkg("libxml2-dev",$ubuntu_label) ||
      check_installed_pkg("libxml2-devel",$centos_label) ){  # ||
#      -e "/usr/include/libxml2" ){

    print "libxml2-dev found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "libxml2-dev";
    $packages2[$idx2++] = "libxml2-devel";
  }

  if( check_installed_pkg("libssl-dev",$ubuntu_label) ||
      check_installed_pkg("openssl-devel",$centos_label) ){ # ||
#      -e "/usr/include/openssl" ){

    print "libssl-dev(OpenSSL) found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "libssl-dev";
    $packages2[$idx2++] = "openssl-devel";
  }
  
  if( check_installed_pkg("libcap-dev",$ubuntu_label) ||
      check_installed_pkg("libcap-devel",$centos_label) ){ # ||
#      -e "/usr/include/sys/capability.h" ){

    print "libcap-dev(libcap1 or 2) found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "libcap-dev";
    $packages2[$idx2++] = "libcap-devel";
  }

  if( check_installed_pkg("libsqlite3-dev",$ubuntu_label) ||
      check_installed_pkg("sqlite-devel",$centos_label) ){ # ||
#      -e "/usr/include/sqlite3.h" ){

    print "libsqlite3-dev found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "libsqlite3-dev";
    $packages2[$idx2++] = "sqlite-devel";
  }
  
  if( check_installed_pkg("libpcap-dev",$ubuntu_label) ||
      check_installed_pkg("libpcap-devel",$centos_label) ){  # ||
#      -e "/usr/include/pcap" ){

    print "libpcap-dev found.\n";

  }else{

    $ret = -1;    
    $packages[$idx++] = "libpcap-dev";
    $packages2[$idx2++] = "libpcap-devel";
  }
  
  if( check_installed_pkg("iptables",undef) ){  # ||
#      -e $iptables ){

    print "iptables found.\n";

  }else{

    $packages[$idx++] = "iptables";
    $packages2[$idx2++] = "iptables";
  }

  if( -e $ip6tables ){

    print "ip6tables found.\n";

  }else{

    print "[NOTICE] If you configure VPN for IPv6, please\n";
    print "         install ip6tables.\n";
    
    print "\nPush <Enter>\n";
    $nxtrtn = <STDIN>;
  }

  if( check_installed_pkg("bridge-utils",undef) ){ # ||
#      -e $brctl || -e $brctl2 ){

    print "brctl found.\n";

  }else{

    if( !$recur ){
      
      print "\n";
      print "[NOTICE] If you want to configure bridge, it needs a bridge-utils \n";
      print "         package(bridge-utils).\n";
      print "         Do you want to install the package by this installer script?\n"; 
      print "[y/N]\n";
    
      my $ans = <STDIN>;
      if( $ans eq "y\n" || $ans eq "Y\n"){
  
        $packages[$idx++] = "bridge-utils";
        $packages2[$idx2++] = "bridge-utils";
        $optpkg++;
  
      }else{
  
        print "\n";
        print "You can install the additonal package manually.\n";
        print "  - Open a terminal window.\n";
        print "  - Install it by apt-get or yum.\n";
        print "    (e.g.) sudo apt-get install bridge-utils\n";  
        print "           sudo yum install bridge-utils\n";  
        print "\nPush <Enter>\n\n";
  
        my $nxtrtn = <STDIN>;
      }
    }
  }


  if( !$recur && ($ret || $optpkg) && ($idx > 0 || $idx2 > 0) ){
    
    print "Required additional packages were not found.\n";    
    if( $dist_name eq $ubuntu_label ){

      foreach my $pkgname (@packages){

        print "- $pkgname\n";
      }
         
    }elsif( $dist_name eq $centos_label ){

      foreach my $pkgname (@packages2){

        print "- $pkgname\n";
      }
    }
  
    print "\n";
    print "Do you want to try installation of these packages now?\n";
    print "Installation process will be executed by 'apt-get' or\n";
    print "'yum' command.\n";
    print "[Y/n]\n";
  
    my $ans = <STDIN>;
    if( $ans eq "\n" || $ans eq "y\n" || $ans eq "Y\n"){
  
      if( $dist_name eq $ubuntu_label ){

        foreach my $pkgname (@packages){

          print "Exec \"apt-get install $pkgname\"\n";
          system("apt-get install $pkgname");
        }
         
      }elsif( $dist_name eq $centos_label ){

        foreach my $pkgname (@packages2){

          print "Exec \"yum install $pkgname\"\n";
          system("yum install $pkgname");
        }
      }
  
      $ret = check_dependencies(1);      
    }
  }
    
  return $ret;
}

sub build_rhptrace_module {

  my $rhptrace_module = "./rhptrace/module";

  if( ! chdir($rhptrace_module) ){
    print "[ERROR] Fail to cd to $rhptrace_module.\n";
    exit;
  }
  
  if( ($kernel_major_ver cmp "2.6.37") < 0  ){

    print "Kernel version is older than 2.6.37.\n";
    print "-DRHP_OBSOLETE_IOCTL and -DRHP_OBSOLETE_MUTEX flags are used to build.\n";    
    sleep(2);

    system("$mv ./Makefile ./Makefile.org");
    system("$cp ./Makefile.to.2.6.36 ./Makefile");
  }

  if( -e "/lib/modules/$kernel_release/build/include" ){

    print "Kernel headers' dir(/lib/modules/$kernel_release/build) found.\n";    
    sleep(2);

  }else{

    print "Kernel headers' dir(/lib/modules/$kernel_release/build) NOT found.\n";    
          
kdir_again:        
    print "\nPlease specify a dir where kernel headers are located \nand push <Enter>.\n\n";      
    print "(ex) /usr/src/kernels/<kernel-release> or\n /lib/modules/<kernel-release>/build \n";      
    my $kdir_path = <STDIN>;
  
    $kdir_path =~ s/\s//g;
  
    if( -e $kdir_path ){
      print "Kernel headers' dir($kdir_path) found.\n";    
      sleep(2);
    }else{
      print "Kernel headers' dir($kdir_path) NOT found.\n";    
      goto kdir_again;
    }
      
    open(FILE1,"./Makefile");
    open(FILE2,"> ./Makefile.kdir_mod");
  
    my $s;
    while( $s = <FILE1> ){
  
      if( $s =~ /\s*KDIR\s*=/ ){
        $s = "KDIR = $kdir_path\n";
      }

      print FILE2 $s;
    }
  
    close(FILE2);
    close(FILE1);
  
    system("$mv ./Makefile ./Makefile.org2");
    system("$mv ./Makefile.kdir_mod ./Makefile");
  }
  
  
  system("$make clean -f ./Makefile");
  
  if( system("$make -f ./Makefile") ){
    print "[ERROR] Fail to build $rhptrace_module.\n";
    exit;
  }
  
  if( !chdir("../..") ){
    print "[ERROR] Fail to cd to $root_dir.\n";
    exit;
  }
  
  return;
}

sub build_rhptrace_lib {

  my $rhptrace_lib = "./rhptrace/lib";

  if( ! chdir($rhptrace_lib) ){
    print "[ERROR] Fail to cd to $rhptrace_lib.\n";
    exit;
  }
  
  system("$make clean -f ./Makefile");
  
  if( system("$make all -f Makefile") ){
    print "[ERROR] Fail to build $rhptrace_lib.\n";
    exit;
  }
  
  if( ! chdir("../..") ){
    print "[ERROR] Fail to cd to $root_dir.\n";
    exit;
  }
  
  return;
}

sub build_rhptrace_tools {

  my $rhptrace_tool = "./rhptrace/tool";

  if( ! chdir($rhptrace_tool) ){
    print "[ERROR] Fail to cd to $rhptrace_tool.\n";
    exit;
  }
  
  system("$make clean -f ./Makefile");
  
  if( system("$make all -f Makefile") ){
    print "[ERROR] Fail to build $rhptrace_tool.\n";
    exit;
  }
  
  if( ! chdir("../..") ){
    print "[ERROR] Fail to cd to $root_dir.\n";
    exit;
  }
  
  return;
}

sub build_app {

  my($path) = @_;
  
  if( ! chdir($path) ){
    print "[ERROR] Fail to cd to $path.\n";
    exit;
  }
  
  my $bld_err_log =  "2>> ./build_mesg.txt";
  if( $verbose ){
    $bld_err_log = "";
  }
  
  system("$make clean -f ./Makefile $bld_err_log");
  
  if( system("$make all -f Makefile 2>> ./build_mesg.txt $bld_err_log") ){
    print "[ERROR] Fail to build $path.\n";
    exit;
  }
  
  if( ! chdir("../../..") ){
    print "[ERROR] Fail to cd to $root_dir.\n";
    exit;
  }
  
  return;
}

my $librhpcert = "./rockhopper/librhpcert_openssl/build";
my $librhpcrypto = "./rockhopper/librhpcrypto_openssl/build";
my $librhpesp_def = "./rockhopper/librhpesp_def/build";
my $librhpeapa_def = "./rockhopper/librhpeapa_def/build";
my $librhpeapa_def_wpa_supplicant = "./rockhopper/librhpeapa_def/build/wpa_supplicant";
my $librhpeaps_def = "./rockhopper/librhpeaps_def/build";
my $librhpeaps_def_wpa_supplicant = "./rockhopper/librhpeaps_def/build/wpa_supplicant";
my $librhplog_def = "./rockhopper/librhplog_def/build";
my $librhpbfltr = "./rockhopper/librhpbfltr/build";
my $librhpradius_def = "./rockhopper/librhpradius_def/build";
my $librhppcap_def = "./rockhopper/librhppcap_def/build";
my $app = "./rockhopper/app/build";


sub build_librhpcert_openssl {
  build_app($librhpcert);
  return;
}

sub build_librhpcrypto_openssl {
  build_app($librhpcrypto);
  return;
}

sub build_librhpesp_def {
  build_app($librhpesp_def);
  return;
}

sub build_librhpeapa_def {
  build_app($librhpeapa_def);
  return;
}

sub build_librhpeaps_def {
  build_app($librhpeaps_def);
  return;
}

sub build_librhplog_def {
  build_app($librhplog_def);
  return;
}

sub build_librhpbfltr {
  build_app($librhpbfltr);
  return;
}

sub build_librhpradius_def {
  build_app($librhpradius_def);
  return;
}

sub build_librhppcap_def {
  build_app($librhppcap_def);
  return;
}



sub build_rockhopper {
  build_app($app);
  return;
}

sub build_tuntap_tool {
  my $tuntap_tool = "./rockhopper/tuntap_tool/build";
  build_app($tuntap_tool);
  return;
}

sub build_tuntap_cfg {
  my $tuntap_cfg = "./rockhopper/tuntap_cfg/build";
  build_app($tuntap_cfg);
  return;
}

sub build_log_tool {
  my $log_tool = "./rockhopper/log_tool/build";
  build_app($log_tool);
  return;
}

sub rhp_addgroup {

  my($name,$passwd,$gid,$members) = getgrnam("rhpenguin");
  
  if( !$name ){

    if( $dist_name eq $ubuntu_label ){

  	   if( system("/usr/sbin/addgroup rhpenguin") ){
    	   print "[ERROR] Fail to add new group \"rhpenguin\".\n";
        return -1;
       }

    }elsif( $dist_name eq $centos_label ){
      
      if( system("/usr/sbin/groupadd rhpenguin") ){
        print "[ERROR] Fail to add new group \"rhpenguin\".\n";
        return -1;
      }

    }else{
      return -1;
    }
  }  
  return 0;  
}

sub rhp_adduser {

  my($new_username) = @_;
  
  my($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $hdir, $shell) = getpwnam($new_username); 

  if( !$name ){  

    if( $dist_name eq $ubuntu_label ){

      if( system("/usr/sbin/adduser --system --ingroup rhpenguin $new_username") ){
        print "[ERROR] Fail to add new user \"$new_username\".\n";
        return -1;
      }

    }elsif( $dist_name eq $centos_label ){

      if( system("/usr/sbin/useradd -m -s /sbin/nologin -g rhpenguin $new_username") ){
        print "[ERROR] Fail to add new user \"$new_username\".\n";
        return -1;
      }
      
    }else{
      return -1;
    }
  }  
  
  return 0;  
}

sub copy_and_setup {
  
  my($from,$to,$mode,$uid,$gid) = @_;  

  print "copying $from to $to, chmod $to to $mode and chown $to to $uid:$gid ... ";  

  if( -d $from ){
    print "Failed.\n[ERROR] $from is directory. Can't copy the file.\n";
    return -1;
  }

  if( -d $to ){
    print "Failed.\n[ERROR] $to is directory. Can't copy the file.\n";
    return -1;
  }

  if( $to ){
    copy($from,$to);
  }else{
    $to = $from;    
  }
  
  if( defined($uid) && defined($gid) ){

    if( chown($uid,$gid,$to) < 1 ){
      print "Failed.\n[ERROR] Fail to chown $to.\n";
      return -1;
    }
  }
  
  if( defined($mode) ){
    
    if( chmod(oct($mode),$to) != 1 ){
      print "Failed.\n[ERROR] Fail to chmod $to.\n";
      return -1;
    }
  }
  
  print "Done.\n";  

  return 0;
}

sub setup_rhpmain_dirs {
  
  my($main_uid,$main_gid,$main_hdir) = @_;  

  if( chmod(0770,$main_hdir) != 1 ){
    print "[ERROR] Fail to chmod users' directory.\n";
    return -1;
  }

  if( ! -e "$main_hdir/config" ){

    if( ! mkdir("$main_hdir/config",0700) ){
      print "[ERROR] Fail to mkdir $main_hdir/config.\n";
      return -1;
    }
  }
  
  if( chown($main_uid,$main_gid,"$main_hdir/config") < 1 ){
    print "[ERROR] Fail to chown $main_hdir/config.\n";
    return -1;
  }


  if( ! -e "$main_hdir/www" ){

    if( ! mkdir("$main_hdir/www",0770) ){
      print "[ERROR] Fail to mkdir $main_hdir/www.\n";
      return -1;
    }

    if( ! mkdir("$main_hdir/www/tmp",0770) ){
      print "[ERROR] Fail to mkdir $main_hdir/www/tmp.\n";
      return -1;
    }
    
    system("$chmod 2770 $main_hdir/www/tmp");
  }
  
  if( chown($main_uid,$main_gid,"$main_hdir/www") < 1 ){
    print "[ERROR] Fail to chown $main_hdir/www.\n";
    return -1;
  }

  if( chown($main_uid,$main_gid,"$main_hdir/www/tmp") < 1 ){
    print "[ERROR] Fail to chown $main_hdir/www/tmp.\n";
    return -1;
  }


  if( ! -e "$main_hdir/log" ){

    if( ! mkdir("$main_hdir/log",0700) ){
      print "[ERROR] Fail to mkdir $main_hdir/log.\n";
      return -1;
    }
  }
  
  if( chown($main_uid,$main_gid,"$main_hdir/log") < 1 ){
    print "[ERROR] Fail to chown $main_hdir/log.\n";
    return -1;
  }


  if( ! -e "$main_hdir/script" ){

    if( ! mkdir("$main_hdir/script",0700) ){
      print "[ERROR] Fail to mkdir $main_hdir/script.\n";
      return -1;
    }
  }
  
  if( chown($main_uid,$main_gid,"$main_hdir/script") < 1 ){
    print "[ERROR] Fail to chown $main_hdir/script.\n";
    return -1;
  }


  if( ! -e "$main_hdir/restore" ){

    if( ! mkdir("$main_hdir/restore",0700) ){
      print "[ERROR] Fail to mkdir $main_hdir/restore.\n";
      return -1;
    }
  }

  if( chown($main_uid,$main_gid,"$main_hdir/restore") < 1 ){
    print "[ERROR] Fail to chown $main_hdir/restore.\n";
    return -1;
  }


  if( ! -e "$main_hdir/tmp" ){

    if( ! mkdir("$main_hdir/tmp",0700) ){
      print "[ERROR] Fail to mkdir $main_hdir/tmp.\n";
      return -1;
    }
  }

  if( chown($main_uid,$main_gid,"$main_hdir/tmp") < 1 ){
    print "[ERROR] Fail to chown $main_hdir/tmp.\n";
    return -1;
  }


  if( ! -e "$main_hdir/certs" ){

    if( ! mkdir("$main_hdir/certs",0770) ){
      print "[ERROR] Fail to mkdir $main_hdir/certs.\n";
      return -1;
    }
  }
  
  if( chown($main_uid,$main_gid,"$main_hdir/certs") < 1 ){
    print "[ERROR] Fail to chown $main_hdir/certs.\n";
    return -1;
  }


  print "chmod $main_hdir to 0750, mkdir $main_hdir/config, chmod it to 0700 and chown it to $main_uid:$main_gid\n";  

  return 0;
}

sub setup_rhpprotected_dirs {

  my($protected_uid,$protected_gid,$protected_hdir) = @_;  
  
  if( chmod(0700,$protected_hdir) != 1 ){
    print "[ERROR] Fail to chmod users' directory.\n";
    return -1;
  }

  if( ! -e "$protected_hdir/config" ){

    if( ! mkdir("$protected_hdir/config",0700) ){
      print "[ERROR] Fail to mkdir $protected_hdir/config.\n";
      return -1;
    }
  }
  
  if( chown($protected_uid,$protected_gid,"$protected_hdir/config") < 1 ){
    print "[ERROR] Fail to chown $protected_hdir/config.\n";
    return -1;
  }

  if( ! -e "$protected_hdir/certs" ){

    if( ! mkdir("$protected_hdir/certs",0700) ){
      print "[ERROR] Fail to mkdir $protected_hdir/certs.\n";
      return -1;
    }
  }
  
  if( chown($protected_uid,$protected_gid,"$protected_hdir/certs") < 1 ){
    print "[ERROR] Fail to chown $protected_hdir/certs.\n";
    return -1;
  }
  
  if( ! -e "$protected_hdir/script" ){

    if( ! mkdir("$protected_hdir/script",0700) ){
      print "[ERROR] Fail to mkdir $protected_hdir/script.\n";
      return -1;
    }
  }
  
  if( chown($protected_uid,$protected_gid,"$protected_hdir/script") < 1 ){
    print "[ERROR] Fail to chown $protected_hdir/script.\n";
    return -1;
  }

  if( ! -e "$protected_hdir/rhptrace" ){

    if( ! mkdir("$protected_hdir/rhptrace",0755) ){
      print "[ERROR] Fail to mkdir $protected_hdir/rhptrace.\n";
      return -1;
    }
  }
  
  if( chown($protected_uid,$protected_gid,"$protected_hdir/rhptrace") < 1 ){
    print "[ERROR] Fail to chown $protected_hdir/rhptrace.\n";
    return -1;
  }

  if( ! -e "$protected_hdir/restore" ){

    if( ! mkdir("$protected_hdir/restore",0700) ){
      print "[ERROR] Fail to mkdir $protected_hdir/restore.\n";
      return -1;
    }
  }

  if( chown($protected_uid,$protected_gid,"$protected_hdir/restore") < 1 ){
    print "[ERROR] Fail to chown $protected_hdir/restore.\n";
    return -1;
  }

  if( ! -e "$protected_hdir/tmp" ){

    if( ! mkdir("$protected_hdir/tmp",0700) ){
      print "[ERROR] Fail to mkdir $protected_hdir/tmp.\n";
      return -1;
    }
  }

  if( chown($protected_uid,$protected_gid,"$protected_hdir/tmp") < 1 ){
    print "[ERROR] Fail to chown $protected_hdir/tmp.\n";
    return -1;
  }

  print "chmod $protected_hdir to 0700, mkdir $protected_hdir/config,$protected_hdir/certs, $protected_hdir/script, and chmod them to 0700 and chown them to $protected_uid:$protected_gid.\n";  

  return 0;
}


sub gen_dbg_init_d {

  my($orgfile, $newfile) = @_;

  open( FILE1, "$orgfile" );
  open( FILE2, "> $newfile" );
  
  my $s;
  while( $s = <FILE1> ){
  
    if( $s =~ /RHPTRACE=0/ ){
      $s =~ s/RHPTRACE=0/RHPTRACE=1/;
    }
    print FILE2 $s;
  }
  
  close(FILE2);
  close(FILE1);
}

sub setup_users_and_files {

  my($no_config) = @_;

  if( rhp_addgroup() ){
    return -1;    
  }
  print "add new group \"rhpenguin\".\n";

  if( rhp_adduser("rhpmain") ){
    return -1;
  }
  print "add new user \"rhpmain\".\n";
  
  if( rhp_adduser("rhpprotected") ){
    return -1;
  }
  print "add new user \"rhpprotected\".\n";

  my($main_name, $main_passwd, $main_uid, $main_gid, $main_quota, $main_comment, $main_gcos, $main_hdir, $main_shell) = getpwnam("rhpmain"); 
  my($protected_name, $protected_passwd, $protected_uid, $protected_gid, $protected_quota, $protected_comment, $protected_gcos, $protected_hdir, $protected_shell) = getpwnam("rhpprotected"); 

  if( !$main_uid || !$main_gid || !$main_hdir ){
    print "[ERROR] Fail to get user info \"rhpmain\".\n";
    return -1;
  }

  if( !$protected_uid || !$protected_gid || !$protected_hdir ){
    print "[ERROR] Fail to get user info \"rhpprotected\".\n";
    return -1;
  }

  print "rhpmain: uid: $main_uid, gid: $main_gid, homedir: $main_hdir\n";
  print "rhpprotected: uid: $protected_uid, gid: $protected_gid, homedir: $protected_hdir\n";


  if( setup_rhpmain_dirs($main_uid,$main_gid,$main_hdir) ){
    return -1;
  }

  if( setup_rhpprotected_dirs($protected_uid,$protected_gid,$protected_hdir) ){
    return -1;
  }

  if( $action eq 'install_dbg' ){

    if( copy_and_setup("./rhptrace/rhp_trace_load_pkg","$protected_hdir/rhptrace/rhp_trace_load","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }
  
    if( copy_and_setup("./rhptrace/module/rhp_trace.ko","$protected_hdir/rhptrace/rhp_trace.ko","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }
  
    if( copy_and_setup("./rhptrace/tool/rhp_trace_helper","$protected_hdir/rhptrace/rhp_trace_helper","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }
  
    if( copy_and_setup("./rhptrace/tool/rhp_trace_start_stop","$protected_hdir/rhptrace/rhp_trace_start_stop","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }
  }

  if( copy_and_setup("./rhptrace/tool/rhp_trace","/usr/local/sbin/rhp_trace","0755",0,0) ){
    return -1;    
  }
  
  if( copy_and_setup("./rhptrace/lib/librhptrace.so","$usrlib_dir/librhptrace.so","0644",0,0) ){
    return -1;    
  }
  
  
  {
    if( copy_and_setup("./rockhopper/librhpbfltr/build/librhpbfltr.so","$usrlib_dir/librhpbfltr.so","0644",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/librhplog_def/build/librhplog.so","$usrlib_dir/librhplog.so","0644",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/librhpcert_openssl/build/librhpcert.so","$usrlib_dir/librhpcert.so","0644",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/librhpcrypto_openssl/build/librhpcrypto.so","$usrlib_dir/librhpcrypto.so","0644",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/librhpesp_def/build/librhpesp.so","$usrlib_dir/librhpesp.so","0644",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/librhpradius_def/build/librhpradius.so","$usrlib_dir/librhpradius.so","0644",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/librhppcap_def/build/librhppcap.so","$usrlib_dir/librhppcap.so","0644",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/librhpeapa_def/build/librhpeapa.so","$usrlib_dir/librhpeapa.so","0644",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/librhpeaps_def/build/librhpeaps.so","$usrlib_dir/librhpeaps.so","0644",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/app/build/rockhopperd","/usr/sbin/rockhopperd","0700",0,0) ){
      return -1;    
    }

    if( -e "/usr/local/sbin/rockhopper.pl" ){
      unlink "/usr/local/sbin/rockhopper.pl";
    }
    if( copy_and_setup("./rockhopper/mng_cmd_tools/rockhopper.pl","/usr/local/sbin/rockhopper","0755",0,0) ){
      return -1;    
    }

    if( -e "/usr/local/sbin/rockhopper_log.pl"){
      unlink "/usr/local/sbin/rockhopper_log.pl";
    }
    if( copy_and_setup("./rockhopper/mng_cmd_tools/rockhopper_log.pl","/usr/local/sbin/rockhopper_log","0755",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/tuntap_tool/build/rhp_tuntap_tool","/usr/local/sbin/rhp_tuntap_tool","0700",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/tuntap_tool/rhp_tuntap_clean.pl","/usr/local/sbin/rhp_tuntap_clean.pl","0700",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/log_tool/build/rhp_logtool","/usr/local/sbin/rhp_logtool","0700",0,0) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/script/rhp_dbg","/usr/local/sbin/rhp_dbg","0750",0,0) ){
      return -1;    
    }
    
    if( chown($protected_uid,$protected_gid,"/usr/local/sbin/rhp_dbg") < 1 ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/gtk2_perl_vpn_client/rhp_client.pl","/usr/local/sbin/rhp_client.pl","0755",0,0) ){
      return -1;    
    }

    if( -e "/usr/share/applications" ){

      if( copy_and_setup("./rockhopper/gtk2_perl_vpn_client/Ubuntu-unity/rockhopper-vpn-client.desktop",
            "/usr/share/applications/rockhopper-vpn-client.desktop","0644",0,0) ){
        return -1;    
      }

      if( -e "/usr/lib/firefox" || -e "/usr/lib64/firefox" || -e "/usr/bin/firefox" ){

        if( copy_and_setup("./rockhopper/gtk2_perl_vpn_client/Ubuntu-unity/rockhopper-vpn-firefox.desktop",
              "/usr/share/applications/rockhopper-vpn-firefox.desktop","0644",0,0) ){
          return -1;    
        }

      }else{

        print "# Firefox was NOT found. Web Console's launcher was NOT installed.\n";        
      }
    }

    if( -e "/usr/share/cinnamon" && $dist_name eq $ubuntu_label ){

      if( ! -e '/usr/share/cinnamon/applets/rockhopper-vpn-client@rockhopper-vpn' ){

        if( ! mkdir('/usr/share/cinnamon/applets/rockhopper-vpn-client@rockhopper-vpn',0755) ){
          print '[ERROR] Fail to mkdir /usr/share/cinnamon/applets/rockhopper-vpn-client@rockhopper-vpn.\n';
          return -1;
        }
      }

      if( copy_and_setup('./rockhopper/gtk2_perl_vpn_client/LinuxMint-cinnamon/rockhopper-vpn-client@rockhopper-vpn/applet.js',
            '/usr/share/cinnamon/applets/rockhopper-vpn-client@rockhopper-vpn/applet.js',"0755",0,0) ){
        return -1;    
      }

      if( copy_and_setup('./rockhopper/gtk2_perl_vpn_client/LinuxMint-cinnamon/rockhopper-vpn-client@rockhopper-vpn/metadata.json',
            '/usr/share/cinnamon/applets/rockhopper-vpn-client@rockhopper-vpn/metadata.json',"0644",0,0) ){
        return -1;    
      }      
    }
  }


  if( !$no_config ){
    
    if( copy_and_setup("./installer/protected.xml","$protected_hdir/config/protected.xml","0640",$protected_uid,$protected_gid) ){
      return -1;    
    }
    
    if( copy_and_setup("./installer/auth.xml","$protected_hdir/config/auth.xml","0640",$protected_uid,$protected_gid) ){
      return -1;    
    }

    if( copy_and_setup("./installer/policy.xml","$protected_hdir/config/policy.xml","0640",$protected_uid,$protected_gid) ){
      return -1;    
    }

    if( copy_and_setup("./installer/main.xml","$main_hdir/config/main.xml","0640",$main_uid,$main_gid) ){
      return -1;    
    }
  }

#  if( copy_and_setup("./installer/index.html","$main_hdir/www/index.html","0640",$main_uid,$main_gid) ){
#    return -1;    
#  }

  print "copy web_mng files...";
  system("$cp -r ./rockhopper/web_mng/* $main_hdir/www/");
  print "Done.\n";

  print "chown web_mng files...";
  system("$chown -R rhpmain:rhpenguin $main_hdir/www/");
  print "Done.\n";


  {
    if( copy_and_setup("./rockhopper/script/rhp_netmng","$protected_hdir/script/rhp_netmng","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }

    if( system("setcap cap_net_admin,cap_net_raw=eip $protected_hdir/script/rhp_netmng") ){
      print "[ERROR] Fail to setcap $protected_hdir/script/ifconfig.\n";
      return -1;    
    }

    if( copy_and_setup("./rockhopper/tuntap_cfg/build/rhp_tuntap_cfg","$protected_hdir/script/rhp_tuntap_cfg","4755",0,0) ){
      return -1;    
    }
  }

  if( copy_and_setup("./rockhopper/script/rhp_mng","$protected_hdir/script/rhp_mng","0700",$protected_uid,$protected_gid) ){
    return -1;    
  }

  {
    if( copy_and_setup("./rockhopper/script/rhp_cfg_cert_file","$protected_hdir/script/rhp_cfg_cert_file","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }
  }


  {    
    if( copy_and_setup("./rockhopper/script/rhp_cfg_bkup_main","$main_hdir/script/rhp_cfg_bkup_main","0700",$main_uid,$main_gid) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/script/rhp_event_log_convert","$main_hdir/script/rhp_event_log_convert","0700",$main_uid,$main_gid) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/script/rhp_cfg_bkup_syspxy","$protected_hdir/script/rhp_cfg_bkup_syspxy","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/script/rhp_restore_cfg","$protected_hdir/script/rhp_restore_cfg","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }

    if( copy_and_setup("./rockhopper/script/rhp_upgrade_conf.pl","$protected_hdir/script/rhp_upgrade_conf.pl","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }
  }

  if( $action eq 'install_dbg' ){

    gen_dbg_init_d("./installer/systemd_rhp_ext","./installer/systemd_rhp_ext_dbg");

    if( copy_and_setup("./installer/systemd_rhp_ext_dbg","$protected_hdir/script/rhp_systemd_ext","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }

    if( $use_systemd_cfg ){
    
      gen_dbg_init_d("./installer/systemd_rhptrace_ext","./installer/systemd_rhptrace_ext_dbg");
      
      if( copy_and_setup("./installer/systemd_rhptrace_ext_dbg","$protected_hdir/script/rhptrace_systemd_ext","0700",$protected_uid,$protected_gid) ){
        return -1;    
      }
    }  

  }else{    
      
    if( copy_and_setup("./installer/systemd_rhp_ext","$protected_hdir/script/rhp_systemd_ext","0700",$protected_uid,$protected_gid) ){
      return -1;    
    }
  }

  if( copy_and_setup("./installer/systemd_rhp_env","$protected_hdir/script/rhp_systemd_env","0400",$protected_uid,$protected_gid) ){
    return -1;    
  }
  
  
  return 0;
}

sub setup_init_d {

  if( $use_systemd_cfg ){

      if( $action eq 'install_dbg' ){

        if( copy_and_setup("./installer/systemd_rhptrace_service","$systemdcfg_path/rhptrace.service","0744",0,0) ){
          return -1;    
        }
        
        if( system("$systemdctl enable rhptrace") ){
          print "[ERROR] Fail to enable rhptrace by systemctl.\n";
          return -1;    
        }else{
          print "$systemdctl enable rhptrace\n";
        }
      }
      
      if( copy_and_setup("./installer/systemd_rockhopper_service","$systemdcfg_path/rockhopper.service","0744",0,0) ){
        return -1;    
      }
      
      if( system("$systemdctl enable rockhopper") ){
        print "[ERROR] Fail to enable rockhopper by systemctl.\n";
        return -1;    
      }else{
        print "$systemdctl enable rockhopper\n";
      }

  }elsif( $dist_name eq $ubuntu_label ){
  
      if( $action eq 'install_dbg' ){
        
        gen_dbg_init_d("./installer/init_d_rockhopper_ubuntu","./installer/init_d_rockhopper_ubuntu_dbg");
  
        if( copy_and_setup("./installer/init_d_rockhopper_ubuntu_dbg","/etc/init.d/rockhopper","0744",0,0) ){
          return -1;    
        }
        
      }else{
  
        if( copy_and_setup("./installer/init_d_rockhopper_ubuntu","/etc/init.d/rockhopper","0744",0,0) ){
          return -1;    
        }
      }
      
      if( system("/usr/sbin/update-rc.d rockhopper start 50 2 3 4 5 . stop 9 0 1 6 .") ){
        print "[ERROR] Fail to enable rockhopper by update-rc.d.\n";
        return -1;    
      }
  
  }elsif( $dist_name eq $centos_label ){
  
    if( $action eq 'install_dbg' ){
        
      gen_dbg_init_d("./installer/init_d_rockhopper_centos","./installer/init_d_rockhopper_centos_dbg");
  
      if( copy_and_setup("./installer/init_d_rockhopper_centos_dbg","/etc/init.d/rockhopper","0744",0,0) ){
        return -1;    
      }
        
    }else{
  
      if( copy_and_setup("./installer/init_d_rockhopper_centos","/etc/init.d/rockhopper","0744",0,0) ){
        return -1;    
      }
    } 
      
    if( system("/sbin/chkconfig --add rockhopper") ){
      print "[ERROR] Fail to enable rockhopper by chkconfig.\n";
      return -1;    
    }
  }
    
  return 0;  
}

sub create_dbg_makefile
{
  my($path,$dbg_flag_type) = @_;
  
  if( $dbg_flag_type eq "all" ){
    print "Dbg_Flag_All is enabled.\n"    
  }

  print "Generating $path/subdir.mk ...";
  
  if( ! chdir($path) ){
    print "[ERROR] Fail to cd to $path. (create_dbg_makefile)\n";
    exit;
  }

  rename("./subdir.mk","./subdir.mk.org");

  open( FILE1, "./subdir.mk.org" );
  open( FILE2, "> ./subdir.mk" );
  
  my $s;
  while( $s = <FILE1> ){
  
    if( $dbg_flag_type eq "all" ){

      if( $s =~ /gcc/ && $s =~ /-D_GNU_SOURCE/ ){
        $s =~ s/-D_GNU_SOURCE/-D_GNU_SOURCE -DRHP_DBG_FUNC_TRC -DRHP_MEMORY_DBG -DRHP_REFCNT_DEBUG_X -DRHP_PKT_DEBUG -DRHP_HASH_SIZE_DBG -finstrument-functions/;
        $s =~ s/-O3/-O0/;
      }

    }elsif( $dbg_flag_type eq "no_optmz" ){

        if( $s =~ /gcc/ && $s =~ /-D_GNU_SOURCE/ ){
          $s =~ s/-O3/-O0/;
        }
    }
    
    if( defined($added_dbg_flags) ){

      my $flags = "-D_GNU_SOURCE " . $added_dbg_flags . " ";

      if( $s =~ /gcc/ && $s =~ /-D_GNU_SOURCE/ ){
        $s =~ s/-D_GNU_SOURCE/$flags/;
      }
    }
        
    print FILE2 $s;
  }
  
  close(FILE2);
  close(FILE1);

  my @dirs = split(/\//,$path);
  my $dirs_len = @dirs;  
  
  for( my $i = 1; $i < $dirs_len; $i++ ){
    if( ! chdir("..") ){
      print "\n[ERROR] Fail to cd to $root_dir from $. (create_dbg_makefile)\n\n";
      exit;
    }
  }
    
  print " Done.\n";
  return;
}

sub create_dbg_makefiles
{
  my($dbg_flag_type) = @_;
  
  create_dbg_makefile($librhpcert,$dbg_flag_type);
  create_dbg_makefile($librhpcrypto,$dbg_flag_type);
  create_dbg_makefile($librhpesp_def,$dbg_flag_type);
  create_dbg_makefile($librhpeapa_def,$dbg_flag_type);
  create_dbg_makefile($librhpeapa_def_wpa_supplicant,$dbg_flag_type);
  create_dbg_makefile($librhpeaps_def,$dbg_flag_type);
  create_dbg_makefile($librhpeaps_def_wpa_supplicant,$dbg_flag_type);
  create_dbg_makefile($librhplog_def,$dbg_flag_type);
  create_dbg_makefile($librhpradius_def,$dbg_flag_type);
  create_dbg_makefile($librhppcap_def,$dbg_flag_type);
  create_dbg_makefile($app,$dbg_flag_type);
  return;
}

sub uninstall()
{
  
  if( -e "$systemdcfg_path/rockhopper.service" ){

    if( system("$systemdctl stop rockhopper") ){
      print "[ERROR] Fail to stop rockhopper daemon by systemctl.\n";
    }else{
      print "$systemdctl stop rockhopper\n";
    }

    if( system("$systemdctl disable rockhopper") ){
      print "[ERROR] Fail to disable rockhopper by systemctl.\n";
    }else{
      print "$systemdctl disable rockhopper\n";
    }
  }

  if( -e "$systemdcfg_path/rhptrace.service" ){

    if( system("$systemdctl stop rhptrace") ){
      print "[ERROR] Fail to stop rhptrace daemon by systemctl.\n";
    }else{
      print "$systemdctl stop rhptrace\n";
    }
  
    if( system("$systemdctl disable rhptrace") ){
      print "[ERROR] Fail to disable rhptrace by systemctl.\n";
    }else{
      print "$systemdctl disable rhptrace\n";
    }
  }
  
  if( -e "/etc/init.d/rockhopper" ){

    if( system("/etc/init.d/rockhopper stop") ){
      print "[ERROR] Fail to stop rockhopper daemon.\n";
    }else{
      print "/etc/init.d/rockhopper stop\n";
    }
  }


  my($main_name, $main_passwd, $main_uid, $main_gid, $main_quota, $main_comment, $main_gcos, $main_hdir, $main_shell) = getpwnam("rhpmain"); 

  if( !$main_uid || !$main_gid || !$main_hdir ){
    print "[ERROR] Fail to get user info \"rhpmain\".\n";
  }
  

  my($protected_name, $protected_passwd, $protected_uid, $protected_gid, $protected_quota, $protected_comment, $protected_gcos, $protected_hdir, $protected_shell) = getpwnam("rhpprotected"); 

  if( !$protected_uid || !$protected_gid || !$protected_hdir ){
    print "[ERROR] Fail to get user info \"rhpprotected\".\n";
  }


  if( $protected_hdir ){
    system("$protected_hdir/rhptrace/rhp_trace_start_stop stop"); 
    sleep(1);
  }   

  my($rhptrace_helper_pid) = split(/\s+/,`ps ax |grep rhp_trace_helper`);
  
  if( $rhptrace_helper_pid =~ /^\d+$/){
    system("/bin/kill -KILL $rhptrace_helper_pid"); 
  }

#  
#  if( -e "/bin/tar" && -e "/bin/gzip" ){
#
#    if( $protected_hdir ){
#      
#      system("/bin/tar -c $protected_hdir | gzip > ./rhpprotected_bkup.tgz"); 
#      print "/bin/tar -c $protected_hdir | gzip > ./rhpprotected_bkup.tgz\n";
#
#      system("/bin/tar -c $protected_hdir/certs | gzip > ./rhpprotected_certs_bkup.tgz"); 
#      print "/bin/tar -c $protected_hdir/certs | gzip > ./rhpprotected_certs_bkup.tgz\n";
#    }
#
#    if( $main_hdir ){
#      system("/bin/tar -c $main_hdir | gzip > ./rhpmain_bkup.tgz"); 
#      print "/bin/tar -c $main_hdir | gzip > ./rhpmain_bkup.tgz\n";
#    }
#  }   

  if( -e "/usr/local/sbin/rockhopper.pl" ){
    unlink "/usr/local/sbin/rockhopper.pl";
  }

  if( -e "/usr/local/sbin/rockhopper_log.pl"){
    unlink "/usr/local/sbin/rockhopper_log.pl";
  }

  unlink "$usrlib_dir/librhptrace.so";
  unlink "$usrlib_dir/librhplog.so";
  unlink "$usrlib_dir/librhpcert.so";
  unlink "$usrlib_dir/librhpcrypto.so";
  unlink "$usrlib_dir/librhpesp.so";
  unlink "$usrlib_dir/librhpeapa.so";
  unlink "$usrlib_dir/librhpradius.so";
  unlink "$usrlib_dir/librhpeaps.so";
  unlink "/usr/sbin/rockhopperd";
  unlink "/usr/local/sbin/rhp_trace";
  unlink "/usr/local/sbin/rhp_tuntap_tool";
  unlink "/usr/local/sbin/rhp_tuntap_clean.pl";
  unlink "/usr/local/sbin/rockhopper";
  unlink "/usr/local/sbin/rockhopper_log";
  unlink "/usr/local/sbin/rhp_logtool";
  unlink "/usr/local/sbin/rhp_dbg";
  unlink "/usr/local/sbin/rhp_client.pl";
  unlink "$usrlib_dir/librhpbfltr.so";
  unlink "$usrlib_dir/librhppcap.so";


  if( -e '/usr/share/applications/rockhopper-vpn-client.desktop' ){
    unlink '/usr/share/applications/rockhopper-vpn-client.desktop';
  }


  if( -e '/usr/share/applications/rockhopper-vpn-firefox.desktop' ){
    unlink '/usr/share/applications/rockhopper-vpn-firefox.desktop';
  }


  if( -e '/usr/share/cinnamon/applets/rockhopper-vpn-client@rockhopper-vpn' ){
    unlink '/usr/share/cinnamon/applets/rockhopper-vpn-client@rockhopper-vpn/applet.js';
    unlink '/usr/share/cinnamon/applets/rockhopper-vpn-client@rockhopper-vpn/metadata.json';
    rmdir('/usr/share/cinnamon/applets/rockhopper-vpn-client@rockhopper-vpn');
  }  
  

  if( -e "/etc/init.d/rockhopper" ){

    if( $dist_name eq $ubuntu_label ){  
  
      if( system("update-rc.d -f rockhopper remove") ){
        print "[ERROR] Fail to update-rc.d rockhopper stop.\n";
      }
  
    }elsif( $dist_name eq $centos_label ){
  
      if( system("/sbin/chkconfig --del rockhopper") ){
        print "[ERROR] Fail to chkconfig rockhopper stop.\n";
      }
    }
  }
    
  if( -e "/dev/net/tun" ){
    system("chown root:root /dev/net/tun");
  }


  if( $dist_name eq $ubuntu_label ){  

    if( system("/usr/sbin/deluser --remove-home rhpmain") ){
      print "[ERROR] Fail to deluser \"rhpmain\".\n";
    }
    
    if( system("/usr/sbin/deluser --remove-home rhpprotected") ){
      print "[ERROR] Fail to deluser \"rhpprotected\".\n";
    }
  
    if( system("/usr/sbin/delgroup --only-if-empty rhpenguin") ){
      print "[ERROR] Fail to delgroup \"rhpenguin\".\n";
    }

  }elsif( $dist_name eq $centos_label ){

    if( system("/usr/sbin/userdel -r rhpmain") ){
      print "[ERROR] Fail to userdel \"rhpmain\".\n";
    }
    
    if( system("/usr/sbin/userdel -r rhpprotected") ){
      print "[ERROR] Fail to userdel \"rhpprotected\".\n";
    }
  
    if( system("/usr/sbin/groupdel rhpenguin") ){
      print "[ERROR] Fail to groupdel \"rhpenguin\".\n";
    }
  }


  if( -e "/var/run/rockhopper" ){
    rmtree("/var/run/rockhopper");
  }


  if( -e "$systemdcfg_path/rockhopper.service" ){
    unlink "$systemdcfg_path/rockhopper.service";
  }

  if( -e "$systemdcfg_path/rhptrace.service" ){
    unlink "$systemdcfg_path/rhptrace.service";
  }
  
  if( -e "/etc/init.d/rockhopper" ){    
    unlink "/etc/init.d/rockhopper";
  }
  
  sleep(2);

#  print "[NOTICE]\n";
#  print "For backup, rhpprotected_bkup.tgz, rhpprotected_bkup.tgz \n";
#  print "and rhpprotected_certs_bkup.tgz were created.\n";

  return;    
}

sub am_i_root {

  my $eusr = `whoami`;
  chop($eusr);
  
  if( $eusr ne 'root' ){
    print "[ERROR] To install or uninstall this software, please run\n";
    print "        this installer's script as root.\n";
    print "(ex) sudo ./install.sh\n";
    print "(ex) sudo ./uninstall.sh\n";
    exit;
  }
  
  return;
}


print "  -- IP Security Software \"Rockhopper VPN\" --\n";
print "  \n";

print "  ## NOTICE ##\n";
print "  This installer is currently tested on the following distributions.\n";
print "   - Ubuntu 12.04 or later\n";
print "   - LinuxMint 17 or later\n";
print "   - Debian 7.1 or later\n";
print "   - CentOS 6.0 or later\n";
print "   - Fedora 21 or later\n";
print "\n";

if( $dist_name ne $ubuntu_label && $dist_name ne $centos_label ){
  print "## NOTICE ##\n";
  print " This software may run on old above distributions and other\n";
  print " distributions corresponding to the above Ubuntu or CentOS\n";
  print " versions.\n";
  print " To install this software, you may need to edit this installer\n";
  print " script by yourself. Sorry!";
  print "\n\n";
  
  exit;
}

sleep(3);

if( $action eq 'uninstall' ){

  print "[NOTICE]\n";
  print " Before uninstalling, you can create a backup file including\n";
  print " all settings, keys and certificates by Web console or\n";
  print " rockhopper command.\n\n";

  print "Do you really uninstall this software now? [N/y]\n";
  
  my $ans = <STDIN>;
  if( $ans eq "y\n" || $ans eq "Y\n"){
  }else{
    exit;    
  }

  print "\n";
  print "Now uninstalling Rockhopper ... \n";

  am_i_root();
  uninstall();
  
  print "\n";
  print "[NOTICE]\n";
  print " Please restart system just to make sure.\n";

  print "Thank you,                   --- Rockhopper VPN Project\n\n";
  exit; 
}


print "  --\n";
print "  Copyright (C) 2009-2016 TETSUHARU HANADA <rhpenguine\@gmail.com>\n";
print "  All rights reserved.\n";
print "  You can redistribute and/or modify this software under the\n";
print "  LESSER GPL version 2.1.\n";
print "  See ./rockhopper/LICENSE.txt and LICENSE_LGPL2.1.txt.\n";
print "  \n";
print "  The following libraries and files of this software are distributed\n"; 
print "  under the BSD license.\n";
print "   - ./rockhopper/librhptrace and librhplog_def\n";
print "   - ./rockhopper/librhpesp_def\n";
print "   - ./rockhopper/librhpeapa_def and librhpeaps_def\n";
print "   - ./rockhopper/librhpcrypto_openssl and librhpcert_openssl\n";
print "   - ./rockhopper/librhpbfltr\n";
print "   - ./rockhopper/librhpradius_def\n";
print "   - ./rockhopper/librhppcap_def\n";
print "   - ./rockhopper/web_mng/*\n";
print "   - ./rockhopper/mng_cmd_tools/rockhopper.pl and rockhopper_log.pl\n";
print "  --\n";

print "\nPush <Enter>\n";
$nxtrtn = <STDIN>;

print "  --\n";
print "  This software includes The Dojo Toolkit. Please confirm the\n";
print "  license information(./rockhopper/web_mng/dojo_license.txt).\n";
print "  Also, please visit the project site (http://dojotoolkit.org)\n";
print "  to get more detailed information.\n";
print "  --\n";
print "  This software includes wpa_supplicant. Please read the license\n";
print "  document(./rockhopper/librhpeapa_def/README).\n";
print "  Also, please visit the project site (http://hostap.epitest.fi/\n";
print "  wpa_supplicant/) to get more detailed information.\n";
print "  --\n";
print "  These are redistributed under the BSD license.";
print "  \n\n";

print "\nPush <Enter>\n";
$nxtrtn = <STDIN>;



am_i_root();

my $overwrite = 0;
my $no_config = 0;

if( -e "/usr/sbin/rockhopperd" ){

  print "Rockhopper VPN Software is already installed.\n\n";

  if( $use_systemd_cfg && -e "/etc/init.d/rockhopper" ){

    print "The old installation isn't configured for systemd.\n\n";
    
    print "After uninstalling the old package, please try to install\n";
    print "this new package again. You can do this by uninstall.sh \n";
    print "script.\n\n";

    print "Before uninstalling, you can create a backup file including\n";
    print "all settings, keys and certificates by Web console or\n";
    print "rockhopper command.\n\n";
    
    exit;        
  }

  print "Do you want to overwrite the old installation anyway? [y/N]\n";

  my $ans = <STDIN>;
  if( $ans ne "y\n" && $ans ne "Y\n" ){
    exit;
  }

  if( $use_systemd_cfg ){

    if( system("$systemdctl stop rockhopper") ){
      print "[ERROR] Fail to stop rockhopper daemon by systemctl.\n";
    }
    
  }else{

    if( system("/etc/init.d/rockhopper stop") ){
      print "[ERROR] Fail to stop rockhopper daemon.\n";
    }
  }
  
  $overwrite = 1;
  $no_config = 1;
}

if( $use_systemd_cfg ){
  print "\nSystemd's configuration is applied.\n\n";
}else{
  print "\nInit.d's configuration is applied.\n\n";
}

sleep(3);

umask(0);

if( check_dependencies(0) < 0 ){
  print "\n";
  exit;
}

print "\nPush <Enter>\n";
$nxtrtn = <STDIN>;


if( $action eq 'install_dbg' ){
  
  my $argn = @ARGV;
  if($argn > 1){
    
    $action2 = $ARGV[1];
    
    print "install_dbg's option: $action2\n";
  }

  if( $action2 eq 'no_optmz' ){
    create_dbg_makefiles("no_optmz");
  }elsif($action2 eq 'all'){
    create_dbg_makefiles("all");
  }elsif( defined($added_dbg_flags) ){
    create_dbg_makefiles("no_flags_type");
  }
  
  build_rhptrace_module();
}
build_rhptrace_tools();
build_rhptrace_lib();

sleep(2);

build_librhpbfltr();
build_librhplog_def();
build_librhppcap_def();
build_librhpcert_openssl();
build_librhpcrypto_openssl();
build_librhpesp_def();
build_librhpradius_def();
build_librhpeapa_def();
build_librhpeaps_def();
build_tuntap_tool();
build_tuntap_cfg();
build_log_tool();
build_rockhopper();

sleep(2);

if( setup_users_and_files($no_config) ){
  uninstall();
  print "\n";
  exit;
}

sleep(2);

if( setup_init_d() ){
  uninstall();
  print "\n";
  exit;  
}


if( $dist_name eq $centos_label || 
    ($dist_name eq $ubuntu_label && !check_installed_pkg("libgtk2-perl",$ubuntu_label)) ){


  if( $dist_name eq $ubuntu_label ){

    print "\n";
    print "[NOTICE]\n";
    print " If you run a Simple VPN Client GUI, it needs\n"; 
    print " a GTK2-perl package.\n";
    print "\n";
    print "Do you want to try installation of the package now?\n";
    print "[y/N]\n";
    
    my $ans = <STDIN>;
    if( $ans eq "y\n" || $ans eq "Y\n"){
    
      print "Exec \"apt-get install libgtk2-perl\"\n";
      system("apt-get install libgtk2-perl");
  
    }else{
  
      print "You can install the additonal package manually.\n";
      print "  - Open a terminal window.\n";
      print "  - Install it by apt-get.\n";
      print "    \$ sudo apt-get install libgtk2-perl\n";  
      
      print "\nPush <Enter>\n";
      my $nxtrtn = <STDIN>;
    }

  }elsif( $dist_name eq $centos_label ){
    
    print "\n";
    print "[NOTICE]\n";
    print " If you run a Simple VPN Client GUI, you need to\n"; 
    print " install or build a GTK2-perl package manually.\n";

    print "\nPush <Enter>\n";
    my $nxtrtn = <STDIN>;
  }
}


if( !$overwrite ){

  if( $use_systemd_cfg ){

    if( $action eq 'install_dbg' ){

      if( system("$systemdctl start rhptrace") ){
        print "\n";
        print "[ERROR] Fail to start rhptrace by systemctl. Please try later...\n";
      }else{
        print "\n";
        print "$systemdctl start rhptrace\n";
      }
    }
    
    if( system("$systemdctl start rockhopper") ){
      print "\n";
      print "[ERROR] Fail to start rockhopper by systemctl. Please try later...\n";
    }else{
      print "\n";
      print "$systemdctl start rockhopper\n";
    }

  }else{
    if( system("/etc/init.d/rockhopper start") ){
      print "\n";
      print "[ERROR] Fail to start rockhopper. Please try later...\n";
    }
  }
  
}else{
  
  my($protected_name, $protected_passwd, $protected_uid, $protected_gid, $protected_quota, $protected_comment, $protected_gcos, $protected_hdir, $protected_shell) = getpwnam("rhpprotected");   
  system("$protected_hdir/script/rhp_upgrade_conf.pl -target install-overwrite");
  sleep(3);
  
  print "\n";
  print "[NOTICE]\n";
  print " Please restart system ...\n";
}

print "\n";
print "[NOTICE]\n";
print " - Default administrator's information for management\n";
print "   tools (Web console and rockhopper command): \n\n";
print "     Name    : admin\n";
print "     Password: secret\n\n";
print "   Please change the default password immediately!\n";

sleep(2);

print "\n";
print " - A default HTTP URL for Web Management Service:\n\n";
print "     URL: http://127.0.0.1:32501/\n";
print "         (http://localhost:32501/)\n\n";
print "   Web console has been tested only on Firefox and\n";
print "   Google Chrome.\n";

sleep(2);

print "\nRockhopper was successfully installed.\n";
print "Enjoy,                    --- Rockhopper VPN Project\n";


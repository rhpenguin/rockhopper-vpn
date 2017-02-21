
#
#  Script to format function call trace.
#
#  (usage)
#    $/usr/bin/perl rhp_trace_split_files.pl <trace_file>
#

if( @ARGV < 1 ){

    print "Usage: $/usr/bin/perl rhp_trace_split_files.pl <trace_file>\n";

}else{

  open(TRC,$ARGV[0]) || "Can't open $ARGV[0]. \n";

	my %pidtids = ();
  my @mem_not_freed_lines = ();
  
  while( <TRC> ){

      if( /p:/ ){
          if( /t:/ ){
              if( !/\[TRF\]/ && !/\[rhp_file_trace\]/ ){
                my @elms = split;
          	    $pidtids{$elms[5]} = 1;
              }
          }
      }
        
      if( /MEM_NOT_FREED/ ){
        
        my %not_freed_rec = ();

        $not_freed_rec{"LINESTR"} = $_;

        my @elms = split(/\(MEM_NOT_FREED\)/,$_);

        my $header = $elms[0];

        my @elms2 = split(/,/,$elms[1]);
        foreach my $elm2 (@elms2){
          $elm2 =~ s/\s+//g;
          my @elms3 = split(/:/,$elm2);
          if( $elms3[0] eq "FILE" ){
            $not_freed_rec{$elms3[0]} = $elms3[1] . ":" . $elms3[2];
          }else{
            $not_freed_rec{$elms3[0]} = $elms3[1];
          }        
#          print "Tag: " . $elms3[0] . " : " . $elms3[1] . "\n";          
        }
          
        push(@mem_not_freed_lines,\%not_freed_rec);          
      }
  }
  
  close(TRC);

  my $pnum = 0;
  while( my($pidtidname,$vvv) = each(%pidtids) ){

      my @elms2 = split(/,/,$pidtidname);
      $elms2[0] =~ s/:/_/g;
      $elms2[1] =~ s/:/_/g;
      my $filename = "output_$elms2[0]_$elms2[1].txt";

      open(TRC,$ARGV[0]) || "Can't open $ARGV[0]. \n";
      open(TRC_SPLIT,"> ./split/$filename") || "Can't open $filename. \n";

      while( <TRC> ){

          if( /$pidtidname/ ){
            print TRC_SPLIT $_;
          }
      }
      close(TRC_SPLIT);
      close(TRC);
      
      $pnum++;
      
      if( $pnum > 100 ){
        print "Max split files reached. Break!\n";
        last;
      }
  }


  my @bybytes = sort { $a->{"BYTES"} <=> $b->{"BYTES"} } @mem_not_freed_lines;

  open(MEM_TRC,"> ./mem_dbg_bybytes.txt") || "Can't open mem_dbg_bybytes.txt. \n";
    
  foreach my $not_freed_rec_ref (@bybytes){
    
    print MEM_TRC $$not_freed_rec_ref{"LINESTR"} . "\n";
  }
  
  close(MEM_TRC);


  my @bytime = sort { $a->{"TIME"} <=> $b->{"TIME"} } @mem_not_freed_lines;

  open(MEM_TRC,"> ./mem_dbg_bytime.txt") || "Can't open mem_dbg_bytime.txt. \n";
    
  foreach my $not_freed_rec_ref (@bytime){
    
    print MEM_TRC $$not_freed_rec_ref{"LINESTR"} . "\n";
  }
  
  close(MEM_TRC);


  my @byelapsing = sort { $a->{"ELAPSING"} <=> $b->{"ELAPSING"} } @mem_not_freed_lines;

  open(MEM_TRC,"> ./mem_dbg_byelapsing.txt") || "Can't open mem_dbg_byelapsing.txt. \n";
    
  foreach my $not_freed_rec_ref (@byelapsing){
    
    print MEM_TRC $$not_freed_rec_ref{"LINESTR"} . "\n";
  }
  
  close(MEM_TRC);


  my @byfile = sort { $a->{"FILE"} cmp $b->{"FILE"} } @mem_not_freed_lines;

  open(MEM_TRC,"> ./mem_dbg_byfile.txt") || "Can't open mem_dbg_byfile.txt. \n";
  open(MEM_TRC2,"> ./mem_dbg_byfile_no_dup.txt") || "Can't open mem_dbg_byfile_no_dup.txt. \n";
    
  my $plinefilename;
  foreach my $not_freed_rec_ref (@byfile){

    if( $plinestr ne $$not_freed_rec_ref{"FILE"} ){      
      print MEM_TRC2 $$not_freed_rec_ref{"LINESTR"} . "\n";
    }
    print MEM_TRC $$not_freed_rec_ref{"LINESTR"} . "\n";
    $plinestr = $$not_freed_rec_ref{"FILE"};
  }
  
  close(MEM_TRC);
  
}


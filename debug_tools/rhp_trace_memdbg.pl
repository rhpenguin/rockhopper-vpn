
  #
  #  Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
  #  All rights reserved.
  #
  #  You can redistribute and/or modify this software under the
  #  LESSER GPL version 2.1.
  #  See also LICENSE.txt and LICENSE_LGPL2.1.txt.
  #

  #
  #  (usage)
  #    $/usr/bin/perl rhp_trace_memdbg.pl
  #
  %files = ();
  %filelines = ();

  open( TRC, "./output.txt" ) || "Can't open ./output.txt. \n";

  while (<TRC>) {

    if (/MEM_NOT_FREED/) {

      @elms  = split(/MEM_NOT_FREED/,$_);
      @elms2 = split(/,/,$elms[1]);

      for ( $elm_i = 0 ; $elm_i < @elms2 ; $elm_i++ ) {

        @elms3 = split(/:/,$elms2[$elm_i]);

        $elms3[0] =~ s/\s*//;
        if ( $elms3[0] eq "FILE" ) {

          $elms3[1] =~ s/\s//;
          if ( !exists $files{ $elms3[1] } ) {
            $files{ $elms3[1] } = 1;
          }
          
          
          if ( !exists $filelines{ $elms2[$elm_i] } ) {
            $filelines{ $elms2[$elm_i] } = 1;
          }else{
            $lines = $filelines{ $elms2[$elm_i] };
            $filelines{ $elms2[$elm_i] } = ++$lines;
          }
        }
      }
    }
  }
  close(TRC);

  foreach $fileline ( keys(%filelines) ){
    $lines = $filelines{ $fileline };
    print "$fileline \t\t\t: $lines \n";
  }
  print "\n\n";
  

  foreach $filename ( keys(%files) ) {

    $line = 0;
    open( TRC, "./output.txt" ) || "Can't open . /output.txt. \n";
    while (<TRC>) {

      $line++;

      if (/MEM_NOT_FREED/) {

        @elms  = split(/MEM_NOT_FREED/,$_);
        @elms2 = split(/,/,$elms[1]);

        for ( $elm_i = 0 ; $elm_i < @elms2 ; $elm_i++ ) {

          @elms3 = split(/:/,$elms2[$elm_i]);

          $elms3[0] =~ s/\s*//;
          $elms3[1] =~ s/\s*//;
          if ( $elms3[0] eq "FILE" && $elms3[1] eq $filename ) {
            print "output.txt($line): $_";
          }
        }
      }
    }
    close(TRC);
    
    print "\n\n";
  }


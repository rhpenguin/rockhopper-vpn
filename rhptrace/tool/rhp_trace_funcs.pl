
#
#  Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
#  All rights reserved.
#
#  You can redistribute and/or modify this software under the
#  LESSER GPL version 2.1.
#  See also LICENSE.txt and LICENSE_LGPL2.1.txt.
#

#
#  Script to format function call trace.
#
#  (usage)
#    $/usr/bin/perl rhp_trace_funcs.pl <trace_file> [program_path]
#

$prog = "../../app/Debug/rockhopper";

if ( @ARGV < 1 ) {

  print "Usage: /usr/bin/perl rhp_trace_funcs.pl <trace_file> [program_path]\n";

} else {

  if ( @ARGV == 2 ) {
    $prog = $ARGV[1];
  }

  open( TRC, $ARGV[0] ) || "Can't open $ARGV[0]. \n";

  %add2line = ();

  $bt_flag = 0;
  while (<TRC>) {

    if (/##FUNC_ADDR_START##/) {

      @elms = split( /##FUNC_ADDR_START##/, $_ );
      $prtflg = 0;
      for ( $elm_i = 0 ; $elm_i < @elms ; $elm_i++ ) {

        if ( @elms[$elm_i] =~ /##FUNC_ADDR_END##/ ) {

          @elms2 = split( /##FUNC_ADDR_END##/, @elms[$elm_i] );

          if ( exists $add2line{ $elms2[0] } ) {
            $ret = $add2line{ $elms2[0] };
          } else {
            $ret = `/usr/bin/addr2line -e $prog -f $elms2[0]`;
            $add2line{ $elms2[0] } = $ret;
          }

          @rets  = split( /\n/, $ret );
          @paths = split( /\//, $rets[1] );

          if ( !$prtflg ) {
            print $elms[0] . "  "
              . $rets[0] . "()["
              . $elms2[0] . "]["
              . $paths[ @paths - 1 ] . "]"
              . $elms2[1];
          } else {
            print $rets[0] . "()["
              . $elms2[0] . "]["
              . $paths[ @paths - 1 ] . "]"
              . $elms2[1];
          }
          $prtflg++;
        }
      }

    } elsif (/##FUNC_TRC_ADR_START##/) {

      @elms  = split( /##FUNC_TRC_ADR_START##/, $_ );
      @elms2 = split( /##FUNC_TRC_ADR_END##/,   @elms[1] );

      if ( exists $add2line{ $elms2[0] } ) {
        $ret = $add2line{ $elms2[0] };
      } else {
        $ret = `/usr/bin/addr2line -e $prog -f $elms2[0]`;
        $add2line{ $elms2[0] } = $ret;
      }

      @rets  = split( /\n/, $ret );
      @paths = split( /\//, $rets[1] );

      print $elms[0] . "\t";
      $ii_num = ( $elms2[1] - 1 );
      if ( $ii_num < 1 ) {
        $ii_num = 0;
      }
      for ( $ii = 0 ; $ii < $ii_num ; $ii++ ) {
        print "  ";
      }
      print $rets[0] . "()[" . $elms2[0] . "][" . $paths[ @paths - 1 ] . "]";

    } elsif (/Backtrace\:/) {

      # For libSegFault.so

      $bt_flag = 1;
      print $_;

    } else {

      print $_;

      if ($bt_flag) {

        # For libSegFault.so

        if (/\[/) {

          @elms = split( /\[/, $_ );
          @elms = split( /\]/, $elms[1] );
          $ret  = `/usr/bin/addr2line -e $prog -f $elms[0]`;

          @rets  = split( /\n/, $ret );
          @paths = split( /\//, $rets[1] );
          print " ($elms[0])==> "
            . $rets[0]
            . "() :\t["
            . $paths[ @paths - 1 ] . "]\n";

        } else {
          $bt_flag = 0;
        }
      }
    }
  }
  close(TRC);
}

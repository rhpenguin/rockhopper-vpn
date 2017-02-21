
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
#    $/usr/bin/perl rhp_trace_split_files.pl <trace_file>
#

if( @ARGV < 1 ){

    print "Usage: $/usr/bin/perl rhp_trace_split_files.pl <trace_file>\n";

}else{

    open(TRC,$ARGV[0]) || "Can't open $ARGV[0]. \n";

	%pidtids = ();

    while( <TRC> ){

        if( /p:/ ){
            if( /t:/ ){
                if( !/\[TRF\]/ ){
                    @elms = split;
            	    $pidtids{$elms[5]} = 1;
                }
            }
        }
    }
  
    close(TRC);

    while( ($pidtidname,$vvv) = each(%pidtids) ){

        @elms2 = split(/,/,$pidtidname);
        $elms2[0] =~ s/:/_/g;
        $elms2[1] =~ s/:/_/g;
        $filename = "output_$elms2[0]_$elms2[1].txt";

        open(TRC,$ARGV[0]) || "Can't open $ARGV[0]. \n";
        open(TRC_SPLIT,"> ./split/$filename") || "Can't open $filename. \n";

        while( <TRC> ){

            if( /$pidtidname/ ){
                print TRC_SPLIT $_;
            }
        }
        close(TRC_SPLIT);
        close(TRC);
    }
}


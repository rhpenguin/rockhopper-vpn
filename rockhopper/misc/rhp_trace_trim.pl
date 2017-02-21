
#
#  Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
#  All rights reserved.
#
#  You can redistribute and/or modify this software under the
#  LESSER GPL version 2.1.
#  See also LICENSE.txt and LICENSE_LGPL2.1.txt.
#

open( FILE1, "$ARGV[0]" )   || "Can't open $ARGV[0]. \n";
open( FILE2, "> $ARGV[1]" ) || "Can't open $ARGV[1]. \n";

$flag = 0;
while (<FILE1>) {

  if ( $flag == 0 && /\<\?xml/ ) {
    $flag = 1;
  }
  if ($flag) {
    print FILE2 $_;
  }
}

close(FILE2);
close(FILE1);


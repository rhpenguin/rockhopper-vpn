./rhp_trace -s tmp.trc
./rhp_trace -t tmp.trc rhp_trc_comm.xml rhp_trc_main.xml rhp_trc_syspxy.xml rhp_trc_mainfreq.xml rhp_trc_syspxyfreq.xml rhp_trc_func.xml rhp_trc_file.xml > ./tmp.txt
perl rhp_trace_funcs.pl ./tmp.txt > ./output.txt
rm split/*.txt
perl rhp_trace_split_files.pl output.txt

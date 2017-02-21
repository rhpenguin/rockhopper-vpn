
rm ./trcfmt/format_template_*.txt 
rm ./trcfmt/rhp_*.h 
rm ./trcfmt/rhp_*.xml
rm ./src/*.c

cp ../app/*.c ./src/
cp ../librhpcert_openssl/*.c ./src/
cp ../librhpcrypto_openssl/*.c ./src/
cp ../librhpeapa_def/*.c ./src/
cp ../librhpeapa_def/wpa_supplicant/*.c ./src/
cp ../librhpeaps_def/*.c ./src/
cp ../librhpeaps_def/wpa_supplicant/*.c ./src/
cp ../librhpesp_def/*.c ./src/
cp ../librhplog_def/*.c ./src/


perl ./rhp_trace_code.pl

cp ./format_template_comm.txt ./trcfmt/rhp_comm_trcfmt.c
cp ./format_template_main.txt ./trcfmt/rhp_main_trcfmt.c
cp ./format_template_syspxy.txt ./trcfmt/rhp_syspxy_trcfmt.c
cp ./format_template_mainfreq.txt ./trcfmt/rhp_mainfreq_trcfmt.c
cp ./format_template_syspxyfreq.txt ./trcfmt/rhp_syspxyfreq_trcfmt.c
cp ./format_template_log.txt ./trcfmt/rhp_logfmt.c

cp ./rhp_*.h ../include/

gcc -E -I../include/ ./trcfmt/rhp_comm_trcfmt.c > ./trcfmt/rhp_trc_comm.xml.tmp
gcc -E -I../include/ ./trcfmt/rhp_main_trcfmt.c > ./trcfmt/rhp_trc_main.xml.tmp
gcc -E -I../include/ ./trcfmt/rhp_syspxy_trcfmt.c > ./trcfmt/rhp_trc_syspxy.xml.tmp
gcc -E -I../include/ ./trcfmt/rhp_mainfreq_trcfmt.c > ./trcfmt/rhp_trc_mainfreq.xml.tmp
gcc -E -I../include/ ./trcfmt/rhp_syspxyfreq_trcfmt.c > ./trcfmt/rhp_trc_syspxyfreq.xml.tmp
gcc -E -I./trcfmt/ ./trcfmt/rhp_logfmt.c > ./trcfmt/rhp_log.xml.tmp

perl ./rhp_trace_trim.pl ./trcfmt/rhp_trc_comm.xml.tmp ./trcfmt/rhp_trc_comm.xml  
perl ./rhp_trace_trim.pl ./trcfmt/rhp_trc_main.xml.tmp ./trcfmt/rhp_trc_main.xml
perl ./rhp_trace_trim.pl ./trcfmt/rhp_trc_syspxy.xml.tmp ./trcfmt/rhp_trc_syspxy.xml
perl ./rhp_trace_trim.pl ./trcfmt/rhp_trc_mainfreq.xml.tmp ./trcfmt/rhp_trc_mainfreq.xml
perl ./rhp_trace_trim.pl ./trcfmt/rhp_trc_syspxyfreq.xml.tmp ./trcfmt/rhp_trc_syspxyfreq.xml
perl ./rhp_trace_trim.pl ./trcfmt/rhp_log.xml.tmp ./trcfmt/rhp_log_template.xml

cp ./trcfmt/*.xml ../../debug_tools/

mv ./format_template_*.txt ./trcfmt/
mv ./*.h ./trcfmt/
rm ./trcfmt/rhp_*.xml.tmp
rm ./trcfmt/rhp_*.c


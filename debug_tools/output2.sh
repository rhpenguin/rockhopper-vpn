cp /home/rhpmain/rockhopper_main.trc ./rockhopper_main.trc
rhp_trace -t rockhopper_main.trc rhp_trc_comm.xml rhp_trc_main.xml rhp_trc_syspxy.xml rhp_trc_mainfreq.xml rhp_trc_syspxyfreq.xml rhp_trc_func.xml rhp_trc_file.xml > ./tmp.txt
perl rhp_trace_funcs.pl ./tmp.txt ../rockhopper/app/build/rockhopperd > ./output_main.txt
chmod a+rw output_main.txt

cp /home/rhpprotected/rockhopper_syspxy.trc ./rockhopper_syspxy.trc
rhp_trace -t rockhopper_syspxy.trc rhp_trc_comm.xml rhp_trc_main.xml rhp_trc_syspxy.xml rhp_trc_mainfreq.xml rhp_trc_syspxyfreq.xml rhp_trc_func.xml rhp_trc_file.xml > ./tmp.txt
perl rhp_trace_funcs.pl ./tmp.txt ../rockhopper/app/build/rockhopperd > ./output_syspxy.txt
chmod a+rw output_syspxy.txt

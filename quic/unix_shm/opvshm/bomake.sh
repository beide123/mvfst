make -j 8

scp -r /home/emma/mvfst/shm root@192.168.80.144:/home/emma/mvfst/

scp -r /home/emma/mvfst/quic/client root@192.168.80.144:/home/emma/mvfst/quic/

scp -r /home/emma/mvfst/quic/server root@192.168.80.144:/home/emma/mvfst/quic/

scp -r /home/emma/mvfst/quic/api root@192.168.80.144:/home/emma/mvfst/quic/

scp uixshm uixshm_client config.txt cli.conf root@192.168.80.144:/home/emma/mvfst/_build/build/quic/unix_shm/
